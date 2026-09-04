# ── Technitium DNS engine module ───────────────────────────────────────────────
# Provisions Technitium DNS Server as the router's filtering resolver.
#
# Technitium's main config (dns.config) is binary and cannot be generated
# declaratively, so provisioning happens in three phases:
#   1. FIRST BOOT: DNS_SERVER_* environment variables seed the config — they
#      are read only when dns.config is absent (verified in DnsServer.cs).
#   2. APP PRE-SEEDING: a root ExecStartPre copies the from-source DNS app
#      payloads (Advanced Blocking, Log Exporter, Block Page — compiled by
#      pkgs/technitium-apps, re-exposed via pkgs/router-dns-tools passthru) into
#      the state dir before the daemon starts, so filtering is enforced from
#      the first second. The Block Page
#      app also receives the Nix-generated branded wwwroot.
#   3. RECONCILE: technitium-reconcile.service (oneshot, re-run by every
#      nixos-rebuild whose generated desired state changed) asserts settings,
#      the local zone, SafeSearch ANAME zones, app configs (including the
#      compiled Advanced Blocking policy config), and the read-only Cockpit
#      API token via the HTTP API.
#
# Split-horizon DNS (router.dns.overrides / forwardZones /
# registerStaticHosts) rides on phase 3: the desired zones and records are
# grouped in Nix and reconciled through the same API client, with their own
# managed-state file so removals are reaped.
#
# router-policy-push.service re-pushes ONLY the compiled Advanced Blocking
# config; a path unit triggers it whenever the synced directory state changes,
# so identity-based assignments follow the IdP without a rebuild.
{
  config,
  lib,
  pkgs,
  routerOverlay,
  ...
}:
with lib;
let
  cfg = config.router;
  tcfg = cfg.dns.technitium;
  inherit (config.router._internal)
    lanGW
    guestGW
    allHomeNets
    brLAN
    ;

  catalog = import ./filter-catalog.nix;

  # Apply the router overlay locally (it closes over the technitium-dns flake
  # input) rather than via nixpkgs.overlays, which conflicts when a consumer
  # supplies nixpkgs.pkgs. router-dns-tools re-exposes the from-source
  # Technitium apps via passthru.
  routerDnsTools = (pkgs.extend routerOverlay).router-dns-tools;

  stateDir = "/var/lib/router-technitium";
  technitiumStateDir = "/var/lib/technitium-dns-server";
  webUrl = "http://127.0.0.1:${toString tcfg.webPort}";
  localZone = "${cfg.hostName}.${cfg.lan.domain}";

  # Bind all interfaces rather than the specific gateway IPs: it avoids racing
  # br-lan/br-guest address assignment at reconcile time, and is safe because
  # nftables drops :53 from WAN and recursion is limited to internal networks
  # (recursionNetworkACL below). Matches Technitium's first-boot default, so the
  # reconcile never has to rebind the listener.
  listenEndpoints = [
    "0.0.0.0:${toString tcfg.listenPort}"
    "[::]:${toString tcfg.listenPort}"
  ];

  # Bind the block-page web server on all interfaces (WAN :80/:443 stays
  # dropped by nftables) so it never races gateway address assignment and can
  # answer on both lanGW and guestGW. Blocked clients are still directed to a
  # gateway IP by the policy's blockingAddresses.
  blockPageAddresses = [
    "0.0.0.0"
    "::"
  ];

  # Branded block page (static-site mode wwwroot). The exception-request form
  # posts to router-logd's portal endpoint — an absolute URL, since the page
  # is served from http://<blocked-domain>/.
  blockPageWwwroot =
    pkgs.runCommand "router-blockpage-wwwroot"
      {
        template = routerDnsTools.passthru.blockPageTemplate;
        inherit (cfg.accessPolicies.blockPage)
          title
          heading
          message
          contactEmail
          ;
        portalUrl = "http://${lanGW}:${toString cfg.reporting.logd.port}";
      }
      ''
        mkdir -p $out
        substitute $template $out/index.html \
          --replace-fail "@TITLE@" "$title" \
          --replace-fail "@HEADING@" "$heading" \
          --replace-fail "@MESSAGE@" "$message" \
          --replace-fail "@CONTACT@" "$contactEmail" \
          --replace-fail "@PORTAL_URL@" "$portalUrl"
      '';

  # ── Unified runtime config for the router-dns-tools CLIs ─
  # One Nix-generated JSON drives reconcile, policy-push, logd, directory
  # sync, and reports. Secrets never appear here — only paths to runtime-
  # generated token/credential files.
  dnsToolsConfig = pkgs.writeText "router-dns-tools.json" (
    builtins.toJSON {
      inherit webUrl;
      adminUser = "admin";
      adminPassFile = "${stateDir}/admin.pass";
      managedZonesFile = "${stateDir}/managed-zones.json";
      lastReconcileFile = "${stateDir}/last-reconcile.json";

      settings = {
        dnsServerDomain = localZone;
        dnsServerLocalEndPoints = concatStringsSep "," listenEndpoints;
        webServiceLocalAddresses = "127.0.0.1";
        webServiceHttpPort = toString tcfg.webPort;
        forwarders = concatStringsSep "," tcfg.upstreamServers;
        forwarderProtocol = "Https";
        concurrentForwarding = "true";
        # Not "Deny" — that would refuse LAN clients. Recursion (including
        # forwarding) is allowed for internal networks + loopback only.
        recursion = "UseSpecifiedNetworkACL";
        recursionNetworkACL = concatStringsSep "," (
          [
            "127.0.0.0/8"
            "::1/128"
          ]
          ++ allHomeNets
        );
        dnssecValidation = "true";
        # The Advanced Blocking app owns ALL blocking; the built-in blocking
        # feature stays off (the app works independently of it).
        enableBlocking = "false";
        # Apps are pinned by Nix — never self-update.
        dnsAppsEnableAutomaticUpdate = "false";
        logQueries = "false"; # Log Exporter → router-logd owns query logging
        maxStatFileDays = toString cfg.reporting.retentionDays;
        maxLogFileDays = "30";
      };

      localZone = {
        zone = localZone;
        address = lanGW;
        # Extra A records contributed by other modules via
        # `router._localDnsRecords` (see modules/wireless.nix). Each carries its
        # own zone rather than living under the router's `<host>.<domain>` zone,
        # because the names that matter — `unifi.lan`, `dashboard.<domain>` —
        # are not below it.
        records = cfg._localDnsRecords;
      };

      safeSearch = {
        enable = tcfg.safeSearch;
        records = catalog.safeSearchRecords;
      };

      # Split-horizon zones (router.dns.overrides / forwardZones /
      # registerStaticHosts), fully grouped and typed here so the reconciler
      # only executes the list. Tracked in its OWN managed-state file rather
      # than the SafeSearch one, so reaping the two never interferes.
      localDns = {
        managedFile = "${stateDir}/managed-local-dns.json";
        zones = localDnsSpec;
      };

      apps = {
        # All three targets must be present: the app dereferences
        # FileTarget/HttpTarget/SyslogTarget unconditionally (with a null-
        # forgiving `!`), so an omitted target NREs. file/syslog stay disabled
        # but carry their required fields (path / address).
        "Log Exporter" = {
          maxQueueSize = 1000000;
          enableEdnsLogging = false;
          file = {
            path = "./dns_logs.json";
            enabled = false;
          };
          http = {
            endpoint = "http://127.0.0.1:${toString cfg.reporting.logd.port}/ingest";
            headers.Authorization = "Bearer @INGEST_TOKEN@"; # substituted by reconcile
            enabled = true;
          };
          syslog = {
            address = "127.0.0.1";
            port = 514;
            protocol = "UDP";
            enabled = false;
          };
        };
        "Block Page" = [
          {
            name = "default";
            enableWebServer = cfg.accessPolicies.blockPage.enable;
            webServerLocalAddresses = blockPageAddresses;
            webServerUseSelfSignedTlsCertificate = true;
            webServerTlsCertificateFilePath = null;
            webServerTlsCertificatePassword = null;
            webServerEnableOnlineCertificateSigning = false;
            webServerRootPath = "wwwroot";
            serveBlockPageFromWebServerRoot = true;
            blockPageTitle = cfg.accessPolicies.blockPage.title;
            blockPageHeading = cfg.accessPolicies.blockPage.heading;
            blockPageMessage = cfg.accessPolicies.blockPage.message;
            includeBlockingInfo = true;
          }
        ];
        # Config for pkgs/technitium-apps/RouterLiveDnsApp — present
        # unconditionally, matching this file's convention above (every Log
        # Exporter target must be present even when disabled). The "local"
        # zone/mdns branch is simply never invoked when resolveMdns is off,
        # since no zone/APP record exists there — see localDnsZones below.
        "Router Live DNS" = {
          hostZone = hostZone;
          dynamicHosts = map (h: {
            inherit (h) slug mac;
          }) dynamicHostSlugsUsable;
          neighborRefreshIntervalSeconds = 20;
          ipTool = "${pkgs.iproute2}/bin/ip";
          mdns = {
            interface = brLAN;
            queryTimeoutMs = 1200;
          };
        };
      };

      policy = {
        staticInputs = config.router._policyStaticInputs;
        directoryState = "/var/lib/router-directory/directory.json";
      };

      cockpit = {
        user = "cockpit";
        passFile = "${stateDir}/cockpit.pass";
        tokenName = "cockpit-router";
        tokenFile = "/var/lib/cockpit-router/technitium-token";
      };

      logd = {
        # .duckdb, not the Turso-era .db. DuckDB opens a SQLite file happily
        # (it auto-attaches it) but then runs with SQLite storage semantics,
        # where CREATE SEQUENCE is rejected outright — so an upgraded router
        # would fail schema setup while a fresh one succeeded. A distinct path
        # keeps one storage mode and one schema everywhere; the old file is left
        # alone and ages out with its 90-day retention.
        dbPath = "/var/lib/router-logd/querylogs.duckdb";
        listenAddress = "0.0.0.0";
        port = cfg.reporting.logd.port;
        ingestTokenFile = "${stateDir}/logd-ingest.token";
        queryTokenFile = "${stateDir}/logd-query.token";
        staticInputs = config.router._policyStaticInputs;
        directoryState = "/var/lib/router-directory/directory.json";
        retentionDays = cfg.reporting.retentionDays;
        portalRateLimitPerHour = 10;
      };

      directory = {
        inherit (cfg.directory) provider;
        # Extra group names to publish even when unreferenced, so Cockpit's
        # directory-group picker has something to offer (SSSD is not enumerated).
        groups = cfg.directory.sssd.groups;
        # The sync resolves ONLY the identities these inputs name:
        # hosts[].user and policies[].assignments.directoryGroups.
        staticInputs = config.router._policyStaticInputs;
        stateDir = "/var/lib/router-directory";
      };

      reporting = {
        inherit (cfg.reporting) schedules email;
        reportsDir = "/var/lib/router-reports";
      };
    }
  );

  # ── Split-horizon DNS: zone model ────────────────────────
  # Technitium answers a name locally only if an authoritative zone covers
  # it, and a Primary zone blackholes everything else under it (which is
  # exactly why the SafeSearch hijack uses one zone per name). So every zone
  # this feature creates is a FORWARDER zone carrying an apex FWD record
  # that mirrors the global upstreams: a declared name is answered locally,
  # anything else in the zone falls through to the real upstream. That is
  # what makes an override at a registrable apex ("example.com" itself)
  # safe without special-casing it.
  #
  # Zone assignment is computed here, once, so the reconciler only executes
  # a list. It never has to re-derive which zone a record belongs to.
  dcfg = cfg.dns;

  dnsLabelChars = lowerChars ++ stringToCharacters "0123456789";

  # Device names allow spaces, dots and underscores (modules/hosts.nix), so
  # they are not DNS labels. Lowercase, map everything else to "-", then
  # collapse and trim the runs.
  slugOf =
    name:
    concatStringsSep "-" (
      filter (s: s != "") (
        splitString "-" (stringAsChars (c: if elem c dnsLabelChars then c else "-") (toLower name))
      )
    );

  hostZone = toLower cfg.lan.domain;
  registerHosts = dcfg.registerStaticHosts;

  staticHostSlugs = map (h: {
    inherit (h) name staticIp;
    slug = slugOf h.name;
  }) (filter (h: h.staticIp != null) cfg.hosts);

  # Adopted hosts with no static IP get no explicit record (hostRecords,
  # below) — instead the "Router Live DNS" app (pkgs/technitium-apps) resolves
  # them live from the ARP/NDP neighbor table, keyed by MAC. Slugified the
  # same way as static hosts so the two sets share one collision check.
  dynamicHostSlugs = map (h: {
    inherit (h) name mac;
    slug = slugOf h.name;
  }) (filter (h: h.staticIp == null) cfg.hosts);

  slugDupes = attrNames (
    filterAttrs (_: c: c > 1) (
      foldl' (acc: e: acc // { ${e.slug} = (acc.${e.slug} or 0) + 1; }) { } (
        staticHostSlugs ++ dynamicHostSlugs
      )
    )
  );

  # A slug that lost a race with an explicit override for the same name, or
  # with the router's own <hostName>.<domain> zone, is dropped too — the
  # hand-written entry is the one the admin meant.
  overrideNames = map (o: toLower o.name) dcfg.overrides;
  hostRecordsUsable = filter (
    e:
    e.slug != ""
    && !(elem e.slug slugDupes)
    && !(elem "${e.slug}.${hostZone}" overrideNames)
    && "${e.slug}.${hostZone}" != toLower localZone
  ) staticHostSlugs;

  dynamicHostSlugsUsable = filter (
    e:
    e.slug != ""
    && !(elem e.slug slugDupes)
    && !(elem "${e.slug}.${hostZone}" overrideNames)
    && "${e.slug}.${hostZone}" != toLower localZone
  ) dynamicHostSlugs;

  hostRecords = optionals registerHosts (
    map (e: {
      name = "${e.slug}.${hostZone}";
      type = "A";
      value = e.staticIp;
      ttl = 300;
      ptr = true;
    }) hostRecordsUsable
  );

  overrideRecords = map (o: {
    name = toLower o.name;
    inherit (o) type value ttl;
    ptr = false;
  }) dcfg.overrides;

  localDnsRecords = overrideRecords ++ hostRecords;

  # FWD record set mirroring the global upstreams — the "fall through to the
  # public horizon" half of every zone this feature creates.
  upstreamFwd = map (u: {
    protocol = "Https";
    forwarder = u;
    dnssecValidation = true;
  }) tcfg.upstreamServers;

  forwardZoneNames = map (z: toLower z.zone) dcfg.forwardZones;

  # Roots an admin declared explicitly. A record lands in the LONGEST of
  # these that is a suffix of its name; with no match it becomes its own
  # zone. `localZone` is deliberately absent: it stays the Primary zone it
  # already is, and a more specific zone always wins in Technitium anyway.
  #
  # hostZone is unconditional (not gated by registerHosts): "adopted hosts
  # should always resolve" — a dynamic (no staticIp) router.hosts entry only
  # ever gets a name via the Router Live DNS app's live lookup, so the zone
  # carrying its apex APP record must exist regardless of registerHosts,
  # which continues to gate only the explicit static hostRecords/PTR below.
  declaredRoots = forwardZoneNames ++ [ hostZone ];

  isUnderZone = name: root: name == root || hasSuffix ".${root}" name;
  rootFor =
    name:
    let
      matches = filter (isUnderZone name) declaredRoots;
      longest = foldl' (a: b: if stringLength b > stringLength a then b else a) "" matches;
    in
    if longest == "" then name else longest;

  implicitRoots = subtractLists declaredRoots (unique (map (r: rootFor r.name) localDnsRecords));

  # Zone-apex APP record dispatching to the "Router Live DNS" app
  # (pkgs/technitium-apps/RouterLiveDnsApp): resolves adopted router.hosts
  # entries without a static IP (hostZone, always) or live mDNS *.local names
  # (the "local" zone, only when resolveMdns is on). classPath must equal the
  # app's C# Type.FullName exactly; appName must equal its installed app name.
  routerLiveDnsAppRecord = zoneName: {
    name = zoneName;
    appName = "Router Live DNS";
    classPath = "RouterLiveDns.App";
    data = "";
    ttl = 60;
  };

  localDnsZones = sort (a: b: a.zone < b.zone) (
    map (z: {
      zone = toLower z.zone;
      type = "Forwarder";
      forwarders = map (f: {
        inherit (z) protocol dnssecValidation;
        forwarder = f;
      }) z.forwarders;
      appRecords = [ ];
    }) dcfg.forwardZones
    ++ [
      {
        zone = hostZone;
        type = "Forwarder";
        forwarders = upstreamFwd;
        appRecords = [ (routerLiveDnsAppRecord hostZone) ];
      }
    ]
    ++ optional tcfg.resolveMdns {
      # Primary, not Forwarder: there is no legitimate public upstream for
      # `.local`, so an unresolved name should NXDOMAIN/NODATA rather than
      # attempt a pointless upstream forward. Its mere existence — any
      # enabled apex zone, Primary or Forwarder — is what defeats
      # Technitium's SpecialZoneManager RFC 6762 blackhole for `local`
      # (see the special-use-domain warning below).
      zone = "local";
      type = "Primary";
      forwarders = [ ];
      appRecords = [ (routerLiveDnsAppRecord "local") ];
    }
    ++ map (r: {
      zone = r;
      type = "Forwarder";
      forwarders = upstreamFwd;
      appRecords = [ ];
    }) implicitRoots
  );

  localDnsSpec = map (
    z: z // { records = filter (r: rootFor r.name == z.zone) localDnsRecords; }
  ) localDnsZones;

  # ── Validation inputs ────────────────────────────────────
  dupsOfList =
    xs:
    attrNames (
      filterAttrs (_: c: c > 1) (foldl' (acc: x: acc // { ${x} = (acc.${x} or 0) + 1; }) { } xs)
    );

  # Underscore is not a hostname character, but it is how SRV and TXT service
  # names are spelled (_sip._udp.example.com), so it belongs here.
  fqdnChars = dnsLabelChars ++ [
    "-"
    "."
    "_"
  ];
  isFqdn =
    name:
    name != ""
    && !(hasPrefix "." name)
    && !(hasSuffix "." name)
    && all (c: elem c fqdnChars) (stringToCharacters (toLower name));

  overrideDupes = dupsOfList (map (o: "${toLower o.name} ${o.type} ${o.value}") dcfg.overrides);
  badOverrideNames = map (o: o.name) (filter (o: !(isFqdn o.name)) dcfg.overrides);
  forwardZoneDupes = dupsOfList forwardZoneNames;
  emptyForwardZones = map (z: z.zone) (filter (z: z.forwarders == [ ]) dcfg.forwardZones);

  shadowedOverrides = map (o: o.name) (
    filter (o: any (z: isUnderZone (toLower o.name) z) forwardZoneNames) dcfg.overrides
  );

  # "example.com" — a name whose zone is created at a registrable apex, as
  # opposed to "nas.example.com". Two labels is the cheap approximation; it
  # only drives a warning, so a public-suffix list would be overkill.
  apexOverrides = unique (
    map (o: o.name) (
      filter (
        o: rootFor (toLower o.name) == toLower o.name && length (splitString "." o.name) == 2
      ) dcfg.overrides
    )
  );

  # Runtime secrets, generated once. Runs as its own oneshot BEFORE any unit
  # that references these files via LoadCredential — systemd resolves
  # credentials before ExecStartPre, so generating them in a pre-start of the
  # consuming unit would fail on first boot.
  secretsScript = pkgs.writeShellScript "router-dns-secrets" ''
    set -euo pipefail
    umask 077
    mkdir -p ${stateDir}
    for f in admin.pass logd-ingest.token logd-query.token; do
      if [ ! -s ${stateDir}/$f ]; then
        ${pkgs.openssl}/bin/openssl rand -base64 24 > ${stateDir}/$f
      fi
    done
  '';

  # Root pre-start: app payload seeding. Version markers keep the copy
  # idempotent; existing dnsApp.config files are preserved (the API push
  # owns them).
  seedScript = pkgs.writeShellScript "technitium-seed" ''
    set -euo pipefail
    apps_src=${routerDnsTools.passthru.technitiumApps}
    apps_dst=${technitiumStateDir}/apps
    mkdir -p "$apps_dst"
    for app in "$apps_src"/*; do
      name=$(basename "$app")
      marker="$apps_dst/$name/.nix-store-path"
      if [ ! -f "$marker" ] || [ "$(cat "$marker")" != "$app" ]; then
        mkdir -p "$apps_dst/$name"
        find "$apps_dst/$name" -mindepth 1 -not -name dnsApp.config -delete
        cp -rT --no-preserve=mode,ownership "$app" "$apps_dst/$name" 2>/dev/null || \
          cp -r --no-preserve=mode,ownership "$app"/. "$apps_dst/$name"/
        echo "$app" > "$marker"
      fi
    done

    # Branded block page site (regenerated every start — cheap and idempotent)
    mkdir -p "$apps_dst/Block Page/wwwroot"
    cp --no-preserve=mode,ownership ${blockPageWwwroot}/index.html "$apps_dst/Block Page/wwwroot/index.html"

    # systemd created/owns StateDirectory as the DynamicUser before this
    # ExecStartPre; give the root-copied app payloads the same owner so the
    # apps can write their working data (blocklists, certs, sqlite).
    chmod -R u+rwX ${technitiumStateDir}/apps
    chown -R --reference=${technitiumStateDir} ${technitiumStateDir}/apps
  '';
in
{
  # `router.dns.upstreamServers` predates this branch — it fed AdGuard Home's
  # `upstream_dns` — so it is sitting in every existing settings JSON. Renaming
  # rather than deleting keeps those configs evaluating, with a warning naming
  # the new path, instead of failing the rebuild on an unknown option.
  imports = [
    (mkRenamedOptionModule
      [ "router" "dns" "upstreamServers" ]
      [ "router" "dns" "technitium" "upstreamServers" ]
    )
  ];

  options.router._dnsToolsConfig = mkOption {
    type = types.path;
    internal = true;
    readOnly = true;
    description = "Generated router-dns-tools runtime config consumed by the service units.";
  };
  # The split-horizon zone set, exposed so tests can assert the grouping
  # without importing the generated JSON from a derivation.
  options.router._localDnsZones = mkOption {
    type = types.listOf types.attrs;
    internal = true;
    readOnly = true;
    description = "Generated split-horizon zone/record spec (also embedded in the runtime config).";
  };
  options.router._dnsToolsPackage = mkOption {
    type = types.package;
    internal = true;
    readOnly = true;
    description = "The router-dns-tools package instance shared by sibling modules.";
  };

  options.router.dns = {
    # Kept for settings-JSON compatibility: Technitium resolves forwarder
    # hostnames internally, so bootstrap servers are a documented no-op.
    bootstrapServers = mkOption {
      type = types.listOf types.str;
      default = [
        "1.1.1.1"
        "8.8.8.8"
      ];
      visible = false;
      description = "Unused with Technitium (kept for config compatibility).";
    };

    # ── Split-horizon DNS ──────────────────────────────────
    # Names the router answers itself for internal clients, leaving the
    # public horizon alone. Every zone this creates is a Technitium
    # Forwarder zone carrying an apex FWD record that mirrors
    # `dns.technitium.upstreamServers`, so a name inside an overridden
    # domain that is NOT declared here still resolves from the real
    # upstream instead of becoming NXDOMAIN.
    overrides = mkOption {
      default = [ ];
      description = "Split-horizon DNS records the router answers for internal clients.";
      example = literalExpression ''
        [
          {
            name = "nas.example.com";
            value = "10.48.4.20";
          }
          {
            name = "vault.example.com";
            type = "ANAME";
            value = "nas.example.com";
          }
        ]
      '';
      type = types.listOf (
        types.submodule {
          options = {
            name = mkOption {
              type = types.str;
              description = "Fully-qualified name this record answers for (no trailing dot).";
            };
            type = mkOption {
              type = types.enum [
                "A"
                "AAAA"
                "CNAME"
                "ANAME"
                "TXT"
                "SRV"
              ];
              default = "A";
              description = ''
                Record type. A CNAME is illegal at a zone apex, so an alias
                that owns its zone must use ANAME (Technitium resolves it and
                answers with the target's addresses).
              '';
            };
            value = mkOption {
              type = types.str;
              description = ''
                Record data: an IP address for A/AAAA, a target name for
                CNAME/ANAME, the text for TXT, or "priority weight port target"
                for SRV.
              '';
            };
            ttl = mkOption {
              type = types.ints.between 1 604800;
              default = 300;
              description = "Record TTL in seconds.";
            };
            notes = mkOption {
              type = types.str;
              default = "";
              description = "Free-form administrator notes.";
            };
          };
        }
      );
    };

    forwardZones = mkOption {
      default = [ ];
      description = "Domains resolved by an internal DNS server instead of the upstream forwarders.";
      example = literalExpression ''
        [
          {
            zone = "corp.example.com";
            forwarders = [ "10.48.4.5" ];
          }
        ]
      '';
      type = types.listOf (
        types.submodule {
          options = {
            zone = mkOption {
              type = types.str;
              description = "Domain to forward (no trailing dot). Applies to the whole subtree.";
            };
            forwarders = mkOption {
              type = types.listOf types.str;
              description = ''
                DNS servers to forward this zone to, as an address, "address:port"
                or a DoH/DoT URL. Queried in the order given.
              '';
            };
            protocol = mkOption {
              type = types.enum [
                "Udp"
                "Tcp"
                "Tls"
                "Https"
                "Quic"
              ];
              default = "Udp";
              description = "Transport used to reach the forwarders.";
            };
            dnssecValidation = mkOption {
              type = types.bool;
              default = false;
              description = "Validate DNSSEC on answers from these forwarders.";
            };
            notes = mkOption {
              type = types.str;
              default = "";
              description = "Free-form administrator notes.";
            };
          };
        }
      );
    };

    registerStaticHosts = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Publish every router.hosts entry that has a staticIp as
        <name>.<lan.domain> (plus a reverse PTR). The device name is
        slugified into a DNS label; names that collide after slugification
        are skipped with a warning.
      '';
    };

    technitium = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Enable Technitium DNS Server (the router's filtering resolver).";
      };

      # Scoped under technitium, not dns, because only Technitium can use these:
      # they are DoH URLs, and the systemd-resolved fallback that answers LAN :53
      # when `enable = false` speaks DoT. Leaving them at dns.* implied they
      # governed the router's DNS generally, which they never did.
      upstreamServers = mkOption {
        type = types.listOf types.str;
        default = [
          "https://dns.cloudflare.com/dns-query"
          "https://dns.google/dns-query"
        ];
        description = "Upstream DNS-over-HTTPS forwarders for Technitium.";
      };
      package = mkOption {
        type = types.package;
        default = pkgs.technitium-dns-server;
        defaultText = literalExpression "pkgs.technitium-dns-server";
        description = "Technitium DNS Server package.";
      };
      listenPort = mkOption {
        type = types.port;
        default = 53;
        description = "DNS listen port.";
      };
      webPort = mkOption {
        type = types.port;
        default = 5380;
        description = "Web console / HTTP API port (bound to localhost).";
      };
      safeSearch = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Enforce SafeSearch (Google, Bing, DuckDuckGo, YouTube) globally via
          provisioned ANAME records. Technitium has no built-in SafeSearch.
        '';
      };
      blockDoHProviders = mkOption {
        type = types.bool;
        default = true;
        description = "Block public DoH resolver domains in every policy (bypass prevention).";
      };
      resolveMdns = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Resolve arbitrary `.local` mDNS (Avahi/Bonjour) hostnames via a live
          multicast DNS probe, in addition to the router's always-on live
          resolution of adopted (router.hosts) devices under router.lan.domain.
        '';
      };
    };
  };

  config = mkMerge [
    { router._localDnsZones = localDnsSpec; }

    # ── Split-horizon DNS validation ───────────────────────
    # Unconditional: these inputs are wrong whether or not Technitium is the
    # active resolver, and a settings file that cannot be fixed until the
    # engine is re-enabled is a worse failure than a loud one now.
    {
      assertions = [
        {
          assertion = overrideDupes == [ ];
          message = "router.dns.overrides: duplicate record(s): ${concatStringsSep ", " overrideDupes}";
        }
        {
          assertion = badOverrideNames == [ ];
          message = "router.dns.overrides: not a fully-qualified name (letters, digits, '-' and '.'; no trailing dot): ${concatStringsSep ", " badOverrideNames}";
        }
        {
          assertion = forwardZoneDupes == [ ];
          message = "router.dns.forwardZones: duplicate zone(s): ${concatStringsSep ", " forwardZoneDupes}";
        }
        {
          assertion = emptyForwardZones == [ ];
          message = "router.dns.forwardZones: no forwarders given for zone(s): ${concatStringsSep ", " emptyForwardZones}";
        }
        {
          # A forward zone hands the WHOLE subtree to another server, so a
          # local override for a name inside it would never be consulted.
          assertion = shadowedOverrides == [ ];
          message = "router.dns.overrides: ${concatStringsSep ", " shadowedOverrides} sits inside a router.dns.forwardZones zone, which forwards the entire subtree — remove the override or narrow the forward zone.";
        }
        {
          # hostZone is always a zone now (adopted hosts resolve live
          # regardless of registerStaticHosts), so this conflict is checked
          # unconditionally rather than only when registerHosts is set.
          assertion = !(elem hostZone forwardZoneNames);
          message = "router.dns.forwardZones: '${hostZone}' is the LAN domain — router.hosts entries (static via registerStaticHosts, dynamic via the Router Live DNS app) publish records into it, so forwarding the whole zone elsewhere would shadow them. Forward a narrower zone instead.";
        }
        {
          assertion = !(tcfg.resolveMdns && (hostZone == "local"));
          message = "router.dns.technitium.resolveMdns and router.lan.domain = \"local\" both want to own the `local` zone apex with incompatible zone types — pick a different router.lan.domain.";
        }
      ];

      warnings =
        optional (slugDupes != [ ]) ''
          router.hosts: these device names slugify to the same DNS label, so
          NONE of them is published: ${concatStringsSep ", " slugDupes}.
          Rename the devices in router.hosts, or add explicit router.dns.overrides.
        ''
        ++ optional (apexOverrides != [ ]) ''
          router.dns.overrides: ${concatStringsSep ", " apexOverrides} override a whole
          domain apex. The router serves it as a conditional-forwarder zone, so other
          names under it still resolve upstream — but every internal client now takes
          this answer for the apex itself.
        '';
    }

    (mkIf tcfg.enable {
      # Technitium 15.4.0 added SpecialZoneManager: with the (default-on)
      # `locallyServedDnsZones` setting it answers the RFC 6761/6762/7686
      # special-use names authoritatively — and it does so inside
      # AuthoritativeQueryAsync, i.e. BEFORE the Advanced Blocking app is
      # consulted. The router's own zone still resolves (an existing apex zone
      # suppresses the special answer), but every OTHER name under such a domain
      # becomes NXDOMAIN and no access policy can touch it.
      warnings =
        optional
          (elem cfg.lan.domain [
            "test"
            "invalid"
            "local"
            "onion"
          ])
          ''
            router.lan.domain = "${cfg.lan.domain}" is a special-use domain. From
            Technitium 15.4.0 the DNS server answers names under it authoritatively
            (NXDOMAIN) before access policies apply, so only ${localZone} itself will
            resolve on the LAN. Pick an ordinary domain such as "lan" or a delegated
            one you own.
          '';

      # ── Base service + first-boot seeding ─────────────────
      services.technitium-dns-server = {
        enable = true;
        package = tcfg.package;
        # Firewall is the router's own nftables ruleset (modules/firewall.nix);
        # the nixpkgs option drives networking.firewall, which is unused here.
        openFirewall = false;
      };

      systemd.services.router-dns-secrets = {
        description = "Generate router DNS runtime secrets";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = secretsScript;
        };
      };

      systemd.services.technitium-dns-server = {
        after = [ "router-dns-secrets.service" ];
        requires = [ "router-dns-secrets.service" ];
        environment = {
          DNS_SERVER_DOMAIN = localZone;
          DNS_SERVER_ADMIN_PASSWORD_FILE = "%d/admin-password";
          DNS_SERVER_WEB_SERVICE_HTTP_PORT = toString tcfg.webPort;
          DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES = "127.0.0.1";
          DNS_SERVER_FORWARDERS = concatStringsSep "," tcfg.upstreamServers;
          DNS_SERVER_FORWARDER_PROTOCOL = "Https";
          DNS_SERVER_RECURSION = "AllowOnlyForPrivateNetworks";
          DNS_SERVER_ENABLE_BLOCKING = "false";
          DOTNET_EnableDiagnostics = "0";
        };
        serviceConfig = {
          LoadCredential = [ "admin-password:${stateDir}/admin.pass" ];
          # "+" = run as root despite DynamicUser (writes secrets + app payloads).
          ExecStartPre = [ "+${seedScript}" ];
          # Run "portable" so the log folder lives under the writable StateDirectory
          # (<state>/logs) instead of the Unix default /var/log/technitium/dns,
          # which ProtectSystem=strict makes read-only. Config and apps already use
          # the explicit config-folder arg, so this only affects log placement.
          ExecStart = mkForce "${tcfg.package}/bin/technitium-dns-server %S/technitium-dns-server --portable-app";
        };
        restartTriggers = [
          routerDnsTools.passthru.technitiumApps
          blockPageWwwroot
        ];
      };

      # ── Reconcile (idempotent, config-change driven) ──────
      systemd.services.technitium-reconcile = {
        description = "Reconcile Technitium DNS Server configuration";
        after = [
          "technitium-dns-server.service"
          "network-online.target"
        ];
        wants = [
          "technitium-dns-server.service"
          "network-online.target"
        ];
        wantedBy = [ "multi-user.target" ];
        restartTriggers = [
          dnsToolsConfig
          config.router._policyStaticInputs
        ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${routerDnsTools}/bin/router-technitium-reconcile --config ${dnsToolsConfig}";
          Restart = "on-failure";
          RestartSec = 15;
        };
        unitConfig.StartLimitIntervalSec = 300;
        unitConfig.StartLimitBurst = 4;
      };

      # ── Policy re-push on directory changes ───────────────
      systemd.services.router-policy-push = {
        description = "Compile and push Advanced Blocking policy config";
        after = [ "technitium-reconcile.service" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${routerDnsTools}/bin/router-policy-push --config ${dnsToolsConfig}";
        };
      };
      systemd.paths.router-policy-push = {
        description = "Re-push policies when directory state changes";
        wantedBy = [ "multi-user.target" ];
        pathConfig.PathChanged = "/var/lib/router-directory/directory.json";
      };

      # ── DNS plumbing shared with the old module ───────────
      networking.nameservers = [
        "127.0.0.1"
        "::1"
      ];
      services.resolved.enable = false;

      # Publish the router's hostname via mDNS (hostname.local).
      services.avahi = {
        enable = true;
        publish = {
          enable = true;
          addresses = true;
          workstation = true;
        };
      };

      # Expose the runtime config path to sibling modules (reporting units).
      router._dnsToolsConfig = dnsToolsConfig;
      router._dnsToolsPackage = routerDnsTools;
    })

    # ── Fallback resolver when filtering is disabled ───────
    # `enable = false` has to mean "no DNS FILTERING", not "no DNS". Neither of
    # the two things that point clients at this box is gated on this option:
    # network.nix advertises the gateway as the LAN resolver (EmitDNS) and
    # firewall.nix DNATs every :53 query to it. With nothing bound there, the
    # LAN is told to use an address it is then forcibly redirected to, where
    # nothing answers — DNS does not degrade, it stops.
    #
    # systemd-resolved fills the role: its stub listener normally binds only
    # 127.0.0.53, so DNSStubListenerExtra puts it on the gateway addresses where
    # the redirected queries actually arrive. It forwards to whatever the WAN
    # link learned over DHCP — it cannot honour the DoH upstreamServers, which
    # DoH URLs, and resolved speaks DoT rather than DoH.
    (mkIf (!tcfg.enable) {
      services.resolved = {
        enable = true;
        settings.Resolve.DNSStubListenerExtra = [ lanGW ] ++ optional cfg.guest.enable guestGW;
      };

      warnings = [
        ''
          router.dns.technitium.enable is false: LAN DNS is being answered by
          systemd-resolved with NO content filtering. Access policies, SafeSearch
          and DoH-provider blocking are all inactive, and queries are forwarded
          in plaintext to the WAN-provided resolvers rather than over DoH.
        ''
      ];
    })
  ];
}
