# ── Technitium DNS engine module ───────────────────────────────────────────────
# Provisions Technitium DNS Server as the router's filtering resolver.
#
# Technitium's main config (dns.config) is binary and cannot be generated
# declaratively, so provisioning happens in three phases:
#   1. FIRST BOOT: DNS_SERVER_* environment variables seed the config — they
#      are read only when dns.config is absent (verified in DnsServer.cs).
#   2. APP PRE-SEEDING: a root ExecStartPre copies the from-source DNS app
#      payloads (Advanced Blocking, Log Exporter, Block Page — compiled by
#      pkg/technitium-apps, re-exposed via pkg/router-dns-tools passthru) into
#      the state dir before the daemon starts, so filtering is enforced from
#      the first second. The Block Page
#      app also receives the Nix-generated branded wwwroot.
#   3. RECONCILE: technitium-reconcile.service (oneshot, re-run by every
#      nixos-rebuild whose generated desired state changed) asserts settings,
#      the local zone, SafeSearch ANAME zones, app configs (including the
#      compiled Advanced Blocking policy config), and the read-only Cockpit
#      API token via the HTTP API.
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
    ;

  catalog = import ./filter-catalog.nix;

  # Apply the router overlay locally (it closes over the turso + technitium-dns
  # flake inputs) rather than via nixpkgs.overlays, which conflicts when a
  # consumer supplies nixpkgs.pkgs. router-dns-tools bundles pyturso and the
  # from-source Technitium apps.
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
        forwarders = concatStringsSep "," cfg.dns.upstreamServers;
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
      };

      safeSearch = {
        enable = tcfg.safeSearch;
        records = catalog.safeSearchRecords;
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
        dbPath = "/var/lib/router-logd/querylogs.db";
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
  options.router._dnsToolsConfig = mkOption {
    type = types.path;
    internal = true;
    readOnly = true;
    description = "Generated router-dns-tools runtime config consumed by the service units.";
  };
  options.router._dnsToolsPackage = mkOption {
    type = types.package;
    internal = true;
    readOnly = true;
    description = "The router-dns-tools package instance shared by sibling modules.";
  };

  options.router.dns = {
    upstreamServers = mkOption {
      type = types.listOf types.str;
      default = [
        "https://dns.cloudflare.com/dns-query"
        "https://dns.google/dns-query"
      ];
      description = "Upstream DNS-over-HTTPS forwarders.";
    };

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

    technitium = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Enable Technitium DNS Server (the router's filtering resolver).";
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
    };
  };

  config = mkMerge [
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
          DNS_SERVER_FORWARDERS = concatStringsSep "," cfg.dns.upstreamServers;
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
    # link learned over DHCP — it cannot honour dns.upstreamServers, which are
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
