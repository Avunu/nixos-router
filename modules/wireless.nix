# ── Wireless controller substrate ─────────────────────────────────────────────
# Shared foundation for the two wireless network controllers this router can
# host (see modules/wireless-unifi.nix and modules/wireless-openwisp.nix):
# the `router.wireless.*` option tree, podman itself, the container networks,
# the runtime secrets, and the derived values the firewall and DNS modules need.
#
# This is the repository's ONLY container infrastructure, so a few decisions are
# made here once and relied on by both controllers:
#
#   • Networks are declared as /etc/containers/networks/*.json rather than
#     created by a `podman network create` oneshot. Netavark reads that
#     directory directly, and nixpkgs' own podman module already uses the same
#     mechanism for the default network — so the networks are pure config with
#     no imperative setup step and no ordering problem.
#
#   • `dns_enabled = false` on every network, which is NOT the usual default.
#     aardvark-dns binds <gateway>:53, and Technitium already binds 0.0.0.0:53
#     (modules/dns-technitium.nix) — enabling it would leave aardvark unable to
#     start. Containers therefore get static IPs plus `--add-host` entries, which
#     is also more declarative than name resolution would have been.
#
#   • Images float, the datastore does not. App containers carry the
#     io.containers.autoupdate label and are refreshed by podman's own timer;
#     `pull = "missing"` everywhere means a normal start never touches a
#     registry, so a boot with the WAN still down is not a failure. See the
#     `database.image` option in wireless-unifi.nix for why that one is pinned.
{
  config,
  lib,
  pkgs,
  ...
}:
with lib;
let
  cfg = config.router;
  wcfg = cfg.wireless;

  stateDir = "/var/lib/router-wireless";

  # Container networks are /24s so that a host address can be derived from the
  # gateway by replacing the last octet (hostIn below). Asserted, not assumed.
  prefixOf = addr: concatStringsSep "." (take 3 (splitString "." addr));
  hostIn = gateway: n: "${prefixOf gateway}.${toString n}";

  # Netavark keys networks by a 64-hex-character id. Deriving it from the name
  # keeps it stable across rebuilds without a magic constant to copy around.
  networkId = name: builtins.hashString "sha256" "nixos-router-wireless-${name}";

  mkNetwork =
    {
      name,
      interface,
      subnet,
      gateway,
    }:
    {
      inherit name subnet gateway;
      file = (pkgs.formats.json { }).generate "podman-network-${name}.json" {
        inherit name;
        driver = "bridge";
        id = networkId name;
        network_interface = interface;
        # MUST stay false — see the header. Containers use --add-host instead.
        dns_enabled = false;
        internal = false;
        ipv6_enabled = false;
        ipam_options.driver = "host-local";
        subnets = [ { inherit subnet gateway; } ];
      };
    };

  owNet = mkNetwork {
    name = "openwisp";
    interface = wcfg.openwisp.network.interface;
    subnet = wcfg.openwisp.network.subnet;
    gateway = wcfg.openwisp.network.gateway;
  };

  unifiNet = mkNetwork {
    name = "unifi";
    interface = wcfg.unifi.network.interface;
    subnet = wcfg.unifi.network.subnet;
    gateway = wcfg.unifi.network.gateway;
  };

  anyEnabled = wcfg.unifi.enable || wcfg.openwisp.enable;

  # Runtime secrets, generated once and never entering the Nix store. Mirrors
  # router-dns-secrets.service (modules/dns-technitium.nix): its own oneshot
  # rather than an ExecStartPre, because the consuming units reference these
  # paths via environmentFiles, which systemd resolves before ExecStartPre runs.
  secretsScript = pkgs.writeShellScript "router-wireless-secrets" ''
    set -euo pipefail
    umask 077
    mkdir -p ${stateDir}

    gen() {
      if [ ! -s "${stateDir}/$1" ]; then
        ${pkgs.openssl}/bin/openssl rand -hex 24 > "${stateDir}/$1"
      fi
    }

    # Hex rather than base64: these end up inside a mongodb:// URI and a
    # PostgreSQL password, where base64's +/= would need URL-escaping.
    ${optionalString wcfg.unifi.enable ''
      gen mongo-root.pass
      gen mongo-unifi.pass
      {
        echo "MONGO_INITDB_ROOT_USERNAME=root"
        echo "MONGO_INITDB_ROOT_PASSWORD=$(cat ${stateDir}/mongo-root.pass)"
        echo "UNIFI_DB_PASSWORD=$(cat ${stateDir}/mongo-unifi.pass)"
      } > ${stateDir}/mongo.env
      chmod 0600 ${stateDir}/mongo.env
    ''}

    ${optionalString wcfg.openwisp.enable ''
      gen django-secret.key
      gen openwisp-db.pass
      gen redis.pass
      # Redis is world-readable to anything that can reach the bridge, and its
      # own protected mode refuses to serve commands over a non-loopback
      # address without a password — so this is required, not just prudent.
      {
        echo "DJANGO_SECRET_KEY=$(cat ${stateDir}/django-secret.key)"
        echo "DB_PASS=$(cat ${stateDir}/openwisp-db.pass)"
        echo "REDIS_PASS=$(cat ${stateDir}/redis.pass)"
      } > ${stateDir}/openwisp.env
      chmod 0600 ${stateDir}/openwisp.env
    ''}
  '';

  enabledNetworks =
    optional wcfg.openwisp.enable wcfg.openwisp.network
    ++ optional wcfg.unifi.enable wcfg.unifi.network;

  # networkd creates the bridges (see the systemd.network block below), but
  # address assignment is asynchronous, so a service that binds the gateway
  # address can still lose the race at boot. Ordering after this makes that
  # deterministic instead of a restart loop.
  bridgeWaitScript = pkgs.writeShellScript "router-wireless-bridges" ''
    set -uo pipefail
    for _ in $(seq 1 120); do
      missing=
      for addr in ${concatMapStringsSep " " (n: n.gateway) enabledNetworks}; do
        ${pkgs.iproute2}/bin/ip -4 addr show to "$addr/32" | grep -q . || missing=1
      done
      [ -z "$missing" ] && exit 0
      sleep 0.5
    done
    echo "container bridge addresses never appeared" >&2
    exit 1
  '';

  mkNetworkOptions =
    {
      interface,
      subnet,
      gateway,
    }:
    {
      interface = mkOption {
        type = types.str;
        default = interface;
        description = ''
          Host-side bridge interface name for this container network. Pinned
          rather than left to podman's sequential naming, because the nftables
          ruleset in modules/firewall.nix refers to it by name and because the
          bridge is created ahead of podman by systemd-networkd (see below).

          Keep the `br-` prefix: the Cockpit UI filters interfaces by it when
          offering NICs to assign, and a container bridge is not assignable.
        '';
      };
      subnet = mkOption {
        type = types.str;
        default = subnet;
        description = ''
          CIDR for the container network. Must be a /24 and must not overlap the
          LAN or guest subnets. Change it if your LAN collides.
        '';
      };
      gateway = mkOption {
        type = types.str;
        default = gateway;
        description = ''
          Host address on the container bridge. Native services (PostgreSQL,
          Redis) bind here so containers can reach them, and it is the address
          containers use for host-provided services.
        '';
      };
    };
in
{
  # ══════════════════════════════════════════════════════════
  #  OPTIONS
  # ══════════════════════════════════════════════════════════
  options.router = {
    wireless = {
      # ── UniFi Network Application ───────────────────────
      unifi = {
        enable = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Run Ubiquiti's UniFi Network Application on this router, in a
            container on the host network, backed by a MongoDB container that is
            reachable only from the host.

            The controller needs roughly 1.5 GB of RSS at the default heap plus
            the database on top, so budget at least 2 GB of RAM for the pair
            beyond whatever Suricata, Technitium and OpenWISP already use.
          '';
        };

        image = mkOption {
          type = types.str;
          default = "lscr.io/linuxserver/unifi-network-application:latest";
          description = ''
            Controller image. Floats on a moving tag and is refreshed by
            `router.wireless.autoUpdate`; pin a specific tag here to freeze it.
          '';
        };

        memoryLimit = mkOption {
          type = types.ints.positive;
          default = 1024;
          description = "JVM maximum heap (-Xmx) in MB.";
        };

        memoryStartup = mkOption {
          type = types.ints.positive;
          default = 1024;
          description = "JVM initial heap (-Xms) in MB.";
        };

        dhcpOption43 = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Advertise this router as the UniFi controller in DHCP option 43 on
            the LAN, so factory-default APs adopt without being told where to
            look. Emitted by systemd-networkd's DHCP server as vendor suboption
            1 (a 4-byte IPv4 address), i.e. option 43 = `01 04 <lan address>`.
          '';
        };

        dnsName = mkOption {
          type = types.nullOr types.str;
          default = "unifi";
          description = ''
            Hostname to publish in the local DNS zone pointing at the
            controller, as a secondary adoption path — a factory-default device
            informs to `http://unifi:8080/inform`. Note this only helps clients
            that append the local search domain, which the DHCP server does not
            currently advertise; DHCP option 43 is the primary mechanism. Set to
            null to publish no record.
          '';
        };

        guestPortal = mkOption {
          type = types.bool;
          default = false;
          description = "Expose the guest hotspot portal ports (8880 HTTP, 8843 HTTPS).";
        };

        speedTest = mkOption {
          type = types.bool;
          default = false;
          description = "Expose the mobile speed-test port (6789/tcp).";
        };

        l2Discovery = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Make the controller discoverable over L2 via SSDP on 1900/udp, for
            the mobile app and the Discovery Utility. Off by default because it
            collides with miniupnpd when `router.upnp.enable` is set.
          '';
        };

        database = {
          image = mkOption {
            type = types.str;
            default = "docker.io/library/mongo:4.4.30";
            description = ''
              MongoDB image, deliberately pinned to 4.4 — DO NOT BUMP THE MAJOR.

              MongoDB 5.0 and newer require AVX on x86_64 and abort with SIGILL
              without it; 4.4 is the last release that runs on CPUs that lack it
              (for example the Atom C2558 this module was developed against).
              UniFi's own supported floor is still MongoDB 3.6, so 4.4 remains
              inside the supported window for current 10.x controllers.

              4.4 reached end of life in February 2024 but still receives
              out-of-band fixes: 4.4.30 patches the actively exploited
              CVE-2025-14847, and 4.4 predates time-series collections so it is
              not affected by CVE-2026-8053. The residual risk is managed by
              reachability — the container publishes no ports, sits alone on its
              own network, and modules/firewall.nix deliberately has no forward
              rule to it, so nothing off-host can reach it.

              This image is excluded from `router.wireless.autoUpdate` because
              MongoDB refuses to start on a data directory written by a newer
              major, which would make a routine reboot unrecoverable.
            '';
          };

          name = mkOption {
            type = types.str;
            default = "unifi";
            description = ''
              Database name. The controller also uses `<name>_stat`,
              `<name>_audit` and `<name>_restore`.
            '';
          };

          user = mkOption {
            type = types.str;
            default = "unifi";
            description = "Database user the controller authenticates as, created on first start.";
          };

          cacheSizeGB = mkOption {
            type = types.str;
            default = "0.5";
            description = ''
              WiredTiger cache size in GB. MongoDB otherwise defaults to half of
              (RAM - 1 GB), which is far too much for a router.
            '';
          };
        };

        network = mkNetworkOptions {
          interface = "br-unifi";
          subnet = "10.90.0.0/24";
          gateway = "10.90.0.1";
        };
      };

      # ── OpenWISP ────────────────────────────────────────
      openwisp = {
        enable = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Run a core OpenWISP deployment on this router: the nginx, dashboard,
            api, websocket, celery and celerybeat containers, backed by the
            router's own PostgreSQL (with PostGIS) and Redis.

            Monitoring, RADIUS, firmware upgrades, network topology, the
            management OpenVPN and Postfix are all left out — they add five more
            containers plus InfluxDB, and none of them are needed to configure
            APs that sit on the router's own LAN.
          '';
        };

        image = mkOption {
          type = types.str;
          default = "docker.io/openwisp";
          description = ''
            Image repository prefix. Each container appends its own name, e.g.
            `docker.io/openwisp/openwisp-dashboard`. Keep the registry host:
            NixOS ships no `unqualified-search-registries`, so a bare
            `openwisp/...` name makes every pull fail with "short-name ... did
            not resolve to an alias".
          '';
        };

        version = mkOption {
          type = types.str;
          default = "latest";
          description = ''
            Image tag. `latest` is a moving alias for the newest stable release.
            Do NOT use `edge` — that is upstream's master branch.
          '';
        };

        domain = mkOption {
          type = types.str;
          default = "openwisp.home.arpa";
          description = ''
            Parent domain for the dashboard and API hostnames, which become
            `dashboard.<domain>` and `api.<domain>`. Both are published in the
            local DNS zone pointing at the router's LAN address.

            The default is under `home.arpa` for a specific reason: OpenWISP
            derives its session and CSRF cookie domains by running the parent
            through the Public Suffix List, and `.lan`, `.local` and `.internal`
            are not in that list. With those, the cookie domain collapses to
            "." and every request fails — first as a rejected Host header, then
            as a rejected CSRF referer. `home.arpa` is in the list, so use it or
            a real domain you own.
          '';
        };

        httpPort = mkOption {
          type = types.port;
          default = 8081;
          description = ''
            Host port for OpenWISP's plain HTTP listener, published on the LAN
            address. Not 80, which the Technitium block page binds on all
            interfaces whenever `router.accessPolicies.blockPage.enable` is set.
          '';
        };

        httpsPort = mkOption {
          type = types.port;
          default = 8444;
          description = ''
            Host port for OpenWISP's HTTPS listener, published on the LAN
            address. Not 443, for the same reason as `httpPort`. This port is
            part of the dashboard URL and of the CSRF trusted origins, so
            changing it after devices are provisioned means re-pointing them.
          '';
        };

        database = {
          name = mkOption {
            type = types.str;
            default = "openwisp";
            description = "PostgreSQL database name.";
          };
          user = mkOption {
            type = types.str;
            default = "openwisp";
            description = "PostgreSQL role name, created as the database owner.";
          };
        };

        network = mkNetworkOptions {
          interface = "br-openwisp";
          subnet = "10.89.0.0/24";
          gateway = "10.89.0.1";
        };
      };

      # ── Image refresh ───────────────────────────────────
      autoUpdate = {
        enable = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Let podman refresh the application containers from their registry on
            a timer, restarting each one and rolling back automatically if the
            new image fails to start. Only containers carrying the
            io.containers.autoupdate label participate — notably NOT the UniFi
            database, which is pinned on purpose.
          '';
        };

        dates = mkOption {
          type = types.str;
          default = "daily";
          description = "systemd calendar expression for the refresh timer.";
        };
      };
    };

    # ── Internal channels ─────────────────────────────────
    # Derived values the firewall and DNS modules consume. Mirrors the
    # `router._policyStaticInputs` pattern in modules/access-policies.nix:
    # internal + readOnly, so it never reaches the public option surface or
    # /etc/router/effective.json.
    _wirelessInternal = mkOption {
      type = types.attrs;
      internal = true;
      readOnly = true;
      description = "Derived wireless-controller values shared with the firewall and DNS modules.";
    };

    _localDnsRecords = mkOption {
      type = types.listOf (
        types.submodule {
          options = {
            zone = mkOption {
              type = types.str;
              description = ''
                Authoritative zone to create if absent. This is a full zone
                name, not the router's own local zone: that one is
                `<hostName>.<lan.domain>`, so a record placed inside it would
                answer for `unifi.948-router.lan` rather than the `unifi.lan`
                clients actually ask for.
              '';
            };
            name = mkOption {
              type = types.str;
              description = "Fully-qualified record name inside `zone`.";
            };
            address = mkOption {
              type = types.str;
              description = "IPv4 address the record resolves to.";
            };
          };
        }
      );
      internal = true;
      default = [ ];
      description = ''
        Extra A records reconciled into Technitium by
        pkgs/router-dns-tools reconcile.py. Not readOnly: several modules may
        contribute, and the definitions merge.
      '';
    };
  };

  # ══════════════════════════════════════════════════════════
  #  CONFIG
  # ══════════════════════════════════════════════════════════
  config = mkMerge [
    {
      router._wirelessInternal = {
        inherit stateDir hostIn;
        openwisp = {
          inherit (owNet) subnet gateway;
          inherit (wcfg.openwisp.network) interface;
          ip = hostIn owNet.gateway;
        };
        unifi = {
          inherit (unifiNet) subnet gateway;
          inherit (wcfg.unifi.network) interface;
          ip = hostIn unifiNet.gateway;
        };
      };
    }

    (mkIf anyEnabled {
      assertions = [
        {
          assertion = !(wcfg.unifi.l2Discovery && cfg.upnp.enable);
          message = ''
            router.wireless.unifi.l2Discovery and router.upnp.enable both need
            1900/udp. miniupnpd binds it on the LAN bridge for SSDP, and the
            UniFi container would bind it on all interfaces. Turn one off — L2
            discovery is only needed by the UniFi mobile app and the Discovery
            Utility, and adoption works without it via DHCP option 43.
          '';
        }
        {
          assertion = !(wcfg.unifi.enable && wcfg.openwisp.enable && wcfg.openwisp.httpsPort == 8443);
          message = ''
            router.wireless.openwisp.httpsPort is 8443, which the UniFi
            controller already binds for its web UI. Pick another port.
          '';
        }
        {
          assertion =
            !(
              wcfg.openwisp.enable
              && elem wcfg.openwisp.httpPort [
                8080
                8443
              ]
            );
          message = ''
            router.wireless.openwisp.httpPort collides with a UniFi port (8080
            device inform, 8443 web UI). Pick another port.
          '';
        }
        {
          assertion = !wcfg.openwisp.enable || (length (splitString "." wcfg.openwisp.domain)) >= 2;
          message = "router.wireless.openwisp.domain must be a dotted domain name, e.g. openwisp.home.arpa.";
        }
        {
          # Not a Public Suffix List check — Nix cannot do that — but it catches
          # the three suffixes people actually reach for, each of which breaks
          # OpenWISP's cookie domain silently. See the `domain` option.
          assertion =
            !wcfg.openwisp.enable
            || !(any (s: hasSuffix ".${s}" wcfg.openwisp.domain) [
              "lan"
              "local"
              "internal"
              "localdomain"
              "home"
            ]);
          message = ''
            router.wireless.openwisp.domain ends in a suffix that is not in the
            Public Suffix List (.lan/.local/.internal/.localdomain/.home).
            OpenWISP derives its session and CSRF cookie domains from the
            registered domain, which comes back empty for these — the dashboard
            then rejects every request, first as a disallowed Host and then as a
            bad CSRF referer. Use something under `home.arpa` (the default) or a
            domain you actually own.
          '';
        }
      ]
      ++ map (n: {
        assertion = hasSuffix "/24" n.subnet;
        message = ''
          The ${n.name} container network subnet must be a /24 (got
          ${n.subnet}); container addresses are derived by replacing the
          gateway's last octet.
        '';
      }) (optional wcfg.openwisp.enable owNet ++ optional wcfg.unifi.enable unifiNet);

      # ── Podman ────────────────────────────────────────
      virtualisation.podman.enable = true;
      virtualisation.oci-containers.backend = "podman";

      # ── Container networks ────────────────────────────
      # Read directly by netavark; see the module header for why these are
      # files rather than a `podman network create` oneshot.
      environment.etc = mkMerge [
        (mkIf wcfg.openwisp.enable {
          "containers/networks/openwisp.json".source = owNet.file;
        })
        (mkIf wcfg.unifi.enable {
          "containers/networks/unifi.json".source = unifiNet.file;
        })
      ];

      # The bridges are created by systemd-networkd rather than left to
      # netavark, which would otherwise only bring them up when the first
      # container starts. That ordering is unworkable here: the router's own
      # PostgreSQL and Redis bind the gateway address so containers can reach
      # them, and a service cannot bind an address that does not exist yet —
      # while the containers in turn depend on those services, so nothing can
      # be reordered out of it. Declaring the bridge up front breaks the cycle,
      # and netavark is happy to adopt an interface that already exists.
      #
      # Everything else on this router is networkd-managed too, so this also
      # keeps `networkctl` an honest view of the machine.
      systemd.network = mkMerge (
        map
          (n: {
            netdevs."45-${n.interface}".netdevConfig = {
              Name = n.interface;
              Kind = "bridge";
            };
            networks."45-${n.interface}" = {
              matchConfig.Name = n.interface;
              address = [ "${n.gateway}/24" ];
              networkConfig = {
                # No carrier until a container attaches a veth.
                ConfigureWithoutCarrier = true;
                IPv4Forwarding = true;
                IPv6AcceptRA = false;
              };
              linkConfig.RequiredForOnline = "no";
            };
          })
          (
            optional wcfg.openwisp.enable {
              inherit (wcfg.openwisp.network) interface gateway;
            }
            ++ optional wcfg.unifi.enable {
              inherit (wcfg.unifi.network) interface gateway;
            }
          )
      );

      # ── Secrets ───────────────────────────────────────
      systemd.services.router-wireless-secrets = {
        description = "Generate wireless controller runtime secrets";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = secretsScript;
        };
      };

      # Anything binding a container bridge's gateway address orders after this.
      systemd.services.router-wireless-bridges = {
        description = "Wait for the wireless container bridge addresses";
        after = [ "systemd-networkd.service" ];
        wants = [ "systemd-networkd.service" ];
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = bridgeWaitScript;
        };
      };

      systemd.tmpfiles.rules = [ "d ${stateDir} 0700 root root -" ];

      # ── Image refresh ─────────────────────────────────
      # The unit and timer ship with the podman package, which the podman
      # module already puts on systemd.packages — so this only has to enable
      # and schedule them.
      systemd.timers.podman-auto-update = mkIf wcfg.autoUpdate.enable {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = mkForce wcfg.autoUpdate.dates;
          Persistent = true;
          RandomizedDelaySec = "30m";
        };
      };
    })
  ];
}
