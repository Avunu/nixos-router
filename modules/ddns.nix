# ── Dynamic DNS module ─────────────────────────────────────────────────────────
# Keeps public DNS names on Cloudflare pointed at the router's dynamic addresses:
#
#   • router.ddns.names          — the router itself: A = WAN IPv4, AAAA = the
#                                  router's own global IPv6 (the WAN's, or the
#                                  LAN bridge's delegated-prefix address when
#                                  the ISP gives the WAN none).
#   • router.reverseProxy.routes[].hostnames — with publishDns on, published
#                                  exactly like router.ddns.names: the proxy on
#                                  the router answers for them.
#   • router.hosts[].publicHostname — a registered device: A = WAN IPv4 (reach
#                                  it through a port forward), AAAA = the
#                                  device's own address, i.e. its network's
#                                  current delegated /64 plus its ipv6Suffix.
#
# The work is done by `router-ddns` (pkgs/router-dns-tools), a timer-driven
# oneshot that detects the addresses, reconciles the records through the
# Cloudflare API and writes a status file the Cockpit Network page shows. The
# API token is a path to a root-owned file (never the token itself), handed to
# the unit through LoadCredential.
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
  dcfg = cfg.ddns;
  netLib = import ./lib/net.nix { inherit lib; };
  inherit (config.router._internal) wanIf brLAN brGuest;

  # The overlay is applied locally, as in dns-technitium.nix: router._dnsTools*
  # only exist when Technitium is enabled, and DDNS must not depend on it.
  routerDnsTools = (pkgs.extend routerOverlay).router-dns-tools;

  stateDir = "/var/lib/router-ddns";

  publicHosts = filter (h: h.publicHostname != null) cfg.hosts;
  routerNames = map toLower dcfg.names;
  proxyNames = optionals (cfg.reverseProxy.enable && cfg.reverseProxy.publishDns) (
    unique (concatMap (r: map toLower r.hostnames) cfg.reverseProxy.routes)
  );
  collisions = filter (n: elem n routerNames) (map (h: toLower h.publicHostname) publicHosts);

  records =
    map (n: {
      name = toLower n;
      v4 = dcfg.ipv4;
      v6 = if dcfg.ipv6 then { kind = "router"; } else null;
    }) (dcfg.names ++ proxyNames)
    ++ map (h: {
      name = toLower h.publicHostname;
      host = h.name;
      v4 = dcfg.ipv4;
      v6 =
        if dcfg.ipv6 && h.ipv6Suffix != null && netLib.parseSuffix h.ipv6Suffix != null then
          {
            kind = "host";
            interface = if h.network == "guest" then brGuest else brLAN;
            suffix = netLib.parseSuffix h.ipv6Suffix;
          }
        else
          null;
    }) publicHosts;

  ddnsSpec = {
    ddns = {
      inherit stateDir records;
      inherit (dcfg)
        ipv4
        ipv6
        ttl
        proxied
        ;
      wanInterface = wanIf;
      routerV6Fallback = brLAN;
      apiTokenFile = dcfg.cloudflare.apiTokenFile;
    };
  };
  ddnsConfig = pkgs.writeText "router-ddns.json" (builtins.toJSON ddnsSpec);
in
{
  options.router._ddnsConfig = mkOption {
    type = types.attrs;
    internal = true;
    readOnly = true;
    description = "Generated router-ddns configuration (tests read it without building the file).";
  };

  options.router.ddns = {
    enable = mkEnableOption "dynamic DNS updates of the router's public addresses (Cloudflare)";

    cloudflare.apiTokenFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/etc/router/secrets/cloudflare-ddns.token";
      description = ''
        Path to a root-owned file holding a Cloudflare API token with
        Zone → Zone → Read and Zone → DNS → Edit on the zones of every managed
        name. The file holds the bare token — never put the token itself here.
      '';
    };

    names = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "home.example.com" ];
      description = ''
        Public names for the router itself: A = WAN IPv4, AAAA = the router's
        own global IPv6 address. Hosts publish their own names through
        router.hosts[].publicHostname.
      '';
    };

    ipv4 = mkOption {
      type = types.bool;
      default = true;
      description = "Publish A records (the WAN IPv4 address).";
    };

    ipv6 = mkOption {
      type = types.bool;
      default = true;
      description = "Publish AAAA records (the router's and hosts' global IPv6 addresses).";
    };

    intervalMinutes = mkOption {
      type = types.ints.between 1 1440;
      default = 5;
      description = "How often to check the addresses. Cloudflare is only written to when one changes.";
    };

    ttl = mkOption {
      type = types.ints.unsigned;
      default = 1;
      description = "Record TTL in seconds: 1 for Cloudflare's automatic TTL, otherwise 60-86400.";
    };

    proxied = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Proxy the records through Cloudflare (orange cloud). Only HTTP(S) on
        Cloudflare's supported ports passes a proxied name, so leave this off
        for anything else a port forward exposes.
      '';
    };
  };

  config = mkMerge [
    { router._ddnsConfig = ddnsSpec; }
    {
      assertions = [
        {
          assertion = !dcfg.enable || dcfg.cloudflare.apiTokenFile != null;
          message = "router.ddns: enabled without router.ddns.cloudflare.apiTokenFile";
        }
        {
          assertion = !dcfg.enable || dcfg.ipv4 || dcfg.ipv6;
          message = "router.ddns: both ipv4 and ipv6 are disabled, so there is nothing to publish";
        }
        {
          assertion = dcfg.ttl == 1 || (dcfg.ttl >= 60 && dcfg.ttl <= 86400);
          message = "router.ddns.ttl must be 1 (automatic) or between 60 and 86400 seconds";
        }
        {
          assertion = all netLib.isHostname dcfg.names;
          message = "router.ddns.names: not a valid DNS name: ${
            concatStringsSep ", " (filter (n: !(netLib.isHostname n)) dcfg.names)
          }";
        }
        {
          assertion = length (unique routerNames) == length routerNames;
          message = "router.ddns.names: duplicate name(s)";
        }
        {
          assertion = collisions == [ ];
          message = "router.ddns.names: ${concatStringsSep ", " collisions} is also a host's publicHostname — a name can point at the router or at a host, not both";
        }
      ];

      warnings =
        optional (dcfg.enable && records == [ ])
          "router.ddns is enabled but no names are configured (router.ddns.names or router.hosts[].publicHostname), so it publishes nothing."
        ++
          optional (!dcfg.enable && publicHosts != [ ])
            "router.hosts: ${
              concatMapStringsSep ", " (h: "'${h.name}'") publicHosts
            } set a publicHostname, but router.ddns is disabled, so nothing publishes it.";
    }

    (mkIf dcfg.enable {
      systemd.services.router-ddns = {
        # The unit name is a UI contract — Cockpit's "Update now" button starts it.
        description = "Update Cloudflare DNS records with the router's addresses";
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        # Every rebuild restarts the active targets, which pulls this inactive
        # oneshot back in: a changed name set is published straight away
        # instead of at the next timer tick (see router-directory-sync for why
        # restartTriggers would be dead code on a timer-driven oneshot).
        wantedBy = [ "multi-user.target" ];
        path = [ pkgs.iproute2 ];

        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${routerDnsTools}/bin/router-ddns --config ${ddnsConfig}";
          DynamicUser = true;
          StateDirectory = "router-ddns";
          StateDirectoryMode = "0750";
          # Guarded so a missing path reports through the assertion above
          # instead of a bare "cannot coerce null to a string".
          LoadCredential = optional (
            dcfg.cloudflare.apiTokenFile != null
          ) "cf-api-token:${dcfg.cloudflare.apiTokenFile}";

          # A failed run (API or network down) retries soon rather than at the
          # next tick; the start limit keeps a bad token from hammering the API.
          Restart = "on-failure";
          RestartSec = 60;

          # Hardening. Needs the network (Cloudflare API, the IPv4 trace
          # endpoint) and netlink (`ip -j addr` to read the addresses).
          CapabilityBoundingSet = [ "" ];
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateTmp = true;
          ProtectClock = true;
          ProtectControlGroups = true;
          ProtectHome = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectSystem = "strict";
          RestrictAddressFamilies = [
            "AF_UNIX"
            "AF_INET"
            "AF_INET6"
            "AF_NETLINK"
          ];
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [
            "@system-service"
            "~@privileged"
            "~@resources"
          ];
        };

        unitConfig = {
          StartLimitIntervalSec = 900;
          StartLimitBurst = 5;
        };
      };

      systemd.timers.router-ddns = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnBootSec = "1min";
          OnUnitActiveSec = "${toString dcfg.intervalMinutes}min";
          RandomizedDelaySec = 30;
        };
      };
    })
  ];
}
