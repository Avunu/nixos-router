# ── Cloudflare Tunnel module ───────────────────────────────────────────────────
# Hostname-based ingress with no inbound port at all: `cloudflared` holds
# outbound connections to Cloudflare's edge, and requests for the tunnel's
# public names arrive down them and are handed to registered LAN hosts. It
# works behind CGNAT, and the router's WAN address is never published.
#
# The router manages the whole tunnel through the Cloudflare API, so it is
# declared entirely in router-settings.json:
#
#   • router-cloudflare-tunnel (pkgs/router-dns-tools, tunnel.py) — a oneshot
#     that creates a locally-configured tunnel named after the router (the
#     tunnel secret is generated on the router and never leaves it except in
#     that one API call), writes its credentials file, and keeps one proxied
#     CNAME per ingress hostname pointing at <id>.cfargotunnel.com. A name
#     already held by another record is taken over and restored when dropped,
#     like router-ddns does. Disabling the tunnel deletes it and its records.
#   • cloudflared — nixpkgs services.cloudflared, with the ingress rules built
#     here from the settings and the credentials file the oneshot wrote. It
#     only runs once there is an ingress hostname to serve.
#
# The API token is a path to a root-owned file (never the token itself),
# handed to the oneshot through LoadCredential.
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
  tcfg = cfg.cloudflareTunnel;
  netLib = import ./lib/net.nix { inherit lib; };

  routerDnsTools = (pkgs.extend routerOverlay).router-dns-tools;

  stateDir = "/var/lib/router-cloudflared";
  tunnelName = cfg.hostName;

  hostByName = listToAttrs (map (h: nameValuePair h.name h) cfg.hosts);

  ingress = map (
    i:
    i
    // {
      hostname = toLower i.hostname;
      h = hostByName.${i.host} or null;
    }
  ) tcfg.ingress;
  hostnames = map (i: i.hostname) ingress;

  tunnelSpec = {
    tunnel = {
      inherit (tcfg) enable;
      inherit stateDir hostnames;
      name = tunnelName;
      apiTokenFile = tcfg.apiTokenFile;
    };
  };
  tunnelConfig = pkgs.writeText "router-cloudflare-tunnel.json" (builtins.toJSON tunnelSpec);

  dupsOf =
    xs:
    attrNames (
      filterAttrs (_: c: c > 1) (foldl' (acc: x: acc // { ${x} = (acc.${x} or 0) + 1; }) { } xs)
    );

  # Every other feature that points a public name somewhere. A tunnel name is
  # a CNAME to Cloudflare; any of these would fight it for the same record.
  otherNames =
    map (n: {
      name = toLower n;
      owner = "router.ddns.names";
    }) cfg.ddns.names
    ++ map (h: {
      name = toLower h.publicHostname;
      owner = "host '${h.name}' (publicHostname)";
    }) (filter (h: h.publicHostname != null) cfg.hosts)
    ++ concatMap (
      r:
      map (n: {
        name = toLower n;
        owner = "reverse proxy route '${if r.name != "" then r.name else head r.hostnames}'";
      }) r.hostnames
    ) (optionals cfg.reverseProxy.enable cfg.reverseProxy.routes);
  clashes = filter (o: elem o.name hostnames) otherNames;

  ingressAssertions = concatMap (
    i:
    let
      pi = "router.cloudflareTunnel.ingress: '${i.hostname}'";
    in
    [
      {
        assertion = netLib.isHostname i.hostname;
        message = "${pi} is not a valid public DNS name";
      }
      {
        assertion = i.h != null;
        message = "${pi} references unknown host '${i.host}' — it must name a router.hosts entry";
      }
      {
        assertion = i.h == null || i.h.staticIp != null;
        message = "${pi} targets host '${i.host}', which has no staticIp (DHCP reservation) — set one";
      }
    ]
  ) ingress;
in
{
  options.router._cloudflareTunnelConfig = mkOption {
    type = types.attrs;
    internal = true;
    readOnly = true;
    description = "Generated router-cloudflare-tunnel configuration (tests read it without building the file).";
  };

  options.router.cloudflareTunnel = {
    enable = mkEnableOption "a Cloudflare Tunnel, managed by the router, for hostname-based ingress without opening a WAN port";

    apiTokenFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/etc/router/secrets/cloudflare-tunnel.token";
      description = ''
        Path to a root-owned file holding a Cloudflare API token with
        Account → Cloudflare Tunnel → Edit, and Zone → Zone → Read plus
        Zone → DNS → Edit on the zones of every ingress hostname. The file
        holds the bare token — never put the token itself here. Keep it set
        when disabling the tunnel: the router needs it to delete the tunnel
        and its DNS records.
      '';
    };

    ingress = mkOption {
      default = [ ];
      description = "Public hostnames served through the tunnel, and the registered host each one reaches.";
      example = literalExpression ''
        [
          {
            hostname = "wiki.example.com";
            host = "nas";
            port = 3000;
          }
        ]
      '';
      type = types.listOf (
        types.submodule {
          options = {
            hostname = mkOption {
              type = types.str;
              example = "wiki.example.com";
              description = "Public name; the router points it at the tunnel with a proxied CNAME.";
            };
            host = mkOption {
              type = types.str;
              example = "nas";
              description = "Name of the router.hosts device the traffic goes to (its staticIp).";
            };
            port = mkOption {
              type = types.port;
              default = 80;
              description = "Port of the service on the host.";
            };
            scheme = mkOption {
              type = types.enum [
                "http"
                "https"
              ];
              default = "http";
              description = "Protocol the host's service speaks.";
            };
            noTLSVerify = mkOption {
              type = types.bool;
              default = true;
              description = "With scheme = \"https\", accept the host's certificate unverified (LAN services are mostly self-signed).";
            };
            httpHostHeader = mkOption {
              type = types.str;
              default = "";
              description = "Host header to send to the service instead of the public name; empty keeps the public name.";
            };
          };
        }
      );
    };
  };

  config = mkMerge [
    { router._cloudflareTunnelConfig = tunnelSpec; }
    {
      assertions = ingressAssertions ++ [
        {
          assertion = !tcfg.enable || tcfg.apiTokenFile != null;
          message = "router.cloudflareTunnel: enabled without router.cloudflareTunnel.apiTokenFile";
        }
        {
          assertion = dupsOf hostnames == [ ];
          message = "router.cloudflareTunnel.ingress: duplicate hostname(s) ${concatStringsSep ", " (dupsOf hostnames)}";
        }
        {
          assertion = !tcfg.enable || clashes == [ ];
          message = "router.cloudflareTunnel.ingress: ${
            concatMapStringsSep "; " (o: "${o.name} is also published by ${o.owner}") clashes
          } — a name can only point one way";
        }
      ];

      warnings =
        optional (tcfg.enable && ingress == [ ])
          "router.cloudflareTunnel is enabled with no ingress hostnames, so no connector runs; the tunnel is created (or the existing one reused) once a hostname is added.";
    }

    # The oneshot also runs while the tunnel is disabled, as long as the token
    # is still there: that is how the tunnel and its records get deleted.
    (mkIf (tcfg.enable || tcfg.apiTokenFile != null) {
      systemd.services.router-cloudflare-tunnel = {
        # The unit name is a UI contract — Cockpit's "Sync now" button starts it.
        description = "Provision the Cloudflare Tunnel and its DNS records";
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        # Pulled in by every rebuild, like router-ddns, so a changed hostname
        # set is published at once rather than at the next timer tick.
        wantedBy = [ "multi-user.target" ];

        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${routerDnsTools}/bin/router-cloudflare-tunnel --config ${tunnelConfig}";
          # A static state directory owned by root, not DynamicUser: the
          # credentials file must survive and stay private, and cloudflared
          # (another DynamicUser) receives it through LoadCredential.
          StateDirectory = "router-cloudflared";
          StateDirectoryMode = "0700";
          LoadCredential = optional (tcfg.apiTokenFile != null) "cf-api-token:${tcfg.apiTokenFile}";
          UMask = "0077";

          Restart = "on-failure";
          RestartSec = 60;

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
          # Disabled, without the token file there is nothing it could tear
          # down: skip the unit rather than fail credential setup, which
          # would fail the switch and so every apply. Enabled, a missing
          # token still fails loudly.
          ConditionPathExists = mkIf (!tcfg.enable) tcfg.apiTokenFile;
        };
      };

      # Refreshes the status file (connector health) and repairs drift in the
      # DNS records or a tunnel deleted from the dashboard.
      systemd.timers.router-cloudflare-tunnel = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnBootSec = "2min";
          OnUnitActiveSec = "5min";
          RandomizedDelaySec = 30;
        };
      };
    })

    # No connector without a hostname: there is nothing to serve, and with no
    # tunnel created yet there are no credentials for it to start with. The
    # oneshot above still runs, keeping an existing tunnel and releasing
    # dropped names.
    (mkIf (tcfg.enable && ingress != [ ]) {
      services.cloudflared = {
        enable = true;
        tunnels.${tunnelName} = {
          credentialsFile = "${stateDir}/credentials.json";
          default = "http_status:404";
          ingress = listToAttrs (
            map (
              i:
              nameValuePair i.hostname {
                service = "${i.scheme}://${
                  if i.h != null then toString i.h.staticIp else "0.0.0.0"
                }:${toString i.port}";
                originRequest = {
                  noTLSVerify = mkIf (i.scheme == "https") i.noTLSVerify;
                  httpHostHeader = mkIf (i.httpHostHeader != "") i.httpHostHeader;
                };
              }
            ) ingress
          );
        };
      };

      # The credentials file only exists once the oneshot has created the
      # tunnel, so order after it — but only `wants`: an API outage failing
      # the oneshot must not keep an already-provisioned tunnel down. On a
      # first boot with the API unreachable, cloudflared keeps retrying until
      # the oneshot's own retry writes the file.
      systemd.services."cloudflared-tunnel-${tunnelName}" = {
        wants = [ "router-cloudflare-tunnel.service" ];
        after = [ "router-cloudflare-tunnel.service" ];
        serviceConfig.RestartSec = 30;
        unitConfig.StartLimitIntervalSec = 0;
      };
    })
  ];
}
