# ── Reverse proxy module ───────────────────────────────────────────────────────
# Hostname-based HTTP(S) ingress: one public IPv4 address, any number of
# services behind it, told apart by the name the client asked for (TLS SNI and
# the Host header) rather than by port. The proxy is `router-proxy`
# (pkgs/router-proxy), a small Pingora program that terminates TLS with the
# route's certificate and forwards to the route's registered host.
#
# Why the odd ports: the Technitium Block Page app owns :80/:443 on every
# address (dns-technitium.nix, `blockPageAddresses`), so the proxy listens on
# `proxyHttpPort`/`proxyHttpsPort` (topology.nix) instead, and firewall.nix redirects to them:
#
#   • WAN → a router address, tcp 80/443 — the public entry point.
#   • LAN/guest/WireGuard → a router address that is NOT the one on the
#     ingress interface, tcp 80/443 — hairpin: a client inside reaching the
#     public name (i.e. the WAN address) gets the same routes. The gateway
#     addresses themselves stay with the Block Page.
#
# Certificates come from security.acme, one per route (see modules/acme.nix
# for the challenge types). A renewal reloads the proxy (SIGHUP), which swaps
# routes and certificates in place without dropping connections; so does a
# rebuild that changes only routes.
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
  pcfg = cfg.reverseProxy;
  acfg = cfg.acme;
  inherit (config.router._internal) proxyHttpPort proxyHttpsPort;
  netLib = import ./lib/net.nix { inherit lib; };

  routerProxy = (pkgs.extend routerOverlay).router-proxy;

  webroot = "/var/lib/acme/acme-challenge";

  hostByName = listToAttrs (map (h: nameValuePair h.name h) cfg.hosts);

  # A wildcard covers exactly one extra label, and only a DNS-01 certificate
  # can carry one.
  isWildcard = hasPrefix "*.";
  isRouteName = n: netLib.isHostname (if isWildcard n then removePrefix "*." n else n);

  # The certificate (and its /var/lib/acme directory and acme-* units) is
  # named after the route's first hostname; `*` is not welcome in a unit or
  # directory name. Cockpit derives the same name (src/ingress.ts certName).
  certName = r: replaceStrings [ "*" ] [ "_" ] (toLower (head r.hostnames));
  challengeOf = r: if r.challenge != "default" then r.challenge else acfg.defaultChallenge;

  routes = map (
    r:
    let
      h = hostByName.${r.host} or null;
    in
    r
    // {
      inherit h;
      hostnames = map toLower r.hostnames;
      cert = certName r;
      challenge = challengeOf r;
      label = if r.name != "" then r.name else head r.hostnames;
    }
  ) (filter (r: r.hostnames != [ ]) pcfg.routes);

  allNames = concatMap (r: r.hostnames) routes;
  dupsOf =
    xs:
    attrNames (
      filterAttrs (_: c: c > 1) (foldl' (acc: x: acc // { ${x} = (acc.${x} or 0) + 1; }) { } xs)
    );

  proxySpec = {
    listen = {
      http = [
        "0.0.0.0:${toString proxyHttpPort}"
        "[::]:${toString proxyHttpPort}"
      ];
      https = [
        "0.0.0.0:${toString proxyHttpsPort}"
        "[::]:${toString proxyHttpsPort}"
      ];
    };
    acmeWebroot = webroot;
    routes = map (r: {
      inherit (r) hostnames tlsVerify hsts;
      upstream = "${if r.h != null then toString r.h.staticIp else "0.0.0.0"}:${toString r.port}";
      tls = r.scheme == "https";
      sni = head (filter (n: !(isWildcard n)) r.hostnames ++ [ (head r.hostnames) ]);
      cert = {
        fullchain = "/var/lib/acme/${r.cert}/fullchain.pem";
        key = "/var/lib/acme/${r.cert}/key.pem";
      };
    }) routes;
  };
  proxyConfig = pkgs.writeText "router-proxy.json" (builtins.toJSON proxySpec);

  acmeUnits = map (r: "acme-${r.cert}.service") routes;

  routeAssertions = concatMap (
    r:
    let
      pr = "router.reverseProxy.routes: route '${r.label}'";
    in
    [
      {
        assertion = all isRouteName r.hostnames;
        message = "${pr} has an invalid hostname in [ ${concatStringsSep ", " r.hostnames} ] — use public DNS names, optionally with a leading `*.`";
      }
      {
        assertion = r.h != null;
        message = "${pr} references unknown host '${r.host}' — it must name a router.hosts entry";
      }
      {
        assertion = r.h == null || r.h.staticIp != null;
        message = "${pr} proxies to host '${r.host}', which has no staticIp (DHCP reservation) — set one";
      }
      {
        assertion = r.challenge != "http" || !(any isWildcard r.hostnames);
        message = "${pr} has a wildcard hostname, which only a DNS-01 certificate can cover — set challenge = \"dns-cloudflare\"";
      }
      {
        assertion = r.challenge != "dns-cloudflare" || acfg.cloudflare.apiTokenFile != null;
        message = "${pr} uses the dns-cloudflare challenge, but router.acme.cloudflare.apiTokenFile is not set";
      }
    ]
  ) routes;

  v4ForwardsOnWeb = filter (
    f: f.protocol == "tcp" && f.family != "ipv6" && (elem 80 f.ports || elem 443 f.ports)
  ) cfg.portForwards;

  ddnsNames = map toLower cfg.ddns.names;
  publicNames = map (h: toLower h.publicHostname) (filter (h: h.publicHostname != null) cfg.hosts);
in
{
  options.router._reverseProxyConfig = mkOption {
    type = types.attrs;
    internal = true;
    readOnly = true;
    description = "Generated router-proxy configuration (tests read it without building the file).";
  };

  options.router.reverseProxy = {
    enable = mkEnableOption "the hostname-routing HTTP(S) reverse proxy on the WAN's ports 80 and 443";

    publishDns = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Publish every route hostname through router.ddns as a name for the
        router itself (A = WAN IPv4, AAAA = the router's global IPv6). Needs
        router.ddns enabled; HTTP-01 certificates depend on it.
      '';
    };

    routes = mkOption {
      default = [ ];
      description = "Public hostnames and the registered host each one is proxied to.";
      example = literalExpression ''
        [
          {
            name = "Nextcloud";
            hostnames = [ "cloud.example.com" ];
            host = "nas";
            port = 8080;
          }
        ]
      '';
      type = types.listOf (
        types.submodule {
          options = {
            name = mkOption {
              type = types.str;
              default = "";
              description = "Descriptive label.";
            };
            hostnames = mkOption {
              type = types.listOf types.str;
              example = [ "cloud.example.com" ];
              description = ''
                Public names routed to the host, all covered by one certificate
                named after the first. A leading `*.` matches one extra label
                and needs a DNS-01 challenge.
              '';
            };
            host = mkOption {
              type = types.str;
              example = "nas";
              description = "Name of the router.hosts device to proxy to (its staticIp).";
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
            tlsVerify = mkOption {
              type = types.bool;
              default = false;
              description = ''
                Verify the host's certificate when scheme = "https". Off by
                default: services inside the LAN mostly present self-signed
                certificates.
              '';
            };
            challenge = mkOption {
              type = types.enum [
                "default"
                "dns-cloudflare"
                "http"
              ];
              default = "default";
              description = "ACME challenge for this route's certificate; `default` uses router.acme.defaultChallenge.";
            };
            hsts = mkOption {
              type = types.bool;
              default = false;
              description = "Send Strict-Transport-Security, so browsers refuse plain HTTP for these names for a year.";
            };
          };
        }
      );
    };
  };

  config = mkMerge [
    { router._reverseProxyConfig = proxySpec; }
    {
      assertions = routeAssertions ++ [
        {
          assertion = all (r: r.hostnames != [ ]) pcfg.routes;
          message = "router.reverseProxy.routes: every route needs at least one hostname";
        }
        {
          assertion = dupsOf allNames == [ ];
          message = "router.reverseProxy.routes: ${concatStringsSep ", " (dupsOf allNames)} appears in more than one route";
        }
        {
          assertion = !pcfg.enable || v4ForwardsOnWeb == [ ];
          message = "router.portForwards: ${
            concatMapStringsSep ", " (f: "'${if f.name != "" then f.name else f.host}'") v4ForwardsOnWeb
          } forwards IPv4 tcp 80/443, which the reverse proxy owns — route the host through router.reverseProxy.routes instead, or set the forward's family = \"ipv6\"";
        }
        {
          assertion = !(pcfg.enable && pcfg.publishDns) || all (n: !(elem n ddnsNames)) allNames;
          message = "router.ddns.names: ${
            concatStringsSep ", " (filter (n: elem n ddnsNames) allNames)
          } is already published by router.reverseProxy.publishDns — remove it from ddns.names";
        }
        {
          assertion = all (n: !(elem n publicNames)) allNames;
          message = "router.reverseProxy.routes: ${
            concatStringsSep ", " (filter (n: elem n publicNames) allNames)
          } is also a host's publicHostname — a name can point at the router or at a host, not both";
        }
      ];

      warnings =
        optional (pcfg.enable && pcfg.publishDns && routes != [ ] && !cfg.ddns.enable)
          "router.reverseProxy.publishDns is on but router.ddns is disabled, so the route hostnames are not published — point them at the router yourself."
        ++ optional (
          pcfg.enable && routes == [ ]
        ) "router.reverseProxy is enabled with no routes; it only answers ACME challenges and 404s.";
    }

    (mkIf pcfg.enable {
      security.acme.certs = listToAttrs (
        map (
          r:
          nameValuePair r.cert (
            {
              domain = head r.hostnames;
              extraDomainNames = tail r.hostnames;
              group = "router-proxy";
              reloadServices = [ "router-proxy.service" ];
            }
            // (
              if r.challenge == "dns-cloudflare" then
                {
                  dnsProvider = "cloudflare";
                  dnsPropagationCheck = true;
                  # Guarded so a missing path reports through the assertion
                  # above instead of a bare "cannot coerce null to a string".
                  credentialFiles = optionalAttrs (acfg.cloudflare.apiTokenFile != null) {
                    CF_DNS_API_TOKEN_FILE = acfg.cloudflare.apiTokenFile;
                  };
                }
              else
                { inherit webroot; }
            )
          )
        ) routes
      );

      users.users.router-proxy = {
        isSystemUser = true;
        group = "router-proxy";
        description = "Reverse proxy";
      };
      users.groups.router-proxy = { };

      systemd.services.router-proxy = {
        # The unit name is a UI contract — Cockpit shows its state.
        description = "Hostname-routing HTTP(S) reverse proxy";
        wantedBy = [ "multi-user.target" ];
        # acme-<cert>.service leaves a self-signed placeholder until the first
        # real order lands, so the proxy can start (and serve the HTTP-01
        # challenge that order needs) before any certificate is issued.
        wants = acmeUnits ++ [ "network-online.target" ];
        after = acmeUnits ++ [ "network-online.target" ];
        # A route or certificate change is a reload (SIGHUP), not a restart:
        # the listeners and live connections survive it.
        reloadTriggers = [ proxyConfig ];

        environment = {
          # Pingora logs every failed TLS handshake at ERROR, and on a WAN
          # port scanners produce a steady stream of them (no SNI, no shared
          # cipher). Access logs and our own errors stay at info.
          RUST_LOG = "info,pingora_core::services::listening=off";
          # For routes with tlsVerify: OpenSSL's compiled-in CA path is in the
          # store, not the system bundle.
          SSL_CERT_FILE = "/etc/ssl/certs/ca-certificates.crt";
        };

        serviceConfig = {
          ExecStart = "${getExe routerProxy} --config ${proxyConfig}";
          ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
          User = "router-proxy";
          Group = "router-proxy";
          Restart = "on-failure";
          RestartSec = 5;

          # Hardening. Unprivileged ports only, so no capabilities at all; it
          # needs just the network and read access to /var/lib/acme.
          CapabilityBoundingSet = [ "" ];
          LockPersonality = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateTmp = true;
          ProtectClock = true;
          ProtectControlGroups = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectProc = "invisible";
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
          ];
        };
      };
    })

    # An HTTP-01 order is answered by the proxy itself, so it must not race the
    # proxy's start at boot (it would fail and wait for the daily timer).
    (mkIf pcfg.enable {
      systemd.services = listToAttrs (
        map (r: nameValuePair "acme-order-renew-${r.cert}" { after = [ "router-proxy.service" ]; }) (
          filter (r: r.challenge == "http") routes
        )
      );
    })
  ];
}
