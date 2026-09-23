# Eval-only regression check — hostname-based ingress (reverse proxy, ACME
# certificates, Cloudflare Tunnel).
#
# Like tests/port-forwards-eval.nix, nearly everything here is config
# GENERATION that fails silently: a redirect that also swallows an IPv6
# pinhole, a hairpin rule that steals the Block Page's gateway address, a
# certificate asking for the wrong challenge, a tunnel CNAME fighting a DDNS
# record. This pins what the generated config says, that nftables accepts the
# ruleset (`nft --check` runs as a build dependency), and that every
# misconfiguration fails with a message naming its culprit.
{
  pkgs,
  routerModule,
  baseSettings,
}:
let
  inherit (pkgs) lib;

  evalWith =
    extra:
    (import "${pkgs.path}/nixos/lib/eval-config.nix" {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        routerModule
        (
          { lib, ... }:
          {
            config = lib.mkMerge [
              { router = lib.mkDefault baseSettings; }
              {
                router.hostName = "gw";
                router.wan.interface = "eth1";
                router.wan.vlan = null;
                router.lan.interfaces = [ "eth2" ];
                disko.enableConfig = lib.mkForce false;
                boot.loader.systemd-boot.enable = lib.mkForce false;
                boot.loader.grub.enable = lib.mkForce false;
                fileSystems."/" = {
                  device = "/dev/vda";
                  fsType = "ext4";
                };
              }
              extra
            ];
          }
        )
      ];
    }).config;

  hosts = [
    {
      mac = "aa:bb:cc:dd:ee:01";
      name = "nas";
      staticIp = "10.48.4.2";
      ipv6Suffix = "::42";
      publicHostname = "nas.example.com";
    }
    {
      mac = "aa:bb:cc:dd:ee:02";
      name = "wiki";
      staticIp = "10.48.4.3";
    }
    {
      mac = "aa:bb:cc:dd:ee:03";
      name = "laptop";
    }
  ];

  sys = evalWith {
    router.hosts = hosts;
    router.guest.enable = true;
    # effective.json (the UI's view of the new keys) is Cockpit's.
    router.cockpit.enable = true;
    router.ddns = {
      enable = true;
      names = [ "home.example.com" ];
      cloudflare.apiTokenFile = "/etc/router/secrets/cloudflare-ddns.token";
    };
    router.acme = {
      email = "admin@example.com";
      acceptTerms = true;
      defaultChallenge = "http";
      cloudflare.apiTokenFile = "/etc/router/secrets/cloudflare-ddns.token";
    };
    router.reverseProxy = {
      enable = true;
      routes = [
        {
          name = "Cloud";
          hostnames = [
            "Cloud.example.com"
            "files.example.com"
          ];
          host = "nas";
          port = 8080;
        }
        {
          hostnames = [ "*.apps.example.com" ];
          host = "wiki";
          port = 8443;
          scheme = "https";
          challenge = "dns-cloudflare";
          hsts = true;
        }
      ];
    };
    router.cloudflareTunnel = {
      enable = true;
      apiTokenFile = "/etc/router/secrets/cloudflare-tunnel.token";
      ingress = [
        {
          hostname = "wiki.example.com";
          host = "wiki";
          port = 3000;
        }
        {
          hostname = "dsm.example.com";
          host = "nas";
          port = 5001;
          scheme = "https";
          httpHostHeader = "nas.lan";
        }
      ];
    };
    # An IPv6-only forward of 443 must survive the proxy's WAN redirect.
    router.portForwards = [
      {
        name = "v6 web";
        host = "nas";
        family = "ipv6";
        ports = [ 443 ];
      }
    ];
  };

  wan = sys.router._internal.wanIf;
  ruleset = sys.networking.nftables.ruleset;
  rulesScript = lib.elemAt sys.systemd.services.nftables.serviceConfig.ExecStart 1;
  has = s: lib.hasInfix s ruleset;

  certs = sys.security.acme.certs;
  proxyUnit = sys.systemd.services.router-proxy;
  proxyConfig = sys.router._reverseProxyConfig;
  routeFor = n: lib.findFirst (r: lib.elem n r.hostnames) null proxyConfig.routes;

  tunnel = sys.services.cloudflared.tunnels.gw;
  tunnelUnit = sys.systemd.services.router-cloudflare-tunnel;
  tunnelConfig = sys.router._cloudflareTunnelConfig.tunnel;
  ddnsNames = map (r: r.name) sys.router._ddnsConfig.ddns.records;

  failedAssertions = c: map (a: a.message) (lib.filter (a: !a.assertion) c.assertions);

  # Every misconfiguration at once, in ONE evaluation (each costs ~1 GB).
  bad = evalWith {
    router.hosts = hosts;
    router.ddns = {
      enable = true;
      names = [ "dup.example.com" ];
      cloudflare.apiTokenFile = "/etc/router/secrets/cloudflare-ddns.token";
    };
    router.acme.defaultChallenge = "http"; # no terms, no email, no token
    router.reverseProxy = {
      enable = true;
      routes = [
        {
          name = "ghost";
          hostnames = [ "ghost.example.com" ];
          host = "ghost";
        }
        {
          name = "no-static";
          hostnames = [ "laptop.example.com" ];
          host = "laptop";
        }
        {
          name = "wild-http";
          hostnames = [ "*.wild.example.com" ];
          host = "nas";
        }
        {
          name = "dns-no-token";
          hostnames = [ "dns.example.com" ];
          host = "nas";
          challenge = "dns-cloudflare";
        }
        {
          name = "bad-name";
          hostnames = [ "under_score.example.com" ];
          host = "nas";
        }
        {
          name = "dup-in-ddns";
          hostnames = [
            "dup.example.com"
            "twice.example.com"
          ];
          host = "nas";
        }
        {
          name = "dup-route";
          hostnames = [
            "TWICE.example.com"
            "nas.example.com"
          ];
          host = "nas";
        }
      ];
    };
    router.cloudflareTunnel = {
      enable = true; # and no token
      ingress = [
        {
          hostname = "home-tunnel.example.com";
          host = "ghost";
        }
        {
          hostname = "dns.example.com";
          host = "nas";
        }
        {
          hostname = "Home-Tunnel.example.com";
          host = "nas";
        }
      ];
    };
    router.portForwards = [
      {
        name = "web";
        host = "nas";
        family = "ipv4";
        ports = [ 443 ];
      }
    ];
  };
  badMessages = failedAssertions bad;
  rejects = name: want: {
    inherit name;
    ok = lib.any (lib.hasInfix want) badMessages;
    detail = "want an assertion containing '${want}', got: ${lib.concatStringsSep " | " badMessages}";
  };

  checks = [
    {
      name = "evaluates";
      ok = failedAssertions sys == [ ];
      detail = "assertions failed: ${lib.concatStringsSep " | " (failedAssertions sys)}";
    }

    # ── firewall ──
    {
      # Only traffic aimed at the router itself: a v6 pinhole to a host's own
      # address on 443 is routed, not local, and must not be captured.
      name = "wan-redirect-limited-to-local-addresses";
      ok =
        has ''iifname "${wan}" fib daddr type local tcp dport 443 redirect to :10443''
        && has ''iifname "${wan}" fib daddr type local tcp dport 80 redirect to :10080'';
      detail = "the WAN 80/443 redirect is missing or not limited to the router's own addresses";
    }
    {
      # The gateway addresses (the Block Page) are on the ingress interface,
      # so `fib daddr . iif type != local` must be part of the hairpin match.
      name = "hairpin-spares-gateway-addresses";
      ok = has ''iifname { "br-lan", "br-guest" } fib daddr type local fib daddr . iif type != local tcp dport 443 redirect to :10443'';
      detail = "the hairpin redirect is missing, misses guest, or would capture the gateway addresses";
    }
    {
      name = "input-accepts-only-redirected-flows";
      ok =
        has ''iifname "${wan}" tcp dport { 10080, 10443 } ct status dnat accept''
        && has ''iifname "br-guest" tcp dport { 10080, 10443 } ct status dnat accept'';
      detail = "the input chain does not admit the redirected proxy flows (WAN and guest)";
    }
    {
      name = "v6-forward-of-443-still-pinholed";
      ok = has "::42 tcp dport 443 ct state new accept";
      detail = "the IPv6-only forward of 443 lost its pinhole";
    }

    # ── certificates ──
    {
      name = "cert-per-route-named-after-first-hostname";
      ok =
        certs ? "cloud.example.com"
        && certs."cloud.example.com".extraDomainNames == [ "files.example.com" ]
        && certs ? "_.apps.example.com"
        && certs."_.apps.example.com".domain == "*.apps.example.com";
      detail = "certificates: ${builtins.toJSON (lib.attrNames certs)}";
    }
    {
      name = "http-challenge-uses-webroot";
      ok =
        certs."cloud.example.com".webroot == "/var/lib/acme/acme-challenge"
        && certs."cloud.example.com".dnsProvider == null;
      detail = "the http-01 certificate is not on the shared webroot";
    }
    {
      name = "dns-challenge-gets-token-by-credential";
      ok =
        certs."_.apps.example.com".dnsProvider == "cloudflare"
        &&
          certs."_.apps.example.com".credentialFiles == {
            CF_DNS_API_TOKEN_FILE = "/etc/router/secrets/cloudflare-ddns.token";
          };
      detail = "the dns-01 certificate does not use Cloudflare with the token file by credential";
    }
    {
      name = "cert-renewal-reloads-proxy";
      ok =
        certs."cloud.example.com".group == "router-proxy"
        && certs."cloud.example.com".reloadServices == [ "router-proxy.service" ];
      detail = "certificates are not readable by, or do not reload, router-proxy";
    }
    {
      name = "acme-account";
      ok = sys.security.acme.acceptTerms && sys.security.acme.defaults.email == "admin@example.com";
      detail = "router.acme did not reach security.acme";
    }

    # ── proxy ──
    {
      name = "proxy-listens-on-both-families";
      ok =
        proxyConfig.listen.https == [
          "0.0.0.0:10443"
          "[::]:10443"
        ];
      detail = "listen: ${builtins.toJSON proxyConfig.listen}";
    }
    {
      name = "proxy-route-to-host-static-ip";
      ok =
        let
          r = routeFor "cloud.example.com";
        in
        r != null
        && r.upstream == "10.48.4.2:8080"
        && !r.tls
        && r.cert.fullchain == "/var/lib/acme/cloud.example.com/fullchain.pem";
      detail = "route: ${builtins.toJSON (routeFor "cloud.example.com")}";
    }
    {
      name = "proxy-https-upstream-with-concrete-sni";
      ok =
        let
          r = routeFor "*.apps.example.com";
        in
        r != null && r.tls && r.hsts && r.sni == "*.apps.example.com";
      detail = "route: ${builtins.toJSON (routeFor "*.apps.example.com")}";
    }
    {
      name = "proxy-waits-for-certificates";
      ok = lib.elem "acme-cloud.example.com.service" proxyUnit.after;
      detail = "router-proxy is not ordered after its certificates' placeholder units";
    }
    {
      name = "proxy-hostnames-published-by-ddns";
      ok = lib.all (n: lib.elem n ddnsNames) [
        "home.example.com"
        "cloud.example.com"
        "files.example.com"
        "*.apps.example.com"
      ];
      detail = "ddns records: ${builtins.toJSON ddnsNames}";
    }

    # ── tunnel ──
    {
      name = "tunnel-named-after-router";
      ok = tunnel.credentialsFile == "/var/lib/router-cloudflared/credentials.json";
      detail = "services.cloudflared.tunnels.gw is missing or has the wrong credentials path";
    }
    {
      name = "tunnel-ingress";
      ok =
        tunnel.ingress."wiki.example.com".service == "http://10.48.4.3:3000"
        && tunnel.ingress."dsm.example.com".service == "https://10.48.4.2:5001"
        && tunnel.ingress."dsm.example.com".originRequest.noTLSVerify == true
        && tunnel.ingress."dsm.example.com".originRequest.httpHostHeader == "nas.lan"
        && tunnel.default == "http_status:404";
      detail = "ingress: ${builtins.toJSON (lib.mapAttrs (_: i: i.service) tunnel.ingress)}";
    }
    {
      name = "tunnel-provisioner-config";
      ok =
        tunnelConfig.enable
        && tunnelConfig.name == "gw"
        &&
          tunnelConfig.hostnames == [
            "wiki.example.com"
            "dsm.example.com"
          ];
      detail = "provisioner config: ${builtins.toJSON tunnelConfig}";
    }
    {
      name = "tunnel-token-by-credential";
      ok =
        tunnelUnit.serviceConfig.LoadCredential == [
          "cf-api-token:/etc/router/secrets/cloudflare-tunnel.token"
        ];
      detail = "router-cloudflare-tunnel does not receive the token through LoadCredential";
    }
    {
      name = "connector-ordered-after-provisioner";
      ok = lib.elem "router-cloudflare-tunnel.service" sys.systemd.services.cloudflared-tunnel-gw.after;
      detail = "cloudflared starts before its credentials file is written";
    }
    {
      name = "effective-json-carries-new-keys";
      ok =
        let
          eff = builtins.fromJSON (
            builtins.unsafeDiscardStringContext sys.environment.etc."router/effective.json".text
          );
        in
        eff ? acme && eff ? reverseProxy && eff ? cloudflareTunnel;
      detail = "effective.json lacks acme/reverseProxy/cloudflareTunnel";
    }
    {
      name = "system-toplevel-instantiates";
      ok = builtins.isString sys.system.build.toplevel.drvPath;
      detail = "the system closure does not instantiate";
    }

    (rejects "acme-terms" "router.acme.acceptTerms must be true")
    (rejects "acme-email" "router.acme.email must be set")
    (rejects "proxy-unknown-host" "route 'ghost' references unknown host 'ghost'")
    (rejects "proxy-needs-static-ip" "route 'no-static' proxies to host 'laptop', which has no staticIp")
    (rejects "wildcard-needs-dns" "route 'wild-http' has a wildcard hostname")
    (rejects "dns-needs-token" "route 'dns-no-token' uses the dns-cloudflare challenge")
    (rejects "proxy-hostname-valid" "route 'bad-name' has an invalid hostname")
    (rejects "proxy-vs-ddns" "dup.example.com is already published by router.reverseProxy.publishDns")
    (rejects "proxy-duplicate" "twice.example.com appears in more than one route")
    (rejects "proxy-vs-public-hostname" "nas.example.com is also a host's publicHostname")
    (rejects "proxy-owns-v4-web-ports" "'web' forwards IPv4 tcp 80/443, which the reverse proxy owns")
    (rejects "tunnel-needs-token" "router.cloudflareTunnel: enabled without")
    (rejects "tunnel-unknown-host" "'home-tunnel.example.com' references unknown host 'ghost'")
    (rejects "tunnel-duplicate" "duplicate hostname(s) home-tunnel.example.com")
    (rejects "tunnel-vs-proxy" "dns.example.com is also published by reverse proxy route 'dns-no-token'")
  ];

  failures = lib.filter (c: !c.ok) checks;
in
pkgs.runCommand "router-routing-eval" { } (
  if failures == [ ] then
    ''
      # Built for its checkPhase: `nft --check` over the generated ruleset.
      echo ${rulesScript} > /dev/null
      touch $out
    ''
  else
    ''
      echo "Hostname-ingress generation regressed:" >&2
      ${lib.concatMapStringsSep "\n" (f: ''
        echo "  FAIL ${f.name}" >&2
        echo ${lib.escapeShellArg "       ${f.detail}"} >&2
      '') failures}
      exit 1
    ''
)
