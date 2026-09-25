# NixOS VM test — the hostname-routing reverse proxy on the wire.
#
# tests/ingress-eval.nix pins what the generated config SAYS; this proves it
# works end to end, including the ACME path nothing else can exercise:
#
#   • HTTP-01 issuance: pebble (the ACME test CA, on the WAN node) validates
#     the route's name by fetching the challenge from WAN :80, which is
#     redirected to the proxy's HTTP listener and served from lego's webroot.
#   • HTTPS by name, over IPv4 and IPv6: the WAN client verifies the issued
#     certificate against pebble's root, so the proxy must send the full chain,
#     and the backend sees X-Forwarded-For/-Proto.
#   • HTTP → HTTPS redirect; an unknown name gets no certificate; the proxy's
#     own ports are not reachable directly from the WAN.
#   • Hairpin: a LAN client reaching the public name (the WAN address) gets
#     the proxy, while the gateway address keeps its own :443 — the Block
#     Page's in production, a stand-in listener here.
#   • A reload (what a renewal triggers) keeps the same process serving.
{
  pkgs,
  routerModule,
  baseSettings,
}:
let
  # Echoes the request's forwarding headers, so the client can see what the
  # backend received.
  echoServer = pkgs.writeText "echo.py" ''
    import http.server, json, socketserver

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({k.lower(): v for k, v in self.headers.items()}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
        pass

    S(("0.0.0.0", 8080), H).serve_forever()
  '';
in
pkgs.testers.runNixOSTest {
  name = "router-reverse-proxy";

  nodes.router =
    { lib, nodes, ... }:
    {
      imports = [ routerModule ];

      config = lib.mkMerge [
        { router = lib.mkDefault baseSettings; }

        {
          router.wan.interface = "eth1";
          router.wan.vlan = null;
          router.lan.interfaces = [ "eth2" ];
          router.lan.vlan = null;
          router.lan.taggedInterfaces = [ ];
          router.trunkInterfaces = [ ];
          router.guest.enable = false;
          # Keep the VM light: no Technitium/dotnet closure, no IPS.
          router.dns.technitium.enable = false;
          router.suricata.enable = false;
          router.cockpit.enable = false;

          router.hosts = [
            {
              mac = "02:00:00:00:00:42";
              name = "nas";
              staticIp = "10.48.4.2";
            }
          ];
          router.acme = {
            email = "hostmaster@example.test";
            acceptTerms = true;
            defaultChallenge = "http";
          };
          router.reverseProxy = {
            enable = true;
            publishDns = false;
            routes = [
              {
                name = "App";
                hostnames = [ "app.example.test" ];
                host = "nas";
                port = 8080;
              }
            ];
          };
        }

        {
          disko.enableConfig = lib.mkForce false;
          boot.loader.systemd-boot.enable = lib.mkForce false;
          boot.loader.grub.enable = lib.mkForce false;

          systemd.network.networks."10-wan".address = [
            "203.0.113.1/24"
            "2001:db8:ffff::1/64"
          ];

          # The test CA instead of Let's Encrypt, trusted by lego.
          security.acme.defaults.server = "https://acme.test/dir";
          security.pki.certificateFiles = [ nodes.acme.test-support.acme.caCert ];
          networking.hosts = lib.mkForce { "203.0.113.2" = [ "acme.test" ]; };

          virtualisation = {
            vlans = [
              1
              2
            ]; # eth1 = WAN, eth2 = LAN
            memorySize = 1536;
          };
          environment.systemPackages = [
            pkgs.iproute2
            pkgs.python3
            pkgs.curl
            pkgs.conntrack-tools
          ];
        }
      ];
    };

  # The internet: the ACME CA, and the client of the public name.
  nodes.acme =
    { lib, ... }:
    {
      imports = [ "${pkgs.path}/nixos/tests/common/acme/server" ];
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 768;
      networking.useDHCP = false;
      networking.interfaces.eth1 = {
        ipv4.addresses = lib.mkForce [
          {
            address = "203.0.113.2";
            prefixLength = 24;
          }
        ];
        ipv6.addresses = lib.mkForce [
          {
            address = "2001:db8:ffff::2";
            prefixLength = 64;
          }
        ];
      };
      # The route's public name is the router's WAN address — what DDNS would
      # publish. Pebble's HTTP-01 validation resolves it here too.
      networking.hosts = lib.mkForce {
        "203.0.113.1" = [ "app.example.test" ];
        "203.0.113.2" = [ "acme.test" ];
      };
      networking.firewall.enable = false;
      environment.systemPackages = [ pkgs.curl ];
    };

  testScript = ''
    import json

    start_all()
    router.wait_for_unit("multi-user.target")
    acme.wait_for_unit("pebble.service")
    router.wait_until_succeeds("ip -4 addr show eth1 | grep -q 203.0.113.1/24", timeout=60)

    # The backend: a netns on br-lan at the host's staticIp.
    router.succeed("ip netns add nas")
    router.succeed("ip link add nas-c type veth peer name nas-br")
    router.succeed("ip link set nas-br master br-lan up")
    router.succeed("ip link set nas-c netns nas")
    router.succeed("ip -n nas link set lo up")
    router.succeed("ip -n nas addr add 10.48.4.2/24 dev nas-c")
    router.succeed("ip -n nas link set nas-c up")
    router.succeed("ip -n nas route add default via 10.48.4.1")
    router.succeed("ip netns exec nas python3 ${echoServer} >/dev/null 2>&1 &")
    router.wait_until_succeeds("ip netns exec nas ss -ltn | grep -q ':8080'")

    # A LAN client, for the hairpin.
    router.succeed("ip netns add lan")
    router.succeed("ip link add lan-c type veth peer name lan-br")
    router.succeed("ip link set lan-br master br-lan up")
    router.succeed("ip link set lan-c netns lan")
    router.succeed("ip -n lan link set lo up")
    router.succeed("ip -n lan addr add 10.48.4.50/24 dev lan-c")
    router.succeed("ip -n lan link set lan-c up")
    router.succeed("ip -n lan route add default via 10.48.4.1")

    router.wait_for_unit("router-proxy.service")

    with subtest("HTTP-01 issuance through the WAN :80 redirect"):
        router.wait_until_succeeds(
            "systemctl start acme-order-renew-app.example.test.service", timeout=180
        )
        router.succeed("test -e /var/lib/acme/app.example.test/acme-success")
        # The renewal hook reloads the proxy; give it a moment, then trust
        # pebble's (per-run) root for the client checks below.
        router.wait_until_succeeds(
            "journalctl -u router-proxy.service | grep -qi reload", timeout=30
        )
        acme.succeed("curl -skf https://localhost:15000/roots/0 > /tmp/root.pem")
        router.succeed("curl -skf https://acme.test:15000/roots/0 > /tmp/root.pem")

    def fetch(url, extra=""):
        return acme.succeed(f"curl -gsSf --max-time 10 --cacert /tmp/root.pem {extra} {url}")

    with subtest("HTTPS by name over IPv4, full chain, forwarding headers"):
        headers = json.loads(fetch("https://app.example.test/"))
        print(headers)
        assert headers["x-forwarded-for"] == "203.0.113.2", headers
        assert headers["x-forwarded-proto"] == "https", headers
        assert headers["host"] == "app.example.test", headers

    with subtest("client-supplied forwarding headers do not reach the backend"):
        # The router is the edge: what the client claims about itself is
        # replaced, not appended to.
        headers = json.loads(
            fetch(
                "https://app.example.test/",
                "-H 'X-Forwarded-For: 6.6.6.6' -H 'X-Real-IP: 6.6.6.6' "
                "-H 'Forwarded: for=6.6.6.6' -H 'X-Forwarded-Host: evil.test'",
            )
        )
        assert headers["x-forwarded-for"] == "203.0.113.2", headers
        assert headers["x-real-ip"] == "203.0.113.2", headers
        assert headers["x-forwarded-host"] == "app.example.test", headers
        assert "forwarded" not in headers, headers

    with subtest("HTTPS by name over IPv6"):
        headers = json.loads(
            fetch("https://app.example.test/", "--resolve app.example.test:443:[2001:db8:ffff::1]")
        )
        assert headers["x-forwarded-for"] == "2001:db8:ffff::2", headers

    with subtest("HTTP redirects to HTTPS"):
        out = acme.succeed(
            "curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://app.example.test/x?y=1"
        )
        assert out == "308 https://app.example.test/x?y=1", out

    with subtest("an unknown name gets no certificate"):
        acme.fail(
            "curl -sk --max-time 5 --resolve other.example.test:443:203.0.113.1 https://other.example.test/"
        )

    with subtest("the proxy's own ports are closed to the WAN"):
        acme.fail("curl -sk --max-time 5 https://203.0.113.1:10443/")
        acme.fail("curl -s --max-time 5 http://203.0.113.1:10080/")

    with subtest("hairpin: the public name from the LAN, the gateway left alone"):
        headers = json.loads(
            router.succeed(
                "ip netns exec lan curl -sSf --max-time 10 --cacert /tmp/root.pem "
                "--resolve app.example.test:443:203.0.113.1 https://app.example.test/"
            )
        )
        assert headers["x-forwarded-for"] == "10.48.4.50", headers
        # Stand-in for the Block Page on the gateway address's :443.
        router.succeed("python3 -m http.server 443 --bind 10.48.4.1 >/dev/null 2>&1 &")
        router.wait_until_succeeds("ss -ltn | grep -q '10.48.4.1:443'")
        router.succeed("ip netns exec lan curl -sf --max-time 5 http://10.48.4.1:443/ >/dev/null")

    with subtest("a reload keeps the same process serving"):
        pid = router.succeed("systemctl show -p MainPID --value router-proxy.service").strip()
        router.succeed("systemctl reload router-proxy.service")
        fetch("https://app.example.test/")
        assert router.succeed("systemctl show -p MainPID --value router-proxy.service").strip() == pid
  '';
}
