# NixOS VM test — host-based port forwards on the wire, and dynamic DNS.
#
# tests/port-forwards-eval.nix pins what the generated rules SAY; this proves
# they do what they say to real packets, over both families:
#
#   • IPv4: a WAN client connecting to the router's public address is DNAT'd to
#     the host's staticIp; a port nobody forwards stays closed.
#   • IPv6: no NAT — the client connects to the host's own global address, and
#     the pinhole admits exactly that host (by its interface ID) on exactly the
#     forwarded port. A neighbour on the same /64 stays unreachable.
#   • `sources` restricts each family on its own: an IPv4-only source list
#     admits the matching IPv4 client and keeps the IPv6 half closed.
#   • router-ddns publishes A/AAAA for the router and for a host's public name
#     into a fake Cloudflare API on the WAN node, computing the host's AAAA from
#     the LAN bridge's /64 plus its suffix — and a second run with nothing
#     changed makes no write calls at all.
#
# No real prefix delegation happens in a VM, so the addresses a delegation
# would produce are assigned statically: 2001:db8:ffff::/64 on the WAN link,
# 2001:db8:4::/64 on br-lan, routed to the router by the WAN node as an ISP
# would route a delegated prefix.
{
  pkgs,
  routerModule,
  baseSettings,
}:
let
  # Just enough of the Cloudflare v4 API for router-ddns: zone lookup and
  # dns_records list/create/patch/delete, in memory. GET /__state exposes the
  # records and the write count to the test script.
  fakeCloudflare = pkgs.writeText "fake-cloudflare.py" ''
    import json, itertools
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs

    ZONE = {"id": "zone-1", "name": "example.com"}
    records = {}
    ids = itertools.count(1)
    writes = 0

    class H(BaseHTTPRequestHandler):
        def reply(self, result, code=200, success=True, errors=()):
            body = json.dumps({"success": success, "errors": [{"message": e} for e in errors], "result": result}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def authorized(self):
            if self.headers.get("Authorization") != "Bearer test-token":
                self.reply(None, 403, False, ["bad token"])
                return False
            return True

        def body(self):
            return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")

        def do_GET(self):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            if u.path == "/__state":
                return self.reply({"records": list(records.values()), "writes": writes})
            if not self.authorized():
                return
            if u.path == "/client/v4/zones":
                return self.reply([ZONE] if q.get("name") == ZONE["name"] else [])
            if u.path == "/client/v4/zones/zone-1/dns_records":
                return self.reply([
                    r for r in records.values()
                    if r["name"] == q.get("name") and r["type"] == q.get("type")
                ])
            self.reply(None, 404, False, ["not found"])

        def do_POST(self):
            global writes
            if not self.authorized():
                return
            writes += 1
            rec = dict(self.body(), id=f"rec-{next(ids)}")
            records[rec["id"]] = rec
            self.reply(rec)

        def do_PATCH(self):
            global writes
            if not self.authorized():
                return
            writes += 1
            rid = self.path.rsplit("/", 1)[1]
            records[rid].update(self.body())
            self.reply(records[rid])

        def do_DELETE(self):
            global writes
            if not self.authorized():
                return
            writes += 1
            rid = self.path.rsplit("/", 1)[1]
            records.pop(rid, None)
            self.reply({"id": rid})

    ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
  '';
in
pkgs.testers.runNixOSTest {
  name = "router-port-forwards";

  nodes.router =
    { lib, ... }:
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
              ipv6Suffix = "::42";
              publicHostname = "nas.example.com";
            }
          ];
          router.portForwards = [
            {
              name = "web";
              host = "nas";
              ports = [ 8080 ];
            }
            {
              # IPv4-only source list: the WAN client matches it over IPv4, and
              # the IPv6 half must stay closed.
              name = "ssh-v4-only";
              host = "nas";
              ports = [ 2222 ];
              sources = [ "203.0.113.2/32" ];
            }
            {
              name = "ssh-elsewhere";
              host = "nas";
              ports = [ 2223 ];
              sources = [
                "198.51.100.0/24"
                "2001:db8:dead::/48"
              ];
            }
          ];

          router.ddns = {
            enable = true;
            names = [ "home.example.com" ];
            cloudflare.apiTokenFile = "/etc/router/secrets/cloudflare-ddns.token";
          };
        }

        {
          disko.enableConfig = lib.mkForce false;
          boot.loader.systemd-boot.enable = lib.mkForce false;
          boot.loader.grub.enable = lib.mkForce false;

          # What prefix delegation would have produced (see header).
          systemd.network.networks."10-wan".address = [
            "203.0.113.1/24"
            "2001:db8:ffff::1/64"
          ];
          systemd.network.networks."40-br-lan".address = [ "2001:db8:4::1/64" ];

          environment.etc."router/secrets/cloudflare-ddns.token" = {
            text = "test-token";
            mode = "0600";
          };
          systemd.services.router-ddns.environment.ROUTER_DDNS_API_BASE = "http://203.0.113.2:8000/client/v4";

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
            pkgs.conntrack-tools
          ];
        }
      ];
    };

  # The internet: a client of the forwards, the upstream router for the
  # "delegated" LAN prefix, and the fake Cloudflare API.
  nodes.wan =
    { lib, ... }:
    {
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 512;
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
        ipv6.routes = [
          {
            address = "2001:db8:4::";
            prefixLength = 64;
            via = "2001:db8:ffff::1";
          }
        ];
      };
      networking.firewall.enable = false;
      environment.systemPackages = [ pkgs.curl ];

      systemd.services.fake-cloudflare = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${fakeCloudflare}";
      };
    };

  testScript = ''
    import json

    start_all()
    router.wait_for_unit("multi-user.target")
    wan.wait_for_unit("fake-cloudflare.service")
    wan.wait_for_open_port(8000)

    router.wait_until_succeeds("ip -6 addr show br-lan | grep -q 2001:db8:4::1/64", timeout=60)
    router.wait_until_succeeds("ip -4 addr show eth1 | grep -q 203.0.113.1/24", timeout=60)

    def mk_host(ns, v4, v6):
        """A netns standing in for a LAN host, statically addressed on br-lan,
        serving HTTP on the forwarded ports and one that is never forwarded."""
        router.succeed(f"ip netns add {ns}")
        router.succeed(f"ip link add {ns}-c type veth peer name {ns}-br")
        router.succeed(f"ip link set {ns}-br master br-lan up")
        router.succeed(f"ip link set {ns}-c netns {ns}")
        router.succeed(f"ip -n {ns} link set lo up")
        router.succeed(f"ip -n {ns} addr add {v4}/24 dev {ns}-c")
        router.succeed(f"ip -n {ns} addr add {v6}/64 dev {ns}-c nodad")
        router.succeed(f"ip -n {ns} link set {ns}-c up")
        router.succeed(f"ip -n {ns} route add default via 10.48.4.1")
        router.succeed(f"ip -n {ns} -6 route add default via 2001:db8:4::1")
        for port in (8080, 2222, 2223, 9999):
            # --bind :: is dual-stack, so one listener answers both families.
            router.succeed(
                f"ip netns exec {ns} python3 -m http.server {port} --bind :: >/dev/null 2>&1 &"
            )
        router.wait_until_succeeds(f"ip netns exec {ns} ss -ltn | grep -q ':9999'")

    mk_host("nas", "10.48.4.2", "2001:db8:4::42")
    # Same /64, different interface ID: the pinhole must not admit it.
    mk_host("other", "10.48.4.3", "2001:db8:4::43")

    def reach(url):
        router.succeed("conntrack -F 2>/dev/null || true")
        rc, _ = wan.execute(f"curl -gsf --max-time 5 -o /dev/null {url}")
        return rc == 0

    matrix = {
        # url: expected reachability
        "http://203.0.113.1:8080/": True,          # IPv4 DNAT to nas
        "http://203.0.113.1:9999/": False,         # never forwarded
        "http://[2001:db8:4::42]:8080/": True,     # IPv6 pinhole to nas
        "http://[2001:db8:4::42]:9999/": False,    # nas, port not forwarded
        "http://[2001:db8:4::43]:8080/": False,    # neighbour on the same /64
        "http://203.0.113.1:2222/": True,          # IPv4 source matches
        "http://[2001:db8:4::42]:2222/": False,    # IPv4-only sources: IPv6 closed
        "http://203.0.113.1:2223/": False,         # IPv4 source does not match
        "http://[2001:db8:4::42]:2223/": False,    # IPv6 source does not match
    }

    with subtest("forwards admit exactly what they declare, per family"):
        wrong = []
        for url, want in matrix.items():
            got = reach(url)
            print(f"{url:36} reachable={got} (want {want})")
            if got != want:
                wrong.append(f"{url}: reachable={got}, want {want}")
        assert not wrong, "\n  - " + "\n  - ".join(wrong)

    def cf_state():
        return json.loads(wan.succeed("curl -sf http://127.0.0.1:8000/__state"))["result"]

    def published():
        return {(r["name"], r["type"]): r["content"] for r in cf_state()["records"]}

    want_records = {
        ("home.example.com", "A"): "203.0.113.1",
        ("home.example.com", "AAAA"): "2001:db8:ffff::1",
        ("nas.example.com", "A"): "203.0.113.1",
        ("nas.example.com", "AAAA"): "2001:db8:4::42",
    }

    with subtest("router-ddns publishes the router's and the host's addresses"):
        # The boot-time run may have raced the fake API; retry until it lands.
        router.wait_until_succeeds("systemctl start router-ddns.service", timeout=120)
        got = published()
        assert got == want_records, f"published {got}, want {want_records}"
        records = cf_state()["records"]
        assert all(r.get("comment") == "managed by nixos-router" for r in records), records
        status = json.loads(router.succeed("cat /var/lib/router-ddns/status.json"))
        assert status["ok"], status

    with subtest("a run with nothing changed writes nothing"):
        before = cf_state()["writes"]
        router.succeed("systemctl start router-ddns.service")
        after = cf_state()["writes"]
        assert after == before, f"{after - before} write(s) with nothing changed"

    with subtest("a full re-verify repairs drift"):
        # Change a record behind the tool's back, then drop its state so the
        # next run cannot trust its cache (as happens every 6 h anyway).
        rid = next(r["id"] for r in cf_state()["records"] if r["name"] == "nas.example.com" and r["type"] == "A")
        wan.succeed(
            "curl -sf -X PATCH -H 'Authorization: Bearer test-token' "
            f"-d '{{\"content\": \"198.51.100.9\"}}' http://127.0.0.1:8000/client/v4/zones/zone-1/dns_records/{rid}"
        )
        router.succeed("rm /var/lib/private/router-ddns/state.json")
        router.succeed("systemctl start router-ddns.service")
        assert published() == want_records, published()
  '';
}
