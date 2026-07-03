# NixOS VM test — Technitium access-protection stack end-to-end.
#
# Boots the router with the full new stack (Technitium + Advanced Blocking +
# Log Exporter + Block Page, router-logd, reporting) and verifies, hermetically
# (no internet — test policies use only static blockDomains, no list URLs):
#   • first-boot env seeding + app pre-seeding + reconcile all succeed;
#   • the new router.* sections surface in /etc/router/effective.json;
#   • DHCP reservations render as [DHCPServerStaticLease] networkd sections;
#   • policy precedence end-to-end via dig from netns "LAN clients":
#       - pinned device in a host group → its group policy (NXDOMAIN),
#       - directory-group tier activates after a directory sync + policy push,
#       - unpinned client → the default policy (block page address answer);
#   • the Log Exporter → router-logd ingest pipeline records the blocked query
#     WITH group attribution;
#   • the block page is served and the exception-request portal round-trips;
#   • a report service produces a PDF offline (Typst).
{
  pkgs,
  routerModule,
  baseSettings,
}:
pkgs.testers.runNixOSTest {
  name = "router-technitium";

  nodes.router =
    { lib, ... }:
    {
      imports = [ routerModule ];

      config = lib.mkMerge [
        { router = lib.mkDefault baseSettings; }

        {
          router.wan.interface = "eth1";
          router.lan.interfaces = [ "eth2" ];
          router.guest.enable = false;
          router.cockpit.enable = true;
          router.suricata.enable = false;

          router.hostGroups = [
            {
              name = "Kids";
              description = "restricted devices";
            }
          ];
          router.hosts = [
            {
              mac = "aa:bb:cc:dd:ee:01";
              name = "lab-1";
              staticIp = "10.48.4.50";
              network = "lan";
              group = "Kids";
            }
            {
              mac = "aa:bb:cc:dd:ee:02";
              name = "jdoe-laptop";
              staticIp = "10.48.4.60";
              network = "lan";
              user = "jdoe@test";
            }
          ];

          # Hermetic policies: static domains only, no list downloads.
          router.accessPolicies = {
            defaultPolicy = "Base";
            blockPage = {
              enable = true;
              heading = "VM-TEST Blocked";
            };
            policies = [
              {
                name = "Base";
                blockDomains = [ "lan-blocked.test" ];
                responseType = "blockingAddress";
              }
              {
                name = "Strict";
                priority = 10;
                blockDomains = [ "kids-blocked.test" ];
                responseType = "nxdomain";
                assignments = {
                  hostGroups = [ "Kids" ];
                  directoryGroups = [ "Students" ];
                };
              }
            ];
          };

          router.reporting.schedules = [
            {
              name = "vmtest";
              frequency = "daily";
              sections = [
                "overview"
                "topBlocked"
                "perGroup"
              ];
            }
          ];
        }

        # Test-only overrides: disko/bootloader are for real hardware.
        {
          disko.enableConfig = lib.mkForce false;
          boot.loader.systemd-boot.enable = lib.mkForce false;
          boot.loader.grub.enable = lib.mkForce false;

          virtualisation = {
            vlans = [
              1
              2
            ]; # eth1 = WAN, eth2 = LAN
            memorySize = 3072;
            cores = 2;
          };
          environment.systemPackages = [
            pkgs.iproute2
            pkgs.dnsutils
            pkgs.curl
            pkgs.jq
          ];
        }
      ];
    };

  testScript = ''
    import json

    start_all()
    router.wait_for_unit("multi-user.target")

    with subtest("technitium + reconcile + logd come up"):
        router.wait_for_unit("technitium-dns-server.service")
        router.wait_until_succeeds(
            "curl -s -o /dev/null http://127.0.0.1:5380/api/user/login", timeout=180
        )
        # oneshot with RemainAfterExit: active == reconcile succeeded
        router.wait_for_unit("technitium-reconcile.service", timeout=300)
        router.wait_for_unit("router-logd.service")
        router.wait_until_succeeds("curl -s http://127.0.0.1:8067/healthz | grep -q true")

    with subtest("new sections reach /etc/router/effective.json"):
        eff = json.loads(router.succeed("cat /etc/router/effective.json"))
        assert eff["accessPolicies"]["defaultPolicy"] == "Base", eff["accessPolicies"]
        assert any(h["name"] == "lab-1" for h in eff["hosts"]), eff["hosts"]
        assert eff["reporting"]["retentionDays"] > 0, eff["reporting"]

    with subtest("DHCP reservations render as networkd static leases"):
        unit = router.succeed("cat /etc/systemd/network/40-br-lan.network")
        assert "DHCPServerStaticLease" in unit, unit
        assert "aa:bb:cc:dd:ee:01" in unit and "10.48.4.50" in unit, unit

    with subtest("cockpit token + logd tokens are provisioned 0600"):
        for f in [
            "/var/lib/cockpit-router/technitium-token",
            "/var/lib/router-technitium/logd-query.token",
        ]:
            assert router.succeed(f"stat -c %a {f}").strip() == "600", f

    # ── netns LAN clients ────────────────────────────────────
    def add_client(name, ip):
        router.succeed(f"ip netns add {name}")
        router.succeed(f"ip link add veth-{name} type veth peer name vbr-{name}")
        router.succeed(f"ip link set vbr-{name} master br-lan up")
        router.succeed(f"ip link set veth-{name} netns {name}")
        router.succeed(f"ip -n {name} link set lo up")
        router.succeed(f"ip -n {name} addr add {ip}/24 dev veth-{name}")
        router.succeed(f"ip -n {name} link set veth-{name} up")
        router.succeed(f"ip -n {name} route add default via 10.48.4.1")

    router.wait_until_succeeds("ip -4 addr show br-lan | grep -qw 10.48.4.1", timeout=60)
    add_client("kid", "10.48.4.50")      # registry: group Kids → Strict
    add_client("jdoe", "10.48.4.60")     # registry: user jdoe@test (no group)
    add_client("guestpc", "10.48.4.99")  # unregistered → Base (default)

    dig = "ip netns exec {ns} dig +time=3 +tries=1 @10.48.4.1 {name}"

    with subtest("host-group tier: Kids device gets Strict (NXDOMAIN)"):
        out = router.wait_until_succeeds(
            dig.format(ns="kid", name="kids-blocked.test"), timeout=60
        )
        assert "NXDOMAIN" in out, out

    with subtest("default tier: unregistered client gets Base (block page address)"):
        out = router.succeed(dig.format(ns="guestpc", name="lan-blocked.test"))
        assert "10.48.4.1" in out, out
        # exactly-one-group check: Base does NOT block Strict's domain
        out = router.succeed(dig.format(ns="kid", name="lan-blocked.test"))
        assert "NXDOMAIN" not in out or "10.48.4.1" not in out, out

    with subtest("directory tier activates after sync + policy push"):
        # jdoe has no directory data yet → kids-blocked.test resolves via Base (not blocked)
        directory = {
            "users": [{"id": "u1", "name": "J Doe", "email": "jdoe@test", "groups": ["g1"]}],
            "groups": [{"id": "g1", "name": "Students"}],
            "syncedAt": "2026-01-01T00:00:00Z",
        }
        router.succeed("mkdir -p /var/lib/router-directory")
        router.succeed(
            "cat > /var/lib/router-directory/directory.json <<'EOF'\n"
            + json.dumps(directory)
            + "\nEOF"
        )
        router.succeed("systemctl start router-policy-push.service")
        out = router.wait_until_succeeds(
            dig.format(ns="jdoe", name="kids-blocked.test") + " | grep NXDOMAIN", timeout=60
        )

    with subtest("blocked queries land in router-logd with group attribution"):
        token = router.succeed("cat /var/lib/router-technitium/logd-query.token").strip()
        entry = router.wait_until_succeeds(
            f"curl -s -H 'Authorization: Bearer {token}' "
            "'http://127.0.0.1:8067/logs?blocked=1&client=10.48.4.50' "
            "| jq -e '.entries[0]'",
            timeout=120,
        )
        parsed = json.loads(entry)
        assert parsed["host_group"] == "Kids", parsed
        assert parsed["policy"] == "Strict", parsed

    with subtest("block page is served with the branded wwwroot"):
        page = router.succeed("ip netns exec guestpc curl -s http://10.48.4.1/")
        assert "VM-TEST Blocked" in page, page[:500]

    with subtest("exception-request portal round-trips"):
        router.succeed(
            "ip netns exec kid curl -s -X POST "
            "-d 'domain=kids-blocked.test&reason=needed for class' "
            "http://10.48.4.1:8067/portal/request-exception | grep -qi 'request submitted'"
        )
        token = router.succeed("cat /var/lib/router-technitium/logd-query.token").strip()
        reqs = json.loads(
            router.succeed(
                f"curl -s -H 'Authorization: Bearer {token}' http://127.0.0.1:8067/portal/requests"
            )
        )["requests"]
        assert any(
            r["domain"] == "kids-blocked.test" and r["device"] == "lab-1" for r in reqs
        ), reqs

    with subtest("a report PDF is generated offline"):
        router.succeed("systemctl start router-report-vmtest.service")
        out = router.succeed("ls /var/lib/router-reports/")
        assert ".pdf" in out, out

    with subtest("cockpit router plugin is installed with the new pages"):
        manifest = "/etc/cockpit/share/cockpit/router/manifest.json"
        router.succeed(f"test -f {manifest}")
        router.succeed(f"grep -q access-policies {manifest}")
  '';
}
