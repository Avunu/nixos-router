# NixOS VM test — Suricata IPS basic functionality.
#
# Boots the router module with Suricata enabled (IPS mode plus a few category /
# signature / suppression policies) and verifies, at runtime:
#   • the service starts hermetically — no internet, suricata-update masked;
#   • the new router.suricata.* options surface in /etc/router/effective.json
#     (the file the Cockpit IPS views read);
#   • the Cockpit plugin is installed;
#   • forwarded traffic matching a rule produces an alert that lands in journald
#     as EVE JSON under SYSLOG_IDENTIFIER=suricata — the exact path the Events /
#     Overview / Statistics tabs consume, and a real check that eve→stdout→journald
#     works under the suricata service's systemd hardening (PrivateDevices, which
#     blocks the /dev/log socket that filetype "syslog" would need).
#
# The "LAN client" is a network namespace wired into the LAN bridge, so the whole
# round-trip runs on a single node: its ping is routed out a dummy egress, which
# means it is *forwarded* through the router's NFQUEUE (the unconditional
# `queue num 0 bypass` rule at the top of the forward chain) and inspected.
{
  pkgs,
  routerModule,
  baseSettings,
}:
pkgs.testers.runNixOSTest {
  name = "router-suricata";

  nodes.router =
    { lib, pkgs, ... }:
    {
      imports = [ routerModule ];

      config = lib.mkMerge [
        # A complete, valid router config as the baseline (mkDefault so the
        # test-specific values below win), mirroring local/flake.nix.
        { router = lib.mkDefault baseSettings; }

        # Settings under test, plus trims that keep the VM hermetic and light.
        {
          router.wan.interface = "eth1";
          router.lan.interfaces = [ "eth2" ];
          router.guest.enable = false;
          router.dns.adguard.enable = false;
          router.cockpit.enable = true;
          router.suricata = {
            enable = true;
            mode = "ips";
            categories = {
              "emerging-malware.rules" = "drop";
              "emerging-pop3.rules" = "disabled";
            };
            policies = [
              {
                sid = 2013028;
                action = "drop";
                comment = "test";
              }
              {
                sid = 2019401;
                action = "disable";
              }
            ];
            suppressions = [
              {
                sid = 2100498;
                ip = "10.48.4.9";
                track = "by_src";
              }
            ];
            # A trivial rule on forwarded ICMP echo, used to drive the round-trip.
            extraRules = ''
              alert icmp any any -> any any (msg:"VM-TEST ICMP forwarded"; itype:8; sid:9000001; rev:1;)
            '';
          };
        }

        # Test-only overrides: disko / bootloader are for real hardware (the test
        # driver supplies the VM root fs); suricata-update needs the internet.
        {
          disko.enableConfig = lib.mkForce false;
          boot.loader.systemd-boot.enable = lib.mkForce false;
          boot.loader.grub.enable = lib.mkForce false;

          systemd.services.suricata-update.enable = lib.mkForce false;
          systemd.timers.suricata-update.enable = lib.mkForce false;
          # Load only the local rules (which carry the test signature); the
          # suricata-update-managed suricata.rules is absent without internet.
          services.suricata.settings.rule-files = lib.mkForce [
            "/etc/suricata/rules/local.rules"
          ];
          # suricata-update normally installs classification.config into the rules
          # dir; without it (masked here) use the copy bundled in the package.
          services.suricata.settings.classification-file = lib.mkForce "${pkgs.suricata}/etc/suricata/classification.config";

          virtualisation = {
            vlans = [
              1
              2
            ]; # eth1 = WAN, eth2 = LAN
            memorySize = 2048;
            cores = 2;
          };
          environment.systemPackages = [
            pkgs.iproute2
            pkgs.iputils
          ];
        }
      ];
    };

  testScript = ''
    import json

    start_all()
    router.wait_for_unit("multi-user.target")
    router.wait_for_unit("suricata.service")

    with subtest("new suricata options reach /etc/router/effective.json"):
        eff = json.loads(router.succeed("cat /etc/router/effective.json"))
        s = eff["suricata"]
        assert s["mode"] == "ips", s
        assert s["categories"]["emerging-malware.rules"] == "drop", s
        assert any(p["sid"] == 2013028 and p["action"] == "drop" for p in s["policies"]), s
        assert any(p["sid"] == 2100498 for p in s["suppressions"]), s

    with subtest("cockpit router plugin is installed"):
        # NixOS exposes cockpit plugins under /etc/cockpit/share/cockpit/.
        manifest = "/etc/cockpit/share/cockpit/router/manifest.json"
        router.succeed(f"test -f {manifest}")
        # The Suricata/IPS views live on the "threat-protection" menu page.
        router.succeed(f"grep -q threat-protection {manifest}")

    with subtest("LAN bridge is up"):
        router.wait_until_succeeds("ip -4 addr show br-lan | grep -qw 10.48.4.1", timeout=60)

    with subtest("forwarded traffic alerts and reaches the suricata journal namespace"):
        # A netns stands in for a LAN host; its frames enter the LAN bridge.
        router.succeed("ip netns add lanclient")
        router.succeed("ip link add veth-c type veth peer name veth-br")
        router.succeed("ip link set veth-br master br-lan up")
        router.succeed("ip link set veth-c netns lanclient")
        router.succeed("ip -n lanclient link set lo up")
        router.succeed("ip -n lanclient addr add 10.48.4.50/24 dev veth-c")
        router.succeed("ip -n lanclient link set veth-c up")
        router.succeed("ip -n lanclient route add default via 10.48.4.1")
        # A dummy egress gives the whole 203.0.113.0/24 a route, so pings to it are
        # *forwarded* (through the NFQUEUE) rather than rejected as unroutable.
        router.succeed("ip link add dummywan type dummy")
        router.succeed("ip addr add 203.0.113.1/24 dev dummywan")
        router.succeed("ip link set dummywan up")
        # Wait until suricata has loaded its rules and attached to the NFQUEUE —
        # the `queue ... bypass` flag lets packets pass uninspected until then.
        router.wait_until_succeeds(
            "journalctl --namespace suricata --no-pager -o cat | grep -q 'Engine started'",
            timeout=180,
        )
        # Generate sustained forwarded ICMP, then check the journal. (Suricata may
        # bypass a flow after its first inspected packet, so a steady stream over
        # time reliably gets at least one packet inspected.)
        # execute (not succeed): the pings get no reply, so the loop's exit code
        # is nonzero — that's expected, we only care that the packets were sent.
        router.execute(
            "for i in $(seq 1 15); do "
            "ip netns exec lanclient ping -c1 -W1 203.0.113.2 >/dev/null 2>&1; sleep 1; done"
        )
        # The UI reads `journalctl --namespace suricata` (the unbuffered EVE stream).
        router.wait_until_succeeds(
            "journalctl --namespace suricata --no-pager -o cat "
            "| grep -q 'VM-TEST ICMP forwarded'",
            timeout=30,
        )

    with subtest("the event is valid EVE JSON the UI can parse"):
        # Mirrors suricata-events.ts: `journalctl --namespace suricata -o json`,
        # then parse each entry's MESSAGE as the EVE record.
        rec = json.loads(
            router.succeed(
                "journalctl --namespace suricata --no-pager -o json "
                "| grep 'VM-TEST ICMP forwarded' | head -n1"
            )
        )
        ev = json.loads(rec["MESSAGE"])
        assert ev["event_type"] in ("alert", "drop"), ev
        assert ev["alert"]["signature"] == "VM-TEST ICMP forwarded", ev
        assert ev["src_ip"] == "10.48.4.50", ev
  '';
}
