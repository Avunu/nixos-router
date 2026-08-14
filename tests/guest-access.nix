# NixOS VM test — LAN ↔ guest segmentation across the forward chain.
#
# The guest network is meant to be one-way: a LAN host may open a connection to
# a guest host (administration), a guest host may only answer one. Both halves
# ride the `inet filter` forward chain, and this test is the regression guard on
# the ordering bug that used to defeat it: `queue num 0 bypass` sat at the TOP of
# that policy-drop chain, and `queue` is a terminal statement, so every rule
# below it — including the drop policy — was dead code whenever Suricata was
# enabled. Guest hosts could open connections straight into the LAN.
#
# Both directions are therefore asserted twice, once with Suricata attached to
# the queue and once with it stopped, because the two failure modes are distinct
# and each alone reproduces the hole: attached, netfilter reinjects an accepted
# packet at the next registered HOOK rather than the next rule; stopped,
# `bypass` accepts it inline. The fix — the queue in its own `inet ips` table at
# priority filter+10 — has to hold in both states.
#
# LAN and guest hosts are network namespaces wired into br-lan / br-guest, so
# the whole round-trip runs on a single node and every packet between them is
# genuinely *forwarded* through the chain under test.
{
  pkgs,
  routerModule,
  baseSettings,
}:
pkgs.testers.runNixOSTest {
  name = "router-guest-access";

  nodes.router =
    { lib, pkgs, ... }:
    {
      imports = [ routerModule ];

      config = lib.mkMerge [
        { router = lib.mkDefault baseSettings; }

        {
          router.wan.interface = "eth1";
          router.lan.interfaces = [ "eth2" ];
          router.lan.vlan = null;
          router.lan.taggedInterfaces = [ ];
          # Untagged guest port, so br-guest is a plain bridge over eth3 — the
          # VLAN plumbing is a separate concern from the forward-chain rules.
          router.guest = {
            enable = true;
            interfaces = [ "eth3" ];
            vlan = null;
            taggedInterfaces = [ ];
          };
          # Keep the VM light: no Technitium/dotnet closure in a firewall test.
          router.dns.technitium.enable = false;
          router.cockpit.enable = false;
          router.suricata = {
            enable = true;
            mode = "ips";
            # A pass-through signature: alerts on forwarded ICMP but never
            # drops, so any packet loss below is the ruleset's doing, not a
            # signature's.
            extraRules = ''
              alert icmp any any -> any any (msg:"VM-TEST ICMP forwarded"; itype:8; sid:9000001; rev:1;)
            '';
          };
        }

        {
          disko.enableConfig = lib.mkForce false;
          boot.loader.systemd-boot.enable = lib.mkForce false;
          boot.loader.grub.enable = lib.mkForce false;

          systemd.services.suricata-update.enable = lib.mkForce false;
          systemd.timers.suricata-update.enable = lib.mkForce false;
          services.suricata.settings.rule-files = lib.mkForce [
            "/etc/suricata/rules/local.rules"
          ];
          services.suricata.settings.classification-file = lib.mkForce "${pkgs.suricata}/etc/suricata/classification.config";

          virtualisation = {
            vlans = [
              1
              2
              3
            ]; # eth1 = WAN, eth2 = LAN, eth3 = guest
            memorySize = 2048;
            cores = 2;
          };
          environment.systemPackages = [
            pkgs.iproute2
            pkgs.iputils
            pkgs.conntrack-tools
          ];
        }
      ];
    };

  testScript = ''
    LAN_IP = "10.48.4.50"
    GUEST_IP = "192.168.20.50"

    start_all()
    router.wait_for_unit("multi-user.target")
    router.wait_for_unit("suricata.service")

    with subtest("both bridges are up with their gateway addresses"):
        router.wait_until_succeeds("ip -4 addr show br-lan | grep -qw 10.48.4.1", timeout=60)
        router.wait_until_succeeds("ip -4 addr show br-guest | grep -qw 192.168.20.1", timeout=60)

    def mk_host(ns, bridge, addr, gw):
        """A netns standing in for a host on `bridge`, addressed statically
        (outside the DHCP pool) so the test never races the DHCP server."""
        router.succeed(f"ip netns add {ns}")
        router.succeed(f"ip link add {ns}-c type veth peer name {ns}-br")
        router.succeed(f"ip link set {ns}-br master {bridge} up")
        router.succeed(f"ip link set {ns}-c netns {ns}")
        router.succeed(f"ip -n {ns} link set lo up")
        router.succeed(f"ip -n {ns} addr add {addr}/24 dev {ns}-c")
        router.succeed(f"ip -n {ns} link set {ns}-c up")
        router.succeed(f"ip -n {ns} route add default via {gw}")

    mk_host("lanhost", "br-lan", LAN_IP, "10.48.4.1")
    mk_host("guesthost", "br-guest", GUEST_IP, "192.168.20.1")

    def ping(ns, dst, count=3):
        """True if `ns` gets at least one echo reply from `dst`."""
        rc, _ = router.execute(f"ip netns exec {ns} ping -c{count} -W2 {dst}")
        return rc == 0

    with subtest("the router itself reaches both segments (baseline)"):
        # Locally-generated traffic uses the output hook, never the forward
        # chain — this is the "works from the router" half of the report, and it
        # establishes that both netns hosts are wired up before the forward-chain
        # assertions below can mean anything.
        assert ping("lanhost", "10.48.4.1"), "LAN host cannot reach its own gateway"
        assert router.execute(f"ping -c3 -W2 {GUEST_IP}")[0] == 0, \
            "router cannot reach the guest host directly"
        # NB: the reverse — guesthost pinging 192.168.20.1 — is *expected* to
        # fail. The input chain grants guest only DHCP/DNS/NDP plus replies to
        # router-initiated flows, so a guest host may not probe the router at all.
        assert not ping("guesthost", "192.168.20.1"), \
            "guest host could ping the router — the input chain should only " \
            "permit guest DHCP/DNS/NDP and established/related"

    # Suricata attaches to NFQUEUE 0 asynchronously; until "Engine started" the
    # `bypass` flag lets packets through uninspected, which would make the
    # suricata-attached subtests below silently test the detached case.
    router.wait_until_succeeds(
        "journalctl --namespace suricata --no-pager -o cat | grep -q 'Engine started'",
        timeout=300,
    )

    def measure(label):
        """Both directions, conntrack flushed between them so neither run's
        state can explain the other's verdict. Returns (lan_to_guest,
        guest_to_lan) rather than asserting, so one run reports the full matrix
        instead of aborting on the first failure."""
        router.succeed("conntrack -F 2>/dev/null || true")
        guest_to_lan = ping("guesthost", LAN_IP)
        router.succeed("conntrack -F 2>/dev/null || true")
        lan_to_guest = ping("lanhost", GUEST_IP)
        print(
            f"[{label}] LAN->guest reachable={lan_to_guest} (want True)   "
            f"guest->LAN reachable={guest_to_lan} (want False)"
        )
        return lan_to_guest, guest_to_lan

    with subtest("forward chain enforces one-way LAN→guest in both Suricata states"):
        on_lan_to_guest, on_guest_to_lan = measure("suricata attached")
        router.succeed("systemctl stop suricata.service")
        off_lan_to_guest, off_guest_to_lan = measure("suricata stopped")

        problems = []
        if not off_lan_to_guest:
            problems.append(
                'LAN→guest is blocked with Suricata stopped: the iifname "br-lan" '
                'oifname "br-guest" accept rule is not taking effect at all.'
            )
        if off_guest_to_lan:
            problems.append(
                "guest→LAN succeeded with Suricata stopped: guest isolation is "
                "broken in the ruleset itself."
            )
        if not on_lan_to_guest:
            problems.append(
                "LAN→guest is blocked only while Suricata is attached to NFQUEUE 0."
            )
        if on_guest_to_lan:
            problems.append(
                "guest→LAN succeeded only while Suricata is attached to NFQUEUE 0 — "
                "the `queue num 0 bypass` rule at the top of the forward chain lets "
                "Suricata's accept verdict skip every rule below it, including the "
                "chain's `policy drop`. Guest isolation is off whenever the IPS runs."
            )
        assert not problems, "\n  - " + "\n  - ".join(problems)
  '';
}
