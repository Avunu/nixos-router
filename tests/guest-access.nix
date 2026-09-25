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
#
# A WireGuard tunnel rides along, because its forwarding is decided by the same
# kind of silent config generation: the router's forwarding and rp_filter
# settings once sat in a networkd unit that nixpkgs' own unit for the tunnel
# shadowed, so `net.ipv4.conf.wg0.forwarding` stayed 0 and a remote site could
# reach the router but nothing behind it. A netns peer on the LAN (its tunnel
# endpoint is the LAN gateway) stands in for the remote site's router, with a
# remote subnet of its own in the router's Allowed IPs.
{
  pkgs,
  routerModule,
  baseSettings,
}:
let
  # Throwaway test keys. A real router's private key lives in /etc/wireguard,
  # never in the store.
  routerKey = "cKQ6Bi8yC5hys1/ACbemMhhU1YHhp0q9BVhyrT5J034=";
  routerPub = "Zs7aplC8mOtxG16L9fkqDfo3pleUAD3Fwd1j4UcfhGc=";
  peerKey = pkgs.writeText "wgpeer.key" "uJFUSrGB76Fhjc7oz/v/IES6MT+rOVtYOZ28ffSXznU=";
  peerPub = "CsExnGzNn3h4vcqD/M8i0Kzj19AlEfpUW1vrQFq5DU4=";
in
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
          router.wireguard.wg0 = {
            address = "10.100.0.1/30";
            privateKeyFile = "${pkgs.writeText "wg0.key" routerKey}";
            peers = [
              {
                publicKey = peerPub;
                # The peer router's tunnel address and the remote site's LAN.
                allowedIPs = [
                  "10.100.0.2/32"
                  "192.168.30.0/24"
                ];
              }
            ];
          };
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
            pkgs.socat
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

    with subtest("mDNS reaches the router from the LAN only"):
        # Nothing binds :5353 in this VM (Technitium, and with it Avahi, is
        # off), so a socat sink stands in for Avahi. Guest sends first: once the
        # LAN datagram has landed, an accepted guest one would have too.
        router.succeed(
            "systemd-run --unit mdns-sink "
            "socat -u UDP4-RECV:5353,reuseaddr OPEN:/tmp/mdns-rx,creat,append"
        )
        router.wait_until_succeeds("ss -uln | grep -q ':5353 '", timeout=15)
        router.succeed(
            "echo from-guest | ip netns exec guesthost socat -u - UDP4-SENDTO:192.168.20.1:5353"
        )
        router.succeed(
            "echo from-lan | ip netns exec lanhost socat -u - UDP4-SENDTO:10.48.4.1:5353"
        )
        router.wait_until_succeeds("grep -q from-lan /tmp/mdns-rx", timeout=15)
        rx = router.succeed("cat /tmp/mdns-rx")
        assert "from-guest" not in rx, f"guest reached the router on 5353/udp: {rx!r}"

    def rpf_drops():
        import json
        ruleset = json.loads(router.succeed("nft -j list chain inet antispoof prerouting"))
        for item in ruleset["nftables"]:
            rule = item.get("rule")
            if rule and rule.get("comment") == "Reverse-path check":
                return next(e["counter"]["packets"] for e in rule["expr"] if "counter" in e)
        raise AssertionError(f"no reverse-path rule in {ruleset}")

    with subtest("the reverse-path check drops spoofed sources from the guest network"):
        # A guest host borrowing a LAN address (IPv4) and a prefix routed
        # nowhere near br-guest (IPv6). Neither is ever answered: the input
        # chain would drop the probes anyway, so the counter on the
        # reverse-path rule is what proves which rule did it.
        before = rpf_drops()
        router.succeed("ip -n guesthost addr add 10.48.4.77/32 dev guesthost-c")
        router.execute("ip netns exec guesthost ping -c2 -W1 -I 10.48.4.77 192.168.20.1")
        after_v4 = rpf_drops()
        assert after_v4 > before, f"IPv4 spoof not dropped by the reverse-path check ({before} -> {after_v4})"

        ll = router.succeed(
            "ip -6 -o addr show dev br-guest scope link | awk '{print $4}' | cut -d/ -f1"
        ).strip()
        router.succeed("ip -n guesthost addr add 2001:db8:dead::1/128 dev guesthost-c nodad")
        router.execute(f"ip netns exec guesthost ping -6 -c2 -W1 -I 2001:db8:dead::1 {ll}%guesthost-c")
        after_v6 = rpf_drops()
        assert after_v6 > after_v4, f"IPv6 spoof not dropped by the reverse-path check ({after_v4} -> {after_v6})"

        # And the legitimate address still works through the same hook.
        router.succeed("conntrack -F 2>/dev/null || true")
        assert ping("lanhost", GUEST_IP), "LAN→guest broke after the spoofing probes"

    with subtest("DoT and DoQ are both dropped from LAN and guest"):
        out = router.succeed("nft list chain inet dns_bypass forward")
        for br in ("br-lan", "br-guest"):
            assert any(
                br in line and "853" in line and "tcp" in line and "udp" in line
                for line in out.splitlines()
            ), f"no tcp+udp :853 drop for {br}:\n{out}"

    with subtest("networkd applies the tunnel's forwarding and rp_filter"):
        # Once networkd has finished configuring the link, its per-link
        # sysctls show which unit it applied.
        router.wait_until_succeeds("ip -4 addr show wg0 | grep -qw 10.100.0.1", timeout=60)
        router.wait_until_succeeds("networkctl list wg0 --no-legend | grep -qw configured", timeout=60)
        fwd = router.succeed("sysctl -n net.ipv4.conf.wg0.forwarding").strip()
        rpf = router.succeed("sysctl -n net.ipv4.conf.wg0.rp_filter").strip()
        units = router.succeed("networkctl status wg0 --no-pager | grep -i 'network file' || true")
        assert fwd == "1", f"net.ipv4.conf.wg0.forwarding = {fwd}, want 1 ({units.strip()})"
        assert rpf == "0", f"net.ipv4.conf.wg0.rp_filter = {rpf}, want 0 ({units.strip()})"

    with subtest("a remote site's subnet reaches the LAN through the tunnel"):
        mk_host("wgpeer", "br-lan", "10.48.4.60", "10.48.4.1")
        # Created inside the netns, so its UDP socket lives there too and the
        # encrypted packets really cross br-lan to the router's listen port.
        router.succeed("ip -n wgpeer link add wgp type wireguard")
        router.succeed(
            "ip netns exec wgpeer wg set wgp private-key ${peerKey} listen-port 51900 "
            "peer ${routerPub} endpoint 10.48.4.1:51820 "
            "allowed-ips 10.100.0.1/32,10.48.4.50/32"
        )
        router.succeed("ip -n wgpeer addr add 10.100.0.2/30 dev wgp")
        router.succeed("ip -n wgpeer link set wgp up")
        # The peer's underlay is the LAN itself, so only the one LAN host the
        # test talks to is routed into the tunnel.
        router.succeed("ip -n wgpeer route add 10.48.4.50/32 dev wgp")
        router.succeed("ip -n wgpeer link add site type dummy")
        router.succeed("ip -n wgpeer addr add 192.168.30.1/24 dev site")
        router.succeed("ip -n wgpeer link set site up")

        # Baseline: the handshake, and the router's own tunnel address — input,
        # not forward, so this passes whatever the forwarding sysctl says.
        router.wait_until_succeeds("ip netns exec wgpeer ping -c1 -W2 10.100.0.1", timeout=30)

        # Forwarded both ways between the remote subnet and the LAN: out of the
        # tunnel into br-lan, and the LAN host's replies back in. The source is
        # an Allowed IPs subnet, not the tunnel address, so the reverse-path
        # check sees a source routed via wg0 rather than a connected one.
        router.succeed("conntrack -F 2>/dev/null || true")
        rc, out = router.execute("ip netns exec wgpeer ping -c3 -W2 -I 192.168.30.1 10.48.4.50")
        assert rc == 0, f"remote subnet → LAN over the tunnel failed:\n{out}"
        router.succeed("conntrack -F 2>/dev/null || true")
        assert ping("lanhost", "192.168.30.1"), "LAN → remote subnet over the tunnel failed"
  '';
}
