# ── Firewall module ───────────────────────────────────────────────────────────
# The complete nftables ruleset (inet filter + inet nat with DNS hijacking + inet
# dns_bypass), generated from the topology and the WireGuard / port-forward
# options, plus optional UPnP-IGD/NAT-PMP via miniupnpd. The ruleset is kept as a
# single atomic flush-ruleset string; interface names come from the shared
# topology (config.router._internal).
{
  config,
  lib,
  ...
}:
with lib;
let
  cfg = config.router;
  netLib = import ./lib/net.nix { inherit lib; };
  inherit (config.router._internal)
    brLAN
    brGuest
    wanIf
    lanGW
    guestGW
    lanCIDR
    nftSet
    trustedIFs
    wgNames
    ;

  # Container bridge for the OpenWISP stack (modules/wireless-openwisp.nix).
  # The interface name is pinned in the netavark network definition precisely so
  # it can be named here.
  owIF = config.router._wirelessInternal.openwisp.interface;
  owEnabled = cfg.wireless.openwisp.enable;

  # ── nftables ruleset generation ─────────────────────────
  # The firewall ruleset is generated as a Nix multi-line string
  # and passed to `networking.nftables.ruleset`. It's built from
  # the user's interface/network config so rules adapt automatically.
  #
  # wgInputRules:
  #   Dynamically generates `accept` rules for each WireGuard
  #   tunnel's UDP listen port on the WAN interface, allowing
  #   inbound VPN connections.
  wgInputRules = concatMapStringsSep "\n          " (
    name:
    let
      wg = cfg.wireguard.${name};
    in
    ''iifname "${wanIf}" udp dport ${toString wg.listenPort} accept comment "Allow WireGuard ${name}"''
  ) wgNames;

  # wgForwardRules:
  #   For each WireGuard tunnel, generates bidirectional forwarding
  #   rules (LAN ↔ WG) and outbound WAN access with stateful return
  #   traffic. This allows VPN clients to reach LAN resources and
  #   route to the internet through the router.
  wgForwardRules = concatMapStringsSep "\n          " (name: ''
    # LAN ↔ ${name} (bidirectional)
    iifname "${brLAN}" oifname "${name}" accept
    iifname "${name}"  oifname "${brLAN}" accept

    # ${name} → WAN
    iifname "${name}" oifname "${wanIf}" accept
    iifname "${wanIf}" oifname "${name}" ct state { established, related } accept'') wgNames;

  # ── Static port forwards ────────────────────────────────
  # Each entry names a router.hosts device and opens its ports for one or both
  # address families. Ports are mapped 1:1 (router port == device port).
  #
  #   • IPv4 — prerouting DNAT of WAN traffic to the host's staticIp, plus a
  #     forward accept limited to connections that DNAT produced (`ct status
  #     dnat`), so the rule cannot also admit packets routed straight at the
  #     internal address from the WAN segment.
  #   • IPv6 — no NAT: a forward-chain pinhole to the host's OWN global
  #     address. The delegated prefix is dynamic, so the address is matched by
  #     its low 64 bits (the host's ipv6Suffix) on the egress bridge of the
  #     host's network — the same `::suffix/-64` technique OpenWrt fw4 uses.
  #     Only the bridge's own /64 is routed out of it, so bridge + suffix pins
  #     one address whatever prefix the ISP hands out today.
  #
  # `sources` may mix IPv4 and IPv6 prefixes; each family's rule only sees its
  # own. A restricted forward with no prefix of a family opens nothing for that
  # family (warned below).
  hostByName = listToAttrs (map (h: nameValuePair h.name h) cfg.hosts);
  bridgeOf = h: if h.network == "guest" then brGuest else brLAN;

  resolveForward =
    f:
    let
      h = hostByName.${f.host} or null;
      restricted = f.sources != [ ];
      v4Sources = filter (s: netLib.familyOf s == "ipv4") f.sources;
      v6Sources = filter (s: netLib.familyOf s == "ipv6") f.sources;
      v4Addr = if h != null then h.staticIp else null;
      v6Suffix = if h != null && h.ipv6Suffix != null then netLib.parseSuffix h.ipv6Suffix else null;
      wantV4 = f.family != "ipv6";
      wantV6 = f.family != "ipv4";
    in
    {
      inherit
        f
        h
        restricted
        v4Sources
        v6Sources
        v4Addr
        v6Suffix
        wantV4
        wantV6
        ;
      label = if f.name != "" then f.name else f.host;
      v4 = wantV4 && v4Addr != null && (!restricted || v4Sources != [ ]);
      v6 = wantV6 && v6Suffix != null && (!restricted || v6Sources != [ ]);
      bridge = if h != null then bridgeOf h else null;
    };
  forwards = map resolveForward cfg.portForwards;
  v4Forwards = filter (r: r.v4) forwards;
  v6Forwards = filter (r: r.v6) forwards;

  pfDports =
    ports:
    if length ports == 1 then
      toString (head ports)
    else
      "{ ${concatMapStringsSep ", " toString ports} }";
  pfSaddr =
    family: sources:
    optionalString (sources != [ ]) "${family} saddr { ${concatStringsSep ", " sources} } ";
  # Names are free text; a double quote would end the nftables string early.
  pfComment = r: " comment \"${replaceStrings [ "\"" "\\" ] [ "'" "" ] r.label}\"";

  portForwardDnatRules = concatMapStringsSep "\n                " (
    r:
    ''iifname "${wanIf}" ${pfSaddr "ip" r.v4Sources}${r.f.protocol} dport ${pfDports r.f.ports} dnat ip to ${r.v4Addr}${pfComment r}''
  ) v4Forwards;
  portForwardFilterRules = concatMapStringsSep "\n                " (
    r:
    ''iifname "${wanIf}" ${pfSaddr "ip" r.v4Sources}ip daddr ${r.v4Addr} ${r.f.protocol} dport ${pfDports r.f.ports} ct status dnat accept${pfComment r}''
  ) v4Forwards;
  portForwardPinholeRules = concatMapStringsSep "\n                " (
    r:
    ''iifname "${wanIf}" oifname "${r.bridge}" ${pfSaddr "ip6" r.v6Sources}ip6 daddr & ::ffff:ffff:ffff:ffff == ${r.v6Suffix} ${r.f.protocol} dport ${pfDports r.f.ports} ct state new accept${pfComment r}''
  ) v6Forwards;

  # Checks on the forwards themselves, each naming the offending forward.
  wgPorts = map (n: cfg.wireguard.${n}.listenPort) wgNames;
  unrestrictedV4Keys = concatMap (r: map (p: "${r.f.protocol}/${toString p}") r.f.ports) (
    filter (r: r.v4Sources == [ ]) v4Forwards
  );
  dupsOf =
    xs:
    attrNames (
      filterAttrs (_: c: c > 1) (foldl' (acc: x: acc // { ${x} = (acc.${x} or 0) + 1; }) { } xs)
    );

  forwardAssertions = concatMap (
    r:
    let
      pf = "router.portForwards: forward '${r.label}'";
    in
    [
      {
        assertion = r.f.ports != [ ] && !(elem 0 r.f.ports);
        message = "${pf} needs at least one port, and port 0 cannot be forwarded";
      }
      {
        assertion = all netLib.isPrefix r.f.sources;
        message = "${pf} has an invalid source prefix in [ ${concatStringsSep ", " r.f.sources} ] — use IPv4 or IPv6 addresses or CIDR prefixes";
      }
      {
        assertion = !(r.f.protocol == "udp" && r.v4 && any (p: elem p wgPorts) r.f.ports);
        message = "${pf} forwards a WireGuard listen port (UDP ${
          concatMapStringsSep ", " toString wgPorts
        }); its DNAT would capture the tunnel's own traffic";
      }
      {
        assertion = r.h != null;
        message = "${pf} references unknown host '${r.f.host}' — it must name a router.hosts entry";
      }
      {
        assertion = r.h == null || !r.wantV4 || r.h.staticIp != null;
        message = "${pf} forwards IPv4 to host '${r.f.host}', which has no staticIp (DHCP reservation) to DNAT to — set one, or set family = \"ipv6\"";
      }
      {
        assertion = r.h == null || !r.wantV6 || r.h.ipv6Suffix != null;
        message = "${pf} forwards IPv6 to host '${r.f.host}', which has no ipv6Suffix to open a pinhole for — set one, or set family = \"ipv4\"";
      }
    ]
  ) forwards;

  forwardWarnings =
    map (
      r:
      "router.portForwards: forward '${r.label}' includes IPv6, but its sources are all IPv4 prefixes, so the IPv6 pinhole stays closed. Add IPv6 source prefixes or set family = \"ipv4\"."
    ) (filter (r: r.wantV6 && r.v6Suffix != null && r.restricted && r.v6Sources == [ ]) forwards)
    ++ map (
      r:
      "router.portForwards: forward '${r.label}' includes IPv4, but its sources are all IPv6 prefixes, so nothing is forwarded over IPv4. Add IPv4 source prefixes or set family = \"ipv6\"."
    ) (filter (r: r.wantV4 && r.v4Addr != null && r.restricted && r.v4Sources == [ ]) forwards);

  # v6DnsDropRules:
  #   IPv6 :53 drops for the policy-enforced segments (LAN + guest), emitted
  #   into BOTH hooks of the `inet dns_bypass` table — see the comment on that
  #   table for why IPv6 DNS is dropped rather than redirected to the resolver.
  #   WireGuard is deliberately excluded: peers are roaming admin devices with
  #   no DHCP reservation to anchor a device-tier policy to in the first place.
  v6DnsSegments = [ brLAN ] ++ optional cfg.guest.enable brGuest;
  v6DnsDropTargets = concatMap (
    br:
    map (proto: { inherit br proto; }) [
      "udp"
      "tcp"
    ]
  ) v6DnsSegments;
  v6DnsDropRules = concatMapStringsSep "\n    " (
    p:
    ''iifname "${p.br}" meta nfproto ipv6 ${p.proto} dport 53 counter drop comment "Block IPv6 DNS (policy tiers are IPv4-anchored)"''
  ) v6DnsDropTargets;

  # nftRuleset:
  #   The complete nftables configuration, organized into three tables:
  #
  #   1. `inet filter` — Stateful firewall (input + forward chains)
  #      • Input: loopback accepted; trusted IFs (LAN+WG) fully open;
  #        guest limited to DHCP/DNS plus replies to router-initiated
  #        flows; WAN allows established + ICMP + WireGuard ports;
  #        everything else dropped.
  #      • Forward: WG bidirectional; LAN→WAN; WAN→LAN established;
  #        guest→WAN only, plus LAN→guest one-way (guest is isolated
  #        from WG entirely and may only answer LAN, never initiate
  #        to it).
  #
  #   2. `inet nat` — NAT and DNS hijacking
  #      • Prerouting: intercepts all IPv4 DNS (port 53) from
  #        LAN/guest and redirects to the local resolver, preventing
  #        clients from bypassing Technitium filtering by hardcoding
  #        external DNS servers; DNATs IPv4 port forwards.
  #      • Postrouting: masquerades outbound WAN traffic.
  #
  #   3. `inet dns_bypass` — DNS bypass prevention
  #      • Runs at priority filter-1 (before the main filter) to drop
  #        DoT (:853) and IPv6 :53 from LAN/guest, on both the input
  #        and forward hooks.
  #
  #   4. `inet ips` — Suricata NFQUEUE hand-off (only when enabled)
  #      • Runs at priority filter+10 (AFTER the main filter), so the
  #        forward chain's drop policy is applied before anything is
  #        handed to the IPS. See the table's own comment for why it
  #        must not live inside the forward chain.
  nftRuleset = ''
    table inet filter {
      chain input {
        type filter hook input priority 0; policy drop;

        # Loopback
        iifname "lo" accept

        # Trusted internal networks
        iifname { ${nftSet trustedIFs} } accept comment "Allow LAN and WG to router"

        ${optionalString cfg.guest.enable ''
          # Replies to router-initiated traffic (e.g. pinging a guest host,
          # probing a guest service). Without this the router can reach the
          # guest subnet but never sees the answer, since this chain drops by
          # policy and guest is not in trustedIFs. Stateful only — guest still
          # cannot open new connections to the router.
          iifname "${brGuest}" ct state { established, related } accept

          # Guest: DHCP/DNS and NDP to router only (all other guest→router dropped)
          iifname "${brGuest}" udp dport { 53, 67 } accept
          iifname "${brGuest}" tcp dport 53 accept
          iifname "${brGuest}" icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept
          ${optionalString cfg.accessPolicies.blockPage.enable ''
            # Block page (Technitium Block Page app) + exception-request portal (router-logd)
            iifname "${brGuest}" tcp dport { 80, 443, ${toString cfg.reporting.logd.port} } accept
          ''}
        ''}

        ${optionalString owEnabled ''
          # Replies to router-initiated traffic. Needed because a published
          # container port reached from the router itself is DNAT'd in the
          # output hook, so the container's answer arrives here on the bridge
          # with an ephemeral destination port that matches no rule below.
          # Stateful only — containers still cannot open new connections to the
          # router beyond the datastore ports.
          iifname "${owIF}" ct state { established, related } accept

          # OpenWISP containers reach the router's own PostgreSQL and Redis on
          # the bridge gateway address. Nothing else on this bridge is allowed
          # to the router.
          #
          # Note there is deliberately NO equivalent rule for the UniFi
          # database bridge: that container is reached only from the host
          # network namespace, where the controller runs, so it needs no input
          # rule at all. See the forward chain for the other half.
          iifname "${owIF}" tcp dport { 5432, 6379 } accept comment "OpenWISP containers → PostgreSQL/Redis"
        ''}

        # mDNS (multicast DNS) for hostname resolution
        udp dport 5353 accept comment "Allow mDNS queries"

        # WAN: only established/related + select ICMP
        iifname "${wanIf}" ct state { established, related } accept
        iifname "${wanIf}" icmp type { echo-request, destination-unreachable, time-exceeded } counter accept
        iifname "${wanIf}" icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } counter accept
        iifname "${wanIf}" udp dport 546 accept comment "DHCPv6 client"
        ${wgInputRules}

        # Drop everything else from WAN
        iifname "${wanIf}" counter drop
      }

      chain forward {
        type filter hook forward priority filter; policy drop;

        ${wgForwardRules}

        # LAN → WAN
        iifname "${brLAN}" oifname "${wanIf}" accept

        # WAN → LAN (established only)
        iifname "${wanIf}" oifname "${brLAN}" ct state { established, related } accept

        ${optionalString cfg.upnp.enable ''
          # UPnP/NAT-PMP: accept inbound traffic matching an active
          # miniupnpd port mapping. miniupnpd installs the DNAT in
          # its own `inet miniupnpd` table; without this rule the
          # redirected packets would hit this chain's `policy drop`.
          iifname "${wanIf}" oifname "${brLAN}" ct status dnat accept
        ''}

        ${optionalString (v4Forwards != [ ]) ''
          # Static IPv4 port forwards: allow the WAN connections the
          # prerouting DNAT below redirected to their host.
          ${portForwardFilterRules}
        ''}

        ${optionalString (v6Forwards != [ ]) ''
          # Static IPv6 port forwards: pinholes to each host's own global
          # address, matched on its interface ID (the delegated prefix is
          # dynamic) and the bridge of the host's network.
          ${portForwardPinholeRules}
        ''}

        ${optionalString owEnabled ''
          # LAN → a PUBLISHED container port. netavark installs the DNAT in its
          # own `inet netavark` table, which cannot override this chain's drop
          # policy, so the redirected packets need an accept here. Matching on
          # `ct status dnat` keeps that narrow: a LAN client can reach the
          # dashboard on its published port, but not any container directly on
          # its address. Same idea as the UPnP rule above.
          iifname "${brLAN}" oifname "${owIF}" ct status dnat accept

          # OpenWISP containers → LAN: celery opens SSH connections to the
          # access points it manages, which live on the LAN.
          iifname "${owIF}" oifname "${brLAN}" accept
          iifname "${brLAN}" oifname "${owIF}" ct state { established, related } accept

          # OpenWISP containers → WAN. The postrouting masquerade below already
          # covers the source NAT for this subnet, so no NAT rule is needed.
          iifname "${owIF}" oifname "${wanIf}" accept
          iifname "${wanIf}" oifname "${owIF}" ct state { established, related } accept
        ''}

        ${optionalString cfg.wireless.unifi.enable ''
          # NOTE: the UniFi database bridge (router.wireless.unifi.network) gets
          # NO rule in this chain, on purpose. With policy drop, that absence is
          # what makes MongoDB unreachable from the LAN, the guest network and
          # the WAN — only the host itself, where the controller runs on the
          # host network namespace, can talk to it. The database image is pinned
          # to MongoDB 4.4 (the last release that runs without AVX) which is
          # past end of life, and this isolation is the control that covers it.
          # Do not "fix" this by adding a rule.
        ''}

        ${optionalString cfg.guest.enable ''
          # Guest → WAN only (fully isolated from LAN and WireGuard)
          iifname "${brGuest}" oifname "${wanIf}" accept
          iifname "${wanIf}" oifname "${brGuest}" ct state { established, related } accept

          # LAN → Guest (one-way access for administration). The return rule
          # is stateful, so guest hosts can answer a LAN-initiated connection
          # but can never initiate one toward the LAN themselves.
          iifname "${brLAN}" oifname "${brGuest}" accept
          iifname "${brGuest}" oifname "${brLAN}" ct state { established, related } accept
        ''}
      }
    }

    table inet nat {
      chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;

        # Force all LAN DNS through the local resolver (prevents bypass).
        # IPv4 only — IPv6 :53 is dropped in `inet dns_bypass` instead of
        # redirected, because the access-policy compiler can only attribute
        # IPv4-sourced queries to a device (see that table's comment).
        iifname "${brLAN}" udp dport 53 ip daddr != ${lanGW} dnat to ${lanGW}:53
        iifname "${brLAN}" tcp dport 53 ip daddr != ${lanGW} dnat to ${lanGW}:53

        ${optionalString cfg.guest.enable ''
          # Force guest DNS through the local resolver (IPv4; see above)
          iifname "${brGuest}" udp dport 53 ip daddr != ${guestGW} dnat to ${guestGW}:53
          iifname "${brGuest}" tcp dport 53 ip daddr != ${guestGW} dnat to ${guestGW}:53
        ''}

        ${optionalString (v4Forwards != [ ]) ''
          # Static IPv4 port forwards (WAN → host staticIp)
          ${portForwardDnatRules}
        ''}
      }

      chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # IPv4 masquerade only — IPv6 uses global PD addresses
        meta nfproto ipv4 oifname "${wanIf}" masquerade
      }
    }

    # ── DNS bypass prevention ─────────────────────────────
    # Priority filter-1 puts these chains BEFORE the main `inet filter`
    # chains, so the drops below win over the blanket trusted-interface
    # accept in the input chain and the LAN→WAN accept in the forward chain.
    #
    #   • DoT (:853) — the router runs no DoT listener, so drop outright.
    #   • IPv6 :53 — the access-policy compiler anchors the device, host
    #     group and directory-user tiers to each device's IPv4 DHCP
    #     reservation, so an IPv6-sourced query can only ever match the
    #     catch-all [::]/0 entry and would silently fall back to the DEFAULT
    #     policy — a bypass for any device pinned to a stricter one. The
    #     router never advertises an IPv6 resolver (ipv6SendRAConfig.EmitDNS
    #     = false), so dropping IPv6 :53 costs nothing and forces every
    #     client onto IPv4, where the policy tiers actually apply. Both hooks
    #     are required: `input` covers queries aimed at the router's own IPv6
    #     addresses, `forward` those aimed at an external resolver.
    table inet dns_bypass {
      chain input {
        type filter hook input priority filter - 1; policy accept;
        ${v6DnsDropRules}
      }

      chain forward {
        type filter hook forward priority filter - 1; policy accept;
        iifname "${brLAN}" tcp dport 853 counter drop comment "Block DoT bypass"
        ${optionalString cfg.guest.enable ''iifname "${brGuest}" tcp dport 853 counter drop comment "Block guest DoT bypass"''}
        ${v6DnsDropRules}
      }
    }
    ${optionalString cfg.suricata.enable ''

      # ── Suricata IPS inline inspection ────────────────────
      # The NFQUEUE hand-off lives in its own table at priority filter+10 —
      # AFTER `inet filter` forward — and never inside that chain. `queue` is a
      # terminal statement: it ends chain evaluation where it sits, so every
      # rule below it is skipped. Both of its outcomes do so:
      #
      #   • Suricata attached — the packet goes to userspace, and netfilter
      #     reinjects an accepted packet at the next registered HOOK, not the
      #     next rule, so the remainder of the originating chain never runs.
      #   • Suricata stopped — `bypass` accepts the packet inline (that is the
      #     whole point of the flag: fail open rather than blackhole traffic),
      #     which is likewise terminal for the chain.
      #
      # Placed at the top of the policy-drop forward chain, as it once was, that
      # made every accept rule AND the `policy drop` itself dead code whenever
      # the IPS was enabled: guest isolation and the WAN→LAN established-only
      # rule silently stopped being enforced. Sequencing it as a separate,
      # later base chain keeps the drop policy authoritative — only traffic
      # `inet filter` has already accepted is ever handed to the IPS — while
      # still inspecting every forwarded packet. Covered by tests/guest-access.nix.
      table inet ips {
        chain forward {
          type filter hook forward priority filter + 10; policy accept;
          queue num 0 bypass
        }
      }
    ''}
  '';
in
{
  options.router = {
    # ── UPnP-IGD / NAT-PMP (miniupnpd) ─────────────────────
    # Optional automatic inbound port forwarding for LAN
    # clients (game consoles, P2P, some self-hosted apps).
    #
    # Disabled by default, deliberately: UPnP/NAT-PMP let LAN
    # devices punch holes in the firewall with no authentication,
    # which runs counter to the rest of the hardened design (IPS,
    # forced DNS, guest isolation). Only enable it with a concrete
    # need, and never expose it to the guest network.
    #
    # When enabled, hardened defaults are applied automatically
    # (see the services.miniupnpd block in the config section):
    #   • nftables backend (auto-selected by the module).
    #   • secure_mode — a client may only map ports to its OWN IP.
    #   • listens on the LAN bridge ONLY (guest/IoT can never
    #     request mappings).
    #   • only non-privileged ports (1024-65535) may be mapped.
    upnp = {
      enable = mkEnableOption "UPnP-IGD / NAT-PMP automatic port forwarding (miniupnpd)";

      extraConfig = mkOption {
        type = types.lines;
        default = "";
        description = "Additional miniupnpd.conf lines, appended after the hardened defaults";
      };
    };

    # ── Static port forwards ──────────────────────────────
    # Explicit inbound port forwarding from the WAN to a registered
    # device (router.hosts). Unlike UPnP, every hole is declared in
    # configuration and auditable. Ports are mapped 1:1 (router port
    # == device port). IPv4 is DNAT'd to the device's staticIp; IPv6
    # is a firewall pinhole to the device's own global address,
    # identified by its ipv6Suffix. Use `sources` to restrict the
    # forward to specific WAN source prefixes.
    #
    # SECURITY: each forward exposes the device directly to the
    # internet. With Suricata enabled the traffic still passes the
    # IPS, but HOME_NET lists only IPv4 networks, so inbound-IPv6
    # signatures keyed on $HOME_NET will not match. Only forward what
    # must be reachable, and narrow `sources` where possible.
    portForwards = mkOption {
      default = [ ];
      description = "Static inbound port forwards from the WAN to registered hosts, over IPv4 (DNAT) and/or IPv6 (pinhole).";
      example = literalExpression ''
        [
          {
            name = "Synology DSM";
            host = "nas";
            ports = [ 5080 5443 ];
          }
        ]
      '';
      type = types.listOf (
        types.submodule {
          options = {
            name = mkOption {
              type = types.str;
              default = "";
              description = "Descriptive label, emitted as an nftables rule comment.";
            };
            protocol = mkOption {
              type = types.enum [
                "tcp"
                "udp"
              ];
              default = "tcp";
              description = "Transport protocol to forward.";
            };
            host = mkOption {
              type = types.str;
              example = "nas";
              description = "Name of the router.hosts device to forward the traffic to.";
            };
            family = mkOption {
              type = types.enum [
                "both"
                "ipv4"
                "ipv6"
              ];
              default = "both";
              description = ''
                Address families to forward. IPv4 needs the host's `staticIp`
                (the DNAT target); IPv6 needs its `ipv6Suffix` (the pinhole).
              '';
            };
            ports = mkOption {
              type = types.listOf types.port;
              example = [
                80
                443
              ];
              description = "WAN-facing ports to forward, each mapped 1:1 to the same port on the host.";
            };
            sources = mkOption {
              type = types.listOf types.str;
              default = [ ];
              example = [
                "203.0.113.0/24"
                "2001:db8:100::/48"
              ];
              description = ''
                WAN source prefixes the forward is restricted to; IPv4 and IPv6
                prefixes may be mixed. Empty allows any source. A family with no
                prefix in a non-empty list is not forwarded at all.
              '';
            };
          };
        }
      );
    };
  };

  config = {
    assertions = forwardAssertions ++ [
      {
        assertion = dupsOf unrestrictedV4Keys == [ ];
        message = "router.portForwards: more than one unrestricted IPv4 forward claims ${concatStringsSep ", " (dupsOf unrestrictedV4Keys)} — only the first DNAT would ever match";
      }
    ];
    warnings = forwardWarnings;

    # ── 4. nftables ──────────────────────────────────────
    # The complete firewall ruleset generated from `nftRuleset` above.
    # See the nftRuleset generation section in the `let` block for
    # detailed documentation of each table and chain.
    networking.nftables = {
      enable = true;
      ruleset = nftRuleset;
    };

    # ── UPnP-IGD / NAT-PMP — miniupnpd ───────────────────
    # Active only when router.upnp.enable = true. The NixOS
    # module auto-selects the nftables backend (because
    # networking.nftables.enable = true) and adds an
    # `inet miniupnpd` table to the ruleset, into which the daemon
    # installs DNAT mappings at runtime. The `ct status dnat accept`
    # rule in the nftRuleset forward chain lets that redirected
    # traffic cross the drop-policy forward chain.
    #
    # Hardened defaults:
    #   • secure_mode=yes — a client may only forward a port to its
    #     OWN IP, never to another host on the LAN.
    #   • internalIPs = LAN bridge only — the guest/IoT network can
    #     never request mappings.
    #   • allow/deny — only ports 1024-65535 from the LAN subnet may
    #     be mapped; everything else is denied.
    #
    # NOTE: when the nftables ruleset reloads (e.g. on a
    # `nixos-rebuild switch`) it is flushed (flushRuleset defaults
    # on for a monolithic ruleset), clearing miniupnpd's live
    # mappings. Clients re-request them on their next renewal; the
    # lease_file + partOf binding lets a miniupnpd restart restore
    # them from disk immediately.
    services.miniupnpd = mkIf cfg.upnp.enable {
      enable = true;
      externalInterface = wanIf;
      internalIPs = [ brLAN ];
      natpmp = true;
      upnp = true;
      appendConfig = ''
        secure_mode=yes
        friendly_name=NixOS Router
        lease_file=/var/lib/miniupnpd/upnp.leases
        # Only non-privileged ports from the LAN subnet may be mapped.
        allow 1024-65535 ${lanCIDR} 1024-65535
        deny 0-65535 0.0.0.0/0 0-65535
        ${cfg.upnp.extraConfig}
      '';
    };

    systemd.services = mkMerge [
      (mkIf cfg.upnp.enable {
        miniupnpd = {
          after = [ "nftables.service" ];
          partOf = [ "nftables.service" ];
          serviceConfig.StateDirectory = "miniupnpd";
        };
      })

      # ── Podman / netavark rule restoration ────────────
      # Same hazard as miniupnpd above, but with worse consequences and a
      # different trigger. When containers are running, podman's NixOS module
      # points netavark at the nftables firewall driver, so netavark installs
      # its own `inet netavark` table carrying published-port DNAT and the
      # container subnets' forwarding. The monolithic ruleset here flushes
      # everything on load, so those rules vanish and published ports go dead.
      #
      # `partOf` alone — the miniupnpd mitigation — is NOT enough here: the
      # nftables unit sets reloadIfChanged and defines ExecReload, so a
      # `nixos-rebuild switch` RELOADS it, and partOf only propagates across
      # stop/restart. ReloadPropagatedFrom covers the reload path, and partOf
      # still covers a genuine restart. `podman network reload --all`
      # reinstalls the rules for every running container without restarting
      # any of them.
      (mkIf (cfg.wireless.unifi.enable || cfg.wireless.openwisp.enable) {
        podman-network-reload = {
          description = "Reinstall podman/netavark firewall rules after an nftables reload";
          after = [
            "nftables.service"
            "podman.service"
          ];
          partOf = [ "nftables.service" ];
          unitConfig.ReloadPropagatedFrom = [ "nftables.service" ];
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = "${config.virtualisation.podman.package}/bin/podman network reload --all";
            ExecReload = "${config.virtualisation.podman.package}/bin/podman network reload --all";
          };
        };
      })
    ];
  };
}
