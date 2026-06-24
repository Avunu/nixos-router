# ── Firewall module ───────────────────────────────────────────────────────────
# The complete nftables ruleset (inet filter + ip nat with DNS hijacking + inet
# dot_block), generated from the topology and the WireGuard / port-forward
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

  # portForwardDnatRules / portForwardFilterRules:
  #   Static inbound port forwarding (DNAT) generated from
  #   cfg.portForwards. Each entry rewrites WAN-inbound traffic on
  #   the listed ports to an internal host (prerouting DNAT), and a
  #   matching accept rule lets that traffic cross the drop-policy
  #   forward chain (matched on destination IP + port, so it does
  #   not depend on which bridge the host is on). IPv4 only; ports
  #   are mapped 1:1 (router port == destination port). An optional
  #   `source` restricts the accepted WAN source prefix.
  pfDports =
    ports:
    if length ports == 1 then
      toString (head ports)
    else
      "{ ${concatMapStringsSep ", " toString ports} }";
  pfSaddr = source: optionalString (source != null) "ip saddr ${source} ";
  pfComment = name: optionalString (name != "") " comment \"${name}\"";
  portForwardDnatRules = concatMapStringsSep "\n                " (
    f:
    ''iifname "${wanIf}" ${pfSaddr f.source}${f.protocol} dport ${pfDports f.ports} dnat ip to ${f.destination}${pfComment f.name}''
  ) cfg.portForwards;
  portForwardFilterRules = concatMapStringsSep "\n                " (
    f:
    ''iifname "${wanIf}" ${pfSaddr f.source}ip daddr ${f.destination} ${f.protocol} dport ${pfDports f.ports} ct state { new, established, related } accept${pfComment f.name}''
  ) cfg.portForwards;

  # nftRuleset:
  #   The complete nftables configuration, organized into three tables:
  #
  #   1. `inet filter` — Stateful firewall (input + forward chains)
  #      • Input: loopback accepted; trusted IFs (LAN+WG) fully open;
  #        guest limited to DHCP/DNS only; WAN allows established +
  #        ICMP + WireGuard ports; everything else dropped.
  #      • Forward: optional Suricata NFQUEUE inspection; WG
  #        bidirectional; LAN→WAN; WAN→LAN established; guest→WAN
  #        only (fully isolated from LAN and WG).
  #
  #   2. `ip nat` — NAT and DNS hijacking
  #      • Prerouting: intercepts all DNS (port 53) from LAN/guest
  #        and redirects to the local resolver, preventing clients
  #        from bypassing AdGuard filtering by hardcoding external
  #        DNS servers.
  #      • Postrouting: masquerades outbound WAN traffic.
  #
  #   3. `inet dot_block` — DNS-over-TLS blocking
  #      • Runs at priority filter-1 (before the main filter) to
  #        drop TCP port 853 from LAN/guest, preventing DoT bypass
  #        of the local DNS resolver.
  nftRuleset = ''
    table inet filter {
      chain input {
        type filter hook input priority 0; policy drop;

        # Loopback
        iifname "lo" accept

        # Trusted internal networks
        iifname { ${nftSet trustedIFs} } accept comment "Allow LAN and WG to router"

        ${optionalString cfg.guest.enable ''
          # Guest: DHCP/DNS and NDP to router only (all other guest→router dropped)
          iifname "${brGuest}" udp dport { 53, 67 } accept
          iifname "${brGuest}" tcp dport 53 accept
          iifname "${brGuest}" icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept
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

        # Suricata IPS inline inspection (NFQUEUE with bypass)
        ${optionalString cfg.suricata.enable "queue num 0 bypass"}

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

        ${optionalString (cfg.portForwards != [ ]) ''
          # Static inbound port forwards: allow WAN traffic destined
          # for the configured internal hosts/ports (DNAT'd above).
          ${portForwardFilterRules}
        ''}

        ${optionalString cfg.guest.enable ''
          # Guest → WAN only (fully isolated from LAN and WireGuard)
          iifname "${brGuest}" oifname "${wanIf}" accept
          iifname "${wanIf}" oifname "${brGuest}" ct state { established, related } accept

          # LAN → Guest (one-way access for administration)
          iifname "${brLAN}" oifname "${brGuest}" accept
        ''}
      }
    }

    table inet nat {
      chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;

        # Force all LAN DNS through local resolver (prevents bypass)
        # IPv4: DNAT to gateway IP; IPv6: redirect (PD address is dynamic)
        iifname "${brLAN}" udp dport 53 ip daddr != ${lanGW} dnat to ${lanGW}:53
        iifname "${brLAN}" tcp dport 53 ip daddr != ${lanGW} dnat to ${lanGW}:53
        iifname "${brLAN}" meta nfproto ipv6 udp dport 53 redirect to :53
        iifname "${brLAN}" meta nfproto ipv6 tcp dport 53 redirect to :53

        ${optionalString cfg.guest.enable ''
          # Force guest DNS through local resolver
          iifname "${brGuest}" udp dport 53 ip daddr != ${guestGW} dnat to ${guestGW}:53
          iifname "${brGuest}" tcp dport 53 ip daddr != ${guestGW} dnat to ${guestGW}:53
          iifname "${brGuest}" meta nfproto ipv6 udp dport 53 redirect to :53
          iifname "${brGuest}" meta nfproto ipv6 tcp dport 53 redirect to :53
        ''}

        ${optionalString (cfg.portForwards != [ ]) ''
          # Static inbound port forwards (WAN → internal hosts)
          ${portForwardDnatRules}
        ''}
      }

      chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # IPv4 masquerade only — IPv6 uses global PD addresses
        meta nfproto ipv4 oifname "${wanIf}" masquerade
      }
    }

    # Block DoT bypass (port 853) in forward chain
    table inet dot_block {
      chain forward {
        type filter hook forward priority filter - 1; policy accept;
        iifname "${brLAN}" tcp dport 853 counter drop comment "Block DoT bypass"
        ${optionalString cfg.guest.enable ''iifname "${brGuest}" tcp dport 853 counter drop comment "Block guest DoT bypass"''}
      }
    }
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

    # ── Static port forwards (DNAT) ───────────────────────
    # Explicit inbound port forwarding from the WAN to internal
    # hosts. Unlike UPnP, every hole is declared in configuration
    # and auditable. Each entry forwards its listed ports to a
    # fixed internal IPv4 host; ports are mapped 1:1 (router port ==
    # destination port). Use the optional `source` to restrict the
    # forward to a specific WAN source prefix.
    #
    # SECURITY: each forward exposes the host directly to the
    # internet. When Suricata is enabled the inbound traffic is
    # IPS-inspected; regardless, only forward what must be reachable
    # and prefer narrowing `source` where possible.
    portForwards = mkOption {
      default = [ ];
      description = "Static inbound port forwards (DNAT) from the WAN to internal hosts. IPv4 only.";
      example = literalExpression ''
        [
          {
            name = "Synology DSM";
            destination = "10.48.4.2";
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
            destination = mkOption {
              type = types.str;
              example = "10.48.4.2";
              description = "Internal IPv4 address to forward the traffic to.";
            };
            ports = mkOption {
              type = types.listOf types.port;
              example = [
                80
                443
              ];
              description = "WAN-facing ports to forward, each mapped 1:1 to the same port on `destination`.";
            };
            source = mkOption {
              type = types.nullOr types.str;
              default = null;
              example = "203.0.113.0/24";
              description = "Optional WAN source prefix the forward is restricted to. Null allows any source.";
            };
          };
        }
      );
    };
  };

  config = {
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

    systemd.services = mkIf cfg.upnp.enable {
      miniupnpd = {
        after = [ "nftables.service" ];
        partOf = [ "nftables.service" ];
        serviceConfig.StateDirectory = "miniupnpd";
      };
    };
  };
}
