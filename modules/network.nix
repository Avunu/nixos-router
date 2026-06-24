# ── Network module ────────────────────────────────────────────────────────────
# systemd-networkd interface/bridge/VLAN configuration for WAN, LAN, guest, and
# WireGuard, plus the interface/VLAN-model validation assertions. The derived
# topology (interface names, the port model, the networkd-unit helpers) comes
# from modules/topology.nix via config.router._internal.
{
  config,
  lib,
  ...
}:
with lib;
let
  cfg = config.router;
  t = config.router._internal;
  inherit (t)
    brLAN
    lanGW
    lanPrefix
    lanCIDR
    wgNames
    wgInterfaces
    wgIFNames
    brGuest
    guestGW
    guestPrefix
    guestCIDR
    lanNets
    wgNets
    guestNets
    allHomeNets
    homeNets
    nftSet
    trustedIFs
    wanPhys
    lanPhys
    guestPhys
    ownedPorts
    netList
    vlanIds
    vlanChild
    childrenOf
    allChildren
    allPhys
    childrenOnPort
    wanIsBridged
    brWAN
    wanIf
    wanNetworkBase
    directWanPort
    parentPorts
    ownerOf
    ownerBridgeOf
    childBridgeOf
    mkPortUnit
    ;

  # ── WireGuard peer submodule type ───────────────────────
  # Defines the schema for a single WireGuard peer. Each peer has:
  #   • publicKey:           The peer's WireGuard public key.
  #   • endpoint:            Optional remote address:port (null for
  #                          peers that connect inbound only).
  #   • allowedIPs:          Subnets routed through the WG tunnel to
  #                          this peer (also used in Suricata HOME_NET).
  #   • persistentKeepalive: Seconds between keepalive packets
  #                          (default 25, useful for NAT traversal).
  wgPeerType = types.submodule {
    options = {
      publicKey = mkOption {
        type = types.str;
        description = "Public key of the WireGuard peer";
      };
      endpoint = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Endpoint address:port of the peer";
      };
      allowedIPs = mkOption {
        type = types.listOf types.str;
        description = "Allowed IP ranges for this peer";
      };
      persistentKeepalive = mkOption {
        type = types.int;
        default = 25;
        description = "Persistent keepalive interval in seconds";
      };
    };
  };

  # ── WireGuard interface submodule type ──────────────────
  # Defines the schema for a WireGuard tunnel interface. The
  # attribute name in `router.wireguard` becomes the interface name
  # (e.g. `wg0`). Each interface gets:
  #   • address:        Local tunnel IP with CIDR (e.g. 10.100.0.1/24).
  #   • listenPort:     UDP port (default 51820; auto-opened in nftables).
  #   • privateKeyFile: Path to the private key file (never in the Nix
  #                    store — should be in /etc/wireguard/ or similar).
  #   • peers:          List of wgPeerType entries.
  #   • routes:         Extra destination CIDRs to add as systemd-networkd
  #                    routes on this tunnel.
  wgInterfaceType = types.submodule {
    options = {
      address = mkOption {
        type = types.str;
        description = "Local WireGuard address with CIDR (e.g. 10.100.0.1/24)";
      };
      listenPort = mkOption {
        type = types.port;
        default = 51820;
        description = "UDP listen port for WireGuard";
      };
      privateKeyFile = mkOption {
        type = types.path;
        description = "Path to the WireGuard private key file";
      };
      peers = mkOption {
        type = types.listOf wgPeerType;
        default = [ ];
        description = "List of WireGuard peers";
      };
      routes = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Additional route destinations to add for this tunnel";
      };
    };
  };
in
{
  options.router = {
    # ── Trunk interfaces ───────────────────────────────────
    # Physical ports that carry VLAN-tagged traffic but have no untagged
    # network of their own. The canonical case is a single-NIC router
    # (e.g. a Raspberry Pi) cabled to a smart switch that delivers every
    # network as a tagged VLAN on that one port. List the port here and
    # give each network a `vlan` id; VLAN sub-interfaces are created on
    # every trunk port (in addition to other networks' interfaces).
    trunkInterfaces = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Physical ports carrying tagged VLANs with no untagged network of their own (e.g. a single switch-trunk uplink).";
    };

    # ── WAN ────────────────────────────────────────────────
    # The upstream (internet-facing) interface. This interface is
    # configured as a DHCPv4 client and is the masquerade source
    # for all outbound NAT. It receives the strictest firewall
    # treatment: only established/related traffic, select ICMP
    # types, and WireGuard UDP ports are allowed inbound.
    wan = {
      interface = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "WAN untagged uplink interface name (e.g. enp1s0). Set null for a VLAN-only WAN.";
      };

      vlan = mkOption {
        type = types.nullOr types.int;
        default = null;
        description = ''
          WAN VLAN id (tagged); null = untagged uplink. The WAN tag is
          carried only on `trunkInterfaces` (never on LAN/guest ports).
          When set, the WAN DHCP client runs on a bridge (br-wan)
          aggregating those VLAN sub-interfaces.
        '';
      };
    };

    # ── LAN ────────────────────────────────────────────────
    # The trusted internal network. Physical ports listed in
    # `interfaces` are bridged together under the bridge device.
    # The bridge gets a static IP (the gateway) and serves as
    # the DHCP server and DNS forwarder for all LAN clients.
    #
    # Addressing example:
    #   address        = "192.168.10.1"   (gateway IP)
    #   networkAddress = "192.168.10.0"   (network base)
    #   prefixLength   = 24               (/24 = 254 hosts)
    #   dhcp.poolOffset/poolSize  = 100/151    (DHCP pool)
    lan = {
      interfaces = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Physical LAN port interface names (untagged). May be empty for a VLAN-only LAN.";
      };

      vlan = mkOption {
        type = types.nullOr types.int;
        default = null;
        description = ''
          VLAN id for this network's tagged traffic; null = untagged-only.
          The tag is carried on `trunkInterfaces` plus this network's
          `taggedInterfaces`.
        '';
      };

      taggedInterfaces = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          Interfaces on which this network's VLAN tag is available, in
          addition to the global `trunkInterfaces`. Non-exclusive: a port
          may carry several networks' tags. Requires `vlan` to be set.
        '';
      };

      address = mkOption {
        type = types.str;
        description = "LAN gateway IP address (e.g. 192.168.10.1)";
      };

      networkAddress = mkOption {
        type = types.str;
        description = "LAN network address (e.g. 192.168.10.0)";
      };

      prefixLength = mkOption {
        type = types.int;
        default = 24;
        description = "LAN subnet prefix length";
      };

      domain = mkOption {
        type = types.str;
        default = "lan";
        description = "Local DNS domain";
      };

      dhcp = {
        poolOffset = mkOption {
          type = types.int;
          description = "Offset from network base to first DHCP address (e.g. 100 for .100)";
        };

        poolSize = mkOption {
          type = types.int;
          description = "Number of addresses in the DHCP pool (e.g. 151 for .100-.250)";
        };

        leaseTime = mkOption {
          type = types.str;
          default = "24h";
          description = "DHCP lease duration";
        };
      };
    };

    # ── Guest Network ──────────────────────────────────────
    # Optional isolated network for untrusted devices. When enabled:
    #   • A separate bridge (br-guest) is created for guest ports.
    #   • nftables restricts guest traffic to WAN-only (no LAN/WG access),
    #     but allows LAN to access Guest (one-way) for administration.
    #   • Guest clients can reach DHCP (port 67) and DNS (port 53)
    #     on the router, but nothing else on the router itself.
    #   • DNS is hijacked to the local resolver (same as LAN).
    #   • DoT (port 853) is blocked to prevent DNS bypass.
    #   • Shorter default DHCP lease (1h) encourages address rotation.
    guest = {
      enable = mkEnableOption "guest network with client isolation";

      interfaces = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Physical interface names to assign to the guest bridge (untagged)";
      };

      vlan = mkOption {
        type = types.nullOr types.int;
        default = null;
        description = ''
          VLAN id for this network's tagged traffic; null = untagged-only.
          The tag is carried on `trunkInterfaces` plus this network's
          `taggedInterfaces`.
        '';
      };

      taggedInterfaces = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          Interfaces on which this network's VLAN tag is available, in
          addition to the global `trunkInterfaces`. Non-exclusive: a port
          may carry several networks' tags. Requires `vlan` to be set.
        '';
      };

      address = mkOption {
        type = types.str;
        default = "192.168.20.1";
        description = "Guest gateway IP address";
      };

      networkAddress = mkOption {
        type = types.str;
        default = "192.168.20.0";
        description = "Guest network address (e.g. 192.168.20.0)";
      };

      prefixLength = mkOption {
        type = types.int;
        default = 24;
        description = "Guest subnet prefix length";
      };

      dhcp = {
        poolOffset = mkOption {
          type = types.int;
          default = 100;
          description = "Offset from network base to first guest DHCP address";
        };

        poolSize = mkOption {
          type = types.int;
          default = 151;
          description = "Number of addresses in the guest DHCP pool";
        };

        leaseTime = mkOption {
          type = types.str;
          default = "1h";
          description = "Guest DHCP lease duration (shorter default encourages rotation)";
        };
      };
    };

    # ── WireGuard ──────────────────────────────────────────
    # Attribute set of WireGuard tunnel interfaces. The attribute
    # name becomes the Linux interface name (e.g. wg0, wg-site).
    # For each tunnel, the module automatically:
    #   • Creates the WG interface via networking.wireguard.interfaces.
    #   • Adds a systemd-networkd .network unit with IPv4Forwarding
    #     and relaxed reverse-path filtering.
    #   • Opens the UDP listen port in the nftables WAN input chain.
    #   • Generates bidirectional LAN↔WG and WG→WAN forward rules.
    #   • Includes WG subnets in Suricata's HOME_NET.
    wireguard = mkOption {
      type = types.attrsOf wgInterfaceType;
      default = { };
      description = "WireGuard tunnel interfaces (keys are interface names, e.g. wg0)";
    };
  };

  config = {
    # ── Network assignment validation ────────────────────
    # Catch misconfiguration of the interface/VLAN model early, with
    # clear messages, rather than producing a broken networkd config.
    assertions = [
      {
        assertion = cfg.wan.interface != null || cfg.wan.vlan != null;
        message = "router.wan: set an `interface` (untagged uplink) and/or a `vlan` id.";
      }
      {
        assertion = cfg.lan.interfaces != [ ] || cfg.lan.vlan != null;
        message = "router.lan: set `interfaces` (untagged) and/or a `vlan` id.";
      }
      {
        assertion = !cfg.guest.enable || (cfg.guest.interfaces != [ ] || cfg.guest.vlan != null);
        message = "router.guest: when enabled, set `interfaces` (untagged) and/or a `vlan` id.";
      }
      {
        assertion = allPhys != [ ];
        message = "router: at least one physical interface must be assigned (no port exists to carry traffic).";
      }
      {
        assertion = ownedPorts == unique ownedPorts;
        message = "router: a physical interface is assigned to more than one network; each port has exactly one untagged owner.";
      }
      {
        assertion = all (n: n.vlan == null || n.taggedPorts != [ ]) netList;
        message = "router: a VLAN-based network has no ports to carry its tag; add to its `taggedInterfaces` (WAN: `trunkInterfaces`) or set `trunkInterfaces`.";
      }
      {
        assertion = cfg.lan.taggedInterfaces == [ ] || cfg.lan.vlan != null;
        message = "router.lan: `taggedInterfaces` is set but `vlan` is null; set a `vlan` id.";
      }
      {
        assertion = cfg.guest.taggedInterfaces == [ ] || cfg.guest.vlan != null;
        message = "router.guest: `taggedInterfaces` is set but `vlan` is null; set a `vlan` id.";
      }
      {
        assertion = vlanIds == unique vlanIds;
        message = "router: two networks share a VLAN id; each network's VLAN id must be distinct.";
      }
      {
        assertion = all (v: v >= 1 && v <= 4094) vlanIds;
        message = "router: VLAN ids must be in the range 1–4094.";
      }
      {
        assertion = all (c: stringLength c.child <= 15) allChildren;
        message = "router: a VLAN sub-interface name (<port>.<vid>) exceeds the 15-char kernel limit (IFNAMSIZ); use a shorter parent interface name.";
      }
    ];

    # ── 3. systemd-networkd — interfaces + bridge ────────
    # All network configuration is handled by systemd-networkd.
    # NixOS's built-in DHCP, NAT, and firewall are disabled to
    # avoid conflicts with our explicit networkd + nftables setup.
    #
    # Interface topology:
    #   Each network (wan/lan/guest) claims UNTAGGED traffic on its
    #   assigned `interfaces` and/or TAGGED traffic for its `vlan` id on
    #   the trunk (`trunkInterfaces`) plus its own `taggedInterfaces`. A
    #   port can carry both at once — untagged frames go to the owner's
    #   bridge, tagged frames to the <port>.<vid> sub-interface (kernel
    #   802.1q demux precedes the bridge), so one wire feeds many networks.
    #
    #   WAN ─── DHCPv4 client (on the uplink, or br-wan when VLAN-based)
    #   LAN ports / <port>.<lanVid> ──── br-lan ─── static IP (gateway)
    #   Guest ports / <port>.<guestVid> ─ br-guest ─ static IP (gateway)
    #   WireGuard (wg0, etc.) ─── tunnel IP, forwarding enabled
    networking = {
      useNetworkd = true;
      useDHCP = false;
      nat.enable = false;
      firewall.enable = false;
    };

    systemd.network = {
      enable = true;
      # Don't block boot waiting for all interfaces — any one is enough.
      wait-online.anyInterface = true;

      # ── Virtual devices (bridges + VLANs) ──────────────
      # The LAN bridge aggregates LAN members (untagged ports and/or
      # tagged VLAN sub-interfaces) into one L2 domain. Guest bridge is
      # created only when guest.enable = true. br-wan is created only
      # when WAN is VLAN-based / has no untagged uplink. One VLAN netdev
      # (<port>.<vid>) is created per (VLAN network × other port) pair.
      netdevs = {
        "20-br-lan" = {
          netdevConfig = {
            Kind = "bridge";
            Name = brLAN;
          };
        };
      }
      // optionalAttrs cfg.guest.enable {
        "21-br-guest" = {
          netdevConfig = {
            Kind = "bridge";
            Name = brGuest;
          };
        };
      }
      // optionalAttrs wanIsBridged {
        "22-br-wan" = {
          netdevConfig = {
            Kind = "bridge";
            Name = brWAN;
          };
        };
      }
      // listToAttrs (
        map (
          c:
          nameValuePair "60-${c.child}" {
            netdevConfig = {
              Kind = "vlan";
              Name = c.child;
            };
            vlanConfig.Id = c.net.vlan;
          }
        ) allChildren
      );

      # ── Network units ────────────────────────────────────
      networks = {
        # WAN interface: DHCP client for upstream connectivity.
        # • IPv4Forwarding: enables kernel forwarding sysctl for this IF.
        # • IPv4ReversePathFilter=strict: drops packets with spoofed
        #   source addresses (BCP38/RFC3704 compliance).
        # • IPv6AcceptRA=true: accept Router Advertisements from ISP.
        # • IPv6Forwarding=true: enables kernel IPv6 forwarding sysctl.
        # • IgnoreCarrierLoss=3s: tolerates brief cable/modem blips
        #   without tearing down DHCP lease and routes.
        # • KeepConfiguration=dynamic-on-stop: preserves DHCP addresses
        #   and routes during networkd restarts (avoids brief outages).
        # • dhcpV4Config: prevents ISP DHCP from overriding local DNS
        #   (UseDNS/UseHostname/UseDomains=false), while still sending
        #   our hostname to the ISP for lease identification.
        #   RouteMetric=100 gives WAN routes explicit priority.
        # • dhcpV6Config: requests prefix delegation (/60) from ISP
        #   for distributing IPv6 subnets to LAN/guest bridges.
        # • ipv6AcceptRAConfig: always start DHCPv6 client (some ISPs
        #   require it even when RA M-flag is set).
        # The shared DHCP-client config (wanNetworkBase) is applied to
        # the untagged uplink, or to the br-wan bridge when WAN is
        # VLAN-based. Other networks' VLAN sub-interfaces that ride on
        # the untagged WAN port are attached via the `vlan` list.
        "10-wan" = wanNetworkBase // {
          matchConfig.Name = wanIf;
          vlan = optionals (!wanIsBridged) (childrenOnPort cfg.wan.interface);
        };

        # LAN bridge: the router's internal gateway interface.
        # • Static IP address (lanGW/lanPrefix) — this is the default
        #   gateway and DNS server for all LAN clients.
        # • DHCPServer=true: networkd serves DHCP directly on the bridge,
        #   eliminating startup-ordering issues with external DHCP daemons.
        # • dhcpServerConfig: pool range via PoolOffset/PoolSize,
        #   DNS points clients to the gateway (AGH on :53), EmitRouter
        #   auto-advertises the bridge IP as the default gateway.
        # • ConfigureWithoutCarrier: keeps config stable even if all
        #   physical ports are unplugged momentarily.
        # • IPv4Forwarding: enables IP forwarding on this interface.
        # • IPv4ReversePathFilter=no: relaxed because traffic arrives
        #   from bridged ports with various source subnets.
        # • IPv6AcceptRA=false: blocks rogue IPv6 RAs on the bridge.
        # • IPv6SendRA=true: advertise delegated IPv6 prefix to LAN
        #   clients via Router Advertisements (SLAAC).
        # • DHCPPrefixDelegation=true: assign a /64 from the WAN-delegated
        #   prefix to this bridge for LAN client use.
        # • LLDP=routers-only: receives LLDP from connected switches
        #   (query via `networkctl lldp` for topology discovery).
        # • EmitLLDP=nearest-bridge: announces this router to directly
        #   connected switches for identification.
        # • RequiredForOnline=no: boot doesn't wait for this interface.
        "40-br-lan" = {
          matchConfig.Name = brLAN;
          address = [ "${lanGW}/${lanPrefix}" ];
          networkConfig = {
            ConfigureWithoutCarrier = true;
            DHCPServer = true;
            DHCPPrefixDelegation = true;
            IPv4Forwarding = true;
            IPv6Forwarding = true;
            IPv4ReversePathFilter = "no";
            IPv6AcceptRA = false;
            IPv6SendRA = true;
            LLDP = "routers-only";
            EmitLLDP = "nearest-bridge";
          };
          dhcpServerConfig = {
            PoolOffset = cfg.lan.dhcp.poolOffset;
            PoolSize = cfg.lan.dhcp.poolSize;
            DefaultLeaseTimeSec = cfg.lan.dhcp.leaseTime;
            DNS = [ lanGW ];
            EmitDNS = true;
            EmitRouter = true;
          };
          dhcpPrefixDelegationConfig = {
            UplinkInterface = wanIf;
            SubnetId = 0;
            Announce = true;
          };
          ipv6SendRAConfig = {
            EmitDNS = false;
          };
          linkConfig.RequiredForOnline = "no";
        };
      }
      # Physical ports: one parent .network per port. An owned port
      # enslaves to its owner network's bridge (untagged); a trunk-only
      # port is a pure carrier. Each attaches (via the `vlan` list) the
      # VLAN sub-interfaces of other networks that ride on it. The kernel
      # delivers tagged frames to those children before the bridge sees
      # them, so untagged + tagged coexist on one wire. (The untagged WAN
      # uplink is handled by 10-wan above.)
      // listToAttrs (map (p: nameValuePair "30-port-${p}" (mkPortUnit p)) parentPorts)
      # VLAN sub-interfaces (<port>.<vid>): each enslaved to the bridge
      # of the network that owns the VLAN id (br-lan/br-guest/br-wan).
      // listToAttrs (
        map (
          c:
          nameValuePair "61-${c.child}" {
            matchConfig.Name = c.child;
            networkConfig = {
              Bridge = childBridgeOf c.net;
              ConfigureWithoutCarrier = true;
              LinkLocalAddressing = "no";
              IPv6AcceptRA = false;
            };
            linkConfig.RequiredForOnline = "enslaved";
          }
        ) allChildren
      )
      # WireGuard tunnel network units: generated dynamically from
      # `router.wireguard` entries. Each tunnel gets forwarding
      # enabled and relaxed rp_filter (WG traffic arrives from the
      # tunnel, not the physical interface the route points to).
      // listToAttrs (
        imap0 (
          i: name:
          let
            wg = cfg.wireguard.${name};
          in
          nameValuePair "50-${name}" {
            matchConfig.Name = name;
            address = [ wg.address ];
            routes = map (dest: { Destination = dest; }) wg.routes;
            networkConfig = {
              IPv4Forwarding = true;
              IPv4ReversePathFilter = "no";
            };
            linkConfig.RequiredForOnline = "no";
          }
        ) wgNames
      )
      # Guest network units (only when guest.enable = true):
      # Same pattern as LAN — member ports enslaved to bridge,
      # bridge gets static IP. LLDP enabled for topology visibility.
      // optionalAttrs cfg.guest.enable {
        # Guest bridge — same config pattern as br-lan, but on
        # a separate subnet with a different PD SubnetId.
        # nftables isolates guest from LAN/WG.
        # DHCPServer config mirrors LAN but with guest-specific pool
        # and shorter lease time for address rotation.
        "41-br-guest" = {
          matchConfig.Name = brGuest;
          address = [ "${guestGW}/${guestPrefix}" ];
          networkConfig = {
            ConfigureWithoutCarrier = true;
            DHCPServer = true;
            DHCPPrefixDelegation = true;
            IPv4Forwarding = true;
            IPv6Forwarding = true;
            IPv4ReversePathFilter = "no";
            IPv6AcceptRA = false;
            IPv6SendRA = true;
            LLDP = "routers-only";
            EmitLLDP = "nearest-bridge";
          };
          dhcpServerConfig = {
            PoolOffset = cfg.guest.dhcp.poolOffset;
            PoolSize = cfg.guest.dhcp.poolSize;
            DefaultLeaseTimeSec = cfg.guest.dhcp.leaseTime;
            DNS = [ guestGW ];
            EmitDNS = true;
            EmitRouter = true;
          };
          dhcpPrefixDelegationConfig = {
            UplinkInterface = wanIf;
            SubnetId = 1;
            Announce = true;
          };
          ipv6SendRAConfig = {
            EmitDNS = false;
          };
          linkConfig.RequiredForOnline = "no";
        };
      };
    };

    # ── WireGuard interfaces ─────────────────────────────
    # Creates WireGuard tunnel interfaces using NixOS's built-in
    # wireguard module. Each `router.wireguard.<name>` entry becomes
    # a kernel WG interface. The `optionalAttrs` block only includes
    # the `endpoint` field when it's non-null, supporting both
    # client-initiated (endpoint set) and server-only (endpoint null)
    # peer configurations.
    networking.wireguard.interfaces = mapAttrs (name: wg: {
      ips = [ wg.address ];
      listenPort = wg.listenPort;
      privateKeyFile = wg.privateKeyFile;
      peers = map (
        p:
        {
          publicKey = p.publicKey;
          allowedIPs = p.allowedIPs;
          persistentKeepalive = p.persistentKeepalive;
        }
        // optionalAttrs (p.endpoint != null) {
          endpoint = p.endpoint;
        }
      ) wg.peers;
    }) cfg.wireguard;
  };
}
