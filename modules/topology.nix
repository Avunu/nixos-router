# ── Shared network topology ───────────────────────────────────────────────────
# Derived values computed once from the user-facing `router.*` options and read
# by every router sub-module (network, firewall, access-protection,
# threat-protection, system) via `config.router._internal`. Centralizing them
# here avoids recomputation and keeps a single source of truth for interface
# names, CIDRs, the VLAN/port model, and the helper functions that build the
# networkd units. `_internal` is hidden (internal) and read-only, so it never
# appears in the public `router.*` API or in /etc/router/effective.json.
{ config, lib, ... }:
with lib;
let
  cfg = config.router;

  # brLAN / lanGW / lanPrefix / lanCIDR:
  #   Bridge name, gateway IP, prefix length, and CIDR notation for the primary
  #   LAN network. Used in networkd, nftables, and Suricata HOME_NET.
  brLAN = "br-lan";
  lanGW = cfg.lan.address;
  lanPrefix = toString cfg.lan.prefixLength;
  lanCIDR = "${cfg.lan.networkAddress}/${lanPrefix}";

  # wgNames / wgInterfaces:
  #   List of WireGuard interface names (e.g. ["wg0"]) and their config attrsets.
  #   Used to generate networkd units, nftables rules, and Suricata HOME_NET.
  wgNames = attrNames cfg.wireguard;
  wgInterfaces = attrValues cfg.wireguard;
  wgIFNames = wgNames;

  # ── Guest network derived values ────────────────────────
  # Mirror of the LAN derived values, for the isolated guest network.
  brGuest = "br-guest";
  guestGW = cfg.guest.address;
  guestPrefix = toString cfg.guest.prefixLength;
  guestCIDR = "${cfg.guest.networkAddress}/${guestPrefix}";

  # homeNets:
  #   Aggregated list of all "internal" subnets (LAN + WireGuard + Guest)
  #   formatted as a Suricata YAML list for $HOME_NET.
  lanNets = [ lanCIDR ];
  wgNets = concatMap (wg: [ wg.address ] ++ concatMap (p: p.allowedIPs) wg.peers) wgInterfaces;
  guestNets = optional cfg.guest.enable guestCIDR;
  allHomeNets = lanNets ++ wgNets ++ guestNets;
  homeNets = "[${concatStringsSep ", " allHomeNets}]";

  # nftSet:
  #   Helper to format a list of interface names as a quoted, comma-separated
  #   nftables set literal, e.g. { "br-lan", "wg0" }.
  # trustedIFs:
  #   Interfaces allowed full access to the router (LAN bridge + all WireGuard
  #   tunnels). Used in the nftables input chain.
  nftSet = items: concatStringsSep ", " (map (i: ''"${i}"'') items);
  trustedIFs = [ brLAN ] ++ wgIFNames;

  # ── VLAN / interface assignment model ───────────────────
  # Each network (wan/lan/guest) may be assigned physical interfaces (claiming
  # UNTAGGED traffic on them) and/or a VLAN id for TAGGED traffic. VLAN
  # availability is EXPLICIT: a network's tag is carried on the global
  # `trunkInterfaces` (implicit for every network) plus that network's own
  # `taggedInterfaces` (WAN: trunk only). A single physical port can therefore
  # carry untagged traffic for its owner network AND tagged VLAN traffic for
  # another: the kernel's 802.1q demux (vlan_do_receive) runs before the bridge
  # rx_handler, so the `<port>.<vid>` sub-interface receives tagged frames before
  # the owner's plain bridge ever sees them. See the network module below.
  #
  # wanPhys/lanPhys/guestPhys:
  #   Untagged physical ports owned by each network.
  wanPhys = optional (cfg.wan.interface != null) cfg.wan.interface;
  lanPhys = cfg.lan.interfaces;
  guestPhys = optionals cfg.guest.enable cfg.guest.interfaces;
  # ownedPorts: physical ports that have an untagged owner network.
  # Untagged ownership is exclusive (a port has at most one owner).
  ownedPorts = wanPhys ++ lanPhys ++ guestPhys;

  # netList:
  #   Uniform description of each network: key, target bridge (null for a
  #   direct/untagged WAN), VLAN id, owned (untagged) ports, and the ports its
  #   VLAN tag rides on (`taggedPorts`). The guest entry only appears when
  #   guest.enable = true.
  netList = [
    {
      key = "wan";
      bridge = null;
      vlan = cfg.wan.vlan;
      phys = wanPhys;
      taggedPorts = cfg.trunkInterfaces;
    }
    {
      key = "lan";
      bridge = brLAN;
      vlan = cfg.lan.vlan;
      phys = lanPhys;
      taggedPorts = unique (cfg.trunkInterfaces ++ cfg.lan.taggedInterfaces);
    }
  ]
  ++ optional cfg.guest.enable {
    key = "guest";
    bridge = brGuest;
    vlan = cfg.guest.vlan;
    phys = guestPhys;
    taggedPorts = unique (cfg.trunkInterfaces ++ cfg.guest.taggedInterfaces);
  };

  # vlanIds: every VLAN id in use (for distinctness / range assertions).
  vlanIds = filter (v: v != null) (
    [
      cfg.wan.vlan
      cfg.lan.vlan
    ]
    ++ optional cfg.guest.enable cfg.guest.vlan
  );

  # vlanChild:
  #   Sub-interface name for a VLAN id on a parent port (kernel 8021q naming
  #   convention, e.g. enp1s0.20).
  vlanChild = parent: vid: "${parent}.${toString vid}";

  # allChildren:
  #   Flat list of every VLAN sub-interface to create — for each network with a
  #   VLAN id, one child per port in its `taggedPorts`.
  childrenOf =
    n:
    if n.vlan == null then
      [ ]
    else
      map (p: {
        inherit p;
        child = vlanChild p n.vlan;
        net = n;
      }) n.taggedPorts;
  allChildren = concatMap childrenOf netList;

  # allPhys: every physical port that needs a parent .network unit — untagged
  # owners, declared trunk ports, and any port a VLAN child rides on.
  allPhys = unique (ownedPorts ++ cfg.trunkInterfaces ++ map (c: c.p) allChildren);

  # childrenOnPort:
  #   VLAN sub-interface names that ride on a given parent port.
  childrenOnPort = parent: map (c: c.child) (filter (c: c.p == parent) allChildren);

  # wanIf:
  #   The WAN L3 interface name used by the firewall, NAT, and IPv6 prefix
  #   delegation. A VLAN-based (or interface-less) WAN runs its DHCP client on a
  #   bridge (br-wan) aggregating its VLAN sub-interfaces; otherwise it is the
  #   untagged uplink interface.
  wanIsBridged = cfg.wan.vlan != null || cfg.wan.interface == null;
  brWAN = "br-wan";
  wanIf = if wanIsBridged then brWAN else cfg.wan.interface;

  # wanNetworkBase:
  #   DHCP-client settings for the WAN L3 interface, applied to either the
  #   untagged uplink (10-wan) or the br-wan bridge (10-br-wan).
  wanNetworkBase = {
    networkConfig = {
      DHCP = "yes";
      IPv4Forwarding = true;
      IPv6Forwarding = true;
      IPv4ReversePathFilter = "strict";
      IPv6AcceptRA = true;
      IgnoreCarrierLoss = "3s";
      KeepConfiguration = "dynamic-on-stop";
    };
    dhcpV4Config = {
      UseDNS = false;
      UseHostname = false;
      UseDomains = false;
      SendHostname = true;
      RouteMetric = 100;
    };
    dhcpV6Config = {
      UseDNS = false;
      UseHostname = false;
      WithoutRA = "solicit";
      PrefixDelegationHint = "::/60";
    };
    ipv6AcceptRAConfig = {
      UseDNS = false;
      DHCPv6Client = "always";
      # Ignore the MTU option in upstream Router Advertisements. Some ISP uplinks
      # advertise a jumbo MTU on the handoff segment; networkd then tries to set
      # the WAN's IPv6 MTU above its 1500 link MTU, which the kernel rejects with
      # EINVAL on every RA — flooding the logs. The internet path MTU is 1500
      # regardless, so the advertised value is useless here.
      UseMTU = false;
    };
    linkConfig.RequiredForOnline = "routable";
  };

  # parentPorts / ownerBridgeOf / childBridgeOf:
  #   parentPorts: physical ports that need their own parent .network unit (the
  #   untagged WAN uplink is excluded when WAN is direct — it has its own 10-wan
  #   DHCP-client unit). childBridgeOf: the bridge a VLAN child enslaves to
  #   (WAN → br-wan).
  directWanPort = optionals (!wanIsBridged) wanPhys;
  parentPorts = subtractLists directWanPort allPhys;
  ownerOf = p: findFirst (n: elem p n.phys) (head netList) netList;
  ownerBridgeOf =
    p:
    let
      n = ownerOf p;
    in
    if n.key == "wan" then brWAN else n.bridge;
  childBridgeOf = net: if net.key == "wan" then brWAN else net.bridge;

  # mkPortUnit:
  #   The parent .network unit for a physical port: attaches the VLAN
  #   sub-interfaces riding on it (`vlan` list) and, if the port has an untagged
  #   owner, enslaves it to that owner's bridge. Trunk-only ports carry tagged
  #   VLANs only and terminate no L3 themselves.
  mkPortUnit =
    p:
    let
      owned = elem p ownedPorts;
    in
    {
      matchConfig.Name = p;
      networkConfig = {
        ConfigureWithoutCarrier = true;
        LinkLocalAddressing = "no";
        IPv6AcceptRA = false;
      }
      // optionalAttrs owned { Bridge = ownerBridgeOf p; };
      vlan = childrenOnPort p;
      linkConfig.RequiredForOnline = if owned then "enslaved" else "no";
    };
in
{
  options.router._internal = mkOption {
    type = types.attrs;
    internal = true;
    readOnly = true;
    description = ''
      Derived network topology shared across the router sub-modules. Computed
      once from `router.*` options; not user-facing and never serialized to
      /etc/router/effective.json.
    '';
  };

  config.router._internal = {
    inherit
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
  };
}
