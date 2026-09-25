---
title: Networks and VLANs
description: How the router's WAN, LAN and guest networks work, how guest isolation is enforced, and how to carry networks as VLANs over trunk ports.
code:
  - modules/network.nix
  - modules/topology.nix
  - modules/firewall.nix
  - pkgs/cockpit-router/src/network.tsx
  - pkgs/cockpit-router/src/interfaces.ts
---

# Networks and VLANs

The router has three networks: the **WAN** towards your internet provider, the **LAN** for your own devices, and an optional **guest** network that can reach the internet but not the LAN. Each network gets its ports as untagged interfaces, as a VLAN, or both. You set all of this on the **Network** page.

## The Network page

| Tab | What it holds |
| --- | --- |
| **Interfaces** | One row per physical port, with its link **Status**, its **Untagged network** (**WAN**, **LAN**, **Guest** or none) and a **Trunk** checkbox. |
| **WAN** | The WAN's untagged interface (read-only; assign it on **Interfaces**) and its **VLAN id**. |
| **LAN** | **Addressing**, **VLAN** and **DHCP** for the LAN. |
| **Guest** | **Enable guest network**, then the same sections as the LAN. |
| **WireGuard** | VPN tunnels. See [WireGuard](/docs/wireguard/). |
| **Dynamic DNS** | Cloudflare records for the router's addresses. See [Dynamic DNS](/docs/dynamic-dns/). |
| **Diagnostics** | `ping`, `traceroute`, `dig` and `mtr`, run from the router. |

:::doc-warning
Reassigning interfaces or changing the LAN address can cut off the computer you manage the router from. Use **Save** to stage the changes, then apply them from the changes tray when you're ready. If the router becomes unreachable, see [Recover from the boot menu](/docs/start/upgrades/#recover-from-the-boot-menu).
:::

## WAN

The WAN is always a DHCP client. There is no setting for a static WAN address or PPPoE.

- **IPv4:** the router takes its address and default route from your provider's DHCP server, and masquerades all outbound traffic behind that address. It sends its host name, and ignores the DNS servers and domain the provider offers.
- **IPv6:** the router accepts router advertisements, runs a DHCPv6 client and asks for a delegated prefix of `/60`. From that prefix it gives one `/64` to the LAN and another to the guest network. IPv6 is routed without NAT.
- **Inbound:** the firewall admits only replies to outbound connections, rate-limited ping, the required ICMPv6 messages, DHCPv6 replies, WireGuard's ports, and whatever you publish through [Ingress](/docs/ingress/). Everything else from the WAN is dropped.

Select the WAN's port on **Network → Interfaces** by setting its **Untagged network** to **WAN**. If your provider hands the internet over as a tagged VLAN, leave the WAN without an untagged port, set its **VLAN id** on the **WAN** tab, and mark the port that carries it as a trunk. The router then runs its DHCP client on a bridge, `br-wan`, fed by the VLAN sub-interface. The WAN's tag is carried on trunk ports only.

```json
{
  "trunkInterfaces": ["enp1s0"],
  "wan": { "interface": null, "vlan": 10 }
}
```

## LAN

The LAN's ports are joined into one bridge, `br-lan`, with the router's **Gateway address** on it. The router serves the LAN with:

- **DHCP.** The pool starts **Pool offset** addresses above the **Network address** and holds **Pool size** addresses: with offset 100 and size 150 on `192.168.1.0/24`, that is `192.168.1.100` to `192.168.1.249`. Leases last **Lease time**, `24h` by default. Devices with a static IP on the [Hosts](/docs/network/hosts/) page get a reservation.
- **Gateway and DNS.** DHCP hands out the gateway address as both the router and the DNS server, and the **Local domain** (`lan` by default) as the search domain, so `nas` resolves as `nas.lan`.
- **IPv6.** The router advertises the LAN's `/64` for SLAAC. It advertises no IPv6 DNS server, and drops IPv6 DNS queries, so every client uses the router's IPv4 resolver, where filtering policies apply. See [DNS enforcement](/docs/access-policies/dns-enforcement/).
- **Forced DNS.** Every IPv4 DNS query from the LAN goes to the router's resolver, whichever server the client asked.

LAN devices can reach the router, the internet, WireGuard peers and the guest network.

```json
{
  "lan": {
    "interfaces": ["enp2s0", "enp3s0"],
    "address": "192.168.1.1",
    "networkAddress": "192.168.1.0",
    "prefixLength": 24,
    "domain": "lan",
    "dhcp": { "poolOffset": 100, "poolSize": 150, "leaseTime": "24h" }
  }
}
```

`address`, `networkAddress`, `dhcp.poolOffset` and `dhcp.poolSize` have no defaults, so every router sets them.

## Guest network

Turn it on with **Enable guest network** on the **Guest** tab. It gets its own bridge, `br-guest`, and works like the LAN, with these differences:

- **Isolation.** Guest devices can reach the internet and nothing else. The LAN can open connections to guest devices, for example to manage a printer, and guest devices can answer them, but they can't open connections to the LAN or to WireGuard peers.
- **Limited access to the router.** Guest devices can use the router's DHCP and DNS, and nothing else on it; the web UI and SSH are out of reach. When the block page is on, they can also reach it and its exception-request form.
- **Short leases.** Leases last `1h` by default, so addresses turn over quickly.
- **Defaults.** Gateway `192.168.20.1`, network `192.168.20.0/24`, pool offset 100 and size 151. The search domain is the LAN's **Local domain**.

Isolation happens in the router, at layer 3. Two guest devices on the same switch or access point still reach each other directly; turn on client isolation in the access point to stop that.

```json
{
  "guest": {
    "enable": true,
    "interfaces": ["enp4s0"],
    "vlan": 20,
    "taggedInterfaces": ["enp2s0", "enp3s0"],
    "address": "192.168.20.1",
    "networkAddress": "192.168.20.0",
    "prefixLength": 24,
    "dhcp": { "poolOffset": 100, "poolSize": 151, "leaseTime": "1h" }
  }
}
```

This guest network owns port `enp4s0`, and is also available as VLAN 20 on the LAN ports, for access points that put a guest SSID on a tagged VLAN.

## VLANs

Each network takes its traffic from two kinds of port:

- **Untagged ports** carry the network's plain traffic. Each port has at most one untagged network. Set it in the **Untagged network** column on **Interfaces**.
- **Tagged ports** carry the network's VLAN, when the network has a **VLAN id**. A network's tag is available on every **trunk** port, plus, for the LAN and guest network, the ports ticked under **Tagged on interfaces** on their own tab. The WAN's tag is on trunk ports only.

A port can do both at once: untagged traffic for its own network, and tagged traffic for others. The router creates one sub-interface per network and port, named `<port>.<vlan>`, such as `enp2s0.20`, and joins it to that network's bridge.

In the settings file, `trunkInterfaces` lists the trunk ports, and each network has `vlan` and, for the LAN and guest network, `taggedInterfaces`.

### A router with one port

A single-port router needs a VLAN-capable switch that delivers every network to it as a tagged VLAN. Make the port a trunk, give no network an untagged port, and give each network a VLAN id:

```json
{
  "trunkInterfaces": ["enp1s0"],
  "wan": { "interface": null, "vlan": 10 },
  "lan": {
    "interfaces": [],
    "vlan": 20,
    "address": "192.168.1.1",
    "networkAddress": "192.168.1.0",
    "prefixLength": 24,
    "dhcp": { "poolOffset": 100, "poolSize": 150 }
  },
  "guest": { "enable": true, "vlan": 30 }
}
```

The build accepts this layout, but the Network page doesn't yet: it reports "Assign at least one physical interface to a network." and keeps **Save & apply** disabled. Click **Save**, then **Apply** in the changes tray.

### Rules the router checks

The Network page lists broken rules under "Network configuration is invalid" and disables **Save & apply** until they are fixed. The build checks the same rules, apart from the single-port case above, and fails with these messages:

| Message | Fix |
| --- | --- |
| ``router.wan: set an `interface` (untagged uplink) and/or a `vlan` id.`` | Give the WAN a port or a VLAN id. |
| ``router.lan: set `interfaces` (untagged) and/or a `vlan` id.`` | Give the LAN at least one port, or a VLAN id. |
| ``router.guest: when enabled, set `interfaces` (untagged) and/or a `vlan` id.`` | The same, for the guest network. |
| `router: a physical interface is assigned to more than one network; each port has exactly one untagged owner.` | Pick one untagged network per port. |
| ``router: a VLAN-based network has no ports to carry its tag; add to its `taggedInterfaces` (WAN: `trunkInterfaces`) or set `trunkInterfaces`.`` | Tick a trunk port, or tag the network on a port. |
| ``router.lan: `taggedInterfaces` is set but `vlan` is null; set a `vlan` id.`` | Set the VLAN id, or clear the tagged ports. The guest network has the same check. |
| `router: two networks share a VLAN id; each network's VLAN id must be distinct.` | Use a different VLAN id per network. |
| `router: VLAN ids must be in the range 1–4094.` | Use a valid VLAN id. |
| `router: a VLAN sub-interface name (<port>.<vid>) exceeds the 15-char kernel limit (IFNAMSIZ); use a shorter parent interface name.` | Linux limits interface names to 15 characters, so a USB adapter named `enx001122334455` can't carry VLAN 20 as `enx001122334455.20`. Use a port with a shorter name. |

## Limits

- The WAN supports DHCP only: no static address, no PPPoE, and only one WAN.
- Guest isolation is at layer 3. Guest devices on the same switch or access point see each other.
- There is one LAN and one guest network. More networks, for example for cameras or IoT devices, are not supported.
- Filtering policies anchor devices to their IPv4 address, which is why IPv6 DNS is dropped. See [Access policies](/docs/access-policies/).
