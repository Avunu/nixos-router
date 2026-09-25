---
title: Port forwards
description: Open WAN ports to a registered LAN host over IPv4 (DNAT) and IPv6 (a pinhole), optionally limited to certain source addresses.
code:
  - modules/firewall.nix
  - modules/reverse-proxy.nix
  - modules/dns-technitium.nix
  - modules/topology.nix
  - lib/settings.nix
  - pkgs/cockpit-router/src/port-forwards.tsx
  - pkgs/cockpit-router/src/forwards.ts
  - pkgs/cockpit-router/src/firewall.tsx
---

# Port forwards

A port forward opens one or more WAN ports to a single host on your network. Use it for services that aren't HTTP, such as a game server, SIP or SSH, or when the host must present its own certificate. For web apps that should share port 443 by name, the [reverse proxy](/docs/ingress/reverse-proxy/) is usually the better fit; see [Choose an ingress](/docs/ingress/).

## Before you start

- **Register the host** on the **Hosts** page. A forward always names a registered host, never an address. See [Hosts and host groups](/docs/network/hosts/).
- **For IPv4,** the host needs a **Static IP** (a DHCP reservation). It is the address the router forwards to.
- **For IPv6,** the host needs an **IPv6 suffix**: the low 64 bits of its address, such as `::20`. The suffix must be stable. Use a token configured on the device, or its EUI-64 identifier if the device really builds its address from its MAC. Privacy addresses and RFC 7217 "stable-privacy" addresses change with the prefix, and the forward would stop matching.
- **For IPv4 behind CGNAT,** a port forward can't work, because the router has no public IPv4 address. Use [Cloudflare Tunnel](/docs/ingress/cloudflare-tunnel/) for web apps instead.

## Add a port forward

1. Open **Ingress → Port forwards** and click **Add port forward**.
2. Fill in the form:

   | Field | What to enter |
   | --- | --- |
   | **Name** | Optional label, such as `Synology DSM`. It is shown in the list and written as the comment on the firewall rules. |
   | **Host** | The registered host. Each entry shows the host's static IP and IPv6 suffix. |
   | **Protocol** | **tcp** or **udp**. To forward both, add two forwards. |
   | **Family** | **IPv4 + IPv6** (the default), **IPv4 only** or **IPv6 only**. The help text: "IPv4 is forwarded from the router's public address to the host's static IP. IPv6 needs no forwarding address: the host's own IPv6 address is opened on these ports." |
   | **Ports** | One or more ports, "Comma or space separated", such as `5000, 5001`. Each port is forwarded to the same port on the host. Ranges aren't supported, and entries that aren't a port number are ignored. |
   | **Sources (optional)** | WAN addresses or prefixes the forward is limited to, IPv4 and IPv6 mixed, such as `203.0.113.0/24` or `2001:db8::/48`. Type one and press Enter or click **Add**. Empty allows any source. |

3. Click **Add** (or **Update** when editing). Problems are listed under the form, and the button stays disabled while there is an error.
4. Click **Save & apply**.

The list shows each forward's name, protocol, host (with its addresses), family, ports and sources. A forward whose host no longer exists is marked **unknown host**.

## How it works

Ports are mapped one to one: WAN port 5000 goes to port 5000 on the host.

### IPv4

The router rewrites the destination of matching WAN traffic to the host's static IP (DNAT, in the `inet nat` prerouting chain). The forward chain then admits only connections that this DNAT produced (`ct status dnat`). A packet sent from the WAN segment straight at the host's internal address is still dropped.

Clients connect to the router's public IPv4 address.

### IPv6

There is no NAT for IPv6. The router opens a pinhole in the forward chain to the host's own global address. The ISP-delegated prefix can change at any time, so the rule matches the address by its low 64 bits on the bridge of the host's network (`br-lan`, or `br-guest` for a host on the guest network), and admits new connections only. This is the same technique OpenWrt uses.

Clients connect to the host's own IPv6 address, not the router's. If the host has a **Public hostname**, [dynamic DNS](/docs/dynamic-dns/) publishes its AAAA record as the current prefix plus the suffix, and its A record as the router's WAN IPv4.

### The generated rules

For a forward of tcp 5000 and 5001 to `nas` (`192.168.1.20`, suffix `::20`), with `eth0` as the WAN interface, the router generates:

```text
# inet nat, prerouting: IPv4 DNAT
iifname "eth0" tcp dport { 5000, 5001 } dnat ip to 192.168.1.20 comment "Synology DSM"
# inet filter, forward: admit only the DNAT'd connections
iifname "eth0" ip daddr 192.168.1.20 tcp dport { 5000, 5001 } ct status dnat accept comment "Synology DSM"
# inet filter, forward: the IPv6 pinhole
iifname "eth0" oifname "br-lan" ip6 daddr & ::ffff:ffff:ffff:ffff == ::20 tcp dport { 5000, 5001 } ct state new accept comment "Synology DSM"
```

**Firewall → Active rules** shows the live ruleset.

### No NAT loopback

Port forwards only match traffic that arrives on the WAN. A LAN client that connects to the router's public IPv4 address doesn't reach the host.

For a host with both a **Public hostname** and a **Static IP**, the router's resolver answers LAN clients with the host's LAN address instead, so the public name works inside too. This split-horizon answer needs the router's Technitium DNS server. The reverse proxy is different: it has its own [hairpin](/docs/ingress/reverse-proxy/#ports-and-hairpin) handling.

## Restrict sources

With an empty **Sources** list, anyone can connect. A non-empty list limits the forward to those addresses and prefixes. Each family uses only its own entries: the IPv4 rules see the IPv4 prefixes, and the IPv6 pinhole sees the IPv6 prefixes.

So a restricted forward with no prefix of one family opens nothing for that family. Cockpit warns about it:

- "All sources are IPv4, so the IPv6 side of this forward stays closed."
- "All sources are IPv6, so nothing is forwarded over IPv4."

The rebuild prints matching warnings. To silence them, add prefixes of the other family, or set **Family** to the one you mean.

## Mix families

**IPv4 + IPv6** needs both host fields: the **Static IP** for the DNAT and the **IPv6 suffix** for the pinhole. If the host lacks one, choose **IPv4 only** or **IPv6 only**.

A common setup is a host with a **Public hostname** and a forward for both families. Clients that use IPv4 reach it through the router's address and the DNAT. Clients that use IPv6 reach the host's own address through the pinhole.

## UPnP and NAT-PMP

UPnP-IGD and NAT-PMP let LAN devices, such as game consoles, open inbound ports for themselves. The router runs miniupnpd for this. It is off by default.

To turn it on, open **Firewall → UPnP**, switch on **Enable UPnP / NAT-PMP**, and click **Save & apply**. **Extra miniupnpd.conf** takes extra configuration lines, which are appended after the router's defaults.

The defaults are strict:

- a device can only map ports to its own address;
- only the LAN can request mappings, never the guest network;
- only ports 1024 to 65535 can be mapped.

How UPnP differs from static port forwards:

- **Nothing to audit:** mappings aren't in the settings file. miniupnpd installs them at runtime in its own nftables table, and devices ask without authentication.
- **IPv4 only:** the firewall admits UPnP traffic by matching connections that miniupnpd has NAT'd. For IPv6, use a static forward.
- **Lost on reload:** when the firewall ruleset reloads, for example after you apply a change to it, live mappings are cleared. Devices request them again when they renew, and a miniupnpd restart restores them from its lease file.

## Threat protection and IPv6

:::doc-warning
Each forward exposes the host directly to the internet. With [threat protection](/docs/threat-protection/) on, forwarded traffic still passes through Suricata. But Suricata's `HOME_NET` doesn't include the ISP-delegated IPv6 prefix, so rules written for traffic to `$HOME_NET` don't match inbound IPv6. Forward only what must be reachable, and restrict sources where you can.
:::

## In the settings file

Port forwards are the top-level `portForwards` list. `protocol` defaults to `tcp`, `family` to `both`, and `sources` to an empty list (any source). The host must exist in `hosts`.

```json
{
  "hosts": [
    {
      "mac": "aa:bb:cc:dd:ee:01",
      "name": "nas",
      "staticIp": "192.168.1.20",
      "ipv6Suffix": "::20"
    }
  ],
  "portForwards": [
    {
      "name": "Synology DSM",
      "protocol": "tcp",
      "host": "nas",
      "family": "both",
      "ports": [5000, 5001]
    },
    {
      "name": "Office SSH",
      "protocol": "tcp",
      "host": "nas",
      "family": "both",
      "ports": [22],
      "sources": ["203.0.113.0/24", "2001:db8:100::/48"]
    }
  ]
}
```

### Forwards from older versions

Older versions stored a forward as an address, with `destination` and `source` keys. The next rebuild upgrades such a forward automatically. It is pointed at the host whose `staticIp` is the old destination, set to `family` `ipv4`, and its `source` moves into `sources`. If no registered host reserves that address, the rebuild stops and names the forward: register the device with that static IP, then apply again. See [Settings migrations](/docs/develop/settings-migrations/).

## Build checks

Cockpit catches most of these before you save. The rebuild enforces all of them. `NAME` is the forward's name, or its host when it has none, and a message shown here starting with `...` begins with `router.portForwards: forward 'NAME'`.

| Message | Fix |
| --- | --- |
| `router.portForwards: forward 'NAME' references unknown host 'HOST' — it must name a router.hosts entry` (Cockpit: "Host 'HOST' is not registered.") | Register the host, or pick another one. |
| `... forwards IPv4 to host 'HOST', which has no staticIp (DHCP reservation) to DNAT to — set one, or set family = "ipv6"` (Cockpit: "HOST has no static IP to forward IPv4 to — reserve one on the Hosts page, or forward IPv6 only.") | Give the host a **Static IP**, or choose **IPv6 only**. |
| `... forwards IPv6 to host 'HOST', which has no ipv6Suffix to open a pinhole for — set one, or set family = "ipv4"` (Cockpit: "HOST has no IPv6 suffix to open a pinhole for — set one on the Hosts page, or forward IPv4 only.") | Give the host an **IPv6 suffix**, or choose **IPv4 only**. |
| `... needs at least one port, and port 0 cannot be forwarded` (Cockpit: "Enter at least one port (1-65535).") | Enter a port from 1 to 65535. |
| `... has an invalid source prefix in [ ... ] — use IPv4 or IPv6 addresses or CIDR prefixes` (Cockpit: "Not an IPv4 or IPv6 address or prefix: ...") | Fix the entry, such as `203.0.113.0/24`. |
| `... forwards a WireGuard listen port (UDP 51820); its DNAT would capture the tunnel's own traffic` | Forward a different port, or make the forward **IPv6 only**. Cockpit doesn't check this one. |
| `router.portForwards: more than one unrestricted IPv4 forward claims tcp/443 — only the first DNAT would ever match` (Cockpit: "Another unrestricted IPv4 forward already claims tcp 443.") | Keep one forward per port and protocol, or restrict both with **Sources**. |
| `router.portForwards: 'NAME' forwards IPv4 tcp 80/443, which the reverse proxy owns — route the host through router.reverseProxy.routes instead, or set the forward's family = "ipv6"` (Cockpit: "tcp 80/443 over IPv4 belong to the reverse proxy — add a Reverse proxy route for the host instead, or forward IPv6 only.") | Publish the app through a [reverse proxy route](/docs/ingress/reverse-proxy/), or make the forward **IPv6 only**. |

## Limits

- Ports are mapped one to one. You can't forward WAN port 2222 to port 22 on the host.
- A forward carries one protocol. Add a second forward for udp.
- Only one unrestricted IPv4 forward can claim a given port and protocol.
- There is no NAT loopback; see [No NAT loopback](#no-nat-loopback).
- While the reverse proxy is on, IPv4 tcp 80 and 443 can't be forwarded.
- IPv6 forwards depend on a stable host suffix.
