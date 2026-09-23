# Port forwards & dynamic DNS

Two features make a device on the LAN reachable from the internet:

-   **Port forwards** (`router.portForwards`) open ports on a registered device over IPv4, IPv6, or both.
-   **Dynamic DNS** (`router.ddns`) keeps public names on Cloudflare pointed at the router's changing addresses.

Both build on the host registry (`router.hosts`, the Cockpit **Hosts** page), and both are edited in Cockpit: **Firewall → Port forwards** and **Network → Dynamic DNS**.

## Hosts: the fields that matter

| Field | Needed for |
| --- | --- |
| `staticIp` | IPv4 forwards. It is the DNAT target, so the device needs a DHCP reservation. |
| `ipv6Suffix` | IPv6 forwards and the device's AAAA record. |
| `publicHostname` | A DNS name dynamic DNS publishes for the device. |

### The IPv6 suffix

The ISP delegates the IPv6 prefix, and it can change at any time. So the router identifies a device by the **low 64 bits** of its address (the interface identifier), e.g. `::42`, and combines that with whatever prefix is current.

The suffix must be **stable**, so pick one of these:

-   **A token set on the device.** On Linux use `ip token set ::42 dev eth0`, or networkd's `Token=::42`, or NetworkManager's `ipv6.token`. This is the most predictable option.
-   **The device's EUI-64 identifier.** Use this only if the device actually builds its address from its MAC. The **EUI-64** button on the Hosts page fills it in.

Do not use a device's privacy or temporary addresses, or RFC 7217 "stable-privacy" addresses (the default on most desktops and phones). They change whenever the prefix changes, so the forward and the AAAA record would stop matching. The Hosts page lists the global addresses a device is using right now, for convenience. Only pick one you know is stable.

## Port forwards

Each forward names a **host**, a **protocol**, one or more **ports** (mapped 1:1), a **family**, and optional **sources**.

-   **IPv4:** traffic to the router's public IPv4 on the port is DNAT'd to the host's `staticIp`. The forward-chain accept only admits connections that DNAT produced.
-   **IPv6:** there is no NAT. The firewall opens a pinhole to the host's own global address, matched as `ip6 daddr & ::ffff:ffff:ffff:ffff == <suffix>` on the host's bridge (`br-lan` or `br-guest`). This is the same technique OpenWrt uses. Clients connect to the host's AAAA address, not the router's.
-   **family:** `both` (the default), `ipv4` or `ipv6`. A family needs the matching host field: `staticIp` for IPv4, `ipv6Suffix` for IPv6. The rebuild fails with a message naming the forward if it is missing, and the Cockpit form refuses to save it.
-   **sources:** a list of WAN prefixes the forward is limited to, and it may mix families. Each family only uses its own entries. A non-empty list with no entries of a family closes that family entirely, and you get a warning about it.

Renaming a host in Cockpit updates its forwards. Removing a host removes its forwards, and the confirmation says how many.

There is **no NAT loopback**. For a host with both a `publicHostname` and a `staticIp`, the router's resolver answers that name with the LAN address for LAN clients. This is a split-horizon record, and it needs Technitium to be enabled.

### Suricata

Inbound traffic passes the IPS as before. But `HOME_NET` lists only IPv4 networks, so signatures keyed on `$HOME_NET` do not match inbound IPv6.

## Dynamic DNS (Cloudflare)

| Name | A record | AAAA record |
| --- | --- | --- |
| each of `ddns.names` (the router) | WAN IPv4 | the router's own global IPv6: the WAN's if the ISP assigns one, otherwise its `br-lan` address from the delegated prefix |
| each host's `publicHostname` | WAN IPv4 (reach it through a port forward) | the host's current /64 plus its `ipv6Suffix` (omitted if it has no suffix) |

### Setup

1.  In the Cloudflare dashboard (**My Profile → API Tokens**), create a token with **Zone → Zone → Read** and **Zone → DNS → Edit**, limited to the zones of your names.
2.  In Cockpit, open **Network → Dynamic DNS → Set token…**. The token is written to `/etc/router/secrets/cloudflare-ddns.token` (root, 0600) through stdin. Only the path goes into the settings file.
3.  Enable dynamic DNS, add the router names, and apply.

`router-ddns.service` then runs at boot, after every rebuild, and every `intervalMinutes` (default 5). Here is how it behaves:

-   **Detecting the WAN IPv4.** If the WAN address is private or CGNAT (for example, the router sits behind an ISP modem that still does NAT), the public address comes from Cloudflare's trace endpoint instead.
-   **Writing to Cloudflare.** It only writes when an address changes. It re-verifies every record every 6 hours, which repairs any edits made by hand.
-   **One record per type.** Each name ends up with exactly one record of each type. Records the tool creates carry the comment `managed by nixos-router`.
-   **A missing family.** If a family has no address during a run (for example, the prefix delegation is briefly lost), those records are **left as they are**, not deleted.
-   **A removed name.** When a name is removed from the configuration, only records carrying the comment are deleted.
-   **Proxying.** `proxied = true` orange-clouds the records. Only HTTP(S) on Cloudflare's supported ports gets through a proxied name.

The **Network → Dynamic DNS** tab shows the last run: the addresses detected and each record's result. It also has an **Update now** button. The raw status is in `/var/lib/router-ddns/status.json`.
