---
title: DNS enforcement
description: How the router keeps clients on its filtering resolver, what it can't enforce, SafeSearch, the resolver settings, and split-horizon DNS records.
code:
  - modules/firewall.nix
  - modules/dns-technitium.nix
  - modules/filter-catalog.nix
  - modules/network.nix
  - modules/threat-protection.nix
  - pkgs/router-dns-tools/router_dns_tools/compile_policies.py
  - pkgs/router-dns-tools/router_dns_tools/reconcile.py
  - pkgs/router-dns-tools/router_dns_tools/local_dns.py
  - pkgs/cockpit-router/src/access-policies.tsx
  - pkgs/cockpit-router/src/dns.tsx
---

# DNS enforcement

A DNS filter only works if clients use it. This page explains how the router steers clients on the LAN and guest networks to its own resolver and blocks the common ways around it. It also covers what the router can't enforce, the SafeSearch and resolver settings, and the local DNS records the resolver answers itself.

## What the router enforces

| Measure | Applies to | Setting |
| --- | --- | --- |
| DHCP hands out the router as the DNS server | LAN, guest | Always on |
| IPv4 DNS to any other server is redirected to the router | LAN, guest | Always on |
| DNS over TLS and DNS over QUIC (port 853) are dropped | LAN, guest | Always on |
| DNS over IPv6 (port 53) is dropped | LAN, guest | Always on |
| Public DNS-over-HTTPS resolver domains are blocked | Every policy | **Block DoH providers**, on by default |
| SafeSearch is forced on Google, Bing, DuckDuckGo and YouTube | Every client | **Enforce SafeSearch**, off by default |
| Suricata alerts on bypass attempts | LAN, guest, WireGuard | On while Suricata is on |

### Redirected DNS

DHCP on the LAN hands out the LAN gateway address as the DNS server, and the guest network hands out the guest gateway. A client that ignores this and sends IPv4 DNS (UDP or TCP port 53) to another server, such as `8.8.8.8`, is redirected: the firewall rewrites the destination to the router's gateway address on that network. The client gets the router's answer, filtered by its policy, and can't tell the difference.

### Dropped DNS over TLS and IPv6

- **Port 853:** the router doesn't offer DNS over TLS or DNS over QUIC, so the firewall drops TCP and UDP port 853 from the LAN and guest networks to anywhere. Android's automatic Private DNS mode falls back to ordinary DNS. A device set to a specific private DNS provider has no DNS until that setting is changed.
- **IPv6 port 53:** the device and directory tiers of a policy are anchored to each device's IPv4 reservation, so an IPv6 query could only ever get the default policy, a bypass for any device on a stricter one. The router doesn't advertise an IPv6 DNS server, and it drops TCP and UDP port 53 over IPv6 from the LAN and guest networks, both to the router and to outside servers. Clients use IPv4 DNS instead.

The drops live in their own nftables table, `inet dns_bypass`, which runs before the main firewall rules. See [Troubleshooting](/docs/access-policies/troubleshooting/#useful-commands) to inspect it.

### Blocked DoH providers

Browsers and apps can send DNS inside ordinary HTTPS (DoH), which the firewall can't tell apart from web traffic. While **Block DoH providers** is on, the router adds these resolver domains, with their subdomains, to every policy's block list:

- `dns.google`
- `cloudflare-dns.com`
- `mozilla.cloudflare-dns.com`
- `dns.quad9.net`
- `doh.opendns.com`
- `dns.nextdns.io`
- `doh.cleanbrowsing.org`
- `dns.adguard.com`
- `doh.mullvad.net`
- `dns.controld.com`

A browser in its default DoH mode that can't resolve its DoH server falls back to the system's DNS, which is the router. A browser set to use DoH strictly fails instead. For broader coverage on strict policies, also turn on the `doh` UT Capitole category ("Site which provides DNS over HTTP service"). An allow rule in a policy overrides this list, like any other block.

### SafeSearch

While **Enforce SafeSearch** is on, the router answers these names with the provider's restricted service, for every client and every policy:

| Name | Answered with |
| --- | --- |
| `www.google.com` | `forcesafesearch.google.com` |
| `www.bing.com` | `strict.bing.com` |
| `duckduckgo.com`, `www.duckduckgo.com` | `safe.duckduckgo.com` |
| `www.youtube.com`, `m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com`, `www.youtube-nocookie.com` | `restrict.youtube.com` |

The router creates a small zone for each name, holding an ANAME record that points at the restricted host. It tracks those zones in `/var/lib/router-technitium/managed-zones.json` and removes them when you turn SafeSearch off. SafeSearch applies to every client, so it can't differ between policies. Only `www.google.com` is covered, not Google's country domains such as `www.google.co.uk`. To close that gap on a strict policy, block the country domains your users reach under **Block domains**.

### Suricata alerts

When [threat protection](/docs/threat-protection/) is on, Suricata loads local rules that raise alerts, without blocking, for bypass attempts from your networks:

| SID | Alert |
| --- | --- |
| 1000001 | `POLICY DoT bypass attempt`: a TLS connection to port 853 |
| 1000002 to 1000007 | `POLICY DoH bypass`: a TLS connection whose server name is Cloudflare, Google DNS, Quad9, NextDNS, Mullvad or AdGuard DNS |
| 1000010, 1000011 | `POLICY SafeSearch bypass`: `safe=off` or `safeSearch=off` in an unencrypted HTTP request |

The DoH rules catch clients that already know a resolver's IP address, for example from a built-in list, and connect without asking DNS, which DNS blocking can't stop. The SafeSearch rules only see plain HTTP, so they rarely fire. The DoT rule fires only for WireGuard peers: the port 853 drop stops LAN and guest traffic before Suricata sees it.

## What the router does not enforce

- **WireGuard clients.** DNS arriving over WireGuard isn't redirected, and the port 853 and IPv6 drops don't apply. A WireGuard peer is filtered only if its configuration names the router as its DNS server. The router treats WireGuard peers as trusted devices. See [WireGuard](/docs/wireguard/).
- **Clients on a VPN or proxy.** A device with its own VPN sends DNS through the tunnel, out of the router's reach. The `vpn` and `redirector` categories block many VPN and proxy websites, but not a VPN that is already configured.
- **DoH the list doesn't know.** A resolver that isn't on the list, or that the client reaches by IP address, isn't blocked. Suricata can alert on some of these.
- **Apps with hard-coded addresses.** An app that connects by IP address never asks DNS.
- **The router itself.** The router's own lookups use an unfiltered built-in group.

## Resolver settings

The same settings appear in two places: **Access Policies → DNS settings** and **DNS → Resolver**. Both edit the same keys, so change them in either one and click **Save & apply**.

| Setting | On **DNS settings** | On **DNS → Resolver** | JSON key | Default |
| --- | --- | --- | --- | --- |
| Upstream DNS-over-HTTPS servers | **Upstream servers** | **Upstream resolvers** | `dns.technitium.upstreamServers` | `https://dns.cloudflare.com/dns-query`, `https://dns.google/dns-query` |
| SafeSearch | **Enforce SafeSearch** | **Enforce SafeSearch** | `dns.technitium.safeSearch` | off |
| DoH blocking | **Block DoH providers** | **Block public DoH resolvers** | `dns.technitium.blockDoHProviders` | on |
| Local names for reserved devices | | **Publish static hosts** | `dns.registerStaticHosts` | on |
| Listening port | **DNS listen port** | | `dns.technitium.listenPort` | 53 |
| Technitium console port | **Web console port** | | `dns.technitium.webPort` | 5380 |

The router forwards queries it can't answer to the upstream servers over DNS-over-HTTPS, queries them concurrently and validates DNSSEC. It answers recursive queries only from the LAN, guest and WireGuard networks, and the firewall drops port 53 from the WAN.

:::doc-warning
Leave **DNS listen port** at 53. The DHCP settings and the port 53 redirect always send clients to port 53, so any other value stops DNS for the whole network.
:::

```json
{
  "dns": {
    "registerStaticHosts": true,
    "technitium": {
      "upstreamServers": [
        "https://dns.cloudflare.com/dns-query",
        "https://dns.google/dns-query"
      ],
      "safeSearch": true,
      "blockDoHProviders": true
    }
  }
}
```

### When Technitium is off

Setting `dns.technitium.enable` to `false` in the settings file turns off filtering, not DNS. DHCP and the port 53 redirect still point clients at the router, so `systemd-resolved` answers on the gateway addresses instead. The build warns:

```text
router.dns.technitium.enable is false: LAN DNS is being answered by
systemd-resolved with NO content filtering. Access policies, SafeSearch
and DoH-provider blocking are all inactive, and queries are forwarded
in plaintext to the WAN-provided resolvers rather than over DoH.
```

In this mode the query log, reports, the block page, directory sync and the split-horizon records below are off as well.

## Split-horizon DNS

The resolver can answer some names itself, so internal clients reach a service at its internal address instead of going out through the WAN address. The answers are served to LAN, guest and WireGuard clients only; the outside world never sees them. You manage them on the **DNS** page.

### Overrides

**DNS → Overrides** holds single records. Click **Add override**, fill in the fields and click **Add**, then **Save & apply**.

- **Name:** the fully qualified name, such as `nas.example.com`. The page lowercases it and removes a trailing dot.
- **Type:** `A`, `AAAA`, `CNAME`, `ANAME`, `TXT` or `SRV`. A CNAME is illegal at the top of a zone, so an alias that owns its own name must use `ANAME`: the router resolves the target and answers with its addresses.
- **Value:** an IP address for `A` and `AAAA`, a target name for `CNAME` and `ANAME`, free text for `TXT`, or `priority weight port target` for `SRV`, such as `10 5 5060 sip.example.com`.
- **TTL (seconds):** 300 by default.
- **Notes:** for your own reference.

### Forward zones

**DNS → Forward zones** hands a whole domain to another DNS server, such as an Active Directory domain controller. Every name under the zone is asked of that server.

- **Zone:** the domain, such as `corp.example.com`. It covers the whole subtree.
- **Forwarders:** one or more servers, each an address, an `address:port` pair, or a DoH or DoT URL. They are queried in the order given.
- **Protocol:** `Udp` (the default), `Tcp`, `Tls`, `Https` or `Quic`.
- **Validate DNSSEC:** off by default.
- **Notes:** for your own reference.

Because a forward zone sends its entire subtree elsewhere, an override for a name inside it would never be used, and the build rejects that combination.

### Names for your devices

With **Publish static hosts** on (the default), every device on the Hosts page that has a static IP gets an `A` record named after it under the LAN domain, plus a reverse `PTR` record. The name is lowercased, and characters other than letters and digits become hyphens: a device named "Lab PC 01" becomes `lab-pc-01.lan`. DHCP hands out the LAN domain as the search domain, so a bare `lab-pc-01` resolves too.

If two device names reduce to the same label, neither is published, and the build warns with that label. A device whose name matches an override, or the router's own name, is skipped as well. Registered devices without a static IP are also answered under the LAN domain, looked up live. See [Hosts and host groups](/docs/network/hosts/).

A device with a public hostname and a static IP is also answered with its LAN address for that public name. The router doesn't loop traffic back from its WAN address, so a LAN client given the public address couldn't reach the device.

The router's own name, `router.lan` with the default host name and LAN domain, always answers with the LAN gateway address.

### How the horizon stays split

A normal zone in Technitium answers everything under it, so a zone for `example.com` holding one record would turn every other name in the domain into "not found" on your network. To avoid that, every zone this feature creates is a *forwarder* zone. It answers the names you declared and sends every other name under it to the upstream servers. That makes an override on a domain apex, such as `example.com` itself, safe. The build still warns about apex overrides, because every internal client takes your answer for that name.

The router groups records into zones like this:

1. The declared zones are your forward zones and the LAN domain.
2. A record goes into the longest declared zone its name ends with.
3. A record under no declared zone gets a zone named exactly after itself, so neighboring names are unaffected.

The router's own zone stays an ordinary zone and isn't touched. The router records every zone and record it creates in `/var/lib/router-technitium/managed-local-dns.json`, and deletes only those when you remove them from the settings. A zone you created by hand in Technitium's console is left alone.

### In the settings file

```json
{
  "dns": {
    "overrides": [
      { "name": "nas.example.com", "type": "A", "value": "192.168.1.20" },
      { "name": "vault.example.com", "type": "ANAME", "value": "nas.example.com" }
    ],
    "forwardZones": [
      { "zone": "corp.example.com", "forwarders": ["192.168.1.5"], "protocol": "Udp" }
    ],
    "registerStaticHosts": true
  }
}
```

### Build errors and warnings

| Message | Fix |
| --- | --- |
| `router.dns.overrides: duplicate record(s): ...` | Remove the repeated record. A duplicate has the same name, type and value. |
| `router.dns.overrides: not a fully-qualified name (letters, digits, '-' and '.'; no trailing dot): ...` | Use a full name such as `nas.example.com`. |
| `router.dns.forwardZones: duplicate zone(s): ...` | Keep one entry per zone. |
| `router.dns.forwardZones: no forwarders given for zone(s): ...` | Add at least one forwarder. |
| `router.dns.overrides: nas.corp.example.com sits inside a router.dns.forwardZones zone, which forwards the entire subtree — remove the override or narrow the forward zone.` | Remove the override, or forward a narrower zone. |
| `router.dns.forwardZones: 'lan' is the LAN domain — ...` | Don't forward the LAN domain; your device names live there. Forward a narrower zone. |
| Warning: `router.hosts: these device names slugify to the same DNS label, so NONE of them is published: ...` | Rename one of the devices, or add an override. |
| Warning: `router.dns.overrides: example.com override a whole domain apex. ...` | Expected when you override an apex on purpose. |
