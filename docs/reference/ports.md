---
title: Ports and services
description: Every port the router listens on or redirects, which networks can reach it, and the settings that open or move it.
code:
  - modules/firewall.nix
  - modules/topology.nix
  - modules/system.nix
  - modules/network.nix
  - modules/dns-technitium.nix
  - modules/reporting.nix
  - modules/reverse-proxy.nix
  - modules/wireless.nix
  - modules/wireless-unifi.nix
  - modules/wireless-openwisp.nix
  - local/flake.nix
---

# Ports and services

This page lists every port the router listens on, and the traffic it redirects. Use it to plan firewall rules upstream, to check what a network segment can reach, or to troubleshoot a service that doesn't answer.

## Who can reach the router

The firewall decides by the interface a packet arrives on:

- **LAN** (`br-lan`) and **WireGuard** tunnels are trusted. They can reach every port the router listens on.
- **Guest** (`br-guest`) can reach DHCP and DNS only, plus the block page and the reverse proxy when those are on.
- **WAN** can reach only what is listed for it below. Everything else from the WAN is dropped.

A service bound to `127.0.0.1` is reachable from the router itself only.

## Always on

| Port | Service | Reachable from | Notes |
| --- | --- | --- | --- |
| 22/tcp | SSH (OpenSSH) | LAN, WireGuard | Key authentication only; no passwords and no root login. |
| 53/udp, 53/tcp | DNS: Technitium, or systemd-resolved when Technitium is off | LAN, WireGuard, guest | Always port 53: DHCP gives clients the router's address, never a port. The WAN is dropped. See [Redirected and blocked traffic](#redirected-and-blocked-traffic). |
| 67/udp | DHCPv4 server (systemd-networkd) | LAN, guest | One server per bridge. |
| 546/udp | DHCPv6 client | WAN | Only replies sent from port 547, for the IPv6 prefix delegation. |
| 5353/udp | mDNS (Avahi) | LAN | Publishes `<hostName>.local`. Avahi answers on the LAN bridge only, and the firewall drops 5353 from the guest network and the WAN. |
| 5380/tcp | Technitium web console and API | The router only | Bound to `127.0.0.1`. Cockpit uses it. `dns.technitium.webPort` moves it. |
| 8067/tcp | `router-logd`: query log and exception requests | LAN, WireGuard; guest when the block page is on | Bound to every address. The exception-request form posts here; the data endpoints need a token. `reporting.logd.port` moves it. |
| 9090/tcp | Cockpit (HTTPS) | LAN, WireGuard | Set with `router.cockpit.port` in the host flake. Cockpit accepts logins at the LAN gateway address, each tunnel's own address, `<hostName>.local` and `<hostName>.<lan.domain>`. See [The web UI](/docs/start/cockpit/#sign-in). |
| ICMP, ICMPv6 | Ping and error messages | LAN, WireGuard, WAN | From the WAN, ping is rate-limited to 20 per second, and only the error and neighbor-discovery messages IPv4 and IPv6 need are admitted. From the guest network, only IPv6 neighbor discovery and replies to the router's own traffic. |

Technitium, `router-logd`, Avahi and the block page only run while `dns.technitium.enable` is on, which is the default.

## When a feature is on

| Port | Service | Turned on by | Reachable from | Notes |
| --- | --- | --- | --- | --- |
| 80/tcp, 443/tcp | Block page (Technitium Block Page app) | `accessPolicies.blockPage.enable` | LAN, WireGuard, guest | Bound to every address, with a self-signed certificate. Blocked names resolve to the LAN gateway address, where the page answers clients from every network, even with the reverse proxy on. |
| 80/tcp, 443/tcp to the router's WAN address | Redirected to the reverse proxy | `reverseProxy.enable` | WAN; LAN, WireGuard and guest by hairpin | See [Redirected and blocked traffic](#redirected-and-blocked-traffic). |
| 10080/tcp, 10443/tcp | Reverse proxy (`router-proxy`), HTTP and HTTPS | `reverseProxy.enable` | LAN and WireGuard directly; WAN and guest only through the redirect | Fixed ports. See [Reverse proxy](/docs/ingress/reverse-proxy/). |
| 51820/udp | WireGuard | A tunnel in `wireguard` | WAN, LAN, WireGuard | The default `listenPort`; each tunnel opens its own port on the WAN. An IPv4 UDP port forward can't use a tunnel's port. |
| 1900/udp, 5351/udp | UPnP IGD (SSDP) and NAT-PMP (miniupnpd) | `upnp.enable` | LAN | miniupnpd listens on `br-lan` only, never the guest network. It also opens an HTTP control port of its own choosing. |
| 8080/tcp, 8443/tcp, 10001/udp | UniFi Network Application: device inform, web UI, device discovery | `wireless.unifi.enable` | LAN, WireGuard | The controller uses the router's own network stack, so any other port it opens is reachable from the LAN and WireGuard too. Its MongoDB database is on a private container network with no published port. |
| 8081/tcp, 8444/tcp | OpenWISP dashboard, HTTP and HTTPS | `wireless.openwisp.enable` | LAN | Published on the LAN gateway address only. `wireless.openwisp.httpPort` and `httpsPort` move them. |
| 5432/tcp, 6379/tcp | PostgreSQL and Redis for OpenWISP | `wireless.openwisp.enable` | OpenWISP containers | Bound to `127.0.0.1` and the container network's gateway. The firewall admits LAN and WireGuard clients to that gateway address too, but PostgreSQL only accepts logins from the container subnet and Redis needs a password the containers hold. |

Port forwards open ports on your devices, not on the router; see [Port forwards](/docs/ingress/port-forwards/). The Cloudflare Tunnel, dynamic DNS, the directory sync and scheduled report emails only make outbound connections, and open no ports to your networks. Suricata inspects traffic in line and opens no network port.

## Redirected and blocked traffic

The router rewrites or drops some traffic before it reaches any service:

- **DNS from LAN and guest devices.** Every IPv4 DNS query on port 53, whichever server it is addressed to, is sent to the router's own resolver on that network's gateway address. See [DNS enforcement](/docs/access-policies/dns-enforcement/).
- **IPv6 DNS.** DNS queries over IPv6 from the LAN and the guest network are dropped, both to the router and to outside servers. The router advertises no IPv6 DNS server, so clients fall back to IPv4, where filtering policies apply.
- **DNS over TLS and QUIC.** Port 853, TCP and UDP, from the LAN and the guest network is dropped.
- **Web traffic to the router's WAN address.** With the reverse proxy on, TCP 80 and 443 aimed at one of the router's own addresses from the WAN are redirected to ports 10080 and 10443. LAN, WireGuard and guest clients are redirected the same way when they connect to any router address that isn't on their own network, in practice the WAN address a public name resolves to (hairpin). A client's connection to its own network's gateway address is left alone, and so is any client's connection to the LAN gateway address while the block page is on: blocked names point every client there. The proxy's own ports are closed to the WAN; only redirected connections reach them.
- **IPv4 port forwards.** Traffic to a forwarded port on the WAN address is sent on to the device's static IP. With the reverse proxy on, TCP 80 and 443 can only be forwarded over IPv6.

## Check what is listening

On the router, list the listening sockets and the processes that own them:

```bash
sudo ss -tulpn
```

The **Firewall → Active rules** tab in Cockpit shows the nftables ruleset in force.
