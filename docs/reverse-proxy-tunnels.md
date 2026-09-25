# Reverse proxy & Cloudflare Tunnel

Both give many web services one public entry point and route requests **by hostname** instead of by port. A port forward can send a WAN port to only one host, so two services that both want 443 cannot both be forwarded.

| | Port forward | Reverse proxy | Cloudflare Tunnel |
| --- | --- | --- | --- |
| Routes by | port | hostname (SNI + Host) | hostname |
| Inbound WAN port | yes, per service | 80 and 443 | none |
| Works behind CGNAT | no | no | yes |
| TLS certificate | the host's own | the router's, from Let's Encrypt | Cloudflare's edge |
| Traffic passes through | nothing | the router | Cloudflare |
| Non-HTTP protocols | yes | no | no (HTTP(S) only here) |

All three are managed on the Cockpit **Ingress** page, which has a tab for each.

## Reverse proxy

`router-proxy` (`pkgs/router-proxy`) is a small Pingora program. It terminates TLS with each route's certificate and forwards the request to the route's registered host. The backend receives `X-Forwarded-For`, `X-Forwarded-Proto: https`, `X-Forwarded-Host` and `X-Real-IP`. The original `Host` header is kept, and WebSockets work.

A route has:

-   **hostnames:** one or more public names, all covered by one certificate named after the first. A leading `*.` matches one extra label, but only a DNS-01 certificate can cover it.
-   **host / port / scheme:** the registered host (its `staticIp`) and the service on it. With `scheme = "https"`, the host's certificate is not verified unless `tlsVerify` is on, because LAN services are usually self-signed.
-   **challenge:** see [Certificates](#certificates).
-   **hsts:** sends `Strict-Transport-Security` for a year.

Plain HTTP to a route's name gets a 308 redirect to HTTPS. A name no route claims gets no certificate, so the TLS handshake fails.

### Ports and hairpin

The Technitium Block Page app already holds ports 80 and 443 on every router address. The proxy therefore listens on 10080 and 10443, and nftables redirects to it:

-   **From the WAN:** tcp 80/443 aimed at one of the router's own addresses. An IPv6 port forward of 443 to a host's own address is routed, not local, so it keeps working.
-   **From inside (LAN, WireGuard, guest):** tcp 80/443 aimed at a router address that is *not* on the interface the packet came in on. In practice that is the WAN address a public name resolves to. LAN clients can use the public names with no split-horizon DNS, and the gateway addresses still go to the Block Page.

The proxy's own ports are closed to the WAN; only the redirected traffic is let in. While the proxy is enabled, an IPv4 port forward of tcp 80 or 443 is rejected.

### Certificates

Certificates come from Let's Encrypt through NixOS `security.acme` (lego), one per route, and live in `/var/lib/acme/<first hostname>/` (a `*` in the name becomes `_`). Set these once under **Ingress → Reverse proxy → Certificates**:

-   **email and accept terms:** both are required before anything is requested.
-   **staging:** uses Let's Encrypt's staging CA, whose certificates browsers do not trust but whose rate limits are much higher. Use it while trying out a new route.
-   **default challenge:** used by routes that do not choose their own.

| Challenge | Needs | Notes |
| --- | --- | --- |
| `http` (HTTP-01) | the name resolves to the router, and WAN :80 is reachable | The CA fetches a file from `http://<name>/.well-known/acme-challenge/`, which the proxy serves from lego's webroot. |
| `dns-cloudflare` (DNS-01) | a Cloudflare token with **Zone → Zone → Read** and **Zone → DNS → Edit** | Needs no inbound port, and works before the name resolves. The only way to get a wildcard. The DDNS token has the right scopes and can be reused. |

Until the first order succeeds, the proxy serves a self-signed placeholder, which Cockpit shows as **Pending**. Renewals run from a daily timer and reload the proxy. A reload swaps certificates and routes in place without dropping connections, and so does a rebuild that only changes routes. **Renew now** on a route starts `acme-order-renew-<cert>.service`.

### DNS

With **publishDns** on (the default), every route hostname is published through dynamic DNS as a name for the router (A = WAN IPv4, AAAA = the router's global IPv6), exactly like `ddns.names`. This needs dynamic DNS to be enabled, and HTTP-01 certificates depend on it. A name cannot be both a route hostname and a host's `publicHostname`.

## Cloudflare Tunnel

`cloudflared` keeps outbound connections open to Cloudflare, and requests for the tunnel's names come back down them to the chosen hosts. No WAN port is opened, it works behind CGNAT, and the router's address is never published.

The router manages the tunnel entirely through the Cloudflare API, so it is declared in the settings file like everything else:

1.  In the Cloudflare dashboard (**My Profile → API Tokens**), create a token with **Account → Cloudflare Tunnel → Edit**, **Zone → Zone → Read** and **Zone → DNS → Edit**, limited to your account and zones.
2.  In Cockpit, open **Ingress → Tunnel → Set token…**. The token is written to `/etc/router/secrets/cloudflare-tunnel.token` (root, 0600).
3.  Enable the tunnel, add the hostnames with their hosts and ports, and apply.

`router-cloudflare-tunnel.service` then does the following:

-   **The tunnel:** creates a locally configured tunnel named after the router. The tunnel secret is generated on the router and leaves it only in that one API call. The credentials are written to `/var/lib/router-cloudflared/credentials.json` (root, 0600), and `cloudflared` receives them through `LoadCredential`.
-   **DNS:** keeps one proxied CNAME per hostname pointing at `<tunnel id>.cfargotunnel.com`, carrying the comment `managed by nixos-router`. A record already at the name is taken over and put back when the name is dropped, the same way dynamic DNS does it.
-   **Drift:** runs at boot, after every rebuild, and every 5 minutes. It recreates a tunnel deleted in the dashboard and repairs records edited by hand.
-   **Disabling:** deletes the tunnel and its records. It needs the token for that, so keep the token set when you switch the tunnel off.

The **Tunnel** tab shows the tunnel, its connections to Cloudflare, and each hostname's DNS state. **Sync now** runs the service. The raw status is in `/var/lib/router-cloudflared/status.json`.

The tunnel's names must not also be dynamic DNS names, hosts' `publicHostname`s or reverse proxy hostnames, since those would fight over the same record.

If `/var/lib/router-cloudflared` is lost while the tunnel still exists, the service stops with an error rather than taking over a tunnel whose secret it does not have. Delete the old tunnel in the dashboard, and the next run creates a new one.
