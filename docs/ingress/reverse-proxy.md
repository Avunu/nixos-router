---
title: Reverse proxy
description: Publish LAN web apps by hostname on the router's ports 80 and 443, with a Let's Encrypt certificate for each route.
code:
  - modules/reverse-proxy.nix
  - modules/acme.nix
  - modules/firewall.nix
  - modules/topology.nix
  - modules/ddns.nix
  - pkgs/router-proxy/src/main.rs
  - pkgs/router-proxy/src/proxy.rs
  - pkgs/router-proxy/src/redirect.rs
  - pkgs/router-proxy/src/state.rs
  - pkgs/cockpit-router/src/reverse-proxy.tsx
  - pkgs/cockpit-router/src/ingress.ts
  - pkgs/cockpit-router/src/ingress-widgets.tsx
  - pkgs/cockpit-router/src/ingress-runtime.ts
---

# Reverse proxy

The reverse proxy publishes web apps on your LAN under their own hostnames, such as `nas.example.com` and `wiki.example.com`, all on the router's ports 80 and 443. The router gets a Let's Encrypt certificate for each route, ends TLS, and passes each request to the route's host. Many apps can share one public IPv4 address, and an app that speaks plain HTTP on the LAN gets HTTPS without changes.

For a step-by-step example, see [Walkthrough: publish a web app](/docs/ingress/walkthrough/).

## Before you start

- **A registered host with a static IP** for each app. See [Hosts and host groups](/docs/network/hosts/).
- **Names that resolve to the router.** With **Publish hostnames** on (the default), [dynamic DNS](/docs/dynamic-dns/) publishes them, so dynamic DNS must be on, with its Cloudflare token set. Otherwise, create the DNS records yourself.
- **For the HTTP challenge,** the router's WAN tcp port 80 must be reachable from the internet.
- **For the Cloudflare DNS challenge or a wildcard name,** a Cloudflare API token with **Zone → Zone → Read** and **Zone → DNS → Edit**. See [Cloudflare API tokens](/docs/reference/cloudflare-tokens/).
- **No IPv4 port forward of tcp 80 or 443.** The proxy owns those ports.

## Turn it on

At the top of **Ingress → Reverse proxy**:

- **Enable reverse proxy** turns the proxy on. The help text: "Serves the routes below on the WAN's ports 80 and 443, choosing the host by name, with a Let's Encrypt certificate per route. Port 80 redirects to HTTPS and answers certificate challenges." Once the proxy is applied, a label next to the switch shows the state of `router-proxy.service`, such as **active** or **failed**.
- **Publish hostnames** is on by default. See [Publish hostnames](#publish-hostnames).

## Certificates

Set up the Let's Encrypt account once, in the **Certificates** card. The router requests nothing until the proxy is on and has at least one route.

| Field | What it does |
| --- | --- |
| **Contact email** | "Let's Encrypt sends certificate expiry warnings here." Required. |
| **Terms of service** | Check **I accept the Let's Encrypt Subscriber Agreement**. Required before any certificate is requested. The link below it opens the agreement. |
| **Staging CA** | Off by default. "Let's Encrypt's staging CA has far higher rate limits, but browsers do not trust its certificates. Use it while testing a new route, then switch back." |
| **Default challenge** | How a certificate proves control of its names, for routes that don't choose their own. **HTTP (port 80)** (the default) or **Cloudflare DNS**. |
| **Cloudflare API token file** | Path to a root-owned file holding the token for the Cloudflare DNS challenge. "Needed only for the Cloudflare DNS challenge." |

### Choose a challenge

| Challenge | How it works | Needs | Use it when |
| --- | --- | --- | --- |
| **HTTP (port 80)** (HTTP-01) | Let's Encrypt fetches a file from the name over port 80, which the proxy serves. | The name already resolves to the router, and WAN tcp port 80 is reachable. | The router has a public IPv4 address and nothing blocks port 80. |
| **Cloudflare DNS** (DNS-01) | The router creates a TXT record through the Cloudflare API. | A Cloudflare token with **Zone → Zone → Read** and **Zone → DNS → Edit** on the name's zone. | Your ISP blocks port 80, you want a certificate before the name resolves, or you need a wildcard. It is the only way to get a wildcard. |

Each route can override the default in its **Certificate challenge** field.

### Set the Cloudflare token

The token itself never goes into the settings file, only the path to it.

- **If dynamic DNS already has a token,** click **Use the DDNS token**. It points the field at the dynamic DNS token file, which has exactly the scopes the DNS challenge needs. The button appears only when a dynamic DNS token is set and the field names a different file.
- **Otherwise,** click **Set token…**. If the field is empty, it fills in `/etc/router/secrets/cloudflare-acme.token`. Paste the token into **API token** and click **Save token**. The token is written to that file, readable by root only.

Create the token under **My Profile → API Tokens** in the Cloudflare dashboard. See [Cloudflare API tokens](/docs/reference/cloudflare-tokens/).

## Add a route

1. Click **Add route**.
2. Fill in the form:

   | Field | What to enter |
   | --- | --- |
   | **Name** | Optional label, such as `NAS`. |
   | **Hostnames** | One or more public names. Type one and press Enter or click **Add**. "Public names routed to the host, all on one certificate named after the first. A leading `*.` matches one extra label and needs the Cloudflare DNS challenge." |
   | **Host** | The registered host. Each entry shows its static IP and IPv6 suffix. |
   | **Port** | The service's port on the host. Defaults to 80. **Scan ports** checks the host's 100 most common ports and lists the open ones; click one to fill it in. |
   | **Scheme** | **http** or **https**: "The protocol the host's service speaks." |
   | **Verify the host's certificate** | Shown for **https**. Off by default: "services inside the network mostly present self-signed certificates." |
   | **Certificate challenge** | **Default** (the card's default challenge, shown in parentheses), **Cloudflare DNS** or **HTTP (port 80)**. |
   | **HSTS** | "Send Strict-Transport-Security, so browsers refuse plain HTTP for these names for a year." Off by default. Turn it on only once the route works. |

3. Click **Add**. Problems are listed under the form, and the button stays disabled while there is an error.
4. Click **Save & apply**. If the configuration would fail the build, the tab lists the problems under **Fix these before applying** and **Save & apply** stays disabled.

The route list shows each route's name, hostnames, target (`host:port` and scheme), challenge, and certificate status.

A wildcard such as `*.apps.example.com` matches `wiki.apps.example.com`, but not `apps.example.com` or `a.b.apps.example.com`. An exact name in another route wins over a wildcard.

## Publish hostnames

With **Publish hostnames** on, dynamic DNS publishes every route hostname as a name for the router itself, exactly like its **Router names**. The help text: "Dynamic DNS points every route hostname at the router (A = WAN IPv4, AAAA = the router's IPv6). The HTTP certificate challenge depends on it."

- The A record is the WAN IPv4 address.
- The AAAA record is the router's global IPv6 address: the WAN's, or its LAN address from the delegated prefix when the ISP gives the WAN none.
- Dynamic DNS's own **Publish IPv4 (A)** and **Publish IPv6 (AAAA)** switches apply.
- Don't also add a route hostname to **Router names**. That fails the build, because two features would write the same record.

If dynamic DNS is off, the switch shows "Dynamic DNS is off (Network → Dynamic DNS), so nothing publishes these names."

Turn **Publish hostnames** off if you manage the records yourself, at Cloudflare or another DNS provider. Point each name at the router's public addresses, for example with a CNAME to one of your dynamic DNS router names. A route that uses the HTTP challenge then gets the warning "The HTTP challenge needs these names to resolve to the router, and publishing them is off — point them at the router yourself."

## Certificate status

The **Certificate** column shows each route's certificate once the proxy is applied:

| Status | Meaning |
| --- | --- |
| **No certificate** | No certificate file exists yet. |
| **Pending** | The self-signed placeholder is still in place. The first order hasn't succeeded. |
| **Valid until** *date* | Issued. Green, or orange with fewer than 14 days left. |
| **Issued** | A certificate is in place, but its end date couldn't be read. |
| **Expired** | The certificate has expired. |
| **Renewing…** | The order job is running, or waiting to retry after a failed run. |

Under the status, **last renewal failed** means the order job's last run failed. Otherwise the time of its last run is shown. The status is read when the tab opens and after **Renew now**; reload the page to refresh it.

A failed order job retries by itself every 15 minutes, so while an order keeps failing the status shows **Renewing…** with **last renewal failed** under it.

**Renew now** starts the route's order job, `acme-order-renew-<cert>.service`, and waits for it. If it fails, **Certificate renewal failed** shows the error. Use it to retry right after you fix the cause of a failed order, instead of waiting for the next automatic retry.

### The placeholder certificate

Until a route's first order succeeds, the router serves a self-signed placeholder certificate. It lets the proxy start and answer the HTTP challenge that the first order needs. Browsers warn about it, and Cockpit shows **Pending**.

### Where certificates live

Each route has one certificate, named after its first hostname in lowercase, with `*` written as `_`:

- `nas.example.com` → `/var/lib/acme/nas.example.com/`
- `*.apps.example.com` → `/var/lib/acme/_.apps.example.com/`

The proxy loads `fullchain.pem` and `key.pem` from that directory. The same name, as `<cert>`, appears in the unit names below.

### Renewal

A daily timer, `acme-renew-<cert>.timer`, starts the order job, which renews the certificate once less than a third of its lifetime is left. A renewal reloads the proxy without dropping connections.

Applying a change to a route's hostnames or to the **Staging CA** switch starts a new order.

## How it works

### The proxy

`router-proxy.service` runs `router-proxy`, a small program built on Cloudflare's Pingora library, as the unprivileged `router-proxy` user. It listens on tcp 10080 for HTTP and 10443 for HTTPS, over IPv4 and IPv6.

It doesn't listen on 80 and 443 because the Technitium [block page](/docs/access-policies/block-page/) already holds those ports on every router address. See [Ports and services](/docs/reference/ports/).

### Ports and hairpin

nftables redirects tcp 80 and 443 to the proxy's ports in two cases:

- **From the WAN,** when the destination is one of the router's own addresses. An IPv6 port forward of 443 to a host's own address is routed rather than delivered to the router, so it isn't redirected and keeps working.
- **From inside** (the LAN, WireGuard, and the guest network when it's on), when the destination is a router address that isn't on the interface the packet came in on. In practice, that's the WAN address a public name resolves to. This "hairpin" lets LAN clients use the public names without split-horizon DNS. Connections to the gateway address itself, such as `192.168.1.1`, still reach the block page.

Direct connections from the WAN to ports 10080 and 10443 are dropped. Only redirected traffic gets in.

### Plain HTTP

On port 80 the proxy never forwards anything:

- Requests for `/.well-known/acme-challenge/` are answered from the ACME webroot, for any name.
- A request for a route's hostname gets a `308 Permanent Redirect` to the same path over HTTPS.
- Anything else gets `404 Not Found`.

### HTTPS

1. The proxy picks the certificate by the name the client asks for in the TLS handshake (SNI). If the client sends no name, or no route covers it, the proxy offers no certificate and the handshake fails.
2. The request's `Host` header picks the route. A name no route claims gets `404 Not Found`. A `Host` that belongs to a different route than the TLS name gets `421 Misdirected Request`, so one route's certificate can't be used to reach another route.
3. The proxy connects to the host's static IP on the route's port, over http or https. HTTP/2 is offered to clients.
4. The request keeps its original `Host` header. The proxy sets these headers from what it saw itself:
   - `X-Forwarded-For` and `X-Real-IP`: the client's address;
   - `X-Forwarded-Proto`: `https`;
   - `X-Forwarded-Host`: the requested name.

   Values the client sent in these headers are replaced, and a client-supplied `Forwarded` header is removed, so the app can trust them.
5. With **HSTS** on, responses carry `Strict-Transport-Security` with `max-age=31536000` (one year).

With **Scheme** set to **https**, the proxy sends the route's first non-wildcard hostname as the TLS name to the host. It doesn't check the host's certificate unless **Verify the host's certificate** is on.

Connecting to the host times out after 10 seconds. There is no read timeout, so long polling and idle WebSockets stay open.

### Reloads

A certificate renewal reloads the proxy with SIGHUP, and so does an apply that edits a route but keeps its first hostname. The proxy re-reads its configuration and every certificate and swaps them in place. Listeners and open connections survive. If the new configuration or a certificate fails to load, the proxy keeps the previous one and logs `reload failed, keeping previous configuration`.

An apply that adds or removes a route, or changes a route's first hostname, changes the set of certificates the proxy waits for at startup, so it restarts the proxy instead, and open connections drop.

### Logs

The proxy writes one line per request to the journal: host, method, path, status, upstream, duration in milliseconds, and client address.

```bash
journalctl -u router-proxy -f
```

## In the settings file

The proxy is the top-level `reverseProxy` key, and the account settings are `acme`. Defaults: `publishDns` `true`; for a route, `port` `80`, `scheme` `"http"`, `tlsVerify` `false`, `challenge` `"default"`, `hsts` `false`; `acme.defaultChallenge` `"http"`, `acme.staging` `false`. Each route's `host` must be an entry in `hosts` with a `staticIp`.

```json
{
  "hosts": [
    { "mac": "aa:bb:cc:dd:ee:01", "name": "nas", "staticIp": "192.168.1.20" },
    { "mac": "aa:bb:cc:dd:ee:02", "name": "wiki", "staticIp": "192.168.1.21" }
  ],
  "acme": {
    "email": "admin@example.com",
    "acceptTerms": true,
    "staging": false,
    "defaultChallenge": "http",
    "cloudflare": {
      "apiTokenFile": "/etc/router/secrets/cloudflare-ddns.token"
    }
  },
  "reverseProxy": {
    "enable": true,
    "publishDns": true,
    "routes": [
      {
        "name": "NAS",
        "hostnames": ["nas.example.com"],
        "host": "nas",
        "port": 5000
      },
      {
        "name": "Apps",
        "hostnames": ["*.apps.example.com"],
        "host": "wiki",
        "port": 8443,
        "scheme": "https",
        "challenge": "dns-cloudflare",
        "hsts": true
      }
    ]
  }
}
```

`challenge` is `"default"`, `"http"` or `"dns-cloudflare"`; `acme.defaultChallenge` is `"http"` or `"dns-cloudflare"`.

## Build checks

Cockpit shows these before you apply, and the rebuild enforces them. `NAME` is the route's name, or its first hostname when it has none, and a message shown here starting with `...` begins with `router.reverseProxy.routes:`.

| Message | Fix |
| --- | --- |
| `router.acme.acceptTerms must be true before the router requests certificates (see https://letsencrypt.org/repository/)` (Cockpit: "Accept the Let's Encrypt terms of service before certificates can be requested.") | Check **I accept the Let's Encrypt Subscriber Agreement**. |
| `router.acme.email must be set before the router requests certificates` (Cockpit: "Set a contact email for the certificates.") | Fill in **Contact email**. |
| `router.reverseProxy.routes: every route needs at least one hostname` (Cockpit: "Enter at least one public hostname.") | Add a hostname. |
| `` router.reverseProxy.routes: route 'NAME' has an invalid hostname in [ ... ] — use public DNS names, optionally with a leading `*.` `` (Cockpit: "Not a valid public DNS name: ...") | Use a public DNS name, optionally with a leading `*.`. |
| `... route 'NAME' references unknown host 'HOST' — it must name a router.hosts entry` (Cockpit: "Host 'HOST' is not registered.") | Register the host, or pick another one. |
| `... route 'NAME' proxies to host 'HOST', which has no staticIp (DHCP reservation) — set one` (Cockpit: "HOST has no static IP to send the traffic to — reserve one on the Hosts page.") | Give the host a **Static IP**. |
| `... route 'NAME' has a wildcard hostname, which only a DNS-01 certificate can cover — set challenge = "dns-cloudflare"` (Cockpit: "A wildcard hostname needs a DNS-01 certificate — choose the Cloudflare DNS challenge.") | Set **Certificate challenge** to **Cloudflare DNS**. |
| `... route 'NAME' uses the dns-cloudflare challenge, but router.acme.cloudflare.apiTokenFile is not set` (Cockpit: "The Cloudflare DNS challenge needs an API token — set the token file under Certificates.") | [Set the Cloudflare token](#set-the-cloudflare-token). |
| `router.reverseProxy.routes: HOSTNAME appears in more than one route` (Cockpit: "HOSTNAME already appears in another route.") | Keep the name in one route. |
| `router.reverseProxy.routes: HOSTNAME is also a host's publicHostname — a name can point at the router or at a host, not both` (Cockpit: "HOSTNAME is also a host's public hostname — a name can point one way only.") | Clear the host's **Public hostname**. |
| `router.ddns.names: HOSTNAME is already published by router.reverseProxy.publishDns — remove it from ddns.names` (Cockpit: "HOSTNAME is also a dynamic DNS router name — remove it there (Network → Dynamic DNS).") | Remove the name from **Router names**. |
| `router.cloudflareTunnel.ingress: HOSTNAME is also published by reverse proxy route 'NAME' — a name can only point one way` (Cockpit: "HOSTNAME is also served through the Cloudflare Tunnel.") | Serve the name through one of them. |
| `router.portForwards: 'FORWARD' forwards IPv4 tcp 80/443, which the reverse proxy owns — ...` (Cockpit: "Port forward(s) FORWARD forward tcp 80/443 over IPv4, which belong to the reverse proxy — route the host here instead, or make the forward IPv6 only.") | Replace the forward with a route, or make it **IPv6 only**. |

In the Cockpit form, a port outside 1 to 65535 gives "Enter a port between 1 and 65535."

These don't stop the build, but print a warning:

- `router.reverseProxy.publishDns is on but router.ddns is disabled, so the route hostnames are not published — point them at the router yourself.`
- `router.reverseProxy is enabled with no routes; it only answers ACME challenges and 404s.`

## Limits

- HTTP and HTTPS only. For other protocols, use a [port forward](/docs/ingress/port-forwards/).
- Plain HTTP is never proxied, only redirected to HTTPS.
- A wildcard covers exactly one extra label, and needs the Cloudflare DNS challenge.
- While the proxy is on, IPv4 tcp 80 and 443 can't be port-forwarded.
- The proxy has no access control of its own. Anyone who reaches a name reaches the app, so the app's own login has to protect it.
- [Threat protection](/docs/threat-protection/) doesn't inspect proxied requests, because they end at the router instead of being forwarded.
- Behind CGNAT, IPv4 clients can't reach the proxy. Use [Cloudflare Tunnel](/docs/ingress/cloudflare-tunnel/) instead.
- If the ISP gives the WAN no global IPv6 address, the router's AAAA record is its LAN address. A LAN client that connects to that address over IPv6 reaches the block page instead of the proxy, because the address belongs to the interface the client is on.
- Let's Encrypt limits how many certificates you can order. Use **Staging CA** while you experiment.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Status stays **Pending**, or shows **last renewal failed**, and the browser warns about a self-signed certificate | The first order failed. With the HTTP challenge, the name doesn't resolve to the router yet, or WAN port 80 is blocked. | Check the name with `dig +short nas.example.com`, and look at `journalctl -u acme-order-renew-nas.example.com`. Fix the cause, or switch the route to **Cloudflare DNS**, then click **Renew now**. |
| The browser doesn't trust a certificate whose issuer mentions staging | **Staging CA** is on. | Turn it off and click **Save & apply**. The router orders a new certificate. |
| The TLS handshake fails | No route covers the name, or you connected by IP address. | Use a route hostname. |
| `404 Not Found` | No route claims the requested name. | Check the route's **Hostnames**. |
| `502 Bad Gateway` | The proxy can't reach the service on the host. | Check that the host is up, and the route's **Port** and **Scheme**. **Scan ports** shows what the host has open. |
| The app's links point to `http://` or to its LAN port | The app builds URLs from its own settings. | Set the app's public URL to `https://nas.example.com`, or turn on its reverse-proxy support. The proxy sends `X-Forwarded-Proto` and `X-Forwarded-Host`. |
| **Save & apply** is disabled | The tab found a problem that would fail the build. | Fix the items under **Fix these before applying**. See [Build checks](#build-checks). |
