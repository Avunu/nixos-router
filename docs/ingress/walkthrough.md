---
title: "Walkthrough: publish a web app"
description: Publish a NAS web interface on your LAN at nas.example.com over HTTPS with the reverse proxy, or through Cloudflare Tunnel behind CGNAT.
code:
  - modules/reverse-proxy.nix
  - modules/acme.nix
  - modules/firewall.nix
  - modules/ddns.nix
  - modules/cloudflare-tunnel.nix
  - pkgs/cockpit-router/src/hosts.tsx
  - pkgs/cockpit-router/src/dynamic-dns.tsx
  - pkgs/cockpit-router/src/reverse-proxy.tsx
  - pkgs/cockpit-router/src/tunnel.tsx
  - pkgs/cockpit-router/src/changes.tsx
---

# Walkthrough: publish a web app

This walkthrough publishes a NAS web interface that runs on your LAN at `http://192.168.1.20:5000` as `https://nas.example.com`, with a trusted Let's Encrypt certificate, through the [reverse proxy](/docs/ingress/reverse-proxy/). If your router is behind CGNAT, follow [the Cloudflare Tunnel variant](#variant-behind-cgnat-with-cloudflare-tunnel) at the end instead.

You need:

- a domain whose DNS is hosted on Cloudflare (`example.com` here);
- a Cloudflare API token with **Zone → Zone → Read** and **Zone → DNS → Edit** on that zone (see [Cloudflare API tokens](/docs/reference/cloudflare-tokens/));
- a public IPv4 address on the router's WAN, with inbound tcp ports 80 and 443 not blocked by your ISP.

## 1. Register the NAS

The proxy sends traffic to a registered host with a fixed address.

1. Open **Hosts → Devices** and find the NAS. Devices that aren't registered yet are listed while **Show unregistered** is on, which is the default.
2. Click **Adopt** on the NAS's row.
3. Set **Name** to `nas` and **Static IP** to `192.168.1.20`. **Suggest** proposes a free address if you'd rather let the router choose. Leave **Public hostname** empty: that field points a name at the device itself, and would conflict with the route.
4. Click **Adopt**, then **Save & apply**.
5. Restart the NAS, or renew its DHCP lease, so it picks up the reserved address.

See [Hosts and host groups](/docs/network/hosts/) for details.

## 2. Point the name at the router

`nas.example.com` has to resolve to the router's public address. The simplest way is to let the router publish it:

1. Open **Network → Dynamic DNS** and turn on **Enable dynamic DNS**.
2. Click **Set token…**, paste the Cloudflare token into **API token**, and click **Save token**.
3. Click **Save & apply**.

Don't add `nas.example.com` to **Router names**. The reverse proxy's **Publish hostnames** switch, which is on by default, publishes every route hostname through dynamic DNS once the route exists. Listing it under **Router names** as well fails the build. See [Cloudflare dynamic DNS](/docs/dynamic-dns/).

If you'd rather manage the record yourself, turn off **Publish hostnames** in step 4, and create the record at your DNS provider: an A record with the router's public IPv4 address, or a CNAME to a name that already points at the router, such as `home.example.com`.

## 3. Set up certificates

1. Open **Ingress → Reverse proxy**.
2. In the **Certificates** card, fill in **Contact email**, such as `admin@example.com`.
3. Check **I accept the Let's Encrypt Subscriber Agreement**.
4. Leave **Default challenge** at **HTTP (port 80)**. Let's Encrypt checks the name by fetching a file over port 80, which the proxy answers.

:::doc-tip
If your ISP blocks inbound port 80, set **Default challenge** to **Cloudflare DNS** and click **Use the DDNS token**. The dynamic DNS token has the right scopes, and this challenge needs no inbound port.
:::

## 4. Add the route

1. Turn on **Enable reverse proxy**. Leave **Publish hostnames** on.
2. Click **Add route** and fill in:
   - **Name:** `NAS`
   - **Hostnames:** type `nas.example.com` and press Enter.
   - **Host:** `nas`
   - **Port:** `5000`. If you're not sure of the port, click **Scan ports** and pick one from the list.
   - **Scheme:** **http**, since the NAS serves plain HTTP on port 5000.
   - **Certificate challenge:** leave it at **Default**.
   - **HSTS:** leave it off until everything works.
3. Click **Add**.

## 5. Save & apply

Click **Save & apply**. The bar at the top of the page shows **Applying configuration…**, then **Configuration applied.**

If **Save & apply** is disabled, the tab lists what's wrong under **Fix these before applying**. The [troubleshooting table](#troubleshooting) covers the usual causes.

## 6. Watch the certificate

The route's **Certificate** column shows **Pending** while the router serves a self-signed placeholder, or **Renewing…** while the order runs. When the order succeeds, it changes to **Valid until** and the certificate's end date. The status doesn't refresh on its own, so reload the page to update it.

If it stays **Pending**, or **last renewal failed** appears under it, the order failed. Check the name with `dig +short nas.example.com`, and read the order's log:

```bash
journalctl -u acme-order-renew-nas.example.com
```

Fix the cause, then click **Renew now** on the route to try again.

## 7. Test it

**From outside** your network, such as a phone on mobile data, open `https://nas.example.com`. The NAS login page appears with no certificate warning. From a computer outside the network you can also check the details:

```bash
dig +short nas.example.com A
curl -I http://nas.example.com/
curl -I https://nas.example.com/
```

- `dig` prints the router's public IPv4 address.
- The first `curl` gets `308 Permanent Redirect`, with a `location` header pointing at `https://nas.example.com/`.
- The second `curl` gets the NAS's own response, such as `200` or a redirect to its login page, with no certificate error.

**From inside,** open the same URL on a laptop on the LAN. The name resolves to the router's WAN address, and the router's hairpin rule hands the connection to the proxy, so the public name works inside without any DNS changes.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| "nas.example.com is also a dynamic DNS router name — remove it there (Network → Dynamic DNS)." | The name is also listed under **Router names**. | Remove it there. The route publishes it. |
| "nas.example.com is also a host's public hostname — a name can point one way only." | The NAS has `nas.example.com` as its **Public hostname**. | Clear the NAS's **Public hostname** on the Hosts page. |
| "Accept the Let's Encrypt terms of service before certificates can be requested." or "Set a contact email for the certificates." | Step 3 is incomplete. | Fill in the **Certificates** card. |
| "nas has no static IP to send the traffic to — reserve one on the Hosts page." | The host has no **Static IP**. | Repeat step 1. |
| `dig` returns nothing, or an old address | Dynamic DNS hasn't published the name yet, or dynamic DNS is off. | On **Network → Dynamic DNS**, check **Last update** and click **Update now**. |
| The certificate stays **Pending**, or shows **last renewal failed** | The name didn't resolve to the router yet, or inbound port 80 is blocked. | Fix DNS, or switch to the Cloudflare DNS challenge (see the tip in step 3), then click **Renew now**. |
| `502 Bad Gateway` | The proxy can't reach the NAS on that port and scheme. | Check that the NAS is at `192.168.1.20`, and use **Scan ports** to confirm the port. |
| The NAS's pages link back to port 5000 or to `http://` | The NAS builds links from its own settings. | Set its public address to `https://nas.example.com`, or turn on its reverse-proxy support. |
| It works from inside but not from outside | The router's WAN address isn't public. An address in `100.64.0.0/10` or a private range means CGNAT. | Use the Cloudflare Tunnel variant below. |

## Variant: behind CGNAT with Cloudflare Tunnel

Behind CGNAT, nothing on the internet can connect to the router over IPv4, so IPv4 clients can't reach the reverse proxy. [Cloudflare Tunnel](/docs/ingress/cloudflare-tunnel/) works anyway, because the router opens the connection to Cloudflare. It needs no certificate settings and no dynamic DNS: Cloudflare provides the certificate, and the router creates the DNS record.

1. **Register the NAS** as in step 1.
2. **Create a token** in the Cloudflare dashboard with **Account → Cloudflare Tunnel → Edit**, **Zone → Zone → Read** and **Zone → DNS → Edit**. See [Cloudflare API tokens](/docs/reference/cloudflare-tokens/).
3. **Remove other uses of the name.** If you followed the steps above, delete the `nas.example.com` route on **Ingress → Reverse proxy**, or turn the proxy off. The name also can't be a dynamic DNS **Router names** entry or a host's **Public hostname**.
4. Open **Ingress → Tunnel**. Click **Set token…**, paste the token into **API token**, and click **Save token**.
5. Turn on **Enable Cloudflare Tunnel**.
6. Click **Add hostname** and fill in **Hostname** `nas.example.com`, **Host** `nas`, **Port** `5000` and **Scheme** **http**. Click **Add**.
7. Click **Save & apply**.
8. In the **Tunnel status** card, click **Sync now**. **Last sync** shows **ok**, `nas.example.com` shows **ok** under the DNS records, and the tunnel's status turns **healthy** once the connector is connected.

Then open `https://nas.example.com` from outside. It works from inside too: the name resolves to Cloudflare, so LAN clients go out to Cloudflare and come back through the tunnel.
