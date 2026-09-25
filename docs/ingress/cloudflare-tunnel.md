---
title: Cloudflare Tunnel
description: Publish LAN web apps through a Cloudflare Tunnel the router creates and maintains, with no inbound WAN port, even behind CGNAT.
code:
  - modules/cloudflare-tunnel.nix
  - pkgs/router-dns-tools/router_dns_tools/tunnel.py
  - pkgs/router-dns-tools/router_dns_tools/cloudflare.py
  - pkgs/cockpit-router/src/tunnel.tsx
  - pkgs/cockpit-router/src/ingress.ts
  - pkgs/cockpit-router/src/ingress-widgets.tsx
  - pkgs/cockpit-router/src/ingress-runtime.ts
---

# Cloudflare Tunnel

Cloudflare Tunnel publishes web apps on your LAN without opening any port on the WAN. The router runs `cloudflared`, which keeps outbound connections open to Cloudflare's edge. Requests for your names arrive at Cloudflare and come back down those connections to the router, which passes them to the right host. The router creates the tunnel and its DNS records through the Cloudflare API, so you configure all of it in Cockpit.

## When to use it

- **The router is behind CGNAT** and has no public IPv4 address, so nothing can connect to it from outside.
- **You don't want any inbound port open.** The router's address is never published either.
- **Your domain's DNS is on Cloudflare.** Every tunnel hostname must be in a zone on your Cloudflare account.

The trade-offs: Cloudflare ends TLS at its edge and sees the traffic decrypted, only HTTP and HTTPS services can be published this way, and [threat protection](/docs/threat-protection/) doesn't inspect tunneled requests. For a comparison with the other options, see [Choose an ingress](/docs/ingress/).

## Before you start

- **A registered host with a static IP** for each app. See [Hosts and host groups](/docs/network/hosts/).
- **A Cloudflare API token** with **Account → Cloudflare Tunnel → Edit**, plus **Zone → Zone → Read** and **Zone → DNS → Edit** on the zones of the tunnel's hostnames. Create it under **My Profile → API Tokens** in the Cloudflare dashboard. See [Cloudflare API tokens](/docs/reference/cloudflare-tokens/).
- **A unique router host name.** The tunnel is named after the router's **Host name** (**System → Settings**, `router` by default). Cloudflare keeps tunnel names unique per account, so two routers with the same host name can't share one account.

## Set it up

1. Open **Ingress → Tunnel**.
2. Next to **Cloudflare API token file**, click **Set token…**. If the field is empty, it fills in `/etc/router/secrets/cloudflare-tunnel.token`. Paste the token into **API token** and click **Save token**. The token is written to that file, readable by root only; only the path goes into the settings file.
3. Turn on **Enable Cloudflare Tunnel**. The help text: "The router creates a tunnel named after itself, runs its connector, and points each hostname below at it with a proxied CNAME. Nothing opens on the WAN."
4. Click **Add hostname** and fill in the form:

   | Field | What to enter |
   | --- | --- |
   | **Hostname** | The public name, such as `wiki.example.com`. Wildcards aren't supported. |
   | **Host** | The registered host. Each entry shows its static IP and IPv6 suffix. |
   | **Port** | The service's port on the host. Defaults to 80. |
   | **Scheme** | **http** or **https**: "The protocol the host's service speaks." |
   | **Skip certificate check** | Shown for **https**, and on by default: "Accept the host's certificate unverified — services inside the network are mostly self-signed." |
   | **Host header (optional)** | "Send this Host header to the service instead of the public name. Empty keeps the public name." Use it for an app that only answers to its LAN name. |

5. Click **Add**, then **Save & apply**. If the configuration would fail the build, the tab lists the problems under **Fix these before applying** and **Save & apply** stays disabled.
6. Check the **Tunnel status** card. The connections are read at the end of each sync, so right after the first apply they can be missing until the next one. Click **Sync now** to refresh them.

## The Tunnel status card

The **Tunnel status** card shows the result of the last sync:

- **Last sync:** when it ran, and **ok** or the error.
- **Tunnel:** the tunnel's name, its status from Cloudflare (green when **healthy**), and its ID. It shows "none" when there's no tunnel, with "add a hostname to create the tunnel" beneath it while there are no hostnames yet.
- **Connector:** the state of the `cloudflared-tunnel-<host name>.service` unit, such as **active**. It's **inactive** while the tunnel has no hostnames, because the connector only runs once there's one to serve.
- **Connections:** one row per connection to Cloudflare, with **Data center**, **Origin IP**, **Opened** and **Version**.
- **DNS records:** one row per hostname, **ok** or **error**, with what the last sync did, such as `created`, `unchanged`, or a note that an existing record was replaced.

**Sync now** runs the sync service at once and waits for it; if it fails, **The sync run failed** shows the error. The button is disabled, with "The tunnel is not running — enable it and apply the configuration.", until an enabled tunnel or a token has been applied. Before the first run, the card says "No sync has run yet."

The raw status is in `/var/lib/router-cloudflared/status.json`.

## How it works

Two services do the work:

- **`router-cloudflare-tunnel.service`** talks to the Cloudflare API. It runs at boot and on every apply, then from a timer 2 minutes after boot and every 5 minutes after that (with up to 30 seconds of random delay). If a run fails, it retries after a minute.
- **`cloudflared-tunnel-<host name>.service`** is the connector. It holds the connections to Cloudflare and passes requests to the hosts. It's installed only while the tunnel is on and has at least one hostname.

On each run, the sync service does the following:

- **Account:** it uses the Cloudflare account that owns the zone of the first hostname. With no hostnames, it keeps the tunnel it already has. With no hostnames and no tunnel yet, it creates nothing: the run succeeds, and **Tunnel** shows "none" with "add a hostname to create the tunnel".
- **Tunnel:** it creates a locally managed tunnel named after the router, if there isn't one yet. The tunnel secret is generated on the router and leaves it only in that one API call. The credentials go to `/var/lib/router-cloudflared/credentials.json`, readable by root only, and the connector receives them from systemd. The connector's routing rules come from the router's configuration, not from the Cloudflare dashboard.
- **DNS:** it keeps one proxied CNAME per hostname, pointing at `<tunnel id>.cfargotunnel.com`, with the comment `managed by nixos-router`. An A, AAAA or CNAME record already at that name is replaced and remembered, and put back when you remove the name from the tunnel. If the name holds a record by then that the remembered one can't sit beside, such as a CNAME you made by hand, that record stays and the remembered one isn't put back. If the router replaced records at the name more than once, an older one that can't sit beside a newer one isn't put back either.
- **Drift:** it recreates a tunnel deleted in the dashboard, moves the records to the new tunnel, and repairs records edited by hand.

The connector sends each hostname to `http://` or `https://` plus the host's static IP and port. A request for any other name gets `404`.

The state lives in `/var/lib/router-cloudflared/`:

| File | Holds |
| --- | --- |
| `credentials.json` | The tunnel's credentials, for the connector. |
| `state.json` | The account and tunnel IDs, the managed names, and the records replaced to take names over. |
| `status.json` | The last run's result, which Cockpit shows. |

## Turn it off

1. Switch off **Enable Cloudflare Tunnel**, but leave the token file set.
2. Click **Save & apply**.
3. The apply runs a sync, and **Sync now** runs another. It deletes the tunnel's CNAMEs and puts back any records they replaced, deletes the tunnel, and removes the credentials file. When the **Tunnel status** card shows **Last sync** **ok** and **Tunnel** **none**, it's done.
4. Only then clear the token file path, if you want to.

The Tunnel tab says the same: "Turning the tunnel off keeps the token, so the router can delete the tunnel and its DNS records — remove the token only after that has run." If the token file itself is gone, systemd skips the sync service, and nothing is deleted.

:::doc-warning
If you remove the token before the teardown has run, the router can't delete anything. The tunnel and its DNS records stay in your Cloudflare account until you delete them in the dashboard.
:::

Removing a single hostname works the same way: the next sync deletes its CNAME and restores whatever record it replaced.

## Name conflicts

A tunnel hostname is a CNAME to Cloudflare, so no other feature may publish the same name. While the tunnel is on, a tunnel hostname can't also be:

- a dynamic DNS **Router names** entry;
- a host's **Public hostname**;
- a reverse proxy route hostname, while the proxy is on.

Two tunnel entries can't share a name either. See [Hostname conflicts](/docs/ingress/#hostname-conflicts) for the full set of rules.

## In the settings file

The tunnel is the top-level `cloudflareTunnel` key. For each entry, `port` defaults to `80`, `scheme` to `"http"`, `noTLSVerify` to `true` (it only matters with `https`), and `httpHostHeader` to empty (keep the public name). Each entry's `host` must be an entry in `hosts` with a `staticIp`.

```json
{
  "hosts": [
    { "mac": "aa:bb:cc:dd:ee:01", "name": "nas", "staticIp": "192.168.1.20" },
    { "mac": "aa:bb:cc:dd:ee:02", "name": "wiki", "staticIp": "192.168.1.21" }
  ],
  "cloudflareTunnel": {
    "enable": true,
    "apiTokenFile": "/etc/router/secrets/cloudflare-tunnel.token",
    "ingress": [
      {
        "hostname": "wiki.example.com",
        "host": "wiki",
        "port": 3000
      },
      {
        "hostname": "dsm.example.com",
        "host": "nas",
        "port": 5001,
        "scheme": "https",
        "httpHostHeader": "nas.lan"
      }
    ]
  }
}
```

## Build checks

Cockpit shows these before you apply, and the rebuild enforces them.

| Message | Fix |
| --- | --- |
| `router.cloudflareTunnel: enabled without router.cloudflareTunnel.apiTokenFile` (Cockpit: "The tunnel needs a Cloudflare API token file.") | [Set the token](#set-it-up). |
| `router.cloudflareTunnel.ingress: 'HOSTNAME' is not a valid public DNS name` (Cockpit: "Not a valid public DNS name: HOSTNAME") | Fix the name. |
| `router.cloudflareTunnel.ingress: 'HOSTNAME' references unknown host 'HOST' — it must name a router.hosts entry` (Cockpit: "Host 'HOST' is not registered.") | Register the host, or pick another one. |
| `router.cloudflareTunnel.ingress: 'HOSTNAME' targets host 'HOST', which has no staticIp (DHCP reservation) — set one` (Cockpit: "HOST has no static IP to send the traffic to — reserve one on the Hosts page.") | Give the host a **Static IP**. |
| `router.cloudflareTunnel.ingress: duplicate hostname(s) HOSTNAME` (Cockpit: "HOSTNAME already has a tunnel entry.") | Keep one entry. |
| `router.cloudflareTunnel.ingress: HOSTNAME is also published by OWNER — a name can only point one way`, where `OWNER` is `router.ddns.names`, `host 'HOST' (publicHostname)` or `reverse proxy route 'NAME'` | Remove the name from the other feature. Cockpit says "HOSTNAME is also a dynamic DNS router name — remove it there (Network → Dynamic DNS).", "HOSTNAME is also a host's public hostname — a name can point one way only." or "HOSTNAME is also a reverse proxy route." |

In the Cockpit form, a missing host gives "Choose the host to send the traffic to.", and a port outside 1 to 65535 gives "Enter a port between 1 and 65535."

With the tunnel on and no hostnames, the rebuild only warns: `router.cloudflareTunnel is enabled with no ingress hostnames, so no connector runs; the tunnel is created (or the existing one reused) once a hostname is added.` Cockpit shows the same under **Check the tunnel configuration**: "The tunnel has no hostnames, so its connector doesn't run. Add a hostname and the router creates the tunnel, or reuses the one it already has."

## Troubleshooting

Sync errors appear in **Last sync** and in `journalctl -u router-cloudflare-tunnel`.

| Error | Cause | Fix |
| --- | --- | --- |
| `a tunnel named 'router' (...) already exists but its credentials are not in /var/lib/router-cloudflared — delete it in the Cloudflare dashboard, or choose another tunnel name` | The router lost `/var/lib/router-cloudflared` while its tunnel still exists, or another router with the same host name uses the account. The router won't take over a tunnel whose secret it doesn't have. | Delete the old tunnel in the dashboard, and the next run creates a new one. Or give the router a different **Host name**. |
| `no Cloudflare zone found for HOSTNAME — does the token have Zone:Read on it?` | The name isn't in an active zone that the token can read. | Add the zone to the token, or fix the name. |
| `no Cloudflare API token (apiTokenFile)` | The token file is empty. | Click **Set token…** and save the token again. |
| **Sync now** fails, and **Last sync** doesn't change | The tunnel is on but the token file is missing, so systemd can't start the sync service at all; `journalctl -u router-cloudflare-tunnel` shows a credentials error. | Click **Set token…** and save the token again. |
| The tunnel is off, and **Sync now** changes nothing | The token file is missing, so systemd skips the sync service: without the token it couldn't delete anything. | Click **Set token…**, save the token again, and click **Sync now** to run the teardown. |
| **Last sync** is **ok**, but **Tunnel** shows "none" with "add a hostname to create the tunnel" | The tunnel is on but has no hostnames, and was never created. The router waits for a hostname, since there's nothing to serve and no zone to tell it which account to use. | Add a hostname. |
| A hostname shows **error** under DNS records | The token lacks **Zone → DNS → Edit** on that name's zone, or the API refused the change. | Read the message next to it, fix the token's scopes, and click **Sync now**. |
| **Connector** isn't **active** | The tunnel has no hostnames, so no connector runs. Or `cloudflared` can't reach Cloudflare, or has no credentials yet. | Add a hostname. Otherwise check `journalctl -u cloudflared-tunnel-router` (with your router's host name); it keeps retrying every 30 seconds. |
