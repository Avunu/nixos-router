---
title: Cloudflare API tokens
description: The Cloudflare API tokens the router uses for dynamic DNS, DNS-01 certificates, Cloudflare Tunnel and report email, and how it stores them.
code:
  - modules/ddns.nix
  - modules/acme.nix
  - modules/reverse-proxy.nix
  - modules/cloudflare-tunnel.nix
  - modules/reporting.nix
  - pkgs/router-dns-tools/router_dns_tools/cloudflare.py
  - pkgs/router-dns-tools/router_dns_tools/ddns.py
  - pkgs/router-dns-tools/router_dns_tools/tunnel.py
  - pkgs/router-dns-tools/router_dns_tools/report.py
  - pkgs/cockpit-router/src/ddns.ts
  - pkgs/cockpit-router/src/ingress-widgets.tsx
  - pkgs/cockpit-router/src/ingress-runtime.ts
  - pkgs/cockpit-router/src/ingress.ts
  - pkgs/cockpit-router/src/dynamic-dns.tsx
  - pkgs/cockpit-router/src/reverse-proxy.tsx
  - pkgs/cockpit-router/src/tunnel.tsx
  - pkgs/cockpit-router/src/reports.tsx
---

# Cloudflare API tokens

Four router features call the Cloudflare API, each with an API token you create in the Cloudflare dashboard. This page lists the permissions each one needs and where its token goes, then shows how to create a token, how the router stores it, and how to rotate or remove it.

## What each feature needs

| Feature | Permissions | Default token file | Where to set it |
| --- | --- | --- | --- |
| [Dynamic DNS](/docs/dynamic-dns/) | Zone → Zone → Read, Zone → DNS → Edit | `/etc/router/secrets/cloudflare-ddns.token` | **Network → Dynamic DNS** |
| [Reverse proxy](/docs/ingress/reverse-proxy/) certificates with the Cloudflare DNS challenge | Zone → Zone → Read, Zone → DNS → Edit | `/etc/router/secrets/cloudflare-acme.token` | **Ingress → Reverse proxy**, **Certificates** card |
| [Cloudflare Tunnel](/docs/ingress/cloudflare-tunnel/) | Account → Cloudflare Tunnel → Edit, Zone → Zone → Read, Zone → DNS → Edit | `/etc/router/secrets/cloudflare-tunnel.token` | **Ingress → Tunnel** |
| Emailed scheduled reports | Email Routing: Edit, plus the account ID | None | **Reports → Scheduled reports**, **Email delivery** section |

Zone permissions must cover the zone of every name the feature manages. The router authenticates with the token as a bearer token, so it needs an API token; your account's Global API Key doesn't work.

## Dynamic DNS

Dynamic DNS looks up the zone of each name, then reads, creates, updates and deletes the A, AAAA and CNAME records at those names.

- **Permissions:** the field's help text says "Create a token in the Cloudflare dashboard (My Profile → API Tokens) with Zone → Zone → Read and Zone → DNS → Edit on the zones of your names." The zones must include those of device names and published reverse proxy hostnames.
- **Where:** **Network → Dynamic DNS**, **Cloudflare API token file**, then **Set token…**.
- **Setting:** `ddns.cloudflare.apiTokenFile`.
- **Missing token:** the build stops with `router.ddns: enabled without router.ddns.cloudflare.apiTokenFile`.
- **Missing zone access:** a record fails with `no Cloudflare zone found for home.example.com — does the token have Zone:Read on it?`.
- **Turning it off:** keep the token until the records are gone. See [Turn off dynamic DNS and the tunnel before removing their tokens](#turn-off-dynamic-dns-and-the-tunnel-before-removing-their-tokens).

## Reverse proxy certificates

A reverse proxy route whose certificate uses the Cloudflare DNS challenge proves control of its names with a TXT record created through the Cloudflare API. It's the only challenge that can get a wildcard certificate. Routes using the HTTP challenge don't need a token.

- **Permissions:** "Create a token in the Cloudflare dashboard (My Profile → API Tokens) with Zone → Zone → Read and Zone → DNS → Edit on the zones of the certificates' names — the dynamic DNS token has exactly these."
- **Where:** **Ingress → Reverse proxy**, in the **Certificates** card, **Cloudflare API token file**, then **Set token…**. The field notes "Needed only for the Cloudflare DNS challenge."
- **Setting:** `acme.cloudflare.apiTokenFile`.
- **Sharing:** a **Use the DDNS token** link appears beside the field when a dynamic DNS token file is set and this field holds a different path. It points this setting at the dynamic DNS token file. See [Share one token between features](#share-one-token-between-features).
- **Missing token:** the tab shows "The Cloudflare DNS challenge needs an API token — set the token file under Certificates.", and the build stops with `router.reverseProxy.routes: route 'cloud' uses the dns-cloudflare challenge, but router.acme.cloudflare.apiTokenFile is not set`.

## Cloudflare Tunnel

The router creates and owns the tunnel through the API. It looks up the zone of the first tunnel hostname, which also tells it the account that owns the zone, so it creates nothing until there's a hostname. In that account it creates a tunnel named after the router, watches its connections, and deletes it when you turn the tunnel off. It also keeps one proxied CNAME per hostname pointing at the tunnel, replacing any A, AAAA or CNAME record already at the name.

- **Permissions:** "Create a token in the Cloudflare dashboard (My Profile → API Tokens) with Account → Cloudflare Tunnel → Edit, plus Zone → Zone → Read and Zone → DNS → Edit on the zones of the tunnel's hostnames." The account permission must cover the account that owns those zones. There's no account ID to enter.
- **Where:** **Ingress → Tunnel**, **Cloudflare API token file**, then **Set token…**.
- **Setting:** `cloudflareTunnel.apiTokenFile`.
- **Missing token:** the tab shows "The tunnel needs a Cloudflare API token file.", and the build stops with `router.cloudflareTunnel: enabled without router.cloudflareTunnel.apiTokenFile`.
- **Turning it off:** keep the token until the tunnel is gone. See [Turn off dynamic DNS and the tunnel before removing their tokens](#turn-off-dynamic-dns-and-the-tunnel-before-removing-their-tokens).

## Report email

A scheduled report can be emailed through Cloudflare's Email Sending API, using the account ID and token you give it.

- **Permissions:** the option's description asks for a token with Email Routing: Edit.
- **Also needed:** your Cloudflare account ID in **Cloudflare account id**, and a **From address** on a domain set up for Cloudflare Email Routing.
- **Where:** **Reports → Scheduled reports**, in the **Email delivery** section, **API token file**. This field takes a path only: there's no **Set token…** button and no default path, so you create the file yourself (see below).
- **Settings:** `reporting.email.accountId`, `reporting.email.apiTokenFile` and `reporting.email.fromAddress`.
- **Delivery failures don't stop the report.** The PDF is still generated and kept in Cockpit. The report's log says `Cloudflare email not configured (accountId/apiTokenFile) — skipping delivery` when the token or account ID is missing, and `Cloudflare email delivery failed:` followed by the reason when the API refuses. Read it with `journalctl -u router-report-weekly.service`, using your schedule's name in place of `weekly`. The exception is a path in **API token file** that doesn't exist: systemd then can't load the credential, the report service fails to start, and no PDF is made.

To create the token file by hand, run this on the router, paste the token, press Enter, then press Ctrl-D:

```bash
sudo install -d -m 700 /etc/router/secrets
sudo sh -c 'umask 077 && cat > /etc/router/secrets/cloudflare-email.token'
```

Then enter `/etc/router/secrets/cloudflare-email.token` in **API token file** and click **Save & apply**.

## Share one token between features

The router doesn't care whether features share a token file. What matters is that the token behind each path has every permission that feature needs.

- **Dynamic DNS and certificates** need exactly the same permissions. **Use the DDNS token** on the **Certificates** card points the certificate setting at the dynamic DNS token file, so one token serves both. Its zones must then cover the certificates' names as well.
- **Cloudflare Tunnel** needs an account permission the others don't. You can type another feature's token file path into its field if that token also has **Account → Cloudflare Tunnel → Edit**, but a separate token keeps that permission away from the DNS-only features and lets you revoke one without breaking the others.
- **Report email** needs a different permission, so give it its own token.

A shared file changes for every feature at once when you rotate it.

## Create a token in the Cloudflare dashboard

Cloudflare's dashboard changes over time, so these steps name the permissions rather than every button.

1. Sign in to the Cloudflare dashboard and open **My Profile → API Tokens**, the page the router's help text names.
2. Start a new custom token. Don't use the Global API Key.
3. Give the token a name that says what it's for, such as `router ddns home.example.com`.
4. Add the permissions from the table in [What each feature needs](#what-each-feature-needs). Each one has a scope (Zone or Account), a permission group and an access level:
   - Zone → Zone → Read
   - Zone → DNS → Edit
   - For the tunnel only: Account → Cloudflare Tunnel → Edit
5. Limit the resources. For zone permissions, include only the specific zones that hold your names, such as `example.com`. For the tunnel's account permission, include the account that owns those zones.
6. Leave client IP address filtering off for dynamic DNS. The router's public address is exactly what changes, and a token tied to the old one stops working. If you give the token an expiry date, plan to rotate it before then.
7. Create the token and copy its value. Cloudflare shows it only once.
8. On the router, open the feature's page, click **Set token…**, paste the token into **API token** and click **Save token**. If the path field was empty, click **Save & apply** too, so the settings file records the path.

## How the router stores tokens

- **In a root-only file.** **Set token…** writes the token to the path in the field, by default a `*.token` file under `/etc/router/secrets/`. A new file is owned by root with mode `0600`, and the directory is set to mode `0700`. The token travels to the router on standard input, so it never shows up in the process list. The card says where the token goes, for example "Written to /etc/router/secrets/cloudflare-ddns.token (root only, never to the settings file).", and the field confirms "Token saved to" that path once it's written.
- **Only the path in the settings file.** `/etc/nixos/router-settings.json` holds the path, never the token, so the token stays out of the settings file, the Nix store and any git repository you keep your configuration in:

  ```json
  {
    "ddns": {
      "cloudflare": { "apiTokenFile": "/etc/router/secrets/cloudflare-ddns.token" }
    },
    "acme": {
      "cloudflare": { "apiTokenFile": "/etc/router/secrets/cloudflare-ddns.token" }
    },
    "cloudflareTunnel": {
      "apiTokenFile": "/etc/router/secrets/cloudflare-tunnel.token"
    },
    "reporting": {
      "email": {
        "accountId": "0123456789abcdef0123456789abcdef",
        "apiTokenFile": "/etc/router/secrets/cloudflare-email.token",
        "fromAddress": "reports@example.com"
      }
    }
  }
  ```

- **Handed to services by systemd.** Each service receives the file through systemd's `LoadCredential`, which gives the service a private copy while it runs. Services that run as an unprivileged dynamic user, such as dynamic DNS, can use the token without any access to `/etc/router/secrets`.

| Feature | Service that reads the token |
| --- | --- |
| Dynamic DNS | `router-ddns.service` |
| Certificates | `acme-order-renew-cloud.example.com.service`, one per route that uses the Cloudflare DNS challenge, named after the route's first hostname |
| Cloudflare Tunnel | `router-cloudflare-tunnel.service` |
| Report email | `router-report-weekly.service`, one per schedule, named after the schedule |

Each service reads the file every time it starts. A token replaced at the same path takes effect at the next run, with no rebuild.

## Rotate a token

1. Create a new token in the Cloudflare dashboard with the same permissions and resources.
2. On the feature's page, click **Set token…**, paste the new token and click **Save token**. The file is overwritten at the same path, so there's nothing to apply. Every feature that points at that file now uses the new token.
3. Check that it works:
   - **Cloudflare Tunnel:** click **Sync now** on **Ingress → Tunnel** and check that **Last sync** shows **ok**.
   - **Dynamic DNS:** click **Update now** on **Network → Dynamic DNS**. A run contacts Cloudflare only when an address, a name, the TTL or the proxy setting changed, or the 6-hourly check is due, so a run that shows every record as `unchanged` may not have used the token. `journalctl -u router-ddns.service` logs a line such as `router-ddns: 0 API write(s)` for each run that did.
   - **Certificates:** the new token is used at the next certificate issue or renewal.
   - **Report email:** the next scheduled report uses it.
4. Revoke the old token in the Cloudflare dashboard.

## Turn off dynamic DNS and the tunnel before removing their tokens

Dynamic DNS and the tunnel clean up after themselves when you turn them off, and they need the token to do it. Their services keep running while a token file path is set and the file exists, even with the feature turned off:

- **Dynamic DNS:** `router-ddns.service` deletes the router's A and AAAA records and puts back any CNAMEs they replaced. The **Network → Dynamic DNS** tab says so: "Turning dynamic DNS off keeps the token, so the router can delete its records and put back the CNAMEs they replaced — remove the token only after that has run." Records left from before the upgrade that added this, when dynamic DNS was already off, stay until you ask; see [Turned off before the upgrade](/docs/dynamic-dns/#turned-off-before-the-upgrade).
- **Cloudflare Tunnel:** `router-cloudflare-tunnel.service` deletes the tunnel, its CNAME records and its credentials, and puts back any records the CNAMEs replaced. The **Ingress → Tunnel** tab says so: "Turning the tunnel off keeps the token, so the router can delete the tunnel and its DNS records — remove the token only after that has run."

For either feature:

1. Turn it off (**Enable dynamic DNS** or **Enable Cloudflare Tunnel**) and click **Save & apply**.
2. Wait until the status card shows a successful run (**Last run** on **Last update**, or **Last sync** on **Tunnel status**), or click **Update now** or **Sync now**. If a row says a record is waiting until the tunnel or dynamic DNS releases the name, the other feature still holds a name you moved to it; keep the token until a later run puts that record back (see [Names moved to or from the tunnel](/docs/dynamic-dns/#names-moved-to-or-from-the-tunnel)).
3. Clear **Cloudflare API token file**, click **Save & apply**, delete the file, and revoke the token in Cloudflare.

If you remove the token first, the records (and the tunnel) stay in your Cloudflare account, and you have to fix them in the dashboard.

## Remove a token

1. Turn off the feature, or make sure it no longer needs the token. Dynamic DNS and the tunnel refuse to build without a token while they're enabled, and so does a route using the Cloudflare DNS challenge. After turning off dynamic DNS or the tunnel, wait for its cleanup run first (see the previous section).
2. Clear the token file field and click **Save & apply**.
3. Make sure no other feature still points at the same file, then delete it:

   ```bash
   sudo rm /etc/router/secrets/cloudflare-ddns.token
   ```

4. Revoke the token in the Cloudflare dashboard.

A token removed before the cleanup ran leaves the records in Cloudflare. See [Turn dynamic DNS off](/docs/dynamic-dns/#turn-dynamic-dns-off) and [Turn it off](/docs/ingress/cloudflare-tunnel/#turn-it-off).
