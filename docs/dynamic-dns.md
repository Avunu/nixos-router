---
title: Cloudflare dynamic DNS
description: Keep A and AAAA records on Cloudflare pointed at the router's changing public addresses, for the router itself and for devices behind it.
code:
  - modules/ddns.nix
  - modules/hosts.nix
  - modules/dns-technitium.nix
  - modules/reverse-proxy.nix
  - modules/cloudflare-tunnel.nix
  - modules/firewall.nix
  - pkgs/router-dns-tools/router_dns_tools/ddns.py
  - pkgs/router-dns-tools/router_dns_tools/cloudflare.py
  - pkgs/cockpit-router/src/dynamic-dns.tsx
  - pkgs/cockpit-router/src/ddns.ts
  - pkgs/cockpit-router/src/ingress-widgets.tsx
  - pkgs/cockpit-router/src/hosts.tsx
  - pkgs/cockpit-router/src/reverse-proxy.tsx
---

# Cloudflare dynamic DNS

Dynamic DNS keeps public names pointed at the router's public addresses as your ISP changes them. It writes A records for the WAN IPv4 address and AAAA records for IPv6, both for the router itself and for registered devices behind it. It works only with DNS zones hosted on Cloudflare, through the Cloudflare API. Other DNS providers aren't supported.

Publishing a name doesn't open anything. Traffic to the name still needs a [port forward](/docs/ingress/port-forwards/), the [reverse proxy](/docs/ingress/reverse-proxy/) or another way in. [Choose an ingress](/docs/ingress/) compares them.

## Before you start

- **A domain on Cloudflare.** Every name you publish, such as `home.example.com`, must sit in an active zone of your Cloudflare account.
- **A Cloudflare API token** with **Zone → Zone → Read** and **Zone → DNS → Edit** on those zones. [Cloudflare API tokens](/docs/reference/cloudflare-tokens/) shows how to create one.
- **For a device name:** the device registered on the **Hosts** page with a **Public hostname**. For its IPv4 record to be useful it needs a **Static IP**; for an AAAA record it needs a stable **IPv6 suffix**. See [Hosts and host groups](/docs/network/hosts/).

## Set up dynamic DNS

1. In Cockpit, open **Network → Dynamic DNS**.
2. Turn on **Enable dynamic DNS**.
3. Next to **Cloudflare API token file**, click **Set token…**. If the path field is empty, this fills in the default, `/etc/router/secrets/cloudflare-ddns.token`. In the **Set Cloudflare API token** card, paste the token into **API token** and click **Save token**.

   The token is written to that file right away, owned by root with mode `0600`, in a directory with mode `0700`. It reaches the router on standard input, never on a command line. The settings file only ever holds the path, never the token. The path itself is saved with the rest of the form in the last step.
4. Under **Router names**, type a public name for the router itself, such as `home.example.com`, and press Enter or click **Add**. Repeat for more names. Names are stored in lowercase. To remove one, click the × on its label.
5. Check **Device names**. This list is read-only. It shows each host that has a **Public hostname** on the **Hosts** page, as `nas.example.com → nas (A + AAAA)`, or as `(A only — no IPv6 suffix)` when the host has no **IPv6 suffix**. To add or change a device name, edit the host on the **Hosts** page.
6. Under **Records**, set the options. They apply to every name.
   - **Publish IPv4 (A):** publish A records with the WAN IPv4 address. On by default.
   - **Publish IPv6 (AAAA):** publish AAAA records with the router's and the devices' global IPv6 addresses. On by default.
   - **Proxy through Cloudflare:** orange-cloud the records. Off by default. Only HTTP(S) on Cloudflare's supported ports gets through a proxied name, so leave this off for anything else a port forward exposes.
   - **TTL (seconds):** `1` for Cloudflare's automatic TTL (the default), otherwise 60 to 86400.
   - **Check every (minutes):** how often the router checks its addresses, from 1 to 1440. The default is 5. The router writes to Cloudflare only when an address or one of these options changes.
7. Click **Save & apply**.

The rebuild starts the first update. The **Last update** card below the form doesn't refresh on its own, so click **Update now** or reopen the tab to see the addresses and each record's result. See [Read the last update](#read-the-last-update).

## Router names and device names

Each name gets an A record, an AAAA record, or both:

| Name | A record | AAAA record |
| --- | --- | --- |
| Each of **Router names** | The WAN IPv4 address | The router's own global IPv6 address: the WAN interface's if the ISP assigns one, otherwise the LAN bridge's address from the delegated prefix |
| A host's **Public hostname** | The WAN IPv4 address | The host network's current delegated /64 plus the host's **IPv6 suffix**; none if the host has no suffix |
| Each reverse proxy hostname, while **Publish hostnames** is on | The WAN IPv4 address | The router's own global IPv6 address |

A device has no public IPv4 address of its own, so its A record is the router's WAN address. A client connecting over IPv4 reaches the router, which passes the traffic on only through an IPv4 [port forward](/docs/ingress/port-forwards/) to the host's **Static IP** or a [reverse proxy](/docs/ingress/reverse-proxy/) route.

A device's AAAA record is the device's own address. The router combines the /64 that the device's network (`br-lan` or `br-guest`) currently holds from the ISP's delegated prefix with the host's **IPv6 suffix**, such as `::42`. It computes the address rather than learning it, so the device doesn't have to be online. The suffix must be one the device keeps across prefix changes: a token set on the device, or its EUI-64 identifier if it really builds its address from its MAC. Privacy, temporary and RFC 7217 "stable-privacy" addresses change with the prefix, so the record would stop matching. [Hosts and host groups](/docs/network/hosts/) explains how to pick one. The AAAA record doesn't open the firewall; the device still needs an IPv6 port forward.

A name points one way only. It can be a router name or a device's public hostname, not both. The **Hosts** page refuses a public hostname that another device or the router already uses, with "Already used by another device or by the router.", and the build refuses the same clash (see [Validation errors and warnings](#validation-errors-and-warnings)).

## Reverse proxy hostnames

When the [reverse proxy](/docs/ingress/reverse-proxy/) is enabled and its **Publish hostnames** switch is on (the default), dynamic DNS also publishes every route hostname as a name for the router, exactly like a router name. The HTTP certificate challenge depends on these records.

- Don't add route hostnames to **Router names** as well. The build refuses the duplicate.
- They don't appear under **Router names** or **Device names**, but they do appear in the **Last update** table.
- They're published only while dynamic DNS is enabled. With it off, the **Ingress → Reverse proxy** tab warns "Dynamic DNS is off (Network → Dynamic DNS), so nothing publishes these names."
- Turning off **Publish hostnames**, disabling the reverse proxy or deleting a route removes those records at the next run.

## Read the last update

The **Last update** card at the bottom of **Network → Dynamic DNS** shows the most recent run. Until a configuration with dynamic DNS enabled, or with a token file set, has been applied, it says "Dynamic DNS is not running — enable it and apply the configuration." and **Update now** is disabled. With dynamic DNS off but the token file still set, **Update now** runs the cleanup described in [Turn dynamic DNS off](#turn-dynamic-dns-off).

- **Update now** starts a run and refreshes the card when the run finishes. If the run fails, the card shows "The update run failed" and the reason.
- A note above **Last run** appears when dynamic DNS was turned off before the upgrade that made turning it off delete the records. It says how to delete them. See [Turned off before the upgrade](#turned-off-before-the-upgrade).
- **Last run** is the time of the run in UTC, followed by a green **ok** label, or a red label with the error, such as `2 record(s) failed`.
- **WAN IPv4** is the public IPv4 address the router found. "(behind another NAT — detected via Cloudflare)" after it means the WAN interface holds a private or CGNAT address, so the router asked Cloudflare which address its traffic comes from. See [Behind CGNAT or another router](#behind-cgnat-or-another-router). "none" means no address was found, or **Publish IPv4 (A)** is off.
- **Router IPv6** is the address used for router names, or "none".
- The records table has one row per name and record type:
  - **Name**: the public name. For a device name, the host's name follows in parentheses.
  - **Type**: `A` or `AAAA`. A `CNAME` row appears for each replaced CNAME when its name is dropped, whether it was put back or not.
  - **Address**: the address the record should hold.
  - **Result**: what the run did, with a note beside it.

| Result | Meaning |
| --- | --- |
| `created` | The record didn't exist and was created, or a replaced CNAME was restored. |
| `updated` | The record was changed, or extra records of the same type were deleted. |
| `unchanged` | The record already matched. A run that didn't need to contact Cloudflare also shows its records as `unchanged`, or `skipped` where there's no address. |
| `skipped` | There was no address of that family this run, so the record was left as it is. |
| `removed` | The name or family is no longer configured, or dynamic DNS was turned off, so the router's own records were deleted. |
| `error` | The Cloudflare API call failed. The note shows the call and Cloudflare's message. |

## In the settings file

Dynamic DNS is the `ddns` key of `/etc/nixos/router-settings.json`. A device name is the host's `publicHostname`, with `ipv6Suffix` for its AAAA record. `ipv4`, `ipv6`, `proxied`, `ttl` and `intervalMinutes` are shown at their defaults, so you can leave them out. `enable` defaults to `false`, `names` to an empty list, and `cloudflare.apiTokenFile` to no path:

```json
{
  "ddns": {
    "enable": true,
    "cloudflare": {
      "apiTokenFile": "/etc/router/secrets/cloudflare-ddns.token"
    },
    "names": ["home.example.com"],
    "ipv4": true,
    "ipv6": true,
    "proxied": false,
    "ttl": 1,
    "intervalMinutes": 5
  },
  "hosts": [
    {
      "mac": "52:54:00:12:34:56",
      "name": "nas",
      "staticIp": "192.168.1.20",
      "ipv6Suffix": "::20",
      "publicHostname": "nas.example.com"
    }
  ]
}
```

Reverse proxy hostnames come from `reverseProxy.routes[].hostnames` and are published while `reverseProxy.publishDns` is `true`. See [The settings file](/docs/start/settings-file/) for how the file is edited and applied.

## How it works

The work is done by `router-ddns.service`, a oneshot systemd service that runs the `router-ddns` tool. The tool finds the addresses, reconciles the records through the Cloudflare API and writes a status file for the **Last update** card.

### When it runs

- **At boot and on every rebuild.** The service is part of the normal boot target, so every **Save & apply** runs it again, and a changed name set is published straight away.
- **On a timer.** `router-ddns.timer` starts it 1 minute after boot, then every **Check every** minutes after the previous run, each time with up to 30 seconds of random delay.
- **On demand.** **Update now** starts the same service.
- **After a failure.** A failed run, for example with Cloudflare or the network down, is retried after 60 seconds. systemd allows at most 5 starts in 15 minutes, so a bad token can't hammer the API.

The service and its timer are installed while dynamic DNS is on, and also while it's off but a token file is still set, so the router can delete its records. With dynamic DNS off, the service runs only if the token file exists: without the token it couldn't delete anything, so systemd skips it rather than fail the apply. See [Turn dynamic DNS off](#turn-dynamic-dns-off).

The service runs as a temporary system user with most privileges removed. It never reads `/etc/router/secrets` itself: systemd hands it the token file as a credential (`LoadCredential`).

### What it writes to Cloudflare

- **Only what changed.** Each run reads the addresses from the router's interfaces, or from Cloudflare's trace endpoint behind another NAT. It contacts the Cloudflare API only when an address changed, a name or record type was added or removed, **TTL (seconds)** or **Proxy through Cloudflare** changed, the previous run had errors, or 6 hours have passed since the last full check. Otherwise it reports the records as `unchanged` without an API call.
- **A full check every 6 hours.** That check compares every record with what it should be, which repairs records someone edited by hand.
- **One record per type per name.** If a name holds several A records, the router keeps one, preferring its own, and deletes the rest.
- **Tagged records.** Records the router writes carry the comment `managed by nixos-router`. An A or AAAA record that already existed at the name is overwritten and tagged. It isn't remembered, so it isn't restored later.
- **Other types left alone.** Apart from a CNAME (see the next section), other record types at the name, such as MX and TXT, are never touched.
- **Zones found automatically.** Each name's zone is the longest suffix of the name that is an active zone the token can see. Names can span several zones, as long as the token covers all of them.
- **A missing family is left alone.** If a family has no usable address during a run, for example while the delegated prefix is briefly lost, its records keep their old address and the result is `skipped`. They aren't deleted.
- **Removal deletes only the router's records.** When you remove a name, turn off a family, clear a host's **IPv6 suffix**, or turn dynamic DNS off, the next run deletes the matching records that carry the comment, and nothing else.

### Names held by a CNAME

DNS allows nothing else beside a CNAME, so Cloudflare would refuse an A record at a name that holds one. When a name has no A or AAAA record yet, the router deletes any CNAME there and remembers it, with its target, TTL, proxying and comment. The note reads, for example, "replaced CNAME → site.example.net (restored if the name is dropped)".

When you later remove the name from the configuration, or turn dynamic DNS off, the router deletes its own A and AAAA records and puts the CNAME back exactly as it was. The table then shows a `CNAME` row, `created` with "restored: the name is no longer configured". If the same CNAME is already back at the name, put back by hand, the router leaves it as it is, and the row shows `unchanged` with "already back: the name is no longer configured".

A CNAME can't sit beside another CNAME, or beside an A or AAAA record, so the router never puts one back where it would clash. If you put a different CNAME at the name by hand, the router leaves yours, and the row for the remembered CNAME shows `unchanged` with "a CNAME is already back: the name is no longer configured". While the name is still configured, though, the next full check takes it back, and your CNAME is remembered as well. When the name is dropped later, the router puts back only the CNAME it deleted last, your latest choice. The row for the older one shows `unchanged` with "superseded by a CNAME taken over later: the name is no longer configured".

### Address detection

- **WAN IPv4:** the WAN interface's global address, unless it's in `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` (CGNAT), `169.254.0.0/16` or `127.0.0.0/8`. Then the router is behind another NAT, and it asks Cloudflare's trace endpoint, `https://1.1.1.1/cdn-cgi/trace`, which answers with the address the request came from.
- **Router IPv6:** the WAN interface's stable global address with the longest preferred lifetime. Temporary, deprecated and unique local (`fc00::/7`) addresses are skipped. If the WAN has none, the same rule picks an address on `br-lan`.
- **Device IPv6:** the /64 of the same kind of address on the device's bridge, plus its suffix.

### Status and state files

- `/var/lib/router-ddns/status.json` is the summary of the last run, written after every run, successful or not. The **Last update** card reads it.
- `/var/lib/router-ddns/state.json` (mode `0600`) holds the zone cache, the set of records the router manages, the last records pushed (address, TTL and proxying), the time of the last full check, every CNAME it replaced, and a `version`. Every run with dynamic DNS on sets `version` to `2`, which is what lets a run with it off delete the records. Don't delete the file: it's the only copy of the replaced CNAMEs.

Because the service runs as a dynamic user, the directory really lives at `/var/lib/private/router-ddns`, and `/var/lib/router-ddns` is a link to it. `/var/lib/private` is readable only by root, so read the files with `sudo`:

```bash
sudo cat /var/lib/router-ddns/status.json
```

```json
{
  "lastRun": "2026-09-25T14:05:12Z",
  "ok": true,
  "error": null,
  "addresses": {
    "ipv4": "203.0.113.7",
    "ipv4Source": "interface",
    "ipv6": "2001:db8:1234::1"
  },
  "records": [
    {
      "name": "nas.example.com",
      "type": "AAAA",
      "host": "nas",
      "content": "2001:db8:1234:1::20",
      "state": "updated",
      "detail": ""
    }
  ]
}
```

`ipv4Source` is `interface` when the address came from the WAN interface, `trace` when it came from Cloudflare, `disabled` when **Publish IPv4 (A)** is off or dynamic DNS is off, or the reason the lookup failed, such as `trace failed: ...`. A `message` field appears only when a run with dynamic DNS off kept records from before the upgrade (see [Turned off before the upgrade](#turned-off-before-the-upgrade)).

### Turn dynamic DNS off

Turning off **Enable dynamic DNS** deletes the router's records from Cloudflare and puts back any CNAMEs they replaced. The router needs the token for that, so the service and its timer stay installed while the token file is set.

1. Switch off **Enable dynamic DNS**, but leave the token file set.
2. Click **Save & apply**.
3. The apply runs the cleanup, and **Update now** runs it again. It doesn't look up any address. When the **Last update** card shows **Last run** **ok**, with each record `removed` and each restored CNAME `created`, it's done.
4. Only then clear **Cloudflare API token file**, if you want to. That removes the service and its timer.

The tab says the same under the switch: "Turning dynamic DNS off keeps the token, so the router can delete its records and put back the CNAMEs they replaced — remove the token only after that has run." Once there's nothing left to delete, later runs do nothing. If the token file itself is gone, systemd skips the service, and nothing is deleted.

:::doc-warning
If you remove the token before the cleanup has run, the router can't delete anything. The records keep their last addresses, and replaced CNAMEs stay gone, until you fix them in the Cloudflare dashboard.
:::

### Turned off before the upgrade

Earlier versions left the records in Cloudflare when you turned dynamic DNS off, and said so. If dynamic DNS was already off when the router upgraded to this behavior, the router keeps that promise: it deletes nothing and restores nothing until you ask. Each run with dynamic DNS off makes no change in Cloudflare, logs a note and shows it above **Last run** on the **Last update** card:

```text
records from before the upgrade are left in Cloudflare, since turning dynamic DNS off used to keep them — to delete them, turn dynamic DNS on and apply, then turn it off and apply again
```

- **To delete them:** turn on **Enable dynamic DNS** and click **Save & apply**. That run brings the records in line with the settings, as any run with dynamic DNS on does: configured names get the current addresses, and names no longer configured are deleted. Then turn it off, click **Save & apply** again, and follow the steps in [Turn dynamic DNS off](#turn-dynamic-dns-off). A replaced CNAME you already put back by hand doesn't make the cleanup fail: the router doesn't create it a second time (see [Names held by a CNAME](#names-held-by-a-cname)). If you pointed a name that's still configured at a different CNAME by hand instead, the "turn on" step takes that name back: it deletes your CNAME and points the name at the router until the "turn off" step, which then puts your CNAME back rather than the one from before.
- **To keep them:** do nothing, or clear **Cloudflare API token file** and click **Save & apply**, which removes the service and its timer.

## LAN clients

The router has no NAT loopback for port forwards. A LAN client that connects to the WAN IPv4 address isn't forwarded to the device. So the router's resolver answers some public names differently on the inside:

- **Device names.** For a host with both a **Public hostname** and a **Static IP**, the router's DNS server (Technitium, on by default) answers A queries for the public name with the host's static IP, with a TTL of 300 seconds. LAN clients then reach the device directly. The record lives in a local zone that forwards every other query to the upstream DNS servers. An override for the same name on **DNS → Overrides** takes precedence. A host without a static IP gets no local record, so LAN clients receive the WAN address and can't reach it over IPv4.
- **Reverse proxy hostnames.** LAN clients get the public answer, the WAN address. The firewall redirects their connections to the WAN address on TCP 80 and 443 to the reverse proxy, so the names work from inside too.
- **Router names.** There's no local record. LAN clients get the same answers as the internet.

## Validation errors and warnings

The rebuild stops with an error and keeps running with a warning. Both appear in the rebuild output when you apply.

### Errors

- `router.ddns: enabled without router.ddns.cloudflare.apiTokenFile`

  Dynamic DNS is on but no token file is set. Click **Set token…** next to **Cloudflare API token file**, save the token, and apply again. The form marks the field red while it's empty.
- `router.ddns: both ipv4 and ipv6 are disabled, so there is nothing to publish`

  Turn on **Publish IPv4 (A)**, **Publish IPv6 (AAAA)** or both.
- `router.ddns.ttl must be 1 (automatic) or between 60 and 86400 seconds`

  Set **TTL (seconds)** to `1` or to a value from 60 to 86400. The form marks the field red.
- `router.ddns.names: not a valid DNS name: home_example.com`

  A router name must be a plain DNS name of at least two labels, made of letters, digits and inner hyphens, with no wildcard and no trailing dot. The form shows "Not a valid DNS name:" and the name under **Router names**. Remove it and add the corrected name.
- `router.ddns.names: duplicate name(s)`

  Names are compared without regard to case. Remove the duplicate from **Router names**.
- `router.ddns.names: nas.example.com is also a host's publicHostname — a name can point at the router or at a host, not both`

  Remove the name from **Router names**, or clear the host's **Public hostname** on the **Hosts** page.
- `router.ddns.names: cloud.example.com is already published by router.reverseProxy.publishDns — remove it from ddns.names`

  The reverse proxy already publishes this route hostname. Remove it from **Router names**.
- `router.cloudflareTunnel.ingress: wiki.example.com is also published by router.ddns.names — a name can only point one way`

  While the [Cloudflare Tunnel](/docs/ingress/cloudflare-tunnel/) is enabled, its hostnames are CNAMEs to Cloudflare and can't also be dynamic DNS names. The same message names a host (`publicHostname`) when the clash is with a device name. Remove the name from one of the two.

A **Check every (minutes)** value outside 1 to 1440 turns the field red, and the build rejects it as the wrong type for `router.ddns.intervalMinutes`.

### Warnings

- `router.ddns is enabled but no names are configured (router.ddns.names or router.hosts[].publicHostname), so it publishes nothing.`

  Add a router name, give a host a **Public hostname**, or publish reverse proxy hostnames.
- `router.hosts: 'nas' set a publicHostname, but router.ddns is disabled, so nothing publishes it.`

  Enable dynamic DNS, or clear the host's **Public hostname**.
- `router.reverseProxy.publishDns is on but router.ddns is disabled, so the route hostnames are not published — point them at the router yourself.`

  Enable dynamic DNS, or turn off **Publish hostnames** and create the records yourself.

## Limits

- **Cloudflare only.** There's no support for other DNS providers or for the classic dynamic DNS update protocols.
- **One set of options for every name.** **Publish IPv4 (A)**, **Publish IPv6 (AAAA)**, **Proxy through Cloudflare** and **TTL (seconds)** apply to all names alike.
- **Hand edits wait for the 6-hour check.** A record edited by hand in Cloudflare is repaired only at the next full check, up to 6 hours later.
- **Only CNAMEs are restored.** An A or AAAA record the router overwrote is deleted, not restored, when you remove the name.
- **IPv4 behind CGNAT isn't reachable.** See [Behind CGNAT or another router](#behind-cgnat-or-another-router).

## Troubleshooting

### A record shows an authentication or permission error

The **Result** is `error`, and the note shows the failed call and Cloudflare's message, such as `GET /zones/.../dns_records:` followed by an authentication error. The token is wrong, revoked or expired, or it lacks a permission on that zone.

Check the token in the Cloudflare dashboard. It needs **Zone → Zone → Read** and **Zone → DNS → Edit** on the zone of every name, including reverse proxy hostnames and device names. Fix the token or create a new one, then click **Set token…**, save it, and click **Update now**. See [Cloudflare API tokens](/docs/reference/cloudflare-tokens/).

### "no Cloudflare zone found for …"

The note reads `no Cloudflare zone found for nas.example.com — does the token have Zone:Read on it?`. The router looked for an active zone for the name and found none the token can see. Either the token doesn't include that zone, or the zone isn't active on Cloudflare yet, for example because the domain's nameservers haven't been switched to Cloudflare.

### The run fails with no records

The **Last run** label shows `no Cloudflare API token (router.ddns.cloudflare.apiTokenFile)`, or the run fails before it starts and the journal says systemd couldn't set up the service's credentials. The token file is empty or doesn't exist at the configured path. Click **Set token…** and save the token again. With dynamic DNS off, a missing token file doesn't fail the run: systemd skips the service instead.

### Records don't update

- **The card says dynamic DNS isn't running.** Apply the configuration with dynamic DNS enabled.
- **Every row is `unchanged`, but the record in Cloudflare differs.** Someone changed the record outside the router. The router doesn't contact Cloudflare until an address or the configuration changes, or the 6-hour check comes round, and that check puts the record right.
- **A row is `skipped`.** The router had no address of that family. For IPv6, check that the ISP delegates a prefix. For IPv4 behind another NAT, check `ipv4Source` in the status file for a `trace failed` reason.
- **A device has no AAAA row.** Its host has no **IPv6 suffix**; **Device names** shows it as "A only — no IPv6 suffix".
- **A device's AAAA address is wrong.** The **IPv6 suffix** isn't what the device actually uses. Set a stable token on the device, or correct the suffix on the **Hosts** page.
- **The address is right in Cloudflare, but clients still get the old one.** Resolvers keep an answer until its TTL runs out.
- **Runs stopped after repeated failures.** After 5 starts in 15 minutes, systemd refuses to start the service again, including from **Update now**, until the 15 minutes have passed. Clear it at once with `sudo systemctl reset-failed router-ddns.service`, then check that the timer is still scheduled with `systemctl list-timers router-ddns.timer`, and start it with `sudo systemctl start router-ddns.timer` if it isn't listed.

### Records stay after turning dynamic DNS off

- **The card shows the note "records from before the upgrade are left in Cloudflare…".** Dynamic DNS was turned off before the upgrade, when turning it off kept the records. See [Turned off before the upgrade](#turned-off-before-the-upgrade).
- **Otherwise,** the token file was cleared or deleted before the cleanup ran, so the service was removed or skipped with nothing deleted. Set the token file again (click **Set token…** if the file is gone), leave **Enable dynamic DNS** off, click **Save & apply**, and wait for a **Last run** **ok** (or click **Update now**). The router still remembers its records and the CNAMEs it replaced, so this run cleans up as usual. If the **Last run** label shows an error instead, fix it as for any other run.

### Behind CGNAT or another router

**WAN IPv4** shows "(behind another NAT — detected via Cloudflare)". The WAN interface holds a private or CGNAT address, so the router published the public address Cloudflare saw its traffic come from.

- **Behind your own modem or router** (the WAN address is in `192.168.0.0/16`, `10.0.0.0/8` or `172.16.0.0/12`): the published address is that device's public address, which is correct. Inbound traffic still stops there. Forward the ports on that device to this router's WAN address, or put it in bridge mode.
- **Behind the ISP's CGNAT** (the WAN address is in `100.64.0.0/10`): the published address belongs to the carrier's shared NAT. Connections to it never reach your router, so IPv4 port forwards and the reverse proxy can't work. If the ISP delegates an IPv6 prefix, the AAAA records still work, and turning off **Publish IPv4 (A)** stops clients from trying the unreachable A record. Otherwise ask the ISP for a public IPv4 address, or use a [Cloudflare Tunnel](/docs/ingress/cloudflare-tunnel/), which needs no inbound connection at all.

### A proxied name doesn't work for SSH, WireGuard or other services

With **Proxy through Cloudflare** on, the names resolve to Cloudflare's edge instead of your address, and Cloudflare passes on only HTTP and HTTPS on its supported ports. Any other service behind a proxied name stops working, including a WireGuard endpoint. The option covers every name, so turn it off if any name serves something other than web traffic.

### Read the logs

```bash
journalctl -u router-ddns.service -n 50
systemctl list-timers router-ddns.timer
sudo cat /var/lib/router-ddns/status.json
```

Each run logs one line per record: the result, the type, the name, the address and any note. A run that contacted Cloudflare also logs how many write calls it made to the API, and a failed run ends with the error:

```text
router-ddns: 1 API write(s)
  updated   A    home.example.com 203.0.113.7
  unchanged AAAA home.example.com 2001:db8:1234::1
```
