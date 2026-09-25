---
title: Troubleshooting
description: Fix common access policy problems, from wrongly blocked sites and wrong policies to certificate warnings, filtering that does nothing, and directory lookups.
code:
  - modules/access-policies.nix
  - modules/dns-technitium.nix
  - modules/directory-sync.nix
  - modules/firewall.nix
  - modules/reporting.nix
  - pkgs/router-dns-tools/router_dns_tools/compile_policies.py
  - pkgs/router-dns-tools/router_dns_tools/reconcile.py
  - pkgs/router-dns-tools/router_dns_tools/local_dns.py
  - pkgs/cockpit-router/src/access-policies.tsx
  - pkgs/cockpit-router/src/policy-resolver.ts
---

# Troubleshooting

Each section starts from what you see, then gives the likely causes and the fix. The commands run on the router over SSH unless the text says to run them on a client. The examples use a LAN of `192.168.1.0/24` with the router at `192.168.1.1`.

## Find out why a site is blocked

1. **Check which policy the client gets.** Open **Access Policies → Preview**, look up the device or its IP address, and read the **Resolution chain**. See [Preview a client](/docs/access-policies/assignments/#preview-a-client).
2. **Ask the router which rule matched.** Every policy answers a TXT query for a blocked name with a report. Run this on the affected client, or on another client that gets the same policy:

   ```bash
   dig @192.168.1.1 ads.example.com TXT +short
   ```

   ```text
   "source=advanced-blocking-app; group=Students; blockListUrl=https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt; domain=example.com"
   ```

   `group` is the policy, `blockListUrl` is the list that matched, and `domain` is the entry in it. A match from **Block domains**, or from the DoH provider list, has no `blockListUrl`. A match from a regex shows `regex` instead of `domain`, and a match from a regex list names it as `regexBlockListUrl`. On Windows, use `nslookup -type=TXT ads.example.com 192.168.1.1`.
3. **Look at the query log.** On **Reports → Query log**, filter on the client's address and turn on **Blocked only**. A page often loads from several domains, and each blocked one appears here.

Don't test from the router itself: its own queries use an unfiltered group, so nothing is ever blocked there.

## A site is blocked but shouldn't be

| Cause | Fix |
| --- | --- |
| A category or list includes the domain | Add the domain to **Allow domains** in the policy, or turn off the category or list that the TXT report names. An allow rule beats every block. |
| The user asked for an exception | Approve it on **Exception requests**, then click **Apply** in the changes tray. See [Handle exception requests](/docs/access-policies/block-page/#handle-exception-requests). |
| The site needs another domain that is blocked, such as a CDN | Find it in the query log with **Blocked only**, and allow it too. |
| The client gets a stricter policy than you expected | See [A device gets the wrong policy](#a-device-gets-the-wrong-policy). |
| You allowed the domain but it is still blocked | The change isn't applied yet, or the client cached the answer. Blocked answers expire after 30 seconds; the browser may hold them a little longer. |
| The domain is a public DoH resolver | It is blocked in every policy while **Block DoH providers** is on. Allow it in one policy if a group needs it. |

## A device gets the wrong policy

| Cause | Fix |
| --- | --- |
| No **Static IP** on the Hosts page | Host group and directory group policies need a DHCP reservation. Add one. The Preview shows "NO static IP — tier skipped". |
| The device hasn't picked up its reserved address yet | Reconnect it or renew its DHCP lease, and check that its address matches the reservation. |
| The device uses a private (random) Wi-Fi MAC address | The reservation is tied to the MAC address. Turn off the private address for your network on the device, or register the MAC it actually uses. |
| A higher tier matches | A host group policy beats a directory group policy, which beats subnets and networks. Check the **Resolution chain**. |
| A more specific subnet matches | In the subnet and network tier, the narrowest range wins regardless of priority. |
| Two policies tie at the same priority | Give them different priorities. |
| The directory user or group doesn't resolve | Check **Users** for "Some referenced names could not be resolved". See [Directory groups](/docs/access-policies/directory/#troubleshooting). |
| The client uses IPv6 or WireGuard | Device tiers are IPv4 only, and WireGuard peers get network or subnet policies only. See [Limits](/docs/access-policies/assignments/#limits). |
| The Preview disagrees with what the client gets | The Preview reads the saved settings, which may not be applied yet. Click **Apply** in the changes tray. |

If the result in the Preview is right but the client still behaves differently, check the compiled mapping of addresses to policies on the router:

```bash
sudo jq '.networkGroupMap' "/var/lib/technitium-dns-server/apps/Advanced Blocking/dnsApp.config"
```

Each key is an address or range, and each value a policy name. A device with a working reservation and device-tier policy has its own `/32`-style entry, such as `"192.168.1.120": "Staff"`.

## The block page shows a certificate warning

That's expected for HTTPS sites: the block page can only offer the router's own self-signed certificate, and sites that use HSTS never show the page at all. The router has no setting that avoids it. Plain HTTP requests show the page directly. See [HTTPS sites show a certificate warning](/docs/access-policies/block-page/#https-sites-show-a-certificate-warning).

If even plain HTTP requests show no page, check that the client's policy uses **Blocking address** rather than **NXDOMAIN**, that **Serve a block page** is on and applied, and that the Block Page app bound ports 80 and 443:

```bash
sudo sh -c 'grep -h "Web server" /var/lib/technitium-dns-server/logs/*.log | tail -n 4'
```

## Filtering does nothing

| Cause | Check and fix |
| --- | --- |
| You're testing from the router | The router's own queries are never filtered. Test from a client. |
| Technitium is turned off | The last build warned `router.dns.technitium.enable is false`. Set `dns.technitium.enable` back to `true`. See [When Technitium is off](/docs/access-policies/dns-enforcement/#when-technitium-is-off). |
| The configuration didn't reach Technitium | Check `systemctl status technitium-reconcile` and its journal. See [The reconcile failed](#the-reconcile-failed). |
| The lists haven't downloaded | Look for `failed to download` in Technitium's log with the command below. Check that the router can reach the list hosts. A custom list filed under the wrong kind blocks nothing. |
| The client bypasses the router's DNS | A VPN, a DoH resolver the router doesn't know, or a WireGuard peer that doesn't use the router for DNS. See [What the router does not enforce](/docs/access-policies/dns-enforcement/#what-the-router-does-not-enforce). |
| The policy has no filters | Check the policy's **Filters** counts on the Policies tab. |

Technitium logs each list download:

```bash
sudo sh -c 'grep -h "Advanced Blocking app" /var/lib/technitium-dns-server/logs/*.log | tail -n 20'
```

## Directory groups don't resolve

Work through the layers on the router, replacing the domain and login with yours:

```bash
systemctl status sssd
sudo sssctl config-check
sudo sssctl domain-status school.example.org
getent passwd jdoe
id -Gn jdoe
journalctl -u router-directory-sync -n 50
```

`getent passwd` with no name returning no directory users is expected. A name that is right in the directory but wrong on the router is usually cached: run `sudo sss_cache -E` and `sudo systemctl restart nscd`, then click **Sync now** on the Users page. Policies keep working on the last good data; a missing or stale directory only affects the directory group tier. [Directory groups](/docs/access-policies/directory/#troubleshooting) covers each message.

## The reconcile failed

`technitium-reconcile.service` pushes the whole DNS configuration. When it fails, the router keeps answering with the previous configuration.

```bash
journalctl -u technitium-reconcile -n 50
```

It retries on its own after 15 seconds, with at most four starts in five minutes. After you fix the cause, run it again. It stays "active" after a successful run, so use `restart` rather than `start`:

```bash
sudo systemctl restart technitium-reconcile
```

## Local names don't resolve

| Symptom | Cause and fix |
| --- | --- |
| An override doesn't answer | Check that the zone exists and is a forwarder zone in Technitium's console. An override inside a forward zone never applies, and the build rejects that combination. |
| A device has no name under the LAN domain | Only devices with a static IP get a published record, and only while **Publish static hosts** is on. A registered device without one is looked up live, so it resolves only while the router sees it on the network. Check the last apply for a warning that two device names reduce to the same label; both are skipped. |
| Every name in a domain returns "not found" | A zone for that domain exists as an ordinary (primary) zone, probably made by hand in Technitium's console. The router leaves zones it didn't create alone. Delete the zone in the console, then run `sudo systemctl restart technitium-reconcile`. |
| Only the router's own name resolves under the LAN domain | The LAN domain is a special-use name such as `local` or `test`, which Technitium answers itself before any policy or zone applies. The build warns about it. Use an ordinary domain such as `lan`. |

See [Split-horizon DNS](/docs/access-policies/dns-enforcement/#split-horizon-dns) for how the zones are built.

## Reset the Technitium admin password

The router manages Technitium's admin password in `/var/lib/router-technitium/admin.pass`. To recreate Technitium's accounts from that file, for example after someone changed the password in the console:

```bash
sudo systemctl stop technitium-dns-server
sudo rm /var/lib/technitium-dns-server/auth.config
sudo systemctl start technitium-dns-server
sudo systemctl restart technitium-reconcile
```

To also generate a new password, delete the password file and regenerate it before starting the server:

```bash
sudo systemctl stop technitium-dns-server
sudo rm /var/lib/technitium-dns-server/auth.config /var/lib/router-technitium/admin.pass
sudo systemctl restart router-dns-secrets
sudo systemctl start technitium-dns-server
sudo systemctl restart technitium-reconcile
```

The reconcile recreates the Cockpit dashboard account and its token.

## Open the Technitium console

You rarely need Technitium's own web console, but it helps to inspect zones and app settings. It listens only on the router's loopback address, on port 5380 by default. Forward it over SSH from your workstation, using your SSH user on the router:

```bash
ssh -L 5380:127.0.0.1:5380 admin@192.168.1.1
```

Then browse to `http://localhost:5380` and log in as `admin` with the password from `sudo cat /var/lib/router-technitium/admin.pass`. The router reapplies its settings, app configurations and managed zones on every reconcile, so make lasting changes in Cockpit or the settings file, not in the console.

## Useful commands

| Command | Shows |
| --- | --- |
| `systemctl status technitium-dns-server` | The DNS server |
| `systemctl status technitium-reconcile` | The last configuration push |
| `journalctl -u router-policy-push` | Policy pushes after directory changes |
| `systemctl status router-policy-push.path` | The watch on the directory state file |
| `systemctl status router-logd` | The query log and exception form service |
| `systemctl list-timers 'router-directory-sync*' 'router-report-*'` | When the directory sync and reports run next |
| `journalctl -u router-directory-sync` | Directory sync results |
| `sudo nft list table inet dns_bypass` | The DoT and IPv6 DNS drops, with packet counters |
| `sudo nft list chain inet nat prerouting` | The port 53 redirects |
| `sudo ls /var/lib/technitium-dns-server/logs/` | Technitium's own log files, kept for 30 days |

## Files on the router

| Path | Contents |
| --- | --- |
| `/var/lib/router-technitium/admin.pass` | Technitium admin password (generated; don't edit) |
| `/var/lib/router-technitium/cockpit.pass` | Password of the read-only dashboard account (generated) |
| `/var/lib/router-technitium/logd-ingest.token`, `logd-query.token` | Tokens between Technitium, `router-logd` and Cockpit (generated) |
| `/var/lib/cockpit-router/technitium-token` | Cockpit's read-only Technitium API token (generated) |
| `/var/lib/router-technitium/managed-local-dns.json` | Split-horizon zones and records the router created |
| `/var/lib/router-technitium/managed-zones.json` | SafeSearch zones the router created |
| `/var/lib/router-technitium/last-reconcile.json` | Time of the last successful reconcile |
| `/var/lib/router-directory/directory.json`, `status.json` | Directory sync results and status |
| `/var/lib/router-logd/querylogs.duckdb` | The query log |
| `/var/lib/router-reports/` | Generated PDF and CSV reports |
| `/etc/router/secrets/` | Your secrets, such as the directory bind password and the Cloudflare email token |
