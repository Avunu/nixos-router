---
title: Events and logs
description: Read Suricata's events in Cockpit, the journal and the log files, check that inspection is running, and fix common problems.
code:
  - modules/threat-protection.nix
  - modules/firewall.nix
  - pkgs/cockpit-router/src/suricata.tsx
  - pkgs/cockpit-router/src/suricata-events.ts
  - pkgs/cockpit-router/src/hosts-live.ts
---

# Events and logs

Suricata's events appear in three places: the **Threat Protection** tabs in Cockpit, the `suricata` journal namespace those tabs read, and log files under `/var/log/suricata`. This page covers each one, the commands that show whether inspection is working, and fixes for common problems. To act on an event, see [Tune the rules](/docs/threat-protection/tuning/).

## Overview tab

**Threat Protection → Overview** summarizes the last 7 days:

- **Status**:
  - **Service** is the state of `suricata.service`: `active`, `activating`, `inactive` or `failed`.
  - **Protection** is **IPS — dropping**, **IDS — alert only** or **disabled**, from the settings that are applied. Saved but unapplied changes don't show here.
  - **Events (7d)** counts alerts and drops.
  - **By severity** splits that count into high, medium and low.
- **Malicious events — last 7 days** shows one bar per day, stacked by **High**, **Medium** and **Low**. Hover over a bar to see its counts.
- **Top offending sources (7d)** lists the ten source addresses with the highest score. Each High event counts 3, Medium 2 and Low 1. An address that answers mDNS lookups shows its name too.

A source can be one of your own hosts: for an outbound alert, such as malware calling home, the source is the infected device. The tab loads once when you open it; switch tabs and back to refresh it.

## Statistics tab

**Threat Protection → Statistics** ranks events over a time range. Choose **7 days**, **30 days** or **All**; the number of events in the range appears next to the list. The cards are:

- **Top source IPs** and **Top destination IPs**
- **Top signatures** and **Top categories**
- **By severity**
- **By protocol**: the application protocol when Suricata identified one, otherwise the transport protocol

Each card shows the top five. **All** covers everything the `suricata` journal namespace still holds.

The Overview and Statistics tabs read at most 5,000 events per query. When a range has more, Statistics shows **Showing the most recent events only**, and older events are left out of the totals. The Overview is capped the same way, without the warning.

## Where events come from

Suricata writes its events twice:

- **Alerts go to the journal.** A second output sends alert events, and nothing else, through syslog into the journald namespace `suricata`. The Cockpit tabs read them with `journalctl --namespace suricata`. Packets Suricata dropped appear as alerts whose action is `blocked`. The namespace also holds Suricata's own messages, such as start-up notices and errors.
- **The full record goes to a file.** `/var/log/suricata/eve.json` holds alerts plus DNS, TLS, HTTP and flow records; see [Logs on disk](#logs-on-disk).

To read the journal from a shell:

```bash
# Follow new entries as they arrive
sudo journalctl --namespace suricata -f

# Today's alerts as columns: time, action, source, destination, SID, signature
sudo journalctl --namespace suricata -o cat --since today \
  | jq -rR 'fromjson? | select(.event_type == "alert") | [.timestamp, .alert.action, .src_ip, .dest_ip, .alert.signature_id, .alert.signature] | @tsv'
```

The router sets its journal limits (500 MB, 30 days) for the main system journal. It sets none specifically for the `suricata` namespace.

## Logs on disk

| File | Contents |
| --- | --- |
| `/var/log/suricata/eve.json` | One JSON record per line: alerts, drops, DNS, TLS, HTTP and flow records, and engine statistics every 30 seconds. |
| `/var/log/suricata/fast.log` | One line of text per alert. |

The router sets up `logrotate` for the `.log` and `.json` files in that directory (daily, 14 rotations), but the rule doesn't match the files, so in practice they aren't rotated. `eve.json` grows with your traffic until you clear it. Check the size with `sudo du -sh /var/log/suricata`. Suricata appends to these files, so you can empty them in place without stopping it: `sudo truncate -s 0 /var/log/suricata/eve.json /var/log/suricata/fast.log`.

Because `eve.json` also has TLS and flow records, you can use it to see what a host was doing around the time of an alert:

```bash
# Follow alerts as one line of text each
sudo tail -f /var/log/suricata/fast.log

# Server names that 192.168.1.20 connected to over TLS
sudo jq -r 'select(.event_type == "tls" and .src_ip == "192.168.1.20") | [.timestamp, .dest_ip, .tls.sni] | @tsv' /var/log/suricata/eve.json
```

## Useful commands

```bash
# Is the service running?
systemctl status suricata.service

# Has Suricata loaded its rules and attached to the queue?
sudo journalctl --namespace suricata -b -o cat | grep 'Engine started'

# Suricata's own messages since boot, without the alert records
sudo journalctl --namespace suricata -b -o cat | grep -v '^{'

# When is the next rule update, and how did the last one go?
systemctl list-timers suricata-update.timer
sudo journalctl -u suricata-update.service -n 50

# Is the queue rule in place?
sudo nft list table inet ips

# Is anything attached to the queue? Look for a line whose first number is 0.
sudo cat /proc/net/netfilter/nfnetlink_queue

# Ask the running engine through its command socket:
# how long it has run, and how many rules loaded or failed at the last (re)load
sudo suricatasc -c uptime
sudo suricatasc -c ruleset-stats
```

If `nft list table inet ips` shows the table but `/proc/net/netfilter/nfnetlink_queue` has no line for queue 0, Suricata isn't attached and forwarded traffic is passing uninspected.

## Troubleshooting

### Suricata won't start or is slow to start

**Symptom:** **Service** stays `activating` for minutes or shows `failed`, or applying settings ends in **Apply failed.**

**Cause and fix:**

- **Slow hardware.** Before starting, Suricata runs a configuration test that loads every rule, which takes about 2 minutes on low-power hardware. Then it loads them again. The service allows 300 seconds to start. If `systemctl status suricata.service` reports a timeout, the router is too slow for the full rule set. Set categories you don't need to **Disable** to shrink it.
- **A rule that doesn't parse, or a duplicate SID.** Read Suricata's messages with `sudo journalctl --namespace suricata -b -o cat | grep -v '^{'`. An error naming a rule, followed by `Loading signatures failed.`, points to a line in **Extra local rules**. `Duplicate signature` means a SID is used twice, often one of the built-in 1000001 to 1000011. Fix or remove the line and apply again.
- **A bad suppression.** A `threshold-config` parse error means a suppression's host isn't a valid IP address or subnet. Fix it on the **Policies** tab and apply.

While Suricata is down, forwarded traffic passes uninspected.

### No events appear

**Symptom:** the Events tab says "No matching alerts or drops." and the Overview counts stay at zero.

**Cause and fix:**

- **Suricata isn't inspecting yet.** Check for `Engine started` with the commands above.
- **The traffic isn't forwarded.** Traffic to the router itself and traffic between devices on the same network is never inspected; see [What it doesn't do](/docs/threat-protection/#what-it-doesnt-do).
- **Nothing has matched.** To test the path end to end, add a temporary rule in **Extra local rules**, apply, and ping an internet IPv4 address from a LAN host, for example `ping -c 5 9.9.9.9`:

  ```text
  alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL test ping"; itype:8; sid:1000199; rev:1;)
  ```

  Once the apply has finished and Suricata has reloaded its rules, an event named `LOCAL test ping` appears on the **Events** tab. Remove the rule afterwards.
- **Cockpit can't read the journal.** The tabs show **Could not read Suricata events** with the error from `journalctl`.

### A site broke after you enabled IPS mode

**Symptom:** a site or app stops working for some users after you switch to IPS mode or set a drop action.

**Fix:**

1. Open **Threat Protection → Events**, set the action filter to **Blocked**, and search for the affected client's IP address.
2. Open the blocking event and note its signature and SID.
3. If the traffic is legitimate, choose **Disable signature** or **Suppress for a host** and click **Save policy**. If the drop came from a category, you can instead set that category back to **Default** on **Policies**.
4. Apply the change.

To stop all drops at once while you investigate, turn off **Drop high-risk packets automatically (IPS mode)** and click **Save & apply**. This empties the drop list, but a `drop` rule you wrote in **Extra local rules** still drops. If you find no blocked event for the client, Suricata didn't drop the traffic; look at the firewall and DNS filtering instead.

### IPv6 inbound traffic doesn't match `$HOME_NET` rules

**Symptom:** an [IPv6 port forward](/docs/ingress/port-forwards/) gets no alerts where the same service over IPv4 does.

**Cause:** `$HOME_NET` holds the IPv4 LAN and guest subnets and the WireGuard addresses and Allowed IPs, but not the IPv6 prefix your ISP delegates. Your hosts' IPv6 addresses count as external, so rules keyed on `$HOME_NET` don't match. Rules written with `any` still do.

**Fix:** there's no setting that adds the delegated prefix. Forward only what must be reachable over IPv6, and narrow the forward's allowed sources where you can.

## Limits

- Of Suricata's event records, the journal namespace carries alerts only. DNS, TLS, HTTP and flow records are in `eve.json` alone.
- The Overview and Statistics tabs read at most 5,000 events per query, and the Events tab keeps 2,000 rows.
- The logs on disk aren't rotated; see [Logs on disk](#logs-on-disk). The router sets no retention limit specific to the `suricata` journal namespace.
- There are no email or push notifications, and no export from the Cockpit tabs.
- Events only cover forwarded traffic, and only while Suricata is running.
