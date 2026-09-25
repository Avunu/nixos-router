---
title: Turn it on
description: Enable Suricata in IDS mode, triage for a week, then switch to IPS mode. Also covers hardware cost, rule updates and restarts.
code:
  - modules/threat-protection.nix
  - modules/firewall.nix
  - pkgs/cockpit-router/src/suricata.tsx
  - pkgs/cockpit-router/src/settings.tsx
  - pkgs/cockpit-router/src/changes.tsx
  - pkgs/suricata-update-preflight/package.nix
---

# Turn it on

Start Suricata in IDS mode, where it only alerts, and leave it there for about a week. Triage what it reports, then switch to IPS mode so the drop actions you chose take effect. This page covers both steps, what inspection costs, and how the rules stay current.

## Before you start

- You can sign in to Cockpit with administrative access; see [the web UI](/docs/start/cockpit/).
- The router has internet access. Rules are downloaded when Suricata is first set up, and daily after that.
- Check whether it's already on. `suricata.enable` defaults to `false`, but the example settings files in the repository's `local/` directory set it to `true`, so a router installed from them already runs Suricata in IDS mode.

## Enable IDS mode

1. In Cockpit, open **Threat Protection → Settings**.
2. Turn on **Enable Suricata IPS**.
3. Leave **Drop high-risk packets automatically (IPS mode)** off. Off is IDS mode.
4. Click **Save & apply**. (Or click **Save**, and later **Apply** in the **Unapplied changes** bar.)
5. When the apply finishes, open **Threat Protection → Overview**. Under **Status**, **Protection** shows **IDS — alert only**. **Service** shows `activating` while Suricata's configuration test runs, then `active`. The tab doesn't refresh itself; switch tabs and back to update it.

`active` means the process has started, not that it's inspecting yet: Suricata loads its rules once more before it attaches to the queue. On low-power hardware the test and the load take a few minutes together. Until then, forwarded traffic passes uninspected; see [While Suricata restarts](#while-suricata-restarts).

## Triage for a week

Leave IDS mode on for about a week, so the events cover a normal cycle of weekday and weekend use, backups and software updates. Then work through them as described in [Tune the rules](/docs/threat-protection/tuning/):

- Disable signatures that fire on legitimate traffic everywhere.
- Suppress signatures that are noisy for one host.
- Choose the categories and signatures you want dropped.

## Switch to IPS mode

1. Open **Threat Protection → Settings**.
2. Turn on **Drop high-risk packets automatically (IPS mode)**.
3. Click **Save & apply**.
4. On **Overview**, **Protection** now shows **IPS — dropping**.

IPS mode doesn't make every rule drop. It applies only the drop actions on the **Policies** tab: categories set to **Drop** and signatures set to **Drop**. With none set, IPS mode behaves like IDS mode.

:::doc-warning
A drop rule that matches legitimate traffic breaks it for your users, without an error message they can act on. Set drops only for signatures and categories you've watched in IDS mode.
:::

## In the settings file

```json
{
  "suricata": {
    "enable": true,
    "mode": "ids"
  }
}
```

`mode` is `ids` (the default) or `ips`. The rule policies live under the same key; see [Tune the rules](/docs/threat-protection/tuning/#in-the-settings-file).

## What it costs

- **Start-up time.** Before Suricata starts, systemd runs a configuration test (`suricata -T`) that loads every rule. That takes about 2 minutes on low-power hardware, and Suricata then loads the rules again to start. The service allows 300 seconds to start (`TimeoutStartSec=300`), instead of systemd's default 90.
- **CPU and throughput.** Every forwarded packet goes to Suricata in user space and back before it leaves. That costs CPU and lowers the throughput the router can forward, more so on low-power hardware. Measure it on your own hardware and traffic.
- **Memory.** Suricata holds the loaded rules in memory. Stream tracking is capped at 64 MB and stream reassembly at 256 MB.
- **Disk.** `/var/log/suricata/eve.json` records DNS, TLS, HTTP and flow events as well as alerts, so it grows with your traffic. See [Events and logs](/docs/threat-protection/monitoring/#logs-on-disk).

## Rule updates

`suricata-update` downloads the rules and builds the rule set Suricata loads. It runs:

- at boot, before Suricata starts. The service is part of the normal boot target, and Suricata is ordered after it.
- on the `suricata-update.timer`: daily at midnight (`OnCalendar=daily`), plus the NixOS module's own triggers, 30 seconds after boot and 24 hours after the last run. Each trigger adds a random delay of up to one hour (`RandomizedDelaySec=1h`). `Persistent=true` catches up on a daily run missed while the router was off.
- whenever you apply settings. This is how changes on the **Policies** tab reach the rule set.

Each run does the following:

1. It checks the cached source index at `/var/lib/suricata/update/cache/index.yaml` and deletes it if it doesn't parse. A power cut during an update can leave that file filled with zeros, and without this check every later update would fail on it.
2. It enables the rule sources and refreshes the source index.
3. It downloads each source, applies your disable and drop lists, and writes `/var/lib/suricata/rules/suricata.rules`. If a download fails, it uses the last cached copy of that source.
4. It tells Suricata to reload its rules. A reload keeps Suricata running on the old rules until the new ones are ready, so inspection doesn't stop.

The sources are the NixOS `services.suricata.enabledSources` default: `et/open`, `abuse.ch/sslbl-blacklist`, `abuse.ch/sslbl-c2`, `abuse.ch/sslbl-ja3`, `etnetera/aggressive`, `stamus/lateral`, `oisf/trafficid`, `tgreen/hunting`, `pawpatrules` and `ptrules/open`. The router settings file doesn't change this list. The categories on the **Policies** tab cover the ET Open rule files; manage rules from the other sources by signature ID.

## While Suricata restarts

Suricata stops inspecting whenever it isn't attached to the queue. That happens:

- when you first enable it, and after every reboot
- when you apply a change to its configuration, such as a new suppression, or a network or WireGuard change that alters `$HOME_NET`
- after a crash, before systemd restarts it

In each case, forwarded traffic passes uninspected until Suricata has loaded its rules and logs `Engine started`. Nothing is blocked, so users see no outage, but nothing is inspected either. To check whether it's running, see [Events and logs](/docs/threat-protection/monitoring/#useful-commands).

## Turn it off

Turn off **Enable Suricata IPS** on **Threat Protection → Settings** and click **Save & apply**. The router stops Suricata and removes the `inet ips` table, so forwarded traffic no longer goes through the queue. Your policies stay in the settings file for when you turn it back on.
