---
title: Reports
description: DNS dashboards, the searchable query log with device and policy attribution, and scheduled PDF and CSV reports emailed through Cloudflare.
code:
  - modules/reporting.nix
  - modules/dns-technitium.nix
  - pkgs/router-dns-tools/router_dns_tools/logd.py
  - pkgs/router-dns-tools/router_dns_tools/report.py
  - pkgs/router-dns-tools/router_dns_tools/report.typ
  - pkgs/cockpit-router/src/reports.tsx
  - pkgs/cockpit-router/src/report-schedules.ts
  - pkgs/cockpit-router/src/logd.ts
---

# Reports

The **Reports** page shows what your clients look up and what the filter blocks. It has three tabs: **Overview** for dashboards, **Query log** for individual queries, and **Scheduled reports** for PDF reports on a timer, optionally emailed. Reporting runs whenever Technitium is on; there is nothing to turn on first.

## Where the data comes from

- **Technitium's own statistics** drive the **DNS statistics** card, the chart and the top domains, blocked domains and clients on the Overview tab.
- **`router-logd`** keeps the query log. Technitium's Log Exporter app sends it every query, and it tags each entry with the client's device name, host group and policy at the moment it arrives. Later changes to hosts or policies don't rewrite old entries. The database is `/var/lib/router-logd/querylogs.duckdb`, and every read goes through `router-logd`'s local HTTP API.

Device names and host groups are known only for devices with a static IP on the Hosts page. Other clients appear by IP address.

## Overview

Choose a time range with **Last hour**, **Last day**, **Last week** or **Last month**. The tab refreshes every 10 seconds, or when you click **Refresh**.

- **DNS statistics:** **Queries**, **Blocked** (with the percentage), **Clients**, **Cached** and **Block list zones**.
- **Queries over time:** total and blocked queries.
- **Top domains**, **Top blocked domains** and **Top clients**. A client with a static IP on the Hosts page shows its device name next to the address.
- **By group** and **By policy:** query counts per host group and per policy from `router-logd`, with the blocked count, such as "Students — 1204 blocked". Clients without a host group are counted under "(unknown)".

If `router-logd` can't be reached, the page shows "Query-log daemon not reachable — group and policy breakdowns unavailable" and hides the last two cards.

## Query log

The **Query log** tab lists individual queries, newest first, 50 per page.

Filters:

- time range: **Last hour**, **Last 24 hours**, **Last 7 days** or **Last 30 days**;
- **Client IP**, an exact address;
- **Domain contains**, any part of the name;
- a host group, or **All groups**;
- **Blocked only**.

Columns: **Time**, **Client** (the device name, or the address; hover to see the address), **Domain**, **Type**, **Response** (red for blocked answers), **Policy** and **Answer**.

**Export CSV** downloads the entries that match the filters, up to 100,000 rows, as a file named `query-log-` followed by the date and time.

To find why a site misbehaves for one user, filter on their device's address and turn on **Blocked only**. Pages often need several domains, and the blocked ones show up here.

## Scheduled reports

A schedule generates a PDF report and a CSV file on a timer, and can email the PDF.

### Before you start

To email reports, you need a Cloudflare account set up to send email for the domain of your sender address, and an API token with the permission [Cloudflare API tokens](/docs/reference/cloudflare-tokens/) lists for report email. The token goes in a file on the router, like any other secret. See [Cloudflare API tokens](/docs/reference/cloudflare-tokens/). To keep reports on the router only, you need neither.

### Set up email delivery

1. Store the token on the router:

   ```bash
   sudo install -d -m 0700 -o root -g root /etc/router/secrets
   sudo sh -c 'umask 077; cat > /etc/router/secrets/cloudflare-email.token'
   ```

   Paste the token, press Enter, then Ctrl+D.

2. Open **Reports → Scheduled reports**. Under **Email delivery**, fill in:
   - **Cloudflare account id:** the account that sends the email.
   - **API token file:** `/etc/router/secrets/cloudflare-email.token`. The help text reads "Path to a root-owned file on the router — never the secret itself."
   - **From address:** the sender, such as `reports@example.org`.
3. Click **Save & apply**.

### Create a schedule

1. On **Reports → Scheduled reports**, click **Add schedule**.
2. Fill in the new card:
   - **Name:** starts as `report-1`, `report-2` and so on. Use letters, digits, hyphens and underscores only, such as `weekly-summary`, and give each schedule its own name. It is used in file and service names.
   - **Frequency:** **Daily**, **Weekly** or **Monthly**.
   - **Day of week:** for weekly reports.
   - **Time:** 24-hour local time, such as `07:30`.
   - **Recipients:** email addresses. The help text reads "Empty = generate the PDF only, no delivery."
   - **Sections:** any of **Overview**, **Top domains**, **Top blocked**, **Per group**, **Per device** and **Per user**.
   - **Host groups:** "Restrict group breakdowns to these host groups; none = all."
3. Click **Save & apply**.

The card checks **Name** and **Time** as you type. While either one shows an error, **Save & apply** stays greyed out.

What each section contains:

| Section | Contents |
| --- | --- |
| **Overview** | Total queries, blocked queries and block rate, and the number of active clients |
| **Top domains** | The 25 most-queried domains |
| **Top blocked** | The 25 most-blocked domains |
| **Per group** | Queries and blocks per host group |
| **Per device** | Queries and blocks per registered device |
| **Per user** | Device counts added up per directory user, using each device's **User** on the Hosts page |

### When reports run

| Frequency | Runs | Covers |
| --- | --- | --- |
| Daily | Every day at **Time** | The last 24 hours |
| Weekly | On **Day of week** at **Time** | The last 7 days |
| Monthly | On the 1st of the month at **Time** | The last 30 days |

Each run starts up to 5 minutes after the set time. A run missed while the router was off happens at the next boot. To run a schedule now, start its service, which is named after the schedule:

```bash
sudo systemctl start router-report-weekly-summary
journalctl -u router-report-weekly-summary -n 20
```

### Files and email

Each run writes a PDF and a CSV to `/var/lib/router-reports/`, named with the date and the schedule, such as `2026-09-28-weekly-summary.pdf`. Reports older than 365 days are deleted. To download one, click **Download** in the **Generated reports** list at the bottom of the tab.

With recipients, an account id and a token set, the PDF is emailed as an attachment through Cloudflare's email sending API, with the totals repeated in the message body. The CSV isn't emailed. If delivery fails, the run still succeeds and the PDF stays on the router. The journal shows one of these:

- `Cloudflare email delivery failed:` followed by the reason;
- `no recipients configured — skipping email delivery`;
- `Cloudflare email not configured (accountId/apiTokenFile) — skipping delivery`.

## Retention

**Retention (days)**, under **Reporting** on **Reports → Scheduled reports**, sets how long query-log entries are kept: 90 days by default, from 1 to 3650. `router-logd` deletes older entries once a day, and Technitium's dashboard statistics use the same limit. The log grows with your query volume, so size the retention to your disk.

## In the settings file

```json
{
  "reporting": {
    "retentionDays": 90,
    "email": {
      "accountId": "0123456789abcdef0123456789abcdef",
      "apiTokenFile": "/etc/router/secrets/cloudflare-email.token",
      "fromAddress": "reports@example.org"
    },
    "schedules": [
      {
        "name": "weekly-summary",
        "frequency": "weekly",
        "dayOfWeek": "Mon",
        "time": "07:30",
        "recipients": ["it@example.org", "principal@example.org"],
        "sections": ["overview", "topDomains", "topBlocked", "perGroup"],
        "groups": []
      }
    ]
  }
}
```

A schedule written in the settings file defaults to `"weekly"` on `"Mon"` at `"06:00"`, with no recipients and the sections `overview`, `topDomains`, `topBlocked` and `perGroup`. Schedules added in Cockpit start at `08:00` with the first three sections. Two more keys have no field in Cockpit: `reporting.enable` (on by default) turns scheduled reports off without deleting them, and `reporting.logd.port` (8067 by default) sets the port `router-logd` listens on.

## Upgrading from the Turso query-log store

Earlier versions kept the query log in a Turso (SQLite-format) file, `querylogs.db`. The current store is DuckDB, in `querylogs.duckdb`, created on first start. History from the old file isn't carried over. Nothing needs to be done, but you can reclaim the space:

```bash
sudo rm -f /var/lib/router-logd/querylogs.db
```

## Troubleshooting

- **The Overview tab shows "Could not load DNS statistics".** Cockpit reads Technitium's statistics with a token in `/var/lib/cockpit-router/technitium-token`, which `technitium-reconcile.service` creates. Check that the file exists and that the reconcile succeeded with `systemctl status technitium-reconcile`.
- **"Query-log daemon not reachable", or the query log is empty.** Check `systemctl status router-logd`. On the router, `curl http://127.0.0.1:8067/healthz` should answer `{"ok": true, "engine": "duckdb"}`.
- **Every client is counted under "(unknown)" in By group.** Only devices with a static IP and a host group are attributed to a group.
- **No report files appear.** Check the timers with `systemctl list-timers 'router-report-*'`, and the last run with `journalctl -u router-report-weekly-summary`, using your schedule's name.
- **Reports aren't emailed.** Look for the journal messages listed under [Files and email](#files-and-email).
