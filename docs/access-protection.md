# Access Protection

Barracuda-style DNS content filtering for schools and businesses, built on
Technitium DNS Server. Multiple named **access policies** are assigned to
device groups, directory groups, subnets, and/or networks; every DNS client
resolves through exactly one policy.

## Architecture

```
settings JSON ──nixos-rebuild──► NixOS modules ──► desired-state files
     ▲                                                    │
  Cockpit UI                                   technitium-reconcile (API)
                                                          │
clients ──:53──► Technitium DNS ──► Advanced Blocking (compiled policies)
                     │    │              │
                     │    └─ Block Page app (:80/:443, exception form)
                     │
                Log Exporter ──HTTP──► router-logd (Turso DB)
                                          │  ├─ /logs, /stats (Cockpit, reports)
                                          │  └─ /portal (exception requests)
                              router-report timers ──Typst──► PDF ──Cloudflare──► email
```

- **modules/filter-catalog.nix** — filter/category catalog (format-tagged),
  DoH-provider list, SafeSearch record map.
- **modules/hosts.nix** — device registry (`router.hosts`) and groups; devices
  with a `staticIp` get a systemd-networkd DHCP reservation, the anchor for
  device-tier policies.
- **modules/access-policies.nix** — `router.accessPolicies`; emits
  `router-policy-static.json` for the runtime compiler.
- **modules/dns-technitium.nix** — engine provisioning (see below).
- **modules/directory-sync.nix** — LDAP / Microsoft Entra / Google Workspace
  user+group sync (`router-directory-sync.timer`) into
  `/var/lib/router-directory/directory.json`. Identity is used ONLY for policy
  assignment; there is no admin SSO.
- **modules/reporting.nix** — `router-logd` (query-log store + exception
  portal) and `router-report-<name>` timers.
- **pkg/router-dns-tools** — the Python package behind all runtime services.

## Technitium provisioning

Technitium's main config (`dns.config`) is binary, so it cannot be generated
declaratively. Provisioning happens in three phases:

1. **First boot** — `DNS_SERVER_*` environment variables seed the config
   (admin password from `/var/lib/router-technitium/admin.pass`, forwarders,
   ports). They are read only when `dns.config` is absent.
2. **App pre-seeding** — pinned official app zips (Advanced Blocking, Log
   Exporter, Block Page) are copied into
   `/var/lib/technitium-dns-server/apps/<Name>/` before the daemon starts, so
   filtering is active from the first second. The Block Page app also gets the
   Nix-generated branded `wwwroot`.
3. **Reconcile** — `technitium-reconcile.service` (idempotent, re-run by every
   rebuild whose desired state changed) asserts settings, the router's local
   zone, SafeSearch ANAME zones, app configs (including the compiled Advanced
   Blocking policy config), and the read-only Cockpit API token.

`router-policy-push.service` re-pushes only the compiled policy config; a path
unit triggers it whenever directory sync updates `directory.json`, so IdP
changes apply without a rebuild.

## Policy resolution

One winning policy per client (the Advanced Blocking app maps each client IP
to exactly one group; most-specific `networkGroupMap` prefix wins):

1. **Host group** — the device's `group` (requires a static IP);
2. **Directory group** — groups of the device's assigned `user`;
3. **Subnet / network** — policy `assignments.subnets` / `networks`;
4. **`accessPolicies.defaultPolicy`**.

Within a tier the highest `priority` wins. DoH-provider domains are appended
to every policy's block list (bypass prevention), complementing the nftables
:53 DNAT and :853 DoT drop.

## Block page & exception requests

With `accessPolicies.blockPage.enable`, policies whose `responseType` is
`blockingAddress` answer blocked queries with the router's LAN IP; the Block
Page app serves the branded page on :80/:443 (self-signed TLS — HTTPS sites
show a certificate warning unless a root CA is deployed to managed devices).
The page's "Request an exception" form posts to `router-logd`, which resolves
the requesting device/user/group and queues the request; admins approve or
deny from Cockpit → Access Policies → Exception requests. Approval appends the
domain to a policy's `allowDomains` — a normal declarative settings change.
NXDOMAIN-type policies intentionally show no page.

## Reporting

- `router-logd` owns the Turso query-log database (Turso does not support
  multi-process access — all reads/writes go through its localhost HTTP API).
  Entries are enriched with device/group/policy attribution at ingest.
  Retention: `router.reporting.retentionDays` (budget several GB for 90 busy
  days).
- Scheduled reports (`router.reporting.schedules`) render a Typst PDF + CSV
  into `/var/lib/router-reports/` and are optionally emailed via the
  **Cloudflare Email Sending API** (`reporting.email.{accountId, apiTokenFile,
  fromAddress}`; the token needs *Email Routing: Edit* on an Email
  Routing-enabled zone).

## Secrets layout

Secrets are always **file paths** in the settings JSON, never inline values.
Recommended location: `/etc/router/secrets/` (root:root, 0600).

| File (example) | Used by |
|---|---|
| `/etc/router/secrets/ldap-bind.pass` | `directory.ldap.bindPasswordFile` |
| `/etc/router/secrets/entra-client.secret` | `directory.entra.clientSecretFile` |
| `/etc/router/secrets/google-sa.json` | `directory.google.serviceAccountKeyFile` |
| `/etc/router/secrets/cloudflare-email.token` | `reporting.email.apiTokenFile` |

Generated at runtime (do not edit): `/var/lib/router-technitium/{admin.pass,
cockpit.pass, logd-ingest.token, logd-query.token}`,
`/var/lib/cockpit-router/technitium-token`.

## Directory provider setup

- **LDAP / AD** — a read-only bind account; `userFilter` / `groupFilter`
  default to `(objectClass=person)` / `(objectClass=group)`; groups resolve
  via `memberOf`.
- **Microsoft Entra** — app registration with **application** permissions
  `User.Read.All` + `GroupMember.Read.All` (admin consent), client-credentials
  flow; store the client secret in the secret file.
- **Google Workspace** — service account with **domain-wide delegation**
  impersonating `adminEmail`; scopes
  `admin.directory.user.readonly` + `admin.directory.group.readonly`; store
  the JSON key as the secret file.

## Migration from AdGuard Home

AdGuard Home was removed. Settings JSON still containing `dns.adguard`:

- keeps evaluating for one release — the module synthesizes a "Base" policy
  from the old keys (loud warning) so auto-upgrading routers never lose
  filtering;
- Cockpit shows a **Migrate settings** banner that rewrites the JSON
  (old filters → the "Base" default policy, `dns.technitium` enabled,
  `dns.adguard` removed). Do this promptly: schema validation blocks other
  saves until migrated.

Old AdGuard state can be removed manually: `rm -rf /var/lib/AdGuardHome`.

## Troubleshooting

- **Reconcile failed** — `journalctl -u technitium-reconcile`; it retries
  automatically. Manual run: `systemctl start technitium-reconcile`.
- **Admin password reset** — stop the service, delete
  `/var/lib/technitium-dns-server/auth.config` and
  `/var/lib/router-technitium/admin.pass`, start, then run the reconcile
  (fresh password is generated and seeded).
- **Dashboards empty** — check `/var/lib/cockpit-router/technitium-token`
  exists and `router-logd.service` is running (`curl
  http://127.0.0.1:8067/healthz`).
- **Directory sync errors** — Cockpit → Users shows the last error;
  `journalctl -u router-directory-sync`. Policies keep working on last-good
  data; a missing/stale directory only disables the user tier.
- **Block page not appearing** — only `blockingAddress` policies show it;
  check the Block Page app is bound (`journalctl -u technitium-dns-server |
  grep "Web server"`) and ports 80/443 are allowed from the client's network.
