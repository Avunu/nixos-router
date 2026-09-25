# Access Protection

Barracuda-style DNS content filtering for schools and businesses, built on Technitium DNS Server. Multiple named **access policies** are assigned to device groups, directory groups, subnets, and/or networks; every DNS client resolves through exactly one policy.

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
                Log Exporter ──HTTP──► router-logd (DuckDB)
                                          │  ├─ /logs, /stats (Cockpit, reports)
                                          │  └─ /portal (exception requests)
                              router-report timers ──Typst──► PDF ──Cloudflare──► email
```

-   **modules/filter-catalog.nix** — filter/category catalog (format-tagged), DoH-provider list, SafeSearch record map.
-   **modules/hosts.nix** — device registry (`router.hosts`) and groups; devices with a `staticIp` get a systemd-networkd DHCP reservation, the anchor for device-tier policies.
-   **modules/access-policies.nix** — `router.accessPolicies`; emits `router-policy-static.json` for the runtime compiler.
-   **modules/dns-technitium.nix** — engine provisioning (see below) and
    split-horizon DNS (`dns.overrides`, `dns.forwardZones`,
    `dns.registerStaticHosts`). Setting
    `dns.technitium.enable = false` means *no filtering*, not *no DNS*: the DHCP
    advert and the :53 DNAT both point clients at the router regardless, so
    systemd-resolved takes over the gateway addresses and forwards queries
    unfiltered (in plaintext to the WAN-provided resolvers — it speaks DoT, not
    the DoH upstreams configured here). A warning is emitted while in that mode.
-   **modules/directory-sync.nix** — connects the router to your LDAP/Active Directory domain via **SSSD** and resolves the users and groups the policies reference through NSS into `/var/lib/router-directory/directory.json` (`router-directory-sync.timer`). SSSD owns the directory connection, its TLS, its credentials and its cache; the router only calls `getpwnam` / `getgrouplist` / `getgrnam`. Identity is used for policy assignment only — there is no admin login unless you explicitly set `directory.sssd.adminGroup`.
-   **modules/reporting.nix** — `router-logd` (query-log store + exception portal) and `router-report-<name>` timers.
-   **pkgs/router-dns-tools** — the Python package behind all runtime services.

### Names are resolved on demand, never enumerated

SSSD does not enumerate the domain (`enumerate = false`; enumeration downloads and caches _every_ user and group and is strongly discouraged at any real scale). `getent passwd` with no argument therefore returns **nothing** for directory users — and that is deliberate, not a fault.

The sync builds `directory.json` from the names your configuration actually references:

| Reference | Set in |
| --- | --- |
| hosts[].user | Hosts → device → User |
| policies[].assignments.directoryGroups | Access policies → Directory groups |
| directory.sssd.groups | Users → Directory settings → Publish groups |

Practical consequences:

-   Cockpit's Users page lists only referenced users. An empty page on a fresh install is normal.
-   The device → user field and the directory-group selector are **free text with autocomplete**, not closed pickers. Type the POSIX login / group name exactly as the domain spells it — `id <name>` on the router is the ground truth. Use _Publish groups_ to pre-seed the group selector before any policy uses them.
-   Names that do not resolve land in `status.json`'s `unresolved` list and show as a **warning** in Cockpit. The sync still succeeds and everyone else keeps their policy. Only a total failure — no referenced user resolved at all, usually SSSD or the directory being unreachable — marks the sync failed, and even then the last-good `directory.json` is kept rather than blanking the user tier.

## Technitium provisioning

Technitium's main config (`dns.config`) is binary, so it cannot be generated declaratively. Provisioning happens in three phases:

1.  **First boot** — `DNS_SERVER_*` environment variables seed the config (admin password from `/var/lib/router-technitium/admin.pass`, forwarders, ports). They are read only when `dns.config` is absent.
2.  **App pre-seeding** — pinned official app zips (Advanced Blocking, Log Exporter, Block Page) are copied into `/var/lib/technitium-dns-server/apps/<Name>/` before the daemon starts, so filtering is active from the first second. The Block Page app also gets the Nix-generated branded `wwwroot`.
3.  **Reconcile** — `technitium-reconcile.service` (idempotent, re-run by every rebuild whose desired state changed) asserts settings, the router's local zone, the split-horizon zones, SafeSearch ANAME zones, app configs (including the compiled Advanced Blocking policy config), and the read-only Cockpit API token.

`router-policy-push.service` re-pushes only the compiled policy config; a path unit triggers it whenever directory sync updates `directory.json`, so IdP changes apply without a rebuild.

## Split-horizon DNS

Names the router answers itself, so internal clients reach a service by its real name over the LAN instead of hairpinning through the WAN address. Edited in Cockpit → DNS, or in the settings JSON:

```nix
router.dns.overrides = [
  { name = "nas.example.com"; value = "10.48.4.20"; }
  { name = "vault.example.com"; type = "ANAME"; value = "nas.example.com"; }
];

router.dns.forwardZones = [
  { zone = "corp.example.com"; forwarders = [ "10.48.4.5" ]; }
];

router.dns.registerStaticHosts = true; # the default
```

-   **`overrides`** — one record each: `A`, `AAAA`, `CNAME`, `ANAME`, `TXT` or `SRV`. A `CNAME` is illegal at the top of a zone, so an alias that owns its own name must use `ANAME` (Technitium resolves the target and answers with its addresses).
-   **`forwardZones`** — hands a whole domain to an internal DNS server (an Active Directory controller, say). Because the entire subtree is forwarded, an `override` for a name inside a forward zone is rejected rather than silently ignored.
-   **`registerStaticHosts`** — publishes every `router.hosts` entry that has a `staticIp` as `<name>.<lan.domain>` with a reverse `PTR`. Device names allow spaces, dots and underscores, so they are slugified into DNS labels; names that collide after slugification are skipped with a warning rather than one of them silently winning. The DHCP server also advertises `lan.domain` as the search domain, so a bare `nas` resolves.

### How the horizon stays split

Technitium answers a name locally only if an authoritative zone covers it, and a *Primary* zone blackholes everything else under it — a `Primary` zone for `example.com` carrying one record would turn every other name in the domain into NXDOMAIN on the LAN. So every zone this feature creates is a **Forwarder zone** carrying an apex `FWD` record that mirrors `dns.technitium.upstreamServers`: a declared name is answered locally, and anything else in the zone falls through to the real upstream. That is what makes an override at a registrable apex (`example.com` itself) safe.

Zone grouping is computed in Nix, so the reconciler only executes a list:

1.  Declared roots are the `forwardZones` zones, plus `lan.domain` when `registerStaticHosts` is on.
2.  A record joins the **longest** declared root that is a suffix of its name.
3.  A record matching no root gets a zone named exactly after itself — the narrowest zone that can answer it, so a neighbouring name is never caught in the blast radius.

The router's own `<hostName>.<lan.domain>` zone stays Primary and is untouched.

The public horizon is untouched in the other direction too: nothing outside sees these answers, because `modules/firewall.nix` drops :53 from the WAN and recursion is limited to internal networks.

Removals are reaped. `router-technitium-reconcile` records everything it created in `/var/lib/router-technitium/managed-local-dns.json` and deletes only those records and zones — a zone an operator added by hand in Technitium's own console is left alone, and a zone whose type drifted is only recreated if the router made it.

## Policy resolution

One winning policy per client (the Advanced Blocking app maps each client IP to exactly one group; most-specific `networkGroupMap` prefix wins):

1.  **Host group** — the device's `group` (requires a static IP);
2.  **Directory group** — POSIX groups of the device's assigned `user`, resolved with `getgrouplist(3)`. That includes the user's **primary** group, which Active Directory stores in `primaryGroupID` and never lists in the group's `member` attribute — so a policy targeting `Domain Users`, or a group made primary for a class or department, works;
3.  **Subnet / network** — policy `assignments.subnets` / `networks`;
4.  **`accessPolicies.defaultPolicy`**.

Within a tier the highest `priority` wins. DoH-provider domains are appended to every policy's block list (bypass prevention), complementing the nftables IPv4 :53 DNAT and the `inet dns_bypass` drops (:853 DoT and IPv6 :53).

The device, host-group and directory-user tiers are anchored to each device's IPv4 DHCP reservation, so **only IPv4 queries can be attributed to a device**. IPv6-sourced queries could only ever match the catch-all `[::]/0` entry and fall back to the default policy, so IPv6 :53 is dropped outright rather than redirected — the router does not advertise an IPv6 resolver (`ipv6SendRAConfig.EmitDNS = false`), so clients use IPv4 regardless.

Policies are a filter, not an access control. A device is identified by its IPv4 address alone, and nothing on the LAN binds an address to the device that holds its reservation: a device that sets another's reserved address (or clones its MAC to get it over DHCP) gets that device's policy. The firewall's reverse-path check stops this across networks — a guest device cannot claim a LAN address — but not within one. Where that matters, pair a strict policy with switch-level controls such as port security or 802.1X.

## Block page & exception requests

With `accessPolicies.blockPage.enable`, policies whose `responseType` is `blockingAddress` answer blocked queries with the router's LAN IP; the Block Page app serves the branded page on :80/:443 (self-signed TLS — HTTPS sites show a certificate warning unless a root CA is deployed to managed devices). The page's "Request an exception" form posts to `router-logd`, which resolves the requesting device/user/group and queues the request; admins approve or deny from Cockpit → Access Policies → Exception requests. Approval appends the domain to a policy's `allowDomains` — a normal declarative settings change. NXDOMAIN-type policies intentionally show no page.

## Reporting

-   `router-logd` owns the DuckDB query-log database (DuckDB takes an exclusive lock on the file — all reads/writes go through its localhost HTTP API, which is why `router-report` queries that API rather than the database). DuckDB's columnar engine suits what is asked of the store: aggregates over a time range rather than point lookups. Entries are enriched with device/group/policy attribution at ingest. Retention: `router.reporting.retentionDays` (budget several GB for 90 busy days).
-   Scheduled reports (`router.reporting.schedules`) render a Typst PDF + CSV into `/var/lib/router-reports/` and are optionally emailed via the **Cloudflare Email Sending API** (`reporting.email.{accountId, apiTokenFile, fromAddress}`; the token needs _Email Routing: Edit_ on an Email Routing-enabled zone).

## Secrets layout

Secrets are always **file paths** in the settings JSON, never inline values. Recommended location: `/etc/router/secrets/` (root:root, 0600).

| File (example) | Used by |
| --- | --- |
| /etc/router/secrets/ldap-bind.pass | directory.sssd.bindPasswordFile |
| /etc/router/secrets/directory-ca.pem | directory.sssd.tlsCaCertFile |
| /etc/router/secrets/secure-ldap.key | directory.sssd.tlsClientKeyFile |
| /etc/router/secrets/cloudflare-email.token | reporting.email.apiTokenFile |
| /etc/router/secrets/cloudflare-ddns.token | ddns.cloudflare.apiTokenFile (see [port-forwards-ddns.md](port-forwards-ddns.md)) |

The bind password file holds the **bare password**. A pre-start unit (`router-sssd-env.service`) copies it into a 0600 env file that SSSD substitutes into its generated config, so the secret never enters the Nix store. Anonymous bind (empty `bindDn`) needs no secret at all.

Generated at runtime (do not edit): `/var/lib/router-technitium/{admin.pass, cockpit.pass, logd-ingest.token, logd-query.token}`, `/var/lib/cockpit-router/technitium-token`.

## Pointing the router at your directory

### Active Directory

1.  Create a **read-only service account** — an ordinary user account is enough; no delegation and no admin rights.
2.  Copy your enterprise CA certificate to the router and set `directory.sssd.tlsCaCertFile`. AD LDAPS certificates are normally issued by a CA that is not in the system trust store.
3.  Cockpit → Users → _Directory settings_:
    -   Provider **SSSD**, Domain `school.example.org`
    -   Server URIs `ldaps://dc1.school.example.org`, `ldaps://dc2.school.example.org`
    -   Search base `dc=school,dc=example,dc=org`, Schema **Active Directory**
    -   Bind DN `CN=router-sync,OU=Service Accounts,DC=school,DC=example,DC=org`
    -   Bind password file `/etc/router/secrets/ldap-bind.pass` (root:root, 0600)
    -   Publish groups: the groups your policies will target
4.  Apply, then verify on the router:
    
    ```
    systemctl status sssd
    sssctl config-check
    sssctl domain-status school.example.org
    getent passwd jdoe        # must succeed
    id -Gn jdoe               # must list the group your policy targets
    systemctl start router-directory-sync
    jq . /var/lib/router-directory/status.json
    ```
    
    `getent passwd` with **no** argument returning nothing is correct.
5.  Assign devices to users under Hosts, and directory groups to policies under Access policies.

A full domain _join_ (`realm join`, `id_provider = ad`, a Kerberos keytab) is not required and is deliberately not automated: a read-only LDAP bind is enough for identity lookups and carries far less operational surface. If you want the native AD provider anyway, `router.directory.sssd.extraDomainSettings` is merged last into the generated `[domain/<name>]` section — expect to also set `security.krb5.settings.includedir` and install `/etc/krb5.keytab` yourself.

### OpenLDAP / 389 Directory Server / FreeIPA

The same flow with Schema **RFC 2307bis** (or **RFC 2307** for `memberUid`\-style groups), and usually `idMapping = false` because the directory already carries `uidNumber`/`gidNumber`. FreeIPA sites may prefer `extraDomainSettings` with `id_provider = "ipa"`.

### Google Workspace

Google Workspace exposes **Secure LDAP**, included with Education Standard, Education Plus, Enterprise and Cloud Identity Premium (not with Education Fundamentals or Business Starter/Standard). In the Admin console create an LDAP client, download its certificate and key, then configure:

-   Server URIs `ldaps://ldap.google.com:636`, Schema **Active Directory**
-   Client certificate / key files — Secure LDAP authenticates the **client by certificate**, not by bind DN and password, so leave Bind DN empty
-   Search base as shown by the Admin console for your domain

If Secure LDAP is not on your plan, use host groups (`router.hostGroups`) for device-tier policies instead of directory groups — that path needs no directory at all.

### Microsoft Entra ID

Entra ID has **no LDAP endpoint**. To drive policy from it you need **Microsoft Entra Domain Services**, a separate paid managed-domain offering, and point the router at its LDAPS endpoint as an Active Directory domain. Note that Domain Services is a synchronised replica: group changes take time to appear. Sites with neither an on-prem DC nor Domain Services should use host groups instead.

### Letting directory users administer the router (optional, off by default)

Set `directory.sssd.adminGroup` to a group name. SSSD then runs its PAM responder with `access_provider = simple` and `simple_allow_groups = <group>`, and the router grants that group sudo and polkit admin, so its members can administer the router through Cockpit. Every other directory user is denied. SSH additionally requires `directory.sssd.adminSsh` (the router is otherwise key-only).

Left empty — the default — SSSD runs `services = nss` only. There is no PAM socket for `pam_sss.so` to talk to, the domain's `access_provider` is `deny`, and the module force-removes `pam_sss` from every PAM stack, so no directory user can authenticate to the router at all.

The admin group name must contain no whitespace and must not collide with a local group: `/etc/nsswitch.conf` is `group: files sss`, so a local group of the same name would win every lookup. Both are enforced by assertions.

## Upgrading from the Turso query-log store

`router-logd` used Turso (SQLite-format) and now uses DuckDB, whose storage is
its own format. The database path therefore changes from `querylogs.db` to
`querylogs.duckdb`, and **existing query-log history is not carried over**.

The path had to change rather than being reused. DuckDB will happily *open* a
SQLite file — it auto-attaches it — but then runs with SQLite storage semantics,
where `CREATE SEQUENCE` is rejected outright. An upgraded router would fail
schema setup while a fresh one succeeded, from the same code. A distinct path
keeps one storage mode and one schema everywhere.

Nothing needs to be done: the new database is created on first start, and the
logs are operational data on a retention window (`reporting.retentionDays`,
90 days by default), not records. Reclaim the old file when convenient:

```
rm -f /var/lib/router-logd/querylogs.db
```

## Troubleshooting

-   **Reconcile failed** — `journalctl -u technitium-reconcile`; it retries automatically. Manual run: `systemctl start technitium-reconcile`.
-   **Admin password reset** — stop the service, delete `/var/lib/technitium-dns-server/auth.config` and `/var/lib/router-technitium/admin.pass`, start, then run the reconcile (fresh password is generated and seeded).
-   **Dashboards empty** — check `/var/lib/cockpit-router/technitium-token` exists and `router-logd.service` is running (`curl http://127.0.0.1:8067/healthz`).
-   **Directory sync errors** — Cockpit → Users shows the last error and the list of unresolved names. Debug layer by layer: `systemctl status sssd` → `sssctl config-check` → `sssctl domain-status <domain>` → `getent passwd <name>` → `id -Gn <name>` → `journalctl -u router-directory-sync`. A name that is right in the directory but wrong here is usually a stale cache: `sss_cache -E` clears SSSD's and `systemctl restart nscd` clears the NSS cache. Policies keep working on last-good data; a missing or stale directory only disables the user tier.
-   **`getent passwd` returns nothing** — expected. See _Names are resolved on demand, never enumerated_.
-   **An override does not resolve** — check the zone exists and is a `Forwarder`: Cockpit → DNS shows what is configured, and Technitium's own Zones page shows what was created. A record inside a `forwardZones` zone never applies; the rebuild rejects that combination.
-   **A device has no DNS name** — only reservations are published. Check `router.hosts` has a `staticIp`, and look for a slug-collision warning from the last rebuild (two device names that reduce to the same DNS label are both skipped).
-   **Every name in a domain went NXDOMAIN** — a zone for it exists as `Primary` rather than `Forwarder`, which the router only leaves alone when it did not create it. Delete the hand-made zone in Technitium and re-run `systemctl start technitium-reconcile`.
-   **Block page not appearing** — only `blockingAddress` policies show it; check the Block Page app is bound (`journalctl -u technitium-dns-server | grep "Web server"`) and ports 80/443 are allowed from the client's network.
