---
title: Directory groups
description: Connect the router to LDAP or Active Directory through SSSD so access policies follow users' directory groups, without a rebuild when membership changes.
code:
  - modules/directory-sync.nix
  - modules/hosts.nix
  - modules/dns-technitium.nix
  - pkgs/router-dns-tools/router_dns_tools/directory_sync/__init__.py
  - pkgs/router-dns-tools/router_dns_tools/directory_sync/sssd.py
  - pkgs/router-dns-tools/router_dns_tools/compile_policies.py
  - pkgs/cockpit-router/src/users.tsx
  - pkgs/cockpit-router/src/directory.ts
  - pkgs/cockpit-router/src/hosts.tsx
  - pkgs/cockpit-router/src/access-policies.tsx
---

# Directory groups

Directory groups let a policy follow people instead of devices. You connect the router to your LDAP or Active Directory domain, assign each device to its user on the Hosts page, and target directory groups such as `Students` or `Staff` from a policy. When someone joins or leaves a group in the directory, their devices change policy at the next sync, without a rebuild.

## How it works

1. **A device belongs to a user.** On the Hosts page, a device with a **Static IP** has its **User** field set to a directory login name, such as `jdoe`.
2. **The router looks the user up.** `router-directory-sync` asks the operating system for the user and their groups, the same lookup `id jdoe` does on the router. SSSD answers from your directory and handles the connection, TLS, credentials and caching. The group list includes the user's primary group, which Active Directory never lists among a group's members. A policy targeting `Domain Users`, or a group made primary for a class or department, therefore works.
3. **The result is saved.** The sync writes the users and groups it resolved to `/var/lib/router-directory/directory.json`, and its status to `status.json` in the same directory.
4. **Policies are recompiled without a rebuild.** A path unit watches `directory.json`. When it changes, `router-policy-push.service` recompiles the policies and pushes them to the DNS server. The device's reserved address now maps to the policy of the user's highest-priority targeted group. See [Assign policies](/docs/access-policies/assignments/#tier-2-directory-group).

The sync runs two minutes after boot, then every **Sync interval (minutes)** (60 by default, between 5 and 1440). It also runs when you apply a configuration change, and when you click **Sync now** on the Users page. SSSD caches each entry for 90 minutes by default, so a group change in the directory can take up to the cache time plus the sync interval to reach the router.

Directory identity is used for policy assignment only. No directory user can log in to the router unless you set an [admin group](#let-directory-users-log-in).

## Names are looked up on demand

The router never downloads the whole directory. SSSD runs with enumeration off, because listing every user and group is slow and discouraged at any real scale. The sync looks up only the names your configuration mentions:

| Reference | Set in |
| --- | --- |
| Each device's user | **Hosts** → device → **User** |
| Each policy's directory groups | **Access Policies** → policy → **Directory groups** |
| Extra groups to publish | **Users → Directory settings** → **Publish groups** |

What that means in practice:

- **The Users page lists only referenced users.** An empty page on a new router is normal.
- **Name fields are free text with autocomplete.** The **User** field on the Hosts page and the **Directory groups** field in the policy editor suggest only names the router has already resolved. Type the login or group name exactly as the directory spells it; `id <name>` on the router is the reference. The **Directory groups** help text puts it this way: "Type the group name exactly as the directory spells it — names are resolved on demand, so a group you have not used before will not autocomplete."
- **Publish groups seeds the suggestions.** Add the groups you plan to target under **Publish groups**, apply, and they appear in the policy editor before any policy uses them.
- **A name that doesn't resolve is a warning, not a failure.** The Users page shows "Some referenced names could not be resolved" with the names, and a policy's unresolved group shows as an orange chip. Everyone else keeps their policy.
- **Only a total failure stops the sync.** If devices reference users and none of them resolves, the sync reports "Directory sync failed", usually because SSSD or the directory is unreachable. It keeps the last good `directory.json`, so users keep their policies. Directory data older than seven days is still used, with a note in the log.
- **`getent passwd` with no name returns no directory users.** That's expected. Look up a specific name instead.

## Before you start

- **A read-only service account.** An ordinary user account is enough; it needs no delegation or admin rights. Google Workspace Secure LDAP uses a client certificate instead.
- **The CA certificate** that issued your directory servers' LDAPS certificates, if it isn't a public CA. Active Directory's usually is an internal enterprise CA.
- **SSH access to the router** to store the secrets. Secrets are always file paths in the settings, never the values themselves.
- **Devices registered with a static IP.** See [Hosts and host groups](/docs/network/hosts/).

## Store the secrets

Keep secret files in `/etc/router/secrets/`, owned by root with mode 0600:

| File (example) | Setting | Cockpit field |
| --- | --- | --- |
| `/etc/router/secrets/ldap-bind.pass` | `directory.sssd.bindPasswordFile` | **Bind password file** |
| `/etc/router/secrets/directory-ca.pem` | `directory.sssd.tlsCaCertFile` | **CA certificate file** |
| `/etc/router/secrets/secure-ldap.crt` | `directory.sssd.tlsClientCertFile` | **Client certificate file** |
| `/etc/router/secrets/secure-ldap.key` | `directory.sssd.tlsClientKeyFile` | **Client key file** |

Create the directory and the bind password file on the router. The second command waits for the password: type it, press Enter, then Ctrl+D. It isn't saved in your shell history.

```bash
sudo install -d -m 0700 -o root -g root /etc/router/secrets
sudo sh -c 'umask 077; cat > /etc/router/secrets/ldap-bind.pass'
```

The file holds only the password; a trailing newline is removed. Before SSSD starts, `router-sssd-env.service` copies it into an environment file with mode 0600, and SSSD substitutes it into its generated configuration, so the password never enters the Nix store. That copy is made on every SSSD start, so after you change the password file, run `sudo systemctl restart sssd`. An anonymous bind, with **Bind DN** empty, needs no password file.

## Connect a directory

1. Open **Users → Directory settings**.
2. Under **Identity provider**, set **Provider** to **SSSD (LDAP / Active Directory)** and choose a **Sync interval (minutes)**.
3. Under **Domain**, fill in:
   - **Domain name:** your directory domain, such as `school.example.org`.
   - **Server URIs:** one entry per server, tried in order, such as `ldaps://dc1.school.example.org`. Prefer `ldaps://`.
   - **Search base:** such as `dc=school,dc=example,dc=org`.
   - **Schema:** **Active Directory**, **RFC 2307bis** or **RFC 2307**. See [Directory types](#directory-types).
   - **Publish groups:** the groups your policies will target, such as `Students` and `Staff`.
4. Under **Credentials**, fill in:
   - **Bind DN:** the service account, such as `CN=router-sync,OU=Service Accounts,DC=school,DC=example,DC=org`. Leave it empty to bind anonymously.
   - **Bind password file:** such as `/etc/router/secrets/ldap-bind.pass`.
   - **CA certificate file:** the PEM bundle that validates the servers' certificates.
   - **Client certificate file** and **Client key file:** only for mutual TLS, such as Google Workspace Secure LDAP.
5. Leave **Admin group** under **Router login** empty unless you want directory users to administer the router. See [Let directory users log in](#let-directory-users-log-in).
6. Click **Save & apply**.
7. Verify on the router, replacing `jdoe` with a real login:

   ```bash
   systemctl status sssd
   sudo sssctl config-check
   sudo sssctl domain-status school.example.org
   getent passwd jdoe
   id -Gn jdoe
   sudo systemctl start router-directory-sync
   sudo cat /var/lib/router-directory/status.json
   ```

   `getent passwd jdoe` must print the user, and `id -Gn jdoe` must list the groups your policies target. `status.json` should show `"ok": true` and an empty `unresolved` list.

8. Assign devices to users: on **Hosts**, edit each device, give it a **Static IP**, and type the login name in **User**. The field's help text reads "The directory login name, exactly as `id <name>` resolves it on the router."
9. Target groups from policies: in the policy editor, type each group under **Directory groups**. See [Assign policies](/docs/access-policies/assignments/).

### Plain LDAP and StartTLS

The **Server URIs** help text says "Prefer ldaps:// — plain ldap:// negotiates StartTLS." StartTLS is used only when `directory.sssd.startTls` is `true` in the settings file, and Cockpit has no switch for it. With an `ldap://` server and `startTls` left off, the bind password and every lookup cross the network in clear text, and the build warns about it. Use `ldaps://`, or set `startTls` to `true`.

### In the settings file

```json
{
  "directory": {
    "provider": "sssd",
    "syncIntervalMinutes": 60,
    "sssd": {
      "domain": "school.example.org",
      "servers": ["ldaps://dc1.school.example.org", "ldaps://dc2.school.example.org"],
      "baseDn": "dc=school,dc=example,dc=org",
      "schema": "ad",
      "bindDn": "CN=router-sync,OU=Service Accounts,DC=school,DC=example,DC=org",
      "bindPasswordFile": "/etc/router/secrets/ldap-bind.pass",
      "tlsCaCertFile": "/etc/router/secrets/directory-ca.pem",
      "groups": ["Students", "Staff"]
    }
  }
}
```

These options exist only in the settings file:

| Key | Default | Purpose |
| --- | --- | --- |
| `directory.sssd.userSearchBase` | `""` (the search base) | A narrower base for user lookups |
| `directory.sssd.groupSearchBase` | `""` (the search base) | A narrower base for group lookups |
| `directory.sssd.idMapping` | `true` | Derive user and group ids from the directory's SIDs; set `false` when the directory has `uidNumber` and `gidNumber` |
| `directory.sssd.startTls` | `false` | Use StartTLS on `ldap://` servers |
| `directory.sssd.tlsReqCert` | `"demand"` | Server certificate checking: `never`, `allow`, `try`, `demand` or `hard` |
| `directory.sssd.cacheTimeoutMinutes` | `90` | How long SSSD serves a cached entry |
| `directory.sssd.adminSsh` | `false` | Also let the admin group in over SSH |

## Directory types

### Active Directory

Use the steps above with **Schema** set to **Active Directory**. Point **CA certificate file** at your enterprise CA, since AD's LDAPS certificates are rarely issued by a public CA. A read-only LDAP bind is enough for these lookups, so the router doesn't join the domain.

If you want a real domain join anyway, the NixOS option `router.directory.sssd.extraDomainSettings` is merged last into the generated SSSD domain section, for example with `id_provider = "ad"`. It isn't a settings-file key, so set it in the router's Nix configuration. You then also need to provide the Kerberos configuration and `/etc/krb5.keytab` yourself. Values in it must not contain a `$` character; the build rejects them.

### OpenLDAP, 389 Directory Server and FreeIPA

Use **RFC 2307bis**, or **RFC 2307** for directories whose groups list members with `memberUid`. These directories usually carry `uidNumber` and `gidNumber`, so set `directory.sssd.idMapping` to `false` in the settings file. FreeIPA sites may prefer `id_provider = "ipa"` through `extraDomainSettings` in the Nix configuration.

### Google Workspace Secure LDAP

Google Workspace offers Secure LDAP on some editions; check yours in the Admin console. Create an LDAP client there, download its certificate and key, and copy them to `/etc/router/secrets/`. Then set:

- **Server URIs:** `ldaps://ldap.google.com:636`
- **Client certificate file** and **Client key file:** the downloaded files. Secure LDAP authenticates the client by certificate, so leave **Bind DN** and **Bind password file** empty.
- **Search base:** the base the Admin console shows for your domain.
- **Schema:** Google's own SSSD instructions use **RFC 2307bis**. The **Schema** help text in Cockpit says **Active Directory** also covers Secure LDAP. Verify with `getent passwd` and `id -Gn` either way.

### Microsoft Entra ID

Entra ID has no LDAP endpoint. To drive policies from it, you need Microsoft Entra Domain Services, a separate paid managed domain, with secure LDAP turned on. Point the router at its LDAPS endpoint as an Active Directory domain. Domain Services is a synchronized copy, so group changes in Entra ID take a while to appear there.

### No directory

If you have neither an on-premises directory nor a service with LDAP, use [host groups](/docs/network/hosts/) instead. They target sets of devices and need no directory.

## The Users page

The **Users** page shows the result of the last sync. The header shows the provider, the last sync time and the **Sync now** button, plus any sync error or unresolved names.

- **Users** tab: one row per resolved user, with **Name**, **Login**, **Groups**, **Devices** and **Effective policy**. When the directory spells a login differently from the reference you typed, the row shows an "alias" label with your spelling. Expand a row to see the user's devices, each with its **Static IP**, **Group** and **Effective policy**.
- **Groups** tab: each resolved group, with **Members** (among resolved users) and **Targeted by policies**.
- **Directory settings** tab: the connection settings described above.

## Let directory users log in

By default, directory users can't log in to the router at all. SSSD runs without its login service, the domain denies access, and the router removes SSSD from every login stack.

To let one group administer the router through Cockpit, set **Admin group** on **Users → Directory settings**. Cockpit warns "Directory users can log in to this router": members of that group get full sudo, and every other directory user is still denied. SSH also requires `directory.sssd.adminSsh` in the settings file, which turns on password-style (keyboard-interactive) SSH login for that group only. The router is otherwise SSH-key-only.

Group membership then decides who is root, so anyone who can impersonate your directory server can make themselves an admin. The build therefore requires TLS with a checked certificate before it accepts an admin group:

```text
router.directory.sssd.adminGroup grants directory members sudo and
Cockpit access, so the directory connection must be TLS with a
checked certificate: use ldaps:// servers (or set startTls = true)
and keep tlsReqCert at "demand" or "hard".
```

The admin group name can't contain whitespace, and it can't be the name of a local group on the router, because local groups are looked up first. The build enforces both.

## Build errors and warnings

| Message | Fix |
| --- | --- |
| `router.directory.sssd.domain must be set when provider = "sssd".` | Fill in **Domain name**. |
| `router.directory.sssd.servers must list at least one LDAP URI.` | Add a server under **Server URIs**. |
| `router.directory.sssd.servers entries must be ldap:// or ldaps:// URIs.` | Start each server with `ldap://` or `ldaps://`. |
| `router.directory.sssd.bindDn is set but bindPasswordFile is null.` | Set **Bind password file**, or clear **Bind DN** for an anonymous bind. |
| `router.directory.sssd.bindPasswordFile is set but bindDn is empty (anonymous bind takes no password).` | Set **Bind DN**, or clear **Bind password file**. |
| `router.directory.sssd: tlsClientCertFile and tlsClientKeyFile must be set together.` | Set both client files, or neither. |
| `router.directory.sssd: the generated sssd.conf contains a literal '$' ...` | Remove the `$` from the value it names. |
| Warning: `router.directory.sssd: the directory connection is not TLS with a checked certificate ...` | Use `ldaps://` or `startTls`, and keep `tlsReqCert` at `demand`. |

If the bind password file is missing or empty, SSSD doesn't start, and `journalctl -u router-sssd-env` shows `router-directory: /etc/router/secrets/ldap-bind.pass is missing or empty`.

## Troubleshooting

Work down the layers until one fails:

```bash
systemctl status sssd
sudo sssctl config-check
sudo sssctl domain-status school.example.org
getent passwd jdoe
id -Gn jdoe
journalctl -u router-directory-sync -n 50
```

- **"Directory sync failed".** No referenced user resolved. Check that SSSD is running and online with the commands above, and that the servers are reachable from the router. The last good data stays in use.
- **"Some referenced names could not be resolved".** A device's **User** or a policy's directory group doesn't match the directory. Fix the spelling under **Hosts** or in the policy. Use `getent passwd <name>` or `getent group <name>` to test a spelling.
- **A user or group is right in the directory but wrong on the router.** The entry is cached. Run `sudo sss_cache -E` to clear SSSD's cache and `sudo systemctl restart nscd` to clear the system's name cache, then click **Sync now**.
- **A user's devices don't get the group's policy.** Check on **Access Policies → Preview** with **Directory user**. The device needs a **Static IP**, and a host group policy beats a directory group policy. See [Assign policies](/docs/access-policies/assignments/).
- **The Users page is empty.** Normal until a device or policy references a directory name. See [Names are looked up on demand](#names-are-looked-up-on-demand).
