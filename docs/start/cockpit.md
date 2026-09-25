---
title: The web UI
description: Sign in to Cockpit, find your way around the router pages, and save, apply or revert changes with the changes tray.
code:
  - modules/system.nix
  - modules/firewall.nix
  - local/flake.nix
  - pkgs/cockpit-router/src/manifest.json
  - pkgs/cockpit-router/src/app.tsx
  - pkgs/cockpit-router/src/settings.tsx
  - pkgs/cockpit-router/src/changes.tsx
  - pkgs/cockpit-router/src/nix.ts
  - pkgs/cockpit-router/src/schema.ts
  - pkgs/cockpit-router/src/settings-json.ts
  - pkgs/cockpit-router/src/network.tsx
---

# The web UI

You manage the router in Cockpit, a web-based admin console, extended with a set of router pages. This page covers signing in, what each page is for, and how a change goes from a form to the running router.

## Sign in

Open Cockpit at `https://<router>:9090` from a computer on the LAN. Any of these addresses works:

- the LAN gateway address, such as `https://192.168.1.1:9090`;
- `https://router.lan:9090`, that is `<hostName>.<lan.domain>`;
- `https://router.local:9090`, the router's mDNS name, from the LAN only.

Over WireGuard, use the LAN gateway address, or `router.lan` if the client resolves names through the router. That works when the client's tunnel sends the LAN subnet to the router. The router's own tunnel address, such as `10.100.0.1`, isn't an allowed name, so Cockpit refuses the login there. See [WireGuard](/docs/wireguard/) for setting up the tunnel.

Sign in with the admin account (`adminUser.name`, `admin` by default) and its password. After a fresh install, that is the initial password from the settings file; change it on Cockpit's **Accounts** page.

- **HTTPS only.** Cockpit uses a self-signed certificate, so your browser warns the first time. Plain `http://` requests are redirected to HTTPS, so the password never crosses the network in clear text.
- **LAN and WireGuard only.** The firewall accepts connections to port 9090 from the LAN bridge and WireGuard tunnels, and drops them from the guest network and the WAN.
- **Known names only.** Cockpit accepts only the LAN gateway address, `<hostName>.local` and `<hostName>.<lan.domain>`, not the router's WAN or WireGuard addresses. To reach it by another name, for example through a reverse proxy, add that origin to `router.cockpit.allowedOrigins` in the host flake.
- **Slow retries.** Each failed password costs a short delay, so the login can't be guessed at network speed.

:::doc-note
Saving and applying need administrative access. If Cockpit's top bar shows **Limited access**, click it and enter your password.
:::

## The router pages

The router adds these entries to Cockpit's menu, next to Cockpit's own pages such as **Accounts**, **Logs** and **Terminal**.

| Menu entry | What it's for |
| --- | --- |
| **Reports** | DNS query overview, the query log, and scheduled PDF reports. |
| **Access Policies** | DNS filtering policies, who they apply to, a preview, DNS settings, and exception requests from the block page. See [Access policies](/docs/access-policies/). |
| **Hosts** | The device registry and device groups. See [Hosts and host groups](/docs/network/hosts/). |
| **DNS** | Local DNS overrides, forward zones, and resolver settings. |
| **Users** | Directory users and groups (LDAP or Active Directory) and the directory connection. |
| **Network** | Interfaces, WAN, LAN, guest network, WireGuard, dynamic DNS and diagnostics. See [Networks and VLANs](/docs/network/). |
| **Ingress** | Port forwards, the reverse proxy and the Cloudflare Tunnel. See [Ingress](/docs/ingress/). |
| **Threat Protection** | The Suricata IPS: overview, events, rule policies, statistics and settings. See [Threat protection](/docs/threat-protection/). |
| **Firewall** | UPnP, and the active nftables rules. |
| **Wireless** | The UniFi and OpenWISP controllers. |
| **System** | Apply, check and update the system, roll back, and system settings. See [Upgrades and rollback](/docs/start/upgrades/). |

## Save and apply

Every settings form ends with two buttons:

- **Save** writes your edits to `/etc/nixos/router-settings.json` and shows "Saved. Apply to take effect." The running router doesn't change.
- **Save & apply** writes the file, then applies it straight away, as the changes tray's **Apply** does.

Both buttons save the form in front of you. On the **Network** and **Hosts** pages, that covers the edits on every tab of the page. On the other pages, each tab is a form of its own, and edits you haven't saved are lost when you switch tabs, so save first.

Use **Save** to stage several related edits, for example reassigning interfaces, and apply them together.

:::doc-warning
Saved changes don't wait for you forever. The nightly upgrade at `03:00` rebuilds from the settings file, so it applies anything you saved and left unapplied.
:::

## The changes tray

Whenever the saved settings file differs from what the router last applied, a yellow bar appears above every router page:

> **Unapplied changes: lan, hosts**

It lists the top-level settings that differ and offers two actions:

- **Apply** checks the saved file against the settings schema, then runs, as root:
  ```bash
  nixos-rebuild switch --flake /etc/nixos#<hostName> --impure
  ```
  The build log streams into the tray while "Applying configuration…" is shown, and **Cancel** stops it. It ends with "Configuration applied." or "Apply failed."; **Dismiss** hides the result. If the build fails, the running system stays as it was.
- **Revert** writes the last-applied settings back to the file and discards everything saved since.

The tray compares the settings file with a snapshot the UI writes after each successful apply, `/var/lib/cockpit-router/applied.json`. When the running system was built after the file's last change, for example by the nightly upgrade or a rebuild from the shell, the tray treats the file itself as applied.

## Validation

Changes are checked at three points:

1. **In the form.** Pages check what they can as you type. For example, the Hosts editor refuses a static IP outside the network's subnet, and the Network page disables **Save & apply** and lists the problems under "Network configuration is invalid".
2. **Before writing.** The whole settings file is validated against `router-settings.schema.json`, which is generated from the router's options. An invalid file is never written; the page shows "Could not save settings" with one line per problem, such as:
   ```text
   Configuration does not match the schema:
   /lan/prefixLength: must be integer
   ```
   **Apply** repeats this check on the file on disk, which catches hand edits.
3. **During the build.** Checks that span several settings, such as a port forward naming a host that doesn't exist, run in Nix. They fail the build with a message naming the problem, which appears in the tray's log, for example `router.hosts: duplicate MAC address(es): aa:bb:cc:dd:ee:01`.

## Fields locked in Nix

A setting in the host flake (`/etc/nixos/flake.nix` or `local.nix`) overrides the same setting in the file; see [The settings file](/docs/start/settings-file/#nix-overrides-the-file). The UI shows such a field disabled, and some pages add a banner, such as "Interface assignment is locked in the Nix configuration."

The UI finds locked fields by comparing the last-applied file with the values the running system actually uses, in `/etc/router/effective.json`. So a field shows as locked only once the file holds a value that Nix overrides. A locked field displays the file's value; the value in effect is the one in `/etc/router/effective.json`.

## Troubleshooting

- **The login page doesn't load.** Check that you are on the LAN or a WireGuard tunnel, not the guest network, and that you used `https://`.
- **Cockpit won't sign in or connect under one name but works under another.** The failing name isn't one of the allowed origins, for example the router's WireGuard tunnel address. Use the LAN address, or add the name to `router.cockpit.allowedOrigins` in the host flake.
- **Save fails with "Configuration does not match the schema".** The line after it names the setting and the problem. Fix that field; if the path points at a value you didn't touch, the file was edited by hand.
- **Apply fails.** Scroll the tray's log to the first `error:` line. An assertion message names the setting to fix. A build that fails changes nothing on the running system, so fix the setting, save and apply again, or use **Revert**.
