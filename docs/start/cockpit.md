---
title: The web UI
description: Sign in to Cockpit, find your way around the router pages, save and apply changes, and follow rebuilds.
code:
  - modules/system.nix
  - modules/cockpit-cert.nix
  - modules/firewall.nix
  - local/flake.nix
  - pkgs/cockpit-router/src/manifest.json
  - pkgs/cockpit-router/src/app.tsx
  - pkgs/cockpit-router/src/settings.tsx
  - pkgs/cockpit-router/src/changes.tsx
  - pkgs/cockpit-router/src/save-actions.tsx
  - pkgs/cockpit-router/src/router-state.ts
  - pkgs/cockpit-router/src/rebuild-job.ts
  - pkgs/cockpit-router/src/rebuild-status.ts
  - pkgs/cockpit-router/src/sections.ts
  - pkgs/cockpit-router/src/nix.ts
  - pkgs/cockpit-router/src/schema.ts
  - pkgs/cockpit-router/src/settings-json.ts
  - pkgs/cockpit-router/src/settings-read.ts
  - pkgs/cockpit-router/src/network.tsx
  - pkgs/cockpit-router/src/system.tsx
---

# The web UI

You manage the router in Cockpit, a web-based admin console, extended with a set of router pages. This page covers signing in, what each page is for, and how a change goes from a form to the running router.

## Sign in

Open Cockpit at `https://<router>:9090` from a computer on the LAN. Any of these addresses works:

- the LAN gateway address, such as `https://192.168.1.1:9090`;
- `https://router.lan:9090`, that is `<hostName>.<lan.domain>`;
- `https://router.local:9090`, the router's mDNS name, from the LAN only;
- the router's address on a WireGuard tunnel, such as `https://10.100.0.1:9090` or `https://[fd00:100::1]:9090`, over that tunnel;
- the router's domain name, such as `https://gw.example.com:9090`, once you set one. See [A trusted certificate](#a-trusted-certificate).

Over WireGuard, the LAN gateway address works too when the client's tunnel sends the LAN subnet to the router, and so does `router.lan` if the client also resolves names through the router. See [WireGuard](/docs/wireguard/) for setting up the tunnel.

Sign in with the admin account (`adminUser.name`, `admin` by default) and its password. After a fresh install, that is the initial password from the settings file; change it on Cockpit's **Accounts** page.

- **HTTPS only.** Cockpit uses a self-signed certificate, so your browser warns the first time, unless you give the router a [domain name](#a-trusted-certificate). Plain `http://` requests are redirected to HTTPS, so the password never crosses the network in clear text.
- **LAN and WireGuard only.** The firewall accepts connections to port 9090 from the LAN bridge and WireGuard tunnels, and drops them from the guest network and the WAN.
- **Known names only.** Cockpit accepts only the LAN gateway address, each WireGuard tunnel's address, `<hostName>.local`, `<hostName>.<lan.domain>` and the router's domain name, not the router's WAN address or any other public name. It compares them with the browser's address as written, ignoring only case, so an IPv6 tunnel address works only if **Address (CIDR)** holds it in the compressed form browsers use: `fd00:100::1/64`, not `fd00:0100:0:0::1/64`. To reach it by another name, for example through a reverse proxy, add that origin to `router.cockpit.allowedOrigins` in the host flake. Each entry is a glob, so escape an IPv6 address's brackets: `"https://\\[2001:db8::1\\]:9090"`.
- **Slow retries.** Each failed password costs a short delay, so the login can't be guessed at network speed.

:::doc-note
The router pages need administrative access. If Cockpit's top bar shows **Limited access**, click it and enter your password. Without it, saving and applying fail. If only root can read the settings file, as after a network install (`local/deploy.sh`), the pages can't even load it: each settings form is replaced by "Administrative access is needed to read and change the router settings.", and the **System** page offers no rebuilds. A rebuild that is already running still shows. Once you switch, the pages load the settings again on their own, with no need to reload the page.
:::

## A trusted certificate

Give the router a domain name and Cockpit serves a Let's Encrypt certificate for it, so the browser no longer warns.

1. Choose a name in a zone your Cloudflare account manages, such as `gw.example.com`. It needs no DNS record: the router answers it with its LAN address for LAN and WireGuard clients, and Let's Encrypt checks it through a TXT record the router creates with the Cloudflare API.
2. On **Ingress → Reverse proxy**, fill in the **Certificates** card: **Contact email**, the terms of service, and **Cloudflare API token file** with a token that has Zone → Zone → Read and Zone → DNS → Edit on that zone. See [Cloudflare API tokens](/docs/reference/cloudflare-tokens/).
3. On **System → Settings**, enter the name in **Domain name** and choose **Save and apply** from the **Save** menu.

When the certificate is issued, open `https://gw.example.com:9090`. Under **Domain name**, **Certificate** shows the certificate's state, and **Renew now** orders a new one.

- **Cockpit restarts to load a certificate.** It happens when the first certificate arrives and at each renewal, about every 60 days. The restart signs everyone out; a rebuild in progress carries on.
- **Until then, the self-signed certificate.** Cockpit keeps its own certificate until Let's Encrypt has issued one. If ordering fails, **Certificate** shows **last renewal failed**, and `journalctl -u acme-order-renew-cockpit.service` says why.
- **The name is public.** Every certificate is listed in public Certificate Transparency logs, so the name can be found there, even though nothing on the internet answers for it.
- **A name of its own.** The name can't also be a reverse proxy route, a Cloudflare Tunnel hostname or a host's public hostname: on the LAN it resolves to the router, not to them. A name only for this, such as `gw.example.com`, avoids that. Dynamic DNS may still publish it.
- **Names Let's Encrypt won't sign.** A name under `.lan`, `.local`, `.home.arpa` or another private suffix gets the warning "is not a public domain name, so Let's Encrypt can't issue a certificate for it".
- **Testing.** Turn on **Staging CA** in the **Certificates** card while you try it out: staging has far higher rate limits, but browsers don't trust its certificates.

## The router pages

The router adds these entries to Cockpit's menu, next to Cockpit's own pages such as **Accounts**, **Logs** and **Terminal**.

| Menu entry | What it's for |
| --- | --- |
| **Reports** | DNS query overview, the query log, and scheduled PDF reports. |
| **Access Policies** | DNS filtering policies, who they apply to, a preview, the block page, and exception requests from it. See [Access policies](/docs/access-policies/). |
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

Every page that edits settings has a **Save** button pinned below its content, with a menu on the arrow beside it:

- **Save** writes your edits to `/etc/nixos/router-settings.json`. The running router doesn't change. The button is available only while the page has unsaved edits.
- **Save and apply** saves, then applies every saved change straight away. When nothing on the page is unsaved, the item reads **Apply saved changes** instead.
- **Discard unsaved changes** puts the page back to the saved settings.
- **Review saved changes…** opens the changes panel on the **System** page.

A page's tabs share one set of edits: switching tabs keeps what you haven't saved, and **Save** saves all of it. While a page holds unsaved edits, its entry in Cockpit's menu shows an information icon, and closing or reloading the web console asks first. Beside the button, one line says how things stand, such as "Saved, not applied yet.", "Applying settings…" or "Applied".

Use **Save** to stage several related edits, even across pages, for example reassigning interfaces, and apply them together.

:::doc-warning
Saved changes don't wait for you forever. The nightly upgrade at `03:00` rebuilds from the settings file, so it applies anything you saved and left unapplied.
:::

## Unapplied changes and rebuilds

The **System** entry in Cockpit's menu shows the state of the whole router, whichever page you are on:

- a warning icon while saved changes aren't applied yet, with a tooltip naming them, such as "Saved changes not applied: Hosts, LAN";
- an information icon while a rebuild runs;
- an error icon when a rebuild failed, until someone dismisses it.

The **Changes** panel at the top of **System → Operations** has the details:

- **Saved changes.** Everything saved that the running system doesn't have yet, by section. Expand a section to see each changed setting, before and after; **Edit** opens the page and tab that edit it.
- **Apply changes** checks the saved file against the settings schema, then rebuilds with `router-rebuild apply`, which runs `nixos-rebuild switch --flake /etc/nixos#<hostName> --impure`.
- **Discard saved changes** puts back the settings the running system was built from, after asking. Everything saved since is lost. Unsaved edits open on other pages are kept.
- **The rebuild.** While one runs: what it is doing (evaluating, building with a count of what is left, activating), how long it has run, **View log**, and **Cancel** until the new configuration starts activating. Otherwise, how the last one ended.

Rebuilds run in the background, as the `router-rebuild` systemd service, whichever page, browser or shell started them. You can move to other pages, keep editing and saving, or close the browser: the rebuild carries on, and every page follows it. Only one runs at a time; the nightly upgrade waits for it, and it waits for the nightly upgrade. The build output never fills a page: **View log** opens the rebuild in Cockpit's **Logs** page, following new lines as they come.

When a rebuild fails, the running system stays as it was. The error stays on the **System** entry and in the panel, with **View log**, **Try again** and **Dismiss**, until someone dismisses it.

Each generation carries a copy of the settings it was built from, `/etc/router/applied-settings.json`, and the panel compares the settings file with it. So it stays right however the router was rebuilt: from the web UI, a shell, the nightly upgrade or a rollback. A router whose flake doesn't load its settings through `nixos-router.lib.settingsModule` has no such copy. The panel then says it can't list saved changes, and **Apply changes** stays available.

Every page follows the settings file as it changes, so a save on one page, in another browser or at a shell shows everywhere at once, and your unsaved edits are kept on top of it. A save built on settings that changed in the meantime is refused rather than overwriting them; the page tries once more on the new version, then asks you to review and save again.

## Validation

Changes are checked at three points:

1. **In the form.** Pages check what they can as you type. For example, the Hosts editor refuses a static IP outside the network's subnet, and the Network page disables **Save and apply** and lists the problems under "Network configuration is invalid".
2. **Before writing.** The whole settings file is validated against `router-settings.schema.json`, which is generated from the router's options. An invalid file is never written; the page shows "Could not save settings" with one line per problem, such as:
   ```text
   Configuration does not match the schema:
   /lan/prefixLength: must be integer
   ```
   Applying repeats this check on the file on disk, which catches hand edits.
3. **During the build.** Checks that span several settings, such as a port forward naming a host that doesn't exist, run in Nix. They fail the build with a message naming the problem, which appears in the rebuild's log, for example `router.hosts: duplicate MAC address(es): aa:bb:cc:dd:ee:01`.

## Fields locked in Nix

A setting made in Nix, in `/etc/nixos/flake.nix` or, on a router installed from the installer image, `/etc/nixos/local.nix`, overrides the same setting in the file; see [The settings file](/docs/start/settings-file/#nix-overrides-the-file). The UI shows such a field disabled, and some pages add a banner, such as "Interface assignment is locked in the Nix configuration."

The UI finds locked fields by comparing the settings the running system was built from, `/etc/router/applied-settings.json`, with the values it actually uses, in `/etc/router/effective.json`. So a field shows as locked only once an applied value is one that Nix overrides. A locked field displays the file's value; the value in effect is the one in `/etc/router/effective.json`.

## Troubleshooting

- **The login page doesn't load.** Check that you are on the LAN or a WireGuard tunnel, not the guest network, and that you used `https://`.
- **Cockpit won't sign in or connect under one name but works under another.** The failing name isn't one of the allowed origins, for example the router's public name. Use one of the addresses under [Sign in](#sign-in), or add the name to `router.cockpit.allowedOrigins` in the host flake.
- **A page says "Administrative access is needed to read and change the router settings."** The session has Limited access, and the page either can't read the settings file or tried to save it. Click **Limited access** in the top bar and enter your password. The page loads the settings again by itself. The UI never saves on top of settings it couldn't read, so nothing was lost.
- **Save fails with "Configuration does not match the schema".** The line after it names the setting and the problem. Fix that field; if the path points at a value you didn't touch, the file was edited by hand.
- **A rebuild fails.** Click **View log** in the changes panel and find the first `error:` line. An assertion message names the setting to fix. A build that fails changes nothing on the running system, so fix the setting and apply again, or use **Discard saved changes**.
- **Applying is greyed out with "A rebuild is already running" or "The nightly upgrade is running".** Only one rebuild runs at a time. Wait for it, or follow it with **View log**. From a shell, `journalctl -fu router-rebuild` follows a rebuild and `systemctl status router-rebuild` shows its state.
- **Save says the settings were changed elsewhere.** Someone saved the same file while you were saving, and the retry met another change. Your edits are still on the page, on top of the new settings; review them and save again.
