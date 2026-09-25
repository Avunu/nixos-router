---
title: The settings file
description: What /etc/nixos/router-settings.json holds, how Nix reads it, where secrets and the effective config live, and how old settings are upgraded.
code:
  - lib/settings.nix
  - local/flake.nix
  - modules/system.nix
  - pkgs/cockpit-router/src/nix.ts
  - pkgs/cockpit-router/src/settings-json.ts
  - pkgs/cockpit-router/src/ddns.ts
  - pkgs/cockpit-router/src/ingress-runtime.ts
  - pkgs/cockpit-router/src/ingress-widgets.tsx
  - pkgs/cockpit-router/src/network.tsx
  - pkgs/cockpit-router/src/router-settings.schema.json
  - tests/settings-loader.nix
---

# The settings file

Everything you configure in the web UI is stored in one JSON file, `/etc/nixos/router-settings.json`. This page explains its layout, how the router's build reads it, how secrets stay out of it, and what happens to it when nixos-router changes an option's format.

## Layout

The file is a single JSON object. Each top-level key is one of the router module's `router.*` options, written without the `router.` prefix:

| Key | What it holds | Guide |
| --- | --- | --- |
| `hostName`, `timeZone` | The router's name and time zone. | **System → Settings** |
| `adminUser` | The admin account: `name`, `sshKeys`, `initialPassword`. | [Install a router](/docs/start/install/) |
| `stateVersion`, `diskDevice`, `bootMode` | Install-time values. Don't change them on a running router. | [Install a router](/docs/start/install/) |
| `wan`, `lan`, `guest`, `trunkInterfaces` | Networks, interfaces and VLANs. | [Networks and VLANs](/docs/network/) |
| `wireguard` | WireGuard tunnels, keyed by interface name. | [WireGuard](/docs/wireguard/) |
| `hosts`, `hostGroups` | The device registry and device groups. | [Hosts and host groups](/docs/network/hosts/) |
| `dns` | Technitium DNS, local overrides and forward zones. | **DNS** page |
| `accessPolicies`, `directory`, `reporting` | Filtering policies, the directory connection, reports. | [Access policies](/docs/access-policies/) |
| `suricata` | The IPS. | [Threat protection](/docs/threat-protection/) |
| `upnp`, `portForwards` | UPnP and static port forwards. | [Port forwards](/docs/ingress/port-forwards/) |
| `ddns` | Cloudflare dynamic DNS. | [Dynamic DNS](/docs/dynamic-dns/) |
| `acme`, `reverseProxy`, `cloudflareTunnel` | Certificates, the reverse proxy, the Cloudflare Tunnel. | [Ingress](/docs/ingress/) |
| `wireless` | The UniFi and OpenWISP controllers. | **Wireless** page |

A key you leave out takes the option's default. Unknown keys are rejected: the web UI refuses to save a file with a key the schema doesn't know, and the build fails on an option that doesn't exist.

Cockpit writes the file with two-space indentation. You can edit it by hand as root; the changes tray then lists what you changed, and **Apply** checks the file against the schema before it builds.

## How the build reads it

The host flake loads the file with `nixos-router.lib.settingsModule`:

```nix
modules = [
  nixos-router.nixosModules.router
  (nixos-router.lib.settingsModule ./router-settings.json)
];
```

The loader parses the JSON, upgrades anything written in an older format (see [Automatic migrations](#automatic-migrations)), and hands the values to the router module as the `router.*` options.

## Nix overrides the file

The loader applies every value from the file as a default, with `lib.mkDefault`. So a value set in Nix wins over the file. Where that Nix goes depends on how the router was installed:

- **Network install** (`local/deploy.sh`): the inline module in `/etc/nixos/flake.nix` that sets `router.cockpit`. This flake doesn't import a `local.nix`, so a file by that name has no effect.
- **Installer image:** `/etc/nixos/local.nix`. The generated `flake.nix` imports it when it exists, and has no inline module of its own.

For example, to lock the WAN port, add this line inside that module's attribute set:

```nix
router.wan.interface = "enp1s0";
```

Then apply from Cockpit, or rebuild from a shell:

```bash
sudo nixos-rebuild switch --flake /etc/nixos#default --impure
```

The web UI then shows that field as locked; see [The web UI](/docs/start/cockpit/#fields-locked-in-nix). Use this for settings that must not change from the UI.

Some settings exist only in Nix and never appear in the file:

- **Cockpit itself:** `router.cockpit.enable`, `port`, `allowedOrigins` and the other `router.cockpit.*` options.
- **Packages:** `router.extraPackages`, and anything else that takes a Nix package rather than a string.
- **Everything outside `router.*`:** any other NixOS option, set in the same place.

## Secrets

The settings file, like every value that goes into a NixOS build, ends up readable by any local user in the Nix store. So it never holds a secret itself. It holds the **path** to a root-owned file that does:

| Setting | Default file | Written by |
| --- | --- | --- |
| `ddns.cloudflare.apiTokenFile` | `/etc/router/secrets/cloudflare-ddns.token` | **Set token…** on **Network → Dynamic DNS** |
| `acme.cloudflare.apiTokenFile` | `/etc/router/secrets/cloudflare-acme.token` | **Set token…** on **Ingress → Reverse proxy** |
| `cloudflareTunnel.apiTokenFile` | `/etc/router/secrets/cloudflare-tunnel.token` | **Set token…** on **Ingress → Tunnel** |
| `wireguard.<name>.privateKeyFile` | `/etc/wireguard/<name>.key` | **Generate keypair** on **Network → WireGuard** |
| `reporting.email.apiTokenFile` | none | You, as root |
| `directory.sssd.bindPasswordFile` | none | You, as root |

**Set token…** opens a form, "Set Cloudflare API token". The token you paste travels to the router over standard input, never on a command line, and is written to the path with mode 0600 in a directory with mode 0700. Only the path is saved in the settings file.

For the files you create yourself, keep the same convention. This is what **Set token…** runs, with the token on standard input:

```bash
sudo sh -c 'umask 077 && install -d -m 700 /etc/router/secrets && cat > /etc/router/secrets/cloudflare-email.token'
```

Paste the token, press Enter, then Ctrl+D. Then enter the path in the matching field.

`adminUser.initialPassword` is the one exception: it sits in the file in plain text. It only matters when the account is first created, so change the password after installing and clear the field. See the [first-boot checklist](/docs/start/install/#first-boot-checklist).

## The effective config

After each build, a router with Cockpit enabled writes `/etc/router/effective.json` (mode 0600). It holds every setting the running system actually uses: the file's values, the option defaults, and anything Nix overrode. The web UI reads it to fill in defaults and to spot locked fields. To see what the router is running, read it rather than the settings file:

```bash
sudo jq .lan /etc/router/effective.json
```

The UI also keeps its own record of the last settings it applied, `/var/lib/cockpit-router/applied.json`, which drives the changes tray.

## Automatic migrations

Sometimes a new version of nixos-router changes the shape of an option. For example, port forwards used to name an IPv4 `destination` and now name a registered `host`. Routers keep working through such a change because the loader upgrades old settings on the way in:

- **The rebuild succeeds.** The settings are upgraded in memory while the configuration is evaluated, and the router behaves as it did before.
- **The file is rewritten.** If anything was upgraded, activation rewrites `router-settings.json` in the current format, keeping its owner and mode. The old contents are saved beside it as `router-settings.json.pre-migration`. From then on, Cockpit only sees the current format.
- **Your edits are safe.** The rewrite only happens if the file is still exactly what the build read. A file edited in the meantime is left alone, and it is upgraded on the next rebuild instead.
- **Ambiguous entries stop the build.** If an old entry can't be upgraded without guessing, the build stops with a message saying what to fix, and the running system is left untouched.

For example, an old port forward to an address that no registered host reserves stops the build with:

```text
router-settings.json: port forward 'Synology DSM' targets 10.48.4.2, but no
host reserves that address, and forwards now point at a registered host.
Register the device with staticIp 10.48.4.2 (Cockpit → Hosts, or an entry
in "hosts" with its MAC address), then rebuild.
```

Register the device on the **Hosts** page with that static IP, then apply again.

| Introduced | What changes |
| --- | --- |
| 2026-09 | Port forwards: `destination` becomes `host` (the device reserving that address), `source` becomes `sources`, and `family` is set to `ipv4`. |

Maintainers add migrations as described in [Settings migrations](/docs/develop/settings-migrations/).

### Routers installed before the loader

Routers deployed before the loader existed read the JSON directly, so an upgrade that changes an option's shape fails on them with an error like:

```text
The option router.portForwards."[definition 1-entry 1]".destination does not exist
```

Nothing is switched, so the running system is unaffected. Fix `/etc/nixos/flake.nix` once:

1. Find the line that loads the settings. It is either `{ router = nixpkgs.lib.mkDefault settings; }` or, on a router installed from an older installer image, `{ router = load "router"; }`.
2. Replace it with `(nixos-router.lib.settingsModule ./router-settings.json)`.
3. A remaining `settings = builtins.fromJSON (…);` line only names the configuration after `hostName`, which never changes shape, so it can stay.
4. Rebuild:
   ```bash
   sudo nixos-rebuild switch --flake /etc/nixos#router --impure
   ```
   Use your router's `hostName` in place of `router`. Don't rely on `system-upgrade` here: it skips the rebuild when the lock file is unchanged, and the failed upgrade has usually updated it already.
