---
title: Upgrades and rollback
description: How the router upgrades itself every night, how to upgrade or roll back by hand, how long old generations are kept, and how to recover from the boot menu.
code:
  - modules/system.nix
  - local/flake.nix
  - pkgs/cockpit-router/src/system.tsx
  - pkgs/cockpit-router/src/changes.tsx
  - pkgs/cockpit-router/src/nix.ts
---

# Upgrades and rollback

Every build of the router is a NixOS generation: a complete, self-contained system. Upgrading builds a new one and switches to it, and rolling back switches to an older one. This page covers the nightly upgrade, upgrading and rolling back by hand, and recovering a router you can no longer reach.

## Nightly upgrades

Every day at `03:00`, in the router's time zone, the router upgrades itself:

1. `flake-update.service` runs `nix flake update` on the host flake in `/etc/nixos`. With the standard host flake, that moves nixos-router, and nixpkgs with it, to the latest commit on nixos-router's `main` branch.
2. `nixos-upgrade.service` builds `/etc/nixos#<hostName>` and makes it the next boot entry.
3. If the new generation has a different kernel, initrd or kernel modules, the router reboots into it one minute later. Otherwise it switches to it in place, without a reboot.

If the router was off at `03:00`, the upgrade runs as soon as it's back on.

Commits reach `main` only after CI has built them and booted test routers from them; see [Development](/docs/develop/#continuous-integration). CI also pushes each commit on `main` to the binary cache, so a router downloads its packages instead of compiling them.

:::doc-warning
The nightly upgrade rebuilds from the settings file as it is on disk. Anything you saved in Cockpit but didn't apply is applied at `03:00`.
:::

To follow an upgrade, or find out why one failed:

```bash
journalctl -u flake-update.service -u nixos-upgrade.service
```

The schedule and the reboot are NixOS defaults set by the router module, so you can override them in the host flake, next to the Cockpit settings:

```nix
{
  system.autoUpgrade.dates = "Sun 04:00";
  system.autoUpgrade.allowReboot = false;
  # system.autoUpgrade.enable = false;   # no automatic upgrades at all
}
```

## Upgrade now

From Cockpit, open **System → Operations** and press **Update system**. From a shell, run:

```bash
system-upgrade
```

Both run the same script. It asks for your password through `sudo` if you aren't root, then:

1. stops any rebuild or upgrade that is stuck from an earlier run;
2. runs `nix flake update` on `/etc/nixos`;
3. if the lock file didn't change, stops with `:: Flake lock unchanged, skipping rebuild`;
4. otherwise runs `nixos-rebuild switch --flake /etc/nixos#<hostName> --impure`.

It never reboots, even for a new kernel; the new kernel runs after the next reboot. To target another flake or configuration, pass them as arguments: `system-upgrade /etc/nixos default`.

:::doc-note
`system-upgrade` only rebuilds when there is an update. To apply saved settings, use **Apply** in the changes tray or **Apply configuration**, and do that before you press **Update system**: once **Update system** succeeds, the changes tray clears, even if it skipped the rebuild and your saved settings are still unapplied.
:::

## The Operations tab

**System → Operations** has three cards.

**Configuration** holds the operations. Each one streams its log into a card below, and **Cancel** stops it.

| Button | What it runs | Use it to |
| --- | --- | --- |
| **Apply configuration** | `nixos-rebuild switch --flake /etc/nixos#<hostName> --impure`, after checking the settings file against the schema | Apply the saved settings, like the changes tray's **Apply**. |
| **Check flake** | `nixos-rebuild dry-build --flake /etc/nixos#<hostName> --impure` | Evaluate the configuration and list what would be built, without switching. It catches Nix errors before you apply. |
| **Update system** | `system-upgrade` | Fetch updates and rebuild, as described above. |

**Generations** lists every generation still on disk, newest first, with its **Date**, **NixOS version** and **Kernel**; the running one is marked **current**. **Roll back to previous** switches to the generation before the current one.

## Roll back

**Roll back to previous** runs `nixos-rebuild switch --rollback`. From a shell, the same is:

```bash
sudo nixos-rebuild switch --rollback
```

The switch is immediate and needs no reboot, unless you want the older kernel too.

:::doc-warning
Rolling back changes the running system, not `/etc/nixos`. The settings file and the lock file still hold the change that caused the problem, and the next apply or the nightly upgrade builds it again. Fix or undo the setting, then apply, before `03:00`.
:::

## Recover from the boot menu

If a change leaves the router unreachable, for example a wrong LAN address or interface assignment, you can still boot an older generation from the console:

1. Connect a keyboard and a display to the router, and reboot it.
2. The boot menu appears for 5 seconds. On UEFI routers it is systemd-boot, which lists up to the 10 newest generations; on legacy BIOS routers it is GRUB.
3. Pick the generation from before the change. The entries show the generation number and build date.
4. Once the router is up and you can reach Cockpit again, fix the setting and apply.

A generation picked in the boot menu runs until the next reboot, when the newest one boots again. To keep the older one as the default until you have fixed the settings, run this on the router:

```bash
sudo /run/current-system/bin/switch-to-configuration boot
```

## How long generations are kept

Once a week, the router deletes generations older than 30 days and collects the store paths nothing uses anymore. The current generation is always kept. So every generation from the last 30 days stays available to roll back to, although the boot menu of a UEFI router shows only the 10 newest.

## Troubleshooting

- **The nightly upgrade failed.** Read `journalctl -u nixos-upgrade.service` for the first `error:` line. The router keeps running the previous generation. Fix the cause, then run **Update system**, or **Apply configuration** if `system-upgrade` reports that the lock is unchanged.
- **Apply fails after you changed the host name.** The configuration is named after `hostName`, and Cockpit still builds the old name until the rename has been applied once, as the warning under **Host name** says. Apply the rename once from a shell with the `default` alias:
  ```bash
  sudo nixos-rebuild switch --flake /etc/nixos#default --impure
  ```
- **An upgrade fails with `The option router.portForwards."[definition 1-entry 1]".destination does not exist`.** The host flake reads the settings without the loader. See [Routers installed before the loader](/docs/start/settings-file/#routers-installed-before-the-loader).
- **"Could not list generations" on the Operations tab.** The card runs `nixos-rebuild list-generations --json`; the message below it is that command's error. Try the same command in a shell.
