---
title: Install a router
description: Install nixos-router over SSH with local/deploy.sh or from an installer USB stick, set up the host flake, and finish the first-boot checklist.
code:
  - local/deploy.sh
  - local/flake.nix
  - local/router-settings.json
  - local/install-settings.json
  - flake.nix
  - lib/settings.nix
  - modules/system.nix
  - modules/network.nix
---

# Install a router

There are two ways to put nixos-router on a machine: a network install over SSH with `local/deploy.sh`, or an installer image that you boot from a USB stick. Both erase the target disk, install the router and leave a host flake in `/etc/nixos` that the router rebuilds itself from.

## Before you start

- **A workstation** running Linux on x86_64, with Nix and flakes enabled. The router's system is built there.
- **A checkout of the repository:**
  ```bash
  git clone https://github.com/Avunu/nixos-router.git
  cd nixos-router
  ```
- **The router's interface names**, such as `enp1s0`. Boot the target from any Linux live image and run `ip -br link` to list them, and note which port is the WAN.
- **An SSH key** for the admin account. The router only accepts key logins over SSH.

## Choose a path

| Path | Use it when | What you run |
| --- | --- | --- |
| Network install | The target can boot a Linux live image and you can reach it over SSH as root. | `local/deploy.sh` |
| Installer USB stick | You want to install offline, or hand a prepared stick to someone on site. | `nix run`, or `nix build .#installerIso` |

## Prepare the settings

Both paths read a settings file: `local/router-settings.json` for the network install and `local/install-settings.json` for the installer image. The copies in the repository are examples from a real site, down to the SSH keys. **Replace the SSH keys with your own**, or those keys get admin access to your router. The examples also turn on Suricata and a guest network on VLAN 20 across the LAN ports; change `suricata` and `guest` if you don't want those.

At a minimum, set these keys:

```json
{
  "hostName": "router",
  "timeZone": "America/Chicago",
  "stateVersion": "26.11",
  "diskDevice": "/dev/sda",
  "bootMode": "uefi",
  "adminUser": {
    "name": "admin",
    "sshKeys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyReplaceMe admin@laptop"],
    "initialPassword": "correct-horse-battery-staple"
  },
  "wan": { "interface": "enp1s0", "vlan": null },
  "lan": {
    "interfaces": ["enp2s0", "enp3s0"],
    "address": "192.168.1.1",
    "networkAddress": "192.168.1.0",
    "prefixLength": 24,
    "domain": "lan",
    "dhcp": { "poolOffset": 100, "poolSize": 150, "leaseTime": "24h" }
  }
}
```

- **`diskDevice`** is the disk that gets erased. Double-check it.
- **`bootMode`** is `uefi` (systemd-boot) or `legacy` (GRUB), to match the machine's firmware.
- **`stateVersion`** is the NixOS release you install with. Set it once and never change it.
- **`adminUser.initialPassword`** is what Cockpit and `sudo` take until you change it. Without one, the admin account has no password: SSH keys still sign you in, but you can neither sign in to Cockpit nor use `sudo`.

Everything else, such as the guest network, VLANs and filtering, can wait until the router runs. [The settings file](/docs/start/settings-file/) describes every top-level key, and [Networks and VLANs](/docs/network/) covers the network keys.

## Network install

`local/deploy.sh` installs the host flake in `local/` onto the target with [nixos-anywhere](https://github.com/nix-community/nixos-anywhere).

1. Boot the target from a Linux live image that runs an SSH server, such as the NixOS minimal installer, and make sure you can sign in as root, for example `ssh root@192.168.1.50`.
2. Edit `local/router-settings.json`. If you want to lock any setting in Nix, edit `local/flake.nix` too; see [The host flake](#the-host-flake).
3. Run the script with the router's future name and the target's current address:
   ```bash
   local/deploy.sh router.lan 192.168.1.50
   ```
4. The first time, Nix asks whether to allow the flake's `extra-substituters` setting, the `nixos-router.cachix.org` binary cache. Answer yes. If your user isn't a trusted user of the Nix daemon, the daemon ignores the setting with a warning, and the workstation compiles the router's packages itself, which works but takes much longer.

The script then:

- **Checks the files.** It stops if `local/flake.nix` or `local/router-settings.json` is missing.
- **Checks the name.** The configuration it installs is named after `hostName` in the settings file. It warns if the first label of the name you passed differs; the name argument is otherwise only used in its messages.
- **Refuses a placeholder password.** An empty `adminUser.initialPassword`, or one of `admin`, `admin123`, `password` or `changeme`, stops the install with:
  ```text
  error: set adminUser.initialPassword in <dir>/router-settings.json to a password of its own
         (change it after the first login, then clear it from the settings)
  ```
- **Stages `/etc/nixos`** with `flake.nix`, `flake.lock` and `router-settings.json`. The settings file is installed readable by root only, because it holds the initial password.
- **Runs nixos-anywhere 1.13.0** against `root@<ip>`. It partitions `diskDevice`, installs the system and reboots the target.

When it finishes, the script prints the SSH command for the admin account and the Cockpit address.

:::doc-tip
The router starts on exactly the inputs in `local/flake.lock`. To start on the newest nixos-router instead, run `nix flake update --flake ./local` before you deploy. The router updates itself every night anyway.
:::

## Installer USB stick

The installer comes from [nixos-install-helper](https://github.com/Avunu/nixos-install-helper). Run it from the root of your checkout:

```bash
nix run
```

The wizard first collects settings, then asks how to deploy:

- **Settings.** The first time, it walks through a questionnaire generated from the router's options and writes the answers to `installer/router-settings.json`. Later runs ask whether to reconfigure. You can also run this step alone with `nix run .#configure`.
- **Unattended ISO.** It builds `installerIso` with the settings from `installer/`, then offers to write it to a USB stick. `nix run .#install` offers the same choice without the settings step; with no settings in `installer/`, it uses `local/install-settings.json`.
- **Network install.** It runs nixos-anywhere against a target you name. The same step runs alone as `nix run .#deploy -- root@<ip>`.

The guided ISO, a generic image that asks for its settings on the box, is turned off: a router cannot be installed without knowing its WAN and LAN ports.

:::doc-warning
Use `local/deploy.sh` for network installs, not the wizard's **Network install** or the `deploy` app. Those install the system but leave `/etc/nixos` empty, so the router has no host flake to rebuild from: Cockpit cannot apply changes and the nightly upgrade fails.
:::

You can also build the image without the wizard. It then uses `local/install-settings.json`:

```bash
nix build .#installerIso
```

The finished image is under `result/iso/`. When the target boots from it:

1. The installer shows the target disk, which is `diskDevice` from the settings, and starts after a 10-second countdown. Press Ctrl+C to abort.
2. If the disk already holds an installed system, the installer waits 10 seconds for you to press Enter to wipe it. If you don't, it leaves the disk alone and stops; remove the stick and reboot to start the existing system.
3. It installs offline, since everything it needs is on the image, and reboots.

The installed router's `/etc/nixos` holds a generated `flake.nix`, a `local.nix` for your own additions, and `router-settings.json`. The generated flake imports `local.nix`, so that file is where this router's Nix settings go.

### Turn Cockpit on after an installer-image install

The generated host flake does not turn Cockpit on. The system the image installs has Cockpit, but the first rebuild from `/etc/nixos` removes it, and the nightly upgrade at `03:00` is such a rebuild. Before then, sign in over SSH and add one line to `/etc/nixos/local.nix`, inside its attribute set:

```nix
{ config, lib, pkgs, inputs, ... }:
{
  router.cockpit.enable = true;

  environment.systemPackages = with pkgs; [ ];
}
```

Then rebuild:

```bash
sudo nixos-rebuild switch --flake /etc/nixos#default --impure
```

## The host flake

`local/flake.nix` is the template for the `/etc/nixos/flake.nix` of a router installed over the network. It is short:

- **Inputs:** `nixos-router` (`github:Avunu/nixos-router`), and `nixpkgs`, which follows nixos-router's own nixpkgs.
- **Modules:** the router module; the settings file, loaded through `nixos-router.lib.settingsModule`; and a module of locked settings, which turns Cockpit on and sets its port and allowed origins. Your own Nix settings go in that module too. This flake doesn't import a `local.nix`.
- **Outputs:** one NixOS configuration, named after the `hostName` in the settings file, plus a `default` alias. The nightly upgrade, `system-upgrade` and Cockpit's apply all build `/etc/nixos#<hostName>`.

The settings part looks like this:

```nix
modules = [
  nixos-router.nixosModules.router
  (nixos-router.lib.settingsModule ./router-settings.json)
  {
    router.cockpit = {
      enable = true;
      port = 9090;
    };
    # router.wan.interface = "enp0s20f0";   # example: lock the WAN NIC
  }
];
```

Always load the settings through `nixos-router.lib.settingsModule`, not `builtins.fromJSON`. The loader upgrades settings written for an older version of nixos-router, so an upgrade never fails on an old option shape. See [The settings file](/docs/start/settings-file/#automatic-migrations).

### Why nixpkgs follows nixos-router

nixos-router's CI builds the router-specific packages and pushes them to the binary cache at [nixos-router.cachix.org](https://nixos-router.cachix.org): the Technitium DNS apps, `router-dns-tools`, the Cockpit plugin bundle and the NixOS system derivations. A router downloads them only when its nixpkgs is the exact revision CI built. So the host flake takes nixpkgs from nixos-router's lock instead of tracking `nixos-unstable` itself:

```nix
inputs = {
  nixos-router.url = "github:Avunu/nixos-router";
  nixpkgs.follows = "nixos-router/nixpkgs";
};
```

This also keeps the Technitium DNS apps in step with the DNS server that loads them. The router module adds the cache on the router itself, and `local/flake.nix` declares it in `nixConfig` for the build on your workstation.

Routers installed before this change have `nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable"` and `nixos-router.inputs.nixpkgs.follows = "nixpkgs"` instead. Change `/etc/nixos/flake.nix` to the block above once, then run `system-upgrade`.

## First-boot checklist

1. **Connect to the LAN.** Plug a computer into a LAN port. It gets an address from the DHCP pool, such as `192.168.1.100`.
2. **Open Cockpit** at `https://192.168.1.1:9090`, your `lan.address`, or at `https://router.lan:9090` (`<hostName>.<lan.domain>`). The certificate is self-signed, so your browser warns once; accept it.
3. **Sign in** as `admin` with the initial password. See [The web UI](/docs/start/cockpit/).
4. **Change the password** on Cockpit's **Accounts** page, or with `passwd` over SSH. It is also your `sudo` password.
5. **Clear the initial password.** On **System → Settings**, empty **Initial password**, then press **Save & apply**. The initial password only matters when the account is created, and until you clear it, it sits readable in the settings file and the Nix store.
6. **Check the WAN.** On **Network → Diagnostics**, pick **ping** as the **Tool**, enter `1.1.1.1` as the **Target** and press **Run**. Then try **dig** with `example.com`.
7. **Check the changes tray.** Above every router page, a yellow **Unapplied changes** bar means the settings file differs from the running system. After a fresh install there should be none.
8. **Register your devices** on the **Hosts** page, and give servers a static IP. Most features build on that; see [Hosts and host groups](/docs/network/hosts/).

## Troubleshooting

- **The script stops with `error: set adminUser.initialPassword ...`.** The settings file has no initial password, or a well-known one. Set a password of your own and run the script again.
- **The script stops with `error: <dir>/flake.nix is missing`.** Run it from a full checkout; it looks for `flake.nix` and `router-settings.json` beside itself.
- **You can sign in over SSH but `sudo` asks for a password you never set.** The settings had no `adminUser.initialPassword`, so the account has no password. Reinstall with one.
- **Cockpit is gone the morning after an installer-image install.** The generated host flake does not enable it. Add `router.cockpit.enable = true;` to `/etc/nixos/local.nix`, as described in [Turn Cockpit on after an installer-image install](#turn-cockpit-on-after-an-installer-image-install).
- **The build fails with `router: at least one physical interface must be assigned (no port exists to carry traffic).`** The settings assign no port to any network. Set `wan.interface` and `lan.interfaces`.
