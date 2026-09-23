# NixOS-powered Router Appliance

A NixOS module that turns a multi-NIC machine into a small business router, using Cockpit as the web UI for management.

## Features

-   WAN over DHCP with IPv6 prefix delegation, LAN and guest networks, and VLANs
-   nftables firewall with NAT and DNS hijacking
-   Port forwards to registered hosts over IPv4 and IPv6, plus optional UPnP
-   Technitium DNS with per-group filtering policies
-   Cloudflare dynamic DNS
-   WireGuard VPN
-   Suricata IPS, optional
-   UniFi or OpenWISP wireless controllers, optional
-   A Cockpit web UI for all of the above

## How it works

A router is a small host flake in `/etc/nixos`, plus a `router-settings.json` file that holds the router's configuration. Cockpit edits that file, and a rebuild applies it. `local/flake.nix` is the host flake template:

```nix
router = nixpkgs.lib.nixosSystem {
  modules = [
    nixos-router.nixosModules.router
    (nixos-router.lib.settingsModule ./router-settings.json)
  ];
};
# Named after the hostName in router-settings.json, plus a `default` alias.
nixosConfigurations = {
  ${router.config.networking.hostName} = router;
  default = router;
};
```

Always load the settings through `nixos-router.lib`. It upgrades settings written for older versions, so an upgrade never fails on them. See [docs/settings-migrations.md](docs/settings-migrations.md).

## Install

-   **Network install:** edit `local/flake.nix` and `local/router-settings.json`, then run `local/deploy.sh <fqdn> <ip>`. It installs over SSH with nixos-anywhere, and copies the flake, its lock and the settings file into the router's `/etc/nixos`.
-   **Installer ISO or guided setup:** run `nix run` for the installer wizard. The `configure`, `install` and `deploy` apps are also available individually. These come from [nixos-install-helper](https://github.com/Avunu/nixos-install-helper).

## Manage

-   **Web UI:** Cockpit at `https://<router>:9090`, reachable from the LAN or WireGuard. Edit settings there, then press **Apply**.
-   **Upgrade:** `system-upgrade` on the router. Upgrades also run nightly.

## Develop

```sh
nix develop                              # nixfmt, pre-commit hooks
nix build .#checks.x86_64-linux.<name>   # e.g. port-forwards-eval, settings-loader
nix flake check                          # everything, including the VM tests
```

The Cockpit plugin lives in `pkgs/cockpit-router`. Run `nix develop ../..#cockpit-router` inside it, then `npm run check`.

## Docs

-   [Access protection (DNS filtering, policies, reports)](docs/access-protection.md)
-   [Port forwards & dynamic DNS](docs/port-forwards-ddns.md)
-   [Settings format & migrations](docs/settings-migrations.md)
-   [disko-install reference](docs/disko-install.md)
