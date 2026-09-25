# NixOS-powered Router Appliance

A NixOS module that turns a multi-NIC machine into a small business router, using Cockpit as the web UI for management.

**Documentation: https://avunu.github.io/nixos-router/**

## Features

-   WAN over DHCP with IPv6 prefix delegation, LAN and guest networks, and VLANs
-   nftables firewall with NAT and DNS hijacking
-   Port forwards to registered hosts over IPv4 and IPv6, plus optional UPnP
-   Hostname-based HTTP(S) routing: a Pingora reverse proxy with Let's Encrypt certificates, or a router-managed Cloudflare Tunnel
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

Always load the settings through `nixos-router.lib`. It upgrades settings written for older versions, so an upgrade never fails on them. See [The settings file](https://avunu.github.io/nixos-router/docs/start/settings-file/).

## Install

-   **Network install:** edit `local/flake.nix` and `local/router-settings.json`, then run `local/deploy.sh <fqdn> <ip>`. It installs over SSH with nixos-anywhere, and copies the flake, its lock and the settings file into the router's `/etc/nixos`.
-   **Installer image:** run `nix run` for the installer wizard, or `nix build .#installerIso`. The `configure`, `install` and `deploy` apps are also available individually. These come from [nixos-install-helper](https://github.com/Avunu/nixos-install-helper).

See [Install a router](https://avunu.github.io/nixos-router/docs/start/install/) for both paths, including what to change in the example settings first.

## Manage

-   **Web UI:** Cockpit at `https://<router>:9090`, reachable from the LAN, or over WireGuard at the router's LAN address. Edit settings there, then press **Apply**.
-   **Upgrade:** `system-upgrade` on the router. Upgrades also run nightly.

## Binary cache

Routers download their router-specific packages from [nixos-router.cachix.org](https://nixos-router.cachix.org) instead of compiling them. These are the Technitium DNS apps, `router-dns-tools`, the Cockpit plugin bundle and the NixOS system derivations. CI builds them from this repository's `flake.lock` and pushes whatever cache.nixos.org doesn't have. The `cache` job in `.github/workflows/checks.yml` does this on every push to `main` and nightly; pull requests build but never publish. The router module adds the substituter, and `flake.nix` declares it in `nixConfig` for deploys and development machines.

A router only hits the cache when its nixpkgs is the rev CI built, so the host flake takes nixpkgs from nixos-router rather than tracking nixos-unstable itself:

```nix
inputs = {
  nixos-router.url = "github:Avunu/nixos-router";
  nixpkgs.follows = "nixos-router/nixpkgs";
};
```

Routers installed before this change still have `nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable"` and `nixos-router.inputs.nixpkgs.follows = "nixpkgs"`. Change `/etc/nixos/flake.nix` to the block above once, then run `system-upgrade`.

CI publishes with the `CACHIX_AUTH_TOKEN` secret. Add it under Actions secrets only. The `cache` job publishes from `main` alone, never from a pull request, so the token must not go in the Dependabot secret store; `.github/workflows/checks.yml` explains why.

## Develop

```sh
nix develop                              # nixfmt, pre-commit hooks
nix build .#checks.x86_64-linux.<name>   # e.g. port-forwards-eval, settings-loader
nix flake check                          # everything, including the VM tests
```

The Cockpit plugin lives in `pkgs/cockpit-router`. Run `nix develop ../..#cockpit-router` inside it, then `npm run check`.

The documentation site lives in `site/`. Run `bun install`, then `bun run dev` for a live preview, and `bun run lint` before pushing a docs change.

## Docs

The guides are published at https://avunu.github.io/nixos-router/docs/. Their source is [docs/](docs/): Markdown, one file per page, with the sidebar in [docs/nav.json](docs/nav.json). The site itself is a [Jx](https://jxsuite.com) project in [site/](site/), and `.github/workflows/site.yml` deploys it from `main`.

-   [Install a router](https://avunu.github.io/nixos-router/docs/start/install/)
-   [Access policies](https://avunu.github.io/nixos-router/docs/access-policies/): DNS filtering, the block page, directory groups, reports
-   [Threat protection](https://avunu.github.io/nixos-router/docs/threat-protection/): Suricata IDS and IPS
-   [Dynamic DNS](https://avunu.github.io/nixos-router/docs/dynamic-dns/)
-   [Ingress](https://avunu.github.io/nixos-router/docs/ingress/): port forwards, reverse proxy, Cloudflare Tunnel
-   [WireGuard](https://avunu.github.io/nixos-router/docs/wireguard/), including [site-to-site VPN](https://avunu.github.io/nixos-router/docs/wireguard/site-to-site/)
-   [Settings format & migrations](https://avunu.github.io/nixos-router/docs/start/settings-file/)

Upstream reference material kept for development (disko-install, Cockpit packaging, systemd.networkd directives, NixOS option lists) lives in [reference/upstream/](reference/upstream/).
