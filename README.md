# NixOS-powered Router Appliance

A NixOS module that turns a multi-NIC machine into a small business router, using Cockpit as the web UI for management.

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

Always load the settings through `nixos-router.lib`. It upgrades settings written for older versions, so an upgrade never fails on them. See [docs/settings-migrations.md](docs/settings-migrations.md).

## Install

-   **Network install:** edit `local/flake.nix` and `local/router-settings.json`, then run `local/deploy.sh <fqdn> <ip>`. It installs over SSH with nixos-anywhere, and copies the flake, its lock and the settings file into the router's `/etc/nixos`.
-   **Installer ISO or guided setup:** run `nix run` for the installer wizard. The `configure`, `install` and `deploy` apps are also available individually. These come from [nixos-install-helper](https://github.com/Avunu/nixos-install-helper).

## Manage

-   **Web UI:** Cockpit at `https://<router>:9090`, reachable from the LAN or WireGuard. Edit settings there, then press **Apply**.
-   **Upgrade:** `system-upgrade` on the router. Upgrades also run nightly.

## Binary cache

Routers download their router-specific packages from [nixos-router.cachix.org](https://nixos-router.cachix.org) instead of compiling them. These are the Technitium DNS apps, `router-dns-tools`, the Cockpit plugin bundle and the NixOS system derivations. CI builds them from this repository's `flake.lock` and pushes whatever cache.nixos.org doesn't have. The `cache` job in `.github/workflows/checks.yml` does this on every pull request, every push to `main`, and nightly. The router module adds the substituter, and `flake.nix` declares it in `nixConfig` for deploys and development machines.

A router only hits the cache when its nixpkgs is the rev CI built, so the host flake takes nixpkgs from nixos-router rather than tracking nixos-unstable itself:

```nix
inputs = {
  nixos-router.url = "github:Avunu/nixos-router";
  nixpkgs.follows = "nixos-router/nixpkgs";
};
```

Routers installed before this change still have `nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable"` and `nixos-router.inputs.nixpkgs.follows = "nixpkgs"`. Change `/etc/nixos/flake.nix` to the block above once, then run `system-upgrade`.

CI publishes with the `CACHIX_AUTH_TOKEN` secret. Add it under **both** Actions secrets and Dependabot secrets, because Dependabot pull requests only see the latter.

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
-   [Reverse proxy & Cloudflare Tunnel](docs/reverse-proxy-tunnels.md)
-   [Settings format & migrations](docs/settings-migrations.md)
-   [disko-install reference](docs/disko-install.md)
