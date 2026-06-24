# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  NixOS Router — Declarative Home/Office Router Configuration               ║
# ║                                                                            ║
# ║  A single-flake NixOS module that turns a multi-NIC machine into a fully   ║
# ║  featured router with:                                                     ║
# ║    • systemd-networkd managed WAN (DHCP) + LAN/Guest bridges w/ DHCPServer ║
# ║    • nftables stateful firewall with NAT, DNS hijacking, DoT blocking      ║
# ║    • AdGuard Home DNS filtering + SafeSearch on :53 (direct to clients)    ║
# ║    • Avahi mDNS for hostname resolution (router.local)                     ║
# ║    • WireGuard VPN tunnels with full LAN ↔ WAN ↔ WG routing                ║
# ║    • Optional Suricata IPS inline via NFQUEUE                              ║
# ║    • Optional Cockpit web UI for administration                            ║
# ║    • Disko-based declarative disk partitioning (UEFI or legacy)            ║
# ║                                                                            ║
# ║  Usage:                                                                    ║
# ║    Import `nixosModules.router` and set the `router.*` options in your     ║
# ║    host configuration. See the MODULE OPTIONS section for all settings.    ║
# ║                                                                            ║
# ║  Architecture:                                                             ║
# ║    DNS flow: clients → AdGuard Home (:53) → DoH upstream                  ║
# ║    mDNS: clients → Avahi (multicast) for .local resolution                ║
# ║    Traffic:  LAN/Guest/WG → nftables (→ Suricata NFQUEUE) → NAT → WAN     ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
{
  description = "NixOS Router";

  # ── Flake Inputs ────────────────────────────────────────────────────────────
  # nixpkgs:   NixOS unstable channel — provides all packages and the NixOS
  #            module system. Unstable is used for the latest kernel, networkd,
  #            and security patches.
  # git-hooks: Pre-commit hook runner (nixfmt formatting, flake check).
  # disko:     Declarative disk partitioning — generates partition layouts from
  #            Nix expressions, supporting both UEFI (GPT+ESP) and legacy
  #            (GPT+BIOS boot) modes.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      ...
    }:
    let
      lib = nixpkgs.lib;
      forAllSystems = lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
    in
    {
      # ── Pre-commit checks ────────────────────────────────────────────────────
      # nixfmt:        auto-formats .nix files on commit
      # flake-checker: runs `nix flake check` to catch evaluation errors
      checks = forAllSystems (system: {
        # NixOS VM test: boots the router with Suricata and checks the IPS
        # integration end-to-end. Build/run with:
        #   nix build .#checks.<system>.suricata-vm
        suricata-vm = import ./tests/suricata.nix {
          pkgs = nixpkgs.legacyPackages.${system};
          routerModule = self.nixosModules.router;
          baseSettings = builtins.fromJSON (builtins.readFile ./local/router-settings.json);
        };

        pre-commit = inputs.git-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            nixfmt = {
              enable = true;
              package = nixpkgs.legacyPackages.${system}.nixfmt;
            };
            # flake-checker = {
            #   enable = true;
            #   name = "nix flake check";
            #   entry = "nix flake check --no-pure-eval --extra-experimental-features nix-command --extra-experimental-features flakes --impure";
            #   pass_filenames = false;
            #   stages = [ "pre-commit" ];
            #   extraPackages = with nixpkgs.legacyPackages.${system}; [
            #     nix
            #   ];
            # };
          };
        };
      });

      # ── Developer Shell ──────────────────────────────────────────────────────
      # Installs the pre-commit hooks and provides nixfmt on PATH.
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              nixd
              nixfmt
            ];
            inherit (self.checks.${system}.pre-commit) shellHook;
          };
        }
      );

      # ── Packages ─────────────────────────────────────────────────────────────
      # The in-repo Cockpit plugin (router views), exposed for standalone
      # `nix build .#cockpit-router` and tests. The router module builds the
      # same derivation via callPackage and installs it through
      # services.cockpit.plugins.
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          cockpit-router = pkgs.callPackage ./pkg/cockpit-router/package.nix { };
        }
      );

      # ── Installer scripts ────────────────────────────────────────────────────
      # The ISO workflow is two repo-relative scripts run directly from a checkout
      # (they read/write local/flake.nix beside themselves, so they are not
      # packaged as `nix run` targets):
      #   ./local/generate-config.sh   — interactively writes local/flake.nix
      #   ./local/build-iso.sh         — builds the installer ISO from it

      # ════════════════════════════════════════════════════════════════════════
      #  ROUTER MODULE
      #
      #  The core of the flake: declares all `router.*` options and maps them to
      #  NixOS config (systemd-networkd, nftables, AdGuard Home, WireGuard,
      #  Suricata, Cockpit, etc.). It is composed from focused sub-modules under
      #  ./modules, each aligned with a Cockpit UI domain:
      #    • topology.nix          — shared derived values (interface names,
      #                              CIDRs, the VLAN/port model) exposed to the
      #                              others via the internal `router._internal`.
      #    • network.nix           — systemd-networkd interfaces/bridges/VLAN/WG.
      #    • threat-protection.nix — Suricata IPS.
      #    • access-protection.nix — AdGuard Home DNS filtering + Avahi.
      #    • firewall.nix          — nftables ruleset, NAT, port-forwards, UPnP.
      #    • system.nix            — boot/disko, kernel, packages, hardening,
      #                              Cockpit, maintenance, effective.json.
      # ════════════════════════════════════════════════════════════════════════
      nixosModules.router = {
        imports = [
          inputs.disko.nixosModules.disko
          ./modules/topology.nix
          ./modules/network.nix
          ./modules/threat-protection.nix
          ./modules/access-protection.nix
          ./modules/firewall.nix
          ./modules/system.nix
        ];
      };
    };

}
