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
    nixos-install-helper = {
      url = "github:Avunu/nixos-install-helper";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.disko.follows = "disko";
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

      # Installer surface (nixos-install-helper). The router settings round-trip
      # through the existing FLAT local/router-settings.json — the same file the
      # Cockpit UI reads/writes — and its derived schema feeds the Cockpit build.
      ih = inputs.nixos-install-helper.lib.mkProject {
        inherit nixpkgs self;
        system = "x86_64-linux";
        installModules = [
          self.nixosModules.router
          # Package-typed / Nix-only bits the JSON schema deliberately drops.
          { router.cockpit.enable = true; }
        ];
        optionRoots = [ "router" ];
        flakeStyle = "local";
        upstream = "github:Avunu/nixos-router";
        settingsFiles.router = ./local/router-settings.json;
        # cockpit.* is Nix-locked (Cockpit-managed), never in the JSON/UI schema.
        schemaExclude = [ "cockpit" ];
        # A router's full topology can't be picked offline on a generic image;
        # deploy via the unattended ISO (per-host) or nixos-anywhere.
        guided = false;
        hints = {
          diskDevice = "disk-device";
          "wan.interface" = "net-iface";
        };
      };
    in
    {
      # ── Pre-commit checks ────────────────────────────────────────────────────
      # nixfmt:        auto-formats .nix files on commit
      # flake-checker: runs `nix flake check` to catch evaluation errors
      checks = forAllSystems (
        system:
        {
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
            };
          };
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
          # Single-source guard: the committed Cockpit schema must equal the
          # schema derived from the router.* options. Regenerate on drift:
          #   nix build .#packages.x86_64-linux.settingsSchema-router \
          #     && jq -S . result > pkg/cockpit-router/src/router-settings.schema.json
          router-schema-fresh =
            nixpkgs.legacyPackages.${system}.runCommand "router-schema-fresh"
              { nativeBuildInputs = [ nixpkgs.legacyPackages.${system}.jq ]; }
              ''
                if diff <(jq -S . ${ih.packages.x86_64-linux."settingsSchema-router"}) \
                        <(jq -S . ${./pkg/cockpit-router/src/router-settings.schema.json}); then
                  touch "$out"
                else
                  echo "router-settings.schema.json is stale vs router.* options — regenerate it." >&2
                  exit 1
                fi
              '';
        }
      );

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
        # Merge the installer artifacts on x86_64: settingsSchema-router,
        # installerIso, guidedIso, settingsSchema. (cockpit-router above wins.)
        // lib.optionalAttrs (system == "x86_64-linux") ih.packages.x86_64-linux
      );

      # install / installTemplate systems + configure/install/deploy/wizard apps.
      nixosConfigurations = ih.nixosConfigurations;
      apps = ih.apps;

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
