# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  NixOS Router — Declarative Home/Office Router Configuration               ║
# ║                                                                            ║
# ║  A single-flake NixOS module that turns a multi-NIC machine into a fully   ║
# ║  featured router with:                                                     ║
# ║    • systemd-networkd managed WAN (DHCP) + LAN/Guest bridges w/ DHCPServer ║
# ║    • nftables stateful firewall with NAT, DNS hijacking, DoT blocking      ║
# ║    • Technitium DNS filtering + per-group access policies on :53           ║
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
# ║    DNS flow: clients → Technitium DNS (:53) → DoH upstream                ║
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
  # turso:     Source-only input for Turso's Python bindings (pyturso), built by
  #            pkg/pyturso. Tracked via flake.lock instead of a pinned hash.
  # technitium-dns: Source-only input for the Technitium DNS Apps (Advanced
  #            Blocking, Log Exporter, Block Page), compiled from source by
  #            pkg/technitium-apps. Its ref MUST equal the version of nixpkgs'
  #            technitium-dns-server so the app DLLs stay ABI-compatible with the
  #            running server — bump both together, and let
  #            `nix run .#update-deps` verify the match rather than trusting a
  #            version number written out here (this comment already went stale
  #            once, across 15.2.0 → 15.4.0).
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
    turso = {
      url = "github:tursodatabase/turso";
      flake = false;
    };
    technitium-dns = {
      url = "github:TechnitiumSoftware/DnsServer/v15.4.0";
      flake = false;
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
        # No generic guided ISO. The guided image bakes the router modules
        # evaluated with NO settings, but a router with no settings is not a
        # router: network.nix asserts that a WAN uplink, a LAN port and at least
        # one physical interface are assigned, and those are the last things that
        # can be guessed generically. The guided installer could not fill them in
        # either — it prompts for `guidedPrompts` paths, which are string-typed
        # only, and `lan.interfaces` is a list. Every router is delivered per-site
        # from a settings JSON via the unattended ISO (local/build-iso.sh) or the
        # network deploy, both of which remain.
        guided = false;
        # Per-root FLAT settings for the per-host install systems: the file holds
        # router.* values at top level and the helper applies it as
        # `{ router = mkDefault <flat> }` — the same shape as the runtime
        # /etc/nixos/router-settings.json the Cockpit UI edits.
        settingsFiles.router = ./local/install-settings.json;
        hints = {
          diskDevice = "disk-device";
          "wan.interface" = "net-iface";
        };
      };

      # The Cockpit UI validates the FLAT router-settings.json, so flatten the
      # install-helper's per-root schema ({ properties.router = {...} }) down to
      # the router subtree. cockpit.* is Nix-locked (Cockpit-managed) and never
      # part of the JSON/UI surface, so its options are marked visible = false
      # in modules/system.nix and drop out of the derived schema.
      flatRouterSchema =
        (ih.settingsSchema.properties.router or {
          type = "object";
          additionalProperties = false;
          properties = { };
        }
        )
        // {
          "$schema" = "http://json-schema.org/draft-07/schema#";
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

          # NixOS VM test: Technitium access-protection stack end-to-end
          # (policies, static leases, logd pipeline, block page, reports).
          #   nix build .#checks.<system>.technitium-vm
          technitium-vm = import ./tests/technitium.nix {
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
                if diff <(jq -S . ${self.packages.${system}.settingsSchema-router}) \
                        <(jq -S . ${./pkg/cockpit-router/src/router-settings.schema.json}); then
                  touch "$out"
                else
                  echo "router-settings.schema.json is stale vs router.* options — regenerate it." >&2
                  exit 1
                fi
              '';
        }
      );

      # ── Overlay ──────────────────────────────────────────────────────────────
      # Adds the router's from-source packages to nixpkgs, closing over the flake
      # inputs for their sources (so they are tracked in flake.lock, not pinned by
      # hardcoded hashes). The router NixOS module applies this overlay, so the
      # sub-modules can build them via `pkgs.router-dns-tools` etc.
      overlays.router = final: _prev: {
        pyturso = final.python3Packages.callPackage ./pkg/pyturso/package.nix {
          src = inputs.turso;
        };
        technitium-dns-apps = final.callPackage ./pkg/technitium-apps/package.nix {
          technitiumSrc = inputs.technitium-dns;
        };
        router-dns-tools = final.callPackage ./pkg/router-dns-tools/package.nix {
          inherit (final) pyturso;
          technitiumApps = final.technitium-dns-apps;
        };
      };

      # ── Developer Shell ──────────────────────────────────────────────────────
      # Installs the pre-commit hooks, nixfmt, and the `update-deps` helper.
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          # `update-deps` — refresh the external dependency pins in one command:
          #   1. update all flake inputs (nixpkgs, turso, technitium-dns, …);
          #   2. report whether the pinned technitium-dns input still matches the
          #      Technitium DNS Server version in the (now updated) nixpkgs — the
          #      app DLLs must stay ABI-compatible with that server, so on a
          #      mismatch the user bumps the input ref by hand;
          #   3. regenerate pkg/technitium-apps/nuget-deps.json for the current
          #      technitium-dns source.
          update-deps = pkgs.writeShellApplication {
            name = "update-deps";
            runtimeInputs = with pkgs; [
              git
              jq
            ];
            text = ''
              root=$(git rev-parse --show-toplevel)
              cd "$root" || exit 1

              echo "==> Updating flake inputs (nix flake update)..."
              nix flake update

              echo
              echo "==> Technitium DNS Server version check"
              nixpkgsVer=$(nix eval --raw --impure --expr \
                '(builtins.getFlake "'"$root"'").inputs.nixpkgs.legacyPackages.${system}.technitium-dns-server.version')
              appsRef=$(jq -r '.nodes."technitium-dns".original.ref // "unknown"' flake.lock)
              echo "    nixpkgs technitium-dns-server: $nixpkgsVer"
              echo "    technitium-dns input ref:      $appsRef"
              if [ "$appsRef" != "v$nixpkgsVer" ]; then
                echo
                echo "    !!  Mismatch: the DNS apps compile from '$appsRef' but nixpkgs now ships"
                echo "        technitium-dns-server $nixpkgsVer. The app DLLs must stay ABI-compatible"
                echo "        with the server. Bump the 'technitium-dns' input in flake.nix to"
                echo "        'v$nixpkgsVer', run 'nix flake update technitium-dns', then re-run update-deps."
              else
                echo "    OK: apps input matches the nixpkgs server version."
              fi

              echo
              echo "==> Regenerating pkg/technitium-apps/nuget-deps.json..."
              fetchDeps=$(nix build --no-link --print-out-paths \
                ".#packages.${system}.technitium-dns-apps.fetch-deps")
              "$fetchDeps" "$root/pkg/technitium-apps/nuget-deps.json"

              echo
              echo "==> Done. Review with:"
              echo "    git diff -- flake.lock pkg/technitium-apps/nuget-deps.json"
              echo "    and re-run: nix build .#checks.${system}.technitium-vm"
            '';
          };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              nixd
              nixfmt
              prek
              update-deps
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
          routerPkgs = pkgs.extend self.overlays.router;
        in
        {
          cockpit-router = pkgs.callPackage ./pkg/cockpit-router/package.nix { };
          inherit (routerPkgs) pyturso technitium-dns-apps router-dns-tools;
        }
        # Merge the installer artifacts on x86_64 (installerIso, guidedIso,
        # settingsSchema, …) plus the FLAT schema the Cockpit UI validates
        # against. Regenerate the committed copy after changing router options:
        #   nix build .#packages.x86_64-linux.settingsSchema-router \
        #     && jq -S . result > pkg/cockpit-router/src/router-settings.schema.json
        // lib.optionalAttrs (system == "x86_64-linux") (
          ih.packages.x86_64-linux
          // {
            settingsSchema-router = pkgs.writeText "router-settings.schema.json" (
              builtins.toJSON flatRouterSchema
            );
          }
        )
      );

      # The `install` system + configure/install/deploy/wizard apps.
      #
      # `installTemplate` — the router modules evaluated with NO settings — is
      # dropped: mkProject exports it unconditionally, but it is only ever read
      # through a guided ISO's manifest (mk-project.nix `hostAttr`,
      # scripts/guided-install.sh), and `guided = false` above means nothing
      # builds one. Left in, it is a nixosConfiguration that cannot evaluate —
      # a settings-free router trips network.nix's "no port exists to carry
      # traffic" assertion — so `nix flake check` fails on an output no consumer
      # has.
      nixosConfigurations = builtins.removeAttrs ih.nixosConfigurations [ "installTemplate" ];
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
      #  NixOS config (systemd-networkd, nftables, Technitium DNS, WireGuard,
      #  Suricata, Cockpit, etc.). It is composed from focused sub-modules under
      #  ./modules, each aligned with a Cockpit UI domain:
      #    • topology.nix          — shared derived values (interface names,
      #                              CIDRs, the VLAN/port model) exposed to the
      #                              others via the internal `router._internal`.
      #    • network.nix           — systemd-networkd interfaces/bridges/VLAN/WG.
      #    • threat-protection.nix — Suricata IPS.
      #    • hosts.nix             — device registry, groups, DHCP reservations.
      #    • access-policies.nix   — named filtering policies + assignments.
      #    • dns-technitium.nix    — Technitium DNS engine provisioning + Avahi.
      #    • directory-sync.nix    — SSSD (LDAP/AD) user+group resolution.
      #    • reporting.nix         — router-logd query-log store + PDF reports.
      #    • firewall.nix          — nftables ruleset, NAT, port-forwards, UPnP.
      #    • system.nix            — boot/disko, kernel, packages, hardening,
      #                              Cockpit, maintenance, effective.json.
      # ════════════════════════════════════════════════════════════════════════
      nixosModules.router = {
        imports = [
          inputs.disko.nixosModules.disko
          ./modules/topology.nix
          ./modules/network.nix
          ./modules/hosts.nix
          ./modules/threat-protection.nix
          ./modules/access-policies.nix
          ./modules/dns-technitium.nix
          ./modules/directory-sync.nix
          ./modules/reporting.nix
          ./modules/firewall.nix
          ./modules/system.nix
        ];
        # Hand the overlay (which closes over the turso + technitium-dns flake
        # inputs) to the sub-modules as a module arg. dns-technitium.nix applies
        # it locally with `pkgs.extend` rather than via `nixpkgs.overlays`, which
        # would conflict with test harnesses / consumers that supply
        # `nixpkgs.pkgs` (making nixpkgs.overlays read-only).
        _module.args.routerOverlay = self.overlays.router;
      };
    };

}
