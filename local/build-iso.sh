#!/usr/bin/env bash
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}::${NC} $*"; }
success() { echo -e "${GREEN}::${NC} $*"; }
error()   { echo -e "${RED}ERROR:${NC} $*" >&2; }
header()  { echo -e "\n${BOLD}$*${NC}\n"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLAKE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOCAL_FLAKE="${SCRIPT_DIR}/flake.nix"
LOCAL_LOCK="${SCRIPT_DIR}/flake.lock"

if [[ ! -f "$LOCAL_FLAKE" ]]; then
  error "No flake.nix found at ${LOCAL_FLAKE}"
  error "Run generate-config.sh first, or create local/flake.nix manually."
  exit 1
fi

# A lock file is required: it is seeded into the installed system's /etc/nixos
# and pins the build so the ISO and the appliance evaluate identically.
if [[ ! -f "$LOCAL_LOCK" ]]; then
  error "No flake.lock found at ${LOCAL_LOCK}"
  error "Generate it first:  (cd ${SCRIPT_DIR} && nix flake lock)"
  exit 1
fi

# Extract hostname from the local flake
HOSTNAME=$(grep -oP 'hostName\s*=\s*"\K[^"]+' "$LOCAL_FLAKE" | head -1)
if [[ -z "$HOSTNAME" ]]; then
  error "Could not extract hostName from ${LOCAL_FLAKE}"
  exit 1
fi

# Extract disk device for display
DISK_DEVICE=$(grep -oP 'diskDevice\s*=\s*"\K[^"]+' "$LOCAL_FLAKE" | head -1)
DISK_DEVICE="${DISK_DEVICE:-unknown}"

# Determine the nixos-router input for the installer flake.
#
# disko-install RE-EVALUATES the flake on the appliance at install time, so the
# nixos-router source must resolve OFFLINE there. An absolute `path:` input to
# this build machine would not exist on the appliance, so when building from a
# local checkout we VENDOR nixos-router (flake.nix + flake.lock — the flake is
# fully self-contained, no ./modules imports) into the installer flake tree and
# reference it by a relative path. The whole tree is shipped on the ISO, so the
# relative path resolves within the Nix store at install time.
if [[ -f "$FLAKE_ROOT/flake.nix" ]] && grep -q "NixOS Router" "$FLAKE_ROOT/flake.nix" 2>/dev/null; then
  NIXOS_ROUTER_INPUT="path:./nixos-router-src"
  VENDOR_NIXOS_ROUTER=1
  info "Using (vendored) local nixos-router flake at $FLAKE_ROOT"
else
  NIXOS_ROUTER_INPUT="github:Avunu/nixos-router"
  VENDOR_NIXOS_ROUTER=0
  info "Using upstream nixos-router from GitHub"
fi

# Output path
DEFAULT_OUTPUT="$(pwd)/router-${HOSTNAME}.iso"
OUTPUT_ISO="${1:-$DEFAULT_OUTPUT}"

header "NixOS Router ISO Builder"
echo "  Hostname:    $HOSTNAME"
echo "  Disk:        $DISK_DEVICE"
echo "  Config:      $LOCAL_FLAKE"
echo "  Output:      $OUTPUT_ISO"
echo ""

# ── Generate installer flake ─────────────────────────────────────────────────
header "Generating installer flake..."

BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

# The installer flake references the local config's nixosConfiguration via a
# path input. This avoids fragile text extraction — Nix evaluates it directly.
#
# disko-install RE-EVALUATES this flake on the appliance, so the whole tree is
# shipped to /etc/installer-flake (self.outPath) and the eval-reachable input
# sources + the prebuilt closure are baked into the ISO store — the install runs
# entirely OFFLINE.
cat > "${BUILD_DIR}/flake.nix" << EOF
{
  inputs = {
    nixos-router.url = "${NIXOS_ROUTER_INPUT}";
    nixpkgs.follows = "nixos-router/nixpkgs";
    disko.follows = "nixos-router/disko";
    local-config = {
      url = "path:./local-config";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.nixos-router.follows = "nixos-router";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      nixos-router,
      disko,
      local-config,
      ...
    }:
    let
      hostname = "${HOSTNAME}";
      system = "x86_64-linux";

      # The target appliance system, evaluated at ISO-BUILD time so its full
      # closure can be baked onto the ISO for an OFFLINE install.
      target = self.nixosConfigurations.\${hostname};
    in
    {
      # Exposed at the top level so the appliance's disko-install can
      # re-evaluate it: \`disko-install --flake /etc/installer-flake#\${hostname}\`.
      nixosConfigurations.\${hostname} =
        local-config.nixosConfigurations.\${hostname};

      packages.\${system}.default =
        self.nixosConfigurations.installerIso.config.system.build.isoImage;

      nixosConfigurations.installerIso = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          "\${nixpkgs}/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix"

          (
            { pkgs, lib, ... }:
            let
              # Recursively collect EVERY flake input's source path. disko-install
              # re-evaluates the whole flake on the appliance, which forces the
              # complete input set — not just the inputs the router config uses.
              # Shipping only nixpkgs/disko/nixos-router left git-hooks,
              # flake-compat and gitignore unresolved, so the offline machine
              # tried to fetch them ("could not resolve hostname"). This collector
              # walks self.inputs transitively. (From disko's offline-install docs.)
              flakeOutPaths =
                let
                  collector =
                    parent:
                    map (
                      child:
                      [ child.outPath ]
                      ++ (if child ? inputs && child.inputs != { } then (collector child) else [ ])
                    ) (lib.attrValues parent.inputs);
                in
                # Keep only top-level store paths. The relative-path inputs
                # (local-config, nixos-router-src) resolve to subpaths of this
                # flake's own source, which is already shipped via
                # /etc/installer-flake; their transitive github inputs are still
                # collected by the recursion above.
                lib.filter (p: builtins.match "/nix/store/[^/]+" (toString p) != null) (
                  lib.unique (lib.flatten (collector self))
                );

              # The set disko-install needs to partition + install OFFLINE: the
              # prebuilt system + disko script (both realized from the store — we
              # proved their drvPaths match what disko-install re-evaluates, so
              # nothing is rebuilt), the perl modules the activation script needs,
              # and every flake input SOURCE for the re-evaluation.
              #
              # NB: we deliberately do NOT ship stdenv.drvPath / *.drvPath here.
              # A .drv's closure pulls the ENTIRE build toolchain (gcc/clang,
              # bootstrap, source tarballs) onto the ISO — gigabytes, and pointless
              # for an appliance that never builds from source. disko-install only
              # *realizes* the prebuilt outputs, and the one derivation it does
              # build at install time (its own closureInfo) needs just coreutils,
              # which is already in the system closure.
              installDeps = [
                target.config.system.build.toplevel
                target.config.system.build.diskoScript
                target.pkgs.perlPackages.ConfigIniFiles
                target.pkgs.perlPackages.FileSlurp
              ]
              ++ flakeOutPaths;

              # closureInfo's store-paths output references the full closure of
              # every dep; referencing it from /etc pulls them all into the
              # installer system's own closure, so they land on the ISO store.
              installClosure = pkgs.closureInfo { rootPaths = installDeps; };
            in
            {
              # Ship the self-contained installer flake (this flake plus its
              # relative-path inputs: the vendored nixos-router and the user's
              # local-config) so disko-install can re-evaluate it offline. The
              # relative paths resolve within this store path on the appliance.
              environment.etc."installer-flake".source = self.outPath;

              # Bake the COMPLETE offline install closure onto the ISO.
              environment.etc."install-closure".source = "\${installClosure}/store-paths";
              isoImage.storeContents = [ installClosure ];

              nix.settings.experimental-features = [
                "nix-command"
                "flakes"
              ];

              # This is a guaranteed-offline appliance install: forbid all
              # network access so a missing store path fails fast with a clear
              # error instead of a confusing "could not resolve host" hang.
              nix.settings.substituters = lib.mkForce [ ];
              nix.settings.builders = lib.mkForce [ ];

              # disko.packages.default provides BOTH \`disko\` and \`disko-install\`.
              # less (scrollable failure log) + efibootmgr (EFI entries) must be
              # on PATH for the installer, which now runs as the console session.
              environment.systemPackages = [
                disko.packages.\${system}.default
                pkgs.nixos-install-tools
                pkgs.util-linux
                pkgs.efibootmgr
                pkgs.less
              ];

              # ── kmscon console ──────────────────────────────────────────────
              # kmscon is a userspace KMS/DRM terminal with real scrollback
              # (Shift+PageUp), unlike the kernel VT. It replaces getty/autovt on
              # every VT, so the installer — which now runs AS the tty1 login
              # session (below) — is fully scrollable while it runs.
              services.kmscon = {
                enable = true;
                config.sb-size = 50000; # scrollback lines
              };
              # Autologin root on tty1 (kmscon honours the getty autologin
              # settings); the installation CD defaults this to the "nixos" user.
              services.getty.autologinUser = lib.mkForce "root";

              # Launch the installer as the first console login (under kmscon, so
              # its output scrolls). The run-once flag keeps later logins on other
              # VTs (Alt+F2…F6) as plain debug shells. exec'ing through bash gives
              # the script a real controlling terminal for its countdown + pager.
              environment.variables = {
                routerHostname = hostname;
                routerDisk = "${DISK_DEVICE}";
                routerDiskName = "main";
              };
              programs.bash.loginShellInit = ''
                if [ ! -e /run/unattended-install.started ]; then
                  : > /run/unattended-install.started
                  exec \${pkgs.bashInteractive}/bin/bash \${./unattended-install.sh}
                fi
              '';

              # ── Lighten the installer image ─────────────────────────────────
              # Drop ZFS (huge kernel module + userspace), all documentation
              # (man-cache + NixOS manual), and bluetooth. mkForce overrides the
              # installation-media defaults (mkImageMediaOverride / mkDefault).
              boot.supportedFilesystems.zfs = lib.mkForce false;
              documentation.enable = lib.mkForce false;
              documentation.nixos.enable = lib.mkForce false; # installer forces this separately
              hardware.bluetooth.enable = lib.mkForce false;
            }
          )
        ];
      };
    };
}
EOF

# Create the local-config subdirectory: the user's actual config, evaluated by
# Nix directly (no text parsing) both at ISO-build time and at install time.
# Its flake.nix/flake.lock are also seeded into the appliance's /etc/nixos
# (by unattended-install.sh) so it can nixos-rebuild later.
mkdir -p "${BUILD_DIR}/local-config"
cp "$LOCAL_FLAKE" "${BUILD_DIR}/local-config/flake.nix"
cp "$LOCAL_LOCK" "${BUILD_DIR}/local-config/flake.lock"

# Vendor the local nixos-router source so the re-evaluation resolves OFFLINE on
# the appliance (an absolute path:/... input to this build machine would not
# exist there). The flake is self-contained — flake.nix + flake.lock only.
if [[ "$VENDOR_NIXOS_ROUTER" == "1" ]]; then
  mkdir -p "${BUILD_DIR}/nixos-router-src"
  cp "$FLAKE_ROOT/flake.nix" "${BUILD_DIR}/nixos-router-src/flake.nix"
  cp "$FLAKE_ROOT/flake.lock" "${BUILD_DIR}/nixos-router-src/flake.lock"
fi

# The unattended installer script, read into the unit via builtins.readFile.
cp "${SCRIPT_DIR}/unattended-install.sh" "${BUILD_DIR}/unattended-install.sh"

info "Generated installer flake at ${BUILD_DIR}/flake.nix"

git init -q "${BUILD_DIR}"
git -C "${BUILD_DIR}" add -A

# Produce a COMPLETE, CONSISTENT flake.lock. disko-install re-evaluates the
# flake offline on the appliance; a missing/stale lock would force a network
# re-lock there. The lock must be git-tracked so it lands in self.outPath that
# is shipped to /etc/installer-flake.
nix flake lock "${BUILD_DIR}" --extra-experimental-features 'nix-command flakes'
git -C "${BUILD_DIR}" add -A

# ── Build ISO ────────────────────────────────────────────────────────────────
header "Building installer ISO..."
echo "This may take a while on first build (packages are cached after)."
echo ""

RESULT_LINK="${BUILD_DIR}/result"
nix build "${BUILD_DIR}" \
  --out-link "$RESULT_LINK" \
  --print-build-logs

ISO_SRC=$(find -L "${RESULT_LINK}/iso" -name "*.iso" | head -1)
if [[ -z "$ISO_SRC" ]]; then
  error "ISO not found in build output."
  exit 1
fi

cp -L "$ISO_SRC" "$OUTPUT_ISO"

success "ISO written to: $OUTPUT_ISO"
echo ""
header "Deployment"
echo "  Flash to USB:"
echo "    sudo dd if=\"$OUTPUT_ISO\" of=/dev/sdX bs=4M status=progress conv=fsync"
echo ""
echo "  Or deploy directly over SSH with nixos-anywhere (no USB needed):"
echo "    nix run github:nix-community/nixos-anywhere -- \\"
echo "      --flake \"${SCRIPT_DIR}#${HOSTNAME}\" \\"
echo "      root@<ip-address>"
echo ""
echo "  When booted, the router installs automatically."
echo "  Monitor progress on tty1 or via serial console."
