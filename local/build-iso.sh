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
            {
              # Ship the self-contained installer flake (this flake plus its
              # relative-path inputs: the vendored nixos-router and the user's
              # local-config) so disko-install can re-evaluate it offline. The
              # relative paths resolve within this store path on the appliance.
              environment.etc."installer-flake".source = self.outPath;

              # Bake everything disko-install needs for an OFFLINE install:
              #   • the prebuilt system toplevel + disko partitioning script, so
              #     neither is rebuilt on the appliance;
              #   • the source trees of the eval-reachable flake inputs (nixpkgs,
              #     disko, nixos-router) so the re-evaluation never hits the
              #     network. local-config and nixos-router-src ride along inside
              #     self.outPath above.
              isoImage.storeContents = [
                target.config.system.build.toplevel
                target.config.system.build.diskoScript
                nixpkgs.outPath
                disko.outPath
                nixos-router.outPath
              ];

              nix.settings.experimental-features = [
                "nix-command"
                "flakes"
              ];

              # disko.packages.default provides BOTH \`disko\` and \`disko-install\`.
              environment.systemPackages = [
                disko.packages.\${system}.default
                pkgs.nixos-install-tools
              ];

              # The installation CD autologins a shell on tty1, which would
              # otherwise hide the installer running behind it. Disable that
              # getty and run the installer ON tty1 in the foreground. Other VTs
              # (Alt+F2…F6) still offer a login shell for debugging.
              systemd.services."getty@tty1".enable = lib.mkForce false;
              systemd.services."autovt@tty1".enable = lib.mkForce false;

              systemd.services.unattended-install = {
                description = "Unattended NixOS Router Installation (disko-install)";
                wantedBy = [ "multi-user.target" ];
                after = [
                  "network.target"
                  "polkit.service"
                ];
                # Replace the getty on tty1 and take its terminal.
                conflicts = [
                  "getty@tty1.service"
                  "autovt@tty1.service"
                ];

                # Parameters consumed by ./unattended-install.sh.
                environment = {
                  routerHostname = hostname;
                  routerDisk = "${DISK_DEVICE}";
                  routerDiskName = "main";
                };

                serviceConfig = {
                  # idle: let boot messages settle so the installer UI is clean.
                  Type = "idle";
                  # Claim tty1 as the controlling terminal (foreground) so output
                  # is visible and the Ctrl+C / Enter abort window is interactive.
                  StandardInput = "tty-force";
                  StandardOutput = "tty";
                  StandardError = "tty";
                  TTYPath = "/dev/tty1";
                  TTYReset = "yes";
                  TTYVHangup = "yes";
                };

                path = [
                  disko.packages.\${system}.default
                  pkgs.nixos-install-tools
                  pkgs.util-linux
                  pkgs.efibootmgr
                  pkgs.coreutils
                  pkgs.nix
                  pkgs.less              # scrollable pager for the failure log
                  pkgs.bashInteractive   # drop-to-shell on failure (bash -i)
                ];

                script = builtins.readFile ./unattended-install.sh;
              };
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
