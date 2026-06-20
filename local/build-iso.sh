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

# Determine nixos-router input
if [[ -f "$FLAKE_ROOT/flake.nix" ]] && grep -q "NixOS Router" "$FLAKE_ROOT/flake.nix" 2>/dev/null; then
  NIXOS_ROUTER_INPUT="path:$FLAKE_ROOT"
  info "Using local nixos-router flake at $FLAKE_ROOT"
else
  NIXOS_ROUTER_INPUT="github:Avunu/nixos-router"
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

# Copy the local flake + lock as the permanent config (seeded to /etc/nixos).
cp "$LOCAL_FLAKE" "${BUILD_DIR}/permanent-flake.nix"
cp "$LOCAL_LOCK" "${BUILD_DIR}/permanent-flake.lock"

# The installer flake references the local config's nixosConfiguration via a
# path input. This avoids fragile text extraction — Nix evaluates it directly.
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
    in
    {
      packages.\${system}.default =
        self.nixosConfigurations.installerIso.config.system.build.isoImage;

      nixosConfigurations.\${hostname} =
        local-config.nixosConfigurations.\${hostname};

      nixosConfigurations.installerIso = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          "\${nixpkgs}/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix"

          (
            { pkgs, lib, ... }:
            let
              # The target system, evaluated at ISO-BUILD time. Its toplevel and
              # disko partition script are baked into the ISO as store paths, so
              # the appliance installs OFFLINE — no flake re-evaluation, and thus
              # no dependency on the build machine's paths or on the network.
              target = self.nixosConfigurations.\${hostname};
            in
            {
              # Seed the installed system's /etc/nixos for future nixos-rebuild.
              environment.etc."nixos-router/flake.nix".source = ./permanent-flake.nix;
              environment.etc."nixos-router/flake.lock".source = ./permanent-flake.lock;

              # Ship the full system closure on the ISO for an offline install.
              isoImage.storeContents = [
                target.config.system.build.toplevel
              ];

              nix.settings.experimental-features = [
                "nix-command"
                "flakes"
              ];

              environment.systemPackages = [ pkgs.nixos-install-tools ];

              # The installation CD autologins a shell on tty1, which would
              # otherwise hide the installer running behind it. Disable that
              # getty and run the installer ON tty1 in the foreground. Other VTs
              # (Alt+F2…F6) still offer a login shell for debugging.
              systemd.services."getty@tty1".enable = lib.mkForce false;
              systemd.services."autovt@tty1".enable = lib.mkForce false;

              systemd.services.unattended-install = {
                description = "Unattended NixOS Router Installation";
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

                serviceConfig = {
                  # idle: let boot messages settle so the installer UI is clean.
                  Type = "idle";
                  # Claim tty1 as the controlling terminal (foreground) so output
                  # is visible and the Ctrl+C abort window is interactive.
                  StandardInput = "tty-force";
                  StandardOutput = "tty";
                  StandardError = "tty";
                  TTYPath = "/dev/tty1";
                  TTYReset = "yes";
                  TTYVHangup = "yes";
                };

                path = [
                  pkgs.nixos-install-tools
                  pkgs.util-linux
                  pkgs.coreutils
                  pkgs.nix
                ];

                script = ''
                  set -euo pipefail

                  echo "=============================================="
                  echo " AUTOMATED NIXOS ROUTER INSTALL"
                  echo " Hostname : ${HOSTNAME}"
                  echo " Disk     : ${DISK_DEVICE}"
                  echo "=============================================="

                  if [ -b "/dev/disk/by-label/ESP" ] || \\
                     [ -b "/dev/disk/by-label/root" ] || \\
                     [ -b "/dev/disk/by-label/boot" ]; then
                    echo ""
                    echo "ERROR: Existing installation detected (partition labels found)."
                    echo "       Halting to prevent accidental data loss."
                    echo "       Manually wipe ${DISK_DEVICE} if a clean install is intended."
                    echo ""
                    exit 1
                  fi

                  echo "No existing installation detected."
                  echo "Waiting 10 seconds — press Ctrl+C to abort..."
                  sleep 10

                  # 1) Partition, format, and mount the target disk at /mnt using
                  #    the prebuilt disko script (no flake eval, no network).
                  echo ":: Partitioning ${DISK_DEVICE}..."
                  \${target.config.system.build.diskoScript}

                  # 2) Install the prebuilt system from the ISO store (offline).
                  echo ":: Installing system..."
                  nixos-install \\
                    --system \${target.config.system.build.toplevel} \\
                    --no-root-passwd \\
                    --no-channel-copy

                  # 3) Seed /etc/nixos so the appliance can rebuild later.
                  install -Dm0644 /etc/nixos-router/flake.nix /mnt/etc/nixos/flake.nix
                  install -Dm0644 /etc/nixos-router/flake.lock /mnt/etc/nixos/flake.lock

                  echo "=============================================="
                  echo " Installation complete! Rebooting in 5 s..."
                  echo "=============================================="
                  sleep 5
                  reboot
                '';
              };
            }
          )
        ];
      };
    };
}
EOF

# Create the local-config subdirectory as a flake the installer evaluates at
# BUILD time (only) to produce the system toplevel + disko script. This is the
# user's actual config — evaluated directly by Nix, no text parsing.
mkdir -p "${BUILD_DIR}/local-config"
cp "$LOCAL_FLAKE" "${BUILD_DIR}/local-config/flake.nix"
cp "$LOCAL_LOCK" "${BUILD_DIR}/local-config/flake.lock"

info "Generated installer flake at ${BUILD_DIR}/flake.nix"

git init -q "${BUILD_DIR}"
git -C "${BUILD_DIR}" add .

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
echo "      --flake \"${BUILD_DIR}#${HOSTNAME}\" \\"
echo "      root@<ip-address>"
echo ""
echo "  When booted, the router installs automatically."
echo "  Monitor progress on tty1 or via serial console."
