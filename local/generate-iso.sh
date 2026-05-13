#!/usr/bin/env bash
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}::${NC} $*"; }
success() { echo -e "${GREEN}::${NC} $*"; }
error()   { echo -e "${RED}ERROR:${NC} $*" >&2; }
warn()    { echo -e "${YELLOW}WARN:${NC} $*"; }
header()  { echo -e "\n${BOLD}$*${NC}\n"; }

# ── Locate the nixos-router flake ─────────────────────────────────────────────
# When run directly from the repo (./local/generate-iso.sh), we use a local
# path reference so the ISO build pre-populates the Nix store with all
# packages — no internet required during headless deployment.
# When run via `nix run github:Avunu/nixos-router#generate-iso`, the local
# repo isn't available and we fall back to the upstream GitHub URL.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLAKE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$FLAKE_ROOT/flake.nix" ]] && grep -q "NixOS Router" "$FLAKE_ROOT/flake.nix" 2>/dev/null; then
  NIXOS_ROUTER_INPUT="path:$FLAKE_ROOT"
  info "Using local nixos-router flake at $FLAKE_ROOT"
else
  NIXOS_ROUTER_INPUT="github:Avunu/nixos-router"
  warn "Local flake not found — using upstream GitHub. Packages will be fetched during ISO boot."
fi

header "NixOS Router ISO Generator"
echo "Builds a self-contained, headless installer ISO customised for your hardware."
echo "Boot the ISO on the target machine; it installs automatically without"
echo "requiring internet access or user interaction."
echo ""

# ── System identity ────────────────────────────────────────────────────────────
read -rp "Hostname [router]: " HOSTNAME
HOSTNAME="${HOSTNAME:-router}"

read -rp "Timezone [America/New_York]: " TIMEZONE
TIMEZONE="${TIMEZONE:-America/New_York}"

# ── Boot mode ─────────────────────────────────────────────────────────────────
echo ""
info "Boot mode:"
echo "  1) uefi   (modern systems, systemd-boot)"
echo "  2) legacy (older BIOS systems, GRUB)"
read -rp "Select [1]: " BOOT_CHOICE
case "${BOOT_CHOICE:-1}" in
  1) BOOT_MODE="uefi" ;;
  2) BOOT_MODE="legacy" ;;
  *) BOOT_MODE="uefi" ;;
esac

# ── Disk device ───────────────────────────────────────────────────────────────
echo ""
info "Available block devices:"
lsblk -d -o NAME,SIZE,MODEL,TYPE 2>/dev/null | grep -E "disk" || true
echo ""
read -rp "Target disk device [/dev/sda]: " DISK_DEVICE
DISK_DEVICE="${DISK_DEVICE:-/dev/sda}"

# ── Network interfaces ────────────────────────────────────────────────────────
echo ""
info "Network interfaces (for reference):"
ip -br link show 2>/dev/null | grep -v "^lo " || true
echo ""

read -rp "WAN interface (internet-facing, e.g. enp1s0): " WAN_IFACE
if [[ -z "$WAN_IFACE" ]]; then
  error "WAN interface is required."
  exit 1
fi

read -rp "LAN interfaces (space-separated, e.g. enp2s0 enp3s0): " LAN_INTERFACES_RAW
if [[ -z "$LAN_INTERFACES_RAW" ]]; then
  error "At least one LAN interface is required."
  exit 1
fi

LAN_IFACES_NIX=""
for iface in $LAN_INTERFACES_RAW; do
  LAN_IFACES_NIX+="
                    \"${iface}\""
done

# ── LAN addressing ────────────────────────────────────────────────────────────
echo ""
info "LAN network configuration:"
read -rp "LAN gateway IP [10.0.0.1]: " LAN_ADDR
LAN_ADDR="${LAN_ADDR:-10.0.0.1}"

DEFAULT_NET="${LAN_ADDR%.*}.0"
read -rp "LAN network address [$DEFAULT_NET]: " LAN_NET
LAN_NET="${LAN_NET:-$DEFAULT_NET}"

read -rp "LAN prefix length [24]: " LAN_PREFIX
LAN_PREFIX="${LAN_PREFIX:-24}"

read -rp "LAN local domain [lan]: " LAN_DOMAIN
LAN_DOMAIN="${LAN_DOMAIN:-lan}"

# ── Guest network ─────────────────────────────────────────────────────────────
echo ""
read -rp "Enable guest network (isolated from LAN)? [y/N]: " GUEST_CHOICE
case "${GUEST_CHOICE:-n}" in
  [yY]*) ENABLE_GUEST="true" ;;
  *) ENABLE_GUEST="false" ;;
esac

GUEST_IFACES_NIX=""
GUEST_ADDR="192.168.20.1"
GUEST_NET="192.168.20.0"
GUEST_BLOCK="
                guest.enable = false;"

if [[ "$ENABLE_GUEST" == "true" ]]; then
  echo ""
  info "Guest network configuration:"
  read -rp "Guest interfaces (space-separated): " GUEST_IFACES_RAW
  for iface in $GUEST_IFACES_RAW; do
    GUEST_IFACES_NIX+="
                    \"${iface}\""
  done

  read -rp "Guest gateway IP [192.168.20.1]: " GUEST_ADDR
  GUEST_ADDR="${GUEST_ADDR:-192.168.20.1}"

  DEFAULT_GUEST_NET="${GUEST_ADDR%.*}.0"
  read -rp "Guest network address [$DEFAULT_GUEST_NET]: " GUEST_NET
  GUEST_NET="${GUEST_NET:-$DEFAULT_GUEST_NET}"

  GUEST_BLOCK="
                guest = {
                  enable = true;
                  interfaces = [${GUEST_IFACES_NIX}
                  ];
                  address = \"${GUEST_ADDR}\";
                  networkAddress = \"${GUEST_NET}\";
                };"
fi

# ── Admin user ────────────────────────────────────────────────────────────────
echo ""
info "Admin user:"
read -rp "Username [admin]: " ADMIN_USER
ADMIN_USER="${ADMIN_USER:-admin}"

read -rp "Initial password [admin123]: " ADMIN_PASSWORD
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin123}"

echo ""
info "SSH public keys (one per line, empty line to finish):"
SSH_KEYS=()
while true; do
  read -rp "  Key: " key
  [[ -z "$key" ]] && break
  SSH_KEYS+=("$key")
done

SSH_KEYS_NIX=""
for key in "${SSH_KEYS[@]}"; do
  SSH_KEYS_NIX+="
                    \"${key}\""
done

# ── Optional features ─────────────────────────────────────────────────────────
echo ""
read -rp "Enable AdGuard Home DNS filtering? [Y/n]: " ADGUARD_CHOICE
case "${ADGUARD_CHOICE:-y}" in
  [nN]*) ENABLE_ADGUARD="false" ;;
  *) ENABLE_ADGUARD="true" ;;
esac

read -rp "Enable Suricata IPS? [y/N]: " SURICATA_CHOICE
case "${SURICATA_CHOICE:-n}" in
  [yY]*) ENABLE_SURICATA="true" ;;
  *) ENABLE_SURICATA="false" ;;
esac

read -rp "Enable Cockpit web UI? [Y/n]: " COCKPIT_CHOICE
case "${COCKPIT_CHOICE:-y}" in
  [nN]*) ENABLE_COCKPIT="false" ;;
  *) ENABLE_COCKPIT="true" ;;
esac

# ── Output path ───────────────────────────────────────────────────────────────
echo ""
DEFAULT_OUTPUT="$(pwd)/router-${HOSTNAME}.iso"
read -rp "Output ISO path [$DEFAULT_OUTPUT]: " OUTPUT_ISO
OUTPUT_ISO="${OUTPUT_ISO:-$DEFAULT_OUTPUT}"

STATE_VERSION="25.11"

# ── Confirmation ──────────────────────────────────────────────────────────────
header "Configuration Summary"
echo "  Hostname:        $HOSTNAME"
echo "  Timezone:        $TIMEZONE"
echo "  Boot mode:       $BOOT_MODE"
echo "  Disk device:     $DISK_DEVICE"
echo "  WAN interface:   $WAN_IFACE"
echo "  LAN interfaces:  $LAN_INTERFACES_RAW"
echo "  LAN gateway:     $LAN_ADDR/$LAN_PREFIX ($LAN_NET)"
echo "  Guest network:   $ENABLE_GUEST"
echo "  Admin user:      $ADMIN_USER"
echo "  SSH keys:        ${#SSH_KEYS[@]} key(s)"
echo "  AdGuard DNS:     $ENABLE_ADGUARD"
echo "  Suricata IPS:    $ENABLE_SURICATA"
echo "  Cockpit UI:      $ENABLE_COCKPIT"
echo "  Output ISO:      $OUTPUT_ISO"
echo ""
read -rp "Build ISO? (type 'yes'): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
  echo "Aborted."
  exit 1
fi

# ── Generate flakes ───────────────────────────────────────────────────────────
header "Generating configuration..."

BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

# The router.* config block is identical in both flakes — only the inputs
# differ (local path vs upstream GitHub).  Defining it once here avoids drift.
ROUTER_CONFIG_BLOCK="
                hostName = hostname;
                timeZone = \"${TIMEZONE}\";
                stateVersion = \"${STATE_VERSION}\";
                diskDevice = \"${DISK_DEVICE}\";
                bootMode = \"${BOOT_MODE}\";

                wan.interface = \"${WAN_IFACE}\";

                lan = {
                  interfaces = [${LAN_IFACES_NIX}
                  ];
                  address = \"${LAN_ADDR}\";
                  networkAddress = \"${LAN_NET}\";
                  prefixLength = ${LAN_PREFIX};
                  domain = \"${LAN_DOMAIN}\";
                  dhcp = {
                    poolOffset = 100;
                    poolSize = 151;
                    leaseTime = \"24h\";
                  };
                };
${GUEST_BLOCK}

                dns = {
                  upstreamServers = [
                    \"https://dns.cloudflare.com/dns-query\"
                    \"https://dns.google/dns-query\"
                  ];
                  bootstrapServers = [
                    \"1.1.1.1\"
                    \"8.8.8.8\"
                  ];
                  adguard = {
                    enable = ${ENABLE_ADGUARD};
                    webPort = 3000;
                    safeSearch = true;
                    utCapitoleCategories = [
                      \"malware\"
                      \"phishing\"
                      \"cryptojacking\"
                      # \"porn\"
                      # \"gambling\"
                    ];
                  };
                };

                suricata.enable = ${ENABLE_SURICATA};

                cockpit = {
                  enable = ${ENABLE_COCKPIT};
                  port = 9090;
                };

                adminUser = {
                  name = \"${ADMIN_USER}\";
                  initialPassword = \"${ADMIN_PASSWORD}\";
                  sshKeys = [${SSH_KEYS_NIX}
                  ];
                };"

# ── Install flake ──────────────────────────────────────────────────────────────
# Used only for `nix build` and by disko-install inside the ISO.
# References the local (or upstream) nixos-router so all packages are already
# in the ISO's Nix store — disko-install copies them to disk without fetching.
cat > "${BUILD_DIR}/flake.nix" << FLAKE
{
  inputs = {
    nixos-router.url = "${NIXOS_ROUTER_INPUT}";
    nixpkgs.follows = "nixos-router/nixpkgs";
    disko.follows = "nixos-router/disko";
  };

  outputs =
    {
      self,
      nixpkgs,
      nixos-router,
      disko,
      ...
    }:
    let
      hostname = "${HOSTNAME}";
      system = "x86_64-linux";
    in
    {
      # Convenience target: nix build <dir>  (produces the ISO)
      packages.\${system}.default =
        self.nixosConfigurations.installerIso.config.system.build.isoImage;

      # Target router configuration — installed by disko-install.
      nixosConfigurations.\${hostname} = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          nixos-router.nixosModules.router
          {
            router = {${ROUTER_CONFIG_BLOCK}
            };
          }
        ];
      };

      # ── Installer ISO ──────────────────────────────────────────────────────
      nixosConfigurations.installerIso = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          "\${nixpkgs}/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix"

          (
            { pkgs, ... }:
            {
              # Embed this flake so disko-install can reference it as a local
              # path — all store paths are already present in the ISO squashfs.
              environment.etc."installer-flake".source = self;

              # Embed the permanent flake so it can be written to /etc/nixos
              # on the installed system for ongoing auto-updates.
              environment.etc."permanent-flake/flake.nix".source = ./permanent-flake.nix;

              # Pre-populate the ISO squashfs with the full router package
              # closure.  disko-install copies from the local store — no
              # network required during headless deployment.
              isoImage.storeContents = [
                self.nixosConfigurations.\${hostname}.config.system.build.toplevel
              ];

              nix.settings.experimental-features = [
                "nix-command"
                "flakes"
              ];

              environment.systemPackages = [
                disko.packages.\${system}.default
                pkgs.nixos-install-tools
              ];

              systemd.services.unattended-install = {
                description = "Unattended NixOS Router Installation";
                wantedBy = [ "multi-user.target" ];
                after = [
                  "network.target"
                  "polkit.service"
                ];

                serviceConfig = {
                  Type = "oneshot";
                  StandardOutput = "tty";
                  StandardError = "tty";
                  TTYPath = "/dev/tty1";
                };

                path = [
                  disko.packages.\${system}.default
                  pkgs.nixos-install-tools
                  pkgs.util-linux
                ];

                script = ''
                  set -euo pipefail

                  echo "=============================================="
                  echo " AUTOMATED NIXOS ROUTER INSTALL"
                  echo " Hostname : ${HOSTNAME}"
                  echo " Disk     : ${DISK_DEVICE}"
                  echo "=============================================="

                  # ── Safety: detect existing installation ────────────────
                  # Halt if known partition labels already exist to prevent
                  # silent data loss when the ISO accidentally boots on the
                  # wrong machine.
                  if [ -b "/dev/disk/by-label/ESP" ] || \
                     [ -b "/dev/disk/by-label/root" ] || \
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

                  # ── Partition, format, and install ───────────────────────
                  # The install flake is embedded in the ISO at /etc/installer-flake.
                  # All referenced store paths are pre-populated in the squashfs so
                  # disko-install copies them to disk without fetching anything.
                  # The permanent flake (upstream GitHub refs) is written to
                  # /etc/nixos/flake.nix for ongoing nixos-rebuild auto-updates.
                  disko-install \
                    --flake /etc/installer-flake#${HOSTNAME} \
                    --extra-files /etc/permanent-flake/flake.nix /etc/nixos/flake.nix

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
FLAKE

# ── Permanent flake ────────────────────────────────────────────────────────────
# Written to /etc/nixos/flake.nix on the installed system.
# References upstream GitHub so the router can auto-update via nixos-rebuild.
cat > "${BUILD_DIR}/permanent-flake.nix" << FLAKE
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    nixos-router = {
      url = "github:Avunu/nixos-router";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      nixos-router,
    }:
    let
      hostname = "${HOSTNAME}";
      system = "x86_64-linux";
    in
    {
      nixosConfigurations.\${hostname} = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          { nix.nixPath = [ "nixpkgs=\${self.inputs.nixpkgs}" ]; }
          nixos-router.nixosModules.router
          {
            router = {${ROUTER_CONFIG_BLOCK}
            };
          }
        ];
      };
    };
}
FLAKE

info "Generated install flake at    ${BUILD_DIR}/flake.nix"
info "Generated permanent flake at  ${BUILD_DIR}/permanent-flake.nix"

# Nix flakes require a git repo to compute consistent hashes.
git init -q "${BUILD_DIR}"
git -C "${BUILD_DIR}" add flake.nix permanent-flake.nix

# ── Build ISO ─────────────────────────────────────────────────────────────────
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
echo ""
echo "  Default admin credentials (change immediately after first login):"
echo "    User:     ${ADMIN_USER}"
echo "    Password: ${ADMIN_PASSWORD}"
echo ""
