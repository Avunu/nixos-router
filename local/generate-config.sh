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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_FLAKE="${SCRIPT_DIR}/flake.nix"
OUTPUT_SETTINGS="${SCRIPT_DIR}/router-settings.nix"

header "NixOS Router Configuration Generator"
echo "Generates local/flake.nix and local/router-settings.nix for your router."
echo "Run build-iso.sh afterwards to build the installer ISO."
echo ""

if [[ -f "$OUTPUT_FLAKE" ]]; then
  warn "Existing flake.nix found at ${OUTPUT_FLAKE}"
  read -rp "Overwrite? [y/N]: " OVERWRITE
  case "${OVERWRITE:-n}" in
    [yY]*) ;;
    *) echo "Aborted."; exit 0 ;;
  esac
fi

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
  LAN_IFACES_NIX+=$'\n'"                    \"${iface}\""
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

GUEST_BLOCK=""
if [[ "$ENABLE_GUEST" == "true" ]]; then
  echo ""
  info "Guest network configuration:"
  read -rp "Guest interfaces (space-separated): " GUEST_IFACES_RAW
  GUEST_IFACES_NIX=""
  for iface in $GUEST_IFACES_RAW; do
    GUEST_IFACES_NIX+=$'\n'"                    \"${iface}\""
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
                };
"
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
  SSH_KEYS_NIX+=$'\n'"                    \"${key}\""
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
echo ""
read -rp "Generate config? (type 'yes'): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
  echo "Aborted."
  exit 1
fi

# ── Generate flake.nix (thin importer) ───────────────────────────────────────
# All router.* options live in router-settings.nix so the Cockpit web UI can
# edit them in place (via nix-editor); the flake just wires the module in.
cat > "$OUTPUT_FLAKE" << FLAKE
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
      hostName = "${HOSTNAME}";
      system = "x86_64-linux";
    in
    {
      nixosConfigurations = {
        "\${hostName}" = nixpkgs.lib.nixosSystem {
          system = system;
          modules = [
            { nix.nixPath = [ "nixpkgs=\${self.inputs.nixpkgs}" ]; }
            nixos-router.nixosModules.router
            # Editable router settings (also written by the Cockpit web UI).
            ./router-settings.nix
          ];
        };
      };
    };
}
FLAKE

# ── Generate router-settings.nix (the editable settings module) ──────────────
cat > "$OUTPUT_SETTINGS" << SETTINGS
# Router settings — the editable \`router.*\` configuration for this host.
#
# This module is imported by flake.nix and is the file the Cockpit "Settings"
# tabs write to (via nix-editor). Hand-edit it freely; the web UI only touches
# the options exposed by its forms (filtering, DNS, firewall, UPnP, IPS, DHCP).
{
  router = {
    hostName = "${HOSTNAME}";
    timeZone = "${TIMEZONE}";
    stateVersion = "${STATE_VERSION}";
    diskDevice = "${DISK_DEVICE}";
    bootMode = "${BOOT_MODE}";

    wan.interface = "${WAN_IFACE}";

    lan = {
      interfaces = [${LAN_IFACES_NIX}
      ];
      address = "${LAN_ADDR}";
      networkAddress = "${LAN_NET}";
      prefixLength = ${LAN_PREFIX};
      domain = "${LAN_DOMAIN}";
      dhcp = {
        poolOffset = 100;
        poolSize = 151;
        leaseTime = "24h";
      };
    };
${GUEST_BLOCK}
    dns = {
      upstreamServers = [
        "https://dns.cloudflare.com/dns-query"
        "https://dns.google/dns-query"
      ];
      bootstrapServers = [
        "1.1.1.1"
        "8.8.8.8"
      ];
      adguard = {
        enable = ${ENABLE_ADGUARD};
        webPort = 3000;
        safeSearch = true;
        utCapitoleCategories = [
          "malware"
          "phishing"
          "cryptojacking"
          # "porn"
          # "gambling"
        ];
      };
    };

    suricata.enable = ${ENABLE_SURICATA};

    upnp.enable = false;

    portForwards = [ ];

    cockpit = {
      enable = ${ENABLE_COCKPIT};
      port = 9090;
    };

    adminUser = {
      name = "${ADMIN_USER}";
      initialPassword = "${ADMIN_PASSWORD}";
      sshKeys = [${SSH_KEYS_NIX}
      ];
    };
  };
}
SETTINGS

success "Configuration written to:"
echo "    $OUTPUT_FLAKE"
echo "    $OUTPUT_SETTINGS"
echo ""
echo "  Edit router-settings.nix to customize further, then run:"
echo "    ./build-iso.sh"
echo ""
