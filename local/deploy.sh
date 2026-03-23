#!/usr/bin/env bash
set -euo pipefail

# Parse arguments
FQDN="${1:-258-router.local}"
IP_ADDRESS="${2:-10.58.1.97}"
HOSTNAME="${FQDN%%.*}"  # Extract hostname from FQDN (everything before first dot)

echo "🚀 Deploying NixOS Development Host to $FQDN (hostname: $HOSTNAME)"
echo ""

# Create a temporary directory for host keys and flake
temp=$(mktemp -d)

# Function to cleanup temporary directory on exit
cleanup() {
  rm -rf "$temp"
}
trap cleanup EXIT

echo "📋 Copying flake configuration to ${temp}/etc/nixos/..."
# Copy the local flake.nix to /etc/nixos/ on the target system
mkdir -p "${temp}/etc/nixos"
cp flake.nix "${temp}/etc/nixos/flake.nix"
chmod 644 "${temp}/etc/nixos/flake.nix"

echo "🔧 Running nixos-anywhere..."
# Install NixOS to the host system with our secrets and flake
nix run github:nix-community/nixos-anywhere -- \
  --extra-files "$temp" \
  --flake ".#${HOSTNAME}" \
  --target-host "root@${IP_ADDRESS}"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "The system is now running with:"
echo "  - Flake configuration in /etc/nixos"
echo "  - Auto-update enabled for /etc/nixos flake"
echo ""
echo "To access the system:"
echo "  ssh root@${FQDN}"
echo ""
echo "To update the system:"
echo "  ssh root@${FQDN} 'cd /etc/nixos && nix flake update && nixos-rebuild switch --flake .'"
