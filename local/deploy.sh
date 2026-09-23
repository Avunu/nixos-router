#!/usr/bin/env bash
# Install a router over SSH with nixos-anywhere, from this directory's host flake.
#
#   ./deploy.sh [FQDN] [IP]
#
# The target's /etc/nixos gets everything the host flake needs to rebuild
# itself after the install: flake.nix, flake.lock (so it starts on exactly the
# inputs it was installed from) and router-settings.json, which flake.nix reads
# and Cockpit edits.
set -euo pipefail

# The flake and its settings sit beside this script; work from here whatever
# directory it was started from.
cd "$(dirname "$(readlink -f "$0")")"

# Parse arguments
FQDN="${1:-258-router.local}"
IP_ADDRESS="${2:-10.58.1.97}"

for f in flake.nix router-settings.json; do
  [ -f "$f" ] || { echo "error: $(pwd)/$f is missing" >&2; exit 1; }
done

# flake.nix names the configuration after hostName in router-settings.json, so
# that — not the FQDN argument — is the attribute to build.
HOSTNAME=$(nix eval --raw --impure --expr '(builtins.fromJSON (builtins.readFile ./router-settings.json)).hostName')
if [ "${FQDN%%.*}" != "$HOSTNAME" ]; then
  echo "warning: router-settings.json names this router '$HOSTNAME', not '${FQDN%%.*}'" >&2
fi

echo "🚀 Deploying router $HOSTNAME to $IP_ADDRESS ($FQDN)"
echo ""

# Staging tree for the files nixos-anywhere copies onto the target.
temp=$(mktemp -d)

# Function to cleanup temporary directory on exit
cleanup() {
  rm -rf "$temp"
}
trap cleanup EXIT

echo "📋 Staging /etc/nixos (flake.nix, flake.lock, router-settings.json)..."
mkdir -p "${temp}/etc/nixos"
install -m 644 flake.nix "${temp}/etc/nixos/flake.nix"
[ -f flake.lock ] && install -m 644 flake.lock "${temp}/etc/nixos/flake.lock"
install -m 644 router-settings.json "${temp}/etc/nixos/router-settings.json"

echo "🔧 Running nixos-anywhere..."
nix run github:nix-community/nixos-anywhere -- \
  --extra-files "$temp" \
  --flake ".#${HOSTNAME}" \
  --target-host "root@${IP_ADDRESS}"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "The router's configuration is in /etc/nixos; manage it from Cockpit"
echo "(https://${FQDN}:9090) or by editing /etc/nixos/router-settings.json."
echo ""
echo "To access the system:"
echo "  ssh root@${FQDN}"
echo ""
echo "To upgrade it now (it also upgrades nightly):"
echo "  ssh root@${FQDN} system-upgrade"
