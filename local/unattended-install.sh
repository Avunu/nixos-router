#!/usr/bin/env bash
set -euo pipefail

# ════════════════════════════════════════════════════════════════════════════
#  Unattended NixOS Router install via disko-install (offline).
#
#  This script runs on tty1 from the installer ISO. It partitions, formats, and
#  installs the router by re-evaluating the self-contained flake shipped on the
#  ISO at /etc/installer-flake. Every flake input and the prebuilt system
#  closure are baked into the ISO, so disko-install runs WITHOUT network.
#
#  Parameters are injected by the systemd unit's `environment` (see build-iso.sh):
#    routerHostname — flake attribute (nixosConfigurations.<name>) to install
#    routerDisk     — target block device (e.g. /dev/sda) — ALL DATA WIPED
#    routerDiskName — disko disk name to map (--disk <name> <device>)
# ════════════════════════════════════════════════════════════════════════════

FLAKE_ATTR="${routerHostname:?routerHostname not set}"
DISK_DEVICE="${routerDisk:?routerDisk not set}"
DISK_NAME="${routerDiskName:-main}"

# ── Prompt helper ───────────────────────────────────────
# wait_for_enter: counts down $timeout seconds.
# Returns 0 if the user pressed Enter, 1 if the countdown expired.
wait_for_enter() {
    local msg="$1" timeout="$2" prompt="$3"
    [ -n "$msg" ] && echo "$msg"
    for i in $(seq "$timeout" -1 1); do
        printf "\r  %2d s — %s " "$i" "$prompt"
        if read -r -t 1; then
            echo ""
            return 0
        fi
    done
    echo ""
    return 1
}

echo "=============================================="
echo " AUTOMATED NIXOS ROUTER INSTALL (disko-install)"
echo " Hostname : ${FLAKE_ATTR}"
echo " Disk     : ${DISK_DEVICE}  (ALL DATA WILL BE WIPED)"
echo "=============================================="

if [ ! -b "$DISK_DEVICE" ]; then
    echo "ERROR: target disk ${DISK_DEVICE} not found (not a block device)."
    echo "       Adjust router.diskDevice in local/flake.nix and rebuild the ISO."
    exit 1
fi

# ── Safety: existing installation detection ─────────────
# The disko layout stamps known GPT/filesystem labels: ESP (UEFI), boot (legacy),
# and root (both). Presence of any of them means the disk is already provisioned.
# If a bootloader is also present, default to RESUMING the normal boot and offer
# a 10 s window to force a fresh wipe — this lets the ISO stay in the boot order
# without re-imaging on every power cycle.
if [ -b "/dev/disk/by-label/ESP" ] || \
   [ -b "/dev/disk/by-label/boot" ] || \
   [ -b "/dev/disk/by-label/root" ]; then
    echo "Found existing partition labels — probing for a bootloader..."
    HAVE_LOADER=0
    mkdir -p /tmp/probe-boot
    for lbl in ESP boot; do
        if [ -b "/dev/disk/by-label/$lbl" ] && \
           mount -o ro "/dev/disk/by-label/$lbl" /tmp/probe-boot 2>/dev/null; then
            # systemd-boot (UEFI), removable EFI fallback, or GRUB (legacy/EFI).
            [ -f /tmp/probe-boot/EFI/systemd/systemd-bootx64.efi ] && HAVE_LOADER=1
            [ -f /tmp/probe-boot/EFI/BOOT/BOOTX64.EFI ]            && HAVE_LOADER=1
            [ -d /tmp/probe-boot/loader ]                          && HAVE_LOADER=1
            [ -d /tmp/probe-boot/grub ]                            && HAVE_LOADER=1
            umount /tmp/probe-boot 2>/dev/null || true
        fi
    done

    if [ "$HAVE_LOADER" = "1" ]; then
        echo ""
        echo "  Existing installation with bootloader detected on ${DISK_DEVICE}."
        echo "  Defaulting to RESUME NORMAL BOOT."
        echo ""
        if ! wait_for_enter "  Press Enter within 10 s to WIPE and force a fresh install." 10 \
            "press Enter to force fresh install, or wait to resume normal boot..."; then
            echo "No input received — resuming normal boot."
            exit 0
        fi
        echo "Fresh install confirmed — proceeding."
    else
        wait_for_enter "  Labels found but no bootloader — installing in 10 s. Press Ctrl+C to abort." 10 \
            "press Enter to install now, Ctrl+C to abort..." || true
    fi
else
    echo "No existing installation detected."
    wait_for_enter "  Installing in 10 s — press Ctrl+C to abort." 10 \
        "press Enter to install now, Ctrl+C to abort..." || true
fi

# ── EFI boot entries ────────────────────────────────────
# Write NVRAM boot entries only when the ISO booted in UEFI mode (matches the
# firmware the appliance will boot with). This also keeps the installed system's
# toplevel identical to the one prebuilt on the ISO — disko-install then realizes
# it from the local store instead of trying to build it offline:
#   • UEFI boot  → --write-efi-boot-entries → canTouchEfiVariables = true
#   • legacy/BIOS → omit                     → canTouchEfiVariables = false
efi_args=()
if [ -d /sys/firmware/efi ]; then
    echo ":: UEFI firmware detected — EFI boot entries will be written."
    efi_args+=(--write-efi-boot-entries)
else
    echo ":: Legacy/BIOS firmware detected — installing GRUB to ${DISK_DEVICE}."
fi

echo ":: Starting disko-install (offline)..."

# disko-install: partition + format + install in one step. It re-evaluates the
# self-contained flake at /etc/installer-flake; all inputs and the prebuilt
# system closure live on the ISO, so no network is required.
#
# The user's flake.nix/flake.lock are seeded into the installed system's
# /etc/nixos so the appliance can `nixos-rebuild` later.
disko-install \
    --flake "/etc/installer-flake#${FLAKE_ATTR}" \
    --disk "${DISK_NAME}" "${DISK_DEVICE}" \
    "${efi_args[@]}" \
    --extra-files /etc/installer-flake/local-config/flake.nix etc/nixos/flake.nix \
    --extra-files /etc/installer-flake/local-config/flake.lock etc/nixos/flake.lock

echo "=============================================="
echo " Installation complete! Rebooting in 5 s..."
echo "=============================================="
sleep 5
reboot
