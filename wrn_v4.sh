#!/bin/bash
#
# Script: wrn_v4.sh  (standalone, test-ready)
# Purpose: WRN boot fix & cleanup + PERSISTENT data-disk mounts via /etc/fstab (UUID)
# Author: Bradford & Troy — v4 test build
# Date: 2025-11-02
#
# Key behavior:
#  - Backs up /etc/fstab with timestamp
#  - Detects non-OS partitions (skips /, /boot, /boot/efi, swap, loop)
#  - Creates mountpoints under /mnt/<label-or-uuid>
#  - Writes idempotent, UUID-based fstab lines (defaults,nofail,x-systemd.device-timeout=10)
#  - Validates with systemd-analyze verify (if available) and mount -a
#  - Restores fstab on failure
#  - Optional conditional reboot with --reboot-if-needed
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  exec sudo --preserve-env=PATH "$0" "$@"
fi

# ---------- Logging ----------
LOGFILE="/var/log/system_cleanup.log"
mkdir -p "$(dirname "$LOGFILE")"
exec > >(tee -a "$LOGFILE") 2>&1

echo "------------------------------------------------"
echo "Starting WRN v4 persistence + cleanup at: $(date)"
echo "Hostname: $(hostname)  Kernel: $(uname -r)"
echo "Log file: $LOGFILE"
echo "------------------------------------------------"

# ---------- Helpers ----------
timestamp() { date +%Y%m%d_%H%M%S; }
free_space_mb() { df -Pm / | awk 'NR==2{print $4}'; }
free_space_human() { df -Ph / | awk 'NR==2{print $4" free of "$2}'; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

START_MB="$(free_space_mb)"
START_HUMAN="$(free_space_human)"
echo "Disk space before cleanup: ${START_HUMAN}"

# ---------- Identify OS mounts to protect ----------
ROOT_DEV="$(findmnt -no SOURCE / || true)"
echo "Root device: ${ROOT_DEV}"

# Build maps from blkid
declare -A UUID_OF FSTYPE_OF LABEL_OF
while IFS= read -r line; do
  dev="${line%%:*}"
  uuid="$(echo "$line" | sed -n 's/.*UUID="\([^"]*\)".*/\1/p')"
  fstype="$(echo "$line" | sed -n 's/.*TYPE="\([^"]*\)".*/\1/p')"
  label="$(echo "$line" | sed -n 's/.*LABEL="\([^"]*\)".*/\1/p')"
  [[ -n "$uuid" ]] && UUID_OF["$dev"]="$uuid"
  [[ -n "$fstype" ]] && FSTYPE_OF["$dev"]="$fstype"
  [[ -n "$label" ]] && LABEL_OF["$dev"]="$label"
done < <(blkid)

# Candidate partitions: sd*/nvme*/vd* parts only
mapfile -t CANDIDATES < <(
  lsblk -rpno NAME,TYPE | awk '$2=="part"{print $1}' \
  | grep -E '^/dev/(sd|nvme|vd)' || true
)

# OS mounts & swap devices (to skip)
OS_MOUNTS="$(awk '($2=="/" || $2=="/boot" || $2=="/boot/efi"){print $1}' /proc/mounts)"
SWAP_DEVICES="$(awk '$3=="swap"{print $1}' /proc/swaps | tail -n +2 || true)"

echo "OS mounts to protect: ${OS_MOUNTS}"
echo "Swap devices: ${SWAP_DEVICES}"

# ---------- Back up fstab ----------
FSTAB="/etc/fstab"
FSTAB_BAK="/etc/fstab.$(timestamp).bak"
cp -a "$FSTAB" "$FSTAB_BAK"
echo "[fstab] Backup created: $FSTAB_BAK"

changed=0

persist_partition() {
  local dev="$1" uuid fstype label mp base

  [[ "$dev" == /dev/loop* ]] && return 0

  if echo "$OS_MOUNTS" | grep -qF "$dev"; then
    echo "[skip] $dev — belongs to OS mount"
    return 0
  fi
  if echo "$SWAP_DEVICES" | grep -qF "$dev"; then
    echo "[skip] $dev — swap device"
    return 0
  fi

  uuid="${UUID_OF[$dev]:-}"
  fstype="${FSTYPE_OF[$dev]:-ext4}"
  label="${LABEL_OF[$dev]:-}"

  if [[ -z "$uuid" ]]; then
    echo "[warn] $dev has no UUID (maybe LVM/RAID/crypto). Skipping."
    return 0
  fi

  # Determine mountpoint name
  if [[ -n "$label" ]]; then base="$label"; else base="$uuid"; fi
  base="$(echo "$base" | tr -cd '[:alnum:]_-')"
  [[ -z "$base" ]] && base="$uuid"
  mp="/mnt/$base"

  mkdir -p "$mp"

  # Remove any existing line for this UUID or mountpoint
  if grep -qE "UUID=$uuid|[[:space:]]$mp[[:space:]]" "$FSTAB"; then
    echo "[fstab] Removing old entries for UUID=$uuid or mp=$mp"
    sed -i "\|UUID=$uuid|d;\|[[:space:]]$mp[[:space:]]|d" "$FSTAB"
  fi

  # Safe options
  opts="defaults,nofail,x-systemd.device-timeout=10"

  printf "UUID=%s %s %s %s 0 2\n" "$uuid" "$mp" "$fstype" "$opts" >> "$FSTAB"
  echo "[fstab] Added: UUID=$uuid -> $mp ($fstype,$opts)"
  changed=1
}

for dev in "${CANDIDATES[@]}"; do
  if [[ -n "${FSTYPE_OF[$dev]:-}" ]]; then
    persist_partition "$dev"
  else
    echo "[skip] $dev — no filesystem (maybe raw/LVM PV)"
  fi
done

# ---------- Validate & mount ----------
echo "Validating /etc/fstab…"
if has_cmd systemd-analyze; then
  if ! systemd-analyze verify "$FSTAB"; then
    echo "[ERROR] systemd-analyze found issues in fstab. Restoring backup and aborting."
    cp -a "$FSTAB_BAK" "$FSTAB"
    exit 1
  fi
else
  echo "[note] systemd-analyze not found; skipping structural verification."
fi

echo "Testing mounts with mount -a…"
if ! mount -a; then
  echo "[ERROR] 'mount -a' failed. Restoring fstab backup and aborting."
  cp -a "$FSTAB_BAK" "$FSTAB"
  exit 1
fi

echo "Mounts after update:"
findmnt -rno TARGET,SOURCE,FSTYPE,OPTIONS | sed 's/^/  /'

# ---------- Light cleanup ----------
echo "Running light package cleanup…"
apt-get autoremove --purge -y || true
apt-get clean || true

END_MB="$(free_space_mb)"
END_HUMAN="$(free_space_human)"
RECLAIMED_MB=$(( END_MB - START_MB ))

echo "------------------------------------------------"
echo "Disk space after cleanup: ${END_HUMAN}"
echo "Space reclaimed: ${RECLAIMED_MB} MB"
echo "FSTAB backup: $FSTAB_BAK"
echo "Changed flag: $changed"
echo "Completed at: $(date)"
echo "------------------------------------------------"

# ---------- Optional reboot ----------
if [[ "${1:-}" == "--reboot-if-needed" ]]; then
  if [[ "$changed" -eq 1 ]]; then
    echo "[info] Rebooting to confirm boot-time mounts…"
    reboot
  else
    echo "[info] No fstab changes; skipping reboot."
  fi
fi
