#!/bin/bash
# WRN installer v2 (TEST-FRIENDLY)
# - Installs a *test* copy of the persistence script at /usr/local/sbin/wrn_v3_test.sh
# - Leaves your existing /usr/local/sbin/wrn_v3.sh untouched
# - You can pass through flags to the script (e.g., --reboot-if-needed)
# - Use --live to install as wrn_v3.sh instead (optional)

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  sudo bash wrn_installer_v2.sh [--reboot-if-needed] [--live]

Default behavior:
  - Installs to /usr/local/sbin/wrn_v3_test.sh (does NOT overwrite your live script)
  - Runs the test script and passes through any extra flags

Optional:
  --live   Install as /usr/local/sbin/wrn_v3.sh (backs up any existing file)
USAGE
}

INSTALL_LIVE=0
EXTRA_ARGS=()

for arg in "$@"; do
  case "$arg" in
    --live) INSTALL_LIVE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) EXTRA_ARGS+=("$arg") ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  # Re-run as root, preserving common env
  exec sudo --preserve-env=PATH,BASHOPTS,SHELLOPTS /bin/bash -c "$0 $*"
fi

mkdir -p /usr/local/sbin
umask 022

if [[ "$INSTALL_LIVE" -eq 1 ]]; then
  dest="/usr/local/sbin/wrn_v3.sh"
  backup_suffix="$(date +%Y%m%d_%H%M%S)"
  if [[ -f "$dest" ]]; then
    cp -a "$dest" "${dest}.bak.${backup_suffix}"
    echo "[installer] Backed up existing $dest -> ${dest}.bak.${backup_suffix}"
  fi
else
  dest="/usr/local/sbin/wrn_v3_test.sh"
fi

log="/var/log/system_cleanup.log"

cat > "$dest" <<"EOF_WRN_V3"
#!/bin/bash
#
# Script: wrn_v3.sh  (revised, testable)
# Purpose: WRN boot fix & cleanup + PERSISTENT data-disk mounts via /etc/fstab (UUID)
# Behavior:
#  - Backs up /etc/fstab
#  - Detects non-OS block devices/partitions
#  - Creates mountpoints under /mnt/<label-or-uuid>
#  - Writes idempotent, UUID-based fstab lines with safe options
#  - Validates fstab and mounts now; optionally reboots ONLY if all checks pass
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  exec sudo --preserve-env=PATH "$0" "$@"
fi

LOGFILE="/var/log/system_cleanup.log"
mkdir -p "$(dirname "$LOGFILE")"
exec > >(tee -a "$LOGFILE") 2>&1

echo "------------------------------------------------"
echo "Starting WRN persistence + cleanup at: $(date)"
echo "Hostname: $(hostname)  Kernel: $(uname -r)"
echo "Log file: $LOGFILE"
echo "------------------------------------------------"

timestamp() { date +%Y%m%d_%H%M%S; }
free_space_mb() { df -Pm / | awk 'NR==2{print $4}'; }
free_space_human() { df -Ph / | awk 'NR==2{print $4" free of "$2}'; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

START_MB="$(free_space_mb)"
START_HUMAN="$(free_space_human)"
echo "Disk space before cleanup: ${START_HUMAN}"

ROOT_DEV="$(findmnt -no SOURCE / || true)"
echo "Root device: ${ROOT_DEV}"

declare -A UUID_OF DEV_OF FSTYPE_OF LABEL_OF
while IFS= read -r line; do
  dev="${line%%:*}"
  uuid="$(echo "$line" | sed -n 's/.*UUID="\([^"]*\)".*/\1/p')"
  fstype="$(echo "$line" | sed -n 's/.*TYPE="\([^"]*\)".*/\1/p')"
  label="$(echo "$line" | sed -n 's/.*LABEL="\([^"]*\)".*/\1/p')"
  [[ -n "$uuid" ]] && UUID_OF["$dev"]="$uuid"
  [[ -n "$fstype" ]] && FSTYPE_OF["$dev"]="$fstype"
  [[ -n "$label" ]] && LABEL_OF["$dev"]="$label"
  DEV_OF["$dev"]="$dev"
done < <(blkid)

mapfile -t CANDIDATES < <(
  lsblk -rpno NAME,TYPE | awk '$2=="part"{print $1}' \
  | grep -E '^/dev/(sd|nvme|vd)' || true
)

OS_MOUNTS="$(awk '($2=="/" || $2=="/boot" || $2=="/boot/efi"){print $1}' /proc/mounts)"
SWAP_DEVICES="$(awk '$3=="swap"{print $1}' /proc/swaps | tail -n +2 || true)"

echo "OS mounts to protect: ${OS_MOUNTS}"
echo "Swap devices: ${SWAP_DEVICES}"

FSTAB="/etc/fstab"
FSTAB_BAK="/etc/fstab.$(timestamp).bak"
cp -a "$FSTAB" "$FSTAB_BAK"
echo "[fstab] Backup created: $FSTAB_BAK"

changed=0

persist_partition() {
  local dev="$1"
  local uuid fstype label mp base

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

  if [[ -n "$label" ]]; then base="$label"; else base="$uuid"; fi
  base="$(echo "$base" | tr -cd '[:alnum:]_-')"
  [[ -z "$base" ]] && base="$uuid"
  mp="/mnt/$base"

  mkdir -p "$mp"

  if grep -qE "UUID=$uuid|[[:space:]]$mp[[:space:]]" "$FSTAB"; then
    echo "[fstab] Removing old entries for UUID=$uuid or mp=$mp"
    sed -i "\|UUID=$uuid|d;\|[[:space:]]$mp[[:space:]]|d" "$FSTAB"
  fi

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

if [[ "${1:-}" == "--reboot-if-needed" ]]; then
  if [[ "$changed" -eq 1 ]]; then
    echo "[info] Rebooting to confirm boot-time mounts…"
    reboot
  else
    echo "[info] No fstab changes; skipping reboot."
  fi
fi
EOF_WRN_V3

chmod 0755 "$dest"
echo "[installer] Installed $dest"
echo "[installer] Log: $log"

# Execute the installed script, passing any extra args (e.g., --reboot-if-needed)
exec "$dest" "${EXTRA_ARGS[@]}"
