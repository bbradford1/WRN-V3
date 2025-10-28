#!/bin/bash
#
# Script: wrn_v3.sh
# Purpose: WRN Boot fix and cleanup + fstab UUID
# Author: Bradford and Troy 
# Date: 2025-10-16
#
if [ "$EUID" -ne 0 ]; then
  exec sudo --preserve-env=PATH "$0" "$@"
fi

set -euo pipefail

LOGFILE="/var/log/system_cleanup.log"
exec > >(tee -a "$LOGFILE") 2>&1

spin() {
  local pid=$!
  local delay=0.15
  local spinstr='|/-\'
  while kill -0 $pid 2>/dev/null; do
    local temp=${spinstr#?}
    printf " [%c]  " "$spinstr"
    spinstr=$temp${spinstr%"$temp"}
    sleep $delay
    printf "\b\b\b\b\b\b"
  done
  printf "      \b\b\b\b\b\b"
}

free_space_mb() { df --output=avail / | tail -n 1; }
free_space_human() { df -h / | awk 'NR==2 {print $4 " free of " $2}'; }

START_MB="$(free_space_mb)"
START_HUMAN="$(free_space_human)"
echo "------------------------------------------------"
echo "Starting WRN fstab + cleanup (Fix2) at $(date)"
echo "Disk space before cleanup: ${START_HUMAN}"
echo "Log file: ${LOGFILE}"
echo "------------------------------------------------"

FSTAB_STATUS="UNKNOWN"
{
  systemctl stop hanwha-mediaserver 2>/dev/null || true

  FSTAB_FILE="/etc/fstab"
  BACKUP_FILE="${FSTAB_FILE}.$(date +%Y%m%d_%H%M%S).bak"
  TARGET_MOUNT_POINTS=("/mnt/sda" "/mnt/sdb" "/mnt/sdc" "/mnt/sdd")

  echo "[fstab] backing up ${FSTAB_FILE} -> ${BACKUP_FILE}"
  cp -a "$FSTAB_FILE" "$BACKUP_FILE"

  
  if grep -E '(^[[:space:]]*/dev/loop|[[:space:]]+/mnt/loop)' "$FSTAB_FILE" >/dev/null 2>&1; then
    echo "[fstab] commenting stale loop entries in fstab to prevent mount -a errors ..."
    sed -i -E 's#^([[:space:]]*/dev/loop[0-9]+[[:space:]].*)#\# disabled by wrn_v2_merged_fix2: \1#' "$FSTAB_FILE"
    sed -i -E 's#^([[:space:]]*[^[:space:]]+[[:space:]]+/mnt/loop[0-9]+[[:space:]].*)#\# disabled by wrn_v2_merged_fix2: \1#' "$FSTAB_FILE"
  fi

  # Root UUID to avoid double-mounting the OS disk elsewhere
  ROOT_SRC="$(findmnt -n / -o SOURCE)"
  ROOT_UUID="$(blkid -o value -s UUID "$ROOT_SRC" 2>/dev/null || true)"
  ROOT_PARENT="/dev/$(lsblk -no PKNAME "$ROOT_SRC" 2>/dev/null || true)"
  echo "[fstab] root device: $ROOT_SRC (UUID=$ROOT_UUID) parent=$ROOT_PARENT"

  # Ensure mountpoint dirs exist
  for MOUNT_POINT in "${TARGET_MOUNT_POINTS[@]}"; do
    mkdir -p "$MOUNT_POINT"
  done

  # Helper: given /dev/sdX, pick first partition (e.g., /dev/sdX1) if present
  pick_first_partition() {
    local base="$1"
    lsblk -nr -o NAME,TYPE "$base" 2>/dev/null | awk '$2=="part"{print "/dev/"$1; exit}'
  }

  # Map /mnt/sdX -> /dev/sdX -> /dev/sdX1 (or first partition)
  for MOUNT_POINT in "${TARGET_MOUNT_POINTS[@]}"; do
    echo "--------------------------------------------------------"
    echo "[fstab] Processing $MOUNT_POINT"

    base="$(basename "$MOUNT_POINT")"        # sda/sdb/sdc/sdd
    dev="/dev/${base}"                       # /dev/sda
    if [ "$dev" = "$ROOT_PARENT" ]; then
      echo "[fstab] SKIP: $dev is the OS disk parent; not used for data mount."
      continue
    fi
    if [ ! -b "$dev" ]; then
      echo "[fstab] SKIP: $dev does not exist."
      continue
    fi

    part="$(pick_first_partition "$dev")"
    if [ -z "$part" ]; then
      echo "[fstab] SKIP: no partition found on $dev (expected something like ${dev}1)."
      continue
    fi
    echo "[fstab] chosen partition: $part"

    INFO="$(blkid -c /dev/null -o export "$part" 2>/dev/null || true)"
    if [ -z "$INFO" ]; then
      echo "[fstab] SKIP: blkid returned no info for $part"
      continue
    fi
    eval "$INFO"  # sets UUID=, TYPE=, PARTUUID=, etc.

    IDENT=""
    if [ -n "${UUID:-}" ]; then
      IDENT="UUID=${UUID}"
    elif [ -n "${PARTUUID:-}" ]; then
      IDENT="PARTUUID=${PARTUUID}"
    else
      echo "[fstab] SKIP: neither UUID nor PARTUUID available for $part"
      continue
    fi

    if [ -n "${ROOT_UUID:-}" ] && [ "${UUID:-}" = "$ROOT_UUID" ]; then
      echo "[fstab] SKIP: resolved UUID equals root filesystem UUID; not mounting OS disk again."
      continue
    fi

    FSTYPE="${TYPE:-auto}"
    echo "[fstab] using identifier: $IDENT (TYPE=$FSTYPE)"

    # Create/update the fstab row for this mount point
    if ! awk -v mp="$MOUNT_POINT" '$0 !~ /^[[:space:]]*#/ && $2==mp {found=1} END{exit !found}' "$FSTAB_FILE"; then
      echo "[fstab] adding new row for $MOUNT_POINT"
      printf "%-22s %-12s %-8s %-20s %d %d\n" "$IDENT" "$MOUNT_POINT" "$FSTYPE" "defaults,nofail" 0 2 >> "$FSTAB_FILE"
    else
      tmp="$(mktemp)"
      awk -v mp="$MOUNT_POINT" -v id="$IDENT" -v fs="$FSTYPE" '
        $0 ~ /^[[:space:]]*#/ { print; next }
        $2==mp {
          $1=id; $3=fs;
          # ensure nofail in options
          n=split($4, a, ","); has=0;
          for(i=1;i<=n;i++){ if(a[i]=="nofail") has=1 }
          if (!has) $4=$4",nofail";
          gsub(/,,+/,",",$4);
          print; next
        }
        { print }
      ' "$FSTAB_FILE" > "$tmp"
      mv "$tmp" "$FSTAB_FILE"
    fi

    # Validate this mount point only
    echo "[fstab] validating mount for $MOUNT_POINT"
    if mount "$MOUNT_POINT"; then
      echo "[fstab] ✅ mounted $MOUNT_POINT"
    else
      echo "[fstab] ❌ failed to mount $MOUNT_POINT"
    fi
  done

  echo "[fstab] final validation: mount -a"
  if mount -a; then
    echo "[fstab] ✅ mount -a succeeded."
    FSTAB_STATUS="SUCCESS"
  else
    echo "[fstab] ❌ mount -a reported errors. Check above. Backup: $BACKUP_FILE"
    FSTAB_STATUS="FAILED"
  fi

  systemctl start hanwha-mediaserver 2>/dev/null || true
} || {
  echo "[fstab] ❌ exception during fstab update."
  FSTAB_STATUS="FAILED"
}

# ----------------- Cleanup Drive -----------------
echo "[*] Configuring log rotation and outchannel ..."
if [ ! -f /etc/logrotate.d/rsyslog ]; then
  touch /etc/logrotate.d/rsyslog
  chown root:root /etc/logrotate.d/rsyslog
else
  : > /etc/logrotate.d/rsyslog
  chown root:root /etc/logrotate.d/rsyslog
fi

cat >/etc/logrotate.d/rsyslog <<'EOL'
su root syslog
/var/log/kern.log
/var/log/syslog
{
    rotate 2
    daily
    size 350M
    missingok
    notifempty
    delaycompress
    compress
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOL

if ! grep -q '\$outchannel mysyslog,/var/log/syslog,367001600' /etc/rsyslog.d/50-default.conf 2>/dev/null; then
  sed -i '/\*\.\*;auth,authpriv\.none/i \$outchannel mysyslog,/var/log/syslog,367001600' /etc/rsyslog.d/50-default.conf
fi
sed -i "s|\*\.\*;auth,authpriv\.none[[:space:]]*-\/var\/log\/syslog|*\.\*;auth,authpriv\.none          :omfile:\$mysyslog|" /etc/rsyslog.d/50-default.conf || true

chown -R root:root /etc
chown -R root:root /system 2>/dev/null || true

echo "[*] Forcing log rotation and journal vacuum..."
logrotate -f /etc/logrotate.conf || true
journalctl --vacuum-size=1G || true

echo "[*] Deleting logs >100MB..."
find /var/log -type f -size +100M -exec rm -f {} \; 2>/dev/null || true

systemctl enable logrotate.service 2>/dev/null || true
systemctl restart logrotate.service 2>/dev/null || true
sync

echo "[*] App & cache cleanup ..."
apt update
apt purge -y libreoffice* thunderbird* aisleriot gnome-mahjongg gnome-mines gnome-sudoku cheese rhythmbox gnome-calculator shotwell bleachbit wireshark || true
apt purge -y cups* printer-driver* || true

LANG_PKGS="$(dpkg -l | awk '/language-pack/ && $2 !~ /en/ {print $2}')"
if [ -n "$LANG_PKGS" ]; then
  apt purge -y $LANG_PKGS || true
fi

for mountp in $(mount | awk '/\/snap\// {print $3}'); do
  ( umount "$mountp" 2>/dev/null || true ) & spin
done

rm -rf ~/"snap" /var/snap /var/lib/snapd /var/cache/snapd 2>/dev/null || true
rm -rf /snap 2>/dev/null || echo "[!] Skipped /snap (read-only)"

rm -rf /var/log/*.gz /var/log/*.[0-9] 2>/dev/null || true
journalctl --vacuum-time=7d || true

systemctl disable apport.service 2>/dev/null || true
systemctl mask apport.service 2>/dev/null || true
rm -rf /var/crash/* 2>/dev/null || true

rm -rf /home/*/.local/share/Trash/* /home/*/.cache/thumbnails/* 2>/dev/null || true
rm -rf ~/.local/share/Trash/* ~/.cache/thumbnails/* 2>/dev/null || true
rm -f /home/wave/core 2>/dev/null || true

apt autoremove --purge -y || true
apt clean || true
apt-get clean || true

END_MB="$(free_space_mb)"
END_HUMAN="$(free_space_human)"
RECLAIMED_MB=$(( END_MB - START_MB ))

echo "------------------------------------------------"
echo "Disk space after cleanup: ${END_HUMAN}"
echo "Space reclaimed: ${RECLAIMED_MB} MB"
echo "fstab process status: ${FSTAB_STATUS}"
echo "Completed at: $(date)"
echo "------------------------------------------------"
