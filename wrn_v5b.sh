#!/bin/bash
#
# wrn_v5.sh
# WRN cleanup + cron install
# Author: Bradford
#
# 
# Self-elevate, log to /var/log/system_cleanup.log
# fstab hardening & mount validation
# system log policy + rotation/junk cleanup
# WAVE Cleanup (logs, cores, caches)
# Install weekly cron (Mon 03:12) to run this script

set -euo pipefail
if [ "$EUID" -ne 0 ]; then exec sudo --preserve-env=PATH "$0" "$@"; fi

usage() {
cat <<'U'
wrn_v5b.sh - WRN one-shot hardening + WAVE/Nx maintenance

Default: v3 tasks + mediaserver audit/cleanup + install weekly cron (Mon 03:12).

Flags:
  --no-ms        Skip mediaserver audit/cleanup
  --no-cron      Skip cron installation
  --no-apt       Skip all apt/package operations
  --audit-only   Report only (no cleaning, no package changes, no cron)
  --help         Show this help
U
}

NO_MS=false
NO_CRON=false
NO_APT=false
AUDIT_ONLY=false
for arg in "$@"; do
  case "$arg" in
    --no-ms) NO_MS=true ;;
    --no-cron) NO_CRON=true ;;
    --no-apt) NO_APT=true ;;
    --audit-only) AUDIT_ONLY=true ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown flag: $arg"; usage; exit 1 ;;
  esac
done

LOGFILE="/var/log/system_cleanup.log"
exec > >(tee -a "$LOGFILE") 2>&1

# ---------------- Summary  ----------------
declare -a SUMMARY
add_summary(){ SUMMARY+=("$1"); }
print_summary() {
  echo "---------------- ACTION SUMMARY ----------------"
  for line in "${SUMMARY[@]}"; do
    printf " • %s\n" "$line"
  done
  echo "------------------------------------------------"
}

free_space_mb() { df --output=avail / | tail -n 1; }
free_space_human() { df -h / | awk 'NR==2 {print $4 " free of " $2}'; }

START_MB="$(free_space_mb)"
START_HUMAN="$(free_space_human)"
FSTAB_STATUS="UNKNOWN"
CRON_INSTALLED="no"
MS_SERVICE_DETECTED=""
MS_AUDIT_PATH=""
MS_LOGS_COMPRESSED=0
MS_LOGS_TRUNCATED=0
MS_CORES_PURGED=0
MS_CACHES_REMOVED=0
PKG_PURGED=0
SNAPS_REMOVED=0
BIG_LOGS_DELETED=0
RSYSLOG_RULE_SET="no"
JOURNAL_VACUUM_DONE="no"
LOGROTATE_FORCED="no"

finalize() {
# print a summary
  END_MB="$(free_space_mb)"
  END_HUMAN="$(free_space_human)"
  RECLAIMED_MB=$(( END_MB - START_MB ))
  echo "================================================"
  echo "Disk space before: ${START_HUMAN}"
  echo "Disk space after:  ${END_HUMAN}"
  echo "Space reclaimed:   ${RECLAIMED_MB} MB"
  echo "fstab status:      ${FSTAB_STATUS}"
  echo "Completed @        $(date)"
  echo "Log file:          ${LOGFILE}"
  echo "================================================"
  print_summary
}
trap finalize EXIT

echo "================================================"
echo "WRN v3 start @ $(date)"
echo "Disk space before: ${START_HUMAN}"
echo "Log: ${LOGFILE}"
echo "================================================"

MS_VAR_BASE="/opt/hanwha/mediaserver/var"
MS_DATA="${MS_VAR_BASE}/data"
MS_LOG="${MS_VAR_BASE}/log"

detect_ms_unit() {
  local u
  for u in hanwha-mediaserver.service networkoptix-mediaserver.service mediaserver.service; do
    if systemctl list-unit-files | grep -q "^${u}"; then
      echo "$u"; return 0
    fi
  done
  echo ""
}
ms_service="$(detect_ms_unit)"; MS_SERVICE_DETECTED="${ms_service:-none}"

ms_stop() { [ -n "$ms_service" ] && ( systemctl stop "$ms_service" || true ); }
ms_start(){ [ -n "$ms_service" ] && ( systemctl start "$ms_service" || true; systemctl --no-pager --full status "$ms_service" || true ); }

ms_audit() {
  local STAMP="$(date +%Y%m%d_%H%M%S)"
  local AUDIT_OUT="/var/log/wrn_wave_disk_audit_${STAMP}.log"
  MS_AUDIT_PATH="$AUDIT_OUT"
  echo "[ms] audit -> $AUDIT_OUT"
  {
    echo "==== WAVE/Nx Mediaserver Disk Audit @ ${STAMP} ===="
    echo "Unit: ${ms_service:-<unknown>}"
    echo
    echo "== df -hT =="; df -hT; echo
    echo "== df -ih =="; df -ih; echo
    echo "== ${MS_DATA} depth1 =="
    [ -d "$MS_DATA" ] && du -xh --max-depth=1 "$MS_DATA" | sort -h || echo "missing: $MS_DATA"
    echo
    echo "== ${MS_LOG} depth1 =="
    [ -d "$MS_LOG" ] && du -xh --max-depth=1 "$MS_LOG" | sort -h || echo "missing: $MS_LOG"
    echo
    echo "== Largest files >500M in ${MS_VAR_BASE} =="
    find "$MS_VAR_BASE" -type f -size +500M -printf "%p %k KB\n" 2>/dev/null | sort -nk2 | tail -n 50
    echo
    echo "== journalctl disk usage =="
    journalctl --disk-usage || true
  } | tee "$AUDIT_OUT"
  echo "[ms] audit saved: $AUDIT_OUT"
  add_summary "Mediaserver audit saved to ${AUDIT_OUT} (service: ${MS_SERVICE_DETECTED})"
}

ms_prune_logs() {
  echo "[ms] prune logs ${MS_LOG} ..."
  mkdir -p "$MS_LOG"
  local list_compress="$(mktemp)"
  find "$MS_LOG" -type f \( -name "*.log" -o -name "*.txt" \) -mtime +14 ! -name "*.gz" -print0 \
    | tee >(xargs -0 -I{} echo "{}" > "$list_compress") >/dev/null \
    | xargs -0 -I{} sh -c 'gzip -9 "{}" && echo "Compressed: {}"' || true
  # count compressed
  [ -s "$list_compress" ] && MS_LOGS_COMPRESSED=$(wc -l < "$list_compress") || MS_LOGS_COMPRESSED=0
  rm -f "$list_compress"

  # truncate oversized
  local list_trunc="$(mktemp)"
  while IFS= read -r f; do
    : > "$f"
    echo "$f" >> "$list_trunc"
    echo "[ms] truncated: $f"
  done < <(find "$MS_LOG" -type f \( -name "*.log" -o -name "*.txt" \) -size +200M -print)
  [ -s "$list_trunc" ] && MS_LOGS_TRUNCATED=$(wc -l < "$list_trunc") || MS_LOGS_TRUNCATED=0
  rm -f "$list_trunc"

  if [ ! -f /etc/logrotate.d/hanwha-mediaserver ]; then
    cat >/etc/logrotate.d/hanwha-mediaserver <<'ROT'
/opt/hanwha/mediaserver/var/log/*.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
ROT
    add_summary "Installed logrotate rule for mediaserver logs"
  fi
  logrotate -f /etc/logrotate.d/hanwha-mediaserver || true
  LOGROTATE_FORCED="yes"
  add_summary "Mediaserver logs: compressed ${MS_LOGS_COMPRESSED}, truncated ${MS_LOGS_TRUNCATED}"
}

ms_purge_cores() {
  echo "[ms] purge core/crash dumps older than 7d in ${MS_VAR_BASE} ..."
  MS_CORES_PURGED=$(find "$MS_VAR_BASE" -type f \( -name "core.*" -o -name "*.dmp" -o -name "*.core" \) -mtime +7 -print | wc -l || echo 0)
  find "$MS_VAR_BASE" -type f \( -name "core.*" -o -name "*.dmp" -o -name "*.core" \) -mtime +7 -print0 | xargs -0 rm -f -- || true
  add_summary "Purged ${MS_CORES_PURGED} old core/crash dump(s)"
}

ms_clean_cache() {
  echo "[ms] clean caches ${MS_DATA} ..."
  mkdir -p "$MS_DATA"
  local CANDIDATES=(
    "transcoder_cache" "thumbnail_cache" "thumbnails" "tmp" "temp" "cache" "export_cache" "exports/tmp" "ffmpeg_cache"
  )
  local removed=0
  for rel in "${CANDIDATES[@]}"; do
    local p="${MS_DATA}/${rel}"
    if [ -e "$p" ]; then rm -rf --one-file-system "$p"; echo "[ms] removed: $p"; removed=$((removed+1)); fi
  done
  MS_CACHES_REMOVED=$removed
  add_summary "Removed ${MS_CACHES_REMOVED} mediaserver cache folder(s) from ${MS_DATA}"
}

do_v3() {
  echo "[v3] fstab hardening + mounts ..."
  systemctl stop hanwha-mediaserver 2>/dev/null || true
  FSTAB_FILE="/etc/fstab"
  BACKUP_FILE="${FSTAB_FILE}.$(date +%Y%m%d_%H%M%S).bak"
  TARGET_MOUNT_POINTS=("/mnt/sda" "/mnt/sdb" "/mnt/sdc" "/mnt/sdd")
  cp -a "$FSTAB_FILE" "$BACKUP_FILE" || true
  add_summary "Backed up /etc/fstab -> ${BACKUP_FILE}"
  sed -i -E 's#^([[:space:]]*/dev/loop[0-9]+[[:space:]].*)#\# disabled by wrn_v5b: \1#' "$FSTAB_FILE" || true
  sed -i -E 's#^([[:space:]]*[^[:space:]]+[[:space:]]+/mnt/loop[0-9]+[[:space:]].*)#\# disabled by wrn_v5b: \1#' "$FSTAB_FILE" || true

  ROOT_SRC="$(findmnt -n / -o SOURCE)"
  ROOT_UUID="$(blkid -o value -s UUID "$ROOT_SRC" 2>/dev/null || true)"
  ROOT_PARENT="/dev/$(lsblk -no PKNAME "$ROOT_SRC" 2>/dev/null || true)"
  echo "[v3] root: $ROOT_SRC (UUID=$ROOT_UUID) parent=$ROOT_PARENT"
  for M in "${TARGET_MOUNT_POINTS[@]}"; do mkdir -p "$M"; done

  pick_first_partition() { local base="$1"; lsblk -nr -o NAME,TYPE "$base" 2>/dev/null | awk '$2=="part"{print "/dev/"$1; exit}'; }

  local mounted_count=0
  for M in "${TARGET_MOUNT_POINTS[@]}"; do
    echo "[v3] mountpoint: $M"
    base="/dev/$(basename "$M")"
    [ "$base" = "$ROOT_PARENT" ] && { echo "[v3] skip OS disk"; continue; }
    [ -b "$base" ] || { echo "[v3] skip: $base not present"; continue; }
    part="$(pick_first_partition "$base")"
    [ -n "$part" ] || { echo "[v3] skip: no partition on $base"; continue; }
    INFO="$(blkid -c /dev/null -o export "$part" 2>/dev/null || true)"
    [ -n "$INFO" ] || { echo "[v3] skip: no blkid for $part"; continue; }
    eval "$INFO"
    IDENT=""; [ -n "${UUID:-}" ] && IDENT="UUID=${UUID}" || { [ -n "${PARTUUID:-}" ] && IDENT="PARTUUID=${PARTUUID}"; }
    [ -n "$IDENT" ] || { echo "[v3] skip: no UUID/PARTUUID for $part"; continue; }
    [ -n "${ROOT_UUID:-}" ] && [ "${UUID:-}" = "$ROOT_UUID" ] && { echo "[v3] skip: root fs"; continue; }
    FSTYPE="${TYPE:-auto}"
    if ! awk -v mp="$M" '$0 !~ /^[[:space:]]*#/ && $2==mp {found=1} END{exit !found}' "$FSTAB_FILE"; then
      printf "%-22s %-12s %-8s %-20s %d %d\n" "$IDENT" "$M" "$FSTYPE" "defaults,nofail" 0 2 >> "$FSTAB_FILE"
    else
      tmp="$(mktemp)"; awk -v mp="$M" -v id="$IDENT" -v fs="$FSTYPE" '
        $0 ~ /^[[:space:]]*#/ { print; next }
        $2==mp { $1=id; $3=fs;
          n=split($4,a,","); has=0; for(i=1;i<=n;i++){ if(a[i]=="nofail") has=1 }
          if(!has) $4=$4",nofail"; gsub(/,,+/,",",$4); print; next }
        { print }' "$FSTAB_FILE" > "$tmp"; mv "$tmp" "$FSTAB_FILE"
    fi
    if mount "$M"; then mounted_count=$((mounted_count+1)); fi
  done

  if mount -a; then FSTAB_STATUS="SUCCESS"; else FSTAB_STATUS="FAILED"; fi
  add_summary "fstab hardened with UUIDs; validated mounts (mounted ${mounted_count} archive mount(s))"
  systemctl start hanwha-mediaserver 2>/dev/null || true

  echo "[v3] system log policy + rotation ..."
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
  RSYSLOG_RULE_SET="yes"
  add_summary "rsyslog size cap & rotation policy ensured"

  logrotate -f /etc/logrotate.conf || true
  LOGROTATE_FORCED="yes"
  journalctl --vacuum-size=1G || true
  JOURNAL_VACUUM_DONE="yes"
  BIG_LOGS_DELETED=$(find /var/log -type f -size +100M -printf '.' | wc -c | awk '{print $1+0}')
  find /var/log -type f -size +100M -exec rm -f {} \; 2>/dev/null || true
  add_summary "Forced logrotate; journal vacuumed to 1G; deleted ${BIG_LOGS_DELETED} big /var/log file(s)"

  if ! $AUDIT_ONLY && ! $NO_APT; then
    echo "[v3] package/junk cleanup ..."
    apt -y update || true
    # Count purges roughly by packages listed
    local to_purge=(libreoffice* thunderbird* aisleriot gnome-mahjongg gnome-mines gnome-sudoku cheese rhythmbox gnome-calculator shotwell bleachbit wireshark cups* printer-driver*)
    for p in "${to_purge[@]}"; do apt -y purge "$p" && PKG_PURGED=$((PKG_PURGED+1)) || true; done
    LANG_PKGS="$(dpkg -l | awk '/language-pack/ && $2 !~ /en/ {print $2}')" || true
    if [ -n "${LANG_PKGS:-}" ]; then apt -y purge $LANG_PKGS || true; fi

    for mountp in $(mount | awk '/\/snap\// {print $3}'); do umount "$mountp" 2>/dev/null && SNAPS_REMOVED=$((SNAPS_REMOVED+1)) || true; done
    rm -rf ~/"snap" /var/snap /var/lib/snapd /var/cache/snapd 2>/dev/null || true
    rm -rf /snap 2>/dev/null || true

    journalctl --vacuum-time=7d || true
    systemctl disable apport.service 2>/dev/null || true
    systemctl mask apport.service 2>/dev/null || true
    rm -rf /var/crash/* 2>/dev/null || true
    rm -rf /home/*/.local/share/Trash/* /home/*/.cache/thumbnails/* 2>/dev/null || true
    rm -rf ~/.local/share/Trash/* ~/.cache/thumbnails/* 2>/dev/null || true
    rm -f /home/wave/core 2>/dev/null || true

    apt -y autoremove --purge || true
    apt clean || true
    apt-get clean || true

    add_summary "Purged ${PKG_PURGED} package group(s); removed ${SNAPS_REMOVED} snap mount(s); cleared crash/trash caches"
  else
    add_summary "Package cleanup skipped (audit-only or --no-apt)"
  fi
}

do_ms() {
  $NO_MS && { add_summary "Mediaserver maintenance skipped (--no-ms)"; return; }
  echo "[ms] maintenance ..."
  [ -n "$ms_service" ] && add_summary "Other: ${ms_service}" || add_summary "Other service: Ok"
  ms_stop
  ms_audit
  if ! $AUDIT_ONLY; then
    ms_prune_logs
    ms_purge_cores
    ms_clean_cache
  else
    add_summary "Cleanup skipped"
  fi
  ms_start
}

install_cron() {
  $NO_CRON && { add_summary "Cron install skipped (--no-cron)"; return; }
  $AUDIT_ONLY && { add_summary "Cron install skipped (audit-only)"; return; }
  echo "[cron] installing weekly job (Mon 03:12) ..."
  if [ "$0" != "/root/wrn_v5b.sh" ]; then
    cp -f "$0" /root/wrn_v5b.sh
    chmod 755 /root/wrn_v5b.sh
  fi
  tmpc="$(mktemp)"
  crontab -l 2>/dev/null | grep -v 'wrn_v5b.sh' > "$tmpc" || true
  echo '12 3 * * 1 /usr/bin/bash /root/wrn_v5b.sh >> /var/log/system_cleanup.log 2>&1' >> "$tmpc"
  crontab "$tmpc"
  rm -f "$tmpc"
  CRON_INSTALLED="yes"
  add_summary "Installed weekly cron: 03:12 Monday → /root/wrn_v5b.sh"
}

# Execute
do_v3
do_ms
install_cron
exit 0
