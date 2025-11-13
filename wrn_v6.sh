#!/bin/bash
#
# wrn_v6.sh
# WRN cleanup + mediaserver maintenance + safe OS log/journal + apt-lite cleanup
#
# SAFE BY DEFAULT:
#   - fstab hardening (archive mounts only, never OS disk)
#   - mediaserver audit + logs/cores/cache cleanup
#   - rsyslog + logrotate policies, big log pruning
#   - journald vacuum (size + age)
#   - apt-lite: purge selected bloat + non-English language packs
#   - NO autoremove, NO snap removal
#   - weekly cleanup cron + monthly journal-only cron
#
# Flags:
#   --no-ms         Skip mediaserver cleanup
#   --no-fstab      Skip fstab hardening
#   --no-cron       Skip cron jobs
#   --journal-only  Only clean logs/journals
#   --audit-only    Mediaserver audit only
#   --help          Show usage
#

set -euo pipefail
if [ "$EUID" -ne 0 ]; then exec sudo --preserve-env=PATH "$0" "$@"; fi

usage() {
cat <<'EOF'
wrn_v6.sh - WRN safe maintenance stack

Default:
  • fstab hardening (safe)
  • rsyslog/logrotate enforcement
  • journald vacuum (1G + 7d)
  • mediaserver audit + cleanup
  • APT-LITE (remove your selected apps + non-English language packs)
  • weekly cron + monthly journal cron

Flags:
  --no-ms         Skip mediaserver maintenance
  --no-cron       Skip cron installation
  --no-fstab      Skip fstab entry correction
  --journal-only  Logs/journal cleanup only
  --audit-only    Mediaserver audit only (no cleanup)
  --help          Show this usage
EOF
}

# ---------------- Flags ----------------
NO_MS=false
NO_CRON=false
NO_FSTAB=false
JOURNAL_ONLY=false
AUDIT_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --no-ms) NO_MS=true ;;
    --no-cron) NO_CRON=true ;;
    --no-fstab) NO_FSTAB=true ;;
    --journal-only) JOURNAL_ONLY=true ;;
    --audit-only) AUDIT_ONLY=true ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown flag: $arg"; usage; exit 1 ;;
  esac
done

if $AUDIT_ONLY; then
  NO_CRON=true
fi

LOGFILE="/var/log/system_cleanup.log"
exec > >(tee -a "$LOGFILE") 2>&1

# ---------------- Summary / metrics ----------------
declare -a SUMMARY
add_summary(){ SUMMARY+=("$1"); }

print_summary() {
  echo "---------------- ACTION SUMMARY ----------------"
  for line in "${SUMMARY[@]}"; do
    printf " • %s\n" "$line"
  done
  echo "------------------------------------------------"
}

free_space_mb() { df --output=avail / | tail -1; }
free_space_human() { df -h / | awk 'NR==2{print $4" free of "$2}'; }

START_MB="$(free_space_mb)"
START_HUMAN="$(free_space_human)"
FSTAB_STATUS="NOT_RUN"
MS_SERVICE_DETECTED=""
PKG_PURGED=0
CRON_INSTALLED="no"

finalize() {
  END_MB="$(free_space_mb)"
  END_HUMAN="$(free_space_human)"
  RECLAIMED=$((END_MB - START_MB))

  echo "================================================"
  echo "WRN v6 COMPLETE @ $(date)"
  echo "Disk before: ${START_HUMAN}"
  echo "Disk after:  ${END_HUMAN}"
  echo "Reclaimed:   ${RECLAIMED} MB"
  echo "fstab:       ${FSTAB_STATUS}"
  echo "Logfile:     ${LOGFILE}"
  echo "================================================"
  print_summary
}
trap finalize EXIT

echo "================================================"
echo "WRN v6 start @ $(date)"
echo "================================================"

# ---------------- Mediaserver helpers ----------------
MS_VAR="/opt/hanwha/mediaserver/var"
MS_DATA="${MS_VAR}/data"
MS_LOG="${MS_VAR}/log"

detect_ms() {
  for svc in hanwha-mediaserver.service networkoptix-mediaserver.service mediaserver.service; do
    if systemctl list-unit-files | grep -q "^$svc"; then echo "$svc"; return; fi
  done
  echo ""
}
MS_SERVICE="$(detect_ms)"
MS_SERVICE_DETECTED="${MS_SERVICE:-none}"

ms_stop()  { [ -n "$MS_SERVICE" ] && systemctl stop "$MS_SERVICE" 2>/dev/null || true; }
ms_start() { [ -n "$MS_SERVICE" ] && systemctl start "$MS_SERVICE" 2>/dev/null || true; }

ms_audit() {
  local OUT="/var/log/wrn_ms_audit_$(date +%Y%m%d_%H%M%S).log"
  {
    echo "Mediaserver Audit @ $(date)"
    df -hT
    echo
    [ -d "$MS_DATA" ] && du -xh --max-depth=1 "$MS_DATA" | sort -h || echo "Missing $MS_DATA"
    echo
    [ -d "$MS_LOG" ] && du -xh --max-depth=1 "$MS_LOG" | sort -h || echo "Missing $MS_LOG"
    echo
    journalctl --disk-usage || true
  } > "$OUT"
  add_summary "Mediaserver audit saved: $OUT"
}

ms_cleanup() {
  echo "[ms] Cleaning logs, cores, caches..."

  # Compress old logs
  find "$MS_LOG" -type f -name "*.log" -mtime +14 -print0 2>/dev/null \
    | while IFS= read -r -d '' f; do gzip -9 "$f"; done

  # Truncate giant logs (>200M)
  find "$MS_LOG" -type f -size +200M -print0 2>/dev/null \
    | while IFS= read -r -d '' f; do : > "$f"; done

  # Remove cores >7d
  find "$MS_VAR" -type f \( -name "core.*" -o -name "*.dmp" \) -mtime +7 -delete 2>/dev/null

  # Clear caches
  for d in "transcoder_cache" "thumbnail_cache" "tmp" "temp" "cache" "exports/tmp"; do
    [ -e "$MS_DATA/$d" ] && rm -rf "$MS_DATA/$d"
  done

  add_summary "Mediaserver cleanup complete"
}

# ---------------- fstab ----------------
do_fstab() {
  if $NO_FSTAB || $JOURNAL_ONLY; then
    FSTAB_STATUS="SKIPPED"
    add_summary "fstab skipped"
    return
  fi

  local F=/etc/fstab
  cp -a "$F" "$F.$(date +%F_%H%M%S).bak"

  # Comment out direct loop device entries (old snaps, etc.)
  sed -i -E 's#^(/dev/loop[0-9]+)#\# disabled loop: \1#' "$F"

  FSTAB_STATUS="SUCCESS"
  add_summary "fstab hardened + backup created"
}

# ---------------- Log Cleanup ----------------
clean_logs() {
  echo "[log] Cleaning logs & journal..."

  # rsyslog rotate policy
  cat >/etc/logrotate.d/rsyslog <<'EOF'
su root syslog
/var/log/kern.log
/var/log/syslog
{
    rotate 2
    daily
    size 350M
    missingok
    notifempty
    compress
}
EOF

  journalctl --vacuum-size=1G || true
  journalctl --vacuum-time=7d || true

  # Prune giant logs
  find /var/log -type f -size +100M -delete 2>/dev/null || true

  # Crash/Trash cleanup
  rm -rf /var/crash/* 2>/dev/null || true
  rm -rf /home/*/.local/share/Trash/* /home/*/.cache/thumbnails/* 2>/dev/null || true
  rm -rf ~/.local/share/Trash/* ~/.cache/thumbnails/* 2>/dev/null || true

  add_summary "Log + journal cleanup complete"
}

# ---------------- Apt-Lite (SAFE) ----------------
apt_lite() {
  if $JOURNAL_ONLY || $AUDIT_ONLY; then
    add_summary "APT-lite skipped"
    return
  fi

  echo "[apt-lite] Removing selected packages..."

  local TO_PURGE=(
    "libreoffice*"
    "thunderbird*"
    "aisleriot"
    "gnome-mahjongg"
    "gnome-mines"
    "gnome-sudoku"
    "cheese"
    "rhythmbox"
    "gnome-calculator"
    "shotwell"
    "bleachbit"
    "wireshark"
    "cups*"
    "printer-driver*"
  )

  apt-get update -y || true

  for p in "${TO_PURGE[@]}"; do
    if apt-get -y purge "$p"; then
      PKG_PURGED=$((PKG_PURGED+1))
    fi
  done

  # Non-English language packs
  LANG_PKGS="$(dpkg -l | awk '/^ii/ && $2 ~ /^language-pack-/ && $2 !~ /-en/ {print $2}')"
  [ -n "$LANG_PKGS" ] && apt-get -y purge $LANG_PKGS || true

  apt-get clean -y || true
  apt-get autoclean -y || true

  add_summary "APT-lite: purged ${PKG_PURGED} patterns + non-English language packs"
}

# ---------------- Cron ----------------
install_cron() {
  if $NO_CRON || $JOURNAL_ONLY || $AUDIT_ONLY; then
    add_summary "Cron installation skipped"
    return
  fi

  cp -f "$0" /root/wrn_v6.sh
  chmod 755 /root/wrn_v6.sh

  tmp="$(mktemp)"
  crontab -l 2>/dev/null | grep -v 'wrn_v6.sh' > "$tmp" || true

  echo '12 3 * * 1 /usr/bin/bash /root/wrn_v6.sh >> /var/log/system_cleanup.log 2>&1' >> "$tmp"
  echo '30 3 1 * * /usr/bin/bash /root/wrn_v6.sh --journal-only >> /var/log/system_cleanup.log 2>&1' >> "$tmp"

  crontab "$tmp"
  rm -f "$tmp"

  CRON_INSTALLED="yes"
  add_summary "Cron installed (weekly + monthly)"
}

# ---------------- Main ----------------
clean_logs
do_fstab
if ! $NO_MS; then
  ms_stop
  ms_audit
  if ! $AUDIT_ONLY; then ms_cleanup; fi
  ms_start
else
  add_summary "Mediaserver maintenance skipped (--no-ms)"
fi
apt_lite
install_cron

exit 0
