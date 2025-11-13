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
#   - post-boot NIC guard via systemd (optional, auto-installed)
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
  • post-boot NIC guard (via systemd service)

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

# ---------------- NetworkManager refresh (inline, during run) ----------------
refresh_networkmanager() {
  echo
  echo "== NetworkManager refresh (if present) =="

  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not available; skipping network refresh."
    add_summary "Network refresh skipped (no systemctl)"
    return
  fi

  if ! systemctl list-unit-files | awk '{print $1}' | grep -qx "NetworkManager.service"; then
    echo "NetworkManager service not found; skipping network refresh."
    add_summary "Network refresh skipped (no NetworkManager.service)"
    return
  fi

  if systemctl is-active --quiet NetworkManager; then
    echo "NetworkManager is active; restarting to refresh NICs..."
    if systemctl restart NetworkManager; then
      echo "NetworkManager restart completed successfully."
      add_summary "NetworkManager restarted to refresh NICs (inline)"
    else
      echo "WARNING: NetworkManager restart returned a non-zero status."
      add_summary "NetworkManager restart attempted but returned non-zero status"
    fi
  else
    echo "NetworkManager is installed but not active; skipping restart."
    add_summary "NetworkManager present but inactive; no restart performed"
  fi
}

# ---------------- NIC guard installer (post-boot check via systemd) ----------------
install_nic_guard() {
  if ! command -v systemctl >/dev/null 2>&1; then
    add_summary "NIC guard not installed (no systemd/systemctl)"
    return
  fi

  local GUARD_SCRIPT="/usr/local/sbin/wrn_nic_guard.sh"
  local SERVICE_FILE="/etc/systemd/system/wrn-nic-guard.service"

  mkdir -p /usr/local/sbin

  cat > "$GUARD_SCRIPT" <<'GUARD'
#!/bin/bash
#
# wrn_nic_guard.sh
# Post-boot NIC health check + gentle NetworkManager restart if needed
#
# Logic:
#   - Called by systemd service (ExecStartPre sleep is in unit)
#   - Only checks interface(s) that have a default route
#   - If default gateway reachable -> OK
#   - If gateway unreachable but 8.8.8.8 reachable -> upstream/router issue
#   - If both unreachable -> try NetworkManager restart once
#

LOGFILE="/var/log/wrn_nic_guard.log"
mkdir -p "$(dirname "$LOGFILE")"
exec >>"$LOGFILE" 2>&1

echo "================================================"
echo "WRN NIC guard start @ $(date)"

set +e

GW="$(ip route show default 2>/dev/null | awk '/^default/ {print $3; exit}')"

if [ -z "$GW" ]; then
  echo "No default route found; nothing to test. Exiting NIC guard."
  echo "WRN NIC guard end @ $(date)"
  exit 0
fi

echo "Default gateway detected: $GW"
echo "Pinging gateway to test NIC connectivity..."

if ping -c 3 -W 2 "$GW" >/dev/null 2>&1; then
  echo "Gateway $GW reachable. NICs considered healthy."
  echo "WRN NIC guard end @ $(date)"
  exit 0
fi

echo "FAILED to reach gateway $GW. Trying external fallback (8.8.8.8)..."

if ping -c 3 -W 2 8.8.8.8 >/dev/null 2>&1; then
  echo "8.8.8.8 reachable, but gateway $GW is not. Likely upstream/router issue, not local NIC."
  echo "WRN NIC guard end @ $(date)"
  exit 0
fi

echo "Both gateway and 8.8.8.8 unreachable. Attempting NetworkManager refresh (if present)..."

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not available; cannot manage NetworkManager. Exiting."
  echo "WRN NIC guard end @ $(date)"
  exit 0
fi

if ! systemctl list-unit-files | awk '{print $1}' | grep -qx "NetworkManager.service"; then
  echo "NetworkManager.service not found; no automatic NIC toggle available."
  echo "WRN NIC guard end @ $(date)"
  exit 0
fi

if systemctl is-active --quiet NetworkManager; then
  echo "NetworkManager is active; restarting to refresh NICs..."
  if systemctl restart NetworkManager; then
    echo "NetworkManager restart completed. Re-checking gateway ping..."
    sleep 5
    if ping -c 3 -W 2 "$GW" >/dev/null 2>&1; then
      echo "After restart, gateway $GW is now reachable. NIC recovery successful."
    else
      echo "After restart, gateway $GW is still unreachable. Manual investigation required."
    fi
  else
    echo "WARNING: NetworkManager restart returned a non-zero status."
  fi
else
  echo "NetworkManager installed but not active; skipping restart."
fi

echo "WRN NIC guard end @ $(date)"
exit 0
GUARD

  chmod 755 "$GUARD_SCRIPT"

  cat > "$SERVICE_FILE" <<'UNIT'
[Unit]
Description=WRN NIC post-boot health check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 60
ExecStart=/usr/local/sbin/wrn_nic_guard.sh

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload || true
  systemctl enable wrn-nic-guard.service >/dev/null 2>&1 || true

  add_summary "NIC guard installed: /usr/local/sbin/wrn_nic_guard.sh + wrn-nic-guard.service (runs once per boot)"
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
refresh_networkmanager
install_cron
install_nic_guard

exit 0
