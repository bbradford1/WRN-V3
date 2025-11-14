#!/bin/bash
#
# wrn_v7.sh
# WRN cleanup + mediaserver maintenance + safe OS log/journal + apt-lite cleanup
# + NetworkManager delayed start + post-boot refresh + NIC guard
#
# SAFE BY DEFAULT:
#   - fstab hardening (only loop devices; never touches OS disk mapping)
#   - mediaserver audit + logs/cores/cache cleanup
#   - rsyslog + logrotate policies, big log pruning
#   - journald vacuum (size + age)
#   - apt-lite: purge selected bloat + non-English language packs
#   - NO autoremove, NO snap removal
#   - weekly cleanup cron + monthly journal-only cron
#   - post-boot NIC guard via systemd
#   - NetworkManager delayed start + post-boot nm/netplan refresh (if NM present)
#
# Flags:
#   --no-ms         Skip mediaserver cleanup
#   --no-fstab      Skip fstab hardening
#   --no-cron       Skip cron + NIC guard + NM boot fixes
#   --journal-only  Only clean logs/journals
#   --audit-only    Mediaserver audit only (no cleanup; also skips cron/sysd installs)
#   --help          Show usage
#

set -euo pipefail
if [ "$EUID" -ne 0 ]; then exec sudo --preserve-env=PATH "$0" "$@"; fi

usage() {
cat <<'EOF'
wrn_v7.sh - WRN safe maintenance stack (with NM boot-fix + logging)

Default:
  • fstab hardening (safe)
  • rsyslog/logrotate enforcement
  • journald vacuum (1G + 7d)
  • mediaserver audit + cleanup
  • APT-LITE (remove selected apps + non-English language packs)
  • inline network refresh (services + netplan apply)
  • weekly cron + monthly journal cron
  • NIC guard (post-boot gateway check + services + netplan apply)
  • NetworkManager delayed start + post-boot nm/netplan refresh (if NM present)
  • Per-boot logs in /var/log + copies to ~/Downloads

Flags:
  --no-ms         Skip mediaserver maintenance
  --no-cron       Skip cron, NIC guard, NM boot-fix installs
  --no-fstab      Skip fstab entry correction
  --journal-only  Logs/journal cleanup only
  --audit-only    Mediaserver audit only (no cleanup or installs)
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
    --no-ms)        NO_MS=true ;;
    --no-cron)      NO_CRON=true ;;
    --no-fstab)     NO_FSTAB=true ;;
    --journal-only) JOURNAL_ONLY=true ;;
    --audit-only)   AUDIT_ONLY=true ;;
    --help|-h)      usage; exit 0 ;;
  esac
  done
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

free_space_mb()    { df --output=avail / | tail -1; }
free_space_human() { df -h / | awk 'NR==2{print $4" free of "$2}'; }

START_MB="$(free_space_mb)"
START_HUMAN="$(free_space_human)"
FSTAB_STATUS="NOT_RUN"
MS_SERVICE_DETECTED=""
PKG_PURGED=0
CRON_INSTALLED="no"
NIC_GUARD_INSTALLED="no"
NM_BOOT_FIX_INSTALLED="no"

finalize() {
  END_MB="$(free_space_mb)"
  END_HUMAN="$(free_space_human)"
  RECLAIMED=$((END_MB - START_MB))

  echo "================================================"
  echo "WRN v7 COMPLETE @ $(date)"
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
echo "WRN v7 start @ $(date)"
echo "Flags: NO_MS=$NO_MS NO_CRON=$NO_CRON NO_FSTAB=$NO_FSTAB JOURNAL_ONLY=$JOURNAL_ONLY AUDIT_ONLY=$AUDIT_ONLY"
echo "================================================"

# ---------------- Mediaserver helpers ----------------
MS_VAR="/opt/hanwha/mediaserver/var"
MS_DATA="${MS_VAR}/data"
MS_LOG="${MS_VAR}/log"

detect_ms() {
  if ! command -v systemctl >/dev/null 2>&1; then
    echo ""
    return
  fi
  for svc in hanwha-mediaserver.service networkoptix-mediaserver.service mediaserver.service; do
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$svc"; then
      echo "$svc"; return
    fi
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
    echo "Unit: ${MS_SERVICE_DETECTED}"
    echo
    df -hT
    echo
    [ -d "$MS_DATA" ] && { echo "== ${MS_DATA} =="; du -xh --max-depth=1 "$MS_DATA" | sort -h; } || echo "Missing $MS_DATA"
    echo
    [ -d "$MS_LOG" ] && { echo "== ${MS_LOG} =="; du -xh --max-depth=1 "$MS_LOG" | sort -h; } || echo "Missing $MS_LOG"
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
  add_summary "fstab hardened + backup created (loop devices commented)"
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

# ---------------- Network stack refresh (inline) ----------------
refresh_network_stack() {
  echo
  echo "== Network stack refresh (if present) =="

  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not available; skipping network refresh."
    add_summary "Network refresh skipped (no systemctl)"
    return
  fi

  local tried=0
  local ok=0

  # 1) NetworkManager
  if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "NetworkManager.service"; then
    tried=1
    if systemctl is-active --quiet NetworkManager; then
      echo "Restarting NetworkManager..."
      if systemctl restart NetworkManager; then
        echo "NetworkManager restart OK."
        add_summary "NetworkManager restarted (inline)"
        ok=1
      else
        echo "WARNING: NetworkManager restart failed."
      fi
    else
      echo "NetworkManager installed but inactive; not restarted."
    fi
  fi

  # 2) systemd-networkd
  if [ $ok -eq 0 ] && systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "systemd-networkd.service"; then
    tried=1
    if systemctl is-active --quiet systemd-networkd; then
      echo "Restarting systemd-networkd..."
      if systemctl restart systemd-networkd; then
        echo "systemd-networkd restart OK."
        add_summary "systemd-networkd restarted (inline)"
        ok=1
      else
        echo "WARNING: systemd-networkd restart failed."
      fi
    else
      echo "systemd-networkd installed but inactive; not restarted."
    fi
  fi

  # 3) networking.service
  if [ $ok -eq 0 ] && systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "networking.service"; then
    tried=1
    if systemctl is-active --quiet networking; then
      echo "Restarting networking.service..."
      if systemctl restart networking; then
        echo "networking.service restart OK."
        add_summary "networking.service restarted (inline)"
        ok=1
      else
        echo "WARNING: networking.service restart failed."
      fi
    else
      echo "networking.service installed but inactive; not restarted."
    fi
  fi

  # 4) netplan apply fallback
  if [ $ok -eq 0 ] && command -v netplan >/dev/null 2>&1; then
    tried=1
    echo "No network services restarted; attempting 'netplan apply'..."
    if netplan apply 2>/dev/null; then
      echo "netplan apply completed."
      add_summary "netplan apply executed (inline network refresh)"
      ok=1
    else
      echo "WARNING: netplan apply failed."
    fi
  fi

  if [ $tried -eq 0 ]; then
    add_summary "Network refresh skipped (no known network services and no netplan)"
  elif [ $ok -eq 0 ]; then
    add_summary "Network refresh attempted (services/netplan) but no restart/apply succeeded"
  fi
}

# ---------------- NIC guard installer ----------------
install_nic_guard() {
  if $NO_CRON; then
    add_summary "NIC guard not installed (--no-cron set)"
    return
  fi

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
# Post-boot NIC health check + gentle network stack restart if needed
#
# Logs to /var/log/wrn_nic_guard.log and also copies to /home/*/Downloads
# Only the latest boot's run is kept (log is truncated at start).
#

LOGFILE="/var/log/wrn_nic_guard.log"

# Helper: copy log to any user's Downloads folder for easy pickup
copy_to_downloads() {
  local src="$1" base
  base="$(basename "$src")"
  for home in /home/*; do
    [ -d "$home/Downloads" ] || continue
    cp "$src" "$home/Downloads/$base" 2>/dev/null || true
  done
}

# Truncate log each run so we only keep the latest boot
: > "$LOGFILE"
exec >>"$LOGFILE" 2>&1

echo "================================================"
echo "WRN NIC guard start @ $(date)"
echo "Uptime: $(uptime -p || echo 'n/a')"
echo "--- ip -4 addr ---"
ip -4 addr || echo "ip -4 addr failed"
echo "--- ip route ---"
ip route || echo "ip route failed"

if command -v nmcli >/dev/null 2>&1; then
  echo "--- nmcli device status ---"
  nmcli device status || echo "nmcli device status failed"
  echo "--- nmcli connection show --active ---"
  nmcli connection show --active || echo "nmcli connection show failed"
else
  echo "nmcli not found; skipping NM state dump."
fi

set +e

bounce_network_stack() {
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not available; cannot manage network services (will still try netplan if present)."
  fi

  local tried=0
  local ok=0

  if command -v systemctl >/dev/null 2>&1; then
    # 1) NetworkManager
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "NetworkManager.service"; then
      tried=1
      if systemctl is-active --quiet NetworkManager; then
        echo "Restarting NetworkManager..."
        if systemctl restart NetworkManager; then
          echo "NetworkManager restart OK."
          ok=1
        else
          echo "WARNING: NetworkManager restart failed."
        fi
      else
        echo "NetworkManager installed but inactive; not restarted."
      fi
    fi

    # 2) systemd-networkd
    if [ $ok -eq 0 ] && systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "systemd-networkd.service"; then
      tried=1
      if systemctl is-active --quiet systemd-networkd; then
        echo "Restarting systemd-networkd..."
        if systemctl restart systemd-networkd; then
          echo "systemd-networkd restart OK."
          ok=1
        else
          echo "WARNING: systemd-networkd restart failed."
        fi
      else
        echo "systemd-networkd installed but inactive; not restarted."
      fi
    fi

    # 3) networking.service
    if [ $ok -eq 0 ] && systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "networking.service"; then
      tried=1
      if systemctl is-active --quiet networking; then
        echo "Restarting networking.service..."
        if systemctl restart networking; then
          echo "networking.service restart OK."
          ok=1
        else
          echo "WARNING: networking.service restart failed."
        fi
      else
        echo "networking.service installed but inactive; not restarted."
      fi
    fi
  fi

  # 4) netplan apply fallback
  if [ $ok -eq 0 ] && command -v netplan >/dev/null 2>&1; then
    tried=1
    echo "No network services restarted; attempting 'netplan apply'..."
    if netplan apply 2>/dev/null; then
      echo "netplan apply completed."
      ok=1
    else
      echo "WARNING: netplan apply failed."
    fi
  fi

  if [ $tried -eq 0 ]; then
    echo "No network services or netplan found to restart/apply."
    return 1
  fi

  [ $ok -eq 1 ] && return 0 || return 1
}

GW="$(ip route show default 2>/dev/null | awk '/^default/ {print $3; exit}')"

if [ -z "$GW" ]; then
  echo "No default route found; nothing to test. Exiting NIC guard."
  echo "WRN NIC guard end @ $(date)"
  copy_to_downloads "$LOGFILE"
  exit 0
fi

echo "Default gateway detected: $GW"
echo "Pinging gateway to test NIC connectivity..."

if ping -c 3 -W 2 "$GW" >/dev/null 2>&1; then
  echo "Gateway $GW reachable. NICs considered healthy."
  echo "WRN NIC guard end @ $(date)"
  copy_to_downloads "$LOGFILE"
  exit 0
fi

echo "FAILED to reach gateway $GW. Trying external fallback (8.8.8.8)..."

if ping -c 3 -W 2 8.8.8.8 >/dev/null 2>&1; then
  echo "8.8.8.8 reachable, but gateway $GW is not. Likely upstream/router issue, not local NIC."
  echo "WRN NIC guard end @ $(date)"
  copy_to_downloads "$LOGFILE"
  exit 0
fi

echo "Both gateway and 8.8.8.8 unreachable. Attempting network stack restart / netplan apply..."

if bounce_network_stack; then
  echo "Network stack restart/apply completed. Re-checking gateway ping..."
  sleep 5
  if ping -c 3 -W 2 "$GW" >/dev/null 2>&1; then
    echo "After restart/apply, gateway $GW is now reachable. NIC recovery successful."
  else
    echo "After restart/apply, gateway $GW is still unreachable. Manual investigation required."
  fi
else
  echo "No network service could be restarted and netplan apply did not succeed or was unavailable."
fi

echo "--- post-recovery ip -4 addr ---"
ip -4 addr || echo "ip -4 addr failed"
echo "--- post-recovery ip route ---"
ip route || echo "ip route failed"

echo "WRN NIC guard end @ $(date)"
copy_to_downloads "$LOGFILE"
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

  NIC_GUARD_INSTALLED="yes"
  add_summary "NIC guard installed: /usr/local/sbin/wrn_nic_guard.sh + wrn-nic-guard.service (runs once per boot)"
}

# ---------------- NetworkManager boot-fix (delay + refresh service) ----------------
install_nm_boot_fix() {
  if $NO_CRON; then
    add_summary "NM boot-fix not installed (--no-cron set)"
    return
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    add_summary "NM boot-fix not installed (no systemd/systemctl)"
    return
  fi

  # Only if NetworkManager exists
  if ! systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "NetworkManager.service"; then
    add_summary "NM boot-fix skipped (NetworkManager.service not found)"
    return
  fi

  mkdir -p /etc/systemd/system/NetworkManager.service.d
  cat > /etc/systemd/system/NetworkManager.service.d/wrn-delay.conf <<'EOF'
[Service]
ExecStartPre=/bin/sleep 15
EOF

  # helper script that does logging + actions
  local NMREFRESH_SCRIPT="/usr/local/sbin/wrn_nm_refresh.sh"
  cat > "$NMREFRESH_SCRIPT" <<'REF'
#!/bin/bash
#
# wrn_nm_refresh.sh
# Runs shortly after boot to reapply NM + netplan state with detailed logging
#
# Logs to /var/log/wrn_nm_refresh.log and also copies to /home/*/Downloads
# Only the latest run is kept.
#

LOGFILE="/var/log/wrn_nm_refresh.log"

copy_to_downloads() {
  local src="$1" base
  base="$(basename "$src")"
  for home in /home/*; do
    [ -d "$home/Downloads" ] || continue
    cp "$src" "$home/Downloads/$base" 2>/dev/null || true
  done
}

: > "$LOGFILE"
exec >>"$LOGFILE" 2>&1

echo "================================================"
echo "WRN NM refresh start @ $(date)"
echo "Uptime: $(uptime -p || echo 'n/a')"

echo "--- ip -4 addr (before) ---"
ip -4 addr || echo "ip -4 addr failed"
echo "--- ip route (before) ---"
ip route || echo "ip route failed"

if command -v nmcli >/dev/null 2>&1; then
  echo "--- nmcli device status (before) ---"
  nmcli device status || echo "nmcli device status failed"
  echo "--- nmcli connection show --active (before) ---"
  nmcli connection show --active || echo "nmcli connection show failed"

  echo "Running nmcli device reapply..."
  nmcli device reapply || echo "nmcli device reapply failed"

  echo "Reloading NM connections..."
  nmcli connection reload || echo "nmcli connection reload failed"
else
  echo "nmcli not found; skipping NM-specific refresh."
fi

if command -v netplan >/dev/null 2>&1; then
  echo "Running netplan apply..."
  netplan apply 2>/dev/null || echo "netplan apply failed"
else
  echo "netplan not found; skipping netplan apply."
fi

echo "--- ip -4 addr (after) ---"
ip -4 addr || echo "ip -4 addr failed"
echo "--- ip route (after) ---"
ip route || echo "ip route failed"

echo "WRN NM refresh end @ $(date)"
copy_to_downloads "$LOGFILE"
exit 0
REF

  chmod 755 "$NMREFRESH_SCRIPT"

  cat > /etc/systemd/system/wrn-nm-refresh.service <<'UNIT'
[Unit]
Description=WRN NetworkManager post-boot refresh
After=network-online.target wrn-nic-guard.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 20
ExecStart=/usr/local/sbin/wrn_nm_refresh.sh

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload || true
  systemctl enable wrn-nm-refresh.service >/dev/null 2>&1 || true

  NM_BOOT_FIX_INSTALLED="yes"
  add_summary "NM boot-fix installed: delayed start + wrn-nm-refresh.service (post-boot nm/netplan refresh + logs to Downloads)"
}

# ---------------- Cron ----------------
install_cron() {
  if $NO_CRON || $JOURNAL_ONLY || $AUDIT_ONLY; then
    add_summary "Cron installation skipped"
    return
  fi

  cp -f "$0" /root/wrn_v7.sh
  chmod 755 /root/wrn_v7.sh

  tmp="$(mktemp)"
  crontab -l 2>/dev/null | grep -v 'wrn_v7.sh' > "$tmp" || true

  echo '12 3 * * 1 /usr/bin/bash /root/wrn_v7.sh >> /var/log/system_cleanup.log 2>&1' >> "$tmp"
  echo '30 3 1 * * /usr/bin/bash /root/wrn_v7.sh --journal-only >> /var/log/system_cleanup.log 2>&1' >> "$tmp"

  crontab "$tmp"
  rm -f "$tmp"

  CRON_INSTALLED="yes"
  add_summary "Cron installed (weekly cleanup + monthly journal-only)"
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
refresh_network_stack
install_cron
install_nic_guard
install_nm_boot_fix

exit 0
