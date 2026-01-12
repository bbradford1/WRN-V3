#!/usr/bin/env bash
#
# wrn_v9.sh
#
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo --preserve-env=PATH "$0" "$@"
fi

# ---------------- Config ----------------
LOGFILE="/var/log/wrn_v9.log"
exec > >(tee -a "$LOGFILE") 2>&1

SCRIPT_NAME="wrn_v9.sh"
NOW="$(date +%Y%m%d_%H%M%S)"

# Defaults (safe)
DO_MS=true
DO_APT_LITE=false
PURGE_LANG=false
JOURNAL_ONLY=false
AUDIT_ONLY=false
FIX_FSTAB_LOOPS=false
INSTALL_CRON=false
NO_REBOOT_PROMPT=false

# ---------------- Helpers ----------------
declare -a SUMMARY
add_summary(){ SUMMARY+=("$1"); }

usage() {
cat <<'EOF'
wrn_v9.sh - HARDENED WRN maintenance (safe-by-default)

Default behavior (SAFE):
  • Truncate oversized /var/log files (keeps files, avoids service breakage)
  • journalctl vacuum (size + age)
  • Optional mediaserver audit + cleanup (enabled by default if detected)
  • Network diagnostics only (no restarts, no netplan apply)

Optional flags (OPT-IN):
  --no-ms            Skip mediaserver maintenance
  --audit-only       Only mediaserver audit (no cleanup); implies --no-ms-clean
  --journal-only     Only logs/journald cleanup (no apt-lite, no mediaserver)
  --apt-lite         Enable apt-lite purge list (still safe; no autoremove)
  --purge-lang       Also purge non-English language packs (only with --apt-lite)
  --fix-fstab-loops  Comment /dev/loop* lines in /etc/fstab (risky; opt-in)
  --install-cron     Install weekly cron + monthly journal-only cron (safe jobs)
  --no-reboot-prompt Never prompt about reboot

Notes:
  • This script will REMOVE legacy /etc/systemd/system/NetworkManager.service.d/wrn-delay.conf if present.
  • This script does NOT restart NetworkManager, systemd-networkd, networking, or run netplan apply (by design).
EOF
}

die(){ echo "ERROR: $*" >&2; exit 1; }

free_space_mb() { df --output=avail / | tail -1 | awk '{print $1}'; }
free_space_human(){ df -h / | awk 'NR==2{print $4" free of "$2}'; }

copy_log_to_downloads() {
  local src="$1" base
  base="$(basename "$src")"
  for home in /home/*; do
    [[ -d "$home/Downloads" ]] || continue
    cp -f "$src" "$home/Downloads/$base" 2>/dev/null || true
  done
}

START_MB="$(free_space_mb)"
START_HUMAN="$(free_space_human)"

finalize() {
  set +e
  local END_MB END_HUMAN RECLAIMED
  END_MB="$(free_space_mb 2>/dev/null || echo "$START_MB")"
  END_HUMAN="$(free_space_human 2>/dev/null || echo "$START_HUMAN")"
  RECLAIMED=$((END_MB - START_MB))

  echo
  echo "================================================"
  echo "${SCRIPT_NAME} COMPLETE @ $(date)"
  echo "Disk before: ${START_HUMAN}"
  echo "Disk after:  ${END_HUMAN}"
  echo "Reclaimed:   ${RECLAIMED} MB"
  echo "Logfile:     ${LOGFILE}"
  echo "================================================"
  echo "---------------- ACTION SUMMARY ----------------"
  for line in "${SUMMARY[@]}"; do
    printf " • %s\n" "$line"
  done
  echo "------------------------------------------------"
  echo "================================================"
  copy_log_to_downloads "$LOGFILE"
}
trap finalize EXIT

# ---------------- Parse args ----------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-ms) DO_MS=false ;;
    --audit-only) AUDIT_ONLY=true ;;
    --journal-only) JOURNAL_ONLY=true ;;
    --apt-lite) DO_APT_LITE=true ;;
    --purge-lang) PURGE_LANG=true ;;
    --fix-fstab-loops) FIX_FSTAB_LOOPS=true ;;
    --install-cron) INSTALL_CRON=true ;;
    --no-reboot-prompt) NO_REBOOT_PROMPT=true ;;
    --help|-h) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
  shift
done

if $AUDIT_ONLY; then
  # audit-only means "don't delete anything in mediaserver"
  # (we'll still run the audit if mediaserver exists)
  :
fi

if $JOURNAL_ONLY; then
  DO_APT_LITE=false
  DO_MS=false
fi

if $PURGE_LANG && ! $DO_APT_LITE; then
  die "--purge-lang requires --apt-lite"
fi

echo "================================================"
echo "${SCRIPT_NAME} start @ $(date)"
echo "Flags: DO_MS=$DO_MS AUDIT_ONLY=$AUDIT_ONLY JOURNAL_ONLY=$JOURNAL_ONLY DO_APT_LITE=$DO_APT_LITE PURGE_LANG=$PURGE_LANG FIX_FSTAB_LOOPS=$FIX_FSTAB_LOOPS INSTALL_CRON=$INSTALL_CRON"
echo "================================================"

# ---------------- Safety: remove legacy NM delay drop-in ----------------
remove_legacy_nm_delay() {
  local f="/etc/systemd/system/NetworkManager.service.d/wrn-delay.conf"
  if [[ -f "$f" ]]; then
    rm -f "$f"
    systemctl daemon-reload >/dev/null 2>&1 || true
    add_summary "Removed legacy NM delay drop-in: $f"
  else
    add_summary "Legacy NM delay drop-in not present"
  fi
}
remove_legacy_nm_delay

# ---------------- Network diagnostics only (safe) ----------------
network_diagnostics() {
  echo
  echo "== Network diagnostics (non-disruptive) =="
  ip -4 addr || true
  ip route || true
  if command -v nmcli >/dev/null 2>&1; then
    nmcli device status || true
    nmcli connection show --active || true
  fi
  add_summary "Captured network diagnostics (no changes applied)"
}

# ---------------- Log/Journald cleanup (safe) ----------------
truncate_oversized_logs() {
  echo
  echo "== Truncate oversized logs (safe) =="
  # Truncate instead of delete to avoid breaking services expecting paths/inodes
  local count=0
  while IFS= read -r -d '' f; do
    : > "$f" || true
    count=$((count+1))
  done < <(find /var/log -type f -size +100M -print0 2>/dev/null || true)
  add_summary "Truncated oversized /var/log files (>100M): $count"
}

journald_vacuum() {
  echo
  echo "== Journald vacuum (safe) =="
  journalctl --disk-usage || true
  journalctl --vacuum-size=1G || true
  journalctl --vacuum-time=7d || true
  journalctl --disk-usage || true
  add_summary "Vacuumed journald (target: 1G, 7d)"
}

clean_crash_and_trash() {
  echo
  echo "== Clean crash + trash (safe) =="
  rm -rf /var/crash/* 2>/dev/null || true
  rm -rf /home/*/.local/share/Trash/* /home/*/.cache/thumbnails/* 2>/dev/null || true
  rm -rf /root/.local/share/Trash/* /root/.cache/thumbnails/* 2>/dev/null || true
  add_summary "Cleared /var/crash and user trash/thumbnail caches"
}

# ---------------- fstab loop hardening (opt-in) ----------------
fix_fstab_loops() {
  if ! $FIX_FSTAB_LOOPS; then
    add_summary "fstab loop-device hardening skipped"
    return
  fi

  echo
  echo "== fstab loop-device hardening (OPT-IN) =="
  local F=/etc/fstab
  cp -a "$F" "$F.${NOW}.bak"
  # Only comment lines that START with /dev/loopN
  # Keep original line content for easy restore.
  sed -i -E 's#^(/dev/loop[0-9]+[[:space:]].*)$#\# wrn_v9 disabled: \1#' "$F"
  add_summary "fstab: commented /dev/loop* entries (backup: $F.${NOW}.bak)"
}

# ---------------- Mediaserver maintenance (safe-ish) ----------------
MS_VAR="/opt/hanwha/mediaserver/var"
MS_DATA="${MS_VAR}/data"
MS_LOG="${MS_VAR}/log"

detect_ms_service() {
  local svc=""
  if command -v systemctl >/dev/null 2>&1; then
    for s in hanwha-mediaserver.service networkoptix-mediaserver.service mediaserver.service; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$s"; then
        svc="$s"; break
      fi
    done
  fi
  echo "$svc"
}

ms_audit() {
  local svc="$1"
  local OUT="/var/log/wrn_v9_ms_audit_${NOW}.log"
  {
    echo "Mediaserver Audit @ $(date)"
    echo "Unit: ${svc:-none}"
    echo
    df -hT
    echo
    if [[ -d "$MS_DATA" ]]; then
      echo "== ${MS_DATA} =="
      du -xh --max-depth=1 "$MS_DATA" 2>/dev/null | sort -h
    else
      echo "Missing ${MS_DATA}"
    fi
    echo
    if [[ -d "$MS_LOG" ]]; then
      echo "== ${MS_LOG} =="
      du -xh --max-depth=1 "$MS_LOG" 2>/dev/null | sort -h
    else
      echo "Missing ${MS_LOG}"
    fi
    echo
    journalctl --disk-usage || true
  } > "$OUT"
  add_summary "Mediaserver audit saved: $OUT"
  copy_log_to_downloads "$OUT"
}

ms_cleanup_safe() {
  # Only touches known mediaserver directories; avoids system-wide deletes.
  echo
  echo "== Mediaserver cleanup (bounded) =="

  [[ -d "$MS_VAR" ]] || { add_summary "Mediaserver paths not present; cleanup skipped"; return; }

  # Compress old *.log (older than 14d)
  if [[ -d "$MS_LOG" ]]; then
    find "$MS_LOG" -type f -name "*.log" -mtime +14 -print0 2>/dev/null \
      | while IFS= read -r -d '' f; do gzip -9 "$f" 2>/dev/null || true; done
    # Truncate huge logs (keep file)
    find "$MS_LOG" -type f -size +200M -print0 2>/dev/null \
      | while IFS= read -r -d '' f; do : > "$f" 2>/dev/null || true; done
  fi

  # Remove old core dumps in mediaserver var
  find "$MS_VAR" -type f \( -name "core.*" -o -name "*.dmp" \) -mtime +7 -delete 2>/dev/null || true

  # Remove known caches safely
  if [[ -d "$MS_DATA" ]]; then
    for d in "transcoder_cache" "thumbnail_cache" "tmp" "temp" "cache" "exports/tmp"; do
      [[ -e "$MS_DATA/$d" ]] && rm -rf "$MS_DATA/$d" 2>/dev/null || true
    done
  fi

  add_summary "Mediaserver cleanup completed (logs/caches/cores bounded to ${MS_VAR})"
}

mediaserver_main() {
  if ! $DO_MS; then
    add_summary "Mediaserver maintenance skipped (--no-ms or --journal-only)"
    return
  fi

  local svc
  svc="$(detect_ms_service)"
  if [[ -z "$svc" && ! -d "$MS_VAR" ]]; then
    add_summary "Mediaserver not detected"
    return
  fi

  ms_audit "$svc"

  if $AUDIT_ONLY; then
    add_summary "Mediaserver cleanup skipped (--audit-only)"
    return
  fi

  # Stop/start is useful but could be disruptive; keep it, but only if service exists.
  if [[ -n "$svc" ]]; then
    systemctl stop "$svc" 2>/dev/null || true
    add_summary "Stopped mediaserver service: $svc"
  fi

  ms_cleanup_safe

  if [[ -n "$svc" ]]; then
    systemctl start "$svc" 2>/dev/null || true
    add_summary "Started mediaserver service: $svc"
  fi
}

# ---------------- Apt-lite (opt-in, still conservative) ----------------
apt_lite() {
  if ! $DO_APT_LITE; then
    add_summary "APT-lite skipped (default)"
    return
  fi

  echo
  echo "== APT-lite (OPT-IN) =="

  # Conservative purge list (remove GUI extras; avoid touching core network stack)
  local TO_PURGE=(
    "libreoffice*"
    "thunderbird*"
    "aisleriot"
    "gnome-mahjongg"
    "gnome-mines"
    "gnome-sudoku"
    "cheese"
    "rhythmbox"
    "shotwell"
    "cups*"
    "printer-driver*"
  )

  apt-get update -y || true

  local purged=0
  for p in "${TO_PURGE[@]}"; do
    if apt-get -y purge "$p" >/dev/null 2>&1; then
      purged=$((purged+1))
    fi
  done

  if $PURGE_LANG; then
    local LANG_PKGS
    LANG_PKGS="$(dpkg -l | awk '/^ii/ && $2 ~ /^language-pack-/ && $2 !~ /-en/ {print $2}')"
    if [[ -n "${LANG_PKGS:-}" ]]; then
      # shellcheck disable=SC2086
      apt-get -y purge $LANG_PKGS >/dev/null 2>&1 || true
      add_summary "APT-lite: purged non-English language packs"
    fi
  else
    add_summary "APT-lite: language-pack purge skipped (default)"
  fi

  apt-get clean -y >/dev/null 2>&1 || true
  apt-get autoclean -y >/dev/null 2>&1 || true

  add_summary "APT-lite complete (purged patterns: ${purged}); NO autoremove performed"
}

# ---------------- Cron install (opt-in) ----------------
install_cron() {
  if ! $INSTALL_CRON; then
    add_summary "Cron install skipped (default)"
    return
  fi

  echo
  echo "== Install cron (OPT-IN) =="

  cp -f "$0" /root/wrn_v9.sh
  chmod 755 /root/wrn_v9.sh

  local tmp
  tmp="$(mktemp)"
  crontab -l 2>/dev/null | grep -v '/root/wrn_v9.sh' > "$tmp" || true

  # Weekly: safe maintenance
  echo '12 3 * * 1 /usr/bin/bash /root/wrn_v9.sh >> /var/log/wrn_v9_cron.log 2>&1' >> "$tmp"
  # Monthly: journal-only
  echo '30 3 1 * * /usr/bin/bash /root/wrn_v9.sh --journal-only >> /var/log/wrn_v9_cron.log 2>&1' >> "$tmp"

  crontab "$tmp"
  rm -f "$tmp"

  add_summary "Cron installed: weekly maintenance + monthly journal-only"
}

# ---------------- Main ----------------
truncate_oversized_logs
journald_vacuum
clean_crash_and_trash
fix_fstab_loops

# If journal-only, we stop here (by design)
if $JOURNAL_ONLY; then
  add_summary "Journal-only mode: skipped mediaserver + apt-lite + cron"
  network_diagnostics
  exit 0
fi

mediaserver_main
apt_lite
install_cron
network_diagnostics

# Optional: reboot prompt (never automatic)
if ! $NO_REBOOT_PROMPT; then
  echo
  echo "NOTE: If you changed packages or services, a reboot may be beneficial."
  echo "      Current uptime: $(uptime -p || true)"
fi

exit 0
