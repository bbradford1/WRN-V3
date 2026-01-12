#!/usr/bin/env bash
# WRN-Legacy-Cleanup (Ubuntu 18)
# Purpose: Fix runaway systemd journal usage on older WRNs (Ubuntu 18)
#
# Script does the following:
#  1) journalctl --vacuum-size=500M
#  2) Stop journald, wipe /var/log/journal/*, start journald
#  3) Install monthly cron vacuum (03:00 on the 1st): --vacuum-size=200M
#
# Created by: Bradford
#
# Usage:
#   sudo bash wrn_journal_fix.sh
#
# Optional:
#   --force   Run even if OS version check fails (not recommended)
#
set -euo pipefail

FORCE=false
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
    --help|-h)
      echo "Usage: sudo bash $(basename "$0") [--force]"
      exit 0
      ;;
    *) echo "Unknown arg: $arg"; exit 1 ;;
  esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "ERROR: run as root (use sudo)."
  exit 1
fi

# ---------------- Logging ----------------
LOG="/var/log/wrn_journal_fix.log"
exec > >(tee -a "$LOG") 2>&1

copy_log_to_downloads() {
  local src="$1" base
  base="$(basename "$src")"
  for home in /home/*; do
    [[ -d "$home/Downloads" ]] || continue
    cp -f "$src" "$home/Downloads/$base" 2>/dev/null || true
  done
}

# ---------------- OS Guard ----------------
is_ubuntu_18_or_lower() {
  [[ -r /etc/os-release ]] || return 1
  # shellcheck disable=SC1091
  . /etc/os-release

  # VERSION_ID like "18.04" -> major "18"
  local major="${VERSION_ID%%.*}"

  [[ "${ID:-}" == "ubuntu" ]] || return 1
  [[ "$major" =~ ^[0-9]+$ ]] || return 1
  (( major <= 18 ))
}

echo "================================================"
echo "WRN Legacy Journal Fix starting @ $(date)"
echo "Created by: Bradford"
echo "Log: $LOG"
echo "================================================"

if ! is_ubuntu_18_or_lower; then
  if $FORCE; then
    echo "WARNING: OS guard failed, but --force supplied. Proceeding anyway."
  else
    echo "ERROR: This legacy script is intended for Ubuntu 18.x (or older) only."
    echo "       If you REALLY want to run anyway, re-run with: --force"
    echo "================================================"
    exit 1
  fi
fi

# ---------------- Metrics ----------------
BEFORE_USED_MB="$(df -Pm / | awk 'NR==2 {print $3}' || echo 0)"

echo
echo "BEFORE"
df -h / || true
journalctl --disk-usage || true

# ---------------- Action 1: Vacuum ----------------
echo
echo "Vacuum journals to 500M"
journalctl --vacuum-size=500M || true

# ---------------- Action 2: Reset persistent journal ----------------
echo
echo "Reset journal store (/var/log/journal/*)"
if [[ -d /var/log/journal ]]; then
  echo "Stopping systemd-journald..."
  systemctl stop systemd-journald || true
  sleep 1

  echo "Wiping /var/log/journal/* ..."
  rm -rf /var/log/journal/* || true

  echo "Starting systemd-journald..."
  systemctl start systemd-journald || true
  sleep 1

  if systemctl is-active --quiet systemd-journald; then
    echo "systemd-journald is active."
  else
    echo "WARNING: systemd-journald does not appear active yet (check: systemctl status systemd-journald)."
  fi
else
  echo "NOTE: /var/log/journal does not exist; skipping"
fi

# ---------------- Action 3: Cron install ----------------
echo
echo "Monthly cron vacuum - set for the first of each month"

# Log cron output so support can validate it ran
CRON_LOG="/var/log/wrn_journal_fix_cron.log"
CRONLINE="0 3 1 * * /usr/bin/journalctl --vacuum-size=200M >> ${CRON_LOG} 2>&1"

TMPCRON="$(mktemp)"
# Remove prior duplicates of our journalctl vacuum line, then append
crontab -l 2>/dev/null | grep -Fv "/usr/bin/journalctl --vacuum-size=200M" > "$TMPCRON" || true
echo "$CRONLINE" >> "$TMPCRON"
crontab "$TMPCRON"
rm -f "$TMPCRON"

echo "Installed/updated cron line:"
crontab -l | grep -F "/usr/bin/journalctl --vacuum-size=200M" || true
echo "Cron log will write to: $CRON_LOG"

# ---------------- After metrics ----------------
AFTER_USED_MB="$(df -Pm / | awk 'NR==2 {print $3}' || echo "$BEFORE_USED_MB")"
FREED_MB=$(( BEFORE_USED_MB - AFTER_USED_MB ))
# This is approximate; filesystem accounting can shift during the run.
# Avoid negative values to prevent confusion.
if (( FREED_MB < 0 )); then FREED_MB=0; fi

echo
echo "AFTER"
df -h / || true
journalctl --disk-usage || true

echo
echo "================================================"
echo "RESULTS SUMMARY"
echo "------------------------------------------------"
echo "Disk used before : ${BEFORE_USED_MB} MB"
echo "Disk used after  : ${AFTER_USED_MB} MB"
echo "Space reclaimed  : ${FREED_MB} MB (approx.)"
echo
echo "Monthly journal maintenance installed via cron."
echo "WRN Legacy Journal Fix completed @ $(date)"
echo "Log file: $LOG"
echo "================================================"

copy_log_to_downloads "$LOG"
