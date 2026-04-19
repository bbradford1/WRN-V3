#!/usr/bin/env bash
#
# Legacy-WRN-Cleanup-v2.sh
# WRN (Hanwha WAVE Recorder Network) maintenance — Ubuntu 18.x or older
#
# Scope (narrower than wrn_v10.sh because 18.x WRNs don't exhibit the
# fstab or rsyslog/logrotate bugs that newer boxes do):
#
# Default run (no flags):
#   • Journal vacuum (size=500M, time=7d, files=5)
#   • Reset /var/log/journal (stop -> wipe -> start) — fixes runaway journald
#   • Write persistent /etc/systemd/journald.conf caps (prevents regrowth)
#   • Bloat removal (named packages only, no autoremove, kernel held)
#   • Non-English language packs (excludes -en*)
#   • Adjacent hygiene: apport disable+mask, /var/crash, user trash+thumbnails,
#     stray /home/*/core, rotated archives (/var/log/*.gz, *.[0-9])
#   • Install monthly cron running this script --journal-only
#   • Mirror this run's log to every /home/*/Downloads for field pickup
#
# Out of scope on 18.x (not needed per field experience):
#   • fstab UUID pinning      (modern-only bug)
#   • rsyslog/logrotate rewrite (modern-only bug)
#   • Mediaserver maintenance  (not typically deployed on 18.x WRNs)
#   • Snap management          (snap usage was minimal on 18.x)
#
# Opt-in flags:
#   --apt-autoremove     Run apt autoremove (off — kernel metapackage risk)
#   --journal-only       Safe subset only — what cron runs monthly
#   --force              Bypass OS guard (legacy script intentionally refuses
#                        to run on Ubuntu 19+; use --force only if you know why)
#   --no-reboot-prompt   Skip reboot hint
#
# Opt-out flags:
#   --no-bloat           Skip package/language-pack bloat removal
#   --no-cron            Don't install monthly cron
#
# Usage:
#   sudo bash Legacy-WRN-Cleanup-v2.sh                 # default run
#   sudo bash Legacy-WRN-Cleanup-v2.sh --journal-only  # safe subset
#   sudo bash Legacy-WRN-Cleanup-v2.sh --help          # this help
#

set -euo pipefail

# ---------------- Self-elevate ----------------
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo --preserve-env=PATH "$0" "$@"
fi

# ---------------- Constants ----------------
SCRIPT_NAME="Legacy-WRN-Cleanup-v2.sh"
SCRIPT_VERSION="2.0"
NOW="$(date +%Y%m%d_%H%M%S)"
LOGFILE="/var/log/wrn_legacy_v2.log"
BACKUP_ROOT="/var/backups/wrn_configs/${NOW}"
CRON_LOG="/var/log/wrn_legacy_v2_cron.log"
CRON_SCRIPT="/root/Legacy-WRN-Cleanup-v2.sh"

exec > >(tee -a "$LOGFILE") 2>&1

# ---------------- Defaults ----------------
DO_BLOAT=true
INSTALL_CRON=true
DO_APT_AUTOREMOVE=false
JOURNAL_ONLY=false
FORCE=false
NO_REBOOT_PROMPT=false

# ---------------- Helpers ----------------
declare -a SUMMARY
add_summary() { SUMMARY+=("$1"); }

die() { echo "ERROR: $*" >&2; exit 1; }

usage() {
  sed -n '3,41p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

free_space_mb()    { df --output=avail / | tail -1 | awk '{print $1}'; }
free_space_human() { df -h / | awk 'NR==2{print $4" free of "$2}'; }

copy_log_to_downloads() {
  local src="$1" base
  base="$(basename "$src")"
  for home in /home/*; do
    [[ -d "$home/Downloads" ]] || continue
    cp -f "$src" "$home/Downloads/$base" 2>/dev/null || true
  done
}

ensure_backup_dir() {
  mkdir -p "$BACKUP_ROOT"
  add_summary "Config backups for this run: ${BACKUP_ROOT}"
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  cp -a "$f" "${BACKUP_ROOT}/$(basename "$f").$(date +%H%M%S)"
}

START_MB="$(free_space_mb)"
START_HUMAN="$(free_space_human)"

# ---------------- Finalize / trap ----------------
finalize() {
  set +e
  local END_MB END_HUMAN RECLAIMED
  END_MB="$(free_space_mb 2>/dev/null || echo "$START_MB")"
  END_HUMAN="$(free_space_human 2>/dev/null || echo "$START_HUMAN")"
  RECLAIMED=$((END_MB - START_MB))

  echo
  echo "================================================"
  echo "${SCRIPT_NAME} (v${SCRIPT_VERSION}) COMPLETE @ $(date)"
  echo "Disk before: ${START_HUMAN}"
  echo "Disk after:  ${END_HUMAN}"
  echo "Reclaimed:   ${RECLAIMED} MB"
  echo "Logfile:     ${LOGFILE}"
  echo "Config bkps: ${BACKUP_ROOT}"
  echo "================================================"
  echo "---------------- ACTION SUMMARY ----------------"
  for line in "${SUMMARY[@]}"; do
    printf " - %s\n" "$line"
  done
  echo "------------------------------------------------"

  if $INSTALL_CRON && [[ -x "$CRON_SCRIPT" ]]; then
    echo
    echo "NOTE: Monthly cron is installed."
    echo "  Schedule: 30 3 1 * *  (03:30 on the 1st of each month)"
    echo "  Runs:     ${CRON_SCRIPT} --journal-only"
    echo "  Log:      ${CRON_LOG}"
    echo "  Remove with: crontab -e  (delete the ${CRON_SCRIPT} line)"
  fi
  echo "================================================"

  copy_log_to_downloads "$LOGFILE"
}
trap finalize EXIT

# ---------------- Parse args ----------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-bloat)          DO_BLOAT=false ;;
    --no-cron)           INSTALL_CRON=false ;;
    --apt-autoremove)    DO_APT_AUTOREMOVE=true ;;
    --journal-only)      JOURNAL_ONLY=true ;;
    --force)             FORCE=true ;;
    --no-reboot-prompt)  NO_REBOOT_PROMPT=true ;;
    --help|-h)           usage ;;
    *) die "Unknown option: $1 (try --help)" ;;
  esac
  shift
done

if $JOURNAL_ONLY; then
  DO_BLOAT=false
  INSTALL_CRON=false
fi

# ---------------- OS guard ----------------
# Legacy script intentionally refuses to run on 19+; those boxes should use wrn_v10.sh.
os_guard() {
  [[ -r /etc/os-release ]] || { echo "[WARN] /etc/os-release unreadable; proceeding with --force only"; $FORCE || die "Cannot verify OS; re-run with --force if intentional"; return 0; }
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    if $FORCE; then
      echo "[WARN] Non-Ubuntu (${ID:-unknown}); --force supplied, proceeding."
      return 0
    fi
    die "Non-Ubuntu system (${ID:-unknown}). Use --force only if you know what you're doing."
  fi
  local ver="${VERSION_ID:-}" major
  [[ -n "$ver" ]] || die "Cannot determine Ubuntu version"
  major="${ver%%.*}"
  if (( major > 18 )); then
    if $FORCE; then
      echo "[WARN] Ubuntu ${ver} detected — legacy script not intended for this version. --force supplied, proceeding."
      return 0
    fi
    die "Ubuntu ${ver} detected — use wrn_v10.sh instead (this legacy script is for Ubuntu 18.x or older)."
  fi
  echo "[OK] Ubuntu ${ver} — legacy-compatible"
}

# ---------------- Start banner ----------------
echo "================================================"
echo "${SCRIPT_NAME} (v${SCRIPT_VERSION}) start @ $(date)"
echo "Flags:"
echo "  DO_BLOAT=$DO_BLOAT  INSTALL_CRON=$INSTALL_CRON  JOURNAL_ONLY=$JOURNAL_ONLY"
echo "  DO_APT_AUTOREMOVE=$DO_APT_AUTOREMOVE  FORCE=$FORCE"
echo "================================================"

os_guard
ensure_backup_dir

# =================================================================
# Journal work — always runs (this is the whole point of the legacy script)
# =================================================================

journald_vacuum() {
  echo
  echo "== journald vacuum =="
  journalctl --disk-usage || true
  journalctl --vacuum-size=500M || true
  journalctl --vacuum-time=7d  || true
  journalctl --vacuum-files=5  || true
  journalctl --disk-usage || true
  add_summary "journald vacuumed (500M / 7d / 5 files)"
}

reset_journal_store() {
  # Skip in --journal-only mode — destructive and not appropriate for monthly cron
  if $JOURNAL_ONLY; then
    add_summary "Journal store reset skipped (--journal-only)"
    return
  fi
  echo
  echo "== Reset persistent journal store (/var/log/journal/*) =="
  if [[ -d /var/log/journal ]]; then
    systemctl stop systemd-journald 2>/dev/null || true
    sleep 1
    rm -rf /var/log/journal/* 2>/dev/null || true
    systemctl start systemd-journald 2>/dev/null || true
    sleep 1
    if systemctl is-active --quiet systemd-journald 2>/dev/null; then
      add_summary "Journal store reset; systemd-journald active"
    else
      add_summary "Journal store reset; systemd-journald NOT active — check systemctl status"
    fi
  else
    add_summary "/var/log/journal not present; journal reset skipped"
  fi
}

write_journald_conf() {
  # Skip config writes in --journal-only; cron shouldn't keep rewriting this
  if $JOURNAL_ONLY; then
    add_summary "journald.conf write skipped (--journal-only)"
    return
  fi
  local f="/etc/systemd/journald.conf"
  backup_file "$f"
  cat > "$f" <<'EOF'
# Managed by Legacy-WRN-Cleanup-v2.sh — persistent journal size caps for WRN 18.x appliances.
# See journald.conf(5) for details.

[Journal]
SystemMaxUse=100M
SystemKeepFree=50M
SystemMaxFileSize=50M
SystemMaxFiles=5
EOF
  systemctl restart systemd-journald 2>/dev/null && \
    add_summary "journald.conf written (SystemMaxUse=100M, MaxFiles=5); journald restarted" || \
    add_summary "journald.conf written; journald restart failed (non-fatal)"
}

# =================================================================
# Adjacent hygiene (default-on per user confirmation)
# =================================================================

delete_rotated_archives() {
  echo
  echo "== Delete rotated log archives =="
  local count
  count=$(find /var/log -type f \( -name '*.gz' -o -regex '.*\.[0-9]+' \) 2>/dev/null | wc -l)
  find /var/log -type f \( -name '*.gz' -o -regex '.*\.[0-9]+' \) -delete 2>/dev/null || true
  add_summary "Deleted rotated archives (*.gz, *.[0-9]): ${count}"
}

clean_crash_and_trash() {
  echo
  echo "== Clear /var/crash + user trash/thumbnails/cores =="
  rm -rf /var/crash/* 2>/dev/null || true
  rm -rf /root/.local/share/Trash/* /root/.cache/thumbnails/* 2>/dev/null || true
  rm -rf /home/*/.local/share/Trash/* /home/*/.cache/thumbnails/* 2>/dev/null || true
  local cores
  cores=$(find /home /root -maxdepth 2 -type f -name 'core' 2>/dev/null || true)
  if [[ -n "$cores" ]]; then
    find /home /root -maxdepth 2 -type f -name 'core' -delete 2>/dev/null || true
    add_summary "Removed stray user core dumps"
  fi
  add_summary "Cleared /var/crash + user trash + thumbnail caches"
}

disable_apport() {
  if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx 'apport.service'; then
    systemctl disable apport.service 2>/dev/null || true
    systemctl mask    apport.service 2>/dev/null || true
    add_summary "apport disabled + masked"
  fi
}

# =================================================================
# Bloat removal (default-on; --no-bloat to skip)
# =================================================================

bloat_purge() {
  if ! $DO_BLOAT; then
    add_summary "Bloat removal skipped (--no-bloat / --journal-only)"
    return
  fi

  echo
  echo "== apt bloat purge (named packages only) =="

  # Ubuntu 18 has linux-image-generic, sometimes linux-image-virtual on VMs.
  # Hold whichever exists — apt-mark tolerates missing names.
  apt-mark hold linux-image-generic linux-headers-generic linux-image-virtual linux-headers-virtual >/dev/null 2>&1 || true
  add_summary "Kernel metapackages held (safety)"

  apt-get update -y >/dev/null 2>&1 || add_summary "apt-get update had errors (non-fatal)"

  # Named packages appropriate for 18.x headless WRN.
  local TO_PURGE=(
    libreoffice-common libreoffice-core libreoffice-writer libreoffice-calc
    libreoffice-impress libreoffice-draw libreoffice-math libreoffice-base-core
    libreoffice-style-breeze libreoffice-style-colibre libreoffice-style-elementary
    libreoffice-style-sifr libreoffice-style-tango
    thunderbird rhythmbox shotwell cheese totem
    aisleriot gnome-mahjongg gnome-mines gnome-sudoku gnome-games
    cups cups-common cups-browsed cups-client cups-daemon
    printer-driver-all bluez-cups
  )

  local purged=0
  for p in "${TO_PURGE[@]}"; do
    if dpkg -l "$p" 2>/dev/null | awk '/^ii/{exit 0} END{exit 1}'; then
      if apt-get -y purge "$p" >/dev/null 2>&1; then
        purged=$((purged+1))
      fi
    fi
  done
  add_summary "Purged ${purged} bloat package(s) by name"

  # Non-English language packs (EXCLUDES -en*)
  local LANG_PKGS
  LANG_PKGS="$(dpkg -l 2>/dev/null | awk '/^ii/ && $2 ~ /^language-pack-/ && $2 !~ /^language-pack-en/ {print $2}')"
  if [[ -n "${LANG_PKGS:-}" ]]; then
    # shellcheck disable=SC2086
    apt-get -y purge $LANG_PKGS >/dev/null 2>&1 || true
    local n
    n="$(echo "$LANG_PKGS" | wc -w)"
    add_summary "Purged ${n} non-English language pack(s)"
  else
    add_summary "No non-English language packs to purge"
  fi

  apt-get clean    >/dev/null 2>&1 || true
  apt-get autoclean >/dev/null 2>&1 || true
  add_summary "apt clean + autoclean"

  if $DO_APT_AUTOREMOVE; then
    apt-get -y autoremove >/dev/null 2>&1 || add_summary "apt autoremove had errors (non-fatal)"
    add_summary "apt autoremove completed (--apt-autoremove)"
  else
    add_summary "apt autoremove skipped (default — not safe unattended)"
  fi
}

# =================================================================
# Cron install
# =================================================================

install_cron() {
  if ! $INSTALL_CRON; then
    add_summary "Monthly cron NOT installed (--no-cron / --journal-only)"
    return
  fi

  echo
  echo "== Install monthly cron (default) =="

  cp -f "$0" "$CRON_SCRIPT"
  chmod 755 "$CRON_SCRIPT"

  local tmp
  tmp="$(mktemp)"
  # Clean up any old cron lines from either this script or the legacy raw-journalctl line
  crontab -l 2>/dev/null \
    | grep -v "$CRON_SCRIPT" \
    | grep -v '/usr/bin/journalctl --vacuum-size=200M' \
    > "$tmp" || true
  echo "30 3 1 * * /usr/bin/bash ${CRON_SCRIPT} --journal-only >> ${CRON_LOG} 2>&1" >> "$tmp"
  crontab "$tmp"
  rm -f "$tmp"

  add_summary "Monthly cron installed: 30 3 1 * * ${CRON_SCRIPT} --journal-only"
}

# =================================================================
# Main
# =================================================================

if $JOURNAL_ONLY; then
  # Safe-for-cron subset ONLY
  journald_vacuum
  delete_rotated_archives
  clean_crash_and_trash
  disable_apport
  exit 0
fi

# Full default run
journald_vacuum
reset_journal_store
write_journald_conf
delete_rotated_archives
clean_crash_and_trash
disable_apport
bloat_purge
install_cron

if ! $NO_REBOOT_PROMPT; then
  echo
  echo "NOTE: If packages changed, a reboot may be beneficial."
  echo "      Uptime: $(uptime -p 2>/dev/null || true)"
fi

exit 0
