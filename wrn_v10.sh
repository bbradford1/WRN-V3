#!/usr/bin/env bash
#
# wrn_v10.sh
# WRN (Hanwha WAVE Recorder Network) maintenance — v10
#
# Default run (no flags) is safe-by-default and does the following:
#   Tier 1 — Root-cause fixes (from HQ's fix_wave_init_logs_260114.sh):
#     • Repair logrotate.service (clear status, syntax-check, restart)
#     • Write persistent /etc/systemd/journald.conf size caps
#     • Write expanded /etc/logrotate.d/rsyslog policy (syslog/kern/auth/mail/daemon/user/cron/...)
#     • Write /etc/rsyslog.d/50-default.conf with $outchannel size-gates on syslog/kern/auth
#     • Restart systemd-journald + rsyslog so new config takes effect
#     • Backup every modified config under /var/backups/wrn_configs/<timestamp>/
#
#   Tier 2 — fstab data-disk UUID pinning (from update_fstab.sh):
#     • For /mnt/sd{a,b,c,d}: resolve partition → UUID → pin with nofail
#     • Skips the boot-disk parent device (safety)
#
#   Tier 3 — Reactive cleanup (from v9, keeping v9's truncate-over-delete rule):
#     • Truncate /var/log files >100M (preserves inodes, services keep writing)
#     • journalctl --vacuum-size=1G --vacuum-time=7d
#     • Delete rotated archives (/var/log/*.gz, *.[0-9])
#     • Force logrotate run
#     • Clear /var/crash, user trash, thumbnails, /home/*/core
#     • Disable + mask apport (prevents /var/crash refill)
#
#   Tier 4 — Bloat removal (safe subset of v3):
#     • Named-package purge (no globs except libreoffice-style-*)
#     • apt-mark hold on kernel before any apt operation
#     • Non-English language pack purge (excludes -en*)
#     • apt clean / autoclean
#     • Snap Tier B: refresh.retain=2, remove disabled revisions, clean cache,
#       remove snap-store + thunderbird snaps (keeps firefox, chromium, snapd, core*)
#
#   Tier 5 — Mediaserver maintenance (from v9, if Hanwha mediaserver detected):
#     • Audit /opt/hanwha/mediaserver/var → /var/log/wrn_v10_ms_audit_<ts>.log
#     • Compress old logs (>14d), truncate giant logs (>200M), delete cores (>7d),
#       clear transcoder/thumbnail caches
#
#   Tier 6 — Scheduling (new default):
#     • Install monthly cron running v10 --journal-only (announced in summary)
#
#   Always:
#     • Remove legacy NetworkManager wrn-delay.conf drop-in (v8 leftover)
#     • Capture read-only network diagnostics (no restart, no netplan apply)
#     • Mirror this run's log to every /home/*/Downloads for field pickup
#     • NEVER run apt autoremove, nuke /snap entirely, restart NetworkManager,
#       or prompt interactively (cron-safe)
#
# Opt-in flags (default-off):
#   --apt-autoremove        Run apt autoremove (off — can break kernel metapackages)
#   --purge-snap-entirely   Cleanly remove snapd + pin it (Tier C)
#   --purge-downloads       Clean /root/Downloads + /home/*/Downloads
#   --fix-fstab-loops       Comment /dev/loop* rows in /etc/fstab
#   --audit-only            Mediaserver audit only (no cleanup)
#   --journal-only          Safe subset only — what cron runs monthly
#   --no-reboot-prompt      Skip reboot hint
#
# Opt-out flags (default-on behaviour):
#   --no-ms                 Skip mediaserver maintenance
#   --no-fstab              Skip fstab UUID pinning
#   --no-bloat              Skip package/lang/snap bloat removal
#   --no-logfix             Skip Tier 1 config writes (not usually useful)
#   --no-cron               Don't install monthly cron
#
# Usage:
#   sudo bash wrn_v10.sh                 # default run
#   sudo bash wrn_v10.sh --journal-only  # safe subset (what cron uses)
#   sudo bash wrn_v10.sh --help          # this help
#

set -euo pipefail

# ---------------- Self-elevate ----------------
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo --preserve-env=PATH "$0" "$@"
fi

# ---------------- Constants ----------------
SCRIPT_NAME="wrn_v10.sh"
SCRIPT_VERSION="10.0"
NOW="$(date +%Y%m%d_%H%M%S)"
LOGFILE="/var/log/wrn_v10.log"
BACKUP_ROOT="/var/backups/wrn_configs/${NOW}"
CRON_LOG="/var/log/wrn_v10_cron.log"
CRON_SCRIPT="/root/wrn_v10.sh"

MS_VAR="/opt/hanwha/mediaserver/var"
MS_DATA="${MS_VAR}/data"
MS_LOG="${MS_VAR}/log"

# Begin teeing all output to the run log
exec > >(tee -a "$LOGFILE") 2>&1

# ---------------- Defaults (safe) ----------------
DO_MS=true
DO_FSTAB=true
DO_BLOAT=true
DO_LOGFIX=true
DO_APPORT=true
DO_SNAP_MGMT=true
INSTALL_CRON=true

DO_APT_AUTOREMOVE=false
DO_PURGE_SNAP_ENTIRELY=false
DO_PURGE_DOWNLOADS=false
FIX_FSTAB_LOOPS=false
AUDIT_ONLY=false
JOURNAL_ONLY=false
NO_REBOOT_PROMPT=false

# ---------------- Helpers ----------------
declare -a SUMMARY
add_summary() { SUMMARY+=("$1"); }

die() { echo "ERROR: $*" >&2; exit 1; }

usage() {
  sed -n '3,70p' "$0" | sed 's/^# \{0,1\}//'
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
  # $1 = file to back up. Copied (with -a) into $BACKUP_ROOT, preserving basename.
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
    --no-ms)                DO_MS=false ;;
    --no-fstab)             DO_FSTAB=false ;;
    --no-bloat)             DO_BLOAT=false ;;
    --no-logfix)            DO_LOGFIX=false ;;
    --no-cron)              INSTALL_CRON=false ;;
    --apt-autoremove)       DO_APT_AUTOREMOVE=true ;;
    --purge-snap-entirely)  DO_PURGE_SNAP_ENTIRELY=true ;;
    --purge-downloads)      DO_PURGE_DOWNLOADS=true ;;
    --fix-fstab-loops)      FIX_FSTAB_LOOPS=true ;;
    --audit-only)           AUDIT_ONLY=true ;;
    --journal-only)         JOURNAL_ONLY=true ;;
    --no-reboot-prompt)     NO_REBOOT_PROMPT=true ;;
    --help|-h)              usage ;;
    *) die "Unknown option: $1 (try --help)" ;;
  esac
  shift
done

# JOURNAL_ONLY cascades: disable everything that isn't safe-for-cron
if $JOURNAL_ONLY; then
  DO_MS=false
  DO_FSTAB=false
  DO_BLOAT=false
  DO_LOGFIX=false
  DO_SNAP_MGMT=false
  INSTALL_CRON=false
  # Keep apport disable + crash/trash cleanup — both idempotent + safe
fi

# ---------------- OS guard ----------------
os_guard() {
  [[ -r /etc/os-release ]] || { echo "[WARN] /etc/os-release unreadable; proceeding with caution"; return 0; }
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    echo "[WARN] Non-Ubuntu system detected (${ID:-unknown}); proceeding."
    return 0
  fi
  local ver="${VERSION_ID:-}"
  [[ -n "$ver" ]] || die "Cannot determine Ubuntu version (VERSION_ID empty)"
  local major="${ver%%.*}"
  if (( major <= 18 )); then
    die "Ubuntu ${ver} detected — use the legacy WRN script instead (Ubuntu 18 or older)."
  fi
  echo "[OK] Ubuntu ${ver} — compatible"
}

# ---------------- Start banner ----------------
echo "================================================"
echo "${SCRIPT_NAME} (v${SCRIPT_VERSION}) start @ $(date)"
echo "Flags:"
echo "  DO_MS=$DO_MS  DO_FSTAB=$DO_FSTAB  DO_BLOAT=$DO_BLOAT  DO_LOGFIX=$DO_LOGFIX"
echo "  DO_APPORT=$DO_APPORT  DO_SNAP_MGMT=$DO_SNAP_MGMT  INSTALL_CRON=$INSTALL_CRON"
echo "  AUDIT_ONLY=$AUDIT_ONLY  JOURNAL_ONLY=$JOURNAL_ONLY"
echo "  DO_APT_AUTOREMOVE=$DO_APT_AUTOREMOVE  DO_PURGE_SNAP_ENTIRELY=$DO_PURGE_SNAP_ENTIRELY"
echo "  DO_PURGE_DOWNLOADS=$DO_PURGE_DOWNLOADS  FIX_FSTAB_LOOPS=$FIX_FSTAB_LOOPS"
echo "================================================"

os_guard
ensure_backup_dir

# ---------------- Remove legacy NM delay drop-in (always) ----------------
remove_legacy_nm_delay() {
  local f="/etc/systemd/system/NetworkManager.service.d/wrn-delay.conf"
  if [[ -f "$f" ]]; then
    rm -f "$f"
    systemctl daemon-reload >/dev/null 2>&1 || true
    add_summary "Removed legacy NM delay drop-in ($f)"
  fi
}
remove_legacy_nm_delay

# =================================================================
# Tier 1 — Root-cause log-bloat prevention (from newer HQ script)
# =================================================================

fix_logrotate_service() {
  echo
  echo "== Repair logrotate.service =="

  # Remove stray backup files that break logrotate parsing
  if ls /etc/logrotate.d/*.backup.* >/dev/null 2>&1; then
    rm -f /etc/logrotate.d/*.backup.*
    add_summary "Removed stray backup files from /etc/logrotate.d/"
  fi

  if ! systemctl is-active --quiet logrotate.service 2>/dev/null \
     && ! systemctl list-timers 2>/dev/null | grep -q 'logrotate.timer'; then
    # Clear status so rotation dates reset
    [[ -f /var/lib/logrotate/status ]] && rm -f /var/lib/logrotate/status
    # Validate syntax
    if logrotate -d /etc/logrotate.conf >/tmp/wrn_v10_logrotate_check.log 2>&1; then
      add_summary "logrotate config syntax OK"
    else
      add_summary "logrotate config has warnings (see /tmp/wrn_v10_logrotate_check.log)"
    fi
    systemctl restart logrotate.service 2>/dev/null || \
      /usr/sbin/logrotate -f /etc/logrotate.conf 2>/dev/null || true
    add_summary "logrotate.service restarted (or force-run)"
  else
    add_summary "logrotate.service/timer already active"
  fi
}

write_journald_conf() {
  local f="/etc/systemd/journald.conf"
  backup_file "$f"
  cat > "$f" <<'EOF'
# Managed by wrn_v10.sh — persistent journal size caps for WRN appliances.
# See journald.conf(5) for details.

[Journal]
SystemMaxUse=100M
SystemKeepFree=50M
SystemMaxFileSize=50M
SystemMaxFiles=5
EOF
  add_summary "journald.conf set to SystemMaxUse=100M, MaxFiles=5"
}

write_rsyslog_logrotate() {
  local f="/etc/logrotate.d/rsyslog"
  backup_file "$f"
  cat > "$f" <<'EOF'
# Managed by wrn_v10.sh — expanded rsyslog rotation policy for WRN appliances.
su root syslog

/var/log/syslog
{
    rotate 2
    daily
    size 350M
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}

/var/log/kern.log
{
    rotate 2
    daily
    size 25M
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}

/var/log/auth.log
{
    rotate 2
    daily
    size 25M
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}

/var/log/mail.info
/var/log/mail.warn
/var/log/mail.err
/var/log/mail.log
/var/log/daemon.log
/var/log/user.log
/var/log/lpr.log
/var/log/cron.log
/var/log/debug
/var/log/messages
{
    rotate 2
    daily
    size 25M
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF
  add_summary "rsyslog logrotate policy written (syslog/kern/auth + mail/daemon/user/cron/...)"
}

write_rsyslog_default_conf() {
  local f="/etc/rsyslog.d/50-default.conf"
  [[ -f "$f" ]] || { add_summary "rsyslog 50-default.conf missing; skipped outchannel edit"; return; }
  backup_file "$f"
  cat > "$f" <<'EOF'
#  Default rules for rsyslog — managed by wrn_v10.sh
#  outchannel size-gates prevent runaway syslog/kern.log/auth.log growth
#  See rsyslog.conf(5) for details.

auth,authpriv.*                 /var/log/auth.log
$outchannel mysyslog,/var/log/syslog,367001600
*.*;auth,authpriv.none          :omfile:$mysyslog
$outchannel mykern,/var/log/kern.log,26214400
*.*;auth,authpriv.none          :omfile:$mykern
$outchannel myauth,/var/log/auth.log,26214400
*.*;auth,authpriv.none          :omfile:$myauth
kern.*                          -/var/log/kern.log
mail.*                          -/var/log/mail.log
mail.err                        /var/log/mail.err
*.emerg                         :omusrmsg:*
EOF
  add_summary "rsyslog 50-default.conf written with outchannel gates on syslog/kern/auth"
}

restart_logging_services() {
  echo
  echo "== Restart local logging services (safe) =="
  systemctl restart systemd-journald 2>/dev/null && add_summary "systemd-journald restarted" \
    || add_summary "systemd-journald restart failed (non-fatal)"
  systemctl restart rsyslog 2>/dev/null && add_summary "rsyslog restarted" \
    || add_summary "rsyslog restart failed (non-fatal)"
}

tier1_logfix() {
  if ! $DO_LOGFIX; then
    add_summary "Tier 1 log-bloat prevention skipped (--no-logfix / --journal-only)"
    return
  fi
  fix_logrotate_service
  write_journald_conf
  write_rsyslog_logrotate
  write_rsyslog_default_conf
  restart_logging_services
}

# =================================================================
# Tier 3 — Reactive log / journal cleanup
# =================================================================

truncate_oversized_logs() {
  echo
  echo "== Truncate oversized /var/log files (>100M) =="
  local count=0
  while IFS= read -r -d '' f; do
    : > "$f" || true
    count=$((count+1))
  done < <(find /var/log -type f -size +100M -print0 2>/dev/null || true)
  add_summary "Truncated /var/log files >100M: ${count}"
}

journald_vacuum() {
  echo
  echo "== journald vacuum =="
  journalctl --disk-usage || true
  journalctl --vacuum-size=1G || true
  journalctl --vacuum-time=7d || true
  journalctl --disk-usage || true
  add_summary "journald vacuumed to 1G / 7d"
}

delete_rotated_archives() {
  echo
  echo "== Delete rotated log archives =="
  local count=0
  count=$(( $(find /var/log -type f \( -name '*.gz' -o -regex '.*\.[0-9]+' \) -print 2>/dev/null | wc -l) ))
  find /var/log -type f \( -name '*.gz' -o -regex '.*\.[0-9]+' \) -delete 2>/dev/null || true
  add_summary "Deleted rotated archives (*.gz, *.[0-9]): ${count}"
}

force_logrotate_run() {
  echo
  echo "== Force logrotate run =="
  logrotate -f /etc/logrotate.conf 2>/dev/null || true
  add_summary "Forced logrotate -f /etc/logrotate.conf"
}

clean_crash_and_trash() {
  echo
  echo "== Clear /var/crash + user trash/thumbnails/cores =="
  rm -rf /var/crash/* 2>/dev/null || true
  rm -rf /root/.local/share/Trash/* /root/.cache/thumbnails/* 2>/dev/null || true
  rm -rf /home/*/.local/share/Trash/* /home/*/.cache/thumbnails/* 2>/dev/null || true
  # /home/*/core and /root/core — iterate, never assume a fixed username
  local cores
  cores=$(find /home /root -maxdepth 2 -type f -name 'core' 2>/dev/null || true)
  if [[ -n "$cores" ]]; then
    find /home /root -maxdepth 2 -type f -name 'core' -delete 2>/dev/null || true
    add_summary "Removed stray user core dumps"
  fi
  add_summary "Cleared /var/crash + user trash + thumbnail caches"
}

disable_apport() {
  if ! $DO_APPORT; then return; fi
  if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx 'apport.service'; then
    systemctl disable apport.service 2>/dev/null || true
    systemctl mask    apport.service 2>/dev/null || true
    add_summary "apport disabled + masked (prevents /var/crash refill)"
  fi
}

# =================================================================
# Tier 4 — Bloat removal
# =================================================================

apt_bloat_purge() {
  echo
  echo "== apt bloat purge (named packages only) =="

  # Hold kernel to guarantee apt never removes it
  apt-mark hold linux-image-generic linux-headers-generic >/dev/null 2>&1 || true
  add_summary "Kernel metapackages held (safety)"

  apt-get update -y >/dev/null 2>&1 || add_summary "apt-get update had errors (non-fatal)"

  # Named packages only — no wildcards that could cascade. libreoffice-style-* is pure-data, safe to glob.
  local TO_PURGE=(
    libreoffice-common libreoffice-core libreoffice-writer libreoffice-calc
    libreoffice-impress libreoffice-draw libreoffice-math libreoffice-base-core
    libreoffice-style-breeze libreoffice-style-colibre libreoffice-style-elementary
    libreoffice-style-sifr libreoffice-style-tango libreoffice-style-yaru
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

# -------------------- Snap management --------------------

is_ubuntu_core() {
  [[ -r /etc/os-release ]] && grep -q '^NAME="Ubuntu Core' /etc/os-release
}

snap_management_tier_b() {
  if ! command -v snap >/dev/null 2>&1; then
    add_summary "snap not installed — snap management skipped"
    return
  fi
  if is_ubuntu_core; then
    add_summary "Ubuntu Core detected — snap management skipped (snap is the OS)"
    return
  fi

  echo
  echo "== Snap management (Tier B: safe hygiene + targeted removals) =="

  snap set system refresh.retain=2 2>/dev/null \
    && add_summary "snap refresh.retain=2" \
    || add_summary "snap refresh.retain set failed (non-fatal)"

  # Remove disabled revisions — biggest disk saver, zero risk
  local removed=0
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local name rev
    name="$(awk '{print $1}' <<<"$line")"
    rev="$(awk '{print $3}' <<<"$line")"
    if snap remove "$name" --revision="$rev" >/dev/null 2>&1; then
      removed=$((removed+1))
    fi
  done < <(LANG=C snap list --all 2>/dev/null | awk '/disabled/{print $1" "$2" "$3}')
  add_summary "Removed ${removed} disabled snap revision(s)"

  # Cache clean
  if [[ -d /var/lib/snapd/cache ]]; then
    rm -rf /var/lib/snapd/cache/* 2>/dev/null || true
    add_summary "Cleared /var/lib/snapd/cache/*"
  fi

  # Targeted app removals (keeps firefox, chromium — user's browsers of choice)
  local SNAP_REMOVE=(snap-store thunderbird)
  local removed_apps=0
  for s in "${SNAP_REMOVE[@]}"; do
    if snap list 2>/dev/null | awk 'NR>1{print $1}' | grep -qx "$s"; then
      if snap remove --purge "$s" >/dev/null 2>&1; then
        removed_apps=$((removed_apps+1))
      fi
    fi
  done
  add_summary "Removed ${removed_apps} named snap app(s) [snap-store, thunderbird]"
}

purge_snap_entirely() {
  if ! $DO_PURGE_SNAP_ENTIRELY; then return; fi
  if ! command -v snap >/dev/null 2>&1; then
    add_summary "--purge-snap-entirely: snap not installed"
    return
  fi
  if is_ubuntu_core; then
    add_summary "--purge-snap-entirely: refused (Ubuntu Core — would brick system)"
    return
  fi

  echo
  echo "== Purge snap entirely (--purge-snap-entirely) =="

  # 1. Remove all snaps (apps first; bases last happen naturally since base snaps block on dependents)
  while IFS= read -r s; do
    [[ -z "$s" ]] && continue
    snap remove --purge "$s" >/dev/null 2>&1 || true
  done < <(snap list 2>/dev/null | awk 'NR>1{print $1}')

  # 2. Stop + disable + mask snapd services
  systemctl stop    snapd.service snapd.socket snapd.seeded.service 2>/dev/null || true
  systemctl disable snapd.service snapd.socket snapd.seeded.service 2>/dev/null || true
  systemctl mask    snapd.service snapd.socket 2>/dev/null || true

  # 3. Lazy unmount anything still clinging to /snap
  while IFS= read -r m; do
    [[ -z "$m" ]] && continue
    umount -l "$m" 2>/dev/null || true
  done < <(mount | awk '/\/snap\// {print $3}' | tac)

  # 4. apt purge snapd (keeps dpkg consistent)
  apt-get purge -y snapd >/dev/null 2>&1 || true

  # 5. Wipe state dirs
  rm -rf /var/cache/snapd /var/snap /var/lib/snapd 2>/dev/null || true
  rm -rf /home/*/snap /root/snap 2>/dev/null || true

  # 6. Prevent reinstall
  apt-mark hold snapd >/dev/null 2>&1 || true
  cat > /etc/apt/preferences.d/no-snap.pref <<'EOF'
Package: snapd
Pin: release a=*
Pin-Priority: -10
EOF

  add_summary "Snap purged entirely + apt pinned to prevent reinstall"
}

# -------------------- Downloads cleanup (opt-in) --------------------
purge_downloads() {
  if ! $DO_PURGE_DOWNLOADS; then return; fi
  echo
  echo "== Purge Downloads folders (--purge-downloads) =="
  local cleared=0
  for d in /root/Downloads /home/*/Downloads; do
    [[ -d "$d" ]] || continue
    rm -rf "$d"/* 2>/dev/null || true
    cleared=$((cleared+1))
  done
  add_summary "Cleared ${cleared} Downloads folder(s) (--purge-downloads)"
}

tier4_bloat() {
  if ! $DO_BLOAT; then
    add_summary "Tier 4 bloat removal skipped (--no-bloat / --journal-only)"
    return
  fi
  apt_bloat_purge
  if $DO_SNAP_MGMT; then
    snap_management_tier_b
  fi
  purge_snap_entirely   # internally gated on --purge-snap-entirely
  purge_downloads       # internally gated on --purge-downloads
}

# =================================================================
# Tier 2 — fstab data-disk UUID pinning (from update_fstab.sh)
# =================================================================

pin_fstab_data_disks() {
  if ! $DO_FSTAB; then
    add_summary "fstab UUID pinning skipped (--no-fstab / --journal-only)"
    return
  fi

  echo
  echo "== fstab data-disk UUID pinning =="

  local FSTAB=/etc/fstab
  backup_file "$FSTAB"

  # Identify root parent (to skip it for safety)
  local ROOT_SRC ROOT_UUID ROOT_PARENT
  ROOT_SRC="$(findmnt -n / -o SOURCE 2>/dev/null || true)"
  ROOT_UUID="$(blkid -o value -s UUID "$ROOT_SRC" 2>/dev/null || true)"
  ROOT_PARENT="/dev/$(lsblk -no PKNAME "$ROOT_SRC" 2>/dev/null || echo '')"
  echo "  root source:  ${ROOT_SRC}"
  echo "  root UUID:    ${ROOT_UUID}"
  echo "  root parent:  ${ROOT_PARENT}"

  local TARGETS=(/mnt/sda /mnt/sdb /mnt/sdc /mnt/sdd)

  # Pre-create mountpoint dirs
  for mp in "${TARGETS[@]}"; do
    mkdir -p "$mp"
  done

  pick_first_partition() {
    local base="$1"
    lsblk -nr -o NAME,TYPE "$base" 2>/dev/null | awk '$2=="part"{print "/dev/"$1; exit}'
  }

  local pinned=0 skipped=0
  for mp in "${TARGETS[@]}"; do
    local base dev
    base="$(basename "$mp")"         # sda / sdb / ...
    dev="/dev/${base}"
    if [[ "$dev" == "$ROOT_PARENT" ]]; then
      echo "  SKIP ${mp}: ${dev} is the root parent"
      skipped=$((skipped+1))
      continue
    fi
    if [[ ! -b "$dev" ]]; then
      echo "  SKIP ${mp}: ${dev} does not exist"
      skipped=$((skipped+1))
      continue
    fi
    local part
    part="$(pick_first_partition "$dev")"
    [[ -n "$part" ]] || { echo "  SKIP ${mp}: no partition on ${dev}"; skipped=$((skipped+1)); continue; }

    local INFO UUID TYPE PARTUUID
    INFO="$(blkid -c /dev/null -o export "$part" 2>/dev/null || true)"
    [[ -n "$INFO" ]] || { echo "  SKIP ${mp}: blkid returned nothing"; skipped=$((skipped+1)); continue; }
    UUID=""; TYPE=""; PARTUUID=""
    eval "$INFO"
    if [[ -n "$ROOT_UUID" && "${UUID:-}" == "$ROOT_UUID" ]]; then
      echo "  SKIP ${mp}: UUID matches root (refusing to re-mount OS disk)"
      skipped=$((skipped+1))
      continue
    fi

    local IDENT FSTYPE
    if [[ -n "${UUID:-}" ]]; then
      IDENT="UUID=${UUID}"
    elif [[ -n "${PARTUUID:-}" ]]; then
      IDENT="PARTUUID=${PARTUUID}"
    else
      echo "  SKIP ${mp}: neither UUID nor PARTUUID available"
      skipped=$((skipped+1))
      continue
    fi
    FSTYPE="${TYPE:-auto}"
    echo "  ${mp} -> ${IDENT} (${FSTYPE})"

    # Upsert the row in /etc/fstab
    if awk -v mp="$mp" '$0 !~ /^[[:space:]]*#/ && $2==mp {found=1} END{exit !found}' "$FSTAB"; then
      local tmp
      tmp="$(mktemp)"
      awk -v mp="$mp" -v id="$IDENT" -v fs="$FSTYPE" '
        $0 ~ /^[[:space:]]*#/ { print; next }
        $2==mp {
          $1=id; $3=fs
          n=split($4, a, ","); has=0
          for (i=1;i<=n;i++) if (a[i]=="nofail") has=1
          if (!has) $4=$4",nofail"
          gsub(/,,+/, ",", $4)
          print; next
        }
        { print }
      ' "$FSTAB" > "$tmp"
      mv "$tmp" "$FSTAB"
    else
      printf "%-22s %-12s %-8s %-20s %d %d\n" "$IDENT" "$mp" "$FSTYPE" "defaults,nofail" 0 2 >> "$FSTAB"
    fi

    if mount "$mp" 2>/dev/null; then
      pinned=$((pinned+1))
    else
      echo "  WARN: mount ${mp} failed (left in fstab for next boot)"
    fi
  done

  if mount -a 2>/dev/null; then
    add_summary "fstab pinned ${pinned} data disk(s); ${skipped} skipped; mount -a OK"
  else
    add_summary "fstab pinned ${pinned} data disk(s); mount -a reported errors (backup in ${BACKUP_ROOT})"
  fi
}

# -------------------- fstab loop comment (opt-in) --------------------
fix_fstab_loops() {
  if ! $FIX_FSTAB_LOOPS; then return; fi
  echo
  echo "== Comment /dev/loop* in /etc/fstab (--fix-fstab-loops) =="
  local F=/etc/fstab
  backup_file "$F"
  sed -i -E 's#^(/dev/loop[0-9]+[[:space:]].*)$#\# wrn_v10 disabled: \1#' "$F"
  add_summary "fstab: /dev/loop* rows commented"
}

# =================================================================
# Tier 5 — Mediaserver maintenance (from v9)
# =================================================================

detect_ms_service() {
  command -v systemctl >/dev/null 2>&1 || { echo ""; return; }
  for s in hanwha-mediaserver.service networkoptix-mediaserver.service mediaserver.service; do
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$s"; then
      echo "$s"; return
    fi
  done
  echo ""
}

ms_audit() {
  local svc="$1"
  local out="/var/log/wrn_v10_ms_audit_${NOW}.log"
  {
    echo "Mediaserver Audit @ $(date)"
    echo "Unit: ${svc:-none}"
    echo
    df -hT
    echo
    [[ -d "$MS_DATA" ]] && { echo "== ${MS_DATA} =="; du -xh --max-depth=1 "$MS_DATA" 2>/dev/null | sort -h; } || echo "Missing ${MS_DATA}"
    echo
    [[ -d "$MS_LOG"  ]] && { echo "== ${MS_LOG} ==";  du -xh --max-depth=1 "$MS_LOG"  2>/dev/null | sort -h; } || echo "Missing ${MS_LOG}"
    echo
    journalctl --disk-usage || true
  } > "$out"
  add_summary "Mediaserver audit saved: ${out}"
  copy_log_to_downloads "$out"
}

ms_cleanup_safe() {
  [[ -d "$MS_VAR" ]] || { add_summary "Mediaserver paths not present; cleanup skipped"; return; }

  if [[ -d "$MS_LOG" ]]; then
    find "$MS_LOG" -type f -name '*.log' -mtime +14 -print0 2>/dev/null \
      | while IFS= read -r -d '' f; do gzip -9 "$f" 2>/dev/null || true; done
    find "$MS_LOG" -type f -size +200M -print0 2>/dev/null \
      | while IFS= read -r -d '' f; do : > "$f" 2>/dev/null || true; done
  fi
  find "$MS_VAR" -type f \( -name 'core.*' -o -name '*.dmp' \) -mtime +7 -delete 2>/dev/null || true
  if [[ -d "$MS_DATA" ]]; then
    for d in transcoder_cache thumbnail_cache tmp temp cache exports/tmp; do
      [[ -e "$MS_DATA/$d" ]] && rm -rf "$MS_DATA/$d" 2>/dev/null || true
    done
  fi
  add_summary "Mediaserver cleanup: logs/caches/cores bounded to ${MS_VAR}"
}

mediaserver_main() {
  if ! $DO_MS; then
    add_summary "Mediaserver maintenance skipped (--no-ms / --journal-only)"
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

  if [[ -n "$svc" ]]; then
    systemctl stop "$svc" 2>/dev/null && add_summary "Stopped ${svc}" || true
  fi
  ms_cleanup_safe
  if [[ -n "$svc" ]]; then
    systemctl start "$svc" 2>/dev/null && add_summary "Started ${svc}" || true
  fi
}

# =================================================================
# Tier 6 — Cron install (default-on)
# =================================================================

install_cron() {
  if ! $INSTALL_CRON; then
    add_summary "Monthly cron NOT installed (--no-cron / --journal-only)"
    return
  fi

  echo
  echo "== Install monthly cron (default) =="

  # Keep a canonical copy at /root so the cron target is stable
  cp -f "$0" "$CRON_SCRIPT"
  chmod 755 "$CRON_SCRIPT"

  local tmp
  tmp="$(mktemp)"
  crontab -l 2>/dev/null | grep -v "$CRON_SCRIPT" > "$tmp" || true
  echo "30 3 1 * * /usr/bin/bash ${CRON_SCRIPT} --journal-only >> ${CRON_LOG} 2>&1" >> "$tmp"
  crontab "$tmp"
  rm -f "$tmp"

  add_summary "Monthly cron installed: 30 3 1 * * ${CRON_SCRIPT} --journal-only"
}

# =================================================================
# Network diagnostics (read-only, always safe)
# =================================================================

network_diagnostics() {
  echo
  echo "== Network diagnostics (read-only) =="
  ip -4 addr || true
  ip route || true
  if command -v nmcli >/dev/null 2>&1; then
    nmcli device status || true
    nmcli connection show --active || true
  fi
  add_summary "Captured network diagnostics (no changes applied)"
}

# =================================================================
# Main
# =================================================================

if $JOURNAL_ONLY; then
  # Safe-for-cron subset ONLY
  truncate_oversized_logs
  journald_vacuum
  delete_rotated_archives
  force_logrotate_run
  clean_crash_and_trash
  disable_apport
  network_diagnostics
  exit 0
fi

# Full default run
tier1_logfix
truncate_oversized_logs
journald_vacuum
delete_rotated_archives
force_logrotate_run
clean_crash_and_trash
disable_apport
tier4_bloat
pin_fstab_data_disks
fix_fstab_loops
mediaserver_main
install_cron
network_diagnostics

if ! $NO_REBOOT_PROMPT; then
  echo
  echo "NOTE: If packages/services changed, a reboot may be beneficial."
  echo "      Uptime: $(uptime -p 2>/dev/null || true)"
fi

exit 0
