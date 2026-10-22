#!/usr/bin/env bash
# WRN 22.04 single-command run: diagnostics -> maintenance -> diagnostics
set -Eeuo pipefail
export LC_ALL=C
[[ "${EUID}" -eq 0 ]] || { echo 'Use sudo bash ~/Downloads/wrn_run_v2.sh --apply' >&2; exit 2; }
MODE="${1:---preview}"
[[ $# -le 1 && ( "$MODE" == --preview || "$MODE" == --apply ) ]] || { echo 'Usage: sudo bash wrn_run_v2.sh [--preview|--apply]' >&2; exit 2; }
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 22.04 ]] || { echo 'STOP: Ubuntu 22.04 required' >&2; exit 2; }
OWNER="${SUDO_USER:-wave}"
HOME_DIR="$(getent passwd "$OWNER" | cut -d: -f6)"
[[ -d "$HOME_DIR/Downloads" ]] || { echo 'Downloads folder missing' >&2; exit 2; }
DIR="$HOME_DIR/Downloads"
for file in wrn_diagnostics_v1_6_1.sh wrn_maintenance_v10_1.sh; do
  [[ -s "$DIR/$file" ]] || { echo "STOP: $file missing" >&2; exit 2; }
  bash -n "$DIR/$file" || exit 2
done
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$DIR/WRN-RUN_$(hostname -s)_${STAMP}.txt"
exec > >(tee "$LOG") 2>&1
trap 's=$?; if (( s != 0 )); then echo "FAILED ($s): stop rollout for this server. Log: $LOG"; fi' EXIT
check() {
  [[ $(systemctl is-active hanwha-mediaserver 2>/dev/null || :) == active ]] || { echo 'STOP: WAVE inactive'; exit 10; }
  [[ $(systemctl is-active display-manager 2>/dev/null || :) == active ]] || { echo 'STOP: GDM inactive'; exit 11; }
  findmnt -n -o OPTIONS /mnt/sda 2>/dev/null | grep -Eq '(^|,)rw(,|$)' || { echo 'STOP: archive not mounted RW'; exit 12; }
}
echo "WRN RUN v2 | $MODE | $(date -Is)"
check
printf '\n=== BEFORE ===\n'; df -h /
if [[ "$MODE" == --preview ]]; then
  bash "$DIR/wrn_diagnostics_v1_6_1.sh"
  bash "$DIR/wrn_maintenance_v10_1.sh" --preview
  echo 'Preview complete. Nothing changed.'
else
  echo '=== PRE-MAINTENANCE DIAGNOSTICS ==='
  bash "$DIR/wrn_diagnostics_v1_6_1.sh"
  echo '=== MAINTENANCE ==='
  bash "$DIR/wrn_maintenance_v10_1.sh" --apply
  check
  echo '=== POST-MAINTENANCE DIAGNOSTICS ==='
  bash "$DIR/wrn_diagnostics_v1_6_1.sh"
  check
  echo '=== ARCHIVE CLEANUP ==='
  echo 'Not executed. The separate archive tool is dry-run by default and must be explicitly invoked.'
  echo '=== COMPLETE ==='
  df -h /
  echo 'Verify recent WAVE recording/playback manually. No reboot requested.'
fi
echo "Summary log: $LOG"
