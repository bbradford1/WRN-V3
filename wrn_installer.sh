#!/usr/bin/env bash
# WRN installer v2.0 - distribution only, no maintenance execution
# Repository: bbradford1/WRN-V3
set -Eeuo pipefail
export LC_ALL=C
REPO_BASE="https://raw.githubusercontent.com/bbradford1/WRN-V3"
REF="${WRN_RELEASE_REF:-main}"
[[ "$REF" =~ ^[A-Za-z0-9._/-]+$ && "$REF" != *..* ]] || { echo 'Invalid WRN_RELEASE_REF' >&2; exit 2; }
[[ "${EUID}" -eq 0 ]] || { echo 'Run with sudo so ownership and directory are reliable.' >&2; exit 2; }
command -v curl >/dev/null || { echo 'curl is required.' >&2; exit 2; }
command -v sha256sum >/dev/null || { echo 'sha256sum is required.' >&2; exit 2; }
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || { echo 'Unsupported operating system (Ubuntu required).' >&2; exit 2; }
case "${VERSION_ID:-}" in
  18.04) FLAVOR=legacy ;;
  22.04) FLAVOR=modern ;;
  *) echo "Unsupported Ubuntu release: ${VERSION_ID:-unknown}; no files downloaded" >&2; exit 2 ;;
esac
REAL_USER="${SUDO_USER:-}"
if [[ -z "$REAL_USER" || "$REAL_USER" == root ]]; then
  # When operator is logged in directly, prefer known WAVE account, but do not guess a root home.
  REAL_USER="${USER:-}"
fi
[[ "$REAL_USER" != root && -n "$REAL_USER" ]] || { echo 'Run sudo from the wave desktop account, not a root session.' >&2; exit 2; }
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
[[ -d "$REAL_HOME" && "$REAL_HOME" != / ]] || { echo "No valid home for $REAL_USER" >&2; exit 2; }
TARGET_DIR="$REAL_HOME/Downloads"
install -d -m 0755 -o "$REAL_USER" "$TARGET_DIR"
TMPDIR_WRN="$(mktemp -d "$TARGET_DIR/.wrn-download.XXXXXXXX")"
trap 'rm -rf -- "$TMPDIR_WRN"' EXIT
FILE_NAMES=(wrn_archive_cleanup.sh)
if [[ $FLAVOR == legacy ]]; then
  FILE_NAMES+=(Legacy-WRN-Cleanup.sh)
else
  FILE_NAMES+=(wrn_diagnostics_v1_6_1.sh wrn_maintenance_v10_1.sh wrn_run_v2.sh)
fi
printf 'WRN installer v2.0\nOS: %s\nBranch: %s\nGitHub ref: %s\nTarget: %s\n\n' "$PRETTY_NAME" "$FLAVOR" "$REF" "$TARGET_DIR"
# Download every required file to staging before replacing any existing version.
for fname in "${FILE_NAMES[@]}"; do
  url="$REPO_BASE/$REF/$fname"
  echo "Downloading $fname"
  curl --fail --location --silent --show-error --retry 2 --connect-timeout 10 --max-time 90 \
    --proto '=https' --proto-redir '=https' -o "$TMPDIR_WRN/$fname" "$url"
  [[ -s "$TMPDIR_WRN/$fname" ]] || { echo "Empty download: $fname" >&2; exit 1; }
  head -n 1 "$TMPDIR_WRN/$fname" | grep -qx '#!/usr/bin/env bash' || { echo "Unexpected content: $fname" >&2; exit 1; }
  bash -n "$TMPDIR_WRN/$fname" || { echo "Syntax validation failed: $fname" >&2; exit 1; }
done
# Publish the full set only after all downloads validate.
for fname in "${FILE_NAMES[@]}"; do
  install -m 0755 "$TMPDIR_WRN/$fname" "$TARGET_DIR/$fname"
  chown "$REAL_USER" "$TARGET_DIR/$fname"
done
MANIFEST="$TARGET_DIR/WRN-Downloaded_$(date -u +%Y%m%dT%H%M%SZ).txt"
{
  echo "OS=$PRETTY_NAME"
  echo "Flavor=$FLAVOR"
  echo "RepositoryRef=$REF"
  echo "InstalledAt=$(date -Is)"
  for fname in "${FILE_NAMES[@]}"; do
    sha256sum "$TARGET_DIR/$fname"
  done
} > "$MANIFEST"
chown "$REAL_USER" "$MANIFEST"
printf '\nDOWNLOAD COMPLETE. Download manifest: %s\n' "$MANIFEST"
printf 'Installed:\n'; printf '  %s\n' "${FILE_NAMES[@]}"
if [[ $FLAVOR == modern ]]; then
  cat <<'INFO'

Modern WRN: run one supervised maintenance sequence:
  sudo bash ~/Downloads/wrn_run_v2.sh --apply

Dry run (no changes):
  sudo bash ~/Downloads/wrn_run_v2.sh --preview

Archive cleanup (SEPARATE, dry-run only):
  sudo bash ~/Downloads/wrn_archive_cleanup.sh
INFO
else
  cat <<'INFO'

Legacy WRN: run manually after reviewing journal data:
  sudo bash ~/Downloads/Legacy-WRN-Cleanup.sh

WARNING: legacy script stops journald, deletes historical journal files,
and installs cron. No automatic execution is performed.
Archive cleanup is separately provided in dry-run mode.
INFO
fi
