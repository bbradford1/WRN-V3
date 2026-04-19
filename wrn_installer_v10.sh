#!/usr/bin/env bash
# WRN v10 Installer Script
# Author: Bradford
# Purpose: Download the correct WRN maintenance script based on Ubuntu version.
#          Modern Ubuntu (>18) -> wrn_v10.sh.  Legacy Ubuntu (<=18) -> Legacy-WRN-Cleanup.sh.
#
# Distribute this URL to field techs:
#   wget -O - https://raw.githubusercontent.com/bbradford1/WRN-V3/main/wrn_installer_v10.sh | bash
#
# The previous installer (wrn_installer.sh -> wrn_v3.sh) is kept unchanged for
# anyone still using the old URL.

set -euo pipefail

# --- Repo raw URLs (same folder as installer) ---
URL_MODERN="https://raw.githubusercontent.com/bbradford1/WRN-V3/main/wrn_v10.sh"
URL_LEGACY="https://raw.githubusercontent.com/bbradford1/WRN-V3/main/Legacy-WRN-Cleanup-v2.sh"

# --- Resolve the "real" user + home (so Downloads is correct even with sudo) ---
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
TARGET_DIR="${REAL_HOME}/Downloads"

# --- OS detection (Ubuntu major) ---
get_ubuntu_major() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    # VERSION_ID like "22.04" -> "22"
    echo "${VERSION_ID%%.*}"
    return 0
  fi
  return 1
}

UBU_MAJOR="$(get_ubuntu_major || echo 0)"

echo "------------------------------------------------"
echo "WRN v10 Installer Script"
echo "------------------------------------------------"
echo "User:         ${REAL_USER}"
echo "Downloads:    ${TARGET_DIR}"
echo "Ubuntu major: ${UBU_MAJOR}"
echo "------------------------------------------------"

mkdir -p "$TARGET_DIR"

# --- Choose which script to download ---
if [[ "$UBU_MAJOR" -le 18 ]]; then
  TARGET="${TARGET_DIR}/Legacy-WRN-Cleanup-v2.sh"
  URL="$URL_LEGACY"
  LABEL="Legacy WRN Cleanup v2 (Ubuntu 18.x or older)"
else
  TARGET="${TARGET_DIR}/wrn_v10.sh"
  URL="$URL_MODERN"
  LABEL="WRN v10 (Ubuntu 20+)"
fi

echo "Selected: ${LABEL}"
echo "Downloading from:"
echo "  ${URL}"
echo "Saving to:"
echo "  ${TARGET}"
echo

# --- Download ---
wget -O "$TARGET" "$URL" || { echo "Download failed. Please check internet connection."; exit 1; }

# --- Fix line endings + permissions ---
sed -i 's/\r$//' "$TARGET" 2>/dev/null || true
chmod +x "$TARGET"
chown "$REAL_USER:$REAL_USER" "$TARGET" 2>/dev/null || true

echo
echo "Download complete."
echo
echo "Next: copy/paste this command to run it:"
echo "  cd ~/Downloads && sudo bash $(basename "$TARGET")"
echo "------------------------------------------------"
