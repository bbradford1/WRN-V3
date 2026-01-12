#!/usr/bin/env bash
# WRN Installer Script
# Author: Bradford
# Purpose: Download the correct WRN maintenance script based on Ubuntu version

set -euo pipefail

# --- Repo raw URLs (same folder as installer) ---
URL_MODERN="https://raw.githubusercontent.com/bbradford1/WRN-V3/main/wrn_v3.sh"
URL_LEGACY="https://raw.githubusercontent.com/bbradford1/WRN-V3/main/Legacy-WRN-Cleanup.sh"

# --- Resolve the "real" user + home (so Downloads is correct even with sudo) ---
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
TARGET_DIR="${REAL_HOME}/Downloads"

# --- OS detection (Ubuntu major) ---
get_ubuntu_major() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    # VERSION_ID like "18.04" -> "18"
    echo "${VERSION_ID%%.*}"
    return 0
  fi
  return 1
}

UBU_MAJOR="$(get_ubuntu_major || echo 0)"

echo "------------------------------------------------"
echo "WRN Installer Script"
echo "------------------------------------------------"
echo "User:  ${REAL_USER}"
echo "Home:  ${REAL_HOME}"
echo "Ubuntu major: ${UBU_MAJOR}"
echo "------------------------------------------------"

mkdir -p "$TARGET_DIR"

# --- Choose which script to download ---
if [[ "$UBU_MAJOR" -le 18 ]]; then
  TARGET="${TARGET_DIR}/wrn_v3_legacy.sh"
  URL="$URL_LEGACY"
  LABEL="Legacy WRN Cleanup (Ubuntu 18.x or older)"
else
  TARGET="${TARGET_DIR}/wrn_v3.sh"
  URL="$URL_MODERN"
  LABEL="WRN v3 (Ubuntu 20+)"
fi

echo "Selected: ${LABEL}"
echo "Downloading to: ${TARGET}"
echo "Source URL:      ${URL}"
echo

# --- Download ---
wget -O "$TARGET" "$URL" || { echo "❌ Download failed. Please check internet connection."; exit 1; }

# --- Fix line endings + permissions ---
sed -i 's/\r$//' "$TARGET" 2>/dev/null || true
chmod +x "$TARGET"
chown "$REAL_USER:$REAL_USER" "$TARGET" 2>/dev/null || true

echo
echo "✅ Download complete!"
echo "Saved to: $TARGET"
echo
echo "Next steps:"
echo "  cd ~/Downloads"
echo "  sudo bash $(basename "$TARGET")"
echo "------------------------------------------------"