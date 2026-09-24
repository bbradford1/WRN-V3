#!/usr/bin/env bash
# WRN Installer Script
# Author: Bradford
#
# Purpose:
#   Detect the Ubuntu version and download the appropriate WRN
#   maintenance script, along with the WAVE archive cleanup utility.

set -euo pipefail


# ============================================================
# Repository URLs
# ============================================================

URL_MODERN="https://raw.githubusercontent.com/bbradford1/WRN-V3/main/wrn_v9.sh"

URL_LEGACY="https://raw.githubusercontent.com/bbradford1/WRN-V3/main/Legacy-WRN-Cleanup.sh"

URL_ARCHIVE="https://raw.githubusercontent.com/bbradford1/WRN-V3/main/wrn_archive_cleanup.sh"


# ============================================================
# Resolve Real User / Downloads Folder
# ============================================================

# This ensures files go into the actual user's Downloads folder
# even if the installer itself is executed using sudo.

REAL_USER="${SUDO_USER:-$USER}"

REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"

TARGET_DIR="${REAL_HOME}/Downloads"

ARCHIVE_TARGET="${TARGET_DIR}/wrn_archive_cleanup.sh"


# ============================================================
# Detect Ubuntu Major Version
# ============================================================

get_ubuntu_major() {

    if [[ -r /etc/os-release ]]; then

        # shellcheck disable=SC1091
        . /etc/os-release

        # VERSION_ID example:
        #
        #   18.04 -> 18
        #   20.04 -> 20
        #   22.04 -> 22
        #
        echo "${VERSION_ID%%.*}"

        return 0
    fi

    return 1
}


UBU_MAJOR="$(get_ubuntu_major || echo 0)"


# ============================================================
# Header
# ============================================================

echo
echo "------------------------------------------------"
echo "WRN Installer Script"
echo "------------------------------------------------"
echo
echo "User:         ${REAL_USER}"
echo "Downloads:    ${TARGET_DIR}"
echo "Ubuntu major: ${UBU_MAJOR}"
echo
echo "------------------------------------------------"
echo


# ============================================================
# Create Downloads Folder If Needed
# ============================================================

mkdir -p "$TARGET_DIR"


# ============================================================
# Choose Maintenance Script
# ============================================================

if [[ "$UBU_MAJOR" -le 18 ]]; then

    TARGET="${TARGET_DIR}/wrn_v3_legacy.sh"

    URL="$URL_LEGACY"

    LABEL="Legacy WRN Cleanup (Ubuntu 18.x or older)"

else

    TARGET="${TARGET_DIR}/wrn_v3.sh"

    URL="$URL_MODERN"

    LABEL="WRN v3 (Ubuntu 20+)"

fi


echo "Selected maintenance script:"
echo
echo "  ${LABEL}"
echo

echo "Downloading from:"
echo
echo "  ${URL}"
echo

echo "Saving to:"
echo
echo "  ${TARGET}"
echo


# ============================================================
# Download Maintenance Script
# ============================================================

wget -O "$TARGET" "$URL" || {

    echo
    echo "ERROR: WRN maintenance script download failed."
    echo "Please check the internet connection."
    echo

    exit 1
}


# ============================================================
# Prepare Maintenance Script
# ============================================================

sed -i 's/\r$//' "$TARGET" 2>/dev/null || true

chmod +x "$TARGET"

chown "$REAL_USER:$REAL_USER" "$TARGET" 2>/dev/null || true


# ============================================================
# Download WAVE Archive Cleanup Utility
# ============================================================

echo
echo "------------------------------------------------"
echo "Downloading WAVE archive cleanup utility..."
echo "------------------------------------------------"
echo

echo "Downloading from:"
echo
echo "  ${URL_ARCHIVE}"
echo

echo "Saving to:"
echo
echo "  ${ARCHIVE_TARGET}"
echo


wget -O "$ARCHIVE_TARGET" "$URL_ARCHIVE" || {

    echo
    echo "ERROR: WAVE archive cleanup script download failed."
    echo "Please check the internet connection."
    echo

    exit 1
}


# ============================================================
# Prepare Archive Cleanup Script
# ============================================================

sed -i 's/\r$//' "$ARCHIVE_TARGET" 2>/dev/null || true

chmod +x "$ARCHIVE_TARGET"

chown "$REAL_USER:$REAL_USER" "$ARCHIVE_TARGET" 2>/dev/null || true


# ============================================================
# Completion Summary
# ============================================================

echo
echo "============================================================"
echo " DOWNLOAD COMPLETE"
echo "============================================================"
echo

echo "The following WRN tools were downloaded:"
echo

echo "Maintenance:"
echo "  $(basename "$TARGET")"
echo

echo "WAVE Archive Cleanup:"
echo "  $(basename "$ARCHIVE_TARGET")"
echo

echo "Saved in:"
echo "  ${TARGET_DIR}"

echo
echo "------------------------------------------------"
echo "WRN Maintenance"
echo "------------------------------------------------"
echo

echo "Run:"
echo
echo "  cd ~/Downloads && sudo bash $(basename "$TARGET")"

echo
echo "------------------------------------------------"
echo "WAVE Archive Cleanup"
echo "------------------------------------------------"
echo

echo "Safe dry run:"
echo
echo "  cd ~/Downloads && sudo bash wrn_archive_cleanup.sh"

echo
echo "Delete detected archive recordings:"
echo
echo "  cd ~/Downloads && sudo bash wrn_archive_cleanup.sh --delete"

echo
echo "Optional selective cleanup:"
echo
echo "  sudo bash ~/Downloads/wrn_archive_cleanup.sh --delete --low-only"
echo
echo "  sudo bash ~/Downloads/wrn_archive_cleanup.sh --delete --high-only"

echo
echo "============================================================"
```
