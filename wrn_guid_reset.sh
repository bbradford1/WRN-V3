#!/usr/bin/env bash
#
# wrn_guid_reset.sh
#
# Purpose:
#   Reset the WAVE Media Server configuration so WAVE generates
#   a new mediaserver.conf and server GUID.
#
# IMPORTANT:
#   Stopping the WAVE Media Server will normally disconnect
#   WAVE/Cockpit-based remote sessions.
#
#   This script writes its progress to:
#
#       /var/log/wrn_guid_reset.log
#
#   When possible, the completed log is also copied to:
#
#       ~/Downloads/wrn_guid_reset.log
#
# Usage:
#
#   sudo bash wrn_guid_reset.sh
#

set -euo pipefail


# ============================================================
# Configuration
# ============================================================

SERVICE="hanwha-mediaserver"

CONF_DIR="/opt/hanwha/mediaserver/etc"
CONF_FILE="${CONF_DIR}/mediaserver.conf"

LOGFILE="/var/log/wrn_guid_reset.log"

NOW="$(date +%Y%m%d_%H%M%S)"

BACKUP_FILE="${CONF_DIR}/mediaserver.conf.${NOW}.bak"


# ============================================================
# Determine Real User / Downloads Folder
# ============================================================

REAL_USER="${SUDO_USER:-${USER:-root}}"

REAL_HOME="$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6 || true)"

if [[ -n "$REAL_HOME" && -d "$REAL_HOME" ]]; then
    DOWNLOAD_LOG="${REAL_HOME}/Downloads/wrn_guid_reset.log"
else
    DOWNLOAD_LOG=""
fi


# ============================================================
# Root Check
# ============================================================

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    exec sudo bash "$0" "$@"
fi


# ============================================================
# Logging
# ============================================================

: > "$LOGFILE"

exec > >(tee -a "$LOGFILE") 2>&1


copy_log_to_downloads() {

    if [[ -z "$DOWNLOAD_LOG" ]]; then
        return
    fi

    mkdir -p "$(dirname "$DOWNLOAD_LOG")" 2>/dev/null || true

    cp -f "$LOGFILE" "$DOWNLOAD_LOG" 2>/dev/null || true

    chown "$REAL_USER:$REAL_USER" "$DOWNLOAD_LOG" 2>/dev/null || true
}


finalize() {

    local rc=$?

    echo
    echo "============================================================"

    if [[ $rc -eq 0 ]]; then
        echo " GUID RESET SCRIPT FINISHED"
    else
        echo " GUID RESET SCRIPT ENDED WITH AN ERROR"
    fi

    echo "============================================================"
    echo
    echo "Log file:"
    echo "  $LOGFILE"

    if [[ -n "$DOWNLOAD_LOG" ]]; then
        echo
        echo "A copy of the log will also be available at:"
        echo "  $DOWNLOAD_LOG"
    fi

    echo

    copy_log_to_downloads

    exit "$rc"
}

trap finalize EXIT


# ============================================================
# Header / Warning
# ============================================================

echo
echo "============================================================"
echo " WARNING - WAVE SERVER GUID RESET"
echo "============================================================"
echo
echo "This utility will:"
echo
echo "  1. STOP the WAVE Media Server."
echo "  2. Back up the current mediaserver.conf file."
echo "  3. Remove the active mediaserver.conf from service use."
echo "  4. START the WAVE Media Server again."
echo "  5. Wait for WAVE to generate a new mediaserver.conf."
echo "  6. This should result in a new WAVE server GUID."
echo
echo "IMPORTANT:"
echo
echo "  - If you are connected through the WAVE Client / Cockpit,"
echo "    this terminal session will likely disconnect when the"
echo "    Media Server is stopped."
echo
echo "  - That is expected."
echo
echo "  - After WAVE reconnects, open a new terminal session and"
echo "    check the log file to verify the result."
echo
echo "  - Only run this utility when correcting a known duplicate"
echo "    WAVE server GUID."
echo
echo "  - The original mediaserver.conf will be preserved as a"
echo "    timestamped backup."
echo
echo "============================================================"
echo

read -r -p "Do you want to continue? Type YES to proceed: " RESPONSE

if [[ "$RESPONSE" != "YES" ]]; then
    echo
    echo "GUID reset cancelled."
    echo "No changes were made."
    echo
    exit 0
fi


# ============================================================
# Validate WAVE Installation
# ============================================================

echo
echo "Validating WAVE installation..."
echo

if [[ ! -d "$CONF_DIR" ]]; then
    echo "ERROR: WAVE configuration directory was not found:"
    echo
    echo "  $CONF_DIR"
    echo
    echo "No changes were made."
    echo
    exit 1
fi


if [[ ! -f "$CONF_FILE" ]]; then
    echo "ERROR: mediaserver.conf was not found:"
    echo
    echo "  $CONF_FILE"
    echo
    echo "No changes were made."
    echo
    exit 1
fi


# Ask systemd directly whether the service exists.
if ! systemctl cat "${SERVICE}.service" >/dev/null 2>&1; then
    echo "ERROR: WAVE Media Server service was not found:"
    echo
    echo "  ${SERVICE}.service"
    echo
    echo "No changes were made."
    echo
    exit 1
fi


echo "WAVE Media Server service detected:"
echo
echo "  ${SERVICE}.service"
echo

echo "WAVE installation detected."
echo

echo "Configuration:"
echo "  $CONF_FILE"
echo

echo "Backup will be:"
echo "  $BACKUP_FILE"
echo


# ============================================================
# Current Service Status
# ============================================================

echo "Current WAVE Media Server status:"
echo

systemctl is-active "$SERVICE" || true

echo


# ============================================================
# Stop WAVE Media Server
# ============================================================

echo "============================================================"
echo "Stopping WAVE Media Server..."
echo "============================================================"
echo

systemctl stop "$SERVICE"

sleep 2


if systemctl is-active --quiet "$SERVICE"; then
    echo
    echo "ERROR: WAVE Media Server is still running."
    echo "The configuration file was NOT changed."
    echo
    exit 1
fi


echo "WAVE Media Server stopped successfully."
echo


# ============================================================
# Back Up mediaserver.conf
# ============================================================

echo "============================================================"
echo "Backing up mediaserver.conf..."
echo "============================================================"
echo

mv "$CONF_FILE" "$BACKUP_FILE"

echo "Original configuration moved to:"
echo
echo "  $BACKUP_FILE"
echo


# ============================================================
# Start WAVE Media Server
# ============================================================

echo "============================================================"
echo "Starting WAVE Media Server..."
echo "============================================================"
echo


if ! systemctl start "$SERVICE"; then
    echo
    echo "ERROR: WAVE Media Server failed to start."
    echo
    echo "Attempting to restore the original configuration..."
    echo

    if [[ ! -f "$CONF_FILE" && -f "$BACKUP_FILE" ]]; then
        mv "$BACKUP_FILE" "$CONF_FILE"
    fi

    systemctl start "$SERVICE" 2>/dev/null || true

    echo
    echo "Original configuration restoration attempted."
    echo

    exit 1
fi


# ============================================================
# Verify Service Restart
# ============================================================

echo "Waiting for WAVE Media Server to initialize..."
echo

sleep 5


if ! systemctl is-active --quiet "$SERVICE"; then
    echo "ERROR: WAVE Media Server is not running after restart."
    echo
    echo "Check manually with:"
    echo
    echo "  sudo systemctl status $SERVICE"
    echo
    exit 1
fi


echo "WAVE Media Server is running."
echo


# ============================================================
# Wait for New mediaserver.conf
# ============================================================

echo "Waiting for new mediaserver.conf..."
echo

NEW_CONF_FOUND=false


for i in {1..15}; do

    if [[ -f "$CONF_FILE" ]]; then
        NEW_CONF_FOUND=true
        break
    fi

    sleep 1
done


if ! $NEW_CONF_FOUND; then
    echo "WARNING:"
    echo
    echo "The Media Server is running, but a new mediaserver.conf"
    echo "was not detected within the expected time."
    echo
    echo "Expected location:"
    echo
    echo "  $CONF_FILE"
    echo
    echo "Original backup is preserved at:"
    echo
    echo "  $BACKUP_FILE"
    echo
    exit 1
fi


# ============================================================
# Final Verification
# ============================================================

echo "New mediaserver.conf detected:"
echo
echo "  $CONF_FILE"
echo

echo "Previous configuration backup:"
echo
echo "  $BACKUP_FILE"
echo


echo "============================================================"
echo " GUID RESET COMPLETE"
echo "============================================================"
echo
echo "WAVE Media Server:"
echo "  RUNNING"
echo
echo "New mediaserver.conf:"
echo "  DETECTED"
echo
echo "Previous configuration:"
echo "  PRESERVED"
echo
echo "WAVE should now be operating with a newly generated"
echo "server configuration and server GUID."
echo
echo "If the WAVE/Cockpit session disconnected, reconnect and run:"
echo
echo "  sudo cat /var/log/wrn_guid_reset.log"
echo

if [[ -n "$DOWNLOAD_LOG" ]]; then
    echo "Or view the copied log:"
    echo
    echo "  cat ~/Downloads/wrn_guid_reset.log"
    echo
fi

echo "============================================================"
