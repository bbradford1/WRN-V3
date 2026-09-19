#!/usr/bin/env bash
#
# wrn_archive_cleanup.sh
#
# Purpose:
#   Detect and optionally remove WAVE recording archive data that has
#   accidentally been written to the OS drive under:
#
#   /opt/hanwha/mediaserver/var/data/<UUID>/hi_quality/<camera>/<YEAR>
#   /opt/hanwha/mediaserver/var/data/<UUID>/low_quality/<camera>/<YEAR>
#
# SAFE BY DEFAULT:
#   Without --delete, this script performs a DRY RUN only.
#
# This script DOES NOT:
#   - Stop the WAVE mediaserver
#   - Delete info.txt files
#   - Delete the server UUID folder
#   - Delete .nxdb files
#   - Delete object_detection.sqlite
#   - Delete taxonomy.json
#   - Delete the archive directory itself
#
# Examples:
#
#   Dry run:
#     sudo bash wrn_archive_cleanup.sh
#
#   Delete both hi_quality and low_quality recordings:
#     sudo bash wrn_archive_cleanup.sh --delete
#
#   Delete only low_quality recordings:
#     sudo bash wrn_archive_cleanup.sh --delete --low-only
#
#   Delete only hi_quality recordings:
#     sudo bash wrn_archive_cleanup.sh --delete --high-only
#

set -euo pipefail


# ============================================================
# Configuration
# ============================================================

DATA_ROOT="/opt/hanwha/mediaserver/var/data"

# OS usage threshold used for informational warning
OS_WARNING_PERCENT=80

DO_DELETE=false
DO_LOW=true
DO_HIGH=true


# ============================================================
# Helper Functions
# ============================================================

usage() {
    cat <<'EOF'
WAVE OS Archive Cleanup

Usage:
  sudo bash wrn_archive_cleanup.sh [options]

Options:

  --delete
      Actually delete the dated WAVE recording directories.

  --low-only
      Process only low_quality recordings.

  --high-only
      Process only hi_quality recordings.

  --help, -h
      Show this help screen.


Examples:

  Preview everything that would be deleted:

    sudo bash wrn_archive_cleanup.sh


  Delete both high and low quality recordings:

    sudo bash wrn_archive_cleanup.sh --delete


  Delete only low quality recordings:

    sudo bash wrn_archive_cleanup.sh --delete --low-only


  Delete only high quality recordings:

    sudo bash wrn_archive_cleanup.sh --delete --high-only

EOF
}


get_os_usage() {
    df --output=pcent / | tail -1 | tr -dc '0-9'
}


show_os_status() {

    local usage
    usage="$(get_os_usage)"

    echo
    echo "OS disk usage status:"
    echo

    df -h /

    echo

    if (( usage >= OS_WARNING_PERCENT )); then
        echo "WARNING: OS drive usage is ${usage}%."
        echo "         Recommended target is below ${OS_WARNING_PERCENT}%."
    else
        echo "PASS: OS drive usage is ${usage}%."
        echo "      Usage is below the ${OS_WARNING_PERCENT}% warning threshold."
    fi

    echo
}


# ============================================================
# Parse Command-Line Arguments
# ============================================================

while [[ $# -gt 0 ]]; do

    case "$1" in

        --delete)
            DO_DELETE=true
            ;;

        --low-only)
            DO_LOW=true
            DO_HIGH=false
            ;;

        --high-only)
            DO_LOW=false
            DO_HIGH=true
            ;;

        --help|-h)
            usage
            exit 0
            ;;

        *)
            echo
            echo "ERROR: Unknown option: $1"
            echo
            usage
            exit 1
            ;;

    esac

    shift
done


# ============================================================
# Root Check
# ============================================================

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then

    echo
    echo "ERROR: This script must be run with sudo."
    echo
    echo "Example:"
    echo
    echo "  sudo bash $0"
    echo

    exit 1
fi


# ============================================================
# Validate WAVE Data Directory
# ============================================================

if [[ ! -d "$DATA_ROOT" ]]; then

    echo
    echo "ERROR: WAVE data directory was not found:"
    echo
    echo "  $DATA_ROOT"
    echo
    echo "No changes were made."
    echo

    exit 1
fi


# ============================================================
# Start
# ============================================================

echo
echo "============================================================"
echo " WAVE OS Archive Cleanup"
echo "============================================================"
echo

echo "Script mode:"

if $DO_DELETE; then
    echo "  DELETE MODE"
else
    echo "  DRY RUN"
    echo "  Nothing will be deleted."
fi

echo

if $DO_LOW && $DO_HIGH; then
    echo "Archive types:"
    echo "  low_quality"
    echo "  hi_quality"
elif $DO_LOW; then
    echo "Archive type:"
    echo "  low_quality only"
elif $DO_HIGH; then
    echo "Archive type:"
    echo "  hi_quality only"
fi

echo


# ============================================================
# Initial Disk Usage
# ============================================================

show_os_status

echo "Current WAVE data usage:"
echo

du -sh "$DATA_ROOT" 2>/dev/null || true

echo
echo "Scanning WAVE server data..."
echo


# ============================================================
# Counters
# ============================================================

TOTAL_FOUND=0
TOTAL_REMOVED=0
SERVER_COUNT=0


# ============================================================
# Archive Processing Function
# ============================================================

clean_quality() {

    local uuid_dir="$1"
    local quality="$2"
    local qdir="$uuid_dir/$quality"

    [[ -d "$qdir" ]] || return

    echo "------------------------------------------------------------"
    echo "Checking:"
    echo
    echo "  $qdir"
    echo

    local before
    before="$(du -sh "$qdir" 2>/dev/null | awk '{print $1}')"

    echo "Current size: ${before:-unknown}"
    echo

    #
    # Expected structure:
    #
    # hi_quality/<camera>/2026
    #
    # or:
    #
    # low_quality/<camera>/2026
    #
    # The year directory is exactly two levels below
    # hi_quality or low_quality.
    #

    mapfile -d '' year_dirs < <(
        find "$qdir" \
            -mindepth 2 \
            -maxdepth 2 \
            -type d \
            -name '20[0-9][0-9]' \
            -print0 2>/dev/null
    )

    if [[ ${#year_dirs[@]} -eq 0 ]]; then

        echo "No dated recording directories found."
        echo

        return
    fi


    echo "Dated recording directories found: ${#year_dirs[@]}"
    echo


    for dir in "${year_dirs[@]}"; do

        local size
        size="$(du -sh "$dir" 2>/dev/null | awk '{print $1}')"

        echo "  ${size:-?}  $dir"

        TOTAL_FOUND=$((TOTAL_FOUND + 1))

    done

    echo


    # --------------------------------------------------------
    # Delete Mode
    # --------------------------------------------------------

    if $DO_DELETE; then

        echo "Removing dated $quality recording directories..."
        echo

        for dir in "${year_dirs[@]}"; do

            echo "  Removing:"
            echo "    $dir"

            rm -rf -- "$dir"

            TOTAL_REMOVED=$((TOTAL_REMOVED + 1))

        done

        echo
        echo "Cleanup complete for $quality."

        local after
        after="$(du -sh "$qdir" 2>/dev/null | awk '{print $1}')"

        echo
        echo "Before: $before"
        echo "After:  $after"

    else

        echo "DRY RUN:"
        echo "No files were deleted."

    fi

    echo
}


# ============================================================
# Scan Each WAVE Server UUID Directory
# ============================================================

for uuid_dir in "$DATA_ROOT"/*; do

    [[ -d "$uuid_dir" ]] || continue

    #
    # Ignore directories that don't contain WAVE quality folders.
    #

    if [[ ! -d "$uuid_dir/hi_quality" && ! -d "$uuid_dir/low_quality" ]]; then
        continue
    fi

    SERVER_COUNT=$((SERVER_COUNT + 1))

    echo
    echo "============================================================"
    echo "WAVE Server Data Directory"
    echo "============================================================"
    echo
    echo "$uuid_dir"
    echo

    if $DO_LOW; then
        clean_quality "$uuid_dir" "low_quality"
    fi

    if $DO_HIGH; then
        clean_quality "$uuid_dir" "hi_quality"
    fi

done


# ============================================================
# Final Summary
# ============================================================

echo
echo "============================================================"
echo " CLEANUP SUMMARY"
echo "============================================================"
echo

echo "WAVE archive data directories detected: $SERVER_COUNT"
echo


# ------------------------------------------------------------
# Nothing Found
# ------------------------------------------------------------

if [[ $TOTAL_FOUND -eq 0 ]]; then

    echo "No dated WAVE recording directories were found."
    echo
    echo "No cleanup is required."
    echo
    echo "Nothing was deleted."

    echo
    echo "Current WAVE data usage:"
    echo

    du -sh "$DATA_ROOT" 2>/dev/null || true

    show_os_status

    echo "============================================================"
    echo

    exit 0
fi


# ------------------------------------------------------------
# Dry Run Summary
# ------------------------------------------------------------

if ! $DO_DELETE; then

    echo "Dated recording directories found: $TOTAL_FOUND"
    echo
    echo "DRY RUN ONLY."
    echo
    echo "Nothing was deleted."

    echo
    echo "If the directories listed above are safe to remove,"
    echo "run:"
    echo
    echo "  sudo bash $0 --delete"

    echo
    echo "Or selectively:"
    echo
    echo "  sudo bash $0 --delete --low-only"
    echo
    echo "  sudo bash $0 --delete --high-only"

    echo
    echo "Current WAVE data usage:"
    echo

    du -sh "$DATA_ROOT" 2>/dev/null || true

    show_os_status

    echo "============================================================"
    echo

    exit 0
fi


# ------------------------------------------------------------
# Delete Summary
# ------------------------------------------------------------

echo "Dated recording directories found:   $TOTAL_FOUND"
echo "Dated recording directories removed: $TOTAL_REMOVED"

echo
echo "Current WAVE data usage:"
echo

du -sh "$DATA_ROOT" 2>/dev/null || true

show_os_status

echo "Cleanup finished successfully."
echo
echo "============================================================"
echo