#!/bin/bash

systemctl stop hanwha-mediaserver

mount -a

# --- Configuration & Safety ---

FSTAB_FILE="/etc/fstab"
BACKUP_FILE="${FSTAB_FILE}.$(date +%Y%m%d_%H%M%S).bak"
TARGET_DEVICES=("/dev/sda" "/dev/sdb" "/dev/sdc" "/dev/sdd")
TARGET_MOUNT_POINTS=("/mnt/sda" "/mnt/sdb" "/mnt/sdc" "/mnt/sdd")

# Must be run as root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Error: Please run as root or with sudo."
  exit 1
fi

# Backup fstab before making any changes
echo "💾 Backing up ${FSTAB_FILE} to ${BACKUP_FILE}..."
cp "$FSTAB_FILE" "$BACKUP_FILE"

# --- 1. Identify the Boot Drive ---

ROOT_DEVICE_KNAME=$(lsblk -no KNAME "$(findmnt -n / -o SOURCE)" | head -n 1)
BOOT_DEV_PARENT="/dev/${ROOT_DEVICE_KNAME%[0-9]*}"

if [ -z "$BOOT_DEV_PARENT" ]; then
    echo "❌ Error: Could not reliably determine the boot device parent. Exiting."
    exit 1
fi
echo "✅ Identified Boot Device Parent: ${BOOT_DEV_PARENT}"

# --- 2. Process Target Devices and Replace UUIDs ---

for i in "${!TARGET_DEVICES[@]}"; do
    DEV_PATH="${TARGET_DEVICES[$i]}"
    MOUNT_POINT="${TARGET_MOUNT_POINTS[$i]}"
    
    echo "--------------------------------------------------------"
    echo "Processing Device: ${DEV_PATH} (Mount: ${MOUNT_POINT})"

    # 2.1. Exclude the boot drive
    if [ "$DEV_PATH" == "$BOOT_DEV_PARENT" ]; then
        echo "❌ Error: Device ${DEV_PATH} is the boot drive parent. Skipping for safety."
        continue
    fi
    
    # 2.2. Check if the device exists
    if [ ! -b "$DEV_PATH" ]; then
        echo "❌ Error: Device file ${DEV_PATH} does not exist. Skipping."
        continue
    fi
    
    # 2.3. Get the required UUID and FSTYPE directly from the whole device node
    DEV_INFO=$(blkid -c /dev/null -o export "$DEV_PATH" 2>/dev/null)
    
    if [ $? -ne 0 ] || [[ "$DEV_INFO" != *UUID=* ]]; then
        echo "❌ Error: blkid failed to find UUID for ${DEV_PATH}. Is the device formatted? Skipping."
        continue
    fi

    # Export variables (UUID, FSTYPE)
    eval "$DEV_INFO" 
    
    if [ -z "$UUID" ]; then
        echo "❌ Error: UUID not extracted for ${DEV_PATH}. Skipping."
        continue
    fi
    
    NEW_IDENTIFIER="UUID=${UUID}"
    
    echo "   -> Found UUID: ${UUID}"
    echo "   -> New Identifier: ${NEW_IDENTIFIER}"
    
    # --- 3. Perform In-Place Replacement using AWK and SED ---

    # Create a temporary file to hold the modified fstab content
    TEMP_FSTAB=$(mktemp)
    
    # 3.1. Use AWK to replace the first field (the identifier) with the NEW_IDENTIFIER
    # $2 == "${MOUNT_POINT}" ensures we only act on the correct line (column 2 is the mount point)
    # The action is to set the first field ($1) to the new UUID and then print the whole line ($0).
    awk -v mp="${MOUNT_POINT}" -v id="${NEW_IDENTIFIER}" '
        $2 == mp && $0 !~ /^#/ { 
            $1 = id; 
            print $0
        }
        $2 != mp || $0 ~ /^#/ { 
            print $0
        }
    ' "$FSTAB_FILE" > "$TEMP_FSTAB"

    # Move the new content back to the fstab file
    mv "$TEMP_FSTAB" "$FSTAB_FILE"
    
    echo "   -> Successfully replaced identifier with UUID using awk."
    
    # 3.2. Use a simple, robust SED command to ensure 'nofail' is in the options field (column 4)
    # This prevents the system from hanging if the drive is disconnected.
    # It simply looks for the line and appends ',nofail' to the options field if it doesn't exist.
    sed -i -E "/[[:space:]]+${MOUNT_POINT}[[:space:]]/ {
        s/^(([^[:space:]]+[[:space:]]+){3})([^[:space:]]+)/\1\3,nofail/ ; 
        s/,,/,/g;
        s/nofail,nofail/nofail/g;
    }" "$FSTAB_FILE"
    
    echo "   -> Successfully ensured 'nofail' option is present."

done

# --- 4. Mount and Final Cleanup ---

echo "--------------------------------------------------------"
echo "--- Applying Changes ---"
echo "Attempting to mount all entries using 'mount -a'..."

# This will re-read and apply all fstab entries
if mount -a; then
    echo "✅ Success! All new UUID entries are active."
    echo "Verify the result by checking the contents of ${FSTAB_FILE} and running 'lsblk'."
else
    echo "❌ Warning: 'mount -a' failed. Review the output above and check ${FSTAB_FILE}."
    echo "Your original fstab is backed up to ${BACKUP_FILE}. Restore it immediately if necessary."
fi

echo "--- Script Complete ---"

systemctl start hanwha-mediaserver
