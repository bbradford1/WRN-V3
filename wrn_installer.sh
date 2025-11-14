#!/bin/bash
# WRN Installer Script
# Author: Bradford
# Date: 2025-10-28
# Purpose: Download and prepare the WRN maintenance script

TARGET=~/Downloads/wrn_v3.sh
URL="https://raw.githubusercontent.com/bbradford1/WRN-V3/main/wrn_v7a.sh"

echo "------------------------------------------------"
echo "WRN Installer Script"
echo "------------------------------------------------"
echo "Downloading WRN maintenance script..."
wget -O "$TARGET" "$URL" || { echo "❌ Download failed. Please check internet connection."; exit 1; }

echo "Fixing line endings and setting permissions..."
sed -i 's/\r$//' "$TARGET" 2>/dev/null || true
chmod +x "$TARGET"

echo
echo "✅ WRN script downloaded successfully!"
echo "Saved to: $TARGET"
echo
echo "To run it later, type:"
echo "bash $TARGET"
echo "------------------------------------------------"
