#!/bin/bash
# WRN installer v2 (for testing wrn_v4.sh)
# Usage:
#   wget -O - https://raw.githubusercontent.com/bbradford1/WRN-V3/main/wrn_installer_v2.sh | bash
#   wget -O - https://raw.githubusercontent.com/bbradford1/WRN-V3/main/wrn_installer_v2.sh | bash -s -- --reboot-if-needed
#
# This installer ONLY downloads and runs wrn_v4.sh from your GitHub repo.
# It does NOT embed any legacy code, and it does NOT call systemd-analyze.

set -euo pipefail

# require root
if [[ $EUID -ne 0 ]]; then
  echo "[installer] Switching to root..."
  exec sudo --preserve-env=PATH,BASHOPTS,SHELLOPTS /bin/bash "$0" "$@"
fi

dest="/usr/local/sbin/wrn_v4.sh"
repo_url="https://raw.githubusercontent.com/bbradford1/WRN-V3/main/wrn_v4.sh"
log="/var/log/system_cleanup.log"

echo "------------------------------------------------"
echo "[installer] WRN Installer v2 -> wrn_v4.sh"
echo "------------------------------------------------"

mkdir -p /usr/local/sbin

# Download the latest v4 (allow passing a nocache query if present)
if ! wget -qO "$dest" "$repo_url"; then
  echo "[installer] ERROR: Failed to download $repo_url"
  exit 1
fi

chmod 0755 "$dest"
echo "[installer] Installed $dest"
echo "[installer] Log file: $log"
echo "------------------------------------------------"

# Run v4 and forward any args (e.g., --reboot-if-needed)
exec "$dest" "$@"
