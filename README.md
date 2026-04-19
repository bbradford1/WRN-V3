# WRN v10 — Field Tech Instructions

Maintenance scripts for Hanwha WAVE Recorder Network (WRN) appliances. The installer auto-detects Ubuntu version and downloads the correct script for your system.

## 1. Download the installer

```bash
wget -O - https://raw.githubusercontent.com/bbradford1/WRN-V3/main/wrn_installer_v10.sh | bash
```

This auto-detects the Ubuntu version and downloads the correct maintenance script to `~/Downloads`.

## 2. Navigate to Downloads and confirm the file

```bash
cd ~/Downloads
ls
```

Depending on the system, you will see **one of two files**:

| Ubuntu version | File downloaded |
|---|---|
| **Ubuntu 20.04 or newer** | `wrn_v10.sh` |
| **Ubuntu 18.04 or older** | `Legacy-WRN-Cleanup-v2.sh` |

## 3. Run the script

**Modern (Ubuntu 20+):**
```bash
sudo bash wrn_v10.sh
```

**Legacy (Ubuntu 18):**
```bash
sudo bash Legacy-WRN-Cleanup-v2.sh
```

## 4. Review the summary after it completes

If you got disconnected during the run (the Hanwha mediaserver briefly stops on modern WRNs), reconnect and view the log:

**Modern:**
```bash
tail -80 /var/log/wrn_v10.log
```

**Legacy:**
```bash
tail -80 /var/log/wrn_legacy_v2.log
```

The log shows disk-space before/after, reclaimed MB, every action taken, and (if installed) the cron job schedule. A copy is also placed in `~/Downloads/` automatically.

## Optional flags

For your first cautious run, you can preview without touching sticky config:

```bash
sudo bash wrn_v10.sh --audit-only        # just reports mediaserver state, changes nothing
sudo bash wrn_v10.sh --journal-only      # safest subset (same as the monthly cron)
sudo bash wrn_v10.sh --help              # full flag list
```
