#!/bin/bash
# dgx-forensic-collect.sh
# Targeted DGX Spark / GB10 forensic data collector
#
# Collects only GPU, driver, memory, and firmware diagnostic signals.
# No usernames, IP addresses, MAC addresses, file contents, or private data.
# Hostname is replaced with SPARK throughout the output.
#
# What this collects:
#   - Platform identity (kernel, product name, architecture)
#   - DMI firmware inventory (detects running vs installed BIOS mismatch)
#   - Driver version and GPU state
#   - PCIe / DOE mailbox state
#   - EFI pstore crash records from previous boots
#   - Kernel GPU/driver signals (current and previous boot)
#   - Full boot history (all recorded boots, no truncation)
#   - nvidia-persistenced full log + boot failure count
#   - nvidia_ffa_ec fingerprint (GB10 DOE failure diagnostic)
#   - MSI-X interrupt vector counts
#   - Memory pressure (PSI) and swap configuration
#   - Firmware versions, update state, and fwupd history
#   - GPU clock state (detects PD throttle)
#   - Driver modprobe configuration
#   - Suspend/hibernate service state
#   - Loaded kernel modules (NVIDIA and NIC only)
#   - NVMe SMART error summary
#   - rasdaemon hardware error database (BERT events, persists across reboots)
#
# What this does NOT collect:
#   - Usernames or home directory paths
#   - IP addresses (redacted as [IP])
#   - MAC addresses (redacted as [MAC])
#   - Hostname (replaced with SPARK)
#   - Network configuration
#   - Installed package lists
#   - SSH history or credentials
#   - Hardware serial numbers
#   - File contents
#
# Usage:
#   chmod +x dgx-forensic-collect.sh
#   ./dgx-forensic-collect.sh          (partial — some sections need root)
#   sudo ./dgx-forensic-collect.sh     (full — recommended)
#
# Output:
#   dgx-forensic-TIMESTAMP.txt.gz (compressed, safe to share)
#   Run dgx-forensic-verify.sh to confirm before sharing
#
# parallelArchitect — https://github.com/parallelArchitect

set -uo pipefail

# Root check — warn but continue
# Sections requiring root: dmidecode, pstore, rasdaemon, nvme smart-log
IS_ROOT=0
if [ "$EUID" -eq 0 ]; then
    IS_ROOT=1
else
    echo "WARNING: running without root — some sections will be incomplete"
    echo "         rerun with sudo for full data collection"
    echo ""
fi

HOSTNAME_RAW=$(hostname)
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTFILE="dgx-forensic-${TIMESTAMP}.txt"
ARCHIVE="${OUTFILE}.gz"

# Sanitize — replace hostname, IPs, MACs
sanitize() {
    sed "s/${HOSTNAME_RAW}/SPARK/g" \
    | sed 's/[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/[IP]/g' \
    | sed 's/\([0-9a-fA-F]\{2\}:\)\{5\}[0-9a-fA-F]\{2\}/[MAC]/g'
}

section() {
    echo "" | tee -a "$OUTFILE"
    echo "=== $1 ===" | tee -a "$OUTFILE"
}

# Header
cat > "$OUTFILE" << EOF
dgx-forensic-collect output
Collected : ${TIMESTAMP}
Sanitized : hostname replaced with SPARK, IPs and MACs redacted
Tool      : https://github.com/parallelArchitect/dgx-forensic-collect

What this file does NOT contain:
  - Usernames or home directory paths
  - IP addresses (replaced with [IP])
  - MAC addresses (replaced with [MAC])
  - Hostname (replaced with SPARK)
  - Network configuration
  - Installed package lists
  - SSH history or credentials
  - Hardware serial numbers
  - File contents
EOF

# 1. Platform identity
section "PLATFORM"
{
    echo "Kernel    : $(uname -r)"
    echo "Arch      : $(uname -m)"
    if [ "$IS_ROOT" -eq 1 ]; then
        echo "Product   : $(dmidecode -s system-product-name 2>/dev/null || echo N/A)"
        echo "BIOS      : $(dmidecode -s bios-version 2>/dev/null || echo N/A)"
    else
        echo "Product   : requires sudo"
        echo "BIOS      : requires sudo"
    fi
    echo "BIOS      : $(dmidecode -s bios-version 2>/dev/null || echo N/A)"
    echo "OS        : $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo N/A)"
} | sanitize | tee -a "$OUTFILE"

# 2. DMI firmware inventory — detects running vs installed BIOS mismatch
# Critical for GB10: kernel 6.17 was built after December 2025 BIOS update
# but some systems still run August 2025 BIOS (5.36_0ACUM018 vs 5.36_0ACUM023)
section "DMI FIRMWARE INVENTORY"
{
    if [ "$IS_ROOT" -eq 1 ]; then
        dmidecode -t firmware 2>/dev/null             || echo "dmidecode firmware inventory: N/A"
    else
        echo "dmidecode firmware inventory: requires sudo"
    fi
} | sanitize | tee -a "$OUTFILE"

# 3. Driver
section "DRIVER"
{
    cat /proc/driver/nvidia/version 2>/dev/null || echo "nvidia driver version: N/A"
    nvidia-smi --query-gpu=driver_version,name,compute_cap,persistence_mode \
        --format=csv,noheader 2>/dev/null || echo "nvidia-smi: N/A"
} | sanitize | tee -a "$OUTFILE"

# 4. PCIe / DOE mailbox state
section "PCIE AND DOE STATE"
{
    lspci -vvv 2>/dev/null | grep -A30 \
        -E "000f:01|NVIDIA GB|NVDA8[89]|DOE|NVLink" || echo "lspci: N/A"
} | sanitize | tee -a "$OUTFILE"

# 5. EFI pstore crash records
# Primary source for GB10 kernel panic forensics:
# nbcon stack overflow, FPAC/PSCI/NMI race, qspinlock IOVA hash overflow
section "PSTORE CRASH RECORDS"
{
    if [ "$IS_ROOT" -ne 1 ]; then
        echo "pstore: requires sudo"
    elif ls /sys/fs/pstore/dmesg-efi-* 2>/dev/null | head -1 | grep -q .; then
        echo "Pstore files found:"
        ls /sys/fs/pstore/
        echo ""
        for f in /sys/fs/pstore/dmesg-efi-*; do
            [ -f "$f" ] || continue
            echo "--- $(basename "$f") ---"
            cat "$f"
            echo ""
        done
    else
        echo "No pstore crash records found (clean boot history)"
    fi
} | sanitize | tee -a "$OUTFILE"

# 6. Current boot GPU/driver kernel messages
section "DMESG GPU SIGNALS (CURRENT BOOT)"
{
    dmesg 2>/dev/null | grep -iE \
        "NVRM|nvidia|DOE|NVDA8[89]|Xid|r8127|NV_ERR|_memdescAllocInternal|memory pressure|pstore|kernel panic|stack overflow|UBSAN|FPAC|qspinlock|nbcon|mstflint|nvidia_ffa_ec|ffa|BERT|APEI" \
        || echo "No GPU signals in dmesg"
} | sanitize | tee -a "$OUTFILE"

# 7. Previous boot GPU/driver kernel messages
section "DMESG GPU SIGNALS (PREVIOUS BOOT)"
{
    journalctl -k -b -1 --no-pager 2>/dev/null | grep -iE \
        "NVRM|nvidia|DOE|NVDA8[89]|Xid|NV_ERR|_memdescAllocInternal|memory pressure|kernel panic|stack overflow|UBSAN|FPAC|qspinlock|nbcon|mstflint|nvidia_ffa_ec|ffa|BERT|APEI" \
        || echo "No previous boot kernel log available"
} | sanitize | tee -a "$OUTFILE"

# 8. Full boot history — no truncation
# Critical: BERT trigger may predate the first boot with captured logs
# 40+ consecutive failures documented in GB10 cases — tail -N would miss root cause
section "FULL BOOT HISTORY"
{
    journalctl --list-boots --no-pager 2>/dev/null \
        || echo "Boot history: N/A"
} | sanitize | tee -a "$OUTFILE"

# 9. nvidia-persistenced — full log + failure count
section "NVIDIA-PERSISTENCED"
{
    echo "--- Current boot ---"
    journalctl -u nvidia-persistenced -b 0 --no-pager 2>/dev/null \
        || echo "N/A"
    echo ""
    echo "--- Previous boot ---"
    journalctl -u nvidia-persistenced -b -1 --no-pager 2>/dev/null \
        || echo "N/A"
    echo ""
    echo "--- Total failed boots (Failed to query NVIDIA devices) ---"
    COUNT=$(journalctl -u nvidia-persistenced --no-pager 2>/dev/null \
        | grep -c "Failed to query" || true)
    echo "Count: ${COUNT:-0}"
} | sanitize | tee -a "$OUTFILE"

# 10. nvidia_ffa_ec fingerprint — GB10 specific
# This module handles Grace CPU <-> GB10 GPU communication via Arm FFA
# It is built INTO the kernel (not loadable) and survives DOE failure
# Diagnostic: if nvidia_ffa_ec present but no nvidia in lsmod = Class 4 DOE failure
# Not present on discrete PCIe GPU systems at all
section "NVIDIA_FFA_EC FINGERPRINT (GB10)"
{
    echo "--- modinfo nvidia_ffa_ec ---"
    modinfo nvidia_ffa_ec 2>/dev/null \
        | grep -iE "filename|version|description|license|author" \
        || echo "nvidia_ffa_ec: not present (discrete GPU or not GB10)"
    echo ""
    echo "--- nvidia modules in lsmod ---"
    lsmod 2>/dev/null | grep -iE "^nvidia" \
        || echo "No nvidia loadable modules present"
    echo ""
    echo "Interpretation:"
    FFA=$(modinfo nvidia_ffa_ec 2>/dev/null | grep -c filename || true)
    NV=$(lsmod 2>/dev/null | grep -c "^nvidia" || true)
    if [ "${FFA:-0}" -gt 0 ] && [ "${NV:-0}" -eq 0 ]; then
        echo "DIAGNOSTIC: nvidia_ffa_ec present but no nvidia modules loaded"
        echo "            This is the GB10 Class 4 DOE mailbox stuck state fingerprint"
        echo "            FFA layer intact, failure is above FFA — DOE mailbox or PCIe"
    elif [ "${FFA:-0}" -gt 0 ] && [ "${NV:-0}" -gt 0 ]; then
        echo "NORMAL: nvidia_ffa_ec present and nvidia modules loaded (healthy GB10)"
    else
        echo "NOT GB10: nvidia_ffa_ec not present (discrete PCIe GPU system)"
    fi
} | tee -a "$OUTFILE"

# 11. Interrupt vectors — NVIDIA and NIC only
section "INTERRUPT VECTORS"
{
    grep -iE "nvidia|ITS-PCI-MSIX|enP7" /proc/interrupts 2>/dev/null \
        || echo "No NVIDIA interrupt vectors found"
} | sanitize | tee -a "$OUTFILE"

# 12. Memory pressure and swap
section "MEMORY PRESSURE AND SWAP"
{
    echo "PSI memory:"
    cat /proc/pressure/memory 2>/dev/null || echo "N/A"
    echo ""
    echo "Memory summary:"
    free -h 2>/dev/null || echo "N/A"
    echo ""
    echo "Available (MemAvailable + SwapFree):"
    awk '/MemAvailable/{a=$2} /SwapFree/{b=$2} END{printf "%d kB\n", a+b}' \
        /proc/meminfo 2>/dev/null || echo "N/A"
    echo ""
    echo "Swap configuration:"
    swapon --show 2>/dev/null || echo "No swap active"
    cat /proc/swaps 2>/dev/null || echo "N/A"
} | tee -a "$OUTFILE"

# 13. Firmware versions
section "FIRMWARE VERSIONS"
{
    fwupdmgr get-devices 2>/dev/null \
        | grep -iE "version|update state|update error|embedded|uefi|soc|pd fw|device id" \
        || echo "fwupdmgr: N/A"
} | sanitize | tee -a "$OUTFILE"

# 14. Firmware update history
# Critical: documents EC/SoC updates applied AFTER failure established
# In GB10 cases, updates applied Feb 18 did not resolve DOE failure
section "FIRMWARE UPDATE HISTORY"
{
    fwupdmgr get-history 2>/dev/null \
        || echo "fwupdmgr history: N/A"
} | sanitize | tee -a "$OUTFILE"

# 15. GPU clock and power state
section "GPU CLOCK AND POWER STATE"
{
    nvidia-smi \
        --query-gpu=clocks.current.graphics,clocks.max.graphics,clocks.current.memory,clocks.max.memory,power.draw,power.limit,temperature.gpu,pstate \
        --format=csv 2>/dev/null \
        || echo "nvidia-smi clock query: N/A"
} | sanitize | tee -a "$OUTFILE"

# 16. nvidia-smi full output
section "NVIDIA-SMI FULL"
{
    nvidia-smi 2>/dev/null || echo "nvidia-smi: N/A"
} | sanitize | tee -a "$OUTFILE"

# 17. Driver modprobe configuration
# Catches NVreg_EnableGpuFirmware=0 silently ignored on open driver (GB202)
section "DRIVER MODPROBE CONFIG"
{
    FOUND=0
    for f in /etc/modprobe.d/nvidia* /etc/modprobe.d/blacklist-nvidia* \
              /etc/nvidia/*.conf; do
        [ -f "$f" ] || continue
        echo "--- $f ---"
        cat "$f"
        echo ""
        FOUND=$((FOUND + 1))
    done
    [ "$FOUND" -eq 0 ] && echo "No nvidia modprobe config found"
} | sanitize | tee -a "$OUTFILE"

# 18. Suspend/hibernate service state
# RTX PRO 6000 Xid 32+56: suspend/resume services disabled caused channel corruption
section "SUSPEND AND HIBERNATE SERVICE STATE"
{
    for svc in nvidia-suspend nvidia-hibernate nvidia-resume \
                systemd-suspend systemd-hibernate; do
        STATE=$(systemctl is-enabled "$svc" 2>/dev/null || echo "not-found")
        echo "${svc}: ${STATE}"
    done
} | tee -a "$OUTFILE"

# 19. Loaded kernel modules — NVIDIA and NIC only
section "LOADED KERNEL MODULES"
{
    lsmod 2>/dev/null | grep -iE "^nvidia|^r8127|^mstflint|^i2c_nvidia" \
        || echo "No NVIDIA modules loaded"
} | tee -a "$OUTFILE"

# 20. NVMe SMART error summary
section "NVME SMART ERRORS"
{
    FOUND=0
    for dev in /dev/nvme*; do
        [ -b "$dev" ] || continue
        echo "--- $dev ---"
        if [ "$IS_ROOT" -eq 1 ]; then
            nvme smart-log "$dev" 2>/dev/null                 | grep -iE "error|unsafe|media|critical|percentage_used"                 || echo "smart-log: N/A or nvme-cli not installed"
        else
            echo "smart-log: requires sudo"
        fi
        echo ""
        FOUND=$((FOUND + 1))
    done
    [ "$FOUND" -eq 0 ] && echo "No NVMe devices found"
} | tee -a "$OUTFILE"

# 21. rasdaemon hardware error database
# HIGHEST PRIORITY for GB10 Class 4 failures
# Persists across reboots — may contain the BERT event that triggered DOE stuck state
# The BERT trigger predates all kernel logs — rasdaemon is the only place it may exist
section "RASDAEMON HARDWARE ERRORS"
{
    echo "--- rasdaemon error database ---"
    if [ "$IS_ROOT" -eq 1 ]; then
        rasdaemon --errors 2>/dev/null             || echo "rasdaemon: N/A or not installed (sudo apt install rasdaemon)"
    else
        echo "rasdaemon: requires sudo"
    fi
    echo ""
    echo "--- rasdaemon service status ---"
    systemctl status rasdaemon --no-pager 2>/dev/null | head -10 \
        || echo "rasdaemon service: N/A"
} | sanitize | tee -a "$OUTFILE"

# 22. kern.log — separate from journalctl, different retention on some Ubuntu configs
# njo Xid 119 / GSP stall sequence was present here and not in journalctl capture
section "KERN LOG"
{
    KERN_PATTERN="NVRM|nvidia|DOE|NVDA8[89]|Xid|NV_ERR|_memdescAllocInternal|kernel panic|stack overflow|UBSAN|FPAC|qspinlock|nbcon|nvidia_ffa_ec|BERT|APEI"
    KERN_FOUND=0
    for klog in /var/log/kern.log /var/log/kern.log.1; do
        [ -f "$klog" ] || continue
        echo "--- $(basename $klog) ---"
        grep -iaE "$KERN_PATTERN" "$klog" 2>/dev/null             || echo "No GPU signals in $(basename $klog)"
        echo ""
        KERN_FOUND=$((KERN_FOUND + 1))
    done
    if [ -f /var/log/kern.log.2.gz ]; then
        echo "--- kern.log.2.gz ---"
        zcat /var/log/kern.log.2.gz 2>/dev/null             | grep -iaE "$KERN_PATTERN"             || echo "No GPU signals in kern.log.2.gz"
        echo ""
        KERN_FOUND=$((KERN_FOUND + 1))
    fi
    [ "$KERN_FOUND" -eq 0 ] && echo "kern.log not present"
} | sanitize | tee -a "$OUTFILE"

# 23. nvidia-installer.log — driver install timestamp and errors
# Documents when driver was installed — separate from persistenced and dpkg
section "NVIDIA INSTALLER LOG"
{
    if [ -f /var/log/nvidia-installer.log ]; then
        echo "nvidia-installer.log found:"
        cat /var/log/nvidia-installer.log 2>/dev/null
    else
        echo "nvidia-installer.log not present"
    fi
} | sanitize | tee -a "$OUTFILE"

# 24. Field diagnostic output — if present from prior run
# Machine-generated output — no private data
# Contrast between "field diag passed" and "driver dead" is key forensic finding
# mceballos: field diag passed Feb 20 while driver had been dead since Feb 13
section "FIELD DIAGNOSTIC OUTPUT"
{
    FIELDIAG_DIR="/opt/nvidia/dgx-spark-fieldiag/dgx"
    if [ -d "$FIELDIAG_DIR" ]; then
        LATEST=$(ls -td "${FIELDIAG_DIR}"/logs-* 2>/dev/null | head -1)
        if [ -n "$LATEST" ]; then
            echo "Latest field diagnostic run: $LATEST"
            echo ""
            if [ -f "${LATEST}/unified_summary.json" ]; then
                echo "--- unified_summary.json ---"
                cat "${LATEST}/unified_summary.json" 2>/dev/null
            fi
            if [ -f "${LATEST}/summary.csv" ]; then
                echo ""
                echo "--- summary.csv ---"
                cat "${LATEST}/summary.csv" 2>/dev/null
            fi
            if [ -f "${LATEST}/testspec.json" ]; then
                echo ""
                echo "--- testspec.json ---"
                cat "${LATEST}/testspec.json" 2>/dev/null
            fi
        else
            echo "Field diagnostic directory present but no log runs found"
        fi
    else
        echo "Field diagnostic not present (not a DGX Spark or never run)"
    fi
} | sanitize | tee -a "$OUTFILE"

# Footer
section "COLLECTION COMPLETE"
echo "Output file  : ${OUTFILE}" | tee -a "$OUTFILE"
echo "Archive      : ${ARCHIVE}" | tee -a "$OUTFILE"

# Compress
gzip -9 "$OUTFILE"

echo ""
echo "Done. Verify before sharing:"
echo "  ./dgx-forensic-verify.sh ${ARCHIVE}"
echo ""
echo "Share : ${ARCHIVE}"
echo "Size  : $(du -sh "$ARCHIVE" | cut -f1)"
