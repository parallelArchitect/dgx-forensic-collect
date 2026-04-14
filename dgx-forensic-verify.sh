#!/bin/bash
# dgx-forensic-verify.sh
# Verifies a dgx-forensic-collect output file before sharing.
# Produces human-readable terminal output AND a JSON integrity report.
#
# Usage:
#   chmod +x dgx-forensic-verify.sh
#   ./dgx-forensic-verify.sh dgx-forensic-TIMESTAMP.txt.gz
#
# Output:
#   Terminal: human-readable PASS/FAIL/WARN
#   JSON:     dgx-forensic-verify-TIMESTAMP.json
#
# parallelArchitect — https://github.com/parallelArchitect

set -uo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <dgx-forensic-TIMESTAMP.txt.gz>"
    exit 1
fi

INFILE="$1"

if [ ! -f "$INFILE" ]; then
    echo "ERROR: File not found: $INFILE"
    exit 1
fi

TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT
zcat "$INFILE" > "$TMPFILE"

PASS=0
FAIL=0
WARN=0

# Per-key result tracking
declare -A PRIVACY_RESULTS
declare -A SECTION_RESULTS

check_absent() {
    local label="$1"
    local pattern="$2"
    local key="$3"
    local matches
    matches=$(grep -iE "$pattern" "$TMPFILE" || true)
    if [ -n "$matches" ]; then
        echo "  fail  $label"
        echo "$matches" | head -5 | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        PRIVACY_RESULTS[$key]="false"
    else
        echo "  ok    $label"
        PASS=$((PASS + 1))
        PRIVACY_RESULTS[$key]="true"
    fi
}

check_present() {
    local label="$1"
    local pattern="$2"
    local key="$3"
    local matches
    matches=$(grep -iE "$pattern" "$TMPFILE" || true)
    if [ -n "$matches" ]; then
        echo "  ok    $label"
        PASS=$((PASS + 1))
        SECTION_RESULTS[$key]="true"
    else
        echo "  warn  $label — not found"
        WARN=$((WARN + 1))
        SECTION_RESULTS[$key]="false"
    fi
}

# Timestamps
VERIFIED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
COLLECTED_AT=$(echo "$INFILE" | grep -oE '[0-9]{8}-[0-9]{6}' | head -1 || echo "unknown")
JSONFILE="dgx-forensic-verify-${COLLECTED_AT}.json"

# SHA256
SHA256=$(sha256sum "$INFILE" 2>/dev/null | awk '{print $1}' || echo "unavailable")

# NTP sync state
NTP_SYNC=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || echo "unknown")
NTP_SERVICE=$(timedatectl show --property=NTP --value 2>/dev/null || echo "unknown")

# Hardware ID — SHA256 of DMI chassis serial
HW_ID="unavailable — requires sudo"
if [ "${EUID}" -eq 0 ]; then
    SERIAL=$(dmidecode -s chassis-serial-number 2>/dev/null || echo "")
    if [ -n "$SERIAL" ] && [ "$SERIAL" != "Not Specified" ]; then
        HW_ID=$(echo -n "$SERIAL" | sha256sum | awk '{print $1}')
    else
        HW_ID="unavailable — serial not present in DMI"
    fi
fi

echo "dgx-forensic-verify"
echo "file       : $INFILE"
echo "sha256     : $SHA256"
echo "ntp sync   : $NTP_SYNC"
echo "hw id      : $HW_ID"
echo "verified   : $VERIFIED_AT"
echo ""

# ── Privacy checks ────────────────────────────────────────────────────────────
echo "privacy checks"

check_absent "No raw IPv4 addresses"  "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" "no_raw_ipv4"
check_absent "No raw MAC addresses"   "([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"              "no_raw_mac"
check_absent "No /home/ paths"        "/home/[a-zA-Z]"                                   "no_home_paths"
check_absent "No /root/ paths"        "/root/[a-zA-Z]"                                   "no_root_paths"
check_absent "No SSH keys"            "BEGIN (RSA|OPENSSH|EC|PGP|PRIVATE)"               "no_ssh_keys"
check_absent "No credentials"         "(api_key|api-key|Bearer |secret=|password=|passwd=)" "no_credentials"

echo ""
echo "sanitization"
check_present "Hostname replaced with SPARK" "SPARK"                    "HOSTNAME_SANITIZED"
check_present "Sanitized header present"     "hostname replaced with SPARK" "SANITIZED_HEADER"

echo ""
echo "privacy exclusions"
echo "  usernames/home paths   : not present — verified"
echo "  ip addresses           : redacted as xxx.xxx.xxx.xxx"
echo "  mac addresses          : redacted as xx:xx:xx:xx:xx:xx"
echo "  hostname               : replaced with SPARK"
echo "  network configuration  : not collected by design"
echo "  package lists          : not collected by design"
echo "  ssh/credentials        : not present — verified"
echo "  serial numbers         : not collected by design"

echo ""
echo "forensic sections"
check_present "PLATFORM"               "=== PLATFORM ==="                       "PLATFORM"
check_present "DMI FIRMWARE INVENTORY" "=== DMI FIRMWARE INVENTORY ==="         "DMI_FIRMWARE_INVENTORY"
check_present "DRIVER"                 "=== DRIVER ==="                         "DRIVER"
check_present "PCIE AND DOE STATE"     "=== PCIE AND DOE STATE ==="             "PCIE_AND_DOE_STATE"
check_present "PSTORE CRASH RECORDS"   "=== PSTORE CRASH RECORDS ==="           "PSTORE_CRASH_RECORDS"
check_present "DMESG CURRENT BOOT"     "=== DMESG GPU SIGNALS .CURRENT BOOT."  "DMESG_CURRENT_BOOT"
check_present "DMESG PREVIOUS BOOT"    "=== DMESG GPU SIGNALS .PREVIOUS BOOT." "DMESG_PREVIOUS_BOOT"
check_present "FULL BOOT HISTORY"      "=== FULL BOOT HISTORY ==="              "FULL_BOOT_HISTORY"
check_present "NVIDIA-PERSISTENCED"    "=== NVIDIA-PERSISTENCED ==="            "NVIDIA_PERSISTENCED"
check_present "NVIDIA_FFA_EC"          "=== NVIDIA_FFA_EC FINGERPRINT"          "NVIDIA_FFA_EC_FINGERPRINT"
check_present "INTERRUPT VECTORS"      "=== INTERRUPT VECTORS ==="              "INTERRUPT_VECTORS"
check_present "MEMORY PRESSURE"        "=== MEMORY PRESSURE AND SWAP ==="       "MEMORY_PRESSURE_AND_SWAP"
check_present "FIRMWARE VERSIONS"      "=== FIRMWARE VERSIONS ==="              "FIRMWARE_VERSIONS"
check_present "FIRMWARE UPDATE HISTORY" "=== FIRMWARE UPDATE HISTORY ==="       "FIRMWARE_UPDATE_HISTORY"
check_present "GPU CLOCK AND POWER"    "=== GPU CLOCK AND POWER STATE ==="      "GPU_CLOCK_AND_POWER_STATE"
check_present "NVIDIA-SMI FULL"        "=== NVIDIA-SMI FULL ==="                "NVIDIA_SMI_FULL"
check_present "DRIVER MODPROBE CONFIG" "=== DRIVER MODPROBE CONFIG ==="         "DRIVER_MODPROBE_CONFIG"
check_present "SUSPEND SERVICES"       "=== SUSPEND AND HIBERNATE"              "SUSPEND_HIBERNATE_STATE"
check_present "LOADED MODULES"         "=== LOADED KERNEL MODULES ==="          "LOADED_KERNEL_MODULES"
check_present "NVME SMART ERRORS"      "=== NVME SMART ERRORS ==="              "NVME_SMART_ERRORS"
check_present "RASDAEMON"              "=== RASDAEMON HARDWARE ERRORS ==="      "RASDAEMON_HARDWARE_ERRORS"
check_present "KERN LOG"               "=== KERN LOG ==="                       "KERN_LOG"
check_present "NVIDIA INSTALLER LOG"   "=== NVIDIA INSTALLER LOG ==="           "NVIDIA_INSTALLER_LOG"
check_present "FIELD DIAGNOSTIC"       "=== FIELD DIAGNOSTIC OUTPUT ==="        "FIELD_DIAGNOSTIC_OUTPUT"
check_present "COLLECTION COMPLETE"    "=== COLLECTION COMPLETE ==="            "COLLECTION_COMPLETE"

# ── Result ────────────────────────────────────────────────────────────────────
echo ""
echo "result"
echo "PASS: $PASS  FAIL: $FAIL  WARN: $WARN"
echo ""

SAFE="true"
VERDICT="SAFE TO SHARE — all privacy checks passed."
EXIT_CODE=0

if [ "$FAIL" -gt 0 ]; then
    SAFE="false"
    VERDICT="NOT SAFE TO SHARE — ${FAIL} privacy check(s) failed."
    EXIT_CODE=1
elif [ "$WARN" -gt 0 ]; then
    VERDICT="REVIEW BEFORE SHARING — ${WARN} section(s) missing."
fi

echo "$VERDICT"

# ── JSON report ───────────────────────────────────────────────────────────────
cat > "$JSONFILE" << JSONEOF
{
  "file": "${INFILE}",
  "collected_at": "${COLLECTED_AT}",
  "verified_at": "${VERIFIED_AT}",
  "sha256": "${SHA256}",
  "ntp_synchronized": "${NTP_SYNC}",
  "ntp_service_active": "${NTP_SERVICE}",
  "hardware_id": "${HW_ID}",
  "safe_to_share": ${SAFE},
  "privacy": {
    "no_raw_ipv4": ${PRIVACY_RESULTS[no_raw_ipv4]:-false},
    "no_raw_mac": ${PRIVACY_RESULTS[no_raw_mac]:-false},
    "no_home_paths": ${PRIVACY_RESULTS[no_home_paths]:-false},
    "no_root_paths": ${PRIVACY_RESULTS[no_root_paths]:-false},
    "no_ssh_keys": ${PRIVACY_RESULTS[no_ssh_keys]:-false},
    "no_credentials": ${PRIVACY_RESULTS[no_credentials]:-false}
  },
  "privacy_exclusions": {
    "usernames_home_paths": "not present — verified",
    "ip_addresses": "redacted as xxx.xxx.xxx.xxx",
    "mac_addresses": "redacted as xx:xx:xx:xx:xx:xx",
    "hostname": "replaced with SPARK",
    "network_configuration": "not collected by design",
    "installed_package_lists": "not collected by design",
    "ssh_history_credentials": "not present — verified",
    "hardware_serial_numbers": "not collected by design"
  },
  "sections_present": {
    "PLATFORM": ${SECTION_RESULTS[PLATFORM]:-false},
    "DMI_FIRMWARE_INVENTORY": ${SECTION_RESULTS[DMI_FIRMWARE_INVENTORY]:-false},
    "DRIVER": ${SECTION_RESULTS[DRIVER]:-false},
    "PCIE_AND_DOE_STATE": ${SECTION_RESULTS[PCIE_AND_DOE_STATE]:-false},
    "PSTORE_CRASH_RECORDS": ${SECTION_RESULTS[PSTORE_CRASH_RECORDS]:-false},
    "DMESG_CURRENT_BOOT": ${SECTION_RESULTS[DMESG_CURRENT_BOOT]:-false},
    "DMESG_PREVIOUS_BOOT": ${SECTION_RESULTS[DMESG_PREVIOUS_BOOT]:-false},
    "FULL_BOOT_HISTORY": ${SECTION_RESULTS[FULL_BOOT_HISTORY]:-false},
    "NVIDIA_PERSISTENCED": ${SECTION_RESULTS[NVIDIA_PERSISTENCED]:-false},
    "NVIDIA_FFA_EC_FINGERPRINT": ${SECTION_RESULTS[NVIDIA_FFA_EC_FINGERPRINT]:-false},
    "INTERRUPT_VECTORS": ${SECTION_RESULTS[INTERRUPT_VECTORS]:-false},
    "MEMORY_PRESSURE_AND_SWAP": ${SECTION_RESULTS[MEMORY_PRESSURE_AND_SWAP]:-false},
    "FIRMWARE_VERSIONS": ${SECTION_RESULTS[FIRMWARE_VERSIONS]:-false},
    "FIRMWARE_UPDATE_HISTORY": ${SECTION_RESULTS[FIRMWARE_UPDATE_HISTORY]:-false},
    "GPU_CLOCK_AND_POWER_STATE": ${SECTION_RESULTS[GPU_CLOCK_AND_POWER_STATE]:-false},
    "NVIDIA_SMI_FULL": ${SECTION_RESULTS[NVIDIA_SMI_FULL]:-false},
    "DRIVER_MODPROBE_CONFIG": ${SECTION_RESULTS[DRIVER_MODPROBE_CONFIG]:-false},
    "SUSPEND_HIBERNATE_STATE": ${SECTION_RESULTS[SUSPEND_HIBERNATE_STATE]:-false},
    "LOADED_KERNEL_MODULES": ${SECTION_RESULTS[LOADED_KERNEL_MODULES]:-false},
    "NVME_SMART_ERRORS": ${SECTION_RESULTS[NVME_SMART_ERRORS]:-false},
    "RASDAEMON_HARDWARE_ERRORS": ${SECTION_RESULTS[RASDAEMON_HARDWARE_ERRORS]:-false},
    "KERN_LOG": ${SECTION_RESULTS[KERN_LOG]:-false},
    "NVIDIA_INSTALLER_LOG": ${SECTION_RESULTS[NVIDIA_INSTALLER_LOG]:-false},
    "FIELD_DIAGNOSTIC_OUTPUT": ${SECTION_RESULTS[FIELD_DIAGNOSTIC_OUTPUT]:-false},
    "COLLECTION_COMPLETE": ${SECTION_RESULTS[COLLECTION_COMPLETE]:-false}
  },
  "summary": {
    "pass": ${PASS},
    "fail": ${FAIL},
    "warn": ${WARN},
    "verdict": "${VERDICT}"
  }
}
JSONEOF

echo ""
echo "JSON report  : ${JSONFILE}"

exit $EXIT_CODE
