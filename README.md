# dgx-forensic-collect

Targeted forensic data collector for NVIDIA DGX Spark (GB10) systems.

Collects kernel, driver, firmware, and hardware signals into a single compressed file suitable for public sharing.

---

## Note on nvidia-bug-report

NVIDIA support requires `nvidia-bug-report.log.gz` for assistance requests. This tool does not replace it — it captures additional signals not included in the bug report, such as EFI pstore crash records, rasdaemon BERT events, and rotated kernel logs. Run both.

---

## Why this exists

Provides a focused, single-command collection of:

- EFI pstore crash records (persistent across reboots)
- rasdaemon BERT hardware error events
- Full kernel log timeline, including rotated logs

On GB10 systems, also detects the Class 4 DOE mailbox stuck state via `nvidia_ffa_ec`.

Background: [Root Cause Analysis — DGX Spark driver failure, kernel 6.17.0-1008-nvidia](https://forums.developer.nvidia.com/t/root-cause-analysis-dgx-spark-driver-failure-kernel-6-17-0-1008-nvidia-aarch64-panics-cause-doe-mailbox-failure-pstore-evidence/366026)

---

## Requirements

- Linux
- `bash`, `gzip`, `journalctl`
- `sudo` recommended — required for pstore, dmidecode, rasdaemon, nvme smart-log

Without `sudo`, the tool runs with partial coverage and reports skipped sections.

---

## Usage

```bash
chmod +x dgx-forensic-collect.sh dgx-forensic-verify.sh

# Full collection (recommended)
sudo ./dgx-forensic-collect.sh

# Verify before sharing
./dgx-forensic-verify.sh dgx-forensic-TIMESTAMP.txt.gz

# Share the .gz output
```

---

## What it collects

- Platform identity — kernel, architecture, product name, BIOS version
- DMI firmware inventory — running vs installed BIOS
- NVIDIA driver version and GPU state
- PCIe / DOE mailbox state (`lspci -vvv`)
- EFI pstore crash records
- Kernel GPU/driver logs — current and previous boot
- `kern.log`, `kern.log.1`, `kern.log.2.gz` — rotated history
- Full boot history
- `nvidia-persistenced` state — current, previous boot, failure count
- `nvidia_ffa_ec` fingerprint — GB10 DOE failure detection
- MSI-X interrupt vector counts
- Memory pressure (PSI) and swap state
- Firmware versions and update history (`fwupdmgr`)
- GPU clock and power state
- Driver modprobe configuration
- Suspend/hibernate service state
- Loaded kernel modules (NVIDIA + NIC)
- NVMe SMART error summary
- rasdaemon hardware error database (persistent BERT events)
- `nvidia-installer.log` — driver install timestamp
- Field diagnostic output (if present)

---

## What it does NOT collect

- Usernames or home directory paths
- IP addresses — redacted as `xxx.xxx.xxx.xxx`
- MAC addresses — redacted as `xx:xx:xx:xx:xx:xx`
- Hostname — replaced with `SPARK`
- Network configuration
- Installed package lists
- SSH history or credentials
- Hardware serial numbers

---

## Output

`dgx-forensic-TIMESTAMP.txt.gz` — compressed and sanitized for sharing.

Run `dgx-forensic-verify.sh` before sharing. Confirms sanitization and flags any missing sections. Produces a JSON integrity report with SHA256, NTP sync state, and hardware ID.

---

## License

MIT License 

---

## Author

parallelArchitect — https://github.com/parallelArchitect
