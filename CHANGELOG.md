# Changelog

## v1.3.0 — 2026-04-14

### Changed — dgx-forensic-verify.sh complete rewrite
- Full JSON integrity report output to dgx-forensic-verify-TIMESTAMP.json
- SHA256 hash of the .gz file — proves output unmodified since collection
- NTP sync state at verify time — timestamps are trustworthy
- Hardware ID — SHA256 of DMI chassis serial, ties output to specific unit without exposing serial
- All 25 section markers checked (was 4)
- privacy_exclusions block — every excluded category listed with status:
  - "not present — verified" — actively checked and confirmed absent
  - "redacted as xxx.xxx.xxx.xxx" — was present, sanitized
  - "redacted as xx:xx:xx:xx:xx:xx" — was present, sanitized
  - "not collected by design" — tool never touches these sources
- Human-readable terminal output preserved alongside JSON

## v1.2.0 — 2026-04-14

### Added — dgx-forensic-collect.sh
- Option A sudo handling — warns if not root, continues with partial data
  - dmidecode, pstore, rasdaemon, nvme smart-log flag "requires sudo"
- kern.log rotated file support — kern.log, kern.log.1, kern.log.2.gz
  - Removes tail -200 limit
  - Adds -a flag for binary file handling

### Fixed — dgx-forensic-verify.sh
- credential pattern false positive on disclaimer header text

## v1.1.0 — 2026-04-14

### Added
- Section 22: kern.log filtered extraction
- Section 23: nvidia-installer.log
- Section 24: Field diagnostic output (unified_summary.json, summary.csv, testspec.json)

### Fixed
- PCIe grep context -A12 → -A30
- Added BERT and APEI to dmesg grep patterns
- Removed -e from set -euo pipefail

## v1.0.0 — 2026-04-14

Initial release. 21 sections. Privacy controls: hostname → SPARK, IPs → [IP],
MACs → [MAC], gzip -9 output.
