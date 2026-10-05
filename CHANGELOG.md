# Changelog

## 1.0.1 — 2026-10-05 (first public release)

- The final state is always the last line of output (`tail -1` gives the verdict).
- Desktop window (GTK 3) with folder pickers, dry run / copy / resume / verify,
  "Stop safely", coloured verdict and an acceptance-status banner; falls back to a
  terminal wizard when GTK is unavailable.
- `acceptance/cyclops_acceptance.py`: one-command machine-local acceptance on a real
  SSD→HDD pair, with an independent coreutils-based proof and V1 preservation.
- `install.sh`: per-user command + app-menu entry.

## 1.0.0

- Initial implementation: preflight guards, rsync copy, structural / SHA-256 / read-back /
  rsync-checksum / git verification, records, resume.
