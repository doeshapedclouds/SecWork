# SecWork

Security research and root cause analysis investigating near-field configuration injection and enrollment lock-in on modern consumer operating systems.

## Overview

This repository documents a multi-vector attack framework discovered during investigation of a device exhibiting persistent anomalous behavior following a factory reset. The investigation expanded from a single-device incident into a generalized threat model spanning ~120 distinct attack vectors across macOS, iOS, Android, Windows, and Linux.

The core finding: **configuration injection via proximity-based transports (BLE GATT, Classic Bluetooth, NFC) can establish persistence that survives factory restoration, propagates across devices via sync mechanisms, and evades standard forensic methodology — including by compromising the analysis tools themselves.**

## Documents

| File | Description | Size |
|------|-------------|------|
| [`rca.md`](rca.md) | Root Cause Analysis — incident-specific findings, observed evidence, timeline, forensic methodology, and diagnostic command reference | ~30KB |
| [`paper.md`](paper.md) | Vector Exploration Framework — generalized threat model mapping ~120 attack vectors across transport layers, OS platforms, and trust boundaries | ~1MB |
| [`progress.md`](progress.md) | Evidence Correlation Matrix — cross-references observed system behaviors against theoretical attack vectors in the framework | ~25KB |

## Threat Model Summary

Transport Layer → Configuration Injection → Daemon Exploitation → Sync Propagation → Persistence (BLE/USB/NFC/WiFi) (cfprefsd/plist/MDM) (ColorSync/Bluetooth) (iCloud/Google) (DFU survival)


## Important Caveats

- Several findings were initially assessed as malicious and later re-evaluated as benign system behavior (documented with full audit trail in `rca.md` §5)
- Analysis provenance is flagged where client-side tools may have been operating in a compromised execution context
- This is a living document — findings are updated as new evidence is gathered

## Disclosure

Intended for review by Apple Security and other vendor security teams. Repository is public to maintain an immutable, timestamped record via git history.

## Author

**tam** — Cloud SME  
Contact through established security channels.

---

*This repository is a research artifact, not a how-to guide. Defensive mitigations are included throughout.*
