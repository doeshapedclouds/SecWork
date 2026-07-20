# Quirk Block: Desktop TCC Block Persists in Safe Boot

**Date Observed**: 2026-07-20
**Boot Mode**: Safe Boot
**Host**: pink (aadmin)
**Device**: MacBook Neo (M4)

## Symptom
All attempts to enumerate, stat, or list files on `~/Desktop` return `Operation not permitted` — including from within the Desktop directory itself (`cd ~/Desktop` succeeds, but `ls .` fails).

## What Was Tried
- `find ~/Desktop` → `Operation not permitted`
- `ls ~/Desktop/*.png` → `no matches found`
- `ls -1 *.png` (from within Desktop) → `no matches found`
- `stat` on known screenshot filename → `No such file or directory`
- `ls` (bare, from within Desktop) → `Operation not permitted`
- `sqlite3` query of user TCC.db for `kTCCServiceSystemPolicyDesktopFolder` → **empty result**

## Context
- Screenshot file was visually confirmed via Preview (image shows `Screenshot 2026-07-19 at 8.39.24 PM.png`)
- File is not enumerable, not stat-able, not glob-matchable from Terminal
- Original inquiry was byte-level encoding anomaly in screenshot filenames (odd-length encodings between last integer and AM/PM prefix)
- Could not reach byte analysis stage due to access block

## Significance
Safe boot reduces running services and should relax TCC enforcement for Terminal. Persistence of `Operation not permitted` in safe boot suggests either:
- TCC database manipulation (missing entries where entries should exist)
- ACL or flags applied at filesystem level on Desktop directory
- Configuration profile or MDM-enforced restriction overriding safe boot defaults

## Status
Unresolved. Pending ACL/flags inspection (`ls -lao`, `stat -f "%Sl"`) and system TCC database query.

# Compiled Quirk Log — Observable Anomalies
**Host**: pink (aadmin)
**Device**: MacBook Neo (M4), purchased new from Apple
**Investigation Start**: 2026-07-04 (post-DFU restore)
**Last Updated**: 2026-07-20

---

## Quirk 01: Desktop Directory Access Denied — Persists in Safe Boot
**Date Observed**: 2026-07-20
**Boot Mode**: Safe Boot

All attempts to enumerate, stat, or list files on `~/Desktop` return `Operation not permitted`. This includes commands executed from *within* the Desktop directory (`cd ~/Desktop` succeeds, `ls .` fails). Screenshot files visually confirmed via Preview but not accessible from Terminal. TCC database query for `kTCCServiceSystemPolicyDesktopFolder` returns empty result — no entry exists for Terminal at all. Block persists in safe boot, which should relax TCC enforcement.

**Status**: Unresolved.

---

## Quirk 02: Operation Not Permitted on Spotlight Index Directories
**Date Observed**: Prior to 2026-07-20
**Boot Mode**: Unknown (likely normal)

Access denied on Spotlight index directories even with `sudo`. Adds to documented TCC/SIP interference patterns during investigative workflow.

**Status**: Unresolved.

---

## Quirk 03: Odd-Length Encoding in Screenshot Filenames
**Date Observed**: Prior to 2026-07-20

Standard macOS screenshot filenames follow the pattern `Screenshot YYYY-MM-DD at H.MM.SS AM/PM.png`. Observed anomalous byte-length encoding between the last integer (seconds) and the AM/PM prefix. Could not reach byte-analysis stage due to Quirk 01 (Desktop access denied). Non-breaking spaces, zero-width characters, or steganographic byte injection suspected.

**Status**: Unresolved — blocked by Quirk 01.

---

## Quirk 04: All screencapture Defaults Return "Does Not Exist"
**Date Observed**: 2026-07-20
**Boot Mode**: Normal boot

Every `defaults read` query against `com.apple.screencapture` and `com.apple.screenshooter` returns `The domain/default pair of (...) does not exist`. This includes `location`, `name`, `type`, `disable-date-in-name`, and `Options`. Screenshots are still being generated and saved to Desktop with default naming, so the capture pipeline is functional — but the preference domain is inaccessible/unset.

**Status**: Unresolved.

---

## Quirk 05: Zero Log Entries for Screenshot Subsystem
**Date Observed**: 2026-07-20
**Boot Mode**: Normal boot

`log show` queries for `process == "screenshot"` and `subsystem == "com.apple.screenshot"` over 24h return zero entries across all log levels (Default, Info, Debug, Error, Fault). Screenshots were confirmed taken during this window. Functional output with no audit trail.

**Status**: Unresolved.

---

## Quirk 06: cfprefsd Quarantine Flag Anomalies on System Plist Files
**Date Observed**: During investigation period

Quarantine flags observed on system preference files (`.plist`) that should not carry them. Examined via `ls -l@` for extended attributes. Investigated as potential indicator of iCloud preference sync exploitation or local preference file tampering as a persistence mechanism.

**Status**: Under investigation.

---

## Quirk 07: Bluetooth Controller Shows NULL Address with State Off
**Date Observed**: During investigation period

Suspect device's Bluetooth controller (MediaTek MTK_7932) reports NULL MAC address with State Off. Anomalous for functional hardware. Used as beacon-based event correlation target (MAC `78:29:34:83:6B:30`) in log predicate filters.

**Status**: Under investigation.

---

## Quirk 08: "Sunrise WAN" Log Entries Increase in Response to Diagnostic Activity
**Date Observed**: During investigation period

`AppleSunriseWLAN` driver extension (dext) activity and "Sunrise WAN" items appear in log streams. Frequency of these entries increases in response to active diagnostic operations, suggesting adaptive behavior — the system or an injected process responds to investigation activity.

**Status**: Under investigation.

---

## Quirk 09: Permission Octets 0082 vs 0086 in Safe Boot
**Date Observed**: During safe boot diagnostics

Items in safe boot exhibit permission octets `0082` and `0086`. These are non-standard and potentially anomalous. `0086` differs from `0082` by the group-execute bit, which is unusual for system-managed files in safe boot context.

**Status**: Unresolved.

---

## Quirk 10: MACL (Managed ACL) Applied by Sandbox.kext on Container Data Folders
**Date Observed**: During investigation period

Extended attribute analysis reveals MACL (managed ACL) entries applied by `Sandbox.kext` on container Data folders. Examined as part of extended attribute forensic analysis alongside quarantine flags and xattr inspection.

**Status**: Under investigation.

---

## Quirk 11: 'doshapedclouds' Naming Convention in MDM/Profile Artifacts
**Date Observed**: During investigation period

Observed MDM/profile artifact naming pattern referencing `'doshapedclouds'` convention. Anomalous naming for system-managed configuration profiles, potentially indicating injected or spoofed MDM artifacts.

**Status**: Under investigation.

---

## Quirk 12: Suspected Pre-Production or Modified Bluetooth Drivers Force-Loaded
**Date Observed**: During investigation period

Behavior differs between safe boot and normal boot. Suspects pre-production or modified Bluetooth drivers are being force-loaded on the device outside of safe boot mode. Gaps between safe boot and normal boot behavior actively documented for forensic integrity.

**Status**: Under investigation.

---

## Quirk 13: TCC Database Manipulation Indicators
**Date Observed**: 2026-07-20

User TCC database (`~/Library/Application Support/com.apple.TCC/TCC.db`) returns empty results for `kTCCServiceSystemPolicyDesktopFolder` — no entry exists for Terminal.app (neither granted nor denied). This is abnormal for a Mac that has been actively used. Combined with Quirk 01 (persistent Desktop access denial in safe boot), suggests TCC database may be manipulated or overridden by external mechanism (MDM profile, configuration profile, or filesystem-level ACL).

**Status**: Unresolved.
