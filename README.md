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

Tam <3 

## TODO 01: TFTP / auto_home Automount Persistence Vector
**Priority**: Critical
**Related Quirks**: 01, 03, 04, 13, 16

The `auto_home` automount map at `/System/Volumes/Data/home` may be redirecting
home directory or Desktop file access through a network path (TFTP/NFS/NetBoot).
This would explain why:
- Screenshots appear in Preview but `stat`/`ls`/`find` fail from Terminal
- TCC has no Desktop entry for Terminal (Desktop may not be local)
- `defaults read com.apple.screencapture` returns "does not exist" (pref domain
  may be served from network location)
- Screenshot filename encoding anomalies can't be analyzed (files inaccessible)

**Tasks**:
- [ ] Dump `/etc/auto_master` and `/etc/auto_home` map contents
- [ ] Check if Desktop is symlinked or automounted: `readlink ~/Desktop`, `mount | grep home`
- [ ] Inspect automount configuration: `cat /etc/auto_master`, `cat /etc/auto_home`
- [ ] Check for TFTP server config: `launchctl list | grep tftp`,
      `cat /etc/launchd.daemons/tftp.plist` (or `/System/Library/LaunchDaemons/tftp.plist`)
- [ ] Check if `tftpboot` directory exists anywhere: `find / -name "tftpboot" -maxdepth 3 2>/dev/null`
- [ ] Inspect NFS exports: `cat /etc/exports 2>/dev/null`, `nfsd status`
- [ ] Trace what happens when accessing `/home/aadmin`: `fs_usage -w -f filesys 2>/dev/null &`
      then `cd /home/aadmin` in another terminal
- [ ] Check if Desktop path resolves through autofs: `automount -m 2>/dev/null`,
      `ls -la /home/ 2>/dev/null`
- [ ] Dump DirectoryService config: `scutil --dns`, `dscl . -list /Users`
- [ ] Verify where screenshot files ACTUALLY land: `defaults read com.apple.screencapture location 2>/dev/null || echo "unset"`,
      then trigger a screenshot with `screencapture -x /tmp/test_screenshot.png` and check if it succeeds
      when writing to /tmp (bypassing Desktop autofs)

---

## TODO 02: Screenshot Filename Byte Analysis
**Priority**: High
**Related Quirks**: 01, 03, 05
**Blocked by**: TODO 01 (need filesystem access to Desktop)

**Tasks**:
- [ ] Once Desktop access is restored, run: `ls -1 ~/Desktop/Screenshot*.png | xxd`
- [ ] Compare filename byte length across multiple screenshots — look for variable-length
      encoding between seconds integer and AM/PM prefix
- [ ] Check for zero-width characters: `ls ~/Desktop/*.png | od -c | grep -E '342|303'`
- [ ] Cross-reference `stat` creation timestamp against filename timestamp — look for mismatch
- [ ] Write screenshot to `/tmp` instead of Desktop — compare naming pattern

---

## TODO 03: TCC Database Deep Inspection
**Priority**: High
**Related Quirks**: 01, 13

**Tasks**:
- [ ] Dump full user TCC database: `sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access ORDER BY service"`
- [ ] Dump full system TCC database: `sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access ORDER BY service"`
- [ ] Check for MDM-enforced privacy restrictions: `profiles show -type configuration 2>/dev/null`
- [ ] Check for privacy profile payloads: `profiles show -type profile 2>/dev/null`
- [ ] Verify if Terminal ever received Full Disk Access: `sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access WHERE client LIKE '%erminal%'"`
- [ ] Check if TCC database has been modified: `stat ~/Library/Application\ Support/com.apple.TCC/TCC.db`
- [ ] Examine for TCC bypass via MDM: `profiles show -type baseband 2>/dev/null`

---

## TODO 04: Boot Firmware Verification (mBoot)
**Priority**: Critical
**Related Quirks**: 12, 15, 20

**Tasks**:
- [ ] Verify `mBoot-18000.121.3` with Apple internal contacts — is this a legitimate firmware identifier for MacBook Neo M4?
- [ ] Dump NVRAM boot variables: `nvram -x` (especially `boot-args`, `csr-active-config`, `bluetoothExternalDongleFailed`)
- [ ] Check Boot UUID against diskutil: `diskutil info / | grep UUID`
- [ ] Verify SSV seal: `csrutil authenticated-root status`
- [ ] Check for recovery/boot volume tampering: `diskutil list`, `bputil -d`
- [ ] Cross-reference firmware hash against Apple's known-good database (via internal contacts)

---

## TODO 05: MediaTek Driver Stack Audit
**Priority**: High
**Related Quirks**: 07, 12, 14, 15

**Tasks**:
- [ ] List all loaded driverkit extensions: `kmutil list -variant-pattern '*.dext'`
- [ ] List all loaded kexts: `kmutil list -variant-pattern '*.kext'`
- [ ] Verify code signatures on MediaTek driver bundles: `codesign -dv --verbose=4 /System/Library/driverkit/MTK*` (locate actual path first)
- [ ] Filter ioreg by MediaTek: `ioreg -l | grep -E '14c3|793[0-9]|MTK'`
- [ ] Filter ioreg by Apple vendor: `ioreg -l | grep -E '004[cC]'`
- [ ] Check if MediaTek drivers survived DFU restore: compare against pre-restore baseline if available
- [ ] Capture BLE advertisement state: `sudo log show --predicate 'process == "bluetoothd"' --last 24h --info --style compact | grep -i 'advert\|gatt\|braille'`
- [ ] Enumerate GATT service handlers: `sudo log show --predicate 'subsystem == "com.apple.bluetooth"' --last 24h --info`

---

## TODO 06: SmartCard / Platform SSO Investigation
**Priority**: Medium
**Related Quirks**: 11, 17

**Tasks**:
- [ ] Verify `fld-ccid.bundle` origin: `codesign -dv --verbose=4 /usr/libexec/SmartCardServices/drivers/fld-ccid.bundle`
- [ ] Check if Platform SSO has active configurations: `profiles show -type configuration | grep -i 'sso\|platform'`
- [ ] Inspect `setoken` entries: `security find-generic-password -s "com.apple.setoken" 2>/dev/null`
- [ ] Check for token enrollment: `tokenutil list 2>/dev/null`
- [ ] Verify CryptoTokenKit plugin: `codesign -dv --verbose=4 /System/Library/Frameworks/CryptoTokenKit.framework/Plugins/pivtoken.appex`
- [ ] Check AccessKey.appex signature: `codesign -dv --verbose=4 /System/Library/ExtensionKit/Extensions/AccessKey.appex`

---

## TODO 07: Silent Wake Event Investigation
**Priority**: Medium
**Related Quirks**: 08, 19

**Tasks**:
- [ ] Identify PID 132: `ps -p 132 -o pid,comm,args`
- [ ] Identify PID 697: `ps -p 697 -o pid,comm,args`
- [ ] Dump pmset scheduled events: `pmset -g sched`
- [ ] Dump pmset assertions: `pmset -g assertions`
- [ ] Dump pmset log: `pmset -g log | tail -500`
- [ ] Check osanalytics configuration: `defaults read com.apple.osanalytics 2>/dev/null`
- [ ] Monitor wake events in real-time: `log stream --predicate 'eventMessage CONTAINS "Wake"' --info`
- [ ] Check if calaccessd has calendar data despite iCloud being disabled:
      `sqlite3 ~/Library/Calendars/Calendar\ Cache "SELECT count(*) FROM Calendar"`
- [ ] Disable silent wake timers: `sudo pmset schedule cancelall` (document first)

---

## TODO 08: AWDL Covert Channel Assessment
**Priority**: Medium
**Related Quirks**: 15

**Tasks**:
- [ ] Capture AWDL traffic baseline: `sudo tcpdump -i awdl0 -c 100 -w ~/Desktop/awdl_baseline.pcap 2>/dev/null`
      (may fail due to Quirk 01 — redirect to /tmp)
- [ ] Check AWDL peer discovery: `sudo log show --predicate 'process == "awdl"' --last 1h --info`
- [ ] Verify AirDrop state: `defaults read com.apple.sharingd 2>/dev/null`
- [ ] Check if AWDL is actively discovering peers: `wdutil info 2>/dev/null`
- [ ] Assess if AWDL could be used for cross-device state sync (correlates with
      browser session sync hypothesis)

---

## TODO 09: Power / Charger Anomaly
**Priority**: Low
**Related Quirks**: 18

**Tasks**:
- [ ] Verify charger with known-good Apple charger if available
- [ ] Check battery health: `system_profiler SPPowerDataType | grep -A5 "Battery"`
- [ ] Check SMC power state: `ioreg -l | grep -i 'power\|charg'`
- [ ] Monitor power source changes: `log stream --predicate 'subsystem == "com.apple.powermanagement"' --info`

---

## TODO 10: Sunrise WAN Adaptive Behavior
**Priority**: High
**Related Quirks**: 08, 19

**Tasks**:
- [ ] Capture Sunrise WAN events during active diagnostics:
      `log stream --predicate 'eventMessage CONTAINS "Sunrise"' --info > /tmp/sunrise_wan.log &`
- [ ] Capture AppleSunriseWLAN dext activity:
      `log stream --predicate 'process CONTAINS "sunrise" OR process CONTAINS "Sunrise"' --info > /tmp/sunrise_dext.log &`
- [ ] Correlate Sunrise WAN frequency spikes against specific diagnostic commands executed
- [ ] Check if Sunrise WAN events correlate with silent wake events (TODO 07)
- [ ] Investigate `AppleSunriseWLAN` driver origin: `kmutil list | grep -i sunrise`
- [ ] Verify if SunriseWLAN is a standard Apple dext or third-party

---

## TODO 11: Update Quirk Log + Evidence Doc
**Priority**: Administrative
**Related Quirks**: All

**Tasks**:
- [ ] Merge Quirks 15–20 into master quirk log
- [ ] Create companion script for each TODO that can be run iteratively
- [ ] Update RCA whitepaper with MediaTek unified stack finding (Wi-Fi + BT)
- [ ] Prepare mBoot firmware question for Apple internal contacts
- [ ] Cross-reference new quirks against existing investigation timeline
- [ ] Package evidence doc for Apple Security team submission

**tam** — Cloud SME  
Contact through established security channels.

---

*This repository is a research artifact, not a how-to guide. Defensive mitigations are included throughout.*
