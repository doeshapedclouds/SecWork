TODO 01: TFTP / auto_home Automount Persistence Vector

Priority: Critical Related Quirks: 01, 03, 04, 13, 16

The auto_home automount map at /System/Volumes/Data/home may be redirecting home directory or Desktop file access through a network path (TFTP/NFS/NetBoot). This would explain why:

Screenshots appear in Preview but stat/ls/find fail from Terminal
TCC has no Desktop entry for Terminal (Desktop may not be local)
defaults read com.apple.screencapture returns "does not exist" (pref domain may be served from network location)
Screenshot filename encoding anomalies can't be analyzed (files inaccessible)
Tasks:

 Dump /etc/auto_master and /etc/auto_home map contents
 Check if Desktop is symlinked or automounted: readlink ~/Desktop, mount | grep home
 Inspect automount configuration: cat /etc/auto_master, cat /etc/auto_home
 Check for TFTP server config: launchctl list | grep tftp, cat /etc/launchd.daemons/tftp.plist (or /System/Library/LaunchDaemons/tftp.plist)
 Check if tftpboot directory exists anywhere: find / -name "tftpboot" -maxdepth 3 2>/dev/null
 Inspect NFS exports: cat /etc/exports 2>/dev/null, nfsd status
 Trace what happens when accessing /home/aadmin: fs_usage -w -f filesys 2>/dev/null & then cd /home/aadmin in another terminal
 Check if Desktop path resolves through autofs: automount -m 2>/dev/null, ls -la /home/ 2>/dev/null
 Dump DirectoryService config: scutil --dns, dscl . -list /Users
 Verify where screenshot files ACTUALLY land: defaults read com.apple.screencapture location 2>/dev/null || echo "unset", then trigger a screenshot with screencapture -x /tmp/test_screenshot.png and check if it succeeds when writing to /tmp (bypassing Desktop autofs)
TODO 02: rc.netboot Investigation

Priority: Critical (NEW) Related Quirks: 16, 20

/etc/rc.netboot exists on the device. This is the NetBoot initialization script — normally only present on NetBoot client images or enterprise-managed machines. Directly relevant to the NetBoot/LAN enrollment lockdown investigation.

Tasks:

 Dump contents: cat /etc/rc.netboot
 Check if NetBoot daemon is loaded: sudo launchctl list | grep -i netboot
 Check NetBoot preferences: defaults read /Library/Preferences/com.apple.NetBoot 2>/dev/null
 Check for NetBoot-related LaunchDaemons: ls /System/Library/LaunchDaemons/ | grep -i netboot
 Check boot image source: nvram boot-device, nvram boot-args
 Check if rc.netboot was recently modified: stat /etc/rc.netboot
 Check if NetBoot shadow file exists: ls -la /var/netboot/ 2>/dev/null
 Verify if NetBoot is active: ifconfig | grep -B5 "en0", look for NetBoot DHCP options
TODO 03: krb5.keytab Investigation

Priority: Critical (NEW) Related Quirks: 11, 17

/etc/krb5.keytab exists. This file stores Kerberos principal keys for machine authentication. It should NOT exist on a personal device with no enterprise or Active Directory enrollment. Presence indicates the device has been (or is) Kerberos-authenticated to a realm.

Tasks:

 List keytab principals: klist -k /etc/krb5.keytab (may need sudo)
 Check keytab modification time: stat /etc/krb5.keytab
 Check Kerberos configuration: cat /etc/krb5.conf (if exists), cat /Library/Preferences/edu.mit.Kerberos 2>/dev/null
 Check for active Kerberos tickets: klist 2>/dev/null
 Check AD binding state: dsconfigad -show 2>/dev/null
 Verify keytab permissions: ls -la /etc/krb5.keytab
 Cross-reference with Platform SSO (Quirk 17) — Kerberos keytab + Platform SSO = enterprise authentication infrastructure staged on personal device
TODO 04: hosts.equiv Investigation

Priority: High (NEW) Related Quirks: 16

/etc/hosts.equiv exists. This file defines trusted hosts for r-commands (rlogin, rsh, rcp). On stock macOS it typically exists but is empty. If it contains entries, it establishes trust relationships the user didn't configure.

Tasks:

 Dump contents: cat /etc/hosts.equiv
 Check modification time: stat /etc/hosts.equiv
 Cross-reference any hostnames against network scan (Quirk 15)
 Check if r-services are enabled: sudo launchctl list | grep -E 'rlogind|rshd|rexecd'
 Check if r-services LaunchDaemons exist: ls /System/Library/LaunchDaemons/ | grep -E 'rlogin|rsh|rexec'
TODO 02: Screenshot Filename Byte Analysis

Priority: High Related Quirks: 01, 03, 05 Blocked by: TODO 01 (need filesystem access to Desktop)

Tasks:

 Once Desktop access is restored, run: ls -1 ~/Desktop/Screenshot*.png | xxd
 Compare filename byte length across multiple screenshots — look for variable-length encoding between seconds integer and AM/PM prefix
 Check for zero-width characters: ls ~/Desktop/*.png | od -c | grep -E '342|303'
 Cross-reference stat creation timestamp against filename timestamp — look for mismatch
 Write screenshot to /tmp instead of Desktop — compare naming pattern
TODO 03: TCC Database Deep Inspection

Priority: High Related Quirks: 01, 13

Tasks:

 Dump full user TCC database: sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access ORDER BY service"
 Dump full system TCC database: sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access ORDER BY service"
 Check for MDM-enforced privacy restrictions: profiles show -type configuration 2>/dev/null
 Check for privacy profile payloads: profiles show -type profile 2>/dev/null
 Verify if Terminal ever received Full Disk Access: sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access WHERE client LIKE '%erminal%'"
 Check if TCC database has been modified: stat ~/Library/Application\ Support/com.apple.TCC/TCC.db
 Examine for TCC bypass via MDM: profiles show -type baseband 2>/dev/null
TODO 04: Boot Firmware Verification (mBoot)

Priority: Critical Related Quirks: 12, 15, 20

Tasks:

 Verify mBoot-18000.121.3 with Apple internal contacts — is this a legitimate firmware identifier for MacBook Neo M4?
 Dump NVRAM boot variables: nvram -x (especially boot-args, csr-active-config, bluetoothExternalDongleFailed)
 Check Boot UUID against diskutil: diskutil info / | grep UUID
 Verify SSV seal: csrutil authenticated-root status
 Check for recovery/boot volume tampering: diskutil list, bputil -d
 Cross-reference firmware hash against Apple's known-good database (via internal contacts)
TODO 05: MediaTek Driver Stack Audit

Priority: High Related Quirks: 07, 12, 14, 15

Tasks:

 List all loaded driverkit extensions: kmutil list -variant-pattern '*.dext'
 List all loaded kexts: kmutil list -variant-pattern '*.kext'
 Verify code signatures on MediaTek driver bundles: codesign -dv --verbose=4 /System/Library/driverkit/MTK* (locate actual path first)
 Filter ioreg by MediaTek: ioreg -l | grep -E '14c3|793[0-9]|MTK'
 Filter ioreg by Apple vendor: ioreg -l | grep -E '004[cC]'
 Check if MediaTek drivers survived DFU restore: compare against pre-restore baseline if available
 Capture BLE advertisement state: sudo log show --predicate 'process == "bluetoothd"' --last 24h --info --style compact | grep -i 'advert\|gatt\|braille'
 Enumerate GATT service handlers: sudo log show --predicate 'subsystem == "com.apple.bluetooth"' --last 24h --info
TODO 06: SmartCard / Platform SSO Investigation

Priority: Medium Related Quirks: 11, 17

Tasks:

 Verify fld-ccid.bundle origin: codesign -dv --verbose=4 /usr/libexec/SmartCardServices/drivers/fld-ccid.bundle
 Check if Platform SSO has active configurations: profiles show -type configuration | grep -i 'sso\|platform'
 Inspect setoken entries: security find-generic-password -s "com.apple.setoken" 2>/dev/null
 Check for token enrollment: tokenutil list 2>/dev/null
 Verify CryptoTokenKit plugin: codesign -dv --verbose=4 /System/Library/Frameworks/CryptoTokenKit.framework/Plugins/pivtoken.appex
 Check AccessKey.appex signature: codesign -dv --verbose=4 /System/Library/ExtensionKit/Extensions/AccessKey.appex
TODO 07: Silent Wake Event Investigation

Priority: Medium Related Quirks: 08, 19

Tasks:

 Identify PID 132: ps -p 132 -o pid,comm,args
 Identify PID 697: ps -p 697 -o pid,comm,args
 Dump pmset scheduled events: pmset -g sched
 Dump pmset assertions: pmset -g assertions
 Dump pmset log: pmset -g log | tail -500
 Check osanalytics configuration: defaults read com.apple.osanalytics 2>/dev/null
 Monitor wake events in real-time: log stream --predicate 'eventMessage CONTAINS "Wake"' --info
 Check if calaccessd has calendar data despite iCloud being disabled: sqlite3 ~/Library/Calendars/Calendar\ Cache "SELECT count(*) FROM Calendar"
 Disable silent wake timers: sudo pmset schedule cancelall (document first)
TODO 08: AWDL Covert Channel Assessment

Priority: Medium Related Quirks: 15

Tasks:

 Capture AWDL traffic baseline: sudo tcpdump -i awdl0 -c 100 -w ~/Desktop/awdl_baseline.pcap 2>/dev/null (may fail due to Quirk 01 — redirect to /tmp)
 Check AWDL peer discovery: sudo log show --predicate 'process == "awdl"' --last 1h --info
 Verify AirDrop state: defaults read com.apple.sharingd 2>/dev/null
 Check if AWDL is actively discovering peers: wdutil info 2>/dev/null
 Assess if AWDL could be used for cross-device state sync (correlates with browser session sync hypothesis)
TODO 09: Power / Charger Anomaly

Priority: Low Related Quirks: 18

Tasks:

 Verify charger with known-good Apple charger if available
 Check battery health: system_profiler SPPowerDataType | grep -A5 "Battery"
 Check SMC power state: ioreg -l | grep -i 'power\|charg'
 Monitor power source changes: log stream --predicate 'subsystem == "com.apple.powermanagement"' --info
TODO 10: Sunrise WAN Adaptive Behavior

Priority: High Related Quirks: 08, 19

Tasks:

 Capture Sunrise WAN events during active diagnostics: log stream --predicate 'eventMessage CONTAINS "Sunrise"' --info > /tmp/sunrise_wan.log &
 Capture AppleSunriseWLAN dext activity: log stream --predicate 'process CONTAINS "sunrise" OR process CONTAINS "Sunrise"' --info > /tmp/sunrise_dext.log &
 Correlate Sunrise WAN frequency spikes against specific diagnostic commands executed
 Check if Sunrise WAN events correlate with silent wake events (TODO 07)
 Investigate AppleSunriseWLAN driver origin: kmutil list | grep -i sunrise
 Verify if SunriseWLAN is a standard Apple dext or third-party
TODO 11: Update Quirk Log + Evidence Doc

Priority: Administrative Related Quirks: All

Tasks:

 Merge Quirks 15–20 into master quirk log
 Create companion script for each TODO that can be run iteratively
 Update RCA whitepaper with MediaTek unified stack finding (Wi-Fi + BT)
 Prepare mBoot firmware question for Apple internal contacts
 Cross-reference new quirks against existing investigation timeline
 Package evidence doc for Apple Security team submission
tam — Cloud SME
Contact through established security channels.

/etc/krb5.keytab` exists. This file does NOT ship with stock macOS. It is only created when a machine is bound to a Kerberos realm (Active Directory, OpenDirectory, or enterprise identity provider). Its presence on a personal device purchased new from Apple with a fresh Apple account and no iCloud services is anomalous regardless of whether the file is empty or populated — the OS does not create this file speculatively.

Tasks:

 List keytab principals: sudo klist -k /etc/krb5.keytab
 Check keytab modification time: stat /etc/krb5.keytab
 Check Kerberos configuration: cat /etc/krb5.conf 2>/dev/null; cat /Library/Preferences/edu.mit.Kerberos 2>/dev/null
 Check for active Kerberos tickets: klist 2>/dev/null
 Check AD binding state: dsconfigad -show 2>/dev/null
 Check DirectoryService for Kerberos realm: dscl . -read /Config/KerberosKDC 2>/dev/null
 Verify keytab permissions and ownership: ls -la /etc/krb5.keytab
 Cross-reference with Platform SSO (Quirk 17) and doshapedclouds MDM artifacts (Quirk 11)
 Check if keytab was created during first-boot enrollment flow (Setup Assistant window)
Priority: High Related Quirks: 01, 13

TCC database returns empty for Terminal.app Desktop access. No entry means no prompt was ever generated or the entry was stripped.

Tasks:

 Dump full user TCC database: sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access ORDER BY service"
 Dump full system TCC database: sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access ORDER BY service"
 Check for MDM-enforced privacy restrictions: profiles show -type configuration 2>/dev/null
 Check for privacy profile payloads: profiles show -type profile 2>/dev/null
 Check if TCC database has been modified: stat ~/Library/Application\ Support/com.apple.TCC/TCC.db
 Check for TCC bypass via MDM profile: profiles show -type baseband 2>/dev/null
