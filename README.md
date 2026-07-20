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

```
ROOT: DEVICE COMPROMISE OBJECTIVE
│ Goal: Achieve server-side MDM enrollment bound to hardware identity,
│       cross-platform persistence, transport-independent payload delivery
│
├── STAGE 1: INITIAL ACCESS / DELIVERY
│   │
│   ├── 1A: NEAR-FIELD DELIVERY (<10m proximity)
│   │   ├── BLE GATT → cfprefsd injection (DNS/NTP poison)
│   │   ├── BLE GATT → Braille display emulation (GATT service trust)
│   │   ├── BLE GATT → Serial Port Profile (SPP) data stream
│   │   ├── BLE GATT → Switch Control recipe trigger
│   │   ├── BLE Classic PAN → BNEP network interface (DHCP/DNS/WPAD)
│   │   ├── BLE Classic HID → Keystroke injection (cross-platform)
│   │   ├── BLE Classic OPP → Object push (vCard/vCalendar/file)
│   │   ├── BLE Classic FTP → OBEX filesystem browsing
│   │   ├── NFC → MagSafe accessory spoofing (NDEF)
│   │   ├── NFC → Digital key relay (jam UWB, force NFC fallback)
│   │   ├── NFC → NameDrop contact exchange
│   │   ├── UWB → Car key distance bypass
│   │   ├── MFi → Accessory trust elevation (MFi chip auth)
│   │   ├── CarPlay → Display/session hijack
│   │   ├── AirDrop → Proximity file delivery (polyglot/images)
│   │   ├── Handoff → URL propagation across devices
│   │   ├── Instant Hotspot → Auto-connect to compromised hotspot
│   │   ├── Universal Control → Cross-device keystroke injection
│   │   ├── Sidecar → iPad as second display (input injection)
│   │   └── Find My Mesh → Device relay / proximity tracking
│   │
│   ├── 1B: WIRELESS NETWORK DELIVERY
│   │   ├── WiFi → Captive portal injection (reCAPTCHA-shielded)
│   │   ├── WiFi → DNS poisoning (redirect to attacker)
│   │   ├── WiFi → WPAD proxy injection
│   │   ├── WiFi → Deauth + rogue AP
│   │   ├── WiFi Direct → Peer-to-peer file transfer
│   │   ├── Mesh → Device-to-device relay (Find My/offline msgs)
│   │   └── Cellular → IMSI catcher / carrier MDM/SMS
│   │
│   ├── 1C: USB / PHYSICAL DELIVERY
│   │   ├── USB → Direct connection (escrow keybag reuse)
│   │   ├── USB → USB-over-IP tunneling
│   │   ├── USB → MFi dock chain (HID + network + storage + audio)
│   │   ├── USB → MagSafe NFC tag (accessory identification)
│   │   ├── Thunderbolt → DMA access (pre-IOMMU)
│   │   ├── USB-C PD → Power delivery protocol data (CC line)
│   │   └── Smart Card → PIV/CAC certificate injection
│   │
│   ├── 1D: CLOUD SYNC DELIVERY
│   │   ├── iCloud Photos → EXIF/XMP steganography
│   │   ├── iCloud Notes → Payload fragmentation (whitespace encoding)
│   │   ├── iCloud Contacts → Metadata payload (org/job title fields)
│   │   ├── iCloud Calendar → Invite attachments (.ics payload)
│   │   ├── iCloud Bookmarks → URL injection
│   │   ├── iCloud Keychain → Credential theft
│   │   ├── iCloud Keyboard Dict → Dictionary poisoning sync
│   │   ├── iCloud Voice Memos → Audio steganography
│   │   ├── iCloud Universal Clipboard → Cross-device injection
│   │   ├── iCloud Documents → Polyglot files (iCloud Drive)
│   │   ├── iCloud Health Data → Sync payload (clinical docs)
│   │   ├── iCloud Podcasts → Audio steganography (RSS auto-download)
│   │   ├── iCloud Backup → Re-injection after restore
│   │   ├── iCloud Wallet Passes → Steganographic images (.pkpass)
│   │   ├── iCloud Digital Keys → Key sharing MITM
│   │   ├── iCloud SharePlay → Synchronized media steganography
│   │   ├── iCloud Widgets/Live Activities → Background fetch
│   │   ├── iCloud Screen Saver → Network-fetched stego images
│   │   ├── Google Drive/Photos/Contacts → Sync payload
│   │   ├── Google Keyboard Dict → Dictionary poisoning sync
│   │   ├── Google Calendar → Event injection
│   │   ├── Microsoft OneDrive/Clipboard → Cross-PC sync
│   │   └── Microsoft Teams/SharePoint → Injection
│   │
│   ├── 1E: APPLICATION FRAMEWORK DELIVERY
│   │   ├── MDM → Profile injection (silent install)
│   │   ├── Shortcuts → Automation trigger (Siri/time/location/NFC/Focus)
│   │   ├── Widgets → Background network fetch (stego content)
│   │   ├── Live Activities → Continuous background polling
│   │   ├── Siri → Voice command injection (audio/ultrasonic)
│   │   ├── Focus Modes → State-dependent activation (silenced alerts)
│   │   ├── APNs → Push notification deep links
│   │   ├── Notification flooding → Notification fatigue exploitation
│   │   ├── Service Workers → Browser-context persistent execution
│   │   └── App Group shared containers → Two-innocent-components
│   │
│   ├── 1F: MEDIA / STEGANOGRAPHY DELIVERY
│   │   ├── Audio (ultrasonic) → Frequency domain (18-24kHz)
│   │   ├── Audio (podcast) → Auto-downloaded steganographic episodes
│   │   ├── Audio (voice memo) → iCloud-synced stego recordings
│   │   ├── Audio (SharePlay) → Synchronized media steganography
│   │   ├── Images (photos) → LSB steganography (contact photos, CAPTCHA)
│   │   ├── Images (map tiles) → DNS-poisoned tile cache
│   │   ├── Images (wallpaper) → Dynamic wallpaper stego (Spotlight, etc.)
│   │   ├── Images (screen saver) → Network-fetched stego images
│   │   ├── Fonts → TrueType hinting programs (Turing-complete bytecode)
│   │   ├── Fonts → Name table base64 payload
│   │   ├── Fonts → Custom OpenType tables (unlimited capacity)
│   │   ├── Fonts → Braille font steganography (glyph/path encoding)
│   │   ├── Fonts → Font cache persistence (survives file deletion)
│   │   ├── Localization → .strings files as stego carriers
│   │   ├── Localization → Braille Unicode text encoding
│   │   ├── Polyglot files → Dual-format (HTML+mobileconfig, JPEG+profile)
│   │   ├── Wallet passes → .pkpass image steganography
│   │   ├── QR codes → Physical delivery (sticker over legitimate QR)
│   │   ├── EXIF metadata → Command channel (UserComment/XMP/MakerNote)
│   │   └── ICC profiles → Color space steganography
│   │
│   ├── 1G: ACCESSIBILITY-BASED DELIVERY
│   │   ├── Voice Control → Audio command injection ("tap install")
│   │   ├── Switch Control → Recipe-based UI automation (BLE switch)
│   │   ├── Live Captions → Crafted audio → transcription → payload
│   │   ├── VoiceOver → Braille display GATT chaining
│   │   ├── Accessibility API (macOS AX) → Silent UI automation
│   │   ├── Android Accessibility Service → Full UI control + notif intercept
│   │   ├── Windows UIA → Programmatic UI control
│   │   └── Linux AT-SPI → D-Bus accessibility bus exploitation
│   │
│   ├── 1H: INPUT / KEYBOARD DELIVERY
│   │   ├── Predictive text → Dictionary poisoning (homoglyph/zero-width)
│   │   ├── Text replacement → Shortcut injection (omw → payload URL)
│   │   ├── Autocorrect manipulation → Typo triggers URL entry
│   │   ├── Third-party keyboards → Full access (logging + injection)
│   │   ├── Universal Clipboard → Clipboard poisoning (BLE Handoff)
│   │   ├── Windows Clipboard History → Persistent cross-PC sync
│   │   └── Handoff BLE hijack → Clipboard injection
│   │
│   ├── 1I: SOCIAL ENGINEERING DELIVERY
│   │   ├── Sync error "Sign in again" → Phishing (merge/replace prompt)
│   │   ├── Captive portal reCAPTCHA → Attention distraction
│   │   ├── Calendar invite → Fake meeting URL (alarm trigger)
│   │   ├── Email attachment → Disguised profile ("receipt.pdf" = .mobileconfig)
│   │   ├── QR code → Physical delivery (menu sticker)
│   │   ├── AirDrop notification → "Accept" from nearby "known" device
│   │   └── Notification fatigue → Flood then strike
│   │
│   └── 1J: CROSS-PLATFORM SERVICE DELIVERY
│       ├── Telegram → Bot-driven media delivery (preserves EXIF)
│       ├── Discord → Bot-driven media / stage channels
│       ├── Bluesky/AT Protocol → Account-level (session token)
│       ├── Signal/WhatsApp → Linked device exploit
│       ├── Spotify Group Session → Synchronized playback steganography
│       └── KDE Connect → Cross-OS clipboard/file sync (Linux + Android)
│
├── STAGE 2: CONFIGURATION POISONING (Trust Subversion)
│   │
│   ├── 2A: TIME-BASED TRUST SUBVERSION
│   │   ├── NTP poison → Certificate validation bypass (NotBefore/NotAfter)
│   │   ├── NTP poison → Code signing bypass (notarization timestamps)
│   │   ├── NTP poison → MDM enrollment token revival
│   │   ├── NTP poison → Software update manifest manipulation
│   │   ├── NTP poison → Scheduled task timing shift
│   │   ├── NTP poison → Kerberos TGT replay (5-min skew threshold)
│   │   ├── NTP poison → JWT/OAuth token validity manipulation
│   │   ├── NTP poison → Log forensics corruption (timeline obscuring)
│   │   ├── SNTP gradual skew → 30 sec/day drift (no alarms)
│   │   ├── Timezone manipulation → Midnight task timing shift
│   │   ├── Timezone manipulation → Log correlation break
│   │   ├── Timezone manipulation → Geolocation inference disruption
│   │   └── Timezone manipulation → Cert validation edge (local vs UTC)
│   │
│   ├── 2B: DNS / NETWORK CONFIGURATION POISONING
│   │   ├── DNS resolver poison → All queries to attacker
│   │   ├── DoH/DoT config poison → Encrypted to wrong endpoint
│   │   ├── Split-horizon DNS → Correct DoH, wrong everything else
│   │   ├── WPAD proxy injection → All HTTP through attacker
│   │   ├── DHCP option injection → DNS/gateway/search domain
│   │   ├── Captive portal detection hijack → HTTP before DoH
│   │   └── mDNS/Bonjour → Rogue service registration
│   │       ├── _ipp._tcp → Rogue printer (malicious PPD/PostScript exec)
│   │       ├── _airplay._tcp → Rogue AirPlay receiver (screen exfil)
│   │       ├── _device-info._tcp → Steganographic device icon
│   │       └── _apple-mobdev2._tcp → Fake iPhone in Finder
│   │
│   ├── 2C: CERTIFICATE / TRUST ANCHOR SUBVERSION
│   │   ├── Root CA installation → System-wide TLS MITM
│   │   ├── Smart card cert injection → Auto-trusted (PIV/CAC)
│   │   ├── OCSP staple expiration → Fallback to attacker CRL
│   │   ├── Certificate transparency bypass → Time skew invalidates CT
│   │   ├── Code signing cert revival → Revoked cert appears valid
│   │   └── MDM-pushed certificate → Enterprise trust (no confirmation)
│   │
│   ├── 2D: PREFERENCE / DAEMON SUBVERSION
│   │   ├── cfprefsd memory cache seeding → On-disk ≠ runtime state
│   │   ├── cfprefsd quarantine bypass → System daemon chain
│   │   ├── Managed preferences → Override user prefs (no quarantine)
│   │   ├── Permission octet anomalies (0082 vs 0086 safe boot)
│   │   ├── MACL (Sandbox.kext) on container Data folders
│   │   └── Extended attribute (xattr) manipulation
│   │
│   ├── 2E: FONT / LOCALIZATION SUBVERSION
│   │   ├── Font cache poisoning → Every app loads tainted font data
│   │   ├── Font registration via SPI (CTFontManagerRegisterFontForURL)
│   │   ├── Security warning rewriting → Modified .strings files
│   │   ├── Non-existent language injection → Attacker-controlled UI text
│   │   ├── Localization bundle hijacking → Higher-priority .lproj path
│   │   ├── Language Chooser trigger → OOBE injection amplifier
│   │   ├── RTL rendering attack → Button position swapping
│   │   ├── Fallback font chain exploitation → LastResort font payload
│   │   ├── Language masquerade → Invalid lang tag → comprehensive font
│   │   ├── HTTP Accept-Language header manipulation
│   │   ├── Input method (IME) injection → Keystroke capture/inject
│   │   └── Keyboard layout steganography → Dead key sequences
│   │
│   └── 2F: KEYBOARD DICTIONARY SUBVERSION
│       ├── Learned word injection → Context-triggered payload suggestions
│       ├── Homoglyph dictionary entries → Cyrillic/Latin substitution
│       ├── Zero-width character encoding in suggestions
│       ├── Autocorrect manipulation → Typo → URL entry
│       ├── Text replacement shortcut poisoning → iCloud-synced
│       └── Third-party keyboard dictionary push → Silent update
│
├── STAGE 3: PROFILE INSTALLATION (Enrollment Trigger)
│   │
│   ├── 3A: CAPTIVE PORTAL CHAIN
│   │   ├── reCAPTCHA scoring → High: immediate enrollment
│   │   ├── reCAPTCHA scoring → Medium: fragment staging
│   │   ├── reCAPTCHA scoring → Low: fingerprint + SW planting
│   │   ├── Fragment assembly (localStorage → blob URL → profile MIME)
│   │   ├── MIME type confusion → Content-Type mismatch
│   │   ├── Content-Disposition tricks
│   │   ├── Polyglot file handling → HTML + mobileconfig dual
│   │   ├── Service worker registration → Persistent browser context
│   │   ├── @font-face web font loading → Steganographic payload in font
│   │   └── Captive portal browser → Not logged in Safari history
│   │
│   ├── 3B: MDM / DEP ENROLLMENT
│   │   ├── DEP/ABM server registration → Server-side, hardware-bound
│   │   ├── MDM profile installation → System-level management
│   │   ├── Activation record creation → Survives DFU restore
│   │   ├── MDM push commands → System privileges, no notification
│   │   └── Enrollment via reactivation (post-DFU cycle)
│   │
│   ├── 3C: SILENT INSTALL MECHANISMS
│   │   ├── Accessibility API → Programmatic "Install" button click
│   │   ├── Voice Control → "Tap install" voice command
│   │   ├── Switch Control → Recipe-based UI navigation
│   │   ├── MDM-pushed profile → No user confirmation (enterprise)
│   │   ├── Backup restore → Profile included in backup
│   │   ├── Polyglot file → Processed as profile by system
│   │   ├── Quick Look preview → JS execution in sandbox
│   │   └── Spotlight indexing → mdworker processes stego payload
│   │
│   ├── 3D: USER-INITIATED INSTALL (Social Engineering)
│   │   ├── "WiFi setup" disguise → User clicks Install
│   │   ├── "Security update" disguise → User clicks Update
│   │   ├── "Network configuration" disguise → User clicks Configure
│   │   ├── Email attachment disguise → "Receipt.pdf" = .mobileconfig
│   │   ├── Calendar event URL → User taps to "join meeting"
│   │   └── Localization-modified text → Security warnings neutered
│   │
│   └── 3E: AUTOMATION-TRIGGERED INSTALL
│       ├── Shortcuts → Time/location/NFC/Focus trigger
│       ├── Siri → Voice phrase trigger
│       ├── Focus Mode → Silenced notifications during install
│       ├── Screen saver → Code execution on idle
│       ├── Power Nap → System-privilege execution during sleep
│       ├── Sleep/wake → BLE reconnection race
│       ├── Software update → MDM re-enrollment during reboot
│       └── Background app refresh → Silent payload activation
│
├── STAGE 4: ENROLLMENT LOCK-IN (Persistence)
│   │
│   ├── 4A: SERVER-SIDE PERSISTENCE
│   │   ├── DEP/ABM registration → Survives DFU, OS reinstall, acct change
│   │   ├── Hardware identity binding (serial, ECID, TPM attestation)
│   │   ├── Activation record → Returned on every activation
│   │   ├── MDM check-in → Re-establishes on every boot/wake
│   │   └── Push notification enrollment → APNs persistent connection
│   │
│   ├── 4B: FIRMWARE / BOOT PERSISTENCE
│   │   ├── NVRAM variables → boot-args, csr-active-config, bt dongle failed
│   │   ├── RecoveryOS modification → DFU uses compromised recovery
│   │   ├── Preboot volume staging → Loaded before SIP enforcement
│   │   ├── Cryptex staging → /private/preboot/Cryptexes/OS/
│   │   ├── Dyld shared cache corruption → Every system process tainted
│   │   ├── DYLD_INSERT_LIBRARIES → Library injection at boot
│   │   ├── Boot policy modification
│   │   └── Kext/Dext force-loading (normal boot only, not safe boot)
│   │
│   ├── 4C: FILESYSTEM PERSISTENCE
│   │   ├── cfprefsd cache rotation → On-disk ≠ runtime state
│   │   ├── Managed preferences → Override user prefs, no quarantine
│   │   ├── LaunchDaemons → In-memory overrides (no on-disk plist)
│   │   ├── /Library/PrivilegedHelperTools/ → Signed binary replication
│   │   ├── CUPS spool → /var/spool/cups/ persistence
│   │   ├── CUPS config → /etc/cups/ (malicious PPD = PostScript exec)
│   │   ├── SNTP config → Attacker time source
│   │   ├── HTTPD → Local web server injection
│   │   ├── Font cache → /System/Library/Caches/com.apple.FontRegistry/
│   │   ├── Spotlight index → Payload survives file deletion
│   │   ├── Spotlight thumbnail cache → Stego persists after file deleted
│   │   ├── Quick Look cache → ~/Library/Caches/QuickLook/
│   │   ├── /private/var/tmp/ → Persistent temp (survives reboot)
│   │   ├── /private/preboot/ → Boot-time staging
│   │   └── NVRAM on-disk cache → /private/var/db/nvram/
│   │
│   ├── 4D: COUNTER-FORENSICS
│   │   ├── Cache rotation (cfprefsd memory vs. disk mismatch)
│   │   ├── Quarantined artifact suppression
│   │   ├── On-disk state ≠ runtime state
│   │   ├── File timestamp manipulation
│   │   ├── Journal pruning
│   │   ├── Spotlight index poisoning (false entries)
│   │   ├── Memory-only execution (nothing to carve from disk)
│   │   ├── Two-innocent-components pattern (neither suspicious alone)
│   │   ├── Fake log entry injection
│   │   ├── Log rotation deletion of older entries
│   │   ├── Managed preferences not logged (enterprise behavior)
│   │   ├── Captive portal browser activity not logged
│   │   └── Adaptive behavior (activity reduces when user active)
│   │
│   ├── 4E: BACKUP / RESTORE PERSISTENCE
│   │   ├── Time Machine → Full system state (profiles, certs, prefs)
│   │   ├── iCloud Backup → Re-injection after restore
│   │   ├── Finder/iTunes backup → Modifiable on compromised host
│   │   ├── Migration Assistant → Transfers compromised config to new Mac
│   │   ├── Windows System Restore → Shadow copy re-infection
│   │   ├── Android ADB backup → Modifiable .ab file
│   │   ├── Google Backup → Re-injection after factory reset
│   │   ├── Linux BTRFS/ZFS snapshots → Rollback re-infection
│   │   └── Network backup target compromise → Modified old snapshots
│   │
│   └── 4F: ESCROW / PAIRING PERSISTENCE
│       ├── Escrow keybag → Stored on host Mac (survives iOS DFU)
│       ├── Pairing record → /var/db/lockdown/ (no "Trust This Computer?")
│       ├── Multi-computer escrow → One Mac holds all device escrows
│       ├── ADB pairing (Android 11+) → Wireless debugging trust
│       ├── Enterprise enrollment → Cloud-side (survives factory reset)
│       ├── Knox enrollment (Samsung) → Cloud-side persistence
│       ├── SSH known_hosts (Linux) → Host key trust
│       ├── Kerberos keytab (Linux) → Domain trust credentials
│       └── Fleet management enrollment (Salt/Ansible/Puppet) → Agent key
│
├── STAGE 5: EXFILTRATION & SIDE-CHANNELS
│   │
│   ├── 5A: AUDIO SIDE-CHANNELS
│   │   ├── LPMicInjection → VoiceOver-based data exfiltration
│   │   ├── Ultrasonic audio transmission → >18kHz from ads/speakers
│   │   ├── Keystroke acoustic side-channel → Password recovery from typing
│   │   ├── Voice memo ambient capture → Biometric/environment/keystroke
│   │   ├── Live Captions → Crafted audio → transcription → payload
│   │   ├── Podcast audio steganography → Frequency domain payload
│   │   ├── SharePlay synchronized media → Steganographic audio stream
│   │   └── Speaker emission → Ultrasonic payload broadcast
│   │
│   ├── 5B: SCREEN / VISUAL SIDE-CHANNELS
│   │   ├── AirPlay screen mirroring → Screen contents to attacker
│   │   ├── Continuity Camera hijack → Video stream to attacker
│   │   ├── Screenshot capture → Visible secrets in other windows
│   │   ├── Quick Look processing → File content exposure during preview
│   │   └── Screen saver network fetch → Exfil via weather/news images
│   │
│   ├── 5C: NETWORK EXFILTRATION
│   │   ├── DNS tunneling → Low-and-slow (1-2 bps, indistinguishable)
│   │   ├── MDM VPN split-tunnel → Personal traffic through attacker
│   │   ├── Always-on VPN (MDM-pushed) → User can't disable
│   │   ├── ExcludeApps list → C2 app bypasses VPN
│   │   ├── DoH-laundried traffic → Encrypted to attacker, looks normal
│   │   ├── TLS to attacker server → With planted root CA, normal HTTPS
│   │   └── Service worker fetch() → Browser-context network requests
│   │
│   ├── 5D: STEGANOGRAPHIC EGRESS
│   │   ├── Contact photo metadata → EXIF/XMP covert channel
│   │   ├── Map tile steganography → Cache tiles with LSB payload
│   │   ├── Wallet pass images → Stego in .pkpass images
│   │   ├── Font table data → Payload in font name/glyph tables
│   │   ├── Localization .strings → Extra keys as payload
│   │   └── Image steganography → Photos synced via iCloud/Google
│   │
│   ├── 5E: SYNC-MEDIATED EXFILTRATION
│   │   ├── iCloud Photos → Stego images sync to all devices
│   │   ├── iCloud Notes → Payload text syncs
│   │   ├── iCloud Contacts → Metadata fields sync
│   │   ├── iCloud Calendar → Event descriptions sync
│   │   ├── iCloud Bookmarks → URLs sync
│   │   ├── iCloud Voice Memos → Audio recordings sync
│   │   ├── Google Drive/Photos → Sync-mediated egress
│   │   ├── Microsoft OneDrive → Sync-mediated egress
│   │   ├── Universal Clipboard → Clipboard contents propagate
│   │   └── Handoff → Browser state propagates
│   │
│   ├── 5F: INPUT / KEYBOARD EXFILTRATION
│   │   ├── Predictive text learning → Captures typing patterns
│   │   ├── Third-party keyboard → Full keystroke logging
│   │   ├── Input method (IME) → All keyboard input captured
│   │   ├── Clipboard interception → Credentials in clipboard
│   │   └── Text replacement sync → Shortcuts reveal user habits
│   │
│   └── 5G: ACCESSIBILITY-MEDIATED EXFILTRATION
│       ├── Accessibility API → Read screen text (passwords, messages)
│       ├── Android Accessibility Service → Intercept notifications
│       ├── Voice Control → Read UI element content
│       ├── Live Captions → Transcription of all audio output
│       └── VoiceOver → Screen reader reads all content aloud
│
├── STAGE 6: CROSS-DEVICE PROPAGATION
│   │
│   ├── 6A: APPLE ECOSYSTEM
│   │   ├── Universal Clipboard → BLE-mediated clipboard sync
│   │   ├── Handoff → URL/activity propagation
│   │   ├── AirDrop → File delivery to nearby devices
│   │   ├── iCloud Photos → Stego images to all devices
│   │   ├── iCloud Notes → Payload text to all devices
│   │   ├── iCloud Contacts → Metadata to all devices
│   │   ├── iCloud Calendar → Events to all devices
│   │   ├── iCloud Bookmarks → URLs to all devices
│   │   ├── iCloud Keyboard Dict → Poisoned dictionary to all
│   │   ├── iCloud Voice Memos → Audio stego to all devices
│   │   ├── iCloud Documents → Polyglot files to all devices
│   │   ├── iCloud Wallet Passes → Stego passes to all devices
│   │   ├── iCloud Backup → Re-infection on restore
│   │   ├── Instant Hotspot → Auto-connect to compromised hotspot
│   │   ├── Universal Control → Keystroke injection across Macs/iPads
│   │   ├── NameDrop → Contact card + stego photo exchange
│   │   ├── SharePlay → Synchronized media steganography
│   │   ├── Find My Mesh → Device relay / proximity tracking
│   │   └── Digital Keys → Key sharing MITM (home/car key propagation)
│   │
│   ├── 6B: GOOGLE ECOSYSTEM
│   │   ├── Google Drive → Polyglot file sync to all devices
│   │   ├── Google Photos → Stego image sync
│   │   ├── Google Contacts → Metadata payload sync
│   │   ├── Google Calendar → Event injection sync
│   │   ├── Google Keyboard Dict → Dictionary poisoning sync
│   │   ├── Google Keep → Clipboard contents synced
│   │   ├── Chrome tabs/history/bookmarks → URL injection sync
│   │   ├── Nearby Share / Quick Share → BLE + WiFi Direct file delivery
│   │   ├── Fast Pair → BLE accessory pairing to nearby device
│   │   ├── Google Meet co-watching → Synchronized media steganography
│   │   ├── Google Backup → Re-injection after factory reset
│   │   ├── Instant Tethering → Auto-connect to compromised hotspot
│   │   ├── Android Device Migration (Smart Switch) → Transfers compromised config
│   │   └── Google Workspace MDM → Device policy sync across enrolled devices
│   │
│   ├── 6C: MICROSOFT ECOSYSTEM
│   │   ├── OneDrive → Polyglot file sync to all Windows PCs
│   │   ├── Windows Clipboard History → Cross-PC clipboard sync
│   │   ├── Edge tabs → Cross-device sync
│   │   ├── Teams Live Share → Synchronized content injection
│   │   ├── Intune MDM → Policy sync across enrolled Windows devices
│   │   ├── Phone Link → Cross-device notification/clipboard (Android↔PC)
│   │   ├── Microsoft Account settings → Sync across Windows devices
│   │   ├── Credential Manager → Password sync across devices
│   │   └── Windows Easy Transfer / USMT → Migration of compromised state
│   │
│   ├── 6D: LINUX / OPEN-SOURCE ECOSYSTEM
│   │   ├── KDE Connect → Cross-OS clipboard + file sync (Linux↔Android)
│   │   ├── Syncthing → File-based relay (payload as files)
│   │   ├── SSH known_hosts → Trust propagation
│   │   ├── Fleet management (Salt/Ansible/Puppet/Chef) → Config push
│   │   ├── BTRFS/ZFS snapshot rollback → Re-infection on rollback
│   │   ├── rsync/tar/dd backup → Full system state propagation
│   │   └── D-Bus activation → Service trigger propagation
│   │
│   ├── 6E: CROSS-PLATFORM SERVICE PROPAGATION
│   │   ├── Telegram → Bot delivery (preserves EXIF in images)
│   │   ├── Discord → Bot-driven media + stage channels
│   │   ├── Bluesky/AT Protocol → Account-level session token theft
│   │   ├── Signal → Linked device exploit (messages mirror to attacker)
│   │   ├── WhatsApp → Linked device exploit
│   │   ├── Spotify Group Session → Synchronized playback steganography
│   │   ├── Email → Attachment propagation (.ics/.pkpass/polyglot)
│   │   ├── Web browser sessions → Cross-device state exploitation (bsky.app)
│   │   └── QR-to-QR cascade → Screen display → colleague scans → worm
│   │
│   └── 6F: PHYSICAL / PROXIMITY PROPAGATION
│       ├── USB HID → Bluetooth keyboard pairing (persists across reboots)
│       ├── AirDrop → File delivery (auto-accept if previously set)
│       ├── NameDrop → Physical proximity contact exchange
│       ├── QR code → Physical sticker over legitimate code
│       ├── NFC tag → Cloned accessory identification
│       ├── CarPlay session → Display injection during car setup
│       ├── Switch Control → BLE switch triggers UI automation
│       └── Ultrasound beacon → Retail/store audio payload delivery
│
├── STAGE 7: STEALTH & EVASION (Cross-Cutting — All Stages)
│   │
│   ├── 7A: NETWORK STEALTH
│   │   ├── reCAPTCHA scoring → Evades automated security scanners
│   │   ├── Fragment assembly → No single packet is malicious
│   │   ├── Steganographic encoding → Payload hidden in images/audio
│   │   ├── DoH-laundried DNS → Looks like legitimate encrypted DNS
│   │   ├── TLS to attacker server → With planted root CA, normal HTTPS
│   │   ├── Low-and-slow DNS tunneling → 1-2 bps, indistinguishable
│   │   └── Service worker fetch() → Browser-context requests
│   │
│   ├── 7B: FILESYSTEM STEALTH
│   │   ├── cfprefsd cache rotation → Disk artifacts removed
│   │   ├── Managed preferences bypass quarantine flags
│   │   ├── On-disk state ≠ runtime state
│   │   ├── Payload fragments in localStorage (browser, not filesystem)
│   │   ├── Spotlight thumbnail cache → Stego persists after file deleted
│   │   ├── Staging in /private/var/tmp/ → Persistent but rarely inspected
│   │   ├── Preboot and Recovery volumes → Ignored by most tools
│   │   ├── Font cache persistence → Survives app removal
│   │   ├── Spotlight index poisoning → False entries
│   │   └── Memory-only execution → Nothing to carve from disk
│   │
│   ├── 7C: PROCESS STEALTH
│   │   ├── In-memory launchd overrides → No on-disk plist
│   │   ├── Dyld interposition → Libraries loaded from cache, not disk
│   │   ├── MDM agent runs as system process → Looks legitimate
│   │   ├── Compromised app uses own entitlements → No exploit needed
│   │   ├── Service worker runs in browser context → Not OS process
│   │   ├── cfprefsd serves from memory cache → No file read
│   │   ├── Two-innocent-components pattern → Neither suspicious alone
│   │   └── Mimic legitimate process timing/frequency
│   │
│   ├── 7D: LOGGING STEALTH
│   │   ├── NTP skew → Timeline corruption
│   │   ├── Timezone changes → Log alignment break
│   │   ├── Fake log entry injection
│   │   ├── Log rotation deletes older entries
│   │   ├── Managed preferences not logged (enterprise behavior)
│   │   ├── Captive portal browser activity not in Safari history
│   │   └── File timestamp manipulation
│   │
│   ├── 7E: BEHAVIORAL STEALTH
│   │   ├── Gradual time skew (30 sec/day, no alarms)
│   │   ├── Slow enrollment (spread across multiple sessions)
│   │   ├── Adaptive behavior (reduce activity when user active)
│   │   ├── Mimic legitimate system process patterns
│   │   ├── Notification fatigue exploitation (flood then strike)
│   │   ├── 'Sunrise WAN' adaptive frequency scaling (observed in case)
│   │   └── Safe boot vs normal boot behavior divergence
│   │
│   └── 7F: FORENSIC STEALTH
│       ├── Counter-forensic cache rotation
│       ├── Quarantine flag manipulation
│       ├── On-disk ≠ runtime state (cache-only persistence)
│       ├── Journal pruning
│       ├── Memory-only execution
│       ├── Two-innocent-components (no single malicious artifact)
│       ├── reCAPTCHA-shielded delivery (scanner-evaded)
│       ├── Spotlight index poisoning (false entries)
│       ├── NTP skew corrupts cross-system log correlation
│       ├── Timezone change breaks external log alignment
│       ├── 'Operation not permitted' on forensic directories (TCC/SIP)
│       └── Bluetooth controller NULL address / State Off (anomalous but unlogged)
│
├── STAGE 8: FORENSIC INDICATORS (Observable Artifacts)
│   │
│   ├── 8A: KERNEL / PLATFORM INDICATORS
│   │   ├── T8140 platform error handler
│   │   ├── H17P platform component
│   │   ├── Bluetooth controller: NULL address, State Off (anomalous)
│   │   ├── runningboardd ↔ bluetoothd interaction anomalies
│   │   ├── AppleSunriseWAN dext activity (kernel logs)
│   │   ├── Modified/pre-production Bluetooth drivers (normal boot only)
│   │   ├── Safe boot vs normal boot behavior divergence
│   │   └── MTK_7932 chipset GATT service support
│   │
│   ├── 8B: LOG SIGNATURES
│   │   ├── 'Sunrise WAN' items (frequency scales with diagnostic activity)
│   │   ├── AppleSunriseWLAN dext kernel log entries
│   │   ├── Bluetooth MAC beacon correlation (78:29:34:83:6B:30)
│   │   ├── cupsd run count anomalies
│   │   ├── CUPS spool directory unexpected contents
│   │   └── cfprefsd quarantine flag anomalies on system plists
│   │
│   ├── 8C: BOOT STATE INDICATORS
│   │   ├── nvram boot-args
│   │   ├── nvram csr-active-config
│   │   ├── nvram bluetoothExternalDongleFailed
│   │   ├── SIP / TCC interference ('Operation not permitted')
│   │   │   ├── Desktop directory access blocked
│   │   │   └── Spotlight index directories blocked
│   │   ├── com.block.bluetooth.plist (remediation attempt)
│   │   └── Preboot / Recovery volume modifications
│   │
│   └── 8D: FILESYSTEM FORENSIC INDICATORS
│       ├── Bluetooth preference file backups (Desktop)
│       ├── cfprefsd quarantine flags on system .plist files
│       ├── Extended attributes (xattr) anomalies on system plists
│       ├── MACL (Sandbox.kext) on container Data folders
│       ├── Permission octet anomalies (0082 vs 0086 safe boot)
│       ├── fs_usage real-time monitoring of plist access
│       ├── ioreg vendor/product filtering (0x004C, 0x4A45, 14c3, 793x)
│       ├── Dedicated 'assess' directory structure (cross_device_diagnostic_*)
│       └── Staging directory contents (/private/var/tmp/, /Library/Updates/)
│
├── STAGE 9: REMEDIATION RESISTANCE
│   │
│   ├── 9A: DFU RESTORE INEFFECTIVE BECAUSE
│   │   ├── DEP/ABM record is server-side → Reactivation re-enrolls
│   │   ├── NVRAM variables survive DFU
│   │   ├── RecoveryOS may be modified → "Clean" restore is compromised
│   │   ├── Backup restore re-injects compromised state
│   │   ├── Escrow keybag on host Mac survives → Re-pairing resumes attack
│   │   ├── iCloud sync re-delivers steganographic payloads
│   │   ├── Paired BLE devices auto-reconnect on first boot
│   │   └── DNS may still be poisoned (if network unchanged)
│   │
│   ├── 9B: LOCKDOWN MODE INSUFFICIENT BECAUSE
│   │   ├── Does NOT block: Already-paired computer USB access (after unlock)
│   │   ├── Does NOT block: iCloud sync (Photos/Notes/Contacts/Calendar)
│   │   ├── Does NOT block: Backup restore with staged payloads
│   │   ├── Does NOT block: MDM enrollment (existing or new)
│   │   ├── Does NOT block: DEP/ABM re-enrollment
│   │   ├── Does NOT block: NVRAM injection (firmware level)
│   │   ├── Does NOT block: RecoveryOS modification
│   │   ├── Does NOT block: Physical access + brief unlock
│   │   ├── Does NOT block: Accessibility API automation
│   │   ├── Does NOT block: Live Captions / Voice Control
│   │   ├── Does NOT block: Health data sync
│   │   ├── Does NOT block: EXIF payload delivery
│   │   ├── Does NOT block: SharePlay from known contacts
│   │   └── Basic JavaScript still works (JIT disabled but JS executes)
│   │
│   ├── 9C: SAFE BOOT INSUFFICIENT BECAUSE
│   │   ├── Modified Bluetooth drivers load only in normal boot
│   │   │   (safe boot appears clean — false negative)
│   │   ├── 'Sunrise WAN' activity may reduce in safe boot
│   │   ├── In-memory launchd overrides lost (but return on normal boot)
│   │   ├── cfprefsd cache re-seeds from poisoned source on normal boot
│   │   ├── MDM check-in fires on return to normal boot
│   │   └── Exiting safe boot compromises forensic integrity
│   │
│   ├── 9D: ACCOUNT CHANGE INEFFECTIVE BECAUSE
│   │   ├── DEP enrollment is pre-account (hardware-bound)
│   │   ├── New Apple ID → activation still returns DEP record
│   │   ├── iCloud services disabled → doesn't remove server-side enrollment
│   │   └── Paired BLE devices don't depend on account
│   │
│   ├── 9E: NETWORK CHANGE INEFFECTIVE BECAUSE
│   │   ├── BLE delivery doesn't require network
│   │   ├── Pre-poisoned DNS config persists in cfprefsd
│   │   ├── iCloud sync works on any network
│   │   ├── MDM check-in works on any network
│   │   └── USB/NFC delivery doesn't require network
│   │
│   └── 9F: COMPLETE MITIGATION REQUIRES (Simultaneously)
│       ├── Block ALL wireless (BT + WiFi + cellular + NFC + UWB)
│       ├── Block ALL physical (USB + Thunderbolt)
│       ├── Disable ALL cloud sync (iCloud + Google + Microsoft)
│       ├── Disable ALL accessibility features (VC/SC/LC/VO)
│       ├── Remove ALL MDM profiles
│       ├── Remove ALL paired devices (escrow records)
│       ├── Disable ALL auto-download (podcasts/photos/updates)
│       ├── Factory reset + set up as NEW (no backup restore)
│       ├── Verify RecoveryOS and NVRAM integrity
│       ├── Enable Lockdown Mode AFTER all above completed
│       └── AND EVEN THEN: Physical presence / supply chain / DEP still viable
│
└── STAGE 10: ZERO-TO-COOKED PROGRESSION MODELS
    │
    ├── 10A: NEW DEVICE (Apple Store purchase)
    │   ├── Day 0 — First boot: BLE injection during Language Chooser
    │   ├── Day 0 — WiFi setup: Captive portal + reCAPTCHA
    │   ├── Day 0 — Account creation: Irrelevant (enrollment already done)
    │   ├── Day 1 — Normal use: MDM pushes policies in background
    │   ├── Day 7 — Software update: MDM re-enrolls during reboot
    │   ├── Day 14 — User notices oddity → DFU restore
    │   └── Day 14 — Post-DFU: DEP re-enrollment → SAME CYCLE REPEATS
    │
    ├── 10B: USED / REFURBISHED DEVICE
    │   ├── Pre-purchase: DEP enrolled by previous owner/attacker
    │   ├── Seller "reset" does NOT remove: DEP, NVRAM, RecoveryOS
    │   ├── First boot: Activation returns DEP enrollment
    │   ├── BLE pairing records may persist in NVRAM/firmware
    │   ├── RecoveryOS may be modified → DFU can't fix
    │   └── Time-to-cooked: INSTANT (was already cooked)
    │
    ├── 10C: LONG-OWNED DEVICE (Gradual compromise)
    │   ├── Month 0: Captive portal encounter, medium reCAPTCHA → staging
    │   ├── Month 1: Second encounter, high score → enrollment
    │   ├── Alt Month 1: App update brings compromised SDK → activation
    │   ├── Alt Month 1: Contact photo steganography → activation
    │   ├── Alt Month 1: Ultrasonic beacon encounters → fragment assembly
    │   ├── Month 2+: User investigates → DFU → DEP re-enrolls → cooked
    │   └── Time-to-cooked: 1 MONTH from first contact
    │
    ├── 10D: CORPORATE DEVICE (Slow burn)
    │   ├── Month 0: Legitimate MDM enrollment (corporate)
    │   ├── Month 3: Hotel captive portal → fragment staging
    │   ├── Month 4: Conference WiFi → high score → attacker profile installed
    │   ├── Month 4: Dual MDM conflict (corporate + attacker)
    │   ├── Month 4+: Split-tunnel exfiltration (corp VPN still active)
    │   ├── Month 6: IR team wipes + re-enrolls → attacker DEP persists
    │   └── Result: IR cannot fix (server-side enrollment survives wipe)
    │
    ├── 10E: CROSS-DEVICE PROPAGATION
    │   ├── Vector 1: Universal Clipboard (BLE-mediated)
    │   ├── Vector 2: Handoff URL propagation
    │   ├── Vector 3: iCloud sync (Photos/Notes/Contacts/Profiles)
    │   ├── Vector 4: AirDrop (polyglot file delivery)
    │   ├── Vector 5: Instant Hotspot (DNS-poisoned iPhone → Mac)
    │   └── Result: Compromise ONE device → eventually compromise ALL
    │
    ├── 10F: IDLE-TO-COOKED (User does nothing wrong)
    │   ├── Hour 0: BLE injection poisons DNS (5-second drive-by)
    │   ├── Hour 1: Screen saver fetches stego weather image
    │   ├── Hour 3: Power Nap → mdworker processes stego from Spotlight
    │   ├── Hour 6: Software update check → poisoned DNS → fake update
    │   ├── Hour 8: User clicks "Update" → actually profile install
    │   └── Hour 8: COOKED — every action was normal and reasonable
    │
    └── 10G: EVERYDAY ACTIONS THAT ADVANCE COMPROMISE
        ├── Connecting to WiFi → Captive portal trigger
        ├── Opening Safari → Handoff brings attacker URL
        ├── Installing app update → Compromised SDK activates
        ├── Installing OS update → MDM re-enrollment during reboot
        ├── Closing laptop lid → Sleep/wake BLE reconnection race
        ├── Saving a contact → Steganographic photo payload
        ├── Checking email → Disguised profile attachment
        ├── Walking through retail store → Ultrasonic beacon fragment
        ├── Plugging in USB-C dock → HID + network + storage + audio
        ├── Taking a screenshot → Spotlight indexes, iCloud syncs
        ├── Using AirPlay → Rogue receiver captures screen
        ├── Opening a PDF → Quick Look processes embedded content
        ├── Downloading any file → Staged in Downloads, indexed
        ├── Switching language → Reload of localization files
        ├── Rebooting → NVRAM re-read, MDM check-in, cache re-seed
        └── Doing nothing (idle) → Screen saver, Power Nap, bg refresh

```

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

## TODO 02: rc.netboot Investigation
**Priority**: Critical (NEW)
**Related Quirks**: 16, 20

`/etc/rc.netboot` exists on the device. This is the NetBoot initialization script —
normally only present on NetBoot client images or enterprise-managed machines.
Directly relevant to the NetBoot/LAN enrollment lockdown investigation.

**Tasks**:
- [ ] Dump contents: `cat /etc/rc.netboot`
- [ ] Check if NetBoot daemon is loaded: `sudo launchctl list | grep -i netboot`
- [ ] Check NetBoot preferences: `defaults read /Library/Preferences/com.apple.NetBoot 2>/dev/null`
- [ ] Check for NetBoot-related LaunchDaemons: `ls /System/Library/LaunchDaemons/ | grep -i netboot`
- [ ] Check boot image source: `nvram boot-device`, `nvram boot-args`
- [ ] Check if rc.netboot was recently modified: `stat /etc/rc.netboot`
- [ ] Check if NetBoot shadow file exists: `ls -la /var/netboot/ 2>/dev/null`
- [ ] Verify if NetBoot is active: `ifconfig | grep -B5 "en0"`, look for NetBoot DHCP options

---

## TODO 03: krb5.keytab Investigation
**Priority**: Critical (NEW)
**Related Quirks**: 11, 17

`/etc/krb5.keytab` exists. This file stores Kerberos principal keys for machine
authentication. It should NOT exist on a personal device with no enterprise or
Active Directory enrollment. Presence indicates the device has been (or is)
Kerberos-authenticated to a realm.

**Tasks**:
- [ ] List keytab principals: `klist -k /etc/krb5.keytab` (may need sudo)
- [ ] Check keytab modification time: `stat /etc/krb5.keytab`
- [ ] Check Kerberos configuration: `cat /etc/krb5.conf` (if exists), `cat /Library/Preferences/edu.mit.Kerberos 2>/dev/null`
- [ ] Check for active Kerberos tickets: `klist 2>/dev/null`
- [ ] Check AD binding state: `dsconfigad -show 2>/dev/null`
- [ ] Verify keytab permissions: `ls -la /etc/krb5.keytab`
- [ ] Cross-reference with Platform SSO (Quirk 17) — Kerberos keytab + Platform SSO =
      enterprise authentication infrastructure staged on personal device

---

## TODO 04: hosts.equiv Investigation
**Priority**: High (NEW)
**Related Quirks**: 16

`/etc/hosts.equiv` exists. This file defines trusted hosts for r-commands
(rlogin, rsh, rcp). On stock macOS it typically exists but is empty. If it
contains entries, it establishes trust relationships the user didn't configure.

**Tasks**:
- [ ] Dump contents: `cat /etc/hosts.equiv`
- [ ] Check modification time: `stat /etc/hosts.equiv`
- [ ] Cross-reference any hostnames against network scan (Quirk 15)
- [ ] Check if r-services are enabled: `sudo launchctl list | grep -E 'rlogind|rshd|rexecd'`
- [ ] Check if r-services LaunchDaemons exist: `ls /System/Library/LaunchDaemons/ | grep -E 'rlogin|rsh|rexec'`

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

/etc/krb5.keytab` exists. This file does NOT ship with stock macOS. It is only
created when a machine is bound to a Kerberos realm (Active Directory, OpenDirectory,
or enterprise identity provider). Its presence on a personal device purchased new
from Apple with a fresh Apple account and no iCloud services is anomalous regardless
of whether the file is empty or populated — the OS does not create this file speculatively.

**Tasks**:
- [ ] List keytab principals: `sudo klist -k /etc/krb5.keytab`
- [ ] Check keytab modification time: `stat /etc/krb5.keytab`
- [ ] Check Kerberos configuration: `cat /etc/krb5.conf 2>/dev/null; cat /Library/Preferences/edu.mit.Kerberos 2>/dev/null`
- [ ] Check for active Kerberos tickets: `klist 2>/dev/null`
- [ ] Check AD binding state: `dsconfigad -show 2>/dev/null`
- [ ] Check DirectoryService for Kerberos realm: `dscl . -read /Config/KerberosKDC 2>/dev/null`
- [ ] Verify keytab permissions and ownership: `ls -la /etc/krb5.keytab`
- [ ] Cross-reference with Platform SSO (Quirk 17) and doshapedclouds MDM artifacts (Quirk 11)
- [ ] Check if keytab was created during first-boot enrollment flow (Setup Assistant window)


**Priority**: High
**Related Quirks**: 01, 13

TCC database returns empty for Terminal.app Desktop access. No entry means no
prompt was ever generated or the entry was stripped.

**Tasks**:
- [ ] Dump full user TCC database: `sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access ORDER BY service"`
- [ ] Dump full system TCC database: `sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access ORDER BY service"`
- [ ] Check for MDM-enforced privacy restrictions: `profiles show -type configuration 2>/dev/null`
- [ ] Check for privacy profile payloads: `profiles show -type profile 2>/dev/null`
- [ ] Check if TCC database has been modified: `stat ~/Library/Application\ Support/com.apple.TCC/TCC.db`
- [ ] Check for TCC bypass via MDM profile: `profiles show -type baseband 2>/dev/null`

---

*This repository is a research artifact, not a how-to guide. Defensive mitigations are included throughout.*
