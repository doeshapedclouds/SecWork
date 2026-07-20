Near-Field Configuration Injection and Enrollment Lock-In: A Platform-Agnostic Threat Model
Document Type: Technical Research Framework
Classification: Public Research Documentation
Date: July 20, 2026
Revision: 1.0

Abstract

This document presents a platform-agnostic threat model for near-field configuration injection attacks that result in enrollment lock-in across modern operating systems. The research examines attack architectures where proximity-based vectors — particularly Bluetooth Low Energy (BLE) GATT injection — deliver configuration payloads during device setup phases or through post-boot channels. The resulting enrollment, once registered server-side via Device Enrollment Program (DEP) or equivalent infrastructure, persists across DFU restores, OS reinstallation, and user account changes.

Key findings include:

Attack success does not require traditional software vulnerabilities (zero-days)
Trust boundary assumptions between OS subsystem layers create cascading attack pathways
reCAPTCHA integration provides misdirection, bot-filtering, and trust laundering simultaneously
Encoding and MIME type confusion create additional delivery surface
Cache rotation and counter-forensic techniques obscure on-disk state from runtime state
Multiple post-boot vectors maintain attack viability beyond initial OOBE window
1. Executive Summary

1.1 Research Objective
This threat model explores configuration injection attack paths across modern operating systems, focusing on the intersection of proximity transport protocols, system daemon trust models, and enrollment infrastructure. The research addresses the question: how can configuration data arrive through untrusted sources yet be accepted by trusted system components without explicit user authorization?

1.2 Scope and Limitations
This document covers:

macOS, iOS, iPadOS (Apple ecosystem focus)
Android, Windows, Linux (comparative analysis)
BLE, NFC, UWB, Wi-Fi Direct, acoustic, and optical proximity vectors
Server-side enrollment persistence mechanisms
Counter-forensic evasion techniques
The research excludes:

Active exploitation guidance (defensive focus)
Specific CVE references (architecture over implementation)
Commercial product vulnerability disclosure
2. Platform-Agnostic Attack Architecture

2.1 Seven-Layer Model
The attack architecture comprises seven layers, each dependent on the layer below it. The vulnerability resides not in any single component but in the trust assumptions at each inter-layer boundary.

┌──────────────────────────────────────────────────────────┐
│  LAYER 6: ENROLLMENT BINDING                             │
│  Server-side activation record creation                  │
│  Hardware identity anchoring (ECID, serial, TPM)         │
│  Persistence mechanisms (NVRAM, cryptex, firmware)       │
└─────────────────────────┬────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────┐
│  LAYER 5: NETWORK INTERPOSITION                          │
│  DNS resolution hijacking                                │
│  Certificate pinning circumvention                       │
│  Time synchronization manipulation                       │
│  DHCP option injection, captive portal simulation        │
└─────────────────────────┬────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────┐
│  LAYER 4: SERVICE ACTIVATION                             │
│  Daemon restart triggers, watchdog behavior              │
│  Dynamic library loading (dyld, ld.so, linker cache)     │
│  Kernel module/driver hotplug                            │
│  Event-driven activation (filewatch, D-Bus, XPC)         │
└─────────────────────────┬────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────┐
│  LAYER 3: CONFIGURATION CONSUMPTION                      │
│  Preference daemon processing (cfprefsd, gsettings)      │
│  Profile installer execution                             │
│  Policy merge conflicts                                  │
│  Validation bypass in schema definition                  │
└─────────────────────────┬────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────┐
│  LAYER 2.5: VALIDATION GAP                               │
│  Quarantine flag bypass                                  │
│  Signature verification gaps                             │
│  Chain-of-trust breaks between system services           │
│  Entitlement confusion (accessibility vs system)         │
└─────────────────────────┬────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────┐
│  LAYER 2: DAEMON RELAY                                   │
│  Privilege escalation at IPC boundary                    │
│  Trust inheritance (sender identity vs data provenance)  │
│  Race conditions during concurrent connection handling   │
│  Buffer overflow in protocol parsers                     │
└─────────────────────────┬────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────┐
│  LAYER 1: PROTOCOL PARSING                               │
│  Advertisement decoding, GATT characteristic parsing     │
│  Packet fragmentation handling, state machine transitions│
│  Vendor extension interpretation, error recovery paths   │
│  Timing-based side channels, clock drift exploitation    │
└─────────────────────────┬────────────────────────────────┘
                          │
┌─────────────────────────▼────────────────────────────────┐
│  LAYER 0: PHYSICAL TRANSPORT                             │
│  BLE, NFC, UWB, Wi-Fi Direct, IR, RF                    │
│  Acoustic (ultrasonic), optical, magnetic coupling       │
│  Power line injection, ground loop coupling              │
└──────────────────────────────────────────────────────────┘

2.2 Core Vulnerability Class
The shared vulnerability across all modern operating systems at each layer boundary is: IPC and configuration intake systems trust the sender's identity without validating the payload's provenance.

Platform	Transport Daemon	Config Daemon	IPC Mechanism
macOS	bluetoothd	cfprefsd	XPC
Windows	bthserv	Registry/Group Policy	COM/RPC
Linux	bluetoothd (BlueZ)	systemd, dconf	D-Bus
Android	BluetoothManagerService	SettingsProvider	Binder
ChromeOS	Bluetooth stack	System services	D-Bus variant
A configuration blob arriving via XPC from bluetoothd is trusted because bluetoothd is a system process — but bluetoothd was merely a relay for untrusted proximity data that was never independently validated.

3. Layer-by-Layer Analysis

3.1 Layer 0: Physical Transport
3.1.1 Attack-Relevant Properties
Proximity transports operate outside traditional network security perimeters. Firewalls, intrusion detection systems, and network segmentation do not apply to BLE, NFC, UWB, or Wi-Fi Direct.

Key properties enabling attack:

Unsolicited data reception: Most BLE stacks parse incoming advertising and GATT data without requiring prior pairing
State machine complexity: BLE has 60+ states; each transition represents a parsing boundary
Vendor extension space: Manufacturers add proprietary GATT characteristics with limited auditing
3.1.2 Protocol Attack Surface Matrix
Protocol	Trust Assumption	Parsing Complexity	Vendor Extensions	Attack Feasibility
BLE GATT	Paired = trusted	High (60+ states)	Extensive	HIGH
BLE Advertising	No pairing required	Medium	Moderate	HIGH
NFC Type 4	Physical proximity = trusted	Low	Minimal	MEDIUM
UWB ranging	Precise location = trusted	High	Emerging	LOW-MEDIUM
Wi-Fi Direct	PBC bypass	High	Extensive	HIGH
Infrared (IrDA)	Line-of-sight = trusted	Medium	None	LOW
Acoustic	No trust model exists	Variable	None	LOW-MEDIUM
Optical (Li-Fi)	Light transmission = trusted	Medium	None	LOW
Magnetic (MagSafe)	Wired = secure	Low	Proprietary	MEDIUM
3.2 Layer 1: Protocol Parsing
3.2.1 Braille Display as GATT Vector
Refreshable braille displays possess unique properties as attack vehicles:

Property	Attack Implication
Proprietary GATT services beyond HOGP	Less audited vendor-specific characteristic UUIDs
Firmware update over BLE	Potential unsigned or weakly-verified update mechanism
Tactile button input encoded in GATT writes	User input can be spoofed or injected
Persistent storage on device	Malicious configuration stored on peripheral
Assistive device trust status	Lower suspicion from users and OS validation layers
3.2.2 VoiceOver Utility Default Configuration
VoiceOver Utility ships with default configuration: "Allow input from: Primary braille display"

This is pre-configured on all macOS installations. Every macOS device accepts GATT input from any device that registers as the "primary braille display" without requiring explicit pairing confirmation. The accessibility trust boundary is the attack entry point, not a configuration flaw specific to a target device.

3.3 Layer 2: Daemon Relay
3.3.1 macOS-Specific Flow
bluetoothd → IOBluetoothFamily (kernel dext) →
brailleScreenInput (BSD daemon) →
Accessibility Services / VoiceOver → cfprefsd

The brailleScreenInput daemon runs with accessibility permissions and communicates configuration to preference domains. The daemon assumes braille GATT data is legitimate. When the display sends a configuration change via GATT, BSD propagates that to cfprefsd, which writes to the preference store. No signature verification is performed on the GATT payload itself.

3.3.2 RunningBoard Interaction
runningboardd manages process lifecycle and resource attribution. Observed runningboardd ↔ bluetoothd interactions indicate Bluetooth daemon events influencing process management decisions. This represents the Layer 0 → Layer 1 → Layer 2 handoff: proximity data influencing process management.

3.4 Layer 2.5: Validation Gap
3.4.1 cfprefsd Quarantine Bypass
cfprefsd runs with system privileges and writes preference files on behalf of requesting processes. When requests originate from a system process chain (bluetoothd → brailleScreenInput → cfprefsd), the resulting preference files inherit the trust of the writing process, not the origin of the data. No quarantine flags are applied because the data arrived through a trusted system daemon chain.

Result: Preference files appear without proper provenance tracking — quarantine flags exist specifically to prevent this class of attack, and their absence is directly explained by the trusted-process-chain relay model.

3.4.2 MDM-Managed Preferences
MDM-delivered managed preferences bypass quarantine by design — managed preferences are treated as enterprise-origin and are not subject to quarantine flags. If silent MDM enrollment occurred, all preferences pushed by the MDM arrive without quarantine, matching observed anomaly patterns.

3.5 Layer 3: Configuration Consumption
Configuration profiles use schema definitions (XML, plist, JSON). Schema validation can be bypassed through:

Technique	Mechanism	Example
Schema extension	Add unrecognized fields processed anyway	<extra><hidden>payload</hidden></extra>
Encoding trickery	Base64, UTF-8 variants, Unicode normalization	Encoded payloads in attributes
Namespace collision	Two schemas define same element differently	XSD namespace conflict exploitation
Comment injection	Payload hidden in comments parsed	<!-- <key>MDMURL</key> -->
Entity expansion	XML entities expand to large payloads	Billion laughs style attacks
Default value abuse	Unspecified fields take dangerous defaults	Empty strings = bypass checks
3.6 Layer 4: Service Activation
3.6.1 CUPS as Downstream Vector
CUPS print spooler activates as downstream service from configuration changes. The /var/spool/cups/ directory is examined during forensic analysis because:

Print jobs queue here for processing
CUPS daemon processes files from this location
Malicious PPD (PostScript Printer Description) installation possible
PPD can contain arbitrary PostScript code (Turing-complete)
3.6.2 AppleSunriseWLAN dext Activity
WLAN subsystem activation alongside Bluetooth suggests cascading service activation — the composition attack pattern. WLAN provides secondary transport channel once BLE completes initial delivery.

3.7 Layer 5: Network Interposition
Network behavior becomes malleable after services activate and configuration is in place.

Mechanisms:

Time manipulation (SNTP/NTP): Shift clock to make expired certificates appear valid
DNS poisoning: Redirect software update servers, enrollment endpoints
DHCP manipulation: Options 43/60 point devices to PXE/NetBoot servers
Captive portal injection: Force HTTP redirects through local web service
3.8 Layer 6: Enrollment Binding
Bound enrollment ties device management to hardware identifiers (serial number, hardware UUID, ECID, TPM attestation) that persist across OS reinstalls.

Persistence Surfaces Surviving DFU:

Surface	Why It Survives
Activation Record	Stored at activation servers, keyed by hardware serial/ECID
NVRAM (selective variables)	Certain NVRAM partitions not wiped by DFU
RecoveryOS	Separate partition with its own OS; DFU may not fully replace
SEP-anchored data	Secure Enclave storage untouched by DFU
DEP/ABM record	Lives entirely on servers, not the device
4. The Language Chooser Timing Attack

4.1 Boot Sequence Timeline
Phase	Action	Security State
T0	BootROM executes	No protections
T1	iBoot selects kernel, reads boot args	Limited protection
T2	Kernel initializes I/O Kit, loads dexts	Partial protection
T3	launchd starts system daemons	Bluetooth/cfprefsd active
T4	Setup Assistant launches	ATTACK WINDOW OPENS
T5	User selects WiFi	Window remains open
T6	Network connects	Window closes
T7	Setup completes	Full protections active
Critical Window: Between T3 and T7, Bluetooth is active, preferences system is running, no network baseline exists, and system is in permissive trust state expecting provisioning.

4.2 Trust State Comparison
Protection	Normal Mode	Setup Assistant / OOBE
Profile installation	Requires user approval	Silent (expected for ADE)
Config profile verification	Strict	Relaxed (expects provisioning)
TCC prompts	Enforced	Deferred (no user session)
SIP enforcement	Fully active	Active, but config writes via system daemons bypass
Network trust	Certificate pinning enforced	No baseline established
Quarantine flags	Applied to untrusted sources	Bypassed for system daemon chain writes
5. Runtime Persistence and Counter-Forensics

5.1 Disk-vs-Runtime Gap
On-disk inspection does not reflect the running system state. The attack transitions from initial delivery into runtime persistence where:

cfprefsd memory cache is populated from non-disk source at boot time
On-disk preference files are shadows or exhaust products of cache rotation
Running system consumes poisoned cache, not on-disk files
5.2 Cache Rotation Cycle
Normal cfprefsd Operation:

Process reads preference → cfprefsd checks memory cache
If not cached → reads plist from disk
Returns value to process
Process writes preference → cfprefsd writes to memory cache
cfprefsd flushes to disk periodically
Subverted Operation:

At early boot (T3), cfprefsd cache populated from non-disk source (NVRAM blob, cryptex, boot-time injection via dext)
Cache contains: MDM config, network config, accessibility prefs
On-disk plists written as shadows of real config → these get quarantine flags
Cache rotation flushes on-disk plists periodically → removes or quarantines them
Memory cache persists real configuration
On-disk inspection reveals stale/rotated/quarantined artifacts
5.3 Non-Disk Persistence Sources
Source	Mechanism	Detection Method
NVRAM blob	Binary configuration payload in NVRAM variable, loaded at boot	nvram -xp full XML dump
Cryptex	Sealed, independently-updated OS component	mount | grep cryptex
APFS snapshot overlay	Configuration injected into snapshot mount process	bless --getSnapshot, diskutil apfs list
Boot token / LocalPolicy	Boot process uses boot token influencing load	nvram -p | grep -i 'boot|policy'
In-memory launchd overrides	Services loaded via launchctl without on-disk plists	launchctl print system/ vs disk inventory
6. reCAPTCHA as Attack Infrastructure

6.1 Architectural Significance
reCAPTCHA occupies a unique position in the modern web trust landscape:

Universally recognized — users encounter it daily
Google-branded — inherits trust reputation implicitly
JavaScript-executing — runs arbitrary code in browser context
Multi-step interactive — engages attention for 3-15 seconds
Token-generating — produces cryptographic tokens for interception, replay, or repurposing
6.2 Trust Psychology
Users exhibit narrowed cognitive focus during CAPTCHA solving:

Task-oriented attention dominates
Environmental awareness drops
Goal completion prioritized over security evaluation
Trust assumptions: "Google vouches for this site," "If reCAPTCHA is here, this is legitimate"
6.3 Parallel Action Window
While user focuses on solving CAPTCHA (3-15 seconds), background JavaScript executes:

Profile download via hidden fetch()
Blob URL creation for downloaded profile
Hidden iframe pointing to blob URL
Navigation to profile URL via meta refresh or location
Service worker registration for future persistence
Timeline:

T+0s: Page loads, reCAPTCHA renders
T+0.5s: Background JS begins profile download
T+1s: User clicks "I'm not a robot"
T+3-10s: User solves image challenge (attention fully occupied)
T+10s: reCAPTCHA token generated
T+11s: Form submission triggers
T+13s: Profile installation prompt appears (user associates with WiFi setup)
T+14s: User clicks "Install" (momentum from CAPTCHA completion)
6.4 Selective Targeting via Risk Score
reCAPTCHA v3 returns score 0.0-1.0, providing bot-detection:

Score 0.9-1.0: Human user → proceed with full attack chain
Score 0.5-0.8: Uncertain → stage fragments, maintain cover
Score 0.0-0.4: Bot/scanner → serve benign page, leave no trace
Critical Property: Security researchers using automated tools receive low score, see benign page, and move on. Only genuine human users trigger the enrollment flow.

7. Encoding and MIME Type Attack Surface

7.1 Configuration Profile MIME Types
macOS / iOS:

.mobileconfig: application/x-apple-aspen-config
.mobileconfig (signed): application/pkcs7-mime
.cer / .crt: application/x-x509-ca-cert
.p12 / .pfx: application/x-pkcs12
Android:

Enrollment: intent:// scheme for DPM (Device Policy Manager)
APK: application/vnd.android.package-archive
Windows:

.ppkg (provisioning packages): application/octet-stream
MDM enrollment: ms-enrollment: URI scheme
Certificate files: application/x-x509-ca-cert
7.2 MIME Type Confusion Attacks
Vector	Mechanism	Platform Behavior
Sniffing Override	Content-Type: text/html, actual content is .mobileconfig XML	Browser renders as HTML but Safari may detect profile structure
Dual Content-Type	Multiple Content-Type headers (first vs last wins?)	Parser ambiguity varies by implementation
Content-Disposition	Content-Type: application/octet-stream, Content-Disposition: filename=config.mobileconfig	Extension may override MIME type
Application/XML	.mobileconfig IS valid XML, Content-Type: application/xml	Browser renders XML tree, profile daemon may still detect
Multipart	HTTP 206 Partial Content or multipart/mixed	Browser processes both parts independently
7.3 Delivery Mechanisms
Base64 Data URI:

data:application/x-apple-aspen-config;base64,<BASE64_DATA>

Payload embedded in URL string, no separate HTTP request, network trace only shows captive portal page load.

Blob URL:

const blob = new Blob([profileXML], {type: 'application/x-apple-aspen-config'});
const url = URL.createObjectURL(blob);
window.location.href = url; // profile handler fires

Payload exists only in browser memory, no disk file until handler processes it, MIME type set by JavaScript not server response.

Fragment Assembly Across Encounters:

Visit 1 (low score): Fragment A stored in localStorage
Visit 2 (low score): Fragment B stored
Visit 3 (low score): Fragment C stored
Visit 4 (high score): Service worker reads fragments, assembles profile in memory, navigates to blob URL
Network Forensics: Four different networks, four different pages, no single request contained identifiable profile data, assembly happened client-side in browser memory.

7.4 Steganographic Encoding
Image-Embedded Payloads: PNG/JPEG images carry payload in pixel LSBs (least significant bits). 1920×1080 image = 6.2 million pixels × 3 bits = 2.3MB capacity. A 100KB profile needs ~267K pixels — fits in 600×450 image.

Extraction: Canvas API reads pixel data, extracts LSBs from RGB channels, converts bit string to bytes, base64 decodes, creates blob URL.

Enhanced: reCAPTCHA challenge images serve as carriers — user interacts with images building cover, Canvas API extracts payload from tile images while user solves visual challenge.

8. Extended Attack Vectors

8.1 HTTPD & Mail Subsystem Delivery
Local HTTPD Exposure: If device has local web server running on localhost:8080, 8000, 5000, etc., captive portal JavaScript can POST payload via cross-origin fetch (if CORS allows). Payload lands in local web server's storage, later activated via app with network access reading from local server.

Email Attachment: User completes CAPTCHA, redirected to "Thank you" page. Page shows "Your WiFi receipt has been emailed." User enters email, receives attachment: "receipt.pdf" (actually .mobileconfig). User opens email later, clicks attachment, profile installs without context of origin.

Mail Account Credential Harvest: Captive portal asks "Enter email to configure WiFi." Credentials sent to attacker mail server, attacker configures MDM profile to push to mail account, profile syncs across all devices using that account.

8.2 Contact Photo Steganography
Attack Premise: Contact photo is trusted image, users sync contacts regularly, photos rarely inspected, image files carry steganographic data imperceptibly.

Delivery: Attacker sends vCard (.vcf) with embedded contact photo ("Save this contact to receive WiFi access"). User saves contact, photo imported into Contacts app, syncs to iCloud/Google Contacts, propagates to all linked devices.

Extraction: Compromised app (with Contacts permission) reads contact photos, extracts steganographic payload from LSBs, decodes base64 → configuration profile fragments, assembles profile, installs via entitlements.

Stego Methods:

JPEG DCT coefficient modification (~10KB per 1000×1000 photo)
PNG chunk embedding (tEXt, iTXt, zTXt — 100KB+ capacity)
Color palette manipulation (indexed images)
8.3 Ultrasound Advertising Channel
Industry Background: Retail stores emit ultrasonic beacons (18-24kHz) for targeted ads. Companies: Gimbal, Shopkick, Adcolony. Same technology weaponized for payload delivery.

Modulation: Frequency-shift keying (FSK), phase-shift keying (PSK), on-off keying (OOK). Data rate: 100-1000 bps achievable. Payload: 10-50KB in 1-2 minutes.

Reception: Device microphone captures ultrasound, compromised app (with mic permission) processes, demodulates, extracts payload, assembly complete → profile installation.

App Permissions Required: Microphone (common for music players, fitness apps), Background audio processing, Location (often paired with beacons).

Correlation with LPMicInjection: LPMicInjection could be receiving end of ultrasound-based attack — injected audio handler listens for ultrasonic commands, acts as silent receiver for beacon-delivered payloads, explains adaptive behavior scaling with activity.

8.4 Polyglot File Fundamentals
A polyglot file is one file simultaneously valid in multiple formats. This creates ambiguity in how systems interpret the file.

Types:

Polyglot Type	Format A	Format B	Attack Application
HTML/XML	.html	.mobileconfig	Renders as benign page, installs as profile
PNG/ZIP	.png	.zip	Image displays normally, archive contains payload
GIF/JS	.gif	.js	Animated image shows content, code executes
PDF/DER	.pdf	.cer	Document appears legitimate, certificate embedded
MP4/XML	.mp4	.xml	Video plays normally, metadata contains config
JPEG/PE	.jpg	.exe	Image displays, executable embedded in appended data
Construction Principle:

Header Overlap: Some bytes satisfy both signatures in different contexts
Ignored Data: HTML ignores content after </html>, XML ignores comments, executables ignore trailing bytes
Comment Embedding: GIF comments hold arbitrary data (GIF89a <COMMENT> block)
Metadata Fields: JPEG EXIF/IPTC/XMP metadata can store arbitrary base64-encoded data
HTML/.mobileconfig Polyglot Example:

<!DOCTYPE html>
<html><!--
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>PayloadIdentifier</key><string>com.attacker.profile</string>
    <!-- Malicious MDM payload here -->
</dict></plist>
--></head><body><h1>Your WiFi Receipt</h1></body></html>

Browser: renders HTML
iOS/macOS Profile Handler: installs profile (reads XML inside comments)

9. Sleep/Wake and Screen Lock Trust Transitions

9.1 Sleep/Wake Injection Windows
During Sleep:

Network interfaces power down (may keep association)
Bluetooth stays active (for Find My, wake triggers)
USB/Thunderbolt stay powered (for wake)
Memory preserved (RAM powered)
During Wake:

Network re-authentication occurs
Bluetooth reconnection attempts fire
Power Nap / background tasks execute (SYSTEM privileges)
Notification sync occurs
Certificate validation re-runs
Attack windows:

Bluetooth reconnection race: Previously paired device reconnects during wake, service handlers process GATT data before full security state restored
Network re-authentication gap: First DNS query goes to configured resolver (if poisoned, poison persists), captive portal may re-trigger
Power Nap execution: Runs during sleep on battery with system privileges, executes poisoned config while user sleeps
Display wake timing: 1-3 second window between wake trigger and display showing content, service activations fire before user sees screen
9.2 Screen Lock/Unlock Trust State
Locked state:

TCC enforcement strengthened
Keychain locked (sensitive items encrypted)
Background tasks may continue
Lock screen widgets execute (iOS)
Unlock transition:

Biometric/password authentication
Keychain unlocked → certificate store accessible
TCC permissions re-evaluated
All user-level services resume full function
Attack surface: Lock screen widgets fetch network content while device locked (if DNS poisoned, widgets contact attacker server while screen locked). Response data stored in widget storage, on unlock read by other processes with shared container access.

10. NTP and Timezone as Trust Weapons

10.1 NTP Manipulation Cascade
NTP is foundational because every trust mechanism depends on accurate time:

Certificate validation:

Not Before / Not After fields checked against system clock
Clock shifted forward: Not-yet-valid attacker cert appears valid
Clock shifted backward: Expired attacker cert appears valid
Code signing:

Notarization tickets have timestamps
Revoked signing cert appears valid if clock shifted
Log forensics:

All log entries timestamped
If clock skewed, attack timeline obscured
Correlation between logs from different systems fails
Gradual time poisoning:

Shift clock by 30 seconds per day
After 10 days: 5 minutes skew (Kerberos threshold)
After 30 days: 15 minutes skew (cert validation issues)
User never notices (clock appears to work fine)
Only cross-referencing with external time source reveals skew
10.2 SNTP vs. NTP Distinction
SNTP (Simple Network Time Protocol) has NO AUTHENTICATION by default. Any server claiming to be time source is trusted. If DNS for time.apple.com is poisoned, device contacts attacker's time server, receives skewed time, adjusts system clock, all time-dependent trust mechanisms compromised.

10.3 Timezone Manipulation
Timezone is offset applied to UTC for display and calculations:

Scheduled task timing: Many tasks fire at local midnight, timezone change shifts "midnight" by hours
Logging confusion: Logs display in local timezone, investigator sees apparent time travel
Geolocation inference disruption: Geolocation-based security policies may be bypassed
App behavior alteration: News/financial/travel apps show different content by timezone
11. Staging Directory Topology

11.1 macOS Staging Surface Map
Directory	Purpose	Attack Relevance
/Library/Updates/	Software update packages	Attacker injects, OS processes as update
/private/var/db/ConfigurationProfiles/	Pending profiles, installed registry	Poisoned profiles install silently
/private/var/db/mds/	Metadata server certificate cache	Certificates cached may be trusted
/Library/Keychains/	System trust store	Root CA planted here trusted system-wide
/var/spool/cups/	Print jobs queued	CUPS processes files, malicious PPD code execution
/private/preboot/	Boot configuration, caches	Loaded before main OS, before SIP enforcement
/private/var/tmp/	Persistent temp directory	Survives reboot, less restrictive
/private/tmp/	Temporary files	World-writable, cleared at reboot
11.2 Cross-Platform Equivalents
Windows:

C:\Windows\SoftwareDistribution\Download\ — Update staging
C:\Windows\System32\GroupPolicy\Machine\ — Group Policy templates
C:\ProgramData\Microsoft\Crypto\ — Certificate store staging
Linux:

/var/cache/apt/archives/ — Package staging
/etc/dpkg/dpkg.cfg.d/ — Package manager config
/usr/local/share/ca-certificates/ — Certificate trust staging
Android:

/data/data/<package>/cache/ — Per-app cache
/data/misc/keystore/ — Key store staging
/data/system/device_policies.xml — Device admin policies
12. Zero-to-Cooked Progression Models

12.1 Scenario 1: Brand New Device
Day	Action	Compromise Status
0	User purchases MacBook (sealed)	Clean
0	First boot (home)	BLE injection delivers DNS+NTP poison
0	WiFi setup	Captive portal → reCAPTCHA → profile install
0	Account creation	Enrollment already happened, irrelevant
7	Software update	MDM re-enrolls on reboot
14	User investigates → DFU restore	Re-enrollment triggers on reactivation
14	Post-DFU	COOKED — DFU doesn't help
12.2 Scenario 2: Used Device Purchase
Pre-purchase: Device enrolled in MDM (attacker's or compromised previous owner's MDM). Seller erases device (erasure doesn't remove DEP enrollment, NVRAM variables, RecoveryOS).

First boot: Activation check returns DEP enrollment, profile installs silently during OOBE. Additional risk: pairing records persist in NVRAM, attacker's BLE device auto-reconnects on first boot.

Time-to-cooked: Instant (already cooked before purchase).

12.3 Scenario 3: Long-Owned Device (Gradual)
Month	Action	Status
0	Coffee shop WiFi → captive portal → reCAPTCHA MEDIUM score	Fragments staged, device fingerprint collected
1	Different coffee shop (same provider) → reCAPTCHA HIGH score	Profile install → enrollment triggered
1+	Alternate path: App update (compromised SDK)	App reads staged fragments, installs profile via entitlements
2+	User discovers quarantine artifacts → DFU	Re-enrollment, still cooked
Time-to-cooked: 1-2 months depending on vector combination.

12.4 Scenario 4: Corporate Device (Slow Burn)
Month	Action	Status
0	Legitimate corporate MDM enrollment	Supervised, managed
3	Hotel WiFi captive portal → staging	Fragments planted
4	Conference WiFi → enrollment	TWO MDM profiles active
4+	Split-tunnel VPN → exfiltration	Personal traffic through attacker VPN
6	Corporate incident response → DFU	Re-enrollment, incident can't fix
Time-to-cooked: 6+ months with slow exfiltration.

13. Stealth Measures — End-to-End

13.1 Stealth Stack
Layer	Techniques
Network	reCAPTCHA scoring, fragment assembly, steganography, DoH laundry, TLS with planted CA, low-and-slow exfiltration
Filesystem	Cache rotation, managed preferences bypass quarantine, on-disk state ≠ runtime, localStorage staging, Spotlight thumbnail cache stego
Process	In-memory launchd overrides, dyld interposition, MDM agent as system process, compromised app uses own entitlements, service worker in browser
Logging	NTP skew corrupts timeline, timezone breaks alignment, fake log injection, rotation pruning, managed preferences not logged
Behavioral	Gradual time skew (30 sec/day), slow enrollment, adaptive timing, mimic legitimate patterns, notification fatigue
Forensic	Cache rotation, quarantine flag manipulation, timestamp manipulation, journal pruning, Spotlight index poisoning, memory-only execution
13.2 Detection Evasion Matrix
Detection Method	Evasion Technique
Network IDS	reCAPTCHA scoring, fragment assembly, stego, DoH
File integrity monitor	Cache rotation, memory-only exec, preboot/cryptex staging
Process monitoring	In-memory launchd, dyld interpose, legitimate process mimicry
Log analysis	NTP skew, timezone change, fake injection, rotation pruning
Behavioral analysis	Gradual changes, adaptive timing, mimic patterns
Memory forensics	Blob URL construction in JS heap, fragmented storage
Certificate pinning	Root CA planted, time skew for expired cert bypass
DNS monitoring	DoH to attacker resolver, low-and-slow tunneling
14. Everyday Actions That Advance Compromise

14.1 Routine Behavior Kill Chain
Action	Compromise Advancement
Connecting to WiFi	Triggers captive portal, may hit attacker portal, DNS may already be poisoned
Opening Safari/browser	Handoff brings attacker's URL from compromised device, bookmarks modified by MDM
Installing app update	App may include compromised SDK, now reads staged payloads, activates profile
Installing OS update	Reboot into recovery mode, reduced security posture, MDM re-enrollment on reboot
Closing laptop lid	BLE reconnection fires on wake, Power Nap executes system-level tasks
Saving a contact	Contact photo may carry stego payload, syncs to all devices
Checking email	Email contains disguised profile attachment, link to captive portal
Walking through retail store	Ultrasound beacon delivers payload fragment, BLE advertisement triggers Handoff
Plugging in USB-C dock	Dock presents as HID/network/display, Thunderbolt DMA access (pre-SIP)
Rebooting device	NVRAM re-read, LaunchDaemons reload, cfprefds cache re-seeds, MDM check-in fires
Doing nothing (idle)	Power Nap runs, MDM polling, software update silent check hits poisoned DNS
15. Cross-Platform Attack Tree

ROOT NODE: DEVICE COMPROMISE OBJECTIVE
│
├── BRANCH 1: FIRST BOOT / OOBE PATH
│   ├── Layer 0: BLE Advertising (braille display, NFC tag, Wi-Fi Direct)
│   ├── Layer 1: Stack-to-Daemon Handoff (bluetoothd → cfprefsd)
│   ├── Layer 2: Config Intake (quarantine bypass, memory cache seeding)
│   ├── Layer 3: Service Activation (DNS proxy, CUPS, WLAN dext)
│   ├── Layer 4: Network Redirect (captive portal, DNS poisoning)
│   └── Layer 5: Enrollment Lock-In (DEP/ABM registration, server-side persistence)
│
├── BRANCH 2: POST-BOOT / ONGOING PATH
│   ├── Pre-existing Trust Exploits (paired devices, compromised apps, service workers)
│   ├── Captive Portal Path (reCAPTCHA engagement, encoding mechanisms, MIME confusion)
│   ├── Audio Channel Path (ultrasound beacons, contact photo stego, audio embedding)
│   ├── HTTPD/Mail Path (local web server, email attachments, SMTP relay)
│   └── User Interaction Path (notifications, email attachments, web form submissions)
│
├── BRANCH 3: SUPPLY CHAIN PATH
│   ├── Manufacturing/Factory (pre-flashed firmware, DEP registered)
│   ├── Retail/Distribution (unpacked, paired, resealed)
│   └── Software Supply Chain (SDK compromise, developer account takeover, CI/CD injection)
│
└── BRANCH 4: USER INTERACTION PATH
    ├── Notification Click (Apple Tips, push notifications, email notifications)
    ├── Email Attachment ("receipt.pdf" = .mobileconfig, certificate files)
    └── Web Form Submission ("Configure WiFi" email entry, business email setup)

Common Final Node (All Branches): Enrollment Lock-In

Server-side DEP/ABM registration
Hardware identity bound
MDM profile active with enforcement
Counter-forensics deployed (cache rotation, quarantine suppression)
Persistence: Survives DFU, OS reinstall, account change, network change
16. Defensive Recommendations

16.1 Immediate Mitigations
Air-gap during OOBE: Do not connect to any network during Setup Assistant until after language selection. Complete setup offline and verify configuration before first network connection.
Disable Bluetooth before first boot: Do not power on in environment with unknown BLE devices nearby.
Verify enrollment before use: Check profiles show -type enrollment and system_profiler SPConfigurationProfileDataType for unexpected supervision after setup.
NVRAM verification: After first boot, dump NVRAM and compare against known-good baseline.
16.2 Architectural Hardening
Layer	Recommendation	Implementation Effort
Notification	Require explicit consent for profile installs from any source	Medium (OS change)
Pairing	Require user confirmation for all new peripheral connections	Low (enable by default)
Config Validation	Sign all configuration profiles; reject unsigned profiles	High (ecosystem-wide)
OOBE	Disable automatic network connectivity during first boot until user confirms	Medium (UI change)
Cache	Log cfprefsd cache seeds; flag non-disk origins for review	Medium (forensic tooling)
Firmware	Require cryptographic verification of peripheral firmware updates	High (vendor cooperation)
NVRAM	Add integrity verification for boot-critical NVRAM variables	Medium (secure boot extension)
16.3 Most Impactful Single Change
Prevent captive portal browser context from triggering profile installation. The captive portal browser should be sandboxed from .mobileconfig URL scheme handling. Profile installation should require explicit user navigation to Settings/System Preferences, not be triggerable from a web page that the OS forced the user to open.

17. Open Research Questions

17.1 Critical Unknowns
What percentage of commercial devices ship with default "trust all peripherals" configurations?
Can proximity-based injection survive full hardware replacement (motherboard swap)?
Do firmware-level protections (Secure Boot, measured boot) prevent configuration injection?
How effective is air-gapping as defense when devices have wireless peripherals?
What is the minimum viable proximity duration for successful injection?
17.2 Encoding and MIME Type Research Priorities
Does macOS captive portal WebKit honor blob: URLs with application/x-apple-aspen-config MIME type?
Does Content-Disposition override Content-Type in captive portal contexts?
Can polyglot XML/HTML files trigger profile installation while rendering as web page?
What is maximum localStorage/IndexedDB capacity in captive portal WebKit?
Do service workers registered in captive portal context persist after network change?
Can Canvas API extraction of steganographic payloads be detected by browser security features?
17.3 Supply Chain Research Priorities
Which common SDKs have device management or certificate management capabilities?
Do App Store review processes detect staged payload activation patterns?
Can MDM-related entitlements be abused by non-enterprise apps?
18. Conclusion

This research presents a threat model for near-field enrollment lock-in supported by forensic evidence from active investigations. The architecture describes a configuration injection mechanism that:

Exploits default trust configurations (braille display auto-accept) in accessibility subsystems
Leverages OOBE/Language Chooser timing window to poison network configuration before trust baseline establishment
Routes device activation through attacker-controlled infrastructure
Registers enrollment server-side, bound to hardware identity
Persists across DFU restores via server-side activation records
Maintains stealth through cache rotation and counter-forensic measures
Key Finding: The attack does not require a traditional software vulnerability. It exploits the trust chain between OS subsystem layers — specifically, the assumption that data arriving through a system daemon has been validated by the originating layer. The vulnerability is architectural, not implementation-specific.

Implications: Server-side persistence (enrollment record, activation record, device fingerprint) means the only truly durable components are on the remote infrastructure. Local artifacts are delivery mechanisms that can be sacrificed. The attack's durability comes from server-side persistence, not local persistence.

Recommended Priority: Blocking captive portal browsers from triggering profile installation eliminates the highest-probability attack path while requiring minimal user behavior change.

References

Apple Device Enrollment Program (DEP) / Apple Business Manager (ABM) documentation
Bluetooth Core Specification v5.3 (GATT Profile)
RFC 1305 (NTP), RFC 5905 (NTPv4)
Common Platform Enumeration (CPE) for OS subsystems
Forensic analysis tools: fs_usage, dtrace, lecoview, vmmap
reCAPTCHA Enterprise API documentation
OAuth 2.0, OpenID Connect specifications
Apple Push Notification Service (APNs) documentation

