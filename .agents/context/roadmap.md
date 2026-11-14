# SOTA Roadmap & Enhancement Checklist

## Completed Milestones (v1.1.0)

- [x] **4-Layer Zero False-Positive Forensic Engine (`ForensicScanner`)**:
  - [x] Code signature authority chain & notarization verification (`codesign -dvvv`, `--verify`).
  - [x] Framework vs. main binary signature hijack detection (`Developer ID` vs stripped ad-hoc/unsigned).
  - [x] Mach-O `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB` injection analysis (`otool -L`).
  - [x] Objective-C runtime swizzling, `mach_vm_*` memory patching, and `_dyld_*` ASLR slide symbol categorization (`nm -u`, `strings`).
- [x] **Prominent Refresh Workflow (`⌘R`)**:
  - [x] Header toolbar Refresh button (`Yenile` / `Refresh` / `Reîmprospătează`).
  - [x] Verdict banner quick-refresh button.
  - [x] Menu bar (`File` & `Audit` menus) and customizable keyboard shortcut (`⌘R`).
- [x] **Sibling App Ecosystem Parity (`Arhivar` / `Redactor` Standard)**:
  - [x] 1:1 exact trilingual localization (`tr`, `en`, `ro`) with dedicated `.lproj` files and restart alert (`restartWarningTitle`, `restartMenuBarNotice`).
  - [x] 4-tab `SettingsView` (General, Scan, Shortcuts, Engine & Updates).
  - [x] `AboutView` + read-only `LicenseViewerSheet` (`GPL-3.0-only` & `THIRD_PARTY_NOTICES.md`).
  - [x] Console-style `LogView` (`⌥⌘L`) backed by persistent `AppLog` (`~/Library/Logs/Verificator/Verificator.log`).
  - [x] GitHub Releases update checker (`AppUpdateChecker`, `UpdateSignature` Ed25519, `UpdateChecksums` SHA-256).
  - [x] Packaging & verification scripts (`Scripts/make_icon.swift`, `build_app.sh`, `verify_bundle.sh`, `package.sh`, `release.sh`, `Paketle.command`, `Yayimla.command`).
- [x] **Agent Intelligence & Graphify Knowledge Graph**:
  - [x] `.agents/` L0–L3 TencentDB Agent Memory structure and 42 Core AI Standards.
  - [x] `graphify-out/` AST knowledge graph and `.agents/context/code_graph_wiki.md`.
- [x] **On-Device AI Forensic Assistant (`ForensicAI`)**:
  - [x] Apple Intelligence (default on macOS 26+), Ollama (`127.0.0.1:11434`), LM Studio (`127.0.0.1:1234`), and Automatic fallback.
  - [x] In-window assistant provider selector and model picker.
  - [x] No-silent-switch policy with diagnostic amber badge for missing local models or unreachable servers.
- [x] **Quarantine Inspection & Touch ID Stripping (`sudo xattr`)**:
  - [x] Real-time detection of `com.apple.quarantine` on bundles and Mach-O executables.
  - [x] Touch ID / administrator authentication prompt to remove quarantine (`sudo xattr -rd com.apple.quarantine`) with auto-rescan.
  - [x] Gatekeeper first-launch warning and terminal unquarantine instructions documented in README and changelog.

## Completed Milestones (v1.3.0 — 2026-11-13)

- [x] **Report & Bundle Diff Mode (`AuditDiff`, `DiffView`, `--diff`)**:
  - [x] Side-by-side baseline comparison (`AuditDiff.compare` / `AuditDiff.loadOrAudit`) supporting `.app`, `.pkg`/`.mpkg`, `.dmg`, `.framework`, Mach-O binaries, and saved `.json` audit reports.
  - [x] Interactive `DiffView` (`⇧⌘D`) with verdict/metadata/finding/dylib/hook/entitlement deltas and Markdown diff export, plus headless `verificator-cli --diff <old> <new>`.
- [x] **Expanded Target Support (`AuditTargetKind` & `ForensicScanner.auditTarget`)**:
  - [x] `.pkg`/`.mpkg` installer signature checks (`pkgutil --check-signature`), `.dmg` disk image inspection, `.framework`/`.bundle`/`.appex`/`.xpc`/`.kext`/`.plugin` bundles, and standalone `.dylib`/`.so`/Mach-O executables.
  - [x] Backward-compatible `BundleAuditReport` JSON decoding for pre-`1.3.0` reports (`targetKind` defaults to `.appBundle`) and dyld-shared-cache ambiguity guard (0% FP on `/System/Library/Frameworks/AppKit.framework`).
- [x] **Informational Entitlement Risk Badges (`EntitlementAnalyzer`)**:
  - [x] Classify sensitive entitlements (`allow-jit`, disabled library validation, `DYLD_*` env flags, privacy/TCC capabilities, explicit `com.apple.security.app-sandbox = false`) in UI, exports, CLI, and `ForensicAI` prompts without mutating `IntegrityVerdict`.
- [x] **Running Processes & System Persistence Audit (`SystemAudit`, `SystemAuditView`)**:
  - [x] Darwin `proc_listallpids`/`proc_pidpath`/`sysctl(KERN_PROCARGS2)` running process & `DYLD_*` inspector (`⌥⌘P`, `--running`) with `PROC_PIDTBSDINFO` parent process lookup, `PROC_PIDREGIONPATHINFO` mapped Mach-O validation, and dynamic `SecCode` vs static `SecStaticCode` verification (`LiveProcessInspector`).
  - [x] LaunchAgents/Daemons/PrivilegedHelperTools persistence scanner (`⌥⌘T`, `--persistence`) with `FullDiskAccess` status check & Settings button.
- [x] **Sibling Security, Revocation, Signature Tracking & Automated Guard Tests**:
  - [x] Opt-in OCSP revocation check (`RevocationChecker`, `--revocation`), persistent `SignatureTracker` / `SignatureTrackerStore` (`signature-history.json`, `0o600`, LRU `2,000`), global `GatekeeperStatus`, signal-safe `ChildProcessGuard`, and `LaunchServicesRegistration` (`LSRegisterURL`).
  - [x] Localized `ServicesMenu.strings` & `AppShortcuts.strings` (`tr`/`en`/`ro`), `HardcodedTextGuardTests`, `AccessibilityLintTests`, `BundleVerificationTests`, and `SystemSecurityFeaturesTests`.
- [x] **Sibling Security, Integrity & Privacy Additions**:
  - [x] Unicode / RTLO filename spoof detection (`OpenSafety` `visibleName` `⟦U+XXXX⟧`) across bundles, nested components, processes, and persistence items.
  - [x] Read-only macOS Application Firewall inspector (`ApplicationFirewall` / `socketfilterfw`, `--no-firewall`) and copyable `--unblockapp` command helper.
  - [x] Single-pass streaming SHA-256 & SHA-512 expected checksum verifier (`ExpectedChecksum`, `ChecksumInput`, `--expected-checksum`) with GNU/BSD/`SHA256SUMS` manifest matching and weak-hash rejection.
  - [x] Little Snitch `InternetAccessPolicy.plist` / `.strings` parser (nested depth < 4) plus Verificator's own bundled trilingual `Resources/InternetAccessPolicy.{plist,strings}`.
  - [x] Per-export salted PII masker (`DiagnosticMasker`, `redactSharedDiagnostics`, CLI `--redact`), unencrypted removable-media detector (`VolumeEncryptionInfo`), Dock batch progress bar (`DockProgress`), and deterministic `SplitMix64` `FuzzTests`.
- [x] **macOS System Integration**:
  - [x] Finder `NSServices` (`auditServiceItem`), expanded `CFBundleDocumentTypes`, `verificator://` URL scheme (`verificator://posture`, `verificator://diff`), Shortcuts/Spotlight `AppIntents` (`VerificatorIntents`), and copyable `verificator-cli` install helper in Settings & menu bar.
- [x] **v1.3.0 Security, Kernel Sockets, System Posture, Enterprise & Integration Wave**:
  - [x] `KernelSocketList` live TCP/UDP socket correlation via `pcblist_n` & Darwin `libproc` fallback (`--running`, `RunningProcessesAuditView` `Sockets` filter).
  - [x] `DirectoryEntries` (`opendir`/`readdir`/`lstat`), `AppleDoubleDetector` (`0x00051607` sidecars ignored, disguised `._*` binaries flagged), `BundleSymlinkAudit` (`(st_dev, st_ino)` loops + `realpath` escapes), and JIT W^X standalone binary calibration.
  - [x] Informational Apple Development certificate pill (`isDevelopmentSigned` / `isDevelopmentCertificateSummary`) and `ManagedConfiguration` enterprise MDM preference locking (`UserDefaults.objectIsForced(forKey:)`).
  - [x] `WatchedFolderService` opt-in folder monitor (`default OFF`), conditional `MenuBarExtra` (`showMenuBarExtra`, `default OFF`), Launch at Login (`SMAppService.mainApp`), `NotificationService`, and proactive `SignatureChangeAlertSheet`.
  - [x] `SettingsTransfer` portable JSON Export/Import (`~/` home path compression/expansion, MDM respect, `SignatureTracker.merge`), `DiagnosticReportBuilder` + `DiagnosticSheet` anonymized Markdown diagnostics, and `SystemSecurityPostureAuditor` + `SystemPostureAuditView` (`⌥⌘G`, `--posture`, `verificator://posture`) including read-only orphaned `/private/var/db/receipts` audit.

## Completed Milestones (v1.2.0 — 2026-11-13)

- [x] **Parallel Batch Folder Audit (`⌥⌘B`) & CLI Tool (`verificator-cli`)**:
  - [x] `ForensicScanner.auditDirectory(..., maxConcurrentScans: 4)` & `BatchAuditSummary` (`wasCancelled`) with searchable GUI Batch View (progress, Stop, filters, row context actions, Markdown/JSON export) and headless CLI (`--batch`, `--lang tr|en|ro`, `--json`, `--spctl`) with standalone `Resources/` fallback discovery.
- [x] **Deep Engine, Safety & Calibration Upgrades**:
  - [x] Streaming `executableSHA256`, exposed `lcRpaths` (`otool -l`) & `rawEntitlementsOutput`, nested `.framework/Libraries/*.dylib`, `.appex`, `.xpc`, and Mach-O helper inspection (`BundledItemKind`), `.framework` Mach-O symbol checks, Mach-O architectures (`lipo -archs`), and entitlements XML inspection.
  - [x] Optional/on-demand Gatekeeper policy assessment (`spctl --assess`) and calibrated `IntegrityVerdict.warning` rules.
  - [x] Multi-process `ScanCancellationToken` + subprocess timeouts and stream byte caps (`runTool`), plus Touch ID/password cancel distinction (`QuarantineRemovalStatus`).
- [x] **Cryptographically Verified In-App Updates**:
  - [x] Connected `AppUpdateChecker.downloadAndVerify(release:)` to enforce `SHA256SUMS.txt` and Ed25519 `.dmg.sig` verification against `VerificatorUpdatePublicEDKey`, plus one-click **Open Downloaded Archive** and **Show in Finder** actions in Settings.
- [x] **UI Search, Filtering, Copy, CI & `VerificatorKit` Test Coverage**:
  - [x] Dylib & batch search, `All`/`Non-System`/`Suspicious` filter, expanded **Raw Forensic Output** (`LC_RPATH`, `Entitlements XML`, `Gatekeeper spctl`), section copy controls, AI Cancel/Copy controls, `⌥⌘S` JSON report export, built-in shortcut collision checks, `set-version.sh` -> `AppInfo` sync, and `VerificatorKit` unit tests.
