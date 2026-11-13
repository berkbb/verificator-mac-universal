# Domain Wiki — macOS Bundle Forensics & Mach-O Integrity Architecture

## 1. Domain Overview

`Verificator` inspects macOS `.app` bundles to determine whether an application is authentic (`CLEAN`), has non-critical anomalies (`WARNING`), or has been modified by a third-party patcher/injector (`TAMPERED`).

## 2. Four-Layer Forensic Pipeline (`ForensicScanner`)

1. **Layer 1 — Primary Code Signature, SHA-256 & Authority Chain (`/usr/bin/codesign`, `/usr/bin/lipo`, optional `/usr/sbin/spctl`):**
   - Computes streaming `executableSHA256`, extracts architectures (`lipo -archs`), entitlements XML, `TeamIdentifier`, `Authority` chain, `Signed Time` / `Timestamp`, `CodeDirectory` flags (`runtime`), `Notarization Ticket`, and `CDHash`.
   - Distinguishes between Official Apple Root CA chains (`Developer ID Application`, `Apple Mac OS Application Signing`, `Software Signing`), local ad-hoc developer builds, and unofficial/self-signed crack certificates (e.g., `TEAM EDiSO`).
2. **Layer 2 — Bundled Library, Extension, XPC & Helper Signature Provenance (`Contents/MacOS`, `Frameworks`, `PlugIns`, `XPCServices`, `Helpers`, `LoginItems`):**
   - Inspects every `.dylib`, `.framework` (including `.framework/Libraries/*.dylib`), `.appex`, `.xpc`, and standalone Mach-O helper inside the bundle (`BundledItemKind`) plus `WrappedBundle` iOS containers.
   - Detects **Signature Hijacking**: when embedded vendor frameworks still carry an official Apple `Developer ID Application` signature (`TeamIdentifier != not set`), while the main executable's signature was stripped and replaced with an ad-hoc or third-party authority, or when an injected dylib in `Contents/MacOS/` carries a different signer than the vendor frameworks.
3. **Layer 3 — Mach-O Load Command Audit (`/usr/bin/otool -L` / `/usr/bin/otool -l`):**
   - Parses `LC_RPATH` entries as well as `LC_LOAD_DYLIB` and `LC_LOAD_WEAK_DYLIB` entries of the main executable.
   - Flags non-system `@executable_path/` or `@rpath/` dylibs that correlate with signature mismatch or known injection patterns without false-flagging legitimate CMake/Electron/SwiftPM dylibs.
4. **Layer 4 — Undefined Symbol & Runtime Hook Analysis (`/usr/bin/nm -u`, `/usr/bin/strings`):**
   - Categorizes imported hook symbols across suspicious dylibs and frameworks into:
     - **Objective-C Swizzling:** `_method_exchangeImplementations`, `_class_replaceMethod`, `_imp_implementationWithBlock`.
     - **Mach VM Patching:** `_mach_vm_protect`, `_mach_vm_write`, `_mach_vm_remap`, `_mach_task_self_`.
     - **DYLD ASLR Slide Inspection:** `__dyld_get_image_vmaddr_slide`, `__dyld_get_image_header`, `__dyld_register_func_for_add_image`.

## 3. Sibling App Architecture Parity

`Verificator` follows the exact structural conventions of its sibling macOS Universal apps (`Arhivar`, `Curatare`, `Copiator`, `Redactor`):
- **Core Target (`VerificatorCore`):** `AppInfo`, `Localization` (`AppLanguage`, `StringTable`, `LKey`), `AppLog`, `AppUpdate` (`AppUpdateChecker`, `UpdateSignature`, `UpdateChecksums`), `ChildProcessGuard`, `ForensicModels` (`AuditTargetKind`, `BundleAuditReport`, `BatchAuditSummary`, `ScanCancellationToken`), `EntitlementAnalyzer` (`EntitlementRiskLevel`, `EntitlementRiskItem`), `AuditDiff` (`AuditReportDiff`), `ForensicScanner` (`auditTarget`, `auditBundle`, `auditInstallerPackage`, `auditDiskImage`, `auditStandaloneMachO`, parallel `auditDirectory`), `SignatureTracker` (`SignatureTrackerStore`), `SystemAudit` (`auditRunningProcesses`, `auditPersistence`), `SystemSecurityChecks` (`GatekeeperStatus`, `FullDiskAccess`, `RevocationStatus`, `RevocationChecker`, `LiveProcessInspector`), and `LocalModels` (`ForensicAI`, `LocalModelServer`, `AIPrerequisites`).
- **UI & State Target (`VerificatorKit`):** `VerificatorApp` (Finder `NSServices`, `verificator://` URL handling, `AppCommands`), `VerificatorIntents` (`AuditApplicationIntent`, `VerificatorShortcutsProvider`), `LaunchServicesRegistration`, `AppSettings`, `AppModel`, `LogStore`, `ContentView`, `DiffView`, `SystemAuditView`, `SettingsView`, `AboutView`, `LicenseViewerSheet`, and `LogView`.
- **Launcher & CLI Targets (`Verificator` & `verificator-cli`):** `VerificatorMain` (`@main` app entry point) and `VerificatorCLI` (headless CLI auditor with `--batch`, `--diff`, `--running`, `--persistence`, `--revocation`, `--lang`, `--json`, and `--spctl`).

## 4. Quarantine Inspection & Administrator Elevation (`com.apple.quarantine`)

- **Quarantine Attribute Detection:** Inspects active, unapproved `com.apple.quarantine` state on the `.app` root and `Contents/MacOS/<exec>` via uncached `URLResourceKey.quarantinePropertiesKey` (checking raw and symlink-resolved URLs) plus `getxattr` flag filtering (`0xC040` cleared mask, excluding `0x0040` `QTN_FLAG_USER_APPROVED` so already-opened apps like `01c3`/`00c3`/`01c1` do not trigger false warnings).
- **Dynamic Action:** When `report.isQuarantined == true`, an interactive **Remove Quarantine (sudo xattr)** action is exposed in the verdict banner and menu bar (`⌘K`).
- **Administrator Privileges:** Prompts macOS native Touch ID / password prompt via `/usr/bin/osascript` with administrator privileges to execute `/usr/bin/xattr -rd com.apple.quarantine <bundlePath>`.
- **First-Launch Gatekeeper Warning:** Because Verificator is ad-hoc signed, downloading from GitHub Releases attaches quarantine, requiring either right-click Open, allowing in **System Settings › Privacy & Security**, or `xattr -dr com.apple.quarantine /Applications/Verificator.app`.

## 5. On-Device AI Architecture (`ForensicAI`)

- **Model Sources:**
  - `Apple Intelligence` (`.apple`): Default first provider on macOS 26+ via Apple `FoundationModels` framework (`SystemLanguageModel.default`).
  - `Ollama` (`.ollama`): Talks exclusively to `127.0.0.1:11434`; filters out cloud/embedding models.
  - `LM Studio` (`.lmStudio`): Talks exclusively to `127.0.0.1:1234`; filters out embedding models.
  - `Automatic` (`.automatic`): Sequential fallback across enabled providers; silent recovery only in this mode.
- **No-Silent-Switch Policy:** When a specific provider is chosen, Verificator does not secretly fall back to another model if the chosen provider is offline or missing local models; it warns with an amber badge and waits.
- **In-Window Selector:** Available directly in the AI Assistant card within the main window as well as the Settings window.

## Sibling Security, Integrity & Privacy Modules (v1.3.0)

- **Deceptive Unicode / RTLO Spoofing (`OpenSafety`):** Scans file names across audited targets, nested bundles, live processes, and persistence items for bidirectional overrides (`U+202E`), blank fillers (`0x2800`, `0x3164`, `0x115F`, `0x1160`, `0xFFA0`), ASCII controls, and default-ignorables while preserving Finder `"Icon\r"`, emoji variation selectors (`U+FE0E`/`U+FE0F`), and `U+200D` ZWJ sequences. Exposes `visibleName` with `⟦U+XXXX⟧` markers and triggers `IntegrityVerdict.warning`.
- **Application Firewall State (`ApplicationFirewall`):** Read-only reader for `/usr/libexec/ApplicationFirewall/socketfilterfw` (`--getglobalstate`, `--getblockall`, `--getstealthmode`, `--getappblocked`). Never mutates firewall rules; exposes copyable `sudo .../socketfilterfw --unblockapp "<path>"` guidance when blocked (`--no-firewall` to skip in CLI).
- **Expected Checksum Verifier (`ExpectedChecksum` / `ChecksumInput`):** Single-pass streaming `executableSHA256` + `executableSHA512` verifier accepting raw hex, `sha256:`/`sha-512=`, GNU `sha256sum`/`shasum`, BSD `SHA256 (...) = ...`, and multi-line `SHA256SUMS` files (matched by basename), while rejecting weak MD5/SHA-1 inputs.
- **Internet Access Policy (`InternetAccessPolicy`):** Parses target `Contents/Resources/InternetAccessPolicy.plist` + localized `<lang>.lproj/InternetAccessPolicy.strings` and nested `Frameworks`/`SharedFrameworks`/`PlugIns`/`XPCServices` policies (depth < 4). Verificator itself bundles a 1:1 localized `Resources/InternetAccessPolicy.plist` and `{tr,en,ro}.lproj/InternetAccessPolicy.strings`.
- **Diagnostic PII Redactor (`DiagnosticMasker`):** Generates a fresh per-export 256-bit random salt so shared Markdown/JSON reports, clipboard copies, Console logs, and CLI `--redact` outputs mask `/Users/<name>`, `~`, OS usernames, and personal path components (`‹user-xxxxxx›`, `‹item-xxxxxx›.ext`) while preserving standard system directories.
- **Volume Encryption & Dock Progress (`VolumeEncryptionInfo`, `DockProgress`):** Surfaces unencrypted removable/external media banners via `URLResourceValues` (`isEncrypted`, `isRemovable`, `isInternal`, `isLocal`) and boot FileVault state in Settings, plus bottom-edge Dock tile progress bars (`DockProgress`, `DockTileView`, `DockTileSurface`) during batch scans.
- **Deterministic Seeded Fuzzing (`FuzzTests`):** Reproducible `SplitMix64` property/fuzz test suite exercising `OpenSafety`, `ChecksumInput`, `ApplicationFirewall`, `InternetAccessPolicy`, `DiagnosticMasker`, `ForensicScanner`, and `GatekeeperStatus`.
