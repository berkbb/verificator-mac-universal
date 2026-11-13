# Code-Graph Memory Wiki (`code_graph_wiki.md`)

> Regenerated via `graphify` (`extract . --code-only` + `cluster-only . --no-label`) in `graphify-out/GRAPH_REPORT.md` (1,814 nodes · 4,069 edges · 84 communities · 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · 0 import cycles · 0 API tokens).

## 1. Core God Nodes & High-Centrality Symbols

| Rank | Symbol | Edges | Module / File | Role |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `LKey` | 543 | `Sources/VerificatorCore/Localization.swift` | Trilingual (`tr`, `en`, `ro`) localization key enum |
| 2 | `AppModel` | 127 | `Sources/VerificatorKit/AppModel.swift` | Main scan, batch, diff, running-process, persistence, signature-history, URL-scheme, multi-target Service routing, update & quarantine orchestrator |
| 3 | `AppSettings` | 74 | `Sources/VerificatorKit/AppSettings.swift` | Observable user settings, language, appearance, OCSP/scan options, shortcuts, recents |
| 4 | `BundleAuditReport` | 63 | `Sources/VerificatorCore/ForensicModels.swift` | Immutable `Codable` forensic audit report (`AuditTargetKind`, `entitlementRisks`, `revocationStatus`, `executableSHA256`, `lcRpaths`, `rawEntitlementsOutput`) |
| 5 | `ForensicScanner` | 50 | `Sources/VerificatorCore/ForensicScanner.swift` | 4-layer zero false-positive `.app`/`.pkg`/`.dmg`/`.framework`/Mach-O, codesign, spctl, revocation, lipo & dylib injection engine |
| 6 | `CodingKeys` | 48 | `Sources/VerificatorCore/ForensicModels.swift` | Backward-compatible `Codable` mapping for pre-`1.3.0` and `1.3.0+` `BundleAuditReport` JSON schemas |
| 7 | `ScanCancellationToken` | 40 | `Sources/VerificatorCore/ForensicModels.swift` | Thread-safe process & cancellation token coordinating multi-worker audit cancellation |
| 8 | `ContentView` | 38 | `Sources/VerificatorKit/Views/ContentView.swift` | Master-detail SwiftUI interface, single-target, batch, diff & system audit routing, search & raw output tabs |
| 9 | `AppLog` | 37 | `Sources/VerificatorCore/AppLog.swift` | Persistent TSV log writer (`~/Library/Logs/Verificator/Verificator.log`) |
| 10 | `LocalModelServer` | 33 | `Sources/VerificatorCore/LocalModels.swift` | Local AI server descriptor (`ollama` `127.0.0.1:11434`, `lmStudio` `127.0.0.1:1234`) |

## 2. Module & Call Hierarchy

- **`VerificatorCore` (Framework Target):**
  - `ForensicScanner.auditTarget(at:options:cancellation:)` / `auditBundle` / `auditInstallerPackage` / `auditDiskImage` / `auditStandaloneMachO` / `batchTargets(in:)` / `auditDirectory` / `auditTargets(..., maxConcurrentScans: 4)` → produces backward-compatible `Codable` `BundleAuditReport` (`AuditTargetKind`, `entitlementRisks`, `revocationStatus`) / `BatchAuditSummary` (`wasCancelled`) with `executableSHA256`, `lcRpaths`, `rawEntitlementsOutput`, `BundledItemKind` (`.framework`, `.dylib`, `.appExtension`, `.xpcService`, `.helperExecutable`), architectures, entitlements, optional `spctl` policy checks, optional `RevocationChecker` OCSP validation, and `isQuarantined`.
  - `AuditDiff` (`AuditDiff.compare`, `AuditDiff.loadOrAudit`, `AuditReportDiff`) → compares two targets or saved `.json` audit reports across verdicts, metadata, findings, dylibs, hooks, and entitlement risks.
  - `EntitlementAnalyzer` (`EntitlementRiskLevel`, `EntitlementRiskItem`) → derives non-verdict-mutating security entitlement risk badges from parsed entitlements and raw XML output.
  - `SystemAudit` (`auditRunningProcesses`, `auditPersistence`, `enclosingAppBundlePath`) & `SystemSecurityChecks` (`GatekeeperStatus`, `FullDiskAccess`, `RevocationChecker`, `LiveProcessInspector`) → inspects live Darwin PIDs (`proc_listallpids`, `proc_pidpath`, `PROC_PIDTBSDINFO` parent lookup, `PROC_PIDREGIONPATHINFO` Mach-O library validation, dynamic vs static `SecCode`, `sysctl(KERN_PROCARGS2)` for `DYLD_*`), LaunchAgents/LaunchDaemons/PrivilegedHelperTools, global Gatekeeper status (`spctl --status`), and Full Disk Access state.
  - `SignatureTracker` & `SignatureTrackerStore` → tracks per-bundle signing authority and `CDHash` baselines in `~/Library/Application Support/Verificator/signature-history.json` (`0600`, LRU `2,000`).
  - `ChildProcessGuard` / `ChildProcessTracker` → tracks spawned external tool PIDs in a signal-safe fixed-capacity table and reaps orphaned helpers cleanly across restarts or signals.
  - `ForensicScanner.removeQuarantineWithAdminPrivileges(at:)` → executes `/usr/bin/xattr -rd com.apple.quarantine` via `osascript` with administrator privileges (`QuarantineRemovalResult`).
  - `ScanCancellationToken` → tracks multiple concurrent subprocesses (`[ObjectIdentifier: Process]`) so parallel batch cancellation terminates all active child tools cleanly.
  - `LocalModels.swift` (`SuggestionProvider`, `LocalModelServer`, `OnDeviceSuggestionModel`, `LocalServerSuggestionModel`, `FallbackSuggestionModel`, `AIPrerequisites`, `ForensicAI`) → provides on-device Apple Intelligence, local Ollama, and LM Studio assessment.
  - `StringTable`, `StringTable.discoverFallbackResourcesDirectory(executablePath:)`, `StringTable.format`, & `AppLanguage` → loads `Resources/{tr,en,ro}.lproj/{Localizable,InfoPlist,ServicesMenu,AppShortcuts}.strings` inside bundles and standalone CLI builds.
  - `AppInfo` (`fallbackVersion`, `fallbackBuild`, `Info.plist` resolution) → resolves version/build across bundled and standalone CLI runs.
  - `AppUpdateChecker`, `UpdateSignature`, `UpdateChecksums` → GitHub Releases check + verified `.dmg`/`.dmg.sig`/`SHA256SUMS.txt` download and Ed25519/SHA-256 verification.
- **`VerificatorKit` & `Verificator` (`VerificatorMain` Launcher) + `VerificatorCLI` (`verificator-cli`):**
  - `VerificatorApp` (`auditServiceItem`, `AppDelegate.extractServiceTargetURLs(from:)`, `applicationWillFinishLaunching`, `open urls` → `handleIncomingURLs`, `openDiff`, `ChildProcessGuard.install()`, `LaunchServicesRegistration.registerIfBuildChanged()`) → hosts `ContentView` (`WindowID.main`), `DiffView` (`⇧⌘D`), `SystemAuditView` (`RunningProcessesAuditView` `⌥⌘P`, `PersistenceAuditView` `⌥⌘T`), `AboutView` (`WindowID.about`), `LogView` (`WindowID.log`), and `SettingsView` (including `settingsCLISection` and `settingsPermissionsSection`), plus `AppCommands` menu bar commands (`⌘O`, `⌥⌘B` Batch, `⇧⌘D` Diff, `⌥⌘P` Processes, `⌥⌘T` Persistence, `⌘R` Refresh, `⇧⌘R` Reveal, `⇧⌘C` Copy, `⌘S` Save Markdown, `⌥⌘S` Save JSON, `⇧⌘W` Clear, `⌘K` Remove Quarantine, `⌥⌘L` Log) and `VerificatorIntents` (`AuditApplicationIntent`, `VerificatorShortcutsProvider`).
- **Sibling Security, Integrity & Privacy Modules (`VerificatorCore` & `VerificatorKit`):**
  - `OpenSafety` (`hasDeceptiveCharacters`, `visibleName` `⟦U+XXXX⟧`, `collectDeceptiveNames`) → wired into `ForensicScanner.collectCrossTargetForensics`, `SystemAudit` (`auditLaunchPlist`, `auditPrivilegedHelper`, `auditRunningProcesses`), `BundleAuditReport.deceptiveNames`, and UI views.
  - `ApplicationFirewall` (`FirewallStatus`, `FirewallAppRuleStatus`, `FirewallAppState`) → read-only `/usr/libexec/ApplicationFirewall/socketfilterfw` inspection integrated into `ForensicScanner`, `AppModel.firewallStatus`, `SettingsView`, `ContentView`, and CLI (`--no-firewall`).
  - `ExpectedChecksum` / `ChecksumInput` (`ChecksumAlgorithm`, `ChecksumParseResult`, `ChecksumVerificationResult`) → pairs with single-pass `ForensicScanner.executableDigests(for:)` (`executableSHA256`, `executableSHA512`) in `AppModel.evaluateExpectedChecksum`, `ContentView`, and CLI (`--expected-checksum`).
  - `InternetAccessPolicy` → parses bundle `Contents/Resources/InternetAccessPolicy.plist` + `.strings` + nested sub-bundles (`depth < 4`); Verificator ships its own `Resources/InternetAccessPolicy.plist` & `{tr,en,ro}.lproj/InternetAccessPolicy.strings`.
  - `DiagnosticMasker` → fresh per-export 256-bit salted SHA-256 redactor backing `BundleAuditReport.redacted(using:)`, `BatchAuditSummary.redacted(using:)`, `AppModel`, `LogView`, `SettingsView` (`redactSharedDiagnostics`), and CLI (`--redact`).
  - `VolumeEncryptionInfo` → read-only `URLResourceValues` check exposing unencrypted removable/external media banners and boot FileVault state in `SettingsView` (`bootVolumeEncryption`).
  - `DockProgress` (`DockTileSurface`, `DockTileView`, `DockTileState`) → batch scan bottom-edge Dock icon progress bar driven by `AppModel.startBatchScan` / `cancelBatchScan` and unit-tested via `FakeDockTile`.
- **Key Graphify God Nodes (`graphify-out/GRAPH_REPORT.md`):**
  - `LKey` (543 edges), `AppModel` (127 edges), `AppSettings` (74 edges), `BundleAuditReport` (63 edges), `ForensicScanner` (50 edges), `CodingKeys` (48 edges), `ScanCancellationToken` (40 edges), `ContentView` (38 edges), `AppLog` (37 edges), `LocalModelServer` (33 edges).
