# Development

## Requirements

- macOS 26 or later
- Xcode 26 or later (Swift 6.2+). Universal (`arm64` + `x86_64`) builds require full Xcode and the macOS system forensic utilities (`/usr/bin/codesign`, `/usr/sbin/spctl`, `/usr/bin/otool`, `/usr/bin/nm`, `/usr/bin/strings`, `/usr/bin/lipo`, `/usr/sbin/pkgutil`).

## Folder layout

```text
Verificator/
├── Package.swift
├── Sources/
│   ├── VerificatorCore/         UI-independent, tested forensic & infrastructure core
│   │   ├── AppInfo.swift                 Version, build, repository, and URL constants
│   │   ├── AppLog.swift                  Unified log + ~/Library/Logs/Verificator/Verificator.log
│   │   ├── AppUpdate.swift               GitHub Releases checker, download staging, Ed25519 & SHA-256 verification
│   │   ├── ApplicationFirewall.swift     Read-only macOS Application Firewall (`socketfilterfw`) state & app-rule reader
│   │   ├── AuditDiff.swift               Report & bundle diff engine (`AuditReportDiff`, `AuditDiff.compare`)
│   │   ├── ChildProcessGuard.swift       Signal-safe external tool PID tracker & orphan process reaper
│   │   ├── DiagnosticMasker.swift        Per-export salted SHA-256 PII path/username redactor
│   │   ├── EntitlementAnalyzer.swift     Informational security entitlement risk badge classifier
│   │   ├── ExpectedChecksum.swift        SHA-256/SHA-512 checksum parser (raw, GNU, BSD, manifests) & weak-hash rejector
│   │   ├── ForensicModels.swift          Codable reports (`AuditTargetKind`), BatchAuditSummary, ScanOptions, ScanCancellationToken
│   │   ├── ForensicScanner.swift         4-layer zero false-positive `.app`/`.pkg`/`.dmg`/`.framework`/Mach-O scanner
│   │   ├── InternetAccessPolicy.swift    Little Snitch `InternetAccessPolicy.plist` & `.strings` reader (nested depth < 4)
│   │   ├── LocalModels.swift             On-device AI (Apple Intelligence, Ollama, LM Studio), LocalModelServer, ForensicAI
│   │   ├── Localization.swift            AppLanguage, StringTable, LKey (all string keys)
│   │   ├── OpenSafety.swift              Unicode RTLO / blank-filler / control-char detector & escaped display formatter
│   │   ├── SignatureTracker.swift        Local app signature & CDHash baseline history (`0600` LRU JSON store)
│   │   ├── SystemAudit.swift             Darwin running-process (`DYLD_*`) & LaunchAgents/Daemons persistence auditor
│   │   ├── SystemSecurityChecks.swift    GatekeeperStatus, FullDiskAccess, RevocationChecker (OCSP), LiveProcessInspector
│   │   └── VolumeEncryption.swift        Read-only `URLResourceValues` boot & removable-drive encryption inspector
│   ├── VerificatorKit/          Testable SwiftUI app & state management layer (default isolation: MainActor)
│   │   ├── VerificatorApp.swift          Scenes (Main, About, Log, Settings), AppCommands, AppDelegate (`NSServices`, URL scheme)
│   │   ├── VerificatorIntents.swift      Shortcuts & Spotlight `AppIntents` (`AuditApplicationIntent`, `VerificatorShortcutsProvider`)
│   │   ├── DockProgress.swift            NSApp Dock tile progress overlay (`DockProgress`, `DockTileView`, `DockTileSurface`)
│   │   ├── LaunchServicesRegistration.swift  Per-build Launch Services (`LSRegisterURL`) auto-registration helper
│   │   ├── AppModel.swift                Scan/batch/diff/system-audit orchestration, verified downloads, Markdown/JSON report export
│   │   ├── AppSettings.swift             UserDefaults preferences, appearance, localization, shortcut conflict checks
│   │   ├── LogStore.swift                Observable log store bridging AppLog to LogView
│   │   └── Views/
│   │       ├── ContentView.swift         Master-detail UI, batch audit view, searchable dylib & entitlement inspector, verdict banner
│   │       ├── DiffView.swift            Side-by-side bundle/report diff workspace (`⇧⌘D`)
│   │       ├── SystemAuditView.swift     Running processes (`⌥⌘P`) and persistence (`⌥⌘T`) audit workspaces
│   │       ├── SettingsView.swift        General, Scan, Shortcuts, and Forensic Engine, CLI & Updates tabs
│   │       ├── AboutView.swift           About window
│   │       ├── LicenseViewerSheet.swift  Read-only license and third-party notices viewer
│   │       └── LogView.swift             Console-style log viewer (⌥⌘L)
│   ├── Verificator/             App launcher entry point (`VerificatorMain.swift`)
│   └── VerificatorCLI/          Standalone CLI tool (`verificator-cli`) sharing `VerificatorCore` (`--batch`, `--diff`, `--running`, `--persistence`, `--revocation`, `--expected-checksum`, `--redact`, `--no-firewall`)
├── Resources/                        {tr,en,ro}.lproj/{Localizable,InfoPlist,ServicesMenu,AppShortcuts,InternetAccessPolicy}.strings, InternetAccessPolicy.plist, AppIcon.icns
├── Support/Info.plist                Bundle metadata, document types, `verificator://` URL scheme, Finder `NSServices`, Ed25519 public key
├── Scripts/                          make_icon.swift, build_app.sh, verify_bundle.sh, package.sh,
│                                     release.sh, set-version.sh, update_signing.swift
├── .github/workflows/ci.yml          macOS CI workflow (plutil -lint, swift test, universal build, CLI smoke test)
├── Tests/VerificatorTests/      Localization parity, update checker, log, and forensic calibration tests
├── Paketle.command                   Double-click in Finder to run tests and package into dist/
├── Yayimla.command                   Double-click in Finder to publish a release to GitHub Releases
├── .agents/                          Agent governance: AGENTS.md, context/, rules/, skills/
├── CLAUDE.md                         Graphify instructions for coding agents
└── .graphifyrc, .graphifyignore      Graphify configuration; output lives in git-ignored graphify-out/
```

## Architecture

- **Read-Only Forensic Guarantee:** `ForensicScanner`, `ApplicationFirewall`, and `VolumeEncryptionInfo` never mutate, strip, unblock, or re-sign any inspected target. All external inspections run out-of-process via `/usr/bin/codesign`, `/usr/sbin/spctl`, `/usr/bin/otool`, `/usr/bin/nm`, `/usr/bin/strings`, `/usr/bin/lipo`, `/usr/sbin/pkgutil`, and `/usr/libexec/ApplicationFirewall/socketfilterfw`.
- **Zero False-Positive Calibration:**
  - Official Apple Root CA chains (`Developer ID Application`, `Apple Mac OS Application Signing`, `Software Signing`) and local ad-hoc builds (`Arhivar`, `Curatare`, `Copiator`, `Redactor`, etc.) evaluate to `IntegrityVerdict.clean`.
  - `IntegrityVerdict.tampered` is emitted only when corroborated by a known patcher authority (`TEAM EDiSO`, `TNT`, etc.), framework-versus-executable signature stripping with an injected dylib, or an unofficial authority combined with runtime hook symbols.
- **Quarantine Inspection & Elevation:**
  - Inspects active, unapproved `com.apple.quarantine` state on `.app` packages and the Mach-O binary via uncached `URLResourceKey.quarantinePropertiesKey` and `getxattr` flag filtering (excluding user-approved `0x0040` / cleared `0x4000`/`0x8000` flags).
  - When active quarantine is present, the user can remove quarantine via `ForensicScanner.removeQuarantineWithAdminPrivileges(at:)`, which triggers native macOS Touch ID or password prompts (`do shell script "/usr/bin/xattr -rd com.apple.quarantine ..." with administrator privileges`).
  - Verificator itself is ad-hoc signed: first launch requires allowing through **System Settings › Privacy & Security** or `xattr -dr com.apple.quarantine /Applications/Verificator.app`.
- **On-Device AI Security Architecture:**
  - `ForensicAI` operates 100% locally on this Mac: **Apple Intelligence** (first and default via `FoundationModels`), local **Ollama** (`127.0.0.1:11434`), or local **LM Studio** (`127.0.0.1:1234`).
  - Network requests strictly target `127.0.0.1` on fixed ports; proxies and HTTP redirects are blocked (`NoRedirects`); cloud and embedding models are filtered out.
  - The model only explains forensic evidence in the user's language and cannot overwrite the deterministic `IntegrityVerdict`.
- **Ed25519 Release Signing (`Scripts/update_signing.swift`):**
  - The Ed25519 private key is stored in the macOS login keychain under service `com.babadogantech.verificator.update-signing` with a mode-`0600` backup in `.secrets/ed25519-private-key.txt` (git-ignored).
  - The base64 public key is embedded in `Support/Info.plist` under `VerificatorUpdatePublicEDKey`.
  - `Scripts/package.sh` signs `dist/Verificator-<version>.dmg` to `dist/Verificator-<version>.dmg.sig` and verifies the signature before writing `dist/SHA256SUMS.txt`.

## Adding strings (localization)

1. Add the key to `LKey` in `Sources/VerificatorCore/Localization.swift`.
2. Add the exact key to **all three** files: `Resources/tr.lproj/Localizable.strings`, `Resources/en.lproj/Localizable.strings`, and `Resources/ro.lproj/Localizable.strings` (and maintain 1:1 parity across `InfoPlist.strings`, `ServicesMenu.strings`, `AppShortcuts.strings`, and `InternetAccessPolicy.strings`).
3. Positional format specifiers (`%1$@`, `%2$@`, `%1$ld`) must match across all three languages.

## Build, test, package

```bash
swift build                      # quick development build
swift test                       # unit, 1:1 localization parity, and 0% FP forensic calibration tests
./Scripts/build_app.sh           # build/Verificator.app
./Scripts/package.sh             # tests + universal .app + dist/Verificator-<version>.dmg, .dmg.sig, SHA256SUMS.txt
```
