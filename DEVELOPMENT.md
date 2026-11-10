# Development

## Requirements

- macOS 26 or later
- Xcode 26 or later (Swift 6.2+). Universal (`arm64` + `x86_64`) builds require full Xcode and the macOS system forensic utilities (`/usr/bin/codesign`, `/usr/sbin/spctl`, `/usr/bin/otool`, `/usr/bin/nm`, `/usr/bin/strings`).

## Folder layout

```text
Verificator/
├── Package.swift
├── Sources/
│   ├── VerificatorCore/         UI-independent, tested forensic & infrastructure core
│   │   ├── AppInfo.swift                 Version, build, repository, and URL constants
│   │   ├── AppLog.swift                  Unified log + ~/Library/Logs/Verificator/Verificator.log
│   │   ├── AppUpdate.swift               GitHub Releases checker, Ed25519 signature & SHA-256 verification
│   │   ├── ForensicModels.swift          BundleAuditReport, IntegrityVerdict, ForensicFinding, ScanOptions
│   │   ├── ForensicScanner.swift         4-layer zero false-positive Mach-O, codesign & dylib scanner, quarantine check/strip
│   │   ├── LocalModels.swift             On-device AI (Apple Intelligence, Ollama, LM Studio), LocalModelServer, ForensicAI
│   │   └── Localization.swift            AppLanguage, StringTable, LKey (all string keys)
│   └── Verificator/             SwiftUI app (default isolation: MainActor)
│       ├── VerificatorApp.swift     Scenes (Main, About, Log, Settings), AppCommands, AppDelegate
│       ├── AppModel.swift                Scan lifecycle, Refresh/Clear actions, Markdown report export
│       ├── AppSettings.swift             UserDefaults preferences, appearance, localization, shortcuts
│       ├── LogStore.swift                Observable log store bridging AppLog to LogView
│       └── Views/
│           ├── ContentView.swift         NavigationSplitView master-detail UI, toolbar, verdict banner
│           ├── SettingsView.swift        General, Scan, Shortcuts, and Forensic Engine & Updates tabs
│           ├── AboutView.swift           About window
│           ├── LicenseViewerSheet.swift  Read-only license and third-party notices viewer
│           └── LogView.swift             Console-style log viewer (⌥⌘L)
├── Resources/                        {tr,en,ro}.lproj/Localizable.strings & InfoPlist.strings, AppIcon.icns
├── Support/Info.plist                Bundle metadata, document types, Ed25519 public key
├── Scripts/                          make_icon.swift, build_app.sh, verify_bundle.sh, package.sh,
│                                     release.sh, set-version.sh, update_signing.swift
├── Tests/VerificatorTests/      Localization parity, update checker, log, and forensic calibration tests
├── Paketle.command                   Double-click in Finder to run tests and package into dist/
├── Yayimla.command                   Double-click in Finder to publish a release to GitHub Releases
├── .agents/                          Agent governance: AGENTS.md, context/, rules/, skills/
├── CLAUDE.md                         Graphify instructions for coding agents
└── .graphifyrc, .graphifyignore      Graphify configuration; output lives in git-ignored graphify-out/
```

## Architecture

- **Read-Only Forensic Guarantee:** `ForensicScanner` never mutates, strips, or re-signs any inspected `.app` bundle. All inspections run out-of-process via `/usr/bin/codesign`, `/usr/sbin/spctl`, `/usr/bin/otool`, `/usr/bin/nm`, and `/usr/bin/strings`.
- **Zero False-Positive Calibration:**
  - Official Apple Root CA chains (`Developer ID Application`, `Apple Mac OS Application Signing`, `Software Signing`) and local ad-hoc builds (`Arhivar`, `Curatare`, `Copiator`, `Redactor`, etc.) evaluate to `IntegrityVerdict.clean`.
  - `IntegrityVerdict.tampered` is emitted only when corroborated by a known patcher authority (`TEAM EDiSO`, `TNT`, etc.), framework-versus-executable signature stripping with an injected dylib, or an unofficial authority combined with runtime hook symbols.
- **Quarantine Inspection & Elevation:**
  - Inspects `com.apple.quarantine` on `.app` packages and the Mach-O binary via `getxattr(..., "com.apple.quarantine", ...)`.
  - When present, the user can remove quarantine via `ForensicScanner.removeQuarantineWithAdminPrivileges(at:)`, which triggers native macOS Touch ID or password prompts (`do shell script "/usr/bin/xattr -rd com.apple.quarantine ..." with administrator privileges`).
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
2. Add the exact key to **all three** files: `Resources/tr.lproj/Localizable.strings`, `Resources/en.lproj/Localizable.strings`, and `Resources/ro.lproj/Localizable.strings`.
3. Positional format specifiers (`%1$@`, `%2$@`, `%1$ld`) must match across all three languages.

## Build, test, package

```bash
swift build                      # quick development build
swift test                       # unit, 1:1 localization parity, and 0% FP forensic calibration tests
./Scripts/build_app.sh           # build/Verificator.app
./Scripts/package.sh             # tests + universal .app + dist/Verificator-<version>.dmg, .dmg.sig, SHA256SUMS.txt
```
