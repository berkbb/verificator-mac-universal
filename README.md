# Verificator

![Swift](https://img.shields.io/badge/Swift-F05138?logo=swift&logoColor=white) ![macOS 26+](https://img.shields.io/badge/macOS-26%2B-000000?logo=apple&logoColor=white) ![Universal](https://img.shields.io/badge/arch-arm64%20%2B%20x86__64-blue)

A native macOS 26+ forensic security inspector, built with SwiftUI and Liquid Glass as a universal app (Apple Silicon `arm64` + Intel `x86_64`). It performs read-only 4-layer Mach-O, code signature, installer/disk image, running process, persistence, and dylib injection analysis with **0% false positives** on legitimate Apple, App Store, Developer ID, and local developer builds.

<p align="center">
  <img src="docs/screenshots/welcome-dark.png" width="850" alt="Verificator welcome screen in dark mode, showing the master-detail sidebar, bundle selection controls, and the forensic drop zone">
</p>

## Features

- **4-Layer Zero False-Positive Forensic Engine (`ForensicScanner`)**
  - **Layer 1 — Code Signature, Entitlements & Authority Chain:** runs `codesign -dvvv`, `codesign -d --entitlements`, `lipo -archs`, and `codesign --verify --no-strict` plus single-pass streaming SHA-256 & SHA-512 hashing (`executableSHA256`, `executableSHA512`) to inspect Mach-O architectures, XML entitlements (highlighted with informational `EntitlementAnalyzer` risk badges without affecting the verdict), `Identifier`, `TeamIdentifier`, certificate authority chains (`Apple Root CA`, `Developer ID Application`), Hardened Runtime flags, Notarization tickets, `CDHash`, and unofficial self-signed crack certificates (such as `TEAM EDiSO`). Supports interactive & CLI expected checksum verification (`ExpectedChecksum`, `--expected-checksum` accepting raw hex, GNU, BSD, or `SHA256SUMS` manifests while rejecting MD5/SHA-1), optional Gatekeeper policy verification (`/usr/sbin/spctl --assess`), opt-in OCSP revocation checks (`RevocationChecker`, `--revocation`), and local signature/`CDHash` baseline tracking (`SignatureTracker`) across re-audits.
  - **Layer 2 — Signature Hijacking Detection:** compares the signing provenance of frameworks, nested libraries, app extensions, XPC services, and Mach-O helpers inside `Contents/Frameworks` (including `.framework/Libraries/*.dylib`), `Contents/MacOS`, `Contents/PlugIns` (`.appex`), `Contents/XPCServices` (`.xpc`), `Contents/Helpers`, `Contents/Library/LoginItems`, and `WrappedBundle` iOS containers against the main executable to detect bundles whose vendor signature was stripped and replaced after injecting a third-party dylib.
  - **Layer 3 — Mach-O Load Command Audit (`otool -L` / `otool -l`):** parses and exposes `LC_RPATH`, `LC_LOAD_DYLIB`, and `LC_LOAD_WEAK_DYLIB` links on the main executable without false-flagging legitimate CMake, Electron, or SwiftPM libraries.
  - **Layer 4 — Runtime Hook & Memory Patch Symbol Categorization (`nm -u`, `strings`):** categorizes imported hook symbols into Objective-C method swizzling (`_method_exchangeImplementations`, `_class_replaceMethod`), Mach VM patching (`_mach_vm_protect`, `_mach_vm_write`, `_mach_vm_remap`), and DYLD ASLR slide inspection (`__dyld_get_image_vmaddr_slide`).
- **Expanded Target Support (`AuditTargetKind`):**
  - Audit `.app` bundles, `.pkg` / `.mpkg` installer packages (`pkgutil --check-signature`), `.dmg` disk images, `.framework` / `.bundle` / `.appex` / `.xpc` / `.kext` / `.plugin` bundles, and standalone `.dylib` / `.so` / Mach-O executables via drag-and-drop, open panel, Finder Services, `verificator://` URLs, or CLI.
- **Report & Bundle Diff Mode (`⇧⌘D`):**
  - Compare any two targets or exported `.json` forensic reports side by side (`AuditDiff` / `DiffView`) to inspect verdict shifts, signer/entitlement changes, added/removed findings, and newly introduced dylibs or hook symbols, with one-click Markdown export.
- **Running Processes (`⌥⌘P`) & System Persistence (`⌥⌘T`) Audit:**
  - Inspect active macOS processes (`SystemAudit.auditRunningProcesses` & `LiveProcessInspector` via `proc_listallpids`, `proc_pidpath`, `PROC_PIDTBSDINFO` parent process info, `PROC_PIDREGIONPATHINFO` mapped Mach-O libraries, dynamic `SecCode` vs static signature comparison, and `KERN_PROCARGS2` for `DYLD_*` variables) and LaunchAgents, LaunchDaemons, and PrivilegedHelperTools (`SystemAudit.auditPersistence` with `FullDiskAccess` status indicator), then open any flagged target directly in the forensic inspector.
- **Parallel Batch Folder Audit (`⌥⌘B`), CLI (`verificator-cli`) & macOS Integration:**
  - Scan an entire folder (such as `/Applications`) concurrently from the **Batch Audit** view or drop a folder onto the window (with live **Dock** tile progress overlay via `DockProgress`) to inspect verdicts and quarantine states in a searchable, filterable summary table with live Stop support, row context menus (including **Remove Quarantine**), and Markdown/JSON export.
  - Run headless single-target, `--batch`, `--diff <old> <new>`, `--running`, or `--persistence` audits in CI/scripts with `verificator-cli` (bundled at `Contents/MacOS/verificator-cli`, with a copyable install command in **Settings**), supporting `--lang tr|en|ro`, `--json`, `--redact`, `--spctl`, `--revocation`, `--expected-checksum <value|file>`, `--no-firewall`, `--no-deep`, and `--no-strings`.
  - Integrate with **Finder › Services** (`NSServices`, localized `ServicesMenu.strings`), custom `verificator://` deep links, **Shortcuts / Spotlight** (`AuditApplicationIntent`, localized `AppShortcuts.strings`), global `GatekeeperStatus` and read-only Application Firewall (`ApplicationFirewall` / `socketfilterfw`) alerts, unencrypted removable-media checks (`VolumeEncryptionInfo`), deceptive Unicode / RTLO filename alerts (`OpenSafety`), Little Snitch-compatible `InternetAccessPolicy.plist` inspection (plus Verificator's own bundled trilingual `InternetAccessPolicy`), per-export salted PII masking (`DiagnosticMasker`), and signal-safe child process protection (`ChildProcessGuard`).
- **On-Device & Local AI Forensic Assessment (`ForensicAI`)**
  - Summarizes and interprets forensic findings in the selected language without altering the deterministic verdict (`CLEAN`, `WARNING`, `TAMPERED`).
  - Supports **Apple Intelligence** (first and default provider on macOS 26+ via `FoundationModels`), local **Ollama** (`127.0.0.1:11434`), local **LM Studio** (`127.0.0.1:1234`), and **Automatic (in order)** fallback.
  - Strict security boundaries: exclusively talks to `127.0.0.1` with proxy/redirects disabled; filters out cloud/embedding models; warns with an amber badge if a chosen provider is unavailable instead of silently falling back.
- **Quarantine Removal (`sudo xattr`)**
  - Dynamically displays a prominent **Remove Quarantine** button when `com.apple.quarantine` is present on the bundle or its executable.
  - Uses macOS administrator authentication (`Touch ID` / password prompt) to safely clear quarantine flags and immediately re-audits the bundle.
- **Master–Detail Interface (`NavigationSplitView`)**
  - Sidebar with forensic inspection sections (**Home**, **Overview & Signature** `⌘1`, **Mach-O & Dylib Analysis** `⌘2`, **Memory & Hook Symbols** `⌘3`, **Raw Forensic Output** `⌘4`, **Report & Bundle Diff** `⇧⌘D`, **Running Processes** `⌥⌘P`, **Launch & Persistence** `⌥⌘T`) and **Recent Bundles** with live app icons, verdict indicators, and context menus.
  - Prominent **Refresh (`⌘R`)**, **Cancel**, and **Clear (`⇧⌘W`)** buttons, searchable/filterable dylib tables (`All`, `Non-System`, `Suspicious`), and per-section Copy buttons.
  - One-click Markdown report copy (`⇧⌘C`), Markdown file export (`⌘S`), and structured JSON export (`⌥⌘S`).
- **Languages:** Turkish (default), English, Romanian (1:1 key parity across dedicated `.lproj` files)
- **Appearance:** System, Light, Dark
- **Windows:** Main Window, 4-tab Settings (`⌘,`), About with read-only License Viewer, and a Console-style Log window (`⌥⌘L`) backed by `~/Library/Logs/Verificator/Verificator.log`
- **Updates:** checks GitHub Releases (`AppUpdateChecker`) and performs in-app downloads with automatic SHA-256 checksum (`UpdateChecksums`) and Ed25519 signature (`UpdateSignature`) verification.

## Installation

**Requires:** macOS 26 (Tahoe) or later. Runs natively on Apple Silicon and Intel Macs.

1. Download the latest `Verificator-<version>.dmg` from the [Releases](https://github.com/berkbb/verificator-mac-universal/releases) page.
2. Optionally verify the download with `SHA256SUMS.txt`:
   ```bash
   shasum -a 256 -c SHA256SUMS.txt
   ```
3. Open the `.dmg` and drag **Verificator** into the **Applications** folder.
4. **First launch & Gatekeeper Quarantine:** Verificator is ad-hoc signed rather than signed with a paid Apple Developer ID and is not notarized by Apple. When a file is downloaded from the internet, macOS automatically attaches the `com.apple.quarantine` extended attribute to it, and Gatekeeper blocks quarantined apps that are not notarized, displaying an alert such as *"Verificator can't be opened because Apple cannot check it for malicious software"*.
   - **Method A (GUI):** Right-click (or Control-click) `Verificator.app` in `/Applications`, choose **Open**, and click **Open** in the confirmation dialog (only required once). Alternatively, allow it in **System Settings › Privacy & Security** (scroll to *"Verificator was blocked..."* and click **Open Anyway**).
   - **Method B (Terminal):** Remove the quarantine attribute manually from the downloaded app:
     ```bash
     xattr -dr com.apple.quarantine /Applications/Verificator.app
     ```
   - **DMG Quarantine:** On newer macOS versions, Gatekeeper may also block opening the downloaded `.dmg` disk image directly. If prompted, allow it in **Privacy & Security**, or strip the quarantine flag prior to mounting:
     ```bash
     xattr -d com.apple.quarantine ~/Downloads/Verificator-*.dmg
     ```

## Development

Double-click in Finder:

- **`Paketle.command`** (package): runs the test suite and produces a universal `build/Verificator.app` plus a `.dmg`, an Ed25519 signature (`.dmg.sig`), and a `SHA256SUMS.txt` checksum file under `dist/`.
- **`Yayimla.command`** (publish): first shows what it will do in dry-run mode. If you confirm, it packages the release and uploads it to GitHub Releases with a `v<version>` tag.

The same tasks from the terminal:

```bash
./Scripts/package.sh                  # tests + universal .app + .dmg + .dmg.sig + SHA256SUMS.txt
./Scripts/build_app.sh                # build/Verificator.app only
./Scripts/set-version.sh 1.2.1        # bump version (Support/Info.plist + AppInfo fallback)
./Scripts/release.sh --dry-run        # rehearse a release without sending anything
./Scripts/release.sh                  # package, tag and upload to GitHub Releases
swift test                            # run all unit, localization & forensic calibration tests
```

Requires Xcode 26 or later. See [DEVELOPMENT.md](DEVELOPMENT.md) for architecture details, [roadmap.md](.agents/context/roadmap.md) for milestones, and [CHANGELOG.md](CHANGELOG.md) for release notes. Coding agents start from [.agents/AGENTS.md](.agents/AGENTS.md); the local code knowledge graph is built with [Graphify](https://github.com/Graphify-Labs/graphify).

## License & Third-Party Notices

Verificator is licensed under the **GNU General Public License, version 3 only** ([GPL-3.0-only](LICENSE)); Copyright (C) 2026 Babadogan Tech and Edu. It comes with no warranty.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for system tool and framework attributions.
