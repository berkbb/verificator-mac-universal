# Verificator — Agent Constitution & L3 Persona Governance (`AGENTS.md`)

> **Mandatory Language Rule:** All files inside the `.agents/` directory — including `AGENTS.md`, `context/`, `rules/`, and `skills/` subdirectories — **MUST** be written exclusively in English.

## 1. Repository Identity & Core Mission

- **Application Name:** `Verificator`
- **Bundle Identifier:** `com.babadogantech.verificator`
- **Target Platform:** Native macOS 26+ Universal (Apple Silicon `arm64` + Intel `x86_64`), Swift 6.2 (`StrictConcurrency`, `@MainActor` UI isolation).
- **Mission:** Read-only 4-layer macOS application bundle (`.app`) forensic auditor that detects third-party dylib injection, code signature hijacking, Mach-O load-command tampering (`LC_LOAD_DYLIB`, `LC_LOAD_WEAK_DYLIB`), Objective-C runtime method swizzling, and Mach virtual memory patching (`mach_vm_protect`, `mach_vm_write`, `_dyld_get_image_vmaddr_slide`) with **0% false positives** on legitimate Apple, App Store, Developer ID, and local ad-hoc builds.

## 2. Constitutional Invariants (Non-Negotiable)

1. **Read-Only Forensic Guarantee:** `ForensicScanner` must never mutate, strip, re-sign, or modify any inspected `.app` bundle on disk. All inspections use read-only system tools (`/usr/bin/codesign`, `/usr/sbin/spctl`, `/usr/bin/otool`, `/usr/bin/nm`, `/usr/bin/strings`).
2. **Zero False Positives (0% FP) Invariant:**
   - Legitimate Apple system apps, App Store apps, notarized Developer ID apps, Electron/Chromium apps, CMake/Homebrew-bundled apps, and local ad-hoc developer builds (`Arhivar`, `Curatare`, `Copiator`, `Redactor`, `Menkul`, `Radyo ILEF`, `RoCheck`, `VisionNative`) **MUST** evaluate to `IntegrityVerdict.clean`.
   - `IntegrityVerdict.tampered` is triggered only when corroborated by:
     - Known crack/patcher signing authority (`TEAM EDiSO`, `TNT`, `HCiSO`, ` Core Keygen`, etc.), OR
     - Authority/Signer mismatch between the main executable and an injected library in `Contents/MacOS/` or `Contents/Frameworks/` where the main bundle's official vendor signature was stripped to ad-hoc/unsigned, OR
     - Unofficial non-Apple CA chain combined with dylib hooking indicators.
3. **1:1 Trilingual Localization Parity (`tr`, `en`, `ro`):**
   - Every user-facing string key in `LKey` must exist with a non-empty translation in `Resources/tr.lproj/Localizable.strings`, `Resources/en.lproj/Localizable.strings`, and `Resources/ro.lproj/Localizable.strings`, as well as `InfoPlist.strings`.
   - All multi-argument format strings must use explicit positional specifiers (`%1$@`, `%2$@`, `%1$ld`).
   - Changing the language in `SettingsView` must trigger the macOS menu bar & system dialog restart notice (`restartWarningTitle` / `restartMenuBarNotice`).
4. **Graphify-First Navigation:**
   - Before performing broad codebase searches, consult `.agents/context/code_graph_wiki.md` and `graphify-out/GRAPH_REPORT.md`.

## 3. TencentDB Agent Memory Four-Tier Mapping (L0–L3)

| Tier | Memory Layer | Repository Artifact |
| :--- | :--- | :--- |
| **L0** | Execution & Audit Logs | `~/Library/Logs/Verificator/Verificator.log` (`AppLog` / `LogStore`) |
| **L1** | Atomic Parameters | `AppSettings` (`UserDefaults`), `ScanOptions`, `ShortcutAction` bindings |
| **L2** | Scenario / Engine State | `AppModel` (`currentBundleURL`, `report`, `isScanning`, `appUpdateStatus`) |
| **L3** | Persona & Governance | `.agents/AGENTS.md`, `.agents/rules/*.md`, `.agents/context/*.md`, `.agents/skills/*.md` |

## 4. Quarantine Invariant & Administrator Elevation Boundary

1. **Detection:** All audited bundles are inspected for `com.apple.quarantine` extended attributes using `getxattr` and `xattr -p`.
2. **Dynamic UI Action:** When `report.isQuarantined == true`, an explicit **Remove Quarantine** action (`⌘K`) is exposed in the verdict banner.
3. **Privileged Execution:** Stripping quarantine invokes `/usr/bin/osascript ... with administrator privileges` to run `/usr/bin/xattr -rd com.apple.quarantine <bundlePath>`. This prompts native macOS Touch ID or admin password elevation and automatically re-audits the bundle upon completion.
4. **Gatekeeper First-Launch Invariant:** Verificator is ad-hoc signed and not notarized. First-launch quarantine warnings must be clearly documented across `README.md` and `CHANGELOG.md` with GUI (right-click Open) and CLI (`xattr -dr com.apple.quarantine /Applications/Verificator.app`) workarounds.

## 5. On-Device AI Boundary

1. **Locality Invariant:** All AI evaluations must run strictly on this Mac. External cloud APIs, remote proxy tunnels, and cloud-hosted LLM endpoints are strictly banned.
2. **Provider Hierarchy:** Apple Intelligence (`FoundationModels`) is the first and default provider, followed by local Ollama (`127.0.0.1:11434`) and LM Studio (`127.0.0.1:1234`).
3. **No-Silent-Switch Invariant:** If a user chooses a specific provider that is offline or lacks local chat models, the engine must never silently switch to another provider; it must surface a diagnostic amber warning and wait. Silent fallback is restricted to `Automatic` mode.
4. **Advisory Role Only:** The AI model generates explanatory summaries of deterministic forensic findings and is strictly forbidden from mutating the deterministic `IntegrityVerdict`.
