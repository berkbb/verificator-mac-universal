# Code-Graph Memory Wiki (`code_graph_wiki.md`)

> Regenerated from `graphify-out/GRAPH_REPORT.md` (585 nodes · 1,080 edges · 23 communities · 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · 0 import cycles).

## 1. Core God Nodes & High-Centrality Symbols

| Rank | Symbol | Edges | Module / File | Role |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `LKey` | 195 | `Sources/VerificatorCore/Localization.swift` | Trilingual (`tr`, `en`, `ro`) localization key enum |
| 2 | `AppSettings` | 44 | `Sources/Verificator/AppSettings.swift` | Observable user settings, language, appearance, shortcuts, recents |
| 3 | `AppLog` | 37 | `Sources/VerificatorCore/AppLog.swift` | Persistent TSV log writer (`~/Library/Logs/Verificator/Verificator.log`) |
| 4 | `ShortcutAction` | 25 | `Sources/Verificator/AppSettings.swift` | Customizable keyboard shortcut actions (`openBundle`, `refresh`, `reveal`, etc.) |
| 5 | `AppModel` | 24 | `Sources/Verificator/AppModel.swift` | Main scan orchestrator (`scan`, `refreshCurrentBundle`, `clearReport`, `checkForAppUpdate`) |
| 6 | `BundleAuditReport` | 21 | `Sources/VerificatorCore/ForensicModels.swift` | Immutable forensic audit report returned by `ForensicScanner.auditBundle` |
| 7 | `LogStore` | 20 | `Sources/Verificator/LogStore.swift` | MainActor observable bridge over `AppLog` for `LogView` |
| 8 | `KeyboardShortcutData` | 19 | `Sources/Verificator/AppSettings.swift` | Serializable key + modifier representation |
| 9 | `LicenseDocument` | 18 | `Sources/Verificator/Views/LicenseViewerSheet.swift` | Read-only bundled license & third-party notices loader |
| 10 | `ForensicScanner` | 16 | `Sources/VerificatorCore/ForensicScanner.swift` | 4-layer zero false-positive Mach-O, codesign, and dylib injection engine |

## 2. Module & Call Hierarchy

- **`VerificatorCore` (Framework Target):**
  - `ForensicScanner.auditBundle(at:options:)` → produces `BundleAuditReport` (`IntegrityVerdict`, `[ForensicFinding]`, `[LinkedDylibItem]`, `[BundledLibraryItem]`, `[HookSymbolCategory]`, `isQuarantined`) and logs to `AppLog.shared`.
  - `ForensicScanner.removeQuarantineWithAdminPrivileges(at:)` → executes `/usr/bin/xattr -rd com.apple.quarantine` via `osascript` with administrator privileges.
  - `LocalModels.swift` (`SuggestionProvider`, `LocalModelServer`, `OnDeviceSuggestionModel`, `LocalServerSuggestionModel`, `FallbackSuggestionModel`, `AIPrerequisites`, `ForensicAI`) → provides on-device Apple Intelligence, local Ollama, and LM Studio assessment.
  - `StringTable` & `AppLanguage` → loads `Resources/{tr,en,ro}.lproj/Localizable.strings`.
  - `AppUpdateChecker`, `UpdateSignature`, `UpdateChecksums` → GitHub Releases check, Ed25519 signature verification, SHA-256 digest parsing.
- **`Verificator` (Executable Target):**
  - `VerificatorApp` → hosts `ContentView` (`WindowID.main`), `AboutView` (`WindowID.about`), `LogView` (`WindowID.log`), and `SettingsView`, plus `AppCommands` menu bar commands (`⌘O`, `⌘R` Refresh, `⇧⌘R` Reveal, `⇧⌘C` Copy, `⌘S` Save, `⇧⌘W` Clear, `⌘K` Remove Quarantine, `⌥⌘L` Log).
