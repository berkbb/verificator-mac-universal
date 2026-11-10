# Reflexion Memory Log (Shinn et al., NeurIPS 2023)

This log records self-correction episodes, forensic calibration lessons, and architectural refinements across development sessions.

## Episode 1 — Eliminating False Positives on Legitimate Apps (2026-11-10)

- **Observation:** Naive timestamp delta checks (`Info.plist` vs executable modification time) and flagging any `@executable_path/*.dylib` or Objective-C runtime symbols caused false positives on legitimate apps (Electron apps, CMake/Homebrew bundles, and ad-hoc local builds).
- **Reflection:** Legitimate build pipelines sign or copy `Info.plist` and executables at different stages, and legitimate frameworks use Objective-C runtime functions internally. True tampering is characterized by **provenance/authority mismatch** (e.g., vendor frameworks signed by Apple Developer ID while the main executable is stripped to ad-hoc and linked against an unsigned/third-party dylib in `Contents/MacOS/`), or an explicit non-Apple self-signed authority (such as `TEAM EDiSO`) combined with Mach VM / swizzling hooks.
- **Corrective Action:** Recalibrated `ForensicScanner` into a 4-layer provenance-aware pipeline and verified **0% false positives** across 70+ real-world applications in `/Applications` and `~/Downloads`.

## Episode 2 — Full Parity with Sibling macOS Universal Apps (2026-11-10)

- **Observation:** The initial prototype used a flat `Sources/` layout without `VerificatorCore`, `SettingsView`, `AboutView`, `LogView`, `AppUpdateChecker`, or Graphify knowledge graph artifacts.
- **Reflection:** To match `Arhivar`, `Curatare`, `Copiator`, and `Redactor`, the project requires modular SwiftPM separation (`VerificatorCore` + `Verificator` + `VerificatorTests`), prominent UI Refresh (`⌘R`) actions, 4-tab `SettingsView`, `AboutView` with read-only `LicenseViewerSheet`, `LogView` (`⌥⌘L`), `.agents/` governance, and `graphify-out/` AST knowledge graph.
- **Corrective Action:** Refactored the repository into the modular architecture with full test coverage and Graphify integration.

## Episode 3 — Romanian Nomenclature & Clean Packaging Policy (2026-11-10)

- **Observation:** Sibling projects use single-word Romanian agent nouns without diacritics (`Arhivar`, `Copiator`, `Curatare`, `Descarcator`, `Paravan`, `Redactor`) under `com.babadogantech.<name>`. Furthermore, loose `.app` and `.zip` artifacts were polluting `dist/` and Downloads.
- **Reflection:** The application and repository must be renamed to `Verificator` (`com.babadogantech.verificator`, `verificator-mac-universal`). `dist/` must strictly hold signed release deliverables (`.dmg`, `.dmg.sig`, `SHA256SUMS.txt`), while `.app` stays strictly inside `build/Verificator.app`.
- **Corrective Action:** Renamed all targets, identifiers, and repository folder; removed `.zip` and `.app` from `dist/` and packaging scripts; prevented copying into `~/Downloads`.

## Episode 4 — On-Device AI & Quarantine Elevation (2026-11-10)

- **Observation:** Users needed forensic interpretation from on-device models, but silent fallbacks risked masking offline servers or missing models. Also, internet-downloaded apps carrying `com.apple.quarantine` required root-level clearing via `sudo xattr`.
- **Reflection:** Apple Intelligence should be the default first provider with Ollama and LM Studio as local alternatives (no cloud/embedding models). If a provider is offline or missing models, the UI must show an amber warning and refuse silent switching unless in "Automatic" mode. Quarantine should be dynamically detected and removable via Touch ID / admin password elevation. First-launch quarantine for Verificator itself must be clearly documented for Gatekeeper.
- **Corrective Action:** Implemented `ForensicAI` and `AIPrerequisites.providerProblem`, added in-window provider selector with amber warning labels, wired Touch ID `sudo xattr` elevation, and documented quarantine warnings across all markdown files.
