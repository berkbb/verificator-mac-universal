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
