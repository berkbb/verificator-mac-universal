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
