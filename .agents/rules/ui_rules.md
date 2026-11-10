# UI Rules, Localization & SwiftUI Presentation Standards (`ui_rules.md`)

> **Memory Category:** Declarative Domain Rule
> **Source:** Project UI & localization governance (`Verificator`)
> **Version / Date:** 1.1.0 (2026-11-10)
> **Last Reviewed:** 2026-11-10
> **Change Summary:** Aligned with `Verificator` and `VerificatorCore` trilingual localization (`tr`, `en`, `ro`), Refresh (`⌘R`) toolbar & banner controls, and the macOS menu bar restart warning standard.
> **Scope:** Trilingual (`tr`, `en`, `ro`) `LKey` localization, one file per language, hardcoded string ban, read-only license viewer, and the in-app language switch restart notice.

---

## 1. Strict Ban on Hardcoded UI Strings, Mandatory 1:1 Exact Translation & Dedicated File per Language

- **Mandatory 1:1 Exact Translation (No Language Exceptions):** Whichever language is supported or added (`tr`, `en`, `ro`), every single string key must have an authentic, idiomatic, and exact 1:1 translation across all language tables.
- **Dedicated File per Language:** Each supported language must possess its own separate, dedicated localization file/table (`Resources/<lang>.lproj/Localizable.strings` and `InfoPlist.strings`).
- **Zero Fallback Tolerance:** Every user-visible string in `Sources/Verificator/` must be retrieved via `settings.t(.key)` using a case of `LKey` (`Sources/VerificatorCore/Localization.swift`).
- Format specifiers (`%@`, `%ld`, `%1$@`, `%2$@`, `%1$ld`) and argument counts must match 1:1 identically across all three languages.

---

## 2. macOS MenuBar, System Dialogs & In-App Language Switching Restart Warning Standard

- Whenever the user changes the application language in `SettingsView`, the UI **must** show an informative alert titled `restartWarningTitle` whose message is `restartMenuBarNotice`, and display the same `restartMenuBarNotice` as a footer notice in `SettingsView`.
- `AppSettings.applySystemLanguage()` writes `[language.rawValue]` to `"AppleLanguages"` in `UserDefaults` (or removes it when `.system` is selected) so the next cold launch updates Cocoa/AppKit system menus and file panels.
