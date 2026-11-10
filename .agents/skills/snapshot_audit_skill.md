# Snapshot & Localization Audit Skill (`snapshot_audit_skill.md`)

## Purpose
Audits 1:1 localization key parity and positional format specifiers across `Resources/tr.lproj`, `Resources/en.lproj`, and `Resources/ro.lproj` (`Localizable.strings` and `InfoPlist.strings`).

## Verification Procedure
1. Validate property list syntax for all localization files:
   ```bash
   plutil -lint Resources/tr.lproj/*.strings Resources/en.lproj/*.strings Resources/ro.lproj/*.strings Support/Info.plist
   ```
2. Run the automated parity tests:
   ```bash
   swift test --filter VerificatorTests
   ```
