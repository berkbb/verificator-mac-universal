# User-Rejected Specifications & Anti-Feature Redlines

1. **No False Positives on Legitimate Local or Third-Party Apps:**
   - Never flag an application as `TAMPERED` or `WARNING` solely because its `Info.plist` modification timestamp differs from the main executable timestamp, or because it is an ad-hoc signed local build (`Arhivar`, `Curatare`, `Copiator`, `Redactor`, `Menkul`, `Radyo ILEF`, `RoCheck`, `VisionNative`).
2. **No Destructive File Operations:**
   - `Verificator` is strictly a read-only forensic auditing tool. Never modify, quarantine-strip, delete, or re-sign any file inside a target `.app` bundle.
3. **No Hardcoded UI Strings Outside `.lproj/Localizable.strings`:**
   - Every user-visible string must be resolved through `AppSettings.t(_:)` and backed by 1:1 keys in `tr.lproj`, `en.lproj`, and `ro.lproj`.
4. **No Editable External Text Editors for License Files:**
   - License documents (`Verificator-License.txt` and `Third-Party-Notices.txt`) must open in the in-app read-only `LicenseViewerSheet`, never in TextEdit or an external editor.
5. **No Homebrew Tap Cask, Finder QuickLook Extension, or PDF Document Security Auditing (User Rejected 2026-11-14):**
   - Do not add a `homebrew-tap` Cask, a Finder QuickLook preview extension, or PDF document security auditing to `Verificator`; keep `Verificator` scoped to binary, bundle, package, disk-image, and system forensic auditing.
