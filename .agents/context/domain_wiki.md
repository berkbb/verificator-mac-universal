# Domain Wiki — macOS Bundle Forensics & Mach-O Integrity Architecture

## 1. Domain Overview

`Verificator` inspects macOS `.app` bundles to determine whether an application is authentic (`CLEAN`), has non-critical anomalies (`WARNING`), or has been modified by a third-party patcher/injector (`TAMPERED`).

## 2. Four-Layer Forensic Pipeline (`ForensicScanner`)

1. **Layer 1 — Primary Code Signature & Authority Chain (`/usr/bin/codesign -dvvv`, `--verify --no-strict`):**
   - Extracts `TeamIdentifier`, `Authority` chain, `Signed Time` / `Timestamp`, `CodeDirectory` flags (`runtime`), `Notarization Ticket`, and `CDHash`.
   - Distinguishes between Official Apple Root CA chains (`Developer ID Application`, `Apple Mac OS Application Signing`, `Software Signing`), local ad-hoc developer builds, and unofficial/self-signed crack certificates (e.g., `TEAM EDiSO`).
2. **Layer 2 — Bundled Library Signature & Provenance Comparison (`Contents/MacOS` & `Contents/Frameworks`):**
   - Inspects every `.dylib` and `.framework` inside the bundle.
   - Detects **Signature Hijacking**: when embedded vendor frameworks still carry an official Apple `Developer ID Application` signature (`TeamIdentifier != not set`), while the main executable's signature was stripped and replaced with an ad-hoc or third-party authority, or when an injected dylib in `Contents/MacOS/` carries a different signer than the vendor frameworks.
3. **Layer 3 — Mach-O Load Command Audit (`/usr/bin/otool -L`):**
   - Parses `LC_LOAD_DYLIB` and `LC_LOAD_WEAK_DYLIB` entries of the main executable.
   - Flags non-system `@executable_path/` or `@rpath/` dylibs that correlate with signature mismatch or known injection patterns without false-flagging legitimate CMake/Electron/SwiftPM dylibs.
4. **Layer 4 — Undefined Symbol & Runtime Hook Analysis (`/usr/bin/nm -u`, `/usr/bin/strings`):**
   - Categorizes imported hook symbols across suspicious dylibs into:
     - **Objective-C Swizzling:** `_method_exchangeImplementations`, `_class_replaceMethod`, `_imp_implementationWithBlock`.
     - **Mach VM Patching:** `_mach_vm_protect`, `_mach_vm_write`, `_mach_vm_remap`, `_mach_task_self_`.
     - **DYLD ASLR Slide Inspection:** `__dyld_get_image_vmaddr_slide`, `__dyld_get_image_header`, `__dyld_register_func_for_add_image`.

## 3. Sibling App Architecture Parity

`Verificator` follows the exact structural conventions of its sibling macOS Universal apps (`Arhivar`, `Curatare`, `Copiator`, `Redactor`):
- **Core Target (`VerificatorCore`):** `AppInfo`, `Localization` (`AppLanguage`, `StringTable`, `LKey`), `AppLog`, `AppUpdate` (`AppUpdateChecker`, `UpdateSignature`, `UpdateChecksums`), `ForensicModels`, `ForensicScanner`, and `LocalModels` (`ForensicAI`, `LocalModelServer`, `AIPrerequisites`).
- **Executable Target (`Verificator`):** `VerificatorApp`, `AppSettings`, `AppModel`, `LogStore`, `ContentView`, `SettingsView`, `AboutView`, `LicenseViewerSheet`, and `LogView`.

## 4. Quarantine Inspection & Administrator Elevation (`com.apple.quarantine`)

- **Quarantine Attribute Detection:** Inspects `com.apple.quarantine` on the `.app` root and `Contents/MacOS/<exec>` via `getxattr(..., "com.apple.quarantine", nil, 0, 0, XATTR_NOFOLLOW)`.
- **Dynamic Action:** When `report.isQuarantined == true`, an interactive **Remove Quarantine (sudo xattr)** action is exposed in the verdict banner and menu bar (`⌘K`).
- **Administrator Privileges:** Prompts macOS native Touch ID / password prompt via `/usr/bin/osascript` with administrator privileges to execute `/usr/bin/xattr -rd com.apple.quarantine <bundlePath>`.
- **First-Launch Gatekeeper Warning:** Because Verificator is ad-hoc signed, downloading from GitHub Releases attaches quarantine, requiring either right-click Open, allowing in **System Settings › Privacy & Security**, or `xattr -dr com.apple.quarantine /Applications/Verificator.app`.

## 5. On-Device AI Architecture (`ForensicAI`)

- **Model Sources:**
  - `Apple Intelligence` (`.apple`): Default first provider on macOS 26+ via Apple `FoundationModels` framework (`SystemLanguageModel.default`).
  - `Ollama` (`.ollama`): Talks exclusively to `127.0.0.1:11434`; filters out cloud/embedding models.
  - `LM Studio` (`.lmStudio`): Talks exclusively to `127.0.0.1:1234`; filters out embedding models.
  - `Automatic` (`.automatic`): Sequential fallback across enabled providers; silent recovery only in this mode.
- **No-Silent-Switch Policy:** When a specific provider is chosen, Verificator does not secretly fall back to another model if the chosen provider is offline or missing local models; it warns with an amber badge and waits.
- **In-Window Selector:** Available directly in the AI Assistant card within the main window as well as the Settings window.
