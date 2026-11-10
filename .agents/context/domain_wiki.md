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
- **Core Target (`VerificatorCore`):** `AppInfo`, `Localization` (`AppLanguage`, `StringTable`, `LKey`), `AppLog`, `AppUpdate` (`AppUpdateChecker`, `UpdateSignature`, `UpdateChecksums`), `ForensicModels`, and `ForensicScanner`.
- **Executable Target (`Verificator`):** `VerificatorApp`, `AppSettings`, `AppModel`, `LogStore`, `ContentView`, `SettingsView`, `AboutView`, `LicenseViewerSheet`, and `LogView`.
