# Third-Party Notices

**Verificator** is a native macOS universal (`arm64` + `x86_64`) forensic bundle inspection application developed by **Babadogan Tech and Edu** under the `GPL-3.0-only` license.

## System Command-Line Utilities Invoked Out-of-Process

Verificator does not bundle or link against any third-party proprietary or copyleft binary libraries. It invokes official Apple macOS / Xcode Command Line Tools out-of-process (`Foundation.Process`) in read-only mode:

1. **`/usr/bin/codesign`** — Apple Code Signing Inspection & Verification Tool (macOS System Utility).
2. **`/usr/sbin/spctl`** — Apple SecAssessment / Gatekeeper Policy Control Utility (macOS System Utility).
3. **`/usr/bin/otool`** — Apple Mach-O Object File Displaying Tool (`LC_LOAD_DYLIB`, `LC_RPATH` inspection).
4. **`/usr/bin/lipo`** — Apple Universal Binary Architecture Inspection Utility (`-archs`).
5. **`/usr/bin/nm`** — Apple Symbol Table Inspection Utility (`nm -u` undefined symbol audit).
6. **`/usr/bin/strings`** — Printable String Extraction Utility.
7. **`/usr/bin/xattr` & `/usr/bin/osascript`** — Extended Attribute Inspection and User-Authorized Quarantine Removal Utilities.

## Apple System Frameworks

- **SwiftUI**, **AppKit**, **Foundation**, **FoundationModels**, **CryptoKit**, **Security**, **UniformTypeIdentifiers**, **Synchronization**, **os.log** — © Apple Inc. Used under the macOS SDK and Xcode license terms.
