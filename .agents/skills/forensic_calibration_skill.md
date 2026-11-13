# Forensic Calibration Skill (`forensic_calibration_skill.md`)

## Purpose
Ensures the 4-layer `ForensicScanner` maintains **0% false positives** across legitimate Apple, App Store, Developer ID, and local ad-hoc bundles while accurately detecting tampered/injected bundles.

## Invariants Checked
1. Official Apple Root CA signed bundles (`Developer ID Application`, `Apple Mac OS Application Signing`, `Software Signing`) evaluate to `IntegrityVerdict.clean`.
2. Local ad-hoc developer builds (`Arhivar`, `Curatare`, `Copiator`, `Redactor`, `Menkul`, `Radyo ILEF`, `RoCheck`, `VisionNative`) evaluate to `IntegrityVerdict.clean`.
3. Bundles signed by known patcher authorities (`TEAM EDiSO`, `TNT`, etc.) or exhibiting framework-vs-executable signature stripping with injected dylibs evaluate to `IntegrityVerdict.tampered`.
4. Active quarantine calibration: bundles whose `com.apple.quarantine` attribute is absent, malformed, or already user-approved (`0x0040` `QTN_FLAG_USER_APPROVED`, e.g. `01c3`/`00c3`/`01c1` in `/Applications`) evaluate to `isQuarantined == false`; only active unapproved quarantine (`0xC040` bits clear, matching `URLResourceKey.quarantinePropertiesKey`) exposes the **Remove Quarantine** UI action.
