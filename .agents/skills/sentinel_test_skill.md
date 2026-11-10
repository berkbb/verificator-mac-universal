# Sentinel Test & Bundle Verification Skill (`sentinel_test_skill.md`)

## Purpose
Executes the full Swift Testing suite (`VerificatorTests`) and verifies that the packaged `Verificator.app` bundle satisfies all code-signing, plist, and 1:1 trilingual localization invariants.

## Authorized Commands
1. Run unit, localization, and forensic calibration tests:
   ```bash
   swift test
   ```
2. Build and verify the application bundle:
   ```bash
   ./Scripts/build_app.sh release
   ./Scripts/verify_bundle.sh build/Verificator.app
   ```

## Pass Criteria
- All 8 test cases in `VerificatorTests` pass with 0 failures.
- `Scripts/verify_bundle.sh` exits with code `0` (`✓ Paket doğrulandı`).
