# Symbolic Short-Term Memory Topo-Graph

```mermaid
stateDiagram-v2
    [*] --> Idle: Launch Verificator
    Idle --> Scanning: Select .app / Drag & Drop / Recent Bundle
    Idle --> BatchScanning: Drop Folder / Batch Scan (Opt+Cmd+B)
    Scanning --> CleanVerdict: 0 Critical & 0 Warning Findings
    Scanning --> WarningVerdict: Non-Critical Signature Anomaly
    Scanning --> TamperedVerdict: Crack Authority / Signature Hijack / Dylib Injection
    Scanning --> Idle: Cancel Scan
    BatchScanning --> BatchReady: Scan Complete or Cancelled (Partial)
    CleanVerdict --> Scanning: Refresh (Cmd+R)
    WarningVerdict --> Scanning: Refresh (Cmd+R)
    TamperedVerdict --> Scanning: Refresh (Cmd+R)
    CleanVerdict --> Idle: Close Report (Shift+Cmd+W)
    WarningVerdict --> Idle: Close Report (Shift+Cmd+W)
    TamperedVerdict --> Idle: Close Report (Shift+Cmd+W)
    BatchReady --> Idle: Close Report (Shift+Cmd+W)
```

## Node ID Lookup Table

| Node ID | Component | Source File | Responsibility |
| :--- | :--- | :--- | :--- |
| `N01` | `VerificatorMain` | `Sources/Verificator/VerificatorMain.swift` | Thin app entry point launching `VerificatorApp` |
| `N02` | `VerificatorApp` | `Sources/VerificatorKit/VerificatorApp.swift` | Main Window, About Window, Log Window, Settings, MenuBarExtra, Menu Commands |
| `N03` | `AppModel` | `Sources/VerificatorKit/AppModel.swift` | Scan, batch, diff, posture, signature alerts, watched folders, diagnostics, settings transfer, updates |
| `N04` | `AppSettings` | `Sources/VerificatorKit/AppSettings.swift` | Language (`tr`/`en`/`ro`), appearance, MDM locks, watched folders, menu bar toggle, portable transfer |
| `N05` | `ForensicScanner` | `Sources/VerificatorCore/ForensicScanner.swift` | 4-layer Mach-O, SHA-256/512, codesign, spctl, lipo, AppleDouble, symlink safety, JIT calibration |
| `N06` | `ContentView` | `Sources/VerificatorKit/Views/ContentView.swift` | Master-detail SwiftUI interface, single-target, batch, diff, posture & system audit routing |
| `N07` | `SettingsView` | `Sources/VerificatorKit/Views/SettingsView.swift` | General, Scan, Shortcuts, and Engine/Transfer/Updates tabs with MDM-lock awareness |
| `N08` | `LogView` / `AppLog` | `Sources/VerificatorKit/Views/LogView.swift` | Persistent forensic audit log viewer and Console integration |
| `N09` | `AboutView` | `Sources/VerificatorKit/Views/AboutView.swift` | App metadata, repository links, and read-only license sheets |
| `N10` | `VerificatorCLI` | `Sources/VerificatorCLI/main.swift` | Headless CLI (`verificator-cli`) supporting single, `--batch`, `--diff`, `--running`, `--persistence`, `--posture`, `--lang`, `--json`, `--spctl` |
| `N11` | `AuditDiff` & `DiffView` | `Sources/VerificatorCore/AuditDiff.swift`, `Sources/VerificatorKit/Views/DiffView.swift` | Side-by-side comparison of targets or JSON audit reports (`⇧⌘D`) |
| `N12` | `EntitlementAnalyzer` | `Sources/VerificatorCore/EntitlementAnalyzer.swift` | Informational security entitlement badge classifier (non-verdict-mutating) |
| `N13` | `SystemAudit` & `SystemAuditView` | `Sources/VerificatorCore/SystemAudit.swift`, `Sources/VerificatorKit/Views/SystemAuditView.swift` | Running processes + `KernelSocketList` (`⌥⌘P`), persistence (`⌥⌘T`), and security posture (`⌥⌘G`) auditors |
| `N14` | `VerificatorIntents` | `Sources/VerificatorKit/VerificatorIntents.swift` | Shortcuts & Spotlight `AppIntents` (`AuditApplicationIntent`, `VerificatorShortcutsProvider`) |
| `N15` | `SystemSecurityChecks`, `SystemSecurityPosture`, `SignatureTracker`, `ChildProcessGuard` | `Sources/VerificatorCore/{SystemSecurityChecks,SystemSecurityPosture,SignatureTracker,ChildProcessGuard}.swift` | Gatekeeper status, FDA probe, host security posture & orphaned receipts, OCSP revocation, signature history, orphan child reaping |
| `N16` | `LaunchServicesRegistration` & `SystemIntegrationServices` | `Sources/VerificatorKit/{LaunchServicesRegistration,SystemIntegrationServices}.swift` | Per-build `LSRegisterURL`, `NotificationService`, `LoginItemService`, `WatchedFolderService` |
| `N17` | `DiagnosticReportBuilder`, `ManagedConfiguration`, `SettingsTransfer`, `BundleDirectorySafety` | `Sources/VerificatorCore/{DiagnosticReportBuilder,ManagedConfiguration,SettingsTransfer,BundleDirectorySafety}.swift` | Anonymized Markdown diagnostics, MDM preference locks, portable JSON transfer, POSIX AppleDouble & symlink audits |
| `N18` | `DiagnosticSheet` & `SignatureChangeAlertSheet` | `Sources/VerificatorKit/Views/{DiagnosticSheet,SignatureChangeAlertSheet}.swift` | Modal UI sheets for masked diagnostic export and proactive signer-change confirmation |
