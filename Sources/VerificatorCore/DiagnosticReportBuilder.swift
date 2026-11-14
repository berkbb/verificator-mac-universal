// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// Single-click, local-only anonymized diagnostic bundle builder (`Copiator/Diagnostics` pattern).
/// Masks home directories, OS usernames, personal filenames, and target user paths via `DiagnosticMasker`.
public struct DiagnosticReportInput: Sendable {
    public let appVersion: String
    public let appBuild: String
    public let languageCode: String
    public let activeReport: BundleAuditReport?
    public let systemPosture: SystemSecurityPosture?
    public let managedKeys: [String]
    public let logLines: [String]
    public let extraSectionLines: [String]

    public init(
        appVersion: String = AppInfo.version,
        appBuild: String = AppInfo.build,
        languageCode: String = "en",
        activeReport: BundleAuditReport? = nil,
        systemPosture: SystemSecurityPosture? = nil,
        managedKeys: [String] = [],
        logLines: [String] = [],
        extraSectionLines: [String] = []
    ) {
        self.appVersion = appVersion
        self.appBuild = appBuild
        self.languageCode = languageCode
        self.activeReport = activeReport
        self.systemPosture = systemPosture
        self.managedKeys = managedKeys
        self.logLines = logLines
        self.extraSectionLines = extraSectionLines
    }
}

public enum DiagnosticReportBuilder {
    public static func buildMarkdown(
        from input: DiagnosticReportInput,
        masker: DiagnosticMasker = DiagnosticMasker(),
        now: Date = Date()
    ) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        var lines: [String] = []
        lines.append("# Verificator Diagnostic Report")
        lines.append("Generated: \(formatter.string(from: now))")
        lines.append("App Version: \(input.appVersion) (\(input.appBuild))")
        lines.append("macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)")
        #if arch(arm64)
        lines.append("Architecture: arm64")
        #elseif arch(x86_64)
        lines.append("Architecture: x86_64")
        #endif
        lines.append("Language: \(input.languageCode)")
        lines.append("MDM Managed Keys: \(input.managedKeys.isEmpty ? "none" : input.managedKeys.sorted().joined(separator: ", "))")

        if !input.extraSectionLines.isEmpty {
            lines.append("")
            lines.append("## Runtime State")
            for extra in input.extraSectionLines {
                lines.append("- \(masker.redact(text: extra))")
            }
        }

        lines.append("")
        lines.append("## Forensic CLI Tools")
        for tool in ForensicScanner.inspectTools() {
            lines.append("- \(tool.name) (`\(tool.path)`): \(tool.isAvailable ? "available" : "MISSING")")
        }

        if let rawPosture = input.systemPosture {
            let posture = rawPosture.redacted(using: masker)
            lines.append("")
            lines.append("## System Security Posture")
            lines.append("- SIP: \(posture.sipStatus.rawValue) — \(posture.sipDetail)")
            lines.append("- Signed System Volume (SSV): \(posture.ssvStatus.rawValue)")
            lines.append("- Gatekeeper: \(posture.gatekeeperMasterStatus.rawValue)")
            lines.append("- Boot FileVault: \(posture.fileVaultBootEncrypted.map { $0 ? "Encrypted" : "Unencrypted" } ?? "Unknown") (\(posture.bootVolumeFormat))")
            lines.append("- Firewall: \(posture.firewallEnabled.map { $0 ? "Enabled" : "Disabled" } ?? "Unknown") (Stealth: \(posture.firewallStealthMode.map { $0 ? "On" : "Off" } ?? "Unknown"))")
            lines.append("- Startup Disk S.M.A.R.T.: \(posture.smartHealthStatus.rawValue) (\(posture.smartDetail))")
            lines.append("- Full Disk Access: \(posture.fullDiskAccessGranted ? "Granted" : "Not Granted")")
            lines.append("- Orphaned Package Receipts: \(posture.orphanedReceipts.count) (audited \(posture.receiptsAuditedCount))")
        }

        if let rawReport = input.activeReport {
            let report = rawReport.redacted(using: masker)
            lines.append("")
            lines.append("## Active Audit Target (Masked)")
            lines.append("- Name: \(report.bundleName) (`\(report.bundleId)`)")
            lines.append("- Path: `\(report.bundlePath)`")
            lines.append("- Verdict: \(report.verdict.rawValue.uppercased()) (\(report.scanDurationMs) ms)")
            lines.append("- Team ID: \(report.teamIdentifier) | Hardened: \(report.hasHardenedRuntime) | Notarized: \(report.isNotarized) | DevCert: \(report.isDevelopmentSigned)")
            lines.append("- Quarantine: \(report.isQuarantined ? "ACTIVE" : "None")")
            lines.append("- Authorities: \(report.authorities.isEmpty ? "-" : report.authorities.joined(separator: " -> "))")
            lines.append("- Findings (\(report.findings.count)):")
            for finding in report.findings {
                let suffix = finding.detailSuffix.isEmpty ? "" : " — \(finding.detailSuffix)"
                lines.append("  - [\(finding.severity.rawValue.uppercased())] \(finding.titleKey.rawValue)\(suffix)")
            }
        }

        let tailLogs = input.logLines.suffix(40)
        if !tailLogs.isEmpty {
            lines.append("")
            lines.append("## Recent Diagnostic Logs (Masked)")
            for line in tailLogs {
                lines.append(masker.redact(text: line))
            }
        }

        return lines.joined(separator: "\n")
    }
}
