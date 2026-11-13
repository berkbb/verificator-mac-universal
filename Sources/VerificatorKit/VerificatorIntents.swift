// SPDX-License-Identifier: GPL-3.0-only
import AppIntents
import Foundation
import VerificatorCore

@available(macOS 14.0, *)
public struct AuditApplicationIntent: AppIntent {
    public static let title: LocalizedStringResource = LocalizedStringResource(
        "intentTitle",
        defaultValue: "Audit with Verificator",
        bundle: .main
    )

    public static let description = IntentDescription(
        LocalizedStringResource(
            "intentDescription",
            defaultValue: "Run Verificator's read-only 4-layer forensic integrity audit on an app bundle, installer package, disk image, or Mach-O binary.",
            bundle: .main
        )
    )

    public static let openAppWhenRun: Bool = false

    @Parameter(
        title: LocalizedStringResource(
            "intentTargetParameterTitle",
            defaultValue: "Target File or App",
            bundle: .main
        )
    )
    public var targetFile: IntentFile?

    @Parameter(
        title: LocalizedStringResource(
            "fieldTargetKind",
            defaultValue: "Target Path",
            bundle: .main
        )
    )
    public var targetPath: String?

    public init() {}

    public func perform() async throws -> some IntentResult & ReturnsValue<String> & ProvidesDialog {
        let candidateURL: URL?
        if let fileURL = targetFile?.fileURL {
            candidateURL = fileURL
        } else if let targetPath, !targetPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            let expanded = NSString(string: targetPath).expandingTildeInPath
            candidateURL = URL(fileURLWithPath: expanded)
        } else {
            candidateURL = nil
        }

        guard let targetURL = candidateURL?.standardizedFileURL,
              FileManager.default.fileExists(atPath: targetURL.path) else {
            throw IntentError.targetNotFound
        }

        let scanOptions = await MainActor.run { AppSettings.shared.scanOptions }
        let language = await MainActor.run { AppSettings.shared.languageCode }

        let report = await Task.detached {
            ForensicScanner.auditTarget(at: targetURL, options: scanOptions)
        }.value

        let table = StringTable(bundle: .main)
        let verdictKey: LKey = switch report.verdict {
        case .clean: .verdictClean
        case .warning: .verdictWarning
        case .tampered: .verdictTampered
        }
        let verdictLabel = table.string(verdictKey, language: language)
        let summary = table.format(
            .intentResultSummary,
            language: language,
            report.bundleName,
            verdictLabel,
            report.findings.count
        )

        let jsonOutput = (try? report.jsonString(prettyPrinted: false)) ?? summary
        return .result(value: jsonOutput, dialog: IntentDialog(stringLiteral: summary))
    }

    private enum IntentError: Swift.Error, CustomLocalizedStringResourceConvertible {
        case targetNotFound

        var localizedStringResource: LocalizedStringResource {
            LocalizedStringResource(
                "serviceInvalidSelectionError",
                defaultValue: "Target file or application could not be found on disk.",
                bundle: .main
            )
        }
    }
}

@available(macOS 14.0, *)
public struct VerificatorShortcutsProvider: AppShortcutsProvider {
    public nonisolated static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: AuditApplicationIntent(),
            phrases: [
                "Audit app with \(.applicationName)",
                "Verify integrity with \(.applicationName)",
            ],
            shortTitle: LocalizedStringResource(
                "intentTitle",
                defaultValue: "Audit with Verificator",
                bundle: .main
            ),
            systemImageName: "checkmark.shield"
        )
    }
}
