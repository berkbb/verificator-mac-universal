// SPDX-License-Identifier: GPL-3.0-only
import Foundation

public struct AuditDiffEndpoint: Sendable, Equatable, Codable {
    public let sourceDescription: String
    public let isFromSavedJSON: Bool
    public let report: BundleAuditReport

    public init(sourceDescription: String, isFromSavedJSON: Bool, report: BundleAuditReport) {
        self.sourceDescription = sourceDescription
        self.isFromSavedJSON = isFromSavedJSON
        self.report = report
    }
}

public struct AuditMetadataChange: Identifiable, Sendable, Equatable, Codable {
    public let id: String
    public let fieldKey: LKey
    public let baselineValue: String
    public let targetValue: String
    public let baselineKey: LKey?
    public let targetKey: LKey?

    public init(
        fieldKey: LKey,
        baselineValue: String,
        targetValue: String,
        baselineKey: LKey? = nil,
        targetKey: LKey? = nil
    ) {
        self.id = fieldKey.rawValue
        self.fieldKey = fieldKey
        self.baselineValue = baselineValue
        self.targetValue = targetValue
        self.baselineKey = baselineKey
        self.targetKey = targetKey
    }

    public func localizedBaseline(with table: StringTable, language: String) -> String {
        if let baselineKey { return table.string(baselineKey, language: language) }
        return baselineValue
    }

    public func localizedTarget(with table: StringTable, language: String) -> String {
        if let targetKey { return table.string(targetKey, language: language) }
        return targetValue
    }
}

public struct AuditDiffFinding: Identifiable, Sendable, Equatable, Codable {
    public let id: UUID
    public let severity: FindingSeverity
    public let messageKey: LKey
    public let arg1: String
    public let arg2: String
    public let arg1Key: LKey?
    public let arg2Key: LKey?

    public init(
        id: UUID = UUID(),
        severity: FindingSeverity,
        messageKey: LKey,
        arg1: String = "",
        arg2: String = "",
        arg1Key: LKey? = nil,
        arg2Key: LKey? = nil
    ) {
        self.id = id
        self.severity = severity
        self.messageKey = messageKey
        self.arg1 = arg1
        self.arg2 = arg2
        self.arg1Key = arg1Key
        self.arg2Key = arg2Key
    }

    public func formattedMessage(with table: StringTable, language: String) -> String {
        let resolvedArg1 = arg1Key.map { table.string($0, language: language) } ?? arg1
        let resolvedArg2 = arg2Key.map { table.string($0, language: language) } ?? arg2
        if !resolvedArg1.isEmpty && !resolvedArg2.isEmpty {
            return table.format(messageKey, language: language, resolvedArg1, resolvedArg2)
        } else if !resolvedArg1.isEmpty {
            return table.format(messageKey, language: language, resolvedArg1)
        } else {
            return table.string(messageKey, language: language)
        }
    }
}

public struct AuditReportDiff: Sendable, Equatable, Codable {
    public let comparedAt: String
    public let baseline: AuditDiffEndpoint
    public let target: AuditDiffEndpoint
    public let metadataChanges: [AuditMetadataChange]
    public let addedEntitlements: [String]
    public let removedEntitlements: [String]
    public let addedRpaths: [String]
    public let removedRpaths: [String]
    public let addedLinkedDylibs: [String]
    public let removedLinkedDylibs: [String]
    public let addedBundledLibraries: [String]
    public let removedBundledLibraries: [String]
    public let addedHookCategories: [LKey]
    public let removedHookCategories: [LKey]
    public let securityFindings: [AuditDiffFinding]

    public var hasChanges: Bool {
        !metadataChanges.isEmpty
            || !addedEntitlements.isEmpty || !removedEntitlements.isEmpty
            || !addedRpaths.isEmpty || !removedRpaths.isEmpty
            || !addedLinkedDylibs.isEmpty || !removedLinkedDylibs.isEmpty
            || !addedBundledLibraries.isEmpty || !removedBundledLibraries.isEmpty
            || !addedHookCategories.isEmpty || !removedHookCategories.isEmpty
            || !securityFindings.isEmpty
    }

    public var regressionCount: Int {
        securityFindings.filter { $0.severity == .critical }.count
    }

    public var warningCount: Int {
        securityFindings.filter { $0.severity == .warning }.count
    }

    public func jsonData(prettyPrinted: Bool = true) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = prettyPrinted ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
        return try encoder.encode(self)
    }

    public func markdown(with table: StringTable, language: String) -> String {
        var md = "# \(table.string(.diffTitle, language: language))\n\n"
        md += "- **\(table.string(.diffBaselineHeader, language: language))**: \(baseline.report.bundleName) (`\(baseline.sourceDescription)`)\n"
        md += "- **\(table.string(.diffTargetHeader, language: language))**: \(target.report.bundleName) (`\(target.sourceDescription)`)\n"
        md += "- **\(table.string(.reportVerdictLabel, language: language))**: \(verdictText(baseline.report.verdict, table: table, language: language)) → \(verdictText(target.report.verdict, table: table, language: language))\n\n"

        md += "## \(table.string(.diffSectionRegressions, language: language))\n\n"
        if securityFindings.isEmpty {
            md += "- \(table.string(.diffSummaryMatches, language: language))\n"
        } else {
            for finding in securityFindings {
                md += "- [\(finding.severity.rawValue.uppercased())] \(finding.formattedMessage(with: table, language: language))\n"
            }
        }

        md += "\n## \(table.string(.diffSectionMetadata, language: language))\n\n"
        if metadataChanges.isEmpty {
            md += "- \(table.string(.diffNoChangesInSection, language: language))\n"
        } else {
            for change in metadataChanges {
                md += "- **\(table.string(change.fieldKey, language: language))**: \(change.localizedBaseline(with: table, language: language)) → \(change.localizedTarget(with: table, language: language))\n"
            }
        }

        appendSetSection(
            &md,
            title: table.string(.diffSectionEntitlements, language: language),
            added: addedEntitlements,
            removed: removedEntitlements,
            table: table,
            language: language
        )
        appendSetSection(
            &md,
            title: table.string(.diffSectionRpaths, language: language),
            added: addedRpaths,
            removed: removedRpaths,
            table: table,
            language: language
        )
        appendSetSection(
            &md,
            title: table.string(.diffSectionLinkedDylibs, language: language),
            added: addedLinkedDylibs,
            removed: removedLinkedDylibs,
            table: table,
            language: language
        )
        appendSetSection(
            &md,
            title: table.string(.diffSectionBundledLibraries, language: language),
            added: addedBundledLibraries,
            removed: removedBundledLibraries,
            table: table,
            language: language
        )
        appendSetSection(
            &md,
            title: table.string(.diffSectionHooks, language: language),
            added: addedHookCategories.map { table.string($0, language: language) },
            removed: removedHookCategories.map { table.string($0, language: language) },
            table: table,
            language: language
        )
        return md
    }

    private func appendSetSection(
        _ md: inout String,
        title: String,
        added: [String],
        removed: [String],
        table: StringTable,
        language: String
    ) {
        md += "\n## \(title)\n\n"
        if added.isEmpty && removed.isEmpty {
            md += "- \(table.string(.diffNoChangesInSection, language: language))\n"
            return
        }
        for item in added {
            md += "- `+ \(item)`\n"
        }
        for item in removed {
            md += "- `− \(item)`\n"
        }
    }

    private func verdictText(_ verdict: IntegrityVerdict, table: StringTable, language: String) -> String {
        switch verdict {
        case .clean: return table.string(.verdictClean, language: language)
        case .warning: return table.string(.verdictWarning, language: language)
        case .tampered: return table.string(.verdictTampered, language: language)
        }
    }
}

public enum AuditDiffError: LocalizedError, Sendable, Equatable {
    case unreadableJSON(String)
    case unsupportedInput(String)

    public var errorDescription: String? {
        switch self {
        case let .unreadableJSON(path):
            return "Could not decode saved audit JSON at \(path)"
        case let .unsupportedInput(path):
            return "Unsupported diff target: \(path)"
        }
    }
}

public enum AuditDiff {
    public static func compare(baseline: AuditDiffEndpoint, target: AuditDiffEndpoint) -> AuditReportDiff {
        let baseReport = baseline.report
        let newReport = target.report

        var metadataChanges: [AuditMetadataChange] = []

        if baseReport.targetKind != newReport.targetKind {
            metadataChanges.append(
                AuditMetadataChange(
                    fieldKey: .fieldTargetKind,
                    baselineValue: baseReport.targetKind.rawValue,
                    targetValue: newReport.targetKind.rawValue,
                    baselineKey: baseReport.targetKind.labelKey,
                    targetKey: newReport.targetKind.labelKey
                )
            )
        }
        if baseReport.verdict != newReport.verdict {
            metadataChanges.append(
                AuditMetadataChange(
                    fieldKey: .reportVerdictLabel,
                    baselineValue: baseReport.verdict.rawValue,
                    targetValue: newReport.verdict.rawValue,
                    baselineKey: verdictKey(baseReport.verdict),
                    targetKey: verdictKey(newReport.verdict)
                )
            )
        }
        let baseVer = "\(baseReport.shortVersion) (\(baseReport.buildVersion))"
        let newVer = "\(newReport.shortVersion) (\(newReport.buildVersion))"
        if baseVer != newVer {
            metadataChanges.append(AuditMetadataChange(fieldKey: .fieldVersion, baselineValue: baseVer, targetValue: newVer))
        }
        if baseReport.bundleId != newReport.bundleId {
            metadataChanges.append(AuditMetadataChange(fieldKey: .fieldBundleId, baselineValue: baseReport.bundleId, targetValue: newReport.bundleId))
        }
        if baseReport.teamIdentifier != newReport.teamIdentifier {
            metadataChanges.append(AuditMetadataChange(fieldKey: .fieldTeamId, baselineValue: baseReport.teamIdentifier, targetValue: newReport.teamIdentifier))
        }
        let baseAuth = baseReport.authorities.isEmpty ? "-" : baseReport.authorities.joined(separator: " → ")
        let newAuth = newReport.authorities.isEmpty ? "-" : newReport.authorities.joined(separator: " → ")
        if baseAuth != newAuth {
            metadataChanges.append(AuditMetadataChange(fieldKey: .fieldAuthorities, baselineValue: baseAuth, targetValue: newAuth))
        }
        if baseReport.cdHash != newReport.cdHash {
            metadataChanges.append(AuditMetadataChange(fieldKey: .fieldCdhash, baselineValue: baseReport.cdHash, targetValue: newReport.cdHash))
        }
        if baseReport.executableSHA256 != newReport.executableSHA256 {
            metadataChanges.append(
                AuditMetadataChange(
                    fieldKey: .fieldExecutableSha256,
                    baselineValue: shortDigest(baseReport.executableSHA256),
                    targetValue: shortDigest(newReport.executableSHA256)
                )
            )
        }
        let baseArch = baseReport.architectures.joined(separator: ", ")
        let newArch = newReport.architectures.joined(separator: ", ")
        if baseArch != newArch {
            metadataChanges.append(AuditMetadataChange(fieldKey: .fieldArchitectures, baselineValue: baseArch.isEmpty ? "-" : baseArch, targetValue: newArch.isEmpty ? "-" : newArch))
        }
        if baseReport.hasHardenedRuntime != newReport.hasHardenedRuntime {
            metadataChanges.append(
                AuditMetadataChange(
                    fieldKey: .fieldHardenedRuntime,
                    baselineValue: String(baseReport.hasHardenedRuntime),
                    targetValue: String(newReport.hasHardenedRuntime),
                    baselineKey: baseReport.hasHardenedRuntime ? .valueEnabled : .valueDisabled,
                    targetKey: newReport.hasHardenedRuntime ? .valueEnabled : .valueDisabled
                )
            )
        }
        if baseReport.isNotarized != newReport.isNotarized {
            metadataChanges.append(
                AuditMetadataChange(
                    fieldKey: .fieldNotarized,
                    baselineValue: String(baseReport.isNotarized),
                    targetValue: String(newReport.isNotarized),
                    baselineKey: baseReport.isNotarized ? .valueYes : .valueNo,
                    targetKey: newReport.isNotarized ? .valueYes : .valueNo
                )
            )
        }
        if baseReport.isQuarantined != newReport.isQuarantined {
            metadataChanges.append(
                AuditMetadataChange(
                    fieldKey: .fieldQuarantine,
                    baselineValue: String(baseReport.isQuarantined),
                    targetValue: String(newReport.isQuarantined),
                    baselineKey: baseReport.isQuarantined ? .valueQuarantined : .valueNotQuarantined,
                    targetKey: newReport.isQuarantined ? .valueQuarantined : .valueNotQuarantined
                )
            )
        }

        let addedEntitlements = setAdded(baseReport.entitlements, newReport.entitlements)
        let removedEntitlements = setRemoved(baseReport.entitlements, newReport.entitlements)
        let addedRpaths = setAdded(baseReport.lcRpaths, newReport.lcRpaths)
        let removedRpaths = setRemoved(baseReport.lcRpaths, newReport.lcRpaths)

        let baseLinked = baseReport.linkedDylibs.map(\.path)
        let newLinked = newReport.linkedDylibs.map(\.path)
        let addedLinkedDylibs = setAdded(baseLinked, newLinked)
        let removedLinkedDylibs = setRemoved(baseLinked, newLinked)

        let baseBundled = baseReport.bundledLibraries.map(\.name)
        let newBundled = newReport.bundledLibraries.map(\.name)
        let addedBundledLibraries = setAdded(baseBundled, newBundled)
        let removedBundledLibraries = setRemoved(baseBundled, newBundled)

        let baseHookKeys = Set(baseReport.hookCategories.map(\.categoryKey))
        let newHookKeys = Set(newReport.hookCategories.map(\.categoryKey))
        let addedHookCategories = newHookKeys.subtracting(baseHookKeys).sorted { $0.rawValue < $1.rawValue }
        let removedHookCategories = baseHookKeys.subtracting(newHookKeys).sorted { $0.rawValue < $1.rawValue }

        var securityFindings: [AuditDiffFinding] = []

        if verdictRank(newReport.verdict) > verdictRank(baseReport.verdict) {
            securityFindings.append(
                AuditDiffFinding(
                    severity: newReport.verdict == .tampered ? .critical : .warning,
                    messageKey: .diffRegressionVerdictWorse,
                    arg1: baseReport.verdict.rawValue,
                    arg2: newReport.verdict.rawValue,
                    arg1Key: verdictKey(baseReport.verdict),
                    arg2Key: verdictKey(newReport.verdict)
                )
            )
        }

        if baseReport.authorities != newReport.authorities {
            let severity: FindingSeverity = (newReport.verdict == .tampered || (!baseReport.authorities.isEmpty && newReport.authorities.isEmpty))
                ? .critical
                : .warning
            securityFindings.append(
                AuditDiffFinding(
                    severity: severity,
                    messageKey: .diffRegressionAuthorityChanged,
                    arg1: baseAuth,
                    arg2: newAuth
                )
            )
        }

        if baseReport.teamIdentifier != newReport.teamIdentifier && (baseReport.teamIdentifier != "-" || newReport.teamIdentifier != "-") {
            let droppedTeam = baseReport.teamIdentifier != "-" && newReport.teamIdentifier == "-"
            securityFindings.append(
                AuditDiffFinding(
                    severity: (droppedTeam || newReport.verdict == .tampered) ? .critical : .warning,
                    messageKey: .diffRegressionTeamChanged,
                    arg1: baseReport.teamIdentifier,
                    arg2: newReport.teamIdentifier
                )
            )
        }

        if !baseReport.isQuarantined && newReport.isQuarantined {
            securityFindings.append(
                AuditDiffFinding(
                    severity: .warning,
                    messageKey: .diffRegressionQuarantineAdded
                )
            )
        }

        for ent in addedEntitlements where EntitlementAnalyzer.isSensitiveEntitlement(ent) {
            securityFindings.append(
                AuditDiffFinding(
                    severity: .warning,
                    messageKey: .diffRegressionEntitlementAdded,
                    arg1: ent
                )
            )
        }

        let baseSuspiciousDylibs = Set(baseReport.linkedDylibs.filter { $0.isSuspicious || $0.isExternalSuspicious }.map(\.path))
        let newSuspiciousDylibs = Set(newReport.linkedDylibs.filter { $0.isSuspicious || $0.isExternalSuspicious }.map(\.path))
        for suspicious in newSuspiciousDylibs.subtracting(baseSuspiciousDylibs).sorted() {
            securityFindings.append(
                AuditDiffFinding(
                    severity: .critical,
                    messageKey: .diffRegressionSuspiciousDylibAdded,
                    arg1: suspicious
                )
            )
        }

        for hook in addedHookCategories {
            securityFindings.append(
                AuditDiffFinding(
                    severity: .critical,
                    messageKey: .diffRegressionHookAdded,
                    arg1: hook.rawValue,
                    arg1Key: hook
                )
            )
        }

        if baseReport.executableSHA256 != "-",
           newReport.executableSHA256 != "-",
           baseReport.executableSHA256 != newReport.executableSHA256 {
            securityFindings.append(
                AuditDiffFinding(
                    severity: .info,
                    messageKey: .diffRegressionBinaryChanged,
                    arg1: shortDigest(baseReport.executableSHA256),
                    arg2: shortDigest(newReport.executableSHA256)
                )
            )
        }

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        return AuditReportDiff(
            comparedAt: formatter.string(from: Date()),
            baseline: baseline,
            target: target,
            metadataChanges: metadataChanges,
            addedEntitlements: addedEntitlements,
            removedEntitlements: removedEntitlements,
            addedRpaths: addedRpaths,
            removedRpaths: removedRpaths,
            addedLinkedDylibs: addedLinkedDylibs,
            removedLinkedDylibs: removedLinkedDylibs,
            addedBundledLibraries: addedBundledLibraries,
            removedBundledLibraries: removedBundledLibraries,
            addedHookCategories: addedHookCategories,
            removedHookCategories: removedHookCategories,
            securityFindings: securityFindings
        )
    }

    public static func loadOrAudit(
        url: URL,
        options: ScanOptions = ScanOptions(),
        cancellation: ScanCancellationToken? = nil
    ) throws -> AuditDiffEndpoint {
        let standardized = url.standardizedFileURL
        if standardized.pathExtension.lowercased() == "json" {
            let data = try Data(contentsOf: standardized)
            guard let decoded = try? JSONDecoder().decode(BundleAuditReport.self, from: data) else {
                throw AuditDiffError.unreadableJSON(standardized.path)
            }
            return AuditDiffEndpoint(
                sourceDescription: standardized.path,
                isFromSavedJSON: true,
                report: decoded
            )
        }

        guard ForensicScanner.isSupportedAuditURL(standardized) else {
            throw AuditDiffError.unsupportedInput(standardized.path)
        }

        let report = ForensicScanner.auditTarget(at: standardized, options: options, cancellation: cancellation)
        return AuditDiffEndpoint(
            sourceDescription: standardized.path,
            isFromSavedJSON: false,
            report: report
        )
    }

    private static func setAdded(_ baseline: [String], _ target: [String]) -> [String] {
        Set(target).subtracting(baseline).sorted()
    }

    private static func setRemoved(_ baseline: [String], _ target: [String]) -> [String] {
        Set(baseline).subtracting(target).sorted()
    }

    private static func verdictRank(_ verdict: IntegrityVerdict) -> Int {
        switch verdict {
        case .clean: return 0
        case .warning: return 1
        case .tampered: return 2
        }
    }

    private static func verdictKey(_ verdict: IntegrityVerdict) -> LKey {
        switch verdict {
        case .clean: return .verdictClean
        case .warning: return .verdictWarning
        case .tampered: return .verdictTampered
        }
    }

    private static func shortDigest(_ value: String) -> String {
        guard value.count > 16 else { return value }
        return String(value.prefix(16)) + "…"
    }
}
