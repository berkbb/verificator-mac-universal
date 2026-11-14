// SPDX-License-Identifier: GPL-3.0-only
import Foundation

public enum IntegrityVerdict: String, Sendable, Equatable, Codable {
    case clean
    case warning
    case tampered
}

public enum AuditTargetKind: String, Sendable, Equatable, Codable, CaseIterable {
    case appBundle
    case installerPackage
    case diskImage
    case nestedBundle
    case standaloneMachO

    public var labelKey: LKey {
        switch self {
        case .appBundle: return .targetKindApp
        case .installerPackage: return .targetKindPkg
        case .diskImage: return .targetKindDmg
        case .nestedBundle: return .targetKindNested
        case .standaloneMachO: return .targetKindMachO
        }
    }
}

public enum FindingSeverity: String, Sendable, Equatable, Codable {
    case critical
    case warning
    case info
}

public struct ForensicFinding: Identifiable, Sendable, Equatable, Codable {
    public let id: UUID
    public let severity: FindingSeverity
    public let titleKey: LKey
    public let descKey: LKey
    public let detailSuffix: String

    public init(
        id: UUID = UUID(),
        severity: FindingSeverity,
        titleKey: LKey,
        descKey: LKey,
        detailSuffix: String = ""
    ) {
        self.id = id
        self.severity = severity
        self.titleKey = titleKey
        self.descKey = descKey
        self.detailSuffix = detailSuffix
    }
}

public struct LinkedDylibItem: Identifiable, Sendable, Equatable, Codable {
    public let id: UUID
    public let path: String
    public let isSystem: Bool
    public let isSuspicious: Bool
    public let isExternalSuspicious: Bool

    public init(
        id: UUID = UUID(),
        path: String,
        isSystem: Bool,
        isSuspicious: Bool,
        isExternalSuspicious: Bool = false
    ) {
        self.id = id
        self.path = path
        self.isSystem = isSystem
        self.isSuspicious = isSuspicious
        self.isExternalSuspicious = isExternalSuspicious
    }
}

public struct BundledLibraryItem: Identifiable, Sendable, Equatable, Codable {
    public let id: UUID
    public let name: String
    public let modifiedDate: String
    public let sizeBytes: Int64
    public let isTimestampAnomaly: Bool
    public let suspiciousSymbols: [String]
    public let targetStrings: [String]

    public init(
        id: UUID = UUID(),
        name: String,
        modifiedDate: String,
        sizeBytes: Int64,
        isTimestampAnomaly: Bool,
        suspiciousSymbols: [String],
        targetStrings: [String]
    ) {
        self.id = id
        self.name = name
        self.modifiedDate = modifiedDate
        self.sizeBytes = sizeBytes
        self.isTimestampAnomaly = isTimestampAnomaly
        self.suspiciousSymbols = suspiciousSymbols
        self.targetStrings = targetStrings
    }
}

public struct HookSymbolCategory: Identifiable, Sendable, Equatable, Codable {
    public let id: UUID
    public let libraryName: String
    public let categoryKey: LKey
    public let symbols: [String]

    public init(
        id: UUID = UUID(),
        libraryName: String,
        categoryKey: LKey,
        symbols: [String]
    ) {
        self.id = id
        self.libraryName = libraryName
        self.categoryKey = categoryKey
        self.symbols = symbols
    }
}

public struct ScanOptions: Sendable, Equatable, Codable {
    public var deepFrameworkSignatureCheck: Bool
    public var extractTargetStrings: Bool
    public var includeGatekeeperAssessment: Bool
    public var checkCertificateRevocation: Bool
    public var checkApplicationFirewall: Bool
    public var policyLanguages: [String]

    enum CodingKeys: String, CodingKey {
        case deepFrameworkSignatureCheck
        case extractTargetStrings
        case includeGatekeeperAssessment
        case checkCertificateRevocation
        case checkApplicationFirewall
        case policyLanguages
    }

    public init(
        deepFrameworkSignatureCheck: Bool = true,
        extractTargetStrings: Bool = true,
        includeGatekeeperAssessment: Bool = false,
        checkCertificateRevocation: Bool = false,
        checkApplicationFirewall: Bool = true,
        policyLanguages: [String] = ["en"]
    ) {
        self.deepFrameworkSignatureCheck = deepFrameworkSignatureCheck
        self.extractTargetStrings = extractTargetStrings
        self.includeGatekeeperAssessment = includeGatekeeperAssessment
        self.checkCertificateRevocation = checkCertificateRevocation
        self.checkApplicationFirewall = checkApplicationFirewall
        self.policyLanguages = policyLanguages.isEmpty ? ["en"] : policyLanguages
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.deepFrameworkSignatureCheck = try container.decodeIfPresent(Bool.self, forKey: .deepFrameworkSignatureCheck) ?? true
        self.extractTargetStrings = try container.decodeIfPresent(Bool.self, forKey: .extractTargetStrings) ?? true
        self.includeGatekeeperAssessment = try container.decodeIfPresent(Bool.self, forKey: .includeGatekeeperAssessment) ?? false
        self.checkCertificateRevocation = try container.decodeIfPresent(Bool.self, forKey: .checkCertificateRevocation) ?? false
        self.checkApplicationFirewall = try container.decodeIfPresent(Bool.self, forKey: .checkApplicationFirewall) ?? true
        self.policyLanguages = try container.decodeIfPresent([String].self, forKey: .policyLanguages) ?? ["en"]
    }
}

public struct ToolStatus: Identifiable, Sendable, Equatable {
    public var id: String { name }
    public let name: String
    public let path: String
    public let isAvailable: Bool

    public init(name: String, path: String, isAvailable: Bool) {
        self.name = name
        self.path = path
        self.isAvailable = isAvailable
    }
}

public enum QuarantineRemovalStatus: String, Sendable, Equatable {
    case success
    case cancelled
    case failed
}

public struct QuarantineRemovalResult: Sendable, Equatable {
    public let status: QuarantineRemovalStatus
    public let message: String

    public var isSuccess: Bool { status == .success }
    public var isCancelled: Bool { status == .cancelled }

    public init(status: QuarantineRemovalStatus, message: String = "") {
        self.status = status
        self.message = message
    }
}

/// Çalışan alt süreçleri (`codesign`, `otool`, `nm`, `strings`, `spctl`, `lipo`) anında sonlandırabilen iş parçacığı güvenli iptal belirteci.
public final class ScanCancellationToken: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var activeProcesses: [ObjectIdentifier: Process] = [:]

    public init() {}

    public var isCancelled: Bool {
        lock.withLock { cancelled }
    }

    public func cancel() {
        let processesToStop: [Process] = lock.withLock {
            cancelled = true
            let list = Array(activeProcesses.values)
            activeProcesses.removeAll()
            return list
        }
        for process in processesToStop where process.isRunning {
            process.terminate()
        }
    }

    func attach(_ process: Process) -> Bool {
        lock.withLock {
            if cancelled { return false }
            activeProcesses[ObjectIdentifier(process)] = process
            return true
        }
    }

    func detach(_ process: Process) {
        lock.withLock {
            _ = activeProcesses.removeValue(forKey: ObjectIdentifier(process))
        }
    }
}

public struct BundleAuditReport: Sendable, Equatable, Codable {
    public let targetKind: AuditTargetKind
    public let bundlePath: String
    public let bundleName: String
    public let bundleId: String
    public let shortVersion: String
    public let buildVersion: String
    public let executableName: String
    public let executableRelativePath: String
    public let executableModDate: String
    public let plistModDate: String
    public let architectures: [String]
    public let executableSHA256: String
    public let executableSHA512: String
    public let lcRpaths: [String]
    public let teamIdentifier: String
    public let authorities: [String]
    public let isDevelopmentSigned: Bool
    public let signedTimestamp: String
    public let hasHardenedRuntime: Bool
    public let isNotarized: Bool
    public let isQuarantined: Bool
    public let entitlements: [String]
    public let spctlAssessment: String?
    public let gatekeeperStatus: String
    public let revocationStatus: RevocationStatus?
    public let cdHash: String
    public let scanDurationMs: Int
    public let verdict: IntegrityVerdict
    public let findings: [ForensicFinding]
    public let linkedDylibs: [LinkedDylibItem]
    public let bundledLibraries: [BundledLibraryItem]
    public let hookCategories: [HookSymbolCategory]
    public let rawCodesignOutput: String
    public let rawOtoolOutput: String
    public let rawEntitlementsOutput: String
    public let deceptiveNames: [String]
    public let firewallAppState: FirewallAppState?
    public let internetAccessPolicy: InternetAccessPolicy?
    public let volumeEncryption: VolumeEncryptionInfo?

    public var entitlementRisks: [EntitlementRiskItem] {
        EntitlementAnalyzer.analyze(entitlements, rawEntitlementsOutput: rawEntitlementsOutput)
    }

    public init(
        targetKind: AuditTargetKind = .appBundle,
        bundlePath: String,
        bundleName: String,
        bundleId: String,
        shortVersion: String,
        buildVersion: String,
        executableName: String,
        executableRelativePath: String? = nil,
        executableModDate: String,
        plistModDate: String,
        architectures: [String] = [],
        executableSHA256: String = "-",
        executableSHA512: String = "-",
        lcRpaths: [String] = [],
        teamIdentifier: String,
        authorities: [String],
        isDevelopmentSigned: Bool = false,
        signedTimestamp: String,
        hasHardenedRuntime: Bool,
        isNotarized: Bool,
        isQuarantined: Bool = false,
        entitlements: [String] = [],
        spctlAssessment: String? = nil,
        gatekeeperStatus: String,
        revocationStatus: RevocationStatus? = nil,
        cdHash: String,
        scanDurationMs: Int,
        verdict: IntegrityVerdict,
        findings: [ForensicFinding],
        linkedDylibs: [LinkedDylibItem],
        bundledLibraries: [BundledLibraryItem],
        hookCategories: [HookSymbolCategory],
        rawCodesignOutput: String,
        rawOtoolOutput: String,
        rawEntitlementsOutput: String = "",
        deceptiveNames: [String] = [],
        firewallAppState: FirewallAppState? = nil,
        internetAccessPolicy: InternetAccessPolicy? = nil,
        volumeEncryption: VolumeEncryptionInfo? = nil
    ) {
        self.targetKind = targetKind
        self.bundlePath = bundlePath
        self.bundleName = bundleName
        self.bundleId = bundleId
        self.shortVersion = shortVersion
        self.buildVersion = buildVersion
        self.executableName = executableName
        self.executableRelativePath = executableRelativePath ?? "Contents/MacOS/\(executableName)"
        self.executableModDate = executableModDate
        self.plistModDate = plistModDate
        self.architectures = architectures
        self.executableSHA256 = executableSHA256
        self.executableSHA512 = executableSHA512
        self.lcRpaths = lcRpaths
        self.teamIdentifier = teamIdentifier
        self.authorities = authorities
        self.isDevelopmentSigned = isDevelopmentSigned
        self.signedTimestamp = signedTimestamp
        self.hasHardenedRuntime = hasHardenedRuntime
        self.isNotarized = isNotarized
        self.isQuarantined = isQuarantined
        self.entitlements = entitlements
        self.spctlAssessment = spctlAssessment
        self.gatekeeperStatus = gatekeeperStatus
        self.revocationStatus = revocationStatus
        self.cdHash = cdHash
        self.scanDurationMs = scanDurationMs
        self.verdict = verdict
        self.findings = findings
        self.linkedDylibs = linkedDylibs
        self.bundledLibraries = bundledLibraries
        self.hookCategories = hookCategories
        self.rawCodesignOutput = rawCodesignOutput
        self.rawOtoolOutput = rawOtoolOutput
        self.rawEntitlementsOutput = rawEntitlementsOutput
        self.deceptiveNames = deceptiveNames
        self.firewallAppState = firewallAppState
        self.internetAccessPolicy = internetAccessPolicy
        self.volumeEncryption = volumeEncryption
    }

    private enum CodingKeys: String, CodingKey {
        case targetKind
        case bundlePath
        case bundleName
        case bundleId
        case shortVersion
        case buildVersion
        case executableName
        case executableRelativePath
        case executableModDate
        case plistModDate
        case architectures
        case executableSHA256
        case executableSHA512
        case lcRpaths
        case teamIdentifier
        case authorities
        case isDevelopmentSigned
        case signedTimestamp
        case hasHardenedRuntime
        case isNotarized
        case isQuarantined
        case entitlements
        case spctlAssessment
        case gatekeeperStatus
        case revocationStatus
        case cdHash
        case scanDurationMs
        case verdict
        case findings
        case linkedDylibs
        case bundledLibraries
        case hookCategories
        case rawCodesignOutput
        case rawOtoolOutput
        case rawEntitlementsOutput
        case deceptiveNames
        case firewallAppState
        case internetAccessPolicy
        case volumeEncryption
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let bundleName = try container.decode(String.self, forKey: .bundleName)
        let executableName = try container.decode(String.self, forKey: .executableName)
        self.targetKind = try container.decodeIfPresent(AuditTargetKind.self, forKey: .targetKind) ?? .appBundle
        self.bundlePath = try container.decode(String.self, forKey: .bundlePath)
        self.bundleName = bundleName
        self.bundleId = try container.decode(String.self, forKey: .bundleId)
        self.shortVersion = try container.decode(String.self, forKey: .shortVersion)
        self.buildVersion = try container.decode(String.self, forKey: .buildVersion)
        self.executableName = executableName
        self.executableRelativePath = try container.decodeIfPresent(String.self, forKey: .executableRelativePath)
            ?? "Contents/MacOS/\(executableName)"
        self.executableModDate = try container.decode(String.self, forKey: .executableModDate)
        self.plistModDate = try container.decode(String.self, forKey: .plistModDate)
        self.architectures = try container.decodeIfPresent([String].self, forKey: .architectures) ?? []
        self.executableSHA256 = try container.decodeIfPresent(String.self, forKey: .executableSHA256) ?? "-"
        self.executableSHA512 = try container.decodeIfPresent(String.self, forKey: .executableSHA512) ?? "-"
        self.lcRpaths = try container.decodeIfPresent([String].self, forKey: .lcRpaths) ?? []
        self.teamIdentifier = try container.decode(String.self, forKey: .teamIdentifier)
        self.authorities = try container.decode([String].self, forKey: .authorities)
        self.isDevelopmentSigned = try container.decodeIfPresent(Bool.self, forKey: .isDevelopmentSigned) ?? false
        self.signedTimestamp = try container.decode(String.self, forKey: .signedTimestamp)
        self.hasHardenedRuntime = try container.decode(Bool.self, forKey: .hasHardenedRuntime)
        self.isNotarized = try container.decode(Bool.self, forKey: .isNotarized)
        self.isQuarantined = try container.decodeIfPresent(Bool.self, forKey: .isQuarantined) ?? false
        self.entitlements = try container.decodeIfPresent([String].self, forKey: .entitlements) ?? []
        self.spctlAssessment = try container.decodeIfPresent(String.self, forKey: .spctlAssessment)
        self.gatekeeperStatus = try container.decode(String.self, forKey: .gatekeeperStatus)
        self.revocationStatus = try container.decodeIfPresent(RevocationStatus.self, forKey: .revocationStatus)
        self.cdHash = try container.decode(String.self, forKey: .cdHash)
        self.scanDurationMs = try container.decode(Int.self, forKey: .scanDurationMs)
        self.verdict = try container.decode(IntegrityVerdict.self, forKey: .verdict)
        self.findings = try container.decode([ForensicFinding].self, forKey: .findings)
        self.linkedDylibs = try container.decode([LinkedDylibItem].self, forKey: .linkedDylibs)
        self.bundledLibraries = try container.decode([BundledLibraryItem].self, forKey: .bundledLibraries)
        self.hookCategories = try container.decode([HookSymbolCategory].self, forKey: .hookCategories)
        self.rawCodesignOutput = try container.decode(String.self, forKey: .rawCodesignOutput)
        self.rawOtoolOutput = try container.decode(String.self, forKey: .rawOtoolOutput)
        self.rawEntitlementsOutput = try container.decodeIfPresent(String.self, forKey: .rawEntitlementsOutput) ?? ""
        self.deceptiveNames = try container.decodeIfPresent([String].self, forKey: .deceptiveNames) ?? []
        self.firewallAppState = try container.decodeIfPresent(FirewallAppState.self, forKey: .firewallAppState)
        self.internetAccessPolicy = try container.decodeIfPresent(InternetAccessPolicy.self, forKey: .internetAccessPolicy)
        self.volumeEncryption = try container.decodeIfPresent(VolumeEncryptionInfo.self, forKey: .volumeEncryption)
    }

    public func jsonData(prettyPrinted: Bool = true) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = prettyPrinted ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
        return try encoder.encode(self)
    }

    public func jsonString(prettyPrinted: Bool = true) throws -> String {
        String(decoding: try jsonData(prettyPrinted: prettyPrinted), as: UTF8.self)
    }

    public func withSpctlAssessment(_ status: String) -> BundleAuditReport {
        BundleAuditReport(
            targetKind: targetKind,
            bundlePath: bundlePath,
            bundleName: bundleName,
            bundleId: bundleId,
            shortVersion: shortVersion,
            buildVersion: buildVersion,
            executableName: executableName,
            executableRelativePath: executableRelativePath,
            executableModDate: executableModDate,
            plistModDate: plistModDate,
            architectures: architectures,
            executableSHA256: executableSHA256,
            executableSHA512: executableSHA512,
            lcRpaths: lcRpaths,
            teamIdentifier: teamIdentifier,
            authorities: authorities,
            isDevelopmentSigned: isDevelopmentSigned,
            signedTimestamp: signedTimestamp,
            hasHardenedRuntime: hasHardenedRuntime,
            isNotarized: isNotarized,
            isQuarantined: isQuarantined,
            entitlements: entitlements,
            spctlAssessment: status,
            gatekeeperStatus: gatekeeperStatus,
            revocationStatus: revocationStatus,
            cdHash: cdHash,
            scanDurationMs: scanDurationMs,
            verdict: verdict,
            findings: findings,
            linkedDylibs: linkedDylibs,
            bundledLibraries: bundledLibraries,
            hookCategories: hookCategories,
            rawCodesignOutput: rawCodesignOutput,
            rawOtoolOutput: rawOtoolOutput,
            rawEntitlementsOutput: rawEntitlementsOutput,
            deceptiveNames: deceptiveNames,
            firewallAppState: firewallAppState,
            internetAccessPolicy: internetAccessPolicy,
            volumeEncryption: volumeEncryption
        )
    }

    /// Produces a PII-redacted copy of this report using a deterministic per-session `DiagnosticMasker`.
    public func redacted(using masker: DiagnosticMasker) -> BundleAuditReport {
        let maskedFirewall = firewallAppState.map {
            let maskedTarget = masker.maskPath($0.targetPath)
            return FirewallAppState(
                targetPath: maskedTarget,
                ruleStatus: $0.ruleStatus,
                blockAllIncomingActive: $0.blockAllIncomingActive,
                unblockCommand: masker.redact(text: $0.unblockCommand)
            )
        }
        return BundleAuditReport(
            targetKind: targetKind,
            bundlePath: masker.maskPath(bundlePath),
            bundleName: masker.redact(text: bundleName),
            bundleId: masker.redact(text: bundleId),
            shortVersion: shortVersion,
            buildVersion: buildVersion,
            executableName: masker.redact(text: executableName),
            executableRelativePath: masker.redact(text: executableRelativePath),
            executableModDate: executableModDate,
            plistModDate: plistModDate,
            architectures: architectures,
            executableSHA256: executableSHA256,
            executableSHA512: executableSHA512,
            lcRpaths: lcRpaths.map { masker.maskPath($0) },
            teamIdentifier: teamIdentifier,
            authorities: authorities,
            isDevelopmentSigned: isDevelopmentSigned,
            signedTimestamp: signedTimestamp,
            hasHardenedRuntime: hasHardenedRuntime,
            isNotarized: isNotarized,
            isQuarantined: isQuarantined,
            entitlements: entitlements,
            spctlAssessment: spctlAssessment.map { masker.redact(text: $0) },
            gatekeeperStatus: masker.redact(text: gatekeeperStatus),
            revocationStatus: revocationStatus,
            cdHash: cdHash,
            scanDurationMs: scanDurationMs,
            verdict: verdict,
            findings: findings.map {
                ForensicFinding(
                    id: $0.id,
                    severity: $0.severity,
                    titleKey: $0.titleKey,
                    descKey: $0.descKey,
                    detailSuffix: masker.redact(text: $0.detailSuffix)
                )
            },
            linkedDylibs: linkedDylibs.map {
                LinkedDylibItem(
                    id: $0.id,
                    path: masker.maskPath($0.path),
                    isSystem: $0.isSystem,
                    isSuspicious: $0.isSuspicious,
                    isExternalSuspicious: $0.isExternalSuspicious
                )
            },
            bundledLibraries: bundledLibraries.map {
                BundledLibraryItem(
                    id: $0.id,
                    name: masker.redact(text: $0.name),
                    modifiedDate: $0.modifiedDate,
                    sizeBytes: $0.sizeBytes,
                    isTimestampAnomaly: $0.isTimestampAnomaly,
                    suspiciousSymbols: $0.suspiciousSymbols,
                    targetStrings: $0.targetStrings.map { masker.redact(text: $0) }
                )
            },
            hookCategories: hookCategories,
            rawCodesignOutput: masker.redact(text: rawCodesignOutput),
            rawOtoolOutput: masker.redact(text: rawOtoolOutput),
            rawEntitlementsOutput: masker.redact(text: rawEntitlementsOutput),
            deceptiveNames: deceptiveNames.map { masker.redact(text: $0) },
            firewallAppState: maskedFirewall,
            internetAccessPolicy: internetAccessPolicy,
            volumeEncryption: volumeEncryption
        )
    }
}

public struct BatchAuditSummary: Sendable, Equatable, Codable {
    public let directoryPath: String
    public let scannedAt: String
    public let totalCount: Int
    public let cleanCount: Int
    public let warningCount: Int
    public let tamperedCount: Int
    public let quarantinedCount: Int
    public let wasCancelled: Bool
    public let reports: [BundleAuditReport]

    public init(directoryPath: String, scannedAt: String, reports: [BundleAuditReport], wasCancelled: Bool = false) {
        self.directoryPath = directoryPath
        self.scannedAt = scannedAt
        self.reports = reports
        self.wasCancelled = wasCancelled
        self.totalCount = reports.count
        self.cleanCount = reports.filter { $0.verdict == .clean }.count
        self.warningCount = reports.filter { $0.verdict == .warning }.count
        self.tamperedCount = reports.filter { $0.verdict == .tampered }.count
        self.quarantinedCount = reports.filter(\.isQuarantined).count
    }

    public func jsonData(prettyPrinted: Bool = true) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = prettyPrinted ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
        return try encoder.encode(self)
    }

    public func redacted(using masker: DiagnosticMasker) -> BatchAuditSummary {
        BatchAuditSummary(
            directoryPath: masker.maskPath(directoryPath),
            scannedAt: scannedAt,
            reports: reports.map { $0.redacted(using: masker) },
            wasCancelled: wasCancelled
        )
    }
}
