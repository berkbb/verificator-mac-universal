// SPDX-License-Identifier: GPL-3.0-only
import Foundation

public enum IntegrityVerdict: String, Sendable, Equatable {
    case clean
    case warning
    case tampered
}

public enum FindingSeverity: String, Sendable, Equatable {
    case critical
    case warning
    case info
}

public struct ForensicFinding: Identifiable, Sendable, Equatable {
    public let id = UUID()
    public let severity: FindingSeverity
    public let titleKey: LKey
    public let descKey: LKey
    public let detailSuffix: String

    public init(severity: FindingSeverity, titleKey: LKey, descKey: LKey, detailSuffix: String = "") {
        self.severity = severity
        self.titleKey = titleKey
        self.descKey = descKey
        self.detailSuffix = detailSuffix
    }
}

public struct LinkedDylibItem: Identifiable, Sendable, Equatable {
    public let id = UUID()
    public let path: String
    public let isSystem: Bool
    public let isSuspicious: Bool

    public init(path: String, isSystem: Bool, isSuspicious: Bool) {
        self.path = path
        self.isSystem = isSystem
        self.isSuspicious = isSuspicious
    }
}

public struct BundledLibraryItem: Identifiable, Sendable, Equatable {
    public let id = UUID()
    public let name: String
    public let modifiedDate: String
    public let sizeBytes: Int64
    public let isTimestampAnomaly: Bool
    public let suspiciousSymbols: [String]
    public let targetStrings: [String]

    public init(
        name: String,
        modifiedDate: String,
        sizeBytes: Int64,
        isTimestampAnomaly: Bool,
        suspiciousSymbols: [String],
        targetStrings: [String]
    ) {
        self.name = name
        self.modifiedDate = modifiedDate
        self.sizeBytes = sizeBytes
        self.isTimestampAnomaly = isTimestampAnomaly
        self.suspiciousSymbols = suspiciousSymbols
        self.targetStrings = targetStrings
    }
}

public struct HookSymbolCategory: Identifiable, Sendable, Equatable {
    public let id = UUID()
    public let libraryName: String
    public let categoryKey: LKey
    public let symbols: [String]

    public init(libraryName: String, categoryKey: LKey, symbols: [String]) {
        self.libraryName = libraryName
        self.categoryKey = categoryKey
        self.symbols = symbols
    }
}

public struct ScanOptions: Sendable, Equatable {
    public var deepFrameworkSignatureCheck: Bool
    public var extractTargetStrings: Bool

    public init(deepFrameworkSignatureCheck: Bool = true, extractTargetStrings: Bool = true) {
        self.deepFrameworkSignatureCheck = deepFrameworkSignatureCheck
        self.extractTargetStrings = extractTargetStrings
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

public struct BundleAuditReport: Sendable, Equatable {
    public let bundlePath: String
    public let bundleName: String
    public let bundleId: String
    public let shortVersion: String
    public let buildVersion: String
    public let executableName: String
    public let executableModDate: String
    public let plistModDate: String
    public let teamIdentifier: String
    public let authorities: [String]
    public let signedTimestamp: String
    public let hasHardenedRuntime: Bool
    public let isNotarized: Bool
    public let isQuarantined: Bool
    public let gatekeeperStatus: String
    public let cdHash: String
    public let scanDurationMs: Int
    public let verdict: IntegrityVerdict
    public let findings: [ForensicFinding]
    public let linkedDylibs: [LinkedDylibItem]
    public let bundledLibraries: [BundledLibraryItem]
    public let hookCategories: [HookSymbolCategory]
    public let rawCodesignOutput: String
    public let rawOtoolOutput: String

    public init(
        bundlePath: String,
        bundleName: String,
        bundleId: String,
        shortVersion: String,
        buildVersion: String,
        executableName: String,
        executableModDate: String,
        plistModDate: String,
        teamIdentifier: String,
        authorities: [String],
        signedTimestamp: String,
        hasHardenedRuntime: Bool,
        isNotarized: Bool,
        isQuarantined: Bool = false,
        gatekeeperStatus: String,
        cdHash: String,
        scanDurationMs: Int,
        verdict: IntegrityVerdict,
        findings: [ForensicFinding],
        linkedDylibs: [LinkedDylibItem],
        bundledLibraries: [BundledLibraryItem],
        hookCategories: [HookSymbolCategory],
        rawCodesignOutput: String,
        rawOtoolOutput: String
    ) {
        self.bundlePath = bundlePath
        self.bundleName = bundleName
        self.bundleId = bundleId
        self.shortVersion = shortVersion
        self.buildVersion = buildVersion
        self.executableName = executableName
        self.executableModDate = executableModDate
        self.plistModDate = plistModDate
        self.teamIdentifier = teamIdentifier
        self.authorities = authorities
        self.signedTimestamp = signedTimestamp
        self.hasHardenedRuntime = hasHardenedRuntime
        self.isNotarized = isNotarized
        self.isQuarantined = isQuarantined
        self.gatekeeperStatus = gatekeeperStatus
        self.cdHash = cdHash
        self.scanDurationMs = scanDurationMs
        self.verdict = verdict
        self.findings = findings
        self.linkedDylibs = linkedDylibs
        self.bundledLibraries = bundledLibraries
        self.hookCategories = hookCategories
        self.rawCodesignOutput = rawCodesignOutput
        self.rawOtoolOutput = rawOtoolOutput
    }
}
