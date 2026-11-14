// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// Portable configuration and trusted signature baseline exchange document.
/// Mirrors `Descarcator` / `Curatare` transfer invariants:
/// - Home directories are normalized to `~/` on export and re-expanded to the active Mac's home on import.
/// - Volatile local histories (`recentBundles`, `recentVerdicts`, AI local server model names) are never exported.
/// - MDM-enforced keys (`ManagedConfiguration`) are reported as skipped and never overwritten on import.
public struct VerificatorPortableDocument: Codable, Equatable, Sendable {
    public static let expectedFormatIdentifier = "com.babadogantech.verificator.settings"
    public static let currentSchemaVersion = 1
    public static let maxPayloadBytes = 2 * 1024 * 1024

    public var format: String
    public var schemaVersion: Int
    public var appVersion: String
    public var exportedAt: Date
    public var preferences: [String: PortableValue]
    public var watchedFolders: [String]
    public var signatureBaselines: [String: SeenSignatureBaseline]

    public var isNewerThanSupported: Bool {
        schemaVersion > Self.currentSchemaVersion
    }

    public init(
        format: String = Self.expectedFormatIdentifier,
        schemaVersion: Int = Self.currentSchemaVersion,
        appVersion: String = AppInfo.version,
        exportedAt: Date = Date(),
        preferences: [String: PortableValue] = [:],
        watchedFolders: [String] = [],
        signatureBaselines: [String: SeenSignatureBaseline] = [:]
    ) {
        self.format = format
        self.schemaVersion = schemaVersion
        self.appVersion = appVersion
        self.exportedAt = exportedAt
        self.preferences = preferences
        self.watchedFolders = watchedFolders
        self.signatureBaselines = signatureBaselines
    }

    private enum CodingKeys: String, CodingKey {
        case format, schemaVersion, appVersion, exportedAt, preferences, watchedFolders, signatureBaselines
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.format = try container.decodeIfPresent(String.self, forKey: .format) ?? ""
        self.schemaVersion = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 1
        self.appVersion = try container.decodeIfPresent(String.self, forKey: .appVersion) ?? ""
        self.exportedAt = try container.decodeIfPresent(Date.self, forKey: .exportedAt) ?? Date()
        self.preferences = try container.decodeIfPresent([String: PortableValue].self, forKey: .preferences) ?? [:]
        self.watchedFolders = try container.decodeIfPresent([String].self, forKey: .watchedFolders) ?? []
        self.signatureBaselines = try container.decodeIfPresent([String: SeenSignatureBaseline].self, forKey: .signatureBaselines) ?? [:]
    }
}

public enum PortableValue: Equatable, Sendable, Codable {
    case bool(Bool)
    case int(Int)
    case string(String)

    public init(from decoder: Decoder) throws {
        let single = try decoder.singleValueContainer()
        if let value = try? single.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? single.decode(Int.self) {
            self = .int(value)
        } else if let value = try? single.decode(String.self) {
            self = .string(value)
        } else {
            throw DecodingError.typeMismatch(
                PortableValue.self,
                DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Unsupported portable preference value")
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var single = encoder.singleValueContainer()
        switch self {
        case .bool(let value): try single.encode(value)
        case .int(let value): try single.encode(value)
        case .string(let value): try single.encode(value)
        }
    }

    public var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }
}

public enum SettingsTransferFailure: Error, Equatable, Sendable {
    case tooLarge
    case malformedOrWrongFormat
    case unsupportedVersion(Int)
}

public struct SettingsImportOutcome: Equatable, Sendable {
    public let appliedPreferenceKeys: [String]
    public let importedBaselinesCount: Int
    public let importedWatchedFoldersCount: Int
    public let skippedManagedKeys: [String]
    public let rejectedEntries: [String]

    public init(
        appliedPreferenceKeys: [String],
        importedBaselinesCount: Int,
        importedWatchedFoldersCount: Int,
        skippedManagedKeys: [String],
        rejectedEntries: [String]
    ) {
        self.appliedPreferenceKeys = appliedPreferenceKeys
        self.importedBaselinesCount = importedBaselinesCount
        self.importedWatchedFoldersCount = importedWatchedFoldersCount
        self.skippedManagedKeys = skippedManagedKeys
        self.rejectedEntries = rejectedEntries
    }
}

public enum SettingsTransfer {
    public static let transferablePreferenceKeys: Set<String> = [
        VerificatorPreferenceKey.language,
        VerificatorPreferenceKey.appearance,
        VerificatorPreferenceKey.deepFrameworkSignatureCheck,
        VerificatorPreferenceKey.extractTargetStrings,
        VerificatorPreferenceKey.includeGatekeeperAssessment,
        VerificatorPreferenceKey.checkCertificateRevocation,
        VerificatorPreferenceKey.autoScanOnDrop,
        VerificatorPreferenceKey.revealAfterExport,
        VerificatorPreferenceKey.redactSharedDiagnostics,
        VerificatorPreferenceKey.checkUpdatesAtLaunch,
        VerificatorPreferenceKey.aiSuggestions,
        VerificatorPreferenceKey.aiProvider,
        VerificatorPreferenceKey.watchedFolderEnabled,
        VerificatorPreferenceKey.showMenuBarExtra,
    ]

    public static let neverExportedKeys: Set<String> = [
        VerificatorPreferenceKey.recentBundles,
        VerificatorPreferenceKey.recentVerdicts,
        VerificatorPreferenceKey.updateConsentAsked,
        VerificatorPreferenceKey.aiOllamaModel,
        VerificatorPreferenceKey.aiLMStudioModel,
        VerificatorPreferenceKey.customShortcuts,
    ]

    public static let validLanguages: Set<String> = Set(AppLanguage.allCases.map(\.rawValue))
    public static let validAppearances: Set<String> = ["system", "light", "dark"]
    public static let validAIProviders: Set<String> = Set(SuggestionProvider.allCases.map(\.rawValue))

    public static func exportData(
        preferences: [String: PortableValue],
        watchedFolders: [String],
        tracker: SignatureTracker,
        home: URL = FileManager.default.homeDirectoryForCurrentUser,
        now: Date = Date()
    ) throws -> Data {
        let normalizedHome = standardizedHomePath(home)
        var exportedPrefs: [String: PortableValue] = [:]
        for (key, value) in preferences {
            guard transferablePreferenceKeys.contains(key), !neverExportedKeys.contains(key) else { continue }
            exportedPrefs[key] = value
        }

        let portableFolders = watchedFolders
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .map { compressHomePrefix($0, homePath: normalizedHome) }

        var portableBaselines: [String: SeenSignatureBaseline] = [:]
        for (rawPath, baseline) in tracker.entries {
            let portablePath = compressHomePrefix(rawPath, homePath: normalizedHome)
            portableBaselines[portablePath] = baseline
        }

        let doc = VerificatorPortableDocument(
            appVersion: AppInfo.version,
            exportedAt: now,
            preferences: exportedPrefs,
            watchedFolders: portableFolders,
            signatureBaselines: portableBaselines
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(doc)
    }

    public static func decodeAndValidate(
        data: Data,
        home: URL = FileManager.default.homeDirectoryForCurrentUser,
        managedKeys: Set<String> = ManagedConfiguration.managedKeys()
    ) throws -> (document: VerificatorPortableDocument, sanitizedWatchedFolders: [String], sanitizedBaselines: [String: SeenSignatureBaseline], skippedManagedKeys: [String], rejected: [String]) {
        guard data.count <= VerificatorPortableDocument.maxPayloadBytes else {
            throw SettingsTransferFailure.tooLarge
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let rawDoc = try? decoder.decode(VerificatorPortableDocument.self, from: data),
              rawDoc.format == VerificatorPortableDocument.expectedFormatIdentifier else {
            throw SettingsTransferFailure.malformedOrWrongFormat
        }

        if rawDoc.isNewerThanSupported {
            throw SettingsTransferFailure.unsupportedVersion(rawDoc.schemaVersion)
        }

        let normalizedHome = standardizedHomePath(home)
        var filteredPrefs: [String: PortableValue] = [:]
        var skippedManaged: [String] = []
        var rejected: [String] = []

        for (key, value) in rawDoc.preferences.sorted(by: { $0.key < $1.key }) {
            if !transferablePreferenceKeys.contains(key) || neverExportedKeys.contains(key) {
                rejected.append(key)
                continue
            }
            if managedKeys.contains(key) {
                skippedManaged.append(key)
                continue
            }
            if isValidValue(value, forKey: key) {
                filteredPrefs[key] = value
            } else {
                rejected.append(key)
            }
        }

        var cleanWatched: [String] = []
        var seenFolders: Set<String> = []
        if managedKeys.contains(VerificatorPreferenceKey.watchedFolderPaths) {
            if !rawDoc.watchedFolders.isEmpty {
                skippedManaged.append(VerificatorPreferenceKey.watchedFolderPaths)
            }
        } else {
            for rawFolder in rawDoc.watchedFolders {
                let expanded = expandHomePrefix(rawFolder, homePath: normalizedHome)
                guard let safePath = validatedAbsolutePath(expanded) else {
                    rejected.append("watchedFolder:\(rawFolder)")
                    continue
                }
                if seenFolders.insert(safePath).inserted {
                    cleanWatched.append(safePath)
                }
            }
        }

        var cleanBaselines: [String: SeenSignatureBaseline] = [:]
        for (rawPath, baseline) in rawDoc.signatureBaselines {
            let expanded = expandHomePrefix(rawPath, homePath: normalizedHome)
            guard let safePath = validatedAbsolutePath(expanded), !baseline.bundleId.isEmpty else {
                rejected.append("baseline:\(rawPath)")
                continue
            }
            cleanBaselines[safePath] = baseline
        }

        var validatedDoc = rawDoc
        validatedDoc.preferences = filteredPrefs
        validatedDoc.watchedFolders = cleanWatched
        validatedDoc.signatureBaselines = cleanBaselines

        return (validatedDoc, cleanWatched, cleanBaselines, skippedManaged.sorted(), rejected.sorted())
    }

    public static func compressHomePrefix(_ path: String, homePath: String) -> String {
        guard !homePath.isEmpty, homePath != "/" else { return path }
        if path == homePath { return "~" }
        let prefix = homePath.hasSuffix("/") ? homePath : homePath + "/"
        if path.hasPrefix(prefix) {
            return "~/" + String(path.dropFirst(prefix.count))
        }
        return path
    }

    public static func expandHomePrefix(_ path: String, homePath: String) -> String {
        if path == "~" { return homePath }
        if path.hasPrefix("~/") {
            let suffix = String(path.dropFirst(2))
            let base = homePath.hasSuffix("/") ? String(homePath.dropLast()) : homePath
            return "\(base)/\(suffix)"
        }
        return path
    }

    private static func standardizedHomePath(_ home: URL) -> String {
        let path = home.standardizedFileURL.path
        return path.hasSuffix("/") && path != "/" ? String(path.dropLast()) : path
    }

    private static func validatedAbsolutePath(_ path: String) -> String? {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("/"), !trimmed.contains("\0") else { return nil }
        let standardized = URL(fileURLWithPath: trimmed).standardizedFileURL.path
        guard standardized.hasPrefix("/") else { return nil }
        return standardized
    }

    private static func isValidValue(_ value: PortableValue, forKey key: String) -> Bool {
        switch key {
        case VerificatorPreferenceKey.language:
            guard let s = value.stringValue else { return false }
            return validLanguages.contains(s)
        case VerificatorPreferenceKey.appearance:
            guard let s = value.stringValue else { return false }
            return validAppearances.contains(s)
        case VerificatorPreferenceKey.aiProvider:
            guard let s = value.stringValue else { return false }
            return validAIProviders.contains(s)
        case VerificatorPreferenceKey.deepFrameworkSignatureCheck,
             VerificatorPreferenceKey.extractTargetStrings,
             VerificatorPreferenceKey.includeGatekeeperAssessment,
             VerificatorPreferenceKey.checkCertificateRevocation,
             VerificatorPreferenceKey.autoScanOnDrop,
             VerificatorPreferenceKey.revealAfterExport,
             VerificatorPreferenceKey.redactSharedDiagnostics,
             VerificatorPreferenceKey.checkUpdatesAtLaunch,
             VerificatorPreferenceKey.aiSuggestions,
             VerificatorPreferenceKey.watchedFolderEnabled,
             VerificatorPreferenceKey.showMenuBarExtra:
            return value.boolValue != nil
        default:
            return false
        }
    }
}
