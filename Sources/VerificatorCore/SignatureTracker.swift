// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// Uygulamalar için son bilinen imza kimliği / CDHash geçmişi (`Paravan` SignatureTracker modeli).
public enum SignatureBaselineChangeKind: String, Sendable, Equatable, Codable {
    case signerChanged
    case lostSignature
    case updatedSameSigner
}

public struct SeenSignatureBaseline: Codable, Equatable, Sendable {
    public var bundleId: String
    public var teamIdentifier: String
    public var authorities: [String]
    public var cdHash: String
    public var executableSHA256: String
    public var shortVersion: String
    public var firstSeen: Date
    public var lastSeen: Date

    public init(
        bundleId: String,
        teamIdentifier: String,
        authorities: [String],
        cdHash: String,
        executableSHA256: String,
        shortVersion: String,
        firstSeen: Date,
        lastSeen: Date
    ) {
        self.bundleId = bundleId
        self.teamIdentifier = teamIdentifier
        self.authorities = authorities
        self.cdHash = cdHash
        self.executableSHA256 = executableSHA256
        self.shortVersion = shortVersion
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }

    public var isFormallySigned: Bool {
        teamIdentifier != "not set" || !authorities.isEmpty
    }

    public var displaySigner: String {
        if let primary = authorities.first, !primary.isEmpty {
            return teamIdentifier == "not set" ? primary : "\(primary) (\(teamIdentifier))"
        }
        return teamIdentifier
    }
}

public struct SignatureBaselineChange: Sendable, Equatable {
    public let bundlePath: String
    public let kind: SignatureBaselineChangeKind
    public let previous: SeenSignatureBaseline
    public let current: SeenSignatureBaseline

    public var currentSignerDisplay: String { current.displaySigner }
    public var previousSignerDisplay: String { previous.displaySigner }
}

public struct SignatureTracker: Codable, Equatable, Sendable {
    public private(set) var entries: [String: SeenSignatureBaseline]
    public static let entryLimit = 2_000

    public init(entries: [String: SeenSignatureBaseline] = [:]) {
        self.entries = entries
    }

    /// Raporun imzasını önceki kayıtla karşılaştırır; imza değişimi/gerilemesi veya aynı imzalayıcıyla güncelleme varsa delta döner.
    /// İlk kez görülen veya imzasız başlayıp sonradan imzalanan yerel derlemelerde `signerChanged` üretmez.
    public mutating func observe(report: BundleAuditReport, at date: Date = Date()) -> SignatureBaselineChange? {
        guard report.targetKind == .appBundle || report.targetKind == .nestedBundle else {
            return nil
        }
        let key = URL(fileURLWithPath: report.bundlePath).standardizedFileURL.path
        guard !key.isEmpty else { return nil }

        let currentAuthorities = Self.nonPlaceholderAuthorities(report.authorities)
        let current = SeenSignatureBaseline(
            bundleId: report.bundleId,
            teamIdentifier: report.teamIdentifier,
            authorities: currentAuthorities,
            cdHash: report.cdHash,
            executableSHA256: report.executableSHA256,
            shortVersion: report.shortVersion,
            firstSeen: entries[key]?.firstSeen ?? date,
            lastSeen: date
        )

        guard let previous = entries[key] else {
            insert(current, for: key)
            return nil
        }

        // Aynı imzalayıcı ve aynı CDHash ise sadece son görülme anını güncelle
        let sameTeam = previous.teamIdentifier == current.teamIdentifier
        let sameAuthorities = previous.authorities == current.authorities
        let sameCode = previous.cdHash == current.cdHash && previous.executableSHA256 == current.executableSHA256

        if sameTeam && sameAuthorities && sameCode {
            if date.timeIntervalSince(previous.lastSeen) > 60 {
                entries[key]?.lastSeen = date
            }
            return nil
        }

        // İmza tamamen kaldırıldı veya ad-hoc'a düşürüldü
        if previous.isFormallySigned && !current.isFormallySigned {
            return SignatureBaselineChange(bundlePath: key, kind: .lostSignature, previous: previous, current: current)
        }

        // Farklı bir Team ID veya farklı kök otoriteye geçti
        if previous.isFormallySigned && (!sameTeam || !sameAuthorities) {
            return SignatureBaselineChange(bundlePath: key, kind: .signerChanged, previous: previous, current: current)
        }

        // Aynı resmi imzalayıcı altında yeni derleme/güncelleme
        insert(current, for: key)
        if previous.isFormallySigned {
            return SignatureBaselineChange(bundlePath: key, kind: .updatedSameSigner, previous: previous, current: current)
        }
        return nil
    }

    /// Kullanıcının onayladığı yeni imza referansını kalıcı olarak kaydeder.
    public mutating func acceptBaseline(for report: BundleAuditReport, at date: Date = Date()) {
        let key = URL(fileURLWithPath: report.bundlePath).standardizedFileURL.path
        guard !key.isEmpty else { return }
        let currentAuthorities = Self.nonPlaceholderAuthorities(report.authorities)
        let baseline = SeenSignatureBaseline(
            bundleId: report.bundleId,
            teamIdentifier: report.teamIdentifier,
            authorities: currentAuthorities,
            cdHash: report.cdHash,
            executableSHA256: report.executableSHA256,
            shortVersion: report.shortVersion,
            firstSeen: entries[key]?.firstSeen ?? date,
            lastSeen: date
        )
        insert(baseline, for: key)
    }

    /// Merges imported trusted baselines (keeping newer timestamps when paths already exist) and enforces `entryLimit`.
    @discardableResult
    public mutating func merge(entries incoming: [String: SeenSignatureBaseline]) -> Int {
        var mergedCount = 0
        for (rawPath, candidate) in incoming {
            let key = URL(fileURLWithPath: rawPath).standardizedFileURL.path
            guard !key.isEmpty else { continue }
            if let existing = entries[key], existing.lastSeen >= candidate.lastSeen {
                continue
            }
            insert(candidate, for: key)
            mergedCount += 1
        }
        return mergedCount
    }

    private static func nonPlaceholderAuthorities(_ authorities: [String]) -> [String] {
        authorities.filter { authority in
            let lower = authority.lowercased()
            return !lower.hasPrefix("ad-hoc") && !lower.hasPrefix("unsigned")
        }
    }

    private mutating func insert(_ seen: SeenSignatureBaseline, for key: String) {
        entries[key] = seen
        guard entries.count > Self.entryLimit else { return }
        let stale = entries.sorted { $0.value.lastSeen < $1.value.lastSeen }.prefix(entries.count - Self.entryLimit)
        for (staleKey, _) in stale {
            entries.removeValue(forKey: staleKey)
        }
    }
}

/// İmza referans geçmişini diskte `0600` izinle saklar.
public struct SignatureTrackerStore: Sendable {
    public let fileURL: URL

    public static var defaultFileURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Verificator/signature-history.json")
    }

    public init(fileURL: URL = SignatureTrackerStore.defaultFileURL) {
        self.fileURL = fileURL
    }

    public func load() -> SignatureTracker {
        guard let data = try? Data(contentsOf: fileURL),
              let tracker = try? Self.decoder.decode(SignatureTracker.self, from: data) else {
            return SignatureTracker()
        }
        return tracker
    }

    public func save(_ tracker: SignatureTracker) throws {
        let dir = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let data = try Self.encoder.encode(tracker)
        try data.write(to: fileURL, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()
}
