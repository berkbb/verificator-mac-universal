// SPDX-License-Identifier: GPL-3.0-only
import CryptoKit
import Foundation

/// GitHub Releases'teki bir Verificator sürümü.
public struct AppRelease: Sendable, Equatable {
    public let version: String
    public let pageURL: URL
    public let downloadURL: URL?
    public let signatureURL: URL?
    public let checksumsURL: URL?

    public init(
        version: String,
        pageURL: URL,
        downloadURL: URL?,
        signatureURL: URL? = nil,
        checksumsURL: URL? = nil
    ) {
        self.version = version
        self.pageURL = pageURL
        self.downloadURL = downloadURL
        self.signatureURL = signatureURL
        self.checksumsURL = checksumsURL
    }
}

public struct VerifiedUpdateResult: Sendable, Equatable {
    public let fileURL: URL
    public let sha256: String
    public let signatureVerified: Bool
    public let checksumVerified: Bool

    public init(fileURL: URL, sha256: String, signatureVerified: Bool, checksumVerified: Bool) {
        self.fileURL = fileURL
        self.sha256 = sha256
        self.signatureVerified = signatureVerified
        self.checksumVerified = checksumVerified
    }
}

/// Verificator güncellemesini GitHub Releases üzerinden denetler ve indirilen sürümü SHA-256 + Ed25519 ile doğrular.
public enum AppUpdateChecker {
    public enum CheckError: Error, Equatable, Sendable {
        case noReleases
        case badResponse(Int)
        case invalidData
    }

    public enum VerifiedDownloadError: Error, Equatable, Sendable, LocalizedError {
        case noDownloadURL
        case downloadFailed(Int)
        case missingPublicKey
        case missingVerificationMetadata
        case checksumMismatch(expected: String, actual: String)
        case signatureInvalid

        public var errorDescription: String? {
            switch self {
            case .noDownloadURL:
                return "No verified download asset URL found."
            case .downloadFailed(let status):
                return "HTTP \(status)"
            case .missingPublicKey:
                return "Embedded Ed25519 public key (VerificatorUpdatePublicEDKey) is missing."
            case .missingVerificationMetadata:
                return "Release does not include .sig or SHA256SUMS verification metadata."
            case .checksumMismatch(let expected, let actual):
                return "SHA-256 mismatch (expected \(expected.prefix(12))..., got \(actual.prefix(12))...)."
            case .signatureInvalid:
                return "Ed25519 signature verification failed."
            }
        }
    }

    public static func latestReleaseURL(repository: String) -> URL? {
        URL(string: "https://api.github.com/repos/\(repository)/releases/latest")
    }

    public static func parse(_ data: Data, repository: String) throws -> AppRelease {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CheckError.invalidData
        }
        if let msg = object["message"] as? String, msg.localizedCaseInsensitiveContains("not found") {
            throw CheckError.noReleases
        }
        guard let tag = object["tag_name"] as? String,
              let page = (object["html_url"] as? String).flatMap(URL.init(string:)),
              object["draft"] as? Bool != true, object["prerelease"] as? Bool != true else {
            throw CheckError.invalidData
        }
        guard isReleaseURL(page, repository: repository, download: false) else {
            AppLog.shared.warning(.update, "Ignored a release page outside GitHub releases of \(repository)", detail: page.absoluteString)
            throw CheckError.invalidData
        }
        let assets = (object["assets"] as? [[String: Any]]) ?? []
        func asset(matching predicate: (String) -> Bool) -> URL? {
            guard let url = assets.first(where: {
                guard let name = ($0["name"] as? String)?.lowercased() else { return false }
                return predicate(name)
            })
            .flatMap({ $0["browser_download_url"] as? String })
            .flatMap(URL.init(string:)) else { return nil }
            guard isReleaseURL(url, repository: repository, download: true) else {
                AppLog.shared.warning(.update, "Ignored a download address outside GitHub releases of \(repository)", detail: url.absoluteString)
                return nil
            }
            return url
        }

        let dmgURL = asset { $0.hasSuffix(".dmg") }
        let zipURL = asset { $0.hasSuffix(".zip") }
        let sigURL = asset { $0.hasSuffix(".dmg.sig") } ?? asset { $0.hasSuffix(".sig") }
        let checksumURL = asset { $0 == "sha256sums.txt" || $0 == "sha256sums" }

        return AppRelease(
            version: normalizedVersion(tag),
            pageURL: page,
            downloadURL: dmgURL ?? zipURL,
            signatureURL: sigURL,
            checksumsURL: checksumURL
        )
    }

    public static func isReleaseURL(_ url: URL, repository: String, download: Bool) -> Bool {
        guard url.scheme?.lowercased() == "https", url.host?.lowercased() == "github.com",
              url.user == nil, url.password == nil, url.port == nil || url.port == 443 else { return false }
        let prefix = "/" + repository.lowercased() + (download ? "/releases/download/" : "/releases/")
        return url.standardized.path.lowercased().hasPrefix(prefix)
    }

    public static func normalizedVersion(_ tag: String) -> String {
        tag.hasPrefix("v") || tag.hasPrefix("V") ? String(tag.dropFirst()) : tag
    }

    public static func isNewer(_ candidate: String, than current: String) -> Bool {
        func parts(_ value: String) -> [Int] {
            normalizedVersion(value).split(separator: ".").map { Int($0.prefix { $0.isNumber }) ?? 0 }
        }
        let lhs = parts(candidate), rhs = parts(current)
        for index in 0..<max(lhs.count, rhs.count) {
            let left = index < lhs.count ? lhs[index] : 0
            let right = index < rhs.count ? rhs[index] : 0
            if left != right { return left > right }
        }
        return false
    }

    public static func latest(repository: String, session: URLSession = .shared) async throws -> AppRelease {
        guard let url = latestReleaseURL(repository: repository) else { throw CheckError.invalidData }
        var request = URLRequest(url: url, timeoutInterval: 20)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        let (data, response) = try await session.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        if status == 404 { throw CheckError.noReleases }
        guard (200..<300).contains(status) else { throw CheckError.badResponse(status) }
        return try parse(data, repository: repository)
    }

    /// Sürüm arşivini geçici bir dosyaya indirir; varsa SHA-256 özetini ve Ed25519 `.sig` imzasını doğruladıktan sonra hedef klasöre taşır.
    public static func downloadAndVerify(
        release: AppRelease,
        destinationDirectory: URL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first ?? FileManager.default.temporaryDirectory,
        publicKeyOverride: String? = nil,
        session: URLSession = .shared
    ) async throws -> VerifiedUpdateResult {
        guard let downloadURL = release.downloadURL else {
            throw VerifiedDownloadError.noDownloadURL
        }
        guard release.signatureURL != nil || release.checksumsURL != nil else {
            throw VerifiedDownloadError.missingVerificationMetadata
        }

        let fm = FileManager.default
        let stagingDir = fm.temporaryDirectory.appendingPathComponent("VerificatorUpdate-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: stagingDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: stagingDir) }

        let (archiveTempURL, archiveResponse) = try await session.download(from: downloadURL)
        let archiveStatus = (archiveResponse as? HTTPURLResponse)?.statusCode ?? 200
        guard (200..<300).contains(archiveStatus) else {
            try? fm.removeItem(at: archiveTempURL)
            throw VerifiedDownloadError.downloadFailed(archiveStatus)
        }

        let fileName = downloadURL.lastPathComponent
        let stagedFileURL = stagingDir.appendingPathComponent(fileName)
        if fm.fileExists(atPath: stagedFileURL.path) {
            try fm.removeItem(at: stagedFileURL)
        }
        try fm.moveItem(at: archiveTempURL, to: stagedFileURL)

        let actualSHA = try UpdateChecksums.sha256(of: stagedFileURL)
        var checksumVerified = false
        var signatureVerified = false

        if let checksumsURL = release.checksumsURL {
            let (sumData, sumResponse) = try await session.data(from: checksumsURL)
            let sumStatus = (sumResponse as? HTTPURLResponse)?.statusCode ?? 200
            guard (200..<300).contains(sumStatus) else {
                throw VerifiedDownloadError.downloadFailed(sumStatus)
            }
            let table = UpdateChecksums.parse(String(decoding: sumData, as: UTF8.self))
            guard let expectedSHA = table[fileName] ?? table["./\(fileName)"] else {
                throw VerifiedDownloadError.checksumMismatch(expected: "missing", actual: actualSHA)
            }
            guard expectedSHA.caseInsensitiveCompare(actualSHA) == .orderedSame else {
                throw VerifiedDownloadError.checksumMismatch(expected: expectedSHA, actual: actualSHA)
            }
            checksumVerified = true
        }

        if let signatureURL = release.signatureURL {
            guard let publicKey = publicKeyOverride ?? UpdateSignature.bundledPublicKey, !publicKey.isEmpty else {
                throw VerifiedDownloadError.missingPublicKey
            }
            let (sigData, sigResponse) = try await session.data(from: signatureURL)
            let sigStatus = (sigResponse as? HTTPURLResponse)?.statusCode ?? 200
            guard (200..<300).contains(sigStatus) else {
                throw VerifiedDownloadError.downloadFailed(sigStatus)
            }
            let sigText = String(decoding: sigData, as: UTF8.self)
            let isValid = try UpdateSignature.isValid(fileURL: stagedFileURL, signatureBase64: sigText, publicKeyBase64: publicKey)
            guard isValid else {
                throw VerifiedDownloadError.signatureInvalid
            }
            signatureVerified = true
        }

        guard checksumVerified || signatureVerified else {
            throw VerifiedDownloadError.missingVerificationMetadata
        }

        try fm.createDirectory(at: destinationDirectory, withIntermediateDirectories: true)
        let finalURL = destinationDirectory.appendingPathComponent(fileName)
        if fm.fileExists(atPath: finalURL.path) {
            try fm.removeItem(at: finalURL)
        }
        try fm.moveItem(at: stagedFileURL, to: finalURL)

        AppLog.shared.info(.update, "Verified update downloaded to \(finalURL.path)", detail: "SHA-256: \(actualSHA), Ed25519: \(signatureVerified)")
        return VerifiedUpdateResult(
            fileURL: finalURL,
            sha256: actualSHA,
            signatureVerified: signatureVerified,
            checksumVerified: checksumVerified
        )
    }
}

// MARK: - Ed25519 Update Signatures

public enum UpdateSignature {
    public static let publicKeyInfoKey = "VerificatorUpdatePublicEDKey"

    public static var bundledPublicKey: String? {
        Bundle.main.object(forInfoDictionaryKey: publicKeyInfoKey) as? String
    }

    public static func isValid(fileURL: URL, signatureBase64: String, publicKeyBase64: String) throws -> Bool {
        guard
            let signature = Data(base64Encoded: signatureBase64.trimmingCharacters(in: .whitespacesAndNewlines)),
            let publicKeyData = Data(base64Encoded: publicKeyBase64),
            let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
        else {
            return false
        }
        let data = try Data(contentsOf: fileURL, options: .mappedIfSafe)
        return publicKey.isValidSignature(signature, for: data)
    }
}

// MARK: - SHA-256 Checksums

public enum UpdateChecksums {
    public static func parse(_ text: String) -> [String: String] {
        var result: [String: String] = [:]
        for line in text.split(whereSeparator: \.isNewline) {
            let parts = line.split(maxSplits: 1, whereSeparator: \.isWhitespace)
            guard parts.count == 2 else { continue }
            let digest = parts[0].lowercased()
            guard digest.count == 64, digest.allSatisfy(\.isHexDigit) else { continue }
            var fileName = parts[1].trimmingCharacters(in: .whitespaces)
            if fileName.hasPrefix("*") {
                fileName.removeFirst()
            }
            result[fileName] = digest
        }
        return result
    }

    public static func sha256(of fileURL: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: fileURL)
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try handle.read(upToCount: 1 << 20), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
