// SPDX-License-Identifier: GPL-3.0-only
import CryptoKit
import Foundation

/// GitHub Releases'teki bir Verificator sürümü.
public struct AppRelease: Sendable, Equatable {
    public let version: String
    public let pageURL: URL
    public let downloadURL: URL?

    public init(version: String, pageURL: URL, downloadURL: URL?) {
        self.version = version
        self.pageURL = pageURL
        self.downloadURL = downloadURL
    }
}

/// Verificator güncellemesini GitHub Releases üzerinden denetler.
public enum AppUpdateChecker {
    public enum CheckError: Error, Equatable, Sendable {
        case noReleases
        case badResponse(Int)
        case invalidData
    }

    public static func latestReleaseURL(repository: String) -> URL? {
        URL(string: "https://api.github.com/repos/\(repository)/releases/latest")
    }

    public static func parse(_ data: Data, repository: String) throws -> AppRelease {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tag = object["tag_name"] as? String,
              let page = (object["html_url"] as? String).flatMap(URL.init(string:)),
              object["draft"] as? Bool != true, object["prerelease"] as? Bool != true else {
            throw CheckError.invalidData
        }
        guard isReleaseURL(page, repository: repository, download: false) else {
            AppLog.shared.warning(.update, "Ignored a release page outside GitHub releases of \(repository)", detail: page.absoluteString)
            throw CheckError.invalidData
        }
        let assets = (object["assets"] as? [[String: Any]]) ?? []
        func asset(withSuffix suffix: String) -> URL? {
            guard let url = assets.first(where: { ($0["name"] as? String)?.lowercased().hasSuffix(suffix) == true })
                .flatMap({ $0["browser_download_url"] as? String })
                .flatMap(URL.init(string:)) else { return nil }
            guard isReleaseURL(url, repository: repository, download: true) else {
                AppLog.shared.warning(.update, "Ignored a download address outside GitHub releases of \(repository)", detail: url.absoluteString)
                return nil
            }
            return url
        }
        return AppRelease(
            version: normalizedVersion(tag),
            pageURL: page,
            downloadURL: asset(withSuffix: ".dmg") ?? asset(withSuffix: ".zip")
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
