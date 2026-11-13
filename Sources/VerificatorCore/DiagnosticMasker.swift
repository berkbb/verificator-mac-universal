// SPDX-License-Identifier: GPL-3.0-only
import CryptoKit
import Foundation

/// Per-export salted SHA-256 PII redactor for forensic reports, paths, usernames, and logs.
/// Same name produces the same deterministic token (`‹name-3fa2c1›.ext`) within one export session,
/// while differing across sessions so personal identifiers cannot be correlated externally.
public struct DiagnosticMasker: Sendable {
    private let salt: Data
    private let homePath: String
    private let userName: String

    /// Standard system/bundle components left readable so forensic reports stay actionable.
    private static let keptComponents: Set<String> = [
        "Applications", "System", "Library", "usr", "bin", "sbin", "opt", "private", "var", "tmp",
        "Volumes", "Users", "Shared", "Contents", "MacOS", "Frameworks", "SharedFrameworks",
        "Resources", "PlugIns", "XPCServices", "LaunchAgents", "LaunchDaemons", "PrivilegedHelperTools",
        "Application Support", "Caches", "Preferences", "Logs", "Developer", "Utilities",
        "en.lproj", "tr.lproj", "ro.lproj", "Base.lproj",
    ]

    public init(
        homePath: String = NSHomeDirectory(),
        userName: String = NSUserName(),
        salt: Data? = nil
    ) {
        self.homePath = (homePath as NSString).standardizingPath
        self.userName = userName
        if let salt {
            self.salt = salt
        } else {
            var bytes = [UInt8](repeating: 0, count: 32)
            _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
            self.salt = Data(bytes)
        }
    }

    public func maskUserName(_ name: String? = nil) -> String {
        let value = (name ?? userName).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return "‹user›" }
        return "‹user-\(shortDigest(for: value))›"
    }

    public func maskComponent(_ component: String) -> String {
        let trimmed = component.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != "/" else { return component }
        if Self.keptComponents.contains(trimmed) { return trimmed }

        let url = URL(fileURLWithPath: trimmed)
        let ext = url.pathExtension
        let hash = shortDigest(for: trimmed)
        if ext.isEmpty {
            return "‹item-\(hash)›"
        }
        return "‹item-\(hash)›.\(ext)"
    }

    /// Masks user home paths and personal subdirectories while preserving `/Applications/*.app/...` and system hierarchies.
    public func maskPath(_ path: String) -> String {
        guard !path.isEmpty, path != "-" else { return path }

        var normalized = path
        let nsHome = homePath
        if !nsHome.isEmpty && nsHome != "/" && normalized.hasPrefix(nsHome) {
            let suffix = String(normalized.dropFirst(nsHome.count))
            let tailComponents = suffix
                .split(separator: "/", omittingEmptySubsequences: true)
                .map(String.init)
            let maskedTail = maskRelativeUserTail(tailComponents)
            return maskedTail.isEmpty ? "~" : "~/" + maskedTail.joined(separator: "/")
        }

        // Handle "/Users/<username>/..." paths even for other user accounts on disk.
        let parts = normalized.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        if parts.count >= 2 && parts[0] == "Users" && parts[1] != "Shared" {
            var rebuilt = ["Users", maskUserName(parts[1])]
            if parts.count > 2 {
                rebuilt += maskRelativeUserTail(Array(parts.dropFirst(2)))
            }
            return "/" + rebuilt.joined(separator: "/")
        }

        // Preserve system and `/Applications/...` structure, but redact personal username strings if embedded.
        if !userName.isEmpty && normalized.contains(userName) {
            normalized = normalized.replacingOccurrences(of: userName, with: maskUserName(userName))
        }
        return normalized
    }

    /// Redacts home paths, `/Users/<name>/...` sequences, and current OS usernames inside free-form reports or logs.
    public func redact(text: String) -> String {
        guard !text.isEmpty else { return text }
        var output = text

        if !homePath.isEmpty && homePath != "/" {
            output = output.replacingOccurrences(of: homePath, with: "~")
        }

        // Match /Users/<segment> where <segment> is not Shared or already masked.
        if let regex = try? NSRegularExpression(pattern: #"/Users/([^/\s`"'(),;:]+)"#) {
            let fullRange = NSRange(output.startIndex..<output.endIndex, in: output)
            let matches = regex.matches(in: output, range: fullRange).reversed()
            for match in matches where match.numberOfRanges >= 2 {
                guard let segmentRange = Range(match.range(at: 1), in: output) else { continue }
                let segment = String(output[segmentRange])
                if segment == "Shared" || segment.hasPrefix("‹user-") { continue }
                output.replaceSubrange(segmentRange, with: maskUserName(segment))
            }
        }

        // Replace standalone occurrences of the current username (e.g., team/user identifiers or home fragments).
        let escapedUser = NSRegularExpression.escapedPattern(for: userName)
        if !userName.isEmpty,
           userName.count >= 2,
           let userRegex = try? NSRegularExpression(pattern: "(?<![A-Za-z0-9_])\(escapedUser)(?![A-Za-z0-9_])") {
            let range = NSRange(output.startIndex..<output.endIndex, in: output)
            output = userRegex.stringByReplacingMatches(in: output, range: range, withTemplate: maskUserName(userName))
        }

        return output
    }

    private func maskRelativeUserTail(_ tail: [String]) -> [String] {
        var result: [String] = []
        var insideBundle = false
        for component in tail {
            if Self.keptComponents.contains(component) {
                result.append(component)
                continue
            }
            if insideBundle {
                // Keep internal app structure (.app/Contents/MacOS/...) readable except personal binary file stems if non-standard.
                if ["Contents", "MacOS", "Frameworks", "Resources", "PlugIns", "XPCServices"].contains(component) {
                    result.append(component)
                } else {
                    result.append(maskComponent(component))
                }
                continue
            }
            if component.lowercased().hasSuffix(".app") {
                insideBundle = true
            }
            result.append(maskComponent(component))
        }
        return result
    }

    private func shortDigest(for value: String) -> String {
        var hasher = SHA256()
        hasher.update(data: salt)
        hasher.update(data: Data(value.utf8))
        return hasher.finalize().prefix(3).map { String(format: "%02x", $0) }.joined()
    }
}
