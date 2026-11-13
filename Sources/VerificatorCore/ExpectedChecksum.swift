// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// Cryptographically strong digest algorithms accepted by Verificator's expected-checksum verifier.
public enum ChecksumAlgorithm: String, Sendable, Equatable, Codable, CaseIterable {
    case sha256 = "SHA-256"
    case sha512 = "SHA-512"

    public var expectedHexLength: Int {
        switch self {
        case .sha256: 64
        case .sha512: 128
        }
    }
}

/// Parsed expected cryptographic digest value for target binary / package / DMG verification.
public struct ExpectedChecksum: Sendable, Equatable, Codable {
    public let algorithm: ChecksumAlgorithm
    public let hex: String

    public init?(algorithm: ChecksumAlgorithm, hex: String) {
        let normalized = hex.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard normalized.count == algorithm.expectedHexLength,
              normalized.unicodeScalars.allSatisfy({ CharacterSet.hexDigits.contains($0) }) else {
            return nil
        }
        self.algorithm = algorithm
        self.hex = normalized
    }

    public init(validatedAlgorithm: ChecksumAlgorithm, lowercasedHex: String) {
        self.algorithm = validatedAlgorithm
        self.hex = lowercasedHex
    }

    /// Compares this expectation against the target's actual SHA-256 and SHA-512 digests.
    public func verify(actualSHA256: String, actualSHA512: String) -> ChecksumVerificationResult {
        let candidateRaw: String = switch algorithm {
        case .sha256: actualSHA256
        case .sha512: actualSHA512
        }
        let actual = candidateRaw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard actual.count == algorithm.expectedHexLength, actual != "-" else {
            return .unavailable(self)
        }
        if actual == hex {
            return .matched(self, actualHex: actual)
        }
        return .mismatch(expected: self, actualHex: actual)
    }
}

/// Result of parsing free-form pasted checksum lines or `SHA256SUMS` / `SHA512SUMS` text.
public enum ChecksumParseResult: Sendable, Equatable {
    case empty
    case parsed(ExpectedChecksum)
    case weakAlgorithm(String)
    case notFoundForFile(String)
    case unrecognized
}

/// Result of verifying an `ExpectedChecksum` against a target's computed digest.
public enum ChecksumVerificationResult: Sendable, Equatable {
    case matched(ExpectedChecksum, actualHex: String)
    case mismatch(expected: ExpectedChecksum, actualHex: String)
    case unavailable(ExpectedChecksum)
}

/// Parses pasted digests, GNU `sha256sum`/`shasum` output, BSD `SHA256 (file) = hex`, or multi-line checksum files.
public enum ChecksumInput {
    public static func parse(_ rawInput: String, fileName: String? = nil) -> ChecksumParseResult {
        let lines = rawInput
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }

        guard !lines.isEmpty else { return .empty }

        if lines.count == 1 {
            return parseSingleLine(lines[0], expectedFileName: fileName)
        }

        // Multi-line checksum file (e.g. SHA256SUMS.txt): match line by file name if provided.
        let normalizedTarget = fileName.map { URL(fileURLWithPath: $0).lastPathComponent.lowercased() }
        var firstParsedIfNoFileName: ExpectedChecksum?

        for line in lines {
            if let entry = extractMultiLineEntry(from: line) {
                if let target = normalizedTarget {
                    if entry.fileName.lowercased() == target {
                        switch entry.result {
                        case .parsed(let expected):
                            return .parsed(expected)
                        case .weakAlgorithm(let algo):
                            return .weakAlgorithm(algo)
                        default:
                            break
                        }
                    }
                } else if firstParsedIfNoFileName == nil, case .parsed(let expected) = entry.result {
                    firstParsedIfNoFileName = expected
                }
            }
        }

        if let firstParsedIfNoFileName {
            return .parsed(firstParsedIfNoFileName)
        }
        if let fileName {
            return .notFoundForFile(fileName)
        }
        return .unrecognized
    }

    /// Loads text from a file path if `valueOrPath` resolves to an existing regular file, otherwise parses it literally.
    public static func parseValueOrFile(_ valueOrPath: String, fileName: String? = nil) -> ChecksumParseResult {
        let expanded = NSString(string: valueOrPath).expandingTildeInPath
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: expanded, isDirectory: &isDir),
           !isDir.boolValue,
           let content = try? String(contentsOfFile: expanded, encoding: .utf8) {
            return parse(content, fileName: fileName)
        }
        return parse(valueOrPath, fileName: fileName)
    }

    private static func parseSingleLine(_ line: String, expectedFileName: String?) -> ChecksumParseResult {
        let lower = line.lowercased()

        // Explicit weak algorithm label checks
        if lower.hasPrefix("md5:") || lower.hasPrefix("md5=") || lower.hasPrefix("md5 ") || lower.hasPrefix("md5(") {
            return .weakAlgorithm("MD5")
        }
        if lower.hasPrefix("sha1:") || lower.hasPrefix("sha-1:") || lower.hasPrefix("sha1=") || lower.hasPrefix("sha-1=") || lower.hasPrefix("sha1 ") || lower.hasPrefix("sha1(") {
            return .weakAlgorithm("SHA-1")
        }

        // Prefix style: "sha256:<hex>", "sha-256=<hex>", "sha512:<hex>", "sha-512=<hex>"
        for (prefixes, algo) in [
            (["sha256:", "sha256=", "sha-256:", "sha-256="], ChecksumAlgorithm.sha256),
            (["sha512:", "sha512=", "sha-512:", "sha-512="], ChecksumAlgorithm.sha512),
        ] {
            for prefix in prefixes where lower.hasPrefix(prefix) {
                let rest = String(line.dropFirst(prefix.count)).trimmingCharacters(in: .whitespacesAndNewlines)
                if let parsed = ExpectedChecksum(algorithm: algo, hex: rest) {
                    return .parsed(parsed)
                }
            }
        }

        // Check BSD/GNU named entry if present
        if let entry = extractMultiLineEntry(from: line) {
            if let expectedFileName,
               URL(fileURLWithPath: expectedFileName).lastPathComponent.lowercased() != entry.fileName.lowercased() {
                return .notFoundForFile(expectedFileName)
            }
            return entry.result
        }

        // Plain hex digest
        if isHexToken(line) {
            switch line.count {
            case 32:
                return .weakAlgorithm("MD5")
            case 40:
                return .weakAlgorithm("SHA-1")
            case 64:
                if let expected = ExpectedChecksum(algorithm: .sha256, hex: line) { return .parsed(expected) }
            case 128:
                if let expected = ExpectedChecksum(algorithm: .sha512, hex: line) { return .parsed(expected) }
            default:
                break
            }
        }

        return .unrecognized
    }

    private static func extractMultiLineEntry(from line: String) -> (fileName: String, result: ChecksumParseResult)? {
        // BSD style: SHA256 (filename) = <hex>
        for algoPrefix in ["SHA256", "SHA512", "SHA1", "MD5"] {
            if let eqRange = line.range(of: " = ", options: .backwards),
               line.uppercased().hasPrefix(algoPrefix),
               let openParen = line.firstIndex(of: "("),
               let closeParen = line.range(of: ")", range: openParen..<eqRange.lowerBound)?.lowerBound {
                let rawName = String(line[line.index(after: openParen)..<closeParen]).trimmingCharacters(in: .whitespaces)
                let fileName = URL(fileURLWithPath: rawName).lastPathComponent
                let digest = String(line[eqRange.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
                return (fileName, classifyRawDigest(digest))
            }
        }

        // GNU sha256sum / shasum style: <hex>  [*| ]<path>
        let parts = line.split(maxSplits: 1, whereSeparator: \.isWhitespace)
        if parts.count == 2 {
            let token = String(parts[0])
            guard isHexToken(token) else { return nil }
            var rawName = String(parts[1]).trimmingCharacters(in: .whitespaces)
            if rawName.hasPrefix("*") {
                rawName = String(rawName.dropFirst()).trimmingCharacters(in: .whitespaces)
            }
            let fileName = URL(fileURLWithPath: rawName).lastPathComponent
            return (fileName, classifyRawDigest(token))
        }

        return nil
    }

    private static func classifyRawDigest(_ token: String) -> ChecksumParseResult {
        guard isHexToken(token) else { return .unrecognized }
        switch token.count {
        case 32:
            return .weakAlgorithm("MD5")
        case 40:
            return .weakAlgorithm("SHA-1")
        case 64:
            return ExpectedChecksum(algorithm: .sha256, hex: token).map(ChecksumParseResult.parsed) ?? .unrecognized
        case 128:
            return ExpectedChecksum(algorithm: .sha512, hex: token).map(ChecksumParseResult.parsed) ?? .unrecognized
        default:
            return .unrecognized
        }
    }

    private static func isHexToken(_ value: String) -> Bool {
        !value.isEmpty && value.unicodeScalars.allSatisfy { CharacterSet.hexDigits.contains($0) }
    }
}

private extension CharacterSet {
    static let hexDigits = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
}
