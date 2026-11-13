// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing
@testable import VerificatorCore

/// Deterministic SplitMix64 generator for reproducible fuzz testing across security parsers.
private struct SplitMix64 {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    mutating func nextInt(_ upperBound: Int) -> Int {
        Int(next() % UInt64(upperBound))
    }

    mutating func nextBool() -> Bool {
        (next() & 1) == 1
    }

    mutating func nextString(length: Int, alphabet: [UnicodeScalar]) -> String {
        var out = ""
        out.reserveCapacity(length)
        for _ in 0..<length {
            out.unicodeScalars.append(alphabet[nextInt(alphabet.count)])
        }
        return out
    }
}

@Suite("Deterministic SplitMix64 Security Parser Fuzz Tests")
struct FuzzTests {

    @Test("OpenSafety survives arbitrary and hostile Unicode splicing without bypassing detection")
    func fuzzOpenSafety() {
        var rng = SplitMix64(seed: 0x5645_5249_4649_4341)
        let asciiSafe = Array("abcdefghijklmnopqrstuvwxyz0123456789.-_ ".unicodeScalars)
        let hostileScalars: [Unicode.Scalar] = [
            Unicode.Scalar(0x202E)!, // RTLO
            Unicode.Scalar(0x202D)!, // LRO
            Unicode.Scalar(0x2066)!, // LRI
            Unicode.Scalar(0x200B)!, // ZWSP
            Unicode.Scalar(0x2800)!, // Braille blank
            Unicode.Scalar(0x3164)!, // Hangul filler
            Unicode.Scalar(0xFEFF)!, // BOM
            Unicode.Scalar(0x0007)!, // BEL control
        ]

        for _ in 0..<600 {
            let prefix = rng.nextString(length: rng.nextInt(16), alphabet: asciiSafe)
            let suffix = rng.nextString(length: rng.nextInt(16), alphabet: asciiSafe)

            #expect(!OpenSafety.hasDeceptiveCharacters(prefix + suffix))
            #expect(OpenSafety.visibleName(prefix + suffix) == prefix + suffix)

            let hostile = hostileScalars[rng.nextInt(hostileScalars.count)]
            var spliced = prefix
            spliced.unicodeScalars.append(hostile)
            spliced += suffix
            #expect(OpenSafety.hasDeceptiveCharacters(spliced))
            let revealed = OpenSafety.visibleName(spliced)
            #expect(revealed.contains("⟦U+"))
            #expect(!OpenSafety.hasDeceptiveCharacters(revealed))
        }
    }

    @Test("ChecksumInput handles arbitrary fuzzed text and multi-line inputs cleanly")
    func fuzzChecksumInput() {
        var rng = SplitMix64(seed: 0x4348_4543_4B53_554D)
        let hexChars = Array("0123456789abcdefABCDEF".unicodeScalars)
        let noisyChars = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 :=*()\n\t#/._-!".unicodeScalars)

        for _ in 0..<500 {
            let valid64 = rng.nextString(length: 64, alphabet: hexChars)
            if case .parsed(let c256) = ChecksumInput.parse(valid64) {
                #expect(c256.algorithm == .sha256)
                #expect(c256.hex == valid64.lowercased())
            } else {
                Issue.record("Valid 64-hex failed to parse")
            }

            let valid128 = rng.nextString(length: 128, alphabet: hexChars)
            if case .parsed(let c512) = ChecksumInput.parse(valid128) {
                #expect(c512.algorithm == .sha512)
            } else {
                Issue.record("Valid 128-hex failed to parse")
            }

            let weak40 = rng.nextString(length: 40, alphabet: hexChars)
            if case .weakAlgorithm = ChecksumInput.parse(weak40) {
                // Expected rejection of SHA-1
            } else {
                Issue.record("40-hex SHA-1 should always be rejected as weak")
            }

            let garbage = rng.nextString(length: rng.nextInt(256), alphabet: noisyChars)
            _ = ChecksumInput.parse(garbage, fileName: "App.dmg")
        }
    }

    @Test("ApplicationFirewall & InternetAccessPolicy & ForensicScanner survive fuzzed inputs")
    func fuzzFirewallIAPAndScannerParsers() {
        var rng = SplitMix64(seed: 0x4657_4941_5053_434E)
        let tokens = [
            "Firewall is enabled. (State = 1)",
            "Firewall is disabled. (State = 0)",
            "Firewall has block all state set to enabled.",
            "Firewall has block all state set to disabled.",
            "Firewall stealth mode is on",
            "Firewall stealth mode is off",
            "Incoming connection to /Applications/App.app is blocked.",
            "Incoming connection to /Applications/App.app is permitted.",
            "random garbage $$$ ??? \n\r",
        ]

        for _ in 0..<400 {
            let lines = (0..<rng.nextInt(12)).map { _ in tokens[rng.nextInt(tokens.count)] }.joined(separator: "\n")
            _ = ApplicationFirewall.parseSystemStatus(lines)
            for line in lines.split(whereSeparator: \.isNewline) {
                _ = ApplicationFirewall.parseAppBlocked(String(line))
            }

            let scheme = ["http://example.com", "https://example.com", "javascript:alert(1)", "file:///etc/passwd", "not a url"][rng.nextInt(5)]
            let dict: [String: Any] = [
                "ApplicationDescription": rng.nextBool() ? "App desc" : "",
                "Website": scheme,
                "Connections": [
                    ["Host": rng.nextBool() ? "example.com, *.apple.com" : "", "Port": rng.nextBool() ? 443 : "bad", "Purpose": "Test"],
                ],
            ]
            if let policy = InternetAccessPolicy.parse(dict, appName: "FuzzApp") {
                if let site = policy.website {
                    #expect(site.hasPrefix("http://") || site.hasPrefix("https://"))
                }
            }

            let rawQuarantine = rng.nextBool()
                ? "0081;67000000;Safari;" + UUID().uuidString
                : "random;\(rng.nextString(length: 12, alphabet: Array("0123456789abcdef;xyz".unicodeScalars)))"
            _ = ForensicScanner.isActiveQuarantineAttributeValue(rawQuarantine)

            let rawGk = ["assessments enabled", "assessments disabled", "", "unexpected\nline"][rng.nextInt(4)]
            _ = GatekeeperStatus.parse(rawGk)

            let masker = DiagnosticMasker(homePath: "/Users/fuzzuser", userName: "fuzzuser")
            let rawText = "Path /Users/fuzzuser/Desktop/secret_\(rng.nextInt(999))/bin by fuzzuser"
            let redacted = masker.redact(text: rawText)
            #expect(!redacted.contains("fuzzuser"))
        }
    }
}
