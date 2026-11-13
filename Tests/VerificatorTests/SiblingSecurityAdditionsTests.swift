// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing
@testable import VerificatorCore

@Suite("Sibling Security Additions Tests")
struct SiblingSecurityAdditionsTests {

    @Test("OpenSafety detects RTLO/fillers and preserves valid emoji & Finder Icon\\r")
    func openSafetyDetectionAndPreservation() {
        #expect(!OpenSafety.hasDeceptiveCharacters("Verificator.app"))
        #expect(!OpenSafety.hasDeceptiveCharacters("Rocket 🚀\u{FE0F}.app"))
        #expect(!OpenSafety.hasDeceptiveCharacters("Dev 👨\u{200D}💻 Tool.app"))
        #expect(!OpenSafety.hasDeceptiveCharacters(OpenSafety.finderCustomIconFileName))

        let rtlo = "invoice\u{202E}gpj.app"
        #expect(OpenSafety.hasDeceptiveCharacters(rtlo))
        #expect(OpenSafety.visibleName(rtlo) == "invoice⟦U+202E⟧gpj.app")

        let brailleBlank = "helper\u{2800}bin"
        #expect(OpenSafety.hasDeceptiveCharacters(brailleBlank))
        #expect(OpenSafety.visibleName(brailleBlank) == "helper⟦U+2800⟧bin")

        let collected = OpenSafety.collectDeceptiveNames(in: [rtlo, rtlo, "clean.app", OpenSafety.finderCustomIconFileName])
        #expect(collected == ["invoice⟦U+202E⟧gpj.app"])
    }

    @Test("ForensicScanner flags RTLO bundle names as warning without false positives on clean bundles")
    func scannerFlagsDeceptiveBundleName() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("OpenSafety-\(UUID().uuidString)")
        let spoofURL = tmp.appendingPathComponent("Document\u{202E}fdp.app", isDirectory: true)
        let contents = spoofURL.appendingPathComponent("Contents", isDirectory: true)
        let macOS = contents.appendingPathComponent("MacOS", isDirectory: true)
        try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let execURL = macOS.appendingPathComponent("AppBin")
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/echo"), to: execURL)
        let info: [String: Any] = [
            "CFBundleIdentifier": "com.example.spoof",
            "CFBundleName": "LegitApp",
            "CFBundleExecutable": "AppBin",
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
        ]
        let plistData = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        try plistData.write(to: contents.appendingPathComponent("Info.plist"))

        // Re-sign ad-hoc so the bundle seal is intact and the only anomaly is the deceptive RTLO name.
        let sign = Process()
        sign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        sign.arguments = ["--force", "--sign", "-", "--deep", spoofURL.path]
        try sign.run()
        sign.waitUntilExit()
        #expect(sign.terminationStatus == 0)

        let report = ForensicScanner.auditTarget(at: spoofURL, options: ScanOptions(checkApplicationFirewall: false))
        #expect(report.verdict == .warning)
        #expect(!report.deceptiveNames.isEmpty)
        #expect(report.findings.contains { $0.titleKey == .findingNameSpoofingTitle })
    }

    @Test("ApplicationFirewall parses socketfilterfw output and quotes unblock command")
    func firewallParserAndCommand() {
        let sample = """
        Firewall is enabled. (State = 1)
        Firewall has block all state set to disabled.
        Firewall stealth mode is off
        """
        let status = ApplicationFirewall.parseSystemStatus(sample)
        #expect(status == FirewallStatus(globalEnabled: true, blockAll: false, stealthMode: false))

        #expect(ApplicationFirewall.parseAppBlocked("Incoming connection to /Applications/App.app is blocked.") == .blocked)
        #expect(ApplicationFirewall.parseAppBlocked("Incoming connection to /Applications/App.app is permitted.") == .permitted)
        #expect(ApplicationFirewall.parseAppBlocked("") == nil)

        let cmd = ApplicationFirewall.unblockCommand(for: "/Applications/My \"App\".app")
        #expect(cmd.contains("--unblockapp"))
        #expect(cmd.hasPrefix("sudo /usr/libexec/ApplicationFirewall/socketfilterfw"))
        #expect(cmd.contains("\\\"App\\\""))
    }

    @Test("ExpectedChecksum parses hex, GNU, BSD, multi-line files, and rejects weak hashes")
    func expectedChecksumParsingAndVerification() throws {
        let digest256 = String(repeating: "a", count: 64)
        let other256 = String(repeating: "b", count: 64)
        let digest512 = String(repeating: "c", count: 128)
        let wrong256 = String(repeating: "d", count: 64)

        if case .parsed(let raw256) = ChecksumInput.parse("SHA256: \(digest256.uppercased())") {
            #expect(raw256 == ExpectedChecksum(validatedAlgorithm: .sha256, lowercasedHex: digest256))
            #expect(raw256.verify(actualSHA256: digest256, actualSHA512: digest512) == .matched(raw256, actualHex: digest256))
            #expect(raw256.verify(actualSHA256: wrong256, actualSHA512: digest512) == .mismatch(expected: raw256, actualHex: wrong256))
        } else {
            Issue.record("Failed to parse prefixed SHA-256")
        }

        if case .parsed(let bsd512) = ChecksumInput.parse("SHA512 (/tmp/MyApp.dmg) = \(digest512)") {
            #expect(bsd512.algorithm == .sha512)
            #expect(bsd512.verify(actualSHA256: digest256, actualSHA512: digest512) == .matched(bsd512, actualHex: digest512))
        } else {
            Issue.record("Failed to parse BSD SHA512")
        }

        let sumsFile = """
        # Release checksums
        \(other256)  OtherApp-1.0.dmg
        \(digest256) *Verificator-1.3.0.dmg
        """
        if case .parsed(let matched) = ChecksumInput.parse(sumsFile, fileName: "Verificator-1.3.0.dmg") {
            #expect(matched.hex == digest256)
        } else {
            Issue.record("Failed to match Verificator-1.3.0.dmg in multi-line sums")
        }

        #expect(ChecksumInput.parse(sumsFile, fileName: "Missing.dmg") == .notFoundForFile("Missing.dmg"))
        #expect(ChecksumInput.parse(String(repeating: "a", count: 32)) == .weakAlgorithm("MD5"))
        #expect(ChecksumInput.parse("sha1:\(String(repeating: "a", count: 40))") == .weakAlgorithm("SHA-1"))
    }

    @Test("InternetAccessPolicy merges nested policies and expands %APPNAME%")
    func internetAccessPolicyLoadAndMerge() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("IAP-\(UUID().uuidString)")
        let res = tmp.appendingPathComponent("Sample.app/Contents/Resources", isDirectory: true)
        let trLproj = res.appendingPathComponent("tr.lproj", isDirectory: true)
        let helperRes = tmp.appendingPathComponent("Sample.app/Contents/XPCServices/Helper.xpc/Contents/Resources", isDirectory: true)
        try FileManager.default.createDirectory(at: trLproj, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: helperRes, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let mainPlist: [String: Any] = [
            "DeveloperName": "Test Dev",
            "ApplicationDescription": "DescKey",
            "Website": "https://example.com",
            "Connections": [
                [
                    "Host": "api.example.com",
                    "Port": "443",
                    "NetworkProtocol": "TCP",
                    "IsIncoming": false,
                    "Relevance": "Essential",
                    "Purpose": "PurposeKey",
                ]
            ],
        ]
        try PropertyListSerialization.data(fromPropertyList: mainPlist, format: .xml, options: 0)
            .write(to: res.appendingPathComponent("InternetAccessPolicy.plist"))
        try "\"DescKey\" = \"%APPNAME% açıklaması\";\n\"PurposeKey\" = \"Güncelleme\";\n"
            .write(to: trLproj.appendingPathComponent("InternetAccessPolicy.strings"), atomically: true, encoding: .utf8)

        let helperPlist: [String: Any] = [
            "ApplicationDescription": "Helper desc",
            "Connections": [
                [
                    "Host": "127.0.0.1",
                    "Port": 11434,
                    "Purpose": "Local AI",
                ]
            ],
        ]
        try PropertyListSerialization.data(fromPropertyList: helperPlist, format: .xml, options: 0)
            .write(to: helperRes.appendingPathComponent("InternetAccessPolicy.plist"))

        let policy = try #require(InternetAccessPolicy.load(bundle: tmp.appendingPathComponent("Sample.app"), languages: ["tr"]))
        #expect(policy.applicationDescription == "Sample açıklaması")
        #expect(policy.connections.count == 2)
        #expect(policy.connections[0].purpose == "Güncelleme")
        #expect(policy.connections[0].isEssential)
        #expect(policy.connections[1].portSpec == "11434")
    }

    @Test("DiagnosticMasker redacts home, username, and report paths consistently within session")
    func diagnosticMaskerRedaction() throws {
        let masker = DiagnosticMasker(homePath: "/Users/alice", userName: "alice")
        let p1 = masker.maskPath("/Users/alice/Desktop/SecretTool/SecretTool.app/Contents/MacOS/SecretTool")
        let p2 = masker.maskPath("/Users/alice/Desktop/SecretTool/SecretTool.app/Contents/MacOS/SecretTool")
        #expect(p1 == p2)
        #expect(!p1.contains("alice"))
        #expect(!p1.contains("SecretTool"))
        #expect(p1.hasPrefix("~/"))
        #expect(p1.contains("/Contents/MacOS/"))

        let redactedText = masker.redact(text: "Scanned /Users/alice/Downloads/mybin by alice at /Users/bob/tmp")
        #expect(!redactedText.contains("alice"))
        #expect(!redactedText.contains("bob"))
        #expect(redactedText.contains("~/Downloads/"))

        let otherSession = DiagnosticMasker(homePath: "/Users/alice", userName: "alice")
        #expect(masker.maskUserName("alice") != otherSession.maskUserName("alice"))
    }

    @Test("VolumeEncryption evaluates removable unencrypted warning logic and reads boot volume")
    func volumeEncryptionLogic() {
        let usbUnencrypted = VolumeEncryptionInfo(
            volumePath: "/Volumes/USB",
            volumeName: "USB",
            format: "ExFAT",
            isEncrypted: false,
            isRemovable: true,
            isInternal: false,
            isLocal: true
        )
        #expect(usbUnencrypted.needsUnencryptedRemovableWarning)

        let encryptedExternal = VolumeEncryptionInfo(
            volumePath: "/Volumes/Vault",
            volumeName: "Vault",
            format: "APFS (Encrypted)",
            isEncrypted: true,
            isRemovable: true,
            isInternal: false,
            isLocal: true
        )
        #expect(!encryptedExternal.needsUnencryptedRemovableWarning)

        let boot = VolumeEncryptionInfo.readBootVolume()
        #expect(boot != nil)
    }
}
