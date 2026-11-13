// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import Foundation
import Testing
@testable import VerificatorCore
@testable import VerificatorKit

@Suite("Bundle & System Resource Verification Tests")
struct BundleVerificationTests {

    private var repoRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func loadStringsTable(named filename: String, language: String) -> [String: String] {
        let url = repoRoot
            .appendingPathComponent("Resources", isDirectory: true)
            .appendingPathComponent("\(language).lproj", isDirectory: true)
            .appendingPathComponent(filename)
        return NSDictionary(contentsOf: url) as? [String: String]
            ?? StringTable.parseStringsFile(at: url)
            ?? [:]
    }

    @Test("ServicesMenu.strings Exists & Has 1:1 Trilingual Parity (tr, en, ro)")
    func servicesMenuStringsParity() {
        var tables: [String: [String: String]] = [:]
        for lang in AppLanguage.supportedCodes {
            let table = loadStringsTable(named: "ServicesMenu.strings", language: lang)
            #expect(!table.isEmpty, "ServicesMenu.strings must not be empty for \(lang)")
            #expect(!(table["Audit with Verificator"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                    "Missing 'Audit with Verificator' entry for \(lang)")
            tables[lang] = table
        }
        let baseKeys = Set(tables["en"]?.keys ?? [:].keys)
        for lang in AppLanguage.supportedCodes {
            #expect(Set(tables[lang]?.keys ?? [:].keys) == baseKeys, "Key mismatch in ServicesMenu.strings for \(lang)")
        }
    }

    @Test("AppShortcuts.strings Exists, Preserves applicationName Token & Has 1:1 Parity")
    func appShortcutsStringsParity() {
        var tables: [String: [String: String]] = [:]
        for lang in AppLanguage.supportedCodes {
            let table = loadStringsTable(named: "AppShortcuts.strings", language: lang)
            #expect(!table.isEmpty, "AppShortcuts.strings must not be empty for \(lang)")
            for (key, value) in table {
                #expect(!value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                        "Empty AppShortcuts value for \(key) in \(lang)")
                #expect(value.contains("${applicationName}"),
                        "AppShortcuts phrase '\(key)' in \(lang) must contain ${applicationName}")
            }
            tables[lang] = table
        }
        let baseKeys = Set(tables["en"]?.keys ?? [:].keys)
        for lang in AppLanguage.supportedCodes {
            #expect(Set(tables[lang]?.keys ?? [:].keys) == baseKeys, "Key mismatch in AppShortcuts.strings for \(lang)")
        }
    }

    @Test("Support/Info.plist Declares Bundle ID, URL Scheme & Finder Services Metadata")
    func infoPlistContract() throws {
        let plistURL = repoRoot.appendingPathComponent("Support/Info.plist")
        let data = try Data(contentsOf: plistURL)
        let dict = try #require(PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])

        #expect(dict["CFBundleIdentifier"] as? String == "com.babadogantech.verificator")
        #expect(dict["CFBundleShortVersionString"] as? String == AppInfo.fallbackVersion)
        #expect(dict["CFBundleVersion"] as? String == AppInfo.fallbackBuild)

        let urlTypes = dict["CFBundleURLTypes"] as? [[String: Any]] ?? []
        let schemes = urlTypes.flatMap { $0["CFBundleURLSchemes"] as? [String] ?? [] }
        #expect(schemes.contains("verificator"))

        let services = dict["NSServices"] as? [[String: Any]] ?? []
        let auditService = services.first { service in
            (service["NSMessage"] as? String) == "auditServiceItem"
        }
        #expect(auditService != nil)
        #expect(auditService?["NSPortName"] as? String == "Verificator")
        #expect(auditService?["NSRequiredContext"] as? [String: Any] != nil)
        let sendFileTypes = Set(auditService?["NSSendFileTypes"] as? [String] ?? [])
        #expect(sendFileTypes.contains("public.item"))
        #expect(sendFileTypes.contains("public.folder"))
    }

    @Test("Finder Service Pasteboard Extraction & Selector Contract")
    @MainActor
    func finderServicePasteboardExtraction() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("verificator-service-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let targetFile = tempDir.appendingPathComponent("Sample.dmg")
        try Data("dmg".utf8).write(to: targetFile)

        let pboard = NSPasteboard.withUniqueName()
        defer { pboard.releaseGlobally() }

        pboard.clearContents()
        pboard.writeObjects([targetFile as NSURL])
        #expect(AppDelegate.extractServiceTargetURLs(from: pboard).first?.standardizedFileURL == targetFile.standardizedFileURL)

        pboard.clearContents()
        pboard.setPropertyList([targetFile.path], forType: NSPasteboard.PasteboardType("NSFilenamesPboardType"))
        #expect(AppDelegate.extractServiceTargetURLs(from: pboard).first?.standardizedFileURL == targetFile.standardizedFileURL)

        pboard.clearContents()
        pboard.setString(targetFile.path, forType: .string)
        #expect(AppDelegate.extractServiceTargetURLs(from: pboard).first?.standardizedFileURL == targetFile.standardizedFileURL)

        let delegate = AppDelegate()
        #expect(delegate.responds(to: NSSelectorFromString("auditServiceItem:userData:error:")))
    }

    @Test("InternetAccessPolicy.plist & tr/en/ro InternetAccessPolicy.strings Exist with 1:1 Parity")
    func internetAccessPolicyParity() throws {
        let plistURL = repoRoot.appendingPathComponent("Resources/InternetAccessPolicy.plist")
        let data = try Data(contentsOf: plistURL)
        let dict = try #require(PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])

        var tables: [String: [String: String]] = [:]
        for lang in AppLanguage.supportedCodes {
            let table = loadStringsTable(named: "InternetAccessPolicy.strings", language: lang)
            #expect(!table.isEmpty, "InternetAccessPolicy.strings must not be empty for \(lang)")
            for (k, v) in table {
                #expect(!v.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                        "Empty InternetAccessPolicy string for \(k) in \(lang)")
            }
            let policy = try #require(InternetAccessPolicy.parse(dict, strings: table, appName: "Verificator"),
                                      "InternetAccessPolicy failed to parse for \(lang)")
            #expect(policy.connections.count >= 3)
            #expect(policy.developerName == "Babadogan Tech and Edu")
            tables[lang] = table
        }
        let baseKeys = Set(tables["en"]?.keys ?? [:].keys)
        for lang in AppLanguage.supportedCodes {
            #expect(Set(tables[lang]?.keys ?? [:].keys) == baseKeys, "Key mismatch in InternetAccessPolicy.strings for \(lang)")
        }
    }
}
