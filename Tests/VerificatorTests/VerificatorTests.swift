// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing
@testable import VerificatorCore

@Suite("Verificator Core & Localization Tests")
struct VerificatorTests {

    private var repoRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func loadLocalizableStrings(for lang: String) -> [String: String] {
        let url = repoRoot
            .appendingPathComponent("Resources", isDirectory: true)
            .appendingPathComponent("\(lang).lproj", isDirectory: true)
            .appendingPathComponent("Localizable.strings")
        return StringTable.parseStringsFile(at: url) ?? [:]
    }

    @Test("1:1 Exact Trilingual Localization Parity (tr, en, ro)")
    func localizationParityAcrossAllLanguages() {
        let languages = AppLanguage.supportedCodes
        let allKeys = Set(LKey.allCases.map(\.rawValue))
        var tables: [String: [String: String]] = [:]

        for lang in languages {
            let dict = loadLocalizableStrings(for: lang)
            tables[lang] = dict
            #expect(!dict.isEmpty, "Language dictionary for \(lang) must not be empty")

            let loadedKeys = Set(dict.keys)
            let missing = allKeys.subtracting(loadedKeys).sorted()
            #expect(missing.isEmpty, "Missing keys in \(lang): \(missing)")

            let extra = loadedKeys.subtracting(allKeys).sorted()
            #expect(extra.isEmpty, "Extra unreferenced keys in \(lang): \(extra)")

            for key in LKey.allCases {
                let value = dict[key.rawValue] ?? ""
                #expect(!value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                        "Empty translation for key \(key.rawValue) in \(lang)")
            }
        }

        let table = StringTable(tables: tables)
        for lang in languages {
            #expect(!table.string(.restartWarningTitle, language: lang).isEmpty)
            #expect(!table.string(.restartMenuBarNotice, language: lang).isEmpty)
        }
    }

    @Test("Positional Format Specifier Parity Across Languages")
    func formatSpecifierParity() {
        let trDict = loadLocalizableStrings(for: "tr")
        let enDict = loadLocalizableStrings(for: "en")
        let roDict = loadLocalizableStrings(for: "ro")

        let specifierRegex = try! NSRegularExpression(pattern: "%(?:\\d+\\$)?[@dDuUxXoOfeEgGcCsSpaA]|%[0-9]*\\.?[0-9]*f|%\\d+\\$ld")

        func extractSpecifiers(_ text: String) -> [String] {
            let ns = text as NSString
            let matches = specifierRegex.matches(in: text, range: NSRange(location: 0, length: ns.length))
            return matches.map { ns.substring(with: $0.range) }.sorted()
        }

        for key in LKey.allCases {
            let trSpecs = extractSpecifiers(trDict[key.rawValue] ?? "")
            let enSpecs = extractSpecifiers(enDict[key.rawValue] ?? "")
            let roSpecs = extractSpecifiers(roDict[key.rawValue] ?? "")

            #expect(trSpecs == enSpecs, "Specifier mismatch between tr and en for key \(key.rawValue): \(trSpecs) vs \(enSpecs)")
            #expect(trSpecs == roSpecs, "Specifier mismatch between tr and ro for key \(key.rawValue): \(trSpecs) vs \(roSpecs)")
        }
    }

    @Test("InfoPlist.strings 1:1 Key Parity Across Languages")
    func infoPlistStringsParity() {
        let langs = AppLanguage.supportedCodes
        var dicts: [String: [String: String]] = [:]

        for lang in langs {
            let url = repoRoot
                .appendingPathComponent("Resources", isDirectory: true)
                .appendingPathComponent("\(lang).lproj", isDirectory: true)
                .appendingPathComponent("InfoPlist.strings")
            let loaded = NSDictionary(contentsOf: url) as? [String: String] ?? [:]
            #expect(!loaded.isEmpty, "InfoPlist.strings for \(lang) must exist and not be empty")
            dicts[lang] = loaded
        }

        let trKeys = Set(dicts["tr"]?.keys ?? [:].keys)
        let enKeys = Set(dicts["en"]?.keys ?? [:].keys)
        let roKeys = Set(dicts["ro"]?.keys ?? [:].keys)

        #expect(trKeys == enKeys, "InfoPlist.strings keys mismatch between tr and en")
        #expect(trKeys == roKeys, "InfoPlist.strings keys mismatch between tr and ro")
    }

    @Test("AppUpdateChecker Version Comparison & URL Validation")
    func updateCheckerInvariants() {
        #expect(AppUpdateChecker.isNewer("1.2.1", than: "1.2.0"))
        #expect(AppUpdateChecker.isNewer("2.0.0", than: "1.9.9"))
        #expect(!AppUpdateChecker.isNewer("1.2.0", than: "1.2.0"))
        #expect(!AppUpdateChecker.isNewer("1.1.9", than: "1.2.0"))

        let repo = AppInfo.repository
        let validRelease = URL(string: "https://github.com/\(repo)/releases/tag/v1.2.0")!
        let validDownload = URL(string: "https://github.com/\(repo)/releases/download/v1.2.0/Verificator.dmg")!
        let invalidHost = URL(string: "https://evil.example.com/Verificator.dmg")!
        let insecureHTTP = URL(string: "http://github.com/\(repo)/releases/tag/v1.2.0")!

        #expect(AppUpdateChecker.isReleaseURL(validRelease, repository: repo, download: false))
        #expect(AppUpdateChecker.isReleaseURL(validDownload, repository: repo, download: true))
        #expect(!AppUpdateChecker.isReleaseURL(invalidHost, repository: repo, download: true))
        #expect(!AppUpdateChecker.isReleaseURL(insecureHTTP, repository: repo, download: false))
    }

    @Test("UpdateChecksums SHA256SUMS Parser")
    func updateChecksumsParser() {
        let sample = """
        # SHA256SUMS
        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 *Verificator-1.2.0.dmg
        0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  ./Verificator-1.2.0.zip
        """
        let parsed = UpdateChecksums.parse(sample)
        #expect(parsed["Verificator-1.2.0.dmg"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        #expect(parsed["./Verificator-1.2.0.zip"] == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    }

    @Test("AppLog Entry Serialization & Deserialization Round-Trip")
    func appLogRoundTrip() {
        let entry = AppLog.Entry(
            id: 42,
            date: Date(timeIntervalSince1970: 1_762_000_000),
            level: .warning,
            category: .scanner,
            process: 1234,
            message: "Test line 1\nTest line 2\tTabbed",
            detail: "Detailed trace\nLine 2"
        )
        let line = AppLog.line(for: entry)
        let parsed = AppLog.parse(line).first
        #expect(parsed != nil)
        #expect(parsed?.level == .warning)
        #expect(parsed?.category == .scanner)
        #expect(parsed?.process == 1234)
        #expect(parsed?.message == "Test line 1\nTest line 2\tTabbed")
        #expect(parsed?.detail == "Detailed trace\nLine 2")
    }

    @Test("Forensic Tool Availability Check")
    func forensicToolsAvailable() {
        let tools = ForensicScanner.inspectTools()
        #expect(tools.count == 5)
        for tool in tools {
            #expect(tool.isAvailable, "System tool \(tool.path) must be present on macOS")
        }
    }

    @Test("ForensicScanner Zero False-Positive & Tampered Detection")
    func forensicScannerCalibration() {
        let fm = FileManager.default

        // 1. Clean sibling app if installed
        let arhivarURL = URL(fileURLWithPath: "/Applications/Arhivar.app")
        if fm.fileExists(atPath: arhivarURL.path) {
            let report = ForensicScanner.auditBundle(at: arhivarURL)
            #expect(report.verdict == .clean, "Arhivar.app must be reported as CLEAN (0% false positive)")
        }

        // 2. Clean vendor installer vs Tampered cracked app if present in ~/Downloads
        let cleanUPDF = URL(fileURLWithPath: "/Users/berkbabadogan/Downloads/UPDF Installer.app")
        if fm.fileExists(atPath: cleanUPDF.path) {
            let report = ForensicScanner.auditBundle(at: cleanUPDF)
            #expect(report.verdict == .clean, "UPDF Installer.app must be reported as CLEAN")
        }

        let crackedUPDF = URL(fileURLWithPath: "/Users/berkbabadogan/Downloads/UPDF.app")
        if fm.fileExists(atPath: crackedUPDF.path) {
            let report = ForensicScanner.auditBundle(at: crackedUPDF)
            #expect(report.verdict == .tampered, "Cracked UPDF.app must be reported as TAMPERED")
            #expect(report.findings.contains { $0.severity == .critical })
        }
    }

    // MARK: - 9. On-Device AI & Local Model Filtering Tests

    @Test("Apple Intelligence Default First Provider, Local Model Filtering & No Silent Fallback")
    func testLocalModelsAndAIPrerequisites() {
        #expect(SuggestionProvider.allCases.first == .apple)
        #expect(SuggestionProvider.models == [.apple, .ollama, .lmStudio])

        let ollamaJSON = """
        {
          "models": [
            {"name": "qwen2.5-coder:7b", "capabilities": ["completion"]},
            {"name": "nomic-embed-text:latest", "capabilities": ["embedding"]},
            {"name": "gpt-oss:120b-cloud", "capabilities": ["completion"]},
            {"name": "remote:latest", "remote_host": "https://ollama.com"}
          ]
        }
        """.data(using: .utf8)!
        #expect(LocalModelServer.ollamaModels(ollamaJSON) == ["qwen2.5-coder:7b"])

        let openAIJSON = """
        {
          "data": [
            {"id": "llama-3.2-3b-instruct"},
            {"id": "text-embedding-nomic-embed-text-v1.5"}
          ]
        }
        """.data(using: .utf8)!
        #expect(LocalModelServer.openAIModels(openAIJSON) == ["llama-3.2-3b-instruct"])

        #expect(LocalModelServer.withoutThinking("<think>internal</think> Clean verdict.") == "Clean verdict.")

        // Server running but no local chat model -> .noLocalModel (no silent fallback)
        let noModelProblem = AIPrerequisites.providerProblem(
            for: .ollama,
            appleProblem: nil,
            runningServers: [.ollama],
            localModels: [.ollama: []],
            selectedModel: ""
        )
        #expect(noModelProblem == .noLocalModel)

        // Server not running -> .serverNotRunning
        let offlineProblem = AIPrerequisites.providerProblem(
            for: .lmStudio,
            appleProblem: nil,
            runningServers: [],
            localModels: [:],
            selectedModel: ""
        )
        #expect(offlineProblem == .serverNotRunning)
    }
}
