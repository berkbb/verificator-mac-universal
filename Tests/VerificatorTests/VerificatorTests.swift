// SPDX-License-Identifier: GPL-3.0-only
import CryptoKit
import Foundation
import Testing
@testable import VerificatorCore
@testable import VerificatorKit

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

        let notFoundJSON = """
        {"message": "Not Found", "documentation_url": "https://docs.github.com/rest/releases/releases#get-the-latest-release"}
        """.data(using: .utf8)!
        #expect(throws: AppUpdateChecker.CheckError.noReleases) {
            try AppUpdateChecker.parse(notFoundJSON, repository: repo)
        }
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
        #expect(tools.count == 7)
        #expect(tools.contains { $0.name == "pkgutil" })
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

        let roCheckURL = URL(fileURLWithPath: "/Applications/RoCheck.app")
        if fm.fileExists(atPath: roCheckURL.path) {
            let report = ForensicScanner.auditBundle(at: roCheckURL)
            #expect(report.verdict == .clean, "RoCheck.app must be reported as CLEAN (0% false positive on local unsigned/ad-hoc developer build)")
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

    @Test("Quarantine Attribute Value Parsing (Active vs User-Approved vs Malformed)")
    func quarantineAttributeValueParsing() {
        // Active unapproved quarantine flags must evaluate to true
        #expect(ForensicScanner.isActiveQuarantineAttributeValue("0183;69eb99db;Safari;12345678-1234-1234-1234-1234567890AB"))
        #expect(ForensicScanner.isActiveQuarantineAttributeValue("0083;69eb99db;Safari;"))
        #expect(ForensicScanner.isActiveQuarantineAttributeValue("0081;69eb99db;curl;"))
        #expect(ForensicScanner.isActiveQuarantineAttributeValue("0281;69eb99db;Safari;"))
        #expect(ForensicScanner.isActiveQuarantineAttributeValue("0183;69eb99db"))

        // User-approved (0x0040) and Gatekeeper-cleared (0x4000 / 0x8000) flags must evaluate to false
        #expect(!ForensicScanner.isActiveQuarantineAttributeValue("01c3;69eb99db;Safari;12345678-1234-1234-1234-1234567890AB"))
        #expect(!ForensicScanner.isActiveQuarantineAttributeValue("00c3;69eb99db;Chrome;"))
        #expect(!ForensicScanner.isActiveQuarantineAttributeValue("01c1;69eb99db;Safari;"))
        #expect(!ForensicScanner.isActiveQuarantineAttributeValue("0040;69eb99db;;"))
        #expect(!ForensicScanner.isActiveQuarantineAttributeValue("4081;69eb99db;;"))
        #expect(!ForensicScanner.isActiveQuarantineAttributeValue("8081;69eb99db;;"))

        // Empty or malformed attribute values must evaluate to false
        #expect(!ForensicScanner.isActiveQuarantineAttributeValue(""))
        #expect(!ForensicScanner.isActiveQuarantineAttributeValue("0183"))
        #expect(!ForensicScanner.isActiveQuarantineAttributeValue("0183;"))
        #expect(!ForensicScanner.isActiveQuarantineAttributeValue("0183;69eb99db;Safari"))
        #expect(!ForensicScanner.isActiveQuarantineAttributeValue("zzzz;69eb99db;Safari;"))
        #expect(!ForensicScanner.isActiveQuarantineAttributeValue("0x0183;69eb99db;Safari;"))
    }

    @Test("Quarantine Bundle Detection Across Synthetic Bundles, Symlinks, and Cache Invalidation")
    func quarantineBundleDetection() throws {
        let fm = FileManager.default
        let rootDir = fm.temporaryDirectory.appendingPathComponent("VerificatorQuarantineTests-\(UUID().uuidString)")
        try fm.createDirectory(at: rootDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: rootDir) }

        func makeAppBundle(named name: String) throws -> (bundle: URL, exec: URL, resource: URL) {
            let appURL = rootDir.appendingPathComponent("\(name).app")
            let macOSDir = appURL.appendingPathComponent("Contents/MacOS")
            let resourcesDir = appURL.appendingPathComponent("Contents/Resources")
            try fm.createDirectory(at: macOSDir, withIntermediateDirectories: true)
            try fm.createDirectory(at: resourcesDir, withIntermediateDirectories: true)

            let infoPlist = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>CFBundleExecutable</key>
                <string>\(name)</string>
                <key>CFBundleIdentifier</key>
                <string>com.example.\(name.lowercased())</string>
            </dict>
            </plist>
            """
            try infoPlist.write(to: appURL.appendingPathComponent("Contents/Info.plist"), atomically: true, encoding: .utf8)

            let execURL = macOSDir.appendingPathComponent(name)
            try Data("#!/bin/sh\necho ok\n".utf8).write(to: execURL)

            let resourceURL = resourcesDir.appendingPathComponent("asset.txt")
            try Data("asset".utf8).write(to: resourceURL)
            return (appURL, execURL, resourceURL)
        }

        func setQuarantine(_ value: String, on path: String, options: Int32 = 0) {
            let bytes = Array(value.utf8)
            let rc = setxattr(path, "com.apple.quarantine", bytes, bytes.count, 0, options)
            #expect(rc == 0, "Failed to set com.apple.quarantine on \(path)")
        }

        // 1. Clean bundle without xattr
        let cleanApp = try makeAppBundle(named: "CleanApp")
        #expect(!ForensicScanner.hasQuarantineAttribute(at: cleanApp.bundle.path, executablePath: cleanApp.exec.path))

        // 2. User-approved quarantine flags on root (01c3, 00c3, 01c1) must be false
        for flag in ["01c3;69eb99db;Safari;", "00c3;69eb99db;Chrome;", "01c1;69eb99db;Safari;"] {
            setQuarantine(flag, on: cleanApp.bundle.path)
            #expect(!ForensicScanner.hasQuarantineAttribute(at: cleanApp.bundle.path, executablePath: cleanApp.exec.path))
        }
        removexattr(cleanApp.bundle.path, "com.apple.quarantine", 0)

        // 3. Active quarantine on root must be true, and removing it must invalidate immediately
        setQuarantine("0183;69eb99db;Safari;", on: cleanApp.bundle.path)
        #expect(ForensicScanner.hasQuarantineAttribute(at: cleanApp.bundle.path, executablePath: cleanApp.exec.path))
        #expect(removexattr(cleanApp.bundle.path, "com.apple.quarantine", 0) == 0)
        #expect(!ForensicScanner.hasQuarantineAttribute(at: cleanApp.bundle.path, executablePath: cleanApp.exec.path))

        // 4. Active quarantine only on main executable must be true
        let execQApp = try makeAppBundle(named: "ExecQuarantined")
        setQuarantine("0183;69eb99db;Safari;", on: execQApp.exec.path)
        #expect(ForensicScanner.hasQuarantineAttribute(at: execQApp.bundle.path, executablePath: execQApp.exec.path))

        // 5. Active quarantine only on nested non-executable resource must be false
        let nestedResApp = try makeAppBundle(named: "NestedResourceOnly")
        setQuarantine("0183;69eb99db;Safari;", on: nestedResApp.resource.path)
        #expect(!ForensicScanner.hasQuarantineAttribute(at: nestedResApp.bundle.path, executablePath: nestedResApp.exec.path))

        // 6. Symlink handling: symlink to clean target -> false; symlink to quarantined target -> true;
        //    actively quarantined symlink to clean target -> true
        let symlinkToClean = rootDir.appendingPathComponent("CleanLink.app")
        try fm.createSymbolicLink(at: symlinkToClean, withDestinationURL: cleanApp.bundle)
        #expect(!ForensicScanner.hasQuarantineAttribute(at: symlinkToClean.path, executablePath: cleanApp.exec.path))

        setQuarantine("0183;69eb99db;Safari;", on: symlinkToClean.path, options: XATTR_NOFOLLOW)
        #expect(ForensicScanner.hasQuarantineAttribute(at: symlinkToClean.path, executablePath: cleanApp.exec.path))

        let quarantinedTarget = try makeAppBundle(named: "QuarantinedTarget")
        setQuarantine("0183;69eb99db;Safari;", on: quarantinedTarget.bundle.path)
        let symlinkToQuarantined = rootDir.appendingPathComponent("QuarantinedLink.app")
        try fm.createSymbolicLink(at: symlinkToQuarantined, withDestinationURL: quarantinedTarget.bundle)
        #expect(ForensicScanner.hasQuarantineAttribute(at: symlinkToQuarantined.path, executablePath: quarantinedTarget.exec.path))
    }

    @Test("/Applications Quarantine Calibration Matches macOS Gatekeeper State")
    func applicationsQuarantineCalibration() {
        let fm = FileManager.default
        let appsURL = URL(fileURLWithPath: "/Applications")
        guard let entries = try? fm.contentsOfDirectory(at: appsURL, includingPropertiesForKeys: nil) else {
            return
        }

        let appBundles = entries.filter { $0.pathExtension == "app" }.sorted { $0.lastPathComponent < $1.lastPathComponent }
        #expect(!appBundles.isEmpty)

        func macOSQuarantineActive(at path: String) -> Bool {
            for candidate in [URL(fileURLWithPath: path), URL(fileURLWithPath: path).resolvingSymlinksInPath()] {
                var u = candidate
                u.removeAllCachedResourceValues()
                if let props = try? u.resourceValues(forKeys: [.quarantinePropertiesKey]).quarantineProperties, !props.isEmpty {
                    return true
                }
            }
            return false
        }

        for appURL in appBundles {
            let execPath = Bundle(url: appURL)?.executablePath
            let detected = ForensicScanner.hasQuarantineAttribute(at: appURL.path, executablePath: execPath)
            let expected = macOSQuarantineActive(at: appURL.path) || (execPath.map(macOSQuarantineActive) ?? false)
            #expect(detected == expected, "Quarantine mismatch for \(appURL.lastPathComponent): detected=\(detected), expected=\(expected)")
        }

        // Verify full auditBundle reports isQuarantined == false for fast user-approved / clean apps when present
        for name in ["Arhivar.app", "Menkul.app", "RoCheck.app", "Verificator.app", "Zed.app"] {
            let url = appsURL.appendingPathComponent(name)
            guard fm.fileExists(atPath: url.path) else { continue }
            let expected = macOSQuarantineActive(at: url.path) || (Bundle(url: url)?.executablePath.map(macOSQuarantineActive) ?? false)
            let report = ForensicScanner.auditBundle(at: url)
            #expect(report.isQuarantined == expected, "\(name) auditBundle isQuarantined mismatch")
            #expect(report.verdict == .clean, "\(name) must remain CLEAN")
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

        let dummyReport = BundleAuditReport(
            bundlePath: "/Applications/Sample.app",
            bundleName: "Sample",
            bundleId: "com.example.sample",
            shortVersion: "1.0",
            buildVersion: "1",
            executableName: "Sample",
            executableRelativePath: "Contents/MacOS/Sample",
            executableModDate: "2026-11-13 10:00:00",
            plistModDate: "2026-11-13 10:00:00",
            teamIdentifier: "not set",
            authorities: [],
            signedTimestamp: "-",
            hasHardenedRuntime: false,
            isNotarized: false,
            isQuarantined: true,
            gatekeeperStatus: "Unsigned (Local Developer Build)",
            cdHash: "-",
            scanDurationMs: 5,
            verdict: .clean,
            findings: [],
            linkedDylibs: [],
            bundledLibraries: [],
            hookCategories: [],
            rawCodesignOutput: "",
            rawOtoolOutput: ""
        )
        let aiPrompt = ForensicAI.prompt(for: dummyReport)
        #expect(aiPrompt.contains("Quarantine (com.apple.quarantine): Active"))
        #expect(aiPrompt.contains("Executable: Contents/MacOS/Sample"))
    }

    @Test("Wrapped iOS Bundle Resolution, Missing Bundle Guard & Framework Binary Size")
    func wrappedBundlesMissingGuardAndFrameworkSize() throws {
        let fm = FileManager.default
        let tempRoot = fm.temporaryDirectory.appendingPathComponent("VerificatorLayoutTests-\(UUID().uuidString)")
        try fm.createDirectory(at: tempRoot, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: tempRoot) }

        // 1. Missing bundle must not trigger false 'Executable Code Integrity Broken' TAMPERED finding
        let missingReport = ForensicScanner.auditBundle(at: tempRoot.appendingPathComponent("DoesNotExist.app"))
        #expect(missingReport.verdict == .clean)
        #expect(missingReport.findings.isEmpty)
        #expect(missingReport.gatekeeperStatus == "Bundle not found on disk")

        // 2. Wrapped iOS-on-Mac layout (Wrapper/<App>.app + WrappedBundle symlink)
        let wrappedOuter = tempRoot.appendingPathComponent("WrappedSample.app")
        let innerApp = wrappedOuter.appendingPathComponent("Wrapper/InnerSample.app")
        let innerFrameworks = innerApp.appendingPathComponent("Frameworks")
        try fm.createDirectory(at: innerFrameworks, withIntermediateDirectories: true)
        try fm.createSymbolicLink(at: wrappedOuter.appendingPathComponent("WrappedBundle"), withDestinationURL: innerApp)

        let innerPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CFBundleName</key>
            <string>WrappedSample</string>
            <key>CFBundleExecutable</key>
            <string>InnerSample</string>
            <key>CFBundleIdentifier</key>
            <string>com.example.wrapped</string>
            <key>CFBundleShortVersionString</key>
            <string>2.4.1</string>
            <key>CFBundleVersion</key>
            <string>42</string>
        </dict>
        </plist>
        """
        try innerPlist.write(to: innerApp.appendingPathComponent("Info.plist"), atomically: true, encoding: .utf8)
        let innerExec = innerApp.appendingPathComponent("InnerSample")
        try Data("#!/bin/sh\necho wrapped\n".utf8).write(to: innerExec)

        // Framework with Versioned binary so directory-only fileSizeKey (0) is resolved to real binary byte size
        let fw = innerFrameworks.appendingPathComponent("CoreHelper.framework")
        let fwVerA = fw.appendingPathComponent("Versions/A")
        try fm.createDirectory(at: fwVerA, withIntermediateDirectories: true)
        let fwBinary = fwVerA.appendingPathComponent("CoreHelper")
        let binaryBytes = Data(repeating: 0xAA, count: 4096)
        try binaryBytes.write(to: fwBinary)
        try fm.createSymbolicLink(at: fw.appendingPathComponent("CoreHelper"), withDestinationURL: fwBinary)

        let wrappedReport = ForensicScanner.auditBundle(at: wrappedOuter)
        #expect(wrappedReport.bundleId == "com.example.wrapped")
        #expect(wrappedReport.shortVersion == "2.4.1")
        #expect(wrappedReport.buildVersion == "42")
        #expect(wrappedReport.executableName == "InnerSample")
        #expect(wrappedReport.executableRelativePath == "Wrapper/InnerSample.app/InnerSample")
        #expect(wrappedReport.bundledLibraries.count == 1)
        #expect(wrappedReport.bundledLibraries.first?.name == "CoreHelper.framework")
        #expect(wrappedReport.bundledLibraries.first?.sizeBytes == 4096)

        // 3. Real wrapped iOS apps in /Applications if installed
        for name in ["Tapo.app", "Xiaomi Home.app"] {
            let appURL = URL(fileURLWithPath: "/Applications/\(name)")
            guard fm.fileExists(atPath: appURL.path) else { continue }
            let report = ForensicScanner.auditBundle(at: appURL)
            #expect(report.verdict == .clean, "\(name) must evaluate to CLEAN")
            #expect(report.bundleId != "-", "\(name) Bundle ID must be resolved from WrappedBundle")
            #expect(!report.linkedDylibs.isEmpty, "\(name) main executable otool -L links must be parsed")
            #expect(!report.executableRelativePath.hasPrefix("Contents/MacOS/"), "\(name) must resolve wrapped executable path")
        }
    }

    // MARK: - 10. VerificatorKit, JSON, Updates, Cancellation & Shortcut Conflicts

    @Test("Shortcut Conflict Detection Covers Custom & Reserved System Shortcuts")
    @MainActor
    func shortcutConflictDetection() {
        let suiteName = "VerificatorShortcutTest-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let settings = AppSettings(defaults: defaults, bundle: .main)

        // Conflict with another custom shortcut (⌘R is refresh by default)
        let customConflict = settings.shortcutConflict(
            for: KeyboardShortcutData(key: "R", command: true),
            editingAction: .openBundle
        )
        #expect(customConflict == .customAction(.refresh))

        // Same action's existing shortcut does not conflict with itself
        #expect(settings.shortcutConflict(for: KeyboardShortcutData(key: "O", command: true), editingAction: .openBundle) == nil)

        // Conflicts with built-in shortcuts (⌘1, ⌘K, ⌥⌘L, ⌥⌘B, ⌥⌘S)
        #expect(settings.shortcutConflict(for: KeyboardShortcutData(key: "1", command: true), editingAction: .openBundle) == .systemShortcut(.tabOverview))
        #expect(settings.shortcutConflict(for: KeyboardShortcutData(key: "K", command: true), editingAction: .openBundle) == .systemShortcut(.actionRemoveQuarantine))
        #expect(settings.shortcutConflict(for: KeyboardShortcutData(key: "L", command: true, option: true), editingAction: .openBundle) == .systemShortcut(.menuShowLog))
        #expect(settings.shortcutConflict(for: KeyboardShortcutData(key: "B", command: true, option: true), editingAction: .openBundle) == .systemShortcut(.menuBatchScan))
        #expect(settings.shortcutConflict(for: KeyboardShortcutData(key: "S", command: true, option: true), editingAction: .openBundle) == .systemShortcut(.menuSaveJSONReport))
    }

    @Test("AppModel Trilingual Markdown & JSON Report Round-Trip")
    @MainActor
    func markdownAndJsonReportGeneration() throws {
        let trDict = loadLocalizableStrings(for: "tr")
        let enDict = loadLocalizableStrings(for: "en")
        let roDict = loadLocalizableStrings(for: "ro")

        // Build localized Bundle fallback using explicit tables if .module/main bundle lacks .lproj in swift test
        let testBundleDir = FileManager.default.temporaryDirectory.appendingPathComponent("VerificatorTestBundle-\(UUID().uuidString).bundle")
        try FileManager.default.createDirectory(at: testBundleDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: testBundleDir) }

        let resourcesURL = testBundleDir.appendingPathComponent("Contents/Resources", isDirectory: true)
        for (lang, dict) in [("tr", trDict), ("en", enDict), ("ro", roDict)] {
            let lproj = resourcesURL.appendingPathComponent("\(lang).lproj", isDirectory: true)
            try FileManager.default.createDirectory(at: lproj, withIntermediateDirectories: true)
            let plistData = try PropertyListSerialization.data(fromPropertyList: dict, format: .binary, options: 0)
            try plistData.write(to: lproj.appendingPathComponent("Localizable.strings"))
        }
        let infoPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.test.strings</string></dict></plist>
        """
        try infoPlist.write(to: testBundleDir.appendingPathComponent("Contents/Info.plist"), atomically: true, encoding: .utf8)
        let testBundle = Bundle(url: testBundleDir)!

        // Verify StringTable resolves bundled/repo Resources without returning raw LKey strings
        let fallbackTable = StringTable(bundle: .main, executablePath: nil)
        #expect(fallbackTable.string(.findingCleanTitle, language: "en") != LKey.findingCleanTitle.rawValue)
        #expect(fallbackTable.string(.findingCleanTitle, language: "tr") != LKey.findingCleanTitle.rawValue)
        #expect(fallbackTable.string(.findingCleanTitle, language: "ro") != LKey.findingCleanTitle.rawValue)

        let report = BundleAuditReport(
            bundlePath: "/Applications/Sample.app",
            bundleName: "Sample",
            bundleId: "com.example.sample",
            shortVersion: "1.2",
            buildVersion: "10",
            executableName: "Sample",
            executableRelativePath: "Contents/MacOS/Sample",
            executableModDate: "2026-11-13 10:00:00",
            plistModDate: "2026-11-13 10:00:00",
            architectures: ["arm64", "x86_64"],
            executableSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            lcRpaths: ["@executable_path/../Frameworks"],
            teamIdentifier: "not set",
            authorities: ["Ad-Hoc (Local Developer Build)"],
            signedTimestamp: "-",
            hasHardenedRuntime: false,
            isNotarized: false,
            isQuarantined: true,
            entitlements: ["com.apple.security.app-sandbox"],
            spctlAssessment: "accepted",
            gatekeeperStatus: "codesign --verify: OK (Valid on disk)",
            cdHash: "abc123",
            scanDurationMs: 12,
            verdict: .clean,
            findings: [ForensicFinding(severity: .info, titleKey: .findingCleanTitle, descKey: .findingCleanDesc)],
            linkedDylibs: [LinkedDylibItem(path: "/usr/lib/libSystem.B.dylib", isSystem: true, isSuspicious: false)],
            bundledLibraries: [],
            hookCategories: [],
            rawCodesignOutput: "",
            rawOtoolOutput: "",
            rawEntitlementsOutput: "<plist><dict/></plist>"
        )

        let json = try report.jsonData(prettyPrinted: true)
        let decoded = try JSONDecoder().decode(BundleAuditReport.self, from: json)
        #expect(decoded == report)
        #expect(decoded.architectures == ["arm64", "x86_64"])
        #expect(decoded.executableSHA256 == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        #expect(decoded.lcRpaths == ["@executable_path/../Frameworks"])
        #expect(decoded.entitlements == ["com.apple.security.app-sandbox"])
        #expect(decoded.spctlAssessment == "accepted")
        #expect(decoded.rawEntitlementsOutput == "<plist><dict/></plist>")

        for lang in [AppLanguage.tr, .en, .ro] {
            let suiteName = "VerificatorReportTest-\(lang.rawValue)-\(UUID().uuidString)"
            let defaults = UserDefaults(suiteName: suiteName)!
            defer { defaults.removePersistentDomain(forName: suiteName) }

            let settings = AppSettings(defaults: defaults, bundle: testBundle)
            settings.language = lang
            let model = AppModel(settings: settings)
            let md = model.markdownReport(for: report)
            #expect(md.contains("arm64, x86_64"))
            #expect(md.contains("@executable_path/../Frameworks"))
            #expect(md.contains("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
            #expect(md.contains("com.apple.security.app-sandbox"))
            #expect(md.contains("accepted"))
            #expect(!md.contains("%1$@"))
        }
    }

    @Test("AppUpdateChecker Parses Signature & Checksum Assets")
    func updateCheckerParsesCryptoAssets() throws {
        let repo = AppInfo.repository
        let releaseJSON = """
        {
          "tag_name": "v9.9.0",
          "html_url": "https://github.com/\(repo)/releases/tag/v9.9.0",
          "draft": false,
          "prerelease": false,
          "assets": [
            {
              "name": "Verificator-9.9.0.dmg",
              "browser_download_url": "https://github.com/\(repo)/releases/download/v9.9.0/Verificator-9.9.0.dmg"
            },
            {
              "name": "Verificator-9.9.0.dmg.sig",
              "browser_download_url": "https://github.com/\(repo)/releases/download/v9.9.0/Verificator-9.9.0.dmg.sig"
            },
            {
              "name": "SHA256SUMS.txt",
              "browser_download_url": "https://github.com/\(repo)/releases/download/v9.9.0/SHA256SUMS.txt"
            }
          ]
        }
        """.data(using: .utf8)!

        let release = try AppUpdateChecker.parse(releaseJSON, repository: repo)
        #expect(release.version == "9.9.0")
        #expect(release.downloadURL?.lastPathComponent == "Verificator-9.9.0.dmg")
        #expect(release.signatureURL?.lastPathComponent == "Verificator-9.9.0.dmg.sig")
        #expect(release.checksumsURL?.lastPathComponent == "SHA256SUMS.txt")
    }

    @Test("ScanCancellationToken Terminates Scan Early & Directory Audit SummarizesCleanly")
    func scanCancellationAndBatchAudit() throws {
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory.appendingPathComponent("VerificatorBatchTests-\(UUID().uuidString)")
        try fm.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: tempDir) }

        // Pre-cancelled token immediately short-circuits without running subprocesses
        let token = ScanCancellationToken()
        token.cancel()
        let cancelledReport = ForensicScanner.auditBundle(at: URL(fileURLWithPath: "/Applications/Safari.app"), cancellation: token)
        #expect(cancelledReport.rawCodesignOutput == "Cancelled" || cancelledReport.rawCodesignOutput.isEmpty)

        // Batch directory audit against empty folder returns empty summary
        let emptyBatch = ForensicScanner.auditDirectory(at: tempDir)
        #expect(emptyBatch.totalCount == 0)
        #expect(!emptyBatch.wasCancelled)
        #expect(emptyBatch.reports.isEmpty)

        // Pre-cancelled batch scan records wasCancelled = true
        let cancelledBatch = ForensicScanner.auditDirectory(at: tempDir, cancellation: token)
        #expect(cancelledBatch.wasCancelled)

        // Expanded folder batch scan covers .app, .dmg, .pkg, and .mpkg while ignoring unrelated files
        let mixedDir = tempDir.appendingPathComponent("MixedDownloads", isDirectory: true)
        let miniApp = mixedDir.appendingPathComponent("Mini.app/Contents/MacOS", isDirectory: true)
        try fm.createDirectory(at: miniApp, withIntermediateDirectories: true)
        try fm.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: miniApp.appendingPathComponent("Mini"))
        let sampleDMG = mixedDir.appendingPathComponent("Sample.dmg")
        let samplePKG = mixedDir.appendingPathComponent("Installer.pkg")
        let sampleMPKG = mixedDir.appendingPathComponent("Bundle.mpkg")
        let ignoredTXT = mixedDir.appendingPathComponent("Notes.txt")
        try Data("dmg".utf8).write(to: sampleDMG)
        try Data("pkg".utf8).write(to: samplePKG)
        try Data("mpkg".utf8).write(to: sampleMPKG)
        try Data("hello".utf8).write(to: ignoredTXT)

        let mixedBatch = ForensicScanner.auditDirectory(at: mixedDir)
        #expect(mixedBatch.reports.count == 4)
        let kinds = Set(mixedBatch.reports.map(\.targetKind))
        #expect(kinds.contains(.appBundle))
        #expect(kinds.contains(.diskImage))
        #expect(kinds.contains(.installerPackage))
        #expect(!mixedBatch.reports.contains(where: { $0.bundlePath.hasSuffix("Notes.txt") }))

        // Nested .appex/.xpc bundle & executable SHA-256 verification on real bundle if Safari is present
        let safariURL = URL(fileURLWithPath: "/Applications/Safari.app")
        if fm.fileExists(atPath: safariURL.path) {
            let safariReport = ForensicScanner.auditBundle(at: safariURL)
            #expect(safariReport.verdict == .clean)
            #expect(safariReport.executableSHA256.count == 64)
        }

        let summaryWithFlag = BatchAuditSummary(directoryPath: tempDir.path, scannedAt: "2026-11-13 16:00:00", reports: [], wasCancelled: true)
        let batchJSON = try summaryWithFlag.jsonData()
        let decodedBatch = try JSONDecoder().decode(BatchAuditSummary.self, from: batchJSON)
        #expect(decodedBatch.totalCount == 0)
        #expect(decodedBatch.wasCancelled)
    }

    @Test("AppUpdateChecker Download Verification Rejects Tampering & Accepts Valid Ed25519 + SHA-256")
    func updateDownloadAndVerifyFlow() async throws {
        final class MockUpdateURLProtocol: URLProtocol {
            nonisolated(unsafe) static var handler: ((URLRequest) -> (HTTPURLResponse, Data))?
            override class func canInit(with request: URLRequest) -> Bool { true }
            override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
            override func startLoading() {
                guard let handler = Self.handler else { return }
                let (resp, data) = handler(request)
                client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
                client?.urlProtocol(self, didLoad: data)
                client?.urlProtocolDidFinishLoading(self)
            }
            override func stopLoading() {}
        }

        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKeyBase64 = privateKey.publicKey.rawRepresentation.base64EncodedString()
        let payload = Data("verificator-verified-dmg-payload".utf8)
        let sigBase64 = try privateKey.signature(for: payload).base64EncodedString()

        let tempPayload = FileManager.default.temporaryDirectory.appendingPathComponent("mock-update-\(UUID().uuidString).dmg")
        try payload.write(to: tempPayload)
        defer { try? FileManager.default.removeItem(at: tempPayload) }
        let shaHex = try UpdateChecksums.sha256(of: tempPayload)
        let checksumsData = Data("\(shaHex)  Verificator-9.9.0.dmg\n".utf8)

        let dmgURL = URL(string: "https://github.com/berkbb/verificator-mac-universal/releases/download/v9.9.0/Verificator-9.9.0.dmg")!
        let sigURL = URL(string: "https://github.com/berkbb/verificator-mac-universal/releases/download/v9.9.0/Verificator-9.9.0.dmg.sig")!
        let sumURL = URL(string: "https://github.com/berkbb/verificator-mac-universal/releases/download/v9.9.0/SHA256SUMS.txt")!

        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockUpdateURLProtocol.self]
        let session = URLSession(configuration: config)

        let destDir = FileManager.default.temporaryDirectory.appendingPathComponent("VerificatorUpdateDest-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: destDir) }

        MockUpdateURLProtocol.handler = { req in
            let url = req.url!
            let resp = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
            if url == dmgURL { return (resp, payload) }
            if url == sigURL { return (resp, Data(sigBase64.utf8)) }
            return (resp, checksumsData)
        }

        let validRelease = AppRelease(version: "9.9.0", pageURL: dmgURL, downloadURL: dmgURL, signatureURL: sigURL, checksumsURL: sumURL)
        let verified = try await AppUpdateChecker.downloadAndVerify(
            release: validRelease,
            destinationDirectory: destDir,
            publicKeyOverride: publicKeyBase64,
            session: session
        )
        #expect(verified.signatureVerified)
        #expect(verified.checksumVerified)
        #expect(verified.sha256 == shaHex)
        #expect(FileManager.default.fileExists(atPath: verified.fileURL.path))

        // Corrupt checksum must fail closed
        MockUpdateURLProtocol.handler = { req in
            let url = req.url!
            let resp = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
            if url == dmgURL { return (resp, Data("tampered-payload".utf8)) }
            if url == sigURL { return (resp, Data(sigBase64.utf8)) }
            return (resp, checksumsData)
        }
        await #expect(throws: AppUpdateChecker.VerifiedDownloadError.self) {
            _ = try await AppUpdateChecker.downloadAndVerify(
                release: validRelease,
                destinationDirectory: destDir,
                publicKeyOverride: publicKeyBase64,
                session: session
            )
        }
    }

    @Test("EntitlementAnalyzer Classifies Informational Risks & Sorts by Severity")
    func entitlementRiskClassification() {
        let sampleEntitlements = [
            "com.apple.security.cs.allow-jit",
            "com.apple.security.cs.disable-library-validation",
            "com.apple.security.get-task-allow",
            "com.apple.security.network.client",
        ]
        let xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
            <key>com.apple.security.app-sandbox</key><false/>
            <key>com.apple.security.get-task-allow</key><true/>
        </dict></plist>
        """

        let risks = EntitlementAnalyzer.analyze(sampleEntitlements, rawEntitlementsOutput: xml)
        #expect(risks.count == 4)
        #expect(risks.first?.entitlementKey == "com.apple.security.get-task-allow")
        #expect(risks.first?.level == .high)
        #expect(risks.contains { $0.entitlementKey == "com.apple.security.cs.disable-library-validation" && $0.level == .elevated })
        #expect(risks.contains { $0.entitlementKey == "com.apple.security.cs.allow-jit" && $0.level == .info })
        #expect(risks.contains { $0.entitlementKey == "com.apple.security.app-sandbox=false" && $0.level == .info })
        #expect(EntitlementAnalyzer.analyze([]).isEmpty)
    }

    @Test("AuditReportDiff Detects Regressions & Decodes Pre-1.3.0 Legacy JSON")
    func auditDiffAndLegacyJSONDecoding() throws {
        // Pre-1.3.0 JSON omits `targetKind`
        let legacyJSON = """
        {
          "architectures" : ["arm64"],
          "authorities" : ["Developer ID Application: Acme Corp (TEAM123456)", "Apple Root CA"],
          "buildVersion" : "10",
          "bundleId" : "com.example.acme",
          "bundleName" : "Acme",
          "bundlePath" : "/Applications/Acme.app",
          "bundledLibraries" : [],
          "cdHash" : "abc123",
          "entitlements" : ["com.apple.security.network.client"],
          "executableModDate" : "2026-01-01 10:00:00",
          "executableName" : "Acme",
          "executableRelativePath" : "Contents/MacOS/Acme",
          "executableSHA256" : "00001111222233334444555566667777",
          "findings" : [],
          "gatekeeperStatus" : "codesign --verify: OK",
          "hasHardenedRuntime" : true,
          "hookCategories" : [],
          "isNotarized" : true,
          "isQuarantined" : false,
          "lcRpaths" : ["@executable_path/../Frameworks"],
          "linkedDylibs" : [{"id":"11111111-1111-1111-1111-111111111111","isExternalSuspicious":false,"isSuspicious":false,"isSystem":true,"path":"/usr/lib/libSystem.B.dylib"}],
          "plistModDate" : "2026-01-01 10:00:00",
          "rawCodesignOutput" : "",
          "rawEntitlementsOutput" : "",
          "rawOtoolOutput" : "",
          "scanDurationMs" : 12,
          "shortVersion" : "1.0.0",
          "signedTimestamp" : "2026-01-01",
          "teamIdentifier" : "TEAM123456",
          "verdict" : "clean"
        }
        """
        let decodedBaseline = try JSONDecoder().decode(BundleAuditReport.self, from: Data(legacyJSON.utf8))
        #expect(decodedBaseline.targetKind == .appBundle)
        #expect(decodedBaseline.bundleName == "Acme")

        let targetReport = BundleAuditReport(
            bundlePath: "/tmp/Acme-Patched.app",
            bundleName: "Acme",
            bundleId: "com.example.acme",
            shortVersion: "1.0.1",
            buildVersion: "11",
            executableName: "Acme",
            executableModDate: "2026-01-02 10:00:00",
            plistModDate: "2026-01-01 10:00:00",
            architectures: ["arm64"],
            executableSHA256: "99998888777766665555444433332222",
            lcRpaths: ["@executable_path/../Frameworks", "/tmp/injected"],
            teamIdentifier: "not set",
            authorities: ["Ad-Hoc"],
            signedTimestamp: "-",
            hasHardenedRuntime: false,
            isNotarized: false,
            isQuarantined: true,
            entitlements: ["com.apple.security.network.client", "com.apple.security.cs.disable-library-validation"],
            gatekeeperStatus: "Tampered",
            cdHash: "def456",
            scanDurationMs: 18,
            verdict: .tampered,
            findings: [],
            linkedDylibs: [
                LinkedDylibItem(path: "/usr/lib/libSystem.B.dylib", isSystem: true, isSuspicious: false),
                LinkedDylibItem(path: "/tmp/libcrack.dylib", isSystem: false, isSuspicious: true, isExternalSuspicious: true),
            ],
            bundledLibraries: [
                BundledLibraryItem(name: "libcrack.dylib", modifiedDate: "2026-01-02", sizeBytes: 1024, isTimestampAnomaly: true, suspiciousSymbols: ["_mach_vm_protect"], targetStrings: []),
            ],
            hookCategories: [
                HookSymbolCategory(libraryName: "libcrack.dylib", categoryKey: .symbolCatMemory, symbols: ["_mach_vm_protect"]),
            ],
            rawCodesignOutput: "",
            rawOtoolOutput: ""
        )

        let diff = AuditDiff.compare(
            baseline: AuditDiffEndpoint(sourceDescription: "/Applications/Acme.app", isFromSavedJSON: true, report: decodedBaseline),
            target: AuditDiffEndpoint(sourceDescription: "/tmp/Acme-Patched.app", isFromSavedJSON: false, report: targetReport)
        )

        #expect(diff.hasChanges)
        #expect(diff.regressionCount >= 4)
        #expect(diff.warningCount >= 1)
        #expect(diff.addedEntitlements == ["com.apple.security.cs.disable-library-validation"])
        #expect(diff.addedRpaths == ["/tmp/injected"])
        #expect(diff.addedLinkedDylibs == ["/tmp/libcrack.dylib"])
        #expect(diff.addedBundledLibraries == ["libcrack.dylib"])
        #expect(diff.addedHookCategories == [.symbolCatMemory])

        let table = StringTable(bundle: .main)
        for code in AppLanguage.supportedCodes {
            let md = diff.markdown(with: table, language: code)
            #expect(md.contains("libcrack.dylib"))
            #expect(md.contains("disable-library-validation"))
            #expect(!md.contains("%1$@"))
        }
    }

    @Test("Expanded Targets Support Standalone Mach-O, System Frameworks, Unsigned DMG & Unsigned PKG")
    func expandedTargetFormats() throws {
        let codesignURL = URL(fileURLWithPath: "/usr/bin/codesign")
        let codesignReport = ForensicScanner.auditTarget(at: codesignURL)
        #expect(codesignReport.targetKind == .standaloneMachO)
        #expect(codesignReport.verdict == .clean)
        #expect(!codesignReport.architectures.isEmpty)

        let appKitURL = URL(fileURLWithPath: "/System/Library/Frameworks/AppKit.framework")
        let appKitReport = ForensicScanner.auditTarget(at: appKitURL)
        #expect(appKitReport.targetKind == .nestedBundle)
        #expect(appKitReport.verdict == .clean)

        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("VerificatorTargets-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let dummyDmg = tempDir.appendingPathComponent("Sample.dmg")
        try Data("unsigned-dmg-payload".utf8).write(to: dummyDmg)
        let dmgReport = ForensicScanner.auditTarget(at: dummyDmg)
        #expect(dmgReport.targetKind == .diskImage)
        #expect(dmgReport.verdict == .clean)
        #expect(dmgReport.findings.contains { $0.titleKey == .findingDmgUnsignedTitle })

        let dummyPkg = tempDir.appendingPathComponent("Sample.pkg")
        try Data("unsigned-pkg-payload".utf8).write(to: dummyPkg)
        let pkgReport = ForensicScanner.auditTarget(at: dummyPkg)
        #expect(pkgReport.targetKind == .installerPackage)
        #expect(pkgReport.verdict != .clean)
    }

    @Test("SystemAudit Persistence Flags DYLD_INSERT & Missing Targets While Calibrating Clean Agents")
    func systemAuditPersistenceAndProcesses() throws {
        let tempRoot = FileManager.default.temporaryDirectory.appendingPathComponent("VerificatorPersist-\(UUID().uuidString)")
        let userAgents = tempRoot.appendingPathComponent("UserAgents", isDirectory: true)
        try FileManager.default.createDirectory(at: userAgents, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempRoot) }

        let cleanPlist: [String: Any] = [
            "Label": "com.example.clean",
            "ProgramArguments": ["/usr/bin/true"],
            "RunAtLoad": true,
        ]
        let cleanData = try PropertyListSerialization.data(fromPropertyList: cleanPlist, format: .xml, options: 0)
        try cleanData.write(to: userAgents.appendingPathComponent("com.example.clean.plist"))

        let missingPlist: [String: Any] = [
            "Label": "com.example.missing",
            "ProgramArguments": ["/nonexistent/path/missing-helper"],
        ]
        let missingData = try PropertyListSerialization.data(fromPropertyList: missingPlist, format: .xml, options: 0)
        try missingData.write(to: userAgents.appendingPathComponent("com.example.missing.plist"))

        let evilPlist: [String: Any] = [
            "Label": "com.example.dyld",
            "ProgramArguments": ["/usr/bin/true"],
            "EnvironmentVariables": ["DYLD_INSERT_LIBRARIES": "/tmp/hook.dylib"],
        ]
        let evilData = try PropertyListSerialization.data(fromPropertyList: evilPlist, format: .xml, options: 0)
        try evilData.write(to: userAgents.appendingPathComponent("com.example.dyld.plist"))

        let persistenceSummary = SystemAudit.auditPersistence(directories: [(.userAgent, userAgents)])
        #expect(persistenceSummary.totalCount == 3)
        #expect(persistenceSummary.cleanCount == 1)
        #expect(persistenceSummary.warningCount == 1)
        #expect(persistenceSummary.tamperedCount == 1)
        #expect(persistenceSummary.missingExecutableCount == 1)

        let dyldItem = persistenceSummary.items.first { $0.label == "com.example.dyld" }
        #expect(dyldItem?.hasDyldInsertEnv == true)
        #expect(dyldItem?.verdict == .tampered)

        // Live process environment read on our own test process must succeed cleanly
        let selfEnv = SystemAudit.readDyldInsertEnv(for: ProcessInfo.processInfo.processIdentifier)
        #expect(selfEnv.readable)
        #expect(selfEnv.libraries.isEmpty)

        let runningSummary = SystemAudit.auditRunningProcesses()
        #expect(runningSummary.totalCount > 0)
        #expect(runningSummary.tamperedCount == 0)
    }

    @Test("AppModel URL Scheme Routing, Target Resolution & CLI Helper")
    @MainActor
    func appModelIntegrationsAndDiffRouting() {
        let model = AppModel(settings: AppSettings())
        #expect(model.cliInstallCommand.contains("/usr/local/bin/verificator-cli"))
        #expect(model.cliInstallCommand.contains("verificator-cli"))

        #expect(model.isSupportedBundleURL(URL(fileURLWithPath: "/Applications/Sample.dmg")))
        #expect(model.isSupportedBundleURL(URL(fileURLWithPath: "/Applications/Sample.pkg")))
        #expect(model.isSupportedBundleURL(URL(fileURLWithPath: "/System/Library/Frameworks/AppKit.framework")))
        #expect(model.isSupportedBundleURL(URL(fileURLWithPath: "/usr/bin/codesign")))

        model.handleIncomingURL(URL(string: "verificator://diff?baseline=/usr/bin/codesign&target=/usr/bin/codesign")!)
        #expect(model.workspaceMode == .diff)
        #expect(model.diffBaselineURL?.path == "/usr/bin/codesign")
        #expect(model.diffTargetURL?.path == "/usr/bin/codesign")

        // Two Finder items passed simultaneously jump straight to Diff comparison
        model.handleIncomingURLs([
            URL(fileURLWithPath: "/usr/bin/codesign"),
            URL(fileURLWithPath: "/usr/bin/true"),
        ])
        #expect(model.workspaceMode == .diff)
        #expect(model.diffBaselineURL?.path == "/usr/bin/codesign")
        #expect(model.diffTargetURL?.path == "/usr/bin/true")

        // Three+ Finder items passed simultaneously open a Batch multi-target scan
        model.handleIncomingURLs([
            URL(fileURLWithPath: "/usr/bin/codesign"),
            URL(fileURLWithPath: "/usr/bin/true"),
            URL(fileURLWithPath: "/usr/bin/false"),
        ])
        #expect(model.workspaceMode == .batch)
        model.cancelBatchScan()
    }

    @Test("Signature Verification Timeouts Never Trigger False Tampered Verdicts")
    func codeSignatureVerificationTimeoutAndOutcomeClassification() {
        #expect(ForensicScanner.bundleVerifyTimeoutSeconds >= 180)
        #expect(ForensicScanner.defaultGatekeeperTimeoutSeconds >= 60)

        let timedOutOutcome = ForensicScanner.evaluateVerifyResult(
            (output: "Process timed out after 180s", exitCode: ForensicScanner.timedOutToolExitCode),
            isUnsigned: false
        )
        #expect(timedOutOutcome == .timedOut("Process timed out after 180s"))

        var timeoutFindings: [ForensicFinding] = []
        ForensicScanner.appendVerificationFindings(timedOutOutcome, findings: &timeoutFindings)
        #expect(timeoutFindings.count == 1)
        #expect(timeoutFindings.first?.severity == .warning)
        #expect(timeoutFindings.first?.titleKey == .findingVerifyTimedOutTitle)
        #expect(timeoutFindings.first?.descKey == .findingVerifyTimedOutDesc)
        #expect(!timeoutFindings.contains { $0.severity == .critical })

        let failedOutcome = ForensicScanner.evaluateVerifyResult(
            (output: "invalid signature (code or signature have been modified)", exitCode: 1),
            isUnsigned: false
        )
        #expect(failedOutcome == .failed("invalid signature (code or signature have been modified)"))

        var failedFindings: [ForensicFinding] = []
        ForensicScanner.appendVerificationFindings(failedOutcome, findings: &failedFindings)
        #expect(failedFindings.count == 1)
        #expect(failedFindings.first?.severity == .critical)
        #expect(failedFindings.first?.titleKey == .findingVerifyFailedTitle)

        let unsignedOutcome = ForensicScanner.evaluateVerifyResult(
            (output: "code object is not signed at all", exitCode: 1),
            isUnsigned: false
        )
        #expect(unsignedOutcome == .skippedUnsigned)
        #expect(ForensicScanner.evaluateVerifyResult((output: "", exitCode: 0), isUnsigned: false) == .valid)

        let token = ScanCancellationToken()
        token.cancel()
        #expect(ForensicScanner.evaluateVerifyResult((output: "", exitCode: 15), isUnsigned: false, cancellation: token) == .cancelled)

        var spctlFindings: [ForensicFinding] = []
        ForensicScanner.appendGatekeeperFindings(
            (accepted: false, timedOut: true, statusText: "Process timed out after 90s"),
            warnOnRejection: true,
            findings: &spctlFindings
        )
        #expect(spctlFindings.count == 1)
        #expect(spctlFindings.first?.severity == .warning)
        #expect(spctlFindings.first?.titleKey == .findingSpctlTimedOutTitle)

        let sleepTimeout = ForensicScanner.runTool("/bin/sleep", args: ["10"], timeoutSeconds: 0.2)
        #expect(sleepTimeout.exitCode == ForensicScanner.timedOutToolExitCode)
        #expect(sleepTimeout.output.localizedCaseInsensitiveContains("timed out"))

        let sleepCancelled = ForensicScanner.runTool("/bin/sleep", args: ["10"], timeoutSeconds: 5, cancellation: token)
        #expect(sleepCancelled.exitCode == ForensicScanner.cancelledToolExitCode)
    }
}
