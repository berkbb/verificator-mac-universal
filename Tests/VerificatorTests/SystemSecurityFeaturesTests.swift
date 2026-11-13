// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Security
import Testing
@testable import VerificatorCore
@testable import VerificatorKit

@Suite("System Security Features Tests")
struct SystemSecurityFeaturesTests {

    private func makeTempDir(prefix: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func sampleReport(
        path: String = "/Applications/Sample.app",
        bundleId: String = "com.example.sample",
        team: String = "ABCDE12345",
        authorities: [String] = ["Developer ID Application: Example (ABCDE12345)", "Developer ID Certification Authority", "Apple Root CA"],
        cdHash: String = "aaaa1111",
        sha256: String = "bbbb2222",
        shortVersion: String = "1.0.0"
    ) -> BundleAuditReport {
        BundleAuditReport(
            targetKind: .appBundle,
            bundlePath: path,
            bundleName: "Sample",
            bundleId: bundleId,
            shortVersion: shortVersion,
            buildVersion: "1",
            executableName: "Sample",
            executableModDate: "2026-11-13 10:00:00",
            plistModDate: "2026-11-13 10:00:00",
            architectures: ["arm64", "x86_64"],
            executableSHA256: sha256,
            teamIdentifier: team,
            authorities: authorities,
            signedTimestamp: "-",
            hasHardenedRuntime: true,
            isNotarized: true,
            isQuarantined: false,
            gatekeeperStatus: "valid on disk",
            revocationStatus: nil,
            cdHash: cdHash,
            scanDurationMs: 12,
            verdict: .clean,
            findings: [],
            linkedDylibs: [],
            bundledLibraries: [],
            hookCategories: [],
            rawCodesignOutput: "",
            rawOtoolOutput: ""
        )
    }

    @Test("GatekeeperStatus Parses spctl --status Output Strictly")
    func gatekeeperStatusParsing() {
        #expect(GatekeeperStatus.parse("assessments enabled\n") == .enabled)
        #expect(GatekeeperStatus.parse("  assessments disabled  \n") == .disabled)
        #expect(GatekeeperStatus.parse("") == .unknown)
        #expect(GatekeeperStatus.parse("assessments enabled\nassessments disabled\n") == .unknown)
        #expect(GatekeeperStatus.parse("unexpected output") == .unknown)
        #expect(GatekeeperStatus.enabled.labelKey == .gatekeeperGlobalEnabled)
        #expect(GatekeeperStatus.disabled.labelKey == .gatekeeperGlobalDisabled)
        #expect(GatekeeperStatus.unknown.labelKey == .gatekeeperGlobalUnknown)
    }

    @Test("FullDiskAccess Probe Detects Missing vs Readable Protected Paths")
    func fullDiskAccessHomeProbe() throws {
        let dir = try makeTempDir(prefix: "verificator-fda")
        defer { try? FileManager.default.removeItem(at: dir) }

        #expect(!FullDiskAccess.isGranted(homeDirectoryURL: dir))

        let safariDir = dir.appendingPathComponent("Library/Safari", isDirectory: true)
        try FileManager.default.createDirectory(at: safariDir, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: safariDir.appendingPathComponent("Bookmarks.plist").path, contents: Data("bplist".utf8))

        #expect(FullDiskAccess.isGranted(homeDirectoryURL: dir))
    }

    @Test("RevocationChecker Maps Revocation Status Codes & Backward-Compatible Models")
    func revocationStatusAndBackwardCompatibility() throws {
        #expect(RevocationChecker.isRevocationStatus(errSecCSRevokedNotarization))
        #expect(RevocationChecker.isRevocationStatus(OSStatus(CSSMERR_TP_CERT_REVOKED)))
        #expect(!RevocationChecker.isRevocationStatus(errSecSuccess))

        #expect(RevocationStatus.valid.labelKey == .revocationStatusOk)
        #expect(RevocationStatus.revoked.labelKey == .revocationStatusRevoked)
        #expect(RevocationStatus.unchecked.labelKey == .valueNotChecked)

        // Pre-1.3.0+ ScanOptions JSON without checkCertificateRevocation must default to false
        let legacyOptionsJSON = #"{"deepFrameworkSignatureCheck":true,"extractTargetStrings":false,"includeGatekeeperAssessment":true}"#
        let decodedOptions = try JSONDecoder().decode(ScanOptions.self, from: Data(legacyOptionsJSON.utf8))
        #expect(decodedOptions.deepFrameworkSignatureCheck == true)
        #expect(decodedOptions.extractTargetStrings == false)
        #expect(decodedOptions.includeGatekeeperAssessment == true)
        #expect(decodedOptions.checkCertificateRevocation == false)

        // Pre-1.3.0+ BundleAuditReport JSON without revocationStatus must decode with nil
        let encoded = try sampleReport().jsonData(prettyPrinted: false)
        var obj = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        obj.removeValue(forKey: "revocationStatus")
        let strippedData = try JSONSerialization.data(withJSONObject: obj)
        let decodedReport = try JSONDecoder().decode(BundleAuditReport.self, from: strippedData)
        #expect(decodedReport.revocationStatus == nil)

        // Legacy RunningProcessItem without parent / dynamic fields must decode cleanly
        let legacyProcJSON = #"{"pid":42,"name":"TestProc","executablePath":"/usr/bin/true","teamIdentifier":"not set","authorities":[],"hasOfficialAppleChain":false,"isQuarantined":false,"dyldInsertLibraries":[],"envReadable":true,"verdict":"clean","findings":[]}"#
        let decodedProc = try JSONDecoder().decode(RunningProcessItem.self, from: Data(legacyProcJSON.utf8))
        #expect(decodedProc.parentPid == nil)
        #expect(decodedProc.parentName == nil)
        #expect(decodedProc.dynamicSignatureMismatch == false)
        #expect(decodedProc.unsignedMappedLibraries.isEmpty)
    }

    @Test("SignatureTracker Detects Updates, Signer Changes, Signature Stripping & Accepts New Baseline")
    func signatureTrackerTransitionsAndStorePermissions() throws {
        let dir = try makeTempDir(prefix: "verificator-sigtrack")
        defer { try? FileManager.default.removeItem(at: dir) }

        let storeURL = dir.appendingPathComponent("signature-history.json")
        let store = SignatureTrackerStore(fileURL: storeURL)
        var tracker = store.load()
        #expect(tracker.entries.isEmpty)

        let baseline = sampleReport(path: "/Applications/Demo.app", team: "TEAM111111", cdHash: "hash1", sha256: "sha1")
        #expect(tracker.observe(report: baseline) == nil)
        #expect(tracker.observe(report: baseline) == nil)

        let sameSignerUpdate = sampleReport(path: "/Applications/Demo.app", team: "TEAM111111", cdHash: "hash2", sha256: "sha2", shortVersion: "1.0.1")
        let updateDelta = tracker.observe(report: sameSignerUpdate)
        #expect(updateDelta?.kind == .updatedSameSigner)
        #expect(tracker.entries["/Applications/Demo.app"]?.cdHash == "hash2")

        let swappedSigner = sampleReport(
            path: "/Applications/Demo.app",
            team: "EVIL999999",
            authorities: ["Untrusted Authority"],
            cdHash: "hash3",
            sha256: "sha3"
        )
        let signerDelta = tracker.observe(report: swappedSigner)
        #expect(signerDelta?.kind == .signerChanged)
        // Baseline must NOT auto-advance before user acceptance
        #expect(tracker.entries["/Applications/Demo.app"]?.teamIdentifier == "TEAM111111")

        let strippedAdhoc = sampleReport(
            path: "/Applications/Demo.app",
            team: "not set",
            authorities: ["Ad-Hoc (Local Developer Build)"],
            cdHash: "hash4",
            sha256: "sha4"
        )
        let lostDelta = tracker.observe(report: strippedAdhoc)
        #expect(lostDelta?.kind == .lostSignature)

        // Accepting new baseline updates stored entry and persists with 0600 permissions
        tracker.acceptBaseline(for: swappedSigner)
        #expect(tracker.entries["/Applications/Demo.app"]?.teamIdentifier == "EVIL999999")
        try store.save(tracker)
        let attrs = try FileManager.default.attributesOfItem(atPath: storeURL.path)
        let perms = (attrs[.posixPermissions] as? NSNumber)?.intValue
        #expect(perms == 0o600)
        #expect(store.load().entries["/Applications/Demo.app"]?.cdHash == "hash3")
    }

    @Test("LiveProcessInspector Resolves Current Parent Process & Filters Non-Binary Mapped Paths")
    func liveProcessInspectionGuards() throws {
        let selfPid = ProcessInfo.processInfo.processIdentifier
        let parent = LiveProcessInspector.parentProcess(of: selfPid)
        #expect(parent != nil)
        #expect((parent?.pid ?? 0) > 0)

        let dir = try makeTempDir(prefix: "verificator-mapped")
        defer { try? FileManager.default.removeItem(at: dir) }

        let pakFile = dir.appendingPathComponent("App.framework/Resources/resources.pak")
        try FileManager.default.createDirectory(at: pakFile.deletingLastPathComponent(), withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: pakFile.path, contents: Data("not-macho".utf8))

        #expect(!LiveProcessInspector.isCandidateMappedLibrary("/System/Library/Frameworks/Foundation.framework/Foundation", executablePath: "/usr/bin/true"))
        #expect(!LiveProcessInspector.isCandidateMappedLibrary(pakFile.path, executablePath: "/usr/bin/true"))
        #expect(!LiveProcessInspector.isCandidateMappedLibrary("/usr/bin/codesign", executablePath: "/usr/bin/true"))
        // Existing system binary or Mach-O outside /System prefix when not matching execPath would be checked by SecStaticCode
    }

    @Test("ChildProcessGuard Tracks, Unregisters & Reaps Stale Child PIDs Safely")
    func childProcessGuardLifecycle() throws {
        let dir = try makeTempDir(prefix: "verificator-pidguard")
        defer { try? FileManager.default.removeItem(at: dir) }
        let pidFile = dir.appendingPathComponent("children.pids")
        let tracker = ChildProcessTracker(pidFileURL: pidFile)

        let sleeper = Process()
        sleeper.executableURL = URL(fileURLWithPath: "/bin/sleep")
        sleeper.arguments = ["15"]
        try sleeper.run()

        let pid = sleeper.processIdentifier
        tracker.register(pid, name: "sleep")
        let persisted = try String(contentsOf: pidFile, encoding: .utf8)
        #expect(persisted.contains("\(pid)\t"))
        #expect(persisted.contains("sleep"))

        tracker.terminateAll(graceMicroseconds: 50_000)
        sleeper.waitUntilExit()
        #expect(!FileManager.default.fileExists(atPath: pidFile.path))

        // Also test previous-run orphan reaping from an existing children.pids file
        let orphan = Process()
        orphan.executableURL = URL(fileURLWithPath: "/bin/sleep")
        orphan.arguments = ["15"]
        try orphan.run()
        let orphanPid = orphan.processIdentifier
        let start = try #require(ChildProcessTracker.processStartTime(orphanPid))
        try "\(orphanPid)\t\(start.sec)\t\(start.usec)\tsleep\n".write(to: pidFile, atomically: true, encoding: .utf8)

        tracker.reapOrphansFromPreviousRun()
        orphan.waitUntilExit()
        #expect(!FileManager.default.fileExists(atPath: pidFile.path))
    }

    @Test("LaunchServicesRegistration Registers Once Per Bundle Build Stamp")
    @MainActor
    func launchServicesBuildStampGuard() throws {
        let dir = try makeTempDir(prefix: "verificator-lsreg")
        defer { try? FileManager.default.removeItem(at: dir) }

        let suiteName = "com.babadogantech.verificator.lsreg-\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        // Test bundle itself isn't an `.app`, verify non-.app bundle returns false safely
        var callCount = 0
        let didRegisterXCTest = LaunchServicesRegistration.registerIfBuildChanged(
            bundle: .main,
            defaults: defaults
        ) { _ in
            callCount += 1
            return noErr
        }
        if Bundle.main.bundleURL.pathExtension.lowercased() != "app" {
            #expect(!didRegisterXCTest)
            #expect(callCount == 0)
        }

        // Create minimal synthetic .app bundle with Info.plist
        let appURL = dir.appendingPathComponent("Mini.app", isDirectory: true)
        let contentsURL = appURL.appendingPathComponent("Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: contentsURL, withIntermediateDirectories: true)
        let plist: [String: Any] = [
            "CFBundleIdentifier": "com.babadogantech.verificator.testmini",
            "CFBundleName": "Mini",
            "CFBundleShortVersionString": "1.3.0",
            "CFBundleVersion": "5",
        ]
        let plistData = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try plistData.write(to: contentsURL.appendingPathComponent("Info.plist"))

        let bundle = try #require(Bundle(url: appURL))
        let first = LaunchServicesRegistration.registerIfBuildChanged(bundle: bundle, defaults: defaults) { _ in
            callCount += 1
            return noErr
        }
        let second = LaunchServicesRegistration.registerIfBuildChanged(bundle: bundle, defaults: defaults) { _ in
            callCount += 1
            return noErr
        }
        #expect(first)
        #expect(!second)
        #expect(callCount == 1)
    }

    @Test("AppModel Signature Change Observation & Acknowledge Flow")
    @MainActor
    func appModelSignatureChangeFlow() throws {
        let dir = try makeTempDir(prefix: "verificator-appmodel-sig")
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = SignatureTrackerStore(fileURL: dir.appendingPathComponent("sig.json"))
        let model = AppModel(settings: AppSettings(), signatureStore: store)
        let firstReport = sampleReport(path: "/Applications/DemoModel.app", team: "TEAMAAA111", cdHash: "h1", sha256: "s1")
        model.report = firstReport
        model.observeSignatureBaseline(for: firstReport, emitBanner: true)
        #expect(model.signatureChange == nil)

        let changedSigner = sampleReport(path: "/Applications/DemoModel.app", team: "TEAMBBB222", cdHash: "h2", sha256: "s2")
        model.report = changedSigner
        model.observeSignatureBaseline(for: changedSigner, emitBanner: true)
        #expect(model.signatureChange?.kind == .signerChanged)

        model.acknowledgeSignatureBaselineChange()
        #expect(model.signatureChange == nil)
        #expect(store.load().entries["/Applications/DemoModel.app"]?.teamIdentifier == "TEAMBBB222")
    }
}
