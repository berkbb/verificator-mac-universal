// SPDX-License-Identifier: GPL-3.0-only
import Darwin
import Foundation
import Testing
@testable import VerificatorCore
@testable import VerificatorKit

@Suite("Group 1 & Group 2 Security, System Integration & Diagnostics Tests")
struct Group1And2Tests {

    private func makeTempDirectory(prefix: String) throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    private func makeIsolatedDefaults() -> (suiteName: String, defaults: UserDefaults) {
        let suiteName = "com.babadogantech.verificator.tests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        return (suiteName, defaults)
    }

    // MARK: - Group 1.1: POSIX Directory Entries & AppleDouble Detection

    @Test("DirectoryEntries & AppleDoubleDetector skip Finder sidecars while catching disguised ._ binaries")
    func directoryEntriesAndAppleDoubleDetection() throws {
        let root = try makeTempDirectory(prefix: "verificator-appledouble")
        defer { try? FileManager.default.removeItem(at: root) }

        // 1. Legitimate AppleDouble sidecar (0x00051607 big-endian magic)
        let sidecarURL = root.appendingPathComponent("._Info.plist")
        var sidecarData = Data([0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00])
        sidecarData.append(Data(repeating: 0, count: 16))
        try sidecarData.write(to: sidecarURL)

        // 2. Disguised ._ Mach-O binary copied from /usr/bin/true
        let disguisedMachOURL = root.appendingPathComponent("._evil.dylib")
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: disguisedMachOURL)

        // 3. Disguised ._ executable shebang script
        let disguisedScriptURL = root.appendingPathComponent("._loader.sh")
        try Data("#!/bin/sh\necho pwn\n".utf8).write(to: disguisedScriptURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: disguisedScriptURL.path)

        // 4. Normal non-executable hidden config file should be ignored
        let hiddenTextURL = root.appendingPathComponent(".DS_Store")
        try Data("Bud1".utf8).write(to: hiddenTextURL)

        let visibleOnly = try #require(DirectoryEntries.list(at: root, includeHidden: false))
        #expect(visibleOnly.isEmpty)

        let allEntries = try #require(DirectoryEntries.list(at: root, includeHidden: true))
        #expect(allEntries.count == 4)

        #expect(AppleDoubleDetector.isAppleDoubleMagic(at: sidecarURL))
        #expect(!AppleDoubleDetector.isAppleDoubleMagic(at: disguisedMachOURL))

        let flagged = AppleDoubleDetector.collectSuspiciousHiddenItems(in: [root], relativeTo: root)
        #expect(!flagged.contains("._Info.plist"))
        #expect(!flagged.contains(".DS_Store"))
        #expect(flagged.contains("._evil.dylib"))
        #expect(flagged.contains("._loader.sh"))
    }

    // MARK: - Group 1.2: Bundle Symlink Escape & Loop Audit

    @Test("BundleSymlinkAudit allows internal Versions/Current links and catches loops + external escapes")
    func bundleSymlinkAudit() throws {
        let root = try makeTempDirectory(prefix: "verificator-symlink")
        defer { try? FileManager.default.removeItem(at: root) }

        let cleanBundle = root.appendingPathComponent("Clean.framework", isDirectory: true)
        let versionsA = cleanBundle.appendingPathComponent("Versions/A", isDirectory: true)
        try FileManager.default.createDirectory(at: versionsA, withIntermediateDirectories: true)
        try Data("hello".utf8).write(to: versionsA.appendingPathComponent("Clean"))
        try FileManager.default.createSymbolicLink(
            atPath: cleanBundle.appendingPathComponent("Versions/Current").path,
            withDestinationPath: "A"
        )
        let cleanResult = BundleSymlinkAudit.audit(bundleURL: cleanBundle)
        #expect(cleanResult.loops.isEmpty)
        #expect(cleanResult.escapes.isEmpty)
        #expect(cleanResult.scannedEntries > 0)

        let suspiciousBundle = root.appendingPathComponent("Suspicious.app", isDirectory: true)
        let subDir = suspiciousBundle.appendingPathComponent("Contents/Resources/Sub", isDirectory: true)
        try FileManager.default.createDirectory(at: subDir, withIntermediateDirectories: true)
        // Loop back to parent folder
        try FileManager.default.createSymbolicLink(
            atPath: subDir.appendingPathComponent("Loop").path,
            withDestinationPath: ".."
        )
        // External escape pointing outside bundle
        try FileManager.default.createSymbolicLink(
            atPath: suspiciousBundle.appendingPathComponent("Contents/Resources/Outside").path,
            withDestinationPath: "/etc"
        )
        let suspiciousResult = BundleSymlinkAudit.audit(bundleURL: suspiciousBundle)
        #expect(!suspiciousResult.loops.isEmpty)
        #expect(!suspiciousResult.escapes.isEmpty)
    }

    // MARK: - Group 1.3: Development Certificate & JIT Standalone Binary 0% FP

    @Test("Development certificate summary detection and JIT standalone binary zero false-positive check")
    func devCertificateAndJITZeroFalsePositive() throws {
        #expect(ForensicScanner.isDevelopmentCertificateSummary("Apple Development: Jane Doe (TEAM123456)"))
        #expect(ForensicScanner.isDevelopmentCertificateSummary("Mac Developer: John Smith (TEAM654321)"))
        #expect(ForensicScanner.isDevelopmentCertificateSummary("iPhone Developer: Dev (ABC)"))
        #expect(!ForensicScanner.isDevelopmentCertificateSummary("Developer ID Application: Acme Corp (TEAM123456)"))
        #expect(!ForensicScanner.isDevelopmentCertificateSummary("Apple Root CA"))

        // Compile a tiny Mach-O standalone executable and a dylib both referencing JIT/dyld symbols
        // (`mach_vm_protect`, `sys_icache_invalidate`, `_dyld_get_image_vmaddr_slide`) via `-undefined dynamic_lookup`.
        let root = try makeTempDirectory(prefix: "verificator-jit")
        defer { try? FileManager.default.removeItem(at: root) }

        let cSource = root.appendingPathComponent("jit_sample.c")
        try Data("""
        extern void mach_vm_protect(void);
        extern void sys_icache_invalidate(void);
        extern void _dyld_get_image_vmaddr_slide(void);
        int main(void) {
            mach_vm_protect();
            sys_icache_invalidate();
            _dyld_get_image_vmaddr_slide();
            return 0;
        }
        """.utf8).write(to: cSource)

        let exeURL = root.appendingPathComponent("jit_standalone")
        let dylibURL = root.appendingPathComponent("libjit_hook.dylib")

        let clangExe = ForensicScanner.runTool(
            "/usr/bin/clang",
            args: ["-x", "c", cSource.path, "-Wl,-undefined,dynamic_lookup", "-o", exeURL.path]
        )
        let clangDylib = ForensicScanner.runTool(
            "/usr/bin/clang",
            args: ["-dynamiclib", "-x", "c", cSource.path, "-Wl,-undefined,dynamic_lookup", "-o", dylibURL.path]
        )

        try #require(clangExe.exitCode == 0 && clangDylib.exitCode == 0, "clang must compile JIT test fixtures")

        // Standalone executable using W^X JIT symbols must NOT be classified as an injected crack
        let standaloneHooks = ForensicScanner.analyzeMachOHooks(
            binaryPath: exeURL.path,
            libraryName: exeURL.lastPathComponent,
            isDylib: false,
            parentHasOfficialChain: false,
            extractTargetStrings: false
        )
        #expect(!standaloneHooks.isInjectedCrack)

        // Dylib with identical memory-patching + dyld-slide imports MUST still flag as injected crack
        let dylibHooks = ForensicScanner.analyzeMachOHooks(
            binaryPath: dylibURL.path,
            libraryName: dylibURL.lastPathComponent,
            isDylib: true,
            parentHasOfficialChain: true,
            extractTargetStrings: false
        )
        #expect(dylibHooks.isInjectedCrack)
    }

    // MARK: - Group 1.4: KernelSocketList Binary pcblist_n Parser

    @Test("KernelSocketList.parse decodes synthetic TCP IPv4 LISTEN, TCP IPv6 ESTABLISHED, and UDP sockets")
    func kernelSocketListBinaryParser() {
        func writeU8(_ data: inout Data, offset: Int, value: UInt8) {
            data[offset] = value
        }
        func writeU16BE(_ data: inout Data, offset: Int, value: UInt16) {
            var be = value.bigEndian
            withUnsafeBytes(of: &be) { bytes in
                data.replaceSubrange(offset..<(offset + 2), with: bytes)
            }
        }
        func writeU32(_ data: inout Data, offset: Int, value: UInt32) {
            var le = value.littleEndian
            withUnsafeBytes(of: &le) { bytes in
                data.replaceSubrange(offset..<(offset + 4), with: bytes)
            }
        }
        func writeU64(_ data: inout Data, offset: Int, value: UInt64) {
            var le = value.littleEndian
            withUnsafeBytes(of: &le) { bytes in
                data.replaceSubrange(offset..<(offset + 8), with: bytes)
            }
        }
        func makeRecord(length: Int, kind: UInt32, populate: (inout Data) -> Void) -> Data {
            let alignedLen = (length + 7) & ~7
            var buf = Data(repeating: 0, count: alignedLen)
            writeU32(&buf, offset: 0, value: UInt32(length))
            writeU32(&buf, offset: 4, value: kind)
            populate(&buf)
            return buf
        }

        // Generation header (24 bytes)
        var tcpBlob = Data(repeating: 0, count: 24)
        writeU32(&tcpBlob, offset: 0, value: 24)

        // Socket 1: IPv4 127.0.0.1:8080 LISTEN pid=4242 uid=501 with traffic counters
        tcpBlob.append(makeRecord(length: KernelSocketList.Layout.inpcbMinimumLength, kind: KernelSocketList.kindInpcb) { buf in
            writeU16BE(&buf, offset: KernelSocketList.Layout.inpcbForeignPort, value: 0)
            writeU16BE(&buf, offset: KernelSocketList.Layout.inpcbLocalPort, value: 8080)
            writeU8(&buf, offset: KernelSocketList.Layout.inpcbVersionFlag, value: KernelSocketList.Layout.versionFlagIPv4)
            let localOff = KernelSocketList.Layout.inpcbLocalAddress + 12
            buf[localOff] = 127
            buf[localOff + 1] = 0
            buf[localOff + 2] = 0
            buf[localOff + 3] = 1
        })
        tcpBlob.append(makeRecord(length: KernelSocketList.Layout.tcpcbMinimumLength, kind: KernelSocketList.kindTcpcb) { buf in
            writeU32(&buf, offset: KernelSocketList.Layout.tcpcbState, value: 1) // LISTEN
        })
        tcpBlob.append(makeRecord(length: KernelSocketList.Layout.socketMinimumLength, kind: KernelSocketList.kindSocket) { buf in
            writeU32(&buf, offset: KernelSocketList.Layout.socketUID, value: 501)
            writeU32(&buf, offset: KernelSocketList.Layout.socketLastPID, value: 4242)
            writeU32(&buf, offset: KernelSocketList.Layout.socketEffectivePID, value: 4242)
        })
        tcpBlob.append(makeRecord(length: KernelSocketList.Layout.statsMinimumLength, kind: KernelSocketList.kindStats) { buf in
            writeU64(&buf, offset: 8, value: 10)   // class 0 rxPackets
            writeU64(&buf, offset: 16, value: 2048) // class 0 rxBytes
            writeU64(&buf, offset: 24, value: 5)    // class 0 txPackets
            writeU64(&buf, offset: 32, value: 512)  // class 0 txBytes
        })

        // Socket 2: IPv6 [::1]:55123 -> [2001:db8::1]:443 ESTABLISHED pid=5252
        tcpBlob.append(makeRecord(length: KernelSocketList.Layout.inpcbMinimumLength, kind: KernelSocketList.kindInpcb) { buf in
            writeU16BE(&buf, offset: KernelSocketList.Layout.inpcbForeignPort, value: 443)
            writeU16BE(&buf, offset: KernelSocketList.Layout.inpcbLocalPort, value: 55123)
            writeU8(&buf, offset: KernelSocketList.Layout.inpcbVersionFlag, value: 0x02) // IPv6
            // Local ::1
            buf[KernelSocketList.Layout.inpcbLocalAddress + 15] = 1
            // Remote 2001:db8::1
            let fOff = KernelSocketList.Layout.inpcbForeignAddress
            buf[fOff] = 0x20
            buf[fOff + 1] = 0x01
            buf[fOff + 2] = 0x0d
            buf[fOff + 3] = 0xb8
            buf[fOff + 15] = 0x01
        })
        tcpBlob.append(makeRecord(length: KernelSocketList.Layout.tcpcbMinimumLength, kind: KernelSocketList.kindTcpcb) { buf in
            writeU32(&buf, offset: KernelSocketList.Layout.tcpcbState, value: 4) // ESTABLISHED
        })
        tcpBlob.append(makeRecord(length: KernelSocketList.Layout.socketMinimumLength, kind: KernelSocketList.kindSocket) { buf in
            writeU32(&buf, offset: KernelSocketList.Layout.socketUID, value: 501)
            writeU32(&buf, offset: KernelSocketList.Layout.socketLastPID, value: 0)
            writeU32(&buf, offset: KernelSocketList.Layout.socketEffectivePID, value: 5252)
        })

        // Parse + trailing generation marker should still parse valid records cleanly
        tcpBlob.append(Data([0, 0, 0]))
        let parsedTCP = KernelSocketList.parse(tcpBlob, tcp: true)
        #expect(parsedTCP?.count == 2)
        let first = parsedTCP?.first
        #expect(first?.pid == 4242)
        #expect(first?.ipProtocol == .tcp)
        #expect(first?.localAddress == "127.0.0.1")
        #expect(first?.localPort == 8080)
        #expect(first?.remoteAddress == nil)
        #expect(first?.isConnected == false)
        #expect(first?.stateName == "LISTEN")
        #expect(first?.counters?.rxBytes == 2048)
        #expect(first?.counters?.txBytes == 512)

        let second = parsedTCP?.dropFirst().first
        #expect(second?.pid == 5252)
        #expect(second?.localAddress == "::1")
        #expect(second?.localPort == 55123)
        #expect(second?.remoteAddress == "2001:db8::1")
        #expect(second?.remotePort == 443)
        #expect(second?.isConnected == true)
        #expect(second?.stateName == "ESTABLISHED")

        // UDP socket parse test
        var udpBlob = Data(repeating: 0, count: 24)
        writeU32(&udpBlob, offset: 0, value: 24)
        udpBlob.append(makeRecord(length: KernelSocketList.Layout.inpcbMinimumLength, kind: KernelSocketList.kindInpcb) { buf in
            writeU16BE(&buf, offset: KernelSocketList.Layout.inpcbLocalPort, value: 5353)
            writeU8(&buf, offset: KernelSocketList.Layout.inpcbVersionFlag, value: KernelSocketList.Layout.versionFlagIPv4)
        })
        udpBlob.append(makeRecord(length: KernelSocketList.Layout.socketMinimumLength, kind: KernelSocketList.kindSocket) { buf in
            writeU32(&buf, offset: KernelSocketList.Layout.socketLastPID, value: 6000)
        })
        let parsedUDP = KernelSocketList.parse(udpBlob, tcp: false)
        #expect(parsedUDP?.count == 1)
        #expect(parsedUDP?.first?.ipProtocol == .udp)
        #expect(parsedUDP?.first?.localPort == 5353)
        #expect(parsedUDP?.first?.pid == 6000)

        // Too-short data returns empty without crashing
        #expect(KernelSocketList.parse(Data([1, 2, 3]), tcp: true) == [])
    }

    // MARK: - Group 1.5 + Group 2: ManagedConfiguration & SettingsTransfer

    @Test("ManagedConfiguration enforces MDM locks and SettingsTransfer round-trips safely with ~/ compression")
    @MainActor
    func managedConfigurationAndSettingsTransferRoundTrip() throws {
        let (suiteName, defaults) = makeIsolatedDefaults()
        defer { UserDefaults.standard.removePersistentDomain(forName: suiteName) }

        let root = try makeTempDirectory(prefix: "verificator-transfer")
        defer { try? FileManager.default.removeItem(at: root) }
        let storeURL = root.appendingPathComponent("sig-store.json")

        let sourceHome = URL(fileURLWithPath: "/Users/alice", isDirectory: true)
        let targetHome = URL(fileURLWithPath: "/Users/bob", isDirectory: true)

        // Verify ManagedConfiguration key filter directly
        let locked = ManagedConfiguration.managedKeys(defaults: defaults) {
            $0 == VerificatorPreferenceKey.language || $0 == VerificatorPreferenceKey.watchedFolderEnabled
        }
        #expect(locked.contains(VerificatorPreferenceKey.language))
        #expect(locked.contains(VerificatorPreferenceKey.watchedFolderEnabled))

        // Build portable export with sourceHome compression
        var tracker = SignatureTracker()
        let report = BundleAuditReport(
            targetKind: .appBundle,
            bundlePath: "/Users/alice/Applications/Sample.app",
            bundleName: "Sample",
            bundleId: "com.example.sample",
            shortVersion: "1.0",
            buildVersion: "1",
            executableName: "Sample",
            executableModDate: "2026-01-01",
            plistModDate: "2026-01-01",
            teamIdentifier: "TEAM123456",
            authorities: ["Developer ID Application: Example (TEAM123456)"],
            signedTimestamp: "2026-01-01",
            hasHardenedRuntime: true,
            isNotarized: true,
            gatekeeperStatus: "OK",
            cdHash: "cdhash-alice",
            scanDurationMs: 5,
            verdict: .clean,
            findings: [],
            linkedDylibs: [],
            bundledLibraries: [],
            hookCategories: [],
            rawCodesignOutput: "",
            rawOtoolOutput: ""
        )
        _ = tracker.observe(report: report, at: Date(timeIntervalSince1970: 1_700_000_000))

        let exportBytes = try SettingsTransfer.exportData(
            preferences: [
                VerificatorPreferenceKey.language: .string("ro"),
                VerificatorPreferenceKey.watchedFolderEnabled: .bool(true),
                VerificatorPreferenceKey.deepFrameworkSignatureCheck: .bool(false),
                VerificatorPreferenceKey.recentBundles: .string("/Users/alice/Desktop/Ignored.app"),
            ],
            watchedFolders: [
                "/Users/alice/Downloads",
                "/Applications",
            ],
            tracker: tracker,
            home: sourceHome
        )

        let rawJSON = String(decoding: exportBytes, as: UTF8.self)
            .replacingOccurrences(of: "\\/", with: "/")
        #expect(rawJSON.contains("~/Downloads"))
        #expect(rawJSON.contains("~/Applications/Sample.app"))
        #expect(!rawJSON.contains("/Users/alice/"))
        #expect(!rawJSON.contains("recentBundles"))

        // Import into target AppSettings where `language` is MDM-locked to `.tr`
        let settings = AppSettings(defaults: defaults)
        settings.language = .tr
        settings.managedKeysOverride = [VerificatorPreferenceKey.language]

        let model = AppModel(settings: settings, signatureStore: SignatureTrackerStore(fileURL: storeURL))
        let didImport = model.importPortableSettings(from: exportBytes, home: targetHome)
        #expect(didImport)
        // Locked key must remain untouched while unlocked keys + ~/ paths expand to Bob's home
        #expect(settings.language == .tr)
        #expect(settings.watchedFolderEnabled == true)
        #expect(settings.deepFrameworkSignatureCheck == false)
        #expect(settings.watchedFolderPaths == ["/Users/bob/Downloads", "/Applications"])
        let persistedTracker = SignatureTrackerStore(fileURL: storeURL).load()
        #expect(persistedTracker.entries["/Users/bob/Applications/Sample.app"] != nil)

        // SignatureTracker.merge respects newer timestamps
        var mergeTarget = SignatureTracker()
        let olderBaseline = SeenSignatureBaseline(
            bundleId: "com.example.merged",
            teamIdentifier: "OLDTEAM",
            authorities: ["Dev Old"],
            cdHash: "old-hash",
            executableSHA256: "old-sha",
            shortVersion: "1.0",
            firstSeen: Date(timeIntervalSince1970: 100),
            lastSeen: Date(timeIntervalSince1970: 200)
        )
        let newerBaseline = SeenSignatureBaseline(
            bundleId: "com.example.merged",
            teamIdentifier: "NEWTEAM",
            authorities: ["Dev New"],
            cdHash: "new-hash",
            executableSHA256: "new-sha",
            shortVersion: "2.0",
            firstSeen: Date(timeIntervalSince1970: 100),
            lastSeen: Date(timeIntervalSince1970: 500)
        )
        #expect(mergeTarget.merge(entries: ["/Applications/Merged.app": newerBaseline]) == 1)
        #expect(mergeTarget.merge(entries: ["/Applications/Merged.app": olderBaseline]) == 0)
        #expect(mergeTarget.entries["/Applications/Merged.app"]?.teamIdentifier == "NEWTEAM")

        // Validation failure paths: >2MB payload, wrong format, newer schemaVersion
        let oversized = Data(repeating: 0x41, count: VerificatorPortableDocument.maxPayloadBytes + 1)
        #expect(throws: SettingsTransferFailure.tooLarge) {
            _ = try SettingsTransfer.decodeAndValidate(data: oversized, home: targetHome, managedKeys: [])
        }
        let wrongFormat = Data("{\"format\":\"other.app\",\"schemaVersion\":1}".utf8)
        #expect(throws: SettingsTransferFailure.malformedOrWrongFormat) {
            _ = try SettingsTransfer.decodeAndValidate(data: wrongFormat, home: targetHome, managedKeys: [])
        }
        let futureVersion = Data("{\"format\":\"\(VerificatorPortableDocument.expectedFormatIdentifier)\",\"schemaVersion\":\(VerificatorPortableDocument.currentSchemaVersion + 10)}".utf8)
        #expect(throws: SettingsTransferFailure.unsupportedVersion(VerificatorPortableDocument.currentSchemaVersion + 10)) {
            _ = try SettingsTransfer.decodeAndValidate(data: futureVersion, home: targetHome, managedKeys: [])
        }
    }

    // MARK: - Group 2: SystemSecurityPosture & Orphaned Package Receipts

    @Test("SystemSecurityPostureAuditor parsers & read-only orphaned pkgutil receipt detection")
    func systemPostureParsersAndOrphanReceipts() throws {
        #expect(SystemSecurityPostureAuditor.parseCsrutilStatus("System Integrity Protection status: enabled.").0 == .enabled)
        #expect(SystemSecurityPostureAuditor.parseCsrutilStatus("System Integrity Protection status: disabled.").0 == .disabled)
        #expect(SystemSecurityPostureAuditor.parseAuthenticatedRootStatus("Authenticated Root status: enabled").0 == .enabled)
        #expect(SystemSecurityPostureAuditor.parseGatekeeperStatus("assessments enabled").0 == .enabled)
        #expect(SystemSecurityPostureAuditor.parseGatekeeperStatus("assessments disabled").0 == .disabled)

        let diskInfo = """
           Device Identifier:         disk3s1s1
           SMART Status:              Verified
           Encrypted:                 No
           FileVault:                 Yes
        """
        let smart = SystemSecurityPostureAuditor.parseDiskutilSmartStatus(diskInfo)
        #expect(smart.0 == .verified)
        #expect(smart.1 == "Verified")

        #expect(VolumeEncryptionInfo.parseFdesetupStatus("FileVault is On.") == true)
        #expect(VolumeEncryptionInfo.parseFdesetupStatus("FileVault is Off.\n") == false)
        #expect(VolumeEncryptionInfo.parseFdesetupStatus("Error: Unknown volume or device specifier: '/'.") == nil)
        #expect(VolumeEncryptionInfo.parseDiskutilFileVault(diskInfo) == true)
        #expect(VolumeEncryptionInfo.parseDiskutilFileVault("   FileVault:                 No\n") == false)
        #expect(VolumeEncryptionInfo.parseDiskutilFileVault("   Encrypted:                 No\n") == nil)

        // Create temporary BOM receipts directory + payload folder
        let root = try makeTempDirectory(prefix: "verificator-receipts")
        defer { try? FileManager.default.removeItem(at: root) }

        let receiptsDir = root.appendingPathComponent("receipts", isDirectory: true)
        let presentPayloadDir = root.appendingPathComponent("present_payload", isDirectory: true)
        let missingPayloadSourceDir = root.appendingPathComponent("missing_source", isDirectory: true)
        let absentInstallPrefix = root.appendingPathComponent("deleted_prefix", isDirectory: true)

        try FileManager.default.createDirectory(at: receiptsDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: presentPayloadDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: missingPayloadSourceDir, withIntermediateDirectories: true)
        try Data("bin".utf8).write(to: presentPayloadDir.appendingPathComponent("tool"))
        try Data("orphan".utf8).write(to: missingPayloadSourceDir.appendingPathComponent("gone_app"))

        // 1. Apple receipt must be excluded even if BOM absent/missing
        let applePlist: [String: Any] = [
            "PackageIdentifier": "com.apple.pkg.CoreSystem",
            "PackageVersion": "1.0",
            "InstallPrefixPath": absentInstallPrefix.path,
        ]
        let appleData = try PropertyListSerialization.data(fromPropertyList: applePlist, format: .xml, options: 0)
        try appleData.write(to: receiptsDir.appendingPathComponent("com.apple.pkg.CoreSystem.plist"))

        // 2. Installed third-party receipt whose payload still exists on disk -> NOT orphaned
        let presentPlist: [String: Any] = [
            "PackageIdentifier": "com.example.installed",
            "PackageVersion": "2.1.0",
            "InstallPrefixPath": presentPayloadDir.path,
        ]
        try PropertyListSerialization.data(fromPropertyList: presentPlist, format: .xml, options: 0)
            .write(to: receiptsDir.appendingPathComponent("com.example.installed.plist"))
        let mkbom1 = ForensicScanner.runTool(
            "/usr/bin/mkbom",
            args: [presentPayloadDir.path, receiptsDir.appendingPathComponent("com.example.installed.bom").path]
        )

        // 3. Orphaned third-party receipt whose InstallPrefixPath no longer contains any BOM entry
        let orphanPlist: [String: Any] = [
            "PackageIdentifier": "com.example.removedtool",
            "PackageVersion": "0.9.4",
            "InstallPrefixPath": absentInstallPrefix.path,
        ]
        try PropertyListSerialization.data(fromPropertyList: orphanPlist, format: .xml, options: 0)
            .write(to: receiptsDir.appendingPathComponent("com.example.removedtool.plist"))
        let mkbom2 = ForensicScanner.runTool(
            "/usr/bin/mkbom",
            args: [missingPayloadSourceDir.path, receiptsDir.appendingPathComponent("com.example.removedtool.bom").path]
        )

        try #require(mkbom1.exitCode == 0 && mkbom2.exitCode == 0, "mkbom must generate test .bom files")

        let audit = SystemSecurityPostureAuditor.auditOrphanedReceipts(in: receiptsDir)
        #expect(audit.count == 2)
        #expect(audit.orphans.count == 1)
        #expect(audit.orphans.first?.packageIdentifier == "com.example.removedtool")
        #expect(audit.orphans.first?.version == "0.9.4")
        #expect(audit.orphans.first?.forgetCommand == "sudo pkgutil --forget 'com.example.removedtool'")

        let samplePaths = SystemSecurityPostureAuditor.extractSampleBomPaths(
            from: ".\n./._sidecar\n./.DS_Store\n./Applications/Sample.app\n./usr/local/bin/tool\n",
            prefixPath: "/opt"
        )
        #expect(samplePaths == ["/opt/Applications/Sample.app", "/opt/usr/local/bin/tool"])
    }

    // MARK: - Group 2: Anonymized Diagnostic Report Builder

    @Test("DiagnosticReportBuilder masks all home paths and usernames across report, posture, and logs")
    func diagnosticReportMasksPII() {
        let masker = DiagnosticMasker(
            homePath: "/Users/alice",
            userName: "alice",
            salt: Data([7, 8, 9, 10])
        )
        let activeReport = BundleAuditReport(
            targetKind: .appBundle,
            bundlePath: "/Users/alice/Downloads/SecretTool.app",
            bundleName: "SecretTool",
            bundleId: "com.alice.secrettool",
            shortVersion: "1.0",
            buildVersion: "1",
            executableName: "SecretTool",
            executableModDate: "2026-01-01",
            plistModDate: "2026-01-01",
            teamIdentifier: "TEAM123",
            authorities: ["Developer ID Application: Acme"],
            signedTimestamp: "2026-01-01",
            hasHardenedRuntime: true,
            isNotarized: true,
            gatekeeperStatus: "OK",
            cdHash: "deadbeef",
            scanDurationMs: 42,
            verdict: .clean,
            findings: [],
            linkedDylibs: [],
            bundledLibraries: [],
            hookCategories: [],
            rawCodesignOutput: "",
            rawOtoolOutput: ""
        )
        let posture = SystemSecurityPosture(
            scannedAt: "2026-01-01T00:00:00Z",
            macOSVersion: "26.2",
            kernelRelease: "25.0.0",
            hardwareModel: "Mac16,1",
            cpuArchitecture: "arm64",
            sipStatus: .enabled,
            sipDetail: "enabled",
            ssvStatus: .enabled,
            ssvDetail: "enabled",
            gatekeeperMasterStatus: .enabled,
            gatekeeperDetail: "enabled",
            fileVaultBootEncrypted: true,
            bootVolumeName: "Macintosh HD",
            bootVolumeFormat: "APFS",
            firewallEnabled: true,
            firewallStealthMode: false,
            smartHealthStatus: .verified,
            smartDetail: "Verified",
            fullDiskAccessGranted: true,
            orphanedReceipts: [],
            receiptsAuditedCount: 12
        )

        let markdown = DiagnosticReportBuilder.buildMarkdown(
            from: DiagnosticReportInput(
                appVersion: "1.3.0",
                appBuild: "20",
                languageCode: "en",
                activeReport: activeReport,
                systemPosture: posture,
                managedKeys: [VerificatorPreferenceKey.language],
                logLines: [
                    "[2026-01-01] Scanned /Users/alice/Desktop/App.app owned by alice",
                    "[2026-01-01] System audit complete",
                ]
            ),
            masker: masker,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        #expect(markdown.contains("# Verificator Diagnostic Report"))
        #expect(markdown.contains("## System Security Posture"))
        #expect(markdown.contains("## Active Audit Target (Masked)"))
        #expect(markdown.contains("## Recent Diagnostic Logs (Masked)"))
        #expect(!markdown.contains("/Users/alice"))
        #expect(!markdown.contains("alice"))
    }

    // MARK: - Group 2: WatchedFolderService & URL Scheme Posture Routing

    @Test("WatchedFolderService ignores baseline and AppleDouble sidecars, catches newly dropped packages, and routes posture URL")
    @MainActor
    func watchedFolderAndPostureRouting() throws {
        let root = try makeTempDirectory(prefix: "verificator-watched")
        defer { try? FileManager.default.removeItem(at: root) }

        // Seed existing items + AppleDouble + unsupported file
        try Data("app".utf8).write(to: root.appendingPathComponent("Existing.dmg"))
        try Data([0x00, 0x05, 0x16, 0x07]).write(to: root.appendingPathComponent("._Existing.dmg"))
        try Data("notes".utf8).write(to: root.appendingPathComponent("readme.txt"))

        let service = WatchedFolderService()
        // First visit builds baseline without alerting on pre-existing items
        let firstPass = service.collectChangedTargets(in: [root.path], includeBaseline: false)
        #expect(firstPass.isEmpty)

        // Second pass with no changes stays empty
        #expect(service.collectChangedTargets(in: [root.path], includeBaseline: false).isEmpty)

        // Dropping a new .pkg and another AppleDouble sidecar should return ONLY NewInstaller.pkg
        let newPkg = root.appendingPathComponent("NewInstaller.pkg")
        try Data("pkg-bytes".utf8).write(to: newPkg)
        try Data([0x00, 0x05, 0x16, 0x07]).write(to: root.appendingPathComponent("._NewInstaller.pkg"))

        let secondPass = service.collectChangedTargets(in: [root.path], includeBaseline: false)
        #expect(secondPass.map(\.lastPathComponent) == ["NewInstaller.pkg"])

        // Manual baseline scan returns all supported targets (both Existing.dmg and NewInstaller.pkg)
        let manualPass = Set(service.collectChangedTargets(in: [root.path], includeBaseline: true).map(\.lastPathComponent))
        #expect(manualPass == ["Existing.dmg", "NewInstaller.pkg"])

        // Verify AppModel URL route `verificator://posture` switches workspace mode cleanly
        let (suiteName, defaults) = makeIsolatedDefaults()
        defer { UserDefaults.standard.removePersistentDomain(forName: suiteName) }
        let storeURL = root.appendingPathComponent("history.json")
        let model = AppModel(settings: AppSettings(defaults: defaults), signatureStore: SignatureTrackerStore(fileURL: storeURL))
        model.handleIncomingURL(URL(string: "verificator://posture")!)
        #expect(model.workspaceMode == .systemPosture)
    }

    @Test("Segmented pickers do not clamp width with maxWidth modifiers that cause macOS segment overlap")
    func segmentedPickersAvoidClampedMaxWidth() throws {
        let viewsDir = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/VerificatorKit/Views", isDirectory: true)

        let files = try FileManager.default.contentsOfDirectory(at: viewsDir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "swift" }
        #expect(!files.isEmpty)

        for file in files {
            let lines = try String(contentsOf: file, encoding: .utf8).components(separatedBy: .newlines)
            for (index, line) in lines.enumerated() where line.contains(".pickerStyle(.segmented)") {
                let lookAheadEnd = min(lines.count - 1, index + 3)
                let modifierSlice = lines[index...lookAheadEnd].joined(separator: "\n")
                #expect(
                    !modifierSlice.contains(".frame(maxWidth:"),
                    "Segmented picker in \(file.lastPathComponent):\(index + 1) must not cap width with .frame(maxWidth:)"
                )
            }
        }
    }
}
