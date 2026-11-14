// SPDX-License-Identifier: GPL-3.0-only
import Darwin
import Foundation

public enum PostureCheckState: String, Sendable, Equatable, Codable {
    case enabled
    case disabled
    case custom
    case verified
    case failing
    case unknown
}

/// Read-only residual third-party installer receipt whose BOM payload paths no longer exist on disk.
public struct OrphanedPackageReceipt: Identifiable, Sendable, Equatable, Codable {
    public var id: String { packageIdentifier }
    public let packageIdentifier: String
    public let version: String
    public let installPrefixPath: String
    public let receiptPlistPath: String
    public let missingPayloadSample: [String]
    public let forgetCommand: String

    public init(
        packageIdentifier: String,
        version: String,
        installPrefixPath: String,
        receiptPlistPath: String,
        missingPayloadSample: [String]
    ) {
        self.packageIdentifier = packageIdentifier
        self.version = version
        self.installPrefixPath = installPrefixPath
        self.receiptPlistPath = receiptPlistPath
        self.missingPayloadSample = missingPayloadSample
        let escaped = packageIdentifier.replacingOccurrences(of: "'", with: "'\\''")
        self.forgetCommand = "sudo pkgutil --forget '\(escaped)'"
    }
}

/// Consolidated read-only host security posture & orphaned installer receipt snapshot.
public struct SystemSecurityPosture: Sendable, Equatable, Codable {
    public let scannedAt: String
    public let macOSVersion: String
    public let kernelRelease: String
    public let hardwareModel: String
    public let cpuArchitecture: String
    public let sipStatus: PostureCheckState
    public let sipDetail: String
    public let ssvStatus: PostureCheckState
    public let ssvDetail: String
    public let gatekeeperMasterStatus: PostureCheckState
    public let gatekeeperDetail: String
    public let fileVaultBootEncrypted: Bool?
    public let bootVolumeName: String
    public let bootVolumeFormat: String
    public let firewallEnabled: Bool?
    public let firewallStealthMode: Bool?
    public let smartHealthStatus: PostureCheckState
    public let smartDetail: String
    public let fullDiskAccessGranted: Bool
    public let orphanedReceipts: [OrphanedPackageReceipt]
    public let receiptsAuditedCount: Int

    public init(
        scannedAt: String,
        macOSVersion: String,
        kernelRelease: String,
        hardwareModel: String,
        cpuArchitecture: String,
        sipStatus: PostureCheckState,
        sipDetail: String,
        ssvStatus: PostureCheckState,
        ssvDetail: String,
        gatekeeperMasterStatus: PostureCheckState,
        gatekeeperDetail: String,
        fileVaultBootEncrypted: Bool?,
        bootVolumeName: String,
        bootVolumeFormat: String,
        firewallEnabled: Bool?,
        firewallStealthMode: Bool?,
        smartHealthStatus: PostureCheckState,
        smartDetail: String,
        fullDiskAccessGranted: Bool,
        orphanedReceipts: [OrphanedPackageReceipt],
        receiptsAuditedCount: Int
    ) {
        self.scannedAt = scannedAt
        self.macOSVersion = macOSVersion
        self.kernelRelease = kernelRelease
        self.hardwareModel = hardwareModel
        self.cpuArchitecture = cpuArchitecture
        self.sipStatus = sipStatus
        self.sipDetail = sipDetail
        self.ssvStatus = ssvStatus
        self.ssvDetail = ssvDetail
        self.gatekeeperMasterStatus = gatekeeperMasterStatus
        self.gatekeeperDetail = gatekeeperDetail
        self.fileVaultBootEncrypted = fileVaultBootEncrypted
        self.bootVolumeName = bootVolumeName
        self.bootVolumeFormat = bootVolumeFormat
        self.firewallEnabled = firewallEnabled
        self.firewallStealthMode = firewallStealthMode
        self.smartHealthStatus = smartHealthStatus
        self.smartDetail = smartDetail
        self.fullDiskAccessGranted = fullDiskAccessGranted
        self.orphanedReceipts = orphanedReceipts
        self.receiptsAuditedCount = receiptsAuditedCount
    }

    public func jsonData(prettyPrinted: Bool = true) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = prettyPrinted ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
        return try encoder.encode(self)
    }

    public func redacted(using masker: DiagnosticMasker) -> SystemSecurityPosture {
        SystemSecurityPosture(
            scannedAt: scannedAt,
            macOSVersion: macOSVersion,
            kernelRelease: kernelRelease,
            hardwareModel: hardwareModel,
            cpuArchitecture: cpuArchitecture,
            sipStatus: sipStatus,
            sipDetail: masker.redact(text: sipDetail),
            ssvStatus: ssvStatus,
            ssvDetail: masker.redact(text: ssvDetail),
            gatekeeperMasterStatus: gatekeeperMasterStatus,
            gatekeeperDetail: masker.redact(text: gatekeeperDetail),
            fileVaultBootEncrypted: fileVaultBootEncrypted,
            bootVolumeName: bootVolumeName,
            bootVolumeFormat: bootVolumeFormat,
            firewallEnabled: firewallEnabled,
            firewallStealthMode: firewallStealthMode,
            smartHealthStatus: smartHealthStatus,
            smartDetail: smartDetail,
            fullDiskAccessGranted: fullDiskAccessGranted,
            orphanedReceipts: orphanedReceipts.map {
                OrphanedPackageReceipt(
                    packageIdentifier: $0.packageIdentifier,
                    version: $0.version,
                    installPrefixPath: masker.maskPath($0.installPrefixPath),
                    receiptPlistPath: masker.maskPath($0.receiptPlistPath),
                    missingPayloadSample: $0.missingPayloadSample.map { masker.maskPath($0) }
                )
            },
            receiptsAuditedCount: receiptsAuditedCount
        )
    }
}

public enum SystemSecurityPostureAuditor {
    public static let receiptsDirectory = URL(fileURLWithPath: "/private/var/db/receipts", isDirectory: true)

    public static func collect(
        includeOrphanReceipts: Bool = true,
        cancellation: ScanCancellationToken? = nil
    ) -> SystemSecurityPosture {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        let macOS = ProcessInfo.processInfo.operatingSystemVersionString
        let kernelRelease = readSysctlString("kern.osrelease") ?? "-"
        let hwModel = readSysctlString("hw.model") ?? "-"
        #if arch(arm64)
        let arch = "arm64"
        #elseif arch(x86_64)
        let arch = "x86_64"
        #else
        let arch = "unknown"
        #endif

        let sipRaw = runReadOnlyTool("/usr/bin/csrutil", args: ["status"], cancellation: cancellation)
        let (sipStatus, sipDetail) = parseCsrutilStatus(sipRaw)

        let ssvRaw = runReadOnlyTool("/usr/bin/csrutil", args: ["authenticated-root", "status"], cancellation: cancellation)
        let (ssvStatus, ssvDetail) = parseAuthenticatedRootStatus(ssvRaw)

        let spctlRaw = runReadOnlyTool("/usr/sbin/spctl", args: ["--status"], cancellation: cancellation)
        let (gkStatus, gkDetail) = parseGatekeeperStatus(spctlRaw)

        let bootVolume = VolumeEncryptionInfo.read(for: URL(fileURLWithPath: "/"))
        let firewall = ApplicationFirewall.readSystemStatus(cancellation: cancellation)

        let diskRaw = runReadOnlyTool("/usr/sbin/diskutil", args: ["info", "/"], cancellation: cancellation)
        let (smartStatus, smartDetail) = parseDiskutilSmartStatus(diskRaw)
        let bootEncrypted = VolumeEncryptionInfo.parseDiskutilFileVault(diskRaw) ?? bootVolume?.isEncrypted

        let fdaGranted = FullDiskAccess.isGranted

        let receiptResult: (orphans: [OrphanedPackageReceipt], count: Int)
        if includeOrphanReceipts && cancellation?.isCancelled != true {
            receiptResult = auditOrphanedReceipts(cancellation: cancellation)
        } else {
            receiptResult = ([], 0)
        }

        return SystemSecurityPosture(
            scannedAt: formatter.string(from: Date()),
            macOSVersion: macOS,
            kernelRelease: kernelRelease,
            hardwareModel: hwModel,
            cpuArchitecture: arch,
            sipStatus: sipStatus,
            sipDetail: sipDetail,
            ssvStatus: ssvStatus,
            ssvDetail: ssvDetail,
            gatekeeperMasterStatus: gkStatus,
            gatekeeperDetail: gkDetail,
            fileVaultBootEncrypted: bootEncrypted,
            bootVolumeName: bootVolume?.volumeName ?? "/",
            bootVolumeFormat: bootVolume?.format ?? "-",
            firewallEnabled: firewall.globalEnabled,
            firewallStealthMode: firewall.stealthMode,
            smartHealthStatus: smartStatus,
            smartDetail: smartDetail,
            fullDiskAccessGranted: fdaGranted,
            orphanedReceipts: receiptResult.orphans,
            receiptsAuditedCount: receiptResult.count
        )
    }

    // MARK: - Deterministic Parsers (Unit-Testable Without Subprocesses)

    public static func parseCsrutilStatus(_ output: String) -> (PostureCheckState, String) {
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return (.unknown, "-") }
        let lower = trimmed.lowercased()
        if lower.contains("enabled.") || (lower.contains("enabled") && !lower.contains("disabled")) {
            return (.enabled, trimmed)
        }
        if lower.contains("disabled.") || lower.contains("disabled") {
            return (.disabled, trimmed)
        }
        if lower.contains("custom configuration") {
            return (.custom, trimmed)
        }
        return (.unknown, trimmed)
    }

    public static func parseAuthenticatedRootStatus(_ output: String) -> (PostureCheckState, String) {
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return (.unknown, "-") }
        let lower = trimmed.lowercased()
        if lower.contains("enabled") && !lower.contains("disabled") {
            return (.enabled, trimmed)
        }
        if lower.contains("disabled") {
            return (.disabled, trimmed)
        }
        return (.unknown, trimmed)
    }

    public static func parseGatekeeperStatus(_ output: String) -> (PostureCheckState, String) {
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return (.unknown, "-") }
        let lower = trimmed.lowercased()
        if lower.contains("assessments enabled") {
            return (.enabled, trimmed)
        }
        if lower.contains("assessments disabled") {
            return (.disabled, trimmed)
        }
        return (.unknown, trimmed)
    }

    public static func parseDiskutilSmartStatus(_ output: String) -> (PostureCheckState, String) {
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return (.unknown, "-") }
        for line in trimmed.components(separatedBy: .newlines) {
            let parts = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
            if key == "smart status" || key == "s.m.a.r.t. status" {
                let lowerVal = value.lowercased()
                if lowerVal.contains("verified") || lowerVal == "ok" {
                    return (.verified, value)
                }
                if lowerVal.contains("fail") {
                    return (.failing, value)
                }
                return (.unknown, value)
            }
        }
        return (.unknown, "-")
    }

    public static func readSysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 1 else { return nil }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return nil }
        let bytes = buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: - Read-Only Orphan Package Receipt Audit

    /// Audits third-party `/private/var/db/receipts/*.plist` + `.bom` receipts on disk.
    /// Reports packages as orphaned strictly when every sampled `.bom` file payload and `.app` target
    /// under `InstallPrefixPath` is absent on disk, with `com.apple.*` OS receipts excluded.
    public static func auditOrphanedReceipts(
        in directory: URL = receiptsDirectory,
        cancellation: ScanCancellationToken? = nil,
        fileManager: FileManager = .default,
        samplePayloadLimit: Int = 48
    ) -> (orphans: [OrphanedPackageReceipt], count: Int) {
        guard let entries = DirectoryEntries.list(at: directory, includeHidden: false) else {
            return ([], 0)
        }
        let plistEntries = entries.filter { $0.kind == .regularFile && $0.name.lowercased().hasSuffix(".plist") }
        var orphans: [OrphanedPackageReceipt] = []
        var audited = 0

        for entry in plistEntries {
            if cancellation?.isCancelled == true { break }
            guard let data = try? Data(contentsOf: entry.url),
                  let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
                  let packageID = plist["PackageIdentifier"] as? String,
                  !packageID.isEmpty else {
                continue
            }
            if packageID.hasPrefix("com.apple.") { continue }
            audited += 1

            let bomURL = entry.url.deletingPathExtension().appendingPathExtension("bom")
            guard fileManager.fileExists(atPath: bomURL.path) else { continue }

            let lsbomOutput = runReadOnlyTool("/usr/bin/lsbom", args: ["-s", "-f", bomURL.path], timeoutSeconds: 4, cancellation: cancellation)
            guard !lsbomOutput.isEmpty else { continue }

            let rawPrefix = (plist["InstallPrefixPath"] as? String) ?? ""
            let resolvedPrefix = rawPrefix.isEmpty ? "/" : (rawPrefix.hasPrefix("/") ? rawPrefix : "/" + rawPrefix)
            let samplePaths = extractSampleBomPaths(from: lsbomOutput, prefixPath: resolvedPrefix, limit: samplePayloadLimit)
            guard !samplePaths.isEmpty else { continue }

            let anyPayloadPresent = samplePaths.contains { fileManager.fileExists(atPath: $0) }
            if !anyPayloadPresent {
                let version = (plist["PackageVersion"] as? String) ?? "-"
                orphans.append(
                    OrphanedPackageReceipt(
                        packageIdentifier: packageID,
                        version: version,
                        installPrefixPath: resolvedPrefix,
                        receiptPlistPath: entry.url.path,
                        missingPayloadSample: Array(samplePaths.prefix(5))
                    )
                )
            }
        }

        orphans.sort { $0.packageIdentifier.localizedCaseInsensitiveCompare($1.packageIdentifier) == .orderedAscending }
        return (orphans, audited)
    }

    public static func extractSampleBomPaths(from lsbomOutput: String, prefixPath: String, limit: Int = 48) -> [String] {
        let baseURL = URL(fileURLWithPath: prefixPath.isEmpty ? "/" : prefixPath, isDirectory: true)
        var collected: [String] = []
        var seen: Set<String> = []

        for rawLine in lsbomOutput.components(separatedBy: .newlines) {
            let trimmed = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, trimmed != "." else { continue }
            let relative = trimmed.hasPrefix("./") ? String(trimmed.dropFirst(2)) : trimmed
            guard !relative.isEmpty else { continue }
            let lastComponent = (relative as NSString).lastPathComponent
            if lastComponent.hasPrefix("._") || lastComponent == ".DS_Store" { continue }

            let resolved = baseURL.appendingPathComponent(relative).standardizedFileURL.path
            if seen.insert(resolved).inserted {
                collected.append(resolved)
                if collected.count >= limit { break }
            }
        }
        return collected
    }

    private static func runReadOnlyTool(
        _ launchPath: String,
        args: [String],
        timeoutSeconds: Double = 6,
        cancellation: ScanCancellationToken? = nil
    ) -> String {
        guard FileManager.default.isExecutableFile(atPath: launchPath), cancellation?.isCancelled != true else {
            return ""
        }
        let result = ForensicScanner.runTool(launchPath, args: args, timeoutSeconds: timeoutSeconds, cancellation: cancellation)
        return result.output
    }
}
