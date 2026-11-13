// SPDX-License-Identifier: GPL-3.0-only
import Darwin
import Foundation

public enum PersistenceScope: String, Sendable, Equatable, Codable, CaseIterable {
    case userAgent
    case systemAgent
    case systemDaemon
    case privilegedHelper

    public var labelKey: LKey {
        switch self {
        case .userAgent: return .persistenceScopeUserAgent
        case .systemAgent: return .persistenceScopeSystemAgent
        case .systemDaemon: return .persistenceScopeSystemDaemon
        case .privilegedHelper: return .persistenceScopePrivilegedHelper
        }
    }
}

public struct PersistenceAuditItem: Identifiable, Sendable, Equatable, Codable {
    public let id: String
    public let scope: PersistenceScope
    public let label: String
    public let plistPath: String?
    public let programPath: String?
    public let executableExists: Bool
    public let runAtLoad: Bool
    public let isDisabled: Bool
    public let hasDyldInsertEnv: Bool
    public let dyldInsertValue: String?
    public let isMachO: Bool
    public let teamIdentifier: String
    public let authorities: [String]
    public let hasOfficialAppleChain: Bool
    public let isQuarantined: Bool
    public let verdict: IntegrityVerdict
    public let findings: [ForensicFinding]

    public init(
        id: String,
        scope: PersistenceScope,
        label: String,
        plistPath: String?,
        programPath: String?,
        executableExists: Bool,
        runAtLoad: Bool,
        isDisabled: Bool,
        hasDyldInsertEnv: Bool,
        dyldInsertValue: String?,
        isMachO: Bool,
        teamIdentifier: String,
        authorities: [String],
        hasOfficialAppleChain: Bool,
        isQuarantined: Bool,
        verdict: IntegrityVerdict,
        findings: [ForensicFinding]
    ) {
        self.id = id
        self.scope = scope
        self.label = label
        self.plistPath = plistPath
        self.programPath = programPath
        self.executableExists = executableExists
        self.runAtLoad = runAtLoad
        self.isDisabled = isDisabled
        self.hasDyldInsertEnv = hasDyldInsertEnv
        self.dyldInsertValue = dyldInsertValue
        self.isMachO = isMachO
        self.teamIdentifier = teamIdentifier
        self.authorities = authorities
        self.hasOfficialAppleChain = hasOfficialAppleChain
        self.isQuarantined = isQuarantined
        self.verdict = verdict
        self.findings = findings
    }
}

public struct PersistenceAuditSummary: Sendable, Equatable, Codable {
    public let scannedAt: String
    public let totalCount: Int
    public let cleanCount: Int
    public let warningCount: Int
    public let tamperedCount: Int
    public let missingExecutableCount: Int
    public let wasCancelled: Bool
    public let items: [PersistenceAuditItem]

    public init(scannedAt: String, items: [PersistenceAuditItem], wasCancelled: Bool = false) {
        self.scannedAt = scannedAt
        self.items = items
        self.wasCancelled = wasCancelled
        self.totalCount = items.count
        self.cleanCount = items.filter { $0.verdict == .clean }.count
        self.warningCount = items.filter { $0.verdict == .warning }.count
        self.tamperedCount = items.filter { $0.verdict == .tampered }.count
        self.missingExecutableCount = items.filter { !$0.executableExists }.count
    }

    public func jsonData(prettyPrinted: Bool = true) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = prettyPrinted ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
        return try encoder.encode(self)
    }
}

public struct RunningProcessItem: Identifiable, Sendable, Equatable, Codable {
    public let id: Int32
    public let pid: Int32
    public let name: String
    public let executablePath: String
    public let bundlePath: String?
    public let teamIdentifier: String
    public let authorities: [String]
    public let hasOfficialAppleChain: Bool
    public let isQuarantined: Bool
    public let dyldInsertLibraries: [String]
    public let envReadable: Bool
    public let parentPid: Int32?
    public let parentName: String?
    public let dynamicSignatureMismatch: Bool
    public let unsignedMappedLibraries: [String]
    public let verdict: IntegrityVerdict
    public let findings: [ForensicFinding]

    public var inspectionTargetPath: String {
        bundlePath ?? executablePath
    }

    public init(
        pid: Int32,
        name: String,
        executablePath: String,
        bundlePath: String?,
        teamIdentifier: String,
        authorities: [String],
        hasOfficialAppleChain: Bool,
        isQuarantined: Bool,
        dyldInsertLibraries: [String],
        envReadable: Bool,
        parentPid: Int32? = nil,
        parentName: String? = nil,
        dynamicSignatureMismatch: Bool = false,
        unsignedMappedLibraries: [String] = [],
        verdict: IntegrityVerdict,
        findings: [ForensicFinding]
    ) {
        self.id = pid
        self.pid = pid
        self.name = name
        self.executablePath = executablePath
        self.bundlePath = bundlePath
        self.teamIdentifier = teamIdentifier
        self.authorities = authorities
        self.hasOfficialAppleChain = hasOfficialAppleChain
        self.isQuarantined = isQuarantined
        self.dyldInsertLibraries = dyldInsertLibraries
        self.envReadable = envReadable
        self.parentPid = parentPid
        self.parentName = parentName
        self.dynamicSignatureMismatch = dynamicSignatureMismatch
        self.unsignedMappedLibraries = unsignedMappedLibraries
        self.verdict = verdict
        self.findings = findings
    }

    private enum CodingKeys: String, CodingKey {
        case id, pid, name, executablePath, bundlePath, teamIdentifier, authorities,
             hasOfficialAppleChain, isQuarantined, dyldInsertLibraries, envReadable,
             parentPid, parentName, dynamicSignatureMismatch, unsignedMappedLibraries,
             verdict, findings
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let pid = try container.decode(Int32.self, forKey: .pid)
        self.id = try container.decodeIfPresent(Int32.self, forKey: .id) ?? pid
        self.pid = pid
        self.name = try container.decode(String.self, forKey: .name)
        self.executablePath = try container.decode(String.self, forKey: .executablePath)
        self.bundlePath = try container.decodeIfPresent(String.self, forKey: .bundlePath)
        self.teamIdentifier = try container.decode(String.self, forKey: .teamIdentifier)
        self.authorities = try container.decode([String].self, forKey: .authorities)
        self.hasOfficialAppleChain = try container.decode(Bool.self, forKey: .hasOfficialAppleChain)
        self.isQuarantined = try container.decode(Bool.self, forKey: .isQuarantined)
        self.dyldInsertLibraries = try container.decode([String].self, forKey: .dyldInsertLibraries)
        self.envReadable = try container.decode(Bool.self, forKey: .envReadable)
        self.parentPid = try container.decodeIfPresent(Int32.self, forKey: .parentPid)
        self.parentName = try container.decodeIfPresent(String.self, forKey: .parentName)
        self.dynamicSignatureMismatch = try container.decodeIfPresent(Bool.self, forKey: .dynamicSignatureMismatch) ?? false
        self.unsignedMappedLibraries = try container.decodeIfPresent([String].self, forKey: .unsignedMappedLibraries) ?? []
        self.verdict = try container.decode(IntegrityVerdict.self, forKey: .verdict)
        self.findings = try container.decode([ForensicFinding].self, forKey: .findings)
    }
}

public struct RunningProcessesAuditSummary: Sendable, Equatable, Codable {
    public let scannedAt: String
    public let totalCount: Int
    public let cleanCount: Int
    public let warningCount: Int
    public let tamperedCount: Int
    public let dyldEnvCount: Int
    public let uniqueBinariesCount: Int
    public let wasCancelled: Bool
    public let items: [RunningProcessItem]

    public init(
        scannedAt: String,
        items: [RunningProcessItem],
        uniqueBinariesCount: Int,
        wasCancelled: Bool = false
    ) {
        self.scannedAt = scannedAt
        self.items = items
        self.uniqueBinariesCount = uniqueBinariesCount
        self.wasCancelled = wasCancelled
        self.totalCount = items.count
        self.cleanCount = items.filter { $0.verdict == .clean }.count
        self.warningCount = items.filter { $0.verdict == .warning }.count
        self.tamperedCount = items.filter { $0.verdict == .tampered }.count
        self.dyldEnvCount = items.filter { !$0.dyldInsertLibraries.isEmpty }.count
    }

    public func jsonData(prettyPrinted: Bool = true) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = prettyPrinted ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
        return try encoder.encode(self)
    }
}

public enum SystemAudit {
    private struct BinaryForensicBaseline: Sendable {
        let teamIdentifier: String
        let authorities: [String]
        let hasOfficialAppleChain: Bool
        let isAdhoc: Bool
        let isUnsigned: Bool
        let isQuarantined: Bool
        let isMachO: Bool
        let verdict: IntegrityVerdict
        let findings: [ForensicFinding]
    }

    // MARK: - Persistence (LaunchAgents, LaunchDaemons, PrivilegedHelperTools)

    public static func defaultPersistenceDirectories() -> [(scope: PersistenceScope, url: URL)] {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return [
            (.userAgent, home.appendingPathComponent("Library/LaunchAgents", isDirectory: true)),
            (.systemAgent, URL(fileURLWithPath: "/Library/LaunchAgents", isDirectory: true)),
            (.systemDaemon, URL(fileURLWithPath: "/Library/LaunchDaemons", isDirectory: true)),
            (.privilegedHelper, URL(fileURLWithPath: "/Library/PrivilegedHelperTools", isDirectory: true)),
        ]
    }

    public static func auditPersistence(
        directories: [(scope: PersistenceScope, url: URL)]? = nil,
        options: ScanOptions = ScanOptions(),
        cancellation: ScanCancellationToken? = nil,
        onProgress: (@Sendable (_ index: Int, _ total: Int, _ label: String) -> Void)? = nil
    ) -> PersistenceAuditSummary {
        let fm = FileManager.default
        let dirs = directories ?? defaultPersistenceDirectories()

        var entries: [(scope: PersistenceScope, url: URL)] = []
        for (scope, dirURL) in dirs {
            guard let contents = try? fm.contentsOfDirectory(
                at: dirURL,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) else { continue }
            for fileURL in contents.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
                if scope == .privilegedHelper {
                    var isDir: ObjCBool = false
                    guard fm.fileExists(atPath: fileURL.path, isDirectory: &isDir), !isDir.boolValue else { continue }
                    entries.append((scope, fileURL))
                } else if fileURL.pathExtension.lowercased() == "plist" {
                    entries.append((scope, fileURL))
                }
            }
        }

        var items: [PersistenceAuditItem] = []
        items.reserveCapacity(entries.count)
        var binaryCache: [String: BinaryForensicBaseline] = [:]

        for (idx, entry) in entries.enumerated() {
            if cancellation?.isCancelled == true { break }
            let name = entry.url.lastPathComponent
            onProgress?(idx + 1, entries.count, name)

            let item: PersistenceAuditItem
            if entry.scope == .privilegedHelper {
                item = auditPrivilegedHelper(at: entry.url, options: options, cancellation: cancellation, cache: &binaryCache)
            } else {
                item = auditLaunchPlist(at: entry.url, scope: entry.scope, options: options, cancellation: cancellation, cache: &binaryCache)
            }
            items.append(item)
        }

        let sorted = items.sorted { lhs, rhs in
            if verdictRank(lhs.verdict) != verdictRank(rhs.verdict) {
                return verdictRank(lhs.verdict) > verdictRank(rhs.verdict)
            }
            if lhs.executableExists != rhs.executableExists {
                return !lhs.executableExists
            }
            return lhs.label.localizedCaseInsensitiveCompare(rhs.label) == .orderedAscending
        }

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return PersistenceAuditSummary(
            scannedAt: formatter.string(from: Date()),
            items: sorted,
            wasCancelled: cancellation?.isCancelled == true
        )
    }

    private static func auditLaunchPlist(
        at plistURL: URL,
        scope: PersistenceScope,
        options: ScanOptions,
        cancellation: ScanCancellationToken?,
        cache: inout [String: BinaryForensicBaseline]
    ) -> PersistenceAuditItem {
        let fm = FileManager.default
        let fallbackLabel = plistURL.deletingPathExtension().lastPathComponent
        var label = fallbackLabel
        var programPath: String?
        var runAtLoad = false
        var isDisabled = false
        var dyldInsertValue: String?

        if let data = try? Data(contentsOf: plistURL),
           let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] {
            if let rawLabel = plist["Label"] as? String, !rawLabel.isEmpty {
                label = rawLabel
            }
            if let program = plist["Program"] as? String, !program.isEmpty {
                programPath = program
            } else if let args = plist["ProgramArguments"] as? [String], let first = args.first, !first.isEmpty {
                programPath = first
            }
            runAtLoad = (plist["RunAtLoad"] as? Bool) ?? false
            isDisabled = (plist["Disabled"] as? Bool) ?? false
            if let env = plist["EnvironmentVariables"] as? [String: Any],
               let dyld = env["DYLD_INSERT_LIBRARIES"] as? String,
               !dyld.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                dyldInsertValue = dyld
            }
        }

        let resolvedProgram = programPath.map { expandUserPath($0) }
        let exists: Bool
        if let resolvedProgram {
            exists = fm.fileExists(atPath: resolvedProgram)
        } else {
            exists = false
        }

        var baseline: BinaryForensicBaseline?
        if let resolvedProgram, exists {
            baseline = inspectExecutableCached(atPath: resolvedProgram, options: options, cancellation: cancellation, cache: &cache)
        }

        var findings: [ForensicFinding] = baseline?.findings ?? []
        let plistQuarantined = ForensicScanner.hasQuarantineAttribute(at: plistURL.path)
        let isQuarantined = (baseline?.isQuarantined ?? false) || plistQuarantined

        if let dyldInsertValue {
            findings.insert(
                ForensicFinding(
                    severity: .critical,
                    titleKey: .persistencePlistDyldEnv,
                    descKey: .runningDyldEnvDetected,
                    detailSuffix: dyldInsertValue
                ),
                at: 0
            )
        }

        if let resolvedProgram, !exists {
            findings.append(
                ForensicFinding(
                    severity: .warning,
                    titleKey: .persistenceExecutableMissing,
                    descKey: .persistenceExecutableMissing,
                    detailSuffix: resolvedProgram
                )
            )
        }

        if plistQuarantined && !(baseline?.isQuarantined ?? false) {
            findings.append(
                ForensicFinding(
                    severity: .warning,
                    titleKey: .fieldQuarantine,
                    descKey: .valueQuarantined,
                    detailSuffix: " (\(plistURL.lastPathComponent))"
                )
            )
        }

        let deceptiveNames = OpenSafety.collectDeceptiveNames(
            in: [label, plistURL.lastPathComponent] + (resolvedProgram.map { [URL(fileURLWithPath: $0).lastPathComponent] } ?? [])
        )
        if !deceptiveNames.isEmpty {
            findings.append(
                ForensicFinding(
                    severity: .warning,
                    titleKey: .findingNameSpoofingTitle,
                    descKey: .findingNameSpoofingDesc,
                    detailSuffix: deceptiveNames.joined(separator: ", ")
                )
            )
        }

        let verdict: IntegrityVerdict
        if dyldInsertValue != nil || baseline?.verdict == .tampered || findings.contains(where: { $0.severity == .critical }) {
            verdict = .tampered
        } else if !exists || isQuarantined || !deceptiveNames.isEmpty || baseline?.verdict == .warning || findings.contains(where: { $0.severity == .warning }) {
            verdict = .warning
        } else {
            verdict = .clean
        }

        return PersistenceAuditItem(
            id: plistURL.path,
            scope: scope,
            label: label,
            plistPath: plistURL.path,
            programPath: resolvedProgram,
            executableExists: exists,
            runAtLoad: runAtLoad,
            isDisabled: isDisabled,
            hasDyldInsertEnv: dyldInsertValue != nil,
            dyldInsertValue: dyldInsertValue,
            isMachO: baseline?.isMachO ?? false,
            teamIdentifier: baseline?.teamIdentifier ?? "not set",
            authorities: baseline?.authorities ?? [],
            hasOfficialAppleChain: baseline?.hasOfficialAppleChain ?? false,
            isQuarantined: isQuarantined,
            verdict: verdict,
            findings: findings
        )
    }

    private static func auditPrivilegedHelper(
        at helperURL: URL,
        options: ScanOptions,
        cancellation: ScanCancellationToken?,
        cache: inout [String: BinaryForensicBaseline]
    ) -> PersistenceAuditItem {
        let baseline = inspectExecutableCached(atPath: helperURL.path, options: options, cancellation: cancellation, cache: &cache)
        var findings = baseline.findings
        let deceptiveNames = OpenSafety.collectDeceptiveNames(in: [helperURL.lastPathComponent])
        if !deceptiveNames.isEmpty {
            findings.append(
                ForensicFinding(
                    severity: .warning,
                    titleKey: .findingNameSpoofingTitle,
                    descKey: .findingNameSpoofingDesc,
                    detailSuffix: deceptiveNames.joined(separator: ", ")
                )
            )
        }
        let verdict: IntegrityVerdict
        if baseline.verdict == .tampered {
            verdict = .tampered
        } else if baseline.isQuarantined || baseline.isUnsigned || !deceptiveNames.isEmpty || baseline.verdict == .warning {
            if baseline.isUnsigned {
                findings.append(
                    ForensicFinding(
                        severity: .warning,
                        titleKey: .findingUnsignedBundledLibTitle,
                        descKey: .findingUnsignedBundledLibDesc,
                        detailSuffix: helperURL.lastPathComponent
                    )
                )
            }
            verdict = .warning
        } else {
            verdict = .clean
        }

        return PersistenceAuditItem(
            id: helperURL.path,
            scope: .privilegedHelper,
            label: helperURL.lastPathComponent,
            plistPath: nil,
            programPath: helperURL.path,
            executableExists: true,
            runAtLoad: true,
            isDisabled: false,
            hasDyldInsertEnv: false,
            dyldInsertValue: nil,
            isMachO: baseline.isMachO,
            teamIdentifier: baseline.teamIdentifier,
            authorities: baseline.authorities,
            hasOfficialAppleChain: baseline.hasOfficialAppleChain,
            isQuarantined: baseline.isQuarantined,
            verdict: verdict,
            findings: findings
        )
    }

    // MARK: - Running Processes (Darwin proc_listallpids + KERN_PROCARGS2)

    public static func auditRunningProcesses(
        options: ScanOptions = ScanOptions(),
        cancellation: ScanCancellationToken? = nil,
        maxConcurrentExecScans: Int = 4,
        onProgress: (@Sendable (_ index: Int, _ total: Int, _ processName: String) -> Void)? = nil
    ) -> RunningProcessesAuditSummary {
        let rawProcesses = enumerateProcesses()
        var uniquePaths: [String] = []
        var seenPaths: Set<String> = []

        for proc in rawProcesses where !proc.executablePath.isEmpty {
            let std = URL(fileURLWithPath: proc.executablePath).standardizedFileURL.path
            if !seenPaths.contains(std) {
                seenPaths.insert(std)
                uniquePaths.append(std)
            }
        }

        final class ExecCacheBox: @unchecked Sendable {
            private let lock = NSLock()
            private var map: [String: BinaryForensicBaseline] = [:]
            private var cursor = 0

            func nextPath(from list: [String]) -> (index: Int, path: String)? {
                lock.withLock {
                    guard cursor < list.count else { return nil }
                    let idx = cursor
                    cursor += 1
                    return (idx, list[idx])
                }
            }

            func store(_ baseline: BinaryForensicBaseline, for path: String) {
                lock.withLock { map[path] = baseline }
            }

            func lookup(_ path: String) -> BinaryForensicBaseline? {
                lock.withLock { map[path] }
            }
        }

        let snapshotUniquePaths = uniquePaths
        let cacheBox = ExecCacheBox()
        let workerCount = max(1, min(maxConcurrentExecScans, snapshotUniquePaths.count))
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "com.babadogantech.verificator.process-audit", attributes: .concurrent)

        for _ in 0..<workerCount {
            group.enter()
            queue.async {
                defer { group.leave() }
                while let next = cacheBox.nextPath(from: snapshotUniquePaths) {
                    if cancellation?.isCancelled == true { break }
                    let execName = URL(fileURLWithPath: next.path).lastPathComponent
                    onProgress?(next.index + 1, snapshotUniquePaths.count, execName)
                    let baseline = inspectProcessExecutable(atPath: next.path, options: options, cancellation: cancellation)
                    cacheBox.store(baseline, for: next.path)
                }
            }
        }
        group.wait()

        var items: [RunningProcessItem] = []
        items.reserveCapacity(rawProcesses.count)

        for proc in rawProcesses {
            if cancellation?.isCancelled == true { break }
            let stdPath = URL(fileURLWithPath: proc.executablePath).standardizedFileURL.path
            let baseline = cacheBox.lookup(stdPath) ?? BinaryForensicBaseline(
                teamIdentifier: "not set",
                authorities: [],
                hasOfficialAppleChain: false,
                isAdhoc: false,
                isUnsigned: true,
                isQuarantined: false,
                isMachO: false,
                verdict: .warning,
                findings: []
            )
            let enclosingApp = enclosingAppBundlePath(forExecutablePath: proc.executablePath)
            let parentInfo = LiveProcessInspector.parentProcess(of: proc.pid)
            let liveVerification = LiveProcessInspector.verifyLiveProcess(
                pid: proc.pid,
                executablePath: proc.executablePath,
                parentHasOfficialChain: baseline.hasOfficialAppleChain,
                isParentAdhoc: baseline.isAdhoc
            )

            var findings = baseline.findings
            if !proc.dyldInsertLibraries.isEmpty {
                findings.insert(
                    ForensicFinding(
                        severity: .critical,
                        titleKey: .persistencePlistDyldEnv,
                        descKey: .runningDyldEnvDetected,
                        detailSuffix: proc.dyldInsertLibraries.joined(separator: ":")
                    ),
                    at: 0
                )
            }
            if liveVerification.hasDynamicSignatureMismatch {
                findings.insert(
                    ForensicFinding(
                        severity: .critical,
                        titleKey: .runningDynamicSigMismatchTitle,
                        descKey: .runningDynamicSigMismatchDesc
                    ),
                    at: 0
                )
            }
            if !liveVerification.unsignedMappedLibraries.isEmpty {
                findings.append(
                    ForensicFinding(
                        severity: .warning,
                        titleKey: .runningUnsignedMappedLibTitle,
                        descKey: .runningUnsignedMappedLibDesc,
                        detailSuffix: liveVerification.unsignedMappedLibraries.joined(separator: ", ")
                    )
                )
            }

            let deceptiveNames = OpenSafety.collectDeceptiveNames(
                in: [proc.name, URL(fileURLWithPath: proc.executablePath).lastPathComponent]
            )
            if !deceptiveNames.isEmpty {
                findings.append(
                    ForensicFinding(
                        severity: .warning,
                        titleKey: .findingNameSpoofingTitle,
                        descKey: .findingNameSpoofingDesc,
                        detailSuffix: deceptiveNames.joined(separator: ", ")
                    )
                )
            }

            let verdict: IntegrityVerdict
            if !proc.dyldInsertLibraries.isEmpty || baseline.verdict == .tampered || liveVerification.hasDynamicSignatureMismatch {
                verdict = .tampered
            } else if baseline.isQuarantined || !deceptiveNames.isEmpty || baseline.verdict == .warning || !liveVerification.unsignedMappedLibraries.isEmpty {
                verdict = .warning
            } else {
                verdict = .clean
            }

            items.append(
                RunningProcessItem(
                    pid: proc.pid,
                    name: proc.name,
                    executablePath: proc.executablePath,
                    bundlePath: enclosingApp,
                    teamIdentifier: baseline.teamIdentifier,
                    authorities: baseline.authorities,
                    hasOfficialAppleChain: baseline.hasOfficialAppleChain,
                    isQuarantined: baseline.isQuarantined,
                    dyldInsertLibraries: proc.dyldInsertLibraries,
                    envReadable: proc.envReadable,
                    parentPid: parentInfo?.pid,
                    parentName: parentInfo?.name,
                    dynamicSignatureMismatch: liveVerification.hasDynamicSignatureMismatch,
                    unsignedMappedLibraries: liveVerification.unsignedMappedLibraries,
                    verdict: verdict,
                    findings: findings
                )
            )
        }

        let sorted = items.sorted { lhs, rhs in
            if verdictRank(lhs.verdict) != verdictRank(rhs.verdict) {
                return verdictRank(lhs.verdict) > verdictRank(rhs.verdict)
            }
            if lhs.dyldInsertLibraries.isEmpty != rhs.dyldInsertLibraries.isEmpty {
                return !lhs.dyldInsertLibraries.isEmpty
            }
            return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
        }

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return RunningProcessesAuditSummary(
            scannedAt: formatter.string(from: Date()),
            items: sorted,
            uniqueBinariesCount: uniquePaths.count,
            wasCancelled: cancellation?.isCancelled == true
        )
    }

    private struct RawProcessEntry {
        let pid: Int32
        let name: String
        let executablePath: String
        let dyldInsertLibraries: [String]
        let envReadable: Bool
    }

    private static func enumerateProcesses() -> [RawProcessEntry] {
        let byteCount = proc_listallpids(nil, 0)
        guard byteCount > 0 else { return [] }
        let capacity = Int(byteCount) / MemoryLayout<pid_t>.stride + 64
        var pids = [pid_t](repeating: 0, count: capacity)
        let actualBytes = pids.withUnsafeMutableBytes { buf in
            proc_listallpids(buf.baseAddress, Int32(buf.count))
        }
        guard actualBytes > 0 else { return [] }
        let count = Int(actualBytes) / MemoryLayout<pid_t>.stride

        var result: [RawProcessEntry] = []
        result.reserveCapacity(count)

        var pathBuffer = [CChar](repeating: 0, count: 4096)
        for idx in 0..<count {
            let pid = pids[idx]
            guard pid > 0 else { continue }
            let pathLen = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
            guard pathLen > 0 else { continue }
            let path = pathBuffer.withUnsafeBufferPointer { ptr -> String in
                let rawBytes = UnsafeRawBufferPointer(start: ptr.baseAddress, count: Int(pathLen))
                return String(decoding: rawBytes, as: UTF8.self)
            }
            guard !path.isEmpty else { continue }
            let procName = URL(fileURLWithPath: path).lastPathComponent
            let envInfo = readDyldInsertEnv(for: pid)
            result.append(
                RawProcessEntry(
                    pid: pid,
                    name: procName,
                    executablePath: path,
                    dyldInsertLibraries: envInfo.libraries,
                    envReadable: envInfo.readable
                )
            )
        }
        return result
    }

    internal static func readDyldInsertEnv(for pid: Int32) -> (libraries: [String], readable: Bool) {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else {
            return ([], false)
        }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else {
            return ([], false)
        }

        let data = Data(buffer.prefix(size))
        let argc = data.withUnsafeBytes { raw -> Int32 in
            raw.loadUnaligned(as: Int32.self)
        }
        guard argc >= 0 && argc < 8192 else {
            return ([], false)
        }

        var cursor = MemoryLayout<Int32>.size

        // Skip executable path
        while cursor < data.count && data[cursor] != 0 { cursor += 1 }
        // Skip trailing NUL padding between exec_path and argv[0]
        while cursor < data.count && data[cursor] == 0 { cursor += 1 }

        // Skip argv[0..<argc]
        for _ in 0..<argc {
            while cursor < data.count && data[cursor] != 0 { cursor += 1 }
            if cursor < data.count { cursor += 1 }
        }

        var libraries: [String] = []
        while cursor < data.count {
            let start = cursor
            while cursor < data.count && data[cursor] != 0 { cursor += 1 }
            if cursor > start {
                let entry = String(decoding: data[start..<cursor], as: UTF8.self)
                if let range = entry.range(of: "DYLD_INSERT_LIBRARIES=") {
                    let rawVal = String(entry[range.upperBound...])
                    let parts = rawVal
                        .split(separator: ":")
                        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                        .filter { !$0.isEmpty }
                    libraries.append(contentsOf: parts)
                }
            }
            if cursor < data.count { cursor += 1 }
        }
        return (libraries, true)
    }

    // MARK: - Shared Forensic Helpers (0% FP Calibration)

    private static func inspectExecutableCached(
        atPath path: String,
        options: ScanOptions,
        cancellation: ScanCancellationToken?,
        cache: inout [String: BinaryForensicBaseline]
    ) -> BinaryForensicBaseline {
        let std = URL(fileURLWithPath: path).standardizedFileURL.path
        if let cached = cache[std] {
            return cached
        }
        let baseline = inspectProcessExecutable(atPath: std, options: options, cancellation: cancellation)
        cache[std] = baseline
        return baseline
    }

    private static func inspectProcessExecutable(
        atPath path: String,
        options: ScanOptions,
        cancellation: ScanCancellationToken?
    ) -> BinaryForensicBaseline {
        let url = URL(fileURLWithPath: path)
        let isMachO = ForensicScanner.isMachOBinary(at: url)
        let bundlePath = enclosingAppBundlePath(forExecutablePath: path)
        let quarantineTarget = bundlePath ?? path
        let isQuarantined = ForensicScanner.hasQuarantineAttribute(at: quarantineTarget, executablePath: path)

        guard isMachO else {
            let findings: [ForensicFinding] = isQuarantined
                ? [ForensicFinding(severity: .warning, titleKey: .fieldQuarantine, descKey: .valueQuarantined)]
                : []
            return BinaryForensicBaseline(
                teamIdentifier: "not set",
                authorities: [],
                hasOfficialAppleChain: false,
                isAdhoc: false,
                isUnsigned: false,
                isQuarantined: isQuarantined,
                isMachO: false,
                verdict: isQuarantined ? .warning : .clean,
                findings: findings
            )
        }

        let sigTarget = bundlePath ?? path
        let (sig, _) = ForensicScanner.parseSignature(for: sigTarget, cancellation: cancellation)

        var findings: [ForensicFinding] = []
        var verdict: IntegrityVerdict = .clean

        if !sig.authorities.isEmpty && !sig.hasOfficialAppleChain {
            findings.append(
                ForensicFinding(
                    severity: .critical,
                    titleKey: .findingUnofficialAuthorityTitle,
                    descKey: .findingUnofficialAuthorityDesc,
                    detailSuffix: sig.authorities.joined(separator: " → ")
                )
            )
            verdict = .tampered
        } else if !sig.hasOfficialAppleChain {
            // Only inspect codesign verify / hook symbols when not protected by official Apple root chain.
            let verify = ForensicScanner.runTool("/usr/bin/codesign", args: ["--verify", "--no-strict", path], cancellation: cancellation)
            if !sig.isUnsigned && verify.exitCode != 0 && !verify.output.isEmpty {
                findings.append(
                    ForensicFinding(
                        severity: .critical,
                        titleKey: .findingVerifyFailedTitle,
                        descKey: .findingVerifyFailedDesc,
                        detailSuffix: verify.output.trimmingCharacters(in: .whitespacesAndNewlines)
                    )
                )
                verdict = .tampered
            } else {
                let analysis = ForensicScanner.analyzeMachOHooks(
                    binaryPath: path,
                    libraryName: url.lastPathComponent,
                    isDylib: false,
                    parentHasOfficialChain: false,
                    extractTargetStrings: options.extractTargetStrings,
                    cancellation: cancellation
                )
                if analysis.isInjectedCrack {
                    verdict = .tampered
                    if analysis.categories.contains(where: { $0.categoryKey == .symbolCatMemory }) {
                        findings.append(ForensicFinding(severity: .critical, titleKey: .findingMachPatchingTitle, descKey: .findingMachPatchingDesc))
                    }
                    if analysis.categories.contains(where: { $0.categoryKey == .symbolCatDyld }) {
                        findings.append(ForensicFinding(severity: .critical, titleKey: .findingDyldSlideTitle, descKey: .findingDyldSlideDesc))
                    }
                }
            }
        }

        if isQuarantined {
            findings.append(
                ForensicFinding(
                    severity: .warning,
                    titleKey: .fieldQuarantine,
                    descKey: .valueQuarantined
                )
            )
            if verdict == .clean {
                verdict = .warning
            }
        }

        return BinaryForensicBaseline(
            teamIdentifier: sig.teamId,
            authorities: sig.authorities,
            hasOfficialAppleChain: sig.hasOfficialAppleChain,
            isAdhoc: sig.isAdhoc,
            isUnsigned: sig.isUnsigned,
            isQuarantined: isQuarantined,
            isMachO: true,
            verdict: verdict,
            findings: findings
        )
    }

    public static func enclosingAppBundlePath(forExecutablePath path: String) -> String? {
        let components = URL(fileURLWithPath: path).standardizedFileURL.pathComponents
        for idx in stride(from: components.count - 1, through: 0, by: -1) {
            if components[idx].lowercased().hasSuffix(".app") {
                return NSString.path(withComponents: Array(components.prefix(idx + 1)))
            }
        }
        return nil
    }

    private static func expandUserPath(_ path: String) -> String {
        if path.hasPrefix("~/") {
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            return home + String(path.dropFirst(1))
        }
        return path
    }

    private static func verdictRank(_ verdict: IntegrityVerdict) -> Int {
        switch verdict {
        case .clean: return 0
        case .warning: return 1
        case .tampered: return 2
        }
    }
}
