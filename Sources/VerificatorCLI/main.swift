// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import VerificatorCore

private func printUsage() {
    let text = """
    verificator-cli \(AppInfo.version) (\(AppInfo.build)) — macOS 4-layer read-only forensic auditor

    USAGE:
      verificator-cli <path-to-target-or-folder> [options]
      verificator-cli --diff <baseline> <target> [options]
      verificator-cli --persistence [options]
      verificator-cli --running [options]
      verificator-cli --posture [options]

    SUPPORTED TARGETS:
      .app, .pkg, .mpkg, .dmg, .framework, .bundle, .appex, .xpc, .kext, .plugin, .dylib, .so, Mach-O binaries
      For --diff, <baseline> and <target> can be any supported target above or saved Verificator .json reports.

    OPTIONS:
      --batch                 Scan every .app, .dmg, .pkg, and .mpkg item inside <path>
      --diff <old> <new>      Compare two bundles, binaries, or saved .json audit reports
      --persistence           Audit LaunchAgents, LaunchDaemons, and PrivilegedHelperTools
      --running               Audit active macOS processes, DYLD_INSERT_LIBRARIES, and kernel sockets
      --posture               Audit host macOS security posture (SIP, SSV, Gatekeeper, FileVault, SMART, orphan pkg receipts)
      --expected-checksum <v> Verify target SHA-256/SHA-512 against hex string, checksum line, or SHA256SUMS file
      --redact                Mask home directories, personal paths, and usernames in output
      --json                  Output structured JSON report
      --spctl                 Run Gatekeeper policy check (/usr/sbin/spctl --assess)
      --revocation            Run online OCSP certificate / notarization revocation check
      --no-firewall           Skip per-target Application Firewall rule lookup
      --lang <code>           Output language (tr, en, ro; default: en)
      --no-deep               Skip per-framework signature verification
      --no-strings            Skip target string extraction from suspicious dylibs
      --version               Print version information
      -h, --help              Show this help message

    EXIT CODES:
      0  All audited items are CLEAN (or diff has zero regressions/warnings)
      1  One or more items evaluated as TAMPERED (or diff has critical regressions)
      2  WARNING encountered (or missing persistence target / invalid usage)
    """
    print(text)
}

private let stderrLock = NSLock()

private func writeStderr(_ line: String) {
    stderrLock.withLock {
        FileHandle.standardError.write(Data((line + "\n").utf8))
    }
}

private func redactTextIfNeeded(_ text: String, masker: DiagnosticMasker?) -> String {
    guard let masker else { return text }
    return masker.redact(text: text)
}

private func printHumanReport(
    _ rawReport: BundleAuditReport,
    strings: StringTable,
    lang: String,
    masker: DiagnosticMasker?,
    expectedChecksumArg: String?
) -> Int32? {
    let report = masker.map { rawReport.redacted(using: $0) } ?? rawReport
    let archText = report.architectures.isEmpty ? "-" : report.architectures.joined(separator: ", ")
    let qText = report.isQuarantined ? "ACTIVE" : "NONE"
    let kindText = strings.string(report.targetKind.labelKey, language: lang)
    print("Target Kind:   \(kindText)")
    print("Target:        \(OpenSafety.visibleName(report.bundleName)) (\(report.bundleId)) v\(report.shortVersion) (\(report.buildVersion))")
    print("Path:          \(report.bundlePath)")
    print("Executable:    \(OpenSafety.visibleName(report.executableRelativePath)) [\(archText)]")
    print("SHA-256:       \(report.executableSHA256)")
    print("SHA-512:       \(report.executableSHA512)")
    print("Verdict:       \(report.verdict.rawValue.uppercased())")
    print("Team ID:       \(report.teamIdentifier)")
    print("Authority:     \(report.authorities.isEmpty ? "-" : report.authorities.joined(separator: " -> "))")
    if report.isDevelopmentSigned {
        print("Cert Profile:  Apple Development Certificate (Informational)")
    }
    print("Quarantine:    \(qText)")
    print("Hardened:      \(report.hasHardenedRuntime ? "Yes" : "No") | Notarized: \(report.isNotarized ? "Yes" : "No")")
    if !report.deceptiveNames.isEmpty {
        print("Deceptive Names: \(report.deceptiveNames.joined(separator: ", "))")
    }
    if let fw = report.firewallAppState {
        let fwText = switch fw.ruleStatus {
        case .permitted: fw.blockAllIncomingActive ? "Blocked (Block All Incoming Active)" : "Permitted"
        case .blocked: "BLOCKED"
        case .unknown: "Unknown"
        }
        print("Firewall:      \(fwText)")
        if fw.isBlocked {
            print("Unblock Cmd:   \(fw.unblockCommand)")
        }
    }
    if let vol = report.volumeEncryption {
        let encLabel = vol.isEncrypted == true ? "Encrypted" : (vol.isEncrypted == false ? "Unencrypted" : "Unknown")
        let extra = vol.needsUnencryptedRemovableWarning ? " [UNENCRYPTED REMOVABLE/EXTERNAL VOLUME]" : ""
        print("Volume:        \(vol.volumeName) (\(vol.format), \(encLabel))\(extra)")
    }
    if let policy = report.internetAccessPolicy {
        print("Access Policy: \(policy.connections.count) connection(s), \(policy.services.count) service(s) — \(policy.applicationDescription)")
    }
    if !report.lcRpaths.isEmpty {
        print("LC_RPATH:      \(report.lcRpaths.joined(separator: ", "))")
    }
    if !report.entitlements.isEmpty {
        print("Entitlements:  \(report.entitlements.joined(separator: ", "))")
    }
    if !report.entitlementRisks.isEmpty {
        print("Entitlement Risks (Informational):")
        for risk in report.entitlementRisks {
            let level = strings.string(risk.level.labelKey, language: lang)
            let title = strings.string(risk.titleKey, language: lang)
            print("  - [\(level)] \(title) (\(risk.entitlementKey))")
        }
    }
    if let spctl = report.spctlAssessment {
        print("Gatekeeper:    \(spctl)")
    }
    if let rev = report.revocationStatus {
        print("Revocation:    \(strings.string(rev.labelKey, language: lang))")
    }
    var checksumExitCode: Int32?
    if let expectedChecksumArg {
        let targetFileName = URL(fileURLWithPath: rawReport.bundlePath).lastPathComponent
        let parsed = ChecksumInput.parseValueOrFile(expectedChecksumArg, fileName: targetFileName)
        switch parsed {
        case .parsed(let expected):
            let verification = expected.verify(actualSHA256: rawReport.executableSHA256, actualSHA512: rawReport.executableSHA512)
            switch verification {
            case .matched(let exp, _):
                print("Checksum:      MATCH (\(exp.algorithm.rawValue))")
            case .mismatch(let exp, let actual):
                print("Checksum:      MISMATCH (\(exp.algorithm.rawValue)) expected=\(exp.hex) actual=\(actual)")
                checksumExitCode = 1
            case .unavailable(let exp):
                print("Checksum:      UNAVAILABLE (\(exp.algorithm.rawValue))")
                checksumExitCode = 2
            }
        case .weakAlgorithm(let algo):
            print("Checksum:      REJECTED weak algorithm (\(algo)) — supply SHA-256 or SHA-512")
            checksumExitCode = 2
        case .notFoundForFile(let name):
            print("Checksum:      No matching digest entry for '\(name)'")
            checksumExitCode = 2
        case .empty, .unrecognized:
            print("Checksum:      Unrecognized expected checksum input")
            checksumExitCode = 2
        }
    }
    print("Duration:      \(report.scanDurationMs) ms")
    print("Findings:")
    for finding in report.findings {
        let title = strings.string(finding.titleKey, language: lang)
        let desc = strings.string(finding.descKey, language: lang)
        print("  - [\(finding.severity.rawValue.uppercased())] \(title): \(desc)\(finding.detailSuffix)")
    }
    return checksumExitCode
}

private enum CLIMode {
    case singleOrBatch
    case diff(baselinePath: String, targetPath: String)
    case persistence
    case runningProcesses
    case posture
}

let args = Array(CommandLine.arguments.dropFirst())
var outputJSON = false
var forceBatch = false
var options = ScanOptions()
var selectedLang = "en"
var targetPath: String?
var expectedChecksumArg: String?
var redactOutput = false
private var mode: CLIMode = .singleOrBatch

var index = 0
while index < args.count {
    let arg = args[index]
    switch arg {
    case "-h", "--help":
        printUsage()
        exit(0)
    case "--version":
        print("\(AppInfo.version) (\(AppInfo.build))")
        exit(0)
    case "--json":
        outputJSON = true
    case "--batch":
        forceBatch = true
    case "--redact":
        redactOutput = true
    case "--persistence":
        mode = .persistence
    case "--running":
        mode = .runningProcesses
    case "--posture":
        mode = .posture
    case "--diff":
        guard index + 2 < args.count else {
            writeStderr("--diff requires <baseline> and <target> paths")
            exit(2)
        }
        mode = .diff(baselinePath: args[index + 1], targetPath: args[index + 2])
        index += 2
    case "--expected-checksum":
        index += 1
        guard index < args.count else {
            writeStderr("Missing value for --expected-checksum")
            exit(2)
        }
        expectedChecksumArg = args[index]
    case "--spctl":
        options.includeGatekeeperAssessment = true
    case "--revocation":
        options.checkCertificateRevocation = true
    case "--no-firewall":
        options.checkApplicationFirewall = false
    case "--no-deep":
        options.deepFrameworkSignatureCheck = false
    case "--no-strings":
        options.extractTargetStrings = false
    case "--lang":
        index += 1
        guard index < args.count else {
            writeStderr("Missing value for --lang (expected tr, en, or ro)")
            exit(2)
        }
        let code = args[index].lowercased()
        guard AppLanguage.supportedCodes.contains(code) else {
            writeStderr("Unsupported language '\(args[index])' (expected tr, en, or ro)")
            exit(2)
        }
        selectedLang = code
    default:
        if arg.hasPrefix("--expected-checksum=") {
            expectedChecksumArg = String(arg.dropFirst("--expected-checksum=".count))
        } else if arg.hasPrefix("--lang=") {
            let code = String(arg.dropFirst("--lang=".count)).lowercased()
            guard AppLanguage.supportedCodes.contains(code) else {
                writeStderr("Unsupported language '\(code)' (expected tr, en, or ro)")
                exit(2)
            }
            selectedLang = code
        } else if arg.hasPrefix("-") {
            writeStderr("Unknown option: \(arg)")
            exit(2)
        } else {
            targetPath = arg
        }
    }
    index += 1
}

options.policyLanguages = [selectedLang, "en"]
let activeMasker: DiagnosticMasker? = redactOutput ? DiagnosticMasker() : nil
let strings = StringTable(bundle: .main)

switch mode {
case let .diff(baselinePath, secondPath):
    let baseURL = URL(fileURLWithPath: NSString(string: baselinePath).expandingTildeInPath).standardizedFileURL
    let newURL = URL(fileURLWithPath: NSString(string: secondPath).expandingTildeInPath).standardizedFileURL
    for url in [baseURL, newURL] where !FileManager.default.fileExists(atPath: url.path) {
        writeStderr("Path not found: \(url.path)")
        exit(2)
    }
    do {
        var baseEndpoint = try AuditDiff.loadOrAudit(url: baseURL, options: options)
        var newEndpoint = try AuditDiff.loadOrAudit(url: newURL, options: options)
        if let activeMasker {
            baseEndpoint = AuditDiffEndpoint(
                sourceDescription: activeMasker.maskPath(baseEndpoint.sourceDescription),
                isFromSavedJSON: baseEndpoint.isFromSavedJSON,
                report: baseEndpoint.report.redacted(using: activeMasker)
            )
            newEndpoint = AuditDiffEndpoint(
                sourceDescription: activeMasker.maskPath(newEndpoint.sourceDescription),
                isFromSavedJSON: newEndpoint.isFromSavedJSON,
                report: newEndpoint.report.redacted(using: activeMasker)
            )
        }
        let diff = AuditDiff.compare(baseline: baseEndpoint, target: newEndpoint)
        if outputJSON {
            let data = try diff.jsonData(prettyPrinted: true)
            print(String(decoding: data, as: UTF8.self))
        } else {
            print(redactTextIfNeeded(diff.markdown(with: strings, language: selectedLang), masker: activeMasker))
        }
        if diff.regressionCount > 0 { exit(1) }
        if diff.warningCount > 0 { exit(2) }
        exit(0)
    } catch {
        writeStderr("Diff error: \(error.localizedDescription)")
        exit(2)
    }

case .persistence:
    let emitJSON = outputJSON
    let summary = SystemAudit.auditPersistence(options: options) { current, total, label in
        if !emitJSON {
            writeStderr("[\(current)/\(total)] \(label)...")
        }
    }
    if outputJSON {
        let data = try summary.jsonData(prettyPrinted: true)
        print(redactTextIfNeeded(String(decoding: data, as: UTF8.self), masker: activeMasker))
    } else {
        print("Persistence Summary: total=\(summary.totalCount) clean=\(summary.cleanCount) warning=\(summary.warningCount) tampered=\(summary.tamperedCount) missing=\(summary.missingExecutableCount)")
        for item in summary.items {
            let scopeName = strings.string(item.scope.labelKey, language: selectedLang)
            let q = item.isQuarantined ? " [QUARANTINED]" : ""
            let missing = item.executableExists ? "" : " [MISSING TARGET]"
            let dyld = item.hasDyldInsertEnv ? " [DYLD_INSERT]" : ""
            let line = "  [\(item.verdict.rawValue.uppercased())]\(q)\(missing)\(dyld) [\(scopeName)] \(OpenSafety.visibleName(item.label)) -> \(item.programPath.map(OpenSafety.visibleName) ?? "-") (\(item.teamIdentifier))"
            print(redactTextIfNeeded(line, masker: activeMasker))
        }
    }
    if summary.tamperedCount > 0 { exit(1) }
    if summary.warningCount > 0 { exit(2) }
    exit(0)

case .runningProcesses:
    let emitJSON = outputJSON
    let summary = SystemAudit.auditRunningProcesses(options: options) { current, total, procName in
        if !emitJSON {
            writeStderr("[\(current)/\(total)] \(procName)...")
        }
    }
    if outputJSON {
        let data = try summary.jsonData(prettyPrinted: true)
        print(redactTextIfNeeded(String(decoding: data, as: UTF8.self), masker: activeMasker))
    } else {
        print("Running Processes: total=\(summary.totalCount) clean=\(summary.cleanCount) warning=\(summary.warningCount) tampered=\(summary.tamperedCount) dyldEnv=\(summary.dyldEnvCount) sockets=\(summary.processesWithSocketsCount) listening=\(summary.listeningSocketsCount) uniqueBinaries=\(summary.uniqueBinariesCount)")
        for proc in summary.items {
            let q = proc.isQuarantined ? " [QUARANTINED]" : ""
            let dyld = proc.dyldInsertLibraries.isEmpty ? "" : " [DYLD_INSERT=\(proc.dyldInsertLibraries.joined(separator: ":"))]"
            let dynMismatch = proc.dynamicSignatureMismatch ? " [DYNAMIC_SIG_MISMATCH]" : ""
            let mapped = proc.unsignedMappedLibraries.isEmpty ? "" : " [UNSIGNED_LIBS=\(proc.unsignedMappedLibraries.count)]"
            let socks = proc.networkSockets.isEmpty ? "" : " [SOCKETS=\(proc.networkSockets.prefix(3).map(\.endpointSummary).joined(separator: "; "))\(proc.networkSockets.count > 3 ? " +\(proc.networkSockets.count - 3)" : "")]"
            let parent = if let pName = proc.parentName, let pPid = proc.parentPid {
                " <- \(pName)(\(pPid))"
            } else {
                ""
            }
            let line = "  [\(proc.verdict.rawValue.uppercased())]\(q)\(dyld)\(dynMismatch)\(mapped)\(socks) PID \(proc.pid)\(parent) \(OpenSafety.visibleName(proc.name)) (\(proc.teamIdentifier)) - \(OpenSafety.visibleName(proc.executablePath))"
            print(redactTextIfNeeded(line, masker: activeMasker))
        }
    }
    if summary.tamperedCount > 0 { exit(1) }
    if summary.warningCount > 0 { exit(2) }
    exit(0)

case .posture:
    let rawPosture = SystemSecurityPostureAuditor.collect(includeOrphanReceipts: true)
    let posture = activeMasker.map { rawPosture.redacted(using: $0) } ?? rawPosture
    if outputJSON {
        let data = try posture.jsonData(prettyPrinted: true)
        print(String(decoding: data, as: UTF8.self))
    } else {
        print("System Security Posture (\(posture.cpuArchitecture) · \(posture.macOSVersion)):")
        print("  SIP:         \(posture.sipStatus.rawValue) — \(posture.sipDetail)")
        print("  SSV:         \(posture.ssvStatus.rawValue)")
        print("  Gatekeeper:  \(posture.gatekeeperMasterStatus.rawValue)")
        print("  FileVault:   \(posture.fileVaultBootEncrypted.map { $0 ? "Encrypted" : "Unencrypted" } ?? "Unknown") (\(posture.bootVolumeFormat))")
        print("  Firewall:    \(posture.firewallEnabled.map { $0 ? "Enabled" : "Disabled" } ?? "Unknown") (Stealth: \(posture.firewallStealthMode.map { $0 ? "On" : "Off" } ?? "Unknown"))")
        print("  S.M.A.R.T.:  \(posture.smartHealthStatus.rawValue) (\(posture.smartDetail))")
        print("  FDA:         \(posture.fullDiskAccessGranted ? "Granted" : "Not Granted")")
        print("  Orphan Pkgs: \(posture.orphanedReceipts.count) (audited \(posture.receiptsAuditedCount))")
        for orphan in posture.orphanedReceipts {
            print("    - \(orphan.packageIdentifier) (\(orphan.version)) -> \(orphan.forgetCommand)")
        }
    }
    exit(posture.sipStatus == .disabled || posture.smartHealthStatus == .failing ? 2 : 0)

case .singleOrBatch:
    guard let targetPath else {
        printUsage()
        exit(2)
    }

    let expandedPath = NSString(string: targetPath).expandingTildeInPath
    let targetURL = URL(fileURLWithPath: expandedPath).standardizedFileURL
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: targetURL.path, isDirectory: &isDirectory) else {
        writeStderr("Path not found: \(targetURL.path)")
        exit(2)
    }

    let ext = targetURL.pathExtension.lowercased()
    let isBundledTarget = ForensicScanner.supportedBundleExtensions.contains(ext)
        || ForensicScanner.supportedContainerExtensions.contains(ext)

    if forceBatch || (isDirectory.boolValue && !isBundledTarget) {
        let emitJSON = outputJSON
        let summary = ForensicScanner.auditDirectory(at: targetURL, options: options) { current, total, currentName in
            if !emitJSON {
                writeStderr("[\(current)/\(total)] \(currentName)...")
            }
        }
        let finalSummary = activeMasker.map { summary.redacted(using: $0) } ?? summary
        if outputJSON {
            let data = try finalSummary.jsonData(prettyPrinted: true)
            print(String(decoding: data, as: UTF8.self))
        } else {
            print("Directory: \(finalSummary.directoryPath)")
            print("Summary:   total=\(finalSummary.totalCount) clean=\(finalSummary.cleanCount) warning=\(finalSummary.warningCount) tampered=\(finalSummary.tamperedCount) quarantined=\(finalSummary.quarantinedCount)")
            for report in finalSummary.reports {
                let q = report.isQuarantined ? " [QUARANTINED]" : ""
                print("  [\(report.verdict.rawValue.uppercased())]\(q) \(OpenSafety.visibleName(report.bundleName)) (\(report.bundleId)) - \(report.teamIdentifier)")
            }
        }
        if summary.tamperedCount > 0 { exit(1) }
        if summary.warningCount > 0 { exit(2) }
        exit(0)
    } else {
        let report = ForensicScanner.auditTarget(at: targetURL, options: options)
        let checksumOverrideExit: Int32?
        if outputJSON {
            let finalReport = activeMasker.map { report.redacted(using: $0) } ?? report
            print(try finalReport.jsonString(prettyPrinted: true))
            if let expectedChecksumArg {
                switch ChecksumInput.parseValueOrFile(expectedChecksumArg, fileName: targetURL.lastPathComponent) {
                case .parsed(let expected):
                    switch expected.verify(actualSHA256: report.executableSHA256, actualSHA512: report.executableSHA512) {
                    case .matched: checksumOverrideExit = nil
                    case .mismatch: checksumOverrideExit = 1
                    case .unavailable: checksumOverrideExit = 2
                    }
                case .weakAlgorithm, .notFoundForFile, .empty, .unrecognized:
                    checksumOverrideExit = 2
                }
            } else {
                checksumOverrideExit = nil
            }
        } else {
            checksumOverrideExit = printHumanReport(
                report,
                strings: strings,
                lang: selectedLang,
                masker: activeMasker,
                expectedChecksumArg: expectedChecksumArg
            )
        }
        if let checksumOverrideExit {
            exit(checksumOverrideExit)
        }
        switch report.verdict {
        case .clean: exit(0)
        case .warning: exit(2)
        case .tampered: exit(1)
        }
    }
}
