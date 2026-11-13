// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// Global macOS Application Firewall status obtained strictly read-only via `socketfilterfw`.
public struct FirewallStatus: Sendable, Equatable, Codable {
    public let globalEnabled: Bool?
    public let blockAll: Bool?
    public let stealthMode: Bool?

    public init(globalEnabled: Bool?, blockAll: Bool?, stealthMode: Bool?) {
        self.globalEnabled = globalEnabled
        self.blockAll = blockAll
        self.stealthMode = stealthMode
    }

    public var isAvailable: Bool {
        globalEnabled != nil || blockAll != nil || stealthMode != nil
    }
}

/// Per-application firewall disposition reported by `socketfilterfw --getappblocked`.
public enum FirewallAppRuleStatus: String, Sendable, Equatable, Codable {
    case permitted
    case blocked
    case unknown
}

/// Read-only Application Firewall inspection result for a specific target bundle or executable.
public struct FirewallAppState: Sendable, Equatable, Codable {
    public let targetPath: String
    public let ruleStatus: FirewallAppRuleStatus
    public let blockAllIncomingActive: Bool
    public let unblockCommand: String

    public init(
        targetPath: String,
        ruleStatus: FirewallAppRuleStatus,
        blockAllIncomingActive: Bool = false,
        unblockCommand: String? = nil
    ) {
        self.targetPath = targetPath
        self.ruleStatus = ruleStatus
        self.blockAllIncomingActive = blockAllIncomingActive
        self.unblockCommand = unblockCommand ?? ApplicationFirewall.unblockCommand(for: targetPath)
    }

    public var isBlocked: Bool {
        ruleStatus == .blocked || blockAllIncomingActive
    }
}

/// Read-only parser and runner for `/usr/libexec/ApplicationFirewall/socketfilterfw`.
/// Verificator never executes `--set*` or `--unblockapp` mutations; it only surfaces copyable admin commands when blocked.
public enum ApplicationFirewall {
    public static let binaryPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"

    public static func readSystemStatus(cancellation: ScanCancellationToken? = nil) -> FirewallStatus {
        guard FileManager.default.isExecutableFile(atPath: binaryPath) else {
            return FirewallStatus(globalEnabled: nil, blockAll: nil, stealthMode: nil)
        }
        let res = ForensicScanner.runTool(
            binaryPath,
            args: ["--getglobalstate", "--getblockall", "--getstealthmode"],
            timeoutSeconds: 5,
            cancellation: cancellation
        )
        return parseSystemStatus(res.output)
    }

    public static func inspectTarget(atPath path: String, cancellation: ScanCancellationToken? = nil) -> FirewallAppState {
        guard FileManager.default.isExecutableFile(atPath: binaryPath),
              FileManager.default.fileExists(atPath: path) else {
            return FirewallAppState(targetPath: path, ruleStatus: .unknown, blockAllIncomingActive: false)
        }
        let res = ForensicScanner.runTool(
            binaryPath,
            args: ["--getblockall", "--getappblocked", path],
            timeoutSeconds: 5,
            cancellation: cancellation
        )
        let lines = res.output.split(whereSeparator: \.isNewline).map(String.init)
        let blockAll = lines.compactMap(parseBlockAll).first == true
        let appStatus = lines.compactMap(parseAppBlocked).last ?? .unknown
        return FirewallAppState(
            targetPath: path,
            ruleStatus: appStatus,
            blockAllIncomingActive: blockAll,
            unblockCommand: unblockCommand(for: path)
        )
    }

    public static func parseSystemStatus(_ output: String) -> FirewallStatus {
        let lines = output.split(whereSeparator: \.isNewline).map(String.init)
        return FirewallStatus(
            globalEnabled: lines.compactMap(parseGlobalState).first,
            blockAll: lines.compactMap(parseBlockAll).first,
            stealthMode: lines.compactMap(parseStealthMode).first
        )
    }

    public static func parseGlobalState(_ line: String) -> Bool? {
        let lower = line.lowercased()
        guard lower.contains("firewall") || lower.contains("state =") else { return nil }
        if lower.contains("state = 1") || lower.contains("state = 2") || lower.contains("enabled") { return true }
        if lower.contains("state = 0") || lower.contains("disabled") { return false }
        return nil
    }

    public static func parseBlockAll(_ line: String) -> Bool? {
        let lower = line.lowercased()
        guard lower.contains("block all") else { return nil }
        if lower.contains("enabled") || lower.contains("on") { return true }
        if lower.contains("disabled") || lower.contains("off") { return false }
        return nil
    }

    public static func parseStealthMode(_ line: String) -> Bool? {
        let lower = line.lowercased()
        guard lower.contains("stealth") else { return nil }
        if lower.contains("enabled") || lower.hasSuffix(" on") || lower.contains(" is on") { return true }
        if lower.contains("disabled") || lower.hasSuffix(" off") || lower.contains(" is off") { return false }
        return nil
    }

    public static func parseAppBlocked(_ line: String) -> FirewallAppRuleStatus? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let lower = trimmed.lowercased()
        if lower.contains("incoming connection") || lower.contains("is blocked") || lower.contains("is permitted") {
            let lastToken = lower
                .trimmingCharacters(in: CharacterSet.punctuationCharacters.union(.whitespaces))
                .split(whereSeparator: \.isWhitespace)
                .last
            if lastToken == "blocked" { return .blocked }
            if lastToken == "permitted" { return .permitted }
        }
        return nil
    }

    public static func unblockCommand(for path: String) -> String {
        let escaped = path
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "sudo \(binaryPath) --unblockapp \"\(escaped)\""
    }
}
