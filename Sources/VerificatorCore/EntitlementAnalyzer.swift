// SPDX-License-Identifier: GPL-3.0-only
import Foundation

public enum EntitlementRiskLevel: String, Sendable, Equatable, Codable, CaseIterable, Comparable {
    case high
    case elevated
    case info

    private var sortOrder: Int {
        switch self {
        case .high: return 0
        case .elevated: return 1
        case .info: return 2
        }
    }

    public static func < (lhs: EntitlementRiskLevel, rhs: EntitlementRiskLevel) -> Bool {
        lhs.sortOrder < rhs.sortOrder
    }

    public var labelKey: LKey {
        switch self {
        case .high: return .entitlementRiskHigh
        case .elevated: return .entitlementRiskElevated
        case .info: return .entitlementRiskInfo
        }
    }
}

public struct EntitlementRiskItem: Identifiable, Sendable, Equatable, Codable {
    public let id: String
    public let entitlementKey: String
    public let level: EntitlementRiskLevel
    public let titleKey: LKey
    public let detailKey: LKey

    public init(
        entitlementKey: String,
        level: EntitlementRiskLevel,
        titleKey: LKey,
        detailKey: LKey
    ) {
        self.id = entitlementKey
        self.entitlementKey = entitlementKey
        self.level = level
        self.titleKey = titleKey
        self.detailKey = detailKey
    }
}

public enum EntitlementAnalyzer {
    private struct Descriptor {
        let level: EntitlementRiskLevel
        let titleKey: LKey
        let detailKey: LKey
    }

    private static let riskCatalog: [String: Descriptor] = [
        "com.apple.security.get-task-allow": Descriptor(
            level: .high,
            titleKey: .entitlementGetTaskAllowTitle,
            detailKey: .entitlementGetTaskAllowDetail
        ),
        "get-task-allow": Descriptor(
            level: .high,
            titleKey: .entitlementGetTaskAllowTitle,
            detailKey: .entitlementGetTaskAllowDetail
        ),
        "com.apple.security.cs.debugger": Descriptor(
            level: .high,
            titleKey: .entitlementDebuggerTitle,
            detailKey: .entitlementDebuggerDetail
        ),
        "com.apple.security.cs.disable-executable-page-protection": Descriptor(
            level: .high,
            titleKey: .entitlementDisableExecPageProtTitle,
            detailKey: .entitlementDisableExecPageProtDetail
        ),
        "com.apple.security.cs.disable-library-validation": Descriptor(
            level: .elevated,
            titleKey: .entitlementDisableLibraryValTitle,
            detailKey: .entitlementDisableLibraryValDetail
        ),
        "com.apple.security.cs.allow-dyld-environment-variables": Descriptor(
            level: .elevated,
            titleKey: .entitlementAllowDyldEnvTitle,
            detailKey: .entitlementAllowDyldEnvDetail
        ),
        "com.apple.security.cs.allow-unsigned-executable-memory": Descriptor(
            level: .elevated,
            titleKey: .entitlementAllowUnsignedMemTitle,
            detailKey: .entitlementAllowUnsignedMemDetail
        ),
        "com.apple.developer.endpoint-security.client": Descriptor(
            level: .elevated,
            titleKey: .entitlementEndpointSecurityTitle,
            detailKey: .entitlementEndpointSecurityDetail
        ),
        "com.apple.security.cs.allow-jit": Descriptor(
            level: .info,
            titleKey: .entitlementAllowJitTitle,
            detailKey: .entitlementAllowJitDetail
        ),
    ]

    public static func analyze(
        _ entitlements: [String],
        rawEntitlementsOutput: String = ""
    ) -> [EntitlementRiskItem] {
        var found: [String: EntitlementRiskItem] = [:]

        for entry in entitlements {
            let trimmed = entry.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed == "com.apple.security.app-sandbox=false" {
                found["com.apple.security.app-sandbox=false"] = EntitlementRiskItem(
                    entitlementKey: "com.apple.security.app-sandbox=false",
                    level: .info,
                    titleKey: .entitlementSandboxDisabledTitle,
                    detailKey: .entitlementSandboxDisabledDetail
                )
                continue
            }
            let key = trimmed.components(separatedBy: "=").first ?? trimmed
            if let descriptor = riskCatalog[key] {
                found[key] = EntitlementRiskItem(
                    entitlementKey: key,
                    level: descriptor.level,
                    titleKey: descriptor.titleKey,
                    detailKey: descriptor.detailKey
                )
            }
        }

        // Check XML output explicitly for `com.apple.security.app-sandbox` set to `<false/>`,
        // since `parseEntitlements` only stores `true`/array/string values.
        if !rawEntitlementsOutput.isEmpty,
           let data = rawEntitlementsOutput.data(using: .utf8),
           let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
           let sandboxBool = plist["com.apple.security.app-sandbox"] as? Bool,
           sandboxBool == false {
            found["com.apple.security.app-sandbox=false"] = EntitlementRiskItem(
                entitlementKey: "com.apple.security.app-sandbox=false",
                level: .info,
                titleKey: .entitlementSandboxDisabledTitle,
                detailKey: .entitlementSandboxDisabledDetail
            )
        }

        return found.values.sorted { lhs, rhs in
            if lhs.level != rhs.level {
                return lhs.level < rhs.level
            }
            return lhs.entitlementKey < rhs.entitlementKey
        }
    }

    public static func isSensitiveEntitlement(_ entry: String) -> Bool {
        let key = entry.components(separatedBy: "=").first ?? entry
        return riskCatalog[key] != nil || entry == "com.apple.security.app-sandbox=false"
    }
}
