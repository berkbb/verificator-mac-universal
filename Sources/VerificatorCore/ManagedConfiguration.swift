// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// Canonical `UserDefaults` keys shared across `AppSettings`, MDM policy enforcement, and portable transfer.
public enum VerificatorPreferenceKey {
    public static let language = "language"
    public static let appearance = "appearance"
    public static let deepFrameworkSignatureCheck = "deepFrameworkSignatureCheck"
    public static let extractTargetStrings = "extractTargetStrings"
    public static let includeGatekeeperAssessment = "includeGatekeeperAssessment"
    public static let checkCertificateRevocation = "checkCertificateRevocation"
    public static let autoScanOnDrop = "autoScanOnDrop"
    public static let revealAfterExport = "revealAfterExport"
    public static let redactSharedDiagnostics = "redactSharedDiagnostics"
    public static let recentBundles = "recentBundles"
    public static let recentVerdicts = "recentVerdicts"
    public static let checkUpdatesAtLaunch = "checkUpdatesAtLaunch"
    public static let updateConsentAsked = "updateConsentAsked"
    public static let customShortcuts = "customShortcuts"
    public static let aiSuggestions = "aiSuggestions"
    public static let aiProvider = "aiProvider"
    public static let aiOllamaModel = "aiOllamaModel"
    public static let aiLMStudioModel = "aiLMStudioModel"
    public static let aiAutomaticOrder = "aiAutomaticOrder"
    public static let aiAutomaticOff = "aiAutomaticOff"
    public static let watchedFolderEnabled = "watchedFolderEnabled"
    public static let watchedFolderPaths = "watchedFolderPaths"
    public static let showMenuBarExtra = "showMenuBarExtra"

    public static let allManagedCapable: [String] = [
        language,
        appearance,
        deepFrameworkSignatureCheck,
        extractTargetStrings,
        includeGatekeeperAssessment,
        checkCertificateRevocation,
        autoScanOnDrop,
        revealAfterExport,
        redactSharedDiagnostics,
        checkUpdatesAtLaunch,
        aiSuggestions,
        aiProvider,
        watchedFolderEnabled,
        watchedFolderPaths,
        showMenuBarExtra,
    ]

    public static let allKeys: [String] = allManagedCapable + [
        recentBundles,
        recentVerdicts,
        updateConsentAsked,
        customShortcuts,
        aiOllamaModel,
        aiLMStudioModel,
        aiAutomaticOrder,
        aiAutomaticOff,
    ]
}

/// Enterprise MDM configuration policy detector (`UserDefaults.objectIsForced(forKey:)`).
/// When an organization pushes a `.mobileconfig` payload targeting `com.babadogantech.verificator`,
/// managed keys are surfaced as read-only in Settings and protected from local or imported overrides.
public enum ManagedConfiguration {
    public typealias KeyLockChecker = @Sendable (String) -> Bool

    /// Returns `true` when `key` is enforced by a managed configuration profile in `defaults`.
    public static func isManaged(_ key: String, defaults: UserDefaults = .standard) -> Bool {
        defaults.objectIsForced(forKey: key)
    }

    /// Returns all preference keys currently locked by a managed configuration profile.
    public static func managedKeys(
        from candidates: [String] = VerificatorPreferenceKey.allManagedCapable,
        defaults: UserDefaults = .standard,
        overrideChecker: KeyLockChecker? = nil
    ) -> Set<String> {
        if let overrideChecker {
            return Set(candidates.filter(overrideChecker))
        }
        return Set(candidates.filter { defaults.objectIsForced(forKey: $0) })
    }

    /// Returns `true` when any supported preference key is locked by MDM.
    public static func isAnyManaged(defaults: UserDefaults = .standard, overrideChecker: KeyLockChecker? = nil) -> Bool {
        !managedKeys(defaults: defaults, overrideChecker: overrideChecker).isEmpty
    }
}
