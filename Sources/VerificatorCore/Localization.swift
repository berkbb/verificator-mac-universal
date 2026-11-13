// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// Arayüz dilleri. `system`, macOS'un tercih ettiği dili izler.
public enum AppLanguage: String, CaseIterable, Identifiable, Sendable {
    case system
    case tr
    case en
    case ro

    public static let supportedCodes = ["tr", "en", "ro"]

    public var id: String { rawValue }

    public var nativeName: String? {
        switch self {
        case .system: nil
        case .tr: "Türkçe"
        case .en: "English"
        case .ro: "Română"
        }
    }

    public var flag: String {
        switch self {
        case .system: "🌐"
        case .tr: "🇹🇷"
        case .en: "🇬🇧"
        case .ro: "🇷🇴"
        }
    }

    public func resolvedCode(preferredLanguages: [String] = Locale.preferredLanguages) -> String {
        if self != .system { return rawValue }
        for identifier in preferredLanguages {
            let code = Locale(identifier: identifier).language.languageCode?.identifier ?? String(identifier.prefix(2))
            if Self.supportedCodes.contains(code) { return code }
        }
        return "tr"
    }
}

/// Her dil için Localizable.strings tablolarını tutar; uygulama içinde anında dil değişimine izin verir.
public struct StringTable: Sendable {
    public let tables: [String: [String: String]]

    public init(tables: [String: [String: String]]) {
        self.tables = tables
    }

    public init(bundle: Bundle = .main, executablePath: String? = CommandLine.arguments.first) {
        var loaded: [String: [String: String]] = [:]
        for code in AppLanguage.supportedCodes {
            if let url = bundle.url(forResource: "Localizable", withExtension: "strings", subdirectory: nil, localization: code),
               let table = Self.parseStringsFile(at: url) {
                loaded[code] = table
            } else if let url = bundle.resourceURL?.appendingPathComponent("\(code).lproj/Localizable.strings"),
                      let table = Self.parseStringsFile(at: url) {
                loaded[code] = table
            }
        }

        if loaded.isEmpty, let resourcesDir = Self.discoverFallbackResourcesDirectory(executablePath: executablePath) {
            for code in AppLanguage.supportedCodes {
                let url = resourcesDir.appendingPathComponent("\(code).lproj/Localizable.strings")
                if let table = Self.parseStringsFile(at: url) {
                    loaded[code] = table
                }
            }
        }
        tables = loaded
    }

    public static func discoverFallbackResourcesDirectory(executablePath: String? = CommandLine.arguments.first) -> URL? {
        let fm = FileManager.default
        var candidateDirs: [URL] = []

        if let executablePath, !executablePath.isEmpty {
            let execURL = URL(fileURLWithPath: executablePath).resolvingSymlinksInPath()
            let macOSDir = execURL.deletingLastPathComponent()
            let contentsDir = macOSDir.deletingLastPathComponent()
            candidateDirs.append(contentsDir.appendingPathComponent("Resources", isDirectory: true))
            candidateDirs.append(macOSDir.appendingPathComponent("Resources", isDirectory: true))

            var ancestor = macOSDir
            for _ in 0..<6 {
                candidateDirs.append(ancestor.appendingPathComponent("Resources", isDirectory: true))
                let next = ancestor.deletingLastPathComponent()
                if next.path == ancestor.path { break }
                ancestor = next
            }
        }

        var cwd = URL(fileURLWithPath: fm.currentDirectoryPath, isDirectory: true)
        for _ in 0..<6 {
            candidateDirs.append(cwd.appendingPathComponent("Resources", isDirectory: true))
            let next = cwd.deletingLastPathComponent()
            if next.path == cwd.path { break }
            cwd = next
        }

        for dir in candidateDirs {
            let probe = dir.appendingPathComponent("en.lproj/Localizable.strings").path
            if fm.fileExists(atPath: probe) {
                return dir
            }
        }
        return nil
    }

    public static func parseStringsFile(at url: URL) -> [String: String]? {
        NSDictionary(contentsOf: url) as? [String: String]
    }

    public func string(_ key: LKey, language code: String) -> String {
        tables[code]?[key.rawValue]
            ?? tables["tr"]?[key.rawValue]
            ?? tables["en"]?[key.rawValue]
            ?? key.rawValue
    }

    public func format(_ key: LKey, language code: String, _ args: CVarArg...) -> String {
        String(format: string(key, language: code), locale: Locale(identifier: code), arguments: args)
    }
}

public enum LKey: String, CaseIterable, Sendable, Codable {
    case appName, appTitle, appSubtitle, appTagline
    case actionSelectApp, actionRefresh, actionRefreshHelp, actionClear, actionClearHelp, actionBackHome, actionBackHomeHelp, actionClearAllHistory, actionRevealInFinder, actionClearReport
    case actionExportReport, actionSaveReport, actionCopied, actionRecentBundles, actionClearRecents
    case actionExportJSON, menuSaveJSONReport, actionCancelScan
    case sidebarSections, sidebarHome, sidebarBatch, sidebarNoRecents, sidebarRemoveRecent
    case statusIdle, statusIdleHint, statusDropActive, statusDropBar, statusScanning
    case verdictClean, verdictWarning, verdictTampered
    case tabOverview, tabDylibs, tabSymbols, tabRaw
    case sectionBundleInfo, sectionCodesign, sectionAnomalies, sectionLinkedDylibs, sectionBundledDylibs, sectionHookIndicators
    case fieldBundleName, fieldBundleId, fieldVersion, fieldExecutable, fieldExecutableDate, fieldResourcesDate
    case fieldTeamId, fieldAuthorities, fieldSignedTime, fieldHardenedRuntime, fieldNotarized, fieldGatekeeper, fieldCdhash, fieldScanDuration
    case fieldArchitectures, fieldEntitlements, fieldSpctlAssessment, fieldExecutableSha256, fieldRpaths
    case valueEnabled, valueDisabled, valueYes, valueNo, valueNotSet, valueQuarantined, valueNotQuarantined, valueNone, valueNotChecked
    case findingUnofficialAuthorityTitle, findingUnofficialAuthorityDesc
    case findingSignatureHijackTitle, findingSignatureHijackDesc
    case findingVerifyFailedTitle, findingVerifyFailedDesc
    case findingInjectedDylibTitle, findingInjectedDylibDesc
    case findingObjcSwizzlingTitle, findingObjcSwizzlingDesc
    case findingMachPatchingTitle, findingMachPatchingDesc
    case findingDyldSlideTitle, findingDyldSlideDesc
    case findingExternalDylibTitle, findingExternalDylibDesc
    case findingPartialHookTitle, findingPartialHookDesc
    case findingUnsignedBundledLibTitle, findingUnsignedBundledLibDesc
    case findingSpctlRejectedTitle, findingSpctlRejectedDesc
    case findingAdhocLocalTitle, findingAdhocLocalDesc
    case findingCleanTitle, findingCleanDesc
    case symbolCatSwizzle, symbolCatMemory, symbolCatDyld, symbolCatTarget
    case emptyNoHookSymbols, emptyNoBundledDylibs
    case languageSystem
    case appearanceSystem, appearanceLight, appearanceDark
    case restartWarningTitle, restartMenuBarNotice
    case menuAbout, menuCheckAppUpdates, menuOpenBundle, menuRefreshScan, menuRevealInFinder
    case menuCopyReport, menuSaveReport, menuCloseReport, menuAudit, menuShowLog, menuWebsite, menuRepository
    case settingsGeneral, settingsScan, settingsShortcuts, settingsEngine
    case settingsLanguage, settingsAppearance, settingsScanSection
    case settingsDeepFrameworkCheck, settingsDeepFrameworkCheckNote, settingsExtractTargetStrings
    case settingsIncludeSpctl, settingsIncludeSpctlNote
    case settingsAutoScanOnDrop, settingsRevealAfterExport, settingsRecentsSection
    case settingsToolsSection, settingsToolsRefresh, settingsToolReady, settingsToolMissing
    case appUpdateSection, appUpdateVersion, updateCheck, updateChecking
    case appUpdateAvailable, appUpdateUpToDate, appUpdateDownload, appUpdateNoReleases, updateAutoCheck
    case appUpdateDownloadAndVerify, appUpdateOpenInBrowser, appUpdateDownloading, appUpdateVerifiedSuccess, appUpdateVerifyFailed, appUpdateOpenInstaller
    case appUpdateAvailableTitle, appUpdateUpToDateTitle, appUpdateNoReleasesTitle, appUpdateFailedTitle
    case settingsReset, settingsResetConfirm
    case shortcutCustomSection, shortcutReferenceSection, shortcutRecordPrompt, shortcutRecordHelp
    case shortcutResetDefault, shortcutResetAll, shortcutModifierRequired, shortcutConflictWarning, shortcutSystemConflictWarning
    case shortcutActionOpenBundle, shortcutActionRefresh, shortcutActionReveal, shortcutActionCopyReport, shortcutActionSaveReport, shortcutActionClearReport
    case aboutVersion, aboutPoweredBy, aboutEngineCredit, aboutRepository, aboutAppLicense, aboutNotices, aboutCopyright
    case licenseAppSubtitle, licenseNoticesSubtitle, licenseReadOnly, licensePublisher, licenseLabel, licenseCopyText, licenseCopied
    case logTitle, logMessageCount, logAllMessages, logProblems, logSearchPrompt, logClear, logOpenInConsole
    case logEmptyTitle, logEmptyMessage, logSelectHint
    case logColumnTime, logColumnType, logColumnCategory, logColumnProcess, logColumnMessage
    case logLevelInfo, logLevelWarning, logLevelError
    case logCategoryApp, logCategoryScanner, logCategorySignature, logCategoryUpdate
    case buttonOK, buttonClose, buttonCopy, buttonShowInFinder
    case settingsAISection, settingsAISuggestions, settingsAISuggestionsNote
    case settingsAIProvider, settingsAIModel, settingsAIRefresh
    case settingsAIServerOff, settingsAIModelMissing, settingsAIReady, settingsAILocalNote
    case settingsAIAutomatic, settingsAIAutomaticNote, settingsAIMoveUp, settingsAIMoveDown
    case settingsAIStatusReady, settingsAIStatusOff, settingsAIChecking, settingsAIRecheck, settingsAINotEnabled
    case aiCheckReady, aiCheckReadyModel, aiCheckDeviceNotEligible, aiCheckAppleOff, aiCheckModelNotReady, aiCheckAppleUnavailable
    case aiCheckServerOff, aiCheckNoModel, aiCheckModelMissing, aiCheckNoAnswer
    case aiForensicSection, aiForensicAnalyze, aiForensicReanalyze, aiForensicCancel, aiForensicThinking, aiForensicSource, aiForensicUnavailable, aiForensicNote
    case fieldQuarantine, actionRemoveQuarantine, actionRemoveQuarantineHelp, quarantineRemovedSuccess, quarantineRemovedFailed, quarantineRemovedCancelled, quarantineRemovedFailedDetail
    case actionAssessGatekeeper, actionAssessGatekeeperHelp
    case searchDylibsPlaceholder, filterAll, filterNonSystem, filterSuspicious, filterMatchCount
    case actionBatchScan, menuBatchScan, batchTitle, batchEmptyHint, batchScanningProgress, batchSummaryStats
    case batchFilterIssues, batchFilterQuarantined, batchOpenSelected, batchExportMarkdown, batchExportJSON, actionCancelBatch, batchNoBundlesFound
    case batchSearchPlaceholder, batchPartialCancelledBadge
    case rawEntitlementsTitle, rawRpathsTitle, rawGatekeeperTitle
    case reportVerdictLabel, reportBundlePathLabel, reportSuspiciousDylibsSection

    // 1.3.0 — Target Kinds & Expanded Formats
    case targetKindApp, targetKindPkg, targetKindDmg, targetKindNested, targetKindMachO
    case fieldTargetKind, openPanelMessageExpanded, dropZoneSupportedHintExpanded
    case findingPkgSignedTitle, findingPkgSignedDetail, findingPkgUnsignedTitle, findingPkgUnsignedDetail
    case findingPkgInvalidTitle, findingPkgInvalidDetail
    case findingDmgSignedTitle, findingDmgSignedDetail, findingDmgUnsignedTitle, findingDmgUnsignedDetail
    case findingDmgBrokenTitle, findingDmgBrokenDetail
    case findingMachOExecutableOnlyDetail, findingUnsupportedTargetTitle, findingUnsupportedTargetDetail

    // 1.3.0 — Entitlement Risk Badges
    case sectionEntitlementRisks, entitlementRisksNone, entitlementRisksInfoNote
    case entitlementRiskHigh, entitlementRiskElevated, entitlementRiskInfo
    case entitlementDisableLibraryValTitle, entitlementDisableLibraryValDetail
    case entitlementAllowDyldEnvTitle, entitlementAllowDyldEnvDetail
    case entitlementAllowUnsignedMemTitle, entitlementAllowUnsignedMemDetail
    case entitlementAllowJitTitle, entitlementAllowJitDetail
    case entitlementGetTaskAllowTitle, entitlementGetTaskAllowDetail
    case entitlementDebuggerTitle, entitlementDebuggerDetail
    case entitlementDisableExecPageProtTitle, entitlementDisableExecPageProtDetail
    case entitlementEndpointSecurityTitle, entitlementEndpointSecurityDetail
    case entitlementSandboxDisabledTitle, entitlementSandboxDisabledDetail
    case reportEntitlementRisksSection

    // 1.3.0 — Report & Bundle Diff Mode
    case navDiffMode, menuCompareMode, diffTitle, diffEmptyHint
    case diffBaselineHeader, diffTargetHeader, diffChooseFile, diffUseCurrentReport
    case diffSwapSides, diffRunComparison, diffRunning, diffSelectFromRecent, diffExportMarkdown
    case diffSummaryMatches, diffSummaryChanged, diffSummaryRegressions, diffSummaryWarnings
    case diffSectionMetadata, diffSectionEntitlements, diffSectionRpaths, diffSectionLinkedDylibs
    case diffSectionBundledLibraries, diffSectionHooks, diffSectionRegressions
    case diffAddedBadge, diffRemovedBadge, diffNoChangesInSection, diffFieldChanged
    case diffRegressionVerdictWorse, diffRegressionAuthorityChanged, diffRegressionTeamChanged
    case diffRegressionQuarantineAdded, diffRegressionEntitlementAdded, diffRegressionSuspiciousDylibAdded
    case diffRegressionHookAdded, diffRegressionBinaryChanged

    // 1.3.0 — Running Processes & Persistence Audit
    case navRunningProcesses, navPersistence, menuRunningProcesses, menuPersistenceAudit
    case runningTitle, runningEmptyHint, runningScanButton, runningRescanButton
    case runningScanningProgress, runningSummaryStats, runningFilterDyldEnv, runningFilterIssues
    case runningSearchPlaceholder, runningColPid, runningDyldEnvDetected, runningEnvUnreadable
    case runningOpenInInspector, runningBinaryMissing
    case persistenceTitle, persistenceEmptyHint, persistenceScanButton, persistenceRescanButton
    case persistenceScanningProgress, persistenceSummaryStats
    case persistenceScopeUserAgent, persistenceScopeSystemAgent, persistenceScopeSystemDaemon, persistenceScopePrivilegedHelper
    case persistenceFilterMissing, persistenceFilterIssues, persistenceSearchPlaceholder
    case persistenceExecutableMissing, persistencePlistDyldEnv, persistenceDisabledBadge, persistenceRunAtLoadBadge
    case persistenceRevealPlist

    // 1.3.0 — macOS System Integration & CLI Helper
    case menuInstallCLI, settingsCLISection, settingsCLIEmbeddedPath, settingsCLIInstallCommand
    case settingsCopyCLIInstall, settingsCopiedCLIInstallNotice, settingsIntegrationsNote
    case serviceInvalidSelectionError, urlSchemeInvalidError
    case intentTitle, intentDescription, intentTargetParameterTitle, intentResultSummary

    // 1.3.0+ — Sibling Security, Live Process Inspection, Revocation & System Parity
    case runningDynamicSigMismatchTitle, runningDynamicSigMismatchDesc
    case runningUnsignedMappedLibTitle, runningUnsignedMappedLibDesc
    case runningParentProcessLabel
    case settingsCheckRevocation, settingsCheckRevocationNote
    case findingRevokedCertificateTitle, findingRevokedCertificateDesc
    case fieldRevocation, revocationStatusOk, revocationStatusRevoked
    case sigChangeBannerSignerChanged, sigChangeBannerLostSignature, sigChangeBannerSameSignerUpdated, sigChangeAcknowledge
    case gatekeeperGlobalEnabled, gatekeeperGlobalDisabled, gatekeeperGlobalUnknown, gatekeeperDisabledBannerNotice
    case fdaStatusGranted, fdaStatusMissing, fdaOpenSettings, fdaPersistenceHint, settingsPermissionsSection

    // 1.3.0+ — Sibling Features: OpenSafety, Firewall, Checksum Verifier, Internet Access Policy, Diagnostic Masker & Volume Encryption
    case findingNameSpoofingTitle, findingNameSpoofingDesc, fieldDeceptiveNames, bannerNameSpoofingWarning
    case fieldFirewallState, firewallStatusEnabled, firewallStatusDisabled, firewallStatusBlockAll, firewallStatusStealthOn, firewallStatusStealthOff, firewallStatusUnavailable
    case firewallAppPermitted, firewallAppBlocked, firewallAppUnknown, firewallAppBlockedNote, firewallCopyUnblockCommand
    case settingsFirewallStatusFormat, settingsFirewallUnavailable
    case sectionChecksumVerifier, checksumPlaceholder, checksumLoadFile, checksumClearButton
    case checksumMatchBadge, checksumMismatchBadge, checksumWeakAlgoWarning, checksumNotFoundWarning, checksumUnrecognizedWarning, checksumUnavailableWarning
    case fieldExecutableSha512
    case sectionInternetAccessPolicy, iapDeveloperLabel, iapWebsiteLabel, iapConnectionsLabel, iapServicesLabel
    case iapDirectionIncoming, iapDirectionOutgoing, iapEssentialBadge, iapDenyLabel, iapNoConnections
    case fieldVolumeEncryption, volumeEncryptedLabel, volumeUnencryptedLabel, volumeUnknownLabel, volumeUnencryptedRemovableBanner
    case settingsBootVolumeEncrypted, settingsBootVolumeUnencrypted
    case actionCopyMaskedReport, actionSaveMaskedMarkdown, actionSaveMaskedJSON, actionCopyMaskedLogs
    case settingsRedactDiagnostics, settingsRedactDiagnosticsNote
}
