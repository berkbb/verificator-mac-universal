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

    public init(bundle: Bundle = .main) {
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
        tables = loaded
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
}

public enum LKey: String, CaseIterable, Sendable {
    case appName, appTitle, appSubtitle, appTagline
    case actionSelectApp, actionRefresh, actionRefreshHelp, actionClear, actionClearHelp, actionBackHome, actionBackHomeHelp, actionClearAllHistory, actionRevealInFinder, actionClearReport
    case actionExportReport, actionSaveReport, actionCopied, actionRecentBundles, actionClearRecents
    case sidebarSections, sidebarHome, sidebarNoRecents, sidebarRemoveRecent
    case statusIdle, statusIdleHint, statusDropActive, statusDropBar, statusScanning
    case verdictClean, verdictWarning, verdictTampered
    case tabOverview, tabDylibs, tabSymbols, tabRaw
    case sectionBundleInfo, sectionCodesign, sectionAnomalies, sectionLinkedDylibs, sectionBundledDylibs, sectionHookIndicators
    case fieldBundleName, fieldBundleId, fieldVersion, fieldExecutable, fieldExecutableDate, fieldResourcesDate
    case fieldTeamId, fieldAuthorities, fieldSignedTime, fieldHardenedRuntime, fieldNotarized, fieldGatekeeper, fieldCdhash, fieldScanDuration
    case valueEnabled, valueDisabled, valueYes, valueNo, valueNotSet
    case findingUnofficialAuthorityTitle, findingUnofficialAuthorityDesc
    case findingSignatureHijackTitle, findingSignatureHijackDesc
    case findingVerifyFailedTitle, findingVerifyFailedDesc
    case findingInjectedDylibTitle, findingInjectedDylibDesc
    case findingObjcSwizzlingTitle, findingObjcSwizzlingDesc
    case findingMachPatchingTitle, findingMachPatchingDesc
    case findingDyldSlideTitle, findingDyldSlideDesc
    case findingAdhocLocalTitle, findingAdhocLocalDesc
    case findingCleanTitle, findingCleanDesc
    case symbolCatSwizzle, symbolCatMemory, symbolCatDyld, symbolCatTarget
    case emptyNoHookSymbols, emptyNoBundledDylibs
    case langPicker, languageSystem
    case appearanceSystem, appearanceLight, appearanceDark
    case restartWarningTitle, restartMenuBarNotice
    case menuAbout, menuCheckAppUpdates, menuOpenBundle, menuRefreshScan, menuRevealInFinder
    case menuCopyReport, menuSaveReport, menuCloseReport, menuAudit, menuShowLog, menuWebsite, menuRepository
    case settingsGeneral, settingsScan, settingsShortcuts, settingsEngine
    case settingsLanguage, settingsAppearance, settingsScanSection
    case settingsDeepFrameworkCheck, settingsDeepFrameworkCheckNote, settingsExtractTargetStrings
    case settingsAutoScanOnDrop, settingsRevealAfterExport, settingsRecentsSection
    case settingsToolsSection, settingsToolsRefresh, settingsToolReady, settingsToolMissing
    case appUpdateSection, appUpdateVersion, updateCheck, updateChecking
    case appUpdateAvailable, appUpdateUpToDate, appUpdateDownload, appUpdateNoReleases, updateAutoCheck
    case appUpdateAvailableTitle, appUpdateUpToDateTitle, appUpdateNoReleasesTitle, appUpdateFailedTitle
    case settingsReset, settingsResetConfirm
    case shortcutCustomSection, shortcutReferenceSection, shortcutRecordPrompt, shortcutRecordHelp
    case shortcutResetDefault, shortcutResetAll, shortcutModifierRequired, shortcutConflictWarning
    case shortcutActionOpenBundle, shortcutActionRefresh, shortcutActionReveal, shortcutActionCopyReport, shortcutActionSaveReport, shortcutActionClearReport
    case aboutVersion, aboutPoweredBy, aboutEngineCredit, aboutRepository, aboutAppLicense, aboutNotices, aboutCopyright
    case licenseAppSubtitle, licenseNoticesSubtitle, licenseReadOnly, licensePublisher, licenseLabel, licenseCopyText, licenseCopied
    case logTitle, logMessageCount, logAllMessages, logProblems, logSearchPrompt, logClear, logOpenInConsole
    case logEmptyTitle, logEmptyMessage, logSelectHint
    case logColumnTime, logColumnType, logColumnCategory, logColumnProcess, logColumnMessage
    case logLevelInfo, logLevelWarning, logLevelError
    case logCategoryApp, logCategoryScanner, logCategorySignature, logCategoryUpdate
    case buttonOK, buttonClose, buttonCopy, buttonShowInFinder, unknown
    case settingsAISection, settingsAISuggestions, settingsAISuggestionsNote
    case settingsAIProvider, settingsAIModel, settingsAIRefresh
    case settingsAIServerOff, settingsAINoLocalModel, settingsAIModelMissing, settingsAIReady, settingsAILocalNote
    case settingsAIAutomatic, settingsAIAutomaticNote, settingsAIMoveUp, settingsAIMoveDown
    case settingsAIStatusReady, settingsAIStatusOff, settingsAIChecking, settingsAIRecheck, settingsAINotEnabled
    case aiCheckReady, aiCheckReadyModel, aiCheckDeviceNotEligible, aiCheckAppleOff, aiCheckModelNotReady, aiCheckAppleUnavailable
    case aiCheckServerOff, aiCheckNoModel, aiCheckModelMissing, aiCheckNoAnswer
    case aiForensicSection, aiForensicAnalyze, aiForensicReanalyze, aiForensicThinking, aiForensicSource, aiForensicUnavailable, aiForensicNote
    case fieldQuarantine, actionRemoveQuarantine, actionRemoveQuarantineHelp, quarantineRemovedSuccess, quarantineRemovedFailed
}
