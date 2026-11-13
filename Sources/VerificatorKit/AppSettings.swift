// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import Foundation
import VerificatorCore
import Observation
import SwiftUI

public enum WindowID {
    public static let main = "main"
    public static let about = "about"
    public static let log = "log"
}

public enum AppAppearance: String, CaseIterable, Identifiable {
    case system
    case light
    case dark

    public var id: String { rawValue }

    public var titleKey: LKey {
        switch self {
        case .system: .appearanceSystem
        case .light: .appearanceLight
        case .dark: .appearanceDark
        }
    }

    public var systemImage: String {
        switch self {
        case .system: "circle.lefthalf.filled"
        case .light: "sun.max"
        case .dark: "moon"
        }
    }

    public var nsAppearance: NSAppearance? {
        switch self {
        case .system: nil
        case .light: NSAppearance(named: .aqua)
        case .dark: NSAppearance(named: .darkAqua)
        }
    }
}

public struct KeyboardShortcutData: Codable, Equatable, Sendable {
    public var key: String
    public var isSpecialKey: Bool
    public var specialKeyCode: UInt16?
    public var command: Bool
    public var shift: Bool
    public var option: Bool
    public var control: Bool

    public init(
        key: String,
        isSpecialKey: Bool = false,
        specialKeyCode: UInt16? = nil,
        command: Bool = true,
        shift: Bool = false,
        option: Bool = false,
        control: Bool = false
    ) {
        self.key = key
        self.isSpecialKey = isSpecialKey
        self.specialKeyCode = specialKeyCode
        self.command = command
        self.shift = shift
        self.option = option
        self.control = control
    }

    public var keyEquivalent: KeyEquivalent {
        if isSpecialKey, let code = specialKeyCode {
            switch code {
            case 51: return .delete
            case 36: return .return
            default:
                if let char = key.lowercased().first {
                    return KeyEquivalent(char)
                }
                return .return
            }
        }
        guard let char = key.lowercased().first else { return KeyEquivalent("?") }
        return KeyEquivalent(char)
    }

    public var eventModifiers: EventModifiers {
        var mods: EventModifiers = []
        if command { mods.insert(.command) }
        if shift { mods.insert(.shift) }
        if option { mods.insert(.option) }
        if control { mods.insert(.control) }
        return mods
    }

    public var displayString: String {
        var str = ""
        if control { str += "⌃" }
        if option { str += "⌥" }
        if shift { str += "⇧" }
        if command { str += "⌘" }
        str += key.uppercased()
        return str
    }
}

public enum ShortcutAction: String, CaseIterable, Identifiable, Sendable {
    case openBundle
    case refresh
    case reveal
    case copyReport
    case saveReport
    case clearReport

    public var id: String { rawValue }

    public var titleKey: LKey {
        switch self {
        case .openBundle: .shortcutActionOpenBundle
        case .refresh: .shortcutActionRefresh
        case .reveal: .shortcutActionReveal
        case .copyReport: .shortcutActionCopyReport
        case .saveReport: .shortcutActionSaveReport
        case .clearReport: .shortcutActionClearReport
        }
    }

    public var defaultShortcut: KeyboardShortcutData {
        switch self {
        case .openBundle:
            return KeyboardShortcutData(key: "O", command: true)
        case .refresh:
            return KeyboardShortcutData(key: "R", command: true)
        case .reveal:
            return KeyboardShortcutData(key: "R", command: true, shift: true)
        case .copyReport:
            return KeyboardShortcutData(key: "C", command: true, shift: true)
        case .saveReport:
            return KeyboardShortcutData(key: "S", command: true)
        case .clearReport:
            return KeyboardShortcutData(key: "W", command: true, shift: true)
        }
    }
}

@Observable
public final class AppSettings {
    public static let shared = AppSettings()
    public static let maxRecentBundles = 10

    private enum Key {
        static let language = "language"
        static let appearance = "appearance"
        static let deepFrameworkSignatureCheck = "deepFrameworkSignatureCheck"
        static let extractTargetStrings = "extractTargetStrings"
        static let includeGatekeeperAssessment = "includeGatekeeperAssessment"
        static let checkCertificateRevocation = "checkCertificateRevocation"
        static let autoScanOnDrop = "autoScanOnDrop"
        static let revealAfterExport = "revealAfterExport"
        static let redactSharedDiagnostics = "redactSharedDiagnostics"
        static let recentBundles = "recentBundles"
        static let recentVerdicts = "recentVerdicts"
        static let checkUpdatesAtLaunch = "checkUpdatesAtLaunch"
        static let updateConsentAsked = "updateConsentAsked"
        static let customShortcuts = "customShortcuts"
        static let aiSuggestions = "aiSuggestions"
        static let aiProvider = "aiProvider"
        static let aiOllamaModel = "aiOllamaModel"
        static let aiLMStudioModel = "aiLMStudioModel"
        static let aiAutomaticOrder = "aiAutomaticOrder"
        static let aiAutomaticOff = "aiAutomaticOff"
        static let all = [
            language, appearance, deepFrameworkSignatureCheck, extractTargetStrings,
            includeGatekeeperAssessment, checkCertificateRevocation, autoScanOnDrop, revealAfterExport,
            redactSharedDiagnostics, recentBundles,
            recentVerdicts, checkUpdatesAtLaunch, updateConsentAsked, customShortcuts,
            aiSuggestions, aiProvider, aiOllamaModel, aiLMStudioModel,
            aiAutomaticOrder, aiAutomaticOff,
        ]
    }

    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored public let strings: StringTable

    public var language: AppLanguage {
        didSet {
            defaults.set(language.rawValue, forKey: Key.language)
            applySystemLanguage()
        }
    }
    public var appearance: AppAppearance {
        didSet {
            defaults.set(appearance.rawValue, forKey: Key.appearance)
            applyAppearance()
        }
    }
    public var deepFrameworkSignatureCheck: Bool {
        didSet { defaults.set(deepFrameworkSignatureCheck, forKey: Key.deepFrameworkSignatureCheck) }
    }
    public var extractTargetStrings: Bool {
        didSet { defaults.set(extractTargetStrings, forKey: Key.extractTargetStrings) }
    }
    public var includeGatekeeperAssessment: Bool {
        didSet { defaults.set(includeGatekeeperAssessment, forKey: Key.includeGatekeeperAssessment) }
    }
    public var checkCertificateRevocation: Bool {
        didSet { defaults.set(checkCertificateRevocation, forKey: Key.checkCertificateRevocation) }
    }
    public var autoScanOnDrop: Bool {
        didSet { defaults.set(autoScanOnDrop, forKey: Key.autoScanOnDrop) }
    }
    public var revealAfterExport: Bool {
        didSet { defaults.set(revealAfterExport, forKey: Key.revealAfterExport) }
    }
    public var redactSharedDiagnostics: Bool {
        didSet { defaults.set(redactSharedDiagnostics, forKey: Key.redactSharedDiagnostics) }
    }
    public var recentBundles: [String] {
        didSet { defaults.set(recentBundles, forKey: Key.recentBundles) }
    }
    public var recentVerdicts: [String: String] {
        didSet { defaults.set(recentVerdicts, forKey: Key.recentVerdicts) }
    }
    public var checkUpdatesAtLaunch: Bool {
        didSet { defaults.set(checkUpdatesAtLaunch, forKey: Key.checkUpdatesAtLaunch) }
    }
    public var updateConsentAsked: Bool {
        didSet { defaults.set(updateConsentAsked, forKey: Key.updateConsentAsked) }
    }
    public var customShortcuts: [String: KeyboardShortcutData] {
        didSet {
            if let data = try? JSONEncoder().encode(customShortcuts) {
                defaults.set(data, forKey: Key.customShortcuts)
            }
        }
    }
    public var aiSuggestions: Bool {
        didSet { defaults.set(aiSuggestions, forKey: Key.aiSuggestions) }
    }
    public var aiProvider: SuggestionProvider {
        didSet { defaults.set(aiProvider.rawValue, forKey: Key.aiProvider) }
    }
    public var aiAutomaticOrder: [SuggestionProvider] {
        didSet { defaults.set(aiAutomaticOrder.map(\.rawValue), forKey: Key.aiAutomaticOrder) }
    }
    public var aiAutomaticOff: Set<SuggestionProvider> {
        didSet { defaults.set(aiAutomaticOff.map(\.rawValue).sorted(), forKey: Key.aiAutomaticOff) }
    }
    public var aiOllamaModel: String {
        didSet { defaults.set(aiOllamaModel, forKey: Key.aiOllamaModel) }
    }
    public var aiLMStudioModel: String {
        didSet { defaults.set(aiLMStudioModel, forKey: Key.aiLMStudioModel) }
    }

    public var automaticProviders: [SuggestionProvider] {
        aiAutomaticOrder.filter { !aiAutomaticOff.contains($0) }
    }

    public var activeProviders: [SuggestionProvider] {
        aiProvider == .automatic ? automaticProviders : [aiProvider]
    }

    public func aiModel(for server: LocalModelServer) -> String {
        server == .ollama ? aiOllamaModel : aiLMStudioModel
    }

    public func setAIModel(_ name: String, for server: LocalModelServer) {
        if server == .ollama { aiOllamaModel = name } else { aiLMStudioModel = name }
    }

    public init(defaults: UserDefaults = .standard, bundle: Bundle = .main) {
        self.defaults = defaults
        strings = StringTable(bundle: bundle)
        language = AppLanguage(rawValue: defaults.string(forKey: Key.language) ?? "") ?? .tr
        appearance = AppAppearance(rawValue: defaults.string(forKey: Key.appearance) ?? "") ?? .system
        deepFrameworkSignatureCheck = defaults.object(forKey: Key.deepFrameworkSignatureCheck) as? Bool ?? true
        extractTargetStrings = defaults.object(forKey: Key.extractTargetStrings) as? Bool ?? true
        includeGatekeeperAssessment = defaults.object(forKey: Key.includeGatekeeperAssessment) as? Bool ?? false
        checkCertificateRevocation = defaults.object(forKey: Key.checkCertificateRevocation) as? Bool ?? false
        autoScanOnDrop = defaults.object(forKey: Key.autoScanOnDrop) as? Bool ?? true
        revealAfterExport = defaults.object(forKey: Key.revealAfterExport) as? Bool ?? true
        redactSharedDiagnostics = defaults.object(forKey: Key.redactSharedDiagnostics) as? Bool ?? false
        recentBundles = defaults.stringArray(forKey: Key.recentBundles) ?? []
        recentVerdicts = (defaults.dictionary(forKey: Key.recentVerdicts) as? [String: String]) ?? [:]
        checkUpdatesAtLaunch = defaults.object(forKey: Key.checkUpdatesAtLaunch) as? Bool ?? false
        updateConsentAsked = defaults.object(forKey: Key.updateConsentAsked) as? Bool ?? false
        aiSuggestions = defaults.object(forKey: Key.aiSuggestions) as? Bool ?? true
        aiProvider = SuggestionProvider(rawValue: defaults.string(forKey: Key.aiProvider) ?? "") ?? .apple
        aiAutomaticOrder = SuggestionProvider.order(defaults.stringArray(forKey: Key.aiAutomaticOrder) ?? [])
        aiAutomaticOff = Set((defaults.stringArray(forKey: Key.aiAutomaticOff) ?? []).compactMap(SuggestionProvider.init(rawValue:)))
        aiOllamaModel = defaults.string(forKey: Key.aiOllamaModel) ?? ""
        aiLMStudioModel = defaults.string(forKey: Key.aiLMStudioModel) ?? ""
        if let data = defaults.data(forKey: Key.customShortcuts),
           let decoded = try? JSONDecoder().decode([String: KeyboardShortcutData].self, from: data) {
            customShortcuts = decoded
        } else {
            customShortcuts = [:]
        }
    }

    public var scanOptions: ScanOptions {
        ScanOptions(
            deepFrameworkSignatureCheck: deepFrameworkSignatureCheck,
            extractTargetStrings: extractTargetStrings,
            includeGatekeeperAssessment: includeGatekeeperAssessment,
            checkCertificateRevocation: checkCertificateRevocation,
            checkApplicationFirewall: true,
            policyLanguages: [languageCode, "en"]
        )
    }

    public func noteOpened(_ url: URL, verdict: IntegrityVerdict? = nil) {
        let path = url.standardizedFileURL.path
        var items = recentBundles.filter { $0 != path }
        items.insert(path, at: 0)
        recentBundles = Array(items.prefix(Self.maxRecentBundles))
        if let verdict {
            var map = recentVerdicts
            map[path] = verdict.rawValue
            recentVerdicts = map
        }
    }

    public func verdict(for url: URL) -> IntegrityVerdict? {
        guard let raw = recentVerdicts[url.standardizedFileURL.path] else { return nil }
        return IntegrityVerdict(rawValue: raw)
    }

    public func removeRecent(_ url: URL) {
        let path = url.standardizedFileURL.path
        recentBundles.removeAll { $0 == path }
        var map = recentVerdicts
        map.removeValue(forKey: path)
        recentVerdicts = map
    }

    public func clearRecents() {
        recentBundles = []
        recentVerdicts = [:]
    }

    public var existingRecentBundles: [URL] {
        recentBundles
            .filter { FileManager.default.fileExists(atPath: $0) }
            .map { URL(fileURLWithPath: $0) }
    }

    public func resetAll() {
        language = .tr
        appearance = .system
        deepFrameworkSignatureCheck = true
        extractTargetStrings = true
        includeGatekeeperAssessment = false
        checkCertificateRevocation = false
        autoScanOnDrop = true
        revealAfterExport = true
        recentBundles = []
        recentVerdicts = [:]
        checkUpdatesAtLaunch = false
        updateConsentAsked = false
        aiSuggestions = true
        aiProvider = .apple
        aiAutomaticOrder = SuggestionProvider.models
        aiAutomaticOff = []
        aiOllamaModel = ""
        aiLMStudioModel = ""
        customShortcuts = [:]
        Key.all.forEach(defaults.removeObject(forKey:))
        defaults.removeObject(forKey: "AppleLanguages")
    }

    // MARK: - Kısayollar

    public func shortcut(for action: ShortcutAction) -> KeyboardShortcutData {
        customShortcuts[action.rawValue] ?? action.defaultShortcut
    }

    public func setShortcut(_ shortcut: KeyboardShortcutData, for action: ShortcutAction) {
        if shortcut == action.defaultShortcut {
            customShortcuts.removeValue(forKey: action.rawValue)
        } else {
            customShortcuts[action.rawValue] = shortcut
        }
    }

    public func resetShortcut(for action: ShortcutAction) {
        customShortcuts.removeValue(forKey: action.rawValue)
    }

    public func resetAllShortcuts() {
        customShortcuts = [:]
    }

    public enum ShortcutConflict: Equatable, Sendable {
        case customAction(ShortcutAction)
        case systemShortcut(LKey)
    }

    public static let reservedSystemShortcuts: [(titleKey: LKey, shortcut: KeyboardShortcutData)] = [
        (.tabOverview, KeyboardShortcutData(key: "1", command: true)),
        (.tabDylibs, KeyboardShortcutData(key: "2", command: true)),
        (.tabSymbols, KeyboardShortcutData(key: "3", command: true)),
        (.tabRaw, KeyboardShortcutData(key: "4", command: true)),
        (.actionRemoveQuarantine, KeyboardShortcutData(key: "K", command: true)),
        (.menuShowLog, KeyboardShortcutData(key: "L", command: true, option: true)),
        (.menuBatchScan, KeyboardShortcutData(key: "B", command: true, option: true)),
        (.menuSaveJSONReport, KeyboardShortcutData(key: "S", command: true, option: true)),
        (.menuCompareMode, KeyboardShortcutData(key: "D", command: true, shift: true)),
        (.menuRunningProcesses, KeyboardShortcutData(key: "P", command: true, option: true)),
        (.menuPersistenceAudit, KeyboardShortcutData(key: "T", command: true, option: true)),
    ]

    public func shortcutConflict(for candidate: KeyboardShortcutData, editingAction: ShortcutAction) -> ShortcutConflict? {
        if let action = ShortcutAction.allCases.first(where: { $0 != editingAction && shortcut(for: $0) == candidate }) {
            return .customAction(action)
        }
        if let reserved = Self.reservedSystemShortcuts.first(where: { $0.shortcut == candidate }) {
            return .systemShortcut(reserved.titleKey)
        }
        return nil
    }

    public var isAllShortcutsDefault: Bool {
        ShortcutAction.allCases.allSatisfy { isDefaultShortcut(for: $0) }
    }

    public func isDefaultShortcut(for action: ShortcutAction) -> Bool {
        customShortcuts[action.rawValue] == nil || customShortcuts[action.rawValue] == action.defaultShortcut
    }

    // MARK: - Görünüm ve Dil

    public func applyAppearance() {
        NSApp?.appearance = appearance.nsAppearance
    }

    private func applySystemLanguage() {
        if language == .system {
            defaults.removeObject(forKey: "AppleLanguages")
        } else {
            defaults.set([language.rawValue], forKey: "AppleLanguages")
        }
    }

    public var languageCode: String { language.resolvedCode() }
    public var locale: Locale { Locale(identifier: languageCode) }

    public func t(_ key: LKey) -> String {
        strings.string(key, language: languageCode)
    }

    public func t(_ key: LKey, _ arguments: any CVarArg...) -> String {
        String(format: t(key), locale: locale, arguments: arguments)
    }

    public func checkText(_ check: AIPrerequisites.Check) -> String {
        let name = check.provider.displayName
        guard let problem = check.problem else {
            if let model = check.model, !model.isEmpty {
                return t(.aiCheckReadyModel, name, model)
            }
            return t(.aiCheckReady, name)
        }
        switch problem {
        case .deviceNotEligible:
            return t(.aiCheckDeviceNotEligible)
        case .appleIntelligenceOff:
            return t(.aiCheckAppleOff)
        case .modelNotReady:
            return t(.aiCheckModelNotReady)
        case .appleUnavailable:
            return t(.aiCheckAppleUnavailable)
        case .serverNotRunning:
            let port = check.provider.server?.port ?? 11434
            return t(.aiCheckServerOff, name, port)
        case .noLocalModel:
            return t(.aiCheckNoModel, name)
        case .modelMissing(let missing):
            return t(.aiCheckModelMissing, name, missing)
        case .noAnswer:
            return t(.aiCheckNoAnswer, name)
        }
    }
}
