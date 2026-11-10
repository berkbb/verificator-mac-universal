// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import Foundation
import VerificatorCore
import Observation
import UniformTypeIdentifiers

@Observable
public final class AppModel {
    public static let shared = AppModel()

    public enum AppUpdateState: Equatable {
        case idle
        case checking
        case available(AppRelease)
        case upToDate
        case noReleases
        case failed(String)
    }

    public var currentBundleURL: URL?
    public var report: BundleAuditReport?
    public var cachedReports: [String: BundleAuditReport] = [:]
    public var isScanning = false
    public var selectedTab = 0
    public var copiedFeedback = false
    public var toolStatuses: [ToolStatus] = ForensicScanner.inspectTools()
    public var appUpdateState: AppUpdateState = .idle

    // MARK: - Cihaz üstü / yerel yapay zekâ durumu (Apple Intelligence, Ollama, LM Studio)
    public var localModels: [LocalModelServer: [String]] = [:]
    public var runningServers: Set<LocalModelServer> = []
    public var aiChecks: [AIPrerequisites.Check] = []
    public var isCheckingAI = false
    public var suggestionModel: any SuggestionModel = OnDeviceSuggestionModel()
    public var aiSummaries: [String: (text: String, source: String)] = [:]
    public var isGeneratingAISummary = false
    public var aiSummaryError: String?
    public var isRemovingQuarantine = false
    public var quarantineFeedback: (text: String, isSuccess: Bool)?
    @ObservationIgnored public var appleProblem: () -> AIPrerequisites.Problem? = AIPrerequisites.appleProblem
    @ObservationIgnored public var appleTestModel: any SuggestionModel = OnDeviceSuggestionModel()
    @ObservationIgnored public var localServerPorts: [LocalModelServer: Int] = [:]

    @ObservationIgnored private let settings: AppSettings

    public init(settings: AppSettings = .shared) {
        self.settings = settings
        updateSuggestionModel()
    }

    public func launch() async {
        settings.applyAppearance()
        refreshTools()
        AppLog.shared.info(.app, "Verificator \(AppInfo.version) (\(AppInfo.build)) launched")
        if settings.aiSuggestions {
            await refreshLocalModels()
        }
        if settings.checkUpdatesAtLaunch {
            await checkForAppUpdate(interactive: false)
        }
    }

    public func refreshTools() {
        toolStatuses = ForensicScanner.inspectTools()
    }

    public func resolveAppBundleURL(from url: URL) -> URL {
        var current = url
        while current.path != "/" {
            if current.pathExtension.lowercased() == "app" {
                return current
            }
            current.deleteLastPathComponent()
        }
        return url
    }

    public func presentOpenPanel() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = false
        panel.allowedContentTypes = [.applicationBundle]
        if panel.runModal() == .OK, let url = panel.url {
            scan(resolveAppBundleURL(from: url))
        }
    }

    public func scan(_ url: URL, forceRescan: Bool = false) {
        let resolved = resolveAppBundleURL(from: url).standardizedFileURL
        currentBundleURL = resolved
        if !forceRescan, let cached = cachedReports[resolved.path] {
            report = cached
            settings.noteOpened(resolved, verdict: cached.verdict)
            return
        }
        settings.noteOpened(resolved)
        isScanning = true
        let opts = settings.scanOptions
        Task.detached {
            let result = ForensicScanner.auditBundle(at: resolved, options: opts)
            await MainActor.run {
                self.cachedReports[resolved.path] = result
                self.settings.noteOpened(resolved, verdict: result.verdict)
                self.report = result
                self.isScanning = false
            }
        }
    }

    /// Mevcut açık olan .app paketini yeniden tarar (Refresh / ⌘R).
    public func refreshCurrentBundle() {
        guard !isScanning, let url = currentBundleURL else { return }
        AppLog.shared.info(.scanner, "Refreshing forensic audit for \(url.lastPathComponent)")
        scan(url, forceRescan: true)
    }

    public func clearReport() {
        report = nil
        currentBundleURL = nil
    }

    public func revealCurrentBundle() {
        guard let url = currentBundleURL else { return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    public func markdownReport(for r: BundleAuditReport) -> String {
        var md = "# \(settings.t(.appTitle))\n\n"
        md += "- **\(settings.t(.fieldBundleName)):** `\(r.bundleName)`\n"
        md += "- **\(settings.t(.fieldBundleId)):** `\(r.bundleId)`\n"
        md += "- **\(settings.t(.fieldVersion)):** `\(r.shortVersion) (\(r.buildVersion))`\n"
        md += "- **\(settings.t(.fieldTeamId)):** `\(r.teamIdentifier)`\n"
        md += "- **\(settings.t(.fieldAuthorities)):** `\(r.authorities.joined(separator: " -> "))`\n"
        md += "- **\(settings.t(.fieldSignedTime)):** `\(r.signedTimestamp)`\n"
        md += "- **\(settings.t(.fieldHardenedRuntime)):** `\(r.hasHardenedRuntime)`\n"
        md += "- **\(settings.t(.fieldNotarized)):** `\(r.isNotarized)`\n"
        md += "- **\(settings.t(.fieldScanDuration)):** `\(r.scanDurationMs) ms`\n\n"
        md += "## \(settings.t(.sectionAnomalies))\n"
        for f in r.findings {
            md += "- **\(settings.t(f.titleKey))**: \(settings.t(f.descKey))\(f.detailSuffix)\n"
        }
        return md
    }

    public func copyMarkdownReport() {
        guard let r = report else { return }
        let md = markdownReport(for: r)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(md, forType: .string)
        copiedFeedback = true
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            copiedFeedback = false
        }
    }

    public func saveMarkdownReport() {
        guard let r = report else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.plainText]
        panel.nameFieldStringValue = "\(r.bundleName)-Forensic-Report.md"
        if panel.runModal() == .OK, let url = panel.url {
            let md = markdownReport(for: r)
            try? Data(md.utf8).write(to: url, options: .atomic)
            if settings.revealAfterExport {
                NSWorkspace.shared.activateFileViewerSelecting([url])
            }
        }
    }

    public func checkForAppUpdate(interactive: Bool) async {
        guard appUpdateState != .checking else { return }
        appUpdateState = .checking
        do {
            let release = try await AppUpdateChecker.latest(repository: AppInfo.repository)
            if AppUpdateChecker.isNewer(release.version, than: AppInfo.version) {
                appUpdateState = .available(release)
                AppLog.shared.info(.update, "Update available: \(release.version)")
            } else {
                appUpdateState = .upToDate
                AppLog.shared.info(.update, "App is up to date (\(AppInfo.version))")
            }
        } catch AppUpdateChecker.CheckError.noReleases {
            appUpdateState = .noReleases
            AppLog.shared.info(.update, "No GitHub releases published yet for \(AppInfo.repository)")
        } catch {
            appUpdateState = .failed(error.localizedDescription)
            if interactive {
                AppLog.shared.warning(.update, "Update check failed", detail: error.localizedDescription)
            }
        }
    }

    public func openAppDownload() {
        guard case .available(let release) = appUpdateState else { return }
        NSWorkspace.shared.open(release.downloadURL ?? release.pageURL)
    }

    // MARK: - Yapay Zekâ (Apple Intelligence, Ollama, LM Studio)

    @discardableResult
    public func setAISuggestions(_ on: Bool) async -> Bool {
        guard on else {
            settings.aiSuggestions = false
            aiChecks = []
            return false
        }
        let ready = await checkAIPrerequisites()
        settings.aiSuggestions = ready
        return ready
    }

    @discardableResult
    public func checkAIPrerequisites() async -> Bool {
        isCheckingAI = true
        defer { isCheckingAI = false }
        var checks: [AIPrerequisites.Check] = []
        for provider in settings.activeProviders {
            if let server = provider.server {
                let check = await AIPrerequisites.checkServer(
                    server,
                    selected: settings.aiModel(for: server),
                    port: localServerPorts[server]
                )
                if let name = check.model, settings.aiModel(for: server).isEmpty {
                    settings.setAIModel(name, for: server)
                }
                checks.append(check)
            } else {
                checks.append(await AIPrerequisites.checkApple(problem: appleProblem(), model: appleTestModel))
            }
        }
        aiChecks = checks
        await refreshLocalModels()
        updateSuggestionModel()
        return checks.contains(where: \.isReady)
    }

    public func refreshLocalModels() async {
        let servers = settings.activeProviders.compactMap(\.server)
        guard !servers.isEmpty else { return }
        for server in servers {
            if let found = await server.models(port: localServerPorts[server]) {
                runningServers.insert(server)
                localModels[server] = found
                if settings.aiModel(for: server).isEmpty, let first = found.first {
                    settings.setAIModel(first, for: server)
                }
            } else {
                runningServers.remove(server)
                localModels[server] = []
            }
        }
        updateSuggestionModel()
    }

    public func updateSuggestionModel() {
        if settings.aiProvider == .automatic {
            suggestionModel = FallbackSuggestionModel(
                settings.automaticProviders.map { (name: sourceName(for: $0), model: model(for: $0)) }
            )
        } else {
            suggestionModel = model(for: settings.aiProvider)
        }
    }

    private func model(for provider: SuggestionProvider) -> any SuggestionModel {
        guard let server = provider.server else { return OnDeviceSuggestionModel() }
        let name = settings.aiModel(for: server)
        return LocalServerSuggestionModel(
            server: server,
            model: name,
            isAvailable: localModels[server]?.contains(name) == true,
            port: localServerPorts[server]
        )
    }

    public func isReady(_ provider: SuggestionProvider) -> Bool {
        model(for: provider).isAvailable
    }

    public func sourceName(for provider: SuggestionProvider) -> String {
        guard let server = provider.server, !settings.aiModel(for: server).isEmpty else { return provider.displayName }
        return provider.displayName + " · " + settings.aiModel(for: server)
    }

    public var suggestionSourceName: String {
        guard settings.aiProvider == .automatic else { return sourceName(for: settings.aiProvider) }
        return (suggestionModel as? FallbackSuggestionModel)?.lastSource ?? settings.t(.settingsAIAutomatic)
    }

    /// Seçili sağlayıcı hazır değilse turuncu uyarı metnini döndürür (sessiz geçiş yok).
    public func currentProviderWarning() -> String? {
        if settings.aiProvider != .automatic {
            let selectedModel = settings.aiProvider.server.map { settings.aiModel(for: $0) } ?? ""
            if let problem = AIPrerequisites.providerProblem(
                for: settings.aiProvider,
                appleProblem: appleProblem(),
                runningServers: runningServers,
                localModels: localModels,
                selectedModel: selectedModel
            ) {
                return settings.checkText(AIPrerequisites.Check(provider: settings.aiProvider, problem: problem))
            }
            return nil
        }

        // Otomatik kipte en az bir sağlayıcı hazırsa uyarı gösterilmez; hiçbiri hazır değilse ilk sağlayıcının sorunu gösterilir.
        let candidates = settings.automaticProviders
        guard !candidates.isEmpty else { return settings.t(.settingsAINotEnabled) }
        if candidates.contains(where: { isReady($0) }) {
            return nil
        }
        if let first = candidates.first {
            let selectedModel = first.server.map { settings.aiModel(for: $0) } ?? ""
            if let problem = AIPrerequisites.providerProblem(
                for: first,
                appleProblem: appleProblem(),
                runningServers: runningServers,
                localModels: localModels,
                selectedModel: selectedModel
            ) {
                return settings.checkText(AIPrerequisites.Check(provider: first, problem: problem))
            }
        }
        return settings.t(.settingsAINotEnabled)
    }

    public func generateAISummary(for report: BundleAuditReport) async {
        guard !isGeneratingAISummary else { return }
        isGeneratingAISummary = true
        aiSummaryError = nil
        defer { isGeneratingAISummary = false }

        await refreshLocalModels()

        // Sessiz geçiş yok: seçilen sağlayıcı hazır değilse uyarır ve bekler.
        if let warning = currentProviderWarning() {
            aiSummaryError = warning
            return
        }

        if let text = await ForensicAI.summarize(
            report: report,
            languageCode: settings.languageCode,
            model: suggestionModel
        ) {
            aiSummaries[report.bundlePath] = (text: text, source: suggestionSourceName)
            AppLog.shared.info(.scanner, "AI forensic summary generated for \(report.bundleName) via \(suggestionSourceName)")
        } else {
            aiSummaryError = currentProviderWarning() ?? settings.t(.aiForensicUnavailable)
        }
    }

    /// Touch ID veya yönetici parolası ile `sudo xattr -rd com.apple.quarantine` çalıştırır ve raporu yeniler.
    public func removeQuarantineForCurrentBundle() {
        guard !isRemovingQuarantine, let url = currentBundleURL else { return }
        isRemovingQuarantine = true
        quarantineFeedback = nil
        let path = url.path
        Task.detached {
            let result = ForensicScanner.removeQuarantineWithAdminPrivileges(at: path)
            await MainActor.run {
                self.isRemovingQuarantine = false
                if result.success {
                    self.quarantineFeedback = (text: self.settings.t(.quarantineRemovedSuccess), isSuccess: true)
                    self.scan(url, forceRescan: true)
                } else {
                    self.quarantineFeedback = (text: self.settings.t(.quarantineRemovedFailed), isSuccess: false)
                }
            }
        }
    }
}
