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

    public enum UpdateDownloadState: Equatable {
        case idle
        case downloading
        case verified(VerifiedUpdateResult)
        case failed(String)
    }

    public enum AuditWorkspaceMode: String, Sendable, Equatable, CaseIterable {
        case single
        case batch
        case diff
        case runningProcesses
        case persistence
    }

    public var workspaceMode: AuditWorkspaceMode = .single
    public var currentBundleURL: URL?
    public var report: BundleAuditReport?
    public var cachedReports: [String: BundleAuditReport] = [:]
    public var isScanning = false
    public var selectedTab = 0
    public var copiedFeedback = false
    public var toolStatuses: [ToolStatus] = ForensicScanner.inspectTools()
    public var appUpdateState: AppUpdateState = .idle
    public var updateDownloadState: UpdateDownloadState = .idle

    // MARK: - Toplu Klasör Denetimi
    public var isBatchMode: Bool {
        get { workspaceMode == .batch }
        set {
            if newValue {
                workspaceMode = .batch
            } else if workspaceMode == .batch {
                workspaceMode = .single
            }
        }
    }
    public var isBatchScanning = false
    public var batchProgress: (current: Int, total: Int, name: String) = (0, 0, "")
    public var batchSummary: BatchAuditSummary?

    // MARK: - Adli Karşılaştırma (Diff)
    public var diffBaselineURL: URL?
    public var diffTargetURL: URL?
    public var diffBaselineEndpoint: AuditDiffEndpoint?
    public var diffTargetEndpoint: AuditDiffEndpoint?
    public var currentDiff: AuditReportDiff?
    public var isComparingDiff = false
    public var diffError: String?

    // MARK: - Çalışan Süreçler & Sistem Kalıcılığı Denetimi
    public var runningSummary: RunningProcessesAuditSummary?
    public var isScanningRunning = false
    public var runningProgress: (current: Int, total: Int, name: String) = (0, 0, "")
    public var persistenceSummary: PersistenceAuditSummary?
    public var isScanningPersistence = false
    public var persistenceProgress: (current: Int, total: Int, name: String) = (0, 0, "")

    // MARK: - İsteğe bağlı Gatekeeper (spctl) & Karantina & İmza Geçmişi
    public var isAssessingGatekeeper = false
    public var isRemovingQuarantine = false
    public var quarantineFeedback: (text: String, isSuccess: Bool)?
    public var gatekeeperStatus: GatekeeperStatus = .unknown
    public var firewallStatus: FirewallStatus?
    public var bootVolumeEncryption: VolumeEncryptionInfo?
    public var isFullDiskAccessGranted: Bool = FullDiskAccess.isGranted
    public var signatureChange: SignatureBaselineChange?
    public var expectedChecksumInput = ""

    public enum ChecksumUIEvaluation: Equatable, Sendable {
        case empty
        case matched(ChecksumAlgorithm)
        case mismatch(ChecksumAlgorithm)
        case weakAlgorithm(String)
        case notFoundForFile(String)
        case unrecognized
        case unavailable(ChecksumAlgorithm)
    }

    // MARK: - Cihaz üstü / yerel yapay zekâ durumu (Apple Intelligence, Ollama, LM Studio)
    public var localModels: [LocalModelServer: [String]] = [:]
    public var runningServers: Set<LocalModelServer> = []
    public var aiChecks: [AIPrerequisites.Check] = []
    public var isCheckingAI = false
    public var suggestionModel: any SuggestionModel = OnDeviceSuggestionModel()
    public var aiSummaries: [String: (text: String, source: String)] = [:]
    public var isGeneratingAISummary = false
    public var aiSummaryError: String?

    @ObservationIgnored public var appleProblem: () -> AIPrerequisites.Problem? = AIPrerequisites.appleProblem
    @ObservationIgnored public var appleTestModel: any SuggestionModel = OnDeviceSuggestionModel()
    @ObservationIgnored public var localServerPorts: [LocalModelServer: Int] = [:]
    @ObservationIgnored private var activeUpdateCheckTask: Task<AppUpdateState, Never>?
    @ObservationIgnored private var activeScanTask: Task<Void, Never>?
    @ObservationIgnored private var activeScanToken: ScanCancellationToken?
    @ObservationIgnored private var scanGeneration = UUID()
    @ObservationIgnored private var activeBatchTask: Task<Void, Never>?
    @ObservationIgnored private var activeBatchToken: ScanCancellationToken?
    @ObservationIgnored private var activeDiffTask: Task<Void, Never>?
    @ObservationIgnored private var activeDiffToken: ScanCancellationToken?
    @ObservationIgnored private var activeRunningTask: Task<Void, Never>?
    @ObservationIgnored private var activeRunningToken: ScanCancellationToken?
    @ObservationIgnored private var activePersistenceTask: Task<Void, Never>?
    @ObservationIgnored private var activePersistenceToken: ScanCancellationToken?
    @ObservationIgnored private var activeAITask: Task<Void, Never>?

    @ObservationIgnored private let settings: AppSettings
    @ObservationIgnored private let signatureStore: SignatureTrackerStore
    @ObservationIgnored private var signatureTracker: SignatureTracker
    @ObservationIgnored private let dockProgress = DockProgress()

    public init(
        settings: AppSettings = .shared,
        signatureStore: SignatureTrackerStore = SignatureTrackerStore()
    ) {
        self.settings = settings
        self.signatureStore = signatureStore
        self.signatureTracker = signatureStore.load()
        updateSuggestionModel()
    }

    public func launch() async {
        settings.applyAppearance()
        refreshTools()
        refreshSystemSecurityStatus()
        AppLog.shared.info(.app, "Verificator \(AppInfo.version) (\(AppInfo.build)) launched")
        if settings.aiSuggestions {
            await refreshLocalModels()
        }
        if settings.checkUpdatesAtLaunch {
            await checkForAppUpdate(interactive: false)
        }
    }

    public func refreshSystemSecurityStatus() {
        isFullDiskAccessGranted = FullDiskAccess.isGranted
        Task.detached { [weak self] in
            let status = GatekeeperStatus.read()
            let fwStatus = ApplicationFirewall.readSystemStatus()
            let bootEnc = VolumeEncryptionInfo.readBootVolume()
            await MainActor.run {
                self?.gatekeeperStatus = status
                self?.firewallStatus = fwStatus
                self?.bootVolumeEncryption = bootEnc
            }
        }
    }

    public func evaluateExpectedChecksum(for report: BundleAuditReport) -> ChecksumUIEvaluation {
        let targetName = URL(fileURLWithPath: report.bundlePath).lastPathComponent
        switch ChecksumInput.parse(expectedChecksumInput, fileName: targetName) {
        case .empty:
            return .empty
        case .weakAlgorithm(let algo):
            return .weakAlgorithm(algo)
        case .notFoundForFile(let name):
            return .notFoundForFile(name)
        case .unrecognized:
            return .unrecognized
        case .parsed(let expected):
            switch expected.verify(actualSHA256: report.executableSHA256, actualSHA512: report.executableSHA512) {
            case .matched(let exp, _):
                return .matched(exp.algorithm)
            case .mismatch(let exp, _):
                return .mismatch(exp.algorithm)
            case .unavailable(let exp):
                return .unavailable(exp.algorithm)
            }
        }
    }

    public func presentChecksumFilePanel() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url,
           let content = try? String(contentsOf: url, encoding: .utf8) {
            expectedChecksumInput = content
        }
    }

    public func clearExpectedChecksum() {
        expectedChecksumInput = ""
    }

    public func copyUnblockFirewallCommand(for path: String) {
        copyTextToClipboard(ApplicationFirewall.unblockCommand(for: path))
    }

    public func observeSignatureBaseline(for report: BundleAuditReport, emitBanner: Bool = true) {
        let change = signatureTracker.observe(report: report)
        if emitBanner {
            signatureChange = change
        }
        try? signatureStore.save(signatureTracker)
    }

    public func acknowledgeSignatureBaselineChange() {
        guard let report else {
            signatureChange = nil
            return
        }
        signatureTracker.acceptBaseline(for: report)
        try? signatureStore.save(signatureTracker)
        signatureChange = nil
    }

    public func refreshTools() {
        toolStatuses = ForensicScanner.inspectTools()
    }

    public static var supportedOpenContentTypes: [UTType] {
        var types: [UTType] = [.applicationBundle, .framework, .bundle, .unixExecutable]
        for ext in ["pkg", "mpkg", "dmg", "plugin", "appex", "xpc", "kext", "dylib", "so"] {
            if let ut = UTType(filenameExtension: ext) {
                types.append(ut)
            }
        }
        return types
    }

    public func resolveAppBundleURL(from url: URL) -> URL {
        resolveAuditTargetURL(from: url)
    }

    public func resolveAuditTargetURL(from url: URL) -> URL {
        let standardized = url.standardizedFileURL
        if ForensicScanner.isSupportedAuditURL(standardized) {
            return standardized
        }
        var current = standardized
        while current.path != "/" {
            if ForensicScanner.supportedBundleExtensions.contains(current.pathExtension.lowercased()) {
                return current
            }
            current.deleteLastPathComponent()
        }
        return standardized
    }

    public func isSupportedBundleURL(_ url: URL) -> Bool {
        ForensicScanner.isSupportedAuditURL(resolveAuditTargetURL(from: url))
    }

    public func presentOpenPanel() {
        let panel = NSOpenPanel()
        panel.message = settings.t(.openPanelMessageExpanded)
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = false
        panel.allowedContentTypes = Self.supportedOpenContentTypes
        if panel.runModal() == .OK, let url = panel.url {
            scan(resolveAuditTargetURL(from: url))
        }
    }

    public func scan(_ url: URL, forceRescan: Bool = false) {
        let resolved = resolveAuditTargetURL(from: url).standardizedFileURL
        guard ForensicScanner.isSupportedAuditURL(resolved) else {
            AppLog.shared.warning(.scanner, "Ignored unsupported item", detail: url.path)
            return
        }
        cancelCurrentScan(clearBundleSelection: false)
        workspaceMode = .single
        let generation = UUID()
        scanGeneration = generation

        if currentBundleURL != resolved {
            quarantineFeedback = nil
            aiSummaryError = nil
            signatureChange = nil
            expectedChecksumInput = ""
        }
        currentBundleURL = resolved
        if !forceRescan, let cached = cachedReports[resolved.path] {
            let execPath: String?
            if cached.targetKind == .appBundle || cached.targetKind == .nestedBundle {
                execPath = URL(fileURLWithPath: cached.bundlePath)
                    .appendingPathComponent(cached.executableRelativePath)
                    .path
            } else {
                execPath = cached.bundlePath
            }
            let currentQuarantined = ForensicScanner.hasQuarantineAttribute(
                at: cached.bundlePath,
                executablePath: execPath
            )
            if currentQuarantined == cached.isQuarantined {
                report = cached
                isScanning = false
                settings.noteOpened(resolved, verdict: cached.verdict)
                return
            }
        }
        settings.noteOpened(resolved)
        isScanning = true
        let opts = settings.scanOptions
        let token = ScanCancellationToken()
        activeScanToken = token

        activeScanTask = Task.detached { [weak self] in
            let result = ForensicScanner.auditTarget(at: resolved, options: opts, cancellation: token)
            await MainActor.run {
                guard let self, !Task.isCancelled, !token.isCancelled, self.scanGeneration == generation else { return }
                self.cachedReports[resolved.path] = result
                self.settings.noteOpened(resolved, verdict: result.verdict)
                self.observeSignatureBaseline(for: result, emitBanner: true)
                self.report = result
                self.isScanning = false
                self.activeScanTask = nil
                self.activeScanToken = nil
            }
        }
    }

    public func cancelCurrentScan(clearBundleSelection: Bool = true) {
        activeScanToken?.cancel()
        activeScanToken = nil
        activeScanTask?.cancel()
        activeScanTask = nil
        scanGeneration = UUID()
        isScanning = false
        if clearBundleSelection && report == nil {
            currentBundleURL = nil
        }
    }

    /// Mevcut açık olan .app paketini yeniden tarar (Refresh / ⌘R).
    public func refreshCurrentBundle() {
        guard !isScanning, let url = currentBundleURL else { return }
        AppLog.shared.info(.scanner, "Refreshing forensic audit for \(url.lastPathComponent)")
        scan(url, forceRescan: true)
    }

    public func clearReport() {
        cancelCurrentScan(clearBundleSelection: true)
        cancelAISummary()
        workspaceMode = .single
        isAssessingGatekeeper = false
        report = nil
        currentBundleURL = nil
        quarantineFeedback = nil
        aiSummaryError = nil
        signatureChange = nil
        expectedChecksumInput = ""
    }

    public func clearAllHistory() {
        settings.clearRecents()
        cachedReports.removeAll()
    }

    public func resetAllSettings() {
        clearReport()
        cancelBatchScan()
        cancelRunningProcessesScan()
        cancelPersistenceScan()
        activeDiffToken?.cancel()
        activeDiffTask?.cancel()
        isComparingDiff = false
        currentDiff = nil
        diffBaselineURL = nil
        diffTargetURL = nil
        diffBaselineEndpoint = nil
        diffTargetEndpoint = nil
        diffError = nil
        batchSummary = nil
        runningSummary = nil
        persistenceSummary = nil
        cachedReports.removeAll()
        aiSummaries.removeAll()
        aiChecks = []
        updateDownloadState = .idle
        settings.resetAll()
        updateSuggestionModel()
        refreshTools()
    }

    public func revealCurrentBundle() {
        guard let url = currentBundleURL else { return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    /// Seçili paket için `/usr/sbin/spctl --assess` Gatekeeper politika değerlendirmesini isteğe bağlı ve asenkron olarak çalıştırır.
    public func runGatekeeperAssessment() {
        guard !isAssessingGatekeeper, let current = report else { return }
        isAssessingGatekeeper = true
        let targetPath = current.bundlePath
        Task.detached { [weak self] in
            let assessment = ForensicScanner.assessGatekeeper(at: targetPath)
            await MainActor.run {
                guard let self, var latest = self.report, latest.bundlePath == targetPath else {
                    self?.isAssessingGatekeeper = false
                    return
                }
                latest = latest.withSpctlAssessment(assessment.statusText)
                self.report = latest
                self.cachedReports[targetPath] = latest
                self.isAssessingGatekeeper = false
                AppLog.shared.info(.signature, "Gatekeeper policy assessed for \(latest.bundleName)", detail: assessment.statusText)
            }
        }
    }

    // MARK: - Toplu Klasör Taraması

    public func presentBatchFolderPanel() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = false
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        if panel.runModal() == .OK, let url = panel.url {
            startBatchScan(in: url)
        }
    }

    public func startBatchScan(in directoryURL: URL) {
        cancelBatchScan()
        isBatchMode = true
        isBatchScanning = true
        batchProgress = (0, 0, directoryURL.lastPathComponent)
        dockProgress.update(fraction: nil, active: true, enabled: true)
        let opts = settings.scanOptions
        let token = ScanCancellationToken()
        activeBatchToken = token

        final class WeakModelBox: @unchecked Sendable {
            @MainActor weak var value: AppModel?
            @MainActor init(_ value: AppModel) { self.value = value }
        }
        let weakBox = WeakModelBox(self)

        activeBatchTask = Task.detached {
            let summary = ForensicScanner.auditDirectory(
                at: directoryURL,
                options: opts,
                cancellation: token
            ) { index, total, currentName in
                Task { @MainActor in
                    guard let model = weakBox.value, !token.isCancelled else { return }
                    model.batchProgress = (index, total, currentName)
                    let fraction = total > 0 ? Double(index) / Double(total) : nil
                    model.dockProgress.update(fraction: fraction, active: true, enabled: true)
                }
            }

            await MainActor.run {
                guard let model = weakBox.value else { return }
                for item in summary.reports {
                    model.cachedReports[item.bundlePath] = item
                    model.observeSignatureBaseline(for: item, emitBanner: false)
                }
                model.batchSummary = summary
                model.isBatchScanning = false
                model.dockProgress.update(fraction: nil, active: false, enabled: true)
                model.activeBatchTask = nil
                model.activeBatchToken = nil
            }
        }
    }

    public func cancelBatchScan() {
        activeBatchToken?.cancel()
        activeBatchToken = nil
        activeBatchTask?.cancel()
        activeBatchTask = nil
        isBatchScanning = false
        dockProgress.update(fraction: nil, active: false, enabled: true)
    }

    public func openBatchReport(_ item: BundleAuditReport) {
        isBatchMode = false
        currentBundleURL = URL(fileURLWithPath: item.bundlePath)
        cachedReports[item.bundlePath] = item
        signatureChange = nil
        report = item
        settings.noteOpened(URL(fileURLWithPath: item.bundlePath), verdict: item.verdict)
    }

    // MARK: - Rapor Oluşturma & Dışa Aktarma

    public func markdownReport(for rawReport: BundleAuditReport, redacted: Bool? = nil) -> String {
        let useMask = redacted ?? settings.redactSharedDiagnostics
        let r = useMask ? rawReport.redacted(using: DiagnosticMasker()) : rawReport
        let verdictKey: LKey = switch r.verdict {
        case .clean: .verdictClean
        case .warning: .verdictWarning
        case .tampered: .verdictTampered
        }
        let teamText = r.teamIdentifier == "not set" ? settings.t(.valueNotSet) : r.teamIdentifier
        let authoritiesText = r.authorities.isEmpty ? "-" : r.authorities.joined(separator: " -> ")
        let architecturesText = r.architectures.isEmpty ? "-" : r.architectures.joined(separator: ", ")
        let entitlementsText = r.entitlements.isEmpty ? settings.t(.valueNone) : r.entitlements.joined(separator: ", ")
        let rpathsText = r.lcRpaths.isEmpty ? settings.t(.valueNone) : r.lcRpaths.joined(separator: ", ")
        let spctlText = r.spctlAssessment ?? settings.t(.valueNotChecked)

        var md = "# \(settings.t(.appTitle))\n\n"
        md += "- **\(settings.t(.reportVerdictLabel)):** `\(settings.t(verdictKey))`\n"
        md += "- **\(settings.t(.fieldTargetKind)):** `\(settings.t(r.targetKind.labelKey))`\n"
        md += "- **\(settings.t(.fieldBundleName)):** `\(OpenSafety.visibleName(r.bundleName))`\n"
        md += "- **\(settings.t(.fieldBundleId)):** `\(r.bundleId)`\n"
        md += "- **\(settings.t(.fieldVersion)):** `\(r.shortVersion) (\(r.buildVersion))`\n"
        md += "- **\(settings.t(.reportBundlePathLabel)):** `\(r.bundlePath)`\n"
        md += "- **\(settings.t(.fieldExecutable)):** `\(OpenSafety.visibleName(r.executableRelativePath))`\n"
        md += "- **\(settings.t(.fieldExecutableSha256)):** `\(r.executableSHA256)`\n"
        if r.executableSHA512 != "-" {
            md += "- **\(settings.t(.fieldExecutableSha512)):** `\(r.executableSHA512)`\n"
        }
        md += "- **\(settings.t(.fieldArchitectures)):** `\(architecturesText)`\n"
        md += "- **\(settings.t(.fieldRpaths)):** `\(rpathsText)`\n"
        md += "- **\(settings.t(.fieldResourcesDate)):** `\(r.plistModDate)`\n"
        md += "- **\(settings.t(.fieldExecutableDate)):** `\(r.executableModDate)`\n"
        md += "- **\(settings.t(.fieldTeamId)):** `\(teamText)`\n"
        md += "- **\(settings.t(.fieldAuthorities)):** `\(authoritiesText)`\n"
        md += "- **\(settings.t(.fieldSignedTime)):** `\(r.signedTimestamp)`\n"
        md += "- **\(settings.t(.fieldHardenedRuntime)):** `\(settings.t(r.hasHardenedRuntime ? .valueEnabled : .valueDisabled))`\n"
        md += "- **\(settings.t(.fieldNotarized)):** `\(settings.t(r.isNotarized ? .valueYes : .valueNo))`\n"
        md += "- **\(settings.t(.fieldQuarantine)):** `\(settings.t(r.isQuarantined ? .valueQuarantined : .valueNotQuarantined))`\n"
        if let fw = r.firewallAppState {
            let fwKey: LKey = fw.isBlocked ? .firewallAppBlocked : (fw.ruleStatus == .permitted ? .firewallAppPermitted : .firewallAppUnknown)
            md += "- **\(settings.t(.fieldFirewallState)):** `\(settings.t(fwKey))`\n"
        }
        if let vol = r.volumeEncryption {
            let encKey: LKey = vol.isEncrypted == true ? .volumeEncryptedLabel : (vol.isEncrypted == false ? .volumeUnencryptedLabel : .volumeUnknownLabel)
            md += "- **\(settings.t(.fieldVolumeEncryption)):** `\(vol.volumeName) (\(vol.format), \(settings.t(encKey)))`\n"
        }
        md += "- **\(settings.t(.fieldEntitlements)):** `\(entitlementsText)`\n"
        md += "- **\(settings.t(.fieldSpctlAssessment)):** `\(spctlText)`\n"
        if let rev = r.revocationStatus {
            md += "- **\(settings.t(.fieldRevocation)):** `\(settings.t(rev.labelKey))`\n"
        }
        md += "- **\(settings.t(.fieldCdhash)):** `\(r.cdHash)`\n"
        md += "- **\(settings.t(.fieldGatekeeper)):** `\(r.gatekeeperStatus)`\n"
        md += "- **\(settings.t(.fieldScanDuration)):** `\(r.scanDurationMs) ms`\n\n"

        md += "## \(settings.t(.sectionAnomalies))\n"
        for f in r.findings {
            md += "- **\(settings.t(f.titleKey))**: \(settings.t(f.descKey))\(f.detailSuffix)\n"
        }

        let suspiciousBundled = r.bundledLibraries.filter { !$0.suspiciousSymbols.isEmpty || $0.isTimestampAnomaly }
        let suspiciousLinked = r.linkedDylibs.filter(\.isSuspicious)
        if !suspiciousBundled.isEmpty || !suspiciousLinked.isEmpty {
            md += "\n## \(settings.t(.reportSuspiciousDylibsSection))\n"
            for item in suspiciousBundled {
                md += "- `\(OpenSafety.visibleName(item.name))` (\(item.modifiedDate))\n"
            }
            for item in suspiciousLinked {
                md += "- `\(item.path)`\n"
            }
        }

        if !r.hookCategories.isEmpty {
            md += "\n## \(settings.t(.sectionHookIndicators))\n"
            for cat in r.hookCategories {
                md += "- **\(OpenSafety.visibleName(cat.libraryName))** — \(settings.t(cat.categoryKey)): `\(cat.symbols.joined(separator: ", "))`\n"
            }
        }

        if !r.entitlementRisks.isEmpty {
            md += "\n## \(settings.t(.reportEntitlementRisksSection))\n"
            for risk in r.entitlementRisks {
                md += "- **[\(settings.t(risk.level.labelKey))]** \(settings.t(risk.titleKey)) (`\(risk.entitlementKey)`): \(settings.t(risk.detailKey))\n"
            }
        }

        if let policy = r.internetAccessPolicy {
            md += "\n## \(settings.t(.sectionInternetAccessPolicy))\n"
            if let dev = policy.developerName {
                md += "- **\(settings.t(.iapDeveloperLabel)):** \(dev)\n"
            }
            md += "- \(policy.applicationDescription)\n"
            for conn in policy.connections {
                let dir = settings.t(conn.isIncoming ? .iapDirectionIncoming : .iapDirectionOutgoing)
                let port = conn.portSpec.map { ":\($0)" } ?? ""
                let proto = conn.networkProtocol.map { "\($0) " } ?? ""
                md += "- [\(dir)] `\(proto)\(conn.hosts.joined(separator: ", "))\(port)` — \(conn.purpose)\n"
            }
        }

        return md
    }

    // MARK: - Adli Karşılaştırma Modu (Diff)

    public func openDiffMode() {
        workspaceMode = .diff
        diffError = nil
        if diffBaselineURL == nil, let current = currentBundleURL {
            diffBaselineURL = current
            if let report {
                diffBaselineEndpoint = AuditDiffEndpoint(
                    sourceDescription: current.path,
                    isFromSavedJSON: false,
                    report: report
                )
            }
        }
    }

    public func presentDiffFilePanel(forBaseline: Bool) {
        let panel = NSOpenPanel()
        panel.message = settings.t(forBaseline ? .diffBaselineHeader : .diffTargetHeader)
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = false
        panel.allowedContentTypes = Self.supportedOpenContentTypes + [.json]
        if panel.runModal() == .OK, let url = panel.url {
            setDiffFile(url, forBaseline: forBaseline)
        }
    }

    public func setDiffFile(_ url: URL, forBaseline: Bool) {
        let resolved = url.pathExtension.lowercased() == "json"
            ? url.standardizedFileURL
            : resolveAuditTargetURL(from: url)
        diffError = nil
        if forBaseline {
            diffBaselineURL = resolved
            if let cached = cachedReports[resolved.path], resolved.pathExtension.lowercased() != "json" {
                diffBaselineEndpoint = AuditDiffEndpoint(sourceDescription: resolved.path, isFromSavedJSON: false, report: cached)
            } else {
                diffBaselineEndpoint = nil
            }
        } else {
            diffTargetURL = resolved
            if let cached = cachedReports[resolved.path], resolved.pathExtension.lowercased() != "json" {
                diffTargetEndpoint = AuditDiffEndpoint(sourceDescription: resolved.path, isFromSavedJSON: false, report: cached)
            } else {
                diffTargetEndpoint = nil
            }
        }
        if diffBaselineURL != nil && diffTargetURL != nil {
            runDiffComparison()
        }
    }

    public func useCurrentReportInDiff(forBaseline: Bool) {
        guard let report else { return }
        let url = URL(fileURLWithPath: report.bundlePath)
        let endpoint = AuditDiffEndpoint(sourceDescription: report.bundlePath, isFromSavedJSON: false, report: report)
        diffError = nil
        if forBaseline {
            diffBaselineURL = url
            diffBaselineEndpoint = endpoint
        } else {
            diffTargetURL = url
            diffTargetEndpoint = endpoint
        }
        if diffBaselineURL != nil && diffTargetURL != nil {
            runDiffComparison()
        }
    }

    public func swapDiffEndpoints() {
        let tmpURL = diffBaselineURL
        let tmpEnd = diffBaselineEndpoint
        diffBaselineURL = diffTargetURL
        diffBaselineEndpoint = diffTargetEndpoint
        diffTargetURL = tmpURL
        diffTargetEndpoint = tmpEnd
        if let base = diffBaselineEndpoint, let tgt = diffTargetEndpoint {
            currentDiff = AuditDiff.compare(baseline: base, target: tgt)
        }
    }

    public func runDiffComparison() {
        guard let baseURL = diffBaselineURL, let newURL = diffTargetURL else { return }
        activeDiffToken?.cancel()
        activeDiffTask?.cancel()
        isComparingDiff = true
        diffError = nil

        let opts = settings.scanOptions
        let cachedBase = (baseURL.pathExtension.lowercased() != "json") ? cachedReports[baseURL.path] : nil
        let cachedTarget = (newURL.pathExtension.lowercased() != "json") ? cachedReports[newURL.path] : nil
        let token = ScanCancellationToken()
        activeDiffToken = token

        activeDiffTask = Task.detached { [weak self] in
            do {
                let baseEndpoint: AuditDiffEndpoint
                if let cachedBase {
                    baseEndpoint = AuditDiffEndpoint(sourceDescription: baseURL.path, isFromSavedJSON: false, report: cachedBase)
                } else {
                    baseEndpoint = try AuditDiff.loadOrAudit(url: baseURL, options: opts, cancellation: token)
                }

                let newEndpoint: AuditDiffEndpoint
                if let cachedTarget {
                    newEndpoint = AuditDiffEndpoint(sourceDescription: newURL.path, isFromSavedJSON: false, report: cachedTarget)
                } else {
                    newEndpoint = try AuditDiff.loadOrAudit(url: newURL, options: opts, cancellation: token)
                }

                let diff = AuditDiff.compare(baseline: baseEndpoint, target: newEndpoint)
                await MainActor.run {
                    guard let self, !token.isCancelled else { return }
                    if !baseEndpoint.isFromSavedJSON {
                        self.cachedReports[baseEndpoint.report.bundlePath] = baseEndpoint.report
                    }
                    if !newEndpoint.isFromSavedJSON {
                        self.cachedReports[newEndpoint.report.bundlePath] = newEndpoint.report
                    }
                    self.diffBaselineEndpoint = baseEndpoint
                    self.diffTargetEndpoint = newEndpoint
                    self.currentDiff = diff
                    self.isComparingDiff = false
                    self.activeDiffTask = nil
                    self.activeDiffToken = nil
                }
            } catch {
                await MainActor.run {
                    guard let self else { return }
                    self.diffError = error.localizedDescription
                    self.isComparingDiff = false
                    self.activeDiffTask = nil
                    self.activeDiffToken = nil
                }
            }
        }
    }

    public func exportDiffMarkdown(redacted: Bool? = nil) {
        guard let diff = currentDiff else { return }
        let table = StringTable(bundle: .main)
        let rawMD = diff.markdown(with: table, language: settings.languageCode)
        let useMask = redacted ?? settings.redactSharedDiagnostics
        let md = useMask ? DiagnosticMasker().redact(text: rawMD) : rawMD
        presentExportSavePanel(
            defaultName: "Verificator-Diff-\(diff.baseline.report.bundleName)-vs-\(diff.target.report.bundleName).md",
            allowedTypes: [.plainText],
            data: Data(md.utf8)
        )
    }

    // MARK: - Çalışan Süreçler & Sistem Kalıcılığı Denetimi

    public func openRunningProcessesMode(startImmediately: Bool = false) {
        workspaceMode = .runningProcesses
        if startImmediately || (runningSummary == nil && !isScanningRunning) {
            startRunningProcessesScan()
        }
    }

    public func startRunningProcessesScan() {
        cancelRunningProcessesScan()
        workspaceMode = .runningProcesses
        isScanningRunning = true
        runningProgress = (0, 0, "")
        let opts = settings.scanOptions
        let token = ScanCancellationToken()
        activeRunningToken = token

        final class WeakModelBox: @unchecked Sendable {
            @MainActor weak var value: AppModel?
            @MainActor init(_ value: AppModel) { self.value = value }
        }
        let weakBox = WeakModelBox(self)

        activeRunningTask = Task.detached {
            let summary = SystemAudit.auditRunningProcesses(options: opts, cancellation: token) { index, total, name in
                Task { @MainActor in
                    guard let model = weakBox.value, !token.isCancelled else { return }
                    model.runningProgress = (index, total, name)
                }
            }
            await MainActor.run {
                guard let model = weakBox.value else { return }
                model.runningSummary = summary
                model.isScanningRunning = false
                model.activeRunningTask = nil
                model.activeRunningToken = nil
            }
        }
    }

    public func cancelRunningProcessesScan() {
        activeRunningToken?.cancel()
        activeRunningToken = nil
        activeRunningTask?.cancel()
        activeRunningTask = nil
        isScanningRunning = false
    }

    public func openPersistenceMode(startImmediately: Bool = false) {
        workspaceMode = .persistence
        if startImmediately || (persistenceSummary == nil && !isScanningPersistence) {
            startPersistenceScan()
        }
    }

    public func startPersistenceScan() {
        cancelPersistenceScan()
        workspaceMode = .persistence
        isScanningPersistence = true
        persistenceProgress = (0, 0, "")
        let opts = settings.scanOptions
        let token = ScanCancellationToken()
        activePersistenceToken = token

        final class WeakModelBox: @unchecked Sendable {
            @MainActor weak var value: AppModel?
            @MainActor init(_ value: AppModel) { self.value = value }
        }
        let weakBox = WeakModelBox(self)

        activePersistenceTask = Task.detached {
            let summary = SystemAudit.auditPersistence(options: opts, cancellation: token) { index, total, name in
                Task { @MainActor in
                    guard let model = weakBox.value, !token.isCancelled else { return }
                    model.persistenceProgress = (index, total, name)
                }
            }
            await MainActor.run {
                guard let model = weakBox.value else { return }
                model.persistenceSummary = summary
                model.isScanningPersistence = false
                model.activePersistenceTask = nil
                model.activePersistenceToken = nil
            }
        }
    }

    public func cancelPersistenceScan() {
        activePersistenceToken?.cancel()
        activePersistenceToken = nil
        activePersistenceTask?.cancel()
        activePersistenceTask = nil
        isScanningPersistence = false
    }

    public func inspectSystemAuditTarget(at path: String) {
        let url = URL(fileURLWithPath: path)
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        scan(url)
    }

    // MARK: - macOS Sistem Entegrasyonu (URL Scheme, Services & CLI)

    public var embeddedCLIPath: String {
        let bundleCLI = Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/verificator-cli")
            .path
        if FileManager.default.isExecutableFile(atPath: bundleCLI) {
            return bundleCLI
        }
        return "/Applications/Verificator.app/Contents/MacOS/verificator-cli"
    }

    public var cliInstallCommand: String {
        let escaped = embeddedCLIPath.replacingOccurrences(of: "\"", with: "\\\"")
        return "sudo mkdir -p /usr/local/bin && sudo ln -sf \"\(escaped)\" /usr/local/bin/verificator-cli"
    }

    public func copyCLIInstallCommand() {
        copyTextToClipboard(cliInstallCommand)
    }

    public func handleIncomingURL(_ url: URL) {
        if url.isFileURL {
            var isDir: ObjCBool = false
            let standardized = url.standardizedFileURL
            if FileManager.default.fileExists(atPath: standardized.path, isDirectory: &isDir),
               isDir.boolValue,
               !ForensicScanner.supportedBundleExtensions.contains(standardized.pathExtension.lowercased()) {
                startBatchScan(in: standardized)
            } else if isSupportedBundleURL(standardized) {
                scan(standardized)
            }
            return
        }

        guard url.scheme?.lowercased() == "verificator",
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return
        }

        let action = (components.host ?? "").lowercased()
        let queryItems = components.queryItems ?? []
        let queryValue: (String) -> String? = { name in
            queryItems.first(where: { $0.name.lowercased() == name })?.value
        }

        switch action {
        case "audit", "scan", "":
            guard let rawPath = queryValue("path") ?? queryValue("file"), !rawPath.isEmpty else {
                AppLog.shared.warning(.app, settings.t(.urlSchemeInvalidError), detail: url.absoluteString)
                return
            }
            let fileURL = URL(fileURLWithPath: NSString(string: rawPath).expandingTildeInPath).standardizedFileURL
            scan(fileURL)

        case "batch":
            guard let rawPath = queryValue("path") ?? queryValue("folder"), !rawPath.isEmpty else { return }
            let dirURL = URL(fileURLWithPath: NSString(string: rawPath).expandingTildeInPath).standardizedFileURL
            startBatchScan(in: dirURL)

        case "diff", "compare":
            workspaceMode = .diff
            if let base = queryValue("baseline") ?? queryValue("old"), !base.isEmpty {
                diffBaselineURL = URL(fileURLWithPath: NSString(string: base).expandingTildeInPath).standardizedFileURL
                diffBaselineEndpoint = nil
            }
            if let tgt = queryValue("target") ?? queryValue("new"), !tgt.isEmpty {
                diffTargetURL = URL(fileURLWithPath: NSString(string: tgt).expandingTildeInPath).standardizedFileURL
                diffTargetEndpoint = nil
            }
            if diffBaselineURL != nil && diffTargetURL != nil {
                runDiffComparison()
            }

        case "running", "processes":
            openRunningProcessesMode(startImmediately: true)

        case "persistence", "launchagents":
            openPersistenceMode(startImmediately: true)

        default:
            AppLog.shared.warning(.app, settings.t(.urlSchemeInvalidError), detail: url.absoluteString)
        }
    }

    public func batchMarkdownSummary(for rawSummary: BatchAuditSummary, redacted: Bool? = nil) -> String {
        let useMask = redacted ?? settings.redactSharedDiagnostics
        let summary = useMask ? rawSummary.redacted(using: DiagnosticMasker()) : rawSummary
        var md = "# \(settings.t(.batchTitle))\n\n"
        md += "- **\(settings.t(.reportBundlePathLabel)):** `\(summary.directoryPath)`\n"
        let cancelledNote = summary.wasCancelled ? " · *\(settings.t(.batchPartialCancelledBadge))*" : ""
        md += "- **\(settings.t(.batchSummaryStats, summary.totalCount, summary.cleanCount, summary.warningCount, summary.tamperedCount))**\(cancelledNote)\n\n"
        md += "| Bundle | Bundle ID | Verdict | Quarantine | Team ID |\n"
        md += "| --- | --- | --- | --- | --- |\n"
        for item in summary.reports {
            let v = item.verdict.rawValue.uppercased()
            let q = item.isQuarantined ? "YES" : "NO"
            md += "| `\(OpenSafety.visibleName(item.bundleName))` | `\(item.bundleId)` | **\(v)** | `\(q)` | `\(item.teamIdentifier)` |\n"
        }
        return md
    }

    public func copyMarkdownReport(redacted: Bool? = nil) {
        guard let r = report else { return }
        copyTextToClipboard(markdownReport(for: r, redacted: redacted))
    }

    public func copyTextToClipboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        copiedFeedback = true
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            copiedFeedback = false
        }
    }

    public func saveMarkdownReport(redacted: Bool? = nil) {
        guard let r = report else { return }
        presentExportSavePanel(
            defaultName: "\(r.bundleName)-Forensic-Report.md",
            allowedTypes: [.plainText],
            data: Data(markdownReport(for: r, redacted: redacted).utf8)
        )
    }

    public func saveJSONReport(redacted: Bool? = nil) {
        guard let raw = report else { return }
        let useMask = redacted ?? settings.redactSharedDiagnostics
        let r = useMask ? raw.redacted(using: DiagnosticMasker()) : raw
        guard let data = try? r.jsonData(prettyPrinted: true) else { return }
        presentExportSavePanel(
            defaultName: "\(raw.bundleName)-Forensic-Report.json",
            allowedTypes: [.json],
            data: data
        )
    }

    public func exportBatchMarkdown(redacted: Bool? = nil) {
        guard let summary = batchSummary else { return }
        presentExportSavePanel(
            defaultName: "Verificator-Batch-Audit.md",
            allowedTypes: [.plainText],
            data: Data(batchMarkdownSummary(for: summary, redacted: redacted).utf8)
        )
    }

    public func exportBatchJSON(redacted: Bool? = nil) {
        guard let rawSummary = batchSummary else { return }
        let useMask = redacted ?? settings.redactSharedDiagnostics
        let summary = useMask ? rawSummary.redacted(using: DiagnosticMasker()) : rawSummary
        guard let data = try? summary.jsonData(prettyPrinted: true) else { return }
        presentExportSavePanel(
            defaultName: "Verificator-Batch-Audit.json",
            allowedTypes: [.json],
            data: data
        )
    }

    private func presentExportSavePanel(defaultName: String, allowedTypes: [UTType], data: Data) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = allowedTypes
        panel.nameFieldStringValue = defaultName
        if panel.runModal() == .OK, let url = panel.url {
            try? data.write(to: url, options: .atomic)
            if settings.revealAfterExport {
                NSWorkspace.shared.activateFileViewerSelecting([url])
            }
        }
    }

    // MARK: - Güncelleme Denetimi ve Kriptografik Doğrulama (Ed25519 + SHA-256)

    public func checkForAppUpdate(interactive: Bool) async {
        if appUpdateState == .checking {
            if let task = activeUpdateCheckTask, interactive {
                let state = await task.value
                await MainActor.run {
                    presentUpdateAlert(for: state)
                }
            }
            return
        }
        let checkTask = Task<AppUpdateState, Never> { @MainActor [weak self] in
            guard let self else { return .idle }
            self.appUpdateState = .checking
            let finalState: AppUpdateState
            do {
                let release = try await AppUpdateChecker.latest(repository: AppInfo.repository)
                if AppUpdateChecker.isNewer(release.version, than: AppInfo.version) {
                    finalState = .available(release)
                    AppLog.shared.info(.update, "Update available: \(release.version)")
                } else {
                    finalState = .upToDate
                    AppLog.shared.info(.update, "App is up to date (\(AppInfo.version))")
                }
            } catch AppUpdateChecker.CheckError.noReleases {
                finalState = .noReleases
                AppLog.shared.warning(.update, "No GitHub releases published yet for \(AppInfo.repository)")
            } catch {
                finalState = .failed(error.localizedDescription)
                AppLog.shared.warning(.update, "Update check failed", detail: error.localizedDescription)
            }
            self.appUpdateState = finalState
            return finalState
        }
        activeUpdateCheckTask = checkTask
        let resultState = await checkTask.value
        activeUpdateCheckTask = nil
        if interactive {
            await MainActor.run {
                presentUpdateAlert(for: resultState)
            }
        }
    }

    @MainActor
    public func presentUpdateAlert(for state: AppUpdateState) {
        NSApplication.shared.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        switch state {
        case .available(let release):
            alert.alertStyle = .informational
            alert.messageText = settings.t(.appUpdateAvailableTitle)
            alert.informativeText = settings.t(.appUpdateAvailable, release.version, AppInfo.version)
            let canVerify = release.downloadURL != nil && (release.signatureURL != nil || release.checksumsURL != nil)
            if canVerify {
                alert.addButton(withTitle: settings.t(.appUpdateDownloadAndVerify))
                alert.addButton(withTitle: settings.t(.appUpdateOpenInBrowser))
                alert.addButton(withTitle: settings.t(.buttonClose))
                let response = alert.runModal()
                if response == .alertFirstButtonReturn {
                    Task { await downloadAndVerifyAppUpdate(release: release) }
                } else if response == .alertSecondButtonReturn {
                    openAppDownload()
                }
            } else {
                alert.addButton(withTitle: settings.t(.appUpdateDownload))
                alert.addButton(withTitle: settings.t(.buttonClose))
                if alert.runModal() == .alertFirstButtonReturn {
                    openAppDownload()
                }
            }
        case .upToDate:
            alert.alertStyle = .informational
            alert.messageText = settings.t(.appUpdateUpToDateTitle)
            alert.informativeText = settings.t(.appUpdateUpToDate, AppInfo.version)
            alert.addButton(withTitle: settings.t(.buttonOK))
            alert.runModal()
        case .noReleases:
            alert.alertStyle = .warning
            alert.messageText = settings.t(.appUpdateNoReleasesTitle)
            alert.informativeText = settings.t(.appUpdateNoReleases, AppInfo.version)
            alert.addButton(withTitle: settings.t(.buttonOK))
            alert.runModal()
        case .failed(let message):
            alert.alertStyle = .warning
            alert.messageText = settings.t(.appUpdateFailedTitle)
            alert.informativeText = message
            alert.addButton(withTitle: settings.t(.buttonOK))
            alert.runModal()
        case .idle, .checking:
            break
        }
    }

    public func openAppDownload() {
        guard case .available(let release) = appUpdateState else { return }
        NSWorkspace.shared.open(release.downloadURL ?? release.pageURL)
    }

    public func downloadAndVerifyAppUpdate(release: AppRelease? = nil) async {
        let target: AppRelease?
        if let release {
            target = release
        } else if case .available(let available) = appUpdateState {
            target = available
        } else {
            target = nil
        }
        guard let target else { return }
        guard updateDownloadState != .downloading else { return }
        updateDownloadState = .downloading

        do {
            let result = try await AppUpdateChecker.downloadAndVerify(release: target)
            updateDownloadState = .verified(result)
            NSWorkspace.shared.activateFileViewerSelecting([result.fileURL])
        } catch {
            let detail = error.localizedDescription
            updateDownloadState = .failed(detail)
            AppLog.shared.error(.update, "Update download or cryptographic verification failed", detail: detail)
        }
    }

    public func openVerifiedUpdate(_ fileURL: URL) {
        NSWorkspace.shared.open(fileURL)
    }

    public func revealVerifiedUpdate(_ fileURL: URL) {
        NSWorkspace.shared.activateFileViewerSelecting([fileURL])
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

    public func aiSummary(for report: BundleAuditReport) -> (text: String, source: String)? {
        aiSummaries["\(report.bundlePath)|\(settings.languageCode)"]
    }

    public func cancelAISummary() {
        activeAITask?.cancel()
        activeAITask = nil
        isGeneratingAISummary = false
    }

    public func generateAISummary(for report: BundleAuditReport) async {
        guard !isGeneratingAISummary else { return }
        activeAITask?.cancel()
        isGeneratingAISummary = true
        aiSummaryError = nil

        let task = Task<Void, Never> { @MainActor [weak self] in
            guard let self else { return }
            defer {
                self.isGeneratingAISummary = false
                self.activeAITask = nil
            }

            await self.refreshLocalModels()
            guard !Task.isCancelled else { return }

            // Sessiz geçiş yok: seçilen sağlayıcı hazır değilse uyarır ve bekler.
            if let warning = self.currentProviderWarning() {
                self.aiSummaryError = warning
                return
            }

            if let text = await ForensicAI.summarize(
                report: report,
                languageCode: self.settings.languageCode,
                model: self.suggestionModel
            ), !Task.isCancelled {
                self.aiSummaries["\(report.bundlePath)|\(self.settings.languageCode)"] = (text: text, source: self.suggestionSourceName)
                AppLog.shared.info(.scanner, "AI forensic summary generated for \(report.bundleName) via \(self.suggestionSourceName)")
            } else if !Task.isCancelled {
                self.aiSummaryError = self.currentProviderWarning() ?? self.settings.t(.aiForensicUnavailable)
            }
        }
        activeAITask = task
        await task.value
    }

    /// Touch ID veya yönetici parolası ile `sudo xattr -rd com.apple.quarantine` çalıştırır ve raporu yeniler.
    public func removeQuarantineForCurrentBundle() {
        guard !isRemovingQuarantine, let url = currentBundleURL else { return }
        removeQuarantine(for: url)
    }

    public func removeQuarantine(for bundleURL: URL) {
        guard !isRemovingQuarantine else { return }
        isRemovingQuarantine = true
        quarantineFeedback = nil
        let path = bundleURL.path
        let opts = settings.scanOptions
        Task.detached {
            let result = ForensicScanner.removeQuarantineWithAdminPrivileges(at: path)
            let refreshedBatchItem: BundleAuditReport? = result.status == .success
                ? ForensicScanner.auditBundle(at: bundleURL, options: opts)
                : nil
            await MainActor.run {
                self.isRemovingQuarantine = false
                switch result.status {
                case .success:
                    self.quarantineFeedback = (text: self.settings.t(.quarantineRemovedSuccess), isSuccess: true)
                    if let updated = refreshedBatchItem {
                        self.cachedReports[path] = updated
                        if self.currentBundleURL?.standardizedFileURL == bundleURL.standardizedFileURL {
                            self.report = updated
                            self.settings.noteOpened(bundleURL, verdict: updated.verdict)
                        }
                        if let existingSummary = self.batchSummary {
                            let updatedReports = existingSummary.reports.map {
                                $0.bundlePath == path ? updated : $0
                            }
                            self.batchSummary = BatchAuditSummary(
                                directoryPath: existingSummary.directoryPath,
                                scannedAt: existingSummary.scannedAt,
                                reports: updatedReports,
                                wasCancelled: existingSummary.wasCancelled
                            )
                        }
                    } else if self.currentBundleURL?.standardizedFileURL == bundleURL.standardizedFileURL {
                        self.scan(bundleURL, forceRescan: true)
                    }
                case .cancelled:
                    self.quarantineFeedback = (text: self.settings.t(.quarantineRemovedCancelled), isSuccess: false)
                case .failed:
                    let text = result.message.isEmpty
                        ? self.settings.t(.quarantineRemovedFailed)
                        : self.settings.t(.quarantineRemovedFailedDetail, result.message)
                    self.quarantineFeedback = (text: text, isSuccess: false)
                }
            }
        }
    }
}
