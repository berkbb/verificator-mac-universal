// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import VerificatorCore
import SwiftUI
import UniformTypeIdentifiers

enum SidebarItem: Hashable {
    case home
    case batch
    case diff
    case runningProcesses
    case persistence
    case systemPosture
    case tab(Int)
    case recent(URL)
}

enum DylibFilter: String, CaseIterable, Identifiable {
    case all
    case nonSystem
    case suspicious

    var id: String { rawValue }

    var titleKey: LKey {
        switch self {
        case .all: .filterAll
        case .nonSystem: .filterNonSystem
        case .suspicious: .filterSuspicious
        }
    }
}

enum BatchFilter: String, CaseIterable, Identifiable {
    case all
    case issues
    case quarantined

    var id: String { rawValue }

    var titleKey: LKey {
        switch self {
        case .all: .filterAll
        case .issues: .batchFilterIssues
        case .quarantined: .batchFilterQuarantined
        }
    }
}

struct ContentView: View {
    @Environment(AppModel.self) private var model
    @Environment(AppSettings.self) private var settings
    @Environment(\.openWindow) private var openWindow
    @State private var isDropTargeted = false
    @State private var columnVisibility: NavigationSplitViewVisibility = .all
    @State private var dylibSearchText = ""
    @State private var dylibFilter: DylibFilter = .all
    @State private var batchSearchText = ""
    @State private var batchFilter: BatchFilter = .all
    @State private var aiCopiedFeedback = false
    @State private var rawCopiedTag: String?

    var body: some View {
        @Bindable var model = model
        NavigationSplitView(columnVisibility: $columnVisibility) {
            sidebarView
                .navigationSplitViewColumnWidth(min: 240, ideal: 270, max: 350)
        } detail: {
            ZStack {
                VStack(spacing: 0) {
                    headerBar
                    Divider()

                    if model.isScanning {
                        scanningView
                    } else if model.workspaceMode == .batch {
                        batchAuditView
                    } else if model.workspaceMode == .diff {
                        DiffView()
                    } else if model.workspaceMode == .runningProcesses {
                        RunningProcessesAuditView()
                    } else if model.workspaceMode == .persistence {
                        PersistenceAuditView()
                    } else if model.workspaceMode == .systemPosture {
                        SystemPostureAuditView()
                    } else if let report = model.report {
                        verdictBanner(for: report)
                        Divider()

                        Picker("", selection: $model.selectedTab) {
                            Text(settings.t(.tabOverview)).tag(0)
                            Text(settings.t(.tabDylibs)).tag(1)
                            Text(settings.t(.tabSymbols)).tag(2)
                            Text(settings.t(.tabRaw)).tag(3)
                        }
                        .pickerStyle(.segmented)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 10)

                        ScrollView {
                            VStack(alignment: .leading, spacing: 18) {
                                switch model.selectedTab {
                                case 0:
                                    overviewSection(report)
                                case 1:
                                    dylibsSection(report)
                                case 2:
                                    symbolsSection(report)
                                default:
                                    rawOutputSection(report)
                                }
                            }
                            .padding(20)
                        }

                        if settings.autoScanOnDrop {
                            Divider()
                            HStack(spacing: 6) {
                                Image(systemName: "arrow.down.app")
                                Text(settings.t(.statusDropBar))
                            }
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 6)
                            .background(Color(NSColor.windowBackgroundColor))
                        }
                    } else {
                        dropZoneIdleView
                    }
                }

                if isDropTargeted {
                    ZStack {
                        Color.blue.opacity(0.14)
                        RoundedRectangle(cornerRadius: 18)
                            .strokeBorder(style: StrokeStyle(lineWidth: 3, dash: [10, 6]))
                            .foregroundStyle(.blue)
                            .padding(16)

                        VStack(spacing: 14) {
                            Image(systemName: "arrow.down.doc.fill")
                                .font(.system(size: 56))
                                .foregroundStyle(.blue)
                            Text(settings.t(.statusDropActive))
                                .font(.title2.bold())
                                .foregroundStyle(.primary)
                        }
                        .padding(28)
                        .background(.ultraThinMaterial)
                        .clipShape(RoundedRectangle(cornerRadius: 16))
                    }
                    .allowsHitTesting(false)
                }
            }
        }
        .navigationSplitViewStyle(.balanced)
        .navigationTitle(windowTitle)
        .navigationSubtitle(windowSubtitle)
        .onDrop(of: [.fileURL], isTargeted: $isDropTargeted) { providers in
            handleDroppedProviders(providers)
        }
        .sheet(isPresented: $model.showDiagnosticSheet) {
            DiagnosticSheet()
                .environment(model)
                .environment(settings)
        }
        .sheet(
            isPresented: Binding(
                get: { model.signatureChangeModal != nil },
                set: { if !$0 { model.dismissSignatureChangeModal() } }
            )
        ) {
            if let change = model.signatureChangeModal {
                SignatureChangeAlertSheet(change: change)
                    .environment(model)
                    .environment(settings)
            }
        }
    }

    private var windowTitle: String {
        switch model.workspaceMode {
        case .batch: return settings.t(.batchTitle)
        case .diff: return settings.t(.diffTitle)
        case .runningProcesses: return settings.t(.runningTitle)
        case .persistence: return settings.t(.persistenceTitle)
        case .systemPosture: return settings.t(.postureTitle)
        case .single: return model.report?.bundleName ?? settings.t(.appName)
        }
    }

    private var windowSubtitle: String {
        switch model.workspaceMode {
        case .batch:
            if let summary = model.batchSummary {
                return "\(summary.directoryPath) · \(settings.t(.batchSummaryStats, summary.totalCount, summary.cleanCount, summary.warningCount, summary.tamperedCount))"
            }
            return ""
        case .runningProcesses:
            if let summary = model.runningSummary {
                return settings.t(.runningSummaryStats, summary.totalCount, summary.cleanCount, summary.warningCount, summary.tamperedCount, summary.uniqueBinariesCount)
            }
            return ""
        case .persistence:
            if let summary = model.persistenceSummary {
                return settings.t(.persistenceSummaryStats, summary.totalCount, summary.cleanCount, summary.warningCount, summary.tamperedCount, summary.missingExecutableCount)
            }
            return ""
        case .systemPosture:
            if let posture = model.systemPosture {
                return "\(posture.hardwareModel) · macOS \(posture.macOSVersion) · \(posture.cpuArchitecture)"
            }
            return ""
        case .diff:
            if let diff = model.currentDiff {
                return "\(diff.baseline.report.bundleName) → \(diff.target.report.bundleName)"
            }
            return ""
        case .single:
            break
        }
        if model.isBatchMode, let summary = model.batchSummary {
            return "\(summary.directoryPath) · \(settings.t(.batchSummaryStats, summary.totalCount, summary.cleanCount, summary.warningCount, summary.tamperedCount))"
        }
        guard let report = model.report else {
            return settings.t(.appTagline)
        }
        return "\(report.bundleId) · v\(report.shortVersion) (\(report.buildVersion)) · \(report.scanDurationMs) ms"
    }

    private var scanningView: some View {
        VStack(spacing: 14) {
            ProgressView()
                .controlSize(.large)
            Text(settings.t(.statusScanning))
                .font(.headline)
                .foregroundStyle(.secondary)
            if let url = model.currentBundleURL {
                Text(url.path)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.tertiary)
            }
            Button(role: .cancel) {
                model.cancelCurrentScan()
            } label: {
                Label(settings.t(.actionCancelScan), systemImage: "xmark.circle")
            }
            .buttonStyle(.bordered)
            .padding(.top, 4)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var sidebarSelection: Binding<SidebarItem?> {
        Binding {
            switch model.workspaceMode {
            case .batch:
                return .batch
            case .diff:
                return .diff
            case .runningProcesses:
                return .runningProcesses
            case .persistence:
                return .persistence
            case .systemPosture:
                return .systemPosture
            case .single:
                if let current = model.currentBundleURL, model.report != nil {
                    return .recent(current.standardizedFileURL)
                }
                return .home
            }
        } set: { item in
            switch item {
            case .home:
                model.clearReport()
            case .batch:
                model.workspaceMode = .batch
            case .diff:
                model.openDiffMode()
            case .runningProcesses:
                model.openRunningProcessesMode(startImmediately: model.runningSummary == nil)
            case .persistence:
                model.openPersistenceMode(startImmediately: model.persistenceSummary == nil)
            case .systemPosture:
                model.openSystemPostureMode(startImmediately: model.systemPosture == nil)
            case .tab(let index):
                model.workspaceMode = .single
                model.selectedTab = index
            case .recent(let url):
                model.workspaceMode = .single
                if model.currentBundleURL?.standardizedFileURL != url.standardizedFileURL || model.report == nil {
                    model.scan(url)
                }
            case nil:
                break
            }
        }
    }

    private var sidebarView: some View {
        let recents = settings.existingRecentBundles
        return VStack(spacing: 0) {
            List(selection: sidebarSelection) {
                Section(settings.t(.sidebarSections)) {
                    Label(settings.t(.sidebarHome), systemImage: "house")
                        .tag(SidebarItem.home)

                    Label(settings.t(.sidebarBatch), systemImage: "square.grid.2x2")
                        .tag(SidebarItem.batch)

                    Label(settings.t(.navDiffMode), systemImage: "arrow.left.arrow.right")
                        .tag(SidebarItem.diff)

                    Label(settings.t(.navRunningProcesses), systemImage: "cpu")
                        .tag(SidebarItem.runningProcesses)

                    Label(settings.t(.navPersistence), systemImage: "checklist")
                        .tag(SidebarItem.persistence)

                    Label(settings.t(.navSystemPosture), systemImage: "checkmark.shield")
                        .tag(SidebarItem.systemPosture)

                    if let report = model.report, model.workspaceMode == .single {
                        sidebarSectionRow(
                            title: settings.t(.tabOverview),
                            icon: "checkmark.shield",
                            badge: report.findings.count,
                            tint: colorForVerdict(report.verdict),
                            tab: 0
                        )
                        sidebarSectionRow(
                            title: settings.t(.tabDylibs),
                            icon: "shippingbox",
                            badge: report.bundledLibraries.count + report.linkedDylibs.count,
                            tint: .secondary,
                            tab: 1
                        )
                        sidebarSectionRow(
                            title: settings.t(.tabSymbols),
                            icon: "memorychip",
                            badge: report.hookCategories.count,
                            tint: report.hookCategories.isEmpty ? .secondary : .red,
                            tab: 2
                        )
                        sidebarSectionRow(
                            title: settings.t(.tabRaw),
                            icon: "terminal",
                            badge: nil,
                            tint: .secondary,
                            tab: 3
                        )
                    }
                }

                Section {
                    if recents.isEmpty {
                        Text(settings.t(.sidebarNoRecents))
                            .foregroundStyle(.secondary)
                            .font(.callout)
                    } else {
                        ForEach(recents, id: \.path) { url in
                            let normalized = url.standardizedFileURL
                            let isSelected = model.workspaceMode == .single && model.currentBundleURL?.standardizedFileURL == normalized && model.report != nil
                            let itemVerdict = model.cachedReports[normalized.path]?.verdict ?? settings.verdict(for: normalized)
                            HStack(spacing: 8) {
                                Image(nsImage: NSWorkspace.shared.icon(forFile: url.path))
                                    .resizable()
                                    .frame(width: 22, height: 22)

                                VStack(alignment: .leading, spacing: 1) {
                                    HStack(spacing: 4) {
                                        Text(url.deletingPathExtension().lastPathComponent)
                                            .font(.callout.weight(isSelected ? .semibold : .regular))
                                            .lineLimit(1)
                                            .truncationMode(.middle)
                                        if let itemVerdict {
                                            Image(systemName: iconForVerdict(itemVerdict))
                                                .font(.caption2)
                                                .foregroundStyle(colorForVerdict(itemVerdict))
                                        }
                                    }
                                    Text(url.deletingLastPathComponent().path)
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                }

                                Spacer(minLength: 4)

                                Button {
                                    removeSingleRecent(url)
                                } label: {
                                    Image(systemName: "xmark.circle.fill")
                                        .font(.callout)
                                        .foregroundStyle(.secondary)
                                }
                                .buttonStyle(.borderless)
                                .help(settings.t(.sidebarRemoveRecent))
                                .accessibilityLabel(settings.t(.sidebarRemoveRecent))
                            }
                            .padding(.vertical, 2)
                            .padding(.trailing, 2)
                            .tag(SidebarItem.recent(normalized))
                            .help(url.path)
                            .contextMenu {
                                Button(settings.t(.actionRefresh)) {
                                    model.scan(url, forceRescan: true)
                                }
                                Button(settings.t(.actionRevealInFinder)) {
                                    NSWorkspace.shared.activateFileViewerSelecting([url])
                                }
                                Divider()
                                Button(settings.t(.sidebarRemoveRecent), role: .destructive) {
                                    removeSingleRecent(url)
                                }
                                Button(settings.t(.actionClearAllHistory), role: .destructive) {
                                    clearAllHistory()
                                }
                            }
                        }

                        Button(role: .destructive) {
                            clearAllHistory()
                        } label: {
                            Label(settings.t(.actionClearAllHistory), systemImage: "trash")
                        }
                        .buttonStyle(.borderless)
                        .foregroundStyle(.secondary)
                        .padding(.top, 2)
                        .help(settings.t(.actionClearRecents))
                    }
                } header: {
                    HStack(spacing: 6) {
                        Text(settings.t(.actionRecentBundles))
                            .lineLimit(1)
                        Spacer(minLength: 4)
                        if !recents.isEmpty {
                            Button {
                                clearAllHistory()
                            } label: {
                                Image(systemName: "trash")
                                    .font(.caption)
                            }
                            .buttonStyle(.borderless)
                            .help(settings.t(.actionClearAllHistory))
                            .accessibilityLabel(settings.t(.actionClearAllHistory))
                        }
                    }
                    .padding(.trailing, 4)
                }
            }
            .listStyle(.sidebar)

            if model.report != nil || model.workspaceMode != .single {
                Divider()
                Button {
                    model.clearReport()
                } label: {
                    Label(settings.t(.actionBackHome), systemImage: "house")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .help(settings.t(.actionBackHomeHelp))
                .padding(10)
            }
        }
    }

    private func clearAllHistory() {
        model.clearAllHistory()
    }

    private func removeSingleRecent(_ url: URL) {
        let isCurrent = model.currentBundleURL?.standardizedFileURL == url.standardizedFileURL
        settings.removeRecent(url)
        if isCurrent {
            model.clearReport()
        }
    }

    private func sidebarSectionRow(title: String, icon: String, badge: Int?, tint: Color, tab: Int) -> some View {
        Button {
            model.selectedTab = tab
        } label: {
            HStack {
                Label(title, systemImage: icon)
                    .foregroundStyle(model.selectedTab == tab ? Color.accentColor : .primary)
                Spacer()
                if let badge {
                    Text("\(badge)")
                        .font(.caption2.monospacedDigit().weight(.semibold))
                        .foregroundStyle(tint)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(tint.opacity(0.14), in: Capsule())
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func colorForVerdict(_ verdict: IntegrityVerdict) -> Color {
        switch verdict {
        case .clean: return .green
        case .warning: return .orange
        case .tampered: return .red
        }
    }

    private func iconForVerdict(_ verdict: IntegrityVerdict) -> String {
        switch verdict {
        case .clean: return "checkmark.seal.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .tampered: return "xmark.octagon.fill"
        }
    }

    private var dropZoneIdleView: some View {
        VStack(spacing: 18) {
            ZStack {
                Circle()
                    .fill(Color.blue.opacity(0.1))
                    .frame(width: 110, height: 110)
                Image(systemName: "arrow.down.doc.fill")
                    .font(.system(size: 50))
                    .foregroundStyle(.blue)
            }

            Text(settings.t(.statusIdle))
                .font(.title2.bold())
                .multilineTextAlignment(.center)

            Text(settings.t(.statusIdleHint))
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            Text(settings.t(.dropZoneSupportedHintExpanded))
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(Capsule().fill(.quaternary.opacity(0.6)))

            HStack(spacing: 12) {
                Button {
                    model.presentOpenPanel()
                } label: {
                    Label(settings.t(.actionSelectApp), systemImage: "folder.badge.magnifyingglass")
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

                Button {
                    model.presentBatchFolderPanel()
                } label: {
                    Label(settings.t(.actionBatchScan), systemImage: "square.grid.2x2")
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)

                if !settings.existingRecentBundles.isEmpty {
                    Button(role: .destructive) {
                        clearAllHistory()
                    } label: {
                        Label(settings.t(.actionClearAllHistory), systemImage: "trash")
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                }
            }
            .padding(.top, 6)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(32)
        .background(
            RoundedRectangle(cornerRadius: 18)
                .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [8, 6]))
                .foregroundStyle(Color.secondary.opacity(0.35))
                .padding(24)
        )
    }

    private var headerBar: some View {
        @Bindable var settings = settings
        return HStack(spacing: 10) {
            if model.report != nil || model.workspaceMode != .single {
                Button {
                    model.clearReport()
                } label: {
                    Label(settings.t(.actionBackHome), systemImage: "house")
                }
                .buttonStyle(.bordered)
                .help(settings.t(.actionBackHomeHelp))
            } else {
                Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                    .font(.system(size: 26))
                    .foregroundStyle(.blue)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(settings.t(.appTitle))
                    .font(.headline)
                    .lineLimit(1)
                Text(settings.t(.appSubtitle))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer()

            Button {
                model.presentOpenPanel()
            } label: {
                Label(settings.t(.actionSelectApp), systemImage: "folder.badge.magnifyingglass")
            }
            .buttonStyle(.borderedProminent)

            Button {
                model.presentBatchFolderPanel()
            } label: {
                Label(settings.t(.sidebarBatch), systemImage: "square.grid.2x2")
            }
            .buttonStyle(.bordered)
            .help(settings.t(.actionBatchScan))

            if model.workspaceMode == .single {
                Button {
                    model.refreshCurrentBundle()
                } label: {
                    Label(settings.t(.actionRefresh), systemImage: "arrow.clockwise")
                }
                .buttonStyle(.bordered)
                .help(settings.t(.actionRefreshHelp))
                .disabled(model.currentBundleURL == nil || model.isScanning)

                Button {
                    model.clearReport()
                } label: {
                    Label(settings.t(.actionClear), systemImage: "trash")
                }
                .buttonStyle(.bordered)
                .help(settings.t(.actionClearHelp))
                .disabled(model.report == nil || model.isScanning)

                if model.report != nil {
                    Button {
                        model.copyMarkdownReport()
                    } label: {
                        Label(
                            model.copiedFeedback ? settings.t(.actionCopied) : settings.t(.actionExportReport),
                            systemImage: model.copiedFeedback ? "checkmark" : "doc.on.doc"
                        )
                    }
                    .buttonStyle(.bordered)

                    Menu {
                        Button(settings.t(.actionSaveReport)) {
                            model.saveMarkdownReport()
                        }
                        Button(settings.t(.actionExportJSON)) {
                            model.saveJSONReport()
                        }
                        Divider()
                        Button(settings.t(.actionCopyMaskedReport)) {
                            model.copyMarkdownReport(redacted: true)
                        }
                        Button(settings.t(.actionSaveMaskedMarkdown)) {
                            model.saveMarkdownReport(redacted: true)
                        }
                        Button(settings.t(.actionSaveMaskedJSON)) {
                            model.saveJSONReport(redacted: true)
                        }
                    } label: {
                        Image(systemName: "square.and.arrow.up")
                    }
                    .menuStyle(.borderedButton)
                    .fixedSize()
                    .help(settings.t(.actionSaveReport))
                    .accessibilityLabel(settings.t(.actionSaveReport))
                }
            }

            Button {
                model.openDiagnosticReportSheet()
            } label: {
                Image(systemName: "stethoscope")
            }
            .buttonStyle(.bordered)
            .help(settings.t(.diagnosticsButtonTitle))
            .accessibilityLabel(settings.t(.diagnosticsButtonTitle))

            Button {
                openWindow(id: WindowID.log)
            } label: {
                Image(systemName: "terminal")
            }
            .buttonStyle(.bordered)
            .help(settings.t(.menuShowLog))
            .accessibilityLabel(settings.t(.menuShowLog))

            SettingsLink {
                Image(systemName: "gearshape")
            }
            .buttonStyle(.bordered)
            .help(settings.t(.settingsGeneral))
            .accessibilityLabel(settings.t(.settingsGeneral))
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .background(Color(NSColor.windowBackgroundColor))
    }

    // MARK: - Toplu Klasör Denetim Görünümü

    private var batchAuditView: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text(settings.t(.batchTitle))
                            .font(.title3.bold())
                        if let summary = model.batchSummary, summary.wasCancelled, !model.isBatchScanning {
                            Text(settings.t(.batchPartialCancelledBadge))
                                .font(.caption2.bold())
                                .padding(.horizontal, 8)
                                .padding(.vertical, 3)
                                .background(Color.orange.opacity(0.18), in: Capsule())
                                .foregroundStyle(.orange)
                        }
                    }
                    if let summary = model.batchSummary {
                        Text(settings.t(.batchSummaryStats, summary.totalCount, summary.cleanCount, summary.warningCount, summary.tamperedCount))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        Text(settings.t(.batchEmptyHint))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if model.isBatchScanning {
                    Button(role: .cancel) {
                        model.cancelBatchScan()
                    } label: {
                        Label(settings.t(.actionCancelBatch), systemImage: "stop.circle")
                    }
                    .buttonStyle(.bordered)
                } else {
                    Button {
                        model.presentBatchFolderPanel()
                    } label: {
                        Label(settings.t(.actionBatchScan), systemImage: "folder.badge.magnifyingglass")
                    }
                    .buttonStyle(.borderedProminent)
                }
                if model.batchSummary != nil && !model.isBatchScanning {
                    Button {
                        model.exportBatchMarkdown()
                    } label: {
                        Label(settings.t(.batchExportMarkdown), systemImage: "doc.text")
                    }
                    .buttonStyle(.bordered)
                    Button {
                        model.exportBatchJSON()
                    } label: {
                        Label(settings.t(.batchExportJSON), systemImage: "curlybraces")
                    }
                    .buttonStyle(.bordered)
                }
            }
            .padding(.horizontal, 20)
            .padding(.top, 16)

            if model.isBatchScanning {
                VStack(alignment: .leading, spacing: 6) {
                    let total = max(1, model.batchProgress.total)
                    ProgressView(value: Double(model.batchProgress.current), total: Double(total))
                    Text(settings.t(.batchScanningProgress, model.batchProgress.current, model.batchProgress.total, model.batchProgress.name))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 20)
            }

            if let summary = model.batchSummary {
                if summary.reports.isEmpty && !model.isBatchScanning {
                    ContentUnavailableView(
                        settings.t(.batchTitle),
                        systemImage: "app.dashed",
                        description: Text(settings.t(.batchNoBundlesFound))
                    )
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    let query = batchSearchText.trimmingCharacters(in: .whitespacesAndNewlines)
                    let filteredReports = summary.reports.filter { item in
                        let matchesFilter: Bool = switch batchFilter {
                        case .all: true
                        case .issues: item.verdict != .clean
                        case .quarantined: item.isQuarantined
                        }
                        let matchesQuery = query.isEmpty
                            || item.bundleName.localizedCaseInsensitiveContains(query)
                            || item.bundleId.localizedCaseInsensitiveContains(query)
                            || item.teamIdentifier.localizedCaseInsensitiveContains(query)
                        return matchesFilter && matchesQuery
                    }

                    HStack(spacing: 12) {
                        TextField(settings.t(.batchSearchPlaceholder), text: $batchSearchText)
                            .textFieldStyle(.roundedBorder)

                        Picker("", selection: $batchFilter) {
                            ForEach(BatchFilter.allCases) { filter in
                                Text(settings.t(filter.titleKey)).tag(filter)
                            }
                        }
                        .pickerStyle(.segmented)
                        .frame(maxWidth: 340)

                        Text(settings.t(.filterMatchCount, filteredReports.count, summary.reports.count))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    }
                    .padding(.horizontal, 20)

                    ScrollView {
                        LazyVStack(spacing: 8) {
                            ForEach(filteredReports, id: \.bundlePath) { item in
                                HStack(spacing: 12) {
                                    Image(nsImage: NSWorkspace.shared.icon(forFile: item.bundlePath))
                                        .resizable()
                                        .frame(width: 28, height: 28)

                                    Image(systemName: iconForVerdict(item.verdict))
                                        .foregroundStyle(colorForVerdict(item.verdict))

                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(OpenSafety.visibleName(item.bundleName))
                                            .font(.subheadline.bold())
                                        Text("\(item.bundleId) · \(item.shortVersion) (\(item.teamIdentifier == "not set" ? settings.t(.valueNotSet) : item.teamIdentifier))")
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                            .lineLimit(1)
                                    }

                                    Spacer()

                                    if item.isQuarantined {
                                        Text(settings.t(.valueQuarantined))
                                            .font(.caption2.bold())
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 3)
                                            .background(Color.orange.opacity(0.18), in: Capsule())
                                            .foregroundStyle(.orange)
                                    }

                                    Text("\(item.scanDurationMs) ms")
                                        .font(.caption2.monospacedDigit())
                                        .foregroundStyle(.tertiary)

                                    Button(settings.t(.batchOpenSelected)) {
                                        model.openBatchReport(item)
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.small)
                                }
                                .padding(10)
                                .background(colorForVerdict(item.verdict).opacity(0.06))
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                                .contextMenu {
                                    Button(settings.t(.batchOpenSelected)) {
                                        model.openBatchReport(item)
                                    }
                                    Button(settings.t(.actionRevealInFinder)) {
                                        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: item.bundlePath)])
                                    }
                                    if item.isQuarantined {
                                        Divider()
                                        Button(settings.t(.actionRemoveQuarantine)) {
                                            model.removeQuarantine(for: URL(fileURLWithPath: item.bundlePath))
                                        }
                                        .disabled(model.isRemovingQuarantine)
                                    }
                                }
                            }
                        }
                        .padding(.horizontal, 20)
                        .padding(.bottom, 16)
                    }
                }
            } else if !model.isBatchScanning {
                ContentUnavailableView(
                    settings.t(.batchTitle),
                    systemImage: "square.grid.2x2",
                    description: Text(settings.t(.batchEmptyHint))
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func verdictBanner(for report: BundleAuditReport) -> some View {
        let color = colorForVerdict(report.verdict)
        let icon: String
        let textKey: LKey

        switch report.verdict {
        case .clean:
            icon = "checkmark.shield.fill"
            textKey = .verdictClean
        case .warning:
            icon = "exclamationmark.shield.fill"
            textKey = .verdictWarning
        case .tampered:
            icon = "xmark.shield.fill"
            textKey = .verdictTampered
        }

        return HStack(spacing: 14) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: report.bundlePath))
                .resizable()
                .frame(width: 38, height: 38)

            Image(systemName: icon)
                .font(.system(size: 24))
                .foregroundStyle(color)

            VStack(alignment: .leading, spacing: 3) {
                Text(settings.t(textKey))
                    .font(.headline)
                    .foregroundStyle(color)
                HStack(spacing: 10) {
                    Text(report.bundlePath)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text("• \(report.scanDurationMs) ms")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.tertiary)
                    if report.isDevelopmentSigned {
                        TagCapsule(text: settings.t(.signingProfileDevCert), color: .blue)
                    }
                }
            }
            Spacer()

            if report.isQuarantined {
                Button {
                    model.removeQuarantineForCurrentBundle()
                } label: {
                    Label(settings.t(.actionRemoveQuarantine), systemImage: "touchid")
                }
                .buttonStyle(.borderedProminent)
                .tint(.orange)
                .controlSize(.small)
                .disabled(model.isRemovingQuarantine)
                .help(settings.t(.actionRemoveQuarantineHelp))
            }

            Button {
                model.revealCurrentBundle()
            } label: {
                Label(settings.t(.actionRevealInFinder), systemImage: "folder")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)

            Button {
                model.refreshCurrentBundle()
            } label: {
                Label(settings.t(.actionRefresh), systemImage: "arrow.clockwise")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .help(settings.t(.actionRefreshHelp))

            Button {
                model.clearReport()
            } label: {
                Label(settings.t(.actionBackHome), systemImage: "house")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .help(settings.t(.actionBackHomeHelp))
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .background(color.opacity(0.12))
    }

    private func overviewSection(_ report: BundleAuditReport) -> some View {
        VStack(alignment: .leading, spacing: 18) {
            if let qFeedback = model.quarantineFeedback {
                HStack(spacing: 8) {
                    Image(systemName: qFeedback.isSuccess ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(qFeedback.isSuccess ? .green : .orange)
                    Text(qFeedback.text)
                        .font(.callout)
                        .foregroundStyle(qFeedback.isSuccess ? Color.primary : Color.orange)
                    Spacer()
                    Button {
                        model.quarantineFeedback = nil
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(settings.t(.buttonClose))
                }
                .padding(10)
                .background((qFeedback.isSuccess ? Color.green : Color.orange).opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            if settings.watchedFolderEnabled && model.notificationService.authState == .denied {
                HStack(spacing: 8) {
                    Image(systemName: "bell.slash.fill")
                        .foregroundStyle(.orange)
                    Text(settings.t(.permissionBannerNotificationsDenied))
                        .font(.callout)
                        .foregroundStyle(.orange)
                    Spacer()
                    Button(settings.t(.permissionBannerOpenSettings)) {
                        model.notificationService.openSystemSettings()
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
                .padding(10)
                .background(Color.orange.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            } else if settings.watchedFolderEnabled && model.notificationService.authState == .unavailable {
                HStack(spacing: 8) {
                    Image(systemName: "bell.badge.slash")
                        .foregroundStyle(.orange)
                    Text(settings.t(.permissionBannerNotificationsUnavailable))
                        .font(.callout)
                        .foregroundStyle(.orange)
                    Spacer()
                }
                .padding(10)
                .background(Color.orange.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            if model.gatekeeperStatus == .disabled {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.shield.fill")
                        .foregroundStyle(.orange)
                    Text(settings.t(.gatekeeperDisabledBannerNotice))
                        .font(.callout)
                        .foregroundStyle(.orange)
                    Spacer()
                }
                .padding(10)
                .background(Color.orange.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            if !report.deceptiveNames.isEmpty {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(settings.t(.bannerNameSpoofingWarning))
                            .font(.callout.weight(.semibold))
                            .foregroundStyle(.orange)
                        Text(report.deceptiveNames.joined(separator: ", "))
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    Spacer()
                }
                .padding(10)
                .background(Color.orange.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            if let vol = report.volumeEncryption, vol.needsUnencryptedRemovableWarning {
                HStack(spacing: 8) {
                    Image(systemName: "externaldrive.badge.exclamationmark")
                        .foregroundStyle(.orange)
                    Text(settings.t(.volumeUnencryptedRemovableBanner, vol.volumeName))
                        .font(.callout)
                        .foregroundStyle(.orange)
                    Spacer()
                }
                .padding(10)
                .background(Color.orange.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            if let sigChange = model.signatureChange {
                let isSevere = sigChange.kind != .updatedSameSigner
                let bannerColor: Color = sigChange.kind == .lostSignature ? .red : (sigChange.kind == .signerChanged ? .orange : .blue)
                let iconName = sigChange.kind == .lostSignature ? "xmark.shield.fill" : (sigChange.kind == .signerChanged ? "exclamationmark.triangle.fill" : "arrow.triangle.2.circlepath")
                let messageText: String = switch sigChange.kind {
                case .signerChanged:
                    settings.t(.sigChangeBannerSignerChanged, sigChange.previousSignerDisplay, sigChange.currentSignerDisplay)
                case .lostSignature:
                    settings.t(.sigChangeBannerLostSignature, sigChange.previousSignerDisplay)
                case .updatedSameSigner:
                    settings.t(.sigChangeBannerSameSignerUpdated, sigChange.currentSignerDisplay)
                }
                HStack(spacing: 10) {
                    Image(systemName: iconName)
                        .foregroundStyle(bannerColor)
                    Text(messageText)
                        .font(.callout)
                        .foregroundStyle(isSevere ? bannerColor : .primary)
                    Spacer()
                    if isSevere {
                        Button(settings.t(.sigChangeAcknowledge)) {
                            model.acknowledgeSignatureBaselineChange()
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    } else {
                        Button {
                            model.signatureChange = nil
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel(settings.t(.buttonClose))
                    }
                }
                .padding(10)
                .background(bannerColor.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            if settings.aiSuggestions {
                aiAssistantCard(for: report)
            }

            GroupBox(label: Label(settings.t(.sectionAnomalies), systemImage: "stethoscope").font(.headline)) {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(report.findings) { finding in
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: iconForSeverity(finding.severity))
                                .foregroundStyle(colorForSeverity(finding.severity))
                                .font(.title3)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(settings.t(finding.titleKey))
                                    .font(.subheadline.bold())
                                Text(settings.t(finding.descKey) + finding.detailSuffix)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                            }
                            Spacer()
                        }
                        .padding(8)
                        .background(colorForSeverity(finding.severity).opacity(0.08))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    }
                }
                .padding(.top, 6)
            }

            HStack(alignment: .top, spacing: 16) {
                GroupBox(label: Label(settings.t(.sectionBundleInfo), systemImage: "info.circle").font(.headline)) {
                    VStack(alignment: .leading, spacing: 8) {
                        infoRow(settings.t(.fieldTargetKind), settings.t(report.targetKind.labelKey))
                        infoRow(settings.t(.fieldBundleName), OpenSafety.visibleName(report.bundleName), highlight: !report.deceptiveNames.isEmpty)
                        infoRow(settings.t(.fieldBundleId), report.bundleId, monospaced: true)
                        infoRow(settings.t(.fieldVersion), "\(report.shortVersion) (\(report.buildVersion))")
                        infoRow(settings.t(.fieldExecutable), OpenSafety.visibleName(report.executableRelativePath), monospaced: true)
                        infoRow(settings.t(.fieldExecutableSha256), report.executableSHA256, monospaced: true)
                        if report.executableSHA512 != "-" {
                            infoRow(settings.t(.fieldExecutableSha512), report.executableSHA512, monospaced: true)
                        }
                        if let vol = report.volumeEncryption {
                            let encKey: LKey = vol.isEncrypted == true ? .volumeEncryptedLabel : (vol.isEncrypted == false ? .volumeUnencryptedLabel : .volumeUnknownLabel)
                            infoRow(
                                settings.t(.fieldVolumeEncryption),
                                "\(vol.volumeName) (\(vol.format) — \(settings.t(encKey)))",
                                highlight: vol.needsUnencryptedRemovableWarning
                            )
                        }
                        infoRow(
                            settings.t(.fieldArchitectures),
                            report.architectures.isEmpty ? "-" : report.architectures.joined(separator: ", "),
                            monospaced: true
                        )
                        infoRow(
                            settings.t(.fieldRpaths),
                            report.lcRpaths.isEmpty ? settings.t(.valueNone) : report.lcRpaths.joined(separator: "\n"),
                            monospaced: true
                        )
                        infoRow(settings.t(.fieldResourcesDate), report.plistModDate, monospaced: true)
                        infoRow(
                            settings.t(.fieldExecutableDate),
                            report.executableModDate,
                            monospaced: true,
                            highlight: report.verdict == .tampered && report.plistModDate != report.executableModDate
                        )
                        infoRow(settings.t(.fieldScanDuration), "\(report.scanDurationMs) ms", monospaced: true)
                    }
                    .padding(.top, 6)
                }

                GroupBox(label: Label(settings.t(.sectionCodesign), systemImage: "signature").font(.headline)) {
                    let isTampered = report.verdict == .tampered
                    VStack(alignment: .leading, spacing: 8) {
                        infoRow(
                            settings.t(.fieldTeamId),
                            report.teamIdentifier == "not set" ? settings.t(.valueNotSet) : report.teamIdentifier,
                            monospaced: true,
                            highlight: isTampered && report.teamIdentifier == "not set"
                        )
                        infoRow(
                            settings.t(.fieldSigningProfile),
                            settings.t(model.signingProfileKey(for: report))
                        )
                        infoRow(
                            settings.t(.fieldAuthorities),
                            report.authorities.isEmpty ? "-" : report.authorities.joined(separator: " → "),
                            monospaced: true,
                            highlight: isTampered && !report.authorities.contains(where: { $0.contains("Apple Root CA") })
                        )
                        infoRow(settings.t(.fieldSignedTime), report.signedTimestamp, monospaced: true)
                        infoRow(
                            settings.t(.fieldHardenedRuntime),
                            report.hasHardenedRuntime ? settings.t(.valueEnabled) : settings.t(.valueDisabled),
                            highlight: isTampered && !report.hasHardenedRuntime
                        )
                        infoRow(
                            settings.t(.fieldNotarized),
                            report.isNotarized ? settings.t(.valueYes) : settings.t(.valueNo),
                            highlight: false
                        )
                        infoRow(
                            settings.t(.fieldQuarantine),
                            report.isQuarantined ? settings.t(.valueQuarantined) : settings.t(.valueNotQuarantined),
                            highlight: report.isQuarantined
                        )
                        infoRow(
                            settings.t(.fieldEntitlements),
                            report.entitlements.isEmpty ? settings.t(.valueNone) : report.entitlements.joined(separator: ", "),
                            monospaced: true
                        )
                        HStack(alignment: .top, spacing: 8) {
                            infoRow(
                                settings.t(.fieldSpctlAssessment),
                                report.spctlAssessment ?? settings.t(.valueNotChecked),
                                monospaced: true
                            )
                            Button {
                                model.runGatekeeperAssessment()
                            } label: {
                                if model.isAssessingGatekeeper {
                                    ProgressView().controlSize(.small)
                                } else {
                                    Label(settings.t(.actionAssessGatekeeper), systemImage: "checkmark.shield")
                                }
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            .disabled(model.isAssessingGatekeeper)
                            .help(settings.t(.actionAssessGatekeeperHelp))
                        }
                        if let rev = report.revocationStatus {
                            infoRow(
                                settings.t(.fieldRevocation),
                                settings.t(rev.labelKey),
                                monospaced: true,
                                highlight: rev == .revoked
                            )
                        }
                        infoRow(settings.t(.fieldCdhash), report.cdHash, monospaced: true)
                        infoRow(settings.t(.fieldGatekeeper), report.gatekeeperStatus, monospaced: true)
                        if let fw = report.firewallAppState {
                            let fwKey: LKey = fw.isBlocked ? .firewallAppBlocked : (fw.ruleStatus == .permitted ? .firewallAppPermitted : .firewallAppUnknown)
                            infoRow(
                                settings.t(.fieldFirewallState),
                                settings.t(fwKey),
                                highlight: fw.isBlocked
                            )
                            if fw.isBlocked {
                                VStack(alignment: .leading, spacing: 6) {
                                    Text(settings.t(.firewallAppBlockedNote))
                                        .font(.caption)
                                        .foregroundStyle(.orange)
                                    HStack(spacing: 8) {
                                        Text(fw.unblockCommand)
                                            .font(.system(.caption2, design: .monospaced))
                                            .foregroundStyle(.secondary)
                                            .textSelection(.enabled)
                                        Spacer()
                                        Button(settings.t(.firewallCopyUnblockCommand)) {
                                            model.copyUnblockFirewallCommand(for: fw.targetPath)
                                        }
                                        .buttonStyle(.bordered)
                                        .controlSize(.small)
                                    }
                                }
                                .padding(8)
                                .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
                            }
                        }
                    }
                    .padding(.top, 6)
                }
            }

            checksumVerifierSection(for: report)

            if let policy = report.internetAccessPolicy {
                internetAccessPolicySection(policy)
            }

            GroupBox(label: Label(settings.t(.sectionEntitlementRisks), systemImage: "lock.shield").font(.headline)) {
                VStack(alignment: .leading, spacing: 10) {
                    if report.entitlementRisks.isEmpty {
                        Label(settings.t(.entitlementRisksNone), systemImage: "checkmark.circle")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(report.entitlementRisks) { risk in
                            let riskColor: Color = switch risk.level {
                            case .high: .red
                            case .elevated: .orange
                            case .info: .blue
                            }
                            HStack(alignment: .top, spacing: 10) {
                                Text(settings.t(risk.level.labelKey))
                                    .font(.caption2.bold())
                                    .foregroundStyle(riskColor)
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 3)
                                    .background(riskColor.opacity(0.14), in: Capsule())

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(settings.t(risk.titleKey))
                                        .font(.subheadline.bold())
                                    Text(risk.entitlementKey)
                                        .font(.system(.caption2, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                        .textSelection(.enabled)
                                    Text(settings.t(risk.detailKey))
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                            }
                            .padding(8)
                            .background(riskColor.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
                        }
                    }

                    Text(settings.t(.entitlementRisksInfoNote))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, 6)
            }
        }
    }

    private func checksumVerifierSection(for report: BundleAuditReport) -> some View {
        @Bindable var model = model
        let evaluation = model.evaluateExpectedChecksum(for: report)
        return GroupBox(label: Label(settings.t(.sectionChecksumVerifier), systemImage: "checkmark.seal").font(.headline)) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 8) {
                    TextField(settings.t(.checksumPlaceholder), text: $model.expectedChecksumInput)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.callout, design: .monospaced))

                    if !model.expectedChecksumInput.isEmpty {
                        Button {
                            model.clearExpectedChecksum()
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.borderless)
                        .help(settings.t(.checksumClearButton))
                        .accessibilityLabel(settings.t(.checksumClearButton))
                    }

                    Button {
                        model.presentChecksumFilePanel()
                    } label: {
                        Label(settings.t(.checksumLoadFile), systemImage: "doc.text.magnifyingglass")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }

                switch evaluation {
                case .empty:
                    EmptyView()
                case .matched(let algo):
                    Label(settings.t(.checksumMatchBadge, algo.rawValue), systemImage: "checkmark.circle.fill")
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(.green)
                case .mismatch(let algo):
                    Label(settings.t(.checksumMismatchBadge, algo.rawValue), systemImage: "xmark.octagon.fill")
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(.red)
                case .weakAlgorithm(let algo):
                    Label(settings.t(.checksumWeakAlgoWarning, algo), systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.orange)
                case .notFoundForFile(let name):
                    Label(settings.t(.checksumNotFoundWarning, name), systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.orange)
                case .unavailable(let algo):
                    Label(settings.t(.checksumUnavailableWarning, algo.rawValue), systemImage: "exclamationmark.circle")
                        .font(.callout)
                        .foregroundStyle(.orange)
                case .unrecognized:
                    Label(settings.t(.checksumUnrecognizedWarning), systemImage: "questionmark.circle")
                        .font(.callout)
                        .foregroundStyle(.orange)
                }
            }
            .padding(.top, 6)
        }
    }

    private func internetAccessPolicySection(_ policy: InternetAccessPolicy) -> some View {
        GroupBox(label: Label(settings.t(.sectionInternetAccessPolicy), systemImage: "network.badge.shield.half.filled").font(.headline)) {
            VStack(alignment: .leading, spacing: 10) {
                if let dev = policy.developerName, !dev.isEmpty {
                    infoRow(settings.t(.iapDeveloperLabel), dev)
                }
                Text(policy.applicationDescription)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let site = policy.website, let url = URL(string: site) {
                    HStack(spacing: 6) {
                        Text(settings.t(.iapWebsiteLabel))
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                        Link(site, destination: url)
                            .font(.caption)
                    }
                }
                if !policy.services.isEmpty {
                    Text(settings.t(.iapServicesLabel))
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    ForEach(policy.services) { svc in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(svc.name)
                                .font(.caption.bold())
                            Text(svc.purpose)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))
                    }
                }
                Text(settings.t(.iapConnectionsLabel))
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                if policy.connections.isEmpty {
                    Text(settings.t(.iapNoConnections))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(policy.connections) { conn in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(spacing: 6) {
                                TagCapsule(
                                    text: settings.t(conn.isIncoming ? .iapDirectionIncoming : .iapDirectionOutgoing),
                                    color: conn.isIncoming ? .orange : .blue
                                )
                                if conn.isEssential {
                                    TagCapsule(text: settings.t(.iapEssentialBadge), color: .green)
                                }
                                let protoPrefix = conn.networkProtocol.map { "\($0) " } ?? ""
                                let portSuffix = conn.portSpec.map { ":\($0)" } ?? ""
                                Text("\(protoPrefix)\(conn.hosts.joined(separator: ", "))\(portSuffix)")
                                    .font(.system(.caption, design: .monospaced).bold())
                                    .textSelection(.enabled)
                            }
                            Text(conn.purpose)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            if let deny = conn.denyConsequences {
                                Text("\(settings.t(.iapDenyLabel)): \(deny)")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                        }
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 6))
                    }
                }
            }
            .padding(.top, 6)
        }
    }

    @ViewBuilder
    private func aiAssistantCard(for report: BundleAuditReport) -> some View {
        @Bindable var settings = settings
        let existingSummary = model.aiSummary(for: report)
        let warning = model.aiSummaryError ?? model.currentProviderWarning()

        GroupBox(label: Label(settings.t(.aiForensicSection), systemImage: "sparkles").font(.headline)) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    Picker(settings.t(.settingsAIProvider), selection: $settings.aiProvider) {
                        ForEach(SuggestionProvider.allCases) { provider in
                            Text(provider == .automatic ? settings.t(.settingsAIAutomatic) : provider.displayName)
                                .tag(provider)
                        }
                    }
                    .frame(maxWidth: 260)
                    .onChange(of: settings.aiProvider) {
                        model.aiSummaryError = nil
                        model.updateSuggestionModel()
                        Task { await model.refreshLocalModels() }
                    }

                    if let server = settings.aiProvider.server {
                        let models = model.localModels[server] ?? []
                        let selected = settings.aiModel(for: server)
                        Picker(settings.t(.settingsAIModel), selection: Binding(
                            get: { settings.aiModel(for: server) },
                            set: {
                                settings.setAIModel($0, for: server)
                                model.aiSummaryError = nil
                                model.updateSuggestionModel()
                            }
                        )) {
                            ForEach(models.contains(selected) || selected.isEmpty ? models : [selected] + models, id: \.self) {
                                Text($0).tag($0)
                            }
                        }
                        .frame(maxWidth: 220)
                        .disabled(models.isEmpty)

                        Button {
                            Task {
                                model.aiSummaryError = nil
                                await model.refreshLocalModels()
                            }
                        } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                        .help(settings.t(.settingsAIRefresh))
                        .accessibilityLabel(settings.t(.settingsAIRefresh))
                    }

                    Spacer()

                    if model.isGeneratingAISummary {
                        Button(settings.t(.aiForensicCancel), role: .cancel) {
                            model.cancelAISummary()
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    } else {
                        Button {
                            Task { await model.generateAISummary(for: report) }
                        } label: {
                            Label(
                                existingSummary == nil ? settings.t(.aiForensicAnalyze) : settings.t(.aiForensicReanalyze),
                                systemImage: "sparkles"
                            )
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                    }
                }

                if model.isGeneratingAISummary {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text(settings.t(.aiForensicThinking))
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                } else if let warning {
                    Label(warning, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }

                if let summary = existingSummary {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(summary.text)
                            .font(.body)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                        HStack {
                            Label(settings.t(.aiForensicSource, summary.source), systemImage: "cpu")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Button {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(summary.text, forType: .string)
                                aiCopiedFeedback = true
                                Task { @MainActor in
                                    try? await Task.sleep(for: .seconds(2))
                                    aiCopiedFeedback = false
                                }
                            } label: {
                                Label(
                                    aiCopiedFeedback ? settings.t(.actionCopied) : settings.t(.buttonCopy),
                                    systemImage: aiCopiedFeedback ? "checkmark" : "doc.on.doc"
                                )
                            }
                            .buttonStyle(.borderless)
                            .font(.caption)
                        }
                        Text(settings.t(.aiForensicNote))
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    .padding(10)
                    .background(Color.accentColor.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }
            }
            .padding(.top, 6)
        }
        .task(id: report.bundlePath) {
            await model.refreshLocalModels()
        }
    }

    private func dylibsSection(_ report: BundleAuditReport) -> some View {
        let query = dylibSearchText.trimmingCharacters(in: .whitespacesAndNewlines)

        let filteredBundled = report.bundledLibraries.filter { item in
            let matchesFilter: Bool = switch dylibFilter {
            case .all, .nonSystem: true
            case .suspicious: !item.suspiciousSymbols.isEmpty || item.isTimestampAnomaly
            }
            let matchesQuery = query.isEmpty || item.name.localizedCaseInsensitiveContains(query)
            return matchesFilter && matchesQuery
        }

        let filteredLinked = report.linkedDylibs.filter { dylib in
            let matchesFilter: Bool = switch dylibFilter {
            case .all: true
            case .nonSystem: !dylib.isSystem
            case .suspicious: dylib.isSuspicious
            }
            let matchesQuery = query.isEmpty || dylib.path.localizedCaseInsensitiveContains(query)
            return matchesFilter && matchesQuery
        }

        return VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 12) {
                TextField(settings.t(.searchDylibsPlaceholder), text: $dylibSearchText)
                    .textFieldStyle(.roundedBorder)

                Picker("", selection: $dylibFilter) {
                    ForEach(DylibFilter.allCases) { filter in
                        Text(settings.t(filter.titleKey)).tag(filter)
                    }
                }
                .pickerStyle(.segmented)
                .frame(maxWidth: 320)
            }

            GroupBox {
                if filteredBundled.isEmpty {
                    Text(settings.t(.emptyNoBundledDylibs))
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(filteredBundled) { item in
                            HStack {
                                Image(systemName: !item.suspiciousSymbols.isEmpty ? "exclamationmark.octagon.fill" : "cube.box")
                                    .foregroundStyle(!item.suspiciousSymbols.isEmpty ? .red : .secondary)
                                Text(item.name)
                                    .font(.system(.body, design: .monospaced).bold())
                                Spacer()
                                Text(formattedLibrarySize(item.sizeBytes))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Text(item.modifiedDate)
                                    .font(.system(.caption, design: .monospaced))
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(item.isTimestampAnomaly ? Color.red.opacity(0.18) : Color.secondary.opacity(0.1))
                                    .clipShape(RoundedRectangle(cornerRadius: 4))
                            }
                            .padding(6)
                            .background(!item.suspiciousSymbols.isEmpty ? Color.red.opacity(0.08) : Color.clear)
                            .clipShape(RoundedRectangle(cornerRadius: 6))
                        }
                    }
                    .padding(.top, 6)
                }
            } label: {
                HStack {
                    Label(settings.t(.sectionBundledDylibs), systemImage: "shippingbox").font(.headline)
                    Spacer()
                    Text(settings.t(.filterMatchCount, filteredBundled.count, report.bundledLibraries.count))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    copyIconButton(
                        tag: "bundled",
                        text: filteredBundled.map { "\($0.name)\t\($0.modifiedDate)" }.joined(separator: "\n")
                    )
                }
            }

            GroupBox {
                LazyVStack(alignment: .leading, spacing: 6) {
                    ForEach(filteredLinked) { dylib in
                        HStack(spacing: 8) {
                            Image(systemName: dylib.isSuspicious ? "bolt.trianglebadge.exclamationmark.fill" : (dylib.isSystem ? "apple.logo" : "puzzlepiece.extension"))
                                .foregroundStyle(dylib.isSuspicious ? .red : (dylib.isSystem ? .secondary : .blue))
                            Text(dylib.path)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(dylib.isSuspicious ? .red : .primary)
                                .textSelection(.enabled)
                            Spacer()
                        }
                        .padding(.vertical, 3)
                        .padding(.horizontal, 6)
                        .background(dylib.isSuspicious ? Color.red.opacity(0.12) : Color.clear)
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                    }
                }
                .padding(.top, 6)
            } label: {
                HStack {
                    Label(settings.t(.sectionLinkedDylibs), systemImage: "link").font(.headline)
                    Spacer()
                    Text(settings.t(.filterMatchCount, filteredLinked.count, report.linkedDylibs.count))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    copyIconButton(
                        tag: "linked",
                        text: filteredLinked.map(\.path).joined(separator: "\n")
                    )
                }
            }
        }
    }

    private func symbolsSection(_ report: BundleAuditReport) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            GroupBox(label: Label(settings.t(.sectionHookIndicators), systemImage: "cpu").font(.headline)) {
                if report.hookCategories.isEmpty {
                    Text(settings.t(.emptyNoHookSymbols))
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    VStack(alignment: .leading, spacing: 12) {
                        ForEach(report.hookCategories) { cat in
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text(cat.libraryName)
                                        .font(.system(.subheadline, design: .monospaced).bold())
                                        .foregroundStyle(.red)
                                    Text("•")
                                    Text(settings.t(cat.categoryKey))
                                        .font(.subheadline.bold())
                                }
                                FlowLayoutSymbols(symbols: cat.symbols)
                            }
                            .padding(10)
                            .background(Color.red.opacity(0.07))
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                        }
                    }
                    .padding(.top, 6)
                }
            }
        }
    }

    private func rawOutputSection(_ report: BundleAuditReport) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            GroupBox {
                rawLinesBlock(report.rawCodesignOutput)
            } label: {
                HStack {
                    Text("codesign -dvvv").font(.system(.headline, design: .monospaced))
                    Spacer()
                    copyIconButton(tag: "codesign", text: report.rawCodesignOutput)
                }
            }

            GroupBox {
                rawLinesBlock(report.rawOtoolOutput)
            } label: {
                HStack {
                    Text("otool -L").font(.system(.headline, design: .monospaced))
                    Spacer()
                    copyIconButton(tag: "otool", text: report.rawOtoolOutput)
                }
            }

            if !report.lcRpaths.isEmpty {
                let rpathsText = report.lcRpaths.joined(separator: "\n")
                GroupBox {
                    rawLinesBlock(rpathsText)
                } label: {
                    HStack {
                        Text(settings.t(.rawRpathsTitle)).font(.system(.headline, design: .monospaced))
                        Spacer()
                        copyIconButton(tag: "rpaths", text: rpathsText)
                    }
                }
            }

            if !report.rawEntitlementsOutput.isEmpty {
                GroupBox {
                    rawLinesBlock(report.rawEntitlementsOutput)
                } label: {
                    HStack {
                        Text(settings.t(.rawEntitlementsTitle)).font(.system(.headline, design: .monospaced))
                        Spacer()
                        copyIconButton(tag: "entitlements", text: report.rawEntitlementsOutput)
                    }
                }
            }

            if let spctl = report.spctlAssessment, !spctl.isEmpty {
                GroupBox {
                    rawLinesBlock(spctl)
                } label: {
                    HStack {
                        Text(settings.t(.rawGatekeeperTitle)).font(.system(.headline, design: .monospaced))
                        Spacer()
                        copyIconButton(tag: "spctl", text: spctl)
                    }
                }
            }
        }
    }

    private func rawLinesBlock(_ text: String) -> some View {
        let lines = text.isEmpty ? ["-"] : text.components(separatedBy: .newlines)
        return LazyVStack(alignment: .leading, spacing: 2) {
            ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                Text(line.isEmpty ? " " : line)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(6)
    }

    private func copyIconButton(tag: String, text: String) -> some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
            rawCopiedTag = tag
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(1.8))
                if rawCopiedTag == tag { rawCopiedTag = nil }
            }
        } label: {
            Label(
                rawCopiedTag == tag ? settings.t(.actionCopied) : settings.t(.buttonCopy),
                systemImage: rawCopiedTag == tag ? "checkmark" : "doc.on.doc"
            )
            .font(.caption)
        }
        .buttonStyle(.borderless)
        .disabled(text.isEmpty)
    }

    private func formattedLibrarySize(_ bytes: Int64) -> String {
        guard bytes > 0 else { return "-" }
        return ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    private func infoRow(_ label: String, _ value: String, monospaced: Bool = false, highlight: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(monospaced ? .system(.callout, design: .monospaced) : .callout)
                .foregroundStyle(highlight ? .red : .primary)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func iconForSeverity(_ severity: FindingSeverity) -> String {
        switch severity {
        case .critical: return "exclamationmark.octagon.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .info: return "checkmark.circle.fill"
        }
    }

    private func colorForSeverity(_ severity: FindingSeverity) -> Color {
        switch severity {
        case .critical: return .red
        case .warning: return .orange
        case .info: return .green
        }
    }

    private func handleDroppedProviders(_ providers: [NSItemProvider]) -> Bool {
        guard settings.autoScanOnDrop else { return false }
        let typeId = UTType.fileURL.identifier
        let fileProviders = providers.filter { $0.hasItemConformingToTypeIdentifier(typeId) }
        guard let provider = fileProviders.first else { return false }

        _ = provider.loadDataRepresentation(forTypeIdentifier: typeId) { data, _ in
            guard let data = data,
                  let finalURL = URL(dataRepresentation: data, relativeTo: nil) else { return }
            Task { @MainActor in
                var isDir: ObjCBool = false
                let resolvedTarget = model.resolveAuditTargetURL(from: finalURL)
                if ForensicScanner.supportedBundleExtensions.contains(resolvedTarget.pathExtension.lowercased()) {
                    model.scan(resolvedTarget)
                } else if FileManager.default.fileExists(atPath: finalURL.path, isDirectory: &isDir), isDir.boolValue {
                    model.startBatchScan(in: finalURL)
                } else if ForensicScanner.isSupportedAuditURL(resolvedTarget) {
                    model.scan(resolvedTarget)
                }
            }
        }
        return true
    }
}

struct FlowLayoutSymbols: View {
    let symbols: [String]

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 220), alignment: .leading)], alignment: .leading, spacing: 6) {
            ForEach(symbols, id: \.self) { sym in
                Text(sym)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color(NSColor.controlBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: 4))
            }
        }
    }
}
