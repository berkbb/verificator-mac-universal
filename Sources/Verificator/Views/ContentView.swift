// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import VerificatorCore
import SwiftUI
import UniformTypeIdentifiers

enum SidebarItem: Hashable {
    case home
    case tab(Int)
    case recent(URL)
}

struct ContentView: View {
    @Environment(AppModel.self) private var model
    @Environment(AppSettings.self) private var settings
    @Environment(\.openWindow) private var openWindow
    @State private var isDropTargeted = false
    @State private var columnVisibility: NavigationSplitViewVisibility = .all

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
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
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
        .navigationTitle(model.report?.bundleName ?? settings.t(.appName))
        .navigationSubtitle(windowSubtitle)
        .onDrop(of: [.fileURL], isTargeted: $isDropTargeted) { providers in
            handleDroppedProviders(providers)
        }
    }

    private var windowSubtitle: String {
        guard let report = model.report else {
            return settings.t(.appTagline)
        }
        return "\(report.bundleId) · v\(report.shortVersion) (\(report.buildVersion)) · \(report.scanDurationMs) ms"
    }

    private var sidebarSelection: Binding<SidebarItem?> {
        Binding {
            if let current = model.currentBundleURL, model.report != nil {
                return .recent(current.standardizedFileURL)
            }
            return .home
        } set: { item in
            switch item {
            case .home:
                model.clearReport()
            case .tab(let index):
                model.selectedTab = index
            case .recent(let url):
                if model.currentBundleURL?.standardizedFileURL != url.standardizedFileURL || model.report == nil {
                    model.scan(url)
                }
            case nil:
                break
            }
        }
    }

    private var sidebarView: some View {
        VStack(spacing: 0) {
            List(selection: sidebarSelection) {
                Section(settings.t(.sidebarSections)) {
                    Label(settings.t(.sidebarHome), systemImage: "house")
                        .tag(SidebarItem.home)

                    if let report = model.report {
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
                    let recents = settings.existingRecentBundles
                    if recents.isEmpty {
                        Text(settings.t(.sidebarNoRecents))
                            .foregroundStyle(.secondary)
                            .font(.callout)
                    } else {
                        ForEach(recents, id: \.path) { url in
                            let normalized = url.standardizedFileURL
                            let isSelected = model.currentBundleURL?.standardizedFileURL == normalized && model.report != nil
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

                                // Tek tek temizle (Listeden kaldır) tuşu
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
                        if !settings.existingRecentBundles.isEmpty {
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

            if model.report != nil {
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
        settings.clearRecents()
        model.cachedReports.removeAll()
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
                Image(systemName: "arrow.down.app.fill")
                    .font(.system(size: 52))
                    .foregroundStyle(.blue)
            }

            Text(settings.t(.statusIdle))
                .font(.title2.bold())
                .multilineTextAlignment(.center)

            Text(settings.t(.statusIdleHint))
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

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

                if !settings.existingRecentBundles.isEmpty {
                    Button(role: .destructive) {
                        settings.clearRecents()
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
            if model.report != nil {
                // Ana Ekrana Dön tuşu
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

            // Refresh butonu (⌘R)
            Button {
                model.refreshCurrentBundle()
            } label: {
                Label(settings.t(.actionRefresh), systemImage: "arrow.clockwise")
            }
            .buttonStyle(.bordered)
            .help(settings.t(.actionRefreshHelp))
            .disabled(model.currentBundleURL == nil || model.isScanning)

            // Temizle butonu (⇧⌘W)
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

                Button {
                    model.saveMarkdownReport()
                } label: {
                    Image(systemName: "square.and.arrow.up")
                }
                .buttonStyle(.bordered)
                .help(settings.t(.actionSaveReport))
            }

            Button {
                openWindow(id: WindowID.log)
            } label: {
                Image(systemName: "terminal")
            }
            .buttonStyle(.bordered)
            .help(settings.t(.menuShowLog))

            SettingsLink {
                Image(systemName: "gearshape")
            }
            .buttonStyle(.bordered)
            .help(settings.t(.settingsGeneral))
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .background(Color(NSColor.windowBackgroundColor))
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
                }
                .padding(10)
                .background((qFeedback.isSuccess ? Color.green : Color.orange).opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            aiAssistantCard(for: report)

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
                        infoRow(settings.t(.fieldBundleName), report.bundleName)
                        infoRow(settings.t(.fieldBundleId), report.bundleId, monospaced: true)
                        infoRow(settings.t(.fieldVersion), "\(report.shortVersion) (\(report.buildVersion))")
                        infoRow(settings.t(.fieldExecutable), "Contents/MacOS/\(report.executableName)", monospaced: true)
                        infoRow(settings.t(.fieldResourcesDate), report.plistModDate, monospaced: true)
                        infoRow(settings.t(.fieldExecutableDate), report.executableModDate, monospaced: true,
                                highlight: report.verdict == .tampered && report.plistModDate != report.executableModDate)
                        infoRow(settings.t(.fieldScanDuration), "\(report.scanDurationMs) ms", monospaced: true)
                    }
                    .padding(.top, 6)
                }

                GroupBox(label: Label(settings.t(.sectionCodesign), systemImage: "signature").font(.headline)) {
                    let isTampered = report.verdict == .tampered
                    VStack(alignment: .leading, spacing: 8) {
                        infoRow(settings.t(.fieldTeamId),
                                report.teamIdentifier == "not set" ? settings.t(.valueNotSet) : report.teamIdentifier,
                                monospaced: true,
                                highlight: isTampered && report.teamIdentifier == "not set")
                        infoRow(settings.t(.fieldAuthorities),
                                report.authorities.isEmpty ? "-" : report.authorities.joined(separator: " → "),
                                monospaced: true,
                                highlight: isTampered && !report.authorities.contains(where: { $0.contains("Apple Root CA") }))
                        infoRow(settings.t(.fieldSignedTime), report.signedTimestamp, monospaced: true)
                        infoRow(settings.t(.fieldHardenedRuntime),
                                report.hasHardenedRuntime ? settings.t(.valueEnabled) : settings.t(.valueDisabled),
                                highlight: isTampered && !report.hasHardenedRuntime)
                        infoRow(settings.t(.fieldNotarized),
                                report.isNotarized ? settings.t(.valueYes) : settings.t(.valueNo),
                                highlight: false)
                        infoRow(settings.t(.fieldQuarantine),
                                report.isQuarantined ? settings.t(.valueYes) : settings.t(.valueNo),
                                highlight: report.isQuarantined)
                        infoRow(settings.t(.fieldCdhash), report.cdHash, monospaced: true)
                        infoRow(settings.t(.fieldGatekeeper), report.gatekeeperStatus, monospaced: true)
                    }
                    .padding(.top, 6)
                }
            }
        }
    }

    @ViewBuilder
    private func aiAssistantCard(for report: BundleAuditReport) -> some View {
        @Bindable var settings = settings
        let existingSummary = model.aiSummaries[report.bundlePath]
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
                    }

                    Spacer()

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
                    .disabled(model.isGeneratingAISummary)
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
                            Text(settings.t(.aiForensicNote))
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
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
        VStack(alignment: .leading, spacing: 18) {
            GroupBox(label: Label(settings.t(.sectionBundledDylibs), systemImage: "shippingbox").font(.headline)) {
                if report.bundledLibraries.isEmpty {
                    Text(settings.t(.emptyNoBundledDylibs))
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(report.bundledLibraries) { item in
                            HStack {
                                Image(systemName: !item.suspiciousSymbols.isEmpty ? "exclamationmark.octagon.fill" : "cube.box")
                                    .foregroundStyle(!item.suspiciousSymbols.isEmpty ? .red : .secondary)
                                Text(item.name)
                                    .font(.system(.body, design: .monospaced).bold())
                                Spacer()
                                Text("\(max(1, item.sizeBytes / 1024)) KB")
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
            }

            GroupBox(label: Label(settings.t(.sectionLinkedDylibs), systemImage: "link").font(.headline)) {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(report.linkedDylibs) { dylib in
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
            GroupBox(label: Text("codesign -dvvv").font(.system(.headline, design: .monospaced))) {
                Text(report.rawCodesignOutput)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
            }

            GroupBox(label: Text("otool -L").font(.system(.headline, design: .monospaced))) {
                Text(report.rawOtoolOutput)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
            }
        }
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
        guard settings.autoScanOnDrop, let provider = providers.first else { return false }
        let typeId = UTType.fileURL.identifier
        guard provider.hasItemConformingToTypeIdentifier(typeId) else { return false }

        _ = provider.loadDataRepresentation(forTypeIdentifier: typeId) { data, _ in
            guard let data = data,
                  let finalURL = URL(dataRepresentation: data, relativeTo: nil) else { return }
            Task { @MainActor in
                let appBundleURL = model.resolveAppBundleURL(from: finalURL)
                model.scan(appBundleURL)
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
