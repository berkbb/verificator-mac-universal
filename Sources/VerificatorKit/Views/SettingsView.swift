// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import VerificatorCore
import SwiftUI

struct SettingsView: View {
    @Environment(AppSettings.self) private var settings

    var body: some View {
        TabView {
            Tab(settings.t(.settingsGeneral), systemImage: "gearshape") {
                GeneralSettingsView()
            }
            Tab(settings.t(.settingsScan), systemImage: "doc.text.magnifyingglass") {
                ScanSettingsView()
            }
            Tab(settings.t(.settingsShortcuts), systemImage: "command") {
                ShortcutsSettingsView()
            }
            Tab(settings.t(.settingsEngine), systemImage: "shield.lefthalf.filled.badge.checkmark") {
                EngineAndUpdateSettingsView()
            }
        }
        .frame(width: 580)
        .frame(minHeight: 460)
    }
}

private struct GeneralSettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(AppSettings.self) private var settings
    @State private var showRestartAlert = false

    var body: some View {
        @Bindable var settings = settings
        Form {
            Section {
                Picker(settings.t(.settingsLanguage), selection: $settings.language) {
                    ForEach(AppLanguage.allCases) { language in
                        Text("\(language.flag)  \(language.nativeName ?? settings.t(.languageSystem))")
                            .tag(language)
                    }
                }
                .onChange(of: settings.language) { old, new in
                    if old != new {
                        showRestartAlert = true
                    }
                }

                Picker(settings.t(.settingsAppearance), selection: $settings.appearance) {
                    ForEach(AppAppearance.allCases) { appearance in
                        Label(settings.t(appearance.titleKey), systemImage: appearance.systemImage)
                            .tag(appearance)
                    }
                }
                .pickerStyle(.segmented)
            } footer: {
                Text(settings.t(.restartMenuBarNotice))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            Section(settings.t(.settingsAISection)) {
                VStack(alignment: .leading, spacing: 4) {
                    Toggle(settings.t(.settingsAISuggestions), isOn: Binding(
                        get: { settings.aiSuggestions },
                        set: { isOn in Task { await model.setAISuggestions(isOn) } }
                    ))
                    .disabled(model.isCheckingAI)
                    .accessibilityIdentifier("verificator.settings.aiSuggestions")
                    Text(settings.t(.settingsAISuggestionsNote))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Picker(settings.t(.settingsAIProvider), selection: $settings.aiProvider) {
                    ForEach(SuggestionProvider.allCases) { provider in
                        Text(provider == .automatic ? settings.t(.settingsAIAutomatic) : provider.displayName)
                            .tag(provider)
                    }
                }
                .disabled(model.isCheckingAI)
                .accessibilityIdentifier("verificator.settings.aiProvider")
                .onChange(of: settings.aiProvider) {
                    model.aiSummaryError = nil
                    model.updateSuggestionModel()
                    Task {
                        await model.refreshLocalModels()
                        if settings.aiSuggestions {
                            await model.checkAIPrerequisites()
                        }
                    }
                }

                if settings.aiProvider == .automatic {
                    automaticRows
                }
                ForEach(settings.activeProviders.compactMap(\.server)) { server in
                    localServerRows(server)
                }

                if let warning = model.currentProviderWarning() {
                    Label(warning, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }

                aiCheckRows
            }
            .task { await model.refreshLocalModels() }
        }
        .formStyle(.grouped)
        .alert(settings.t(.restartWarningTitle), isPresented: $showRestartAlert) {
            Button(settings.t(.buttonOK), role: .cancel) { }
        } message: {
            Text(settings.t(.restartMenuBarNotice))
        }
    }

    @ViewBuilder
    private var aiCheckRows: some View {
        if model.isCheckingAI {
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text(settings.t(.settingsAIChecking))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        } else if !model.aiChecks.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(model.aiChecks.enumerated()), id: \.offset) { _, check in
                    Label(
                        settings.checkText(check),
                        systemImage: check.isReady ? "checkmark.circle.fill" : "exclamationmark.triangle.fill"
                    )
                    .font(.footnote)
                    .foregroundStyle(check.isReady ? Color.green : Color.orange)
                    .fixedSize(horizontal: false, vertical: true)
                }
                if !settings.aiSuggestions {
                    Text(settings.t(.settingsAINotEnabled))
                        .font(.footnote)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Button(settings.t(.settingsAIRecheck), systemImage: "arrow.clockwise") {
                    Task {
                        if settings.aiSuggestions {
                            await model.checkAIPrerequisites()
                        } else {
                            await model.setAISuggestions(true)
                        }
                    }
                }
                .accessibilityIdentifier("verificator.settings.aiRecheck")
            }
        }
    }

    @ViewBuilder
    private var automaticRows: some View {
        let order = settings.aiAutomaticOrder
        ForEach(Array(order.enumerated()), id: \.element) { index, provider in
            HStack(spacing: 8) {
                Toggle(isOn: Binding(
                    get: { !settings.aiAutomaticOff.contains(provider) },
                    set: { isOn in
                        if isOn {
                            settings.aiAutomaticOff.remove(provider)
                        } else {
                            settings.aiAutomaticOff.insert(provider)
                        }
                        model.updateSuggestionModel()
                        Task { await model.refreshLocalModels() }
                    }
                )) {
                    Text(verbatim: "\(index + 1). \(provider.displayName)")
                }
                .toggleStyle(.checkbox)
                .accessibilityIdentifier("verificator.settings.aiAutomatic.\(provider.rawValue)")
                Spacer()
                let ready = model.isReady(provider)
                Text(settings.t(ready ? .settingsAIStatusReady : .settingsAIStatusOff))
                    .font(.caption)
                    .foregroundStyle(ready ? Color.secondary : Color.orange)
                Button(settings.t(.settingsAIMoveUp), systemImage: "arrow.up") { move(index, by: -1) }
                    .labelStyle(.iconOnly)
                    .disabled(index == 0)
                Button(settings.t(.settingsAIMoveDown), systemImage: "arrow.down") { move(index, by: 1) }
                    .labelStyle(.iconOnly)
                    .disabled(index == order.count - 1)
            }
        }
        Text(settings.t(.settingsAIAutomaticNote))
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func move(_ index: Int, by offset: Int) {
        var order = settings.aiAutomaticOrder
        guard order.indices.contains(index + offset) else { return }
        order.swapAt(index, index + offset)
        settings.aiAutomaticOrder = order
        model.updateSuggestionModel()
    }

    @ViewBuilder
    private func localServerRows(_ server: LocalModelServer) -> some View {
        let models = model.localModels[server] ?? []
        let selected = settings.aiModel(for: server)
        HStack {
            Picker(settings.t(.settingsAIModel) + " · " + server.displayName, selection: Binding(
                get: { settings.aiModel(for: server) },
                set: {
                    settings.setAIModel($0, for: server)
                    model.updateSuggestionModel()
                }
            )) {
                ForEach(models.contains(selected) || selected.isEmpty ? models : [selected] + models, id: \.self) {
                    Text($0).tag($0)
                }
            }
            .disabled(models.isEmpty)
            .accessibilityIdentifier("verificator.settings.aiModel")
            Button(settings.t(.settingsAIRefresh), systemImage: "arrow.clockwise") {
                Task { await model.refreshLocalModels() }
            }
        }
        let address = "127.0.0.1:\(server.port)"
        let provider: SuggestionProvider = server == .ollama ? .ollama : .lmStudio
        Group {
            if !model.runningServers.contains(server) {
                Text(settings.t(.settingsAIServerOff, server.displayName, address)).foregroundStyle(.orange)
            } else if models.isEmpty {
                Text(settings.checkText(AIPrerequisites.Check(provider: provider, problem: .noLocalModel)))
                    .foregroundStyle(.orange)
            } else if !models.contains(selected) {
                Text(settings.t(.settingsAIModelMissing, selected)).foregroundStyle(.orange)
            } else {
                Text(settings.t(.settingsAIReady, models.count)).foregroundStyle(.secondary)
            }
        }
        .font(.footnote)
        .fixedSize(horizontal: false, vertical: true)
        Text(settings.t(.settingsAILocalNote, address))
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

private struct ScanSettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(AppSettings.self) private var settings

    var body: some View {
        @Bindable var settings = settings
        Form {
            Section(settings.t(.settingsScanSection)) {
                VStack(alignment: .leading, spacing: 4) {
                    Toggle(settings.t(.settingsDeepFrameworkCheck), isOn: $settings.deepFrameworkSignatureCheck)
                    Text(settings.t(.settingsDeepFrameworkCheckNote))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Toggle(settings.t(.settingsExtractTargetStrings), isOn: $settings.extractTargetStrings)
                VStack(alignment: .leading, spacing: 4) {
                    Toggle(settings.t(.settingsIncludeSpctl), isOn: $settings.includeGatekeeperAssessment)
                    Text(settings.t(.settingsIncludeSpctlNote))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Toggle(settings.t(.settingsCheckRevocation), isOn: $settings.checkCertificateRevocation)
                    Text(settings.t(.settingsCheckRevocationNote))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Toggle(settings.t(.settingsAutoScanOnDrop), isOn: $settings.autoScanOnDrop)
                Toggle(settings.t(.settingsRevealAfterExport), isOn: $settings.revealAfterExport)
                VStack(alignment: .leading, spacing: 4) {
                    Toggle(settings.t(.settingsRedactDiagnostics), isOn: $settings.redactSharedDiagnostics)
                    Text(settings.t(.settingsRedactDiagnosticsNote))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Section(settings.t(.settingsPermissionsSection)) {
                HStack(spacing: 8) {
                    Image(systemName: model.gatekeeperStatus == .disabled ? "exclamationmark.shield.fill" : "checkmark.shield.fill")
                        .foregroundStyle(model.gatekeeperStatus == .enabled ? .green : (model.gatekeeperStatus == .disabled ? .orange : .secondary))
                    Text(settings.t(model.gatekeeperStatus.labelKey))
                    Spacer()
                }
                HStack(spacing: 8) {
                    Image(systemName: model.firewallStatus?.globalEnabled == true ? "flame.fill" : "flame")
                        .foregroundStyle(model.firewallStatus?.globalEnabled == true ? .green : (model.firewallStatus?.globalEnabled == false ? .orange : .secondary))
                    if let fw = model.firewallStatus, fw.isAvailable {
                        let globalStr = settings.t(fw.globalEnabled == true ? .firewallStatusEnabled : .firewallStatusDisabled)
                        let stealthStr = settings.t(fw.stealthMode == true ? .firewallStatusStealthOn : .firewallStatusStealthOff)
                        let blockAllSuffix = fw.blockAll == true ? " · \(settings.t(.firewallStatusBlockAll))" : ""
                        Text(settings.t(.settingsFirewallStatusFormat, globalStr, stealthStr) + blockAllSuffix)
                    } else {
                        Text(settings.t(.settingsFirewallUnavailable))
                    }
                    Spacer()
                }
                if let bootVol = model.bootVolumeEncryption {
                    HStack(spacing: 8) {
                        Image(systemName: bootVol.isEncrypted == true ? "lock.doc.fill" : "lock.open.trianglebadge.exclamationmark")
                            .foregroundStyle(bootVol.isEncrypted == true ? .green : .orange)
                        Text(settings.t(bootVol.isEncrypted == true ? .settingsBootVolumeEncrypted : .settingsBootVolumeUnencrypted, bootVol.volumeName))
                        Spacer()
                    }
                }
                HStack(spacing: 8) {
                    Image(systemName: model.isFullDiskAccessGranted ? "lock.open.fill" : "lock.fill")
                        .foregroundStyle(model.isFullDiskAccessGranted ? .green : .orange)
                    Text(settings.t(model.isFullDiskAccessGranted ? .fdaStatusGranted : .fdaStatusMissing))
                    Spacer()
                    if !model.isFullDiskAccessGranted {
                        Button(settings.t(.fdaOpenSettings)) {
                            FullDiskAccess.openSystemSettings()
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                }
            }

            Section(settings.t(.settingsRecentsSection)) {
                HStack {
                    Text("\(settings.existingRecentBundles.count) / \(AppSettings.maxRecentBundles)")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button(settings.t(.actionClearRecents)) {
                        model.clearAllHistory()
                    }
                    .disabled(settings.recentBundles.isEmpty)
                }
            }
        }
        .formStyle(.grouped)
        .onAppear {
            model.refreshSystemSecurityStatus()
        }
    }
}

private struct ShortcutsSettingsView: View {
    @Environment(AppSettings.self) private var settings
    @State private var recordingAction: ShortcutAction? = nil
    @State private var monitor: Any? = nil
    @State private var recordingWarning: String? = nil

    var body: some View {
        Form {
            Section {
                ForEach(ShortcutAction.allCases) { action in
                    customShortcutRow(for: action)
                }
            } header: {
                Text(settings.t(.shortcutCustomSection))
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text(settings.t(.shortcutRecordHelp))
                    if let warning = recordingWarning {
                        Text(warning)
                            .foregroundStyle(.red)
                            .fontWeight(.semibold)
                    }
                }
                .font(.footnote)
                .foregroundStyle(.secondary)
            }

            Section(settings.t(.shortcutReferenceSection)) {
                readOnlyShortcutRow(title: settings.t(.tabOverview), shortcut: "⌘1")
                readOnlyShortcutRow(title: settings.t(.tabDylibs), shortcut: "⌘2")
                readOnlyShortcutRow(title: settings.t(.tabSymbols), shortcut: "⌘3")
                readOnlyShortcutRow(title: settings.t(.tabRaw), shortcut: "⌘4")
                readOnlyShortcutRow(title: settings.t(.actionRemoveQuarantine), shortcut: "⌘K")
                readOnlyShortcutRow(title: settings.t(.menuBatchScan), shortcut: "⌥⌘B")
                readOnlyShortcutRow(title: settings.t(.menuSaveJSONReport), shortcut: "⌥⌘S")
                readOnlyShortcutRow(title: settings.t(.menuShowLog), shortcut: "⌥⌘L")
            }

            Section {
                Button(settings.t(.shortcutResetAll)) {
                    stopRecording()
                    settings.resetAllShortcuts()
                }
                .disabled(settings.isAllShortcutsDefault)
            }
        }
        .formStyle(.grouped)
        .onDisappear {
            stopRecording()
        }
    }

    private func customShortcutRow(for action: ShortcutAction) -> some View {
        let currentShortcut = settings.shortcut(for: action)
        let isRecording = recordingAction == action
        let isCustomized = !settings.isDefaultShortcut(for: action)

        return HStack {
            Text(settings.t(action.titleKey))
            Spacer()
            if isCustomized && !isRecording {
                Button {
                    settings.resetShortcut(for: action)
                } label: {
                    Image(systemName: "arrow.counterclockwise")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help(settings.t(.shortcutResetDefault))
                .accessibilityLabel(settings.t(.shortcutResetDefault))
            }

            Button {
                if isRecording {
                    stopRecording()
                } else {
                    startRecording(for: action)
                }
            } label: {
                HStack(spacing: 4) {
                    if isRecording {
                        ProgressView()
                            .controlSize(.mini)
                        Text(settings.t(.shortcutRecordPrompt))
                            .foregroundStyle(.tint)
                    } else {
                        Text(currentShortcut.displayString)
                    }
                }
                .font(.system(.body, design: .monospaced))
                .padding(.horizontal, 10)
                .padding(.vertical, 4)
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .fill(isRecording ? Color.accentColor.opacity(0.15) : Color(nsColor: .quaternaryLabelColor).opacity(0.2))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(isRecording ? Color.accentColor : Color.clear, lineWidth: 1.5)
                )
            }
            .buttonStyle(.plain)
        }
    }

    private func readOnlyShortcutRow(title: String, shortcut: String) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(shortcut)
                .font(.system(.body, design: .monospaced))
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(Color(nsColor: .quaternaryLabelColor).opacity(0.2), in: RoundedRectangle(cornerRadius: 6))
        }
    }

    private func startRecording(for action: ShortcutAction) {
        stopRecording()
        recordingAction = action
        recordingWarning = nil
        monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            handleKeyDown(event, for: action)
        }
    }

    private func stopRecording() {
        if let monitor {
            NSEvent.removeMonitor(monitor)
            self.monitor = nil
        }
        recordingAction = nil
        recordingWarning = nil
    }

    private func handleKeyDown(_ event: NSEvent, for action: ShortcutAction) -> NSEvent? {
        if event.keyCode == 53 {
            DispatchQueue.main.async { self.stopRecording() }
            return nil
        }

        let flags = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
        let hasCommand = flags.contains(.command)
        let hasShift = flags.contains(.shift)
        let hasOption = flags.contains(.option)
        let hasControl = flags.contains(.control)

        if event.keyCode == 51 && !hasCommand && !hasOption && !hasControl {
            DispatchQueue.main.async {
                self.settings.resetShortcut(for: action)
                self.stopRecording()
            }
            return nil
        }

        guard let chars = event.charactersIgnoringModifiers, !chars.isEmpty,
              let firstChar = chars.first else {
            return nil
        }
        let keyString = String(firstChar).uppercased()

        let hasPrimaryModifier = hasCommand || hasOption || hasControl
        if !hasPrimaryModifier {
            NSSound.beep()
            DispatchQueue.main.async {
                self.recordingWarning = self.settings.t(.shortcutModifierRequired)
            }
            return nil
        }

        let newShortcut = KeyboardShortcutData(
            key: keyString,
            command: hasCommand,
            shift: hasShift,
            option: hasOption,
            control: hasControl
        )

        if let conflict = settings.shortcutConflict(for: newShortcut, editingAction: action) {
            NSSound.beep()
            DispatchQueue.main.async {
                switch conflict {
                case .customAction(let conflictingAction):
                    self.recordingWarning = self.settings.t(.shortcutConflictWarning, self.settings.t(conflictingAction.titleKey))
                case .systemShortcut(let titleKey):
                    self.recordingWarning = self.settings.t(.shortcutSystemConflictWarning, self.settings.t(titleKey))
                }
            }
            return nil
        }

        DispatchQueue.main.async {
            self.settings.setShortcut(newShortcut, for: action)
            self.stopRecording()
        }
        return nil
    }
}

private struct EngineAndUpdateSettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(AppSettings.self) private var settings
    @State private var confirmReset = false
    @State private var copiedCLI = false

    var body: some View {
        @Bindable var settings = settings
        Form {
            Section(settings.t(.settingsToolsSection)) {
                ForEach(model.toolStatuses) { tool in
                    LabeledContent(tool.name) {
                        HStack(spacing: 8) {
                            Text(tool.path)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary)
                            Label(
                                settings.t(tool.isAvailable ? .settingsToolReady : .settingsToolMissing),
                                systemImage: tool.isAvailable ? "checkmark.seal.fill" : "xmark.octagon.fill"
                            )
                            .foregroundStyle(tool.isAvailable ? .green : .red)
                        }
                    }
                }
                Button(settings.t(.settingsToolsRefresh)) {
                    model.refreshTools()
                }
            }

            Section(settings.t(.settingsCLISection)) {
                LabeledContent(settings.t(.settingsCLIEmbeddedPath)) {
                    Text(model.embeddedCLIPath)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text(settings.t(.settingsCLIInstallCommand))
                        .font(.subheadline)
                    Text(model.cliInstallCommand)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(NSColor.textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))

                    HStack(spacing: 10) {
                        Button {
                            model.copyCLIInstallCommand()
                            copiedCLI = true
                            Task { @MainActor in
                                try? await Task.sleep(for: .seconds(2))
                                copiedCLI = false
                            }
                        } label: {
                            Label(
                                settings.t(copiedCLI ? .actionCopied : .settingsCopyCLIInstall),
                                systemImage: copiedCLI ? "checkmark" : "doc.on.doc"
                            )
                        }
                        if copiedCLI {
                            Text(settings.t(.settingsCopiedCLIInstallNotice))
                                .font(.caption)
                                .foregroundStyle(.green)
                        }
                    }
                }

                Text(settings.t(.settingsIntegrationsNote))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            Section(settings.t(.appUpdateSection)) {
                LabeledContent(settings.t(.appUpdateVersion), value: "\(AppInfo.version) (\(AppInfo.build))")
                appUpdateStatus
                HStack {
                    Button(settings.t(.updateCheck)) {
                        Task { await model.checkForAppUpdate(interactive: true) }
                    }
                    .disabled(model.appUpdateState == .checking)

                    if case .available(let release) = model.appUpdateState {
                        if release.downloadURL != nil && (release.signatureURL != nil || release.checksumsURL != nil) {
                            Button(settings.t(.appUpdateDownloadAndVerify)) {
                                Task { await model.downloadAndVerifyAppUpdate(release: release) }
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(model.updateDownloadState == .downloading)

                            Button(settings.t(.appUpdateOpenInBrowser)) {
                                model.openAppDownload()
                            }
                        } else {
                            Button(settings.t(.appUpdateDownload)) {
                                model.openAppDownload()
                            }
                            .buttonStyle(.borderedProminent)
                        }
                    }
                }
                updateDownloadStatus
                Toggle(settings.t(.updateAutoCheck), isOn: $settings.checkUpdatesAtLaunch)
                    .onChange(of: settings.checkUpdatesAtLaunch) { settings.updateConsentAsked = true }
            }

            Section {
                Button(settings.t(.settingsReset), role: .destructive) {
                    confirmReset = true
                }
            }
        }
        .formStyle(.grouped)
        .confirmationDialog(settings.t(.settingsResetConfirm), isPresented: $confirmReset) {
            Button(settings.t(.settingsReset), role: .destructive) {
                model.resetAllSettings()
            }
        }
    }

    @ViewBuilder
    private var appUpdateStatus: some View {
        switch model.appUpdateState {
        case .idle:
            EmptyView()
        case .checking:
            Label { Text(settings.t(.updateChecking)) } icon: { ProgressView().controlSize(.small) }
        case .available(let release):
            Label(settings.t(.appUpdateAvailable, release.version, AppInfo.version), systemImage: "arrow.down.circle.fill")
                .foregroundStyle(.tint)
        case .upToDate:
            Label(settings.t(.appUpdateUpToDate, AppInfo.version), systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
        case .noReleases:
            Label(settings.t(.appUpdateNoReleases, AppInfo.version), systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
        case .failed(let message):
            Label(message, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
        }
    }

    @ViewBuilder
    private var updateDownloadStatus: some View {
        switch model.updateDownloadState {
        case .idle:
            EmptyView()
        case .downloading:
            Label { Text(settings.t(.appUpdateDownloading)) } icon: { ProgressView().controlSize(.small) }
        case .verified(let result):
            VStack(alignment: .leading, spacing: 6) {
                Label(
                    settings.t(.appUpdateVerifiedSuccess, String(result.sha256.prefix(12)), result.fileURL.lastPathComponent),
                    systemImage: "checkmark.seal.fill"
                )
                .font(.footnote)
                .foregroundStyle(.green)
                .textSelection(.enabled)

                HStack(spacing: 8) {
                    Button(settings.t(.appUpdateOpenInstaller), systemImage: "arrow.up.forward.app") {
                        model.openVerifiedUpdate(result.fileURL)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)

                    Button(settings.t(.buttonShowInFinder), systemImage: "folder") {
                        model.revealVerifiedUpdate(result.fileURL)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
        case .failed(let message):
            Label(settings.t(.appUpdateVerifyFailed, message), systemImage: "xmark.octagon.fill")
                .font(.footnote)
                .foregroundStyle(.red)
        }
    }
}
