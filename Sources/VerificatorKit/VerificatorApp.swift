// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import VerificatorCore
import SwiftUI

public struct VerificatorApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var settings = AppSettings.shared
    @State private var model = AppModel.shared

    public init() {}

    public var body: some Scene {
        let _ = settings.customShortcuts
        Window(settings.t(.appName), id: WindowID.main) {
            ContentView()
                .environment(model)
                .environment(settings)
                .environment(\.locale, settings.locale)
                .frame(minWidth: 960, minHeight: 680)
                .task { await model.launch() }
        }
        .defaultSize(width: 1120, height: 760)
        .commands { AppCommands(model: model, settings: settings) }

        Window(settings.t(.menuAbout), id: WindowID.about) {
            AboutView()
                .environment(model)
                .environment(settings)
                .environment(\.locale, settings.locale)
        }
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)
        .defaultPosition(.center)
        .restorationBehavior(.disabled)
        .defaultLaunchBehavior(.suppressed)
        .commandsRemoved()

        Window(settings.t(.logTitle), id: WindowID.log) {
            LogView(store: LogStore.shared)
                .environment(settings)
                .environment(\.locale, settings.locale)
        }
        .defaultSize(width: 940, height: 540)
        .restorationBehavior(.disabled)
        .defaultLaunchBehavior(.suppressed)
        .commandsRemoved()

        Settings {
            SettingsView()
                .environment(model)
                .environment(settings)
                .environment(\.locale, settings.locale)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        NSApplication.shared.servicesProvider = self
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.setActivationPolicy(.regular)
        NSApplication.shared.servicesProvider = self
        ChildProcessGuard.install()
        LaunchServicesRegistration.registerIfBuildChanged()
        NSUpdateDynamicServices()
        AppSettings.shared.applyAppearance()
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        AppModel.shared.refreshSystemSecurityStatus()
    }

    func applicationWillTerminate(_ notification: Notification) {
        ChildProcessGuard.terminateAll()
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls {
            AppModel.shared.handleIncomingURL(url)
        }
        bringMainWindowToFront()
    }

    static func extractServiceTargetURLs(from pboard: NSPasteboard) -> [URL] {
        var collected: [URL] = []
        var seen = Set<String>()

        func appendIfNew(_ url: URL) {
            let resolved = ((url as NSURL).filePathURL ?? url).standardizedFileURL
            guard resolved.isFileURL else { return }
            if seen.insert(resolved.path).inserted {
                collected.append(resolved)
            }
        }

        if let urls = pboard.readObjects(
            forClasses: [NSURL.self],
            options: [.urlReadingFileURLsOnly: true]
        ) as? [URL] {
            for url in urls {
                appendIfNew(url)
            }
        }

        if let paths = pboard.propertyList(
            forType: NSPasteboard.PasteboardType("NSFilenamesPboardType")
        ) as? [String] {
            for path in paths where !path.isEmpty {
                appendIfNew(URL(fileURLWithPath: path))
            }
        }

        if collected.isEmpty,
           let rawFileURL = pboard.string(forType: .fileURL)?
               .trimmingCharacters(in: .whitespacesAndNewlines),
           !rawFileURL.isEmpty,
           let parsed = URL(string: rawFileURL),
           parsed.isFileURL {
            appendIfNew(parsed)
        }

        if collected.isEmpty,
           let rawText = pboard.string(forType: .string)?
               .trimmingCharacters(in: .whitespacesAndNewlines),
           !rawText.isEmpty {
            if rawText.hasPrefix("file://"),
               let parsed = URL(string: rawText),
               parsed.isFileURL {
                appendIfNew(parsed)
            } else {
                let expanded = NSString(string: rawText).expandingTildeInPath
                if FileManager.default.fileExists(atPath: expanded) {
                    appendIfNew(URL(fileURLWithPath: expanded))
                }
            }
        }

        return collected
    }

    @objc(auditServiceItem:userData:error:)
    func auditServiceItem(
        _ pboard: NSPasteboard,
        userData: String?,
        error: AutoreleasingUnsafeMutablePointer<NSString?>?
    ) {
        let urls = Self.extractServiceTargetURLs(from: pboard)
        guard let targetURL = urls.first else {
            AppLog.shared.warning(.app, "Service invoked with unreadable Finder selection")
            error?.pointee = AppSettings.shared.t(.serviceInvalidSelectionError) as NSString
            return
        }

        AppLog.shared.info(.app, "Service invoked for item", detail: targetURL.path)
        NSApplication.shared.activate(ignoringOtherApps: true)
        AppModel.shared.handleIncomingURL(targetURL)
        bringMainWindowToFront()
    }

    private func bringMainWindowToFront() {
        if let window = NSApp.windows.first(where: { $0.identifier?.rawValue == WindowID.main }) {
            window.makeKeyAndOrderFront(nil)
            return
        }
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(120))
            NSApp.windows.first(where: { $0.identifier?.rawValue == WindowID.main })?.makeKeyAndOrderFront(nil)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}

struct AppCommands: Commands {
    let model: AppModel
    let settings: AppSettings
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(replacing: .appInfo) {
            Button(settings.t(.menuAbout)) { openWindow(id: WindowID.about) }
            Button(settings.t(.menuCheckAppUpdates)) {
                Task { await model.checkForAppUpdate(interactive: true) }
            }
        }

        CommandGroup(replacing: .newItem) {
            let openShortcut = settings.shortcut(for: .openBundle)
            Button(settings.t(.menuOpenBundle)) {
                openWindow(id: WindowID.main)
                model.presentOpenPanel()
            }
            .keyboardShortcut(openShortcut.keyEquivalent, modifiers: openShortcut.eventModifiers)

            Button(settings.t(.menuBatchScan)) {
                openWindow(id: WindowID.main)
                model.presentBatchFolderPanel()
            }
            .keyboardShortcut("b", modifiers: [.command, .option])

            Button(settings.t(.menuCompareMode)) {
                openWindow(id: WindowID.main)
                model.openDiffMode()
            }
            .keyboardShortcut("d", modifiers: [.command, .shift])

            Button(settings.t(.menuRunningProcesses)) {
                openWindow(id: WindowID.main)
                model.openRunningProcessesMode(startImmediately: true)
            }
            .keyboardShortcut("p", modifiers: [.command, .option])

            Button(settings.t(.menuPersistenceAudit)) {
                openWindow(id: WindowID.main)
                model.openPersistenceMode(startImmediately: true)
            }
            .keyboardShortcut("t", modifiers: [.command, .option])

            let refreshShortcut = settings.shortcut(for: .refresh)
            Button(settings.t(.menuRefreshScan)) {
                model.refreshCurrentBundle()
            }
            .keyboardShortcut(refreshShortcut.keyEquivalent, modifiers: refreshShortcut.eventModifiers)
            .disabled(model.currentBundleURL == nil || model.isScanning)

            Divider()

            let clearShortcut = settings.shortcut(for: .clearReport)
            Button(settings.t(.menuCloseReport)) {
                model.clearReport()
            }
            .keyboardShortcut(clearShortcut.keyEquivalent, modifiers: clearShortcut.eventModifiers)
            .disabled(model.report == nil || model.isScanning)
        }

        CommandMenu(settings.t(.menuAudit)) {
            let refreshShortcut = settings.shortcut(for: .refresh)
            Button(settings.t(.menuRefreshScan)) {
                model.refreshCurrentBundle()
            }
            .keyboardShortcut(refreshShortcut.keyEquivalent, modifiers: refreshShortcut.eventModifiers)
            .disabled(model.currentBundleURL == nil || model.isScanning)

            let clearShortcut = settings.shortcut(for: .clearReport)
            Button(settings.t(.actionClearReport)) {
                model.clearReport()
            }
            .keyboardShortcut(clearShortcut.keyEquivalent, modifiers: clearShortcut.eventModifiers)
            .disabled(model.report == nil || model.isScanning)

            let revealShortcut = settings.shortcut(for: .reveal)
            Button(settings.t(.menuRevealInFinder)) {
                model.revealCurrentBundle()
            }
            .keyboardShortcut(revealShortcut.keyEquivalent, modifiers: revealShortcut.eventModifiers)
            .disabled(model.currentBundleURL == nil)

            if model.report?.isQuarantined == true {
                Button(settings.t(.actionRemoveQuarantine)) {
                    model.removeQuarantineForCurrentBundle()
                }
                .keyboardShortcut("k", modifiers: [.command])
                .disabled(model.isRemovingQuarantine)
            }

            Divider()

            let copyShortcut = settings.shortcut(for: .copyReport)
            Button(settings.t(.menuCopyReport)) {
                model.copyMarkdownReport()
            }
            .keyboardShortcut(copyShortcut.keyEquivalent, modifiers: copyShortcut.eventModifiers)
            .disabled(model.report == nil)

            let saveShortcut = settings.shortcut(for: .saveReport)
            Button(settings.t(.menuSaveReport)) {
                model.saveMarkdownReport()
            }
            .keyboardShortcut(saveShortcut.keyEquivalent, modifiers: saveShortcut.eventModifiers)
            .disabled(model.report == nil)

            Button(settings.t(.menuSaveJSONReport)) {
                model.saveJSONReport()
            }
            .keyboardShortcut("s", modifiers: [.command, .option])
            .disabled(model.report == nil)

            Divider()

            Button(settings.t(.actionClearRecents)) {
                model.clearAllHistory()
            }
            .disabled(settings.recentBundles.isEmpty)

            Divider()

            Button(settings.t(.menuInstallCLI)) {
                model.copyCLIInstallCommand()
            }
        }

        CommandGroup(before: .toolbar) {
            Button(settings.t(.tabOverview)) { model.selectedTab = 0 }
                .keyboardShortcut("1")
                .disabled(model.report == nil)
            Button(settings.t(.tabDylibs)) { model.selectedTab = 1 }
                .keyboardShortcut("2")
                .disabled(model.report == nil)
            Button(settings.t(.tabSymbols)) { model.selectedTab = 2 }
                .keyboardShortcut("3")
                .disabled(model.report == nil)
            Button(settings.t(.tabRaw)) { model.selectedTab = 3 }
                .keyboardShortcut("4")
                .disabled(model.report == nil)
            Divider()
        }

        CommandGroup(before: .windowList) {
            Button(settings.t(.menuShowLog)) { openWindow(id: WindowID.log) }
                .keyboardShortcut("l", modifiers: [.command, .option])
            Divider()
        }

        CommandGroup(replacing: .help) {
            Button(settings.t(.menuRepository)) { NSWorkspace.shared.open(AppLinks.repository) }
            Button(settings.t(.menuWebsite)) { NSWorkspace.shared.open(AppLinks.website) }
        }
    }
}
