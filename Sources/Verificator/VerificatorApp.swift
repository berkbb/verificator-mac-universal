// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import VerificatorCore
import SwiftUI

@main
struct VerificatorApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var settings = AppSettings.shared
    @State private var model = AppModel.shared

    var body: some Scene {
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
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.setActivationPolicy(.regular)
        AppSettings.shared.applyAppearance()
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        guard let first = urls.first else { return }
        AppModel.shared.scan(first)
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

            Divider()

            Button(settings.t(.actionClearRecents)) {
                settings.clearRecents()
            }
            .disabled(settings.recentBundles.isEmpty)
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
