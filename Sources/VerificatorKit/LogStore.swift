// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import VerificatorCore
import Observation

@Observable
public final class LogStore {
    public static let shared = LogStore(log: .shared)

    public enum Scope: String, CaseIterable, Identifiable {
        case all, problems
        public var id: String { rawValue }
    }

    public private(set) var entries: [AppLog.Entry]
    public var scope: Scope = .all
    public var searchText = ""
    @ObservationIgnored public let log: AppLog
    @ObservationIgnored private var observer: UUID?
    @ObservationIgnored private var refreshPending = false

    public init(log: AppLog) {
        self.log = log
        entries = log.entries
        observer = log.observe { [weak self] in
            Task { @MainActor in self?.scheduleRefresh() }
        }
    }

    isolated deinit {
        if let observer { log.removeObserver(observer) }
    }

    public var visibleEntries: [AppLog.Entry] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        return entries.filter { entry in
            (scope == .all || entry.level.isProblem)
                && (query.isEmpty || entry.message.localizedCaseInsensitiveContains(query)
                    || entry.detail?.localizedCaseInsensitiveContains(query) == true)
        }
    }

    public var hasFile: Bool {
        log.fileURL.map { FileManager.default.fileExists(atPath: $0.path) } ?? false
    }

    public func refresh() {
        refreshPending = false
        entries = log.entries
    }

    public func clear() {
        log.clear()
        refresh()
    }

    public func revealFile() {
        guard hasFile, let url = log.fileURL else { return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    public func openInConsole() {
        guard hasFile, let url = log.fileURL,
              let console = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Console") else { return }
        NSWorkspace.shared.open([url], withApplicationAt: console, configuration: NSWorkspace.OpenConfiguration())
    }

    private func scheduleRefresh() {
        guard !refreshPending else { return }
        refreshPending = true
        Task { @MainActor in self.refresh() }
    }
}
