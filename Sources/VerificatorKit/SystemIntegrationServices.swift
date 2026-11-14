// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import Foundation
import Observation
import ServiceManagement
import UserNotifications
import VerificatorCore

public enum RuntimeBundleEnvironment {
    public static var isPackagedAppBundle: Bool {
        Bundle.main.bundleURL.pathExtension.lowercased() == "app"
            && Bundle.main.bundleIdentifier == "com.babadogantech.verificator"
    }

    public static var isInstalledInApplications: Bool {
        isPackagedAppBundle && Bundle.main.bundleURL.path.hasPrefix("/Applications/")
    }
}

public enum NotificationAuthState: String, Sendable, Equatable {
    case unknown
    case notDetermined
    case authorized
    case denied
    case unavailable
}

/// Safe wrapper over `UNUserNotificationCenter` that never touches NotificationCenter
/// inside headless CLI or XCTest processes.
@MainActor
@Observable
public final class NotificationService {
    public private(set) var authState: NotificationAuthState = .unknown

    public init() {}

    public func refreshAuthorizationStatus() async {
        guard RuntimeBundleEnvironment.isPackagedAppBundle else {
            authState = .unknown
            return
        }
        guard RuntimeBundleEnvironment.isInstalledInApplications else {
            authState = .unavailable
            return
        }
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        switch settings.authorizationStatus {
        case .authorized, .provisional, .ephemeral:
            authState = .authorized
        case .denied:
            authState = .denied
        case .notDetermined:
            authState = .notDetermined
        @unknown default:
            authState = .unknown
        }
    }

    public func requestPermissionIfNeeded() async {
        guard RuntimeBundleEnvironment.isInstalledInApplications else {
            await refreshAuthorizationStatus()
            return
        }
        await refreshAuthorizationStatus()
        if authState == .notDetermined {
            _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])
            await refreshAuthorizationStatus()
        }
    }

    public func postAlert(identifier: String, title: String, body: String, bundlePath: String? = nil) async {
        guard RuntimeBundleEnvironment.isInstalledInApplications else { return }
        await requestPermissionIfNeeded()
        guard authState == .authorized else { return }

        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        if let bundlePath {
            content.userInfo = ["bundlePath": bundlePath]
        }
        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
        try? await UNUserNotificationCenter.current().add(request)
    }

    public func openSystemSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }
}

/// Safe wrapper over `SMAppService.mainApp` that never invokes Login Items APIs during unit tests.
@MainActor
@Observable
public final class LoginItemService {
    public private(set) var isEnabled = false
    public private(set) var needsApproval = false

    public init() {}

    public func refresh() {
        guard RuntimeBundleEnvironment.isPackagedAppBundle else {
            isEnabled = false
            needsApproval = false
            return
        }
        switch SMAppService.mainApp.status {
        case .enabled:
            isEnabled = true
            needsApproval = false
        case .requiresApproval:
            isEnabled = true
            needsApproval = true
        case .notRegistered, .notFound:
            isEnabled = false
            needsApproval = false
        @unknown default:
            isEnabled = false
            needsApproval = false
        }
    }

    public func setEnabled(_ enable: Bool) {
        guard RuntimeBundleEnvironment.isPackagedAppBundle else { return }
        do {
            if enable {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            AppLog.shared.info(.app, enable ? "Registered launch at login item" : "Unregistered launch at login item")
        } catch {
            AppLog.shared.warning(.app, "Login item update failed: \(error.localizedDescription)")
        }
        refresh()
    }

    public func openLoginItemsSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }
}

/// Opt-in, strictly read-only background monitor for user-selected folders (such as `~/Downloads`).
/// Audits newly arrived or modified `.app`, `.dmg`, `.pkg`, `.mpkg`, and Mach-O items without mutating disk state.
@MainActor
@Observable
public final class WatchedFolderService {
    public struct FileFingerprint: Equatable, Sendable {
        public let modifiedSeconds: Int64
        public let inode: UInt64
    }

    public private(set) var isRunning = false
    public private(set) var isScanningNow = false
    public private(set) var lastScanDate: Date?
    public private(set) var lastAuditedTarget: String?
    public private(set) var lastIssueCount = 0

    @ObservationIgnored private var monitorTask: Task<Void, Never>?
    @ObservationIgnored private var activeScanTask: Task<Void, Never>?
    @ObservationIgnored private var seenEntries: [String: FileFingerprint] = [:]
    @ObservationIgnored private var initializedFolders: Set<String> = []

    public init() {}

    public func configure(
        enabled: Bool,
        folderPaths: [String],
        scanOptions: @escaping @MainActor () -> ScanOptions,
        onReport: @escaping @MainActor (BundleAuditReport) -> Void
    ) {
        monitorTask?.cancel()
        monitorTask = nil

        let normalized = Self.normalizedExistingFolders(folderPaths)
        guard enabled, !normalized.isEmpty else {
            isRunning = false
            return
        }

        isRunning = true
        monitorTask = Task { @MainActor [weak self] in
            guard let self else { return }
            // First pass captures existing files cleanly without alert fatigue.
            await self.pollFolders(normalized, includeBaseline: false, scanOptions: scanOptions(), onReport: onReport)
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(12))
                guard !Task.isCancelled else { break }
                await self.pollFolders(normalized, includeBaseline: false, scanOptions: scanOptions(), onReport: onReport)
            }
        }
    }

    public func stop() {
        monitorTask?.cancel()
        monitorTask = nil
        activeScanTask?.cancel()
        activeScanTask = nil
        isRunning = false
        isScanningNow = false
    }

    public func scanNow(
        folderPaths: [String],
        scanOptions: ScanOptions,
        onReport: @escaping @MainActor (BundleAuditReport) -> Void
    ) {
        let normalized = Self.normalizedExistingFolders(folderPaths)
        guard !normalized.isEmpty else { return }
        activeScanTask?.cancel()
        activeScanTask = Task { @MainActor [weak self] in
            await self?.pollFolders(normalized, includeBaseline: true, scanOptions: scanOptions, onReport: onReport)
        }
    }

    /// Collects auditable top-level bundle/container targets in `folders`.
    /// When `includeBaseline` is `false`, returns only newly added or modified entries since the prior snapshot.
    public func collectChangedTargets(
        in folders: [String],
        includeBaseline: Bool
    ) -> [URL] {
        var targets: [URL] = []
        let supported = ForensicScanner.supportedBundleExtensions
            .union(ForensicScanner.supportedContainerExtensions)

        for folder in folders {
            let isFirstVisit = !initializedFolders.contains(folder)
            guard let entries = DirectoryEntries.list(
                at: URL(fileURLWithPath: folder),
                includeHidden: false
            ) else { continue }
            var changedInFolder: [URL] = []

            for entry in entries {
                if entry.name.hasPrefix("._") || entry.isHidden { continue }
                let entryPath = entry.url.path
                let ext = entry.url.pathExtension.lowercased()
                guard supported.contains(ext) else { continue }

                let statInfo = Self.fingerprint(atPath: entryPath)
                let previous = seenEntries[entryPath]
                if let statInfo {
                    seenEntries[entryPath] = statInfo
                }

                if includeBaseline || (!isFirstVisit && previous != statInfo) {
                    changedInFolder.append(entry.url)
                }
            }

            initializedFolders.insert(folder)
            targets.append(contentsOf: changedInFolder)
        }
        return targets
    }

    private func pollFolders(
        _ folders: [String],
        includeBaseline: Bool,
        scanOptions: ScanOptions,
        onReport: @escaping @MainActor (BundleAuditReport) -> Void
    ) async {
        guard !isScanningNow else { return }
        let targets = collectChangedTargets(in: folders, includeBaseline: includeBaseline)
        lastScanDate = Date()
        guard !targets.isEmpty else { return }

        isScanningNow = true
        defer { isScanningNow = false }

        // Cap manual immediate passes to avoid unbounded background waits in huge folders.
        let batch = includeBaseline ? Array(targets.prefix(32)) : targets
        var issues = 0
        for url in batch {
            if Task.isCancelled { break }
            let audited = await Task.detached(priority: .utility) {
                ForensicScanner.auditTarget(at: url, options: scanOptions)
            }.value
            lastAuditedTarget = audited.bundleName
            if audited.verdict != .clean {
                issues += 1
            }
            onReport(audited)
        }
        lastIssueCount = issues
        lastScanDate = Date()
    }

    private static func normalizedExistingFolders(_ paths: [String]) -> [String] {
        var result: [String] = []
        var seen = Set<String>()
        for raw in paths {
            let expanded = (raw as NSString).expandingTildeInPath
            let std = URL(fileURLWithPath: expanded).standardizedFileURL.path
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: std, isDirectory: &isDir), isDir.boolValue, seen.insert(std).inserted {
                result.append(std)
            }
        }
        return result
    }

    private static func fingerprint(atPath path: String) -> FileFingerprint? {
        var st = stat()
        guard lstat(path, &st) == 0 else { return nil }
        return FileFingerprint(
            modifiedSeconds: Int64(st.st_mtimespec.tv_sec),
            inode: UInt64(st.st_ino)
        )
    }
}
