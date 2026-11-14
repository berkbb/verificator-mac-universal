// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// Read-only FileVault / APFS encryption state of the volume hosting an inspected target or the boot volume.
public struct VolumeEncryptionInfo: Sendable, Equatable, Codable {
    public let volumePath: String
    public let volumeName: String
    public let format: String
    public let isEncrypted: Bool?
    public let isRemovable: Bool?
    public let isInternal: Bool?
    public let isLocal: Bool?

    public init(
        volumePath: String,
        volumeName: String,
        format: String,
        isEncrypted: Bool?,
        isRemovable: Bool?,
        isInternal: Bool?,
        isLocal: Bool?
    ) {
        self.volumePath = volumePath
        self.volumeName = volumeName
        self.format = format
        self.isEncrypted = isEncrypted
        self.isRemovable = isRemovable
        self.isInternal = isInternal
        self.isLocal = isLocal
    }

    /// True when the target lives on a locally mounted unencrypted removable or external drive.
    public var needsUnencryptedRemovableWarning: Bool {
        isLocal == true && isEncrypted == false && (isRemovable == true || isInternal == false)
    }

    /// Evaluates FileVault / CoreStorage / APFS volume encryption status directly from URL resource keys.
    public static func read(for url: URL) -> VolumeEncryptionInfo? {
        let keys: Set<URLResourceKey> = [
            .volumeURLKey,
            .volumeNameKey,
            .volumeLocalizedFormatDescriptionKey,
            .volumeIsEncryptedKey,
            .volumeIsRemovableKey,
            .volumeIsInternalKey,
            .volumeIsLocalKey,
        ]
        let standardized = url.standardizedFileURL
        guard let directValues = try? standardized.resourceValues(forKeys: keys) else {
            return nil
        }
        let volumeURL = directValues.volume ?? standardized
        let volValues = (try? volumeURL.resourceValues(forKeys: keys)) ?? directValues

        var resolvedEncrypted = volValues.volumeIsEncrypted
        if isBootVolumeURL(volumeURL), resolvedEncrypted != true {
            if let fileVaultActive = cachedBootFileVaultStatus() {
                resolvedEncrypted = fileVaultActive
            }
        }

        return VolumeEncryptionInfo(
            volumePath: volumeURL.path,
            volumeName: volValues.volumeName ?? volumeURL.lastPathComponent,
            format: volValues.volumeLocalizedFormatDescription ?? "APFS",
            isEncrypted: resolvedEncrypted,
            isRemovable: volValues.volumeIsRemovable,
            isInternal: volValues.volumeIsInternal,
            isLocal: volValues.volumeIsLocal
        )
    }

    /// Evaluates the boot volume (`/`).
    public static func readBootVolume() -> VolumeEncryptionInfo? {
        read(for: URL(fileURLWithPath: "/"))
    }

    /// Parses `/usr/bin/fdesetup status` text (`"FileVault is On."` / `"FileVault is Off."`).
    /// Returns `nil` for errors or unrecognized output so callers can fall back cleanly.
    public static func parseFdesetupStatus(_ output: String) -> Bool? {
        let lower = output.lowercased()
        if lower.contains("filevault is on") { return true }
        if lower.contains("filevault is off") { return false }
        return nil
    }

    /// Parses `/usr/sbin/diskutil info /` APFS `FileVault:` or CoreStorage `Encrypted:` lines.
    public static func parseDiskutilFileVault(_ output: String) -> Bool? {
        for line in output.components(separatedBy: .newlines) {
            let parts = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let val = parts[1].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if key == "filevault" {
                if val == "yes" || val == "on" { return true }
                if val == "no" || val == "off" { return false }
            }
        }
        return nil
    }

    private static func isBootVolumeURL(_ volumeURL: URL) -> Bool {
        let path = volumeURL.standardizedFileURL.path
        return path == "/" || path == "/System/Volumes/Data" || path.hasPrefix("/System/Volumes/")
    }

    private static let bootCacheLock = NSLock()
    private nonisolated(unsafe) static var cachedBootFileVaultValue: Bool?
    private nonisolated(unsafe) static var cachedBootFileVaultDate: Date?

    private static func cachedBootFileVaultStatus() -> Bool? {
        let now = Date()
        bootCacheLock.lock()
        if let cachedDate = cachedBootFileVaultDate,
           now.timeIntervalSince(cachedDate) < 10.0,
           let cached = cachedBootFileVaultValue {
            bootCacheLock.unlock()
            return cached
        }
        bootCacheLock.unlock()

        let statusOut = ForensicScanner.runTool("/usr/bin/fdesetup", args: ["status"], timeoutSeconds: 4).output
        let parsed = parseFdesetupStatus(statusOut)
            ?? parseDiskutilFileVault(ForensicScanner.runTool("/usr/sbin/diskutil", args: ["info", "/"], timeoutSeconds: 4).output)

        bootCacheLock.lock()
        cachedBootFileVaultValue = parsed
        cachedBootFileVaultDate = now
        bootCacheLock.unlock()
        return parsed
    }
}
