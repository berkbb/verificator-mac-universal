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

        return VolumeEncryptionInfo(
            volumePath: volumeURL.path,
            volumeName: volValues.volumeName ?? volumeURL.lastPathComponent,
            format: volValues.volumeLocalizedFormatDescription ?? "APFS",
            isEncrypted: volValues.volumeIsEncrypted,
            isRemovable: volValues.volumeIsRemovable,
            isInternal: volValues.volumeIsInternal,
            isLocal: volValues.volumeIsLocal
        )
    }

    /// Evaluates the boot volume (`/`).
    public static func readBootVolume() -> VolumeEncryptionInfo? {
        read(for: URL(fileURLWithPath: "/"))
    }
}
