// SPDX-License-Identifier: GPL-3.0-only
import Darwin
import Foundation

/// POSIX `opendir` / `readdir` + `lstat` directory enumerator.
/// Unlike `FileManager.contentsOfDirectory`, this preserves `._*` AppleDouble entries
/// and dotfiles on macOS 27 APFS volumes so hidden executables cannot slip past audits.
public enum DirectoryEntries {
    public enum EntryKind: String, Sendable, Equatable {
        case regularFile
        case directory
        case symlink
        case other
    }

    public struct Entry: Sendable, Equatable {
        public let name: String
        public let url: URL
        public let kind: EntryKind

        public var isHidden: Bool { name.hasPrefix(".") }

        public init(name: String, url: URL, kind: EntryKind) {
            self.name = name
            self.url = url
            self.kind = kind
        }
    }

    /// Lists raw child names under `path` using POSIX `readdir`. Returns `nil` when `path` cannot be opened as a directory.
    public static func names(atPath path: String, includeHidden: Bool = true) -> [String]? {
        guard let dir = opendir(path) else { return nil }
        defer { closedir(dir) }

        var result: [String] = []
        while let direntPtr = readdir(dir) {
            let name = withUnsafePointer(to: &direntPtr.pointee.d_name) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) {
                    String(cString: $0)
                }
            }
            if name == "." || name == ".." || name.isEmpty { continue }
            if !includeHidden && name.hasPrefix(".") { continue }
            result.append(name)
        }
        return result.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }

    /// Lists child entries with resolved `lstat` file types (not following symlinks).
    public static func list(at directoryURL: URL, includeHidden: Bool = true) -> [Entry]? {
        let basePath = directoryURL.path
        guard let dir = opendir(basePath) else { return nil }
        defer { closedir(dir) }

        var entries: [Entry] = []
        while let direntPtr = readdir(dir) {
            let rawType = Int32(direntPtr.pointee.d_type)
            let name = withUnsafePointer(to: &direntPtr.pointee.d_name) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) {
                    String(cString: $0)
                }
            }
            if name == "." || name == ".." || name.isEmpty { continue }
            if !includeHidden && name.hasPrefix(".") { continue }

            let childURL = directoryURL.appendingPathComponent(name, isDirectory: rawType == DT_DIR)
            let kind: EntryKind
            switch rawType {
            case DT_REG: kind = .regularFile
            case DT_DIR: kind = .directory
            case DT_LNK: kind = .symlink
            case DT_UNKNOWN: kind = lstatKind(atPath: childURL.path)
            default: kind = lstatKind(atPath: childURL.path)
            }
            entries.append(Entry(name: name, url: childURL, kind: kind))
        }
        return entries.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    /// Convenience helper returning child `URL`s sorted by filename.
    public static func urls(at directoryURL: URL, includeHidden: Bool = false) -> [URL]? {
        list(at: directoryURL, includeHidden: includeHidden)?.map(\.url)
    }

    private static func lstatKind(atPath path: String) -> EntryKind {
        var st = stat()
        guard lstat(path, &st) == 0 else { return .other }
        switch st.st_mode & S_IFMT {
        case S_IFREG: return .regularFile
        case S_IFDIR: return .directory
        case S_IFLNK: return .symlink
        default: return .other
        }
    }
}

/// Inspects `._*` AppleDouble sidecar names discovered via `DirectoryEntries`.
/// Genuine macOS Finder/tar AppleDouble resource-fork files start with magic `0x00051607` and are never flagged;
/// only `._*` regular files that actually disguise Mach-O binaries or POSIX executable scripts are surfaced.
public enum AppleDoubleDetector {
    private static let appleDoubleMagic: UInt32 = 0x00051607

    public static func isAppleDoubleMagic(at url: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: url),
              let header = try? handle.read(upToCount: 4),
              header.count == 4 else {
            return false
        }
        try? handle.close()
        let magic = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
        return magic == appleDoubleMagic
    }

    public static func isSuspiciousHiddenBinary(entry: DirectoryEntries.Entry) -> Bool {
        guard entry.kind == .regularFile, entry.name.hasPrefix("._") else { return false }
        if isAppleDoubleMagic(at: entry.url) { return false }
        if ForensicScanner.isMachOBinary(at: entry.url) { return true }
        var st = stat()
        guard lstat(entry.url.path, &st) == 0 else { return false }
        let isExecutableBit = (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0
        return isExecutableBit && hasShebangHeader(at: entry.url)
    }

    /// Scans enumerated bundle directories for disguised `._*` Mach-O/script binaries invisible to `FileManager`.
    public static func collectSuspiciousHiddenItems(in directories: [URL], relativeTo bundleRoot: URL) -> [String] {
        let rootStd = bundleRoot.standardizedFileURL.path
        let rootPrefix = rootStd.hasSuffix("/") ? rootStd : rootStd + "/"
        var suspicious: [String] = []
        var seen: Set<String> = []

        for dir in directories {
            guard let entries = DirectoryEntries.list(at: dir, includeHidden: true) else { continue }
            for entry in entries where entry.isHidden {
                guard isSuspiciousHiddenBinary(entry: entry) else { continue }
                let path = entry.url.standardizedFileURL.path
                let rel = path.hasPrefix(rootPrefix) ? String(path.dropFirst(rootPrefix.count)) : entry.name
                if seen.insert(rel).inserted {
                    suspicious.append(rel)
                }
            }
        }
        return suspicious.sorted()
    }

    private static func hasShebangHeader(at url: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: url),
              let header = try? handle.read(upToCount: 2),
              header.count == 2 else {
            return false
        }
        try? handle.close()
        return header[0] == 0x23 && header[1] == 0x21 // "#!"
    }
}

/// Detects symlink loops (`(st_dev, st_ino)` ancestor cycles or `ELOOP`) and symlinks escaping the audited bundle root.
/// Standard intra-bundle framework symlinks (`Versions/Current -> A`, `Resources -> Versions/Current/Resources`) remain clean.
public enum BundleSymlinkAudit {
    public struct Result: Sendable, Equatable {
        public let loops: [String]
        public let escapes: [String]
        public let scannedEntries: Int

        public init(loops: [String] = [], escapes: [String] = [], scannedEntries: Int = 0) {
            self.loops = loops
            self.escapes = escapes
            self.scannedEntries = scannedEntries
        }
    }

    private struct FolderIdentity: Hashable {
        let dev: dev_t
        let ino: ino_t

        init(_ st: stat) {
            self.dev = st.st_dev
            self.ino = st.st_ino
        }
    }

    /// System-owned immutable paths that legitimate SDK/runtime bundles may reference (zero false positives).
    private static let allowedImmutableSystemPrefixes = [
        "/System/",
        "/usr/lib/",
        "/usr/share/",
        "/Library/Apple/",
        "/private/etc/ssl/",
        "/etc/ssl/",
    ]

    public static func audit(bundleURL: URL, maxEntries: Int = 20_000) -> Result {
        guard let rootReal = resolvedRealPath(bundleURL.path) else {
            return Result()
        }
        var rootStat = stat()
        guard stat(rootReal, &rootStat) == 0 else {
            return Result()
        }

        let rootPrefix = rootReal == "/" ? "/" : rootReal + "/"
        var loops: [String] = []
        var escapes: [String] = []
        var visitedCount = 0

        // Seed prioritized code-bearing directories first so huge bundles (e.g. Xcode) still audit Mach-O trees completely.
        var stack: [(url: URL, relative: String, ancestors: Set<FolderIdentity>)] = []
        let initialAncestors: Set<FolderIdentity> = [FolderIdentity(rootStat)]
        stack.append((URL(fileURLWithPath: rootReal, isDirectory: true), "", initialAncestors))

        var processedDirs: Set<String> = []
        while let current = stack.popLast(), visitedCount < maxEntries {
            guard processedDirs.insert(current.url.path).inserted else { continue }
            guard let entries = DirectoryEntries.list(at: current.url, includeHidden: true) else { continue }

            // Push non-prioritized subdirs before prioritized code subdirs so LIFO DFS pops code dirs first.
            var normalSubdirs: [(url: URL, relative: String, ancestors: Set<FolderIdentity>)] = []
            var prioritySubdirs: [(url: URL, relative: String, ancestors: Set<FolderIdentity>)] = []

            for entry in entries {
                if visitedCount >= maxEntries { break }
                visitedCount += 1

                let relPath = current.relative.isEmpty ? entry.name : "\(current.relative)/\(entry.name)"
                let fullPath = current.url.appendingPathComponent(entry.name).path

                switch entry.kind {
                case .directory:
                    var dirStat = stat()
                    guard lstat(fullPath, &dirStat) == 0 else { continue }
                    let key = FolderIdentity(dirStat)
                    if current.ancestors.contains(key) {
                        loops.append(relPath)
                        continue
                    }
                    let nextItem = (entry.url, relPath, current.ancestors.union([key]))
                    if isPriorityBundleDirectory(entry.name) {
                        prioritySubdirs.append(nextItem)
                    } else {
                        normalSubdirs.append(nextItem)
                    }

                case .symlink:
                    var targetStat = stat()
                    let statResult = stat(fullPath, &targetStat)
                    if statResult != 0 && errno == ELOOP {
                        loops.append(relPath)
                        continue
                    }

                    if let resolvedTarget = resolvedRealPath(fullPath) {
                        let isInsideBundle = resolvedTarget == rootReal || resolvedTarget.hasPrefix(rootPrefix)
                        if !isInsideBundle && !isAllowedSystemTarget(resolvedTarget) {
                            escapes.append("\(relPath) -> \(resolvedTarget)")
                            continue
                        }
                    } else if let rawDest = try? FileManager.default.destinationOfSymbolicLink(atPath: fullPath),
                              danglingEscapesBundle(rawTarget: rawDest, symlinkDir: current.url, rootReal: rootReal, rootPrefix: rootPrefix) {
                        escapes.append("\(relPath) -> \(rawDest)")
                        continue
                    }

                    if statResult == 0, (targetStat.st_mode & S_IFMT) == S_IFDIR {
                        let targetKey = FolderIdentity(targetStat)
                        if current.ancestors.contains(targetKey) {
                            loops.append(relPath)
                        } else {
                            let resolvedDir = resolvedRealPath(fullPath) ?? fullPath
                            let nextItem = (URL(fileURLWithPath: resolvedDir, isDirectory: true), relPath, current.ancestors.union([targetKey]))
                            if isPriorityBundleDirectory(entry.name) {
                                prioritySubdirs.append(nextItem)
                            } else {
                                normalSubdirs.append(nextItem)
                            }
                        }
                    }

                case .regularFile, .other:
                    continue
                }
            }

            stack.append(contentsOf: normalSubdirs)
            stack.append(contentsOf: prioritySubdirs)
        }

        return Result(
            loops: loops.sorted(),
            escapes: escapes.sorted(),
            scannedEntries: visitedCount
        )
    }

    private static func isPriorityBundleDirectory(_ name: String) -> Bool {
        switch name {
        case "Contents", "MacOS", "Frameworks", "Libraries", "PlugIns", "XPCServices", "Helpers", "Library", "LoginItems", "Versions":
            return true
        default:
            return false
        }
    }

    private static func resolvedRealPath(_ path: String) -> String? {
        guard let cPtr = realpath(path, nil) else { return nil }
        defer { free(cPtr) }
        return String(cString: cPtr)
    }

    private static func isAllowedSystemTarget(_ resolvedPath: String) -> Bool {
        allowedImmutableSystemPrefixes.contains { resolvedPath.hasPrefix($0) }
    }

    private static func danglingEscapesBundle(rawTarget: String, symlinkDir: URL, rootReal: String, rootPrefix: String) -> Bool {
        let candidate: String
        if rawTarget.hasPrefix("/") {
            candidate = URL(fileURLWithPath: rawTarget).standardizedFileURL.path
        } else {
            candidate = symlinkDir.appendingPathComponent(rawTarget).standardizedFileURL.path
        }
        if isAllowedSystemTarget(candidate) { return false }
        return candidate != rootReal && !candidate.hasPrefix(rootPrefix)
    }
}
