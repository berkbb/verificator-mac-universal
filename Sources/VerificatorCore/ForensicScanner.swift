// SPDX-License-Identifier: GPL-3.0-only
import CryptoKit
import Darwin
import Foundation

/// 4 katmanlı, sıfır yanlış pozitif (0% FP) garantili salt-okunur macOS adli paket denetçisi.
public enum ForensicScanner {
    private static let swizzleSymbols: Set<String> = [
        "_method_exchangeImplementations",
        "_method_setImplementation",
        "_method_getImplementation",
        "_class_replaceMethod",
        "_class_addMethod",
        "_class_getInstanceMethod",
        "_class_getClassMethod",
        "_imp_implementationWithBlock",
        "_objc_getClass",
        "_sel_registerName",
    ]

    private static let memoryPatchSymbols: Set<String> = [
        "_mach_vm_protect",
        "_mach_vm_write",
        "_mach_vm_read",
        "_mach_vm_remap",
        "_mach_vm_allocate",
        "_mach_vm_deallocate",
        "_mach_task_self_",
        "_vm_protect",
        "_sys_icache_invalidate",
    ]

    private static let dyldSlideSymbols: Set<String> = [
        "__dyld_get_image_vmaddr_slide",
        "__dyld_get_image_header",
        "__dyld_get_image_name",
        "__dyld_image_count",
        "__dyld_register_func_for_add_image",
    ]

    private static let externalSuspiciousPrefixes = [
        "/tmp/",
        "/var/tmp/",
        "/private/tmp/",
        "/Users/Shared/",
    ]

    public static let supportedBundleExtensions: Set<String> = [
        "app", "framework", "bundle", "appex", "xpc", "kext", "plugin",
    ]

    public static let supportedContainerExtensions: Set<String> = [
        "pkg", "mpkg", "dmg",
    ]

    public static let supportedBinaryExtensions: Set<String> = [
        "dylib", "so",
    ]

    public static let requiredTools: [(name: String, path: String)] = [
        ("codesign", "/usr/bin/codesign"),
        ("spctl", "/usr/sbin/spctl"),
        ("otool", "/usr/bin/otool"),
        ("nm", "/usr/bin/nm"),
        ("strings", "/usr/bin/strings"),
        ("lipo", "/usr/bin/lipo"),
        ("pkgutil", "/usr/sbin/pkgutil"),
    ]

    public static func inspectTools() -> [ToolStatus] {
        let fm = FileManager.default
        return requiredTools.map { tool in
            ToolStatus(name: tool.name, path: tool.path, isAvailable: fm.isExecutableFile(atPath: tool.path))
        }
    }

    public static func isSupportedAuditURL(_ url: URL) -> Bool {
        let ext = url.pathExtension.lowercased()
        if supportedBundleExtensions.contains(ext)
            || supportedContainerExtensions.contains(ext)
            || supportedBinaryExtensions.contains(ext) {
            return true
        }
        return isMachOBinary(at: url)
    }

    internal struct SignatureInfo {
        var identifier: String = "-"
        var teamId: String = "not set"
        var authorities: [String] = []
        var isAdhoc: Bool = false
        var isUnsigned: Bool = false
        var signedTime: String = "-"
        var hasHardenedRuntime: Bool = false
        var isNotarized: Bool = false
        var cdHash: String = "-"

        var hasOfficialAppleChain: Bool {
            authorities.contains {
                $0.contains("Apple Root CA")
                    || $0.contains("Developer ID Application")
                    || $0.contains("Developer ID Installer")
                    || $0.contains("Apple Mac OS Application Signing")
                    || $0.contains("Apple iPhone OS Application Signing")
                    || $0.contains("3rd Party Mac Developer Installer")
                    || $0.contains("Apple Software Update Certification Authority")
                    || $0.contains("Software Signing")
            }
        }
    }

    internal static func parseSignature(
        for path: String,
        cancellation: ScanCancellationToken? = nil
    ) -> (info: SignatureInfo, raw: String) {
        let out = runTool("/usr/bin/codesign", args: ["-dvvv", path], cancellation: cancellation).output
        var info = SignatureInfo()
        if out.contains("code object is not signed at all") {
            info.isUnsigned = true
            return (info, out)
        }
        for line in out.components(separatedBy: .newlines) {
            if line.hasPrefix("Identifier=") {
                info.identifier = String(line.dropFirst("Identifier=".count))
            } else if line.hasPrefix("TeamIdentifier=") {
                info.teamId = String(line.dropFirst("TeamIdentifier=".count))
            } else if line.hasPrefix("Authority=") {
                info.authorities.append(String(line.dropFirst("Authority=".count)))
            } else if line.hasPrefix("Signature=adhoc") || (line.contains("flags=") && line.contains("adhoc")) {
                info.isAdhoc = true
            } else if line.hasPrefix("Signed Time=") {
                info.signedTime = String(line.dropFirst("Signed Time=".count))
            } else if line.hasPrefix("Timestamp=") {
                info.signedTime = String(line.dropFirst("Timestamp=".count))
            } else if line.hasPrefix("CodeDirectory ") && line.contains("runtime") {
                info.hasHardenedRuntime = true
            } else if line.hasPrefix("Notarization Ticket=stapled") {
                info.isNotarized = true
            } else if line.hasPrefix("CDHash=") {
                info.cdHash = String(line.dropFirst("CDHash=".count))
            }
        }
        return (info, out)
    }

    internal static func parseArchitectures(
        for execPath: String,
        cancellation: ScanCancellationToken? = nil
    ) -> [String] {
        guard FileManager.default.fileExists(atPath: execPath) else { return [] }
        let res = runTool("/usr/bin/lipo", args: ["-archs", execPath], timeoutSeconds: 8, cancellation: cancellation)
        guard res.exitCode == 0 else { return [] }
        return res.output
            .split(whereSeparator: \.isWhitespace)
            .map(String.init)
            .filter { !$0.isEmpty }
    }

    internal static func executableDigests(for execPath: String) -> (sha256: String, sha512: String) {
        guard FileManager.default.isReadableFile(atPath: execPath),
              let handle = try? FileHandle(forReadingFrom: URL(fileURLWithPath: execPath)) else {
            return ("-", "-")
        }
        defer { try? handle.close() }
        var sha256 = SHA256()
        var sha512 = SHA512()
        while let chunk = try? handle.read(upToCount: 1 << 20), !chunk.isEmpty {
            sha256.update(data: chunk)
            sha512.update(data: chunk)
        }
        return (
            sha256: sha256.finalize().map { String(format: "%02x", $0) }.joined(),
            sha512: sha512.finalize().map { String(format: "%02x", $0) }.joined()
        )
    }

    internal static func executableSHA256(for execPath: String) -> String {
        executableDigests(for: execPath).sha256
    }

    private struct CrossTargetForensics {
        let deceptiveNames: [String]
        let firewallAppState: FirewallAppState?
        let internetAccessPolicy: InternetAccessPolicy?
        let volumeEncryption: VolumeEncryptionInfo?
    }

    private static func collectCrossTargetForensics(
        url: URL,
        bundleName: String,
        targetKind: AuditTargetKind,
        candidateNames: [String],
        options: ScanOptions,
        cancellation: ScanCancellationToken?,
        findings: inout [ForensicFinding],
        verdict: inout IntegrityVerdict
    ) -> CrossTargetForensics {
        let deceptiveNames = OpenSafety.collectDeceptiveNames(in: candidateNames)
        if !deceptiveNames.isEmpty {
            findings.append(ForensicFinding(
                severity: .warning,
                titleKey: .findingNameSpoofingTitle,
                descKey: .findingNameSpoofingDesc,
                detailSuffix: deceptiveNames.joined(separator: ", ")
            ))
            if verdict == .clean {
                verdict = .warning
            }
        }

        let firewallAppState: FirewallAppState?
        if options.checkApplicationFirewall,
           cancellation?.isCancelled != true,
           targetKind == .appBundle || targetKind == .nestedBundle || targetKind == .standaloneMachO {
            firewallAppState = ApplicationFirewall.inspectTarget(atPath: url.path, cancellation: cancellation)
        } else {
            firewallAppState = nil
        }

        let policy: InternetAccessPolicy?
        switch targetKind {
        case .appBundle, .nestedBundle:
            policy = InternetAccessPolicy.load(bundle: url, languages: options.policyLanguages, appName: bundleName)
        case .standaloneMachO:
            policy = InternetAccessPolicy.load(executable: url, languages: options.policyLanguages)
        case .installerPackage, .diskImage:
            policy = nil
        }

        let volumeEncryption = VolumeEncryptionInfo.read(for: url)
        return CrossTargetForensics(
            deceptiveNames: deceptiveNames,
            firewallAppState: firewallAppState,
            internetAccessPolicy: policy,
            volumeEncryption: volumeEncryption
        )
    }

    internal static func isMachOBinary(at url: URL) -> Bool {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), !isDir.boolValue,
              let handle = try? FileHandle(forReadingFrom: url),
              let header = try? handle.read(upToCount: 4),
              header.count == 4 else {
            return false
        }
        try? handle.close()
        let magic = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
        switch magic {
        case 0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE, 0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA:
            return true
        default:
            return false
        }
    }

    internal static func parseEntitlements(
        for targetPath: String,
        cancellation: ScanCancellationToken? = nil
    ) -> (keys: [String], rawXML: String) {
        let res = runTool(
            "/usr/bin/codesign",
            args: ["-d", "--entitlements", ":-", "--xml", targetPath],
            timeoutSeconds: 8,
            cancellation: cancellation
        )
        guard res.exitCode == 0 else { return ([], "") }
        let raw = res.output
        let xmlStart = raw.range(of: "<?xml") ?? raw.range(of: "<plist")
        guard let start = xmlStart else { return ([], "") }
        let xmlString = String(raw[start.lowerBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = xmlString.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            return ([], xmlString)
        }

        var enabled: [String] = []
        for (key, value) in plist.sorted(by: { $0.key < $1.key }) {
            if let boolVal = value as? Bool, boolVal {
                enabled.append(key)
            } else if let arrayVal = value as? [Any], !arrayVal.isEmpty {
                enabled.append(key)
            } else if let strVal = value as? String, !strVal.isEmpty {
                enabled.append("\(key)=\(strVal)")
            }
        }
        return (enabled, xmlString)
    }

    internal static func extractRpaths(
        for execPath: String,
        execDir: URL,
        cancellation: ScanCancellationToken? = nil
    ) -> (urls: [URL], rawPaths: [String]) {
        guard FileManager.default.fileExists(atPath: execPath) else { return ([], []) }
        let res = runTool("/usr/bin/otool", args: ["-l", execPath], timeoutSeconds: 10, cancellation: cancellation)
        guard res.exitCode == 0 else { return ([], []) }

        var rawPaths: [String] = []
        var rpathURLs: [URL] = []
        var sawRpathCmd = false
        for line in res.output.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed == "cmd LC_RPATH" {
                sawRpathCmd = true
                continue
            }
            if sawRpathCmd && trimmed.hasPrefix("path ") {
                let withoutPrefix = String(trimmed.dropFirst("path ".count))
                let rawPath = withoutPrefix.components(separatedBy: " (offset").first?.trimmingCharacters(in: .whitespaces) ?? ""
                sawRpathCmd = false
                guard !rawPath.isEmpty else { continue }
                if !rawPaths.contains(rawPath) {
                    rawPaths.append(rawPath)
                }
                if rawPath == "@executable_path" || rawPath == "@loader_path" {
                    rpathURLs.append(execDir.standardizedFileURL)
                } else if rawPath.hasPrefix("@executable_path/") {
                    let rel = String(rawPath.dropFirst("@executable_path/".count))
                    rpathURLs.append(execDir.appendingPathComponent(rel).standardizedFileURL)
                } else if rawPath.hasPrefix("@loader_path/") {
                    let rel = String(rawPath.dropFirst("@loader_path/".count))
                    rpathURLs.append(execDir.appendingPathComponent(rel).standardizedFileURL)
                } else if rawPath.hasPrefix("/") {
                    rpathURLs.append(URL(fileURLWithPath: rawPath).standardizedFileURL)
                }
            } else if trimmed.hasPrefix("cmd ") {
                sawRpathCmd = false
            }
        }
        return (rpathURLs, rawPaths)
    }

    private struct BundleLayout {
        let plistURL: URL
        let execURL: URL
        let executableName: String
        let executableRelativePath: String
        let bundleName: String
        let bundleId: String
        let shortVersion: String
        let buildVersion: String
        let scanDirectories: [URL]
        let frameworksURL: URL
        let macosURL: URL
        let isWrappedBundle: Bool
    }

    private struct BundledInspectionContext {
        let mainSig: SignatureInfo
        let plistModDate: Date?
        let options: ScanOptions
        let dateFormatter: DateFormatter
        var bundledItems: [BundledLibraryItem] = []
        var hookCategories: [HookSymbolCategory] = []
        var suspiciousDylibNames: Set<String> = []
        var partialHookItems: [String] = []
        var unsignedBundledItems: [String] = []
        var originalVendorSignatures: Set<String> = []
        var inspectedPaths: Set<String> = []
    }

    internal static func makePosixDateFormatter() -> DateFormatter {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter
    }

    private static func resolveBundleLayout(at url: URL) -> BundleLayout {
        let fm = FileManager.default
        let standardizedRoot = url.standardizedFileURL
        let contentsURL = url.appendingPathComponent("Contents", isDirectory: true)
        let standardPlistURL = contentsURL.appendingPathComponent("Info.plist")

        var bundleRootURL = contentsURL
        var plistURL = standardPlistURL
        var isWrappedBundle = false

        if !fm.fileExists(atPath: standardPlistURL.path) {
            let versionedPlist = url.appendingPathComponent("Versions/Current/Resources/Info.plist")
            let resourcesPlist = url.appendingPathComponent("Resources/Info.plist")
            let flatPlist = url.appendingPathComponent("Info.plist")
            let wrappedSymlink = url.appendingPathComponent("WrappedBundle")
            let resolvedWrapped = wrappedSymlink.resolvingSymlinksInPath()
            let wrappedPlist = resolvedWrapped.appendingPathComponent("Info.plist")

            if fm.fileExists(atPath: versionedPlist.path) {
                bundleRootURL = url.appendingPathComponent("Versions/Current", isDirectory: true).resolvingSymlinksInPath()
                plistURL = versionedPlist.resolvingSymlinksInPath()
            } else if fm.fileExists(atPath: resourcesPlist.path) {
                bundleRootURL = url
                plistURL = resourcesPlist
            } else if fm.fileExists(atPath: flatPlist.path) {
                bundleRootURL = url
                plistURL = flatPlist
            } else if fm.fileExists(atPath: wrappedPlist.path) {
                bundleRootURL = resolvedWrapped
                plistURL = wrappedPlist
                isWrappedBundle = true
            } else {
                let wrapperDir = url.appendingPathComponent("Wrapper", isDirectory: true)
                if let wrappedApps = try? fm.contentsOfDirectory(at: wrapperDir, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]),
                   let innerApp = wrappedApps.first(where: { $0.pathExtension.lowercased() == "app" }),
                   fm.fileExists(atPath: innerApp.appendingPathComponent("Info.plist").path) {
                    bundleRootURL = innerApp
                    plistURL = innerApp.appendingPathComponent("Info.plist")
                    isWrappedBundle = true
                }
            }
        }

        var bundleName = url.deletingPathExtension().lastPathComponent
        var bundleId = "-"
        var shortVersion = "-"
        var buildVersion = "-"
        var executableName = bundleName

        if let plistData = try? Data(contentsOf: plistURL),
           let plist = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil) as? [String: Any] {
            bundleName = (plist["CFBundleName"] as? String) ?? (plist["CFBundleDisplayName"] as? String) ?? bundleName
            bundleId = (plist["CFBundleIdentifier"] as? String) ?? "-"
            shortVersion = (plist["CFBundleShortVersionString"] as? String) ?? "-"
            buildVersion = (plist["CFBundleVersion"] as? String) ?? "-"
            executableName = (plist["CFBundleExecutable"] as? String) ?? bundleName
        } else if let bundle = Bundle(url: url) {
            bundleId = bundle.bundleIdentifier ?? "-"
        }

        let isFrameworkLayout = url.pathExtension.lowercased() == "framework"
        let frameworksURL = bundleRootURL.appendingPathComponent("Frameworks", isDirectory: true)
        let librariesURL = bundleRootURL.appendingPathComponent("Libraries", isDirectory: true)
        let macosURL = (isWrappedBundle || isFrameworkLayout)
            ? bundleRootURL
            : bundleRootURL.appendingPathComponent("MacOS", isDirectory: true)
        let pluginsURL = bundleRootURL.appendingPathComponent("PlugIns", isDirectory: true)
        let xpcURL = bundleRootURL.appendingPathComponent("XPCServices", isDirectory: true)
        let helpersURL = bundleRootURL.appendingPathComponent("Helpers", isDirectory: true)
        let loginItemsURL = bundleRootURL.appendingPathComponent("Library/LoginItems", isDirectory: true)

        let candidateExecURL = macosURL.appendingPathComponent(executableName)
        let execURL: URL
        if fm.fileExists(atPath: candidateExecURL.path) {
            execURL = candidateExecURL
        } else if let bundleExecURL = Bundle(url: url)?.executableURL, fm.fileExists(atPath: bundleExecURL.path) {
            execURL = bundleExecURL
        } else if fm.fileExists(atPath: bundleRootURL.appendingPathComponent(executableName).path) {
            execURL = bundleRootURL.appendingPathComponent(executableName)
        } else {
            execURL = candidateExecURL
        }

        let execStdPath = execURL.standardizedFileURL.path
        let rootPrefix = standardizedRoot.path.hasSuffix("/") ? standardizedRoot.path : standardizedRoot.path + "/"
        let relativePath: String
        if execStdPath.hasPrefix(rootPrefix) {
            relativePath = String(execStdPath.dropFirst(rootPrefix.count))
        } else {
            relativePath = isWrappedBundle ? "WrappedBundle/\(executableName)" : "Contents/MacOS/\(executableName)"
        }

        let scanDirs: [URL] = isWrappedBundle
            ? [frameworksURL, librariesURL, bundleRootURL, pluginsURL]
            : [frameworksURL, librariesURL, macosURL, pluginsURL, xpcURL, helpersURL, loginItemsURL]

        return BundleLayout(
            plistURL: plistURL,
            execURL: execURL,
            executableName: executableName,
            executableRelativePath: relativePath,
            bundleName: bundleName,
            bundleId: bundleId,
            shortVersion: shortVersion,
            buildVersion: buildVersion,
            scanDirectories: scanDirs,
            frameworksURL: frameworksURL,
            macosURL: macosURL,
            isWrappedBundle: isWrappedBundle
        )
    }

    private enum BundledItemKind {
        case dylib
        case framework
        case nestedBundle
        case helperBinary

        var isNestedBundle: Bool {
            self == .framework || self == .nestedBundle
        }
    }

    private static func resolveBinaryURL(for itemURL: URL, kind: BundledItemKind) -> URL {
        if !kind.isNestedBundle {
            return itemURL.resolvingSymlinksInPath()
        }
        if let exec = Bundle(url: itemURL)?.executableURL {
            return exec.resolvingSymlinksInPath()
        }
        let stem = itemURL.deletingPathExtension().lastPathComponent
        let macOSCandidate = itemURL.appendingPathComponent("Contents/MacOS/\(stem)")
        if FileManager.default.fileExists(atPath: macOSCandidate.path) {
            return macOSCandidate.resolvingSymlinksInPath()
        }
        return itemURL.appendingPathComponent(stem).resolvingSymlinksInPath()
    }

    private static func resolveBinarySize(for itemURL: URL, kind: BundledItemKind) -> Int64 {
        let resolved = resolveBinaryURL(for: itemURL, kind: kind)
        return (try? resolved.resourceValues(forKeys: [.fileSizeKey]).fileSize).map { Int64($0) } ?? 0
    }

    private static func inspectBundledItem(
        at itemURL: URL,
        displayName: String,
        kind: BundledItemKind,
        cancellation: ScanCancellationToken? = nil,
        context: inout BundledInspectionContext
    ) {
        if cancellation?.isCancelled == true { return }
        let standardizedPath = itemURL.standardizedFileURL.path
        guard !context.inspectedPaths.contains(standardizedPath) else { return }
        context.inspectedPaths.insert(standardizedPath)

        let rawFileName = itemURL.lastPathComponent
        let itemSig = context.options.deepFrameworkSignatureCheck
            ? parseSignature(for: itemURL.path, cancellation: cancellation).info
            : context.mainSig

        if (kind == .dylib || kind == .framework),
           itemSig.hasOfficialAppleChain,
           itemSig.teamId != "not set",
           let devAuth = itemSig.authorities.first {
            context.originalVendorSignatures.insert("\(devAuth)")
        }

        let modDate = modificationDate(for: itemURL)
        let modDateStr = modDate.map { context.dateFormatter.string(from: $0) } ?? "-"
        let fileSize = resolveBinarySize(for: itemURL, kind: kind)
        let binaryURL = resolveBinaryURL(for: itemURL, kind: kind)

        let isOfficialVendorLibrary = itemSig.hasOfficialAppleChain
            && (itemSig.teamId == context.mainSig.teamId || itemSig.teamId != "not set")

        if context.options.deepFrameworkSignatureCheck && context.mainSig.hasOfficialAppleChain && itemSig.isUnsigned && kind == .dylib {
            context.unsignedBundledItems.append(displayName)
        }

        var detectedSwizzle: [String] = []
        var detectedMemory: [String] = []
        var detectedDyld: [String] = []
        var targetStrings: [String] = []

        // Resmi olmayan (satıcı imzasız / ad-hoc) .dylib, .framework, .appex/.xpc ve yardımcı Mach-O ikililerini nm -u ile denetle.
        let shouldScanSymbols = !isOfficialVendorLibrary && (kind == .dylib || !itemSig.hasOfficialAppleChain)
        if shouldScanSymbols && FileManager.default.fileExists(atPath: binaryURL.path) {
            let analysis = analyzeMachOHooks(
                binaryPath: binaryURL.path,
                libraryName: rawFileName,
                isDylib: kind == .dylib,
                parentHasOfficialChain: context.mainSig.hasOfficialAppleChain,
                extractTargetStrings: context.options.extractTargetStrings,
                cancellation: cancellation
            )
            detectedSwizzle = analysis.swizzle
            detectedMemory = analysis.memory
            detectedDyld = analysis.dyld
            targetStrings = analysis.targetStrings

            if analysis.isInjectedCrack {
                context.suspiciousDylibNames.insert(rawFileName)
                context.hookCategories.append(contentsOf: analysis.categories)
            } else if analysis.isPartialSwizzle {
                context.partialHookItems.append(displayName)
                context.hookCategories.append(contentsOf: analysis.categories)
            }
        }

        var isTimestampAnomaly = false
        if context.suspiciousDylibNames.contains(rawFileName), let pDate = context.plistModDate, let mDate = modDate {
            if abs(mDate.timeIntervalSince(pDate)) > 3600 {
                isTimestampAnomaly = true
            }
        }

        let sigBadge = itemSig.hasOfficialAppleChain
            ? "✓ \(itemSig.teamId)"
            : (itemSig.authorities.first ?? (itemSig.isUnsigned ? "unsigned" : "adhoc"))
        let allSuspicious = detectedSwizzle + detectedMemory + detectedDyld
        context.bundledItems.append(
            BundledLibraryItem(
                name: displayName,
                modifiedDate: "\(modDateStr) [\(sigBadge)]",
                sizeBytes: fileSize,
                isTimestampAnomaly: isTimestampAnomaly,
                suspiciousSymbols: allSuspicious,
                targetStrings: targetStrings
            )
        )
    }

    internal struct MachOHookAnalysis {
        let swizzle: [String]
        let memory: [String]
        let dyld: [String]
        let targetStrings: [String]
        let isInjectedCrack: Bool
        let isPartialSwizzle: Bool
        let categories: [HookSymbolCategory]
    }

    internal static func analyzeMachOHooks(
        binaryPath: String,
        libraryName: String,
        isDylib: Bool,
        parentHasOfficialChain: Bool,
        extractTargetStrings: Bool,
        cancellation: ScanCancellationToken? = nil
    ) -> MachOHookAnalysis {
        let nmOut = runTool("/usr/bin/nm", args: ["-u", binaryPath], cancellation: cancellation).output
        let symbols = Set(
            nmOut.components(separatedBy: .newlines)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        )

        let detectedSwizzle = swizzleSymbols.intersection(symbols).sorted()
        let detectedMemory = memoryPatchSymbols.intersection(symbols).sorted()
        let detectedDyld = dyldSlideSymbols.intersection(symbols).sorted()

        let hasActiveSwizzle = symbols.contains("_method_exchangeImplementations")
            || symbols.contains("_method_setImplementation")
            || symbols.contains("_class_replaceMethod")
        let hasActiveMemoryPatch = symbols.contains("_mach_vm_protect")
            || symbols.contains("_mach_vm_write")
            || symbols.contains("_sys_icache_invalidate")

        let isInjectedCrack = hasActiveMemoryPatch
            || (hasActiveSwizzle && (!detectedDyld.isEmpty || (isDylib && !parentHasOfficialChain)))

        var categories: [HookSymbolCategory] = []
        var targetStrings: [String] = []

        if isInjectedCrack {
            if !detectedSwizzle.isEmpty {
                categories.append(HookSymbolCategory(libraryName: libraryName, categoryKey: .symbolCatSwizzle, symbols: detectedSwizzle))
            }
            if !detectedMemory.isEmpty {
                categories.append(HookSymbolCategory(libraryName: libraryName, categoryKey: .symbolCatMemory, symbols: detectedMemory))
            }
            if !detectedDyld.isEmpty {
                categories.append(HookSymbolCategory(libraryName: libraryName, categoryKey: .symbolCatDyld, symbols: detectedDyld))
            }
            if extractTargetStrings {
                targetStrings = extractInjectedTargetStrings(at: binaryPath, cancellation: cancellation)
                if !targetStrings.isEmpty {
                    categories.append(HookSymbolCategory(libraryName: libraryName, categoryKey: .symbolCatTarget, symbols: Array(targetStrings.prefix(24))))
                }
            }
            return MachOHookAnalysis(
                swizzle: detectedSwizzle,
                memory: detectedMemory,
                dyld: detectedDyld,
                targetStrings: targetStrings,
                isInjectedCrack: true,
                isPartialSwizzle: false,
                categories: categories
            )
        }

        if hasActiveSwizzle && parentHasOfficialChain {
            if !detectedSwizzle.isEmpty {
                categories.append(HookSymbolCategory(libraryName: libraryName, categoryKey: .symbolCatSwizzle, symbols: detectedSwizzle))
            }
            return MachOHookAnalysis(
                swizzle: detectedSwizzle,
                memory: [],
                dyld: [],
                targetStrings: [],
                isInjectedCrack: false,
                isPartialSwizzle: true,
                categories: categories
            )
        }

        return MachOHookAnalysis(
            swizzle: [],
            memory: [],
            dyld: [],
            targetStrings: [],
            isInjectedCrack: false,
            isPartialSwizzle: false,
            categories: []
        )
    }

    private static func extractInjectedTargetStrings(
        at path: String,
        cancellation: ScanCancellationToken? = nil
    ) -> [String] {
        let strOut = runTool("/usr/bin/strings", args: [path], timeoutSeconds: 12, maxOutputBytes: 4 * 1024 * 1024, cancellation: cancellation).output
        var seenTargets: Set<String> = []
        var results: [String] = []
        for line in strOut.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.count >= 4 && trimmed.count <= 90 else { continue }
            if trimmed.hasPrefix("_TtC")
                || trimmed.hasPrefix("$s")
                || trimmed.contains("AppDelegate")
                || trimmed.contains("License")
                || trimmed.contains("Subscription")
                || trimmed.contains("VIP")
                || trimmed == "__TEXT"
                || trimmed == "__DATA"
                || trimmed.contains("not found!") {
                if !seenTargets.contains(trimmed) {
                    seenTargets.insert(trimmed)
                    results.append(trimmed)
                }
            }
        }
        return results
    }

    private static func resolveBundleInternalDylib(
        _ loadPath: String,
        bundleURL: URL,
        layout: BundleLayout,
        rpathURLs: [URL]
    ) -> URL? {
        let fm = FileManager.default
        let bundleStdPath = bundleURL.standardizedFileURL.path
        let bundlePrefix = bundleStdPath.hasSuffix("/") ? bundleStdPath : bundleStdPath + "/"
        let execDir = layout.execURL.deletingLastPathComponent()

        var candidates: [URL] = []
        if loadPath.hasPrefix("@executable_path/") {
            let rel = String(loadPath.dropFirst("@executable_path/".count))
            candidates.append(execDir.appendingPathComponent(rel).standardizedFileURL)
        } else if loadPath.hasPrefix("@loader_path/") {
            let rel = String(loadPath.dropFirst("@loader_path/".count))
            candidates.append(execDir.appendingPathComponent(rel).standardizedFileURL)
        } else if loadPath.hasPrefix("@rpath/") {
            let rel = String(loadPath.dropFirst("@rpath/".count))
            for base in rpathURLs {
                candidates.append(base.appendingPathComponent(rel).standardizedFileURL)
            }
            candidates.append(layout.frameworksURL.appendingPathComponent(rel).standardizedFileURL)
            candidates.append(layout.macosURL.appendingPathComponent(rel).standardizedFileURL)
            candidates.append(execDir.appendingPathComponent(rel).standardizedFileURL)
        } else if loadPath.hasPrefix(bundlePrefix) {
            candidates.append(URL(fileURLWithPath: loadPath).standardizedFileURL)
        }

        return candidates.first { candidate in
            candidate.path.hasPrefix(bundlePrefix)
                && candidate.pathExtension.lowercased() == "dylib"
                && fm.fileExists(atPath: candidate.path)
        }
    }

    /// Seçili pakette isteğe bağlı Gatekeeper politika değerlendirmesi (`/usr/sbin/spctl --assess -vvv`) çalıştırır.
    public static func assessGatekeeper(
        at bundlePath: String,
        type assessType: String = "execute",
        timeoutSeconds: TimeInterval = 15,
        cancellation: ScanCancellationToken? = nil
    ) -> (accepted: Bool, statusText: String) {
        let res = runTool(
            "/usr/sbin/spctl",
            args: ["--assess", "-vvv", "--type", assessType, bundlePath],
            timeoutSeconds: timeoutSeconds,
            cancellation: cancellation
        )
        let compact = res.output
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .joined(separator: " | ")
        let accepted = res.exitCode == 0 || compact.localizedCaseInsensitiveContains("accepted")
        return (accepted, compact.isEmpty ? "exit \(res.exitCode)" : compact)
    }

    public static func auditTarget(
        at url: URL,
        options: ScanOptions = ScanOptions(),
        cancellation: ScanCancellationToken? = nil
    ) -> BundleAuditReport {
        let ext = url.pathExtension.lowercased()
        switch ext {
        case "app":
            return auditMachOBundle(at: url, targetKind: .appBundle, options: options, cancellation: cancellation)
        case "framework", "bundle", "appex", "xpc", "kext", "plugin":
            return auditMachOBundle(at: url, targetKind: .nestedBundle, options: options, cancellation: cancellation)
        case "pkg", "mpkg":
            return auditInstallerPackage(at: url, options: options, cancellation: cancellation)
        case "dmg":
            return auditDiskImage(at: url, options: options, cancellation: cancellation)
        default:
            if supportedBinaryExtensions.contains(ext) || isMachOBinary(at: url) {
                return auditStandaloneMachO(at: url, options: options, cancellation: cancellation)
            }
            return unsupportedTargetReport(at: url)
        }
    }

    public static func auditBundle(
        at url: URL,
        options: ScanOptions = ScanOptions(),
        cancellation: ScanCancellationToken? = nil
    ) -> BundleAuditReport {
        let ext = url.pathExtension.lowercased()
        if ext != "app" && !ext.isEmpty {
            return auditTarget(at: url, options: options, cancellation: cancellation)
        }
        return auditMachOBundle(at: url, targetKind: .appBundle, options: options, cancellation: cancellation)
    }

    private static func auditMachOBundle(
        at url: URL,
        targetKind: AuditTargetKind,
        options: ScanOptions = ScanOptions(),
        cancellation: ScanCancellationToken? = nil
    ) -> BundleAuditReport {
        let startTime = ContinuousClock.now
        let bundlePath = url.path
        let fm = FileManager.default
        let layout = resolveBundleLayout(at: url)
        let dateFmt = makePosixDateFormatter()

        let plistModDate = modificationDate(for: layout.plistURL)
        let execModDate = modificationDate(for: layout.execURL)
        let plistDateStr = plistModDate.map { dateFmt.string(from: $0) } ?? "-"
        let execDateStr = execModDate.map { dateFmt.string(from: $0) } ?? "-"

        guard fm.fileExists(atPath: bundlePath) else {
            let elapsed = ContinuousClock.now - startTime
            let durationMs = max(1, Int(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000))
            AppLog.shared.warning(.scanner, "Bundle not found on disk", detail: bundlePath)
            return BundleAuditReport(
                targetKind: targetKind,
                bundlePath: bundlePath,
                bundleName: layout.bundleName,
                bundleId: layout.bundleId,
                shortVersion: layout.shortVersion,
                buildVersion: layout.buildVersion,
                executableName: layout.executableName,
                executableRelativePath: layout.executableRelativePath,
                executableModDate: execDateStr,
                plistModDate: plistDateStr,
                architectures: [],
                teamIdentifier: "not set",
                authorities: [],
                signedTimestamp: "-",
                hasHardenedRuntime: false,
                isNotarized: false,
                isQuarantined: false,
                entitlements: [],
                spctlAssessment: nil,
                gatekeeperStatus: "Bundle not found on disk",
                cdHash: "-",
                scanDurationMs: durationMs,
                verdict: .clean,
                findings: [],
                linkedDylibs: [],
                bundledLibraries: [],
                hookCategories: [],
                rawCodesignOutput: "",
                rawOtoolOutput: ""
            )
        }

        // 1. Ana paket kod imzası, mimariler, SHA-256 / SHA-512, yetkiler ve bütünlük denetimi
        var (mainSig, codesignOut) = parseSignature(for: bundlePath, cancellation: cancellation)
        let architectures = parseArchitectures(for: layout.execURL.path, cancellation: cancellation)
        let digests = cancellation?.isCancelled == true ? (sha256: "-", sha512: "-") : executableDigests(for: layout.execURL.path)
        let execSHA256 = digests.sha256
        let execSHA512 = digests.sha512
        let entitlementData = parseEntitlements(for: layout.execURL.path, cancellation: cancellation)
        let entitlements = entitlementData.keys
        let rawEntitlementsOut = entitlementData.rawXML
        let verifyResult = runTool("/usr/bin/codesign", args: ["--verify", "--no-strict", bundlePath], cancellation: cancellation)
        let isNotSignedAtAll = verifyResult.output.contains("code object is not signed at all")
        if isNotSignedAtAll {
            mainSig.isUnsigned = true
        }

        let gatekeeperStatus: String
        if mainSig.isUnsigned {
            gatekeeperStatus = "Unsigned (Local Developer Build)"
        } else if verifyResult.exitCode == 0 {
            gatekeeperStatus = "codesign --verify: OK (Valid on disk)"
        } else {
            gatekeeperStatus = verifyResult.output.components(separatedBy: .newlines).filter { !$0.isEmpty }.joined(separator: " | ")
        }

        var spctlResult: (accepted: Bool, statusText: String)?
        if options.includeGatekeeperAssessment && cancellation?.isCancelled != true {
            spctlResult = assessGatekeeper(at: bundlePath, cancellation: cancellation)
        }

        // 2. Paket içi kütüphaneler (Frameworks / Libraries / MacOS / PlugIns / XPCServices / Helpers / WrappedBundle)
        var context = BundledInspectionContext(
            mainSig: mainSig,
            plistModDate: plistModDate,
            options: options,
            dateFormatter: dateFmt
        )

        for dirURL in layout.scanDirectories {
            if cancellation?.isCancelled == true { break }
            guard let items = try? fm.contentsOfDirectory(
                at: dirURL,
                includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey],
                options: [.skipsHiddenFiles]
            ) else {
                continue
            }
            let dirTag = dirURL.lastPathComponent
            let allowsHelperScan = (dirURL == layout.macosURL || dirTag == "Helpers" || dirTag == "LoginItems")
            for itemURL in items.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
                if cancellation?.isCancelled == true { break }
                let name = itemURL.lastPathComponent
                if dirURL == layout.macosURL && name == layout.executableName {
                    continue
                }

                let lowerName = name.lowercased()
                let isDylib = lowerName.hasSuffix(".dylib")
                let isFramework = lowerName.hasSuffix(".framework")
                let isNestedBundle = lowerName.hasSuffix(".appex") || lowerName.hasSuffix(".xpc")
                    || (allowsHelperScan && lowerName.hasSuffix(".app"))

                let kind: BundledItemKind
                if isDylib {
                    kind = .dylib
                } else if isFramework {
                    kind = .framework
                } else if isNestedBundle {
                    kind = .nestedBundle
                } else if allowsHelperScan && isMachOBinary(at: itemURL) {
                    kind = .helperBinary
                } else {
                    continue
                }

                let displayName = (dirTag == "Frameworks") ? name : "\(dirTag)/\(name)"
                inspectBundledItem(
                    at: itemURL,
                    displayName: displayName,
                    kind: kind,
                    cancellation: cancellation,
                    context: &context
                )

                // Electron/CEF gibi .framework/Libraries/*.dylib iç katmanlarını da denetle.
                if isFramework {
                    let nestedLibsDir = itemURL.appendingPathComponent("Libraries", isDirectory: true)
                    if let nestedItems = try? fm.contentsOfDirectory(
                        at: nestedLibsDir,
                        includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey],
                        options: [.skipsHiddenFiles]
                    ) {
                        for nestedURL in nestedItems.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
                            if cancellation?.isCancelled == true { break }
                            guard nestedURL.lastPathComponent.lowercased().hasSuffix(".dylib") else { continue }
                            inspectBundledItem(
                                at: nestedURL,
                                displayName: "\(displayName)/Libraries/\(nestedURL.lastPathComponent)",
                                kind: .dylib,
                                cancellation: cancellation,
                                context: &context
                            )
                        }
                    }
                }
            }
        }

        // 3. Ana çalıştırılabilir dosya LC_LOAD_DYLIB bağlantıları (otool -L) ve gerçek LC_RPATH yolları
        let hasExec = fm.fileExists(atPath: layout.execURL.path)
        let otoolOut = hasExec && cancellation?.isCancelled != true
            ? runTool("/usr/bin/otool", args: ["-L", layout.execURL.path], cancellation: cancellation).output
            : ""
        let rpathResult = hasExec && cancellation?.isCancelled != true
            ? extractRpaths(for: layout.execURL.path, execDir: layout.execURL.deletingLastPathComponent(), cancellation: cancellation)
            : (urls: [URL](), rawPaths: [String]())
        let rpathURLs = rpathResult.urls
        let rawRpaths = rpathResult.rawPaths

        var rawLoadPaths: [String] = []
        var seenPaths: Set<String> = []

        for line in otoolOut.components(separatedBy: .newlines) {
            if cancellation?.isCancelled == true { break }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("/") || trimmed.hasPrefix("@") else { continue }
            if trimmed.hasSuffix(":") { continue }
            let pathPart = trimmed.components(separatedBy: " (compatibility").first ?? trimmed
            if seenPaths.contains(pathPart) { continue }
            seenPaths.insert(pathPart)
            rawLoadPaths.append(pathPart)

            // Resources vb. alternatif paket içi konumdan yüklenen .dylib varsa denetle.
            if !pathPart.hasPrefix("/System/"),
               !pathPart.hasPrefix("/usr/lib/"),
               let internalDylibURL = resolveBundleInternalDylib(pathPart, bundleURL: url, layout: layout, rpathURLs: rpathURLs) {
                let rootStd = url.standardizedFileURL.path
                let prefix = rootStd.hasSuffix("/") ? rootStd : rootStd + "/"
                let relName = internalDylibURL.path.hasPrefix(prefix)
                    ? String(internalDylibURL.path.dropFirst(prefix.count))
                    : internalDylibURL.lastPathComponent
                inspectBundledItem(
                    at: internalDylibURL,
                    displayName: relName,
                    kind: .dylib,
                    cancellation: cancellation,
                    context: &context
                )
            }
        }

        let linkedDylibs: [LinkedDylibItem] = rawLoadPaths.map { pathPart in
            let isSystem = pathPart.hasPrefix("/System/") || pathPart.hasPrefix("/usr/lib/")
            let loadFileName = URL(fileURLWithPath: pathPart).lastPathComponent
            let isSuspicious = context.suspiciousDylibNames.contains(loadFileName)
            let isExternalSuspicious = externalSuspiciousPrefixes.contains { pathPart.hasPrefix($0) }
            return LinkedDylibItem(
                path: pathPart,
                isSystem: isSystem,
                isSuspicious: isSuspicious || isExternalSuspicious,
                isExternalSuspicious: isExternalSuspicious
            )
        }

        let bundledItems = context.bundledItems
        let hookCategories = context.hookCategories
        let suspiciousDylibNames = context.suspiciousDylibNames
        let originalVendorSignatures = context.originalVendorSignatures

        // 4. 4 Katmanlı Kanıt Tabanlı Karar Motoru (0% Yanlış Pozitif Kalibrasyonu)
        var findings: [ForensicFinding] = []

        // Katman 1: Sahte / Resmi Olmayan İmza Otoritesi (ör. Authority=TEAM EDiSO, TNT vb.)
        if !mainSig.authorities.isEmpty && !mainSig.hasOfficialAppleChain {
            findings.append(ForensicFinding(
                severity: .critical,
                titleKey: .findingUnofficialAuthorityTitle,
                descKey: .findingUnofficialAuthorityDesc,
                detailSuffix: mainSig.authorities.joined(separator: " → ")
            ))
        }

        // Katman 2: İmza Bölünmesi (Signature Stripping / Hijack)
        if !mainSig.hasOfficialAppleChain && !originalVendorSignatures.isEmpty {
            findings.append(ForensicFinding(
                severity: .critical,
                titleKey: .findingSignatureHijackTitle,
                descKey: .findingSignatureHijackDesc,
                detailSuffix: originalVendorSignatures.sorted().joined(separator: ", ")
            ))
        }

        // Katman 3: Bozulmuş Çalıştırılabilir Kod İmzası
        // Not: macOS /System/Library altındaki dyld shared cache çerçevelerinde disk üzerinde ikili dosya bulunmadığından
        // `codesign` çıktısı "bundle format is ambiguous" dönebilir; SSV/SIP korumalı bu sistem çerçevelerinde sahte pozitif üretme.
        let isDyldSharedCacheSystemFramework = !hasExec
            && targetKind == .nestedBundle
            && url.path.hasPrefix("/System/Library/")
            && verifyResult.output.contains("bundle format is ambiguous")

        if !isDyldSharedCacheSystemFramework
            && !mainSig.isUnsigned
            && verifyResult.exitCode != 0
            && !verifyResult.output.isEmpty
            && cancellation?.isCancelled != true {
            findings.append(ForensicFinding(
                severity: .critical,
                titleKey: .findingVerifyFailedTitle,
                descKey: .findingVerifyFailedDesc,
                detailSuffix: verifyResult.output.trimmingCharacters(in: .whitespacesAndNewlines)
            ))
        }

        // Katman 4: Enjekte Hooking / Bellek Yamalama Kütüphanesi
        if !suspiciousDylibNames.isEmpty {
            findings.append(ForensicFinding(
                severity: .critical,
                titleKey: .findingInjectedDylibTitle,
                descKey: .findingInjectedDylibDesc,
                detailSuffix: suspiciousDylibNames.sorted().joined(separator: ", ")
            ))
        }

        if hookCategories.contains(where: { $0.categoryKey == .symbolCatSwizzle }) && !suspiciousDylibNames.isEmpty {
            findings.append(ForensicFinding(
                severity: .critical,
                titleKey: .findingObjcSwizzlingTitle,
                descKey: .findingObjcSwizzlingDesc
            ))
        }

        if hookCategories.contains(where: { $0.categoryKey == .symbolCatMemory }) {
            findings.append(ForensicFinding(
                severity: .critical,
                titleKey: .findingMachPatchingTitle,
                descKey: .findingMachPatchingDesc
            ))
        }

        if hookCategories.contains(where: { $0.categoryKey == .symbolCatDyld }) {
            findings.append(ForensicFinding(
                severity: .critical,
                titleKey: .findingDyldSlideTitle,
                descKey: .findingDyldSlideDesc
            ))
        }

        // Kalibreli Uyarı Sinyalleri (.warning)
        let externalPaths = linkedDylibs.filter(\.isExternalSuspicious).map(\.path)
        if !externalPaths.isEmpty {
            findings.append(ForensicFinding(
                severity: .warning,
                titleKey: .findingExternalDylibTitle,
                descKey: .findingExternalDylibDesc,
                detailSuffix: externalPaths.joined(separator: ", ")
            ))
        }

        if !context.partialHookItems.isEmpty {
            findings.append(ForensicFinding(
                severity: .warning,
                titleKey: .findingPartialHookTitle,
                descKey: .findingPartialHookDesc,
                detailSuffix: context.partialHookItems.sorted().joined(separator: ", ")
            ))
        }

        if !context.unsignedBundledItems.isEmpty {
            findings.append(ForensicFinding(
                severity: .warning,
                titleKey: .findingUnsignedBundledLibTitle,
                descKey: .findingUnsignedBundledLibDesc,
                detailSuffix: context.unsignedBundledItems.sorted().joined(separator: ", ")
            ))
        }

        if let spctlResult, !spctlResult.accepted && (mainSig.hasOfficialAppleChain || !mainSig.authorities.isEmpty) {
            findings.append(ForensicFinding(
                severity: .warning,
                titleKey: .findingSpctlRejectedTitle,
                descKey: .findingSpctlRejectedDesc,
                detailSuffix: spctlResult.statusText
            ))
        }

        let revocationStatus = evaluateRevocationStatus(
            atPath: bundlePath,
            isSigned: !mainSig.isUnsigned && !mainSig.isAdhoc,
            options: options,
            cancellation: cancellation,
            findings: &findings
        )

        var verdict: IntegrityVerdict
        if findings.contains(where: { $0.severity == .critical }) {
            verdict = .tampered
        } else if findings.contains(where: { $0.severity == .warning }) {
            verdict = .warning
        } else if (mainSig.isAdhoc || mainSig.isUnsigned) && mainSig.authorities.isEmpty {
            verdict = .clean
            findings.append(ForensicFinding(
                severity: .info,
                titleKey: .findingAdhocLocalTitle,
                descKey: .findingAdhocLocalDesc
            ))
        } else {
            verdict = .clean
            findings.append(ForensicFinding(
                severity: .info,
                titleKey: .findingCleanTitle,
                descKey: .findingCleanDesc
            ))
        }

        let crossTarget = collectCrossTargetForensics(
            url: url,
            bundleName: layout.bundleName,
            targetKind: targetKind,
            candidateNames: [url.lastPathComponent, layout.bundleName, layout.executableName] + bundledItems.map(\.name),
            options: options,
            cancellation: cancellation,
            findings: &findings,
            verdict: &verdict
        )

        let elapsed = ContinuousClock.now - startTime
        let durationMs = max(1, Int(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000))

        switch verdict {
        case .clean:
            AppLog.shared.info(.scanner, "Verified clean bundle (\(durationMs) ms)", detail: "\(layout.bundleName) (\(layout.bundleId)) — Team: \(mainSig.teamId)")
        case .warning:
            AppLog.shared.warning(.scanner, "Bundle completed with warning (\(durationMs) ms)", detail: "\(layout.bundleName) (\(layout.bundleId))")
        case .tampered:
            AppLog.shared.error(.scanner, "Tampered bundle detected (\(durationMs) ms)", detail: "\(layout.bundleName) (\(layout.bundleId)) — Authority: \(mainSig.authorities.joined(separator: ", ")) — Injected: \(suspiciousDylibNames.sorted().joined(separator: ", "))")
        }

        let resolvedAuthorities: [String]
        if !mainSig.authorities.isEmpty {
            resolvedAuthorities = mainSig.authorities
        } else if mainSig.isAdhoc {
            resolvedAuthorities = ["Ad-Hoc (Local Developer Build)"]
        } else if mainSig.isUnsigned {
            resolvedAuthorities = ["Unsigned (Local Developer Build)"]
        } else {
            resolvedAuthorities = []
        }

        let isQuarantined = hasQuarantineAttribute(at: bundlePath, executablePath: layout.execURL.path)

        return BundleAuditReport(
            targetKind: targetKind,
            bundlePath: bundlePath,
            bundleName: layout.bundleName,
            bundleId: layout.bundleId,
            shortVersion: layout.shortVersion,
            buildVersion: layout.buildVersion,
            executableName: layout.executableName,
            executableRelativePath: layout.executableRelativePath,
            executableModDate: execDateStr,
            plistModDate: plistDateStr,
            architectures: architectures,
            executableSHA256: execSHA256,
            executableSHA512: execSHA512,
            lcRpaths: rawRpaths,
            teamIdentifier: mainSig.teamId,
            authorities: resolvedAuthorities,
            signedTimestamp: mainSig.signedTime,
            hasHardenedRuntime: mainSig.hasHardenedRuntime,
            isNotarized: mainSig.isNotarized,
            isQuarantined: isQuarantined,
            entitlements: entitlements,
            spctlAssessment: spctlResult?.statusText,
            gatekeeperStatus: gatekeeperStatus,
            revocationStatus: revocationStatus,
            cdHash: mainSig.cdHash,
            scanDurationMs: durationMs,
            verdict: verdict,
            findings: findings,
            linkedDylibs: linkedDylibs,
            bundledLibraries: bundledItems,
            hookCategories: hookCategories,
            rawCodesignOutput: codesignOut,
            rawOtoolOutput: otoolOut,
            rawEntitlementsOutput: rawEntitlementsOut,
            deceptiveNames: crossTarget.deceptiveNames,
            firewallAppState: crossTarget.firewallAppState,
            internetAccessPolicy: crossTarget.internetAccessPolicy,
            volumeEncryption: crossTarget.volumeEncryption
        )
    }

    // MARK: - Expanded Targets (.pkg / .mpkg / .dmg / Standalone Mach-O)

    private static func auditInstallerPackage(
        at url: URL,
        options: ScanOptions,
        cancellation: ScanCancellationToken?
    ) -> BundleAuditReport {
        let startTime = ContinuousClock.now
        let path = url.path
        let name = url.lastPathComponent
        let dateFmt = makePosixDateFormatter()
        let modDateStr = modificationDate(for: url).map { dateFmt.string(from: $0) } ?? "-"
        let digests = cancellation?.isCancelled == true ? (sha256: "-", sha512: "-") : executableDigests(for: path)
        let fileSHA = digests.sha256
        let fileSHA512 = digests.sha512
        let isQuarantined = hasQuarantineAttribute(at: path)

        let res = runTool("/usr/sbin/pkgutil", args: ["--check-signature", path], timeoutSeconds: 15, cancellation: cancellation)
        let out = res.output

        var statusLine = "-"
        var authorities: [String] = []
        var teamId = "not set"
        var signedTime = "-"
        var isNotarized = false
        var inCertChain = false

        for line in out.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("Status:") {
                statusLine = String(trimmed.dropFirst("Status:".count)).trimmingCharacters(in: .whitespaces)
            } else if trimmed.hasPrefix("Notarization:") {
                let note = String(trimmed.dropFirst("Notarization:".count)).trimmingCharacters(in: .whitespaces)
                isNotarized = note.localizedCaseInsensitiveContains("trusted")
            } else if trimmed.hasPrefix("Signed with a trusted timestamp on:") {
                signedTime = String(trimmed.dropFirst("Signed with a trusted timestamp on:".count)).trimmingCharacters(in: .whitespaces)
            } else if trimmed.hasPrefix("Certificate Chain:") {
                inCertChain = true
            } else if inCertChain,
                      let dotRange = trimmed.range(of: #"^\d+\.\s+"#, options: .regularExpression) {
                let cert = String(trimmed[dotRange.upperBound...]).trimmingCharacters(in: .whitespaces)
                if !cert.isEmpty {
                    authorities.append(cert)
                    if authorities.count == 1, let extracted = extractTeamIDFromCertificateSubject(cert) {
                        teamId = extracted
                    }
                }
            }
        }

        let isUnsigned = out.localizedCaseInsensitiveContains("no signature")
        let hasValidAppleInstallerChain = authorities.contains {
            $0.contains("Apple Root CA")
                || $0.contains("Developer ID Installer")
                || $0.contains("3rd Party Mac Developer Installer")
                || $0.contains("Apple Software Update")
        }

        var findings: [ForensicFinding] = []
        var verdict: IntegrityVerdict
        let gatekeeperStatus: String

        if isUnsigned {
            verdict = .warning
            gatekeeperStatus = statusLine == "-" ? "no signature" : statusLine
            findings.append(ForensicFinding(
                severity: .warning,
                titleKey: .findingPkgUnsignedTitle,
                descKey: .findingPkgUnsignedDetail
            ))
        } else if res.exitCode == 0 && statusLine.localizedCaseInsensitiveContains("signed by") {
            if !authorities.isEmpty && !hasValidAppleInstallerChain {
                verdict = .tampered
                gatekeeperStatus = statusLine
                findings.append(ForensicFinding(
                    severity: .critical,
                    titleKey: .findingUnofficialAuthorityTitle,
                    descKey: .findingUnofficialAuthorityDesc,
                    detailSuffix: authorities.joined(separator: " → ")
                ))
            } else {
                verdict = .clean
                gatekeeperStatus = statusLine
                findings.append(ForensicFinding(
                    severity: .info,
                    titleKey: .findingPkgSignedTitle,
                    descKey: .findingPkgSignedDetail,
                    detailSuffix: authorities.first ?? statusLine
                ))
            }
        } else {
            verdict = .tampered
            let errDetail = statusLine != "-" ? statusLine : out.trimmingCharacters(in: .whitespacesAndNewlines)
            gatekeeperStatus = errDetail
            findings.append(ForensicFinding(
                severity: .critical,
                titleKey: .findingPkgInvalidTitle,
                descKey: .findingPkgInvalidDetail,
                detailSuffix: errDetail
            ))
        }

        let revocationStatus = evaluateRevocationStatus(
            atPath: path,
            isSigned: !isUnsigned,
            options: options,
            cancellation: cancellation,
            findings: &findings
        )
        if revocationStatus == .revoked {
            verdict = .tampered
        }

        var spctlResult: (accepted: Bool, statusText: String)?
        if options.includeGatekeeperAssessment && !isUnsigned && cancellation?.isCancelled != true {
            spctlResult = assessGatekeeper(at: path, type: "install", cancellation: cancellation)
        }

        let crossTarget = collectCrossTargetForensics(
            url: url,
            bundleName: name,
            targetKind: .installerPackage,
            candidateNames: [name],
            options: options,
            cancellation: cancellation,
            findings: &findings,
            verdict: &verdict
        )

        let resolvedAuths = authorities.isEmpty ? (isUnsigned ? ["Unsigned (.pkg)"] : []) : authorities
        let durationMs = elapsedMillis(since: startTime)

        return BundleAuditReport(
            targetKind: .installerPackage,
            bundlePath: path,
            bundleName: name,
            bundleId: "installer-pkg:\(name)",
            shortVersion: "-",
            buildVersion: "-",
            executableName: name,
            executableRelativePath: name,
            executableModDate: modDateStr,
            plistModDate: modDateStr,
            architectures: [],
            executableSHA256: fileSHA,
            executableSHA512: fileSHA512,
            lcRpaths: [],
            teamIdentifier: teamId,
            authorities: resolvedAuths,
            signedTimestamp: signedTime,
            hasHardenedRuntime: false,
            isNotarized: isNotarized,
            isQuarantined: isQuarantined,
            entitlements: [],
            spctlAssessment: spctlResult?.statusText,
            gatekeeperStatus: gatekeeperStatus,
            revocationStatus: revocationStatus,
            cdHash: "-",
            scanDurationMs: durationMs,
            verdict: verdict,
            findings: findings,
            linkedDylibs: [],
            bundledLibraries: [],
            hookCategories: [],
            rawCodesignOutput: out,
            rawOtoolOutput: "",
            rawEntitlementsOutput: "",
            deceptiveNames: crossTarget.deceptiveNames,
            firewallAppState: crossTarget.firewallAppState,
            internetAccessPolicy: crossTarget.internetAccessPolicy,
            volumeEncryption: crossTarget.volumeEncryption
        )
    }

    private static func auditDiskImage(
        at url: URL,
        options: ScanOptions,
        cancellation: ScanCancellationToken?
    ) -> BundleAuditReport {
        let startTime = ContinuousClock.now
        let path = url.path
        let name = url.lastPathComponent
        let dateFmt = makePosixDateFormatter()
        let modDateStr = modificationDate(for: url).map { dateFmt.string(from: $0) } ?? "-"
        let digests = cancellation?.isCancelled == true ? (sha256: "-", sha512: "-") : executableDigests(for: path)
        let fileSHA = digests.sha256
        let fileSHA512 = digests.sha512
        let isQuarantined = hasQuarantineAttribute(at: path)

        var (sig, codesignOut) = parseSignature(for: path, cancellation: cancellation)
        let verifyResult = runTool("/usr/bin/codesign", args: ["--verify", "--no-strict", path], cancellation: cancellation)
        if verifyResult.output.contains("code object is not signed at all") {
            sig.isUnsigned = true
        }

        var findings: [ForensicFinding] = []
        var verdict: IntegrityVerdict
        let gatekeeperStatus: String

        if sig.isUnsigned {
            verdict = .clean
            gatekeeperStatus = "Unsigned Disk Image (.dmg)"
            findings.append(ForensicFinding(
                severity: .info,
                titleKey: .findingDmgUnsignedTitle,
                descKey: .findingDmgUnsignedDetail
            ))
        } else if !sig.authorities.isEmpty && !sig.hasOfficialAppleChain {
            verdict = .tampered
            gatekeeperStatus = "Unofficial certificate chain"
            findings.append(ForensicFinding(
                severity: .critical,
                titleKey: .findingUnofficialAuthorityTitle,
                descKey: .findingUnofficialAuthorityDesc,
                detailSuffix: sig.authorities.joined(separator: " → ")
            ))
        } else if verifyResult.exitCode != 0 && cancellation?.isCancelled != true {
            verdict = .tampered
            let errText = verifyResult.output.components(separatedBy: .newlines).filter { !$0.isEmpty }.joined(separator: " | ")
            gatekeeperStatus = errText
            findings.append(ForensicFinding(
                severity: .critical,
                titleKey: .findingDmgBrokenTitle,
                descKey: .findingDmgBrokenDetail,
                detailSuffix: errText
            ))
        } else {
            verdict = .clean
            gatekeeperStatus = "codesign --verify: OK (Valid on disk)"
            findings.append(ForensicFinding(
                severity: .info,
                titleKey: .findingDmgSignedTitle,
                descKey: .findingDmgSignedDetail,
                detailSuffix: sig.authorities.first ?? "Ad-Hoc"
            ))
        }

        let revocationStatus = evaluateRevocationStatus(
            atPath: path,
            isSigned: !sig.isUnsigned && !sig.isAdhoc,
            options: options,
            cancellation: cancellation,
            findings: &findings
        )
        if revocationStatus == .revoked {
            verdict = .tampered
        }

        var spctlResult: (accepted: Bool, statusText: String)?
        if options.includeGatekeeperAssessment && !sig.isUnsigned && cancellation?.isCancelled != true {
            spctlResult = assessGatekeeper(at: path, type: "open", cancellation: cancellation)
        }

        let crossTarget = collectCrossTargetForensics(
            url: url,
            bundleName: name,
            targetKind: .diskImage,
            candidateNames: [name],
            options: options,
            cancellation: cancellation,
            findings: &findings,
            verdict: &verdict
        )

        let resolvedAuths: [String]
        if !sig.authorities.isEmpty {
            resolvedAuths = sig.authorities
        } else if sig.isAdhoc {
            resolvedAuths = ["Ad-Hoc"]
        } else {
            resolvedAuths = ["Unsigned (.dmg)"]
        }

        let durationMs = elapsedMillis(since: startTime)
        return BundleAuditReport(
            targetKind: .diskImage,
            bundlePath: path,
            bundleName: name,
            bundleId: sig.identifier != "-" ? sig.identifier : "dmg:\(name)",
            shortVersion: "-",
            buildVersion: "-",
            executableName: name,
            executableRelativePath: name,
            executableModDate: modDateStr,
            plistModDate: modDateStr,
            architectures: [],
            executableSHA256: fileSHA,
            executableSHA512: fileSHA512,
            lcRpaths: [],
            teamIdentifier: sig.teamId,
            authorities: resolvedAuths,
            signedTimestamp: sig.signedTime,
            hasHardenedRuntime: sig.hasHardenedRuntime,
            isNotarized: sig.isNotarized,
            isQuarantined: isQuarantined,
            entitlements: [],
            spctlAssessment: spctlResult?.statusText,
            gatekeeperStatus: gatekeeperStatus,
            revocationStatus: revocationStatus,
            cdHash: sig.cdHash,
            scanDurationMs: durationMs,
            verdict: verdict,
            findings: findings,
            linkedDylibs: [],
            bundledLibraries: [],
            hookCategories: [],
            rawCodesignOutput: codesignOut,
            rawOtoolOutput: "",
            rawEntitlementsOutput: "",
            deceptiveNames: crossTarget.deceptiveNames,
            firewallAppState: crossTarget.firewallAppState,
            internetAccessPolicy: crossTarget.internetAccessPolicy,
            volumeEncryption: crossTarget.volumeEncryption
        )
    }

    private static func auditStandaloneMachO(
        at url: URL,
        options: ScanOptions,
        cancellation: ScanCancellationToken?
    ) -> BundleAuditReport {
        let startTime = ContinuousClock.now
        let path = url.path
        let name = url.lastPathComponent
        let ext = url.pathExtension.lowercased()
        let isDylibExt = supportedBinaryExtensions.contains(ext)
        let dateFmt = makePosixDateFormatter()
        let execDateStr = modificationDate(for: url).map { dateFmt.string(from: $0) } ?? "-"
        let fileSize = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).map { Int64($0) } ?? 0

        var (sig, codesignOut) = parseSignature(for: path, cancellation: cancellation)
        let architectures = parseArchitectures(for: path, cancellation: cancellation)
        let digests = cancellation?.isCancelled == true ? (sha256: "-", sha512: "-") : executableDigests(for: path)
        let execSHA = digests.sha256
        let execSHA512 = digests.sha512
        let entitlementData = parseEntitlements(for: path, cancellation: cancellation)
        let verifyResult = runTool("/usr/bin/codesign", args: ["--verify", "--no-strict", path], cancellation: cancellation)
        if verifyResult.output.contains("code object is not signed at all") {
            sig.isUnsigned = true
        }

        let gatekeeperStatus: String
        if sig.isUnsigned {
            gatekeeperStatus = "Unsigned (Local Developer Build)"
        } else if verifyResult.exitCode == 0 {
            gatekeeperStatus = "codesign --verify: OK (Valid on disk)"
        } else {
            gatekeeperStatus = verifyResult.output.components(separatedBy: .newlines).filter { !$0.isEmpty }.joined(separator: " | ")
        }

        let otoolOut = cancellation?.isCancelled != true
            ? runTool("/usr/bin/otool", args: ["-L", path], cancellation: cancellation).output
            : ""
        let rawRpaths = cancellation?.isCancelled != true
            ? extractRpaths(for: path, execDir: url.deletingLastPathComponent(), cancellation: cancellation).rawPaths
            : []

        var rawLoadPaths: [String] = []
        var seenPaths: Set<String> = []
        for line in otoolOut.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("/") || trimmed.hasPrefix("@") else { continue }
            if trimmed.hasSuffix(":") { continue }
            let pathPart = trimmed.components(separatedBy: " (compatibility").first ?? trimmed
            if !seenPaths.contains(pathPart) {
                seenPaths.insert(pathPart)
                rawLoadPaths.append(pathPart)
            }
        }

        let linkedDylibs: [LinkedDylibItem] = rawLoadPaths.map { pathPart in
            let isSystem = pathPart.hasPrefix("/System/") || pathPart.hasPrefix("/usr/lib/")
            let isExternalSuspicious = externalSuspiciousPrefixes.contains { pathPart.hasPrefix($0) }
            return LinkedDylibItem(
                path: pathPart,
                isSystem: isSystem,
                isSuspicious: isExternalSuspicious,
                isExternalSuspicious: isExternalSuspicious
            )
        }

        var hookCategories: [HookSymbolCategory] = []
        var bundledItems: [BundledLibraryItem] = []
        var isInjectedMachO = false

        if !sig.hasOfficialAppleChain && cancellation?.isCancelled != true {
            let analysis = analyzeMachOHooks(
                binaryPath: path,
                libraryName: name,
                isDylib: isDylibExt,
                parentHasOfficialChain: false,
                extractTargetStrings: options.extractTargetStrings,
                cancellation: cancellation
            )
            isInjectedMachO = analysis.isInjectedCrack
            hookCategories = analysis.categories
            if isInjectedMachO {
                let allSuspicious = analysis.swizzle + analysis.memory + analysis.dyld
                let sigBadge = sig.authorities.first ?? (sig.isUnsigned ? "unsigned" : "adhoc")
                bundledItems.append(
                    BundledLibraryItem(
                        name: name,
                        modifiedDate: "\(execDateStr) [\(sigBadge)]",
                        sizeBytes: fileSize,
                        isTimestampAnomaly: false,
                        suspiciousSymbols: allSuspicious,
                        targetStrings: analysis.targetStrings
                    )
                )
            }
        }

        var findings: [ForensicFinding] = []
        if !sig.authorities.isEmpty && !sig.hasOfficialAppleChain {
            findings.append(ForensicFinding(
                severity: .critical,
                titleKey: .findingUnofficialAuthorityTitle,
                descKey: .findingUnofficialAuthorityDesc,
                detailSuffix: sig.authorities.joined(separator: " → ")
            ))
        }
        if !sig.isUnsigned && verifyResult.exitCode != 0 && !verifyResult.output.isEmpty && cancellation?.isCancelled != true {
            findings.append(ForensicFinding(
                severity: .critical,
                titleKey: .findingVerifyFailedTitle,
                descKey: .findingVerifyFailedDesc,
                detailSuffix: verifyResult.output.trimmingCharacters(in: .whitespacesAndNewlines)
            ))
        }
        if isInjectedMachO {
            findings.append(ForensicFinding(
                severity: .critical,
                titleKey: .findingInjectedDylibTitle,
                descKey: .findingInjectedDylibDesc,
                detailSuffix: name
            ))
        }
        if hookCategories.contains(where: { $0.categoryKey == .symbolCatMemory }) {
            findings.append(ForensicFinding(severity: .critical, titleKey: .findingMachPatchingTitle, descKey: .findingMachPatchingDesc))
        }
        if hookCategories.contains(where: { $0.categoryKey == .symbolCatDyld }) {
            findings.append(ForensicFinding(severity: .critical, titleKey: .findingDyldSlideTitle, descKey: .findingDyldSlideDesc))
        }

        let externalPaths = linkedDylibs.filter(\.isExternalSuspicious).map(\.path)
        if !externalPaths.isEmpty {
            findings.append(ForensicFinding(
                severity: .warning,
                titleKey: .findingExternalDylibTitle,
                descKey: .findingExternalDylibDesc,
                detailSuffix: externalPaths.joined(separator: ", ")
            ))
        }

        var spctlResult: (accepted: Bool, statusText: String)?
        if options.includeGatekeeperAssessment && cancellation?.isCancelled != true {
            spctlResult = assessGatekeeper(at: path, cancellation: cancellation)
            if let spctlResult, !spctlResult.accepted && (sig.hasOfficialAppleChain || !sig.authorities.isEmpty) {
                findings.append(ForensicFinding(
                    severity: .warning,
                    titleKey: .findingSpctlRejectedTitle,
                    descKey: .findingSpctlRejectedDesc,
                    detailSuffix: spctlResult.statusText
                ))
            }
        }

        let revocationStatus = evaluateRevocationStatus(
            atPath: path,
            isSigned: !sig.isUnsigned && !sig.isAdhoc,
            options: options,
            cancellation: cancellation,
            findings: &findings
        )

        var verdict: IntegrityVerdict
        if findings.contains(where: { $0.severity == .critical }) {
            verdict = .tampered
        } else if findings.contains(where: { $0.severity == .warning }) {
            verdict = .warning
        } else if (sig.isAdhoc || sig.isUnsigned) && sig.authorities.isEmpty {
            verdict = .clean
            findings.append(ForensicFinding(
                severity: .info,
                titleKey: .findingAdhocLocalTitle,
                descKey: .findingMachOExecutableOnlyDetail
            ))
        } else {
            verdict = .clean
            findings.append(ForensicFinding(
                severity: .info,
                titleKey: .findingCleanTitle,
                descKey: .findingMachOExecutableOnlyDetail
            ))
        }

        let crossTarget = collectCrossTargetForensics(
            url: url,
            bundleName: name,
            targetKind: .standaloneMachO,
            candidateNames: [name],
            options: options,
            cancellation: cancellation,
            findings: &findings,
            verdict: &verdict
        )

        let resolvedAuths: [String]
        if !sig.authorities.isEmpty {
            resolvedAuths = sig.authorities
        } else if sig.isAdhoc {
            resolvedAuths = ["Ad-Hoc (Local Developer Build)"]
        } else if sig.isUnsigned {
            resolvedAuths = ["Unsigned (Local Developer Build)"]
        } else {
            resolvedAuths = []
        }

        let isQuarantined = hasQuarantineAttribute(at: path)
        let durationMs = elapsedMillis(since: startTime)

        return BundleAuditReport(
            targetKind: .standaloneMachO,
            bundlePath: path,
            bundleName: name,
            bundleId: sig.identifier != "-" ? sig.identifier : name,
            shortVersion: "-",
            buildVersion: "-",
            executableName: name,
            executableRelativePath: name,
            executableModDate: execDateStr,
            plistModDate: execDateStr,
            architectures: architectures,
            executableSHA256: execSHA,
            executableSHA512: execSHA512,
            lcRpaths: rawRpaths,
            teamIdentifier: sig.teamId,
            authorities: resolvedAuths,
            signedTimestamp: sig.signedTime,
            hasHardenedRuntime: sig.hasHardenedRuntime,
            isNotarized: sig.isNotarized,
            isQuarantined: isQuarantined,
            entitlements: entitlementData.keys,
            spctlAssessment: spctlResult?.statusText,
            gatekeeperStatus: gatekeeperStatus,
            revocationStatus: revocationStatus,
            cdHash: sig.cdHash,
            scanDurationMs: durationMs,
            verdict: verdict,
            findings: findings,
            linkedDylibs: linkedDylibs,
            bundledLibraries: bundledItems,
            hookCategories: hookCategories,
            rawCodesignOutput: codesignOut,
            rawOtoolOutput: otoolOut,
            rawEntitlementsOutput: entitlementData.rawXML,
            deceptiveNames: crossTarget.deceptiveNames,
            firewallAppState: crossTarget.firewallAppState,
            internetAccessPolicy: crossTarget.internetAccessPolicy,
            volumeEncryption: crossTarget.volumeEncryption
        )
    }

    private static func unsupportedTargetReport(at url: URL) -> BundleAuditReport {
        let name = url.lastPathComponent
        let digests = executableDigests(for: url.path)
        let deceptiveNames = OpenSafety.collectDeceptiveNames(in: [name])
        var findings = [
            ForensicFinding(
                severity: .warning,
                titleKey: .findingUnsupportedTargetTitle,
                descKey: .findingUnsupportedTargetDetail,
                detailSuffix: name
            )
        ]
        if !deceptiveNames.isEmpty {
            findings.append(ForensicFinding(
                severity: .warning,
                titleKey: .findingNameSpoofingTitle,
                descKey: .findingNameSpoofingDesc,
                detailSuffix: deceptiveNames.joined(separator: ", ")
            ))
        }
        return BundleAuditReport(
            targetKind: .standaloneMachO,
            bundlePath: url.path,
            bundleName: name,
            bundleId: "-",
            shortVersion: "-",
            buildVersion: "-",
            executableName: name,
            executableRelativePath: name,
            executableModDate: "-",
            plistModDate: "-",
            architectures: [],
            executableSHA256: digests.sha256,
            executableSHA512: digests.sha512,
            lcRpaths: [],
            teamIdentifier: "not set",
            authorities: [],
            signedTimestamp: "-",
            hasHardenedRuntime: false,
            isNotarized: false,
            isQuarantined: hasQuarantineAttribute(at: url.path),
            entitlements: [],
            spctlAssessment: nil,
            gatekeeperStatus: "Unsupported target format",
            cdHash: "-",
            scanDurationMs: 1,
            verdict: .warning,
            findings: findings,
            linkedDylibs: [],
            bundledLibraries: [],
            hookCategories: [],
            rawCodesignOutput: "",
            rawOtoolOutput: "",
            rawEntitlementsOutput: "",
            deceptiveNames: deceptiveNames,
            volumeEncryption: VolumeEncryptionInfo.read(for: url)
        )
    }

    private static func evaluateRevocationStatus(
        atPath path: String,
        isSigned: Bool,
        options: ScanOptions,
        cancellation: ScanCancellationToken?,
        findings: inout [ForensicFinding]
    ) -> RevocationStatus? {
        guard options.checkCertificateRevocation,
              isSigned,
              cancellation?.isCancelled != true else {
            return nil
        }
        let status = RevocationChecker.checkValidity(atPath: path)
        if status == .revoked {
            findings.append(ForensicFinding(
                severity: .critical,
                titleKey: .findingRevokedCertificateTitle,
                descKey: .findingRevokedCertificateDesc
            ))
        }
        return status
    }

    private static func extractTeamIDFromCertificateSubject(_ subject: String) -> String? {
        guard let open = subject.lastIndex(of: "("),
              let close = subject.lastIndex(of: ")"),
              open < close else {
            return nil
        }
        let candidate = String(subject[subject.index(after: open)..<close])
        guard candidate.count == 10, candidate.allSatisfy({ $0.isASCII && ($0.isUppercase || $0.isNumber) }) else {
            return nil
        }
        return candidate
    }

    private static func elapsedMillis(since start: ContinuousClock.Instant) -> Int {
        let elapsed = ContinuousClock.now - start
        return max(1, Int(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000))
    }

    /// Belirtilen klasördeki tüm `.app` paketlerini sınırlı eşzamanlılıkla (sıralı çıktı korunarak) denetler.
    public static func auditDirectory(
        at directoryURL: URL,
        options: ScanOptions = ScanOptions(),
        cancellation: ScanCancellationToken? = nil,
        maxConcurrentScans: Int = 4,
        onProgress: (@Sendable (_ index: Int, _ total: Int, _ currentName: String) -> Void)? = nil
    ) -> BatchAuditSummary {
        final class BatchAccumulator: @unchecked Sendable {
            private let lock = NSLock()
            private var started = 0
            private var slots: [BundleAuditReport?]

            init(count: Int) {
                self.slots = [BundleAuditReport?](repeating: nil, count: count)
            }

            func nextIndex() -> Int {
                lock.withLock {
                    started += 1
                    return started
                }
            }

            func store(_ report: BundleAuditReport, at index: Int) {
                lock.withLock {
                    slots[index] = report
                }
            }

            var finalizedReports: [BundleAuditReport] {
                lock.withLock { slots.compactMap { $0 } }
            }
        }

        let fm = FileManager.default
        let entries = (try? fm.contentsOfDirectory(
            at: directoryURL,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )) ?? []
        let appBundles = entries
            .filter { $0.pathExtension.lowercased() == "app" }
            .sorted { $0.lastPathComponent.localizedCaseInsensitiveCompare($1.lastPathComponent) == .orderedAscending }

        let total = appBundles.count
        guard total > 0 else {
            return BatchAuditSummary(
                directoryPath: directoryURL.path,
                scannedAt: makePosixDateFormatter().string(from: Date()),
                reports: [],
                wasCancelled: cancellation?.isCancelled == true
            )
        }

        let workerLimit = max(1, min(maxConcurrentScans, total))
        let semaphore = DispatchSemaphore(value: workerLimit)
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "com.babadogantech.verificator.batch", attributes: .concurrent)
        let accumulator = BatchAccumulator(count: total)

        for (idx, appURL) in appBundles.enumerated() {
            if cancellation?.isCancelled == true { break }
            semaphore.wait()
            if cancellation?.isCancelled == true {
                semaphore.signal()
                break
            }
            group.enter()
            queue.async {
                defer {
                    semaphore.signal()
                    group.leave()
                }
                if cancellation?.isCancelled == true { return }
                let progressIndex = accumulator.nextIndex()
                onProgress?(progressIndex, total, appURL.lastPathComponent)
                let report = auditBundle(at: appURL, options: options, cancellation: cancellation)
                if cancellation?.isCancelled == true { return }
                accumulator.store(report, at: idx)
            }
        }

        group.wait()
        return BatchAuditSummary(
            directoryPath: directoryURL.path,
            scannedAt: makePosixDateFormatter().string(from: Date()),
            reports: accumulator.finalizedReports,
            wasCancelled: cancellation?.isCancelled == true
        )
    }

    /// Pakette veya ana çalıştırılabilir dosyada etkin (kullanıcı tarafından henüz onaylanmamış)
    /// `com.apple.quarantine` özniteliği var mı?
    public static func hasQuarantineAttribute(at path: String, executablePath: String? = nil) -> Bool {
        if hasActiveQuarantine(atPath: path) {
            return true
        }
        if let executablePath, hasActiveQuarantine(atPath: executablePath) {
            return true
        }
        return false
    }

    /// Ham `com.apple.quarantine` xattr değerinin (`<bayrak>;<zaman>;<uygulama>;<uuid>`)
    /// hâlâ etkin bir karantina durumu belirtip belirtmediğini doğrular.
    public static func isActiveQuarantineAttributeValue(_ rawValue: String) -> Bool {
        let trimmed = rawValue.trimmingCharacters(
            in: CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "\0"))
        )
        guard !trimmed.isEmpty else { return false }
        let fields = trimmed.split(separator: ";", omittingEmptySubsequences: false)
        guard fields.count == 2 || fields.count >= 4 else { return false }
        let flagsField = fields[0]
        let timestampField = fields[1]
        guard !flagsField.isEmpty,
              !timestampField.isEmpty,
              !flagsField.hasPrefix("0x"),
              !flagsField.hasPrefix("0X"),
              let flags = UInt32(flagsField, radix: 16),
              UInt64(timestampField, radix: 16) != nil else {
            return false
        }
        // 0x0040 = QTN_FLAG_USER_APPROVED, 0x4000 / 0x8000 = LaunchServices inert/cleared flags
        let clearedFlagsMask: UInt32 = 0xC040
        return (flags & clearedFlagsMask) == 0
    }

    private static func hasActiveQuarantine(atPath targetPath: String) -> Bool {
        let fm = FileManager.default
        guard fm.fileExists(atPath: targetPath) else { return false }
        let rawURL = URL(fileURLWithPath: targetPath)
        let resolvedURL = rawURL.resolvingSymlinksInPath()
        if hasActiveQuarantine(at: rawURL) {
            return true
        }
        if resolvedURL.path != rawURL.path, hasActiveQuarantine(at: resolvedURL) {
            return true
        }
        return false
    }

    private static func hasActiveQuarantine(at url: URL) -> Bool {
        var freshURL = URL(fileURLWithPath: url.path)
        freshURL.removeAllCachedResourceValues()
        do {
            let values = try freshURL.resourceValues(forKeys: [.quarantinePropertiesKey])
            return values.quarantineProperties != nil
        } catch {
            if let raw = readQuarantineXattr(atPath: url.path) {
                return isActiveQuarantineAttributeValue(raw)
            }
            return false
        }
    }

    private static func readQuarantineXattr(atPath path: String) -> String? {
        let attrName = "com.apple.quarantine"
        let size = getxattr(path, attrName, nil, 0, 0, XATTR_NOFOLLOW)
        guard size > 0 else { return nil }
        var buffer = [UInt8](repeating: 0, count: size)
        let bytesRead = getxattr(path, attrName, &buffer, size, 0, XATTR_NOFOLLOW)
        guard bytesRead > 0 else { return nil }
        return String(decoding: buffer.prefix(bytesRead), as: UTF8.self)
    }

    /// `sudo xattr -rd com.apple.quarantine <bundlePath>` komutunu macOS yönetici yetkisiyle (Touch ID / Parola) çalıştırır.
    public static func removeQuarantineWithAdminPrivileges(at bundlePath: String) -> QuarantineRemovalResult {
        let script = """
        on run argv
            do shell script "/usr/bin/xattr -rd com.apple.quarantine " & quoted form of item 1 of argv with administrator privileges
        end run
        """
        let res = runTool("/usr/bin/osascript", args: ["-e", script, bundlePath], timeoutSeconds: 120)
        if res.exitCode == 0 {
            AppLog.shared.info(.signature, "Removed com.apple.quarantine via administrator privileges for \(bundlePath)")
            return QuarantineRemovalResult(status: .success)
        }
        let trimmed = res.output.trimmingCharacters(in: .whitespacesAndNewlines)
        let isUserCancelled = trimmed.contains("(-128)") || trimmed.localizedCaseInsensitiveContains("User canceled")
        if isUserCancelled {
            AppLog.shared.info(.signature, "Quarantine removal cancelled by user for \(bundlePath)")
            return QuarantineRemovalResult(status: .cancelled, message: trimmed)
        }
        AppLog.shared.warning(.signature, "Quarantine removal failed for \(bundlePath)", detail: trimmed)
        return QuarantineRemovalResult(status: .failed, message: trimmed)
    }

    internal static func modificationDate(for url: URL) -> Date? {
        try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate
    }

    internal static func runTool(
        _ launchPath: String,
        args: [String],
        timeoutSeconds: TimeInterval = 20,
        maxOutputBytes: Int = 8 * 1024 * 1024,
        cancellation: ScanCancellationToken? = nil
    ) -> (output: String, exitCode: Int32) {
        if cancellation?.isCancelled == true {
            return ("Cancelled", -2)
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = args
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
        } catch {
            return ("Error executing \(launchPath): \(error.localizedDescription)", -1)
        }

        let toolPID = process.processIdentifier
        let toolName = URL(fileURLWithPath: launchPath).lastPathComponent
        ChildProcessGuard.register(toolPID, name: toolName)
        defer { ChildProcessGuard.unregister(toolPID) }

        guard cancellation?.attach(process) ?? true else {
            if process.isRunning { process.terminate() }
            return ("Cancelled", -2)
        }
        defer { cancellation?.detach(process) }

        let stateLock = NSLock()
        var timedOut = false
        let timeoutItem = DispatchWorkItem {
            stateLock.withLock { timedOut = true }
            if process.isRunning {
                process.terminate()
            }
        }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeoutSeconds, execute: timeoutItem)

        let reader = pipe.fileHandleForReading
        var buffer = Data()
        while true {
            let chunk: Data
            do {
                guard let read = try reader.read(upToCount: 65536), !read.isEmpty else {
                    break
                }
                chunk = read
            } catch {
                break
            }

            let remaining = maxOutputBytes - buffer.count
            if remaining > 0 {
                buffer.append(chunk.prefix(remaining))
            }
            if buffer.count >= maxOutputBytes {
                if process.isRunning { process.terminate() }
                break
            }
        }

        process.waitUntilExit()
        timeoutItem.cancel()

        let wasTimedOut = stateLock.withLock { timedOut }
        let text = String(decoding: buffer, as: UTF8.self)
        if wasTimedOut {
            return (text.isEmpty ? "Process timed out after \(Int(timeoutSeconds))s" : text, -3)
        }
        return (text, process.terminationStatus)
    }
}
