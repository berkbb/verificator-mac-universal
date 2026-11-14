// SPDX-License-Identifier: GPL-3.0-only
import Foundation

public enum AppInfo {
    public static let fallbackVersion = "1.3.0"
    public static let fallbackBuild = "10"
    public static let fallbackRepository = "berkbb/verificator-mac-universal"

    private static let resolvedPlist: [String: String]? = {
        let fm = FileManager.default
        var candidates: [URL] = []

        if let arg0 = CommandLine.arguments.first, !arg0.isEmpty {
            let execURL = URL(fileURLWithPath: arg0).resolvingSymlinksInPath()
            let macOSDir = execURL.deletingLastPathComponent()
            let contentsDir = macOSDir.deletingLastPathComponent()
            candidates.append(contentsDir.appendingPathComponent("Info.plist"))
            candidates.append(macOSDir.appendingPathComponent("Support/Info.plist"))

            var ancestor = macOSDir
            for _ in 0..<6 {
                candidates.append(ancestor.appendingPathComponent("Support/Info.plist"))
                let next = ancestor.deletingLastPathComponent()
                if next.path == ancestor.path { break }
                ancestor = next
            }
        }

        var cwd = URL(fileURLWithPath: fm.currentDirectoryPath, isDirectory: true)
        for _ in 0..<6 {
            candidates.append(cwd.appendingPathComponent("Support/Info.plist"))
            let next = cwd.deletingLastPathComponent()
            if next.path == cwd.path { break }
            cwd = next
        }

        for url in candidates where fm.fileExists(atPath: url.path) {
            if let data = try? Data(contentsOf: url),
               let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
               plist["CFBundleShortVersionString"] != nil {
                var strings: [String: String] = [:]
                for (key, value) in plist {
                    if let str = value as? String {
                        strings[key] = str
                    }
                }
                return strings
            }
        }
        return nil
    }()

    public static var version: String {
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String)
            ?? resolvedPlist?["CFBundleShortVersionString"]
            ?? fallbackVersion
    }

    public static var build: String {
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String)
            ?? resolvedPlist?["CFBundleVersion"]
            ?? fallbackBuild
    }

    public static var repository: String {
        (Bundle.main.object(forInfoDictionaryKey: "VerificatorRepository") as? String)
            ?? resolvedPlist?["VerificatorRepository"]
            ?? fallbackRepository
    }

    public static var currentYear: String {
        String(Calendar.current.component(.year, from: Date()))
    }
}

public enum AppLinks {
    public static let website = URL(string: "https://github.com/berkbb")!
    public static let repository = URL(string: "https://github.com/berkbb/verificator-mac-universal")!
}
