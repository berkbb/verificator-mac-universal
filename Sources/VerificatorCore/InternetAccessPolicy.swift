// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// Read-only parser for an application bundle's developer-declared `InternetAccessPolicy.plist`
/// and `<lang>.lproj/InternetAccessPolicy.strings` (including nested `Frameworks`, `SharedFrameworks`,
/// `PlugIns`, and `XPCServices`). Nothing is ever fetched over the network.
public struct InternetAccessPolicy: Sendable, Equatable, Codable {
    public struct Connection: Identifiable, Sendable, Equatable, Codable {
        public let id: String
        public let hosts: [String]
        public let isIncoming: Bool
        public let networkProtocol: String?
        public let portSpec: String?
        public let isEssential: Bool
        public let purpose: String
        public let denyConsequences: String?

        public init(
            hosts: [String],
            isIncoming: Bool = false,
            networkProtocol: String? = nil,
            portSpec: String? = nil,
            isEssential: Bool = false,
            purpose: String,
            denyConsequences: String? = nil
        ) {
            self.hosts = hosts
            self.isIncoming = isIncoming
            self.networkProtocol = networkProtocol
            self.portSpec = portSpec
            self.isEssential = isEssential
            self.purpose = purpose
            self.denyConsequences = denyConsequences
            self.id = "\(isIncoming ? "in" : "out")|\(hosts.joined(separator: ","))|\(networkProtocol ?? "*")|\(portSpec ?? "*")|\(purpose)"
        }
    }

    public struct Service: Identifiable, Sendable, Equatable, Codable {
        public let id: String
        public let identifier: String?
        public let name: String
        public let purpose: String

        public init(identifier: String? = nil, name: String, purpose: String) {
            self.identifier = identifier
            self.name = name
            self.purpose = purpose
            self.id = "\(identifier ?? "")|\(name)|\(purpose)"
        }
    }

    public let developerName: String?
    public let applicationDescription: String
    public let website: String?
    public let connections: [Connection]
    public let services: [Service]

    public init(
        developerName: String?,
        applicationDescription: String,
        website: String?,
        connections: [Connection],
        services: [Service]
    ) {
        self.developerName = developerName
        self.applicationDescription = applicationDescription
        self.website = website
        self.connections = connections
        self.services = services
    }

    public static let fileName = "InternetAccessPolicy"

    /// Parses an `InternetAccessPolicy` property list dictionary with optional localized string resolution
    /// and `%APPNAME%` substitution.
    public static func parse(
        _ dictionary: [String: Any],
        strings: [String: String] = [:],
        appName: String = ""
    ) -> InternetAccessPolicy? {
        func resolveText(_ value: Any?) -> String? {
            guard let raw = value as? String, !raw.isEmpty else { return nil }
            let translated = strings[raw] ?? raw
            let expanded = translated
                .replacingOccurrences(of: "%APPNAME%", with: appName)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return expanded.isEmpty ? nil : expanded
        }

        guard let description = resolveText(dictionary["ApplicationDescription"]) else { return nil }

        let connections = (dictionary["Connections"] as? [[String: Any]] ?? []).compactMap { entry -> Connection? in
            guard let hostRaw = entry["Host"] as? String,
                  let purpose = resolveText(entry["Purpose"]) else {
                return nil
            }
            let hosts = hostRaw
                .split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            guard !hosts.isEmpty else { return nil }

            let proto = (entry["NetworkProtocol"] as? String)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .uppercased()
            let portText = (entry["Port"] as? String) ?? (entry["Port"] as? NSNumber)?.stringValue

            return Connection(
                hosts: hosts,
                isIncoming: (entry["IsIncoming"] as? Bool) ?? false,
                networkProtocol: (proto?.isEmpty == false) ? proto : nil,
                portSpec: portText?.trimmingCharacters(in: .whitespacesAndNewlines),
                isEssential: (entry["Relevance"] as? String)?.lowercased() == "essential",
                purpose: purpose,
                denyConsequences: resolveText(entry["DenyConsequences"])
            )
        }

        let services = (dictionary["Services"] as? [[String: Any]] ?? []).compactMap { entry -> Service? in
            guard let name = resolveText(entry["Name"]),
                  let purpose = resolveText(entry["Purpose"]) else {
                return nil
            }
            return Service(
                identifier: (entry["Identifier"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
                name: name,
                purpose: purpose
            )
        }

        let website: String? = (dictionary["Website"] as? String)
            .flatMap(URL.init(string:))
            .flatMap { url in
                guard let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
                    return nil
                }
                return url.absoluteString
            }

        return InternetAccessPolicy(
            developerName: resolveText(dictionary["DeveloperName"]),
            applicationDescription: description,
            website: website,
            connections: connections,
            services: services
        )
    }

    /// Loads `Contents/Resources/InternetAccessPolicy.plist` and merges any nested policies under
    /// `Frameworks`, `SharedFrameworks`, `PlugIns`, and `XPCServices`.
    public static func load(
        bundle url: URL,
        languages: [String] = ["en"],
        appName: String? = nil
    ) -> InternetAccessPolicy? {
        let name = appName ?? url.deletingPathExtension().lastPathComponent
        let resources = url.appendingPathComponent("Contents/Resources", isDirectory: true)
        let rootResources = FileManager.default.fileExists(atPath: resources.appendingPathComponent("\(fileName).plist").path)
            ? resources
            : url.appendingPathComponent("Resources", isDirectory: true)
        let plist = rootResources.appendingPathComponent("\(fileName).plist")

        guard let data = try? Data(contentsOf: plist),
              let dictionary = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any],
              let base = parse(dictionary, strings: localizedStrings(in: rootResources, languages: languages), appName: name) else {
            return nil
        }

        var mergedConnections = base.connections
        var mergedServices = base.services

        for nestedResources in nestedResourceFolders(in: url) {
            guard let nestedData = try? Data(contentsOf: nestedResources.appendingPathComponent("\(fileName).plist")),
                  let nestedDict = (try? PropertyListSerialization.propertyList(from: nestedData, format: nil)) as? [String: Any],
                  let inner = parse(nestedDict, strings: localizedStrings(in: nestedResources, languages: languages), appName: name) else {
                continue
            }
            mergedConnections += inner.connections
            mergedServices += inner.services
        }

        return InternetAccessPolicy(
            developerName: base.developerName,
            applicationDescription: base.applicationDescription,
            website: base.website,
            connections: mergedConnections,
            services: mergedServices
        )
    }

    /// Reads embedded `InternetAccessPolicy` metadata from standalone signed/Info.plist binaries when available.
    public static func load(executable url: URL, languages: [String] = ["en"]) -> InternetAccessPolicy? {
        guard let info = CFBundleCopyInfoDictionaryForURL(url as CFURL) as? [String: Any],
              let dictionary = info[fileName] as? [String: Any] else {
            return nil
        }
        let localizations = dictionary["Localizations"] as? [String: [String: String]] ?? [:]
        let resolvedStrings = (languages + ["en", "Base"]).compactMap { localizations[$0] }.first ?? [:]
        return parse(dictionary, strings: resolvedStrings, appName: url.lastPathComponent)
    }

    static func localizedStrings(in resources: URL, languages: [String]) -> [String: String] {
        for language in languages + ["en", "Base"] {
            let url = resources.appendingPathComponent("\(language).lproj/\(fileName).strings")
            if let table = NSDictionary(contentsOf: url) as? [String: String] {
                return table
            }
            if let table = StringTable.parseStringsFile(at: url), !table.isEmpty {
                return table
            }
        }
        return [:]
    }

    static func nestedResourceFolders(in bundle: URL, depth: Int = 0) -> [URL] {
        guard depth < 4 else { return [] }
        var found: [URL] = []
        let contents = FileManager.default.fileExists(atPath: bundle.appendingPathComponent("Contents").path)
            ? bundle.appendingPathComponent("Contents")
            : bundle
        let bundleExtensions: Set<String> = ["xpc", "framework", "appex", "bundle", "plugin", "app"]
        for folder in ["Frameworks", "SharedFrameworks", "PlugIns", "XPCServices"] {
            let directory = contents.appendingPathComponent(folder, isDirectory: true)
            let items = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
            for item in items where bundleExtensions.contains(item.pathExtension.lowercased()) {
                for candidate in [item.appendingPathComponent("Contents/Resources"), item.appendingPathComponent("Resources")] {
                    if FileManager.default.fileExists(atPath: candidate.appendingPathComponent("\(fileName).plist").path) {
                        found.append(candidate)
                        break
                    }
                }
                found += nestedResourceFolders(in: item, depth: depth + 1)
            }
        }
        return found
    }
}
