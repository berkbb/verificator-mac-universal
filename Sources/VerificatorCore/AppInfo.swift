// SPDX-License-Identifier: GPL-3.0-only
import Foundation

public enum AppInfo {
    public static var version: String {
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "1.1.0"
    }

    public static var build: String {
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String) ?? "2"
    }

    public static var repository: String {
        (Bundle.main.object(forInfoDictionaryKey: "VerificatorRepository") as? String) ?? "berkbb/verificator-mac-universal"
    }

    public static var currentYear: String {
        String(Calendar.current.component(.year, from: Date()))
    }
}

public enum AppLinks {
    public static let website = URL(string: "https://github.com/berkbb")!
    public static let repository = URL(string: "https://github.com/berkbb/verificator-mac-universal")!
}
