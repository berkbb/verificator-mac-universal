// SPDX-License-Identifier: GPL-3.0-only
import CoreServices
import Foundation

/// Uygulamayı Launch Services veritabanına (`LSRegisterURL`) sürüm/derleme başına bir kez kaydeder (`Copiator`/`Paravan` deseni).
public enum LaunchServicesRegistration {
    private static let defaultsKey = "lastRegisteredBundleBuild"

    /// Verilen paket daha önce bu sürüm/derleme için kaydedilmediyse `LSRegisterURL(..., true)` çalıştırır.
    @discardableResult
    public static func registerIfBuildChanged(
        bundle: Bundle = .main,
        defaults: UserDefaults = .standard,
        registrar: (URL) -> OSStatus = { LSRegisterURL($0 as CFURL, true) }
    ) -> Bool {
        let bundleURL = bundle.bundleURL
        guard bundleURL.pathExtension.lowercased() == "app" else { return false }

        let shortVersion = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
        let build = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? ""
        let stamp = "\(shortVersion) (\(build)):\(bundleURL.standardizedFileURL.path)"
        guard defaults.string(forKey: defaultsKey) != stamp else { return false }

        let status = registrar(bundleURL)
        guard status == noErr else { return false }
        defaults.set(stamp, forKey: defaultsKey)
        return true
    }
}
