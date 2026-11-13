// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import Darwin
import Foundation
import Security

/// Sistem Gatekeeper değerlendirme durumu (`spctl --status`, salt-okunur).
public enum GatekeeperStatus: String, Sendable, Equatable, Codable, CaseIterable {
    case enabled
    case disabled
    case unknown

    public static let spctlPath = "/usr/sbin/spctl"
    public static let defaultTimeout: TimeInterval = 3

    /// `/usr/sbin/spctl --status` çıktısını ayrıştırır; yalnızca kesin satırları kabul eder.
    public static func parse(_ output: String) -> GatekeeperStatus {
        let lines = output
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
        let isEnabled = lines.contains("assessments enabled")
        let isDisabled = lines.contains("assessments disabled")
        switch (isEnabled, isDisabled) {
        case (true, false): return .enabled
        case (false, true): return .disabled
        default: return .unknown
        }
    }

    /// Gatekeeper sistem durumunu okur (yönetici izni istemez; hata/zaman aşımı `.unknown` döner).
    public static func read(executablePath: String = spctlPath, timeout: TimeInterval = defaultTimeout) -> GatekeeperStatus {
        guard FileManager.default.isExecutableFile(atPath: executablePath) else { return .unknown }
        let res = ForensicScanner.runTool(executablePath, args: ["--status"], timeoutSeconds: timeout)
        return parse(res.output)
    }

    public var labelKey: LKey {
        switch self {
        case .enabled: return .gatekeeperGlobalEnabled
        case .disabled: return .gatekeeperGlobalDisabled
        case .unknown: return .gatekeeperGlobalUnknown
        }
    }
}

/// macOS Tam Disk Erişimi (TCC Full Disk Access) salt-okunur durum denetimi.
public enum FullDiskAccess: Sendable {
    public static var isGranted: Bool {
        isGranted(homeDirectoryURL: FileManager.default.homeDirectoryForCurrentUser)
    }

    /// Yalnızca Tam Disk Erişimi verildiğinde okunabilen standart kullanıcı TCC yollarını yoklar.
    public static func isGranted(homeDirectoryURL: URL) -> Bool {
        let home = homeDirectoryURL.path
        let probePaths = [
            home + "/Library/Application Support/com.apple.TCC/TCC.db",
            home + "/Library/Safari/Bookmarks.plist",
            home + "/Library/Suggestions",
        ]
        let fm = FileManager.default
        return probePaths.contains { fm.isReadableFile(atPath: $0) }
    }

    @MainActor
    public static func openSystemSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }
}

/// Seçime bağlı OCSP sertifika / notarization iptal (revocation) denetimi (`Security.framework`).
public enum RevocationStatus: String, Sendable, Equatable, Codable {
    case valid
    case revoked
    case unchecked

    public var labelKey: LKey {
        switch self {
        case .valid: return .revocationStatusOk
        case .revoked: return .revocationStatusRevoked
        case .unchecked: return .valueNotChecked
        }
    }
}

public enum RevocationChecker: Sendable {
    private static let enforceRevocationChecks = SecCSFlags(rawValue: 1 << 30)
    private static let basicValidateOnly = SecCSFlags(rawValue: (1 << 1) | (1 << 2))

    /// İsteğe bağlı: Apple OCSP üzerinden imzalayan sertifikanın veya notarization biletinin iptal edilip edilmediğini denetler.
    public static func checkValidity(atPath path: String) -> RevocationStatus {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode else {
            return .unchecked
        }
        let status = SecStaticCodeCheckValidity(staticCode, [enforceRevocationChecks, basicValidateOnly], nil)
        if isRevocationStatus(status) {
            return .revoked
        }
        if status == errSecSuccess {
            return .valid
        }
        return .unchecked
    }

    public static func isRevocationStatus(_ status: OSStatus) -> Bool {
        status == errSecCSRevokedNotarization || status == OSStatus(CSSMERR_TP_CERT_REVOKED)
    }
}

/// Çalışan süreç için canlı üst süreç, dinamik `SecCode` geçerliliği ve belleğe eşlenmiş Mach-O kütüphane denetimi.
public struct LiveProcessVerification: Sendable, Equatable {
    public let hasDynamicSignatureMismatch: Bool
    public let unsignedMappedLibraries: [String]

    public init(hasDynamicSignatureMismatch: Bool = false, unsignedMappedLibraries: [String] = []) {
        self.hasDynamicSignatureMismatch = hasDynamicSignatureMismatch
        self.unsignedMappedLibraries = unsignedMappedLibraries
    }
}

public enum LiveProcessInspector {
    private static let basicValidateOnly = SecCSFlags(rawValue: (1 << 1) | (1 << 2))

    /// Çalışan sürecin üst sürecini (`PROC_PIDTBSDINFO` + `proc_pidpath`) döndürür.
    public static func parentProcess(of pid: pid_t) -> (pid: Int32, name: String, path: String)? {
        guard pid > 0 else { return nil }
        var bsd = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, size) == size else { return nil }
        let ppid = pid_t(bsd.pbi_ppid)
        guard ppid > 0 else { return nil }

        var pathBuffer = [CChar](repeating: 0, count: 4096)
        let len = proc_pidpath(ppid, &pathBuffer, UInt32(pathBuffer.count))
        guard len > 0 else { return nil }
        let path = pathBuffer.withUnsafeBufferPointer { ptr in
            String(decoding: UnsafeRawBufferPointer(start: ptr.baseAddress, count: Int(len)), as: UTF8.self)
        }
        guard !path.isEmpty else { return nil }

        let name: String
        if let appPath = SystemAudit.enclosingAppBundlePath(forExecutablePath: path),
           let bundle = Bundle(url: URL(fileURLWithPath: appPath)) {
            name = (bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
                ?? (bundle.object(forInfoDictionaryKey: "CFBundleName") as? String)
                ?? URL(fileURLWithPath: path).lastPathComponent
        } else {
            name = URL(fileURLWithPath: path).lastPathComponent
        }
        return (Int32(ppid), name, path)
    }

    /// Çalışan sürecin bellek alanına eşlediği dosya yollarını okur (`proc_pidinfo(PROC_PIDREGIONPATHINFO)`).
    public static func mappedPaths(pid: pid_t, limit: Int = 2048) -> [String] {
        guard pid > 0 else { return [] }
        var address: UInt64 = 0
        var seen: Set<String> = []
        var paths: [String] = []
        var regionInfo = proc_regionwithpathinfo()
        let size = Int32(MemoryLayout<proc_regionwithpathinfo>.stride)

        for _ in 0..<limit {
            let read = proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, address, &regionInfo, size)
            guard read == size else { break }
            let path = withUnsafeBytes(of: regionInfo.prp_vip.vip_path) { raw in
                String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
            }
            if !path.isEmpty, seen.insert(path).inserted {
                paths.append(path)
            }
            let next = regionInfo.prp_prinfo.pri_address + regionInfo.prp_prinfo.pri_size
            guard next > address else { break }
            address = next
        }
        return paths
    }

    /// Yalnızca sistem dışı dinamik kütüphane veya framework ikilisi adaylarını seçer (veri/kaynak dosyalarını hariç tutar).
    public static func isCandidateMappedLibrary(_ path: String, executablePath: String) -> Bool {
        guard path != executablePath,
              !path.hasPrefix("/System/"),
              !path.hasPrefix("/usr/lib/"),
              !path.hasPrefix("/Library/Apple/"),
              !path.hasPrefix("/private/var/db/dyld/") else {
            return false
        }
        let lower = path.lowercased()
        let isBinaryPath = lower.hasSuffix(".dylib")
            || lower.hasSuffix(".so")
            || (!lower.contains("/resources/") && (lower.contains(".framework/") || lower.contains(".bundle/")))
        guard isBinaryPath else { return false }
        return ForensicScanner.isMachOBinary(at: URL(fileURLWithPath: path))
    }

    /// Çalışan bir sürecin dinamik bellek imzasını ve belleğe eşlenmiş imzasız/geçersiz Mach-O kütüphanelerini denetler.
    public static func verifyLiveProcess(
        pid: pid_t,
        executablePath: String,
        parentHasOfficialChain: Bool,
        isParentAdhoc: Bool,
        mappedLimit: Int = 5
    ) -> LiveProcessVerification {
        guard pid > 0 else { return LiveProcessVerification() }

        // 1) Dinamik SecCode vs Statik SecStaticCode karşılaştırması
        var dynamicMismatch = false
        let attributes: [CFString: Any] = [kSecGuestAttributePid: pid]
        var guestCode: SecCode?
        if SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &guestCode) == errSecSuccess,
           let guestCode {
            var staticCode: SecStaticCode?
            let gotStatic = SecCodeCopyStaticCode(guestCode, [], &staticCode) == errSecSuccess ? staticCode : nil
            if let gotStatic {
                let dynamicStatus = SecCodeCheckValidity(guestCode, [], nil)
                let staticStatus = SecStaticCodeCheckValidity(gotStatic, [basicValidateOnly], nil)
                if staticStatus == errSecSuccess && dynamicStatus != errSecSuccess {
                    // Bazı ad-hoc / yerel derlemeler hariç, çalışan imza açıkça geçersizleştiyse bildir
                    let invalidationCodes: Set<OSStatus> = [
                        errSecCSUnsigned,
                        errSecCSSignatureFailed,
                        errSecCSStaticCodeChanged,
                        errSecCSSignatureNotVerifiable,
                        errSecCSBadResource,
                    ]
                    if invalidationCodes.contains(dynamicStatus) && !isParentAdhoc {
                        dynamicMismatch = true
                    }
                }
            }
        }

        // 2) Belleğe eşlenmiş kütüphanelerde geçersiz / imzasız Mach-O denetimi
        //    (Ad-hoc ana ikiliye sahip yerel geliştirici araçlarında gürültü üretmemek için imzasızlığı yalnızca geçersiz imzalarda veya resmi zincirli süreçlerde raporlar)
        var unsignedLibs: [String] = []
        for path in mappedPaths(pid: pid) where isCandidateMappedLibrary(path, executablePath: executablePath) {
            if !hasValidMappedSignature(atPath: path, allowAdhoc: !parentHasOfficialChain) {
                unsignedLibs.append(path)
                if unsignedLibs.count >= mappedLimit { break }
            }
        }

        return LiveProcessVerification(
            hasDynamicSignatureMismatch: dynamicMismatch,
            unsignedMappedLibraries: unsignedLibs
        )
    }

    static func hasValidMappedSignature(atPath path: String, allowAdhoc: Bool) -> Bool {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode else {
            return false
        }
        let status = SecStaticCodeCheckValidity(staticCode, [basicValidateOnly], nil)
        guard status == errSecSuccess else {
            return false
        }
        if allowAdhoc {
            return true
        }
        // Resmi Apple zinciri taşıyan bir süreçte, belleğe imzasız/yalnızca ad-hoc eklenmiş dış dylib olmamalı
        var infoCF: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &infoCF) == errSecSuccess,
              let info = infoCF as? [String: Any] else {
            return true
        }
        let certs = info[kSecCodeInfoCertificates as String] as? [SecCertificate] ?? []
        let team = info[kSecCodeInfoTeamIdentifier as String] as? String
        if certs.isEmpty && (team == nil || team?.isEmpty == true) {
            return false
        }
        return true
    }
}
