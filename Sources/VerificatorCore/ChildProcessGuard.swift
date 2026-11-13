// SPDX-License-Identifier: GPL-3.0-only
import Darwin
import Foundation

/// Alt süreç bekçisi: çalışan dış adli araç süreçlerinin (`codesign`, `otool`, `nm`, `strings`, `spctl`, `lipo`, `pkgutil`)
/// PID bilgilerini sinyal-güvenli (signal-safe) sabit boyutlu bir tabloda izler; normal kapanışta, ölümcül sinyallerde veya
/// önceki çökmeden kalan yetim süreçlerde yalnızca aynı başlatma zamanı ve komut adına sahip çocuk süreçleri temizler.
internal final class ChildProcessTracker: @unchecked Sendable {
    static let capacity = 64
    private static let nameLimit = 63

    struct Slot {
        var pid: pid_t = 0
        var startSec: Int = 0
        var startUsec: Int32 = 0
        var name: (
            CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
            CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
            CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
            CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
            CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
            CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
            CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
            CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar
        ) = (
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        )
    }

    let pidFileURL: URL
    let slots: UnsafeMutablePointer<Slot>
    private var lock = os_unfair_lock()

    init(pidFileURL: URL) {
        self.pidFileURL = pidFileURL
        self.slots = UnsafeMutablePointer<Slot>.allocate(capacity: Self.capacity)
        self.slots.initialize(repeating: Slot(), count: Self.capacity)
    }

    deinit {
        slots.deinitialize(count: Self.capacity)
        slots.deallocate()
    }

    func register(_ pid: pid_t, name: String) {
        guard pid > 0 else { return }
        let start = Self.processStartTime(pid)
        os_unfair_lock_lock(&lock)
        for index in 0..<Self.capacity where slots[index].pid == 0 || slots[index].pid == pid {
            slots[index].pid = pid
            slots[index].startSec = start?.sec ?? 0
            slots[index].startUsec = start?.usec ?? 0
            Self.writeName(name, into: &slots[index])
            break
        }
        os_unfair_lock_unlock(&lock)
        persistPIDFile()
    }

    func unregister(_ pid: pid_t) {
        guard pid > 0 else { return }
        os_unfair_lock_lock(&lock)
        for index in 0..<Self.capacity where slots[index].pid == pid {
            slots[index] = Slot()
        }
        os_unfair_lock_unlock(&lock)
        persistPIDFile()
    }

    func terminateAll(graceMicroseconds: useconds_t = 250_000) {
        os_unfair_lock_lock(&lock)
        var snapshot: [(pid: pid_t, sec: Int, usec: Int32, name: String)] = []
        for index in 0..<Self.capacity where slots[index].pid > 0 {
            snapshot.append((slots[index].pid, slots[index].startSec, slots[index].startUsec, Self.readName(from: &slots[index])))
            slots[index] = Slot()
        }
        os_unfair_lock_unlock(&lock)

        var alive: [(pid: pid_t, sec: Int, usec: Int32, name: String)] = []
        for item in snapshot where Self.isSameProcess(pid: item.pid, sec: item.sec, usec: item.usec, name: item.name) {
            kill(item.pid, SIGTERM)
            alive.append(item)
        }
        if !alive.isEmpty && graceMicroseconds > 0 {
            usleep(graceMicroseconds)
            for item in alive where Self.isSameProcess(pid: item.pid, sec: item.sec, usec: item.usec, name: item.name) {
                kill(item.pid, SIGKILL)
            }
        }
        persistPIDFile()
    }

    func killAllFromSignalHandler() {
        for index in 0..<Self.capacity {
            let pid = slots[index].pid
            if pid > 0 {
                kill(pid, SIGKILL)
                slots[index].pid = 0
            }
        }
    }

    func reapOrphansFromPreviousRun() {
        guard let content = try? String(contentsOf: pidFileURL, encoding: .utf8) else { return }
        try? FileManager.default.removeItem(at: pidFileURL)
        for line in content.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: "\t")
            guard parts.count >= 4,
                  let pid = pid_t(parts[0]),
                  let sec = Int(parts[1]),
                  let usec = Int32(parts[2]) else { continue }
            let name = String(parts[3])
            if Self.isSameProcess(pid: pid, sec: sec, usec: usec, name: name) {
                kill(pid, SIGTERM)
                usleep(100_000)
                if Self.isSameProcess(pid: pid, sec: sec, usec: usec, name: name) {
                    kill(pid, SIGKILL)
                }
            }
        }
    }

    private func persistPIDFile() {
        os_unfair_lock_lock(&lock)
        var lines: [String] = []
        for index in 0..<Self.capacity where slots[index].pid > 0 {
            let name = Self.readName(from: &slots[index])
            lines.append("\(slots[index].pid)\t\(slots[index].startSec)\t\(slots[index].startUsec)\t\(name)")
        }
        os_unfair_lock_unlock(&lock)

        if lines.isEmpty {
            try? FileManager.default.removeItem(at: pidFileURL)
            return
        }
        try? FileManager.default.createDirectory(at: pidFileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let text = lines.joined(separator: "\n") + "\n"
        try? text.write(to: pidFileURL, atomically: true, encoding: .utf8)
    }

    private static func writeName(_ name: String, into slot: inout Slot) {
        let utf8 = Array(name.utf8.prefix(nameLimit))
        withUnsafeMutableBytes(of: &slot.name) { buffer in
            for idx in 0..<buffer.count { buffer[idx] = 0 }
            for (idx, byte) in utf8.enumerated() {
                buffer[idx] = byte
            }
        }
    }

    private static func readName(from slot: inout Slot) -> String {
        withUnsafePointer(to: &slot.name) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: nameLimit + 1) {
                String(cString: $0)
            }
        }
    }

    static func processStartTime(_ pid: pid_t) -> (sec: Int, usec: Int32)? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { return nil }
        let tv = info.kp_proc.p_un.__p_starttime
        return (tv.tv_sec, tv.tv_usec)
    }

    static func processCommandName(_ pid: pid_t) -> String? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { return nil }
        return withUnsafePointer(to: &info.kp_proc.p_comm) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN) + 1) {
                String(cString: $0)
            }
        }
    }

    static func isSameProcess(pid: pid_t, sec: Int, usec: Int32, name: String) -> Bool {
        guard pid > 0, let current = processStartTime(pid) else { return false }
        if sec > 0 && (current.sec != sec || current.usec != usec) { return false }
        if !name.isEmpty, let comm = processCommandName(pid) {
            let prefix = String(name.prefix(Int(MAXCOMLEN)))
            if !comm.hasPrefix(prefix) && !prefix.hasPrefix(comm) {
                return false
            }
        }
        return true
    }
}

public enum ChildProcessGuard {
    static let capacity = ChildProcessTracker.capacity

    private static var isRunningUnderXCTest: Bool {
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
            || ProcessInfo.processInfo.processName.contains("xctest")
    }

    public static var pidFileURL: URL {
        if isRunningUnderXCTest {
            return FileManager.default.temporaryDirectory
                .appendingPathComponent("verificator-tests-children-\(ProcessInfo.processInfo.processIdentifier).pids")
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Verificator/children.pids")
    }

    private static let sharedTracker = ChildProcessTracker(pidFileURL: pidFileURL)

    private static let installOnce: Void = {
        sharedTracker.reapOrphansFromPreviousRun()
        atexit { ChildProcessGuard.terminateAll(graceMicroseconds: 200_000) }
        let fatalSignals: [Int32] = [SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP]
        for sig in fatalSignals {
            var action = sigaction()
            action.__sigaction_u.__sa_handler = { received in
                ChildProcessGuard.killAllFromSignalHandler()
                signal(received, SIG_DFL)
                raise(received)
            }
            sigemptyset(&action.sa_mask)
            action.sa_flags = SA_RESETHAND
            sigaction(sig, &action, nil)
        }
    }()

    public static func install() {
        _ = installOnce
    }

    public static func register(_ pid: pid_t, name: String) {
        _ = installOnce
        sharedTracker.register(pid, name: name)
    }

    public static func unregister(_ pid: pid_t) {
        sharedTracker.unregister(pid)
    }

    public static func terminateAll(graceMicroseconds: useconds_t = 250_000) {
        sharedTracker.terminateAll(graceMicroseconds: graceMicroseconds)
    }

    static func killAllFromSignalHandler() {
        sharedTracker.killAllFromSignalHandler()
    }
}
