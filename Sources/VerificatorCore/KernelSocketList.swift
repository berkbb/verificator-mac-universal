// SPDX-License-Identifier: GPL-3.0-only
import Darwin
import Foundation

public enum KernelIPProtocol: String, Sendable, Equatable, Hashable, Codable {
    case tcp = "TCP"
    case udp = "UDP"
}

/// Process-correlated TCP/UDP socket snapshot suitable for persistence in process audit reports and JSON/CLI output.
public struct ProcessSocketInfo: Identifiable, Sendable, Equatable, Hashable, Codable {
    public let id: UUID
    public let ipProtocol: KernelIPProtocol
    public let localAddress: String
    public let localPort: UInt16
    public let remoteAddress: String?
    public let remotePort: UInt16
    public let state: String?

    public var isListening: Bool { state == "LISTEN" }
    public var isConnected: Bool { remoteAddress != nil }

    public var localEndpoint: String {
        "\(localAddress):\(localPort)"
    }

    public var remoteEndpoint: String? {
        guard let remoteAddress else { return nil }
        return "\(remoteAddress):\(remotePort)"
    }

    public var endpointSummary: String {
        if let remoteEndpoint {
            let statePart = state.map { " (\($0))" } ?? ""
            return "\(ipProtocol.rawValue) \(localEndpoint) -> \(remoteEndpoint)\(statePart)"
        }
        let statePart = state.map { " (\($0))" } ?? ""
        return "\(ipProtocol.rawValue) \(localEndpoint)\(statePart)"
    }

    public init(
        id: UUID = UUID(),
        ipProtocol: KernelIPProtocol,
        localAddress: String,
        localPort: UInt16,
        remoteAddress: String? = nil,
        remotePort: UInt16 = 0,
        state: String? = nil
    ) {
        self.id = id
        self.ipProtocol = ipProtocol
        self.localAddress = localAddress
        self.localPort = localPort
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.state = state
    }

    private enum CodingKeys: String, CodingKey {
        case id, ipProtocol, localAddress, localPort, remoteAddress, remotePort, state
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        self.ipProtocol = try container.decode(KernelIPProtocol.self, forKey: .ipProtocol)
        self.localAddress = try container.decode(String.self, forKey: .localAddress)
        self.localPort = try container.decode(UInt16.self, forKey: .localPort)
        self.remoteAddress = try container.decodeIfPresent(String.self, forKey: .remoteAddress)
        self.remotePort = try container.decodeIfPresent(UInt16.self, forKey: .remotePort) ?? 0
        self.state = try container.decodeIfPresent(String.self, forKey: .state)
    }

    public func redacted(using masker: DiagnosticMasker) -> ProcessSocketInfo {
        ProcessSocketInfo(
            id: id,
            ipProtocol: ipProtocol,
            localAddress: localAddress,
            localPort: localPort,
            remoteAddress: remoteAddress.map { masker.redact(text: $0) },
            remotePort: remotePort,
            state: state
        )
    }
}

/// Read-only XNU kernel socket table reader via `net.inet.tcp.pcblist_n` and `net.inet.udp.pcblist_n` sysctls.
/// Eliminates subprocess spawns (`lsof`/`netstat`) and safely degrades to `nil` under sandbox restrictions
/// or if kernel struct layout changes. Record field offsets follow XNU `#pragma pack(4)` layout verified on macOS 27.
public enum KernelSocketList {
    static let kindSocket: UInt32 = 0x001
    static let kindReceiveBuffer: UInt32 = 0x002
    static let kindSendBuffer: UInt32 = 0x004
    static let kindStats: UInt32 = 0x008
    static let kindInpcb: UInt32 = 0x010
    static let kindTcpcb: UInt32 = 0x020

    enum Layout {
        // xsocket_n (#pragma pack(4)): uid 64, last_pid 68, e_pid 72
        static let socketMinimumLength = 76
        static let socketUID = 64
        static let socketLastPID = 68
        static let socketEffectivePID = 72
        // xinpcb_n (#pragma pack(4)): fport 16, lport 18, vflag 44, faddr 48 (16B), laddr 64 (16B)
        static let inpcbMinimumLength = 80
        static let inpcbForeignPort = 16
        static let inpcbLocalPort = 18
        static let inpcbVersionFlag = 44
        static let inpcbForeignAddress = 48
        static let inpcbLocalAddress = 64
        static let tcpcbMinimumLength = 40
        static let tcpcbState = 36
        static let statsMinimumLength = 8 + 4 * 32
        static let statsClasses = 4
        static let versionFlagIPv4: UInt8 = 0x1
    }

    static func roundedUp(_ length: Int) -> Int { (length + 7) & ~7 }

    public static let tcpStateNames = [
        "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED",
        "CLOSE_WAIT", "FIN_WAIT_1", "CLOSING", "LAST_ACK", "FIN_WAIT_2", "TIME_WAIT",
    ]

    public struct Counters: Hashable, Sendable {
        public var rxBytes: UInt64
        public var txBytes: UInt64
        public var rxPackets: UInt64
        public var txPackets: UInt64

        public init(rxBytes: UInt64 = 0, txBytes: UInt64 = 0, rxPackets: UInt64 = 0, txPackets: UInt64 = 0) {
            self.rxBytes = rxBytes
            self.txBytes = txBytes
            self.rxPackets = rxPackets
            self.txPackets = txPackets
        }
    }

    public struct Socket: Hashable, Sendable {
        public var pid: Int32
        public var uid: UInt32
        public var ipProtocol: KernelIPProtocol
        public var localAddress: String
        public var localPort: UInt16
        public var remoteAddress: String?
        public var remotePort: UInt16
        public var tcpState: Int32?
        public var counters: Counters?

        public var stateName: String? {
            tcpState.flatMap { $0 >= 0 && Int($0) < tcpStateNames.count ? tcpStateNames[Int($0)] : nil }
        }

        public var isConnected: Bool { remoteAddress != nil }
    }

    public struct Snapshot: Sendable {
        public var sockets: [Socket]
        public var hasCounters: Bool { sockets.contains { $0.counters != nil } }

        public init(sockets: [Socket]) {
            self.sockets = sockets
        }
    }

    /// Reads both TCP and UDP kernel socket tables; returns `nil` when sysctl is blocked or layout mismatches.
    public static func read() -> Snapshot? {
        guard let tcp = readList("net.inet.tcp.pcblist_n"),
              let udp = readList("net.inet.udp.pcblist_n"),
              let tcpSockets = parse(tcp, tcp: true),
              let udpSockets = parse(udp, tcp: false) else {
            return nil
        }
        return Snapshot(sockets: tcpSockets + udpSockets)
    }

    /// Reads the live socket snapshot grouped by owning PID for direct correlation in `RunningProcesses`.
    /// Prefers XNU `pcblist_n` sysctls when permitted (e.g., privileged/entitled execution) and automatically
    /// falls back to Darwin `libproc` (`PROC_PIDLISTFDS` / `PROC_PIDFDSOCKETINFO`) per PID on macOS 26+ where
    /// unprivileged processes receive empty `pcblist_n` tables.
    public static func socketsByPID(forPids pids: [Int32]? = nil) -> [Int32: [ProcessSocketInfo]] {
        var seenPerPID: [Int32: Set<String>] = [:]
        var grouped: [Int32: [ProcessSocketInfo]] = [:]

        func appendSocket(_ info: ProcessSocketInfo, pid: Int32) {
            let dedupKey = "\(info.ipProtocol.rawValue)|\(info.localAddress)|\(info.localPort)|\(info.remoteAddress ?? "")|\(info.remotePort)|\(info.state ?? "")"
            if seenPerPID[pid, default: []].insert(dedupKey).inserted {
                grouped[pid, default: []].append(info)
            }
        }

        if let snapshot = read(), !snapshot.sockets.isEmpty {
            for sock in snapshot.sockets where sock.pid > 0 {
                let info = ProcessSocketInfo(
                    ipProtocol: sock.ipProtocol,
                    localAddress: sock.localAddress,
                    localPort: sock.localPort,
                    remoteAddress: sock.remoteAddress,
                    remotePort: sock.remotePort,
                    state: sock.stateName
                )
                appendSocket(info, pid: sock.pid)
            }
        } else {
            let targetPids = pids ?? allProcessIDs()
            for pid in targetPids where pid > 0 {
                for info in socketsViaLibproc(for: pid) {
                    appendSocket(info, pid: pid)
                }
            }
        }

        for pid in grouped.keys {
            grouped[pid]?.sort { lhs, rhs in
                if lhs.isListening != rhs.isListening { return lhs.isListening }
                if lhs.localPort != rhs.localPort { return lhs.localPort < rhs.localPort }
                return lhs.endpointSummary < rhs.endpointSummary
            }
        }
        return grouped
    }

    /// Collects live TCP/UDP sockets for a single PID using `proc_pidinfo(PROC_PIDLISTFDS)` and `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`.
    public static func socketsViaLibproc(for pid: Int32) -> [ProcessSocketInfo] {
        guard pid > 0 else { return [] }
        let estimatedBytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard estimatedBytes > 0 else { return [] }
        let stride = MemoryLayout<proc_fdinfo>.stride
        let countGuess = Int(estimatedBytes) / stride + 16
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: countGuess)
        let actualBytes = fds.withUnsafeMutableBytes { buf in
            proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buf.baseAddress, Int32(buf.count))
        }
        guard actualBytes > 0 else { return [] }
        let fdCount = min(fds.count, Int(actualBytes) / stride)

        var results: [ProcessSocketInfo] = []
        var sinfo = socket_fdinfo()
        let sinfoSize = Int32(MemoryLayout<socket_fdinfo>.stride)

        for idx in 0..<fdCount {
            let fd = fds[idx]
            guard fd.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) else { continue }
            let readSize = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &sinfo, sinfoSize)
            guard readSize == sinfoSize else { continue }
            let family = sinfo.psi.soi_family
            guard family == AF_INET || family == AF_INET6 else { continue }

            let kind = sinfo.psi.soi_kind
            if kind == Int32(SOCKINFO_TCP) {
                let tcp = sinfo.psi.soi_proto.pri_tcp
                let ini = tcp.tcpsi_ini
                let stateIndex = Int(tcp.tcpsi_state)
                let stateName = (stateIndex >= 0 && stateIndex < tcpStateNames.count) ? tcpStateNames[stateIndex] : nil
                if let info = makeSocketInfo(from: ini, ipProtocol: .tcp, state: stateName) {
                    results.append(info)
                }
            } else if kind == Int32(SOCKINFO_IN), sinfo.psi.soi_protocol == IPPROTO_UDP {
                let ini = sinfo.psi.soi_proto.pri_in
                if let info = makeSocketInfo(from: ini, ipProtocol: .udp, state: nil) {
                    results.append(info)
                }
            }
        }
        return results
    }

    private static func makeSocketInfo(
        from ini: in_sockinfo,
        ipProtocol: KernelIPProtocol,
        state: String?
    ) -> ProcessSocketInfo? {
        let localPort = UInt16(bigEndian: UInt16(truncatingIfNeeded: ini.insi_lport))
        let remotePort = UInt16(bigEndian: UInt16(truncatingIfNeeded: ini.insi_fport))
        guard localPort > 0 || remotePort > 0 else { return nil }

        let isIPv4 = (ini.insi_vflag & UInt8(INI_IPV4)) != 0
        let localAddr: String = isIPv4
            ? (formatIPv4Address(ini.insi_laddr.ina_46.i46a_addr4) ?? "*")
            : (formatIPv6Address(ini.insi_laddr.ina_6) ?? "*")
        let remoteAddr: String? = remotePort == 0
            ? nil
            : (isIPv4 ? formatIPv4Address(ini.insi_faddr.ina_46.i46a_addr4) : formatIPv6Address(ini.insi_faddr.ina_6))

        return ProcessSocketInfo(
            ipProtocol: ipProtocol,
            localAddress: localAddr,
            localPort: localPort,
            remoteAddress: remoteAddr,
            remotePort: remotePort,
            state: state
        )
    }

    private static func formatIPv4Address(_ v4: in_addr) -> String? {
        var copy = v4
        guard copy.s_addr != 0 else { return nil }
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &copy, &buf, socklen_t(INET_ADDRSTRLEN)) != nil else { return nil }
        return String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    private static func formatIPv6Address(_ v6: in6_addr) -> String? {
        var copy = v6
        let hasNonZero = withUnsafeBytes(of: copy) { raw in
            raw.contains(where: { $0 != 0 })
        }
        guard hasNonZero else { return nil }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &copy, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil else { return nil }
        return String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    private static func allProcessIDs() -> [Int32] {
        let estimated = proc_listallpids(nil, 0)
        guard estimated > 0 else { return [] }
        let capacity = Int(estimated) + 32
        var pids = [pid_t](repeating: 0, count: capacity)
        let actual = pids.withUnsafeMutableBytes { buf in
            proc_listallpids(buf.baseAddress, Int32(buf.count))
        }
        guard actual > 0 else { return [] }
        return Array(pids.prefix(min(capacity, Int(actual)))).filter { $0 > 0 }
    }

    static func readList(_ name: String) -> Data? {
        var length = 0
        guard sysctlbyname(name, nil, &length, nil, 0) == 0, length > 0 else { return nil }
        length += 64 << 10
        var buffer = Data(count: length)
        let result = buffer.withUnsafeMutableBytes { raw -> Int32 in
            sysctlbyname(name, raw.baseAddress, &length, nil, 0)
        }
        guard result == 0 else { return nil }
        return buffer.prefix(length)
    }

    public static func parse(_ data: Data, tcp: Bool) -> [Socket]? {
        data.withUnsafeBytes { raw -> [Socket]? in
            guard raw.count >= 8 else { return [] }
            func u8(_ offset: Int) -> UInt8 { raw.loadUnaligned(fromByteOffset: offset, as: UInt8.self) }
            func u16(_ offset: Int) -> UInt16 { raw.loadUnaligned(fromByteOffset: offset, as: UInt16.self) }
            func u32(_ offset: Int) -> UInt32 { raw.loadUnaligned(fromByteOffset: offset, as: UInt32.self) }
            func u64(_ offset: Int) -> UInt64 { raw.loadUnaligned(fromByteOffset: offset, as: UInt64.self) }

            var sockets: [Socket] = []
            struct Pending {
                var hasInpcb = false
                var hasSocket = false
                var pid: Int32 = 0
                var uid: UInt32 = 0
                var localAddress = "*"
                var localPort: UInt16 = 0
                var remoteAddress: String?
                var remotePort: UInt16 = 0
                var tcpState: Int32?
                var counters: Counters?
            }

            var pending: Pending?
            func flush() {
                guard let entry = pending, entry.hasInpcb, entry.hasSocket else {
                    pending = nil
                    return
                }
                sockets.append(Socket(
                    pid: entry.pid,
                    uid: entry.uid,
                    ipProtocol: tcp ? .tcp : .udp,
                    localAddress: entry.localAddress,
                    localPort: entry.localPort,
                    remoteAddress: entry.remoteAddress,
                    remotePort: entry.remotePort,
                    tcpState: entry.tcpState,
                    counters: entry.counters
                ))
                pending = nil
            }

            let generationLength = Int(u32(0))
            guard generationLength >= 8, generationLength <= raw.count else { return nil }
            var offset = generationLength
            while offset + 8 <= raw.count {
                let length = Int(u32(offset))
                let kind = u32(offset + 4)
                guard length >= 8, offset + length <= raw.count else { break }

                switch kind {
                case kindInpcb:
                    guard length >= Layout.inpcbMinimumLength else { return nil }
                    if pending?.hasInpcb == true { flush() }
                    var entry = pending ?? Pending()
                    entry.hasInpcb = true
                    entry.remotePort = UInt16(bigEndian: u16(offset + Layout.inpcbForeignPort))
                    entry.localPort = UInt16(bigEndian: u16(offset + Layout.inpcbLocalPort))
                    let isIPv4 = (u8(offset + Layout.inpcbVersionFlag) & Layout.versionFlagIPv4) != 0
                    let foreign = address(raw, at: offset + Layout.inpcbForeignAddress, ipv4: isIPv4)
                    let local = address(raw, at: offset + Layout.inpcbLocalAddress, ipv4: isIPv4)
                    entry.localAddress = local ?? "*"
                    entry.remoteAddress = entry.remotePort == 0 ? nil : foreign
                    pending = entry
                case kindTcpcb:
                    guard length >= Layout.tcpcbMinimumLength else { return nil }
                    var entry = pending ?? Pending()
                    entry.tcpState = Int32(bitPattern: u32(offset + Layout.tcpcbState))
                    pending = entry
                case kindSocket:
                    guard length >= Layout.socketMinimumLength else { return nil }
                    if pending?.hasSocket == true { flush() }
                    var entry = pending ?? Pending()
                    entry.hasSocket = true
                    entry.uid = u32(offset + Layout.socketUID)
                    let last = Int32(bitPattern: u32(offset + Layout.socketLastPID))
                    let effective = Int32(bitPattern: u32(offset + Layout.socketEffectivePID))
                    entry.pid = last > 0 ? last : effective
                    pending = entry
                case kindStats:
                    guard length >= Layout.statsMinimumLength else { return nil }
                    var counters = Counters()
                    for index in 0..<Layout.statsClasses {
                        let base = offset + 8 + index * 32
                        counters.rxPackets &+= u64(base)
                        counters.rxBytes &+= u64(base + 8)
                        counters.txPackets &+= u64(base + 16)
                        counters.txBytes &+= u64(base + 24)
                    }
                    var entry = pending ?? Pending()
                    entry.counters = counters
                    pending = entry
                default:
                    break
                }
                offset += Self.roundedUp(length)
            }
            flush()
            return sockets
        }
    }

    static func address(_ raw: UnsafeRawBufferPointer, at offset: Int, ipv4: Bool) -> String? {
        if ipv4 {
            let bytes = (0..<4).map { raw.loadUnaligned(fromByteOffset: offset + 12 + $0, as: UInt8.self) }
            guard bytes.contains(where: { $0 != 0 }) else { return nil }
            return bytes.map(String.init).joined(separator: ".")
        }
        var bytes = (0..<16).map { raw.loadUnaligned(fromByteOffset: offset + $0, as: UInt8.self) }
        guard bytes.contains(where: { $0 != 0 }) else { return nil }
        var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let formatted = bytes.withUnsafeMutableBytes { source in
            inet_ntop(AF_INET6, source.baseAddress, &text, socklen_t(INET6_ADDRSTRLEN)) != nil
        }
        guard formatted else { return nil }
        return String(decoding: text.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
