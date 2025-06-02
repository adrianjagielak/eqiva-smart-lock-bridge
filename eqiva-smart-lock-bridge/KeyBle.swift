//  KeyBleAsync.swift
//  Eqiva-Mac
//
//  A modern, async‑await re‑implementation of the Eqiva "Key‑Ble" protocol.
//  ──────────────────────────────────────────────────────────────────────────────
//  © 2025 Your‑Name‑Here  •  MIT Licence
//  Built with the excellent AsyncBluetooth package for a clean concurrency story
//
//  This rewrite intentionally *forgets* the historic stream/ACK dance of the
//  original keyble.js port and exposes a *message*‑centric API:
//
//      let lock = try await EqivaLock.connect(userKey:"…")
//      try await lock.open()
//      let status = await lock.status
//
//  Internally we still respect the device’s 16‑byte fragment format, but that
//  is kept entirely behind the scenes and sequenced through a single actor so
//  that *you* never have to think about fragments, counters or queues again.
//  All public calls are full‑fledged async functions that can happily run in
//  parallel – the actor makes sure only one BLE exchange is on‑air at a time.
//
//  Dependencies:  • Swift 5.10+  • AsyncBluetooth (SPM)  • CommonCrypto
//  Platform: macOS 11 / iOS 14 or newer (Crypto & async/await baseline)
//  ──────────────────────────────────────────────────────────────────────────────

import Foundation
import CoreBluetooth
import AsyncBluetooth       // https://github.com/manolofdez/AsyncBluetooth
import CommonCrypto

// MARK: ‑‑ Public façade ------------------------------------------------------

public actor EqivaLock {

    // MARK: Public types

    public enum LockState: UInt8, Codable, Equatable {
        case unknown  = 0
        case moving   = 1
        case unlocked = 2
        case locked   = 3
        case opened   = 4
    }

    public struct Status: Sendable {
        public let state        : LockState
        public let batteryLow   : Bool
        public let pairingAllowed: Bool
    }

    // MARK: Static entry‑point

    /// Scan, connect and complete crypto handshake in one go.
    /// - Parameter userKeyHex: 32‑char hex AES‑128 key, as shown by keyble‑register.
    /// - Parameter timeout:    Total time budget for scanning+connecting.
    /// - Returns: Ready‑to‑use connected `EqivaLock`.
    public static func connect(address: String? = nil,
                               userID  : UInt8 = 255,
                               userKeyHex: String,
                               timeout : TimeInterval = 15) async throws -> EqivaLock {
        let lock = EqivaLock(userID: userID, userKeyHex: userKeyHex)
        try await lock.establishConnection(targetAddress: address, timeout: timeout)
        return lock
    }

    // MARK: User‑facing actions ------------------------------------------------

    public func lock()   async throws { try await sendCommand(.lock,    expect: .locked)   }
    public func unlock() async throws { try await sendCommand(.unlock,  expect: .unlocked) }
    public func open()   async throws { try await sendCommand(.open,    expect: .opened)   }
    public func toggle() async throws { try await sendCommand(.toggle,  expect: nil)       }

    /// Ask the lock for its current status *now* (independent of the periodic
    /// auto‑updates we keep running in the background).
    public func requestStatus() async throws -> Status {
        let payload = Self.timestampBytes()
        let reply = try await sendSecure(.statusRequest, payload: payload)
        return try Self.parseStatusInfo(from: reply)
    }

    /// The most recently observed status (updated push + pull).
    public private(set) var status: Status = .init(state: .unknown, batteryLow: false, pairingAllowed: false)

    /// A stream that yields a new `Status` every time the lock reports an update.
    public var statusStream: AsyncStream<Status> {
        AsyncStream { continuation in
            statusContinuations.append(continuation)
            continuation.yield(status)      // immediate first value
        }
    }

    // MARK: De‑initialisation --------------------------------------------------

    deinit {
        Task { await underlyingDisconnect() }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // MARK: ‑‑ Private implementation below -----------------------------------
    // ──────────────────────────────────────────────────────────────────────────

    // MARK: Constants

    private static let serviceUUID = CBUUID(string: "58E06900-15D8-11E6-B737-0002A5D5C51B")
    private static let sendUUID    = CBUUID(string: "3141DD40-15DB-11E6-A24B-0002A5D5C51B")
    private static let recvUUID    = CBUUID(string: "359D4820-15DB-11E6-82BD-0002A5D5C51B")

    // MARK: BLE stack

    private let central = CentralManager()
    private var peripheral: Peripheral!

    // MARK: Crypto session state

    private var userID: UInt8
    private var userKey: [UInt8]  // 16B
    private var localNonce  = [UInt8](repeating: 0, count: 8)
    private var remoteNonce = [UInt8](repeating: 0, count: 8)
    private var localCtr:  UInt16 = 1
    private var remoteCtr: UInt16 = 0

    // MARK: Concurrency & callbacks

    private var pendingContinuations: [UInt8: CheckedContinuation<[UInt8], Error>] = [:]
    private var statusContinuations: [AsyncStream<Status>.Continuation] = []

    // Serialised message inflight protection (BLE can’t do pipelining)
    private var inflight = false

    // MARK: Init

    init(userID: UInt8, userKeyHex: String) {
        self.userID  = userID
        self.userKey = Array<UInt8>(hex: userKeyHex)
    }

    // MARK: Connection / handshake -------------------------------------------

    private func establishConnection(targetAddress: String?, timeout: TimeInterval) async throws {
        try await central.waitUntilReady()

        let scan = try await central.scanForPeripherals(withServices: [Self.serviceUUID])

        let stopTask = Task {           // auto stop after timeout
            try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            await central.stopScan()
            throw NSError(domain: "EqivaLock", code: 1, userInfo: [NSLocalizedDescriptionKey: "Lock not found within timeout"])
        }

        do {
            for try await scanData in scan {
                if let addr = targetAddress {
                    guard scanData.peripheral.identifier.uuidString == addr else { continue }
                }
                peripheral = scanData.peripheral
                break
            }
        } catch {
            stopTask.cancel()
            throw error
        }
        stopTask.cancel()

        try await central.connect(peripheral, options: nil)

        // Enable characteristic notification right away (we need answers)
        try await peripheral.setNotifyValue(true, forCharacteristicWithCBUUID: Self.recvUUID, ofServiceWithCBUUID: Self.serviceUUID)

        // Subscribe to every notification – messages all come through a single chr.
        peripheral.characteristicValueUpdatedPublisher
            .filter { $0.characteristic.uuid == Self.recvUUID }
            .sink { [weak self] update in
                Task { await self?.handleIncoming(data: update.value) }
            }.store(in: &cancellables)

        try await performHandshake()
    }

    private func performHandshake() async throws {
        // 1. Send Connection Request (userID + random 8‑byte nonce)
        localNonce = (0..<8).map { _ in UInt8.random(in: .min ... .max) }
        let connInfo = try await sendPlain(.connectionRequest, payload: [userID] + localNonce)

        // 2. Receive Connection Info with remote nonce
        guard connInfo.count >= 9 else { throw ProtocolError.badHandshake }
        userID      = connInfo[0]
        remoteNonce = Array(connInfo[1...8])
        remoteCtr   = 0
        localCtr    = 1
    }

    // MARK: Public helpers ----------------------------------------------------

    private func sendCommand(_ cmd: Command, expect: LockState?) async throws {
        let reply = try await sendSecure(.command, payload: [cmd.rawValue])
        if let expect {
            let status = try Self.parseStatusInfo(from: reply)
            guard status.state == expect else { throw ProtocolError.unexpectedState(status.state) }
        }
    }

    // MARK: Message primitives (plain / secure) ------------------------------

    private func sendPlain(_ type: MsgID, payload: [UInt8] = []) async throws -> [UInt8] {
        try await send(type, payload: payload, secure: false)
    }

    private func sendSecure(_ type: MsgID, payload: [UInt8]) async throws -> [UInt8] {
        try await send(type, payload: payload, secure: true)
    }

    private func send(_ type: MsgID, payload: [UInt8], secure: Bool) async throws -> [UInt8] {
        // Ensure *global* serial ordering – await only once per actor call.
        while inflight { try await Task.sleep(nanoseconds: 1_000_000) } // 1 ms spin wait
        inflight = true
        defer { inflight = false }

        let (frags, expectedReply) =  secure
        ? try wrapSecure(type: type, payload: payload)
        : (Fragment.build(type: type, payload: payload), MsgID.answerWithoutSecurity.rawValue)

        for fragment in frags {
            try await peripheral.writeValue(Data(fragment), forCharacteristicWithCBUUID: Self.sendUUID, ofServiceWithCBUUID: Self.serviceUUID)
        }

        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<[UInt8], Error>) in
            pendingContinuations[expectedReply] = cont
        }
    }

    // MARK: Incoming processing ---------------------------------------------

    private func handleIncoming(data: Data?) {
        guard let data = data, let frag = Fragment(data) else { return }
        assembler.append(frag)

        if let msg = assembler.tryAssemble() {
            process(message: msg)
        }
    }

    private func process(message: Message) {
        if let cont = pendingContinuations.removeValue(forKey: message.type) {
            cont.resume(returning: message.payload)
        }

        if message.typeEnum == .statusInfo {
            if let newStatus = try? Self.parseStatusInfo(from: message.payload) {
                status = newStatus
                for c in statusContinuations { c.yield(newStatus) }
            }
        }
    }

    // MARK: Status parsing helper

    private static func parseStatusInfo(from payload: [UInt8]) throws -> Status {
        guard payload.count >= 3 else { throw ProtocolError.badStatus }
        let flags    = payload[1]
        let stateRaw = payload[2] & 0x07
        guard let state = LockState(rawValue: stateRaw) else { throw ProtocolError.badStatus }
        return Status(state: state,
                      batteryLow: (flags & 0x80) != 0,
                      pairingAllowed: (flags & 0x01) != 0)
    }

    // MARK: Secure wrapping ---------------------------------------------------

    private func wrapSecure(type: MsgID, payload: [UInt8]) throws -> ([[UInt8]], UInt8) {
        let padded = payload.padded(to: Self.paddedLen(for: payload.count))

        let cipher = Self.crypt(padded,
                                type: type.rawValue,
                                sessionNonce: remoteNonce,
                                counter: localCtr,
                                key: userKey)
        let auth = Self.authentication(for: padded,
                                       originalLen: payload.count,
                                       type: type.rawValue,
                                       sessionNonce: remoteNonce,
                                       counter: localCtr,
                                       key: userKey)
        let full = cipher + UInt16(localCtr).leBytes + auth
        localCtr &+= 1
        return (Fragment.build(type: type, payload: full), MsgID.answerWithSecurity.rawValue)
    }

    // MARK: Disconnection helper --------------------------------------------

    private func underlyingDisconnect() async {
        await peripheral?.cancelAllOperations()
        try? await central.cancelAllOperations()
    }

    // MARK: Support types / helpers -----------------------------------------

    /// BLE command IDs the firmware understands.
    private enum Command: UInt8 { case lock = 0, unlock = 1, open = 2, toggle = 3 }

    /// Protocol message identifiers
    private enum MsgID: UInt8 {
        case connectionRequest = 0x02
        case answerWithoutSecurity = 0x01
        case answerWithSecurity    = 0x81
        case statusRequest         = 0x82
        case statusInfo            = 0x83
        case command               = 0x87
    }

    private struct Message {
        let type: UInt8           // raw
        let payload: [UInt8]
        var typeEnum: MsgID? { MsgID(rawValue: type) }
    }

    // ‑‑ Fragment assembler ---------------------------------------------------

    private var assembler = Assembler()

    private struct Fragment {
        let header: UInt8
        let body  : [UInt8]       // always 15B (padded)

        var isFirst  : Bool { (header & 0x80) != 0 }
        var remaining: Int  { Int(header & 0x7F) }

        /// Parse from raw 16-byte Data received
        init?(_ data: Data) {
            guard data.count == 16 else { return nil }
            header = data[0]
            body   = Array(data[1..<16])
        }

        static func build(type: MsgID, payload: [UInt8]) -> [[UInt8]] {
            let chunks = stride(from: 0, to: payload.count, by: 15)
                .map { Array(payload[$0..<min($0+15, payload.count)]) }
            return chunks.enumerated().map { (i, chunk) in
                let h: UInt8 = (i == 0 ? 0x80 : 0) | UInt8(chunks.count - 1 - i)
                var b = chunk
                if i == 0 { b.insert(type.rawValue, at: 0) }
                return [h] + b.padded(to: 15)
            }
        }
    }

    private struct Assembler {
        private var incoming: [Fragment] = []

        mutating func append(_ frag: Fragment) {
            incoming.append(frag)
        }

        mutating func tryAssemble() -> Message? {
            guard let first = incoming.first, first.isFirst else { return nil }
            guard first.remaining == incoming.count - 1 else { return nil }

            var bytes: [UInt8] = []
            for (i, f) in incoming.enumerated() {
                bytes += i == 0 ? Array(f.body.dropFirst()) : f.body
            }

            incoming.removeAll()
            let type = first.body[0]
            return Message(type: type, payload: bytes)
        }
    }

    // ‑‑ Crypto helpers (ported 1:1 from legacy port) ------------------------

    private static func aesEncrypt(key: [UInt8], block: [UInt8]) -> [UInt8] {
        precondition(block.count == 16 && key.count == 16)
        var out = [UInt8](repeating: 0, count: 16)
        var outLen: size_t = 0
        let stat = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                           key, kCCKeySizeAES128, nil,
                           block, 16, &out, 16, &outLen)
        precondition(stat == kCCSuccess && outLen == 16)
        return out
    }

    private static func crypt(_ input: [UInt8], type: UInt8, sessionNonce: [UInt8], counter: UInt16, key: [UInt8]) -> [UInt8] {
        let nonce = [type] + sessionNonce + [0,0] + UInt16(counter).leBytes
        var out = [UInt8](repeating: 0, count: input.count)
        var blk: UInt16 = 1
        var idx = 0
        while idx < input.count {
            let keystream = aesEncrypt(key: key, block: [1] + nonce + UInt16(blk).leBytes)
            let n = min(16, input.count - idx)
            let chunk = Array(input[idx..<idx+n])
            out.replaceSubrange(idx..<idx+n, with: chunk ^ keystream[0..<n])
            idx += n; blk += 1
        }
        return out
    }

    private static func authentication(for padded: [UInt8], originalLen: Int, type: UInt8, sessionNonce: [UInt8], counter: UInt16, key: [UInt8]) -> [UInt8] {
        let nonce = [type] + sessionNonce + [0,0] + UInt16(counter).leBytes
        var state = aesEncrypt(key: key, block: [9] + nonce + UInt16(originalLen).leBytes)
        for off in stride(from: 0, to: padded.count, by: 16) {
            let blk = Array(padded[off..<min(off+16,padded.count)]).padded(to: 16)
            state = aesEncrypt(key: key, block: state ^ blk)
        }
        let s1 = aesEncrypt(key: key, block: [1] + nonce + [0,0])
        return Array((state ^ s1)[0..<4])
    }

    private static func paddedLen(for len: Int) -> Int {
        ((len - 1 + 14) / 15) * 15 + 1
    }

    // MARK: Little helpers ----------------------------------------------------

    private static func timestampBytes() -> [UInt8] {
        let cal = Calendar(identifier: .gregorian)
        let d = Date()
        return [UInt8(cal.component(.year,  from: d) - 2000),
                UInt8(cal.component(.month, from: d)),
                UInt8(cal.component(.day,   from: d)),
                UInt8(cal.component(.hour,  from: d)),
                UInt8(cal.component(.minute,from: d)),
                UInt8(cal.component(.second,from: d))]
    }

    private enum ProtocolError: Error {
        case badHandshake, badStatus, unexpectedState(LockState)
    }

    // MARK: Combine bag (for BLE publisher)
    private var cancellables: Set<AnyCancellable> = []
}

// MARK: ‑‑ Swift candy extensions -------------------------------------------

import Combine

private extension Array where Element == UInt8 {
    mutating func xor(with other: [UInt8]) { self = zip(self, other).map(^) }
}

private func ^(lhs: [UInt8], rhs: ArraySlice<UInt8>) -> [UInt8] {
    zip(lhs, rhs).map(^)
}

private func ^(lhs: [UInt8], rhs: [UInt8]) -> [UInt8] {
    zip(lhs, rhs).map(^)
}

private extension UInt16 {
    var leBytes: [UInt8] { [UInt8(self & 0xFF), UInt8(self >> 8)] }
}

private extension Array where Element == UInt8 {
    init(hex str: String) {
        let clean = str.replacingOccurrences(of: "[^0-9A-Fa-f]", with: "", options: .regularExpression)
        self.init(); var idx = clean.startIndex
        while idx < clean.endIndex {
            let nxt = clean.index(idx, offsetBy: 2)
            self.append(UInt8(clean[idx..<nxt], radix: 16)!)
            idx = nxt
        }
    }

    func padded(to len: Int) -> [UInt8] { self + Array(repeating: 0, count: Swift.max(0, len - count)) }
}
