// EqivaLock.swift
// Modern, message‑based Swift library for eQ‑3 Eqiva Bluetooth Smart Lock
// Created 2 Jun 2025 – rewritten from the legacy keyble.js logic
// No async/await – public API uses completion handlers.
// -----------------------------------------------------------------------------

import Foundation
import CoreBluetooth
import CommonCrypto

// MARK: – Helper extensions --------------------------------------------------

private extension Array where Element == UInt8 {
    /// Pretty hex dump (for debugging)
    var hex: String { map { String(format: "%02X", $0) }.joined(separator: " ") }

    /// XOR two equal‑length buffers
    func xor(_ other: [UInt8]) -> [UInt8] {
        precondition(count == other.count)
        return zip(self, other).map(^)
    }

    /// Little‑endian UInt16 helpers (protocol specifies LE)
    static func le(_ value: UInt16) -> [UInt8] { [UInt8(value & 0xFF), UInt8(value >> 8)] }
    func toUInt16LE(at offset: Int) -> UInt16 {
        UInt16(self[offset]) | (UInt16(self[offset + 1]) << 8)
    }

    /// Eqiva wants ciphertext length ≡ 1 (mod 15)
    static func paddedLength(for len: Int) -> Int {
        ((len - 1 + 14) / 15) * 15 + 1
    }
    func padded(to len: Int) -> [UInt8] {
        self + Array(repeating: 0, count: Swift.max(0, len - count))
    }
}

private extension Data { var hex: String { [UInt8](self).hex } }

private extension String {                     // Hex → [UInt8]
    var bytesFromHex: [UInt8] {
        let clean = replacingOccurrences(of: "[^0-9A-Fa-f]", with: "", options: .regularExpression)
        var out: [UInt8] = []
        var idx = clean.startIndex
        while idx < clean.endIndex {
            let nxt = clean.index(idx, offsetBy: 2)
            out.append(UInt8(clean[idx ..< nxt], radix: 16)!)
            idx = nxt
        }
        return out
    }
}

// MARK: – Protocol definitions ---------------------------------------------

fileprivate enum MessageID: UInt8 {
    case fragmentAck               = 0x00
    case answerPlain               = 0x01
    case connectionRequest         = 0x02
    case connectionInfo            = 0x03
    case pairingRequest            = 0x04
    case statusChangedNotification = 0x05
    case closeConnection           = 0x06

    // Bootloader 0x1* omitted

    case answerSecure       = 0x81
    case statusRequest      = 0x82
    case statusInfo         = 0x83
    case command            = 0x87

    var secure: Bool { rawValue & 0x80 != 0 }
}

public enum EqivaCommand: UInt8 { case lock = 0, unlock = 1, open = 2 }

public enum LockState: UInt8 { case unknown = 0, moving = 1, unlocked = 2, locked = 3, opened = 4 }

public struct LockStatus { public let state: LockState; public let batteryLow: Bool }

public protocol EqivaLockDelegate: AnyObject {
    func eqivaLockDidConnect(_ lock: EqivaLock)
    func eqivaLockDidDisconnect(_ lock: EqivaLock)
    func eqivaLock(_ lock: EqivaLock, didUpdateStatus status: LockStatus)
}

public enum EqivaLockError: Error { case bluetoothOff, handshakeFailed, timeout, protocolError(String) }

// MARK: – Cryptography ------------------------------------------------------

fileprivate struct Crypto {
    static func aesECBEncrypt(key: [UInt8], block: [UInt8]) -> [UInt8] {
        precondition(key.count == 16 && block.count == 16)
        var out = [UInt8](repeating: 0, count: 16)
        var outLen: size_t = 0
        let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                             key, kCCKeySizeAES128, nil, block, 16, &out, 16, &outLen)
        precondition(status == kCCSuccess && outLen == 16)
        return out
    }

    static func makeNonce(type: UInt8, session: [UInt8], counter: UInt16) -> [UInt8] {
        [type] + session + [0, 0] + .le(counter)
    }

    /// AES‑CTR (Eqiva: AES‑ECB‑keystream) encrypt/decrypt
    static func crypt(_ plain: [UInt8], key: [UInt8], type: UInt8, session: [UInt8], counter: UInt16) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: plain.count)
        let nonce = makeNonce(type: type, session: session, counter: counter)
        var blk: UInt16 = 1
        var offset = 0
        while offset < plain.count {
            let ks = aesECBEncrypt(key: key, block: [1] + nonce + .le(blk))
            let n   = min(16, plain.count - offset)
            let xorResult = Array(plain[offset ..< offset+n]).xor(Array(ks.prefix(n)))
            for i in 0..<n {
                out[offset + i] = xorResult[i]
            }
            offset += n; blk += 1
        }
        return out
    }

    /// 4‑byte auth value – spec reverse‑engineered from keyble.js
    static func auth(for padded: [UInt8], originalLen: Int, key: [UInt8], type: UInt8, session: [UInt8], counter: UInt16) -> [UInt8] {
        let nonce = makeNonce(type: type, session: session, counter: counter)
        var state = aesECBEncrypt(key: key, block: [9] + nonce + .le(UInt16(originalLen)))
        for off in stride(from: 0, to: padded.count, by: 16) {
            let chunk = Array(padded[off ..< min(off+16, padded.count)]).padded(to: 16)
            state = aesECBEncrypt(key: key, block: state.xor(chunk))
        }
        let s1 = aesECBEncrypt(key: key, block: [1] + nonce + [0,0])
        return Array(state.prefix(4)).xor(Array(s1.prefix(4)))
    }
}

// MARK: – Fragment structure ----------------------------------------------

fileprivate struct Fragment {
    let status: UInt8       // MSB == 1 on FIRST fragment
    let body:   [UInt8]     // up to 15 bytes

    var isFirst: Bool { status & 0x80 != 0 }
    var remaining: Int { Int(status & 0x7F) }
    var isLast: Bool { remaining == 0 }

    var data: Data { Data([status] + body.padded(to: 15)) }

    static func make(messageType: MessageID, payload: [UInt8]) -> [Fragment] {
        let parts = stride(from: 0, to: payload.count, by: 15).map {
            Array(payload[$0 ..< min($0+15, payload.count)])
        }
        return parts.enumerated().map { idx, part in
            let remaining = parts.count - idx - 1
            let st: UInt8 = (idx == 0 ? 0x80 : 0) | UInt8(remaining)
            let b = idx == 0 ? [messageType.rawValue] + part : part
            return Fragment(status: st, body: b)
        }
    }
    
    init?(raw: Data) {
        guard raw.count == 16 else { return nil }
        status = raw[0]
        body   = Array(raw[1..<16])
    }
    
    init(status: UInt8, body: [UInt8]) {
        self.status = status
        self.body = body
    }
}

// MARK: – Operation abstraction -------------------------------------------

fileprivate final class Operation {
    let messageType: MessageID
    let payload: [UInt8]
    let expectedResponse: MessageID?
    let onComplete: (Result<[UInt8], Error>) -> Void
    private var timeoutTimer: DispatchSourceTimer?

    init(type: MessageID, payload: [UInt8], expected: MessageID?, queue: DispatchQueue,
         timeout: TimeInterval = 10, completion: @escaping (Result<[UInt8], Error>) -> Void) {
        self.messageType = type; self.payload = payload; self.expectedResponse = expected; self.onComplete = completion
        if timeout > 0 {
            timeoutTimer = DispatchSource.makeTimerSource(queue: queue)
            timeoutTimer?.schedule(deadline: .now() + timeout)
            timeoutTimer?.setEventHandler { [weak self] in
                self?.finish(.failure(EqivaLockError.timeout))
            }
            timeoutTimer?.resume()
        }
    }

    func finish(_ result: Result<[UInt8], Error>) {
        timeoutTimer?.cancel(); onComplete(result)
    }
}

// MARK: – Main class -------------------------------------------------------

public final class EqivaLock: NSObject {

    // === Public API ===
    public weak var delegate: EqivaLockDelegate?

    public init(userKeyHex: String, userID: UInt8 = 255) {
        self.userKey = userKeyHex.bytesFromHex
        self.userID  = userID
        self.queue   = DispatchQueue(label: "EqivaLock.Serial")
        super.init()
    }

    public func connect(completion: @escaping (Result<Void, Error>) -> Void) {
        queue.async {
            self.connectCompletion = completion
            self.central = CBCentralManager(delegate: self, queue: self.queue)
        }
    }

    public func disconnect() {
        queue.async { [weak self] in
            guard let self = self else { return }
            if let p = self.peripheral { self.central?.cancelPeripheralConnection(p) }
            self.reset()
        }
    }

    /// Lock / unlock / open -------------------------------------------------
    public func send(_ cmd: EqivaCommand, completion: @escaping (Result<LockStatus, Error>) -> Void) {
        let payload = [cmd.rawValue]
        enqueueSecure(message: .command, payload: payload, expected: .statusInfo) { [weak self] res in
            switch res {
            case .failure(let e): completion(.failure(e))
            case .success(let data):
                guard let st = self?.parseStatusInfo(data) else {
                    completion(.failure(EqivaLockError.protocolError("Malformed status")))
                    return
                }
                completion(.success(st))
            }
        }
    }

    /// Query current status (does NOT alter lock state)
    public func getStatus(completion: @escaping (Result<LockStatus, Error>) -> Void) {
        let ts = EqivaLock.timestamp()
        enqueueSecure(message: .statusRequest, payload: ts, expected: .statusInfo) { [weak self] res in
            switch res {
            case .failure(let e): completion(.failure(e))
            case .success(let data):
                guard let st = self?.parseStatusInfo(data) else {
                    completion(.failure(EqivaLockError.protocolError("Malformed status")))
                    return
                }
                completion(.success(st))
            }
        }
    }

    // =========================================================================
    // MARK: – Internal state

    private let queue: DispatchQueue
    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var txChar: CBCharacteristic?
    private var rxChar: CBCharacteristic?

    private var connectCompletion: ((Result<Void, Error>) -> Void)?

    private enum ConnState { case idle, scanning, connecting, ready, secured }
    private var state: ConnState = .idle

    // ––– Crypto/session
    private var userKey: [UInt8]
    private var userID: UInt8
    private var localNonce:  [UInt8] = Array(repeating: 0, count: 8)
    private var remoteNonce: [UInt8] = Array(repeating: 0, count: 8)
    private var localCounter:  UInt16 = 1
    private var remoteCounter: UInt16 = 0

    // ––– Operation queue (message‑level)
    private var opQueue: [Operation] = []
    private var inFlight: Operation?

    // ––– Fragment assembly
    private var inFragments: [Fragment] = []
    private var awaitingAckStatus: UInt8?

    // =========================================================================
    // MARK: – Constants

    private static let serviceUUID = CBUUID(string: "58E06900-15D8-11E6-B737-0002A5D5C51B")
    private static let txUUID      = CBUUID(string: "3141DD40-15DB-11E6-A24B-0002A5D5C51B") // write
    private static let rxUUID      = CBUUID(string: "359D4820-15DB-11E6-82BD-0002A5D5C51B") // notify

    // =========================================================================
    // MARK: – Message queue helpers

    private func enqueuePlain(message type: MessageID, payload: [UInt8], expected: MessageID?,
                              completion: @escaping (Result<[UInt8], Error>) -> Void) {
        queue.async {
            let op = Operation(type: type, payload: payload, expected: expected, queue: self.queue, completion: completion)
            self.opQueue.append(op); self.pump()
        }
    }

    private func enqueueSecure(message type: MessageID, payload: [UInt8], expected: MessageID?,
                               completion: @escaping (Result<[UInt8], Error>) -> Void) {
        queue.async {
            guard self.state == .secured else {
                // handshake needed first – prepend operation to queue after CR
                self.ensureSecureChannel()
                let op = Operation(type: type, payload: payload, expected: expected, queue: self.queue, completion: completion)
                self.opQueue.append(op); return
            }

            // pad, encrypt, auth
            let padLen = [UInt8].paddedLength(for: payload.count)
            let padded = payload.padded(to: padLen)
            let cipher = Crypto.crypt(padded, key: self.userKey, type: type.rawValue, session: self.remoteNonce, counter: self.localCounter)
            let auth   = Crypto.auth(for: padded, originalLen: payload.count, key: self.userKey, type: type.rawValue, session: self.remoteNonce, counter: self.localCounter)
            let full   = cipher + .le(self.localCounter) + auth
            self.localCounter &+= 1
            let op = Operation(type: type, payload: full, expected: expected, queue: self.queue, completion: completion)
            self.opQueue.append(op); self.pump()
        }
    }

    private func ensureSecureChannel() {
        guard state == .ready else { return }
        localNonce = (0..<8).map { _ in UInt8.random(in: 0...255) }
        let cr = Operation(type: .connectionRequest, payload: [userID] + localNonce, expected: .connectionInfo, queue: queue) { [weak self] res in
            switch res {
            case .failure(let e): self?.connectCompletion?(.failure(e))
            case .success:
                self?.state = .secured
                self?.connectCompletion?(.success(()))
            }
        }
        opQueue.insert(cr, at: 0)
    }

    private func pump() {
        guard inFlight == nil, let op = opQueue.first, let p = peripheral, let tx = txChar else { return }
        inFlight = op
        let frags = Fragment.make(messageType: op.messageType, payload: op.payload)
        sendFragments(frags, via: p, char: tx, index: 0)
    }

    private func sendFragments(_ frags: [Fragment], via p: CBPeripheral, char: CBCharacteristic, index: Int) {
        guard index < frags.count else {
            awaitingAckStatus = nil
            return   // all sent; waiting for response
        }
        let frag = frags[index]
        awaitingAckStatus = frag.isLast ? nil : frag.status      // need ACK for non‑last fragments
        p.writeValue(frag.data, for: char, type: .withResponse)
        if frag.isLast { return } // next fragment will be triggered by ACK
    }

    // =========================================================================
    // MARK: – Helper: parse status

    private func parseStatusInfo(_ data: [UInt8]) -> LockStatus? {
        guard data.count >= 3 else { return nil }
        let id  = LockState(rawValue: data[2] & 0x07) ?? .unknown
        let low = data[1] & 0x80 != 0
        return LockStatus(state: id, batteryLow: low)
    }

    private static func timestamp() -> [UInt8] {
        let c = Calendar(identifier: .gregorian); let d = Date()
        return [UInt8(c.component(.year,  from: d) - 2000),
                UInt8(c.component(.month, from: d)),
                UInt8(c.component(.day,   from: d)),
                UInt8(c.component(.hour,  from: d)),
                UInt8(c.component(.minute,from: d)),
                UInt8(c.component(.second,from: d))]
    }

    private func reset() {
        opQueue.removeAll(); inFlight = nil; inFragments.removeAll(); awaitingAckStatus = nil
        state = .idle; central = nil; peripheral = nil; txChar = nil; rxChar = nil
    }
}

// MARK: – CBCentralManagerDelegate ----------------------------------------

extension EqivaLock: CBCentralManagerDelegate {
    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard central.state == .poweredOn else {
            connectCompletion?(.failure(EqivaLockError.bluetoothOff)); return
        }
        guard state == .idle else { return }
        state = .scanning; central.scanForPeripherals(withServices: [Self.serviceUUID])
    }

    public func centralManager(_ c: CBCentralManager, didDiscover p: CBPeripheral, advertisementData: [String : Any], rssi: NSNumber) {
        c.stopScan(); state = .connecting; peripheral = p; p.delegate = self; c.connect(p)
    }

    public func centralManager(_ c: CBCentralManager, didConnect p: CBPeripheral) {
        state = .ready; delegate?.eqivaLockDidConnect(self); p.discoverServices([Self.serviceUUID])
    }

    public func centralManager(_ c: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) {
        reset(); delegate?.eqivaLockDidDisconnect(self)
    }
}

// MARK: – CBPeripheralDelegate --------------------------------------------

extension EqivaLock: CBPeripheralDelegate {
    public func peripheral(_ p: CBPeripheral, didDiscoverServices error: Error?) {
        guard let svc = p.services?.first(where: { $0.uuid == Self.serviceUUID }) else { return }
        p.discoverCharacteristics([Self.txUUID, Self.rxUUID], for: svc)
    }

    public func peripheral(_ p: CBPeripheral, didDiscoverCharacteristicsFor svc: CBService, error: Error?) {
        for ch in svc.characteristics ?? [] {
            if ch.uuid == Self.txUUID { txChar = ch }
            if ch.uuid == Self.rxUUID { rxChar = ch; p.setNotifyValue(true, for: ch) }
        }
        pump()
    }

    public func peripheral(_ p: CBPeripheral, didUpdateValueFor ch: CBCharacteristic, error: Error?) {
        guard let raw = ch.value, let frag = Fragment(raw: raw) else { return }
        if frag.isFirst { inFragments.removeAll() }
        inFragments.append(frag)

        // If ACK expected
        if frag.isFirst == false && frag.isLast == false && frag.body.count == 0 { /* skip */ }
        if frag.status == awaitingAckStatus {      // Received ACK → send next fragment
            awaitingAckStatus = nil
            if let op = inFlight, let p = peripheral, let tx = txChar {
                let frags = Fragment.make(messageType: op.messageType, payload: op.payload)
                sendFragments(frags, via: p, char: tx, index: frags.firstIndex(where: { $0.status == frag.status })! + 1)
            }
            return
        }

        guard frag.isLast else { return }
        let completePayload = inFragments.enumerated().flatMap { idx, f -> [UInt8] in
            idx == 0 ? Array(f.body.dropFirst()) : f.body
        }
        let type = MessageID(rawValue: inFragments[0].body[0]) ?? .fragmentAck
        handleIncoming(type: type, payload: completePayload)
    }

    private func handleIncoming(type: MessageID, payload: [UInt8]) {
        switch type {
        case .fragmentAck:
            // handled earlier when we compared status – nothing extra
            break
        case .connectionInfo:
            guard payload.count >= 9 else {
                inFlight?.finish(.failure(EqivaLockError.protocolError("Malformed CI"))); inFlight = nil; pump(); return
            }
            remoteNonce = Array(payload[1...8]); remoteCounter = 0; localCounter = 1
            inFlight?.finish(.success(payload)); inFlight = nil; pump()
        case .statusInfo:
            let st = parseStatusInfo(payload)
            if let op = inFlight, op.expectedResponse == .statusInfo {
                op.finish(.success(payload)); inFlight = nil; pump()
            }
            if let st = st { delegate?.eqivaLock(self, didUpdateStatus: st) }
        case .answerSecure:
            inFlight?.finish(.failure(EqivaLockError.protocolError("Auth failed"))); inFlight = nil; pump()
        default:
            // Some other response we don't expect – ignore
            break
        }
    }
}
