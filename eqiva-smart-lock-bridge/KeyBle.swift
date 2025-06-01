//
//  KeyBle.swift
//  Eqiva-Mac
//
//  Created 1 Jun 2025
//
//  Pure-Swift port of keyble.js (© its respective authors)
//  Uses CoreBluetooth + CommonCrypto, no async/await.
//

import Foundation
import CoreBluetooth
import CommonCrypto

// MARK: -- Helpers -----------------------------------------------------------

private extension Array where Element == UInt8 {

    /// Hex dump – nice for logs
    var hex: String { map { String(format: "%02X", $0) }.joined(separator: " ") }

    /// XOR two equal-length buffers
    func xor(with other: [UInt8]) -> [UInt8] {
        precondition(count == other.count)
        return zip(self, other).map(^)
    }

    /// Big-endian integer ⇄ byte helpers
    static func fromUInt16(_ value: UInt16) -> [UInt8] {
        [UInt8(value >> 8), UInt8(value & 0xFF)]
    }
    func toUInt16(offset: Int) -> UInt16 {
        let hi = UInt16(self[offset])
        let lo = UInt16(self[offset + 1])
        return (hi << 8) | lo
    }

    /// Ceiling function used by keyble.js → 8,23,38,…
    static func paddedLength(for original: Int,
                             step: Int = 15,
                             offset: Int = 8) -> Int {
        ((Int(ceil(Double(original - offset) / Double(step)))) * step) + offset
    }

    /// Pad with zeros to length
    func padded(to length: Int) -> [UInt8] {
        self + Array(repeating: 0, count: Swift.max(0, length - count))
    }
}

/// 16-byte AES-128 ECB encryption (no padding) via CommonCrypto
private func aesEncryptECB(key: [UInt8], block: [UInt8]) -> [UInt8] {
    precondition(block.count == 16 && key.count == 16)
    var out = [UInt8](repeating: 0, count: 16)
    var outLen: size_t = 0
    let status = CCCrypt(CCOperation(kCCEncrypt),
                         CCAlgorithm(kCCAlgorithmAES),
                         CCOptions(kCCOptionECBMode),
                         key, kCCKeySizeAES128,
                         nil,
                         block, 16,
                         &out, 16,
                         &outLen)
    precondition(status == kCCSuccess && outLen == 16)
    return out
}

// MARK: -- Message / Crypto --------------------------------------------------

private enum MsgID: UInt8 {
    case fragmentAck           = 0x00
    case connectionRequest     = 0x02
    case connectionInfo        = 0x03
    case closeConnection       = 0x06
    case statusRequest         = 0x82     // secure
    case statusInfo            = 0x83     // secure
    case command               = 0x87     // secure
    // …add more if needed
    var isSecure: Bool { (rawValue & 0x80) != 0 }
}

/// Compute 13-byte nonce = [typeID | sessionNonce(8) | 0,0 | secCounter(2)]
private func makeNonce(type: UInt8,
                       sessionNonce: [UInt8],
                       counter: UInt16) -> [UInt8] {
    [type] + sessionNonce + [0, 0] + .fromUInt16(counter)
}

/// AES-CTR (ECB-keystream) encrypt / decrypt
private func crypt(_ input: [UInt8],
                   type: UInt8,
                   sessionNonce: [UInt8],
                   counter: UInt16,
                   key: [UInt8]) -> [UInt8] {

    let nonce = makeNonce(type: type, sessionNonce: sessionNonce, counter: counter)
    precondition(nonce.count == 13)

    var output = [UInt8](repeating: 0, count: input.count)

    var blockIndex: UInt16 = 1
    var offset = 0
    while offset < input.count {
        let keystream = aesEncryptECB(key: key,
                                      block: [1] + nonce + .fromUInt16(blockIndex))
        let n = min(16, input.count - offset)
        let slice = Array(input[offset ..< offset + n])
        let xorred = slice.xor(with: Array(keystream.prefix(n)))
        output.replaceSubrange(offset ..< offset + n, with: xorred)
        offset += n
        blockIndex += 1
    }
    return output
}

/// 4-byte authentication value as in keyble.js
private func authentication(for plain: [UInt8],
                            originalLen: Int,
                            type: UInt8,
                            sessionNonce: [UInt8],
                            counter: UInt16,
                            key: [UInt8]) -> [UInt8] {

    let nonce = makeNonce(type: type, sessionNonce: sessionNonce, counter: counter)

    var state = aesEncryptECB(key: key,
                              block: [9] + nonce + .fromUInt16(UInt16(originalLen)))

    // CBC-XOR over padded plaintext
    for chunkStart in stride(from: 0, to: plain.count, by: 16) {
        let chunk = Array(plain[chunkStart ..< min(chunkStart + 16, plain.count)])
            .padded(to: 16)
        state = aesEncryptECB(key: key, block: state.xor(with: chunk))
    }

    let s1 = aesEncryptECB(key: key,
                           block: [1] + nonce + [0, 0])
    return Array(Array(state.prefix(4)).xor(with: Array(s1.prefix(4))))
}

// MARK: -- Low-level Fragments ----------------------------------------------

private struct Fragment {
    /// First byte: 0x80 if first fragment | remainingFragments
    let status: UInt8
    /// Up to 15 bytes (padded with zeros)
    let body: [UInt8]

    var isFirst: Bool { (status & 0x80) != 0 }
    var remaining: Int { Int(status & 0x7F) }
    var isLast: Bool { remaining == 0 }

    /// Serialize to 16-byte Data
    var data: Data { Data([status] + body.padded(to: 15)) }

    static func makeFragments(type: MsgID, payload: [UInt8]) -> [Fragment] {
        let chunks = stride(from: 0, to: payload.count, by: 15)
            .map { Array(payload[$0 ..< min($0 + 15, payload.count)]) }

        return chunks.enumerated().map { (i, chunk) in
            let remaining = chunks.count - 1 - i
            let isFirst = i == 0
            let status: UInt8 = (isFirst ? 0x80 : 0) | UInt8(remaining & 0x7F)
            let body = isFirst ? [type.rawValue] + chunk : chunk
            return Fragment(status: status, body: body)
        }
    }

    /// Parse from raw 16-byte Data received
    init?(data: Data) {
        guard data.count == 16 else { return nil }
        status = data[0]
        body   = Array(data[1 ..< 16])
    }

    init(status: UInt8, body: [UInt8]) {
        self.status = status
        self.body   = body
    }
}

// MARK: -- Public API: delegate & status model ------------------------------

public enum LockStatusID: UInt8 {
    case unknown  = 0
    case moving   = 1
    case unlocked = 2
    case locked   = 3
    case opened   = 4
}

public struct LockStatus {
    public let id: LockStatusID
    public let batteryLow: Bool
    public let pairingAllowed: Bool
}

public protocol KeyBleDelegate: AnyObject {
    func keyBleDidConnect(_ key: KeyBle)
    func keyBleDidDisconnect(_ key: KeyBle)
    func keyBle(_ key: KeyBle, didUpdateStatus: LockStatus)
    func keyBle(_ key: KeyBle, didChangeStatus: LockStatus)
}

// MARK: -- KeyBle class ------------------------------------------------------

public final class KeyBle: NSObject {

    // === PUBLIC ===
    weak var delegate: KeyBleDelegate?

    // Start scanning / connect
    public func start() {
        central = CBCentralManager(delegate: self, queue: queue)
    }

    // Disconnect politely
    public func disconnect() {
        queue.async { [weak self] in
            self?.send(message: (.closeConnection, []))
            if let p = self?.peripheral { self?.central?.cancelPeripheralConnection(p) }
        }
    }

    public func lock()   { sendCommand(0, expect: .locked)   }
    public func unlock() { sendCommand(1, expect: .unlocked) }
    public func open()   { sendCommand(2, expect: .opened)   }
    public func toggle() {
        switch lockStatusID {
        case .locked:   unlock()
        case .unlocked, .opened: lock()
        default:        requestStatus()
        }
    }
    public func requestStatus() {
        queue.async { [weak self] in
            self?.sendSecure(type: .statusRequest,
                             payload: KeyBle.buildTimestamp(),
                             completion: nil)
        }
    }

    // === INITIALISER ===
    public init(userID: UInt8             = 255,
                userKeyHex: String,
                autoDisconnectTime: TimeInterval = 15,
                statusUpdateTime:  TimeInterval  = 600) {

        self.userID             = userID
        self.userKey            = Array<UInt8>(hex: userKeyHex)
        self.autoDisconnectTime = autoDisconnectTime
        self.statusUpdateTime   = statusUpdateTime
        self.queue              = DispatchQueue(label: "KeyBle.Serial")
        super.init()
    }

    // MARK: -- Private state -------------------------------------------------

    private enum ConnState: Int {
        case disconnected, connected, noncesExchanged
    }

    private let queue: DispatchQueue
    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var sendChar: CBCharacteristic?
    private var recvChar: CBCharacteristic?

    private var connState: ConnState = .disconnected

    private var userID: UInt8
    private var userKey: [UInt8]                // 16 B
    private var autoDisconnectTime: TimeInterval
    private var statusUpdateTime: TimeInterval

    // Session crypto
    private var localNonce  = [UInt8](repeating: 0, count: 8)
    private var remoteNonce = [UInt8](repeating: 0, count: 8)
    private var localCtr:  UInt16 = 1
    private var remoteCtr: UInt16 = 0

    // Outgoing queue – one message in flight
    private var pendingMessages: [(MsgID, [UInt8], (() -> Void)?)] = []
    private var awaitingAck = false

    // Incoming
    private var incomingFragments: [Fragment] = []

    // Latest status
    private var lockStatusID: LockStatusID = .unknown

    // MARK: -- UUIDs ---------------------------------------------------------

    private static let serviceUUID   = CBUUID(string: "58E06900-15D8-11E6-B737-0002A5D5C51B")
    private static let sendUUID      = CBUUID(string: "3141DD40-15DB-11E6-A24B-0002A5D5C51B")
    private static let recvUUID      = CBUUID(string: "359D4820-15DB-11E6-82BD-0002A5D5C51B")

    // MARK: -- Message building / sending -----------------------------------

    /// Build 6-byte timestamp YY MM DD hh mm ss
    private static func buildTimestamp() -> [UInt8] {
        let c = Calendar(identifier: .gregorian)
        let d = Date()
        return [UInt8(c.component(.year,  from: d) - 2000),
                UInt8(c.component(.month, from: d)),
                UInt8(c.component(.day,   from: d)),
                UInt8(c.component(.hour,  from: d)),
                UInt8(c.component(.minute,from: d)),
                UInt8(c.component(.second,from: d))]
    }

    /// Queue a **plain** (non-secure) message
    private func send(message: (MsgID, [UInt8]), completion: (() -> Void)? = nil) {
        queue.async {
            self.pendingMessages.append((message.0, message.1, completion))
            self.flushQueue()
        }
    }

    /// Queue a secure message; performs handshake if necessary
    private func sendSecure(type: MsgID,
                            payload: [UInt8],
                            completion: (() -> Void)?) {

        queue.async {
            guard self.connState == .noncesExchanged else {
                // perform handshake first, enqueue afterwards
                self.pendingMessages.append((type, payload, completion))
                self.ensureNonces()
                return
            }

            let padded = payload.padded(to: [UInt8].paddedLength(for: payload.count))
            let cipher = crypt(padded,
                               type: type.rawValue,
                               sessionNonce: self.remoteNonce,
                               counter: self.localCtr,
                               key: self.userKey)
            let auth   = authentication(for: padded,
                                        originalLen: payload.count,
                                        type: type.rawValue,
                                        sessionNonce: self.remoteNonce,
                                        counter: self.localCtr,
                                        key: self.userKey)
            let full   = cipher + .fromUInt16(self.localCtr) + auth
            self.localCtr &+= 1
            self.pendingMessages.append((type, full, completion))
            self.flushQueue()
        }
    }

    /// Called inside queue – sends next fragments if nothing in flight
    private func flushQueue() {
        guard !awaitingAck,
              let (type, payload, completion) = pendingMessages.first,
              !(type.isSecure && connState != .noncesExchanged),
              let sendChar = sendChar,
              let peripheral = peripheral
        else { return }

        let fragments = Fragment.makeFragments(type: type, payload: payload)
        awaitingAck = !fragments.isEmpty               // even single fragment waits for write CB

        // Recursive helper to send fragment-by-fragment waiting for ACKs
        func sendNextFragment(_ idx: Int) {
            guard idx < fragments.count else {
                awaitingAck = false
                pendingMessages.removeFirst()
                completion?()
                flushQueue()
                return
            }
            let frag = fragments[idx]
            print("⬆️  Sending fragment \(idx)/\(fragments.count-1) "
                + "type \(type) status 0x\(String(format:"%02X",frag.status))")
            peripheral.writeValue(frag.data,
                                  for: sendChar,
                                  type: .withResponse)
            if frag.isLast {               // last one: we’re done
                sendNextFragment(idx + 1)
            } else {
                // wait for Fragment-ACK from lock
                pendingAckHandler = { [weak self] ackStatus in
                    guard ackStatus == frag.status else { return }
                    self?.pendingAckHandler = nil
                    sendNextFragment(idx + 1)
                }
            }
        }
        sendNextFragment(0)
    }

    // MARK: -- Handshake -----------------------------------------------------

    /// Ensure connection + notification subscription
    private func ensureConnected() {
        guard connState == .disconnected else { return }
        central?.scanForPeripherals(withServices: [Self.serviceUUID], options: nil)
        print("🔍  Scanning for Eqiva lock …")
    }

    /// Ensure nonces exchanged (secure channel)
    private func ensureNonces() {
        guard connState == .connected else {  // already exchanging or done
            ensureConnected()
            return
        }

        // build the message just once
        if !pendingMessages.contains(where: { $0.0 == .connectionRequest }) {
            localNonce = (0..<8).map { _ in UInt8.random(in: 0...255) }

            // INSERT at index 0 instead of appending
            pendingMessages.insert((.connectionRequest,
                                    [userID] + localNonce,
                                    nil),
                                   at: 0)
        }
        flushQueue()
    }

    // MARK: -- Send command convenience -------------------------------------

    private func sendCommand(_ id: UInt8, expect expected: LockStatusID) {
        sendSecure(type: .command,
                   payload: [id]) { [weak self] in
            // optionally wait for status change if needed
            self?.expectedStatus = expected
        }
    }

    private var expectedStatus: LockStatusID?

    // MARK: -- Fragment ACK handling ----------------------------------------

    private var pendingAckHandler: ((UInt8) -> Void)?

    // MARK: -- Status update timer ------------------------------------------

    private var statusTimer: DispatchSourceTimer?
    private func restartStatusTimer() {
        statusTimer?.cancel()
        guard statusUpdateTime > 0 else { return }
        statusTimer = DispatchSource.makeTimerSource(queue: queue)
        statusTimer?.schedule(deadline: .now() + statusUpdateTime)
        statusTimer?.setEventHandler { [weak self] in self?.requestStatus() }
        statusTimer?.resume()
    }
}

// MARK: -- CBCentralManagerDelegate -----------------------------------------

extension KeyBle: CBCentralManagerDelegate {

    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard central.state == .poweredOn else { return }
        ensureConnected()
    }

    public func centralManager(_ c: CBCentralManager,
                               didDiscover p: CBPeripheral,
                               advertisementData: [String: Any],
                               rssi RSSI: NSNumber) {

        print("🔎  Found peripheral \(p.identifier) – connecting …")
        central?.stopScan()
        peripheral = p
        connState  = .connected
        p.delegate = self
        central?.connect(p, options: nil)
    }

    public func centralManager(_ c: CBCentralManager,
                               didConnect p: CBPeripheral) {

        print("✅  Connected – discovering services …")
        delegate?.keyBleDidConnect(self)
        p.discoverServices([Self.serviceUUID])
    }

    public func centralManager(_ c: CBCentralManager,
                               didFailToConnect p: CBPeripheral,
                               error: Error?) {
        print("❌  Connect failed: \(error?.localizedDescription ?? "unknown")")
    }

    public func centralManager(_ c: CBCentralManager,
                               didDisconnectPeripheral p: CBPeripheral,
                               error: Error?) {
        print("🔌  Disconnected")
        connState = .disconnected
        delegate?.keyBleDidDisconnect(self)
    }
}

// MARK: -- CBPeripheralDelegate ---------------------------------------------

extension KeyBle: CBPeripheralDelegate {

    public func peripheral(_ p: CBPeripheral, didDiscoverServices error: Error?) {
        if let s = p.services?.first(where: { $0.uuid == Self.serviceUUID }) {
            p.discoverCharacteristics([Self.sendUUID, Self.recvUUID], for: s)
        }
    }

    public func peripheral(_ p: CBPeripheral,
                           didDiscoverCharacteristicsFor s: CBService,
                           error: Error?) {

        for ch in s.characteristics ?? [] {
            if ch.uuid == Self.sendUUID { sendChar = ch }
            if ch.uuid == Self.recvUUID { recvChar = ch }
        }
        guard let recvChar = recvChar else { return }
        p.setNotifyValue(true, for: recvChar)
        print("📡  Notifications enabled – ready")
        restartStatusTimer()
    }

    public func peripheral(_ p: CBPeripheral,
                           didUpdateValueFor ch: CBCharacteristic,
                           error: Error?) {

        guard error == nil,
              let data = ch.value,
              let frag = Fragment(data: data)
        else { return }

        print("⬇️  Fragment status 0x\(String(format:"%02X", frag.status))")

        incomingFragments.append(frag)
        if frag.isLast { assembleMessage() }
    }

    // MARK: -- Assemble and process complete message ------------------------

    private func assembleMessage() {
        guard let first = incomingFragments.first,
              first.isFirst else { return }

        let typeID = first.body[0]
        let type   = MsgID(rawValue: typeID) ?? .fragmentAck
        let payload = incomingFragments.enumerated().flatMap { (i, f) -> [UInt8] in
            if i == 0 { return Array(f.body.dropFirst()) }
            return f.body
        }

        incomingFragments.removeAll()

        print("📨  Full message \(type) – \(payload.hex)")

        switch type {

        case .fragmentAck:
            if let handler = pendingAckHandler {
                handler(payload.first ?? 0)
            }

        case .connectionInfo:
            guard payload.count >= 11 else { return }
            userID      = payload[0]
            remoteNonce = Array(payload[1 ... 8])
            remoteCtr   = 0
            localCtr    = 1
            connState   = .noncesExchanged
            flushQueue()

        case .statusInfo:
            guard payload.count >= 6 else { return }

            let lockID = LockStatusID(rawValue: payload[2] & 0x07) ?? .unknown
            lockStatusID = lockID
            let status  = LockStatus(id: lockID,
                                     batteryLow: (payload[1] & 0x80) != 0,
                                     pairingAllowed: (payload[1] & 0x01) != 0)
            delegate?.keyBle(self, didUpdateStatus: status)
            if expectedStatus == lockID {
                delegate?.keyBle(self, didChangeStatus: status)
                expectedStatus = nil
            }
            restartStatusTimer()

        default:
            break
        }
    }
}

// MARK: -- Array<UInt8>(hex:) convenience initialiser -----------------------

private extension Array where Element == UInt8 {

    /// Parse hex string (any separators allowed) → byte array
    init(hex str: String) {
        let clean = str.replacingOccurrences(of: "[^0-9A-Fa-f]",
                                             with: "",
                                             options: .regularExpression)
        self.init()
        var idx = clean.startIndex
        while idx < clean.endIndex {
            let next = clean.index(idx, offsetBy: 2)
            let byte = UInt8(clean[idx ..< next], radix: 16)!
            self.append(byte)
            idx = next
        }
    }
}
