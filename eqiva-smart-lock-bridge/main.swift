//  A Swift reimplementation of eqiva-homekit-bridge.ts for macOS terminal,
//  using CoreBluetooth to communicate with an eQ-3/eqiva Bluetooth Smart Lock.
//  This program maintains a secure BLE connection to the lock, listens for
//  stdin commands ("lock", "unlock", "open", "status", "toggle"), and outputs
//  status updates to stdout. It automatically reconnects if disconnected.
//
//  Usage:
//    1. Fill in USER_ID and USER_KEY_HEX below.
//    2. Build with `swiftc EQivaBridge.swift -o EQivaBridge`
//    3. Run `./EQivaBridge`
//    4. Type commands (“lock”, “unlock”, “open”, “status”, “toggle”) followed by Enter.
//
//  Dependencies:
//    - CoreBluetooth
//    - CommonCrypto (for AES-ECB encryption)
//

import Foundation
import CoreBluetooth
import CommonCrypto

// MARK: ───────────────────────────────────────────────────────────────────────
// CONFIGURATION (fill in your own values here)
// ─────────────────────────────────────────────────────────────────────────────

// As returned from keyble-registeruser
let USER_ID: UInt8 = 123
let USER_KEY_HEX = "1234567890abcdef1234567890abcdef"  // 32-hex characters

// BLE Service & Characteristics UUIDs
let SERVICE_UUID = CBUUID(string: "58E06900-15D8-11E6-B737-0002A5D5C51B")
let SEND_CHAR_UUID = CBUUID(string: "3141DD40-15DB-11E6-A24B-0002A5D5C51B")
let RECV_CHAR_UUID = CBUUID(string: "359D4820-15DB-11E6-82BD-0002A5D5C51B")


// MARK: ───────────────────────────────────────────────────────────────────────
// GLOBAL VARIABLES
// ─────────────────────────────────────────────────────────────────────────────

var _macAddressUuid: UUID? = nil

// MARK: ───────────────────────────────────────────────────────────────────────
// UTILITIES: AES-ECB, Nonce & Auth computations
// ─────────────────────────────────────────────────────────────────────────────

fileprivate extension Data {
    /// XOR this Data with another Data (repeating the key as needed).
    func xor(with key: Data) -> Data {
        let result = zip(self, key.cycled(to: count)).map { $0 ^ $1 }
        return Data(result)
    }

    /// Repeat or truncate this Data to target length.
    func cycled(to length: Int) -> Data {
        guard !isEmpty else { return Data(repeating: 0, count: length) }
        var data = Data()
        while data.count < length {
            data.append(self)
        }
        if data.count > length {
            data = data.subdata(in: 0..<length)
        }
        return data
    }

    /// Pad this Data with zeros up to a multiple of blockSize.
    func padded(toMultipleOf blockSize: Int) -> Data {
        let remainder = count % blockSize
        guard remainder != 0 else { return self }
        let padLength = blockSize - remainder
        return self + Data(repeating: 0, count: padLength)
    }

    func hexEncodedString() -> String {
        return map { String(format: "%02x", $0) }.joined()
    }

    /// Initialize from hex string (e.g. "a1b2c3").
    init(hexString: String) {
        self.init()
        var hex = hexString
        hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            let byteString = hex[index..<nextIndex]
            if let num = UInt8(byteString, radix: 16) {
                self.append(num)
            }
            index = nextIndex
        }
    }
}

/// AES-128-ECB encryption of a single block (16 bytes) using CommonCrypto
func aes128EncryptBlock(_ block: Data, key: Data) -> Data {
    precondition(block.count == kCCBlockSizeAES128, "Block size must be 16 bytes")
    precondition(key.count == kCCKeySizeAES128, "Key size must be 16 bytes")

    var outData = Data(repeating: 0, count: kCCBlockSizeAES128)
    var numBytesEncrypted: size_t = 0

    let outDataCount = outData.count
    let status = outData.withUnsafeMutableBytes { outBytes in
        block.withUnsafeBytes { inBytes in
            key.withUnsafeBytes { keyBytes in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionECBMode),
                    keyBytes.baseAddress, key.count,
                    nil,
                    inBytes.baseAddress, block.count,
                    outBytes.baseAddress, outDataCount,
                    &numBytesEncrypted
                )
            }
        }
    }

    precondition(status == kCCSuccess, "AES encryption failed with status \(status)")
    return outData
}

/// Compute a 10-byte nonce: [messageTypeID (1B)] + sessionOpenNonce (8B) + [0x00, 0x00 (2B)] + securityCounter (2B)
func computeNonce(messageTypeID: UInt8, sessionOpenNonce: Data, securityCounter: UInt16) -> Data {
    var data = Data()
    data.append(messageTypeID)
    data.append(sessionOpenNonce)
    data.append(contentsOf: [0x00, 0x00])
    data.append(contentsOf: withUnsafeBytes(of: securityCounter.bigEndian) { Array($0) })
    return data
}

/// Encrypt or decrypt a Data array (arbitrary length) part of a secure message.
/// XOR against a keystream generated by AES-ECB(key, [0x01] + nonce + blockCounter).
func cryptData(_ data: Data, messageTypeID: UInt8, sessionOpenNonce: Data, securityCounter: UInt16, key: Data) -> Data {
    let nonce = computeNonce(messageTypeID: messageTypeID, sessionOpenNonce: sessionOpenNonce, securityCounter: securityCounter)
    let blockCount = Int(ceil(Double(data.count) / Double(kCCBlockSizeAES128)))
    var keystream = Data()

    for i in 0..<blockCount {
        let blockCounter = UInt16(i + 1).bigEndian
        var inputBlock = Data([0x01])
        inputBlock.append(nonce)
        inputBlock.append(contentsOf: withUnsafeBytes(of: blockCounter) { Array($0) })
        precondition(inputBlock.count == 1 + nonce.count + 2, "Invalid nonce construction")
        let keyStreamBlock = aes128EncryptBlock(inputBlock, key: key)
        keystream.append(keyStreamBlock)
    }

    return Data(zip(data, keystream).map { $0 ^ $1 })
}

/// Compute the 4-byte authentication value for a secure message.
/// Following the algorithm in keyble: AES-CMAC-like via ECB chaining.
func computeAuthenticationValue(data: Data, messageTypeID: UInt8, sessionOpenNonce: Data, securityCounter: UInt16, key: Data) -> Data {
    let nonce = computeNonce(messageTypeID: messageTypeID, sessionOpenNonce: sessionOpenNonce, securityCounter: securityCounter)
    let paddedData = data.padded(toMultipleOf: 16)
    let dataLengthBE = withUnsafeBytes(of: UInt16(data.count).bigEndian) { Data($0) }

    // Initial vector: [0x09] + nonce + dataLengthBE
    var iv = Data([0x09])
    iv.append(nonce)
    iv.append(dataLengthBE)
    precondition(iv.count == 1 + nonce.count + dataLengthBE.count)

    // Encrypt IV
    var encrypted = aes128EncryptBlock(iv, key: key)

    // Process each 16-byte block of paddedData
    for chunkStart in stride(from: 0, to: paddedData.count, by: 16) {
        let block = paddedData.subdata(in: chunkStart..<(chunkStart + 16))
        let xored = Data(zip(encrypted, block).map { $0 ^ $1 })
        encrypted = aes128EncryptBlock(xored, key: key)
    }

    // Calculate final: encrypted[0..<4] XOR AES-ECB([0x01] + nonce + [0x00,0x00], key)
    var iv2 = Data([0x01])
    iv2.append(nonce)
    iv2.append(contentsOf: [0x00, 0x00])
    let encrypted2 = aes128EncryptBlock(iv2, key: key)
    let authValue = Data(zip(encrypted.prefix(4), encrypted2).map { $0 ^ $1 })
    return authValue  // 4 bytes
}

// ───────────────────────────────────────────────────────────────────────────────
// MESSAGE FRAGMENTATION / PARSING
// ───────────────────────────────────────────────────────────────────────────────

/// A BLE message fragment (15 bytes of payload + 1 status byte).
struct MessageFragment {
    let raw: Data  // 16 bytes: [statusByte][15 bytes payload]

    var statusByte: UInt8 { return raw[0] }
    var isFirst: Bool { return (statusByte & 0x80) != 0 }
    var remainingCount: Int { return Int(statusByte & 0x7F) }
    var isLast: Bool { return remainingCount == 0 }
    var dataPayload: Data {
        // If first fragment, the first payload byte is actually the message type
        if isFirst {
            return raw.subdata(in: 2..<raw.count)
        } else {
            return raw.subdata(in: 1..<raw.count)
        }
    }
}

/// Reconstruct a full message from fragments.
func assembleMessage(from fragments: [MessageFragment]) -> Data {
    var messageData = Data()
    for frag in fragments {
        messageData.append(frag.dataPayload)
    }
    return messageData
}

/// Helper to split Data into 15-byte chunks, each prefixed by status byte.
func fragmentMessage(typeID: UInt8, dataBytes: Data) -> [MessageFragment] {
    // Prepend typeID to dataBytes
    var full = Data([typeID]) + dataBytes
    // Split into chunks of 15 bytes
    var chunks: [Data] = []
    while !full.isEmpty {
        let slice = full.prefix(15)
        chunks.append(Data(slice))
        full.removeFirst(min(15, full.count))
    }
    let total = chunks.count
    var fragments: [MessageFragment] = []
    for (i, chunk) in chunks.enumerated() {
        let isFirst = (i == 0)
        let rem = total - 1 - i
        let status: UInt8 = (isFirst ? 0x80 : 0x00) | UInt8(rem & 0x7F)
        var raw = Data([status])
        // Pad chunk to 15 bytes if needed
        var padded = chunk
        if padded.count < 15 {
            padded.append(Data(repeating: 0, count: 15 - padded.count))
        }
        raw.append(padded)
        fragments.append(MessageFragment(raw: raw))
    }
    return fragments
}

// ───────────────────────────────────────────────────────────────────────────────
// MESSAGE TYPES (IDs) & Parsing
// ───────────────────────────────────────────────────────────────────────────────

// Message type IDs
enum MessageType: UInt8 {
    case answerWithoutSecurity = 0x01
    case connectionRequest      = 0x02
    case connectionInfo         = 0x03
    case pairRequest            = 0x04
    case statusChangedNotify    = 0x05
    case closeConnection        = 0x06
    case command                = 0x87
    case statusRequest          = 0x82
    case statusInfo             = 0x83
    case userNameSet            = 0x90
    // ... add other types as needed
}

/// Parsed status info fields
struct StatusInfo {
    let lockStatusID: UInt8  // 0=UNKNOWN,1=MOVING,2=UNLOCKED,3=LOCKED,4=OPENED
    let batteryLow: Bool
    let pairingAllowed: Bool
}

/// Parse STATUS_INFO message (type 0x83)
func parseStatusInfo(from data: Data) -> StatusInfo {
    // data bytes: [byte0, byte1, byte2, ...]
    // batteryLow = (byte1 & 0x80) != 0
    // pairingAllowed = (byte1 & 0x01) != 0
    // lockStatus = byte2 & 0x07
    let byte1 = data[1]
    let byte2 = data[2]
    let batteryLow = (byte1 & 0x80) != 0
    let pairingAllowed = (byte1 & 0x01) != 0
    let lockStatus = byte2 & 0x07
    return StatusInfo(lockStatusID: lockStatus, batteryLow: batteryLow, pairingAllowed: pairingAllowed)
}

// ───────────────────────────────────────────────────────────────────────────────
// CORE CLASS: KeyBle
// ───────────────────────────────────────────────────────────────────────────────

class KeyBle: NSObject {
    // ───────────────────────────────────────────────────────────────────────────
    // CBCentralManager & CBPeripheral
    // ───────────────────────────────────────────────────────────────────────────
    private var centralManager: CBCentralManager!
    private var peripheral: CBPeripheral?

    // Characteristics
    private var sendChar: CBCharacteristic?
    private var recvChar: CBCharacteristic?

    // ───────────────────────────────────────────────────────────────────────────
    // STATE MACHINE
    // ───────────────────────────────────────────────────────────────────────────
    private enum ConnectionState: Int {
        case disconnected = 0
        case connected = 1
        case noncesExchanged = 2
    }
    private var state: ConnectionState = .disconnected

    // Once we've called `peripheral.setNotifyValue(true)` on `recvChar`, we set this to true in
    // didUpdateNotificationStateFor. That ensures we never send any secure fragment until notifications
    // are truly active.
    private var notificationsEnabled = false

    // Used to ensure we only trigger the first handshake once.
    private var handshakeStarted = false

    // ───────────────────────────────────────────────────────────────────────────
    // SECURITY
    // ───────────────────────────────────────────────────────────────────────────
    private var userID: UInt8
    private var userKey: Data
    private var localSessionNonce = Data()   // 8 bytes
    private var remoteSessionNonce = Data()  // 8 bytes
    private var localSecurityCounter: UInt16 = 1
    private var remoteSecurityCounter: UInt16 = 0

    // ───────────────────────────────────────────────────────────────────────────
    // FRAGMENT BUFFER
    // ───────────────────────────────────────────────────────────────────────────
    private var fragmentBuffer: [MessageFragment] = []

    // ───────────────────────────────────────────────────────────────────────────
    // STATUS
    // ───────────────────────────────────────────────────────────────────────────
    private var lockStatusID: UInt8?

    // ───────────────────────────────────────────────────────────────────────────
    // AUTO-RECONNECT
    // ───────────────────────────────────────────────────────────────────────────
    private var reconnectTimer: Timer?

    // ───────────────────────────────────────────────────────────────────────────
    // CALLBACKS (for external use)
    // ───────────────────────────────────────────────────────────────────────────
    /// Called once the peripheral is connected, before service/char discovery.
    var onConnected: (() -> Void)?
    /// Called once the peripheral is (re)disconnected.
    var onDisconnected: (() -> Void)?
    /// Called whenever a STATUS_INFO arrives (parsed JSON). Runs on main thread.
    var onStatusUpdate: ((StatusInfo) -> Void)?
    /// Called whenever lock state actually changes (e.g. UNLOCKED→LOCKED).
    var onStatusChange: ((StatusInfo) -> Void)?

    // ───────────────────────────────────────────────────────────────────────────
    // PROMISE‐LIKE CALLBACKS FOR MULTIPLE “ENSURE NONCES” CALLERS
    // ───────────────────────────────────────────────────────────────────────────
    /// Instead of a single `onConnectionInfo`, we store an array of callbacks.
    /// Every secure‐send that happens before nonces are exchanged will append here.
    private var onConnectionInfoCallbacks: [() -> Void] = []
    /// A serial queue to protect onConnectionInfoCallbacks.
    private let callbackQueue = DispatchQueue(label: "KeyBle.callbackQueue")

    // ───────────────────────────────────────────────────────────────────────────
    // SERIAL COMMAND QUEUE (to prevent overlapping sends)
    // ───────────────────────────────────────────────────────────────────────────
    /// All high‐level sends (`lock()`, `unlock()`, `requestStatus()`, etc.) are
    /// dispatched onto this serial queue, ensuring they run one at a time.
    private let commandQueue = DispatchQueue(label: "KeyBle.commandQueue")

    // ───────────────────────────────────────────────────────────────────────────
    // SEMAPHORE FOR FRAGMENT_ACK
    // ───────────────────────────────────────────────────────────────────────────
    private var fragmentAckSemaphore = DispatchSemaphore(value: 0)

    // ───────────────────────────────────────────────────────────────────────────
    // INITIALIZER
    // ───────────────────────────────────────────────────────────────────────────
    init(userID: UInt8, userKeyHex: String) {
        self.userID = userID
        self.userKey = Data(hexString: userKeyHex)
        super.init()
        // CoreBluetooth callbacks come on a background queue
        self.centralManager = CBCentralManager(delegate: self, queue: DispatchQueue.global(qos: .background))
    }

    // ───────────────────────────────────────────────────────────────────────────
    // PUBLIC API: START / DISCONNECT
    // ───────────────────────────────────────────────────────────────────────────
    /// Start scanning and connecting to the lock.
    func start() {
        if centralManager.state == .poweredOn {
            beginScan()
        } else {
            let stateDesc: String
            switch centralManager.state {
                case .unknown:      stateDesc = "unknown"
                case .resetting:    stateDesc = "resetting"
                case .unsupported:  stateDesc = "unsupported"
                case .unauthorized: stateDesc = "unauthorized"
                case .poweredOff:   stateDesc = "poweredOff"
                case .poweredOn:    stateDesc = "poweredOn"
                @unknown default:   stateDesc = "(!) <new state>"
            }
            print("[KeyBle] centralManager.state is “\(stateDesc)”, waiting…")
        }
    }

    func disconnect() {
        guard let p = peripheral else { return }
        // Send a clean closeConnection (0x06), then cancel
        sendMessage(type: .closeConnection) {
            self.centralManager.cancelPeripheralConnection(p)
        }
    }

    // ───────────────────────────────────────────────────────────────────────────
    // AUTO‐RECONNECT
    // ───────────────────────────────────────────────────────────────────────────
    private func scheduleReconnect() {
        reconnectTimer?.invalidate()
        reconnectTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: false) { [weak self] _ in
            self?.start()
        }
    }

    // ───────────────────────────────────────────────────────────────────────────
    // SCANNING & CONNECTION
    // ───────────────────────────────────────────────────────────────────────────
    private func beginScan() {
        print("[KeyBle] Scanning for peripheral...")
        if let uuid = _macAddressUuid {
            let peripherals = centralManager.retrievePeripherals(withIdentifiers: [uuid])
            if let p = peripherals.first {
                self.peripheral = p
                centralManager.connect(p, options: nil)
                return
            }
        }
        // Either by service UUID or everything
        centralManager.scanForPeripherals(withServices: [SERVICE_UUID], options: nil)
    }

    // ───────────────────────────────────────────────────────────────────────────
    // HIGH‐LEVEL COMMANDS: enqueued onto commandQueue to serialize
    // ───────────────────────────────────────────────────────────────────────────
    func lock() {
        commandQueue.async {
            self.sendMessage(type: .command, payload: Data([0x00])) // 0=lock
        }
    }

    func unlock() {
        commandQueue.async {
            self.sendMessage(type: .command, payload: Data([0x01])) // 1=unlock
        }
    }

    func open() {
        commandQueue.async {
            if self.lockStatusID == 4 { return } // already open
            self.sendMessage(type: .command, payload: Data([0x02])) // 2=open
        }
    }

    func toggle() {
        commandQueue.async {
            guard let status = self.lockStatusID else {
                self.requestStatus()  // if unknown, just request status first
                return
            }
            switch status {
                case 2, 4: self.lock()   // if unlocked or opened, lock
                case 3:   self.unlock() // if locked, unlock
                default:  print("[KeyBle] Cannot toggle from status \(status)")
            }
        }
    }

    func requestStatus() {
        commandQueue.async {
            // Build timestamp [YY,MM,DD,hh,mm,ss]
            let now = Date()
            let cal = Calendar.current
            let year = UInt8(cal.component(.year, from: now) - 2000)
            let month = UInt8(cal.component(.month, from: now))
            let day = UInt8(cal.component(.day, from: now))
            let hour = UInt8(cal.component(.hour, from: now))
            let minute = UInt8(cal.component(.minute, from: now))
            let second = UInt8(cal.component(.second, from: now))
            let payload = Data([year, month, day, hour, minute, second])
            self.sendMessage(type: .statusRequest, payload: payload)
        }
    }

    // ───────────────────────────────────────────────────────────────────────────
    // INTERNAL: SEND A MESSAGE (handles both secure & insecure)
    // ───────────────────────────────────────────────────────────────────────────
    private func sendMessage(type: MessageType, payload: Data? = nil, completion: (() -> Void)? = nil) {
        let isSecure = (type.rawValue & 0x80) != 0

        func logMessageSent() {
            switch type {
                case .command:
                    let byte = payload?.first ?? 0xff
                    print("[KeyBle] ⬆️ Sending COMMAND payload: \(String(format: "%02x", byte))")
                case .statusRequest:
                    print("[KeyBle] ⬆️ Sending STATUS_REQUEST (encrypted)…")
                case .connectionRequest:
                    print("[KeyBle] ⬆️ Sending CONNECTION_REQUEST payload: \(payload?.hexEncodedString() ?? "")")
                default:
                    break
            }
        }

        var dataBytes = Data()
        if isSecure {
            // Secure: first ensure nonces are exchanged
            ensureNoncesExchanged { [weak self] in
                guard let self = self else { return }
                // Now state ≥ .noncesExchanged, so we can encrypt the payload
                let plainData = payload ?? Data()
                let padded = plainData.padded(toMultipleOf: 15)
                let crypted = cryptData(
                    padded,
                    messageTypeID: type.rawValue,
                    sessionOpenNonce: self.remoteSessionNonce,
                    securityCounter: self.localSecurityCounter,
                    key: self.userKey
                )
                var bytes = Data(crypted)
                // Append 2-byte counter (big endian) and 4-byte auth
                let scBE = self.localSecurityCounter.bigEndian
                bytes.append(contentsOf: withUnsafeBytes(of: scBE) { Array($0) })
                let auth = computeAuthenticationValue(
                    data: padded,
                    messageTypeID: type.rawValue,
                    sessionOpenNonce: self.remoteSessionNonce,
                    securityCounter: self.localSecurityCounter,
                    key: self.userKey
                )
                bytes.append(auth)
                self.localSecurityCounter &+= 1

                dataBytes = bytes
                logMessageSent()
                self._sendFragments(typeID: type.rawValue, dataBytes: dataBytes, completion: completion)
            }
        } else {
            // Unsecured: only ensure connected, then send raw
            ensureConnected { [weak self] in
                guard let self = self else { return }
                dataBytes = payload ?? Data()
                logMessageSent()
                self._sendFragments(typeID: type.rawValue, dataBytes: dataBytes, completion: completion)
            }
        }
    }

    /// Internal: Break into fragments and write them sequentially, waiting for FRAGMENT_ACK between non-last fragments.
    private func _sendFragments(typeID: UInt8, dataBytes: Data, completion: (() -> Void)?) {
        print("[KeyBle] About to send fragment: typeID: \(String(format: "%02x", typeID)), dataBytes: \(dataBytes.hexEncodedString())")
        guard let sendC = sendChar, let peripheral = peripheral else { return }
        let fragments = fragmentMessage(typeID: typeID, dataBytes: dataBytes)

        let group = DispatchGroup()
        for frag in fragments {
            group.enter()
            print("[KeyBle] Sending fragment: typeID: \(String(format: "%02x", typeID)), dataBytes: \(dataBytes.hexEncodedString())")
            peripheral.writeValue(frag.raw, for: sendC, type: .withResponse)
            // Always wait for the lock’s FRAGMENT_ACK, even if this is the last fragment
            waitForFragmentAck {
                group.leave()
            }
            group.wait()
        }
        group.notify(queue: DispatchQueue.global()) {
            completion?()
        }
    }

    /// Semaphore-style wait for next FRAGMENT_ACK.
    private func waitForFragmentAck(completion: @escaping () -> Void) {
        DispatchQueue.global().async {
            self.fragmentAckSemaphore.wait()
            completion()
        }
    }

    // ───────────────────────────────────────────────────────────────────────────
    // ENSURE CONNECTED & ENSURE NONCES EXCHANGED
    // ───────────────────────────────────────────────────────────────────────────
    private func ensureConnected(completion: @escaping () -> Void) {
        if state.rawValue >= ConnectionState.connected.rawValue {
            completion()
        } else {
            // Wait until didConnect calls onConnected
            onConnected = {
                completion()
            }
        }
    }

    private func ensureNoncesExchanged(completion: @escaping () -> Void) {
        if state.rawValue >= ConnectionState.noncesExchanged.rawValue {
            completion()
        } else {
            // We haven't yet sent a CONNECTION_REQUEST or received CONNECTION_INFO.
            // Generate a local nonce, send unencrypted CONNECTION_REQUEST, then push the
            // `completion` onto onConnectionInfoCallbacks so that when CONNECTION_INFO arrives,
            // all pending callers get unblocked.
            localSessionNonce = Data((0..<8).map { _ in UInt8.random(in: 0...255) })
            let payload = Data([userID]) + localSessionNonce

            // Enqueue the completion into our array:
            callbackQueue.sync {
                self.onConnectionInfoCallbacks.append(completion)
            }

            // Now send the unencrypted CONNECTION_REQUEST. We do not block here—once the lock
            // replies with CONNECTION_INFO, dispatchMessage(type: .connectionInfo) will fire all callbacks.
            sendMessage(type: .connectionRequest, payload: payload)
        }
    }

    // ───────────────────────────────────────────────────────────────────────────
    // CBCentralManagerDelegate & CBPeripheralDelegate
    // ───────────────────────────────────────────────────────────────────────────
}

extension KeyBle: CBCentralManagerDelegate, CBPeripheralDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        let stateDesc: String
        switch central.state {
            case .unknown:      stateDesc = "unknown"
            case .resetting:    stateDesc = "resetting"
            case .unsupported:  stateDesc = "unsupported"
            case .unauthorized: stateDesc = "unauthorized"
            case .poweredOff:   stateDesc = "poweredOff"
            case .poweredOn:    stateDesc = "poweredOn"
            @unknown default:   stateDesc = "(!) <new state>"
        }
        print("[KeyBle] centralManagerDidUpdateState: \(stateDesc)")
        if central.state == .poweredOn {
            beginScan()
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String : Any], rssi RSSI: NSNumber) {
        self.peripheral = peripheral
        central.stopScan()
        peripheral.delegate = self
        let nameDesc = peripheral.name ?? "(no name)"
        print("[KeyBle] Discovered “\(nameDesc)” @ \(peripheral.identifier.uuidString), attempting to connect…")
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        _macAddressUuid = peripheral.identifier
        state = .connected
        print("[KeyBle] Connected to \(peripheral.identifier.uuidString)")
        onConnected?()
        onConnected = nil
        peripheral.discoverServices([SERVICE_UUID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        print("[KeyBle] Failed to connect: \(error?.localizedDescription ?? "unknown")")
        state = .disconnected
        scheduleReconnect()
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        print("[KeyBle] Disconnected")
        state = .disconnected
        onDisconnected?()
        onDisconnected = nil
        // Reset flags so that if we reconnect afresh, we’ll redo handshake
        notificationsEnabled = false
        handshakeStarted = false
        // Clear any pending onConnectionInfoCallbacks (they should all error out)
        callbackQueue.sync { self.onConnectionInfoCallbacks.removeAll() }
        scheduleReconnect()
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil else {
            print("[KeyBle] Service discovery failed: \(error!.localizedDescription)")
            return
        }
        guard let services = peripheral.services else { return }
        for srv in services where srv.uuid == SERVICE_UUID {
            peripheral.discoverCharacteristics([SEND_CHAR_UUID, RECV_CHAR_UUID], for: srv)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard error == nil else {
            print("[KeyBle] Char discovery failed: \(error!.localizedDescription)")
            return
        }
        guard let chars = service.characteristics else { return }
        for ch in chars {
            if ch.uuid == SEND_CHAR_UUID {
                sendChar = ch
            } else if ch.uuid == RECV_CHAR_UUID {
                recvChar = ch
            }
        }
        // As soon as we find recvChar, request notifications. We do NOT send any secure fragment until
        // didUpdateNotificationStateFor tells us `isNotifying == true`.
        if let recv = recvChar {
            peripheral.setNotifyValue(true, for: recv)
        }
        print("[KeyBle] Ready for communication")
    }

    func peripheral(_ peripheral: CBPeripheral,
                    didUpdateNotificationStateFor characteristic: CBCharacteristic,
                    error: Error?) {
        if let err = error {
            print("[KeyBle] Notification state failed: \(err.localizedDescription)")
            return
        }
        guard characteristic.uuid == recvChar?.uuid else { return }

        if characteristic.isNotifying {
            // Now iOS is truly subscribed to notifications on recvChar.
            print("[KeyBle] ✅ Notifications enabled on recvChar.")
            notificationsEnabled = true

            // If we’ve never started the handshake yet, do so now:
            if state == .connected && !handshakeStarted {
                handshakeStarted = true
                // Kick off one STATUS_REQUEST (this will trigger ensureNoncesExchanged → CONNECTION_REQUEST).
                print("[KeyBle] ▶︎ Automatically kicking off nonce‐handshake (Status Request)…")
                requestStatus()
            }

            // If state ≥ .noncesExchanged, it means we've just handled CONNECTION_INFO but were waiting
            // on notifications. Now that notifications are on, run all pending callbacks.
            if state.rawValue >= ConnectionState.noncesExchanged.rawValue {
                callbackQueue.sync {
                    for cb in self.onConnectionInfoCallbacks {
                        cb()
                    }
                    self.onConnectionInfoCallbacks.removeAll()
                }
            }
        } else {
            print("[KeyBle] ⚠️ Notifications disabled on recvChar unexpectedly.")
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard error == nil, let data = characteristic.value else {
            print("[KeyBle] didUpdateValueFor error: \(error!.localizedDescription)")
            return
        }

        // 1) Print raw fragment
        print("[KeyBle] ⬇️ Raw fragment: \(data.hexEncodedString())")

        // 2) If this is FRAGMENT_ACK (raw[1] == 0x00), signal semaphore and return:
        let rawBytes = [UInt8](data)
        if rawBytes.count >= 2 && rawBytes[1] == 0x00 {
            // FRAGMENT_ACK has arrived
            fragmentAckSemaphore.signal()
            return
        }

        // 3) Otherwise, parse it as a normal fragment
        let fragment = MessageFragment(raw: data)
        print("""
            [KeyBle]   Fragment → isFirst:\(fragment.isFirst) \
            remaining:\(fragment.remainingCount)  payload:\(fragment.dataPayload.hexEncodedString())
            """)

        fragmentBuffer.append(fragment)
        if fragment.isLast {
            let full = assembleMessage(from: fragmentBuffer)
            fragmentBuffer.removeAll()
            print("[KeyBle]   Assembled full message: \(full.hexEncodedString())")
            handleDecodedMessage(full)
        }
    }

    func peripheral(_ peripheral: CBPeripheral,
                    didWriteValueFor characteristic: CBCharacteristic,
                    error: Error?) {
        if let err = error {
            print("[KeyBle] ⚠️ ERROR writing to \(characteristic.uuid.uuidString): \(err.localizedDescription)")
        } else {
            print("[KeyBle] didWriteValueFor \(characteristic.uuid.uuidString) (OK)")
        }
    }

    // ───────────────────────────────────────────────────────────────────────────
    // MESSAGE HANDLING
    // ───────────────────────────────────────────────────────────────────────────
    private func handleDecodedMessage(_ data: Data) {
        guard data.count >= 1 else {
            print("[KeyBle] ⚠️ handleDecodedMessage got <1 byte, ignoring")
            return
        }
        let typeID = data[0]
        let payload = data.advanced(by: 1)
        print("[KeyBle] ▶︎ Dispatching message type=0x\(String(format: "%02x", typeID)), rawPayload=\(payload.hexEncodedString())")

        if (typeID & 0x80) != 0 {
            // Secure message: decrypt + auth
            guard payload.count >= 6 else {
                print("[KeyBle]   ⚠️ Secure payload <6 bytes, ignoring")
                return
            }
            let counterBE = payload.subdata(in: (payload.count - 6)..<(payload.count - 4))
            let msgCounter = UInt16(bigEndian: counterBE.withUnsafeBytes { $0.load(as: UInt16.self) })
            let msgAuth = payload.subdata(in: (payload.count - 4)..<payload.count)
            let encData = payload.subdata(in: 0..<(payload.count - 6))

            print("[KeyBle]   Secure → encData=\(encData.hexEncodedString()) counter=\(msgCounter) auth=\(msgAuth.hexEncodedString())")

            // Decrypt
            let decrypted = cryptData(
                encData,
                messageTypeID: typeID,
                sessionOpenNonce: localSessionNonce,
                securityCounter: msgCounter,
                key: userKey
            )
            let computedAuth = computeAuthenticationValue(
                data: decrypted,
                messageTypeID: typeID,
                sessionOpenNonce: localSessionNonce,
                securityCounter: msgCounter,
                key: userKey
            )
            if msgAuth != computedAuth {
                print("[KeyBle]   ⚠️ Invalid authentication: got \(msgAuth.hexEncodedString()), expected \(computedAuth.hexEncodedString())")
                return
            }
            remoteSecurityCounter = msgCounter
            print("[KeyBle]   Decrypted payload for type=0x\(String(format: "%02x", typeID)): \(decrypted.hexEncodedString())")
            dispatchMessage(typeID: typeID, payload: decrypted)
        } else {
            // Unsecured
            dispatchMessage(typeID: typeID, payload: payload)
        }
    }

    private func dispatchMessage(typeID: UInt8, payload: Data) {
        guard let msgType = MessageType(rawValue: typeID) else {
            print("[KeyBle]   ⚠️ Unknown message type 0x\(String(format: "%02x", typeID))")
            return
        }
        switch msgType {
            case .connectionInfo:
                // payload: [userID(1B), remoteNonce(8B), bootldrVer(1B), appVer(1B)]
                guard payload.count >= 10 else { return }
                print("[KeyBle] ◀︎ Received CONNECTION_INFO payload: \(payload.hexEncodedString())")

                // 1) Extract remote nonce, reset counters
                remoteSessionNonce = payload.subdata(in: 1..<9)
                localSecurityCounter = 1
                remoteSecurityCounter = 0
                state = .noncesExchanged

                // 2) Now that we have the lock’s nonce, re-subscribe to notifications
                //    so that we’re guaranteed to catch FRAGMENT_ACK for the encrypted STATUS_REQUEST.
                if let recv = recvChar {
                    peripheral?.setNotifyValue(true, for: recv)
                    print("[KeyBle] ▶︎ Re-subscribing for notifications (post-handshake)…")
                }

                // Do NOT fire callbacks here.  Wait until didUpdateNotificationStateFor sees isNotifying.

        case .statusInfo:
                print("[KeyBle] ◀︎ Received STATUS_INFO payload: \(payload.hexEncodedString())")
                let status = parseStatusInfo(from: payload)
                DispatchQueue.main.async {
                    self.onStatusUpdate?(status)
                    if self.lockStatusID != status.lockStatusID {
                        self.lockStatusID = status.lockStatusID
                        self.onStatusChange?(status)
                    }
                }
                // If you want periodic polling, schedule it _here_ after receiving a valid STATUS_INFO:
                // DispatchQueue.main.asyncAfter(deadline: .now() + 30) { self.requestStatus() }

            case .statusChangedNotify:
                print("[KeyBle] ◀︎ Received STATUS_CHANGED_NOTIFY")
                // On a notify, immediately enqueue another requestStatus
                self.requestStatus()

            default:
                print("[KeyBle]   ⚠️ Unhandled msgType=\(msgType) (0x\(String(format: "%02x", typeID)))")
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────────
// MAIN CLI LOGIC
// ───────────────────────────────────────────────────────────────────────────────

let keyBle = KeyBle(userID: USER_ID, userKeyHex: USER_KEY_HEX)

var shouldKeepRunning = true

// Handle status updates
keyBle.onStatusUpdate = { status in
    let lockState: String
    switch status.lockStatusID {
        case 0: lockState = "UNKNOWN"
        case 1: lockState = "MOVING"
        case 2: lockState = "UNLOCKED"
        case 3: lockState = "LOCKED"
        case 4: lockState = "OPENED"
        default: lockState = "INVALID"
    }
    let battery = status.batteryLow ? "LOW" : "OK"
    let pairing = status.pairingAllowed ? "YES" : "NO"
    let output: [String: String] = [
        "lock_status": lockState,
        "battery": battery,
        "pairing_allowed": pairing
    ]
    if let json = try? JSONSerialization.data(withJSONObject: output, options: []),
       let str = String(data: json, encoding: .utf8) {
        print("[StatusUpdate] \(str)")
    } else {
        print("[StatusUpdate] status=\(lockState) battery=\(battery) pairing=\(pairing)")
    }
}

// Handle status changes (optional)
keyBle.onStatusChange = { status in
    // Already printed by onStatusUpdate, but you could do extra logic here.
}

// Start connection
keyBle.start()

// Simulate incoming requests (TODO DEBUG)
DispatchQueue.main.asyncAfter(deadline: .now() + 20) {
    print("[KeyBle] (TODO DEBUG) calling requestStatus()")
    keyBle.requestStatus()
}
DispatchQueue.main.asyncAfter(deadline: .now() + 50) {
    print("[KeyBle] (TODO DEBUG) calling unlock()")
    keyBle.unlock()
}
DispatchQueue.main.asyncAfter(deadline: .now() + 70) {
    print("[KeyBle] (TODO DEBUG) calling lock()")
    keyBle.lock()
}

// Read stdin in background (external commands)
DispatchQueue.global(qos: .background).async {
    let input = FileHandle.standardInput
    while shouldKeepRunning {
        if let lineData = try? input.read(upToCount: 1024), !lineData.isEmpty {
            if let cmd = String(data: lineData, encoding: .utf8)?
                                .trimmingCharacters(in: .whitespacesAndNewlines)
                                .lowercased() {
                switch cmd {
                    case "lock":
                        keyBle.lock()
                    case "unlock":
                        keyBle.unlock()
                    case "open":
                        keyBle.open()
                    case "status":
                        keyBle.requestStatus()
                    case "toggle":
                        keyBle.toggle()
                    case "exit", "quit":
                        shouldKeepRunning = false
                        keyBle.disconnect()
                        exit(0)
                    default:
                        print("[CLI] Unknown command: \(cmd)")
                }
            }
        } else {
            // stdin closed or EOF
            shouldKeepRunning = false
            keyBle.disconnect()
            exit(0)
        }
    }
}

// Keep the RunLoop alive
RunLoop.main.run()
