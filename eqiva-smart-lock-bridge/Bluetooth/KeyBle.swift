//
//  KeyBle.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 01/06/2025.
//

import Foundation
import CoreBluetooth

var macAddressUuid: UUID? = nil

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
    var lockStatusID: UInt8?

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
    let commandQueue = DispatchQueue(label: "KeyBle.commandQueue")

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
        if let uuid = macAddressUuid {
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
    // INTERNAL: SEND A MESSAGE (handles both secure & insecure)
    // ───────────────────────────────────────────────────────────────────────────
    func sendMessage(type: MessageType, payload: Data? = nil, completion: (() -> Void)? = nil) {
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
        macAddressUuid = peripheral.identifier
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
