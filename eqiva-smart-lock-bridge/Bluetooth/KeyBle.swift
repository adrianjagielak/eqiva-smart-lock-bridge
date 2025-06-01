// KeyBle.swift

import Foundation
import CoreBluetooth
import CommonCrypto

var macAddressUuid: UUID? = nil

class KeyBle: NSObject {
    // CoreBluetooth
    private var centralManager: CBCentralManager!
    private var peripheral: CBPeripheral?
    private var sendChar: CBCharacteristic?
    private var recvChar: CBCharacteristic?

    // Connection State
    private enum ConnectionState: Int {
        case disconnected = 0
        case connected = 1
        case noncesExchanged = 2
    }
    private var state: ConnectionState = .disconnected

    // Flags
    private var notificationsEnabled = false
    private var handshakeStarted = false

    // Security
    private let userID: UInt8
    private let userKey: Data
    private var localSessionNonce = Data()
    private var remoteSessionNonce = Data()
    private var localSecurityCounter: UInt16 = 1
    private var remoteSecurityCounter: UInt16 = 0

    // Fragment buffer for incoming
    private var fragmentBuffer: [MessageFragment] = []

    // Status
    var lockStatusID: UInt8?

    // Reconnect timer
    private var reconnectTimer: Timer?

    // Callbacks (external)
    var onConnected: (() -> Void)?
    var onDisconnected: (() -> Void)?
    var onStatusUpdate: ((StatusInfo) -> Void)?
    var onStatusChange: ((StatusInfo) -> Void)?

    // Queue for sending commands serially
    let commandQueue = DispatchQueue(label: "KeyBle.commandQueue")

    // Pending callbacks awaiting connectionInfo (post‐handshake)
    private var onConnectionInfoCallbacks: [() -> Void] = []
    private let callbackQueue = DispatchQueue(label: "KeyBle.callbackQueue")

    // Semaphore for fragment ACK
    private let fragmentAckSemaphore = DispatchSemaphore(value: 0)

    // BLE UUIDs
    private let SERVICE_UUID = CBUUID(string: "58E06900-15D8-11E6-B737-0002A5D5C51B")
    private let SEND_CHAR_UUID = CBUUID(string: "3141DD40-15DB-11E6-A24B-0002A5D5C51B")
    private let RECV_CHAR_UUID = CBUUID(string: "359D4820-15DB-11E6-82BD-0002A5D5C51B")

    init(userID: UInt8, userKeyHex: String) {
        self.userID = userID
        self.userKey = Data(hexString: userKeyHex)
        super.init()
        self.centralManager = CBCentralManager(delegate: self, queue: DispatchQueue.global(qos: .background))
    }

    // MARK: ───────────────────────────────────────────────────────────────────
    // PUBLIC API
    // ───────────────────────────────────────────────────────────────────────────

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
        sendMessage(type: .closeConnection) {
            self.centralManager.cancelPeripheralConnection(p)
        }
    }

    // MARK: ───────────────────────────────────────────────────────────────────
    // SCANNING & CONNECTION
    // ───────────────────────────────────────────────────────────────────────────

    private func beginScan() {
        print("[KeyBle] Scanning for lock…")
        if let uuid = macAddressUuid {
            let peripherals = centralManager.retrievePeripherals(withIdentifiers: [uuid])
            if let p = peripherals.first {
                self.peripheral = p
                centralManager.connect(p, options: nil)
                return
            }
        }
        centralManager.scanForPeripherals(withServices: [SERVICE_UUID], options: nil)
    }

    // MARK: ───────────────────────────────────────────────────────────────────
    // SENDING MESSAGES
    // ───────────────────────────────────────────────────────────────────────────

    func sendMessage(type: MessageType, payload: Data? = nil, completion: (() -> Void)? = nil) {
        let isSecure = type.isSecure
        if isSecure {
            ensureNoncesExchanged {
                self._encryptAndSend(type: type, payload: payload ?? Data(), completion: completion)
            }
        } else {
            ensureConnected {
                let dataBytes = payload ?? Data()
                self._sendRaw(typeID: type.rawValue, dataBytes: dataBytes, completion: completion)
            }
        }
    }

    private func _encryptAndSend(type: MessageType, payload: Data, completion: (() -> Void)?) {
        let plain = payload.padded(toMultipleOf: 15)
        let enc = cryptData(plain,
                            messageTypeID: type.rawValue,
                            sessionOpenNonce: remoteSessionNonce,
                            securityCounter: localSecurityCounter,
                            key: userKey)
        var msgData = Data(enc)
        let scBE = localSecurityCounter.bigEndian
        msgData.append(contentsOf: withUnsafeBytes(of: scBE) { Array($0) })
        let auth = computeAuthenticationValue(data: plain,
                                              messageTypeID: type.rawValue,
                                              sessionOpenNonce: remoteSessionNonce,
                                              securityCounter: localSecurityCounter,
                                              key: userKey)
        msgData.append(auth)
        localSecurityCounter &+= 1
        print("[KeyBle] ⬆️ Secure send \(type): \(msgData.hexEncodedString())")
        _sendRaw(typeID: type.rawValue, dataBytes: msgData, completion: completion)
    }

    private func _sendRaw(typeID: UInt8, dataBytes: Data, completion: (() -> Void)?) {
        guard let sendC = sendChar, let p = peripheral else { return }
        print("[KeyBle] ⬆️ Sending \(String(format: "%02x", typeID)) payload: \(dataBytes.hexEncodedString())")
        let fragments = fragmentMessage(typeID: typeID, dataBytes: dataBytes)
        let group = DispatchGroup()
        for frag in fragments {
            group.enter()
            p.writeValue(frag.raw, for: sendC, type: .withResponse)
            waitForFragmentAck {
                group.leave()
            }
            group.wait()
        }
        group.notify(queue: .global()) {
            completion?()
        }
    }

    private func waitForFragmentAck(completion: @escaping () -> Void) {
        DispatchQueue.global().async {
            self.fragmentAckSemaphore.wait()
            completion()
        }
    }

    // MARK: ───────────────────────────────────────────────────────────────────
    // ENSURE CONNECTED & ENSURE NONCES EXCHANGED
    // ───────────────────────────────────────────────────────────────────────────

    private func ensureConnected(completion: @escaping () -> Void) {
        if state.rawValue >= ConnectionState.connected.rawValue {
            completion()
        } else {
            onConnected = {
                completion()
            }
        }
    }

    private func ensureNoncesExchanged(completion: @escaping () -> Void) {
        if state.rawValue >= ConnectionState.noncesExchanged.rawValue {
            completion()
        } else {
            // Generate local nonce, enqueue callback, send unencrypted CONNECTION_REQUEST
            localSessionNonce = Data((0..<8).map { _ in UInt8.random(in: 0...255) })
            let payload = Data([userID]) + localSessionNonce

            callbackQueue.sync {
                self.onConnectionInfoCallbacks.append(completion)
            }

            // Send CONNECTION_REQUEST (unencrypted)
            _sendRaw(typeID: MessageType.connectionRequest.rawValue, dataBytes: payload, completion: nil)
            print("[KeyBle] ⬆️ Sending CONNECTION_REQUEST payload: \(payload.hexEncodedString())")
        }
    }

    // MARK: ───────────────────────────────────────────────────────────────────
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
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        central.stopScan()
        self.peripheral = peripheral
        peripheral.delegate = self
        let nameDesc = peripheral.name ?? "(no name)"
        print("[KeyBle] Discovered “\(nameDesc)” @ \(peripheral.identifier.uuidString), connecting…")
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
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
        notificationsEnabled = false
        handshakeStarted = false
        callbackQueue.sync { self.onConnectionInfoCallbacks.removeAll() }
        scheduleReconnect()
    }

    private func scheduleReconnect() {
        reconnectTimer?.invalidate()
        reconnectTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: false) { [weak self] _ in
            self?.start()
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard error == nil, let services = peripheral.services else {
            print("[KeyBle] Service discovery error: \(error?.localizedDescription ?? "unknown")")
            return
        }
        for s in services where s.uuid == SERVICE_UUID {
            peripheral.discoverCharacteristics([SEND_CHAR_UUID, RECV_CHAR_UUID], for: s)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard error == nil, let chars = service.characteristics else {
            print("[KeyBle] Char discovery error: \(error?.localizedDescription ?? "unknown")")
            return
        }
        for ch in chars {
            if ch.uuid == SEND_CHAR_UUID {
                sendChar = ch
            } else if ch.uuid == RECV_CHAR_UUID {
                recvChar = ch
            }
        }
        print("[KeyBle] Ready for communication")

        if let recv = recvChar {
            // Attempt to subscribe for notifications; if this fails, we’ll proceed anyway
            peripheral.setNotifyValue(true, for: recv)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if let err = error {
            print("[KeyBle] Notification state failed: \(err.localizedDescription)")
            // Even though subscribe failed, proceed as if notifications are enabled
            notificationsEnabled = true

            // Kick off handshake if connected but not started
            if state == .connected && !handshakeStarted {
                handshakeStarted = true
                print("[KeyBle] ▶︎ Handshake fallback: starting Status Request despite notification error…")
                requestStatus()
            }

            // If handshake already done, invoke pending callbacks
            if state.rawValue >= ConnectionState.noncesExchanged.rawValue {
                callbackQueue.sync {
                    for cb in self.onConnectionInfoCallbacks { cb() }
                    self.onConnectionInfoCallbacks.removeAll()
                }
            }
            return
        }
        guard characteristic.uuid == recvChar?.uuid else { return }

        if characteristic.isNotifying {
            print("[KeyBle] ✅ Notifications enabled")
            notificationsEnabled = true

            if state == .connected && !handshakeStarted {
                handshakeStarted = true
                print("[KeyBle] ▶︎ Starting handshake (Status Request)…")
                requestStatus()
            }

            if state.rawValue >= ConnectionState.noncesExchanged.rawValue {
                callbackQueue.sync {
                    for cb in self.onConnectionInfoCallbacks { cb() }
                    self.onConnectionInfoCallbacks.removeAll()
                }
            }
        } else {
            print("[KeyBle] ⚠️ Notifications disabled unexpectedly")
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard error == nil, let data = characteristic.value else {
            print("[KeyBle] didUpdateValueFor error: \(error?.localizedDescription ?? "unknown")")
            return
        }
        print("[KeyBle] ⬇️ Raw fragment: \(data.hexEncodedString())")

        let rawBytes = [UInt8](data)
        if rawBytes.count >= 2 && rawBytes[1] == 0x00 {
            // FRAGMENT_ACK
            fragmentAckSemaphore.signal()
            return
        }

        let fragment = MessageFragment(raw: data)
        print("[KeyBle]   Fragment → isFirst:\(fragment.isFirst) remaining:\(fragment.remainingCount) payload:\(fragment.dataPayload.hexEncodedString())")
        fragmentBuffer.append(fragment)
        if fragment.isLast {
            let full = assembleMessage(from: fragmentBuffer)
            fragmentBuffer.removeAll()
            print("[KeyBle]   Assembled full: \(full.hexEncodedString())")
            handleDecodedMessage(full)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        if let e = error {
            print("[KeyBle] Write error: \(e.localizedDescription)")
        } else {
            print("[KeyBle] didWriteValueFor \(characteristic.uuid.uuidString) (OK)")
        }
    }

    // MARK: ───────────────────────────────────────────────────────────────────
    // MESSAGE HANDLING
    // ───────────────────────────────────────────────────────────────────────────

    private func handleDecodedMessage(_ data: Data) {
        guard data.count >= 1 else { return }
        let typeID = data[0]
        let payload = data.advanced(by: 1)
        print("[KeyBle] ▶︎ Dispatching type=0x\(String(format: "%02x", typeID)), rawPayload=\(payload.hexEncodedString())")

        if (typeID & 0x80) != 0 {
            // Secure
            guard payload.count >= 6 else { return }
            let encData = payload.subdata(in: 0..<(payload.count - 6))
            let counterBE = payload.subdata(in: (payload.count - 6)..<(payload.count - 4))
            let msgCounter = UInt16(bigEndian: counterBE.withUnsafeBytes { $0.load(as: UInt16.self) })
            let msgAuth = payload.subdata(in: (payload.count - 4)..<payload.count)
            let decrypted = cryptData(encData,
                                      messageTypeID: UInt8(typeID),
                                      sessionOpenNonce: localSessionNonce,
                                      securityCounter: msgCounter,
                                      key: userKey)
            let computedAuth = computeAuthenticationValue(data: decrypted,
                                                          messageTypeID: UInt8(typeID),
                                                          sessionOpenNonce: localSessionNonce,
                                                          securityCounter: msgCounter,
                                                          key: userKey)
            if msgAuth != computedAuth {
                print("[KeyBle] ⚠️ Invalid auth, ignoring")
                return
            }
            remoteSecurityCounter = msgCounter
            print("[KeyBle]   Decrypted payload: \(decrypted.hexEncodedString())")
            dispatchMessage(typeID: typeID, payload: decrypted)
        } else {
            dispatchMessage(typeID: typeID, payload: payload)
        }
    }

    private func dispatchMessage(typeID: UInt8, payload: Data) {
        guard let msgType = MessageType(rawValue: typeID) else {
            print("[KeyBle] ⚠️ Unknown type 0x\(String(format: "%02x", typeID))")
            return
        }
        switch msgType {
            case .connectionInfo:
                guard payload.count >= 10 else { return }
                print("[KeyBle] ◀︎ Received CONNECTION_INFO: \(payload.hexEncodedString())")
                remoteSessionNonce = payload.subdata(in: 1..<9)
                localSecurityCounter = 1
                remoteSecurityCounter = 0
                state = .noncesExchanged

                if notificationsEnabled {
                    callbackQueue.sync {
                        for cb in self.onConnectionInfoCallbacks { cb() }
                        self.onConnectionInfoCallbacks.removeAll()
                    }
                }

            case .statusInfo:
                print("[KeyBle] ◀︎ Received STATUS_INFO: \(payload.hexEncodedString())")
                let status = parseStatusInfo(from: payload)
                DispatchQueue.main.async {
                    self.onStatusUpdate?(status)
                    if self.lockStatusID != status.lockStatusID {
                        self.lockStatusID = status.lockStatusID
                        self.onStatusChange?(status)
                    }
                }

            case .statusChangedNotify:
                print("[KeyBle] ◀︎ Received STATUS_CHANGED_NOTIFY")
                requestStatus()

            default:
                print("[KeyBle]   ⚠️ Unhandled msgType=\(msgType)")
        }
    }
}
