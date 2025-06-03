//  main.swift
//  EqivaLockController
//  Created: 2025‑06‑03 by ChatGPT
//
//  A robust command‑line controller for the Eqiva eQ‑3 BLE smart lock.
//  – Handles BLE connection + automatic reconnect
//  – Bridges the lock over WebSocket to a Node.js HomeKit bridge
//  – Requires Swift 5.7+ and Foundation (Linux or macOS)
//
//  IMPORTANT:  Replace `userKeyHex` with your real key before building.
//

import Foundation

// MARK: ‑‑ Configuration ‑‑

private let userKeyHex = "1234567890abcdef1234567890abcdef"
private let userID: UInt8 = 123
private let webSocketURL = URL(string: "ws://localhost:9099")!

// MARK: ‑‑ Helper Types ‑‑

private struct StatusMessage: Codable {
    let state: String
    let batteryLow: Bool
    let timestamp: Date
}

private enum IncomingCommand: String {
    case lock, unlock, open

    var eqiva: EqivaCommand {
        switch self {
        case .lock:   return .lock
        case .unlock: return .unlock
        case .open:   return .open
        }
    }
}

// MARK: ‑‑ SmartLockController ‑‑

final class SmartLockController: NSObject {

    // BLE
    fileprivate let lock: EqivaLock
    private var lockConnected: Bool = false
    private let lockReconnectDelay: TimeInterval = 5 // 5s

    // WebSocket
    private lazy var urlSession: URLSession = {
        let cfg = URLSessionConfiguration.default
        cfg.waitsForConnectivity = true
        return URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
    }()
    private var wsTask: URLSessionWebSocketTask?
    private let wsReconnectDelay: TimeInterval = 5 // 5s
    private var wsReconnectTask: DispatchWorkItem?

    // Serial work queue keeps state changes thread‑safe.
    private let queue = DispatchQueue(label: "EqivaLockController")

    // Store commands issued while the lock is offline.
    private var pendingCommands: [EqivaCommand] = []

    // MARK: Init / start

    init(userKeyHex: String, userID: UInt8) {
        self.lock = EqivaLock(userKeyHex: userKeyHex, userID: userID)
        super.init()
        self.lock.delegate = self
    }

    func start() {
        queue.async {
            self.connectLock()
            self.connectWebSocket()
        }
    }
}

// MARK: ‑‑ EqivaLockDelegate (BLE) ‑‑

extension SmartLockController: EqivaLockDelegate {
    func eqivaLockDidConnect(_ lock: EqivaLock) {
        print("\(logTimestamp()) 🔒 Lock connected")
        lockConnected = true
        flushPending()
        lock.getStatus { _ in }
    }

    func eqivaLockDidDisconnect(_ lock: EqivaLock) {
        print("\(logTimestamp()) ⚠️  Lock disconnected")
        lockConnected = false
        scheduleLockReconnect()
    }

    func eqivaLock(_ lock: EqivaLock, didUpdateStatus status: LockStatus) {
        send(status: status)
    }

    private func connectLock() {
        print("\(logTimestamp()) 🔍 Connecting to lock…")
        lock.connect { [weak self] result in
            guard let self else { return }
            if case .failure(let err) = result {
                print("\(logTimestamp()) ❌ Lock connect failed: \(err.localizedDescription)")
                self.scheduleLockReconnect()
            }
        }
    }

    private func scheduleLockReconnect() {
        print("\(logTimestamp()) ⏳ Reconnecting lock in \(Int(lockReconnectDelay)) s")
        queue.asyncAfter(deadline: .now() + lockReconnectDelay) { [weak self] in
            self?.connectLock()
        }
    }

    private func flushPending() {
        guard !pendingCommands.isEmpty else { return }
        pendingCommands.forEach { dispatch($0) }
        pendingCommands.removeAll()
    }

    private func dispatch(_ cmd: EqivaCommand) {
        lock.send(cmd) { [weak self] result in
            if case .failure(let err) = result {
                print("\(logTimestamp()) ❌ Failed to send command: \(err.localizedDescription)")
            } else if case .success(let status) = result {
                self?.send(status: status)
            }
        }
    }
}

// MARK: ‑‑ URLSessionWebSocketDelegate ‑‑

extension SmartLockController: URLSessionWebSocketDelegate {

    private func connectWebSocket() {
        print("\(logTimestamp()) 🌐 Connecting WebSocket → \(webSocketURL.absoluteString)…")
        wsTask = urlSession.webSocketTask(with: webSocketURL)
        wsTask?.resume()
        listen()
    }

    private func listen() {
        wsTask?.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let msg):
                switch msg {
                case .string(let str):
                    handleCommand(str)
                case .data(let data):
                    if let str = String(data: data, encoding: .utf8) {
                        handleCommand(str)
                    }
                @unknown default: break
                }
                listen()
            case .failure(let err):
                print("\(logTimestamp()) ❌ WebSocket error: \(err.localizedDescription)")
                wsTask?.cancel()
                scheduleWSReconnect()
            }
        }
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask,
                            didOpenWithProtocol protocol: String?) {
        print("\(logTimestamp()) ✅ WebSocket connected")
        wsReconnectTask?.cancel()
        lock.getStatus { _ in }
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask,
                            didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        print("\(logTimestamp()) ⚠️  WebSocket closed (code \(closeCode.rawValue))")
        scheduleWSReconnect()
    }

    private func scheduleWSReconnect() {
        print("\(logTimestamp()) ⏳ Reconnecting WebSocket in \(Int(wsReconnectDelay)) s")

        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }

            wsTask?.cancel(with: .goingAway, reason: nil)
            wsTask = nil
            
            self.scheduleWSReconnect()
            self.connectWebSocket()
        }

        wsReconnectTask?.cancel()
        wsReconnectTask = work
        queue.asyncAfter(deadline: .now() + wsReconnectDelay, execute: work)
    }

    private func handleCommand(_ raw: String) {
        guard let cmd = IncomingCommand(rawValue: raw.lowercased()) else {
            print("\(logTimestamp()) ⚠️  Unknown command ‘\(raw)’ received via WebSocket")
            return
        }
        queue.async { [weak self] in
            guard let self else { return }
            if lockConnected {
                dispatch(cmd.eqiva)
            } else {
                pendingCommands.append(cmd.eqiva)
            }
        }
    }

    // Send status → WS
    private func send(status: LockStatus) {
        let msg = StatusMessage(state: status.state.description,
                                batteryLow: status.batteryLow,
                                timestamp: Date())
        guard let data = try? JSONEncoder().encode(msg),
              let str = String(data: data, encoding: .utf8) else { return }
        wsTask?.send(.string(str)) { err in
            if let err { print("\(logTimestamp()) ❌ WS send failed: \(err.localizedDescription)") }
        }
    }
}

// MARK: ‑‑ Convenience ‑‑

private extension LockState {
    var description: String {
        switch self {
        case .unknownProbablyJammed: return "unknownProbablyJammed"
        case .moving:                return "moving"
        case .unlocked:              return "unlocked"
        case .locked:                return "locked"
        case .opened:                return "opened"
        case .trulyUnkonwn:          return "trulyUnkonwn"
        @unknown default:            return "trulyUnkonwn"
        }
    }
}

// MARK: ‑‑ Main ‑‑

let controller = SmartLockController(userKeyHex: userKeyHex, userID: userID)
controller.start()


func _ping(){
    DispatchQueue.main.asyncAfter(deadline: .now() + 60) {
        print("\(logTimestamp()) Ping")
        if         controller.lock.state == .ready || controller.lock.state == .secured {
            controller.lock.getStatus { _ in }
        }

        _ping()
    }
}
_ping()

RunLoop.main.run()
