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

// ───────────────────────────────────────────────────────────────────────────────
// MAIN CLI LOGIC
// ───────────────────────────────────────────────────────────────────────────────

let keyBle = KeyBle(userID: USER_ID, userKeyHex: USER_KEY_HEX)

var shouldKeepRunning = true

//// Handle status updates
//keyBle.onStatusUpdate = { status in
////    let lockState: String
////    switch status.lockStatusID {
////        case 0: lockState = "UNKNOWN"
////        case 1: lockState = "MOVING"
////        case 2: lockState = "UNLOCKED"
////        case 3: lockState = "LOCKED"
////        case 4: lockState = "OPENED"
////        default: lockState = "INVALID"
////    }
////    let battery = status.batteryLow ? "LOW" : "OK"
////    let pairing = status.pairingAllowed ? "YES" : "NO"
////    let output: [String: String] = [
////        "lock_status": lockState,
////        "battery": battery,
////        "pairing_allowed": pairing
////    ]
////    if let json = try? JSONSerialization.data(withJSONObject: output, options: []),
////       let str = String(data: json, encoding: .utf8) {
////        print("[StatusUpdate] \(str)")
////    } else {
////        print("[StatusUpdate] status=\(lockState) battery=\(battery) pairing=\(pairing)")
////    }
//}

// Start connection
keyBle.start()
    
// Simulate incoming requests (TODO DEBUG)
DispatchQueue.main.asyncAfter(deadline: .now() + 20) {
        print("👨‍💻  Calling keyBle.requestStatus()")
         keyBle.requestStatus()
}
DispatchQueue.main.asyncAfter(deadline: .now() + 50) {
   print("👨‍💻  Calling keyBle.unlock()")
    keyBle.unlock()
}
DispatchQueue.main.asyncAfter(deadline: .now() + 70) {
   print("👨‍💻  Calling keyBle.lock()")
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
