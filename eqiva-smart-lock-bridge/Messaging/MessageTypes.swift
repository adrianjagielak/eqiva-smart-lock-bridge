//
//  MessageTypes.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 01/06/2025.
//

import Foundation

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
