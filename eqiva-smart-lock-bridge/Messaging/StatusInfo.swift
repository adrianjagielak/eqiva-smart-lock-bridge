//
//  StatusInfo.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 01/06/2025.
//

import Foundation

/// Parsed STATUS_INFO message (type 0x83).
struct StatusInfo {
    let lockStatusID: UInt8  // 0=UNKNOWN,1=MOVING,2=UNLOCKED,3=LOCKED,4=OPENED
    let batteryLow: Bool
    let pairingAllowed: Bool
}

func parseStatusInfo(from data: Data) -> StatusInfo {
    let byte1 = data[1]
    let byte2 = data[2]
    let batteryLow = (byte1 & 0x80) != 0
    let pairingAllowed = (byte1 & 0x01) != 0
    let lockStatus = byte2 & 0x07
    return StatusInfo(lockStatusID: lockStatus, batteryLow: batteryLow, pairingAllowed: pairingAllowed)
}
