//
//  MessageTypes.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 01/06/2025.
//

import Foundation

// Message type IDs
enum MessageType: UInt8 {
    case connectionRequest   = 0x02
    case connectionInfo      = 0x03
    case closeConnection     = 0x06
    case command             = 0x87
    case statusRequest       = 0x82
    case statusInfo          = 0x83
    case statusChangedNotify = 0x05

    var isSecure: Bool {
        return (rawValue & 0x80) != 0
    }
}
