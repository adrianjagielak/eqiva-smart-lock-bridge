//
//  Fragmentation.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 01/06/2025.
//

import Foundation

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
