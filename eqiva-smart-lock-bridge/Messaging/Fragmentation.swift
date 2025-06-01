//
//  Fragmentation.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 01/06/2025.
//

import Foundation

struct MessageFragment {
    let raw: Data  // 16 bytes: [statusByte][15 bytes payload]

    var statusByte: UInt8 { raw[0] }
    var isFirst: Bool { (statusByte & 0x80) != 0 }
    var remainingCount: Int { Int(statusByte & 0x7F) }
    var isLast: Bool { remainingCount == 0 }
    var dataPayload: Data {
        if isFirst {
            // First fragment’s payload skips two bytes: status and message type
            return raw.subdata(in: 2..<raw.count)
        } else {
            // Subsequent fragments skip only the status byte
            return raw.subdata(in: 1..<raw.count)
        }
    }
}

/// Split a message (typeID + dataBytes) into 15‐byte chunks with a 1‐byte status prefix
func fragmentMessage(typeID: UInt8, dataBytes: Data) -> [MessageFragment] {
    var full = Data([typeID]) + dataBytes
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
        let rem = UInt8((total - 1 - i) & 0x7F)
        let status: UInt8 = (isFirst ? 0x80 : 0x00) | rem
        var raw = Data([status])
        var padded = chunk
        if padded.count < 15 {
            padded.append(Data(repeating: 0, count: 15 - padded.count))
        }
        raw.append(padded)
        fragments.append(MessageFragment(raw: raw))
    }
    return fragments
}

/// Reassemble full message from received fragments
func assembleMessage(from fragments: [MessageFragment]) -> Data {
    var messageData = Data()
    for frag in fragments {
        messageData.append(frag.dataPayload)
    }
    return messageData
}
