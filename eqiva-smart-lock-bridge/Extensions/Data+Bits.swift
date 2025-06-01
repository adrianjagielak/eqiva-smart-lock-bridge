//
//  Data+Bits.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 01/06/2025.
//

import Foundation

extension Data {
    /// XOR with another Data (cycling the key if needed)
    func xor(with key: Data) -> Data {
        guard !key.isEmpty else { return self }
        var result = Data(capacity: count)
        for i in 0..<count {
            result.append(self[i] ^ key[i % key.count])
        }
        return result
    }

    /// Pad with zeros up to a multiple of blockSize
    func padded(toMultipleOf blockSize: Int) -> Data {
        let rem = count % blockSize
        guard rem != 0 else { return self }
        return self + Data(repeating: 0, count: blockSize - rem)
    }

    /// Initialize from hex string
    init(hexString: String) {
        self.init()
        var hex = hexString
        hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var i = hex.startIndex
        while i < hex.endIndex {
            let next = hex.index(i, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            if let b = UInt8(hex[i..<next], radix: 16) {
                append(b)
            }
            i = next
        }
    }

    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
