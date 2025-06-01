//
//  Data+Bits.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 01/06/2025.
//

import Foundation

extension Data {
    /// XOR this Data with another Data (repeating the key as needed).
    func xor(with key: Data) -> Data {
        let result = zip(self, key.cycled(to: count)).map { $0 ^ $1 }
        return Data(result)
    }

    /// Repeat or truncate this Data to target length.
    func cycled(to length: Int) -> Data {
        guard !isEmpty else { return Data(repeating: 0, count: length) }
        var data = Data()
        while data.count < length {
            data.append(self)
        }
        if data.count > length {
            data = data.subdata(in: 0..<length)
        }
        return data
    }

    /// Pad this Data with zeros up to a multiple of blockSize.
    func padded(toMultipleOf blockSize: Int) -> Data {
        let remainder = count % blockSize
        guard remainder != 0 else { return self }
        let padLength = blockSize - remainder
        return self + Data(repeating: 0, count: padLength)
    }

    func hexEncodedString() -> String {
        return map { String(format: "%02x", $0) }.joined()
    }

    /// Initialize from hex string (e.g. "a1b2c3").
    init(hexString: String) {
        self.init()
        var hex = hexString
        hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            let byteString = hex[index..<nextIndex]
            if let num = UInt8(byteString, radix: 16) {
                self.append(num)
            }
            index = nextIndex
        }
    }
}
