//
//  SessionCrypto.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 01/06/2025.
//

import Foundation
import CommonCrypto

/// Compute a 10-byte nonce: [messageTypeID (1B)] + sessionOpenNonce (8B) + [0x00, 0x00 (2B)] + securityCounter (2B)
func computeNonce(messageTypeID: UInt8, sessionOpenNonce: Data, securityCounter: UInt16) -> Data {
    var data = Data([messageTypeID])
    data.append(sessionOpenNonce)
    data.append(contentsOf: [0x00, 0x00])
    let scBE = securityCounter.bigEndian
    data.append(contentsOf: withUnsafeBytes(of: scBE) { Array($0) })
    return data
}

/// Encrypt or decrypt arbitrary‐length payload via AES‐CTR style using AES‐ECB
func cryptData(_ data: Data, messageTypeID: UInt8, sessionOpenNonce: Data, securityCounter: UInt16, key: Data) -> Data {
    let nonce = computeNonce(messageTypeID: messageTypeID, sessionOpenNonce: sessionOpenNonce, securityCounter: securityCounter)
    let blockCount = Int(ceil(Double(data.count) / Double(kCCBlockSizeAES128)))
    var keystream = Data()
    for i in 0..<blockCount {
        let blockCounterBE = UInt16(i + 1).bigEndian
        var input = Data([0x01])
        input.append(nonce)
        input.append(contentsOf: withUnsafeBytes(of: blockCounterBE) { Array($0) })
        precondition(input.count == 1 + nonce.count + 2)
        keystream.append(aes128EncryptBlock(input, key: key))
    }
    return Data(zip(data, keystream).map { $0 ^ $1 })
}

/// Compute 4‐byte authentication value (AES‐CMAC‐like) for secure message
func computeAuthenticationValue(data: Data, messageTypeID: UInt8, sessionOpenNonce: Data, securityCounter: UInt16, key: Data) -> Data {
    let nonce = computeNonce(messageTypeID: messageTypeID, sessionOpenNonce: sessionOpenNonce, securityCounter: securityCounter)
    let paddedData = data.padded(toMultipleOf: 16)
    let dataLengthBE = withUnsafeBytes(of: UInt16(data.count).bigEndian) { Data($0) }

    var iv = Data([0x09])
    iv.append(nonce)
    iv.append(dataLengthBE)
    precondition(iv.count == 1 + nonce.count + 2)

    var x = aes128EncryptBlock(iv, key: key)
    for chunkStart in stride(from: 0, to: paddedData.count, by: 16) {
        let block = paddedData.subdata(in: chunkStart..<(chunkStart + 16))
        x = aes128EncryptBlock(Data(zip(x, block).map { $0 ^ $1 }), key: key)
    }

    var iv2 = Data([0x01])
    iv2.append(nonce)
    iv2.append(contentsOf: [0x00, 0x00])
    let x2 = aes128EncryptBlock(iv2, key: key)
    let auth = Data(zip(x.prefix(4), x2).map { $0 ^ $1 })
    return auth
}
