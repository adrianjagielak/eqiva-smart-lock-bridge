//
//  AES.swift
//  eqiva-smart-lock-bridge
//
//  Created by Adrian Jagielak on 01/06/2025.
//

import Foundation
import CommonCrypto

/// AES-128-ECB encryption of a single block (16 bytes) using CommonCrypto
func aes128EncryptBlock(_ block: Data, key: Data) -> Data {
    precondition(block.count == kCCBlockSizeAES128, "Block size must be 16 bytes")
    precondition(key.count == kCCKeySizeAES128, "Key size must be 16 bytes")

    var outData = Data(repeating: 0, count: kCCBlockSizeAES128)
    var numBytesEncrypted: size_t = 0

    let outDataCount = outData.count
    let status = outData.withUnsafeMutableBytes { outBytes in
        block.withUnsafeBytes { inBytes in
            key.withUnsafeBytes { keyBytes in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionECBMode),
                    keyBytes.baseAddress, key.count,
                    nil,
                    inBytes.baseAddress, block.count,
                    outBytes.baseAddress, outDataCount,
                    &numBytesEncrypted
                )
            }
        }
    }

    precondition(status == kCCSuccess, "AES encryption failed with status \(status)")
    return outData
}
