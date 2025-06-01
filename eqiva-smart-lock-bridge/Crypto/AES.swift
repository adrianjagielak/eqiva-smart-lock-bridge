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
    precondition(block.count == kCCBlockSizeAES128 && key.count == kCCKeySizeAES128)
    var out = Data(repeating: 0, count: kCCBlockSizeAES128)
    var numEncrypted: size_t = 0
    let outCount = out.count
    let status = out.withUnsafeMutableBytes { outBytes in
        block.withUnsafeBytes { inBytes in
            key.withUnsafeBytes { keyBytes in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionECBMode),
                    keyBytes.baseAddress, key.count,
                    nil,
                    inBytes.baseAddress, block.count,
                    outBytes.baseAddress, outCount,
                    &numEncrypted
                )
            }
        }
    }
    precondition(status == kCCSuccess)
    return out
}
