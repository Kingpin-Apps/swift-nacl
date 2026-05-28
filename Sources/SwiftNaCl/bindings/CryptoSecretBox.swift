import Clibsodium
import Foundation

public struct CryptoSecretBox {
    public let keyBytes = crypto_secretbox_keybytes()
    public let nonceBytes = crypto_secretbox_noncebytes()
    public let zeroBytes = crypto_secretbox_zerobytes()
    public let boxZeroBytes = crypto_secretbox_boxzerobytes()
    public let macBytes = crypto_secretbox_macbytes()
    public let messageBytesMax = crypto_secretbox_messagebytes_max()

    /**
     Encrypts the given message using the provided nonce and key.

     - Parameters:
       - message: The message to encrypt.
       - nonce: The nonce to use for encryption.
       - key: The key to use for encryption.
     - Returns: The encrypted message.
     - Throws: `CryptoError.invalidKey` if the key length is invalid.
               `CryptoError.invalidNonce` if the nonce length is invalid.
               `CryptoError.encryptionFailed` if encryption fails.
     */
    func box(message: Data, nonce: Data, key: Data) throws -> Data {
        try ensure(key.count == keyBytes, raising: .valueError("Invalid key"))
        try ensure(
            nonce.count == nonceBytes,
            raising: .valueError("Invalid nonce")
        )

        let padded = Data(repeating: 0, count: zeroBytes) + message
        var ciphertext = Data(count: padded.count)

        let res = nonce.withUnsafeBytes { noncePtr in
                key.withUnsafeBytes { keyPtr in
                    ciphertext.withUnsafeMutableBytes { ciphertextPtr in
                        padded.withUnsafeBytes { paddedPtr in
                            guard let nonceRawPtr = noncePtr.baseAddress,
                                  let ciphertextRawPtr = ciphertextPtr.baseAddress,
                                  let paddedRawPtr = paddedPtr.baseAddress,
                                  let keyRawPtr = keyPtr.baseAddress else {
                                return Int32(-1)
                            }
                            return crypto_secretbox(
                                ciphertextRawPtr.assumingMemoryBound(to: UInt8.self),
                                paddedRawPtr.assumingMemoryBound(to: UInt8.self),
                                UInt64(padded.count),
                                nonceRawPtr.assumingMemoryBound(to: UInt8.self),
                                keyRawPtr.assumingMemoryBound(to: UInt8.self)
                            )
                    }
                }
            }
        }
        
        try ensure(res == 0, raising: .cryptoError("Encryption failed"))

        return ciphertext.subdata(in: boxZeroBytes..<ciphertext.count)
    }

    /**
     Decrypts the given ciphertext using the provided nonce and key.

     - Parameters:
       - ciphertext: The ciphertext to decrypt.
       - nonce: The nonce to use for decryption.
       - key: The key to use for decryption.
     - Returns: The decrypted message.
     - Throws: `CryptoError.invalidKey` if the key length is invalid.
               `CryptoError.invalidNonce` if the nonce length is invalid.
               `CryptoError.decryptionFailed` if decryption fails.
     */
    func open(ciphertext: Data, nonce: Data, key: Data) throws -> Data {
        try ensure(key.count == keyBytes, raising: .valueError("Invalid key"))
        try ensure(
            nonce.count == nonceBytes,
            raising: .valueError("Invalid nonce")
        )
        
        let padded = Data(repeating: 0, count: boxZeroBytes) + ciphertext
        var plaintext = Data(count: padded.count)

        let res = nonce.withUnsafeBytes { noncePtr in
                key.withUnsafeBytes { keyPtr in
                    padded.withUnsafeBytes { paddedPtr in
                        plaintext.withUnsafeMutableBytes { plaintextPtr in
                            guard let nonceRawPtr = noncePtr.baseAddress,
                                  let plaintextRawPtr = plaintextPtr.baseAddress,
                                  let paddedRawPtr = paddedPtr.baseAddress,
                                  let keyRawPtr = keyPtr.baseAddress else {
                                return Int32(-1)
                            }
                            return crypto_secretbox_open(
                                plaintextRawPtr.assumingMemoryBound(to: UInt8.self),
                                paddedRawPtr.assumingMemoryBound(to: UInt8.self),
                                UInt64(padded.count),
                                nonceRawPtr.assumingMemoryBound(to: UInt8.self),
                                keyRawPtr.assumingMemoryBound(to: UInt8.self)
                            )
                        }
                    }
            }
        }
        
        try ensure(res == 0, raising: .cryptoError("Decryption failed. Ciphertext failed verification"))

        return plaintext.subdata(in: zeroBytes..<plaintext.count)
    }

    /**
     Encrypts the given message using the provided nonce and key with easy method.

     - Parameters:
       - message: The message to encrypt.
       - nonce: The nonce to use for encryption.
       - key: The key to use for encryption.
     - Returns: The encrypted message.
     - Throws: `CryptoError.invalidKey` if the key length is invalid.
               `CryptoError.invalidNonce` if the nonce length is invalid.
               `CryptoError.encryptionFailed` if encryption fails.
     */
    func easy(message: Data, nonce: Data, key: Data) throws -> Data {
        try ensure(key.count == keyBytes, raising: .valueError("Invalid key"))
        try ensure(
            nonce.count == nonceBytes,
            raising: .valueError("Invalid nonce")
        )

        let mlen = message.count
        let clen = macBytes + mlen
        var ciphertext = Data(count: clen)
        
        let res = nonce.withUnsafeBytes { noncePtr in
                key.withUnsafeBytes { keyPtr in
                    ciphertext.withUnsafeMutableBytes { ciphertextPtr in
                        message.withUnsafeBytes { messagePtr in
                            guard let nonceRawPtr = noncePtr.baseAddress,
                                  let keyRawPtr = keyPtr.baseAddress,
                                  let ciphertextRawPtr = ciphertextPtr.baseAddress,
                                  let messageRawPtr = messagePtr.baseAddress else {
                                return Int32(-1)
                            }
                            return crypto_secretbox_easy(
                                ciphertextRawPtr.assumingMemoryBound(to: UInt8.self),
                                messageRawPtr.assumingMemoryBound(to: UInt8.self),
                                UInt64(mlen),
                                nonceRawPtr.assumingMemoryBound(to: UInt8.self),
                                keyRawPtr.assumingMemoryBound(to: UInt8.self)
                            )
                        }
                    }
            }
        }
        
        try ensure(res == 0, raising: .cryptoError("Encryption failed"))

        return ciphertext
    }

    /**
     Decrypts the given ciphertext using the provided nonce and key with easy method.

     - Parameters:
       - ciphertext: The ciphertext to decrypt.
       - nonce: The nonce to use for decryption.
       - key: The key to use for decryption.
     - Returns: The decrypted message.
     - Throws: `CryptoError.invalidKey` if the key length is invalid.
               `CryptoError.invalidNonce` if the nonce length is invalid.
               `CryptoError.invalidCiphertext` if the ciphertext length is invalid.
               `CryptoError.decryptionFailed` if decryption fails.
     */
    func openEasy(ciphertext: Data, nonce: Data, key: Data) throws -> Data {
        try ensure(key.count == keyBytes, raising: .valueError("Invalid key"))
        try ensure(
            nonce.count == nonceBytes,
            raising: .valueError("Invalid nonce")
        )

        let clen = ciphertext.count
        try ensure(clen >= macBytes, raising: .valueError("Input ciphertext must be at least \(macBytes) long"))

        let mlen = clen - macBytes
        var plaintext = Data(count: max(1, mlen))
        
        let res = nonce.withUnsafeBytes { noncePtr in
            plaintext.withUnsafeMutableBytes { plaintextPtr in
                key.withUnsafeBytes { keyPtr in
                    ciphertext.withUnsafeBytes { ciphertextPtr in
                        guard let nonceRawPtr = noncePtr.baseAddress,
                              let keyRawPtr = keyPtr.baseAddress,
                              let plaintextRawPtr = plaintextPtr.baseAddress,
                              let ciphertextRawPtr = ciphertextPtr.baseAddress else {
                            return Int32(-1)
                        }
                        return crypto_secretbox_open_easy(
                            plaintextRawPtr.assumingMemoryBound(to: UInt8.self),
                            ciphertextRawPtr.assumingMemoryBound(to: UInt8.self),
                            UInt64(clen),
                            nonceRawPtr.assumingMemoryBound(to: UInt8.self),
                            keyRawPtr.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
        }
            
        try ensure(res == 0, raising: .cryptoError("Decryption failed. Ciphertext failed verification"))

        return plaintext
    }
}
