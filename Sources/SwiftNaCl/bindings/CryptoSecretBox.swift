import Clibsodium
import Foundation

/// Bindings to libsodium's secret-key authenticated encryption
/// (`crypto_secretbox`, XSalsa20-Poly1305).
///
/// For a higher-level API that manages nonces, use ``SecretBox``.
public struct CryptoSecretBox {
    /// The size of a key in bytes (32).
    public let keyBytes = crypto_secretbox_keybytes()
    /// The size of a nonce in bytes (24).
    public let nonceBytes = crypto_secretbox_noncebytes()
    /// The zero padding that the original NaCl API expects before a message, in bytes (32).
    public let zeroBytes = crypto_secretbox_zerobytes()
    /// The zero padding that the original NaCl API leaves before a ciphertext, in bytes (16).
    public let boxZeroBytes = crypto_secretbox_boxzerobytes()
    /// The size of the authentication tag in bytes (16).
    public let macBytes = crypto_secretbox_macbytes()
    /// The largest message, in bytes, that can be encrypted with one key/nonce pair.
    ///
    /// libsodium returns `SIZE_MAX - macBytes` as a `size_t`, which does not fit in
    /// an `Int`, so the value is clamped to `Int.max`.
    public let messageBytesMax = Int(clamping: UInt(bitPattern: crypto_secretbox_messagebytes_max()))

    /// Encrypts `message` with the original NaCl `crypto_secretbox` API.
    ///
    /// The result is the ciphertext with the leading ``boxZeroBytes`` padding removed,
    /// so it is the same as ``easy(message:nonce:key:)``.
    ///
    /// - Parameters:
    ///   - message: The message to encrypt.
    ///   - nonce: The ``nonceBytes``-byte (24) nonce; never reuse a nonce with the same key.
    ///   - key: The ``keyBytes``-byte (32) secret key.
    /// - Returns: The authentication tag followed by the encrypted message.
    /// - Throws: ``SodiumError/valueError(_:)`` if the key or nonce has the wrong length,
    ///   or ``SodiumError/cryptoError(_:)`` if encryption fails.
    public func box(message: Data, nonce: Data, key: Data) throws -> Data {
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

    /// Decrypts a ciphertext produced by ``box(message:nonce:key:)`` with the original NaCl
    /// `crypto_secretbox_open` API.
    ///
    /// - Parameters:
    ///   - ciphertext: The authentication tag followed by the encrypted message.
    ///   - nonce: The ``nonceBytes``-byte (24) nonce used for encryption.
    ///   - key: The ``keyBytes``-byte (32) secret key.
    /// - Returns: The decrypted message.
    /// - Throws: ``SodiumError/valueError(_:)`` if the key or nonce has the wrong length,
    ///   or ``SodiumError/cryptoError(_:)`` if the ciphertext fails authentication.
    public func open(ciphertext: Data, nonce: Data, key: Data) throws -> Data {
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

    /// Encrypts `message` with `crypto_secretbox_easy` (XSalsa20-Poly1305).
    ///
    /// - Parameters:
    ///   - message: The message to encrypt.
    ///   - nonce: The ``nonceBytes``-byte (24) nonce; never reuse a nonce with the same key.
    ///   - key: The ``keyBytes``-byte (32) secret key.
    /// - Returns: The ``macBytes``-byte authentication tag followed by the encrypted message.
    /// - Throws: ``SodiumError/valueError(_:)`` if the key or nonce has the wrong length,
    ///   or ``SodiumError/cryptoError(_:)`` if encryption fails.
    public func easy(message: Data, nonce: Data, key: Data) throws -> Data {
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

    /// Decrypts and authenticates a ciphertext produced by ``easy(message:nonce:key:)``
    /// (`crypto_secretbox_open_easy`).
    ///
    /// - Parameters:
    ///   - ciphertext: The authentication tag followed by the encrypted message.
    ///   - nonce: The ``nonceBytes``-byte (24) nonce used for encryption.
    ///   - key: The ``keyBytes``-byte (32) secret key.
    /// - Returns: The decrypted message.
    /// - Throws: ``SodiumError/valueError(_:)`` if the key or nonce has the wrong length or
    ///   the ciphertext is shorter than ``macBytes``, or ``SodiumError/cryptoError(_:)`` if
    ///   the ciphertext fails authentication.
    public func openEasy(ciphertext: Data, nonce: Data, key: Data) throws -> Data {
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

        return Data(plaintext.prefix(mlen))
    }
}
