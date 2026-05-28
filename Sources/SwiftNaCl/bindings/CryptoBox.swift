import Clibsodium
import Foundation

public struct CryptoBox {
    public let secretKeyBytes = Int(crypto_box_secretkeybytes())
    public let publicKeyBytes = Int(crypto_box_publickeybytes())
    public let seedBytes = Int(crypto_box_seedbytes())
    public let nonceBytes = Int(crypto_box_noncebytes())
    public let zeroBytes = Int(crypto_box_zerobytes())
    public let boxZeroBytes = Int(crypto_box_boxzerobytes())
    public let beforeNmBytes = Int(crypto_box_beforenmbytes())
    public let sealBytes = Int(crypto_box_sealbytes())
    public let macBytes = Int(crypto_box_macbytes())

    /// Returns a randomly generated public and secret key.
    ///
    /// - Returns: A tuple containing the public key and secret key.
    /// - Throws: Raises a `SodiumError` if keypair generation fails.
    public func keypair() throws -> (publicKey: Data, secretKey: Data) {
        var pk = Data(count: publicKeyBytes)
        var sk = Data(count: secretKeyBytes)

        let rc = pk.withUnsafeMutableBytes { (pkPtr: UnsafeMutableRawBufferPointer) in
            sk.withUnsafeMutableBytes { (skPtr: UnsafeMutableRawBufferPointer) in
                guard let pkRawPtr = pkPtr.baseAddress,
                    let skRawPtr = skPtr.baseAddress
                else {
                    return Int32(-1)
                }
                return crypto_box_keypair(
                    pkRawPtr.assumingMemoryBound(to: UInt8.self),
                    skRawPtr.assumingMemoryBound(to: UInt8.self))
            }
        }

        try ensure(rc == 0, raising: .runtimeError("Unexpected library error"))

        return (Data(pk.prefix(Int(publicKeyBytes))), Data(sk.prefix(Int(secretKeyBytes))))
    }

    /// Returns a (public, secret) key pair deterministically generated from an input ``seed``.
    /// - Warning: The seed **must** be high-entropy; therefore, its generator **must** be a cryptographic quality random function like, for example, :func:`utils.random`.
    /// - Warning: The seed **must** be protected and remain secret. Anyone who knows the seed is really in possession of the corresponding PrivateKey.
    /// - Parameters:
    ///     - seed: `Data`
    ///
    /// - Returns: A tuple containing the public key and secret key.
    /// - Throws: Raises a `SodiumError` if keypair generation fails.
    public func seedKeypair(seed: Data) throws -> (publicKey: Data, secretKey: Data) {
        try ensure(
            seed.count == seedBytes,
            raising: .valueError("Invalid seed")
        )

        var pk = Data(count: publicKeyBytes)
        var sk = Data(count: secretKeyBytes)

        let rc = pk.withUnsafeMutableBytes { (pkPtr: UnsafeMutableRawBufferPointer) in
            sk.withUnsafeMutableBytes { (skPtr: UnsafeMutableRawBufferPointer) in
                seed.withUnsafeBytes { (seedPtr: UnsafeRawBufferPointer) in
                    guard let pkRawPtr = pkPtr.baseAddress,
                        let skRawPtr = skPtr.baseAddress,
                        let seedRawPtr = seedPtr.baseAddress
                    else {
                        return Int32(-1)
                    }
                    return crypto_box_seed_keypair(
                        pkRawPtr.assumingMemoryBound(to: UInt8.self),
                        skRawPtr.assumingMemoryBound(to: UInt8.self),
                        seedRawPtr.assumingMemoryBound(to: UInt8.self))
                }
            }
        }

        try ensure(rc == 0, raising: .runtimeError("Unexpected library error"))

        return (Data(pk.prefix(Int(publicKeyBytes))), Data(sk.prefix(Int(secretKeyBytes))))
    }

    /// Encrypts and returns a message ``message`` using the secret key ``sk``, public key ``pk``, and the nonce ``nonce``.
    ///
    /// - Parameters:
    ///    - message: `Data`
    ///    - nonce: `Data`
    ///    - publicKey: `Data`
    ///    - secretKey: `Data`
    ///
    /// - Returns: The encrypted message.
    /// - Throws: Raises a `SodiumError` if input is invalid.
    public func box(message: Data, nonce: Data, publicKey: Data, secretKey: Data) throws
        -> Data
    {
        try ensure(
            nonce.count == nonceBytes,
            raising: .valueError("Invalid nonce size")
        )

        try ensure(
            publicKey.count == publicKeyBytes,
            raising: .valueError("Invalid public key")
        )

        try ensure(
            secretKey.count == secretKeyBytes,
            raising: .valueError("Invalid secret key")
        )

        let paddedMessage = Data(repeating: 0, count: zeroBytes) + message
        var ciphertext = Data(count: paddedMessage.count)

        let rc = ciphertext.withUnsafeMutableBytes { ciphertextPtr in
            paddedMessage.withUnsafeBytes { paddedMessagePtr in
                nonce.withUnsafeBytes { noncePtr in
                    publicKey.withUnsafeBytes { publicKeyPtr in
                        secretKey.withUnsafeBytes { secretKeyPtr in
                            guard let ciphertextRawPtr = ciphertextPtr.baseAddress,
                                let paddedMessageRawPtr = paddedMessagePtr.baseAddress,
                                let nonceRawPtr = noncePtr.baseAddress,
                                let publicKeyRawPtr = publicKeyPtr.baseAddress,
                                let secretKeyRawPtr = secretKeyPtr.baseAddress
                            else {
                                return Int32(-1)  // Return an appropriate error code in case of failure
                            }
                            return crypto_box(
                                ciphertextRawPtr.assumingMemoryBound(to: UInt8.self),
                                paddedMessageRawPtr.assumingMemoryBound(to: UInt8.self),
                                UInt64(paddedMessage.count),
                                nonceRawPtr.assumingMemoryBound(to: UInt8.self),
                                publicKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                                secretKeyRawPtr.assumingMemoryBound(to: UInt8.self)
                            )
                        }
                    }
                }
            }
        }

        try ensure(rc == 0, raising: SodiumError.runtimeError("Unexpected library error"))

        return ciphertext.dropFirst(boxZeroBytes)
    }

    /// Decrypts and returns an encrypted message ``ciphertext``, using the secret key ``sk``, public key ``pk``, and the nonce ``nonce``.
    ///
    /// - Parameters:
    ///    - ciphertext: `Data`
    ///    - nonce: `Data`
    ///    - publicKey: `Data`
    ///    - secretKey: `Data`
    ///
    /// - Returns: The decrypted message.
    /// - Throws: Raises a `SodiumError` if input is invalid.
    public func open(ciphertext: Data, nonce: Data, publicKey: Data, secretKey: Data) throws -> Data
    {
        try ensure(
            nonce.count == nonceBytes,
            raising: .valueError("Invalid nonce size")
        )

        try ensure(
            publicKey.count == publicKeyBytes,
            raising: .valueError("Invalid public key")
        )

        try ensure(
            secretKey.count == secretKeyBytes,
            raising: .valueError("Invalid secret key")
        )

        let paddedCiphertext =
            Data(
                repeating: 0,
                count: boxZeroBytes
            ) + ciphertext
        var plaintext = Data(count: paddedCiphertext.count)

        let rc = plaintext.withUnsafeMutableBytes { plaintextPtr in
            paddedCiphertext.withUnsafeBytes { paddedCiphertextPtr in
                nonce.withUnsafeBytes { noncePtr in
                    publicKey.withUnsafeBytes { publicKeyPtr in
                        secretKey.withUnsafeBytes { secretKeyPtr in
                            guard let plaintextRawPtr = plaintextPtr.baseAddress,
                                let paddedCiphertextRawPtr = paddedCiphertextPtr.baseAddress,
                                let nonceRawPtr = noncePtr.baseAddress,
                                let publicKeyRawPtr = publicKeyPtr.baseAddress,
                                let secretKeyRawPtr = secretKeyPtr.baseAddress
                            else {
                                return Int32(-1)
                            }
                            return crypto_box_open(
                                plaintextRawPtr.assumingMemoryBound(to: UInt8.self),
                                paddedCiphertextRawPtr.assumingMemoryBound(to: UInt8.self),
                                UInt64(paddedCiphertext.count),
                                nonceRawPtr.assumingMemoryBound(to: UInt8.self),
                                publicKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                                secretKeyRawPtr.assumingMemoryBound(to: UInt8.self)
                            )
                        }
                    }
                }
            }
        }

        try ensure(
            rc == 0,
            raising: SodiumError.runtimeError("An error occurred trying to decrypt the message"))

        return plaintext.dropFirst(zeroBytes)
    }

    /// Computes and returns the shared key for the public key ``pk`` and the secret key ``sk``. This can be used to speed up operations where the same set of keys is going to be used multiple times.
    ///
    /// - Parameters:
    ///    - publicKey: `Data`
    ///    - secretKey: `Data`
    ///
    /// - Returns: The shared key.
    /// - Throws: Raises a `SodiumError` if input is invalid.
    public func beforenm(publicKey: Data, secretKey: Data) throws -> Data {
        try ensure(
            publicKey.count == publicKeyBytes,
            raising: .valueError("Invalid public key")
        )

        try ensure(
            secretKey.count == secretKeyBytes,
            raising: .valueError("Invalid secret key")
        )

        var sharedKey = Data(count: beforeNmBytes)

        let rc = sharedKey.withUnsafeMutableBytes { sharedKeyPtr in
            publicKey.withUnsafeBytes { publicKeyPtr in
                secretKey.withUnsafeBytes { secretKeyPtr in
                    guard let sharedKeyRawPtr = sharedKeyPtr.baseAddress,
                        let publicKeyRawPtr = publicKeyPtr.baseAddress,
                        let secretKeyRawPtr = secretKeyPtr.baseAddress
                    else {
                        return Int32(-1)
                    }
                    return crypto_box_beforenm(
                        sharedKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                        publicKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                        secretKeyRawPtr.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }

        try ensure(rc == 0, raising: SodiumError.runtimeError("Unexpected library error"))

        return Data(sharedKey.prefix(beforeNmBytes))
    }

    /// Encrypts and returns the message ``message`` using the shared key ``k`` and the nonce ``nonce``.
    ///
    /// - Parameters:
    ///    - message: `Data`
    ///    - nonce: `Data`
    ///    - sharedKey: `Data`
    ///
    /// - Returns: An encrypted message.
    /// - Throws: Raises a `SodiumError` if input is invalid.
    public func afternm(message: Data, nonce: Data, sharedKey: Data) throws -> Data {
        try ensure(
            nonce.count == nonceBytes,
            raising: .valueError("Invalid nonce")
        )

        try ensure(
            sharedKey.count == beforeNmBytes,
            raising: .valueError("Invalid shared key")
        )

        let paddedMessage = Data(repeating: 0, count: zeroBytes) + message
        var ciphertext = Data(count: paddedMessage.count)

        let rc = ciphertext.withUnsafeMutableBytes { ciphertextPtr in
            paddedMessage.withUnsafeBytes { paddedMessagePtr in
                nonce.withUnsafeBytes { noncePtr in
                    sharedKey.withUnsafeBytes { sharedKeyPtr in
                        guard let ciphertextRawPtr = ciphertextPtr.baseAddress,
                            let paddedMessageRawPtr = paddedMessagePtr.baseAddress,
                            let nonceRawPtr = noncePtr.baseAddress,
                            let sharedKeyRawPtr = sharedKeyPtr.baseAddress
                        else {
                            return Int32(-1)
                        }
                        return crypto_box_afternm(
                            ciphertextRawPtr.assumingMemoryBound(to: UInt8.self),
                            paddedMessageRawPtr.assumingMemoryBound(to: UInt8.self),
                            UInt64(paddedMessage.count),
                            nonceRawPtr.assumingMemoryBound(to: UInt8.self),
                            sharedKeyRawPtr.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
        }

        try ensure(rc == 0, raising: SodiumError.runtimeError("Unexpected library error"))

        return ciphertext.dropFirst(boxZeroBytes)
    }

    /// Decrypts and returns the encrypted message ``ciphertext``, using the shared key ``k`` and the nonce ``nonce``.
    ///
    /// - Parameters:
    ///   - ciphertext: `Data`
    ///   - nonce: `Data`
    ///   - sharedKey: `Data`
    ///
    /// - Returns: A tuple containing the public key and secret key.
    /// - Throws: Raises a `SodiumError` if keypair generation fails.
    public func openAfternm(ciphertext: Data, nonce: Data, sharedKey: Data) throws -> Data {
        try ensure(
            nonce.count == nonceBytes,
            raising: .valueError("Invalid nonce")
        )
        try ensure(
            sharedKey.count == beforeNmBytes,
            raising: .valueError("Invalid shared key")
        )

        let paddedCiphertext =
            Data(
                repeating: 0,
                count: boxZeroBytes
            ) + ciphertext

        var plaintext = Data(count: paddedCiphertext.count)

        let res = plaintext.withUnsafeMutableBytes { plaintextPtr in
            paddedCiphertext.withUnsafeBytes { paddedCiphertextPtr in
                nonce.withUnsafeBytes { noncePtr in
                    sharedKey.withUnsafeBytes { sharedKeyPtr in
                        guard let plaintextRawPtr = plaintextPtr.baseAddress,
                            let paddedCiphertextRawPtr = paddedCiphertextPtr.baseAddress,
                            let nonceRawPtr = noncePtr.baseAddress,
                            let sharedKeyRawPtr = sharedKeyPtr.baseAddress
                        else {
                            return Int32(-1)  // Return an appropriate error code in case of failure
                        }
                        return crypto_box_open_afternm(
                            plaintextRawPtr.assumingMemoryBound(to: UInt8.self),
                            paddedCiphertextRawPtr.assumingMemoryBound(to: UInt8.self),
                            UInt64(paddedCiphertext.count),
                            nonceRawPtr.assumingMemoryBound(to: UInt8.self),
                            sharedKeyRawPtr.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
        }

        try ensure(
            res == 0,
            raising: SodiumError.runtimeError("An error occurred trying to decrypt the message"))

        return plaintext.dropFirst(zeroBytes)
    }

    /// Encrypts and returns a message ``message`` using the secret key ``sk``, public key ``pk``, and the nonce ``nonce``.
    ///
    /// - Parameters:
    ///   - message: `Data`
    ///   - nonce: `Data`
    ///   - publicKey: `Data`
    ///   - secretKey
    ///
    /// - Returns: The encrypted message.
    /// - Throws: Raises a `SodiumError` if input is invalid.
    public func easy(message: Data, nonce: Data, publicKey: Data, secretKey: Data) throws -> Data {
        try ensure(
            nonce.count == nonceBytes,
            raising: .valueError("Invalid nonce")
        )
        try ensure(
            publicKey.count == publicKeyBytes,
            raising: .valueError("Invalid public key")
        )
        try ensure(
            secretKey.count == secretKeyBytes,
            raising: .valueError("Invalid secret key")
        )

        // Calculate lengths
        let messageLength = message.count
        let ciphertextLength = macBytes + messageLength

        // Allocate memory for the ciphertext
        var ciphertext = Data(count: ciphertextLength)

        // Encrypt the message
        let rc = ciphertext.withUnsafeMutableBytes { ciphertextPtr in
            message.withUnsafeBytes { messagePtr in
                nonce.withUnsafeBytes { noncePtr in
                    publicKey.withUnsafeBytes { publicKeyPtr in
                        secretKey.withUnsafeBytes { secretKeyPtr in
                            guard let ciphertextRawPtr = ciphertextPtr.baseAddress,
                                let messageRawPtr = messagePtr.baseAddress,
                                let nonceRawPtr = noncePtr.baseAddress,
                                let publicKeyRawPtr = publicKeyPtr.baseAddress,
                                let secretKeyRawPtr = secretKeyPtr.baseAddress
                            else {
                                return Int32(-1)
                            }
                            return crypto_box_easy(
                                ciphertextRawPtr.assumingMemoryBound(to: UInt8.self),
                                messageRawPtr.assumingMemoryBound(to: UInt8.self),
                                UInt64(messageLength),
                                nonceRawPtr.assumingMemoryBound(to: UInt8.self),
                                publicKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                                secretKeyRawPtr.assumingMemoryBound(to: UInt8.self)
                            )
                        }
                    }
                }
            }
        }

        try ensure(rc == 0, raising: .runtimeError("Unexpected library error"))

        return ciphertext
    }

    /// Decrypts and returns an encrypted message ``ciphertext``, using the secret key ``sk``, public key ``pk``, and the nonce ``nonce``.
    ///
    /// - Parameters:
    ///     - ciphertext: `Data`
    ///     - nonce: `Data`
    ///     - publicKey: `Data`
    ///     - secretKey: `Data`
    ///
    /// - Returns: The decrypted message.
    /// - Throws: Raises a `SodiumError` if input is invalid.
    public func openEasy(ciphertext: Data, nonce: Data, publicKey: Data, secretKey: Data) throws
        -> Data
    {
        try ensure(
            nonce.count == nonceBytes,
            raising: .valueError("Invalid nonce size")
        )

        try ensure(
            publicKey.count == publicKeyBytes,
            raising: .valueError("Invalid public key")
        )

        try ensure(
            secretKey.count == secretKeyBytes,
            raising: .valueError("Invalid secret key")
        )

        let ciphertextLength = ciphertext.count

        try ensure(
            ciphertextLength >= macBytes,
            raising:
                .runtimeError(
                    "Input ciphertext must be at least \(macBytes) bytes long"
                )
        )

        let messageLength = ciphertextLength - macBytes
        var plaintext = Data(count: messageLength)

        let rc = plaintext.withUnsafeMutableBytes { plaintextPtr in
            ciphertext.withUnsafeBytes { ciphertextPtr in
                nonce.withUnsafeBytes { noncePtr in
                    publicKey.withUnsafeBytes { publicKeyPtr in
                        secretKey.withUnsafeBytes { secretKeyPtr in
                            guard let plaintextRawPtr = plaintextPtr.baseAddress,
                                let ciphertextRawPtr = ciphertextPtr.baseAddress,
                                let nonceRawPtr = noncePtr.baseAddress,
                                let publicKeyRawPtr = publicKeyPtr.baseAddress,
                                let secretKeyRawPtr = secretKeyPtr.baseAddress
                            else {
                                return Int32(-1)  // Return an appropriate error code in case of failure
                            }
                            return crypto_box_open_easy(
                                plaintextRawPtr.assumingMemoryBound(to: UInt8.self),
                                ciphertextRawPtr.assumingMemoryBound(to: UInt8.self),
                                UInt64(ciphertextLength),
                                nonceRawPtr.assumingMemoryBound(to: UInt8.self),
                                publicKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                                secretKeyRawPtr.assumingMemoryBound(to: UInt8.self)
                            )
                        }
                    }
                }
            }
        }

        try ensure(
            rc == 0, raising: .runtimeError("An error occurred trying to decrypt the message"))

        return plaintext
    }

    /// Encrypts and returns the message ``message`` using the shared key ``k`` and the nonce ``nonce``.
    ///
    /// - Parameters:
    ///    - message: `Data`
    ///    - nonce: `Data`
    ///    - sharedKey: `Data`
    ///
    /// - Returns: The encrypted message.
    /// - Throws: Raises a `SodiumError` if input is invalid.
    public func easyAfternm(message: Data, nonce: Data, sharedKey: Data) throws -> Data {
        try ensure(
            nonce.count == nonceBytes,
            raising: .valueError("Invalid nonce")
        )

        try ensure(
            sharedKey.count == beforeNmBytes,
            raising: .valueError("Invalid shared key")
        )

        let messageLength = message.count
        let ciphertextLength = macBytes + messageLength

        var ciphertext = Data(count: ciphertextLength)

        let rc = ciphertext.withUnsafeMutableBytes { ciphertextPtr in
            message.withUnsafeBytes { messagePtr in
                nonce.withUnsafeBytes { noncePtr in
                    sharedKey.withUnsafeBytes { sharedKeyPtr in
                        guard let ciphertextRawPtr = ciphertextPtr.baseAddress,
                            let messageRawPtr = messagePtr.baseAddress,
                            let nonceRawPtr = noncePtr.baseAddress,
                            let sharedKeyRawPtr = sharedKeyPtr.baseAddress
                        else {
                            return Int32(-1)
                        }
                        return crypto_box_easy_afternm(
                            ciphertextRawPtr.assumingMemoryBound(to: UInt8.self),
                            messageRawPtr.assumingMemoryBound(to: UInt8.self),
                            UInt64(messageLength),
                            nonceRawPtr.assumingMemoryBound(to: UInt8.self),
                            sharedKeyRawPtr.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
        }

        try ensure(rc == 0, raising: .runtimeError("Unexpected library error"))

        return ciphertext
    }

    /// Decrypts and returns the encrypted message ``ciphertext``, using the shared key ``k`` and the nonce ``nonce``.
    ///
    /// - Parameters:
    ///  - ciphertext: `Data`
    ///  - nonce: `Data`
    ///  - sharedKey: `Data`
    ///
    /// - Returns: The decrypted message.
    /// - Throws: Raises a `SodiumError` if input is invalid.
    public func openEasyAfternm(ciphertext: Data, nonce: Data, sharedKey: Data) throws -> Data {
        try ensure(
            nonce.count == nonceBytes,
            raising: .valueError("Invalid nonce")
        )
        try ensure(
            sharedKey.count == beforeNmBytes,
            raising: .valueError("Invalid shared key")
        )

        let ciphertextLength = ciphertext.count

        try ensure(
            ciphertextLength >= macBytes,
            raising: .valueError("Input ciphertext must be at least \(macBytes) bytes long")
        )

        let messageLength = ciphertextLength - macBytes

        var plaintext = Data(count: messageLength)

        let rc = plaintext.withUnsafeMutableBytes { plaintextPtr in
            ciphertext.withUnsafeBytes { ciphertextPtr in
                nonce.withUnsafeBytes { noncePtr in
                    sharedKey.withUnsafeBytes { sharedKeyPtr in
                        guard let plaintextRawPtr = plaintextPtr.baseAddress,
                            let ciphertextRawPtr = ciphertextPtr.baseAddress,
                            let nonceRawPtr = noncePtr.baseAddress,
                            let sharedKeyRawPtr = sharedKeyPtr.baseAddress
                        else {
                            return Int32(-1)
                        }
                        return crypto_box_open_easy_afternm(
                            plaintextRawPtr.assumingMemoryBound(to: UInt8.self),
                            ciphertextRawPtr.assumingMemoryBound(to: UInt8.self),
                            UInt64(ciphertextLength),
                            nonceRawPtr.assumingMemoryBound(to: UInt8.self),
                            sharedKeyRawPtr.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
        }

        try ensure(
            rc == 0, raising: .runtimeError("An error occurred trying to decrypt the message"))

        return plaintext
    }

    /// Encrypts and returns a message ``message`` using an ephemeral secret key and the public key ``pk``.
    /// The ephemeral public key, which is embedded in the sealed box, is also used, in combination with ``pk``, to derive the nonce needed for the underlying box construct.
    ///
    /// - Parameters:
    ///   - message: `Data`
    ///   - publicKey: `Data`
    ///
    /// - Returns: The encrypted message.
    /// - Throws: Raises a `SodiumError` if input is invalid.
    public func seal(message: Data, publicKey: Data) throws -> Data {
        try ensure(
            publicKey.count == publicKeyBytes,
            raising: .valueError("Invalid public key")
        )

        let messageLength = message.count
        let ciphertextLength = sealBytes + messageLength

        var ciphertext = Data(count: ciphertextLength)

        let rc = ciphertext.withUnsafeMutableBytes { ciphertextPtr in
            message.withUnsafeBytes { messagePtr in
                publicKey.withUnsafeBytes { publicKeyPtr in
                    guard let ciphertextRawPtr = ciphertextPtr.baseAddress,
                        let messageRawPtr = messagePtr.baseAddress,
                        let publicKeyRawPtr = publicKeyPtr.baseAddress
                    else {
                        return Int32(-1)
                    }
                    return crypto_box_seal(
                        ciphertextRawPtr.assumingMemoryBound(to: UInt8.self),
                        messageRawPtr.assumingMemoryBound(to: UInt8.self),
                        UInt64(messageLength),
                        publicKeyRawPtr.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }

        try ensure(rc == 0, raising: SodiumError.runtimeError("Unexpected library error"))

        return ciphertext
    }

    /// Decrypts and returns an encrypted message ``ciphertext``, using the recipient's secret key ``sk`` and the sender's ephemeral public key embedded in the sealed box. The box construct nonce is derived from the recipient's public key ``pk`` and the sender's public key.
    ///
    /// - Parameters:
    ///  - ciphertext: `Data`
    ///  - publicKey: `Data`
    ///  - secretKey: `Data`
    ///
    /// - Returns: The decrypted message.
    /// - Throws: Raises a `SodiumError` if input is invalid.
    public func sealOpen(ciphertext: Data, publicKey: Data, secretKey: Data) throws -> Data {
        try ensure(
            publicKey.count == publicKeyBytes,
            raising: .valueError("Invalid public key")
        )
        try ensure(
            secretKey.count == secretKeyBytes,
            raising: .valueError("Invalid secret key")
        )
        let ciphertextLength = ciphertext.count

        // Ensure the ciphertext length is at least as long as the SEALBYTES
        try ensure(
            ciphertextLength >= sealBytes,
            raising: .valueError("Input ciphertext must be at least \(sealBytes) bytes long")
        )

        let messageLength = ciphertextLength - sealBytes

        var plaintext = Data(count: messageLength)

        let rc = plaintext.withUnsafeMutableBytes { plaintextPtr in
            ciphertext.withUnsafeBytes { ciphertextPtr in
                publicKey.withUnsafeBytes { publicKeyPtr in
                    secretKey.withUnsafeBytes { secretKeyPtr in
                        guard let plaintextRawPtr = plaintextPtr.baseAddress,
                            let ciphertextRawPtr = ciphertextPtr.baseAddress,
                            let publicKeyRawPtr = publicKeyPtr.baseAddress,
                            let secretKeyRawPtr = secretKeyPtr.baseAddress
                        else {
                            return Int32(-1)
                        }
                        return crypto_box_seal_open(
                            plaintextRawPtr.assumingMemoryBound(to: UInt8.self),
                            ciphertextRawPtr.assumingMemoryBound(to: UInt8.self),
                            UInt64(ciphertextLength),
                            publicKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                            secretKeyRawPtr.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
        }

        try ensure(
            rc == 0,
            raising: SodiumError.runtimeError("An error occurred trying to decrypt the message"))

        return plaintext
    }
}
