import Clibsodium
/// Implementations of authenticated encription with associated data (*AEAD*)
/// constructions building on the chacha20 stream cipher and the poly1305
/// authenticator
import Foundation

public struct CryptoAead {
    public let chacha20poly1305IetfKeyBytes = crypto_aead_chacha20poly1305_ietf_keybytes()
    public let chacha20poly1305IetfNsecBytes = crypto_aead_chacha20poly1305_ietf_nsecbytes()
    public let chacha20poly1305IetfNpubBytes = crypto_aead_chacha20poly1305_ietf_npubbytes()
    public let chacha20poly1305IetfABytes = crypto_aead_chacha20poly1305_ietf_abytes()
    public let chacha20poly1305IetfMessageBytesMax =
        crypto_aead_chacha20poly1305_ietf_messagebytes_max()
    public var chacha20poly1305IetfCryptBytesMax: Int {
        return chacha20poly1305IetfMessageBytesMax + chacha20poly1305IetfABytes
    }

    public let chacha20poly1305KeyBytes = crypto_aead_chacha20poly1305_keybytes()
    public let chacha20poly1305NsecBytes = crypto_aead_chacha20poly1305_nsecbytes()
    public let chacha20poly1305NpubBytes = crypto_aead_chacha20poly1305_npubbytes()
    public let chacha20poly1305ABytes = crypto_aead_chacha20poly1305_abytes()
    public let chacha20poly1305MessageBytesMax: UInt64 = {
        return sodiumSizeMax - UInt64(crypto_aead_chacha20poly1305_abytes())
    }()
    public var chacha20poly1305CryptBytesMax: UInt64 {
        return chacha20poly1305MessageBytesMax + UInt64(chacha20poly1305ABytes)
    }

    public let xchacha20poly1305IetfKeyBytes = crypto_aead_xchacha20poly1305_ietf_keybytes()
    public let xchacha20poly1305IetfNsecBytes = crypto_aead_xchacha20poly1305_ietf_nsecbytes()
    public let xchacha20poly1305IetfNpubBytes = crypto_aead_xchacha20poly1305_ietf_npubbytes()
    public let xchacha20poly1305IetfABytes = crypto_aead_xchacha20poly1305_ietf_abytes()
    public let xchacha20poly1305IetfMessageBytesMax: UInt64 = {
        return sodiumSizeMax - UInt64(crypto_aead_xchacha20poly1305_ietf_abytes())
    }()
    public var xchacha20poly1305IetfCryptBytesMax: UInt64 {
        return xchacha20poly1305IetfMessageBytesMax + UInt64(
            xchacha20poly1305IetfABytes
        )
    }

    public func chacha20poly1305IetfEncrypt(message: Data, aad: Data?, nonce: Data, key: Data)
        throws -> Data
    {
        /// Encrypt the given ``message`` using the IETF ratified chacha20poly1305 construction described in RFC7539.
        ///
        /// - Parameters:
        ///     - message: `Data` to encrypt
        ///     - aad: Additional authenticated data `Data`
        ///     - nonce: Nonce `Data`
        ///     - key: Key `Data`
        ///
        /// - Returns: Authenticated ciphertext `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.

        let mlen = message.count

        try ensure(
            mlen <= chacha20poly1305IetfMessageBytesMax,
            raising: .valueError(
                "Message must be at most \(chacha20poly1305IetfMessageBytesMax) bytes long"))

        try ensure(
            nonce.count == chacha20poly1305IetfNpubBytes,
            raising: .typeError(
                "Nonce must be a \(chacha20poly1305IetfNpubBytes) bytes long bytes sequence"))

        try ensure(
            key.count == chacha20poly1305IetfKeyBytes,
            raising: .typeError(
                "Key must be a \(chacha20poly1305IetfKeyBytes) bytes long bytes sequence"))

        let _aad = aad ?? Data()
        let aalen = aad?.count ?? 0

        let mxout = mlen + chacha20poly1305IetfABytes

        var clen = UInt64(0)

        var ciphertext = Data(repeating: 0, count: mxout)

        let res = message.withUnsafeBytes { messagePtr in
            ciphertext.withUnsafeMutableBytes { ciphertextPtr in
                _aad.withUnsafeBytes { aadPtr in
                    nonce.withUnsafeBytes { noncePtr in
                        key.withUnsafeBytes { keyPtr in
                            guard let messageRawPtr = messagePtr.baseAddress,
                                let ciphertextRawPtr = ciphertextPtr.baseAddress,
                                let aadERawPtr = aadPtr.baseAddress,
                                let nonceRawPtr = noncePtr.baseAddress,
                                let keyRawPtr = keyPtr.baseAddress
                            else {
                                return Int32(-1)
                            }
                            return crypto_aead_chacha20poly1305_ietf_encrypt(
                                ciphertextRawPtr,
                                &clen,
                                messageRawPtr,
                                UInt64(mlen),
                                aadERawPtr,
                                UInt64(aalen),
                                nil,
                                nonceRawPtr,
                                keyRawPtr
                            )
                        }
                    }
                }
            }
        }

        try ensure(res == 0, raising: .cryptoError("Encryption failed."))

        return Data(ciphertext[0..<Int(clen)])
    }

    public func chacha20poly1305IetfDecrypt(ciphertext: Data, aad: Data?, nonce: Data, key: Data)
        throws -> Data
    {
        /// Decrypt the given ``ciphertext`` using the IETF ratified chacha20poly1305 construction described in RFC7539.
        ///
        /// - Parameters:
        ///     - ciphertext: `Data` to decrypt
        ///     - aad: Additional authenticated data `Data`
        ///     - nonce: Nonce `Data`
        ///     - key: Key `Data`
        ///
        /// - Returns: The decrypted message `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.

        let clen = ciphertext.count

        try ensure(
            clen <= chacha20poly1305IetfCryptBytesMax,
            raising: .valueError(
                "Ciphertext must be at most \(chacha20poly1305IetfCryptBytesMax) bytes long"))

        try ensure(
            nonce.count == chacha20poly1305IetfNpubBytes,
            raising: .typeError(
                "Nonce must be a \(chacha20poly1305IetfNpubBytes) bytes long bytes sequence"))

        try ensure(
            key.count == chacha20poly1305IetfKeyBytes,
            raising: .typeError(
                "Key must be a \(chacha20poly1305IetfKeyBytes) bytes long bytes sequence"))

        let mxout = clen - chacha20poly1305IetfABytes

        var mlen = UInt64(0)

        var message = [UInt8](repeating: 0, count: mxout)

        let _aad = aad ?? Data()
        let aalen = aad?.count ?? 0

        let res = message.withUnsafeMutableBytes { messagePtr in
            ciphertext.withUnsafeBytes { ciphertextPtr in
                _aad.withUnsafeBytes { aadPtr in
                    nonce.withUnsafeBytes { noncePtr in
                        key.withUnsafeBytes { keyPtr in
                            guard let messageRawPtr = messagePtr.baseAddress,
                                let ciphertextRawPtr = ciphertextPtr.baseAddress,
                                let aadERawPtr = aadPtr.baseAddress,
                                let nonceRawPtr = noncePtr.baseAddress,
                                let keyRawPtr = keyPtr.baseAddress
                            else {
                                return Int32(-1)  // Return an appropriate error code in case of failure
                            }
                            return crypto_aead_chacha20poly1305_ietf_decrypt(
                                messageRawPtr,
                                &mlen,
                                nil,
                                ciphertextRawPtr,
                                UInt64(clen),
                                aadERawPtr,
                                UInt64(aalen),
                                nonceRawPtr,
                                keyRawPtr
                            )
                        }
                    }
                }
            }
        }

        try ensure(res == 0, raising: .cryptoError("Decryption failed."))

        return Data(message[0..<Int(mlen)])
    }

    public func chacha20poly1305Encrypt(message: Data, aad: Data?, nonce: Data, key: Data) throws
        -> Data
    {
        /// Encrypt the given ``message`` using the "legacy" construction described in draft-agl-tls-chacha20poly1305.
        ///
        /// - Parameters:
        ///     - message: `Data` to encrypt
        ///     - aad: Additional authenticated data `Data`
        ///     - nonce: Nonce `Data`
        ///     - key: Key `Data`
        ///
        /// - Returns: Authenticated ciphertext `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.

        let mlen = message.count

        try ensure(
            mlen <= chacha20poly1305MessageBytesMax,
            raising: .valueError(
                "Message must be at most \(chacha20poly1305MessageBytesMax) bytes long"))

        try ensure(
            nonce.count == chacha20poly1305NpubBytes,
            raising: .typeError(
                "Nonce must be a \(chacha20poly1305NpubBytes) bytes long bytes sequence"))

        try ensure(
            key.count == chacha20poly1305KeyBytes,
            raising: .typeError(
                "Key must be a \(chacha20poly1305KeyBytes) bytes long bytes sequence"))

        let _aad = aad ?? Data()
        let aalen = aad?.count ?? 0

        let mxout = mlen + chacha20poly1305ABytes

        var clen = UInt64(0)

        var ciphertext = Data(repeating: 0, count: mxout)

        let res = message.withUnsafeBytes { messagePtr in
            ciphertext.withUnsafeMutableBytes { ciphertextPtr in
                _aad.withUnsafeBytes { aadPtr in
                    nonce.withUnsafeBytes { noncePtr in
                        key.withUnsafeBytes { keyPtr in
                            guard let messageRawPtr = messagePtr.baseAddress,
                                let ciphertextRawPtr = ciphertextPtr.baseAddress,
                                let aadERawPtr = aadPtr.baseAddress,
                                let nonceRawPtr = noncePtr.baseAddress,
                                let keyRawPtr = keyPtr.baseAddress
                            else {
                                return Int32(-1)  // Return an appropriate error code in case of failure
                            }
                            return crypto_aead_chacha20poly1305_encrypt(
                                ciphertextRawPtr,
                                &clen,
                                messageRawPtr,
                                UInt64(mlen),
                                aadERawPtr,
                                UInt64(aalen),
                                nil,
                                nonceRawPtr,
                                keyRawPtr
                            )
                        }
                    }
                }
            }
        }

        try ensure(res == 0, raising: .cryptoError("Encryption failed."))

        return Data(ciphertext[0..<Int(clen)])
    }

    public func chacha20poly1305Decrypt(ciphertext: Data, aad: Data?, nonce: Data, key: Data) throws
        -> Data
    {
        /// Decrypt the given ``ciphertext`` using the "legacy" construction described in draft-agl-tls-chacha20poly1305.
        ///
        /// - Parameters:
        ///     - ciphertext: `Data` to decrypt
        ///     - aad: Additional authenticated data `Data`
        ///     - nonce: Nonce `Data`
        ///     - key: Key `Data`
        ///
        /// - Returns: The decrypted message `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.

        let clen = ciphertext.count

        try ensure(
            clen <= chacha20poly1305CryptBytesMax,
            raising: .valueError(
                "Ciphertext must be at most \(chacha20poly1305CryptBytesMax) bytes long"))

        try ensure(
            nonce.count == chacha20poly1305NpubBytes,
            raising: .typeError(
                "Nonce must be a \(chacha20poly1305NpubBytes) bytes long bytes sequence"))

        try ensure(
            key.count == chacha20poly1305KeyBytes,
            raising: .typeError(
                "Key must be a \(chacha20poly1305KeyBytes) bytes long bytes sequence"))

        let mxout = clen - chacha20poly1305ABytes

        var mlen = UInt64(0)

        var message = [UInt8](repeating: 0, count: mxout)

        let _aad = aad ?? Data()
        let aalen = aad?.count ?? 0

        let res = message.withUnsafeMutableBytes { messagePtr in
            ciphertext.withUnsafeBytes { ciphertextPtr in
                _aad.withUnsafeBytes { aadPtr in
                    nonce.withUnsafeBytes { noncePtr in
                        key.withUnsafeBytes { keyPtr in
                            guard let messageRawPtr = messagePtr.baseAddress,
                                let ciphertextRawPtr = ciphertextPtr.baseAddress,
                                let aadERawPtr = aadPtr.baseAddress,
                                let nonceRawPtr = noncePtr.baseAddress,
                                let keyRawPtr = keyPtr.baseAddress
                            else {
                                return Int32(-1)
                            }
                            return crypto_aead_chacha20poly1305_decrypt(
                                messageRawPtr,
                                &mlen,
                                nil,
                                ciphertextRawPtr,
                                UInt64(clen),
                                aadERawPtr,
                                UInt64(aalen),
                                nonceRawPtr,
                                keyRawPtr
                            )
                        }
                    }
                }
            }
        }

        try ensure(res == 0, raising: .cryptoError("Decryption failed."))

        return Data(message[0..<Int(mlen)])
    }

    public func xchacha20poly1305IetfEncrypt(message: Data, aad: Data?, nonce: Data, key: Data)
        throws -> Data
    {
        /// Encrypt the given ``message`` using the long-nonces xchacha20poly1305 construction.
        ///
        /// - Parameters:
        ///     - message: `Data` to encrypt
        ///     - aad: Additional authenticated data `Data`
        ///     - nonce: Nonce `Data`
        ///     - key: Key `Data`
        ///
        /// - Returns: Authenticated ciphertext `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.

        let mlen = message.count

        try ensure(
            mlen <= xchacha20poly1305IetfMessageBytesMax,
            raising: .valueError(
                "Message must be at most \(xchacha20poly1305IetfMessageBytesMax) bytes long"))

        try ensure(
            nonce.count == xchacha20poly1305IetfNpubBytes,
            raising: .typeError(
                "Nonce must be a \(xchacha20poly1305IetfNpubBytes) bytes long bytes sequence"))

        try ensure(
            key.count == xchacha20poly1305IetfKeyBytes,
            raising: .typeError(
                "Key must be a \(xchacha20poly1305IetfKeyBytes) bytes long bytes sequence"))

        let _aad = aad ?? Data()
        let aalen = aad?.count ?? 0

        let mxout = mlen + xchacha20poly1305IetfABytes

        var clen = UInt64(0)

        var ciphertext = Data(repeating: 0, count: mxout)

        let res = message.withUnsafeBytes { messagePtr in
            ciphertext.withUnsafeMutableBytes { ciphertextPtr in
                _aad.withUnsafeBytes { aadPtr in
                    nonce.withUnsafeBytes { noncePtr in
                        key.withUnsafeBytes { keyPtr in
                            guard let messageRawPtr = messagePtr.baseAddress,
                                let ciphertextRawPtr = ciphertextPtr.baseAddress,
                                let aadERawPtr = aadPtr.baseAddress,
                                let nonceRawPtr = noncePtr.baseAddress,
                                let keyRawPtr = keyPtr.baseAddress
                            else {
                                return Int32(-1)
                            }
                            return crypto_aead_xchacha20poly1305_ietf_encrypt(
                                ciphertextRawPtr,
                                &clen,
                                messageRawPtr,
                                UInt64(mlen),
                                aadERawPtr,
                                UInt64(aalen),
                                nil,
                                nonceRawPtr,
                                keyRawPtr
                            )
                        }
                    }
                }
            }
        }

        try ensure(res == 0, raising: .cryptoError("Encryption failed."))

        return Data(ciphertext[0..<Int(clen)])
    }

    public func xchacha20poly1305IetfDecrypt(ciphertext: Data, aad: Data?, nonce: Data, key: Data)
        throws -> Data
    {
        /// Decrypt the given ``ciphertext`` using the long-nonces xchacha20poly1305 construction.
        ///
        /// - Parameters:
        ///     - ciphertext: `Data` to decrypt
        ///     - aad: Additional authenticated data `Data`
        ///     - nonce: Nonce `Data`
        ///     - key: Key `Data`
        ///
        /// - Returns: The decrypted message `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.

        let clen = ciphertext.count

        try ensure(
            clen <= xchacha20poly1305IetfCryptBytesMax,
            raising: .valueError(
                "Ciphertext must be at most \(xchacha20poly1305IetfCryptBytesMax) bytes long"))

        try ensure(
            nonce.count == xchacha20poly1305IetfNpubBytes,
            raising: .typeError(
                "Nonce must be a \(xchacha20poly1305IetfNpubBytes) bytes long bytes sequence"))

        try ensure(
            key.count == xchacha20poly1305IetfKeyBytes,
            raising: .typeError(
                "Key must be a \(xchacha20poly1305IetfKeyBytes) bytes long bytes sequence"))

        let mxout = clen - xchacha20poly1305IetfABytes

        var mlen = UInt64(0)

        var message = [UInt8](repeating: 0, count: mxout)

        let _aad = aad ?? Data()
        let aalen = aad?.count ?? 0

        let res = message.withUnsafeMutableBytes { messagePtr in
            ciphertext.withUnsafeBytes { ciphertextPtr in
                _aad.withUnsafeBytes { aadPtr in
                    nonce.withUnsafeBytes { noncePtr in
                        key.withUnsafeBytes { keyPtr in
                            guard let messageRawPtr = messagePtr.baseAddress,
                                let ciphertextRawPtr = ciphertextPtr.baseAddress,
                                let aadERawPtr = aadPtr.baseAddress,
                                let nonceRawPtr = noncePtr.baseAddress,
                                let keyRawPtr = keyPtr.baseAddress
                            else {
                                return Int32(-1)
                            }
                            return crypto_aead_xchacha20poly1305_ietf_decrypt(
                                messageRawPtr,
                                &mlen,
                                nil,
                                ciphertextRawPtr,
                                UInt64(clen),
                                aadERawPtr,
                                UInt64(aalen),
                                nonceRawPtr,
                                keyRawPtr
                            )
                        }
                    }
                }
            }
        }

        try ensure(res == 0, raising: .cryptoError("Decryption failed."))

        return Data(message[0..<Int(mlen)])
    }

}
