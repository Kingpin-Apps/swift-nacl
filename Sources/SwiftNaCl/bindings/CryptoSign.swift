import Foundation
import Clibsodium

public class CryptoSignEd25519phState {
    /// State object wrapping the sha-512 state used in ed25519ph computation
    var state: Data
    
    init() throws {
        state = Data(count: crypto_sign_ed25519ph_statebytes())
        
        let rc: Int32 = state.withUnsafeMutableBytes { (statePtr: UnsafeMutableRawBufferPointer) -> Int32 in
            guard let stateRawPtr = statePtr.baseAddress else {
                return -1 // Return an appropriate error code in case of failure
            }
            return crypto_sign_ed25519ph_init(stateRawPtr.assumingMemoryBound(to: crypto_sign_ed25519ph_state.self))
        }
        try ensure(rc == 0, raising: .runtimeError("Unexpected library error"))
    }
}

public struct CryptoSign {
    public let bytes = crypto_sign_bytes()
    public let seedBytes = crypto_sign_secretkeybytes() / 2
    public let publicKeyBytes = crypto_sign_publickeybytes()
    public let secretKeyBytes = crypto_sign_secretkeybytes()
    public let curve25519Bytes = crypto_box_secretkeybytes()
    public let ed25519phStateBytes = crypto_sign_ed25519ph_statebytes()
    
    public func keypair() throws -> (publicKey: Data, secretKey: Data) {
        /// Returns a randomly generated public key and secret key.
        ///
        /// - Returns: A tuple containing the public key and secret key.
        /// - Throws: Raises a `SodiumError` if keypair generation fails.
        
        var pk = Data(count: publicKeyBytes)
        var sk = Data(count: secretKeyBytes)
        
        let rc = pk.withUnsafeMutableBytes { (pkPtr: UnsafeMutableRawBufferPointer) in
            sk.withUnsafeMutableBytes { (skPtr: UnsafeMutableRawBufferPointer) in
                guard let pkRawPtr = pkPtr.baseAddress,
                      let skRawPtr = skPtr.baseAddress else {
                    return Int32(-1) // Return an appropriate error code in case of failure
                }
                return crypto_sign_keypair(pkRawPtr.assumingMemoryBound(to: UInt8.self),
                                               skRawPtr.assumingMemoryBound(to: UInt8.self))
            }
        }
        
        try ensure(rc == 0, raising: .runtimeError("Unexpected library error"))
        
        return (Data(pk.prefix(Int(publicKeyBytes))), Data(sk.prefix(Int(secretKeyBytes))))
    }

    public func seedKeypair(seed: Data) throws -> (publicKey: Data, secretKey: Data) {
        /// Computes and returns the public key and secret key using the seed ``seed``.
        ///
        /// - Parameters:
        ///     - seed: `Data`
        ///
        /// - Returns: A tuple containing the public key and secret key.
        /// - Throws: Raises a `SodiumError` if keypair generation fails.
        
        try ensure(seed.count == seedBytes, raising: .valueError("Invalid seed"))
        
        var pk = Data(count: publicKeyBytes)
        var sk = Data(count: secretKeyBytes)
        
        let rc = pk.withUnsafeMutableBytes { (pkPtr: UnsafeMutableRawBufferPointer) in
            sk.withUnsafeMutableBytes { (skPtr: UnsafeMutableRawBufferPointer) in
                seed.withUnsafeBytes { (seedPtr: UnsafeRawBufferPointer) in
                    guard let pkRawPtr = pkPtr.baseAddress,
                          let skRawPtr = skPtr.baseAddress,
                          let seedRawPtr = seedPtr.baseAddress else {
                        return Int32(-1) // Return an appropriate error code in case of failure
                    }
                    return crypto_sign_seed_keypair(pkRawPtr.assumingMemoryBound(to: UInt8.self),
                                skRawPtr.assumingMemoryBound(to: UInt8.self),
                                seedRawPtr.assumingMemoryBound(to: UInt8.self))
                        }
            }
        }
        try ensure(rc == 0, raising: .runtimeError("Unexpected library error"))
        
        return (Data(pk.prefix(Int(publicKeyBytes))), Data(sk.prefix(Int(secretKeyBytes))))
    }

    public func sign(message: Data, sk: Data) throws -> Data {
        /// Signs the message ``message`` using the secret key ``sk`` and returns the signed message.
        ///
        /// - Parameters:
        ///     - message: `Data`
        ///     - sk: `Data`
        ///
        /// - Returns: The signed message.
        /// - Throws: Raises a `SodiumError` if the signature could not be created.

        var signed = Data(count: message.count + bytes)
        var signedLen = UInt64(0)
        
        let rc = signed.withUnsafeMutableBytes { (signedPtr: UnsafeMutableRawBufferPointer) in
            sk.withUnsafeBytes { (skPtr: UnsafeRawBufferPointer) in
                message.withUnsafeBytes { (messagePtr: UnsafeRawBufferPointer) in
                        guard let signedRawPtr = signedPtr.baseAddress,
                              let skRawPtr = skPtr.baseAddress,
                              let messageRawPtr = messagePtr.baseAddress else {
                            return Int32(-1) // Return an appropriate error code in case of failure
                        }
                    return crypto_sign(
                        signedRawPtr.assumingMemoryBound(to: UInt8.self),
                        &signedLen,
                        messageRawPtr.assumingMemoryBound(to: UInt8.self),
                        UInt64(message.count),
                        skRawPtr.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        try ensure(rc == 0, raising: .runtimeError("Unexpected library error"))
        
        return Data(signed.prefix(Int(signedLen)))
    }

    public func open(signed: Data, pk: Data) throws -> Data {
        /// Verifies the signature of the signed message ``signed`` using the public key ``pk`` and returns the unsigned message.
        ///
        /// - Parameters:
        ///     - signed: `Data`
        ///     - pk: `Data`
        ///
        /// - Returns: The unsigned message.
        /// - Throws: Raises a `SodiumError` if the signature was forged or corrupt

        var message = Data(count: signed.count)
        var messageLen = UInt64(0)
        
        let rc = message.withUnsafeMutableBytes { (messagePtr: UnsafeMutableRawBufferPointer) in
            signed.withUnsafeBytes { (signedPtr: UnsafeRawBufferPointer) in
                pk.withUnsafeBytes { (pkPtr: UnsafeRawBufferPointer) in
                    guard let signedRawPtr = signedPtr.baseAddress,
                          let pkRawPtr = pkPtr.baseAddress,
                          let messageRawPtr = messagePtr.baseAddress else {
                        return Int32(-1) // Return an appropriate error code in case of failure
                    }
                    return crypto_sign_open(
                        messageRawPtr.assumingMemoryBound(to: UInt8.self),
                        &messageLen,
                        signedRawPtr.assumingMemoryBound(to: UInt8.self),
                        UInt64(signed.count),
                        pkRawPtr.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        try ensure(rc == 0, raising: .badSignatureError("Signature was forged or corrupt"))
        
        return Data(message.prefix(Int(messageLen)))
    }

    public func ed25519PkToCurve25519(publicKeyBytes: Data) throws -> Data {
        /// Converts a public Ed25519 key (encoded as bytes ``public_key_bytes``) to a public Curve25519 key as bytes.
        ///
        /// - Parameters:
        ///     - public_key_bytes: `Data`
        ///
        /// - Returns: The public Curve25519 key as bytes.
        /// - Throws: Raises a `SodiumError` if the public key is invalid.
        
        try ensure(publicKeyBytes.count == self.publicKeyBytes, raising: .valueError("Invalid curve public key"))

        let curvePublicKeyLen = curve25519Bytes
        var curvePublicKey = Data(count: curvePublicKeyLen)
        
        let rc = curvePublicKey.withUnsafeMutableBytes { (curvePublicKeyPtr: UnsafeMutableRawBufferPointer) in
            publicKeyBytes.withUnsafeBytes { (publicKeyBytesPtr: UnsafeRawBufferPointer) in
                guard let curvePublicKeyRawPtr = curvePublicKeyPtr.baseAddress,
                      let publicKeyBytesRawPtr = publicKeyBytesPtr.baseAddress else {
                    return Int32(-1)
                }
                return crypto_sign_ed25519_pk_to_curve25519(
                    curvePublicKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                    publicKeyBytesRawPtr.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        try ensure(rc == 0, raising: .runtimeError("Unexpected library error"))
        
        return Data(curvePublicKey.prefix(Int(curvePublicKeyLen)))
    }

    public func ed25519SkToCurve25519(secretKeyBytes: Data) throws -> Data {
        /// Converts a secret Ed25519 key (encoded as bytes ``secret_key_bytes``) to a secret Curve25519 key as bytes.
        ///
        /// - Parameters:
        ///     - secret_key_bytes: `Data`
        ///
        /// - Returns: The  secret Curve25519 key as bytes.
        /// - Throws: Raises a `SodiumError` if the secret key is invalid.
        
        try ensure(secretKeyBytes.count == self.secretKeyBytes, raising: .valueError("Invalid curve secret key"))
        
        let curveSecretKeyLen = curve25519Bytes
        var curveSecretKey = Data(count: curveSecretKeyLen)
        
        let rc = curveSecretKey.withUnsafeMutableBytes { (curveSecretKeyPtr: UnsafeMutableRawBufferPointer) in
            secretKeyBytes.withUnsafeBytes { (secretKeyBytesPtr: UnsafeRawBufferPointer) in
                guard let curveSecretKeyRawPtr = curveSecretKeyPtr.baseAddress,
                      let secretKeyBytesRawPtr = secretKeyBytesPtr.baseAddress else {
                    return Int32(-1) // Return an appropriate error code in case of failure
                }
                return crypto_sign_ed25519_sk_to_curve25519(curveSecretKeyRawPtr, secretKeyBytesRawPtr)
            }
        }
        try ensure(rc == 0, raising: .runtimeError("Unexpected library error"))
        
        return Data(curveSecretKey.prefix(Int(curveSecretKeyLen)))
    }

    public func ed25519SkToPk(secretKeyBytes: Data) throws -> Data {
        ///  Extract the public Ed25519 key from a secret Ed25519 key (encoded as bytes ``secret_key_bytes``).
        ///
        /// - Parameters:
        ///     - secret_key_bytes: `Data`
        ///
        /// - Returns: The public Ed25519 key as bytes.
        /// - Throws: Raises a `SodiumError` if the secret key is invalid.
        
        try ensure(secretKeyBytes.count == self.secretKeyBytes, raising: .valueError("Invalid curve secret key"))
        
        return secretKeyBytes.suffix(from: seedBytes)
    }

    public func ed25519SkToSeed(secretKeyBytes: Data) throws -> Data {
        ///  Extract the seed from a secret Ed25519 key (encoded as bytes ``secret_key_bytes``).
        ///
        /// - Parameters:
        ///     - secret_key_bytes: `Data`
        ///
        /// - Returns: The seed as bytes.
        /// - Throws: Raises a `SodiumError` if the secret key is invalid.
        
        try ensure(secretKeyBytes.count == self.secretKeyBytes, raising: .valueError("Invalid curve secret key"))
        
        return secretKeyBytes.prefix(seedBytes)
    }

    public func ed25519phUpdate(edph: CryptoSignEd25519phState, pmsg: Data) throws {
        ///  Update the hash state wrapped in edph
        ///
        /// - Parameters:
        ///     - edph: The ed25519ph state being updated `CryptoSignEd25519phState`
        ///     - pmsg: The partial message `Data`
        ///
        /// - Returns: The updated state
        /// - Throws: Raises a `SodiumError` if the state or message are invalid.
        
        let rc = edph.state.withUnsafeMutableBytes { (statePtr: UnsafeMutableRawBufferPointer) in
            pmsg.withUnsafeBytes { (pmsgPtr: UnsafeRawBufferPointer) in
                guard let stateRawPtr = statePtr.baseAddress,
                      let pmsgRawPtr = pmsgPtr.baseAddress else {
                    return Int32(-1) // Return an appropriate error code in case of failure
                }
                return crypto_sign_ed25519ph_update(
                    stateRawPtr.assumingMemoryBound(to: crypto_sign_ed25519ph_state.self),
                    pmsgRawPtr.assumingMemoryBound(to: UInt64.self),
                    UInt64(pmsg.count))
            }
        }
        try ensure(rc == 0, raising: .runtimeError("Unexpected library error"))
    }

    public func ed25519phFinalCreate(edph: CryptoSignEd25519phState, sk: Data) throws -> Data {
        ///  Create a signature for the data hashed in edph using the secret key sk
        ///
        /// - Parameters:
        ///     - edph: the ed25519ph state for the data being signed `CryptoSignEd25519phState`
        ///     - sk: the ed25519 secret key (secret and public part) `Data`
        ///
        /// - Returns: The ed25519ph signature `Data`
        /// - Throws: Raises a `SodiumError` if the state or message are invalid.
        
        try ensure(sk.count == secretKeyBytes, raising: .typeError("secret key must be \(secretKeyBytes) bytes long"))
        
        var signature = Data(count: bytes)
        
        let rc = signature.withUnsafeMutableBytes { (signaturePtr: UnsafeMutableRawBufferPointer) in
            edph.state.withUnsafeMutableBytes { (statePtr: UnsafeMutableRawBufferPointer) in
                sk.withUnsafeBytes { (skPtr: UnsafeRawBufferPointer) in
                    guard let signatureRawPtr = signaturePtr.baseAddress,
                          let stateRawPtr = statePtr.baseAddress,
                          let skRawPtr = skPtr.baseAddress else {
                        return Int32(-1) // Return an appropriate error code in case of failure
                    }
                    return crypto_sign_ed25519ph_final_create(
                        stateRawPtr.assumingMemoryBound(to: crypto_sign_ed25519ph_state.self),
                        signatureRawPtr.assumingMemoryBound(to: UInt8.self),
                        nil,
                        skRawPtr.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        try ensure(rc == 0, raising: .runtimeError("Unexpected library error"))
        
        return Data(signature.prefix(Int(bytes)))
    }

    public func ed25519phFinalVerify(edph: CryptoSignEd25519phState, signature: Data, pk: Data) throws -> Bool {
        ///  Verify a prehashed signature using the public key pk
        ///
        /// - Parameters:
        ///     - edph: The ed25519ph state for the data being signed `CryptoSignEd25519phState`
        ///     - signature: The signature being verified `Data`
        ///     - signature: The ed25519 public part of the signing key `Data`
        ///
        /// - Returns: True if the signature is valid `bool`
        /// - Throws: Raises a `SodiumError` if the signature or public key are invalid.
        
        try ensure(signature.count == bytes, raising: .typeError("signature must be \(bytes) bytes long"))
        try ensure(pk.count == publicKeyBytes, raising: .typeError("public key must be \(publicKeyBytes) bytes long"))
        
        let rc = edph.state.withUnsafeMutableBytes { (statePtr: UnsafeMutableRawBufferPointer) in
            signature.withUnsafeBytes { (signaturePtr: UnsafeRawBufferPointer) in
                pk.withUnsafeBytes { (pkPtr: UnsafeRawBufferPointer) in
                    guard let stateRawPtr = statePtr.baseAddress,
                          let signatureRawPtr = signaturePtr.baseAddress,
                          let pkRawPtr = pkPtr.baseAddress else {
                        return Int32(-1) // Return an appropriate error code in case of failure
                    }
                    return crypto_sign_ed25519ph_final_verify(
                        stateRawPtr.assumingMemoryBound(to: crypto_sign_ed25519ph_state.self),
                        signatureRawPtr.assumingMemoryBound(to: UInt8.self),
                        pkRawPtr.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        try ensure(rc != 0, raising: .badSignatureError("Signature was forged or corrupt"))
        
        return true
    }

}
