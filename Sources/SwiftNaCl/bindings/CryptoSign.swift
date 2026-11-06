import Foundation
import Clibsodium

/// The SHA-512 state used for an incremental Ed25519ph (pre-hashed) signature.
///
/// Feed message chunks with ``CryptoSign/ed25519phUpdate(edph:pmsg:)``, then call
/// ``CryptoSign/ed25519phFinalCreate(edph:sk:)`` or
/// ``CryptoSign/ed25519phFinalVerify(edph:signature:pk:)``.
public class CryptoSignEd25519phState {
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

/// Bindings to libsodium's Ed25519 signatures (`crypto_sign`), including
/// Ed25519ph (pre-hashed) signing and Ed25519-to-Curve25519 key conversion.
public struct CryptoSign {
    /// The size of a signature in bytes (64).
    public let bytes = crypto_sign_bytes()
    /// The size of a seed in bytes (32).
    public let seedBytes = crypto_sign_secretkeybytes() / 2
    /// The size of a public key in bytes (32).
    public let publicKeyBytes = crypto_sign_publickeybytes()
    /// The size of a secret key (seed and public key) in bytes (64).
    public let secretKeyBytes = crypto_sign_secretkeybytes()
    /// The size of a Curve25519 key in bytes (32).
    public let curve25519Bytes = crypto_box_secretkeybytes()
    /// The size of the Ed25519ph hash state in bytes.
    public let ed25519phStateBytes = crypto_sign_ed25519ph_statebytes()
    
    /// Returns a randomly generated public key and secret key.
    ///
    /// - Returns: A tuple containing the public key and secret key.
    /// - Throws: A ``SodiumError`` if keypair generation fails.
    public func keypair() throws -> (publicKey: Data, secretKey: Data) {
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

    /// Computes the Ed25519 public key and secret key from `seed`.
    ///
    /// - Parameters:
    ///   - seed: A ``seedBytes``-byte (32) seed.
    ///
    /// - Returns: A tuple containing the public key and secret key.
    /// - Throws: A ``SodiumError`` if keypair generation fails.
    public func seedKeypair(seed: Data) throws -> (publicKey: Data, secretKey: Data) {
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

    /// Signs `message` with the secret key `sk` and returns the signed message.
    ///
    /// - Parameters:
    ///   - message: The message to sign.
    ///   - sk: The 64-byte Ed25519 secret key.
    ///
    /// - Returns: The signature followed by the message.
    /// - Throws: A ``SodiumError`` if the signature could not be created.
    public func sign(message: Data, sk: Data) throws -> Data {
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

    /// Verifies the signed message `signed` with the public key `pk` and returns the message.
    ///
    /// - Parameters:
    ///   - signed: The signature followed by the message, as returned by ``sign(message:sk:)``.
    ///   - pk: The 32-byte Ed25519 public key.
    ///
    /// - Returns: The message without its signature.
    /// - Throws: A ``SodiumError`` if the signature is forged or corrupt.
    public func open(signed: Data, pk: Data) throws -> Data {
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

    /// Converts an Ed25519 public key to a Curve25519 public key.
    ///
    /// - Parameter publicKeyBytes: The 32-byte Ed25519 public key.
    ///
    /// - Returns: The public Curve25519 key as bytes.
    /// - Throws: A ``SodiumError`` if the public key is invalid.
    public func ed25519PkToCurve25519(publicKeyBytes: Data) throws -> Data {
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

    /// Converts an Ed25519 secret key to a Curve25519 secret key.
    ///
    /// - Parameter secretKeyBytes: The 64-byte Ed25519 secret key.
    ///
    /// - Returns: The secret Curve25519 key as bytes.
    /// - Throws: A ``SodiumError`` if the secret key is invalid.
    public func ed25519SkToCurve25519(secretKeyBytes: Data) throws -> Data {
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

    /// Extracts the Ed25519 public key from an Ed25519 secret key.
    ///
    /// - Parameter secretKeyBytes: The 64-byte Ed25519 secret key.
    ///
    /// - Returns: The public Ed25519 key as bytes.
    /// - Throws: A ``SodiumError`` if the secret key is invalid.
    public func ed25519SkToPk(secretKeyBytes: Data) throws -> Data {
        try ensure(secretKeyBytes.count == self.secretKeyBytes, raising: .valueError("Invalid curve secret key"))
        
        return secretKeyBytes.suffix(from: seedBytes)
    }

    /// Extracts the seed from an Ed25519 secret key.
    ///
    /// - Parameter secretKeyBytes: The 64-byte Ed25519 secret key.
    ///
    /// - Returns: The seed as bytes.
    /// - Throws: A ``SodiumError`` if the secret key is invalid.
    public func ed25519SkToSeed(secretKeyBytes: Data) throws -> Data {
        try ensure(secretKeyBytes.count == self.secretKeyBytes, raising: .valueError("Invalid curve secret key"))
        
        return secretKeyBytes.prefix(seedBytes)
    }

    /// Adds a chunk of the message to the Ed25519ph hash state.
    ///
    /// - Parameters:
    ///   - edph: The Ed25519ph state to update.
    ///   - pmsg: The next chunk of the message.
    ///
    /// - Throws: A ``SodiumError`` if the state or message are invalid.
    public func ed25519phUpdate(edph: CryptoSignEd25519phState, pmsg: Data) throws {
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

    /// Creates an Ed25519ph signature for the data hashed into `edph`, using the secret key `sk`.
    ///
    /// - Parameters:
    ///   - edph: The Ed25519ph state holding the hashed message.
    ///   - sk: The 64-byte Ed25519 secret key (seed and public key).
    ///
    /// - Returns: The 64-byte Ed25519ph signature.
    /// - Throws: A ``SodiumError`` if the state or message are invalid.
    public func ed25519phFinalCreate(edph: CryptoSignEd25519phState, sk: Data) throws -> Data {
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

    /// Verifies an Ed25519ph signature over the data hashed into `edph`, using the public key `pk`.
    ///
    /// - Parameters:
    ///   - edph: The Ed25519ph state holding the hashed message.
    ///   - signature: The 64-byte signature to verify.
    ///   - pk: The 32-byte Ed25519 public key.
    ///
    /// - Returns: `true` when the signature is valid. An invalid signature throws instead.
    /// - Throws: ``SodiumError/typeError(_:)`` if the signature or public key has the wrong
    ///   length, or ``SodiumError/badSignatureError(_:)`` if the signature is forged or corrupt.
    public func ed25519phFinalVerify(edph: CryptoSignEd25519phState, signature: Data, pk: Data) throws -> Bool {
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
        try ensure(rc == 0, raising: .badSignatureError("Signature was forged or corrupt"))
        
        return true
    }

}
