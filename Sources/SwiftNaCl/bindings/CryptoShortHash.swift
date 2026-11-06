import Clibsodium
import Foundation

/// Bindings to libsodium's short-input keyed hash (`crypto_shorthash`, SipHash).
///
/// Useful for hash tables and other places that need a fast keyed hash, not
/// as a general-purpose cryptographic hash.
public struct CryptoShortHash {
    /// The size of a SipHash-2-4 hash in bytes (8).
    public let bytes = crypto_shorthash_siphash24_bytes()
    /// The size of a SipHash-2-4 key in bytes (16).
    public let keyBytes = crypto_shorthash_siphash24_keybytes()

    /// The size of a SipHashX-2-4 hash in bytes (16).
    public let xBytes = crypto_shorthash_siphashx24_bytes()
    /// The size of a SipHashX-2-4 key in bytes (16).
    public let xKeyBytes = crypto_shorthash_siphashx24_keybytes()
    
    /// Computes a fast, cryptographic-quality keyed hash of `data` with SipHash-2-4
    /// (`crypto_shorthash_siphash24`).
    ///
    /// - Parameters:
    ///   - data: The input data to hash.
    ///   - key: The ``keyBytes``-byte (16) secret key.
    /// - Returns: The ``bytes``-byte (8) hash.
    /// - Throws: ``SodiumError/valueError(_:)`` if the key has the wrong length, or
    ///   ``SodiumError/runtimeError(_:)`` if hashing fails.
    public func siphash24(data: Data, key: Data) throws -> Data {
        try ensure(key.count == keyBytes, raising: .valueError("Invalid key"))
        
        var digest = [UInt8](repeating: 0, count: bytes)
        let rc = crypto_shorthash_siphash24(
            &digest,
            [UInt8](data),
            UInt64(data.count),
            [UInt8](key)
        )
        
        try ensure(rc == 0, raising: .runtimeError("Unexpected failure"))
        
        return Data(digest)
    }
    
    /// Computes a 128-bit keyed hash of `data` with SipHashX-2-4
    /// (`crypto_shorthash_siphashx24`).
    ///
    /// - Parameters:
    ///   - data: The input data to hash.
    ///   - key: The ``xKeyBytes``-byte (16) secret key.
    /// - Returns: The ``xBytes``-byte (16) hash.
    /// - Throws: ``SodiumError/valueError(_:)`` if the key has the wrong length, or
    ///   ``SodiumError/runtimeError(_:)`` if hashing fails.
    public func siphashx24(data: Data, key: Data) throws -> Data {
        try ensure(key.count == xKeyBytes, raising: .valueError("Invalid key"))
        
        var digest = [UInt8](repeating: 0, count: xBytes)
        let rc = crypto_shorthash_siphashx24(
            &digest,
            [UInt8](data),
            UInt64(data.count),
            [UInt8](key)
        )
        
        try ensure(rc == 0, raising: .runtimeError("Unexpected failure"))
        
        return Data(digest)
    }
}
