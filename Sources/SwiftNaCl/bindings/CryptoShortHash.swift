import Clibsodium
import Foundation

public struct CryptoShortHash {
    let bytes = crypto_shorthash_siphash24_bytes()
    let keyBytes = crypto_shorthash_siphash24_keybytes()
    
    var xBytes = crypto_shorthash_siphashx24_bytes()
    var xKeyBytes = crypto_shorthash_siphashx24_keybytes()
    
    /**
     Computes a fast, cryptographic quality, keyed hash of the input data.
     
     - Parameters:
     - data: The input data to hash.
     - key: The key to use for hashing.
     - Returns: The computed hash as `Data`.
     - Throws: `CryptoError.invalidKey` if the key length is invalid.
     `CryptoError.encryptionFailed` if hashing fails.
     */
    func siphash24(data: Data, key: Data) throws -> Data {
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
    
    /**
     Computes a fast, cryptographic quality, keyed hash of the input data using SipHashX24.
     
     - Parameters:
     - data: The input data to hash.
     - key: The key to use for hashing.
     - Returns: The computed hash as `Data`.
     - Throws: `CryptoError.unavailable` if the function is not available.
     `CryptoError.invalidKey` if the key length is invalid.
     `CryptoError.encryptionFailed` if hashing fails.
     */
    func siphashx24(data: Data, key: Data) throws -> Data {
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
