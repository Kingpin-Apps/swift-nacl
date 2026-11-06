import Clibsodium
import Foundation

/// One-shot hashing and keyed hashing helpers: SHA-256, SHA-512, BLAKE2b and SipHash.
///
/// Digests are hex-encoded by default; pass `encoder: RawEncoder.self` for raw bytes.
public struct Hash {
    /// Default digest size for `blake2b` hash
    public let blake2bBytes: Int
    /// Minimum allowed digest size for `blake2b` hash
    public let blake2bBytesMin: Int
    /// Maximum allowed digest size for `blake2b` hash
    public let blake2bBytesMax: Int
    /// Default size of the `key` byte array for `blake2b` hash
    public let blake2bKeyBytes: Int
    /// Minimum allowed size of the `key` byte array for `blake2b` hash
    public let blake2bKeyBytesMin: Int
    /// Maximum allowed size of the `key` byte array for `blake2b` hash
    public let blake2bKeyBytesMax: Int
    /// Maximum allowed length of the `salt` byte array for `blake2b` hash
    public let blake2bSaltBytes: Int
    /// Maximum allowed length of the `personalization` byte array for `blake2b` hash
    public let blake2bPersonalBytes: Int

    /// Size of the `siphash24` digest
    public let siphashBytes: Int
    /// Size of the secret `key` used by the `siphash24` MAC
    public let siphashKeyBytes: Int

    /// Size of the `siphashx24` digest
    public let siphashxBytes: Int
    /// Size of the secret `key` used by the `siphashx24` MAC
    public let siphashxKeyBytes: Int
    
    private let sodium: Sodium
    
    public init() {
        self.sodium = Sodium()
        
        self.blake2bBytes = sodium.cryptoGenericHash.bytes
        self.blake2bBytesMin = sodium.cryptoGenericHash.bytesMin
        self.blake2bBytesMax = sodium.cryptoGenericHash.bytesMax
        self.blake2bKeyBytes = sodium.cryptoGenericHash.keyBytes
        self.blake2bKeyBytesMin = sodium.cryptoGenericHash.keyBytesMin
        self.blake2bKeyBytesMax = sodium.cryptoGenericHash.keyBytesMax
        self.blake2bSaltBytes = sodium.cryptoGenericHash.saltBytes
        self.blake2bPersonalBytes = sodium.cryptoGenericHash.personalBytes

        self.siphashBytes = sodium.cryptoShortHash.bytes
        self.siphashKeyBytes = sodium.cryptoShortHash.keyBytes

        self.siphashxBytes = sodium.cryptoShortHash.xBytes
        self.siphashxKeyBytes = sodium.cryptoShortHash.xKeyBytes
    }

    /// Hashes `message` with SHA256.
    ///
    /// - Parameters:
    ///   - message: The message to hash.
    ///   - encoder: The encoder applied to the digest (hex by default).
    /// - Returns: The encoded digest.
    /// - Throws: A ``SodiumError`` if hashing fails.
    public func sha256(message: Data, encoder: Encoder.Type = HexEncoder.self) throws -> Data {
        return encoder.encode(data: try sodium.cryptoHash.sha256(message: message))
    }

    /// Hashes `message` with SHA512.
    ///
    /// - Parameters:
    ///   - message: The message to hash.
    ///   - encoder: The encoder applied to the digest (hex by default).
    /// - Returns: The encoded digest.
    /// - Throws: A ``SodiumError`` if hashing fails.
    public func sha512(message: Data, encoder: Encoder.Type  = HexEncoder.self) throws -> Data {
        return encoder
            .encode(data: try sodium.cryptoHash.sha512(message: message))
    }

    /// Hashes `data` with BLAKE2b, optionally keyed, salted and personalized.
    ///
    /// - Parameters:
    ///   - data: The digest input byte sequence.
    ///   - digestSize: The requested digest size; must be at most `blake2bBytesMax`; the default digest size is `blake2bBytes`.
    ///   - key: The key to be set for keyed MAC/PRF usage; if set, the key must be at most `blake2bKeyBytesMax` long.
    ///   - salt: An initialization salt at most `blake2bSaltBytes` long; it will be zero-padded if needed.
    ///   - person: A personalization string at most `blake2bPersonalBytes` long; it will be zero-padded if needed.
    ///   - encoder: The encoder applied to the digest (hex by default).
    /// - Returns: The encoded digest.
    /// - Throws: A ``SodiumError`` if a parameter is out of range.
    public func blake2b(data: Data, digestSize: Int? = nil, key: Data = Data(), salt: Data = Data(), person: Data = Data(), encoder: Encoder.Type = HexEncoder.self) throws -> Data {
        let digest = try sodium.cryptoGenericHash.blake2bSaltPersonal(
            data: data,
            digestSize: digestSize ?? blake2bBytes,
            key: key,
            salt: salt,
            person: person
        )
        return encoder.encode(data: digest)
    }

    /// Computes a keyed MAC of `message` using the short-input-optimized siphash-2-4 construction.
    ///
    /// - Parameters:
    ///   - message: The message to hash.
    ///   - key: The 16-byte (``siphashKeyBytes``) secret key.
    ///   - encoder: The encoder applied to the digest (hex by default).
    /// - Returns: The encoded 8-byte digest.
    /// - Throws: ``SodiumError/valueError(_:)`` if the key is not 16 bytes long.
    public func siphash24(message: Data, key: Data = Data(), encoder: Encoder.Type = HexEncoder.self) throws -> Data {
        let digest = try sodium.cryptoShortHash.siphash24(
            data: message,
            key: key
        )
        return encoder.encode(data: digest)
    }

    /// Computes a keyed MAC of `message` using the 128 bit variant of the siphash-2-4 construction.
    ///
    /// - Parameters:
    ///   - message: The message to hash.
    ///   - key: The 16-byte (``siphashxKeyBytes``) secret key.
    ///   - encoder: The encoder applied to the digest (hex by default).
    /// - Returns: The encoded 16-byte digest.
    /// - Throws: ``SodiumError/valueError(_:)`` if the key is not 16 bytes long.
    public func siphashx24(message: Data, key: Data = Data(), encoder: Encoder.Type = HexEncoder.self) throws -> Data {
        let digest = try sodium.cryptoShortHash.siphashx24(
            data: message,
            key: key
        )
        return encoder.encode(data: digest)
    }
}
