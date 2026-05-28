import Clibsodium
import Foundation

public class Blake2b {
    /// Maximum digest size
    public let maxDigestSize: Int
    /// Maximum key size
    public let maxKeySize: Int
    /// Personalization size
    public let personSize: Int
    /// Salt size
    public let saltSize: Int

    private var state: Blake2State
    private var digestSize: Int
    
    private let sodium: Sodium

    /// Blake2b algorithm initializer
    ///
    /// - Parameters:
    ///   - data: The data to hash.
    ///   - digestSize: The requested digest size; must be at most `maxDigestSize`; the default digest size is `bytes`.
    ///   - key: The key to be set for keyed MAC/PRF usage; if set, the key must be at most `maxKeySize` long.
    ///   - salt: An initialization salt at most `saltSize` long; it will be zero-padded if needed.
    ///   - person: A personalization string at most `personSize` long; it will be zero-padded if needed.
    public init(data: Data = Data(), digestSize: Int? = nil, key: Data = Data(), salt: Data = Data(), person: Data = Data()) throws {
        self.sodium = Sodium()
        
        self.maxDigestSize = sodium.cryptoGenericHash.bytes
        self.maxKeySize = sodium.cryptoGenericHash.keyBytes
        self.personSize = sodium.cryptoGenericHash.personalBytes
        self.saltSize = sodium.cryptoGenericHash.saltBytes
        
        self.state = try sodium.cryptoGenericHash
            .blake2bInit(
                key: key,
                salt: salt,
                person: person,
                digestSize: digestSize ?? maxDigestSize
            )
        self.digestSize = digestSize ?? maxDigestSize

        if !data.isEmpty {
            try self.update(data: data)
        }
    }

    public var blockSize: Int {
        return 128
    }

    public var name: String {
        return "blake2b"
    }

    public func update(data: Data) throws {
        try sodium.cryptoGenericHash.blake2bUpdate(state: self.state, data: data)
    }

    public func digest() throws -> Data {
        return try sodium.cryptoGenericHash.blake2bFinal(state: self.state)
    }

    public func hexdigest() throws -> String {
        return bytesAsString(bytesIn: try digest())
    }

    public func copy() throws -> Blake2b {
        let copy = try Blake2b(
            digestSize: self.digestSize)
        copy.state = self.state.copy()
        return copy
    }

    public func reduce() throws -> Never {
        throw SodiumError.unavailableError("can't pickle Blake2b objects")
    }
}

public struct Hashlib {
    public let bytes: Int
    /// Default digest size for `blake2b` hash
    public let bytesMin: Int
    /// Minimum allowed digest size for `blake2b` hash
    public let bytesMax: Int
    /// Maximum allowed digest size for `blake2b` hash
    public let keyBytes: Int
    /// Default size of the `key` byte array for `blake2b` hash
    public let keyBytesMin: Int
    /// Minimum allowed size of the `key` byte array for `blake2b` hash
    public let keyBytesMax: Int
    /// Maximum allowed size of the `key` byte array for `blake2b` hash
    public let saltBytes: Int
    /// Maximum allowed length of the `salt` byte array for `blake2b` hash
    public let personalBytes: Int
    /// Maximum allowed length of the `personalization` byte array for `blake2b` hash
    
    private let sodium: Sodium

    public init() {
        self.sodium = Sodium()
        
        self.bytes = sodium.cryptoGenericHash.bytes
        self.bytesMin = sodium.cryptoGenericHash.bytesMin
        self.bytesMax = sodium.cryptoGenericHash.bytesMax
        self.keyBytes = sodium.cryptoGenericHash.keyBytes
        self.keyBytesMin = sodium.cryptoGenericHash.keyBytesMin
        self.keyBytesMax = sodium.cryptoGenericHash.keyBytesMax
        self.saltBytes = sodium.cryptoGenericHash.saltBytes
        self.personalBytes = sodium.cryptoGenericHash.personalBytes
    }
    
    public func scrypt(password: Data, salt: Data = Data(), n: Int = 1 << 4, r: Int = 8, p: Int = 1, maxmem: Int = 1 << 25, dklen: Int = 64) throws -> Data {
        /// Derive a cryptographic key using the scrypt KDF.
        ///
        /// - Parameters:
        ///   - password: The password to hash.
        ///   - salt: The salt to use.
        ///   - n: CPU/memory cost parameter.
        ///   - r: Block size parameter.
        ///   - p: Parallelization parameter.
        ///   - maxmem: Maximum memory to use.
        ///   - dklen: Desired key length.
        /// - Returns: The derived key.
        /// - Throws: `UnavailableError` if called when using a minimal build of libsodium.
        return try sodium.cryptoPwHash
            .scryptsalsa208sha256LL(
                passwd: password,
                salt: salt,
                n: n,
                r: r,
                p: p,
                dklen: dklen,
                maxmem: maxmem
            )
    }
}
