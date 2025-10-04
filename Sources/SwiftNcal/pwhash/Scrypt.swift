import Clibsodium
import Foundation

public struct Scrypt {
    public let strbytesPlusOne: Int
    
    public let strPrefix: String

    public let saltBytes: Int
    
    public let passwdMin: Int
    public let passwdMax: Int

    public let pwhashSize: Int
    
    public let bytesMin: Int
    public let bytesMax: Int
    
    public let memLimitMin: Int
    public let memLimitMax: Int
    public let opsLimitMin: Int
    public let opsLimitMax: Int
    public let opsLimitInteractive: Int
    public let memLimitInteractive: Int
    public let opsLimitModerate: Int
    public let memLimitModerate: Int
    public let opsLimitSensitive: Int
    public let memLimitSensitive: Int
    
    private let sodium: Sodium
    
    public init() {
        self.sodium = Sodium()
        
        self.strbytesPlusOne = sodium.cryptoPwHash.scryptsalsa208sha256Strbytes
        self.strPrefix = sodium.cryptoPwHash.scryptsalsa208sha256Strprefix

        self.saltBytes = sodium.cryptoPwHash.scryptsalsa208sha256Saltbytes
        
        self.passwdMin = sodium.cryptoPwHash.scryptsalsa208sha256PasswdMin
        self.passwdMax = sodium.cryptoPwHash.scryptsalsa208sha256PasswdMax

        self.pwhashSize = sodium.cryptoPwHash.scryptsalsa208sha256Strbytes - 1
        
        self.bytesMin = sodium.cryptoPwHash.scryptsalsa208sha256BytesMin
        self.bytesMax = sodium.cryptoPwHash.scryptsalsa208sha256BytesMax
        
        self.memLimitMin = sodium.cryptoPwHash.scryptsalsa208sha256MemlimitMin
        self.memLimitMax = sodium.cryptoPwHash.scryptsalsa208sha256MemlimitMax
        self.opsLimitMin = sodium.cryptoPwHash.scryptsalsa208sha256OpslimitMin
        self.opsLimitMax = sodium.cryptoPwHash.scryptsalsa208sha256OpslimitMax
        self.opsLimitInteractive = sodium.cryptoPwHash.scryptsalsa208sha256OpslimitInteractive
        self.memLimitInteractive = sodium.cryptoPwHash.scryptsalsa208sha256MemlimitInteractive
        self.opsLimitModerate = 8 * sodium.cryptoPwHash.scryptsalsa208sha256OpslimitInteractive
        self.memLimitModerate = 8 * sodium.cryptoPwHash.scryptsalsa208sha256MemlimitInteractive
        self.opsLimitSensitive = sodium.cryptoPwHash.scryptsalsa208sha256OpslimitSensitive
        self.memLimitSensitive = sodium.cryptoPwHash.scryptsalsa208sha256MemlimitSensitive
    }

    /**
     Derive a `size` bytes long key from a caller-supplied
     `password` and `salt` pair using the scryptsalsa208sha256
     memory-hard construct.

     the enclosing module provides the constants

     - `opsLimitInteractive`
     - `memLimitInteractive`
     - `opsLimitSensitive`
     - `memLimitSensitive`
     - `opsLimitModerate`
     - `memLimitModerate`

     as a guidance for correct settings respectively for the
     interactive login and the long term key protecting sensitive data
     use cases.

     - parameter size: derived key size, must be between `bytesMin` and `bytesMax`
     - parameter password: password used to seed the key derivation procedure; it length must be between `passwdMin` and `passwdMax`
     - parameter salt: **RANDOM** salt used in the key derivation procedure; its length must be exactly `saltBytes`
     - parameter opsLimit: the time component (operation count) of the key derivation procedure's computational cost; it must be between `opsLimitMin` and `opsLimitMax`
     - parameter memLimit: the memory occupation component of the key derivation procedure's computational cost; it must be between `memLimitMin` and `memLimitMax`
     - parameter encoder: a closure that will be used to encode the output key; the default is the identity
     - returns: bytes
     - throws: UnavailableError if called when using a minimal build of libsodium

     .. versionadded:: 1.2
     */
    public func kdf(size: Int, password: Data, salt: Data, opsLimit: Int? = nil, memLimit: Int? = nil, encoder: (Data) -> Data = { $0 }) throws -> Data {
        let memLim = memLimit ?? memLimitSensitive
        let opsLim = opsLimit ?? opsLimitSensitive
        
        try ensure(
            salt.count == saltBytes,
            raising:
                    .valueError(
                        "The salt must be exactly \(saltBytes), not \(salt.count) bytes long"
                    )
        )
        
        // Validate operations limit
        try ensure(
            opsLim >= opsLimitMin && opsLim <= opsLimitMax,
            raising:
                    .valueError(
                        "The operations limit must be between \(opsLimitMin) and \(opsLimitMax), not \(opsLim)"
                    )
        )
        
        // Validate memory limit
        try ensure(
            memLim >= memLimitMin && memLim <= memLimitMax,
            raising:
                    .valueError(
                        "The memory limit must be between \(memLimitMin) and \(memLimitMax), not \(memLim)"
                    )
        )

        let (nLog2, r, p) = sodium.cryptoPwHash.naclBindingsPickScryptParams(
            opsLimit: opsLim,
            memLimit: memLim
        )
        let maxMem = memLim + (1 << 16)

        return encoder(
            try sodium.cryptoPwHash
                .scryptsalsa208sha256LL(
                    passwd: password,
                    salt: salt,
                    n: Int(pow(2.0, Double(nLog2))),
                    r: r,
                    p: p,
                    dklen: size,
                    maxmem: maxMem
                )
        )
    }

    /**
     Hashes a password with a random salt, using the memory-hard
     scryptsalsa208sha256 construct and returning an ascii string
     that has all the needed info to check against a future password

     The default settings for opsLimit and memLimit are those deemed
     correct for the interactive user login case.

     - parameter password: bytes
     - parameter opsLimit: int
     - parameter memLimit: int
     - returns: string
     - throws: UnavailableError if called when using a minimal build of libsodium

     .. versionadded:: 1.2
     */
    public func str(password: Data, opsLimit: Int? = nil, memLimit: Int? = nil) throws -> String {
        return try sodium.cryptoPwHash.scryptsalsa208sha256Str(
            passwd: password,
            opsLimit: opsLimit,
            memLimit: memLimit
        )
    }

    /**
     Takes the output of scryptsalsa208sha256 and compares it against
     a user provided password to see if they are the same

     - parameter passwordHash: bytes
     - parameter password: bytes
     - returns: boolean
     - throws: UnavailableError if called when using a minimal build of libsodium

     .. versionadded:: 1.2
     */
    public func verify(passwordHash: Data, password: Data) throws -> Bool {
        // Validate password hash length with some tolerance for platform differences
        // but still enforce reasonable bounds
        try ensure(
            passwordHash.count >= pwhashSize - 1 && passwordHash.count <= pwhashSize + 1,
            raising: .valueError("The password hash must be approximately \(pwhashSize) bytes long")
        )
        return try sodium.cryptoPwHash
            .scryptsalsa208sha256StrVerify(
                passwd_hash: passwordHash,
                passwd: password
            )

        
    }
}
