import Clibsodium
import Foundation

public struct Argon2id {
    public let alg: Int
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
        
        self.alg = sodium.cryptoPwHash.algArgon2id13
        self.strPrefix = sodium.cryptoPwHash.argon2idStrprefix

        self.saltBytes = sodium.cryptoPwHash.saltBytes
        
        self.passwdMin = sodium.cryptoPwHash.passwdMin
        self.passwdMax = sodium.cryptoPwHash.passwdMax

        self.pwhashSize = sodium.cryptoPwHash.strBytes - 1
        
        self.bytesMin = sodium.cryptoPwHash.bytesMin
        self.bytesMax = sodium.cryptoPwHash.bytesMax
        
        self.memLimitMin = sodium.cryptoPwHash.argon2idMemlimitMin
        self.memLimitMax = sodium.cryptoPwHash.argon2idMemlimitMax
        self.opsLimitMin = sodium.cryptoPwHash.argon2idOpslimitMin
        self.opsLimitMax = sodium.cryptoPwHash.argon2idOpslimitMax
        self.opsLimitInteractive = sodium.cryptoPwHash.argon2idOpslimitInteractive
        self.memLimitInteractive = sodium.cryptoPwHash.argon2idMemlimitInteractive
        self.opsLimitModerate = sodium.cryptoPwHash.argon2idOpslimitModerate
        self.memLimitModerate = sodium.cryptoPwHash.argon2idMemlimitModerate
        self.opsLimitSensitive = sodium.cryptoPwHash.argon2idOpslimitSensitive
        self.memLimitSensitive = sodium.cryptoPwHash.argon2idMemlimitSensitive
    }

    /**
     Takes a modular crypt encoded argon2i or argon2id stored password hash
     and checks if the user provided password will hash to the same string
     when using the stored parameters

     - parameter passwordHash: password hash serialized in modular crypt() format
     - parameter password: user provided password
     - returns: boolean

     .. versionadded:: 1.2
     */
    public func verify(passwordHash: Data, password: Data) throws -> Bool {
        do {
            return try sodium.cryptoPwHash.strVerify(passwd_hash: passwordHash, passwd: password)
        } catch SodiumError.invalidKeyError {
            return false
        }
    }

    /**
     Derive a `size` bytes long key from a caller-supplied
     `password` and `salt` pair using the argon2i
     memory-hard construct.

     the enclosing module provides the constants

     - `opsLimitInteractive`
     - `memLimitInteractive`
     - `opsLimitModerate`
     - `memLimitModerate`
     - `opsLimitSensitive`
     - `memLimitSensitive`

     as a guidance for correct settings.

     - parameter size: derived key size, must be between `bytesMin` and `bytesMax`
     - parameter password: password used to seed the key derivation procedure; it length must be between `passwdMin` and `passwdMax`
     - parameter salt: **RANDOM** salt used in the key derivation procedure; its length must be exactly `saltBytes`
     - parameter opsLimit: the time component (operation count) of the key derivation procedure's computational cost; it must be between `opsLimitMin` and `opsLimitMax`
     - parameter memLimit: the memory occupation component of the key derivation procedure's computational cost; it must be between `memLimitMin` and `memLimitMax`
     - parameter encoder: a function that will encode the derived key before returning it
     - returns: bytes

     .. versionadded:: 1.2
     */
    public func kdf(size: Int, password: Data, salt: Data, opsLimit: Int? = nil, memLimit: Int? = nil, encoder: (Data) -> Data = { $0 }) throws -> Data {
        let memLim = memLimit ?? memLimitSensitive
        let opsLim = opsLimit ?? opsLimitSensitive
        return encoder(
            try sodium.cryptoPwHash
                .alg(
                    outlen: size,
                    passwd: password,
                    salt: salt,
                    opslimit: opsLim,
                    memlimit: memLim,
                    alg: alg
                )
        )
    }

    /**
     Hashes a password with a random salt, using the memory-hard
     argon2i construct and returning an ascii string that has all
     the needed info to check against a future password

     The default settings for opsLimit and memLimit are those deemed
     correct for the interactive user login case.

     - parameter password: bytes
     - parameter opsLimit: int
     - parameter memLimit: int
     - returns: bytes

     .. versionadded:: 1.2
     */
    public func str(password: Data, opsLimit: Int? = nil, memLimit: Int? = nil) throws -> Data {
        let memLim = memLimit ?? memLimitInteractive
        let opsLim = opsLimit ?? opsLimitInteractive
        return try sodium.cryptoPwHash
            .strAlg(
                passwd: password,
                opslimit: opsLim,
                memlimit: memLim,
                alg: alg
            )
    }
}
