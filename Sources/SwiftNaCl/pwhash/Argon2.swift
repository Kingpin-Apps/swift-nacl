import Clibsodium
import Foundation

public struct Argon2 {
    public let strbytesPlusOne: Int

    public let pwhashSize: Int
    public let saltBytes: Int

    public let passwdMin: Int
    public let passwdMax: Int

    public let bytesMax: Int
    public let bytesMin: Int

    public let algArgon2i13: Int
    public let algArgon2id13: Int
    public let algArgon2Default: Int
    
    private let sodium: Sodium
    
    public init() {
        self.sodium = Sodium()
        
        self.strbytesPlusOne = sodium.cryptoPwHash.strBytes

        self.pwhashSize = sodium.cryptoPwHash.strBytes - 1
        self.saltBytes = sodium.cryptoPwHash.saltBytes

        self.passwdMin = sodium.cryptoPwHash.passwdMin
        self.passwdMax = sodium.cryptoPwHash.passwdMax

        self.bytesMax = sodium.cryptoPwHash.bytesMax
        self.bytesMin = sodium.cryptoPwHash.bytesMin

        self.algArgon2i13 = sodium.cryptoPwHash.algArgon2i13
        self.algArgon2id13 = sodium.cryptoPwHash.algArgon2id13
        self.algArgon2Default = sodium.cryptoPwHash.algDefault
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
}
