import Clibsodium
import Foundation
import BigInt

public struct PwHash {
    public let argon2 = Argon2()
    public let argon2i = Argon2i()
    public let argon2id = Argon2id()
    public let scrypt = Scrypt()
    
    public let strPrefix: String

    public let pwhashSize: Int

    public let passwdMin: Int
    public let passwdMax: Int
    public let memLimitMax: Int
    public let memLimitMin: Int
    public let opsLimitMax: Int
    public let opsLimitMin: Int
    public let opsLimitInteractive: Int
    public let memLimitInteractive: Int
    public let opsLimitModerate: Int
    public let memLimitModerate: Int
    public let opsLimitSensitive: Int
    public let memLimitSensitive: Int

    public let scryptSaltBytes: Int
    public let scryptPwhashSize: Int
    public let scryptOpsLimitInteractive: Int
    public let scryptMemLimitInteractive: Int
    public let scryptOpsLimitSensitive: Int
    public let scryptMemLimitSensitive: Int
    
    public init() {
        self.strPrefix = argon2id.strPrefix
        self.pwhashSize = argon2id.pwhashSize
        self.passwdMin = argon2id.passwdMin
        self.passwdMax = argon2id.passwdMax
        self.memLimitMax = argon2id.memLimitMax
        self.memLimitMin = argon2id.memLimitMin
        self.opsLimitMax = argon2id.opsLimitMax
        self.opsLimitMin = argon2id.opsLimitMin
        self.opsLimitInteractive = argon2id.opsLimitInteractive
        self.memLimitInteractive = argon2id.memLimitInteractive
        self.opsLimitModerate = argon2id.opsLimitModerate
        self.memLimitModerate = argon2id.memLimitModerate
        self.opsLimitSensitive = argon2id.opsLimitSensitive
        self.memLimitSensitive = argon2id.memLimitSensitive
        self.scryptSaltBytes = scrypt.saltBytes
        self.scryptPwhashSize = scrypt.pwhashSize
        self.scryptOpsLimitInteractive = scrypt.opsLimitInteractive
        self.scryptMemLimitInteractive = scrypt.memLimitInteractive
        self.scryptOpsLimitSensitive = scrypt.opsLimitSensitive
        self.scryptMemLimitSensitive = scrypt.memLimitSensitive
    }

    public func kdfScryptsalsa208sha256(size: Int, password: Data, salt: Data, opsLimit: Int? = nil, memLimit: Int? = nil, encoder: (Data) -> Data = { $0 }) throws -> Data {
        return encoder(
            try scrypt.kdf(
                size: size,
                password: password,
                salt: salt,
                opsLimit: opsLimit ?? scrypt.opsLimitSensitive,
                memLimit: memLimit ?? scrypt.memLimitSensitive
            )
        )
    }

    public func scryptsalsa208sha256Str(password: Data, opsLimit: Int? = nil, memLimit: Int? = nil) throws -> String {
        return try scrypt.str(
            password: password,
            opsLimit: opsLimit ?? opsLimitInteractive,
            memLimit: memLimit ?? memLimitInteractive
        )
    }

    public func verifyScryptsalsa208sha256(passwordHash: Data, password: Data) throws -> Bool {
        return try scrypt.verify(passwordHash: passwordHash, password: password)
    }

    public func verify(passwordHash: Data, password: Data) throws -> Bool {
        
        guard let passwordHashStr = String(data: passwordHash, encoding: .utf8) else {
            throw SodiumError
                .valueError("passwordHash must be a valid UTF-8 string")
        }
        
        if passwordHashStr.starts(with: argon2id.strPrefix) {
            return try argon2id
                .verify(passwordHash: passwordHash, password: password)
        } else if passwordHashStr.starts(with: argon2i.strPrefix) {
            return try argon2i
                .verify(passwordHash: passwordHash, password: password)
        } else if passwordHashStr.starts(with: scrypt.strPrefix) {
            return try scrypt
                .verify(passwordHash: passwordHash, password: password)
        } else {
            throw SodiumError.cryptPrefixError("Given password_hash is not in a supported format")
        }
    }
    
}
