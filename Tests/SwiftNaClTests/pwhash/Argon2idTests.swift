import Foundation
import Testing

@testable import SwiftNaCl

@Suite("Argon2id Password Hashing Tests")
struct Argon2idTests {
    let argon2id = Argon2id()
    let sodium = Sodium()
    let password = "password".data(using: .utf8)!
    let salt = Data(repeating: 0, count: 16)  // 16 bytes salt
    let opsLimit = 3
    let memLimit = 1 << 12  // 4 MB

    @Test("Argon2id password verification succeeds with correct password")
    func argon2idVerify() async throws {
        // Generate a password hash using Argon2id algorithm
        let passwordHash = try sodium.cryptoPwHash.strAlg(
            passwd: password,
            opslimit: sodium.cryptoPwHash.argon2idOpslimitMin,
            memlimit: sodium.cryptoPwHash.argon2idMemlimitMin,
            alg: argon2id.alg
        )
        
        // Verify the password against the generated hash
        let isValid = try argon2id.verify(passwordHash: passwordHash, password: password)
        #expect(isValid, "Password verification should succeed with correct password")
    }

    @Test("Argon2id password verification fails with incorrect password")
    func argon2idVerifyWithInvalidPassword() async throws {
        // Generate a password hash using Argon2id algorithm
        let passwordHash = try sodium.cryptoPwHash.strAlg(
            passwd: password,
            opslimit: sodium.cryptoPwHash.argon2idOpslimitMin,
            memlimit: sodium.cryptoPwHash.argon2idMemlimitMin,
            alg: argon2id.alg
        )
        
        // Attempt verification with wrong password
        let invalidPassword = "wrongpassword".data(using: .utf8)!
        let isValid = try argon2id.verify(passwordHash: passwordHash, password: invalidPassword)
        #expect(!isValid, "Password verification should fail for incorrect password")
    }

    @Test("Argon2id password verification throws error with invalid hash format")
    func argon2idVerifyWithInvalidHash() async throws {
        // Create an invalid hash with wrong length
        let invalidHash = Data(repeating: 0, count: 129)  // Invalid hash length
        
        // Expect error when verifying with invalid hash format
        #expect(throws: (any Error).self) {
            try argon2id.verify(passwordHash: invalidHash, password: password)
        }
    }

    @Test("Argon2id KDF generates key with correct length")
    func argon2idKdf() async throws {
        // Derive a 32-byte key using Argon2id key derivation function
        let derivedKey = try argon2id.kdf(
            size: 32,
            password: password,
            salt: salt,
            opsLimit: sodium.cryptoPwHash.argon2idOpslimitMin,
            memLimit: sodium.cryptoPwHash.argon2idMemlimitMin
        )
        
        // Verify the derived key has the expected length
        #expect(derivedKey.count == 32, "Derived key should be exactly 32 bytes long")
    }

    @Test("Argon2id KDF throws error with invalid salt length")
    func argon2idKdfWithInvalidSalt() async throws {
        // Create a salt with invalid length (one byte shorter than required)
        let invalidSalt = Data(repeating: 0, count: argon2id.saltBytes - 1)
        
        // Expect error when using invalid salt length
        #expect(throws: (any Error).self) {
            try argon2id.kdf(
                size: 32,
                password: password,
                salt: invalidSalt,
                opsLimit: sodium.cryptoPwHash.argon2idOpslimitMin,
                memLimit: sodium.cryptoPwHash.argon2idMemlimitMin
            )
        }
    }

    @Test("Argon2id KDF throws error with invalid operations limit")
    func argon2idKdfWithInvalidOpsLimit() async throws {
        // Use zero operations limit which is invalid
        let invalidOpsLimit = 0
        
        // Expect error when using invalid operations limit
        #expect(throws: (any Error).self) {
            try argon2id.kdf(
                size: 32,
                password: password,
                salt: salt,
                opsLimit: invalidOpsLimit,
                memLimit: sodium.cryptoPwHash.argon2idMemlimitMin
            )
        }
    }

    @Test("Argon2id KDF throws error with invalid memory limit")
    func argon2idKdfWithInvalidMemLimit() async throws {
        // Use zero memory limit which is invalid
        let invalidMemLimit = 0
        
        // Expect error when using invalid memory limit
        #expect(throws: (any Error).self) {
            try argon2id.kdf(
                size: 32,
                password: password,
                salt: salt,
                opsLimit: sodium.cryptoPwHash.argon2idOpslimitMin,
                memLimit: invalidMemLimit
            )
        }
    }
}
