import Testing
import Foundation

@testable import SwiftNcal

@Suite("Argon2i Password Hashing Tests")
struct Argon2iTests {
    let argon2i = Argon2i()
    let sodium = Sodium()
    let password = "password".data(using: .utf8)!
    let salt = Data(repeating: 0, count: 16)  // 16 bytes salt
    let opsLimit = 3
    let memLimit = 1 << 12  // 4 MB

    @Test("Argon2i password verification succeeds with correct password")
    func testArgon2iVerify() async throws {
        let passwordHash = try sodium.cryptoPwHash.strAlg(
            passwd: password,
            opslimit: sodium.cryptoPwHash.argon2iOpslimitMin,
            memlimit: sodium.cryptoPwHash.argon2iMemlimitMin,
            alg: argon2i.alg
        )
        let isValid = try argon2i.verify(passwordHash: passwordHash, password: password)
        #expect(isValid, "Password verification failed")
    }

    @Test("Argon2i password verification fails with incorrect password")
    func testArgon2iVerifyWithInvalidPassword() async throws {
        let passwordHash = try sodium.cryptoPwHash.strAlg(
            passwd: password,
            opslimit: sodium.cryptoPwHash.argon2iOpslimitMin,
            memlimit: sodium.cryptoPwHash.argon2iMemlimitMin,
            alg: argon2i.alg
        )
        let invalidPassword = "wrongpassword".data(using: .utf8)!
        let isValid = try argon2i.verify(passwordHash: passwordHash, password: invalidPassword)
        #expect(!isValid, "Password verification should fail for invalid password")
    }

    @Test("Argon2i password verification throws error with invalid hash format")
    func testArgon2iVerifyWithInvalidHash() async throws {
        let invalidHash = Data(repeating: 0, count: 129)  // Invalid hash length
        #expect(throws: Error.self) {
            try argon2i.verify(passwordHash: invalidHash, password: password)
        }
    }

    @Test("Argon2i KDF generates key with correct length")
    func testArgon2iKdf() async throws {
        let derivedKey = try argon2i.kdf(
            size: 32, password: password, salt: salt)
        #expect(derivedKey.count == 32, "Derived key length mismatch")
    }

    @Test("Argon2i KDF throws error with invalid salt length")
    func testArgon2iKdfWithInvalidSalt() async throws {
        let invalidSalt = Data(repeating: 0, count: argon2i.saltBytes - 1)  // Invalid salt length
        #expect(throws: Error.self) {
            try argon2i.kdf(
                size: 32, password: password, salt: invalidSalt, opsLimit: opsLimit,
                memLimit: memLimit)
        }
    }

    @Test("Argon2i KDF throws error with invalid operations limit")
    func testArgon2iKdfWithInvalidOpsLimit() async throws {
        let invalidOpsLimit = 0  // Invalid ops limit
        #expect(throws: Error.self) {
            try argon2i.kdf(
                size: 32, password: password, salt: salt, opsLimit: invalidOpsLimit,
                memLimit: memLimit)
        }
    }

    @Test("Argon2i KDF throws error with invalid memory limit")
    func testArgon2iKdfWithInvalidMemLimit() async throws {
        let invalidMemLimit = 0  // Invalid memory limit
        #expect(throws: Error.self) {
            try argon2i.kdf(
                size: 32, password: password, salt: salt, opsLimit: opsLimit,
                memLimit: invalidMemLimit)
        }
    }
}
