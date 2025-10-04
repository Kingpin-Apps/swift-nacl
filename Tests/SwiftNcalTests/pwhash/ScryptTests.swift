import Testing
import Foundation

@testable import SwiftNcal

@Suite("Scrypt Key Derivation and Password Hashing Tests")
struct ScryptTests {
    let scrypt = Scrypt()
    let sodium = Sodium()
    let password = "password".data(using: .utf8)!
    let salt = Data(repeating: 0, count: 16)  // 16 bytes salt
    // Use interactive values for better cross-platform compatibility
    var opsLimit: Int { scrypt.opsLimitInteractive }
    var memLimit: Int { scrypt.memLimitInteractive }

    @Test("Scrypt KDF generates key with correct length")
    func testScryptKdf() async throws {
        let derivedKey = try scrypt.kdf(
            size: 32,
            password: password,
            salt: Data(repeating: 0, count: scrypt.saltBytes),
            opsLimit: scrypt.opsLimitMin,
            memLimit: scrypt.memLimitMin
        )
        #expect(derivedKey.count == 32, "Derived key length mismatch")
    }

    @Test("Scrypt KDF throws error with invalid salt length")
    func testScryptKdfWithInvalidSalt() async throws {
        let invalidSalt = Data(repeating: 0, count: scrypt.saltBytes - 1)  // Invalid salt length
        #expect(throws: Error.self) {
            try scrypt.kdf(
                size: 32, password: password, salt: invalidSalt, opsLimit: scrypt.opsLimitInteractive,
                memLimit: scrypt.memLimitInteractive)
        }
    }

    @Test("Scrypt KDF throws error with invalid operations limit")
    func testScryptKdfWithInvalidOpsLimit() async throws {
        let invalidOpsLimit = 0  // Invalid ops limit
        #expect(throws: Error.self) {
            try scrypt.kdf(
                size: 32,
                password: password,
                salt: Data(repeating: 0, count: scrypt.saltBytes),
                opsLimit: invalidOpsLimit,
                memLimit: scrypt.memLimitInteractive)
        }
    }

    @Test("Scrypt KDF throws error with invalid memory limit")
    func testScryptKdfWithInvalidMemLimit() async throws {
        let invalidMemLimit = 0  // Invalid memory limit
        #expect(throws: Error.self) {
            try scrypt.kdf(
                size: 32,
                password: password,
                salt: Data(repeating: 0, count: scrypt.saltBytes),
                opsLimit: scrypt.opsLimitInteractive,
                memLimit: invalidMemLimit)
        }
    }

    @Test("Scrypt password hashing generates hash with correct prefix")
    func testScryptStr() async throws {
        let passwordHash = try scrypt.str(
            password: password, opsLimit: opsLimit, memLimit: memLimit)
        #expect(
            String(passwordHash.prefix(scrypt.strPrefix.count)) == scrypt.strPrefix,
            "Password hash prefix mismatch")
    }

    @Test("Scrypt password verification succeeds with correct password")
    func testScryptVerify() async throws {
        let passwordHash = try scrypt.str(
            password: password, opsLimit: opsLimit, memLimit: memLimit
        ).data(using: .utf8)!
        let isValid = try scrypt.verify(passwordHash: passwordHash, password: password)
        #expect(isValid, "Password verification failed")
    }

    @Test("Scrypt password verification fails with incorrect password")
    func testScryptVerifyWithInvalidPassword() async throws {
        let passwordHash = try scrypt.str(
            password: password,
            opsLimit: scrypt.opsLimitMin,
            memLimit: scrypt.memLimitMin
        ).data(using: .utf8)!
        let invalidPassword = "wrongpassword".data(using: .utf8)!
        let isValid = try scrypt.verify(passwordHash: passwordHash, password: invalidPassword)
        #expect(!isValid, "Password verification should fail for invalid password")
    }

    @Test("Scrypt password verification throws error with invalid hash format")
    func testScryptVerifyWithInvalidHash() async throws {
        let invalidHash = "invalidhash".data(using: .utf8)!
        #expect(throws: Error.self) {
            try scrypt.verify(passwordHash: invalidHash, password: password)
        }
    }
}
