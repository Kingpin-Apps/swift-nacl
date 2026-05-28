import Testing
import Foundation

@testable import SwiftNaCl

@Suite("Argon2 password hashing")
struct Argon2Tests {
    let argon2 = Argon2()
    let sodium = Sodium()
    let password = "password".data(using: .utf8)!
    let salt = Data(repeating: 0, count: 16) // 16 bytes salt
    let opsLimit = 3
    let memLimit = 1 << 12 // 4 MB

    @Test("verifies a valid password hash")
    func testArgon2Verify() async throws {
        let passwordHash = try sodium.cryptoPwHash.strAlg(
            passwd: password,
            opslimit: sodium.cryptoPwHash.argon2iOpslimitMin,
            memlimit: sodium.cryptoPwHash.argon2iMemlimitMin,
            alg: argon2.algArgon2i13
        )
        let isValid = try argon2.verify(passwordHash: passwordHash, password: password)
        #expect(isValid, "Password verification failed")
    }

    @Test("fails verification with invalid password")
    func testArgon2VerifyWithInvalidPassword() async throws {
        let passwordHash = try sodium.cryptoPwHash.strAlg(
            passwd: password,
            opslimit: sodium.cryptoPwHash.argon2iOpslimitMin,
            memlimit: sodium.cryptoPwHash.argon2iMemlimitMin,
            alg: argon2.algArgon2i13
        )
        let invalidPassword = "wrongpassword".data(using: .utf8)!
        let isValid = try argon2.verify(passwordHash: passwordHash, password: invalidPassword)
        #expect(!isValid, "Password verification should fail for invalid password")
    }

    @Test("throws for invalid hash input")
    func testArgon2VerifyWithInvalidHash() async throws {
        let invalidHash = Data(repeating: 0, count: 129)
        #expect(throws: Error.self) {
            _ = try argon2.verify(passwordHash: invalidHash, password: password)
        }
    }
}
