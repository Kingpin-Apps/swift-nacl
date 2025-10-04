import Testing
import Foundation

@testable import SwiftNcal

@Suite("Password hashing (Scrypt and Argon2)")
struct PwHashTests {
    let pwHash = PwHash()
    let password = "password".data(using: .utf8)!
    let salt = Data(repeating: 0, count: 16)  // 16 bytes salt
    // Use interactive values for better cross-platform compatibility  
    var opsLimit: Int { pwHash.scrypt.opsLimitInteractive }
    var memLimit: Int { pwHash.scrypt.memLimitInteractive }

    @Test("derives a 32-byte key using scryptsalsa208sha256")
    func testKdfScryptsalsa208sha256() async throws {
        let derivedKey = try pwHash.kdfScryptsalsa208sha256(
            size: 32,
            password: password,
            salt: Data(repeating: 0, count: pwHash.scrypt.saltBytes))
        #expect(derivedKey.count == 32, "Derived key length mismatch")
    }

    @Test("produces a scrypt hash with the expected prefix")
    func testScryptsalsa208sha256Str() async throws {
        let passwordHash = try pwHash.scryptsalsa208sha256Str(
            password: password, opsLimit: opsLimit, memLimit: memLimit)
        #expect(
            String(passwordHash.prefix(pwHash.scrypt.strPrefix.count)) == pwHash.scrypt.strPrefix,
            "Password hash prefix mismatch")
    }

    @Test("verifies scryptsalsa208sha256 hashes correctly")
    func testVerifyScryptsalsa208sha256() async throws {
        let passwordHash = try pwHash.scryptsalsa208sha256Str(
            password: password
        ).data(using: .utf8)!
        let isValid = try pwHash.verifyScryptsalsa208sha256(
            passwordHash: passwordHash, password: password)
        #expect(isValid, "Password verification failed")
    }

    @Test("verifies generic scrypt hashes correctly")
    func testVerify() async throws {
        let passwordHash = try pwHash.scryptsalsa208sha256Str(
            password: password, opsLimit: opsLimit, memLimit: memLimit
        ).data(using: .utf8)!
        let isValid = try pwHash.verify(passwordHash: passwordHash, password: password)
        #expect(isValid, "Password verification failed")
    }

    @Test("fails verification with an invalid password")
    func testVerifyWithInvalidPassword() async throws {
        let passwordHash = try pwHash.scryptsalsa208sha256Str(
            password: password, opsLimit: opsLimit, memLimit: memLimit
        ).data(using: .utf8)!
        let invalidPassword = "wrongpassword".data(using: .utf8)!
        let isValid = try pwHash.verify(passwordHash: passwordHash, password: invalidPassword)
        #expect(!isValid, "Password verification should fail for invalid password")
    }

    @Test("throws for an invalid hash input")
    func testVerifyWithInvalidHash() async throws {
        let invalidHash = "invalidhash".data(using: .utf8)!
        do {
            _ = try pwHash.verify(passwordHash: invalidHash, password: password)
            Issue.record("Expected error for invalid hash")
        } catch {
            // Expected to throw
        }
    }

    @Test("verifies when the hash has an Argon2id prefix")
    func testVerifyWithArgon2idPrefix() async throws {
        let passwordHash = try pwHash.argon2id.str(password: password)
        let isValid = try pwHash.verify(passwordHash: passwordHash, password: password)
        #expect(isValid, "Password verification failed for Argon2id prefix")
    }

    @Test("verifies when the hash has an Argon2i prefix")
    func testVerifyWithArgon2iPrefix() async throws {
        let passwordHash = try pwHash.argon2i.str(password: password)
        let isValid = try pwHash.verify(passwordHash: passwordHash, password: password)
        #expect(isValid, "Password verification failed for Argon2i prefix")
    }

    @Test("verifies when the hash has a scrypt prefix")
    func testVerifyWithScryptPrefix() async throws {
        let passwordHash = try pwHash.scrypt.str(password: password).data(using: .utf8)!
        let isValid = try pwHash.verify(passwordHash: passwordHash, password: password)
        #expect(isValid, "Password verification failed for Scrypt prefix")
    }

    @Test("throws for an unsupported hash prefix")
    func testVerifyWithUnsupportedPrefix() async throws {
        let unsupportedHash = "unsupported$hash".data(using: .utf8)!
        do {
            _ = try pwHash.verify(passwordHash: unsupportedHash, password: password)
            Issue.record("Expected error for unsupported hash prefix")
        } catch {
            // Expected to throw
        }
    }
}
