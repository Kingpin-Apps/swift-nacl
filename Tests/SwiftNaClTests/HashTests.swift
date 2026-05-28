import Foundation
import Testing

@testable import SwiftNaCl

@Suite("Hashing algorithms")
struct HashTests {
    let _hash = Hash()
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let key = Data(repeating: 0, count: 16)  // 16 bytes key
    let salt = Data(repeating: 0, count: 16)  // 16 bytes salt
    let person = Data(repeating: 0, count: 16)  // 16 bytes personalization

    @Test("computes SHA-256 and returns expected length")
    func testSha256() async throws {
        let hashedMessage = try _hash.sha256(message: message)
        #expect(hashedMessage.count == 64, "SHA256 hash length mismatch")
    }

    @Test("computes SHA-512 and returns expected length")
    func testSha512() async throws {
        let hashedMessage = try _hash.sha512(message: message)
        #expect(hashedMessage.count == 128, "SHA512 hash length mismatch")
    }

    @Test("computes Blake2b with custom parameters and returns expected length")
    func testBlake2b() async throws {
        let hashedMessage = try _hash.blake2b(
            data: message, digestSize: 32, key: key, salt: salt, person: person)
        #expect(hashedMessage.count == 64, "Blake2b hash length mismatch")
    }

    @Test("computes Blake2b with default parameters and returns expected length")
    func testBlake2bWithDefaultParameters() async throws {
        let hashedMessage = try _hash.blake2b(data: message)
        #expect(
            hashedMessage.count == 64,
            "Blake2b hash length mismatch with default parameters"
        )
    }

    @Test("computes SipHash-2-4 and returns expected length")
    func testSiphash24() async throws {
        let hashedMessage = try _hash.siphash24(
            message: message,
            key: Data(repeating: 0, count: _hash.siphashKeyBytes)
        )
        #expect(
            hashedMessage.count == _hash.siphashKeyBytes,
            "Siphash24 hash length mismatch"
        )
    }

    @Test("computes SipHash-x-2-4 and returns expected length")
    func testSiphashx24() async throws {
        let hashedMessage = try _hash.siphashx24(message: message, key: key)
        #expect(hashedMessage.count == 32, "Siphashx24 hash length mismatch")
    }
}
