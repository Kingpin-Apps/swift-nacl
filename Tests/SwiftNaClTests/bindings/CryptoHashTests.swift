import Clibsodium
import Testing

@testable import SwiftNaCl

@Suite("Crypto Hash Tests")
struct CryptoHashTests {
    let cryptoHash = Sodium().cryptoHash

    @Test("Hash function works correctly")
    func hash() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let digest = try cryptoHash.hash(message: message)

        #expect(digest.count == cryptoHash.bytes, "Hash length mismatch")
    }

    @Test("SHA-256 function works correctly")
    func sha256() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let digest = try cryptoHash.sha256(message: message)

        #expect(digest.count == cryptoHash.sha256Bytes, "SHA-256 hash length mismatch")
    }

    @Test("SHA-512 function works correctly")
    func sha512() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let digest = try cryptoHash.sha512(message: message)

        #expect(digest.count == cryptoHash.sha512Bytes, "SHA-512 hash length mismatch")
    }
}
