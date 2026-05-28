import Clibsodium
import Testing
import Foundation

@testable import SwiftNaCl

@Suite("Crypto Short Hash Tests") struct CryptoShortHashTests {
    let sodium = Sodium()

    @Test("siphash24 returns hash with expected length")
    func testSiphash24() throws {
        let cryptoShortHash = sodium.cryptoShortHash
        
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoShortHash.keyBytes)

        let hash = try cryptoShortHash.siphash24(data: message, key: key)

        #expect(hash.count == cryptoShortHash.bytes, "Hash length mismatch")
    }

    @Test("siphash24 throws for invalid key length")
    func testSiphash24WithInvalidKey() throws {
        let cryptoShortHash = sodium.cryptoShortHash
        
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoShortHash.keyBytes - 1) // Invalid key length

        #expect(throws: Error.self, "Expected error for invalid key length") { try cryptoShortHash.siphash24(data: message, key: key) }
    }

    @Test("siphashx24 returns hash with expected length")
    func testSiphashx24() throws {
        let cryptoShortHash = sodium.cryptoShortHash
        
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoShortHash.xKeyBytes)

        let hash = try cryptoShortHash.siphashx24(data: message, key: key)

        #expect(hash.count == cryptoShortHash.xKeyBytes, "Hash length mismatch")
    }

    @Test("siphashx24 throws for invalid key length")
    func testSiphashx24WithInvalidKey() throws {
        let cryptoShortHash = sodium.cryptoShortHash
        
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoShortHash.xKeyBytes - 1) // Invalid key length

        #expect(throws: Error.self, "Expected error for invalid key length") { try cryptoShortHash.siphashx24(data: message, key: key) }
    }
}
