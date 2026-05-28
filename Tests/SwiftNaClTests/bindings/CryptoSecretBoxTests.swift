import Clibsodium
import Foundation
import Testing

@testable import SwiftNaCl

@Suite("Crypto Secret Box Tests")
struct CryptoSecretBoxTests {
    let cryptoSecretBox = Sodium().cryptoSecretBox
    
    @Test("Box encryption works correctly")
    func box() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.box(message: message, nonce: nonce, key: key)

        #expect(ciphertext.count == message.count + cryptoSecretBox.boxZeroBytes, "Ciphertext length mismatch")
    }

    @Test("Box throws error with invalid key")
    func boxWithInvalidKey() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes - 1) // Invalid key length
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        #expect(throws: (any Error).self) {
            try cryptoSecretBox.box(message: message, nonce: nonce, key: key)
        }
    }

    @Test("Box throws error with invalid nonce")
    func boxWithInvalidNonce() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes - 1) // Invalid nonce length

        #expect(throws: (any Error).self) {
            try cryptoSecretBox.box(message: message, nonce: nonce, key: key)
        }
    }
    
    @Test("Box decryption works correctly")
    func open() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.box(message: message, nonce: nonce, key: key)
        let decryptedMessage = try cryptoSecretBox.open(ciphertext: ciphertext, nonce: nonce, key: key)

        #expect(message == decryptedMessage, "Decrypted message does not match the original message")
    }

    @Test("Open throws error with invalid key")
    func openWithInvalidKey() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.box(message: message, nonce: nonce, key: key)
        let invalidKey = Data(repeating: 0, count: cryptoSecretBox.keyBytes - 1) // Invalid key length

        #expect(throws: (any Error).self) {
            try cryptoSecretBox.open(ciphertext: ciphertext, nonce: nonce, key: invalidKey)
        }
    }

    @Test("Open throws error with invalid nonce")
    func openWithInvalidNonce() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.box(message: message, nonce: nonce, key: key)
        let invalidNonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes - 1) // Invalid nonce length

        #expect(throws: (any Error).self) {
            try cryptoSecretBox.open(ciphertext: ciphertext, nonce: invalidNonce, key: key)
        }
    }

    @Test("Open throws error with tampered ciphertext")
    func openWithTamperedCiphertext() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        var ciphertext = try cryptoSecretBox.box(message: message, nonce: nonce, key: key)
        ciphertext[0] ^= 0xFF // Tamper with the ciphertext

        #expect(throws: (any Error).self) {
            try cryptoSecretBox.open(ciphertext: ciphertext, nonce: nonce, key: key)
        }
    }
    
    @Test("Easy with tampered message throws error")
    func easyWithTamperedMessage() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        var ciphertext = try cryptoSecretBox.easy(message: message, nonce: nonce, key: key)
        ciphertext[0] ^= 0xFF // Tamper with the ciphertext

        #expect(throws: (any Error).self) {
            try cryptoSecretBox.open(ciphertext: ciphertext, nonce: nonce, key: key)
        }
    }
    
    @Test("Open easy throws error with tampered ciphertext")
    func openEasyWithTamperedCiphertext() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        var ciphertext = try cryptoSecretBox.easy(message: message, nonce: nonce, key: key)
        ciphertext[0] ^= 0xFF // Tamper with the ciphertext

        #expect(throws: (any Error).self) {
            try cryptoSecretBox.openEasy(ciphertext: ciphertext, nonce: nonce, key: key)
        }
    }

    @Test("Easy throws error with invalid nonce")
    func easyWithInvalidNonce() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes - 1) // Invalid nonce length

        #expect(throws: (any Error).self) {
            try cryptoSecretBox.easy(message: message, nonce: nonce, key: key)
        }
    }

    @Test("Easy encryption works correctly")
    func easy() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.easy(message: message, nonce: nonce, key: key)

        #expect(ciphertext.count == cryptoSecretBox.macBytes + message.count, "Ciphertext length mismatch")
    }

    @Test("Easy throws error with invalid key")
    func easyWithInvalidKey() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes - 1) // Invalid key length
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        #expect(throws: (any Error).self) {
            try cryptoSecretBox.easy(message: message, nonce: nonce, key: key)
        }
    }
    
    @Test("Open easy decryption works correctly")
    func openEasy() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.easy(message: message, nonce: nonce, key: key)
        let decryptedMessage = try cryptoSecretBox.openEasy(ciphertext: ciphertext, nonce: nonce, key: key)

        #expect(message == decryptedMessage, "Decrypted message does not match the original message")
    }

    @Test("Open easy throws error with invalid key")
    func openEasyWithInvalidKey() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.easy(message: message, nonce: nonce, key: key)
        let invalidKey = Data(repeating: 0, count: cryptoSecretBox.keyBytes - 1) // Invalid key length

        #expect(throws: (any Error).self) {
            try cryptoSecretBox.openEasy(ciphertext: ciphertext, nonce: nonce, key: invalidKey)
        }
    }

    @Test("Open easy throws error with invalid nonce")
    func openEasyWithInvalidNonce() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let key = Data(repeating: 0, count: cryptoSecretBox.keyBytes)
        let nonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes)

        let ciphertext = try cryptoSecretBox.easy(message: message, nonce: nonce, key: key)
        let invalidNonce = Data(repeating: 0, count: cryptoSecretBox.nonceBytes - 1) // Invalid nonce length

        #expect(throws: (any Error).self) {
            try cryptoSecretBox.openEasy(ciphertext: ciphertext, nonce: invalidNonce, key: key)
        }
    }
}
