import Foundation
import Clibsodium
import Testing

@testable import SwiftNaCl

@Suite("Crypto AEAD Tests")
struct CryptoAEADTests {
    let cryptoAead = Sodium().cryptoAead

    @Test("ChaCha20-Poly1305 IETF encryption and decryption")
    func cryptoAeadChacha20poly1305Ietf() async throws {
        let key = Data(repeating: 0x01, count: cryptoAead.chacha20poly1305IetfKeyBytes)
        let nonce = Data(repeating: 0x02, count: cryptoAead.chacha20poly1305IetfNpubBytes)
        let message = "Hello, secure world!".data(using: .utf8)!
        let aad = "Additional Data".data(using: .utf8)

        // Encrypt
        let ciphertext = try cryptoAead.chacha20poly1305IetfEncrypt(
            message: message, aad: aad, nonce: nonce, key: key)
        #expect(!ciphertext.isEmpty, "Ciphertext should not be empty.")

        // Decrypt
        let decryptedMessage = try cryptoAead.chacha20poly1305IetfDecrypt(
            ciphertext: ciphertext, aad: aad, nonce: nonce, key: key)
        #expect(decryptedMessage == message, "Decrypted message should match the original.")
    }

    @Test("ChaCha20-Poly1305 encryption and decryption")
    func cryptoAeadChacha20poly1305() async throws {
        let key = Data(repeating: 0x01, count: cryptoAead.chacha20poly1305KeyBytes)
        let nonce = Data(repeating: 0x02, count: cryptoAead.chacha20poly1305NpubBytes)
        let message = "Hello, secure world!".data(using: .utf8)!
        let aad = "Additional Data".data(using: .utf8)

        // Encrypt
        let ciphertext = try cryptoAead.chacha20poly1305Encrypt(
            message: message, aad: aad, nonce: nonce, key: key)
        #expect(!ciphertext.isEmpty, "Ciphertext should not be empty.")

        // Decrypt
        let decryptedMessage = try cryptoAead.chacha20poly1305Decrypt(
            ciphertext: ciphertext, aad: aad, nonce: nonce, key: key)
        #expect(decryptedMessage == message, "Decrypted message should match the original.")
    }

    @Test("XChaCha20-Poly1305 IETF encryption and decryption")
    func cryptoAeadXchacha20poly1305Ietf() async throws {
        let key = Data(repeating: 0x01, count: cryptoAead.xchacha20poly1305IetfKeyBytes)
        let nonce = Data(repeating: 0x03, count: cryptoAead.xchacha20poly1305IetfNpubBytes)
        let message = "Hello, extended nonce!".data(using: .utf8)!
        let aad = "Extended Additional Data".data(using: .utf8)

        // Encrypt
        let ciphertext = try cryptoAead.xchacha20poly1305IetfEncrypt(
            message: message, aad: aad, nonce: nonce, key: key)
        #expect(!ciphertext.isEmpty, "Ciphertext should not be empty.")

        // Decrypt
        let decryptedMessage = try cryptoAead.xchacha20poly1305IetfDecrypt(
            ciphertext: ciphertext, aad: aad, nonce: nonce, key: key)
        #expect(decryptedMessage == message, "Decrypted message should match the original.")
    }

    @Test("Invalid key length throws SodiumError")
    func invalidKeyLength() async throws {
        let key = Data(repeating: 0x01, count: 10)  // Invalid key length
        let nonce = Data(repeating: 0x02, count: cryptoAead.chacha20poly1305IetfNpubBytes)
        let message = "Short key test".data(using: .utf8)!

        #expect(throws: SodiumError.self) {
            try cryptoAead.chacha20poly1305IetfEncrypt(
                message: message, aad: nil, nonce: nonce, key: key)
        }

        #expect(throws: SodiumError.self) {
            try cryptoAead.chacha20poly1305Encrypt(
                message: message, aad: nil, nonce: nonce, key: key)
        }

        #expect(throws: SodiumError.self) {
            try cryptoAead.xchacha20poly1305IetfEncrypt(
                message: message, aad: nil, nonce: nonce, key: key)
        }
    }

    @Test("Invalid nonce length throws SodiumError")
    func invalidNonceLength() async throws {
        let key = Data(repeating: 0x01, count: cryptoAead.chacha20poly1305IetfKeyBytes)
        let nonce = Data(repeating: 0x02, count: 5)  // Invalid nonce length
        let message = "Short nonce test".data(using: .utf8)!

        #expect(throws: SodiumError.self) {
            try cryptoAead.chacha20poly1305IetfEncrypt(
                message: message, aad: nil, nonce: nonce, key: key)
        }

        #expect(throws: SodiumError.self) {
            try cryptoAead.chacha20poly1305Encrypt(
                message: message, aad: nil, nonce: nonce, key: key)
        }

        #expect(throws: SodiumError.self) {
            try cryptoAead.xchacha20poly1305IetfEncrypt(
                message: message, aad: nil, nonce: nonce, key: key)
        }
    }
}
