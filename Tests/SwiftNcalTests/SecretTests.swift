import Foundation
import Testing

@testable import SwiftNcal

@Suite("SecretBox encryption")
struct SecretBoxTests {
    let sodium = Sodium()
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!

    @Test("initializes with correct key size")
    func testSecretBoxInit() async throws {
        let secretBox = try SecretBox(key: Data(repeating: 0, count: sodium.cryptoSecretBox.keyBytes))
        #expect(secretBox.keySize == sodium.cryptoSecretBox.keyBytes, "SecretBox key size mismatch")
    }

    @Test("fails to initialize with invalid key size")
    func testSecretBoxInvalidKeySize() async throws {
        let invalidKey = Data(repeating: 0, count: sodium.cryptoSecretBox.keyBytes - 1)
        do {
            _ = try SecretBox(key: invalidKey)
            Issue.record("Expected error for invalid key size")
        } catch {
            // Expected to throw
        }
    }

    @Test("encrypts and decrypts successfully")
    func testSecretBoxEncryptDecrypt() async throws {
        let secretBox = try SecretBox(key: Data(repeating: 0, count: sodium.cryptoSecretBox.keyBytes))
        let encryptedMessage = try secretBox.encrypt(plaintext: message)
        let decryptedMessage = try secretBox.decrypt(
            ciphertext: encryptedMessage.getMessage
        )
        #expect(decryptedMessage == message, "SecretBox encrypt/decrypt failed")
    }

    @Test("encrypts and decrypts with provided nonce")
    func testSecretBoxEncryptWithNonce() async throws {
        let secretBox = try SecretBox(key: Data(repeating: 0, count: sodium.cryptoSecretBox.keyBytes))
        let nonce = Data(repeating: 0, count: sodium.cryptoSecretBox.nonceBytes)
        let encryptedMessage = try secretBox.encrypt(plaintext: message, nonce: nonce)
        let decryptedMessage = try secretBox.decrypt(
            ciphertext: encryptedMessage.getMessage, nonce: nonce)
        #expect(decryptedMessage == message, "SecretBox encrypt/decrypt with nonce failed")
    }

    @Test("decrypt throws with invalid nonce size")
    func testSecretBoxDecryptWithInvalidNonce() async throws {
        let secretBox = try SecretBox(key: Data(repeating: 0, count: sodium.cryptoSecretBox.keyBytes))
        let encryptedMessage = try secretBox.encrypt(plaintext: message)
        let invalidNonce = Data(repeating: 0, count: sodium.cryptoSecretBox.nonceBytes - 1)
        #expect(throws: Error.self) {
            _ = try secretBox.decrypt(ciphertext: encryptedMessage.getMessage, nonce: invalidNonce)
        }
    }
}

@Suite("AEAD XChaCha20-Poly1305")
struct AeadTests {
    let sodium = Sodium()
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let aad = "Additional authenticated data".data(using: .utf8)!

    @Test("initializes with correct key size")
    func testAeadInit() async throws {
        let aead = try Aead(key: Data(repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes))
        #expect(aead.keySize == sodium.cryptoAead.xchacha20poly1305IetfKeyBytes, "Aead key size mismatch")
    }

    @Test("fails to initialize with invalid key size")
    func testAeadInvalidKeySize() async throws {
        let invalidKey = Data(
            repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes - 1)
        #expect(throws: Error.self) {
            _ = try Aead(key: invalidKey)
        }
    }

    @Test("encrypts and decrypts successfully with AAD")
    func testAeadEncryptDecrypt() async throws {
        let aead = try Aead(key: Data(repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes))
        let encryptedMessage = try aead.encrypt(plaintext: message, aad: aad)
        let decryptedMessage = try aead.decrypt(ciphertext: encryptedMessage.getMessage, aad: aad)
        #expect(decryptedMessage == message, "Aead encrypt/decrypt failed")
    }

    @Test("encrypts and decrypts with provided nonce and AAD")
    func testAeadEncryptWithNonce() async throws {
        let aead = try Aead(key: Data(repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes))
        let nonce = Data(repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfNpubBytes)
        let encryptedMessage = try aead.encrypt(plaintext: message, aad: aad, nonce: nonce)
        let decryptedMessage = try aead.decrypt(
            ciphertext: encryptedMessage.getMessage, aad: aad, nonce: nonce)
        #expect(decryptedMessage == message, "Aead encrypt/decrypt with nonce failed")
    }

    @Test("decrypt throws with invalid nonce size")
    func testAeadDecryptWithInvalidNonce() async throws {
        let aead = try Aead(key: Data(repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes))
        let encryptedMessage = try aead.encrypt(plaintext: message, aad: aad)
        let invalidNonce = Data(
            repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfNpubBytes - 1)
        #expect(throws: Error.self) {
            _ = try aead.decrypt(ciphertext: encryptedMessage.getMessage, aad: aad, nonce: invalidNonce)
        }
    }
}
