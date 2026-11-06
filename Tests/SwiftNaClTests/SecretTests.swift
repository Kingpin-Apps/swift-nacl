import Foundation
import Testing

@testable import SwiftNaCl

@Suite("SecretBox encryption")
struct SecretBoxTests {
    let sodium = Sodium()
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!

    @Test("initializes with correct key size")
    func testSecretBoxInit() async throws {
        let secretBox = try SecretBox(key: Data(repeating: 0, count: sodium.cryptoSecretBox.keyBytes))
        #expect(secretBox.keySize == sodium.cryptoSecretBox.keyBytes, "SecretBox key size mismatch")
    }

    @Test("exposes the libsodium secretbox size constants")
    func testSecretBoxConstants() async throws {
        let secretBox = try SecretBox(key: Data(repeating: 0, count: sodium.cryptoSecretBox.keyBytes))
        #expect(secretBox.keySize == 32)
        #expect(secretBox.nonceSize == 24)
        #expect(secretBox.macBytes == 16)
        #expect(secretBox.macBytes == sodium.cryptoSecretBox.macBytes)
        #expect(secretBox.messageBytesMax == UInt64(UInt.max) - 16)
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
            ciphertext: encryptedMessage.combined
        )
        #expect(decryptedMessage == message, "SecretBox encrypt/decrypt failed")
    }

    @Test("encrypts and decrypts with provided nonce")
    func testSecretBoxEncryptWithNonce() async throws {
        let secretBox = try SecretBox(key: Data(repeating: 0, count: sodium.cryptoSecretBox.keyBytes))
        let nonce = Data(repeating: 0, count: sodium.cryptoSecretBox.nonceBytes)
        let encryptedMessage = try secretBox.encrypt(plaintext: message, nonce: nonce)
        let decryptedMessage = try secretBox.decrypt(
            ciphertext: encryptedMessage.ciphertext, nonce: nonce)
        #expect(decryptedMessage == message, "SecretBox encrypt/decrypt with nonce failed")
    }

    @Test("an explicit nonce decrypts the bare ciphertext, not the combined bytes")
    func testSecretBoxExplicitNonceUsesBareCiphertext() async throws {
        let secretBox = try SecretBox(key: Data(repeating: 7, count: sodium.cryptoSecretBox.keyBytes))
        let nonce = Data(repeating: 1, count: sodium.cryptoSecretBox.nonceBytes)
        let encryptedMessage = try secretBox.encrypt(plaintext: message, nonce: nonce)
        #expect(encryptedMessage.ciphertext.count == message.count + sodium.cryptoSecretBox.macBytes)
        #expect(try secretBox.decrypt(ciphertext: encryptedMessage.ciphertext, nonce: nonce) == message)
        #expect(throws: SodiumError.self) {
            _ = try secretBox.decrypt(ciphertext: encryptedMessage.combined, nonce: nonce)
        }
    }

    @Test("validates the decoded key length, not the encoded one")
    func testSecretBoxHexEncodedKey() async throws {
        let rawKey = Data(repeating: 0xab, count: sodium.cryptoSecretBox.keyBytes)
        let hexKey = HexEncoder.encode(data: rawKey)
        let fromHex = try SecretBox(key: hexKey, encoder: HexEncoder.self)
        let fromRaw = try SecretBox(key: rawKey)
        let encrypted = try fromHex.encrypt(plaintext: message)
        #expect(try fromRaw.decrypt(ciphertext: encrypted.combined) == message)
    }

    @Test("decrypt throws with invalid nonce size")
    func testSecretBoxDecryptWithInvalidNonce() async throws {
        let secretBox = try SecretBox(key: Data(repeating: 0, count: sodium.cryptoSecretBox.keyBytes))
        let encryptedMessage = try secretBox.encrypt(plaintext: message)
        let invalidNonce = Data(repeating: 0, count: sodium.cryptoSecretBox.nonceBytes - 1)
        #expect(throws: Error.self) {
            _ = try secretBox.decrypt(ciphertext: encryptedMessage.combined, nonce: invalidNonce)
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
        let decryptedMessage = try aead.decrypt(ciphertext: encryptedMessage.combined, aad: aad)
        #expect(decryptedMessage == message, "Aead encrypt/decrypt failed")
    }

    @Test("encrypts and decrypts with provided nonce and AAD")
    func testAeadEncryptWithNonce() async throws {
        let aead = try Aead(key: Data(repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes))
        let nonce = Data(repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfNpubBytes)
        let encryptedMessage = try aead.encrypt(plaintext: message, aad: aad, nonce: nonce)
        let decryptedMessage = try aead.decrypt(
            ciphertext: encryptedMessage.ciphertext, aad: aad, nonce: nonce)
        #expect(decryptedMessage == message, "Aead encrypt/decrypt with nonce failed")
    }

    @Test("an explicit nonce decrypts the bare ciphertext, not the combined bytes")
    func testAeadExplicitNonceUsesBareCiphertext() async throws {
        let aead = try Aead(key: Data(repeating: 7, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes))
        let nonce = Data(repeating: 1, count: sodium.cryptoAead.xchacha20poly1305IetfNpubBytes)
        let encryptedMessage = try aead.encrypt(plaintext: message, aad: aad, nonce: nonce)
        #expect(try aead.decrypt(ciphertext: encryptedMessage.ciphertext, aad: aad, nonce: nonce) == message)
        #expect(throws: SodiumError.self) {
            _ = try aead.decrypt(ciphertext: encryptedMessage.combined, aad: aad, nonce: nonce)
        }
    }

    @Test("validates the decoded key length, not the encoded one")
    func testAeadHexEncodedKey() async throws {
        let rawKey = Data(repeating: 0xcd, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes)
        let fromHex = try Aead(key: HexEncoder.encode(data: rawKey), encoder: HexEncoder.self)
        let fromRaw = try Aead(key: rawKey)
        let encrypted = try fromHex.encrypt(plaintext: message, aad: aad)
        #expect(try fromRaw.decrypt(ciphertext: encrypted.combined, aad: aad) == message)
    }

    @Test("round-trips with the default empty AAD and an empty message")
    func testAeadEmptyAadAndMessage() async throws {
        let aead = try Aead(key: Data(repeating: 3, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes))
        let encrypted = try aead.encrypt(plaintext: message)
        #expect(try aead.decrypt(ciphertext: encrypted.combined) == message)
        let empty = try aead.encrypt(plaintext: Data())
        #expect(try aead.decrypt(ciphertext: empty.combined) == Data())
    }

    @Test("decrypt throws with invalid nonce size")
    func testAeadDecryptWithInvalidNonce() async throws {
        let aead = try Aead(key: Data(repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfKeyBytes))
        let encryptedMessage = try aead.encrypt(plaintext: message, aad: aad)
        let invalidNonce = Data(
            repeating: 0, count: sodium.cryptoAead.xchacha20poly1305IetfNpubBytes - 1)
        #expect(throws: Error.self) {
            _ = try aead.decrypt(ciphertext: encryptedMessage.combined, aad: aad, nonce: invalidNonce)
        }
    }
}
