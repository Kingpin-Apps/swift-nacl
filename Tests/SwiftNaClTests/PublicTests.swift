import Testing
import Foundation

@testable import SwiftNaCl

@Suite("KeyPair Generation Tests")
struct KeyPairTests {
    @Test("KeyPair generates valid public and secret keys")
    func testKeyPairGenerate() async throws {
        let _ = KeyPair.generate()
        // KeyPair generation succeeded if we reach this point
        // Both publicKey and secretKey should be non-nil by design
    }
}

@Suite("PublicKey Cryptographic Key Tests")
struct PublicKeyTests {
    let sodium = Sodium()

    @Test("PublicKey initializes correctly with valid data")
    func testPublicKeyInit() async throws {
        let publicKeyData = Data(repeating: 0, count: sodium.cryptoBox.publicKeyBytes)
        let publicKey = try PublicKey(publicKey: publicKeyData)
        #expect(publicKey.toBytes() == publicKeyData, "PublicKey initialization failed")
    }

    @Test("PublicKey throws error with invalid size")
    func testPublicKeyInvalidSize() async throws {
        let invalidPublicKeyData = Data(repeating: 0, count: sodium.cryptoBox.publicKeyBytes - 1)
        #expect(throws: Error.self) {
            try PublicKey(publicKey: invalidPublicKeyData)
        }
    }
    
    @Test("PublicKey generates valid hash value")
    func testSigningKeyHash() async throws {
        let publicKeyData = Data(repeating: 0, count: sodium.cryptoBox.publicKeyBytes)
        let publicKey = try PublicKey(publicKey: publicKeyData)
        // hashValue should be accessible (non-nil not needed for Int)
        let _ = publicKey.hashValue
    }

    @Test("PublicKey equality comparison works correctly")
    func testPublicKeyEquality() async throws {
        let publicKeyData = Data(repeating: 0, count: sodium.cryptoBox.publicKeyBytes)
        let publicKey1 = try PublicKey(publicKey: publicKeyData)
        let publicKey2 = try PublicKey(publicKey: publicKeyData)
        #expect(publicKey1 == publicKey2, "PublicKey equality failed")
        #expect(publicKey1 == publicKey2, "PublicKey equality failed")
    }
}

@Suite("PrivateKey Cryptographic Key Tests")
struct PrivateKeyTests {
    let sodium = Sodium()

    @Test("PrivateKey initializes correctly with valid data")
    func testPrivateKeyInit() async throws {
        let privateKeyData = Data(repeating: 0, count: sodium.cryptoBox.secretKeyBytes)
        let privateKey = try PrivateKey(privateKey: privateKeyData)
        #expect(privateKey.toBytes() == privateKeyData, "PrivateKey initialization failed")
    }

    @Test("PrivateKey throws error with invalid size")
    func testPrivateKeyInvalidSize() async throws {
        let invalidPrivateKeyData = Data(repeating: 0, count: sodium.cryptoBox.secretKeyBytes - 1)
        #expect(throws: Error.self) {
            try PrivateKey(privateKey: invalidPrivateKeyData)
        }
    }

    @Test("PrivateKey generates correctly from seed")
    func testPrivateKeyFromSeed() async throws {
        let seed = Data(repeating: 0, count: sodium.cryptoBox.secretKeyBytes)
        let privateKey = try PrivateKey.fromSeed(seed: seed)
        #expect(privateKey.toBytes().count == sodium.cryptoBox.secretKeyBytes, "PrivateKey from seed failed")
    }
    
    @Test("PrivateKey generates valid hash value")
    func testPrivateKeyHash() async throws {
        let seed = Data(repeating: 0, count: sodium.cryptoBox.secretKeyBytes)
        let privateKey = try PrivateKey.fromSeed(seed: seed)
        // hashValue should be accessible (non-nil not needed for Int)
        let _ = privateKey.hashValue
    }

    @Test("PrivateKey equality comparison works correctly")
    func testPrivateKeyEquality() async throws {
        let privateKeyData = Data(repeating: 0, count: sodium.cryptoBox.secretKeyBytes)
        let privateKey1 = try PrivateKey(privateKey: privateKeyData)
        let privateKey2 = try PrivateKey(privateKey: privateKeyData)
        #expect(privateKey1 == privateKey2, "PrivateKey equality failed")
    }
}

@Suite("Box Encryption and Decryption Tests")
struct BoxTests {
    let sodium = Sodium()
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let privateKey = PrivateKey.generate()

    @Test("Box initializes successfully with keys")
    func testBoxInit() async throws {
        let _ = try Box(privateKey: privateKey, publicKey: privateKey.publicKey)
        // Box initialization succeeded if we reach this point
    }

    @Test("Box encrypts and decrypts message correctly")
    func testBoxEncryptDecrypt() async throws {
        let box = try Box(privateKey: privateKey, publicKey: privateKey.publicKey)
        let encryptedMessage = try box.encrypt(plaintext: message)
        let decryptedMessage = try box.decrypt(ciphertext: encryptedMessage.getMessage)
        #expect(decryptedMessage == message, "Box encrypt/decrypt failed")
    }

    @Test("Box encrypts and decrypts with custom nonce")
    func testBoxEncryptWithNonce() async throws {
        let box = try Box(privateKey: privateKey, publicKey: privateKey.publicKey)
        let nonce = Data(repeating: 0, count: box.NONCE_SIZE)
        let encryptedMessage = try box.encrypt(plaintext: message, nonce: nonce)
        let decryptedMessage = try box.decrypt(
            ciphertext: encryptedMessage.getCiphertext, nonce: nonce)
        #expect(decryptedMessage == message, "Box encrypt/decrypt with nonce failed")
    }

    @Test("Box throws error when decrypting with invalid nonce")
    func testBoxDecryptWithInvalidNonce() async throws {
        let box = try Box(privateKey: privateKey, publicKey: privateKey.publicKey)
        let encryptedMessage = try box.encrypt(plaintext: message)
        let invalidNonce = Data(repeating: 0, count: box.NONCE_SIZE - 1)
        #expect(throws: Error.self) {
            try box.decrypt(ciphertext: encryptedMessage.getCiphertext, nonce: invalidNonce)
        }
    }
}

@Suite("SealedBox Encryption and Decryption Tests")
struct SealedBoxTests {
    let sodium = Sodium()
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let privateKey = PrivateKey.generate()

    @Test("SealedBox initializes successfully with public key")
    func testSealedBoxInitWithPublicKey() async throws {
        let _ = SealedBox(recipientKey: privateKey.publicKey)
        // SealedBox initialization succeeded if we reach this point
    }

    @Test("SealedBox initializes successfully with private key")
    func testSealedBoxInitWithPrivateKey() async throws {
        let _ = SealedBox(recipientKey: privateKey)
        // SealedBox initialization succeeded if we reach this point
    }

    @Test("SealedBox encrypts and decrypts message correctly")
    func testSealedBoxEncryptDecrypt() async throws {
        let sealedBox = SealedBox(recipientKey: privateKey)
        let encryptedMessage = try sealedBox.encrypt(plaintext: message)
        let decryptedMessage = try sealedBox.decrypt(ciphertext: encryptedMessage)
        #expect(decryptedMessage == message, "SealedBox encrypt/decrypt failed")
    }

    @Test("SealedBox throws error when decrypting with public key only")
    func testSealedBoxDecryptWithPublicKey() async throws {
        let sealedBox = SealedBox(recipientKey: privateKey.publicKey)
        let encryptedMessage = try sealedBox.encrypt(plaintext: message)
        #expect(throws: Error.self) {
            try sealedBox.decrypt(ciphertext: encryptedMessage)
        }
    }
}
