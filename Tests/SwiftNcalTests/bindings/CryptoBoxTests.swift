import Foundation
import Clibsodium
import Testing

@testable import SwiftNcal

@Suite("Crypto Box Tests")
struct CryptoBoxTests {
    let sodium = Sodium()
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    
    @Test("Box encryption works correctly")
    func box() async throws {
        let keyPair = try sodium.cryptoBox.keypair()
        let nonce = Data(repeating: 0, count: sodium.cryptoBox.nonceBytes)
        
        let ciphertext = try sodium.cryptoBox.box(message: message, nonce: nonce, publicKey: keyPair.publicKey, secretKey: keyPair.secretKey)
        #expect(ciphertext.count > 0, "Box encryption should produce non-empty ciphertext")
    }

    @Test("Box decryption works correctly")
    func open() async throws {
        let keyPair = try sodium.cryptoBox.keypair()
        let nonce = Data(repeating: 0, count: sodium.cryptoBox.nonceBytes)
        
        let ciphertext = try sodium.cryptoBox.box(message: message, nonce: nonce, publicKey: keyPair.publicKey, secretKey: keyPair.secretKey)
        let decryptedMessage = try sodium.cryptoBox.open(
            ciphertext: ciphertext, nonce: nonce, publicKey: keyPair.publicKey,
            secretKey: keyPair.secretKey)
        #expect(decryptedMessage == message, "Box decryption should recover original message")
    }

    @Test("Afternm encryption works correctly")
    func afternm() async throws {
        let keyPair = try sodium.cryptoBox.keypair()
        let nonce = Data(repeating: 0, count: sodium.cryptoBox.nonceBytes)
        
        let sharedKey = try sodium.cryptoBox.beforenm(
            publicKey: keyPair.publicKey, secretKey: keyPair.secretKey)
        let ciphertext = try sodium.cryptoBox.afternm(
            message: message, nonce: nonce, sharedKey: sharedKey)
        #expect(ciphertext.count > 0, "Afternm encryption should produce non-empty ciphertext")
    }

    @Test("Afternm decryption works correctly")
    func openAfternm() async throws {
        let keyPair = try sodium.cryptoBox.keypair()
        let nonce = Data(repeating: 0, count: sodium.cryptoBox.nonceBytes)
        
        let sharedKey = try sodium.cryptoBox.beforenm(
            publicKey: keyPair.publicKey, secretKey: keyPair.secretKey)
        let ciphertext = try sodium.cryptoBox.afternm(
            message: message, nonce: nonce, sharedKey: sharedKey)
        let decryptedMessage = try sodium.cryptoBox.openAfternm(
            ciphertext: ciphertext, nonce: nonce, sharedKey: sharedKey)
        #expect(decryptedMessage == message, "Afternm decryption should recover original message")
    }

    @Test("Box with invalid public key throws error")
    func boxWithInvalidPublicKey() async throws {
        let keyPair = try sodium.cryptoBox.keypair()
        let nonce = Data(repeating: 0, count: sodium.cryptoBox.nonceBytes)
        
        let invalidPublicKey = Data(repeating: 0, count: sodium.cryptoBox.publicKeyBytes - 1)
        #expect(throws: SodiumError.self) {
            try sodium.cryptoBox.box(
                message: message, nonce: nonce, publicKey: invalidPublicKey,
                secretKey: keyPair.secretKey)
        }
    }

    @Test("Keypair generation produces correct key sizes")
    func keypair() async throws {
        let cryptoBox = sodium.cryptoBox
        let keypair = try cryptoBox.keypair()
        #expect(
            keypair.publicKey.count == cryptoBox.publicKeyBytes, "Public key should have correct length")
        #expect(
            keypair.secretKey.count == cryptoBox.secretKeyBytes, "Secret key should have correct length")
    }

    @Test("Seed-based keypair generation produces correct key sizes")
    func seedKeypair() async throws {
        let cryptoBox = sodium.cryptoBox
        let seed = Data(repeating: 0x01, count: cryptoBox.seedBytes)
        let keypair = try cryptoBox.seedKeypair(seed: seed)
        #expect(
            keypair.publicKey.count == cryptoBox.publicKeyBytes, "Public key should have correct length")
        #expect(
            keypair.secretKey.count == cryptoBox.secretKeyBytes, "Secret key should have correct length")
    }

    @Test("Complete crypto box operations work correctly")
    func cryptoBox() async throws {
        let cryptoBox = sodium.cryptoBox

        // Generate keypairs
        let A_keypair = try cryptoBox.keypair()
        #expect(A_keypair.publicKey.count == cryptoBox.publicKeyBytes, "Public key A should have correct length")
        #expect(A_keypair.secretKey.count == cryptoBox.secretKeyBytes, "Secret key A should have correct length")

        let B_keypair = try cryptoBox.keypair()

        // Compute shared keys
        let k1 = try cryptoBox.beforenm(
            publicKey: B_keypair.publicKey, secretKey: A_keypair.secretKey)
        #expect(k1.count == cryptoBox.beforeNmBytes, "Shared key should have correct length")

        let k2 = try cryptoBox.beforenm(
            publicKey: A_keypair.publicKey, secretKey: B_keypair.secretKey)
        #expect(k1 == k2, "Shared keys computed from both directions should be equal")

        // Encrypt message
        let message = "message".data(using: .utf8)!
        let nonce = Data(repeating: 0x01, count: cryptoBox.nonceBytes)

        let ct1 = try cryptoBox.easyAfternm(message: message, nonce: nonce, sharedKey: k1)
        #expect(ct1.count == message.count + cryptoBox.macBytes, "Ciphertext should have correct length")

        let ct2 = try cryptoBox.easy(
            message: message, nonce: nonce, publicKey: B_keypair.publicKey,
            secretKey: A_keypair.secretKey)
        #expect(ct1 == ct2, "Ciphertexts from easy and afternm should be equal")

        // Decrypt message
        let m1 = try cryptoBox.openEasy(
            ciphertext: ct1, nonce: nonce, publicKey: A_keypair.publicKey,
            secretKey: B_keypair.secretKey)
        #expect(m1 == message, "Decrypted message should match original")

        let m2 = try cryptoBox.openEasyAfternm(ciphertext: ct1, nonce: nonce, sharedKey: k1)
        #expect(m2 == message, "Decrypted message from afternm should match original")

        // Test decryption failure
        #expect(throws: SodiumError.self) {
            try cryptoBox.openEasy(
                ciphertext: message + Data([0x21]), nonce: nonce, publicKey: A_keypair.publicKey,
                secretKey: A_keypair.secretKey)
        }
    }

    @Test("Box easy operations work correctly")
    func boxEasy() async throws {
        let cryptoBox = sodium.cryptoBox

        // Generate keypairs
        let A_keypair = try cryptoBox.keypair()
        #expect(A_keypair.publicKey.count == cryptoBox.publicKeyBytes, "Public key A should have correct length")
        #expect(A_keypair.secretKey.count == cryptoBox.secretKeyBytes, "Secret key A should have correct length")

        let B_keypair = try cryptoBox.keypair()

        // Compute shared keys
        let k1 = try cryptoBox.beforenm(
            publicKey: B_keypair.publicKey, secretKey: A_keypair.secretKey)
        #expect(k1.count == cryptoBox.beforeNmBytes, "Shared key should have correct length")

        let k2 = try cryptoBox.beforenm(
            publicKey: A_keypair.publicKey, secretKey: B_keypair.secretKey)
        #expect(k1 == k2, "Shared keys computed from both directions should be equal")

        // Encrypt message
        let message = "message".data(using: .utf8)!
        let nonce = Data(repeating: 0x01, count: cryptoBox.nonceBytes)

        let ct1 = try cryptoBox.easyAfternm(message: message, nonce: nonce, sharedKey: k1)
        #expect(ct1.count == message.count + cryptoBox.macBytes, "Ciphertext should have correct length")

        let ct2 = try cryptoBox.easy(
            message: message, nonce: nonce, publicKey: B_keypair.publicKey,
            secretKey: A_keypair.secretKey)
        #expect(ct1 == ct2, "Ciphertexts from easy and afternm should be equal")

        // Decrypt message
        let m1 = try cryptoBox.openEasy(
            ciphertext: ct1, nonce: nonce, publicKey: A_keypair.publicKey,
            secretKey: B_keypair.secretKey)
        #expect(m1 == message, "Decrypted message should match original")

        let m2 = try cryptoBox.openEasyAfternm(ciphertext: ct1, nonce: nonce, sharedKey: k1)
        #expect(m2 == message, "Decrypted message from afternm should match original")

        // Test decryption failure
        #expect(throws: SodiumError.self) {
            try cryptoBox.openEasy(
                ciphertext: message + Data([0x21]), nonce: nonce, publicKey: A_keypair.publicKey,
                secretKey: A_keypair.secretKey)
        }
    }

    @Test("Box operations handle wrong lengths correctly")
    func boxWrongLengths() async throws {
        let cryptoBox = sodium.cryptoBox

        // Generate keypair
        let A_keypair = try cryptoBox.keypair()

        // Test invalid lengths for crypto_box
        #expect(throws: SodiumError.self) {
            try cryptoBox.easy(
                message: Data("abc".utf8), nonce: Data([0x00]), publicKey: A_keypair.publicKey,
                secretKey: A_keypair.secretKey)
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.easy(
                message: Data("abc".utf8),
                nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes), publicKey: Data(),
                secretKey: A_keypair.secretKey)
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.easy(
                message: Data("abc".utf8),
                nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                publicKey: A_keypair.publicKey, secretKey: Data())
        }

        // Test invalid lengths for crypto_box_open
        #expect(throws: SodiumError.self) {
            try cryptoBox.openEasy(
                ciphertext: Data(), nonce: Data(), publicKey: Data(), secretKey: Data())
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.openEasy(
                ciphertext: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                publicKey: Data(), secretKey: Data())
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.openEasy(
                ciphertext: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                publicKey: A_keypair.publicKey, secretKey: Data())
        }

        // Test invalid lengths for crypto_box_beforenm
        #expect(throws: SodiumError.self) {
            try cryptoBox.beforenm(publicKey: Data(), secretKey: Data())
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.beforenm(publicKey: A_keypair.publicKey, secretKey: Data())
        }

        // Test invalid lengths for crypto_box_afternm
        #expect(throws: SodiumError.self) {
            try cryptoBox.easyAfternm(message: Data(), nonce: Data(), sharedKey: Data())
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.easyAfternm(
                message: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                sharedKey: Data())
        }

        // Test invalid lengths for crypto_box_open_afternm
        #expect(throws: SodiumError.self) {
            try cryptoBox.openEasyAfternm(ciphertext: Data(), nonce: Data(), sharedKey: Data())
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.openEasyAfternm(
                ciphertext: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                sharedKey: Data())
        }
    }

    @Test("Box easy operations handle wrong lengths correctly")
    func boxEasyWrongLengths() async throws {
        let cryptoBox = sodium.cryptoBox

        // Generate keypair
        let A_keypair = try cryptoBox.keypair()

        // Test invalid lengths for crypto_box_easy
        #expect(throws: SodiumError.self) {
            try cryptoBox.easy(
                message: Data("abc".utf8), nonce: Data([0x00]), publicKey: A_keypair.publicKey,
                secretKey: A_keypair.secretKey)
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.easy(
                message: Data("abc".utf8),
                nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes), publicKey: Data(),
                secretKey: A_keypair.secretKey)
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.easy(
                message: Data("abc".utf8),
                nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                publicKey: A_keypair.publicKey, secretKey: Data())
        }

        // Test invalid lengths for crypto_box_open_easy
        #expect(throws: SodiumError.self) {
            try cryptoBox.openEasy(
                ciphertext: Data(), nonce: Data(), publicKey: Data(), secretKey: Data())
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.openEasy(
                ciphertext: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                publicKey: Data(), secretKey: Data())
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.openEasy(
                ciphertext: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                publicKey: A_keypair.publicKey, secretKey: Data())
        }

        // Test invalid lengths for crypto_box_beforenm
        #expect(throws: SodiumError.self) {
            try cryptoBox.beforenm(publicKey: Data(), secretKey: Data())
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.beforenm(publicKey: A_keypair.publicKey, secretKey: Data())
        }

        // Test invalid lengths for crypto_box_easy_afternm
        #expect(throws: SodiumError.self) {
            try cryptoBox.easyAfternm(message: Data(), nonce: Data(), sharedKey: Data())
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.easyAfternm(
                message: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                sharedKey: Data())
        }

        // Test invalid lengths for crypto_box_open_easy_afternm
        #expect(throws: SodiumError.self) {
            try cryptoBox.openEasyAfternm(ciphertext: Data(), nonce: Data(), sharedKey: Data())
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.openEasyAfternm(
                ciphertext: Data(), nonce: Data(repeating: 0x00, count: cryptoBox.nonceBytes),
                sharedKey: Data())
        }
    }

    @Test("Box seal works with empty message")
    func boxSealEmpty() async throws {
        let cryptoBox = sodium.cryptoBox

        // Generate keypair
        let keypair = try cryptoBox.keypair()

        // Encrypt an empty message
        let emptyMessage = Data()
        let sealedMessage = try cryptoBox.seal(message: emptyMessage, publicKey: keypair.publicKey)

        // Decrypt the sealed message
        let decryptedMessage = try cryptoBox.sealOpen(
            ciphertext: sealedMessage, publicKey: keypair.publicKey, secretKey: keypair.secretKey)

        // Assert that the decrypted message is equal to the empty message
        #expect(decryptedMessage == emptyMessage, "Decrypted empty message should match original")
    }

    @Test("Box seal empty message is verified")
    func boxSealEmptyIsVerified() async throws {
        let cryptoBox = sodium.cryptoBox

        // Generate keypair
        let keypair = try cryptoBox.keypair()

        // Encrypt an empty message
        let emptyMessage = Data()
        var sealedMessage = try cryptoBox.seal(message: emptyMessage, publicKey: keypair.publicKey)

        // Tamper with the sealed message
        sealedMessage[sealedMessage.count - 1] ^= 1

        // Attempt to decrypt the tampered message and expect a failure
        #expect(throws: SodiumError.self) {
            try cryptoBox.sealOpen(
                ciphertext: sealedMessage, publicKey: keypair.publicKey,
                secretKey: keypair.secretKey)
        }
    }

    @Test("Box seal operations handle wrong lengths correctly")
    func boxSealWrongLengths() async throws {
        let cryptoBox = sodium.cryptoBox

        // Generate keypair
        let keypair = try cryptoBox.keypair()

        // Test invalid lengths for crypto_box_seal
        #expect(throws: SodiumError.self) {
            try cryptoBox.seal(message: Data("abc".utf8), publicKey: keypair.publicKey.dropLast())
        }

        // Test invalid lengths for crypto_box_seal_open
        #expect(throws: SodiumError.self) {
            try cryptoBox.sealOpen(
                ciphertext: Data("abc".utf8), publicKey: Data(), secretKey: keypair.secretKey)
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.sealOpen(
                ciphertext: Data("abc".utf8), publicKey: keypair.publicKey,
                secretKey: keypair.secretKey.dropLast())
        }

        // Encrypt an empty message
        let emptyMessage = Data()
        let sealedMessage = try cryptoBox.seal(message: emptyMessage, publicKey: keypair.publicKey)

        // Tamper with the sealed message
        let tamperedMessage = sealedMessage.dropLast()

        // Attempt to decrypt the tampered message and expect a failure
        #expect(throws: SodiumError.self) {
            try cryptoBox.sealOpen(
                ciphertext: tamperedMessage, publicKey: keypair.publicKey,
                secretKey: keypair.secretKey)
        }
    }

    @Test("Box seal operations handle wrong types correctly")
    func boxSealWrongTypes() async throws {
        let cryptoBox = sodium.cryptoBox

        // Generate keypair
        let keypair = try cryptoBox.keypair()

        // Test invalid types for crypto_box_seal
        #expect(throws: SodiumError.self) {
            try cryptoBox.seal(message: Data("abc".utf8), publicKey: Data())
        }

        // Test invalid types for crypto_box_seal_open
        #expect(throws: SodiumError.self) {
            try cryptoBox.sealOpen(
                ciphertext: Data("abc".utf8), publicKey: Data(), secretKey: keypair.secretKey)
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.sealOpen(
                ciphertext: Data("abc".utf8), publicKey: keypair.publicKey, secretKey: Data())
        }
        #expect(throws: SodiumError.self) {
            try cryptoBox.sealOpen(
                ciphertext: Data(), publicKey: keypair.publicKey, secretKey: keypair.secretKey)
        }
    }

    @Test("Box seed keypair works with random seed")
    func boxSeedKeypairRandom() async throws {
        let cryptoBox = sodium.cryptoBox

        // Generate a random seed
        let seed = sodium.randomBytes.randomBytes(size: cryptoBox.seedBytes)

        // Generate keypair from seed
        let keypair = try cryptoBox.seedKeypair(seed: seed)

        // Compute public key from secret key
        let computedPublicKey = try sodium.cryptoScalarmult.base(
            n: keypair.secretKey
        )

        // Assert that the generated public key matches the computed public key
        #expect(keypair.publicKey == computedPublicKey, "Generated public key should match computed public key")
    }

    @Test("Box seed keypair handles short seed correctly")
    func boxSeedKeypairShortSeed() async throws {
        let cryptoBox = sodium.cryptoBox

        // Generate a short seed
        let shortSeed = sodium.randomBytes.randomBytes(
            size: cryptoBox.seedBytes - 1
        )

        // Test invalid seed length for seedKeypair
        #expect(throws: SodiumError.self) {
            try cryptoBox.seedKeypair(seed: shortSeed)
        }
    }

    @Test("Box seed keypair works with reference test vectors")
    func boxSeedKeypairReference() async throws {
        let cryptoBox = sodium.cryptoBox

        // Read test vectors
        let vectors = readCryptoTestVectors(fileName: "box_from_seed", delimiter: "\t")

        for (seed, expectedPublicKey, expectedSecretKey) in vectors {
            // Generate keypair from seed
            let keypair = try cryptoBox.seedKeypair(seed: seed)

            // Assert that the generated keys match the expected keys
            #expect(keypair.publicKey == expectedPublicKey, "Generated public key should match expected")
            #expect(keypair.secretKey == expectedSecretKey, "Generated secret key should match expected")
        }
    }

    @Test("Crypto box open easy works correctly")
    func cryptoBoxOpenEasy() async throws {
        let cryptoBox = sodium.cryptoBox

        // Generate keypair
        let keypair = try cryptoBox.keypair()
        let publicKey = keypair.publicKey
        let secretKey = keypair.secretKey

        let message = "Hello, World!".data(using: .utf8)!
        let nonce = Data(count: cryptoBox.nonceBytes)

        let ciphertext = try cryptoBox.easy(
            message: message, nonce: nonce, publicKey: publicKey, secretKey: secretKey)
        let decryptedMessage = try cryptoBox.openEasy(
            ciphertext: ciphertext, nonce: nonce, publicKey: publicKey, secretKey: secretKey)
        #expect(message == decryptedMessage, "Decrypted message should match original")
    }

    @Test("Crypto box seal works correctly")
    func cryptoBoxSeal() async throws {
        let cryptoBox = sodium.cryptoBox

        // Generate keypair
        let keypair = try cryptoBox.keypair()

        let message = "Hello, World!".data(using: .utf8)!
        let publicKey = keypair.publicKey

        let ciphertext = try cryptoBox.seal(message: message, publicKey: publicKey)
        #expect(ciphertext.count > 0, "Seal should produce non-empty ciphertext")
    }

    @Test("Crypto box seal open works correctly")
    func cryptoBoxSealOpen() async throws {
        let cryptoBox = sodium.cryptoBox

        // Generate keypair
        let keypair = try cryptoBox.keypair()
        let publicKey = keypair.publicKey
        let secretKey = keypair.secretKey

        let message = "Hello, World!".data(using: .utf8)!

        let ciphertext = try cryptoBox.seal(message: message, publicKey: publicKey)
        let decryptedMessage = try cryptoBox.sealOpen(
            ciphertext: ciphertext, publicKey: publicKey, secretKey: secretKey)
        #expect(message == decryptedMessage, "Decrypted message should match original")
    }

    @Test("Crypto box easy afternm works correctly")
    func cryptoBoxEasyAfternm() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let nonce = Data(count: Int(crypto_box_noncebytes()))
        let sharedKey = Data(count: Int(crypto_box_beforenmbytes()))

        let cryptoBox = CryptoBox()

        let ciphertext = try cryptoBox.easyAfternm(
            message: message, nonce: nonce, sharedKey: sharedKey)
        #expect(ciphertext.count > 0, "Easy afternm should produce non-empty ciphertext")
    }

    @Test("Crypto box open easy afternm works correctly")
    func cryptoBoxOpenEasyAfternm() async throws {
        let message = "Hello, World!".data(using: .utf8)!
        let nonce = Data(count: Int(crypto_box_noncebytes()))
        let sharedKey = Data(count: Int(crypto_box_beforenmbytes()))

        let cryptoBox = CryptoBox()

        let ciphertext = try cryptoBox.easyAfternm(
            message: message, nonce: nonce, sharedKey: sharedKey)
        let decryptedMessage = try cryptoBox.openEasyAfternm(
            ciphertext: ciphertext, nonce: nonce, sharedKey: sharedKey)
        #expect(message == decryptedMessage, "Decrypted message should match original")
    }
}
