import Foundation
import Testing

// Deliberately not `@testable`: everything in this file must compile against
// the public API alone, the way an external package sees SwiftNaCl.
import SwiftNaCl

@Suite("Public API round-trips (no @testable import)")
struct PublicAPIRoundTripTests {
    let message = Data("Attack at dawn".utf8)

    @Test("Box.encrypt output decrypts on the other side via combined bytes")
    func boxRoundTripCombined() throws {
        let alice = PrivateKey.generate()
        let bob = PrivateKey.generate()

        let sender = try Box(privateKey: alice, publicKey: bob.publicKey)
        let receiver = try Box(privateKey: bob, publicKey: alice.publicKey)

        let encrypted = try sender.encrypt(plaintext: message)
        #expect(encrypted.nonce.count == sender.NONCE_SIZE)
        #expect(encrypted.ciphertext.count == message.count + 16)
        #expect(encrypted.combined == encrypted.nonce + encrypted.ciphertext)

        #expect(try receiver.decrypt(ciphertext: encrypted.combined) == message)
    }

    @Test("Box.encrypt output decrypts via ciphertext plus explicit nonce")
    func boxRoundTripExplicitNonce() throws {
        let alice = PrivateKey.generate()
        let bob = PrivateKey.generate()
        let sender = try Box(privateKey: alice, publicKey: bob.publicKey)
        let receiver = try Box(privateKey: bob, publicKey: alice.publicKey)

        let nonce = random(size: sender.NONCE_SIZE)
        let encrypted = try sender.encrypt(plaintext: message, nonce: nonce)
        #expect(encrypted.nonce == nonce)
        #expect(try receiver.decrypt(ciphertext: encrypted.ciphertext, nonce: encrypted.nonce) == message)
    }

    @Test("Box.encrypt with an encoder encodes every part and decrypts with the same encoder")
    func boxRoundTripEncoded() throws {
        let alice = PrivateKey.generate()
        let bob = PrivateKey.generate()
        let sender = try Box(privateKey: alice, publicKey: bob.publicKey)
        let receiver = try Box(privateKey: bob, publicKey: alice.publicKey)

        let encrypted = try sender.encrypt(plaintext: message, encoder: HexEncoder.self)
        #expect(encrypted.nonce.count == sender.NONCE_SIZE * 2)
        #expect(encrypted.combined == encrypted.nonce + encrypted.ciphertext)
        #expect(try receiver.decrypt(ciphertext: encrypted.combined, encoder: HexEncoder.self) == message)
    }

    @Test("Box.decrypt rejects a tampered ciphertext")
    func boxRejectsTampering() throws {
        let alice = PrivateKey.generate()
        let bob = PrivateKey.generate()
        let sender = try Box(privateKey: alice, publicKey: bob.publicKey)
        let receiver = try Box(privateKey: bob, publicKey: alice.publicKey)

        var combined = try sender.encrypt(plaintext: message).combined
        combined[combined.count - 1] ^= 0x01
        #expect(throws: SodiumError.self) {
            _ = try receiver.decrypt(ciphertext: combined)
        }
    }
}

@Suite("SecretBox and Aead public API (no @testable import)")
struct SecretPublicAPITests {
    let message = Data("Attack at dawn".utf8)

    @Test("SecretBox round-trips via combined bytes and via ciphertext plus nonce")
    func secretBoxRoundTrip() throws {
        let key = random(size: Sodium().cryptoSecretBox.keyBytes)
        let box = try SecretBox(key: key)
        #expect(box.keySize == 32)
        #expect(box.nonceSize == 24)
        #expect(box.macBytes == 16)

        let encrypted = try box.encrypt(plaintext: message)
        #expect(encrypted.combined == encrypted.nonce + encrypted.ciphertext)
        #expect(try box.decrypt(ciphertext: encrypted.combined) == message)
        #expect(try box.decrypt(ciphertext: encrypted.ciphertext, nonce: encrypted.nonce) == message)

        let other = try SecretBox(key: random(size: 32))
        #expect(throws: SodiumError.self) {
            _ = try other.decrypt(ciphertext: encrypted.combined)
        }
    }

    @Test("SecretBox matches the NaCl XSalsa20-Poly1305 test vector")
    func secretBoxKnownAnswer() throws {
        let key = hexData("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
        let nonce = hexData("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
        let plaintext = hexData(
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705")
        let ciphertext = hexData(
            "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5")

        let box = try SecretBox(key: key)
        let encrypted = try box.encrypt(plaintext: plaintext, nonce: nonce)
        #expect(encrypted.ciphertext == ciphertext)
        #expect(encrypted.combined == nonce + ciphertext)
        #expect(try box.decrypt(ciphertext: ciphertext, nonce: nonce) == plaintext)
    }

    @Test("Aead round-trips with AAD and rejects mismatched AAD")
    func aeadRoundTrip() throws {
        let key = random(size: Sodium().cryptoAead.xchacha20poly1305IetfKeyBytes)
        let aead = try Aead(key: key)
        let header = Data("v1".utf8)
        #expect(aead.keySize == 32)
        #expect(aead.nonceSize == 24)
        #expect(aead.macBytes == 16)

        let encrypted = try aead.encrypt(plaintext: message, aad: header)
        #expect(encrypted.combined == encrypted.nonce + encrypted.ciphertext)
        #expect(try aead.decrypt(ciphertext: encrypted.combined, aad: header) == message)
        #expect(
            try aead.decrypt(ciphertext: encrypted.ciphertext, aad: header, nonce: encrypted.nonce) == message)
        #expect(throws: SodiumError.self) {
            _ = try aead.decrypt(ciphertext: encrypted.combined, aad: Data("v2".utf8))
        }
    }

    @Test("Aead output matches the low-level XChaCha20-Poly1305 binding")
    func aeadMatchesBinding() throws {
        let binding = Sodium().cryptoAead
        let key = random(size: binding.xchacha20poly1305IetfKeyBytes)
        let nonce = random(size: binding.xchacha20poly1305IetfNpubBytes)
        let header = Data("header".utf8)

        let encrypted = try Aead(key: key).encrypt(plaintext: message, aad: header, nonce: nonce)
        let expected = try binding.xchacha20poly1305IetfEncrypt(
            message: message, aad: header, nonce: nonce, key: key)
        #expect(encrypted.ciphertext == expected)
    }

    private func hexData(_ hex: String) -> Data {
        HexEncoder.decode(data: Data(hex.utf8))
    }
}
