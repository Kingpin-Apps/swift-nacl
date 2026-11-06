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
