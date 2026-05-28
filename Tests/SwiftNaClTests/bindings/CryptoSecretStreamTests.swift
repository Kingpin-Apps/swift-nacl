import Clibsodium
import Testing
import Foundation

@testable import SwiftNaCl

@Suite("Crypto Secret Stream Tests") struct CryptoSecretStreamTests {
    let cryptoSecretStream = Sodium().cryptoSecretStream

    @Test("keygen returns key with expected length")
    func testKeygen() {
        let key = cryptoSecretStream.xchacha20poly1305Keygen()
        #expect(key.count == cryptoSecretStream.xchacha20poly1305Keybytes, "Generated key length mismatch")
    }

    @Test("initPush produces header of expected length and initPull succeeds")
    func testInitPushAndPull() throws {
        let key = cryptoSecretStream.xchacha20poly1305Keygen()
        let statePush = CryptoSecretstreamXchacha20poly1305State()
        let statePull = CryptoSecretstreamXchacha20poly1305State()

        let header = try cryptoSecretStream.xchacha20poly1305InitPush(state: statePush, key: key)
        #expect(header.count == cryptoSecretStream.xchacha20poly1305Headerbytes, "Header length mismatch")

        try cryptoSecretStream.xchacha20poly1305InitPull(state: statePull, header: header, key: key)
    }

    @Test("push/pull roundtrip yields original message and tag")
    func testPushAndPull() throws {
        let key = cryptoSecretStream.xchacha20poly1305Keygen()
        let statePush = CryptoSecretstreamXchacha20poly1305State()
        let statePull = CryptoSecretstreamXchacha20poly1305State()

        let header = try cryptoSecretStream.xchacha20poly1305InitPush(state: statePush, key: key)
        try cryptoSecretStream.xchacha20poly1305InitPull(state: statePull, header: header, key: key)

        let message = "Hello, World!".data(using: .utf8)!
        let additionalData = "Additional data".data(using: .utf8)
        let tag: UInt8 = cryptoSecretStream.xchacha20poly1305TagMessage

        let ciphertext = try cryptoSecretStream.xchacha20poly1305Push(state: statePush, message: message, additionalData: additionalData, tag: tag)
        let (decryptedMessage, decryptedTag) = try cryptoSecretStream.xchacha20poly1305Pull(state: statePull, ciphertext: ciphertext, additionalData: additionalData)

        #expect(message == decryptedMessage, "Decrypted message does not match the original message")
        #expect(tag == UInt8(decryptedTag), "Decrypted tag does not match the original tag")
    }

    @Test("rekey executes without throwing")
    func testRekey() throws {
        let key = cryptoSecretStream.xchacha20poly1305Keygen()
        let statePush = CryptoSecretstreamXchacha20poly1305State()

        _ = try cryptoSecretStream.xchacha20poly1305InitPush(state: statePush, key: key)
        cryptoSecretStream.xchacha20poly1305Rekey(state: statePush)
    }

    @Test("initPush throws for invalid key length")
    func testInitPushWithInvalidKey() throws {
        let key = Data(repeating: 0, count: cryptoSecretStream.xchacha20poly1305Keybytes - 1) // Invalid key length
        let statePush = CryptoSecretstreamXchacha20poly1305State()

        #expect(throws: Error.self, "Expected error for invalid key length") {
            try cryptoSecretStream
                .xchacha20poly1305InitPush(state: statePush, key: key)
        }
    }

    @Test("initPull throws for invalid header length")
    func testInitPullWithInvalidHeader() throws {
        let key = cryptoSecretStream.xchacha20poly1305Keygen()
        let statePull = CryptoSecretstreamXchacha20poly1305State()
        let header = Data(repeating: 0, count: cryptoSecretStream.xchacha20poly1305Headerbytes - 1) // Invalid header length

        #expect(throws: Error.self, "Expected error for invalid header length") { try cryptoSecretStream.xchacha20poly1305InitPull(state: statePull, header: header, key: key) }
    }
}

