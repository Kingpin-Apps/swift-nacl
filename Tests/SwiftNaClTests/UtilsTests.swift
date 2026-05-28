import Foundation
import Testing

@testable import SwiftNaCl

@Suite("EncryptedMessage utilities")
struct EncryptedMessageTests {
    let nonce = Data(repeating: 0, count: 24)  // 24 bytes nonce
    let ciphertext = Data(repeating: 1, count: 64)  // 64 bytes ciphertext

    @Test("initializes with provided nonce, ciphertext, and combined data")
    func testEncryptedMessageInit() async throws {
        let combined = nonce + ciphertext
        let encryptedMessage = EncryptedMessage(
            nonce: nonce, ciphertext: ciphertext, combined: combined)
        #expect(encryptedMessage.getNonce == nonce, "EncryptedMessage nonce mismatch")
        #expect(
            encryptedMessage.getCiphertext == ciphertext,
            "EncryptedMessage ciphertext mismatch"
        )
        #expect(encryptedMessage.getMessage == combined, "EncryptedMessage combined mismatch")
    }

    @Test("creates from parts and preserves values")
    func testEncryptedMessageFromParts() async throws {
        let combined = nonce + ciphertext
        let encryptedMessage = EncryptedMessage.fromParts(
            nonce: nonce, ciphertext: ciphertext, combined: combined)
        #expect(encryptedMessage.getNonce == nonce, "EncryptedMessage nonce mismatch")
        #expect(
            encryptedMessage.getCiphertext == ciphertext,
            "EncryptedMessage ciphertext mismatch"
        )
        #expect(encryptedMessage.getMessage == combined, "EncryptedMessage combined mismatch")
    }
}

@Suite("StringFixer utilities")
struct StringFixerTests {
    @Test("converts Data to String using UTF-8")
    func testToString() async throws {
        let data = "Hello, World!".data(using: .utf8)!
        let stringFixer = StringFixer()
        let result = stringFixer.toString(data: data)
        #expect(result == "Hello, World!", "StringFixer toString failed")
    }
}

@Suite("General utilities")
struct UtilsTests {
    @Test("formats bytes as lowercase hex string")
    func testBytesAsString() async throws {
        let data = Data([0x00, 0x01, 0x02, 0x03])
        let result = bytesAsString(bytesIn: data)
        #expect(result == "00010203", "bytesAsString failed")
    }

    @Test("generates random data of requested size")
    func testRandom() async throws {
        let size = 32
        let randomData = random(size: size)
        #expect(randomData.count == size, "Random data size mismatch")
    }

    @Test("generates deterministic random data of requested size")
    func testRandomBytesDeterministic() async throws {
        let size = 32
        let seed = Data(repeating: 0, count: 32)
        let deterministicData = try randomBytesDeterministic(size: size, seed: seed)
        #expect(deterministicData.count == size, "Deterministic random data size mismatch")
    }
}
