import Foundation
import Testing

@testable import SwiftNcal

@Suite("Signed message utilities")
struct SignedMessageTests {
    let signature = Data(repeating: 0, count: 64)
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let combined = Data(repeating: 0, count: 128)

    @Test("initializes with provided parts")
    func testSignedMessageInit() async throws {
        let signedMessage = SignedMessage(
            signature: signature, message: message, combined: combined)
        #expect(signedMessage.getSignature == signature, "SignedMessage signature mismatch")
        #expect(signedMessage.getMessage == message, "SignedMessage message mismatch")
        #expect(signedMessage.getCombined == combined, "SignedMessage combined mismatch")
    }

    @Test("creates from parts and preserves values")
    func testSignedMessageFromParts() async throws {
        let signedMessage = SignedMessage.fromParts(
            signature: signature, message: message, combined: combined)
        #expect(signedMessage.getSignature == signature, "SignedMessage signature mismatch")
        #expect(signedMessage.getMessage == message, "SignedMessage message mismatch")
        #expect(signedMessage.getCombined == combined, "SignedMessage combined mismatch")
    }
}

@Suite("VerifyKey operations")
struct VerifyKeyTests {
    let sodium = Sodium()

    @Test("initializes with correct public key size")
    func testVerifyKeyInit() async throws {
        let verifyKey = try VerifyKey(key: Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes))
        #expect(
            verifyKey.bytes == Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes),
            "VerifyKey initialization failed"
        )
    }

    @Test("hash value is stable for the same instance")
    func testVerifyKeyHash() async throws {
        let verifyKey = try VerifyKey(key: Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes))
        let h1 = verifyKey.hashValue
        let h2 = verifyKey.hashValue
        #expect(h1 == h2, "VerifyKey hash failed")
    }

    @Test("fails to initialize with invalid public key size")
    func testVerifyKeyInvalidSize() async throws {
        let invalidPublicKeyData = Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes - 1)
        #expect(throws: Error.self) {
            _ = try VerifyKey(key: invalidPublicKeyData)
        }
    }

    @Test("equality holds for identical keys")
    func testVerifyKeyEquality() async throws {
        let verifyKey1 = try VerifyKey(key: Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes))
        let verifyKey2 = try VerifyKey(key: Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes))
        #expect(verifyKey1 == verifyKey2, "VerifyKey equality failed")
    }

    @Test("verify throws for invalid signed message")
    func testVerifyKeyVerify() async throws {
        let verifyKey = try VerifyKey(key: Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes))
        let signedMessage = Data(repeating: 0, count: sodium.cryptoSign.bytes + 32)
        #expect(throws: Error.self) {
            _ = try verifyKey.verify(smessage: signedMessage)
        }
    }

    @Test("verify throws for invalid signature size")
    func testVerifyKeyVerifyInvalidSignature() async throws {
        let verifyKey = try VerifyKey(key: Data(repeating: 0, count: sodium.cryptoSign.publicKeyBytes))
        let signedMessage = Data(repeating: 0, count: sodium.cryptoSign.bytes + 32)
        let invalidSignature = Data(repeating: 0, count: 32)
        #expect(throws: Error.self) {
            _ = try verifyKey.verify(
                smessage: signedMessage,
                signature: invalidSignature
            )
        }
    }

    @Test("converts to Curve25519 public key")
    func testVerifyKeyToCurve25519PublicKey() async throws {
        let keypair = try sodium.cryptoSign.keypair()
        let verifyKey = try VerifyKey(key: keypair.publicKey)
        let _ = try verifyKey.toCurve25519PublicKey()
    }
}

@Suite("SigningKey operations")
struct SigningKeyTests {
    let sodium = Sodium()

    @Test("initializes with correct seed size")
    func testSigningKeyInit() async throws {
        let signingKey = try SigningKey(seed: Data(repeating: 0, count: sodium.cryptoSign.seedBytes))
        #expect(
            signingKey.bytes == Data(repeating: 0, count: sodium.cryptoSign.seedBytes),
            "SigningKey initialization failed"
        )
    }

    @Test("hash value is stable for the same instance")
    func testSigningKeyHash() async throws {
        let signingKey = try SigningKey(seed: Data(repeating: 0, count: sodium.cryptoSign.seedBytes))
        let h1 = signingKey.hashValue
        let h2 = signingKey.hashValue
        #expect(h1 == h2, "VerifyKey hash failed")
    }

    @Test("equality holds for identical seeds")
    func testSigningKeyEquality() async throws {
        let signingKey1 = try SigningKey(seed: Data(repeating: 0, count: sodium.cryptoSign.seedBytes))
        let signingKey2 = try SigningKey(seed: Data(repeating: 0, count: sodium.cryptoSign.seedBytes))
        #expect(signingKey1 == signingKey2, "SigningKey equality failed")
    }

    @Test("fails to initialize with invalid seed size")
    func testSigningKeyInvalidSize() async throws {
        let invalidSeed = Data(repeating: 0, count: sodium.cryptoSign.seedBytes - 1)
        #expect(throws: Error.self) {
            _ = try SigningKey(seed: invalidSeed)
        }
    }

    @Test("generates a seed of expected size")
    func testSigningKeyGenerate() async throws {
        let signingKey = try SigningKey.generate()
        #expect(signingKey.bytes.count == sodium.cryptoSign.seedBytes, "SigningKey generate failed")
    }

    @Test("signs a message and preserves payload")
    func testSigningKeySign() async throws {
        let signingKey = try SigningKey(seed: Data(repeating: 0, count: sodium.cryptoSign.seedBytes))
        let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
        let signedMessage = try signingKey.sign(message: message)
        #expect(signedMessage.getMessage == message, "SigningKey sign message mismatch")
    }

    @Test("converts to Curve25519 private key")
    func testSigningKeyToCurve25519PrivateKey() async throws {
        let signingKey = try SigningKey(seed: Data(repeating: 0, count: sodium.cryptoSign.seedBytes))
        _ = try signingKey.toCurve25519PrivateKey()
    }
}
