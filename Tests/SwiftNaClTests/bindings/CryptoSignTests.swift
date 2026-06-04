import Foundation
import Testing

@testable import SwiftNaCl

@Suite("Crypto Sign Tests")
struct CryptoSignTests {
    let cryptoSign = Sodium().cryptoSign
    
    @Test("Keypair generation works correctly")
    func keypair() async throws {
        let keypair = try cryptoSign.keypair()
        #expect(keypair.publicKey.count == cryptoSign.publicKeyBytes, "Public key length mismatch")
        #expect(keypair.secretKey.count == cryptoSign.secretKeyBytes, "Secret key length mismatch")
    }
    
    @Test("Seed-based keypair generation works correctly")
    func seedKeypair() async throws {
        let seed = Data(repeating: 0x01, count: cryptoSign.seedBytes)
        let keypair = try cryptoSign.seedKeypair(seed: seed)
        #expect(keypair.publicKey.count == cryptoSign.publicKeyBytes, "Public key length mismatch")
        #expect(keypair.secretKey.count == cryptoSign.secretKeyBytes, "Secret key length mismatch")
    }
    
    @Test("Message signing and verification works correctly")
    func signAndOpen() async throws {
        let keypair = try cryptoSign.keypair()
        let message = "Hello, Sodium!".data(using: .utf8)!
        
        let signedMessage = try cryptoSign.sign(message: message, sk: keypair.secretKey)
        #expect(
            signedMessage.count == message.count + cryptoSign.bytes,
            "Signed message length should equal message length plus signature bytes"
        )
        
        let unsignedMessage = try cryptoSign.open(signed: signedMessage, pk: keypair.publicKey)
        
        #expect(
            unsignedMessage.count == message.count,
            "Unsigned message length should match original message length"
        )
        #expect(unsignedMessage == message, "Unsigned message should match original message")
    }
    
    @Test("Ed25519 public key conversion to Curve25519 works correctly")
    func ed25519PkToCurve25519() async throws {
        let keypair = try cryptoSign.keypair()
        let curve25519PublicKey = try cryptoSign.ed25519PkToCurve25519(publicKeyBytes: keypair.publicKey)
        #expect(curve25519PublicKey.count == cryptoSign.curve25519Bytes, "Curve25519 public key length mismatch")
    }
    
    @Test("Ed25519 secret key conversion to Curve25519 works correctly")
    func ed25519SkToCurve25519() async throws {
        let keypair = try cryptoSign.keypair()
        let curve25519SecretKey = try cryptoSign.ed25519SkToCurve25519(secretKeyBytes: keypair.secretKey)
        #expect(curve25519SecretKey.count == cryptoSign.curve25519Bytes, "Curve25519 secret key length mismatch")
    }
    
    @Test("Extracting public key from secret key works correctly")
    func ed25519SkToPk() async throws {
        let keypair = try cryptoSign.keypair()
        let extractedPublicKey = try cryptoSign.ed25519SkToPk(secretKeyBytes: keypair.secretKey)
        #expect(extractedPublicKey == keypair.publicKey, "Extracted public key does not match original")
    }
    
    @Test("Extracting seed from secret key works correctly")
    func ed25519SkToSeed() async throws {
        let seed = Data(repeating: 0x01, count: cryptoSign.seedBytes)
        let keypair = try cryptoSign.seedKeypair(seed: seed)
        let extractedSeed = try cryptoSign.ed25519SkToSeed(secretKeyBytes: keypair.secretKey)
        #expect(extractedSeed == seed, "Extracted seed does not match the original")
    }
    
    @Test("Prehashed signing and verification works correctly")
    func ed25519ph() async throws {
        let keypair = try cryptoSign.keypair()
        let message = "Prehashed test message".data(using: .utf8)!

        let edphSign = try CryptoSignEd25519phState()
        try cryptoSign.ed25519phUpdate(edph: edphSign, pmsg: message)
        let signature = try cryptoSign.ed25519phFinalCreate(edph: edphSign, sk: keypair.secretKey)
        #expect(signature.count == cryptoSign.bytes, "Signature length mismatch")

        let edphVerify = try CryptoSignEd25519phState()
        try cryptoSign.ed25519phUpdate(edph: edphVerify, pmsg: message)
        let isValid = try cryptoSign.ed25519phFinalVerify(edph: edphVerify, signature: signature, pk: keypair.publicKey)
        #expect(isValid, "Signature verification failed")
    }
}
