import Foundation
import Testing

@testable import SwiftNaCl

@Suite("VRF (Verifiable Random Function)")
struct VRFTests {

    // MARK: - Test Constants

    @Test("exposes expected constant sizes")
    func testVRFConstants() async throws {
        #expect(VRF.seedBytes == 32, "VRF seed should be 32 bytes")
        #expect(VRF.secretKeyBytes == 64, "VRF secret key should be 64 bytes")
        #expect(VRF.publicKeyBytes == 32, "VRF public key should be 32 bytes")
        #expect(VRF.proofBytes == 80, "VRF proof should be 80 bytes")
        #expect(VRF.outputBytes == 64, "VRF output should be 64 bytes")
    }

    // MARK: - VRF Seed Tests

    @Test("generates distinct seeds of expected size")
    func testVRFSeedGeneration() async throws {
        let seed1 = VRFSeed.generate()
        let seed2 = VRFSeed.generate()

        #expect(seed1.bytes.count == VRF.seedBytes)
        #expect(seed2.bytes.count == VRF.seedBytes)
        #expect(seed1 != seed2, "Generated seeds should be different")
    }

    @Test("creates seed from bytes of correct size")
    func testVRFSeedFromBytes() async throws {
        let randomBytes = Data(repeating: 0x42, count: VRF.seedBytes)
        let seed = try VRFSeed(bytes: randomBytes)

        #expect(seed.bytes == randomBytes)
    }

    @Test("fails to create seed from bytes with invalid size")
    func testVRFSeedFromBytesInvalidSize() async throws {
        let invalidBytes = Data(repeating: 0x42, count: VRF.seedBytes - 1)

        do {
            _ = try VRFSeed(bytes: invalidBytes)
            Issue.record("Expected VRFSeed init to fail with invalid input size")
        } catch {
            #expect((error as? VRFError) == VRFError.invalidInputSize)
        }
    }

    @Test("creates seed from hex string and encodes back to the same hex")
    func testVRFSeedFromHexString() async throws {
        let hexString = String(repeating: "42", count: VRF.seedBytes)
        let seed = try VRFSeed(hexString: hexString)
        let expectedBytes = Data(repeating: 0x42, count: VRF.seedBytes)

        #expect(seed.bytes == expectedBytes)
        #expect(seed.hexEncodedString() == hexString)
    }

    @Test("fails to create seed from invalid hex string")
    func testVRFSeedFromInvalidHexString() async throws {
        let invalidHex = "invalidhex"

        do {
            _ = try VRFSeed(hexString: invalidHex)
            Issue.record("Expected VRFSeed init to fail with invalid hex")
        } catch {
            #expect((error as? VRFError) == VRFError.invalidInputSize)
        }
    }

    @Test("seed equality matches underlying bytes")
    func testVRFSeedEquality() async throws {
        let bytes = Data(repeating: 0x42, count: VRF.seedBytes)
        let seed1 = try VRFSeed(bytes: bytes)
        let seed2 = try VRFSeed(bytes: bytes)
        let differentSeed = VRFSeed.generate()

        #expect(seed1 == seed2)
        #expect(seed1 != differentSeed)
    }

    // MARK: - VRF Key Pair Tests

    @Test("generates key pair of expected sizes")
    func testVRFKeyPairGeneration() async throws {
        let keyPair = VRFKeyPair.generate()

        #expect(keyPair.signingKey.bytes.count == VRF.secretKeyBytes)
        #expect(keyPair.verifyingKey.bytes.count == VRF.publicKeyBytes)
    }

    @Test("derives deterministic key pair from seed")
    func testVRFKeyPairFromSeed() async throws {
        let seed = VRFSeed.generate()
        let keyPair = try VRFKeyPair.from(seed: seed)

        #expect(keyPair.signingKey.bytes.count == VRF.secretKeyBytes)
        #expect(keyPair.verifyingKey.bytes.count == VRF.publicKeyBytes)

        // Deterministic from the same seed
        let keyPair2 = try VRFKeyPair.from(seed: seed)
        #expect(keyPair.signingKey == keyPair2.signingKey)
        #expect(keyPair.verifyingKey == keyPair2.verifyingKey)
    }

    @Test("computes verifying key from signing key deterministically")
    func testVRFSigningKeyToVerifyingKey() async throws {
        let keyPair = VRFKeyPair.generate()
        let derivedVerifyingKey = keyPair.signingKey.verifyingKey

        #expect(keyPair.verifyingKey == derivedVerifyingKey)
    }

    @Test("derives seed from signing key deterministically")
    func testVRFSigningKeyToSeed() async throws {
        let seed = VRFSeed.generate()
        let keyPair = try VRFKeyPair.from(seed: seed)
        let derivedSeed = keyPair.signingKey.seed

        #expect(seed == derivedSeed)
    }

    // MARK: - VRF Signing Key Tests

    @Test("creates signing key from bytes of correct size")
    func testVRFSigningKeyFromBytes() async throws {
        let randomBytes = Data((0..<VRF.secretKeyBytes).map { _ in UInt8.random(in: 0...255) })
        let signingKey = try VRFSigningKey(bytes: randomBytes)

        #expect(signingKey.bytes == randomBytes)
    }

    @Test("fails to create signing key from bytes with invalid size")
    func testVRFSigningKeyFromBytesInvalidSize() async throws {
        let invalidBytes = Data(repeating: 0x42, count: VRF.secretKeyBytes - 1)

        do {
            _ = try VRFSigningKey(bytes: invalidBytes)
            Issue.record("Expected VRFSigningKey init to fail with invalid input size")
        } catch {
            #expect((error as? VRFError) == VRFError.invalidInputSize)
        }
    }

    @Test("produces a short fingerprint string")
    func testVRFSigningKeyFingerprint() async throws {
        let keyPair = VRFKeyPair.generate()
        let fingerprint = keyPair.signingKey.fingerprint()

        #expect(fingerprint.hasSuffix("..."))
        #expect(fingerprint.count == 19) // 16 hex chars + "..."
    }

    // MARK: - VRF Verifying Key Tests

    @Test("creates verifying key from bytes of correct size")
    func testVRFVerifyingKeyFromBytes() async throws {
        let keyPair = VRFKeyPair.generate()
        let verifyingKey = try VRFVerifyingKey(bytes: keyPair.verifyingKey.bytes)

        #expect(verifyingKey == keyPair.verifyingKey)
    }

    @Test("fails to create verifying key from bytes with invalid size")
    func testVRFVerifyingKeyFromBytesInvalidSize() async throws {
        let invalidBytes = Data(repeating: 0x42, count: VRF.publicKeyBytes - 1)

        do {
            _ = try VRFVerifyingKey(bytes: invalidBytes)
            Issue.record("Expected VRFVerifyingKey init to fail with invalid input size")
        } catch {
            #expect((error as? VRFError) == VRFError.invalidInputSize)
        }
    }

    @Test("creates verifying key from hex string")
    func testVRFVerifyingKeyFromHexString() async throws {
        let keyPair = VRFKeyPair.generate()
        let hexString = keyPair.verifyingKey.hexEncodedString()
        let verifyingKey = try VRFVerifyingKey(hexString: hexString)

        #expect(verifyingKey == keyPair.verifyingKey)
    }

    // MARK: - VRF Proof Tests

    @Test("generates proof of expected size")
    func testVRFProofGeneration() async throws {
        let keyPair = VRFKeyPair.generate()
        let message = "Hello, VRF!".data(using: .utf8)!

        let proof = try keyPair.signingKey.prove(message: message)

        #expect(proof.bytes.count == VRF.proofBytes)
    }

    @Test("creates proof from bytes and preserves equality")
    func testVRFProofFromBytes() async throws {
        let keyPair = VRFKeyPair.generate()
        let message = "Hello, VRF!".data(using: .utf8)!
        let originalProof = try keyPair.signingKey.prove(message: message)

        let proof = try VRFProof(bytes: originalProof.bytes)

        #expect(proof == originalProof)
    }

    @Test("fails to create proof from bytes with invalid size")
    func testVRFProofFromBytesInvalidSize() async throws {
        let invalidBytes = Data(repeating: 0x42, count: VRF.proofBytes - 1)

        do {
            _ = try VRFProof(bytes: invalidBytes)
            Issue.record("Expected VRFProof init to fail with invalid input size")
        } catch {
            #expect((error as? VRFError) == VRFError.invalidInputSize)
        }
    }

    @Test("creates proof from hex string and preserves equality")
    func testVRFProofFromHexString() async throws {
        let keyPair = VRFKeyPair.generate()
        let message = "Hello, VRF!".data(using: .utf8)!
        let originalProof = try keyPair.signingKey.prove(message: message)

        let hexString = originalProof.hexEncodedString()
        let proof = try VRFProof(hexString: hexString)

        #expect(proof == originalProof)
    }

    @Test("hashes proof to output of expected size")
    func testVRFProofHash() async throws {
        let keyPair = VRFKeyPair.generate()
        let message = "Hello, VRF!".data(using: .utf8)!
        let proof = try keyPair.signingKey.prove(message: message)

        let output = try proof.hash()

        #expect(output.bytes.count == VRF.outputBytes)
    }

    // MARK: - VRF Output Tests

    @Test("creates output from bytes and preserves equality")
    func testVRFOutputFromBytes() async throws {
        let keyPair = VRFKeyPair.generate()
        let message = "Hello, VRF!".data(using: .utf8)!
        let proof = try keyPair.signingKey.prove(message: message)
        let originalOutput = try keyPair.verifyingKey.verify(message: message, proof: proof)

        let output = try VRFOutput(bytes: originalOutput.bytes)

        #expect(output == originalOutput)
    }

    @Test("fails to create output from bytes with invalid size")
    func testVRFOutputFromBytesInvalidSize() async throws {
        let invalidBytes = Data(repeating: 0x42, count: VRF.outputBytes - 1)

        do {
            _ = try VRFOutput(bytes: invalidBytes)
            Issue.record("Expected VRFOutput init to fail with invalid input size")
        } catch {
            #expect((error as? VRFError) == VRFError.invalidInputSize)
        }
    }

    // MARK: - VRF Full Workflow Tests

    @Test("signs, verifies, and hashes deterministically for a message")
    func testVRFFullWorkflow() async throws {
        // Generate a key pair
        let keyPair = VRFKeyPair.generate()
        let message = "Hello, VRF World!".data(using: .utf8)!

        // Create a proof
        let proof = try keyPair.signingKey.prove(message: message)

        // Verify the proof and get output
        let output = try keyPair.verifyingKey.verify(message: message, proof: proof)

        // Extract output from proof directly
        let directOutput = try proof.hash()

        // Both methods should produce the same output
        #expect(output == directOutput)

        // The output should be deterministic
        let proof2 = try keyPair.signingKey.prove(message: message)
        let output2 = try keyPair.verifyingKey.verify(message: message, proof: proof2)

        #expect(output == output2)
        #expect(proof == proof2)
    }

    @Test("deterministic output for same seed and message")
    func testVRFDeterministicOutput() async throws {
        // Same seed should produce same keys
        let seed = VRFSeed.generate()
        let keyPair1 = try VRFKeyPair.from(seed: seed)
        let keyPair2 = try VRFKeyPair.from(seed: seed)

        #expect(keyPair1.signingKey == keyPair2.signingKey)
        #expect(keyPair1.verifyingKey == keyPair2.verifyingKey)

        // Same key and message should produce same proof and output
        let message = "Deterministic test".data(using: .utf8)!
        let proof1 = try keyPair1.signingKey.prove(message: message)
        let proof2 = try keyPair2.signingKey.prove(message: message)

        #expect(proof1 == proof2)

        let output1 = try keyPair1.verifyingKey.verify(message: message, proof: proof1)
        let output2 = try keyPair2.verifyingKey.verify(message: message, proof: proof2)

        #expect(output1 == output2)
    }

    @Test("different messages produce different outputs")
    func testVRFDifferentMessagesProduceDifferentOutputs() async throws {
        let keyPair = VRFKeyPair.generate()
        let message1 = "Message 1".data(using: .utf8)!
        let message2 = "Message 2".data(using: .utf8)!

        let proof1 = try keyPair.signingKey.prove(message: message1)
        let proof2 = try keyPair.signingKey.prove(message: message2)

        let output1 = try keyPair.verifyingKey.verify(message: message1, proof: proof1)
        let output2 = try keyPair.verifyingKey.verify(message: message2, proof: proof2)

        #expect(proof1 != proof2)
        #expect(output1 != output2)
    }

    @Test("different keys produce different outputs for same message")
    func testVRFDifferentKeysProduceDifferentOutputs() async throws {
        let keyPair1 = VRFKeyPair.generate()
        let keyPair2 = VRFKeyPair.generate()
        let message = "Same message".data(using: .utf8)!

        let proof1 = try keyPair1.signingKey.prove(message: message)
        let proof2 = try keyPair2.signingKey.prove(message: message)

        let output1 = try keyPair1.verifyingKey.verify(message: message, proof: proof1)
        let output2 = try keyPair2.verifyingKey.verify(message: message, proof: proof2)

        #expect(proof1 != proof2)
        #expect(output1 != output2)
    }

    // MARK: - VRF Error Tests

    @Test("verification fails with wrong key")
    func testVRFVerificationFailureWithWrongKey() async throws {
        let keyPair1 = VRFKeyPair.generate()
        let keyPair2 = VRFKeyPair.generate()
        let message = "Test message".data(using: .utf8)!

        let proof = try keyPair1.signingKey.prove(message: message)

        // Try to verify with wrong key
        do {
            _ = try keyPair2.verifyingKey.verify(message: message, proof: proof)
            Issue.record("Expected verification to fail with wrong key")
        } catch {
            #expect((error as? VRFError) == VRFError.verificationFailed)
        }
    }

    @Test("verification fails with wrong message")
    func testVRFVerificationFailureWithWrongMessage() async throws {
        let keyPair = VRFKeyPair.generate()
        let message1 = "Original message".data(using: .utf8)!
        let message2 = "Different message".data(using: .utf8)!

        let proof = try keyPair.signingKey.prove(message: message1)

        // Try to verify with wrong message
        do {
            _ = try keyPair.verifyingKey.verify(message: message2, proof: proof)
            Issue.record("Expected verification to fail with wrong message")
        } catch {
            #expect((error as? VRFError) == VRFError.verificationFailed)
        }
    }

    @Test("fails to create verifying key from invalid public key bytes")
    func testVRFInvalidPublicKey() async throws {
        let invalidBytes = Data(repeating: 0x00, count: VRF.publicKeyBytes)

        do {
            _ = try VRFVerifyingKey(bytes: invalidBytes)
            Issue.record("Expected VRFVerifyingKey init to fail with invalid public key")
        } catch {
            #expect((error as? VRFError) == VRFError.invalidPublicKey)
        }
    }

    // MARK: - Known Test Vectors

    @Test("produces consistent results for a known seed and message")
    func testVRFWithKnownVector() async throws {
        // Using a known seed for deterministic testing
        let seedHex = "0000000000000000000000000000000000000000000000000000000000000000"
        let seed = try VRFSeed(hexString: seedHex)
        let keyPair = try VRFKeyPair.from(seed: seed)

        let message = "test".data(using: .utf8)!
        let proof = try keyPair.signingKey.prove(message: message)
        let output = try keyPair.verifyingKey.verify(message: message, proof: proof)

        // Verify that we get consistent results
        #expect(proof.bytes.count == VRF.proofBytes)
        #expect(output.bytes.count == VRF.outputBytes)

        // Test that the same input produces the same output
        let proof2 = try keyPair.signingKey.prove(message: message)
        let output2 = try keyPair.verifyingKey.verify(message: message, proof: proof2)

        #expect(proof == proof2)
        #expect(output == output2)
    }

    // MARK: - Edge Cases

    @Test("handles empty message")
    func testVRFWithEmptyMessage() async throws {
        let keyPair = VRFKeyPair.generate()
        let emptyMessage = Data()

        let proof = try keyPair.signingKey.prove(message: emptyMessage)
        let output = try keyPair.verifyingKey.verify(message: emptyMessage, proof: proof)

        #expect(proof.bytes.count == VRF.proofBytes)
        #expect(output.bytes.count == VRF.outputBytes)
    }

    @Test("handles large message")
    func testVRFWithLargeMessage() async throws {
        let keyPair = VRFKeyPair.generate()
        let largeMessage = Data(repeating: 0x42, count: 10000)

        let proof = try keyPair.signingKey.prove(message: largeMessage)
        let output = try keyPair.verifyingKey.verify(message: largeMessage, proof: proof)

        #expect(proof.bytes.count == VRF.proofBytes)
        #expect(output.bytes.count == VRF.outputBytes)
    }

    // MARK: - Performance (converted to functional checks)

    @Test("sign/verify completes without error")
    func testVRFPerformance() async throws {
        let keyPair = VRFKeyPair.generate()
        let message = "Performance test message".data(using: .utf8)!

        let proof = try keyPair.signingKey.prove(message: message)
        _ = try keyPair.verifyingKey.verify(message: message, proof: proof)
    }

    @Test("generates key pair successfully")
    func testVRFKeyGenerationPerformance() async throws {
        _ = VRFKeyPair.generate()
    }
}
