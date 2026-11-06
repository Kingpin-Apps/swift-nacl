# Verifiable Random Functions (VRF)

Generate cryptographically secure, deterministic, and verifiable pseudorandom outputs.

## Overview

Verifiable Random Functions (VRF) allow you to generate pseudorandom outputs that can be verified by anyone with the corresponding public key. The output is deterministic for a given private key and input message, but appears random to anyone without the private key.

SwiftNaCl implements the IETF draft 03 VRF specification (draft-irtf-cfrg-vrf-03) using Ed25519, through the `crypto_vrf_ietfdraft03_*` functions in the Cardano fork of libsodium that ships with this package. This is the VRF used by the Cardano protocol.

### Key Properties

- **Deterministic**: The same private key and input always produce the same output
- **Pseudorandom**: Outputs appear random to anyone without the private key
- **Verifiable**: Anyone can verify that an output was generated correctly using the public key
- **Unforgeable**: Only the holder of the private key can generate valid proofs

## Getting Started

### Basic VRF Operations

Here's a simple example showing the core VRF workflow:

```swift
import SwiftNaCl

// Generate a VRF key pair
let keyPair = VRFKeyPair.generate()

// Create a proof for a message
let message = "Hello, VRF!".data(using: .utf8)!
let proof = try keyPair.signingKey.prove(message: message)

// Verify the proof and get the deterministic output
let output = try keyPair.verifyingKey.verify(message: message, proof: proof)
print("VRF Output: \(output.hexEncodedString())")
```

### Deterministic Key Generation

You can generate VRF keys deterministically from a seed:

```swift
// Create a seed (must be exactly 32 bytes)
// For real keys, use VRFSeed.generate() or another secure random source
let seedData = "my-deterministic-seed-32-bytes!!".data(using: .utf8)!
let seed = try VRFSeed(bytes: seedData)

// Generate keys from seed - always produces the same keys
let keyPair = try VRFKeyPair.from(seed: seed)

// You can extract the original seed from a signing key
let originalSeed = keyPair.signingKey.seed
assert(originalSeed == seed) // Always true
```

## Advanced Usage

### Working with Hexadecimal Representations

The VRF seed, verifying key, proof and output types support hexadecimal string representations. ``VRFSigningKey`` does not; store its ``VRFSigningKey/seed`` instead:

```swift
let keyPair = VRFKeyPair.generate()
let message = "test".data(using: .utf8)!
let proof = try keyPair.signingKey.prove(message: message)

// Convert to hex strings for storage or transmission
let seedHex = keyPair.signingKey.seed.hexEncodedString()
let verifyingKeyHex = keyPair.verifyingKey.hexEncodedString()
let proofHex = proof.hexEncodedString()

// Recreate from hex strings
let recreatedSeed = try VRFSeed(hexString: seedHex)
let recreatedKey = try VRFVerifyingKey(hexString: verifyingKeyHex)
let recreatedProof = try VRFProof(hexString: proofHex)
```

### Extracting Output from Proof

You can extract the VRF output directly from a proof without verification:

```swift
let keyPair = VRFKeyPair.generate()
let message = "data".data(using: .utf8)!
let proof = try keyPair.signingKey.prove(message: message)

// Extract output directly from proof (unverified)
let directOutput = try proof.hash()

// Verify and extract output (verified)
let verifiedOutput = try keyPair.verifyingKey.verify(message: message, proof: proof)

// Both outputs are identical
assert(directOutput == verifiedOutput)
```

## Error Handling

VRF operations can fail in several ways. The ``VRFError`` enum provides detailed error information:

```swift
do {
    // This will throw VRFError.invalidInputSize
    let invalidSeed = try VRFSeed(bytes: Data(repeating: 0, count: 16))
} catch VRFError.invalidInputSize {
    print("Seed must be exactly 32 bytes")
} catch {
    print("Other VRF error: \(error)")
}
```

Common error scenarios:
- **Invalid input sizes**: Seeds and verifying keys must be 32 bytes, signing keys 64 bytes, proofs 80 bytes and outputs 64 bytes
- **Invalid public keys**: Not all 32-byte values are valid Ed25519 public keys
- **Verification failures**: Wrong key, tampered proof, or incorrect message
- **Invalid proofs**: Malformed or corrupted proof data

## Security Considerations

### Private Key Security

⚠️ **Warning**: VRF signing keys must be kept secret and secure. Anyone who knows your signing key can:
- Generate VRF proofs for any message
- Impersonate you in VRF-based protocols
- Predict future VRF outputs

### Best Practices

1. **Use cryptographically secure random seeds**: Use ``VRFSeed/generate()`` or ``VRFKeyPair/generate()`` for random key generation
2. **Validate inputs**: Always handle ``VRFError`` cases appropriately
3. **Protect signing keys**: Store signing keys securely and never transmit them
4. **Use deterministic generation carefully**: Only use deterministic key generation when necessary

### Memory Safety

VRF keys and seeds are stored in ordinary `Data` values and are not zeroed automatically when they are released, so follow good security practices:

- Don't log sensitive data like signing keys or seeds. ``VRFSigningKey/fingerprint()`` still includes 8 bytes of the secret key, so log the verifying key instead
- Use secure storage mechanisms for long-term key storage
- Be cautious when serializing keys to disk or network

## Performance Characteristics

Key generation is very fast. Proof generation and verification each take well under a millisecond on modern hardware, so VRF operations are suitable for high-frequency use cases. Measure on your target devices if timing matters.

## Integration Examples

### Blockchain Random Beacons

VRFs are commonly used in blockchain systems for generating random beacons:

```swift
// Block producer generates VRF proof using their private key
let blockProducerKeyPair = VRFKeyPair.generate()
let blockHeight = 12345
let blockHeightData = withUnsafeBytes(of: blockHeight.bigEndian) { Data($0) }

let randomnessProof = try blockProducerKeyPair.signingKey.prove(message: blockHeightData)
let blockRandomness = try blockProducerKeyPair.verifyingKey.verify(
    message: blockHeightData, 
    proof: randomnessProof
)

// Other nodes receive the proof and the producer's public verifying key,
// then check the proof and derive the same randomness themselves
let producerVerifyingKey = blockProducerKeyPair.verifyingKey
let checkedRandomness = try producerVerifyingKey.verify(
    message: blockHeightData,
    proof: randomnessProof
) // Throws VRFError.verificationFailed if the proof is invalid
assert(checkedRandomness == blockRandomness)
```

### Cryptographic Lotteries

VRFs can provide fair, verifiable randomness for lotteries:

```swift
let lotteryOperatorKeyPair = VRFKeyPair.generate()
let drawDate = "2024-12-25".data(using: .utf8)!

// Generate lottery numbers
let proof = try lotteryOperatorKeyPair.signingKey.prove(message: drawDate)
let randomnessOutput = try lotteryOperatorKeyPair.verifyingKey.verify(
    message: drawDate, 
    proof: proof
)

// Convert randomness to lottery numbers
// (simple modulo for illustration; it is slightly biased)
let randomBytes = randomnessOutput.bytes
let lotteryNumber1 = Int(randomBytes[0]) % 50 + 1
let lotteryNumber2 = Int(randomBytes[1]) % 50 + 1
// ... etc

print("Lottery numbers: \(lotteryNumber1), \(lotteryNumber2)")
```

## See Also

- ``VRF``
- ``VRFSeed``
- ``VRFSigningKey``
- ``VRFVerifyingKey``
- ``VRFProof``
- ``VRFOutput``
- ``VRFKeyPair``
- ``VRFError``