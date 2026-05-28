# Verifiable Random Functions (VRF)

Generate cryptographically secure, deterministic, and verifiable pseudorandom outputs.

## Overview

Verifiable Random Functions (VRF) allow you to generate pseudorandom outputs that can be verified by anyone with the corresponding public key. The output is deterministic for a given private key and input message, but appears random to anyone without the private key.

SwiftNaCl implements the IETF Draft 03 VRF specification using Ed25519 curves, providing both security and performance.

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
let seedData = "my-deterministic-seed-32-bytes!".data(using: .utf8)!
let seed = try VRFSeed(bytes: seedData)

// Generate keys from seed - always produces the same keys
let keyPair = try VRFKeyPair.from(seed: seed)

// You can extract the original seed from a signing key
let originalSeed = keyPair.signingKey.seed
assert(originalSeed == seed) // Always true
```

## Advanced Usage

### Working with Hexadecimal Representations

All VRF types support hexadecimal string representations:

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
- **Invalid input sizes**: Seeds must be 32 bytes, public keys 32 bytes, etc.
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

1. **Use cryptographically secure random seeds**: Use ``VRFSeed.generate()`` for random key generation
2. **Validate inputs**: Always handle ``VRFError`` cases appropriately
3. **Protect signing keys**: Store signing keys securely and never transmit them
4. **Use deterministic generation carefully**: Only use deterministic key generation when necessary

### Memory Safety

SwiftNaCl automatically handles secure memory cleanup, but you should still follow good security practices:

- Don't log sensitive data like signing keys or seeds
- Use secure storage mechanisms for long-term key storage
- Be cautious when serializing keys to disk or network

## Performance Characteristics

VRF operations have different performance characteristics:

- **Key Generation**: ~0.0001 seconds (very fast)
- **Proof Generation**: ~0.0007 seconds (fast)
- **Proof Verification**: ~0.0007 seconds (fast)

These operations are suitable for high-frequency use cases and real-time applications.

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

// Other nodes can verify the randomness
let isValidRandomness = try blockProducerKeyPair.verifyingKey.verify(
    message: blockHeightData,
    proof: randomnessProof
) == blockRandomness
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
let randomBytes = randomnessOutput.bytes
let lotteryNumber1 = Int(randomBytes[0]) % 50 + 1
let lotteryNumber2 = Int(randomBytes[1]) % 50 + 1
// ... etc

print("Lottery numbers: \(lotteryNumber1), \(lotteryNumber2)")
```

## See Also

- ``VRFSeed``
- ``VRFSigningKey`` 
- ``VRFVerifyingKey``
- ``VRFProof``
- ``VRFOutput``
- ``VRFKeyPair``
- ``VRFError``