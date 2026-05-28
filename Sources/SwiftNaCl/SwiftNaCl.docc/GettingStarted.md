# Getting Started with SwiftNaCl

Learn how to integrate and use SwiftNaCl's cryptographic primitives in your Swift applications.

## Overview

SwiftNaCl is a modern Swift binding to the libsodium cryptographic library. This guide will walk you through installation, basic usage, and common patterns to help you get started quickly and securely.

## Installation

### Swift Package Manager

Add SwiftNaCl to your project using Swift Package Manager:

#### Using Xcode

1. Open your project in Xcode
2. Select `File` → `Swift Packages` → `Add Package Dependency`
3. Enter the repository URL: `https://github.com/Kingpin-Apps/swift-ncal.git`
4. Choose the version or branch you want to use
5. Import both `SwiftNaCl` and `Clibsodium` in your project

#### Using Package.swift

Add the following to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/Kingpin-Apps/swift-ncal.git", from: "0.1.4")
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: [
            .product(name: "SwiftNaCl", package: "swift-ncal")
        ]
    )
]
```

## Basic Usage

### Import the Library

```swift
import SwiftNaCl
```

### Your First Cryptographic Operation

Let's start with a simple example using digital signatures:

```swift
import SwiftNaCl

// Generate a signing key
let signingKey = try SigningKey.generate()
let verifyKey = signingKey.verifyKey

// Sign a message
let message = "Hello, SwiftNaCl!".data(using: .utf8)!
let signedMessage = try signingKey.sign(message: message)

// Verify the signature
let verifiedMessage = try verifyKey.verify(smessage: signedMessage.getCombined)
print(String(data: verifiedMessage, encoding: .utf8)!) // "Hello, SwiftNaCl!"
```

## Core Concepts

### Memory Safety

SwiftNaCl automatically handles secure memory cleanup for sensitive data. Private keys and other sensitive materials are automatically zeroed when they're no longer needed.

### Error Handling

SwiftNaCl uses Swift's error handling mechanism. Always wrap cryptographic operations in do-catch blocks:

```swift
do {
    let keyPair = KeyPair.generate()
    let encrypted = try keyPair.publicKey.encrypt(message: data)
    let decrypted = try keyPair.secretKey.decrypt(ciphertext: encrypted.combined)
} catch {
    print("Cryptographic operation failed: \(error)")
}
```

### Thread Safety

All SwiftNaCl types conform to `Sendable` and are designed to be thread-safe. You can safely use them across multiple threads and in concurrent environments.

## Common Use Cases

### 1. Digital Signatures

Perfect for ensuring message authenticity and integrity:

```swift
// Key generation
let signingKey = try SigningKey.generate()
let publicKey = signingKey.verifyKey

// Signing
let document = "Important document".data(using: .utf8)!
let signature = try signingKey.sign(message: document)

// Verification
let verifiedData = try publicKey.verify(smessage: signature.getCombined)
// verifiedData contains the original document if signature is valid
```

### 2. Secret-Key Encryption

For encrypting data with a shared secret:

```swift
// Generate a random key (keep this secret!)
let key = random(size: 32)
let secretBox = try SecretBox(key: key)

// Encrypt
let plaintext = "Secret message".data(using: .utf8)!
let encrypted = try secretBox.encrypt(plaintext: plaintext)

// Decrypt
let decrypted = try secretBox.decrypt(ciphertext: encrypted.combined)
print(String(data: decrypted, encoding: .utf8)!) // "Secret message"
```

### 3. Public-Key Encryption

For secure communication between parties:

```swift
// Alice generates her key pair
let aliceKeyPair = KeyPair.generate()

// Bob generates his key pair
let bobKeyPair = KeyPair.generate()

// Alice encrypts a message for Bob
let aliceBox = try Box(privateKey: aliceKeyPair.secretKey, publicKey: bobKeyPair.publicKey)
let message = "Hello Bob!".data(using: .utf8)!
let encrypted = try aliceBox.encrypt(plaintext: message)

// Bob decrypts the message from Alice
let bobBox = try Box(privateKey: bobKeyPair.secretKey, publicKey: aliceKeyPair.publicKey)
let decrypted = try bobBox.decrypt(ciphertext: encrypted.combined)
print(String(data: decrypted, encoding: .utf8)!) // "Hello Bob!"
```

### 4. Cryptographic Hashing

For data integrity and message authentication:

```swift
let hash = Hash()
let data = "Data to hash".data(using: .utf8)!

// SHA-256
let sha256 = try hash.sha256(message: data)
print("SHA-256: \(sha256.hexEncodedString())")

// BLAKE2b with custom parameters
let blake2b = try hash.blake2b(
    data: data,
    digestSize: 32,
    key: "secret-key".data(using: .utf8)!
)
print("BLAKE2b: \(blake2b.hexEncodedString())")
```

### 5. Verifiable Random Functions

For generating verifiable, deterministic randomness:

```swift
// Generate VRF key pair
let vrfKeyPair = VRFKeyPair.generate()

// Create proof for a message
let input = "randomness-seed".data(using: .utf8)!
let proof = try vrfKeyPair.signingKey.prove(message: input)

// Verify and get deterministic output
let output = try vrfKeyPair.verifyingKey.verify(message: input, proof: proof)
print("VRF Output: \(output.hexEncodedString())")

// The output is always the same for the same key and input!
```

## Best Practices

### 1. Key Management

- **Generate keys securely**: Always use the provided generation methods
- **Store keys safely**: Use secure storage mechanisms like Keychain on iOS/macOS
- **Never hardcode keys**: Load keys from secure storage or environment variables
- **Rotate keys regularly**: Implement key rotation for long-lived applications

```swift
// ✅ Good: Generate keys using SwiftNaCl methods
let keyPair = KeyPair.generate()

// ❌ Bad: Don't create keys from predictable data
// let weakKey = try PrivateKey(privateKey: Data(repeating: 1, count: 32))
```

### 2. Random Number Generation

SwiftNaCl uses cryptographically secure random number generation by default:

```swift
// Generate secure random bytes
let randomData = random(size: 32)

// Generate secure random keys
let signingKey = try SigningKey.generate()
let vrfSeed = VRFSeed.generate()
```

### 3. Error Handling

Always handle potential errors appropriately:

```swift
func secureEncrypt(data: Data, key: Data) -> Data? {
    do {
        let secretBox = try SecretBox(key: key)
        let encrypted = try secretBox.encrypt(plaintext: data)
        return encrypted.combined
    } catch {
        // Log error securely (don't log sensitive data!)
        print("Encryption failed: \(error.localizedDescription)")
        return nil
    }
}
```

### 4. Secure Cleanup

While SwiftNaCl handles most cleanup automatically, be mindful of sensitive data:

```swift
// SwiftNaCl types automatically clean up sensitive data
var signingKey = try SigningKey.generate()
// Key material is automatically zeroed when signingKey goes out of scope

// For your own sensitive data, zero it manually
var sensitiveData = Data("secret".utf8)
defer {
    sensitiveData.withUnsafeMutableBytes { bytes in
        bytes.bindMemory(to: UInt8.self).initialize(repeating: 0)
    }
}
```

## Platform Support

SwiftNaCl works across all Apple platforms and Linux:

- **iOS** 13.0+
- **macOS** 10.15+
- **tvOS** 13.0+
- **watchOS** 6.0+
- **visionOS** 1.0+
- **Linux** (Ubuntu 18.04+)

The library automatically uses optimized implementations for each platform.

## Next Steps

Now that you understand the basics, explore more advanced features:

- **<doc:VerifiableRandomFunctions>** for blockchain and cryptographic protocols
- **Password hashing** with Argon2 and Scrypt for secure authentication
- **Key derivation** for generating multiple keys from a single seed
- **Advanced encryption** with authenticated encryption and additional data (AEAD)

## Getting Help

- Check the full API documentation for detailed method descriptions
- Review the test suite for more usage examples
- Report issues on the GitHub repository
- Read the libsodium documentation for cryptographic background

## Security Notice

⚠️ **Important**: Cryptographic software requires careful handling. Always:

1. Keep private keys and sensitive data secure
2. Use the library's built-in random number generation
3. Validate all inputs and handle errors appropriately  
4. Stay updated with the latest version for security fixes
5. Consider having your implementation reviewed by security experts

Welcome to secure Swift programming with SwiftNaCl!