# Getting Started with SwiftNaCl

Learn how to integrate and use SwiftNaCl's cryptographic primitives in your Swift applications.

## Overview

SwiftNaCl is a modern Swift binding to the libsodium cryptographic library. This guide will walk you through installation, basic usage, and common patterns to help you get started quickly and securely.

## Installation

### Swift Package Manager

Add SwiftNaCl to your project using Swift Package Manager. The package needs Swift 6.0 or later.

#### Using Xcode

1. Open your project in Xcode
2. Select `File` → `Add Package Dependencies…`
3. Enter the repository URL: `https://github.com/Kingpin-Apps/swift-nacl.git`
4. Choose the version or branch you want to use
5. Add the `SwiftNaCl` library to your target

#### Using Package.swift

Add the following to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/Kingpin-Apps/swift-nacl.git", from: "1.0.0")
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: [
            .product(name: "SwiftNaCl", package: "swift-nacl")
        ]
    )
]
```

The package also vends a `Clibsodium` library with the raw C functions. You only need it if you want to call libsodium directly.

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

### High-level Types and Low-level Bindings

SwiftNaCl has two layers. High-level types such as ``SigningKey``, ``Box``, ``SealedBox``, ``SecretBox``, ``Aead``, ``Hash`` and ``VRFKeyPair`` wrap keys and common operations, and generate nonces for you. The low-level bindings are reached through ``Sodium`` (for example `Sodium().cryptoAead` or `Sodium().cryptoBox`) and work directly with raw `Data`, close to the libsodium C API.

### Error Handling

SwiftNaCl uses Swift's error handling mechanism. Operations that can fail throw a ``SodiumError`` (or a ``VRFError`` for VRF operations), so wrap them in do-catch blocks:

```swift
do {
    let keyPair = KeyPair.generate()
    let data = "Top secret".data(using: .utf8)!

    // Anyone with the public key can encrypt...
    let encrypted = try SealedBox(recipientKey: keyPair.publicKey).encrypt(plaintext: data)

    // ...but only the private key holder can decrypt
    let decrypted = try SealedBox(recipientKey: keyPair.secretKey).decrypt(ciphertext: encrypted)
} catch {
    print("Cryptographic operation failed: \(error)")
}
```

### Thread Safety

The VRF types (``VRFSeed``, ``VRFSigningKey``, ``VRFVerifyingKey``, ``VRFProof``, ``VRFOutput`` and ``VRFKeyPair``) are immutable value types that conform to `Sendable`. The other types, such as ``SigningKey``, ``PrivateKey`` and ``Box``, are classes that do not conform to `Sendable`. Create them where you use them, or protect shared instances yourself, for example with an actor.

## Common Use Cases

### 1. Digital Signatures

Perfect for ensuring message authenticity and integrity:

```swift
// Key generation
let signingKey = try SigningKey.generate()
let verifyKey = signingKey.verifyKey

// Signing
let document = "Important document".data(using: .utf8)!
let signedMessage = try signingKey.sign(message: document)

// Verification (throws if the signature is not valid)
let verifiedData = try verifyKey.verify(smessage: signedMessage.getCombined)
// verifiedData contains the original document
```

### 2. Secret-Key Encryption

For encrypting data with a shared secret, use ``SecretBox`` (XSalsa20-Poly1305) or ``Aead`` (XChaCha20-Poly1305, which can also authenticate unencrypted data). Both generate a random nonce for every message and return an ``EncryptedMessage``:

```swift
// Generate a random 32-byte key (keep this secret!)
let key = random(size: 32)
let plaintext = "Secret message".data(using: .utf8)!

let box = try SecretBox(key: key)
let encrypted = try box.encrypt(plaintext: plaintext)

// `combined` is the nonce followed by the ciphertext, so it is all you need to store or send
let decrypted = try box.decrypt(ciphertext: encrypted.combined)
print(String(data: decrypted, encoding: .utf8)!) // "Secret message"

// Aead also authenticates data that travels with the message without encrypting it
let aead = try Aead(key: key)
let header = "v1".data(using: .utf8)!
let sealed = try aead.encrypt(plaintext: plaintext, aad: header)
let opened = try aead.decrypt(ciphertext: sealed.combined, aad: header)
```

The low-level ``CryptoSecretBox`` and ``CryptoAead`` bindings take an explicit nonce instead.

### 3. Public-Key Encryption

For secure communication between two parties, use ``Box``:

```swift
// Alice and Bob each generate a key pair
let aliceKeyPair = KeyPair.generate()
let bobKeyPair = KeyPair.generate()

// Alice encrypts a message for Bob (a random nonce is generated for her)
let message = "Hello Bob!".data(using: .utf8)!
let aliceBox = try Box(privateKey: aliceKeyPair.secretKey, publicKey: bobKeyPair.publicKey)
let encrypted = try aliceBox.encrypt(plaintext: message)

// Bob decrypts the message from Alice
let bobBox = try Box(privateKey: bobKeyPair.secretKey, publicKey: aliceKeyPair.publicKey)
let decrypted = try bobBox.decrypt(ciphertext: encrypted.combined)
print(String(data: decrypted, encoding: .utf8)!) // "Hello Bob!"
```

If the recipient does not need to know who sent the message, ``SealedBox`` is simpler: it only needs the recipient's public key, as shown in the error handling example above.

### 4. Cryptographic Hashing

For data integrity and message authentication. ``Hash`` returns hex-encoded `Data` by default; pass `encoder: RawEncoder.self` to get the raw digest bytes instead:

```swift
let hash = Hash()
let data = "Data to hash".data(using: .utf8)!

// SHA-256 (hex-encoded by default)
let sha256 = try hash.sha256(message: data)
print("SHA-256: \(String(decoding: sha256, as: UTF8.self))")

// BLAKE2b with custom parameters
let blake2b = try hash.blake2b(
    data: data,
    digestSize: 32,
    key: "secret-key".data(using: .utf8)!
)
print("BLAKE2b: \(String(decoding: blake2b, as: UTF8.self))")

// Raw 32-byte digest
let rawDigest = try hash.sha256(message: data, encoder: RawEncoder.self)
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

``random(size:)`` and the `generate()` methods use libsodium's `randombytes_buf`, which reads the operating system's cryptographically secure random number generator:

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
        // The combined bytes keep the nonce with the ciphertext
        return try Aead(key: key).encrypt(plaintext: data).combined
    } catch {
        // Log error securely (don't log sensitive data!)
        print("Encryption failed: \(error.localizedDescription)")
        return nil
    }
}
```

### 4. Secure Cleanup

SwiftNaCl keeps key material in ordinary `Data` values and does not currently zero it when a key is released. Keep secrets in memory only as long as you need them, and clear buffers you own when you are done:

```swift
var sensitiveData = Data("secret".utf8)
defer {
    // Overwrite the bytes with zeros
    sensitiveData.resetBytes(in: 0..<sensitiveData.count)
}
```

Swift may copy `Data` values, so this reduces exposure but cannot guarantee that no other copy remains in memory.

## Platform Support

SwiftNaCl works on:

- **iOS**, **macOS**, **Mac Catalyst**, **tvOS**, **watchOS** and **visionOS**, using the bundled `Clibsodium.xcframework`
- **Linux** and **Android** (x86_64 and aarch64), compiling libsodium from vendored source

WebAssembly (WASI) is not currently supported.

## Next Steps

Now that you understand the basics, explore more advanced features:

- **<doc:VerifiableRandomFunctions>** for blockchain and cryptographic protocols
- **<doc:SecurityGuide>** for security practices and common pitfalls
- **Password hashing** with ``Argon2id``, ``Argon2i`` and ``Scrypt``
- **Key derivation** with the `kdf(size:password:salt:opsLimit:memLimit:encoder:)` methods on the password hashing types
- **Advanced encryption** with additional authenticated data through ``Aead`` or ``CryptoAead``, key exchange through ``CryptoKx``, and streaming encryption through ``CryptoSecretStream``

## Getting Help

- Check the full API documentation for detailed method descriptions
- Review the test suite for more usage examples
- Report issues on the [GitHub repository](https://github.com/Kingpin-Apps/swift-nacl)
- Read the [libsodium documentation](https://doc.libsodium.org/) for cryptographic background

## Security Notice

⚠️ **Important**: Cryptographic software requires careful handling. Always:

1. Keep private keys and sensitive data secure
2. Use the library's built-in random number generation
3. Validate all inputs and handle errors appropriately
4. Stay updated with the latest version for security fixes
5. Consider having your implementation reviewed by security experts

Welcome to secure Swift programming with SwiftNaCl!
