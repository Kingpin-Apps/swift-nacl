# Security Guide

Best practices and security considerations for using SwiftNaCl safely and securely.

## Overview

SwiftNaCl provides powerful cryptographic primitives, but they must be used correctly to maintain security. This guide covers essential security practices, common pitfalls, and recommended patterns for secure applications.

Some examples below call helper functions or error types that belong to your application (for example `getStoredHash(for:)` or `ValidationError`). Those are placeholders; every SwiftNaCl call shown is part of the library's API.

## General Security Principles

### Defense in Depth

Never rely on a single security measure. Layer multiple security controls:

```swift
// ✅ Good: Multiple layers of security
func secureProcess(data: Data, password: Data) throws -> Data {
    // 1. Validate input
    guard !data.isEmpty else { throw ValidationError.emptyData }

    // 2. Derive a 32-byte key from the password using a strong KDF
    //    (kdf uses the sensitive ops and memory limits by default)
    let argon2id = Argon2id()
    let salt = random(size: argon2id.saltBytes) // 16 bytes
    let key = try argon2id.kdf(size: 32, password: password, salt: salt)

    // 3. Encrypt with authenticated encryption
    let aead = Sodium().cryptoAead
    let nonce = random(size: Int(aead.xchacha20poly1305IetfNpubBytes))
    let ciphertext = try aead.xchacha20poly1305IetfEncrypt(
        message: data, aad: nil, nonce: nonce, key: key
    )

    // 4. Return salt + nonce + ciphertext for later decryption
    return salt + nonce + ciphertext
}
```

### Fail Securely

When operations fail, ensure the failure doesn't leak sensitive information:

```swift
// ✅ Good: Secure error handling
let pwHash = PwHash()

// A real hash, computed once, so unknown users take as long as known ones
let dummyHash = try Argon2id().str(password: Data("dummy-password".utf8))

func authenticate(username: String, password: Data) -> Bool {
    guard let storedHash = getStoredHash(for: username) else {
        // Still perform password hashing to prevent timing attacks
        _ = try? pwHash.verify(passwordHash: dummyHash, password: password)
        return false
    }

    do {
        return try pwHash.verify(passwordHash: storedHash, password: password)
    } catch {
        return false
    }
}
```

## Key Management

### Key Generation

Always use SwiftNaCl's secure key generation methods:

```swift
// ✅ Good: Cryptographically secure key generation
let signingKey = try SigningKey.generate()
let keyPair = KeyPair.generate()
let vrfSeed = VRFSeed.generate()

// ❌ Bad: Predictable key generation
let weakKey = Data(repeating: 0x42, count: 32)
```

### Key Storage

#### iOS/macOS Keychain

Store sensitive keys in the system keychain:

```swift
import Security

func storeKeyInKeychain(key: Data, identifier: String) -> Bool {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: identifier,
        kSecValueData as String: key,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]

    let status = SecItemAdd(query as CFDictionary, nil)
    return status == errSecSuccess
}
```

#### Environment Variables

For server applications, use environment variables:

```swift
func loadKeyFromEnvironment(name: String) throws -> Data {
    // Expects the key as a Base64 string
    guard let encoded = ProcessInfo.processInfo.environment[name],
          let keyData = Data(base64Encoded: encoded) else {
        throw KeyError.notFound
    }
    return keyData
}
```


## Random Number Generation

``random(size:)`` and the `generate()` methods use the system's cryptographically secure random number generator. Always use them for keys, nonces and salts:

```swift
// ✅ Good: Use a secure random number generator
let nonce = random(size: 24)
let salt = random(size: 16)
let seed = VRFSeed.generate()

// ❌ Bad: Don't use predictable sources
// let weakNonce = Data(Date().timeIntervalSince1970.description.utf8)
```

## Memory Security

### No Automatic Zeroing

SwiftNaCl stores keys, seeds and other secrets in ordinary `Data` values. It does not currently zero this memory when a key object is released, and accessors such as ``SigningKey/bytes`` return copies:

```swift
func processSecret() throws {
    let signingKey = try SigningKey.generate()

    // This is a copy of the 32-byte seed; it is not zeroed for you
    let keyData = signingKey.bytes
}
```

Keep secrets in memory only as long as you need them, and avoid making unnecessary copies.

### Manual Cleanup

For additional security, manually zero sensitive data you own:

```swift
func secureProcess() {
    var password = "secret".data(using: .utf8)!
    defer {
        // Zero out password data
        password.resetBytes(in: 0..<password.count)
    }

    // Use password...
}
```

Swift may copy `Data` values, so manual zeroing reduces exposure but cannot guarantee that no other copy remains.

### Avoid String Interpolation

Don't accidentally leak sensitive data in logs:

```swift
// ❌ Bad: Sensitive data might be logged
print("Processing with key: \(signingKey.bytes)")

// ✅ Good: Identify keys by their public half, never the secret half
print("Processing with key: \(bytesAsString(bytesIn: signingKey.verifyKey.bytes))")
```

## Encryption Best Practices

### Always Use Authenticated Encryption

Use constructions that provide both confidentiality and integrity. Both ``CryptoAead`` and ``CryptoBox`` authenticate the ciphertext, so decryption fails if it has been changed:

```swift
let aead = Sodium().cryptoAead

// ✅ Good: Authenticated encryption
let nonce = random(size: Int(aead.xchacha20poly1305IetfNpubBytes))
let encrypted = try aead.xchacha20poly1305IetfEncrypt(
    message: data, aad: nil, nonce: nonce, key: key
)

// ✅ Also good: AEAD with additional data, which is authenticated but not encrypted
let metadata = "file_v1".data(using: .utf8)!
let nonce2 = random(size: Int(aead.xchacha20poly1305IetfNpubBytes))
let encryptedWithMetadata = try aead.xchacha20poly1305IetfEncrypt(
    message: data, aad: metadata, nonce: nonce2, key: key
)
// Decryption must pass the same metadata as `aad`
```

### Unique Nonces

Never reuse nonces with the same key:

```swift
final class SecureStorage {
    private let key: Data
    private let aead = Sodium().cryptoAead

    init(key: Data) {
        self.key = key
    }

    func encrypt(data: Data) throws -> Data {
        // XChaCha20-Poly1305 has 24-byte nonces, which are large enough
        // to be chosen at random for every message
        let nonce = random(size: Int(aead.xchacha20poly1305IetfNpubBytes))

        let ciphertext = try aead.xchacha20poly1305IetfEncrypt(
            message: data, aad: nil, nonce: nonce, key: key
        )
        return nonce + ciphertext
    }
}
```

With the 12-byte nonces of `chacha20poly1305IetfEncrypt(message:aad:nonce:key:)`, random nonces are not safe for large numbers of messages; use a counter instead, or prefer XChaCha20-Poly1305.

## Digital Signatures

### Verify Before Using

Always verify signatures before trusting signed data. ``VerifyKey/verify(smessage:signature:encoder:)`` throws if the signature is not valid and returns the message only when it is:

```swift
func processSignedDocument(signedData: Data, verifyKey: VerifyKey) throws -> Data {
    // Verify signature first
    let verifiedData = try verifyKey.verify(smessage: signedData)

    // Only then process the verified data
    return verifiedData
}
```

### Use Detached Signatures When Appropriate

For large documents, use detached signatures:

```swift
func createDetachedSignature(document: Data, signingKey: SigningKey) throws -> Data {
    let signedMessage = try signingKey.sign(message: document)
    return signedMessage.getSignature // Return only the 64-byte signature
}

func verifyDetachedSignature(document: Data, signature: Data, verifyKey: VerifyKey) -> Bool {
    do {
        _ = try verifyKey.verify(smessage: document, signature: signature)
        return true
    } catch {
        return false
    }
}
```

## Password Handling

### Use Strong Password Hashing

Always use proper password hashing for authentication. ``Argon2id/str(password:opsLimit:memLimit:)`` uses the interactive limits by default and returns the encoded hash as `Data` (a fixed-size buffer padded with zero bytes), which you store as-is:

```swift
// ✅ Good: Use Argon2id for password hashing
let argon2id = Argon2id()

func hashPassword(_ password: Data) throws -> Data {
    return try argon2id.str(
        password: password,
        opsLimit: argon2id.opsLimitInteractive,
        memLimit: argon2id.memLimitInteractive
    )
}

func verifyPassword(_ password: Data, hash: Data) -> Bool {
    return (try? argon2id.verify(passwordHash: hash, password: password)) ?? false
}
```

``PwHash/verify(passwordHash:password:)`` can verify Argon2i, Argon2id and scrypt hashes, choosing the algorithm from the hash prefix.

### Secure Password Derivation

Use a proper KDF for deriving encryption keys from passwords. The salt must be ``Argon2id/saltBytes`` (16) bytes long, random, and stored alongside the encrypted data:

```swift
func deriveKeyFromPassword(_ password: Data, salt: Data) throws -> Data {
    let argon2id = Argon2id()
    return try argon2id.kdf(
        size: 32,
        password: password,
        salt: salt,
        opsLimit: argon2id.opsLimitSensitive,
        memLimit: argon2id.memLimitSensitive
    )
}
```

The sensitive limits are also the default when you omit `opsLimit` and `memLimit`. They use 1 GiB of memory, so they can be slow or fail on memory-constrained devices. Use the moderate or interactive limits where that matters.

## VRF Security

### Protect VRF Signing Keys

VRF signing keys must be kept strictly confidential:

```swift
// ✅ Good: Generate keys securely and protect them
let vrfKeyPair = VRFKeyPair.generate()
try storeKeySecurely(vrfKeyPair.signingKey.seed.bytes)

// Only share the verifying key publicly
let publicKey = vrfKeyPair.verifyingKey
```

The signing key can be rebuilt from its 32-byte seed with ``VRFKeyPair/from(seed:)``, so the seed is as sensitive as the key itself.

### Verify Proofs You Receive

``VRFProof/hash()`` extracts the output from a proof without checking it. When a proof comes from someone else, always use ``VRFVerifyingKey/verify(message:proof:)`` with their verifying key:

```swift
func acceptVRFOutput(input: Data, proof: VRFProof, from verifyingKey: VRFVerifyingKey) throws -> VRFOutput {
    // Throws VRFError.verificationFailed if the proof does not match the key and input
    return try verifyingKey.verify(message: input, proof: proof)
}
```

VRF messages can be any length. Validate the input format your protocol expects before you prove or verify it.


## Network Security

### Protect Data in Transit

Always use TLS for network communication, but add application-layer encryption for sensitive data:

```swift
struct SecureMessage {
    let nonce: Data
    let encryptedPayload: Data
    let signature: Data
    let senderVerifyKey: Data

    static func create(
        message: Data,
        recipientKey: PublicKey,
        senderEncryptionKey: PrivateKey,
        senderSigningKey: SigningKey
    ) throws -> SecureMessage {
        let box = Sodium().cryptoBox

        // Encrypt for recipient
        let nonce = random(size: Int(box.nonceBytes))
        let encrypted = try box.easy(
            message: message,
            nonce: nonce,
            publicKey: recipientKey.toBytes(),
            secretKey: senderEncryptionKey.toBytes()
        )

        // Sign the nonce and encrypted message
        let signedMessage = try senderSigningKey.sign(message: nonce + encrypted)

        return SecureMessage(
            nonce: nonce,
            encryptedPayload: encrypted,
            signature: signedMessage.getSignature,
            senderVerifyKey: senderSigningKey.verifyKey.bytes
        )
    }
}
```


## Common Vulnerabilities to Avoid

### 1. Key Reuse
```swift
// ❌ Bad: Reusing keys across different contexts
let masterKey = random(size: 32)
let encryptionKey = masterKey  // Don't reuse directly
let macKey = masterKey         // Definitely don't do this

// ✅ Good: Derive different keys for different purposes
// (keyed BLAKE2b, using the master key as the key and the purpose as the input)
let hash = Hash()
let rootKey = random(size: 32)
let derivedEncryptionKey = try hash.blake2b(
    data: Data("encryption".utf8), digestSize: 32, key: rootKey, encoder: RawEncoder.self
)
let derivedMacKey = try hash.blake2b(
    data: Data("authentication".utf8), digestSize: 32, key: rootKey, encoder: RawEncoder.self
)
```

### 2. Information Leakage
```swift
// ❌ Bad: Error messages leak information
func decryptFile(path: String, key: Data) throws -> Data {
    guard fileExists(path) else { throw FileError.notFound }
    guard key.count == 32 else { throw CryptoError.invalidKeyLength }
    // ... decrypt ...
}

// ✅ Good: Consistent error handling
func decryptFile(path: String, key: Data) throws -> Data {
    do {
        return try performDecryption(path: path, key: key)
    } catch {
        throw CryptoError.decryptionFailed // Generic error
    }
}
```

### 3. Side-Channel Attacks

Comparing secrets with `==` can stop at the first differing byte, which leaks timing information. Use the constant-time comparison from ``CryptoUtils`` instead:

```swift
// ❌ Bad: Early-exit comparison of secret values
func tagsMatch(_ expected: Data, _ received: Data) -> Bool {
    return expected == received  // Timing leak
}

// ✅ Good: Constant-time comparison
func tagsMatch(_ expected: Data, _ received: Data) -> Bool {
    return Sodium().utils.sodiumMemcmp(expected, received)
}
```

Also avoid branching on secret data in your own code.

## Security Checklist

Before deploying applications using SwiftNaCl:

- [ ] All keys are generated using SwiftNaCl's secure methods
- [ ] Private keys are stored securely (keychain, environment variables, etc.)
- [ ] Error handling doesn't leak sensitive information
- [ ] All cryptographic operations are wrapped in proper error handling
- [ ] Input validation is performed before cryptographic operations
- [ ] Nonces are never reused with the same key
- [ ] Passwords use proper key derivation functions
- [ ] Memory containing sensitive data is properly cleaned up
- [ ] Timing attacks are considered and mitigated where possible
- [ ] Security-critical code has comprehensive tests
- [ ] The application has been reviewed by security experts

## Getting Security Help

- Review the [libsodium documentation](https://doc.libsodium.org/) for cryptographic details
- Consider professional security audits for high-stakes applications
- Stay updated with security advisories and update SwiftNaCl regularly
- Follow secure coding practices specific to your platform (iOS, macOS, Linux)

Remember: **Security is a process, not a product.** Regular review and updates are essential for maintaining security over time.
