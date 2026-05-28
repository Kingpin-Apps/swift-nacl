# Security Guide

Best practices and security considerations for using SwiftNaCl safely and securely.

## Overview

SwiftNaCl provides powerful cryptographic primitives, but they must be used correctly to maintain security. This guide covers essential security practices, common pitfalls, and recommended patterns for secure applications.

## General Security Principles

### Defense in Depth

Never rely on a single security measure. Layer multiple security controls:

```swift
// ✅ Good: Multiple layers of security
func secureProcess(data: Data, password: String) throws -> Data {
    // 1. Validate input
    guard !data.isEmpty else { throw ValidationError.emptyData }
    
    // 2. Derive key from password using strong KDF
    let salt = random(size: 32)
    let key = try derivedKey(from: password, salt: salt)
    
    // 3. Encrypt with authenticated encryption
    let secretBox = try SecretBox(key: key)
    let encrypted = try secretBox.encrypt(plaintext: data)
    
    // 4. Return salt + encrypted data for later decryption
    return salt + encrypted.combined
}
```

### Fail Securely

When operations fail, ensure the failure doesn't leak sensitive information:

```swift
// ✅ Good: Secure error handling
func authenticate(username: String, password: String) -> Bool {
    guard let storedHash = getStoredHash(for: username) else {
        // Still perform password hashing to prevent timing attacks
        _ = try? PwHash.scryptVerify(hash: "dummy", password: password)
        return false
    }
    
    do {
        return try PwHash.scryptVerify(hash: storedHash, password: password)
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
    guard let hexString = ProcessInfo.processInfo.environment[name],
          let keyData = Data(hexString: hexString) else {
        throw KeyError.notFound
    }
    return keyData
}
```


## Random Number Generation

SwiftNaCl uses cryptographically secure random number generation. Always use the provided functions:

```swift
// ✅ Good: Use SwiftNaCl's secure RNG
let nonce = random(size: 24)
let salt = random(size: 32)
let seed = VRFSeed.generate()

// ❌ Bad: Don't use predictable sources
// let weakNonce = Data(Date().timeIntervalSince1970.description.utf8)
```

## Memory Security

### Automatic Cleanup

SwiftNaCl automatically cleans up sensitive memory, but understand the limitations:

```swift
func processSecret(data: Data) {
    var signingKey = try SigningKey.generate()
    // Key material is automatically zeroed when signingKey goes out of scope
    
    // However, be careful with copies
    let keyData = signingKey.bytes // This creates a copy!
    // keyData won't be automatically zeroed
}
```

### Manual Cleanup

For additional security, manually zero sensitive data:

```swift
func secureProcess() {
    var password = "secret".data(using: .utf8)!
    defer {
        // Zero out password data
        password.withUnsafeMutableBytes { bytes in
            bytes.bindMemory(to: UInt8.self).initialize(repeating: 0)
        }
    }
    
    // Use password...
}
```

### Avoid String Interpolation

Don't accidentally leak sensitive data in logs:

```swift
// ❌ Bad: Sensitive data might be logged
print("Processing with key: \(signingKey)")

// ✅ Good: Use fingerprints or omit sensitive data
print("Processing with key fingerprint: \(signingKey.fingerprint())")
```

## Encryption Best Practices

### Always Use Authenticated Encryption

Use AEAD constructions that provide both confidentiality and integrity:

```swift
// ✅ Good: Authenticated encryption
let secretBox = try SecretBox(key: key)
let encrypted = try secretBox.encrypt(plaintext: data)

// ✅ Also good: AEAD with additional data
let aead = try Aead(key: key)
let metadata = "file_v1".data(using: .utf8)!
let encrypted = try aead.encrypt(plaintext: data, aad: metadata)
```

### Unique Nonces

Never reuse nonces with the same key:

```swift
class SecureStorage {
    private let key: Data
    private var nonceCounter: UInt64 = 0
    
    func encrypt(data: Data) throws -> Data {
        // Generate unique nonce
        let nonce = random(size: 24)  // Better: use counter + random
        
        let secretBox = try SecretBox(key: key)
        return try secretBox.encrypt(plaintext: data, nonce: nonce).combined
    }
}
```

## Digital Signatures

### Verify Before Using

Always verify signatures before trusting signed data:

```swift
func processSignedDocument(signedData: Data, publicKey: VerifyKey) throws -> Document {
    // Verify signature first
    let verifiedData = try publicKey.verify(smessage: signedData)
    
    // Only then process the verified data
    return try Document(data: verifiedData)
}
```

### Use Detached Signatures When Appropriate

For large documents, use detached signatures:

```swift
func createDetachedSignature(document: Data, signingKey: SigningKey) throws -> Data {
    let signature = try signingKey.sign(message: document)
    return signature.getSignature // Return only the signature part
}

func verifyDetachedSignature(document: Data, signature: Data, publicKey: VerifyKey) throws -> Bool {
    do {
        _ = try publicKey.verify(smessage: document, signature: signature)
        return true
    } catch {
        return false
    }
}
```

## Password Handling

### Use Strong Key Derivation

Always use proper password hashing for authentication:

```swift
// ✅ Good: Use Argon2id for password hashing
func hashPassword(_ password: String) throws -> String {
    return try PwHash.str(
        passwd: password,
        opsLimit: PwHash.OpsLimitInteractive,
        memLimit: PwHash.MemLimitInteractive
    )
}

func verifyPassword(_ password: String, hash: String) -> Bool {
    return (try? PwHash.strVerify(hash: hash, passwd: password)) ?? false
}
```

### Secure Password Derivation

Use proper KDF for deriving encryption keys from passwords:

```swift
func deriveKeyFromPassword(_ password: String, salt: Data) throws -> Data {
    return try PwHash.kdf(
        outputLength: 32,
        passwd: password,
        salt: salt,
        opsLimit: PwHash.OpsLimitSensitive,
        memLimit: PwHash.MemLimitSensitive,
        alg: PwHash.Algorithm.argon2id
    )
}
```

## VRF Security

### Protect VRF Signing Keys

VRF signing keys must be kept strictly confidential:

```swift
// ✅ Good: Generate keys securely and protect them
let vrfKeyPair = VRFKeyPair.generate()
try storeKeySecurely(vrfKeyPair.signingKey)

// Only share the verifying key publicly
let publicKey = vrfKeyPair.verifyingKey
```

### Validate VRF Inputs

Always validate VRF inputs to prevent attacks:

```swift
func generateVRFOutput(input: Data, signingKey: VRFSigningKey) throws -> VRFOutput {
    // Validate input size/format
    guard input.count <= 10000 else {
        throw VRFError.invalidInputSize
    }
    
    let proof = try signingKey.prove(message: input)
    return try proof.hash()
}
```


## Network Security

### Protect Data in Transit

Always use TLS for network communication, but add application-layer encryption for sensitive data:

```swift
struct SecureMessage {
    let encryptedPayload: Data
    let signature: Data
    let publicKey: Data
    
    static func create(message: Data, recipientKey: PublicKey, senderKey: SigningKey) throws -> SecureMessage {
        // Encrypt for recipient
        let box = try Box(privateKey: /* sender's private key */, publicKey: recipientKey)
        let encrypted = try box.encrypt(plaintext: message)
        
        // Sign the encrypted message
        let signature = try senderKey.sign(message: encrypted.combined)
        
        return SecureMessage(
            encryptedPayload: encrypted.combined,
            signature: signature.getCombined,
            publicKey: senderKey.verifyKey.bytes
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
let signingKey = masterKey     // Definitely don't do this

// ✅ Good: Derive different keys for different purposes
let masterKey = random(size: 32)
let encryptionKey = try deriveKey(masterKey, context: "encryption")
let macKey = try deriveKey(masterKey, context: "authentication")
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
```swift
// ❌ Bad: Branching on secret data
func processSecret(secret: Data, threshold: UInt8) {
    if secret[0] > threshold {  // Timing leak
        // Process one way
    } else {
        // Process another way
    }
}

// ✅ Good: Constant-time processing
func processSecret(secret: Data, threshold: UInt8) {
    let mask = constantTimeGreater(secret[0], threshold)
    let result1 = processWay1(secret)
    let result2 = processWay2(secret)
    return constantTimeSelect(mask, result1, result2)
}
```

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

- Review the [libsodium documentation](https://libsodium.gitbook.io/) for cryptographic details
- Consider professional security audits for high-stakes applications
- Stay updated with security advisories and update SwiftNaCl regularly
- Follow secure coding practices specific to your platform (iOS, macOS, Linux)

Remember: **Security is a process, not a product.** Regular review and updates are essential for maintaining security over time.
