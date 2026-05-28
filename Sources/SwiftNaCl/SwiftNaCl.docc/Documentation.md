# ``SwiftNaCl``

A Swift binding to the libsodium library providing modern cryptographic primitives for secure communication, data integrity, and authentication.

## Overview

SwiftNaCl provides a Swift interface to the libsodium cryptographic library, offering state-of-the-art cryptographic primitives with a focus on usability, security, and performance. The library includes support for digital signatures, public-key encryption, secret-key encryption, cryptographic hashing, verifiable random functions (VRF), and more.

### Key Features

- **Digital Signatures**: Ed25519 signing and verification
- **Secret-key Encryption**: XSalsa20-Poly1305 and XChacha20-Poly1305 AEAD
- **Public-key Encryption**: Curve25519 key exchange with authenticated encryption
- **Cryptographic Hashing**: SHA-256, SHA-512, BLAKE2b, SipHash variants
- **Verifiable Random Functions (VRF)**: IETF Draft 03 specification with Ed25519
- **Message Authentication**: Poly1305 MAC
- **Key Derivation**: Password-based and deterministic key generation
- **Cross-platform**: Works on Apple platforms and Linux
- **Memory Safe**: Secure memory handling with automatic cleanup

## Topics

### Digital Signatures

- ``SigningKey``
- ``VerifyKey``
- ``SignedMessage``

### Public-key Encryption

- ``PrivateKey``
- ``PublicKey``
- ``KeyPair``
- ``Box``
- ``SealedBox``

### Secret-key Encryption

- ``SecretBox``
- ``Aead``
- ``EncryptedMessage``

### Verifiable Random Functions

- ``VRFSeed``
- ``VRFSigningKey``
- ``VRFVerifyingKey``
- ``VRFProof``
- ``VRFOutput``
- ``VRFKeyPair``
- ``VRFError``

### Cryptographic Hashing

- ``Hash``
- ``Blake2b``

### Encoding and Utilities

- ``Encoder``
- ``RawEncoder``
- ``HexEncoder``
- ``Base64Encoder``
- ``Base32Encoder``
- ``URLSafeBase64Encoder``

### Password Hashing

- ``PwHash``
- ``Scrypt``
- ``Argon2i``
- ``Argon2id``

### Error Handling

- ``SodiumError``
- ``VRFError``

## Articles and Guides

### Getting Started

- <doc:GettingStarted>
- <doc:VerifiableRandomFunctions>

### Security and Best Practices

- <doc:SecurityGuide>
