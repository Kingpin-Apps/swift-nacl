# ``SwiftNaCl``

A Swift binding to the libsodium library providing modern cryptographic primitives for secure communication, data integrity, and authentication.

## Overview

SwiftNaCl provides a Swift interface to the libsodium cryptographic library, offering state-of-the-art cryptographic primitives with a focus on usability, security, and performance. The library includes support for digital signatures, public-key encryption, authenticated secret-key encryption, cryptographic hashing, password hashing, verifiable random functions (VRF), and more.

SwiftNaCl is built on [IntersectMBO/libsodium](https://github.com/IntersectMBO/libsodium), the Cardano fork of libsodium that adds the VRF primitives. Apple platforms use the bundled `Clibsodium.xcframework`; Linux and Android compile the same fork from vendored source. You do not need to install libsodium separately, and a system libsodium will not provide the VRF functions.

The API has two layers:

- **High-level types** such as ``SigningKey``, ``SealedBox``, ``Hash``, ``Argon2id`` and the VRF types, which wrap keys and common operations.
- **Low-level bindings** reached through ``Sodium``, such as `Sodium().cryptoAead` or `Sodium().cryptoBox`, which map closely to the libsodium C functions and work with raw `Data`.

### Key Features

- **Digital Signatures**: Ed25519 signing and verification
- **Public-key Encryption**: Curve25519 authenticated encryption (XSalsa20-Poly1305) and anonymous sealed boxes
- **Secret-key Encryption**: ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD, plus XChaCha20-Poly1305 secret streams
- **Cryptographic Hashing**: SHA-256, SHA-512, BLAKE2b (optionally keyed), SipHash-2-4 and its 128-bit variant
- **Password Hashing and Key Derivation**: Argon2i, Argon2id and scrypt
- **Verifiable Random Functions (VRF)**: IETF draft 03 (draft-irtf-cfrg-vrf-03) with Ed25519
- **Deterministic Key Generation**: Keys and random bytes derived from a seed
- **Cross-platform**: Apple platforms, Linux and Android

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:SecurityGuide>

### Digital Signatures

- ``SigningKey``
- ``VerifyKey``
- ``SignedMessage``

### Public-key Encryption

- ``PrivateKey``
- ``PublicKey``
- ``KeyPair``
- ``SealedBox``
- ``Box``
- ``EncryptedMessage``

### Verifiable Random Functions

- <doc:VerifiableRandomFunctions>
- ``VRF``
- ``VRFSeed``
- ``VRFSigningKey``
- ``VRFVerifyingKey``
- ``VRFProof``
- ``VRFOutput``
- ``VRFKeyPair``

### Cryptographic Hashing

- ``Hash``
- ``Blake2b``
- ``Hashlib``

### Password Hashing

- ``PwHash``
- ``Argon2``
- ``Argon2i``
- ``Argon2id``
- ``Scrypt``

### Encoding and Utilities

- ``Encoder``
- ``RawEncoder``
- ``HexEncoder``
- ``Base32Encoder``
- ``Base64Encoder``
- ``URLSafeBase64Encoder``
- ``random(size:)``
- ``randomBytesDeterministic(size:seed:encoder:)``
- ``bytesAsString(bytesIn:)``

### Low-level libsodium Bindings

- ``Sodium``
- ``CryptoAead``
- ``CryptoBox``
- ``CryptoSecretStream``
- ``CryptoSecretstreamXchacha20poly1305State``
- ``CryptoSign``
- ``CryptoSignEd25519phState``
- ``CryptoHash``
- ``CryptoGenericHash``
- ``Blake2State``
- ``CryptoShortHash``
- ``CryptoPwHash``
- ``CryptoScalarmult``
- ``CryptoCore``
- ``RandomBytes``
- ``CryptoUtils``
- ``Version``
- ``Lib``

### Error Handling

- ``SodiumError``
- ``VRFError``
- ``ensure(_:raising:)``
