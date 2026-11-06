## 2.0.0 (2026-11-06)

### Feat

- throw from Encoder.decode on malformed input instead of trapping

### Fix

- reject VRFSigningKey bytes whose public key does not match the seed
- default PwHash scrypt strings to the scrypt interactive limits
- validate scrypt parameters before arithmetic and allocation
- NUL-terminate Argon2 hashes before verification
- require exact key lengths in the scalarmult and CryptoSign bindings
- reject AEAD ciphertexts and secretstream chunks shorter than the tag

## 1.1.0 (2026-11-06)

### Feat

- make the Ed25519ph state initializer and ed25519ScalarInvert public
- make CryptoSecretBox, CryptoKx and CryptoShortHash methods public
- make SecretBox and Aead public
- expose EncryptedMessage nonce, ciphertext and combined bytes

### Fix

- allow Blake2b digests up to the 64-byte maximum
- return only the requested digest size from blake2bFinal
- require a key for Hash.siphash24 and siphashx24
- keep CryptoSecretBox.messageBytesMax an Int by clamping the libsodium value
- return an empty plaintext from CryptoSecretBox.openEasy for an empty message
- draw random(size:) bytes from libsodium randombytes_buf
- derive the VRF signing key fingerprint from the public key
- encode Base16Encoder output as hex
- match PyNaCl nonce handling and key validation in SecretBox and Aead
- use the secretbox MAC and message-size constants in SecretBox

## 1.0.3 (2026-09-22)

### Fix

- allow BigInt 6.x and refresh dependency pins

## 1.0.2 (2026-06-04)

### Fix

- invert signature verification length and rc checks

## 1.0.1 (2026-05-28)

### Fix

- update BigInt

## 1.0.0 (2026-05-27)

### Feat

- rename SwiftNcal module to SwiftNaCl

## 0.3.2 (2026-05-27)

### Fix

- gate HAVE_GETENTROPY on supported platforms

## 0.3.1 (2026-05-27)

### Fix

- improve wasm compatibility

## 0.3.0 (2026-05-25)

### Feat

- vendor IntersectMBO/libsodium source for Linux pre-Swift 6.2

### Refactor

- drop Package@swift-6.2.swift + Clibsodium.artifactbundle, use vendored source on all non-Apple

## 0.2.3 (2026-05-14)

### Fix

- use version-specific manifest for Linux artifact bundle (Swift 6.2+)
- improve swift version compatibility

## 0.2.2 (2026-04-01)

### Fix

- rename C folders for safer namespacing

## 0.2.1 (2025-10-04)

### Fix

- migrate Tests to Swift Testing and use artifact bundle

## 0.2.0 (2025-09-24)

### Feat

- add VRFs

### Fix

- add binaries for Linux and add docs

## 0.1.4 (2025-02-07)

### Fix

- change access to public

## 0.1.3 (2025-01-04)

### Fix

- make properties public

## 0.1.2 (2025-01-04)

### Fix

- make functions public

## 0.1.1 (2024-11-28)

### Fix

- make functions public
- add more functions and tests
- latest additions
