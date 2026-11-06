![GitHub Workflow Status](https://github.com/Kingpin-Apps/swift-nacl/actions/workflows/swift.yml/badge.svg)
[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FKingpin-Apps%2Fswift-nacl%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/Kingpin-Apps/swift-nacl)
[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FKingpin-Apps%2Fswift-nacl%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/Kingpin-Apps/swift-nacl)

# Swift-NaCL - Swift binding to libsodium (Cardano fork)

Swift-NaCL is a Swift binding to **[IntersectMBO/libsodium](https://github.com/IntersectMBO/libsodium)** — a Cardano-maintained fork of [jedisct1/libsodium](https://github.com/jedisct1/libsodium) that adds **Verifiable Random Function (VRF, draft-irtf-cfrg-vrf-03)** primitives required by the Cardano protocol. This fork is **not API-compatible with vanilla libsodium** for VRF features — distribution-installed packages (`apt install libsodium-dev`, Homebrew `libsodium`, etc.) lack the `crypto_vrf_ietfdraft03_*` symbols. Apple platforms get the fork via the bundled `Clibsodium.xcframework`; everywhere else compiles it from vendored source at `ClibsodiumLinuxSource/`.

This package provides a modern, idiomatic Swift interface to the cryptographic primitives, offering state-of-the-art crypto for secure communication, data integrity, authentication, and VRF.

## Platform Support

| Platform | Architectures | libsodium source |
|---|---|---|
| iOS, Mac Catalyst | device + simulator | bundled `Clibsodium.xcframework` |
| macOS | arm64, x86_64 | bundled `Clibsodium.xcframework` |
| tvOS | device + simulator | bundled `Clibsodium.xcframework` |
| watchOS | device + simulator | bundled `Clibsodium.xcframework` |
| visionOS | device + simulator | bundled `Clibsodium.xcframework` |
| Linux | x86_64, aarch64 | vendored C source at `ClibsodiumLinuxSource/` |
| Android | x86_64, aarch64 | vendored C source at `ClibsodiumLinuxSource/` |

The package requires Swift 6.0 or later and does not declare minimum OS versions, so SwiftPM's defaults for your toolchain apply.

There is no need to install libsodium via your system package manager. In fact, **doing so will not work** for any code path using VRF (`crypto_vrf_*`) — system libsodium is the upstream jedisct1 build, which does not contain those symbols.

**WASI / Wasm** is not currently supported. The libsodium source relies on POSIX features (pthread, mmap, signal.h) that WASI doesn't provide; supporting Wasm would require a substantial set of `.when(platforms: [.wasi])` conditional defines (see [WASI / Wasm](#wasi--wasm) below).

## Installation

### Swift Package Manager

To add Swift-NaCL as a dependency to your Xcode project, select `File` > `Add Package Dependencies…` and enter its repository URL:

```
https://github.com/Kingpin-Apps/swift-nacl.git
```

Add the `SwiftNaCl` library to your target and `import SwiftNaCl`. The package also vends a `Clibsodium` library with the raw C functions; you only need it to call libsodium directly.

### Package.swift

Add the following to your `Package.swift` file:

``swift
dependencies: [
    .package(url: "https://github.com/Kingpin-Apps/swift-nacl.git", from: "2.0.0")
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: [
            .product(name: "SwiftNaCl", package: "swift-nacl")
        ]
    )
]
``

### Usage

In your Swift files, import the library:

``swift
import SwiftNaCl
``

## Key Features

- ✅ **Digital Signatures** - Ed25519 signing and verification
- ✅ **Secret-key Encryption** - XSalsa20-Poly1305 secret boxes, ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD, plus XChaCha20-Poly1305 secret streams
- ✅ **Public-key Encryption** - Curve25519 authenticated encryption (XSalsa20-Poly1305) and anonymous sealed boxes
- ✅ **Cryptographic Hashing** - SHA-256, SHA-512, BLAKE2b (optionally keyed), SipHash-2-4 and its 128-bit variant
- ✅ **Verifiable Random Functions (VRF)** - IETF Draft 03 specification with Ed25519
- ✅ **Password Hashing and Key Derivation** - Argon2i, Argon2id and scrypt, plus deterministic key generation from seeds
- ✅ **Cross-platform** - Works on Apple platforms, Linux and Android

## Quick Start Examples

### Digital Signatures (Ed25519)

``swift
import SwiftNaCl

// Generate a signing key
let signingKey = try SigningKey.generate()
let verifyKey = signingKey.verifyKey

// Sign a message
let message = "Hello, World!".data(using: .utf8)!
let signedMessage = try signingKey.sign(message: message)

// Verify the signature
let verifiedMessage = try verifyKey.verify(smessage: signedMessage.getCombined)
print(String(data: verifiedMessage, encoding: .utf8)!) // "Hello, World!"
``

### Secret-key Encryption

`SecretBox` (XSalsa20-Poly1305) and `Aead` (XChaCha20-Poly1305 with additional data) generate a random nonce for every message and return an `EncryptedMessage` holding the `nonce`, the `ciphertext`, and both `combined`:

``swift
import SwiftNaCl

// Generate a random 32-byte key
let key = random(size: 32)
let plaintext = "Secret message".data(using: .utf8)!

// SecretBox: the combined bytes carry the nonce, so they are all you need to store or send
let box = try SecretBox(key: key)
let encrypted = try box.encrypt(plaintext: plaintext)
let decrypted = try box.decrypt(ciphertext: encrypted.combined)
print(String(data: decrypted, encoding: .utf8)!) // "Secret message"

// Aead: also authenticates data sent alongside the message without encrypting it
let aead = try Aead(key: key)
let header = "v1".data(using: .utf8)!
let sealed = try aead.encrypt(plaintext: plaintext, aad: header)
let opened = try aead.decrypt(ciphertext: sealed.combined, aad: header)
``

The low-level `CryptoSecretBox` and `CryptoAead` bindings (`Sodium().cryptoSecretBox`, `Sodium().cryptoAead`) take an explicit nonce instead.

### Public-key Encryption (Curve25519)

```swift
import SwiftNaCl

// Generate key pairs
let aliceKeyPair = KeyPair.generate()
let bobKeyPair = KeyPair.generate()

// Alice encrypts a message for Bob (a random nonce is generated for her)
let message = "Hello Bob!".data(using: .utf8)!
let aliceBox = try Box(privateKey: aliceKeyPair.secretKey, publicKey: bobKeyPair.publicKey)
let encrypted = try aliceBox.encrypt(plaintext: message)

// Bob decrypts the message from Alice; `combined` is the nonce followed by the ciphertext
let bobBox = try Box(privateKey: bobKeyPair.secretKey, publicKey: aliceKeyPair.publicKey)
let decrypted = try bobBox.decrypt(ciphertext: encrypted.combined)
print(String(data: decrypted, encoding: .utf8)!) // "Hello Bob!"

// Or send the parts separately
let same = try bobBox.decrypt(ciphertext: encrypted.ciphertext, nonce: encrypted.nonce)

// Anonymous alternative: only the recipient's public key is needed to encrypt
let sealed = try SealedBox(recipientKey: bobKeyPair.publicKey).encrypt(plaintext: message)
let opened = try SealedBox(recipientKey: bobKeyPair.secretKey).decrypt(ciphertext: sealed)
``

### Cryptographic Hashing

``swift
import SwiftNaCl

let hash = Hash()
let message = "Hello, World!".data(using: .utf8)!

// SHA-256 (Hash returns hex-encoded Data by default)
let sha256Hash = try hash.sha256(message: message)
print(String(decoding: sha256Hash, as: UTF8.self))

// Raw 32-byte digest instead of hex
let rawDigest = try hash.sha256(message: message, encoder: RawEncoder.self)

// BLAKE2b with custom parameters
let blake2bHash = try hash.blake2b(
    data: message,
    digestSize: 32,
    key: "secret-key".data(using: .utf8)!,
    salt: "salt1234".data(using: .utf8)!,
    person: "personal".data(using: .utf8)!
)
``

### Verifiable Random Functions (VRF)

``swift
import SwiftNaCl

// Generate a VRF key pair
let keyPair = VRFKeyPair.generate()

// Create a proof for a message
let message = "Hello, VRF!".data(using: .utf8)!
let proof = try keyPair.signingKey.prove(message: message)

// Verify the proof and get the deterministic output
let output = try keyPair.verifyingKey.verify(message: message, proof: proof)
print("VRF Output: \(output.hexEncodedString())")

// The same message always produces the same output with the same key
let proof2 = try keyPair.signingKey.prove(message: message)
let output2 = try keyPair.verifyingKey.verify(message: message, proof: proof2)
assert(output == output2) // Always true!
```

## API Reference

### Core Classes

#### Digital Signatures
- `SigningKey` - Ed25519 private key for signing
- `VerifyKey` - Ed25519 public key for verification
- `SignedMessage` - Container for signed messages

#### Public-key Encryption
- `PrivateKey` - Curve25519 private key
- `PublicKey` - Curve25519 public key
- `KeyPair` - Combined public/private key pair
- `SealedBox` - Anonymous public-key encryption to a recipient
- `Box` - Public-key authenticated encryption with a precomputed shared key
- `EncryptedMessage` - The `nonce`, `ciphertext` and `combined` bytes returned by `Box`, `SecretBox` and `Aead`

#### Secret-key Encryption
- `SecretBox` - XSalsa20-Poly1305 authenticated encryption with a shared key
- `Aead` - XChaCha20-Poly1305 authenticated encryption with additional data

#### Low-level Bindings (via `Sodium()`)
- `CryptoAead` - ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD encryption with additional data
- `CryptoBox` - Curve25519 public-key authenticated encryption and sealed boxes
- `CryptoSecretBox` - XSalsa20-Poly1305 secret-key authenticated encryption
- `CryptoSecretStream` - XChaCha20-Poly1305 streaming encryption
- `CryptoKx` - Client-server key exchange (session keys)
- `CryptoShortHash` - SipHash-2-4 and SipHashX-2-4 short-input keyed hashing
- `CryptoSign`, `CryptoHash`, `CryptoGenericHash`, `CryptoPwHash`, `CryptoScalarmult`, `CryptoCore`, `RandomBytes`, `CryptoUtils`

#### Hashing
- `Hash` - Cryptographic hash functions (SHA-256, SHA-512, BLAKE2b, SipHash)
- `Blake2b` - Incremental BLAKE2b hashing

#### Password Hashing
- `Argon2id`, `Argon2i`, `Scrypt` - Password hashing (`str`, `verify`) and key derivation (`kdf`)
- `PwHash` - Verifies any supported password hash by its prefix

#### Verifiable Random Functions
- `VRFSeed` - 32-byte cryptographic seed for key generation
- `VRFSigningKey` - Ed25519 private key for creating VRF proofs
- `VRFVerifyingKey` - Ed25519 public key for verifying VRF proofs
- `VRFProof` - 80-byte VRF proof
- `VRFOutput` - 64-byte deterministic VRF output
- `VRFKeyPair` - Convenience wrapper for signing and verifying keys

#### Encoding
- `RawEncoder` - Raw binary data (default)
- `HexEncoder` - Hexadecimal encoding (lowercase)
- `Base16Encoder` - Base16 (RFC 4648) encoding: uppercase hex, decodes either case
- `Base64Encoder` - Base64 encoding (via Foundation)
- `Base32Encoder`, `URLSafeBase64Encoder` - Base32 and URL-safe Base64 encoding

`decode(data:)` throws `SodiumError.valueError` on malformed input (an odd number of hex digits, a non-hex character, invalid UTF-8, or invalid Base32/Base64), so APIs that decode untrusted input throw instead of terminating the process. Since 2.0 `decode(data:)` is a throwing requirement: call it with `try`, and mark `decode` in custom `Encoder` types as `throws`.

### Error Handling

Swift-NaCL uses Swift's error handling mechanism. Operations that can fail throw a `SodiumError` (or a `VRFError` for VRF operations):

``swift
do {
    let signingKey = try SigningKey(seed: Data(count: 5)) // must be 32 bytes
} catch {
    print("Failed to create signing key: \(error)")
    // Failed to create signing key: valueError("The seed must be exactly 32 bytes long")
}
``

### Memory Security

Keys, seeds and other secrets are held in ordinary `Data` values and are **not** zeroed automatically when they are released. Follow security best practices:

- Don't log sensitive data
- Clear sensitive buffers you own when no longer needed (for example with `Data.resetBytes(in:)`)
- Use secure storage for long-term key storage

The VRF types are `Sendable` value types; the other key and box types are classes that are not `Sendable`.

## Advanced Usage

### Custom Encoders

You can specify different encoders for input/output:

``swift
// Pass a hex-encoded 32-byte seed (64 hex characters) and let HexEncoder decode it
let hexSeed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
let signingKey = try SigningKey(seed: Data(hexSeed.utf8), encoder: HexEncoder.self)

// Sign with hex output (the signature and combined message are hex-encoded Data)
let message = "Hello".data(using: .utf8)!
let signedMessage = try signingKey.sign(message: message, encoder: HexEncoder.self)

// Verify hex-encoded input
let verified = try signingKey.verifyKey.verify(smessage: signedMessage.getCombined, encoder: HexEncoder.self)
``

### Key Conversion

Convert between Ed25519 and Curve25519 keys:

``swift
let signingKey = try SigningKey.generate()
let verifyKey = signingKey.verifyKey

// Convert to Curve25519 for encryption
let curve25519Private = try signingKey.toCurve25519PrivateKey()
let curve25519Public = try verifyKey.toCurve25519PublicKey()
``

### VRF Deterministic Key Generation

Generate VRF keys deterministically from a seed:

``swift
// Create a deterministic seed (must be exactly 32 bytes)
let seedData = "my-deterministic-seed-32-bytes!!".data(using: .utf8)!
let seed = try VRFSeed(bytes: seedData)

// Generate keys from seed - always the same for the same seed
let keyPair = try VRFKeyPair.from(seed: seed)

// Extract the original seed from a signing key
let originalSeed = keyPair.signingKey.seed
assert(originalSeed == seed)
``

### VRF Proof Extraction

Extract VRF output directly from a proof (without verification):

``swift
let keyPair = VRFKeyPair.generate()
let message = "data".data(using: .utf8)!
let proof = try keyPair.signingKey.prove(message: message)

// Extract output directly from proof (unverified)
let directOutput = try proof.hash()

// Verify and extract output (verified)
let verifiedOutput = try keyPair.verifyingKey.verify(message: message, proof: proof)

// Both outputs are identical
assert(directOutput == verifiedOutput)
``

## Dependencies

- **[IntersectMBO/libsodium](https://github.com/IntersectMBO/libsodium)** — Cardano fork of libsodium with VRF. Embedded in this package; no separate install needed.
- [Base32](https://github.com/norio-nomura/Base32.git) — Base32 encoding support
- [BigInt](https://github.com/attaswift/BigInt.git) — Large integer arithmetic

## Platform-specific Notes

### Apple Platforms

The Cardano libsodium fork ships as a precompiled `Clibsodium.xcframework` covering iOS, macOS, tvOS, watchOS, visionOS (device + simulator slices, arm64 + x86_64 where applicable). Nothing to install — `swift build` against any Apple platform Just Works.

### Linux & Android

The Cardano libsodium fork is compiled from vendored C source at `ClibsodiumLinuxSource/`. First build is ~10–30s depending on toolchain; subsequent builds reuse the cached objects. Works on any Linux or Android system with a C compiler — no apt/yum/brew install needed.

The pinned upstream commit is recorded in `ClibsodiumLinuxSource/UPSTREAM_COMMIT`. To refresh from a newer `IntersectMBO/libsodium` checkout, run `scripts/sync-libsodium-source.sh` (re-syncs source + regenerates `version.h`).

CPU-specific SIMD variants (AVX2, SSE4.1, SSSE3, AVX-512F) are intentionally excluded from the build because SwiftPM doesn't expose per-source-file compile flags. Runtime CPU dispatch in `sodium/runtime.c` falls back cleanly to the portable ref paths.

**Do not** install vanilla libsodium via `apt`, `yum`, or `brew` — on Linux/Android it will be silently ignored, and on Apple platforms the bundled xcframework takes precedence. If you installed it for an earlier version of this package (when it was named swift-ncal), you can safely uninstall it.

### WASI / Wasm

Not currently supported. The libsodium source relies on POSIX features absent from WASI (pthread, mmap, signal.h, sys/mman.h, mlock/munlock). Supporting Wasm would need a substantial set of `.when(platforms: [.wasi])` conditional `cSettings` excluding `HAVE_PTHREAD`, `HAVE_SYS_MMAN_H`, `HAVE_MLOCK`, `HAVE_MADVISE`, `HAVE_MPROTECT`, plus likely `-D_WASI_EMULATED_*` flags and linker emulation libs. Tracked as future work.

## Testing

Run the test suite:

``bash
swift test
``

Tests cover:
- Signing, public-key and secret-key encryption, hashing, password hashing and VRF
- The low-level libsodium bindings
- Key generation and validation
- Encoders and utilities
- Error conditions

## Security Considerations

⚠️ **Important Security Notes:**

1. **Private Key Protection**: Private keys and seeds must be kept secret and secure
2. **Nonce Uniqueness**: Never reuse nonces with the same key
3. **Random Generation**: Use cryptographically secure random number generation (`random(size:)` and the `generate()` methods use libsodium's `randombytes_buf`, which reads the operating system's secure generator)
4. **Memory Handling**: Sensitive data is not cleared from memory automatically; clear buffers you own and avoid unnecessary copies
5. **Constant-time Comparisons**: Key, VRF proof and VRF output equality (`==`) uses libsodium's constant-time `sodium_memcmp`; use `Sodium().utils.sodiumMemcmp` for your own secret comparisons

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is released under the MIT License (see `LICENSE`). The bundled libsodium is distributed under its own ISC license.

## Acknowledgments

- Based on the [libsodium](https://libsodium.org/) library
- Inspired by the Python [PyNaCl](https://pynacl.readthedocs.io/) library
- Built for the Swift ecosystem with modern Swift best practices
