import Clibsodium
import Foundation

/// A Curve25519 ``PrivateKey`` together with its ``PublicKey``.
public struct KeyPair: Hashable {
    /// The public half of the pair.
    public var publicKey: PublicKey
    /// The private half of the pair.
    public var secretKey: PrivateKey

    /// Creates a key pair from an existing public and private key.
    ///
    /// - Parameter publicKey: The public key.
    /// - Parameter secretKey: The matching private key.
    public init(publicKey: PublicKey, secretKey: PrivateKey) {
        self.publicKey = publicKey
        self.secretKey = secretKey
    }

    /// Generates a random ``PrivateKey`` and its corresponding ``PublicKey``.
    ///
    /// - Returns: A randomly generated key pair.
    public static func generate() -> KeyPair {
        let randomBytes = Data(random(size:  Sodium().cryptoBox.seedBytes))
        let privateKey = try! PrivateKey(privateKey: randomBytes)
        return KeyPair(publicKey: privateKey.publicKey, secretKey: privateKey)
    }
}

/// The public key counterpart to a Curve25519 ``PrivateKey``, used to
/// encrypt messages with ``Box`` and ``SealedBox``.
public class PublicKey: Hashable {
    /// The size of a public key in bytes (32).
    public let SIZE: Int

    private var publicKey: Data
    private let sodium: Sodium

    /// Creates a public key from its encoded bytes.
    ///
    /// - Parameter publicKey: The Curve25519 public key, encoded with `encoder`.
    /// - Parameter encoder: The encoder used to decode `publicKey`.
    /// - Throws: ``SodiumError/valueError(_:)`` if the decoded key is not ``SIZE`` bytes long.
    public init(publicKey: Data, encoder: Encoder.Type = RawEncoder.self) throws {
        self.sodium = Sodium()
        self.SIZE = sodium.cryptoBox.publicKeyBytes
        self.publicKey = try encoder.decode(data: publicKey)

        try ensure(
            self.publicKey.count == SIZE,
            raising: .valueError("The public key must be exactly \(SIZE) bytes long")
        )
    }

    /// Returns the raw public key bytes.
    public func toBytes() -> Data {
        return self.publicKey
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.toBytes())
    }

    public static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return Sodium().utils.sodiumMemcmp(lhs.toBytes(), rhs.toBytes())
    }
}

/// A Curve25519 private key for decrypting messages.
///
/// - Warning: This key **must** be protected and kept secret. Anyone who
///   knows it can decrypt any message encrypted to the corresponding
///   ``PublicKey``.
public class PrivateKey: Hashable {
    /// The size of a private key in bytes (32).
    public let SIZE: Int
    /// The size of a seed for ``fromSeed(seed:encoder:)`` in bytes (32).
    public let SEED_SIZE: Int
    /// The public key derived from this private key.
    public var publicKey: PublicKey

    private var privateKey: Data
    private let sodium: Sodium

    /// Creates a private key from its encoded bytes and derives its public key.
    ///
    /// - Parameter privateKey: The Curve25519 private key, encoded with `encoder`.
    /// - Parameter encoder: The encoder used to decode `privateKey`.
    /// - Throws: ``SodiumError/valueError(_:)`` if the decoded key is not ``SIZE`` bytes long.
    public init(privateKey: Data, encoder: Encoder.Type = RawEncoder.self) throws {
        self.sodium = Sodium()
        self.SIZE = sodium.cryptoBox.secretKeyBytes
        self.SEED_SIZE = sodium.cryptoBox.seedBytes
        self.privateKey = try encoder.decode(data: privateKey)

        try ensure(
            self.privateKey.count == SIZE,
            raising: .valueError("The private key must be exactly \(SIZE) bytes long")
        )

        let rawPublicKey = try sodium.cryptoScalarmult.base(
            n: self.privateKey
        )
        self.publicKey = try PublicKey(publicKey: rawPublicKey)
    }

    /// Derives a private key deterministically from a caller-provided seed.
    ///
    /// - Warning: The seed **must** be high-entropy, so generate it with a
    ///   cryptographically secure random function such as ``random(size:)``.
    ///
    /// - Warning: The seed **must** be protected and kept secret. Anyone who
    ///   knows the seed can recreate the private key.
    ///
    /// - Parameter seed: The seed, encoded with `encoder`. After decoding it must
    ///   be 32 bytes long.
    /// - Parameter encoder: The encoder used to decode `seed`.
    /// - Returns: The derived private key.
    /// - Throws: ``SodiumError/valueError(_:)`` if the decoded seed has the wrong length.
    public static func fromSeed(seed: Data, encoder: Encoder.Type = RawEncoder.self) throws -> PrivateKey {
        let sodium = Sodium()
        let decodedSeed = try encoder.decode(data: seed)

        try ensure(
            decodedSeed.count == sodium.cryptoBox.seedBytes,
            raising: .valueError("The seed must be exactly \(sodium.cryptoBox.seedBytes) bytes long")
        )

        let (rawPrivateKey, _) = try sodium.cryptoBox.seedKeypair(seed: decodedSeed)
        return try PrivateKey(privateKey: rawPrivateKey)
    }

    /// Returns the raw private key bytes.
    public func toBytes() -> Data {
        return privateKey
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.toBytes())
        hasher.combine(publicKey.toBytes())
    }

    public static func == (lhs: PrivateKey, rhs: PrivateKey) -> Bool {
        let sodium = Sodium()
        return sodium.utils
            .sodiumMemcmp(lhs.publicKey.toBytes(), rhs.publicKey.toBytes())
    }

    /// Generates a random private key.
    ///
    /// - Returns: A randomly generated private key.
    public static func generate() -> PrivateKey {
        let sodium = Sodium()
        let randomBytes = Data(random(size: sodium.cryptoBox.seedBytes))
        return try! PrivateKey(privateKey: randomBytes)
    }
}

/// Encrypts and decrypts messages between a pair of Curve25519 keys
/// (libsodium `crypto_box`, XSalsa20-Poly1305).
///
/// The ciphertexts that `Box` produces include a 16-byte authenticator,
/// which is checked during decryption. An invalid authenticator makes
/// ``decrypt(ciphertext:nonce:encoder:)`` throw. The authenticator is not a
/// signature: once you have decrypted a message you can create valid
/// messages yourself, so messages are repudiable. For non-repudiable
/// messages, sign them after encryption.
///
/// ```swift
/// let alice = PrivateKey.generate()
/// let bob = PrivateKey.generate()
///
/// let encrypted = try Box(privateKey: alice, publicKey: bob.publicKey)
///     .encrypt(plaintext: Data("hello".utf8))
/// let plaintext = try Box(privateKey: bob, publicKey: alice.publicKey)
///     .decrypt(ciphertext: encrypted.combined)
/// ```
public class Box {
    /// The required nonce size in bytes (24).
    public let NONCE_SIZE: Int

    private var _sharedKey: Data
    private let sodium: Sodium

    /// Creates a box from your private key and the other party's public key.
    ///
    /// - Parameter privateKey: Your private key.
    /// - Parameter publicKey: The other party's public key.
    /// - Throws: A ``SodiumError`` if the shared key cannot be computed.
    public init(privateKey: PrivateKey, publicKey: PublicKey) throws {
        self.sodium = Sodium()
        self.NONCE_SIZE = sodium.cryptoBox.nonceBytes

        self._sharedKey = try sodium.cryptoBox.beforenm(
            publicKey: publicKey.toBytes(),
            secretKey: privateKey.toBytes()
        )
    }

    /// Creates a box from a precomputed shared key, such as one returned by ``sharedKey()``.
    ///
    /// - Parameter encoded: The shared key, encoded with `encoder`.
    /// - Parameter encoder: The encoder used to decode `encoded`.
    public init(encoded: Data, encoder: Encoder.Type = RawEncoder.self) throws {
        self.sodium = Sodium()
        self.NONCE_SIZE = sodium.cryptoBox.nonceBytes
        self._sharedKey = try encoder.decode(data: encoded)
    }

    /// Generates a random ``PrivateKey``.
    ///
    /// - Returns: A randomly generated private key.
    public static func generate() -> PrivateKey {
        let sodium = Sodium()
        let randomBytes = Data(random(size: sodium.cryptoBox.secretKeyBytes))
        return try! PrivateKey(privateKey: randomBytes)
    }

    /// Encrypts `plaintext` and returns the nonce and ciphertext.
    ///
    /// - Warning: The nonce must never be reused with the same pair of keys;
    ///   reuse compromises the privacy of the messages. Leave `nonce` as `nil`
    ///   to use a random one.
    ///
    /// - Parameter plaintext: The message to encrypt.
    /// - Parameter nonce: A ``NONCE_SIZE``-byte (24) raw nonce, or `nil` to generate a random one.
    /// - Parameter encoder: The encoder applied to the nonce, ciphertext and combined bytes
    ///   of the result.
    /// - Returns: An ``EncryptedMessage`` holding the nonce, the ciphertext, and both combined.
    /// - Throws: ``SodiumError/valueError(_:)`` if the nonce has the wrong length, or
    ///   another ``SodiumError`` if encryption fails.
    public func encrypt(
        plaintext: Data, nonce: Data? = nil, encoder: Encoder.Type = RawEncoder.self
    ) throws -> EncryptedMessage {
        let nonce = nonce ?? Data(random(size: self.NONCE_SIZE))

        try ensure(
            nonce.count == self.NONCE_SIZE,
            raising: .valueError("The nonce must be exactly \(self.NONCE_SIZE) bytes long")
        )

        let ciphertext = try sodium.cryptoBox.easyAfternm(
            message: plaintext,
            nonce: nonce,
            sharedKey: self._sharedKey
        )

        let encodedNonce = encoder.encode(data: nonce)
        let encodedCiphertext = encoder.encode(data: ciphertext)

        return EncryptedMessage.fromParts(
            nonce: encodedNonce,
            ciphertext: encodedCiphertext,
            combined: encoder.encode(data: nonce + ciphertext)
        )
    }

    /// Decrypts and authenticates a ciphertext.
    ///
    /// When `nonce` is `nil`, `ciphertext` must be the combined bytes
    /// (nonce followed by ciphertext), such as ``EncryptedMessage/combined``.
    /// When you pass `nonce`, `ciphertext` must be the bare ciphertext,
    /// such as ``EncryptedMessage/ciphertext``.
    ///
    /// - Parameter ciphertext: The combined or bare ciphertext, encoded with `encoder`.
    /// - Parameter nonce: The raw nonce used for encryption, or `nil` to read it from
    ///   the start of `ciphertext`.
    /// - Parameter encoder: The encoder used to decode `ciphertext`.
    /// - Returns: The decrypted plaintext.
    /// - Throws: ``SodiumError/valueError(_:)`` if the nonce has the wrong length, or
    ///   another ``SodiumError`` if the ciphertext fails authentication.
    public func decrypt(
        ciphertext: Data, nonce: Data? = nil, encoder: Encoder.Type = RawEncoder.self
    ) throws -> Data {
        var ciphertext = try encoder.decode(data: ciphertext)
        var nonceData = nonce

        if nonceData == nil {
            nonceData = Data(ciphertext.prefix(self.NONCE_SIZE))
            ciphertext = Data(ciphertext.dropFirst(self.NONCE_SIZE))
        }

        try ensure(
            nonceData!.count == self.NONCE_SIZE,
            raising: .valueError("The nonce must be exactly \(self.NONCE_SIZE) bytes long")
        )

        let plaintext = try sodium.cryptoBox.openEasyAfternm(
            ciphertext: ciphertext,
            nonce: nonceData!,
            sharedKey: self._sharedKey
        )
        return plaintext
    }

    /// Returns the precomputed Curve25519 shared key.
    ///
    /// The key can be passed to ``init(encoded:encoder:)`` to rebuild the box,
    /// or used as a key for other symmetric ciphers.
    ///
    /// - Returns: The 32-byte shared key.
    public func sharedKey() -> Data {
        return _sharedKey
    }
}

/// Encrypts messages to a recipient's public key with an ephemeral sender key
/// pair (libsodium `crypto_box_seal`).
///
/// The private half of the ephemeral key pair is discarded right after
/// encrypting a single message, so only the recipient can decrypt it. Each
/// ciphertext starts with the ephemeral public key, followed by the
/// ``Box`` ciphertext.
///
/// Create a `SealedBox` from a ``PublicKey`` to encrypt, or from a
/// ``PrivateKey`` to decrypt (and encrypt).
public class SealedBox {
    private var publicKey: Data
    private var privateKey: Data?
    private let sodium: Sodium

    /// Creates a sealed box that can only encrypt, addressed to `recipientKey`.
    ///
    /// - Parameter recipientKey: The recipient's public key.
    public init(recipientKey: PublicKey) {
        self.sodium = Sodium()
        self.publicKey = recipientKey.toBytes()
        self.privateKey = nil
    }

    /// Creates a sealed box that can decrypt messages sent to `recipientKey`.
    ///
    /// - Parameter recipientKey: The recipient's private key.
    public init(recipientKey: PrivateKey) {
        self.sodium = Sodium()
        self.publicKey = recipientKey.publicKey.toBytes()
        self.privateKey = recipientKey.toBytes()
    }

    /// Returns the recipient's raw public key bytes.
    public func toBytes() -> Data {
        return publicKey
    }

    /// Encrypts `plaintext` to the recipient with a fresh ephemeral key pair.
    ///
    /// The result contains the ephemeral public key followed by the
    /// ciphertext. The sender cannot decrypt it afterwards.
    ///
    /// - Parameter plaintext: The message to encrypt.
    /// - Parameter encoder: The encoder applied to the result.
    /// - Returns: The encoded sealed ciphertext.
    /// - Throws: A ``SodiumError`` if encryption fails.
    public func encrypt(plaintext: Data, encoder: Encoder.Type = RawEncoder.self) throws -> Data {
        let ciphertext = try sodium.cryptoBox.seal(
            message: plaintext,
            publicKey: self.publicKey
        )
        return encoder.encode(data: ciphertext)
    }

    /// Decrypts a sealed ciphertext with the recipient's private key.
    ///
    /// - Parameter ciphertext: The sealed ciphertext, encoded with `encoder`.
    /// - Parameter encoder: The encoder used to decode `ciphertext`.
    /// - Returns: The decrypted plaintext.
    /// - Throws: ``SodiumError/valueError(_:)`` if the box was created from a
    ///   ``PublicKey``, or another ``SodiumError`` if decryption fails.
    public func decrypt(ciphertext: Data, encoder: Encoder.Type = RawEncoder.self) throws -> Data {
        try ensure(
            privateKey != nil,
            raising: .valueError("SealedBoxes created with a public key cannot decrypt")
        )

        let ciphertext = try encoder.decode(data: ciphertext)
        let plaintext = try sodium.cryptoBox.sealOpen(
            ciphertext: ciphertext,
            publicKey: self.publicKey,
            secretKey: self.privateKey!
        )
        return plaintext
    }
}
