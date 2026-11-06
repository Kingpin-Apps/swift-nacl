import Clibsodium
import Foundation

nonisolated(unsafe) private let sodium = Sodium()

/// Encrypts and decrypts messages with a shared secret key, using
/// XSalsa20-Poly1305 (libsodium `crypto_secretbox`).
///
/// This is the Swift counterpart of PyNaCl's `nacl.secret.SecretBox`.
///
/// The ciphertexts that `SecretBox` produces include a 16-byte authenticator,
/// which is checked during decryption. An invalid authenticator makes
/// ``decrypt(ciphertext:nonce:encoder:)`` throw. The authenticator is not a
/// signature: anyone who can decrypt a message can also create valid
/// messages, so messages are repudiable. For non-repudiable messages, sign
/// them after encryption.
///
/// There are no practical limits on the number or size of messages
/// (up to 2⁶⁴ messages, each up to 2⁶⁴ bytes).
///
/// ```swift
/// let key = random(size: Sodium().cryptoSecretBox.keyBytes)
/// let box = try SecretBox(key: key)
///
/// let encrypted = try box.encrypt(plaintext: Data("secret".utf8))
/// let plaintext = try box.decrypt(ciphertext: encrypted.combined)
/// ```
public class SecretBox {
    /// The required key size in bytes (32).
    public let keySize: Int
    /// The required nonce size in bytes (24).
    public let nonceSize: Int
    /// The size of the authentication tag added to each ciphertext, in bytes (16).
    public let macBytes: Int
    /// The largest message, in bytes, that can be encrypted with one key/nonce pair.
    public let messageBytesMax: UInt64

    private var key: Data

    /// Creates a secret box from a secret key.
    ///
    /// - Parameter key: The secret key, encoded with `encoder`. After decoding
    ///   it must be ``keySize`` (32) bytes long.
    /// - Parameter encoder: The encoder used to decode `key`.
    /// - Throws: ``SodiumError/valueError(_:)`` if the decoded key has the wrong length.
    public init(key: Data, encoder: Encoder.Type = RawEncoder.self) throws {
        self.key = try encoder.decode(data: key)

        keySize = sodium.cryptoSecretBox.keyBytes
        nonceSize = sodium.cryptoSecretBox.nonceBytes
        macBytes = sodium.cryptoSecretBox.macBytes
        messageBytesMax = UInt64(UInt(bitPattern: crypto_secretbox_messagebytes_max()))

        try ensure(self.key.count == keySize, raising: .valueError("The key must be exactly \(keySize) bytes long"))
    }

    /// Encrypts `plaintext` and returns the nonce and ciphertext.
    ///
    /// - Warning: The nonce must never be reused with the same key; reuse
    ///   compromises the privacy of the messages. Leave `nonce` as `nil` to
    ///   use a random one. If you manage nonces yourself, give each side a
    ///   different prefix, or have one side use odd counters and the other even.
    ///
    /// - Parameter plaintext: The message to encrypt.
    /// - Parameter nonce: A ``nonceSize``-byte (24) raw nonce, or `nil` to generate a random one.
    /// - Parameter encoder: The encoder applied to the nonce, ciphertext and combined bytes
    ///   of the result.
    /// - Returns: An ``EncryptedMessage`` holding the nonce, the ciphertext, and both combined.
    /// - Throws: ``SodiumError/valueError(_:)`` if the nonce has the wrong length, or
    ///   ``SodiumError/cryptoError(_:)`` if encryption fails.
    public func encrypt(plaintext: Data, nonce: Data? = nil, encoder: Encoder.Type = RawEncoder.self) throws -> EncryptedMessage {
        let nonce = nonce ?? random(size: nonceSize)
        try ensure(nonce.count == nonceSize, raising: .valueError("The nonce must be exactly \(nonceSize) bytes long"))

        let ciphertext = try sodium.cryptoSecretBox.easy(
            message: plaintext,
            nonce: nonce,
            key: key
        )
        let encodedNonce = encoder.encode(data: nonce)
        let encodedCiphertext = encoder.encode(data: ciphertext)

        return EncryptedMessage(nonce: encodedNonce, ciphertext: encodedCiphertext, combined: encoder.encode(data: nonce + ciphertext))
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
    /// - Throws: ``SodiumError/valueError(_:)`` if the nonce or ciphertext has the wrong
    ///   length, or ``SodiumError/cryptoError(_:)`` if the ciphertext fails authentication.
    public func decrypt(ciphertext: Data, nonce: Data? = nil, encoder: Encoder.Type = RawEncoder.self) throws -> Data {
        var ciphertext = try encoder.decode(data: ciphertext)
        let resolvedNonce: Data
        if let nonce {
            resolvedNonce = nonce
        } else {
            resolvedNonce = Data(ciphertext.prefix(nonceSize))
            ciphertext = Data(ciphertext.dropFirst(nonceSize))
        }

        try ensure(resolvedNonce.count == nonceSize, raising: .valueError("The nonce must be exactly \(nonceSize) bytes long"))

        return try sodium.cryptoSecretBox.openEasy(ciphertext: ciphertext, nonce: resolvedNonce, key: key)
    }
}

/// Encrypts and decrypts messages with a shared secret key and optional
/// additional authenticated data, using XChaCha20-Poly1305 (IETF).
///
/// This is the Swift counterpart of PyNaCl's `nacl.secret.Aead`.
///
/// Unlike ``SecretBox``, `Aead` can also authenticate data that is sent
/// alongside the message but not encrypted, such as a length or type tag.
/// Like ``SecretBox``, it provides authenticated encryption: an inauthentic
/// message or mismatched additional data makes
/// ``decrypt(ciphertext:aad:nonce:encoder:)`` throw.
///
/// The authenticator is not a (public-key) signature: anyone who can decrypt
/// can also create valid messages, so messages are repudiable. For
/// non-repudiable messages, sign them after encryption.
///
/// There are no practical limits to how much can be encrypted under one key
/// (up to 2⁶⁴ messages, each up to 2⁶⁴ bytes).
///
/// ```swift
/// let key = random(size: Sodium().cryptoAead.xchacha20poly1305IetfKeyBytes)
/// let aead = try Aead(key: key)
///
/// let header = Data("v1".utf8)
/// let encrypted = try aead.encrypt(plaintext: Data("secret".utf8), aad: header)
/// let plaintext = try aead.decrypt(ciphertext: encrypted.combined, aad: header)
/// ```
public class Aead {
    /// The required key size in bytes (32).
    public let keySize: Int
    /// The required nonce size in bytes (24).
    public let nonceSize: Int
    /// The size of the authentication tag added to each ciphertext, in bytes (16).
    public let macBytes: Int
    /// The largest message, in bytes, that can be encrypted with one key/nonce pair.
    public let messageBytesMax: UInt64

    private var key: Data

    /// Creates an AEAD box from a secret key.
    ///
    /// - Parameter key: The secret key, encoded with `encoder`. After decoding
    ///   it must be ``keySize`` (32) bytes long.
    /// - Parameter encoder: The encoder used to decode `key`.
    /// - Throws: ``SodiumError/valueError(_:)`` if the decoded key has the wrong length.
    public init(key: Data, encoder: Encoder.Type = RawEncoder.self) throws {
        self.key = try encoder.decode(data: key)

        keySize = sodium.cryptoAead.xchacha20poly1305IetfKeyBytes
        nonceSize = sodium.cryptoAead.xchacha20poly1305IetfNpubBytes
        macBytes = sodium.cryptoAead.xchacha20poly1305IetfABytes
        messageBytesMax = sodium.cryptoAead.xchacha20poly1305IetfMessageBytesMax

        try ensure(self.key.count == keySize, raising: .valueError("The key must be exactly \(keySize) bytes long"))
    }

    /// Encrypts `plaintext` and authenticates it together with `aad`.
    ///
    /// - Warning: The nonce must be unique for each message under a key. By
    ///   default a random 24-byte nonce is generated; because XChaCha20 uses
    ///   an extended nonce, the risk of a random collision is negligible, and
    ///   keeping this default is strongly recommended. If you must manage
    ///   nonces yourself, use split counters (for example, each side counts its
    ///   own messages and prefixes a one-bit side id), and never roll a counter
    ///   back.
    ///
    /// - Parameter plaintext: The message to encrypt.
    /// - Parameter aad: Additional data to authenticate but not encrypt. The same
    ///   bytes must be passed to ``decrypt(ciphertext:aad:nonce:encoder:)``.
    /// - Parameter nonce: A ``nonceSize``-byte (24) raw nonce, or `nil` to generate a random one.
    /// - Parameter encoder: The encoder applied to the nonce, ciphertext and combined bytes
    ///   of the result.
    /// - Returns: An ``EncryptedMessage`` holding the nonce, the ciphertext, and both combined.
    /// - Throws: ``SodiumError/valueError(_:)`` if the nonce has the wrong length, or
    ///   ``SodiumError/cryptoError(_:)`` if encryption fails.
    public func encrypt(plaintext: Data, aad: Data = Data(), nonce: Data? = nil, encoder: Encoder.Type = RawEncoder.self) throws -> EncryptedMessage {
        let nonce = nonce ?? random(size: nonceSize)
        try ensure(nonce.count == nonceSize, raising: .valueError("The nonce must be exactly \(nonceSize) bytes long"))

        let ciphertext = try sodium.cryptoAead.xchacha20poly1305IetfEncrypt(
              message: plaintext, aad: aad, nonce: nonce, key: key)
        let encodedNonce = encoder.encode(data: nonce)
        let encodedCiphertext = encoder.encode(data: ciphertext)

        return EncryptedMessage(nonce: encodedNonce, ciphertext: encodedCiphertext, combined: encoder.encode(data: nonce + ciphertext))
    }

    /// Decrypts a ciphertext and checks it, together with `aad`.
    ///
    /// When `nonce` is `nil`, `ciphertext` must be the combined bytes
    /// (nonce followed by ciphertext), such as ``EncryptedMessage/combined``.
    /// When you pass `nonce`, `ciphertext` must be the bare ciphertext,
    /// such as ``EncryptedMessage/ciphertext``.
    ///
    /// - Parameter ciphertext: The combined or bare ciphertext, encoded with `encoder`.
    /// - Parameter aad: The additional data passed to ``encrypt(plaintext:aad:nonce:encoder:)``.
    /// - Parameter nonce: The raw nonce used for encryption, or `nil` to read it from
    ///   the start of `ciphertext`.
    /// - Parameter encoder: The encoder used to decode `ciphertext`.
    /// - Returns: The decrypted plaintext.
    /// - Throws: ``SodiumError/valueError(_:)`` if the nonce has the wrong length, or
    ///   ``SodiumError/cryptoError(_:)`` if the ciphertext or `aad` fails authentication.
    public func decrypt(ciphertext: Data, aad: Data = Data(), nonce: Data? = nil, encoder: Encoder.Type = RawEncoder.self) throws -> Data {
        var ciphertext = try encoder.decode(data: ciphertext)
        let resolvedNonce: Data
        if let nonce {
            resolvedNonce = nonce
        } else {
            resolvedNonce = Data(ciphertext.prefix(nonceSize))
            ciphertext = Data(ciphertext.dropFirst(nonceSize))
        }

        try ensure(resolvedNonce.count == nonceSize, raising: .valueError("The nonce must be exactly \(nonceSize) bytes long"))

        return try sodium.cryptoAead.xchacha20poly1305IetfDecrypt(
            ciphertext: ciphertext, aad: aad, nonce: resolvedNonce, key: key)
    }
}
