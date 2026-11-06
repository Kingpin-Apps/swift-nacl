import Clibsodium
import Foundation

/// The result of ``Box/encrypt(plaintext:nonce:encoder:)``,
/// ``SecretBox/encrypt(plaintext:nonce:encoder:)`` or
/// ``Aead/encrypt(plaintext:aad:nonce:encoder:)``.
///
/// Mirrors PyNaCl's `EncryptedMessage`: it carries the ``nonce``, the bare
/// ``ciphertext`` (which includes the authentication tag), and the ``combined``
/// bytes (`nonce + ciphertext`). Each value is already encoded with the
/// encoder passed to `encrypt`.
///
/// Pass ``combined`` to `decrypt` on its own, or pass ``ciphertext`` together
/// with the raw nonce:
///
/// ```swift
/// let encrypted = try box.encrypt(plaintext: message)
/// let a = try box.decrypt(ciphertext: encrypted.combined)
/// let b = try box.decrypt(ciphertext: encrypted.ciphertext, nonce: encrypted.nonce)
/// ```
public class EncryptedMessage {
    /// The nonce used to encrypt the message, encoded with the `encrypt` encoder.
    public let nonce: Data

    /// The ciphertext, including the authentication tag but not the nonce,
    /// encoded with the `encrypt` encoder.
    public let ciphertext: Data

    /// The nonce followed by the ciphertext (`nonce + ciphertext`), encoded
    /// with the `encrypt` encoder. This is what PyNaCl returns as the bytes
    /// value of an `EncryptedMessage`.
    public let combined: Data

    init(nonce: Data, ciphertext: Data, combined: Data) {
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.combined = combined
    }

    class func fromParts(nonce: Data, ciphertext: Data, combined: Data) -> EncryptedMessage {
        return EncryptedMessage(nonce: nonce, ciphertext: ciphertext, combined: combined)
    }
}

public class StringFixer {
    func toString(data: Data) -> String {
        return String(data: data, encoding: .utf8) ?? ""
    }
}

public func bytesAsString(bytesIn: Data) -> String {
    return bytesIn.map { String(format: "%02hhx", $0) }.joined()
}

/// Returns `size` bytes from libsodium's cryptographically secure random number generator.
///
/// Wraps `randombytes_buf`, so the bytes come from the same generator on every
/// platform the package supports (the OS CSPRNG that libsodium selects).
///
/// - Parameter size: The number of random bytes to return. Must not be negative.
/// - Returns: `size` unpredictable bytes.
public func random(size: Int = 32) -> Data {
    precondition(size >= 0, "size must not be negative")
    _ = Sodium()  // ensures sodium_init() has run
    var buffer = Data(count: size)
    buffer.withUnsafeMutableBytes { bufferPtr in
        if let baseAddress = bufferPtr.baseAddress {
            randombytes_buf(baseAddress, size)
        }
    }
    return buffer
}

/**
 Returns `size` number of deterministically generated pseudorandom bytes from a seed

 - parameter size: Int
 - parameter seed: Data
 - parameter encoder: The encoder class used to encode the produced bytes
 - returns: Data
 */
public func randomBytesDeterministic(size: Int, seed: Data, encoder: Encoder.Type = RawEncoder.self) throws -> Data {
    let rawData = try Sodium().randomBytes.bufDeterministic(
        size: size,
        seed: seed
    )
    return encoder.encode(data: rawData)
}
