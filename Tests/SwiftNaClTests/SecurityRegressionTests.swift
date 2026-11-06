import Foundation
import Testing

import SwiftNaCl

// Regression tests for the 2026-11 security audit. They use the public API only
// (no @testable import) so they exercise what a consuming app can reach.

@Suite("Malformed encoded input throws instead of trapping")
struct MalformedEncodingTests {
    static let malformed: [(String, Encoder.Type, Data)] = [
        ("hex non-digit", HexEncoder.self, Data("zz".utf8)),
        ("hex odd length", HexEncoder.self, Data("abc".utf8)),
        ("hex sign prefix", HexEncoder.self, Data("+f".utf8)),
        ("hex invalid UTF-8", HexEncoder.self, Data([0xff, 0xfe])),
        ("base16 odd length", Base16Encoder.self, Data("ABC".utf8)),
        ("base16 non-digit", Base16Encoder.self, Data("ZZ".utf8)),
        ("base32", Base32Encoder.self, Data("1".utf8)),
        ("base64", Base64Encoder.self, Data("!!!".utf8)),
        ("url-safe base64", URLSafeBase64Encoder.self, Data("a".utf8)),
        ("url-safe base64 invalid UTF-8", URLSafeBase64Encoder.self, Data([0xff])),
    ]

    @Test("decode throws valueError", arguments: malformed)
    func decodeThrows(name: String, encoder: Encoder.Type, input: Data) {
        #expect(throws: SodiumError.self) { _ = try encoder.decode(data: input) }
    }

    @Test("hex decoding accepts either case")
    func hexAcceptsBothCases() throws {
        #expect(try HexEncoder.decode(data: Data("aBcD".utf8)) == Data([0xab, 0xcd]))
    }

    @Test("decrypt, verify and key APIs throw on malformed encoded input")
    func highLevelAPIsThrow() throws {
        let secretBox = try SecretBox(key: Data(repeating: 1, count: 32))
        #expect(throws: SodiumError.self) {
            _ = try secretBox.decrypt(ciphertext: Data("zz".utf8), encoder: HexEncoder.self)
        }
        let aead = try Aead(key: Data(repeating: 2, count: 32))
        #expect(throws: SodiumError.self) {
            _ = try aead.decrypt(ciphertext: Data("%%%".utf8), encoder: Base64Encoder.self)
        }
        let privateKey = PrivateKey.generate()
        let box = try Box(privateKey: privateKey, publicKey: privateKey.publicKey)
        #expect(throws: SodiumError.self) {
            _ = try box.decrypt(ciphertext: Data("g0".utf8), encoder: HexEncoder.self)
        }
        #expect(throws: SodiumError.self) {
            _ = try SealedBox(recipientKey: privateKey).decrypt(ciphertext: Data("ZZ".utf8), encoder: Base16Encoder.self)
        }
        let verifyKey = try SigningKey.generate().verifyKey
        #expect(throws: SodiumError.self) {
            _ = try verifyKey.verify(smessage: Data("!!!".utf8), encoder: Base64Encoder.self)
        }
        #expect(throws: SodiumError.self) {
            _ = try PublicKey(publicKey: Data("ABC".utf8), encoder: Base16Encoder.self)
        }
    }
}

@Suite("AEAD rejects ciphertexts shorter than the tag")
struct ShortAeadCiphertextTests {
    let key = Data(repeating: 9, count: 32)

    @Test("Aead.decrypt throws for combined blobs of 24 to 39 bytes", arguments: [24, 25, 31, 39])
    func combinedBlobTooShort(length: Int) throws {
        let aead = try Aead(key: key)
        #expect(throws: SodiumError.self) {
            _ = try aead.decrypt(ciphertext: Data(repeating: 0xab, count: length))
        }
    }

    @Test("Aead.decrypt throws for a bare ciphertext shorter than the tag")
    func bareCiphertextTooShort() throws {
        let aead = try Aead(key: key)
        #expect(throws: SodiumError.self) {
            _ = try aead.decrypt(ciphertext: Data([1]), nonce: Data(count: 24))
        }
    }

    @Test("CryptoAead decrypt bindings throw for 0- and 15-byte ciphertexts", arguments: [0, 15])
    func bindingsThrow(length: Int) {
        let aead = Sodium().cryptoAead
        let ciphertext = Data(count: length)
        #expect(throws: SodiumError.self) {
            _ = try aead.chacha20poly1305IetfDecrypt(ciphertext: ciphertext, aad: nil, nonce: Data(count: 12), key: key)
        }
        #expect(throws: SodiumError.self) {
            _ = try aead.chacha20poly1305Decrypt(ciphertext: ciphertext, aad: nil, nonce: Data(count: 8), key: key)
        }
        #expect(throws: SodiumError.self) {
            _ = try aead.xchacha20poly1305IetfDecrypt(ciphertext: ciphertext, aad: nil, nonce: Data(count: 24), key: key)
        }
    }

    @Test("A valid empty-plaintext AEAD message still decrypts")
    func emptyPlaintextRoundTrip() throws {
        let aead = try Aead(key: key)
        let encrypted = try aead.encrypt(plaintext: Data())
        #expect(try aead.decrypt(ciphertext: encrypted.combined) == Data())
    }
}

@Suite("Raw key bindings enforce exact key lengths")
struct RawBindingKeyLengthTests {
    let sodium = Sodium()

    @Test("scalarmult base rejects scalars that are not 32 bytes", arguments: [0, 1, 31, 33])
    func scalarmultBase(length: Int) {
        #expect(throws: SodiumError.self) { _ = try sodium.cryptoScalarmult.base(n: Data(repeating: 1, count: length)) }
    }

    @Test("scalarmult rejects scalars and points that are not 32 bytes", arguments: [0, 1, 31, 33])
    func scalarmult(length: Int) {
        let valid = Data(repeating: 9, count: 32)
        let wrong = Data(repeating: 9, count: length)
        #expect(throws: SodiumError.self) { _ = try sodium.cryptoScalarmult.cryptoScalarmult(n: valid, p: wrong) }
        #expect(throws: SodiumError.self) { _ = try sodium.cryptoScalarmult.cryptoScalarmult(n: wrong, p: valid) }
    }

    @Test("scalarmult still works with 32-byte inputs")
    func scalarmultValid() throws {
        let alice = Data(repeating: 1, count: 32)
        let bob = Data(repeating: 2, count: 32)
        let shared1 = try sodium.cryptoScalarmult.cryptoScalarmult(n: alice, p: try sodium.cryptoScalarmult.base(n: bob))
        let shared2 = try sodium.cryptoScalarmult.cryptoScalarmult(n: bob, p: try sodium.cryptoScalarmult.base(n: alice))
        #expect(shared1 == shared2)
    }

    @Test("CryptoSign.open rejects public keys that are not 32 bytes, including a truncated slice of the real key")
    func openRejectsWrongLengthKey() throws {
        let sign = sodium.cryptoSign
        let keys = try sign.seedKeypair(seed: Data(1...32))
        let signed = try sign.sign(message: Data("hello".utf8), sk: keys.secretKey)
        for pk in [keys.publicKey.prefix(31), Data(), Data([1]), keys.publicKey + Data([0])] {
            #expect(throws: SodiumError.self) { _ = try sign.open(signed: signed, pk: pk) }
        }
        #expect(try sign.open(signed: signed, pk: keys.publicKey) == Data("hello".utf8))
    }

    @Test("CryptoSign.sign rejects secret keys that are not 64 bytes", arguments: [0, 32, 63, 65])
    func signRejectsWrongLengthKey(length: Int) {
        #expect(throws: SodiumError.self) {
            _ = try sodium.cryptoSign.sign(message: Data("hello".utf8), sk: Data(repeating: 1, count: length))
        }
    }
}

@Suite("Password hashing")
struct PasswordHashRegressionTests {
    let password = Data("pw".utf8)

    private func argon2idHash() throws -> Data {
        let argon2id = Argon2id()
        let padded = try argon2id.str(password: password, opsLimit: argon2id.opsLimitMin, memLimit: argon2id.memLimitMin)
        return Data(padded.prefix(while: { $0 != 0 }))
    }

    @Test("Argon2 verify accepts the hash as text, padded, or as a slice of a larger buffer")
    func verifyAcceptsUnterminatedHash() throws {
        let hash = try argon2idHash()
        let text = String(decoding: hash, as: UTF8.self)
        #expect(try Argon2id().verify(passwordHash: Data(text.utf8), password: password))
        #expect(try PwHash().verify(passwordHash: Data(text.utf8), password: password))
        #expect(try Argon2id().verify(passwordHash: hash + Data(count: 10), password: password))

        let storage = hash + Data("Z".utf8) + Data([0])
        let exact = storage.prefix(hash.count)
        #expect(try Argon2id().verify(passwordHash: exact, password: password))
        #expect(try !Argon2id().verify(passwordHash: hash, password: Data("wrong".utf8)))
    }

    @Test("Argon2 verify reads only the bytes it is given")
    func verifyDoesNotReadPastSlice() throws {
        let hash = try argon2idHash()
        // The byte after the slice completes the hash; a verifier that reads past
        // the slice would wrongly accept this truncated hash.
        let truncated = (hash + Data([0])).prefix(hash.count - 1)
        #expect(try !Argon2id().verify(passwordHash: truncated, password: password))
        #expect(try !PwHash().verify(passwordHash: truncated, password: password))
    }

    @Test("Argon2 verify rejects a hash with an embedded NUL")
    func verifyRejectsEmbeddedNul() throws {
        var hash = try argon2idHash()
        hash.insert(0, at: 10)
        #expect(try !Argon2id().verify(passwordHash: hash, password: password))
    }

    @Test("PwHash scrypt string defaults to the scrypt interactive cost (N = 2^14)")
    func scryptDefaultsUseScryptLimits() throws {
        let hash = try PwHash().scryptsalsa208sha256Str(password: password)
        #expect(hash.hasPrefix("$7$C"), "expected N_log2 = 14, got \(hash.prefix(4))")
        #expect(try PwHash().verifyScryptsalsa208sha256(passwordHash: Data(hash.utf8), password: password))
    }

    @Test("Hashlib.scrypt throws on out-of-range parameters", arguments: [
        (2, 1, -1, 32),
        (1 << 53, 8, 1, 32),
        (Int.min, 8, 1, 32),
        (0, 8, 1, 32),
        (16, 0, 1, 32),
        (16, -1, 1, 32),
        (16, 8, 1, -1),
        (16, 8, 1, 0),
    ])
    func scryptRejectsBadParameters(n: Int, r: Int, p: Int, dklen: Int) {
        #expect(throws: SodiumError.self) {
            _ = try Hashlib().scrypt(password: password, salt: Data(repeating: 0x41, count: 32), n: n, r: r, p: p, dklen: dklen)
        }
    }

    @Test("Hashlib.scrypt still derives keys with valid parameters")
    func scryptValid() throws {
        let key = try Hashlib().scrypt(password: password, salt: Data(repeating: 0x41, count: 32), n: 16, r: 8, p: 1, dklen: 32)
        #expect(key.count == 32)
    }

    @Test("Scrypt.kdf throws for a key size outside bytesMin...bytesMax", arguments: [-1, 0])
    func scryptKdfRejectsBadSize(size: Int) {
        let scrypt = Scrypt()
        #expect(throws: SodiumError.self) {
            _ = try scrypt.kdf(size: size, password: password, salt: Data(repeating: 1, count: scrypt.saltBytes),
                               opsLimit: scrypt.opsLimitMin, memLimit: scrypt.memLimitMin)
        }
    }
}

@Suite("VRF signing key validation")
struct VRFSigningKeyRegressionTests {
    @Test("VRFSigningKey rejects a key whose public half is not derived from its seed")
    func rejectsMismatchedPublicKey() throws {
        let seed = Data(repeating: 0x42, count: 32)
        let otherPublicKey = VRFKeyPair.generate().verifyingKey.bytes
        let identity = Data([1]) + Data(count: 31)
        for publicHalf in [Data(count: 32), identity, otherPublicKey] {
            #expect(throws: VRFError.invalidSecretKey) { _ = try VRFSigningKey(bytes: seed + publicHalf) }
        }
    }

    @Test("A VRFSigningKey built from valid bytes exposes its verifying key and fingerprint")
    func validKeyRoundTrips() throws {
        let pair = try VRFKeyPair.from(seed: VRFSeed(bytes: Data(repeating: 0x11, count: 32)))
        let key = try VRFSigningKey(bytes: pair.signingKey.bytes)
        #expect(key.verifyingKey == pair.verifyingKey)
        #expect(!key.fingerprint().isEmpty)
    }
}
