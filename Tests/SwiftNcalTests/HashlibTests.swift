import Testing
import Foundation

@testable import SwiftNcal

@Suite("Hashlib Tests - Blake2b and Scrypt Functions")
struct HashlibTests {
    let sodium = Sodium()
    let message = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let key = Data(repeating: 0, count: 16)  // 16 bytes key
    let salt = Data(repeating: 0, count: 16)  // 16 bytes salt
    let person = Data(repeating: 0, count: 16)  // 16 bytes personalization
    let hashlib = Hashlib()
    let password = "password".data(using: .utf8)!
    let n = 16
    let r = 8
    let p = 1
    let maxmem = 1 << 25
    let dklen = 64
    
    @Test("Blake2b initializes successfully with parameters")
    func testBlake2bInit() async throws {
        let _ = try Blake2b(
            data: message,
            key: key,
            salt: salt,
            person: person
        )
        // Blake2b initialization succeeded if we reach this point
    }

    @Test("Blake2b update produces correct digest size")
    func testBlake2bUpdate() async throws {
        let blake2b = try Blake2b(digestSize: sodium.cryptoGenericHash.bytes)
        try blake2b.update(data: message)
        let digest = try blake2b.digest()
        #expect(digest.count == 64, "Blake2b update digest size mismatch")
    }

    @Test("Blake2b digest generates correct hash size")
    func testBlake2bDigest() async throws {
        let blake2b = try Blake2b(
            data: message,
            digestSize: sodium.cryptoGenericHash.bytes,
            key: key,
            salt: salt,
            person: person
        )
        let digest = try blake2b.digest()
        #expect(digest.count == 64, "Blake2b digest size mismatch")
    }

    @Test("Blake2b hexdigest generates valid hex string")
    func testBlake2bHexdigest() async throws {
        let blake2b = try Blake2b(
            data: message,
            digestSize: sodium.cryptoGenericHash.bytes,
            key: key,
            salt: salt,
            person: person
        )
        
        let hexdigest = try blake2b.hexdigest()
        #expect(!hexdigest.isEmpty, "Blake2b hexdigest should not be empty")
    }

    @Test("Blake2b copy produces identical hash")
    func testBlake2bCopy() async throws {
        let blake2b = try Blake2b(
            data: message, digestSize: 32, key: key, salt: salt, person: person)
        let blake2bCopy = try blake2b.copy()
        let originalHex = try blake2b.hexdigest()
        let copyHex = try blake2bCopy.hexdigest()
        #expect(originalHex == copyHex, "Blake2b copy digest mismatch")
    }

    @Test("Blake2b reduce method throws error as expected")
    func testBlake2bReduce() async throws {
        let blake2b = try Blake2b(
            data: message, digestSize: 32, key: key, salt: salt, person: person)
        #expect(throws: Error.self) {
            try blake2b.reduce()
        }
    }
    
    @Test("Scrypt generates derived key with correct length")
    func testScrypt() async throws {
        let derivedKey = try hashlib.scrypt(
            password: password,
            salt: salt,
            n: n,
            r: r,
            p: p,
            maxmem: sodium.cryptoPwHash.scryptMaxMem,
            dklen: dklen)
        #expect(derivedKey.count == dklen, "Scrypt derived key length mismatch")
    }

    @Test("Scrypt works with default parameters")
    func testScryptWithDefaultParameters() async throws {
        let derivedKey = try hashlib.scrypt(password: password)
        #expect(derivedKey.count == dklen, "Scrypt derived key length mismatch with default parameters")
    }

    @Test("Scrypt throws error with invalid n parameter")
    func testScryptWithInvalidN() async throws {
        let invalidN = 0 // Invalid n parameter
        #expect(throws: Error.self) {
            try hashlib.scrypt(password: password, salt: salt, n: invalidN, r: r, p: p, maxmem: maxmem, dklen: dklen)
        }
    }

    @Test("Scrypt throws error with invalid r parameter")
    func testScryptWithInvalidR() async throws {
        let invalidR = 0 // Invalid r parameter
        #expect(throws: Error.self) {
            try hashlib.scrypt(password: password, salt: salt, n: n, r: invalidR, p: p, maxmem: maxmem, dklen: dklen)
        }
    }

    @Test("Scrypt throws error with invalid p parameter")
    func testScryptWithInvalidP() async throws {
        let invalidP = 0 // Invalid p parameter
        #expect(throws: Error.self) {
            try hashlib.scrypt(password: password, salt: salt, n: n, r: r, p: invalidP, maxmem: maxmem, dklen: dklen)
        }
    }

    @Test("Scrypt throws error with invalid maxmem parameter")
    func testScryptWithInvalidMaxmem() async throws {
        let invalidMaxmem = 0 // Invalid maxmem parameter
        #expect(throws: Error.self) {
            try hashlib.scrypt(password: password, salt: salt, n: n, r: r, p: p, maxmem: invalidMaxmem, dklen: dklen)
        }
    }
}
