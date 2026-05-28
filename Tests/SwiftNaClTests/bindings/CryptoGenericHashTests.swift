import Testing

@testable import SwiftNaCl

@Suite("Crypto Generic Hash Tests")
struct CryptoGenericHashTests {
    let sodium = Sodium()
    
    @Test("BLAKE2b hash computation")
    func testBlake2bSaltPersonal() async throws {
        let cryptoGenericHash = sodium.cryptoGenericHash

        let message = "Hello, World!".data(using: .utf8)!
        let salt = "somesalt".data(using: .utf8)!
        let person = "someperson".data(using: .utf8)!
        let digestSize = cryptoGenericHash.bytes

        let hash = try cryptoGenericHash.blake2bSaltPersonal(
            data: message, digestSize: digestSize, salt: salt, person: person)

        #expect(hash.count == digestSize, "Hash length mismatch")
    }

    @Test("BLAKE2b state initialization")
    func testBlake2bInit() async throws {
        let cryptoGenericHash = sodium.cryptoGenericHash

        let key = "supersecretkey".data(using: .utf8)!
        let salt = "somesalt".data(using: .utf8)!
        let person = "someperson".data(using: .utf8)!
        let digestSize = cryptoGenericHash.bytes

        let state = try cryptoGenericHash.blake2bInit(
            key: key, salt: salt, person: person, digestSize: digestSize)

        #expect(state.digestSize == digestSize, "Digest size mismatch")
    }

    @Test("BLAKE2b hash update")
    func testBlake2bUpdate() async throws {
        let cryptoGenericHash = sodium.cryptoGenericHash

        let key = "supersecretkey".data(using: .utf8)!
        let salt = "somesalt".data(using: .utf8)!
        let person = "someperson".data(using: .utf8)!
        let digestSize = cryptoGenericHash.bytes
        let message = "Hello, World!".data(using: .utf8)!

        let state = try cryptoGenericHash.blake2bInit(
            key: key, salt: salt, person: person, digestSize: digestSize)
        try cryptoGenericHash.blake2bUpdate(state: state, data: message)

        #expect(
            state.statebuf.count == cryptoGenericHash.stateBytes,
            "Hash length mismatch"
        )
    }

    @Test("BLAKE2b finalization")
    func testBlake2bFinal() async throws {
        let cryptoGenericHash = sodium.cryptoGenericHash

        let key = "supersecretkey".data(using: .utf8)!
        let salt = "somesalt".data(using: .utf8)!
        let person = "someperson".data(using: .utf8)!
        let digestSize = cryptoGenericHash.bytes
        let message = "Hello, World!".data(using: .utf8)!

        let state = try cryptoGenericHash.blake2bInit(
            key: key, salt: salt, person: person, digestSize: digestSize)
        try cryptoGenericHash.blake2bUpdate(state: state, data: message)

        let hash = try cryptoGenericHash.blake2bFinal(state: state)

        #expect(hash.count == cryptoGenericHash.bytesMax, "Hash length mismatch")
    }
}
