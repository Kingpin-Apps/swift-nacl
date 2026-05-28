import Clibsodium
import Testing
import Foundation

@testable import SwiftNaCl

@Suite("Crypto PwHash Tests")
struct CryptoPwHashTests {
    let cryptoPwHash = Sodium().cryptoPwHash

    @Test("Scryptsalsa208sha256 LL function works correctly")
    func scryptsalsa208sha256LL() async throws {
        let passwd = "password".data(using: .utf8)!
        let salt = Data(repeating: 0, count: cryptoPwHash.scryptsalsa208sha256Saltbytes)
        let n = 16384
        let r = 8
        let p = 1
        let dklen = 64

        let derivedKey = try cryptoPwHash.scryptsalsa208sha256LL(
            passwd: passwd, salt: salt, n: n, r: r, p: p, dklen: dklen)

        #expect(derivedKey.count == dklen, "Derived key length mismatch")
    }

    @Test("Scryptsalsa208sha256 Str function works correctly")
    func scryptsalsa208sha256Str() async throws {
        let passwd = "password".data(using: .utf8)!
        let opslimit = cryptoPwHash.scryptOpslimitInteractive
        let memlimit = cryptoPwHash.scryptMemlimitInteractive

        let hashStr = try cryptoPwHash.scryptsalsa208sha256Str(
            passwd: passwd, opsLimit: opslimit, memLimit: memlimit)

        #expect(
            hashStr.count == cryptoPwHash.scryptStrbytes - 1, "Hash string length mismatch")
    }

    @Test("Scryptsalsa208sha256 Str Verify function works correctly")
    func scryptsalsa208sha256StrVerify() async throws {
        let passwd = "password".data(using: .utf8)!
        let opslimit = cryptoPwHash.scryptOpslimitInteractive
        let memlimit = cryptoPwHash.scryptMemlimitInteractive

        let hashStr = try cryptoPwHash.scryptsalsa208sha256Str(
            passwd: passwd, opsLimit: opslimit, memLimit: memlimit)
        let hashData = hashStr.data(using: .utf8)!

        let isValid = try cryptoPwHash.scryptsalsa208sha256StrVerify(
            passwd_hash: hashData, passwd: passwd)

        #expect(isValid, "Password verification failed")
    }

    @Test("Argon2i alg hash produces expected length")
    func cryptoPwhashAlg() async throws {
        let passwd = "password".data(using: .utf8)!
        let salt = Data(repeating: 0, count: cryptoPwHash.saltBytes)
        let opslimit = cryptoPwHash.argon2iOpslimitInteractive
        let memlimit = cryptoPwHash.argon2iMemlimitInteractive
        let alg = cryptoPwHash.algArgon2i13
        let outlen = 64

        let derivedKey = try cryptoPwHash.alg(
            outlen: outlen, passwd: passwd, salt: salt, opslimit: opslimit, memlimit: memlimit,
            alg: alg)

        #expect(derivedKey.count == outlen, "Derived key length mismatch")
    }

    @Test("Argon2i strAlg produces expected hash length")
    func strAlg() async throws {
        let passwd = "password".data(using: .utf8)!
        let opslimit = cryptoPwHash.argon2iOpslimitInteractive
        let memlimit = cryptoPwHash.argon2iMemlimitInteractive
        let alg = cryptoPwHash.algArgon2i13

        let hashData = try cryptoPwHash.strAlg(
            passwd: passwd, opslimit: opslimit, memlimit: memlimit, alg: alg)

        #expect(hashData.count == 128, "Hash data length mismatch")
    }

    @Test("Argon2i strVerify validates password correctly")
    func strVerify() async throws {
        let passwd = "password".data(using: .utf8)!
        let opslimit = cryptoPwHash.argon2iOpslimitInteractive
        let memlimit = cryptoPwHash.argon2iMemlimitInteractive
        let alg = cryptoPwHash.algArgon2i13

        let hashData = try cryptoPwHash.strAlg(
            passwd: passwd, opslimit: opslimit, memlimit: memlimit, alg: alg)

        let isValid = try cryptoPwHash.strVerify(passwd_hash: hashData, passwd: passwd)

        #expect(isValid, "Password verification failed")
    }
}
