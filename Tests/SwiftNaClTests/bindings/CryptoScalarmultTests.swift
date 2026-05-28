import Testing
import Foundation
@testable import SwiftNaCl

@Suite("CryptoScalarmultTests")
struct CryptoScalarmultTests {
    
    let cryptoScalarmult = Sodium().cryptoScalarmult
    
    @Test("base returns expected length")
    func testCryptoScalarmultBase() throws {
        let scalar = Data(repeating: 0x01, count: Int(cryptoScalarmult.scalarBytes))
        let result = try cryptoScalarmult.base(n: scalar)
        #expect(result.count == Int(cryptoScalarmult.scalarBytes), "Result length mismatch")
    }

    @Test("cryptoScalarmult returns expected length")
    func testCryptoScalarmult() throws {
        let scalar = Data(repeating: 0x01, count: Int(cryptoScalarmult.scalarBytes))
        let point = Data(repeating: 0x02, count: Int(cryptoScalarmult.bytes))
        let result = try cryptoScalarmult.cryptoScalarmult(n: scalar, p: point)
        #expect(result.count == Int(cryptoScalarmult.scalarBytes), "Result length mismatch")
    }

    @Test("ed25519Base returns expected length")
    func testCryptoScalarmultEd25519Base() throws {
        let scalar = Data(repeating: 0x03, count: Int(cryptoScalarmult.ed25519ScalarBytes))
        let result = try cryptoScalarmult.ed25519Base(n: scalar)
        #expect(result.count == Int(cryptoScalarmult.ed25519Bytes), "Result length mismatch")
    }

    @Test("ed25519BaseNoclamp returns expected length")
    func testCryptoScalarmultEd25519BaseNoclamp() throws {
        let scalar = Data(repeating: 0x04, count: Int(cryptoScalarmult.ed25519ScalarBytes))
        let result = try cryptoScalarmult.ed25519BaseNoclamp(n: scalar)
        #expect(result.count == Int(cryptoScalarmult.ed25519Bytes), "Result length mismatch")
    }

    @Test("ed25519 returns expected length")
    func testCryptoScalarmultEd25519() throws {
        let scalar = Data(repeating: 0x05, count: Int(cryptoScalarmult.ed25519ScalarBytes))
        let point = Data(repeating: 0x06, count: Int(cryptoScalarmult.ed25519Bytes))
        let result = try cryptoScalarmult.ed25519(n: scalar, p: point)
        #expect(result.count == Int(cryptoScalarmult.ed25519Bytes), "Result length mismatch")
    }

    @Test("ed25519 noclamp equivalence and clamping behavior")
    func testCryptoScalarmultEd25519Noclamp() throws {
        // An arbitrary scalar that differs once clamped
        let scalar = Data(repeating: 0x01, count: Int(cryptoScalarmult.ed25519ScalarBytes))
        
        // A predefined basepoint 
        let basepoint = Data([
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
        ])
        
        // Perform `crypto_scalarmult_ed25519_noclamp`
        let p = try cryptoScalarmult.ed25519Noclamp(n: scalar, p: basepoint)
        
        // Perform `crypto_scalarmult_ed25519_base_noclamp`
        let pb = try cryptoScalarmult.ed25519BaseNoclamp(n: scalar)
        
        // Perform `crypto_scalarmult_ed25519_base` (clamped version)
        let pc = try cryptoScalarmult.ed25519Base(n: scalar)
        
        // Validate results
        #expect(p == pb, "Results from noclamp and base_noclamp should match")
        #expect(pb != pc, "Results from base_noclamp and base should differ")

        // Manually clamp the scalar
        var clampedScalar = scalar
        clampedScalar[0] &= 0xF8
        clampedScalar[31] &= 0x7F
        clampedScalar[31] |= 0x40

        // Perform `crypto_scalarmult_ed25519_noclamp` with clamped scalar
        let p1 = try cryptoScalarmult.ed25519Noclamp(n: clampedScalar, p: basepoint)

        // Perform `crypto_scalarmult_ed25519` with original scalar
        let p2 = try cryptoScalarmult.ed25519(n: scalar, p: basepoint)

        // Validate that the results are identical
        #expect(p1 == p2, "Results from manually clamped and automatic clamping should match")
    }
}

