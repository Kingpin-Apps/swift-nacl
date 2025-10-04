import Testing

@testable import SwiftNcal

@Suite("SodiumError equality and ensure() behavior")
struct SodiumErrorTests {

    @Test("equates and differentiates SodiumError cases by value")
    func testSodiumErrorEquatable() async throws {
        #expect(
            SodiumError.badSignatureError("error") == SodiumError.badSignatureError("error")
        )
        #expect(
            SodiumError.badSignatureError("error1") != SodiumError.badSignatureError("error2")
        )

        #expect(SodiumError.cryptoError("error") == SodiumError.cryptoError("error"))
        #expect(SodiumError.cryptoError("error1") != SodiumError.cryptoError("error2"))

        #expect(SodiumError.cryptPrefixError("error") == SodiumError.cryptPrefixError("error"))
        #expect(
            SodiumError.cryptPrefixError("error1") != SodiumError.cryptPrefixError("error2")
        )

        #expect(SodiumError.invalidKeyError("error") == SodiumError.invalidKeyError("error"))
        #expect(
            SodiumError.invalidKeyError("error1") != SodiumError.invalidKeyError("error2")
        )

        #expect(SodiumError.invalidSeedLength("error") == SodiumError.invalidSeedLength("error"))
        #expect(
            SodiumError.invalidSeedLength("error1") != SodiumError.invalidSeedLength("error2")
        )

        #expect(SodiumError.runtimeError("error") == SodiumError.runtimeError("error"))
        #expect(SodiumError.runtimeError("error1") != SodiumError.runtimeError("error2"))

        #expect(SodiumError.typeError("error") == SodiumError.typeError("error"))
        #expect(SodiumError.typeError("error1") != SodiumError.typeError("error2"))

        #expect(SodiumError.unavailableError("error") == SodiumError.unavailableError("error"))
        #expect(
            SodiumError.unavailableError("error1") != SodiumError.unavailableError("error2")
        )

        #expect(SodiumError.valueError("error") == SodiumError.valueError("error"))
        #expect(SodiumError.valueError("error1") != SodiumError.valueError("error2"))
    }

    @Test("ensure(_:raising:) throws the provided error when condition is false and not when true")
    func testEnsureFunction() async throws {
        // Should not throw
        try ensure(true, raising: .runtimeError("This should not throw"))

        // Should throw runtimeError
        #expect(throws: SodiumError.runtimeError("This should throw")) {
            try ensure(false, raising: .runtimeError("This should throw"))
        }

        // Should throw valueError
        #expect(throws: SodiumError.valueError("Value error")) {
            try ensure(false, raising: .valueError("Value error"))
        }

        // Should throw cryptoError
        #expect(throws: SodiumError.cryptoError("Crypto error")) {
            try ensure(false, raising: .cryptoError("Crypto error"))
        }
    }
}
