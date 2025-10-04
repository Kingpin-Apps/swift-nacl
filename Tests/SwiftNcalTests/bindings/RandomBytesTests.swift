import Foundation
import Testing

@testable import SwiftNcal

@Suite("Random Bytes Tests") struct RandomBytesTests {
    let randomBytes = Sodium().randomBytes

    @Test("randomBytes generates the requested number of bytes")
    func testRandomBytesGeneratesCorrectSize() async throws {
        let size = 32
        let randomData = randomBytes.randomBytes(size: size)

        #expect(randomData.count == size, "randomBytes did not generate the correct number of bytes")
    }

    @Test("randomBytes produces different values across calls")
    func testRandomBytesGeneratesUniqueValues() async throws {
        let size = 32
        let randomData1 = randomBytes.randomBytes(size: size)
        let randomData2 = randomBytes.randomBytes(size: size)

        #expect(randomData1 != randomData2, "randomBytes generated identical values for different calls")
    }

    @Test("bufDeterministic generates the requested number of bytes")
    func testRandomBytesBufDeterministicGeneratesCorrectSize() async throws {
        let size = 32
        let seed = Data(repeating: 1, count: randomBytes.seedBytes)

        let deterministicData = try randomBytes.bufDeterministic(size: size, seed: seed)

        #expect(deterministicData.count == size, "randomBytesBufDeterministic did not generate the correct number of bytes")
    }

    @Test("bufDeterministic same seed produces same output")
    func testRandomBytesBufDeterministicWithSameSeedProducesSameOutput() async throws {
        let size = 32
        let seed = Data(repeating: 1, count: randomBytes.seedBytes)

        let deterministicData1 = try randomBytes.bufDeterministic(size: size, seed: seed)
        let deterministicData2 = try randomBytes.bufDeterministic(size: size, seed: seed)

        #expect(deterministicData1 == deterministicData2, "randomBytesBufDeterministic with the same seed produced different outputs")
    }

    @Test("bufDeterministic different seeds produce different outputs")
    func testRandomBytesBufDeterministicWithDifferentSeedsProducesDifferentOutput() async throws {
        let size = 32
        let seed1 = Data(repeating: 1, count: randomBytes.seedBytes)
        let seed2 = Data(repeating: 2, count: randomBytes.seedBytes)

        let deterministicData1 = try randomBytes.bufDeterministic(size: size, seed: seed1)
        let deterministicData2 = try randomBytes.bufDeterministic(size: size, seed: seed2)

        #expect(deterministicData1 != deterministicData2, "randomBytesBufDeterministic with different seeds produced the same output")
    }

    @Test("bufDeterministic throws for invalid seed length")
    func testRandomBytesBufDeterministicThrowsErrorForInvalidSeedLength() async throws {
        let size = 32
        let invalidSeed = Data(repeating: 1, count: randomBytes.seedBytes - 1)  // Invalid seed length
        
        #expect(throws: SodiumError.invalidSeedLength("Seed must be \(randomBytes.seedBytes) bytes long")) {
            try randomBytes.bufDeterministic(size: size, seed: invalidSeed)
        }
    }

    @Test("random returns value in 32-bit range")
    func testRandom() async throws {
        let randomValue = randomBytes.random()
        #expect(randomValue >= 0 && randomValue <= 0xffff_ffff, "Random value out of bounds")
    }

    @Test("uniform returns value within upperBound")
    func testUniform() async throws {
        let upperBound: UInt32 = 100
        let uniformValue = randomBytes.uniform(upperBound: upperBound)
        #expect(uniformValue >= 0 && uniformValue < upperBound, "Uniform value out of bounds")
    }

    @Test("uniform with power-of-two upperBound returns value within bound")
    func testUniformWithPowerOfTwoUpperBound() async throws {
        let upperBound: UInt32 = 128
        let uniformValue = randomBytes.uniform(upperBound: upperBound)
        #expect(uniformValue >= 0 && uniformValue < upperBound, "Uniform value out of bounds for power of two upper bound")
    }

    @Test("uniform with non-power-of-two upperBound returns value within bound")
    func testUniformWithNonPowerOfTwoUpperBound() async throws {
        let upperBound: UInt32 = 150
        let uniformValue = randomBytes.uniform(upperBound: upperBound)
        #expect(uniformValue >= 0 && uniformValue < upperBound, "Uniform value out of bounds for non-power of two upper bound")
    }
}
