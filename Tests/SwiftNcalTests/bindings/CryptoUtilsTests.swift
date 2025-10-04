import Testing
import Foundation
@testable import SwiftNcal

@Suite("Crypto Utility Tests")
struct CryptoUtilityTests {
    let utils = Sodium().utils

    // MARK: - sodiumMemcmp Tests
    
    @Test("sodiumMemcmp returns true for identical data")
    func testSodiumMemcmpIdenticalData() async throws {
        let data1 = Data([0x01, 0x02, 0x03])
        let data2 = Data([0x01, 0x02, 0x03])
        
        #expect(utils.sodiumMemcmp(data1, data2), "sodiumMemcmp failed to recognize identical data")
    }
    
    @Test("sodiumMemcmp returns false for different data")
    func testSodiumMemcmpDifferentData() async throws {
        let data1 = Data([0x01, 0x02, 0x03])
        let data2 = Data([0x01, 0x02, 0x04])
        
        #expect(!utils.sodiumMemcmp(data1, data2), "sodiumMemcmp failed to distinguish different data")
    }
    
    @Test("sodiumMemcmp returns false for different lengths")
    func testSodiumMemcmpDifferentLengths() async throws {
        let data1 = Data([0x01, 0x02])
        let data2 = Data([0x01, 0x02, 0x03])
        
        #expect(!utils.sodiumMemcmp(data1, data2), "sodiumMemcmp failed to handle inputs of different lengths")
    }
    
    // MARK: - sodiumPad Tests
    
    @Test("sodiumPad pads to blocksize and preserves prefix")
    func testSodiumPad() async throws {
        let input = Data([0x01, 0x02, 0x03])
        let blocksize = 8
        let padded = try utils.sodiumPad(input, blocksize: blocksize)
        
        #expect(padded.count % blocksize == 0, "Padded data is not a multiple of the block size")
        #expect(padded.starts(with: input), "Padded data does not start with the input data")
    }
    
    @Test("sodiumPad throws for invalid block size")
    func testSodiumPadInvalidBlocksize() async throws {
        let input = Data([0x01, 0x02, 0x03])
        
        #expect(throws: Error.self, "sodiumPad did not throw error for invalid block size") { try utils.sodiumPad(input, blocksize: 0) }
    }
    
    // MARK: - sodiumUnpad Tests
    
    @Test("sodiumUnpad removes padding correctly")
    func testSodiumUnpad() async throws {
        let input = Data([0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00])
        let blocksize = 8
        let unpadded = try utils.sodiumUnpad(input, blocksize: blocksize)
        
        #expect(unpadded == Data([0x01, 0x02, 0x03]), "sodiumUnpad did not correctly remove padding")
    }
    
    @Test("sodiumUnpad throws for invalid padding")
    func testSodiumUnpadInvalidPadding() async throws {
        let input = Data([0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00])
        let blocksize = 8
        
        #expect(throws: Error.self, "sodiumUnpad did not throw error for invalid padding") { try utils.sodiumUnpad(input, blocksize: blocksize) }
    }
    
    // MARK: - sodiumIncrement Tests
    
    @Test("sodiumIncrement increments little-endian buffer")
    func testSodiumIncrement() async throws {
        let input = Data([0xFF, 0x00, 0x01])
        let incremented = utils.sodiumIncrement(input)
        
        #expect(incremented == Data([0x00, 0x01, 0x01]), "sodiumIncrement did not produce the expected result")
    }
    
    // MARK: - sodiumAdd Tests
    
    @Test("sodiumAdd sums buffers element-wise")
    func testSodiumAdd() async throws {
        let data1 = Data([0x01, 0x02, 0x03])
        let data2 = Data([0x04, 0x05, 0x06])
        let result = utils.sodiumAdd(data1, data2)
        
        #expect(result == Data([0x05, 0x07, 0x09]), "sodiumAdd did not produce the expected result")
    }
    
    @Test("sodiumAdd handles carry-over correctly")
    func testSodiumAddWithCarry() async throws {
        let data1 = Data([0xFF, 0xFF, 0xFF])
        let data2 = Data([0x01, 0x00, 0x00])
        let result = utils.sodiumAdd(data1, data2)
        
        #expect(result == Data([0x00, 0x00, 0x00]), "sodiumAdd did not correctly handle carry-over")
    }
}
