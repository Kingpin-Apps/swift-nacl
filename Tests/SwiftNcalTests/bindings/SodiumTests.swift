import Testing

@testable import SwiftNcal

@Suite("Sodium Tests")
struct SodiumTests {
    @Test("Sodium library initializes correctly")
    func testSodiumInit() async throws {
        let sodium = Sodium()
        // Test that the Sodium instance is created successfully by using a simple operation
        let randomData = sodium.randomBytes.randomBytes(size: 16)
        #expect(randomData.count == 16, "Sodium should be properly initialized and functional")
    }
}
