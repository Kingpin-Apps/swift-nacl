import Foundation
import Testing

@testable import SwiftNcal

@Suite("CryptoKxTests")
struct CryptoKxTests {
    let cryptoKx = Sodium().cryptoKx

    @Test("keypair generates keys with expected lengths")
    func testKeypair() throws {
        let (publicKey, secretKey) = try cryptoKx.keypair()

        #expect(publicKey.count == cryptoKx.publicKeyBytes, "Public key length mismatch")
        #expect(secretKey.count == cryptoKx.secretKeyBytes, "Secret key length mismatch")
    }

    @Test("seedKeypair generates keys with expected lengths")
    func testSeedKeypair() throws {
        let seed = Data(repeating: 0, count: cryptoKx.seedBytes)
        let (publicKey, secretKey) = try cryptoKx.seedKeypair(seed: seed)

        #expect(publicKey.count == cryptoKx.publicKeyBytes, "Public key length mismatch")
        #expect(secretKey.count == cryptoKx.secretKeyBytes, "Secret key length mismatch")
    }

    @Test("clientSessionKeys returns rx/tx keys with expected lengths")
    func testClientSessionKeys() throws {
        let (clientPublicKey, clientSecretKey) = try cryptoKx.keypair()
        let (serverPublicKey, _) = try cryptoKx.keypair()

        let (rxKey, txKey) = try cryptoKx.clientSessionKeys(
            clientPublicKey: clientPublicKey,
            clientSecretKey: clientSecretKey,
            serverPublicKey: serverPublicKey
        )

        #expect(rxKey.count == cryptoKx.sessionKeyBytes, "Receive key length mismatch")
        #expect(txKey.count == cryptoKx.sessionKeyBytes, "Transmit key length mismatch")
    }

    @Test("serverSessionKeys returns rx/tx keys with expected lengths")
    func testServerSessionKeys() throws {
        let (serverPublicKey, serverSecretKey) = try cryptoKx.keypair()
        let (clientPublicKey, _) = try cryptoKx.keypair()

        let (rxKey, txKey) = try cryptoKx.serverSessionKeys(
            serverPublicKey: serverPublicKey,
            serverSecretKey: serverSecretKey,
            clientPublicKey: clientPublicKey
        )

        #expect(rxKey.count == cryptoKx.sessionKeyBytes, "Receive key length mismatch")
        #expect(txKey.count == cryptoKx.sessionKeyBytes, "Transmit key length mismatch")
    }
}
