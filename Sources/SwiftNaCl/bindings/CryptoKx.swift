/// Implementations of client, server key exchange
import Clibsodium
import Foundation

public struct CryptoKx {
    let publicKeyBytes = Int(crypto_kx_publickeybytes())
    let secretKeyBytes = Int(crypto_kx_secretkeybytes())
    let seedBytes = Int(crypto_kx_seedbytes())
    let sessionKeyBytes = Int(crypto_kx_sessionkeybytes())
    
    func keypair() throws -> (publicKey: Data, secretKey: Data) {
        /// Generate a key pair.
        ///
        /// - Note: This is a duplicate crypto_box_keypair, but is included for api consistency.
        ///
        /// - Returns: Tuple containing the public and secret keys.
        /// - Throws: Raises a `SodiumError` if key generation fails.
        
        var publicKey = Data(count: publicKeyBytes)
        var secretKey = Data(count: secretKeyBytes)
        
        let res = publicKey.withUnsafeMutableBytes { publicKeyPtr in
            secretKey.withUnsafeMutableBytes { secretKeyPtr in
                guard let publicKeyRawPtr = publicKeyPtr.baseAddress,
                      let secretKeyRawPtr = secretKeyPtr.baseAddress else {
                    return Int32(-1)
                }
                return crypto_kx_keypair(
                    publicKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                    secretKeyRawPtr.assumingMemoryBound(to: UInt8.self)
                )
            }
        }

        try ensure(res == 0, raising: .cryptoError("Key generation failed."))
        return (publicKey, secretKey)
    }

    func seedKeypair(seed: Data) throws -> (publicKey: Data, secretKey: Data) {
        /// Returns a (public, secret) key pair deterministically generated from an input ``seed``.
        /// - Note: This is functionally the same as crypto_box_seed_keypair, however it uses the blake2b hash primitive instead of sha512.
        /// It is included mainly for api consistency when using crypto_kx.
        ///
        /// - Parameters:
        ///     - seed: `Data`
        ///
        /// - Returns: A tuple containing the public key and secret key.
        /// - Throws: Raises a `SodiumError` if keypair generation fails.
        
        try ensure(
            seed.count == seedBytes,
            raising: .valueError("Seed must be a \(seedBytes) byte long Data sequence")
        )
        
        var publicKey = Data(count: publicKeyBytes)
        var secretKey = Data(count: secretKeyBytes)
        
        let res = publicKey.withUnsafeMutableBytes { (pkPtr: UnsafeMutableRawBufferPointer) in
            secretKey.withUnsafeMutableBytes { (skPtr: UnsafeMutableRawBufferPointer) in
                seed.withUnsafeBytes { (seedPtr: UnsafeRawBufferPointer) in
                    guard let pkRawPtr = pkPtr.baseAddress,
                        let skRawPtr = skPtr.baseAddress,
                        let seedRawPtr = seedPtr.baseAddress
                    else {
                        return Int32(-1)
                    }
                    return crypto_kx_seed_keypair(
                        pkRawPtr.assumingMemoryBound(to: UInt8.self),
                        skRawPtr.assumingMemoryBound(to: UInt8.self),
                        seedRawPtr.assumingMemoryBound(to: UInt8.self))
                }
            }
        }
        
        try ensure(res == 0, raising: .cryptoError("Key generation failed."))
        return (publicKey, secretKey)
    }

    func clientSessionKeys(clientPublicKey: Data, clientSecretKey: Data, serverPublicKey: Data) throws -> (rxKey: Data, txKey: Data) {
        /// Generate session keys for the client.
        ///
        /// - Parameters:
        ///     - clientPublicKey: The client's public key.
        ///     - clientSecretKey: The client's secret key.
        ///     - serverPublicKey: The server's public key.
        ///
        /// - Returns: A tuple containing the receive and transmit keys.
        /// - Throws: Raises a `SodiumError` if input is invalid or key generation fails.
        
        try ensure(
            clientPublicKey.count == publicKeyBytes,
            raising: .valueError("Client public key must be a \(publicKeyBytes) bytes long Data sequence")
        )
        try ensure(
            clientSecretKey.count == secretKeyBytes,
            raising: .valueError("Client secret key must be a \(secretKeyBytes) bytes long Data sequence")
        )
        try ensure(
            serverPublicKey.count == publicKeyBytes,
            raising: .valueError("Server public key must be a \(publicKeyBytes) bytes long Data sequence")
        )
        
        var rxKey = Data(count: sessionKeyBytes)
        var txKey = Data(count: sessionKeyBytes)
        
        let res = rxKey.withUnsafeMutableBytes { rxKeyPtr in
            txKey.withUnsafeMutableBytes { txKeyPtr in
                clientPublicKey.withUnsafeBytes { clientPublicKeyPtr in
                    clientSecretKey.withUnsafeBytes { clientSecretKeyPtr in
                        serverPublicKey.withUnsafeBytes { serverPublicKeyPtr in
                            guard let rxKeyRawPtr = rxKeyPtr.baseAddress,
                                  let txKeyRawPtr = txKeyPtr.baseAddress,
                                  let clientPublicKeyRawPtr = clientPublicKeyPtr.baseAddress,
                                  let clientSecretKeyRawPtr = clientSecretKeyPtr.baseAddress,
                                  let serverPublicKeyRawPtr = serverPublicKeyPtr.baseAddress
                            else {
                                return Int32(-1)
                            }
                            return crypto_kx_client_session_keys(
                                rxKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                                txKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                                clientPublicKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                                clientSecretKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                                serverPublicKeyRawPtr.assumingMemoryBound(to: UInt8.self)
                            )
                        }
                    }
                }
            }
        }
        
        try ensure(res == 0, raising: .cryptoError("Client session key generation failed."))
        return (rxKey, txKey)
    }

    func serverSessionKeys(serverPublicKey: Data, serverSecretKey: Data, clientPublicKey: Data) throws -> (rxKey: Data, txKey: Data) {
        /// Generate session keys for the server.
        ///
        /// - Parameters:
        ///    - serverPublicKey: The server's public key.
        ///    - serverSecretKey: The server's secret key.
        ///    - clientPublicKey: The client's public key.
        ///
        /// - Returns: A tuple containing the receive and transmit keys.
        /// - Throws: Raises a `SodiumError` if input is invalid or key generation fails.
        
        try ensure(
            serverPublicKey.count == publicKeyBytes,
            raising: .valueError("Server public key must be a \(publicKeyBytes) bytes long Data sequence")
        )
        try ensure(
            serverSecretKey.count == secretKeyBytes,
            raising: .valueError("Server secret key must be a \(secretKeyBytes) bytes long Data sequence")
        )
        try ensure(
            clientPublicKey.count == publicKeyBytes,
            raising: .valueError("Client public key must be a \(publicKeyBytes) bytes long Data sequence")
        )
        
        var rxKey = Data(count: sessionKeyBytes)
        var txKey = Data(count: sessionKeyBytes)
        
        let res = rxKey.withUnsafeMutableBytes { rxKeyPtr in
            txKey.withUnsafeMutableBytes { txKeyPtr in
                serverPublicKey.withUnsafeBytes { serverPublicKeyPtr in
                    serverSecretKey.withUnsafeBytes { serverSecretKeyPtr in
                        clientPublicKey.withUnsafeBytes { clientPublicKeyPtr in
                            guard let rxKeyRawPtr = rxKeyPtr.baseAddress,
                                  let txKeyRawPtr = txKeyPtr.baseAddress,
                                  let serverPublicKeyRawPtr = serverPublicKeyPtr.baseAddress,
                                  let serverSecretKeyRawPtr = serverSecretKeyPtr.baseAddress,
                                  let clientPublicKeyRawPtr = clientPublicKeyPtr.baseAddress
                            else {
                                return Int32(-1)
                            }
                            return crypto_kx_server_session_keys(
                                rxKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                                txKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                                serverPublicKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                                serverSecretKeyRawPtr.assumingMemoryBound(to: UInt8.self),
                                clientPublicKeyRawPtr.assumingMemoryBound(to: UInt8.self)
                            )
                        }
                    }
                }
            }
        }
        
        try ensure(
            res == 0,
            raising: .cryptoError("Server session key generation failed.")
        )
        return (rxKey, txKey)
    }
}
