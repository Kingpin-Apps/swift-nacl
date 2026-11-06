import Clibsodium
import Foundation

/// Bindings to libsodium's client-server key exchange (`crypto_kx`).
///
/// Both sides derive a pair of shared session keys: one for receiving (`rxKey`)
/// and one for transmitting (`txKey`).
public struct CryptoKx {
    /// The size of a public key in bytes (32).
    public let publicKeyBytes = Int(crypto_kx_publickeybytes())
    /// The size of a secret key in bytes (32).
    public let secretKeyBytes = Int(crypto_kx_secretkeybytes())
    /// The size of a seed for ``seedKeypair(seed:)`` in bytes (32).
    public let seedBytes = Int(crypto_kx_seedbytes())
    /// The size of each session key in bytes (32).
    public let sessionKeyBytes = Int(crypto_kx_sessionkeybytes())
    
    /// Generates a random key-exchange key pair (`crypto_kx_keypair`).
    ///
    /// - Note: This duplicates `crypto_box_keypair`, but is included for API consistency.
    ///
    /// - Returns: A tuple containing the public key and secret key.
    /// - Throws: A ``SodiumError`` if key generation fails.
    public func keypair() throws -> (publicKey: Data, secretKey: Data) {
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

    /// Returns a key pair deterministically generated from `seed` (`crypto_kx_seed_keypair`).
    ///
    /// - Note: This is functionally the same as `crypto_box_seed_keypair`, but it uses
    ///   the BLAKE2b hash primitive instead of SHA-512. It is included mainly for API
    ///   consistency when using `crypto_kx`.
    ///
    /// - Parameter seed: A ``seedBytes``-byte (32) seed.
    ///
    /// - Returns: A tuple containing the public key and secret key.
    /// - Throws: A ``SodiumError`` if keypair generation fails.
    public func seedKeypair(seed: Data) throws -> (publicKey: Data, secretKey: Data) {
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

    /// Computes the client's session keys (`crypto_kx_client_session_keys`).
    ///
    /// The client's `rxKey` equals the server's `txKey`, and vice versa.
    ///
    /// - Parameters:
    ///   - clientPublicKey: The client's public key.
    ///   - clientSecretKey: The client's secret key.
    ///   - serverPublicKey: The server's public key.
    ///
    /// - Returns: A tuple containing the receive and transmit keys.
    /// - Throws: A ``SodiumError`` if input is invalid or key generation fails.
    public func clientSessionKeys(clientPublicKey: Data, clientSecretKey: Data, serverPublicKey: Data) throws -> (rxKey: Data, txKey: Data) {
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

    /// Computes the server's session keys (`crypto_kx_server_session_keys`).
    ///
    /// The server's `rxKey` equals the client's `txKey`, and vice versa.
    ///
    /// - Parameters:
    ///   - serverPublicKey: The server's public key.
    ///   - serverSecretKey: The server's secret key.
    ///   - clientPublicKey: The client's public key.
    ///
    /// - Returns: A tuple containing the receive and transmit keys.
    /// - Throws: A ``SodiumError`` if input is invalid or key generation fails.
    public func serverSessionKeys(serverPublicKey: Data, serverSecretKey: Data, clientPublicKey: Data) throws -> (rxKey: Data, txKey: Data) {
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
