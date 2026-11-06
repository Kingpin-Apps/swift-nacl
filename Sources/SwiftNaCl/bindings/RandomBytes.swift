import Foundation
import Clibsodium

/// Bindings to libsodium's random number generator (`randombytes`).
public struct RandomBytes {
    /// The size of a seed for ``bufDeterministic(size:seed:)`` in bytes (32).
    public let seedBytes = Int(randombytes_seedbytes())
    
    /// Returns `size` unpredictable bytes (`randombytes`).
    ///
    /// - Parameter size: The number of bytes to generate.
    ///
    /// - Returns: The generated data.
    public func randomBytes(size: Int) -> Data {
        var buffer = [UInt8](repeating: 0, count: size)
        randombytes(&buffer, UInt64(size))
        return Data(buffer)
    }

    
    /// Returns a random 32-bit value (`randombytes_random`).
    ///
    /// - Returns: An unpredictable value between 0 and 0xffffffff (included).
    public func random() -> UInt32 {
        return randombytes_random()
    }

    
    /// Returns an unpredictable value between 0 and `upperBound` (excluded) (`randombytes_uniform`).
    ///
    /// Unlike `random() % upperBound`, it guarantees a uniform distribution of the
    /// possible output values even when `upperBound` is not a power of 2.
    ///
    /// - Parameter upperBound: The upper bound (excluded) of the returned value.
    ///
    /// - Returns: The unpredictable value.
    public func uniform(upperBound: UInt32) -> UInt32 {
        return randombytes_uniform(upperBound)
    }

    
    /// Returns `size` bytes deterministically derived from `seed` (`randombytes_buf_deterministic`).
    ///
    /// The same seed always produces the same bytes.
    ///
    /// - Parameter size: The number of bytes to generate.
    /// - Parameter seed: A 32-byte seed (``seedBytes``).
    ///
    /// - Returns: The generated data.
    /// - Throws: ``SodiumError/invalidSeedLength(_:)`` if the seed is not 32 bytes long.
    public func bufDeterministic(size: Int, seed: Data) throws -> Data {
        try ensure(seed.count == crypto_core_ed25519_bytes(), raising: .invalidSeedLength("Seed must be \(crypto_core_ed25519_bytes()) bytes long"))

        var buffer = [UInt8](repeating: 0, count: size)
        seed.withUnsafeBytes { (seedPtr: UnsafeRawBufferPointer) in
            guard let seedRawPtr = seedPtr.baseAddress else {
                return
            }
            randombytes_buf_deterministic(&buffer, size, seedRawPtr.assumingMemoryBound(to: UInt8.self))
        }
        return Data(buffer)
    }
}




