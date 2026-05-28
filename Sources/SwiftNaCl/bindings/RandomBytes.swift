import Foundation
import Clibsodium

public struct RandomBytes {
    public let seedBytes = Int(randombytes_seedbytes())
    
    public func randomBytes(size: Int) -> Data {
        /**
         Returns a `Bytes object of length `length` containing an unpredictable sequence of bytes.

         - Parameter size: The number of bytes to generate.

         - Returns: The generated data.
         */
        var buffer = [UInt8](repeating: 0, count: size)
        randombytes(&buffer, UInt64(size))
        return Data(buffer)
    }

    
    public func random() -> UInt32 {
        /**
         - Returns: An unpredictable value between 0 and 0xffffffff (included).
         */
        return randombytes_random()
    }

    
    public func uniform(upperBound: UInt32) -> UInt32 {
        /**
         Returns an unpredictable value between 0 and `upper_bound` (excluded). Unlike randombytes_random() % upper_bound, it does its best to guarantee a uniform distribution of the possible output values even when upper_bound is not a power of 2.

         - Parameter upperBound: The upper bound (excluded) of the returned value.

         - Returns: The unpredictable value.
         */
        return randombytes_uniform(upperBound)
    }

    
    public func bufDeterministic(size: Int, seed: Data) throws -> Data {
        /**
         Returns a deterministic stream of unbiased bits derived from a seed.

         - Parameter size: The number of bytes to generate.
         - Parameter seed: The seed.

         - Returns: The generated data.
         */
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




