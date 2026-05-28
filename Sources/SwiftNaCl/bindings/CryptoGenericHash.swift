import Clibsodium
import Foundation

public class Blake2State {
    /// Swift-level wrapper for the crypto_generichash_blake2b state buffer
    var statebuf: Data
    var digestSize: Int

    init(digestSize: Int) {
        self.statebuf = Data(count: crypto_generichash_statebytes())
        self.digestSize = digestSize
    }

    func copy() -> Blake2State {
        let newState = Blake2State(digestSize: self.digestSize)
        newState.statebuf = self.statebuf
        return newState
    }
}

public struct CryptoGenericHash {
    public let bytes = Int(crypto_generichash_blake2b_bytes())
    public let bytesMin = Int(crypto_generichash_blake2b_bytes_min())
    public let bytesMax = Int(crypto_generichash_blake2b_bytes_max())
    public let keyBytes = Int(crypto_generichash_blake2b_keybytes())
    public let keyBytesMin = Int(crypto_generichash_blake2b_keybytes_min())
    public let keyBytesMax = Int(crypto_generichash_blake2b_keybytes_max())
    public let saltBytes = Int(crypto_generichash_blake2b_saltbytes())
    public let personalBytes = Int(crypto_generichash_blake2b_personalbytes())
    public let stateBytes = Int(crypto_generichash_statebytes())

    private let overlong = "{0} length greater than {1} bytes"
    private let tooBig = "{0} greater than {1}"

    private func checkParams(digestSize: Int, key: Data, salt: Data, person: Data) throws {
        /// Check hash parameters
        ///
        /// - Throws: Raises a `SodiumError` if the parameters are invalid.

        try ensure(
            digestSize <= bytesMax,
            raising: .valueError(String(format: tooBig, "Digest_size", bytesMax)))
        try ensure(
            key.count <= keyBytesMax,
            raising: .valueError(String(format: overlong, "Key", bytesMax)))
        try ensure(
            salt.count <= saltBytes,
            raising: .valueError(String(format: overlong, "Salt", saltBytes)))
        try ensure(
            person.count <= personalBytes,
            raising: .valueError(String(format: overlong, "Person", personalBytes)))
    }

    public func blake2bSaltPersonal(
        data: Data, digestSize: Int = crypto_generichash_blake2b_bytes(), key: Data = Data(),
        salt: Data = Data(), person: Data = Data()
    ) throws -> Data {
        /// One shot hash interface
        ///
        /// - Parameters:
        ///    - data: The input data to the hash function
        ///    - digestSize: The size of the hash digest. Must be at most `crypto_generichash_blake2b_bytes()`
        ///    - key: Must be at most `crypto_generichash_blake2b_keybytes()`
        ///    - salt: Must be at most `crypto_generichash_blake2b_saltbytes()`. Will be zero-padded if needed
        ///    - person: The personalization string.  Will be zero-padded if needed
        ///
        /// - Returns: The digest_size long digest
        /// - Throws: Raises a `SodiumError` if the parameters are invalid.
        
        try checkParams(digestSize: digestSize, key: key, salt: salt, person: person)

        var digest = Data(count: digestSize)
        var saltPadded = Data(count: saltBytes)
        var personPadded = Data(count: personalBytes)

        saltPadded.replaceSubrange(0..<salt.count, with: salt)
        personPadded.replaceSubrange(0..<person.count, with: person)
        
        let rc = data.withUnsafeBytes { (dataPtr: UnsafeRawBufferPointer) in
            digest.withUnsafeMutableBytes { (digestPtr: UnsafeMutableRawBufferPointer) in
                key.withUnsafeBytes { (keyPtr: UnsafeRawBufferPointer) in
                    saltPadded.withUnsafeMutableBytes { (saltPtr: UnsafeMutableRawBufferPointer) in
                        personPadded.withUnsafeMutableBytes { (personPtr: UnsafeMutableRawBufferPointer) in
                            guard let dataRawPtr = dataPtr.baseAddress,
                                  let digestRawPtr = digestPtr.baseAddress,
                                  let keyRawPtr = keyPtr.baseAddress,
                                  let saltRawPtr = saltPtr.baseAddress,
                                  let personRawPtr = personPtr.baseAddress else {
                                return Int32(-1)
                            }
                            return crypto_generichash_blake2b_salt_personal(
                                digestRawPtr.assumingMemoryBound(to: UInt8.self),
                                digestSize,
                                dataRawPtr.assumingMemoryBound(to: UInt8.self),
                                UInt64(data.count),
                                keyRawPtr.assumingMemoryBound(to: UInt8.self),
                                key.count,
                                saltRawPtr.assumingMemoryBound(to: UInt8.self),
                                personRawPtr.assumingMemoryBound(to: UInt8.self)
                            )
                        }
                    }
                }
            }
        }
        
        try ensure(rc == 0, raising: .runtimeError("Unexpected failure"))

        return digest
    }

    public func blake2bInit(
        key: Data = Data(), salt: Data = Data(), person: Data = Data(),
        digestSize: Int = crypto_generichash_blake2b_bytes()
    ) throws -> Blake2State {
        /// Create a new initialized blake2b hash state.
        ///
        /// - Parameters:
        ///    - key: Must be at most `crypto_generichash_blake2b_keybytes()`
        ///    - salt: Must be at most `crypto_generichash_blake2b_saltbytes()`. Will be zero-padded if needed
        ///    - person: The personalization string.  Will be zero-padded if needed
        ///    - digestSize: The size of the hash digest. Must be at most `crypto_generichash_blake2b_bytes()`
        ///
        ///
        /// - Returns: An initialized `Blake2State`
        /// - Throws: Raises a `SodiumError` if input is invalid.
        try checkParams(digestSize: digestSize, key: key, salt: salt, person: person)

        let state = Blake2State(digestSize: digestSize)
        var saltPadded = Data(count: saltBytes)
        var personPadded = Data(count: personalBytes)

        saltPadded.replaceSubrange(0..<salt.count, with: salt)
        personPadded.replaceSubrange(0..<person.count, with: person)

        let rc = key.withUnsafeBytes { (keyPtr: UnsafeRawBufferPointer) in
            saltPadded.withUnsafeMutableBytes { (saltPtr: UnsafeMutableRawBufferPointer) in
                personPadded.withUnsafeMutableBytes { (personPtr: UnsafeMutableRawBufferPointer) in
                    state.statebuf.withUnsafeMutableBytes { (statePtr: UnsafeMutableRawBufferPointer) in
                        guard let keyRawPtr = keyPtr.baseAddress,
                              let saltRawPtr = saltPtr.baseAddress,
                              let personRawPtr = personPtr.baseAddress,
                              let stateRawPtr = statePtr.baseAddress else {
                            return Int32(-1)
                        }
                        return crypto_generichash_blake2b_init_salt_personal(
                            OpaquePointer(stateRawPtr.assumingMemoryBound(to: UInt8.self)),
                            keyRawPtr.assumingMemoryBound(to: UInt8.self),
                            key.count,
                            digestSize,
                            saltRawPtr.assumingMemoryBound(to: UInt8.self),
                            personRawPtr.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
        }
            
        try ensure(rc == 0, raising: .runtimeError("Unexpected failure"))

        return state
    }

    public func blake2bUpdate(state: Blake2State, data: Data) throws {
        /// Update the blake2b hash state
        ///
        /// - Parameters:
        ///   - state: An initialized Blake2bState object as returned from `crypto_generichash_blake2b_init`
        ///   - data: The input data to the hash function
        ///
        /// - Throws: Raises a `SodiumError` if failed to update the state.

        let rc = state.statebuf.withUnsafeMutableBytes { (statePtr: UnsafeMutableRawBufferPointer) in
            data.withUnsafeBytes { (dataPtr: UnsafeRawBufferPointer) in
                guard let stateRawPtr = statePtr.baseAddress,
                      let dataRawPtr = dataPtr.baseAddress else {
                    return Int32(-1)
                }
                return crypto_generichash_blake2b_update(
                    OpaquePointer(stateRawPtr.assumingMemoryBound(to: UInt8.self)),
                    dataRawPtr.assumingMemoryBound(to: UInt8.self),
                    UInt64(data.count)
                )
            }
        }
        try ensure(rc == 0, raising: .runtimeError("Unexpected failure"))
    }

    public func blake2bFinal(state: Blake2State) throws -> Data {
        /// Finalize the blake2b hash state and return the digest.
        ///
        /// - Parameters:
        ///   - state: An initialized Blake2bState object as returned from `crypto_generichash_blake2b_init`
        /// - Returns: The blake2 digest of the passed-in data stream
        ///
        /// - Throws: Raises a `SodiumError` if failed to finalize the state.

        var digest = Data(count: bytesMax)
        
        let rc = state.statebuf.withUnsafeMutableBytes { (statePtr: UnsafeMutableRawBufferPointer) in
            digest.withUnsafeMutableBytes { (digestPtr: UnsafeMutableRawBufferPointer) in
                guard let stateRawPtr = statePtr.baseAddress,
                      let digestRawPtr = digestPtr.baseAddress else {
                    return Int32(-1)
                }
                return crypto_generichash_blake2b_final(
                    OpaquePointer(stateRawPtr.assumingMemoryBound(to: UInt8.self)),
                    digestRawPtr.assumingMemoryBound(to: UInt8.self),
                    state.digestSize
                )
            }
        }
        
        try ensure(rc == 0, raising: .runtimeError("Unexpected failure"))

        return digest
    }
}
