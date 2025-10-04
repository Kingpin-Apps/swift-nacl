import Clibsodium
import Foundation
import BigInt

public struct CryptoPwHash {
    public let saltBytes = Int(crypto_pwhash_saltbytes())
    public let strBytes = Int(crypto_pwhash_strbytes())
    public let passwdMin = Int(crypto_pwhash_passwd_min())
    public let passwdMax = Int(crypto_pwhash_passwd_max())
    public let bytesMin = Int(crypto_pwhash_bytes_min())
    public let bytesMax = Int(crypto_pwhash_bytes_max())
    public let algArgon2i13 = Int(crypto_pwhash_alg_argon2i13())
    public let algArgon2id13 = Int(crypto_pwhash_alg_argon2id13())
    public let algDefault = Int(crypto_pwhash_alg_default())

    public let scryptsalsa208sha256Strprefix: String = String(
        cString: crypto_pwhash_scryptsalsa208sha256_strprefix())
    public let scryptsalsa208sha256Saltbytes: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_saltbytes())
    public let scryptsalsa208sha256Strbytes: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_strbytes())
    public let scryptsalsa208sha256PasswdMin: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_passwd_min())
    public let scryptsalsa208sha256PasswdMax: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_passwd_max())
    public let scryptsalsa208sha256BytesMin: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_bytes_min())
    public let scryptsalsa208sha256BytesMax: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_bytes_max())
    public let scryptsalsa208sha256MemlimitMin: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_memlimit_min())
    public let scryptsalsa208sha256MemlimitMax: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_memlimit_max())
    public let scryptsalsa208sha256OpslimitMin: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_opslimit_min())
    public let scryptsalsa208sha256OpslimitMax: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_opslimit_max())
    public let scryptsalsa208sha256OpslimitInteractive: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_opslimit_interactive())
    public let scryptsalsa208sha256MemlimitInteractive: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_memlimit_interactive())
    public let scryptsalsa208sha256OpslimitSensitive: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive())
    public let scryptsalsa208sha256MemlimitSensitive: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive())

    public let argon2iStrprefix: String = String(cString: crypto_pwhash_argon2i_strprefix())
    public let argon2iMemlimitMin: Int = Int(crypto_pwhash_argon2i_memlimit_min())
    public let argon2iMemlimitMax: Int = Int(crypto_pwhash_argon2i_memlimit_max())
    public let argon2iOpslimitMin: Int = Int(crypto_pwhash_argon2i_opslimit_min())
    public let argon2iOpslimitMax: Int = Int(crypto_pwhash_argon2i_opslimit_max())
    public let argon2iOpslimitInteractive: Int = Int(crypto_pwhash_argon2i_opslimit_interactive())
    public let argon2iMemlimitInteractive: Int = Int(crypto_pwhash_argon2i_memlimit_interactive())
    public let argon2iOpslimitModerate: Int = Int(crypto_pwhash_argon2i_opslimit_moderate())
    public let argon2iMemlimitModerate: Int = Int(crypto_pwhash_argon2i_memlimit_moderate())
    public let argon2iOpslimitSensitive: Int = Int(crypto_pwhash_argon2i_opslimit_sensitive())
    public let argon2iMemlimitSensitive: Int = Int(crypto_pwhash_argon2i_memlimit_sensitive())

    public let argon2idStrprefix: String = String(cString: crypto_pwhash_argon2id_strprefix())
    public let argon2idMemlimitMin: Int = Int(crypto_pwhash_argon2id_memlimit_min())
    public let argon2idMemlimitMax: Int = Int(crypto_pwhash_argon2id_memlimit_max())
    public let argon2idOpslimitMin: Int = Int(crypto_pwhash_argon2id_opslimit_min())
    public let argon2idOpslimitMax: Int = Int(crypto_pwhash_argon2id_opslimit_max())
    public let argon2idOpslimitInteractive: Int = Int(crypto_pwhash_argon2id_opslimit_interactive())
    public let argon2idMemlimitInteractive: Int = Int(crypto_pwhash_argon2id_memlimit_interactive())
    public let argon2idOpslimitModerate: Int = Int(crypto_pwhash_argon2id_opslimit_moderate())
    public let argon2idMemlimitModerate: Int = Int(crypto_pwhash_argon2id_memlimit_moderate())
    public let argon2idOpslimitSensitive: Int = Int(crypto_pwhash_argon2id_opslimit_sensitive())
    public let argon2idMemlimitSensitive: Int = Int(crypto_pwhash_argon2id_memlimit_sensitive())

    public let scryptOpslimitInteractive: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_opslimit_interactive())
    public let scryptMemlimitInteractive: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_memlimit_interactive())
    public let scryptOpslimitSensitive: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive())
    public let scryptMemlimitSensitive: Int = Int(
        crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive())
    public let scryptSaltbytes: Int = Int(crypto_pwhash_scryptsalsa208sha256_saltbytes())
    public let scryptStrbytes: Int = Int(crypto_pwhash_scryptsalsa208sha256_strbytes())

    public let scryptPrMax: Int = (1 << 30) - 1
    public let log2Uint64Max: Int = 63
    public let uint64Max: UInt64 = UInt64.max
    public let scryptMaxMem: Int = 32 * (1024 * 1024)

    private func checkMemoryOccupation(n: Int, r: Int, p: Int, maxmem: Int? = nil) throws {
        let maxMem = maxmem ?? scryptMaxMem

        try ensure(r != 0, raising: .valueError("Invalid block size"))
        try ensure(p != 0, raising: .valueError("Invalid parallelization factor"))
        try ensure((n & (n - 1)) == 0, raising: .valueError("Cost factor must be a power of 2"))
        try ensure(n > 1, raising: .valueError("Cost factor must be at least 2"))
        try ensure(p <= scryptPrMax / r, raising: .valueError("p*r is greater than \(scryptPrMax)"))
        try ensure(
            n < (BigInt(1) << (16 * r)),
            raising: .valueError("Cost factor is too large")
        )

        let Blen = p * 128 * r
        let i = UInt64.max / 128

        try ensure(n + 2 <= Int(i) / r, raising: .valueError("Value Error"))

        let Vlen = 32 * r * (n + 2) * 4

        try ensure(
            Blen <= UInt64.max - UInt64(Vlen),
            raising: .valueError("Value Error")
        )
        try ensure(Blen <= Int.max - Vlen, raising: .valueError("Value Error"))
        try ensure(
            Blen + Vlen <= maxMem,
            raising: .valueError("Memory limit would be exceeded with the chosen n, r, p"))
    }

    /// Swift implementation of libsodium's pickparams
    func naclBindingsPickScryptParams(opsLimit: Int, memLimit: Int) -> (Int, Int, Int) {
        var opslimit = opsLimit
        if opslimit < 32768 {
            opslimit = 32768
        }

        let r = 8
        var p: Int
        var nLog2: Int = 1

        if opslimit < (memLimit / 32) {
            p = 1
            let maxn = opslimit / (4 * r)
            for i in 1..<63 {
                if (1 << i) > (maxn / 2) {
                    nLog2 = i
                    break
                }
            }
        } else {
            let maxn = memLimit / (r * 128)
            for i in 1..<63 {
                if (1 << i) > (maxn / 2) {
                    nLog2 = i
                    break
                }
            }

            var maxrp = (opslimit / 4) / (1 << nLog2)
            if maxrp > 0x3FFF_FFFF {
                maxrp = 0x3FFF_FFFF
            }
            p = maxrp / r
        }

        return (nLog2, r, p)
    }

    /**
     Derive a cryptographic key using the `passwd` and `salt` given as input.

     The work factor can be tuned by picking different values for the parameters.

     - Parameters:
       - passwd: The input password.
       - salt: The input salt. Must be exactly `cryptoPwhashScryptsalsa208sha256Saltbytes` bytes long.
       - n: The cost factor.
       - r: The block size.
       - p: The parallelism factor.
       - dklen: The length of the derived key. Default is 64.
       - maxmem: The maximum available memory for scrypt's operations. Default is `scryptMaxMem`.
     - Returns: The derived key as `Data`.
     - Throws: `CryptoError` if any of the conditions are not met or if key derivation fails.
     */
    public func scryptsalsa208sha256LL(
        passwd: Data, salt: Data, n: Int, r: Int, p: Int, dklen: Int = 64, maxmem: Int? = nil
    ) throws -> Data {
        let maxMem = maxmem ?? scryptMaxMem

        try checkMemoryOccupation(n: n, r: r, p: p, maxmem: maxMem)

        var buf = Data(count: dklen)
        let ret = buf.withUnsafeMutableBytes { bufPtr in
            passwd.withUnsafeBytes { passwdPtr in
                salt.withUnsafeBytes { saltPtr in
                    guard let bufPtr = bufPtr.baseAddress,
                        let passwdPtr = passwdPtr.baseAddress,
                        let saltPtr = saltPtr.baseAddress
                    else {
                        return Int32(-1)
                    }
                    return crypto_pwhash_scryptsalsa208sha256_ll(
                        passwdPtr.assumingMemoryBound(to: UInt8.self),
                        passwd.count,
                        saltPtr.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        UInt64(n),
                        UInt32(r),
                        UInt32(p),
                        bufPtr.assumingMemoryBound(to: UInt8.self),
                        dklen
                    )
                }
            }
        }

        try ensure(ret == 0, raising: .runtimeError("Unexpected failure in key derivation"))

        return buf
    }

    /**
     Derive a cryptographic key using the `passwd` given as input, returning a string representation which includes the salt and the tuning parameters.

     The returned string can be directly stored as a password hash.

     - Parameters:
       - passwd: The input password.
       - opsLimit: The computational cost. Default is `scryptOpslimitInteractive`.
       - memLimit: The memory cost. Default is `scryptMemlimitInteractive`.
     - Returns: Serialized key hash, including salt and tuning parameters.
     - Throws: `CryptoError` if any of the conditions are not met or if password hashing fails.
     */
    public func scryptsalsa208sha256Str(passwd: Data, opsLimit: Int? = nil, memLimit: Int? = nil)
        throws -> String
    {
        var buf = Data(count: scryptStrbytes)
        let ret = buf.withUnsafeMutableBytes { bufPtr in
            passwd.withUnsafeBytes { passwdPtr in
                guard let bufPtr = bufPtr.baseAddress,
                    let passwdPtr = passwdPtr.baseAddress
                else {
                    return Int32(-1)
                }
                return crypto_pwhash_scryptsalsa208sha256_str(
                    bufPtr.assumingMemoryBound(to: Int8.self),
                    passwdPtr.assumingMemoryBound(to: UInt8.self),
                    UInt64(passwd.count),
                    UInt64(opsLimit ?? scryptOpslimitInteractive),
                    memLimit ?? scryptMemlimitInteractive
                )
            }
        }

        try ensure(ret == 0, raising: .runtimeError("Unexpected failure in password hashing"))

        return String(
            cString: buf.withUnsafeBytes { $0.baseAddress!.assumingMemoryBound(to: CChar.self) })
    }

    /**
     Verifies the `passwd` against the `passwd_hash` that was generated.
     Returns `true` or `false` depending on the success.

     - Parameters:
       - passwd_hash: The password hash to verify against.
       - passwd: The password to verify.
     - Returns: `true` if the password is correct, `false` otherwise.
     - Throws: `CryptoError` if any of the conditions are not met or if verification fails.
     */
    func scryptsalsa208sha256StrVerify(passwd_hash: Data, passwd: Data) throws -> Bool {

        // Remove strict length validation since different platforms may handle
        // null-terminated strings differently. The actual validation should happen
        // at the libsodium level.
        try ensure(
            !passwd_hash.isEmpty && passwd_hash.count <= scryptStrbytes, 
            raising: .valueError("Invalid password hash"))

        // Ensure the password hash data is properly null-terminated
        var nullTerminatedHash = passwd_hash
        if passwd_hash.last != 0 {
            nullTerminatedHash.append(0)
        }
        
        let ret = nullTerminatedHash.withUnsafeBytes { passwdHashPtr in
            passwd.withUnsafeBytes { passwdPtr in
                guard let passwdHashPtr = passwdHashPtr.baseAddress,
                    let passwdPtr = passwdPtr.baseAddress
                else {
                    return Int32(-1)
                }
                return crypto_pwhash_scryptsalsa208sha256_str_verify(
                    passwdHashPtr.assumingMemoryBound(to: Int8.self),
                    passwdPtr.assumingMemoryBound(to: UInt8.self),
                    UInt64(passwd.count)
                )
            }
        }

        if ret == 0 {
            return true
        } else {
            return false
        }
    }

    private func checkArgon2LimitsAlg(opslimit: Int, memlimit: Int, alg: Int) throws {
        if alg == algArgon2i13 {
            if memlimit < argon2iMemlimitMin {
                throw SodiumError.cryptoError(
                    "memlimit must be at least \(argon2iMemlimitMin) bytes")
            } else if memlimit > argon2iMemlimitMax {
                throw SodiumError.cryptoError(
                    "memlimit must be at most \(argon2iMemlimitMax)  bytes")
            }
            if opslimit < argon2iOpslimitMin {
                throw SodiumError.cryptoError("opslimit must be at least \(argon2iOpslimitMin)")
            } else if opslimit > argon2iOpslimitMax {
                throw SodiumError.cryptoError("opslimit must be at most \(argon2iOpslimitMax)")
            }
        } else if alg == algArgon2id13 {
            if memlimit < argon2idMemlimitMin {
                throw SodiumError.cryptoError(
                    "memlimit must be at least \(argon2idMemlimitMin) bytes")
            } else if memlimit > argon2idMemlimitMax {
                throw SodiumError.cryptoError(
                    "memlimit must be at most \(argon2idMemlimitMax) bytes")
            }
            if opslimit < argon2idOpslimitMin {
                throw SodiumError.cryptoError("opslimit must be at least \(argon2idOpslimitMin)")
            } else if opslimit > argon2idOpslimitMax {
                throw SodiumError.cryptoError("opslimit must be at most \(argon2idOpslimitMax)")
            }
        } else {
            throw SodiumError.typeError("Unsupported algorithm")
        }
    }

    /**
     Derive a raw cryptographic key using the `passwd` and the `salt` given as input to the `alg` algorithm.

     - Parameters:
       - outlen: The length of the derived key.
       - passwd: The input password.
       - salt: The input salt.
       - opslimit: The computational cost.
       - memlimit: The memory cost.
       - alg: The algorithm identifier.
     - Returns: The derived key as `Data`.
     - Throws: `CryptoError` if any of the conditions are not met or if key derivation fails.
     */
    public func alg(
        outlen: Int, passwd: Data, salt: Data, opslimit: Int, memlimit: Int, alg: Int
    ) throws -> Data {

        try ensure(
            outlen >= bytesMin && outlen <= bytesMax,
            raising: .valueError(
                "Derived key must be between \(bytesMin) and \(bytesMax) bytes long"))
        try ensure(
            salt.count == saltBytes,
            raising: .valueError("Salt must be exactly \(saltBytes) bytes long"))

        try checkArgon2LimitsAlg(opslimit: opslimit, memlimit: memlimit, alg: alg)

        var outbuf = Data(count: outlen)
        let ret = outbuf.withUnsafeMutableBytes { outbufPtr in
            passwd.withUnsafeBytes { passwdPtr in
                salt.withUnsafeBytes { saltPtr in
                    guard let outbufPtr = outbufPtr.baseAddress,
                        let passwdPtr = passwdPtr.baseAddress,
                        let saltPtr = saltPtr.baseAddress
                    else {
                        return Int32(-1)
                    }
                    return crypto_pwhash(
                        outbufPtr.assumingMemoryBound(to: UInt8.self),
                        UInt64(outlen),
                        passwdPtr.assumingMemoryBound(to: UInt8.self),
                        UInt64(passwd.count),
                        saltPtr.assumingMemoryBound(to: UInt8.self),
                        UInt64(opslimit),
                        size_t(memlimit),
                        Int32(alg)
                    )
                }
            }
        }

        try ensure(ret == 0, raising: .runtimeError("Unexpected failure in key derivation"))

        return outbuf
    }

    /**
     Derive a cryptographic key using the `passwd` given as input and a random salt, returning a string representation which includes the salt, the tuning parameters, and the used algorithm.

     - Parameters:
       - passwd: The input password.
       - opslimit: The computational cost.
       - memlimit: The memory cost.
       - alg: The algorithm to use.
     - Returns: Serialized derived key and parameters as `Data`.
     - Throws: `CryptoError` if any of the conditions are not met or if key derivation fails.
     */
    func strAlg(passwd: Data, opslimit: Int, memlimit: Int, alg: Int) throws -> Data {

        try checkArgon2LimitsAlg(opslimit: opslimit, memlimit: memlimit, alg: alg)

        var outbuf = Data(count: 128)
        let ret = outbuf.withUnsafeMutableBytes { outbufPtr in
            passwd.withUnsafeBytes { passwdPtr in
                guard let outbufPtr = outbufPtr.baseAddress,
                    let passwdPtr = passwdPtr.baseAddress
                else {
                    return Int32(-1)
                }
                return crypto_pwhash_str_alg(
                    outbufPtr.assumingMemoryBound(to: Int8.self),
                    passwdPtr.assumingMemoryBound(to: UInt8.self),
                    UInt64(passwd.count),
                    UInt64(opslimit),
                    size_t(memlimit),
                    Int32(alg)
                )
            }
        }

        try ensure(ret == 0, raising: .runtimeError("Unexpected failure in key derivation"))

        return outbuf
    }

    /**
     Verifies the `passwd` against a given password hash.

     Returns `true` on success, throws `CryptoError.invalidKeyError` on failure.

     - Parameters:
       - passwd_hash: The saved password hash.
       - passwd: The password to be checked.
     - Returns: `true` if the password is correct.
     - Throws: `CryptoError` if any of the conditions are not met or if verification fails.
     */
    func strVerify(passwd_hash: Data, passwd: Data) throws -> Bool {
        try ensure(
            passwd_hash.count <= 128, raising: .valueError("Hash must be at most 128 bytes long"))

        let ret = passwd_hash.withUnsafeBytes { passwdHashPtr in
            passwd.withUnsafeBytes { passwdPtr in
                guard let passwdHashPtr = passwdHashPtr.baseAddress,
                    let passwdPtr = passwdPtr.baseAddress
                else {
                    return Int32(-1)
                }
                return crypto_pwhash_str_verify(
                    passwdHashPtr.assumingMemoryBound(to: Int8.self),
                    passwdPtr.assumingMemoryBound(to: UInt8.self),
                    UInt64(passwd.count)
                )
            }
        }

        if ret == 0 {
            return true
        } else {
            return false
        }
    }
}
