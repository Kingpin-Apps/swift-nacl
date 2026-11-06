import Foundation
import Clibsodium

/// Bindings to libsodium's low-level edwards25519 point and scalar arithmetic
/// (`crypto_core_ed25519_*`).
///
/// `L` below is the order of the main subgroup.
public struct CryptoCore {
    /// The size of an encoded point in bytes (32).
    public let ed25519Bytes = crypto_core_ed25519_bytes()
    /// The size of a reduced scalar in bytes (32).
    public let ed25519ScalarBytes = crypto_core_ed25519_scalarbytes()
    /// The size of a non-reduced scalar accepted by ``ed25519ScalarReduce(_:)`` in bytes (64).
    public let ed25519NonReducedScalarBytes = crypto_core_ed25519_nonreducedscalarbytes()
    
    
    /// Checks whether `p` represents a point on the edwards25519 curve, in canonical form, on the main subgroup, and that the point doesn't have a small order.
    ///
    /// - Parameters:
    ///   - p: A 32-byte point on the edwards25519 curve.
    ///
    /// - Returns: `true` if `p` is a valid point.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519IsValidPoint(_ p: Data) throws -> Bool {
        try ensure(p.count == ed25519Bytes, raising: .typeError("Point must be a \(ed25519Bytes) long bytes sequence"))
        
        let result = crypto_core_ed25519_is_valid_point([UInt8](p))
        return result == 1
    }
    
    /// Maps a 32-byte vector `r` to a point. The point is guaranteed to be on the main subgroup. This function directly exposes the Elligator 2 map, uses the high bit to set the sign of the X coordinate, and the resulting point is multiplied by the cofactor.
    ///
    /// - Parameters:
    ///   - r: 32 bytes of arbitrary data.
    ///
    /// - Returns: A 32-byte point on the main subgroup of the edwards25519 curve.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519FromUniform(_ r: Data) throws -> Data {
        try ensure(r.count == ed25519Bytes, raising: .typeError("Input must be a \(ed25519Bytes) long bytes sequence"))
        
        var p = [UInt8](repeating: 0, count: Int(ed25519Bytes))
        let result = crypto_core_ed25519_from_uniform(&p, [UInt8](r))
        
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(p.prefix(Int(ed25519Bytes)))
    }
    
    /// Adds two points on the edwards25519 curve.
    ///
    /// - Parameters:
    ///   - p: A 32-byte point on the edwards25519 curve.
    ///   - q: A 32-byte point on the edwards25519 curve.
    ///
    /// - Returns: A 32-byte point on the main subgroup of the edwards25519 curve.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519Add(_ p: Data, _ q: Data) throws -> Data {
        try ensure(p.count == ed25519Bytes && q.count == ed25519Bytes, raising: .typeError("Each point must be a \(ed25519Bytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519Bytes))
        let result = crypto_core_ed25519_add(&r, [UInt8](p), [UInt8](q))
        
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(r.prefix(Int(ed25519Bytes)))
    }
    
    /// Subtracts a point from another on the edwards25519 curve.
    ///
    /// - Parameters:
    ///   - p: A 32-byte point on the edwards25519 curve.
    ///   - q: A 32-byte point on the edwards25519 curve.
    ///
    /// - Returns: A 32-byte point on the main subgroup of the edwards25519 curve.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519Sub(_ p: Data, _ q: Data) throws -> Data {
        try ensure(p.count == ed25519Bytes && q.count == ed25519Bytes, raising: .typeError("Each point must be a \(ed25519Bytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519Bytes))
        let result = crypto_core_ed25519_sub(&r, [UInt8](p), [UInt8](q))
        
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(r.prefix(Int(ed25519Bytes)))
    }
    
    /// Returns the multiplicative inverse of integer `s` modulo `L`, i.e an integer `i` such that `s * i = 1 (mod L)`, where `L` is the order of the main subgroup.
    ///
    /// - Parameters:
    ///   - s: A 32-byte scalar (little-endian integer).
    ///
    /// - Returns: A 32-byte scalar.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519ScalarInvert(_ s: Data) throws -> Data {
        try ensure(s.count == ed25519ScalarBytes, raising: .typeError("Integer s must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519ScalarBytes))
        let result = crypto_core_ed25519_scalar_invert(&r, [UInt8](s))
        
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(r.prefix(Int(ed25519ScalarBytes)))
    }
    
    /// Returns the integer `n` such that `s + n = 0 (mod L)`, where `L` is the order of the main subgroup.
    ///
    /// - Parameters:
    ///   - s: A 32-byte scalar (little-endian integer).
    ///
    /// - Returns: A 32-byte scalar.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519ScalarNegate(_ s: Data) throws -> Data {
        try ensure(s.count == ed25519ScalarBytes, raising: .typeError("Integer s must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519ScalarBytes))
        crypto_core_ed25519_scalar_negate(&r, [UInt8](s))
        return Data(r.prefix(Int(ed25519ScalarBytes)))
    }
    
    /// Returns the complement of integer `s` modulo `L`, i.e. an integer `c` such that `s + c = 1 (mod L)`, where `L` is the order of the main subgroup.
    ///
    /// - Parameters:
    ///   - s: A 32-byte scalar (little-endian integer).
    ///
    /// - Returns: A 32-byte scalar.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519ScalarComplement(_ s: Data) throws -> Data {
        try ensure(s.count == ed25519ScalarBytes, raising: .typeError("Integer s must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519ScalarBytes))
        crypto_core_ed25519_scalar_complement(&r, [UInt8](s))
        return Data(r.prefix(Int(ed25519ScalarBytes)))
    }
    
    /// Adds integers `p` and `q` modulo `L`, where `L` is the order of the main subgroup.
    ///
    /// - Parameters:
    ///   - p: A 32-byte scalar (little-endian integer).
    ///   - q: A 32-byte scalar (little-endian integer).
    ///
    /// - Returns: A 32-byte scalar.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519ScalarAdd(_ p: Data, _ q: Data) throws -> Data {
        try ensure(p.count == ed25519ScalarBytes && q.count == ed25519ScalarBytes, raising: .typeError("Each point must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519ScalarBytes))
        crypto_core_ed25519_scalar_add(&r, [UInt8](p), [UInt8](q))
        return Data(r.prefix(Int(ed25519ScalarBytes)))
    }
    
    /// Subtracts integers `p` and `q` modulo `L`, where `L` is the order of the main subgroup.
    ///
    /// - Parameters:
    ///   - p: A 32-byte scalar (little-endian integer).
    ///   - q: A 32-byte scalar (little-endian integer).
    ///
    /// - Returns: A 32-byte scalar.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519ScalarSub(_ p: Data, _ q: Data) throws -> Data {
        try ensure(p.count == ed25519ScalarBytes && q.count == ed25519ScalarBytes, raising: .typeError("Each point must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519ScalarBytes))
        crypto_core_ed25519_scalar_sub(&r, [UInt8](p), [UInt8](q))
        return Data(r.prefix(Int(ed25519ScalarBytes)))
    }
    
    /// Multiplies integers `p` and `q` modulo `L`, where `L` is the order of the main subgroup.
    ///
    /// - Parameters:
    ///   - p: A 32-byte scalar (little-endian integer).
    ///   - q: A 32-byte scalar (little-endian integer).
    ///
    /// - Returns: A 32-byte scalar.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519ScalarMul(_ p: Data, _ q: Data) throws -> Data {
        try ensure(p.count == ed25519ScalarBytes && q.count == ed25519ScalarBytes, raising: .typeError("Each point must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519ScalarBytes))
        crypto_core_ed25519_scalar_mul(&r, [UInt8](p), [UInt8](q))
        return Data(r.prefix(Int(ed25519ScalarBytes)))
    }
    
    /// Reduces integer `s` to `s` modulo `L`, where `L` is the order of the main subgroup.
    ///
    /// - Parameters:
    ///   - s: A 64-byte little-endian integer (``ed25519NonReducedScalarBytes``).
    ///
    /// - Returns: A 32-byte scalar.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519ScalarReduce(_ s: Data) throws -> Data {
        try ensure(s.count == ed25519NonReducedScalarBytes, raising: .typeError("Input must be a \(ed25519NonReducedScalarBytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519ScalarBytes))
        crypto_core_ed25519_scalar_reduce(&r, [UInt8](s))
        return Data(r.prefix(Int(ed25519ScalarBytes)))
    }
    
}
