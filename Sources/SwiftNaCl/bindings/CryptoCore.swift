import Foundation
import Clibsodium

public struct CryptoCore {
    
    public let ed25519Bytes = crypto_core_ed25519_bytes()
    public let ed25519ScalarBytes = crypto_core_ed25519_scalarbytes()
    public let ed25519NonReducedScalarBytes = crypto_core_ed25519_nonreducedscalarbytes()
    
    
    public func ed25519IsValidPoint(_ p: Data) throws -> Bool {
        /// Check if `p` represents a point on the edwards25519 curve, in canonical form, on the main subgroup, and that the point doesn't have a small order.
        ///
        /// - Parameters:
        ///     - p: `Data` long bytes sequence representing a point on the edwards25519 curve
        ///
        /// - Returns: Point validity `bool`.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(p.count == ed25519Bytes, raising: .typeError("Point must be a \(ed25519Bytes) long bytes sequence"))
        
        let result = crypto_core_ed25519_is_valid_point([UInt8](p))
        return result == 1
    }
    
    public func ed25519FromUniform(_ r: Data) throws -> Data {
        /// Maps a 32 bytes vector `r` to a point. The point is guaranteed to be on the main subgroup. This function directly exposes the Elligator 2 map, uses the high bit to set the sign of the X coordinate, and the resulting point is multiplied by the cofactor.
        ///
        /// - Parameters:
        ///     - r: `Data` long bytes sequence representing arbitrary data
        ///
        /// - Returns: a point on the edwards25519 curve main order subgroup, represented as a long bytes sequence `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(r.count == ed25519Bytes, raising: .typeError("Input must be a \(ed25519Bytes) long bytes sequence"))
        
        var p = [UInt8](repeating: 0, count: Int(ed25519Bytes))
        let result = crypto_core_ed25519_from_uniform(&p, [UInt8](r))
        
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(p.prefix(Int(ed25519Bytes)))
    }
    
    public func ed25519Add(_ p: Data, _ q: Data) throws -> Data {
        /// Add two points on the edwards25519 curve.
        ///
        /// - Parameters:
        ///     - p: `Data` long bytes sequence representing a point on the edwards25519 curve
        ///     - q: `Data` long bytes sequence representing a point on the edwards25519 curve
        ///
        /// - Returns: a point on the edwards25519 curve main order subgroup, represented as a long bytes sequence `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(p.count == ed25519Bytes && q.count == ed25519Bytes, raising: .typeError("Each point must be a \(ed25519Bytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519Bytes))
        let result = crypto_core_ed25519_add(&r, [UInt8](p), [UInt8](q))
        
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(r.prefix(Int(ed25519Bytes)))
    }
    
    public func ed25519Sub(_ p: Data, _ q: Data) throws -> Data {
        /// Subtract a point from another on the edwards25519 curve.
        ///
        /// - Parameters:
        ///     - p: `Data` long bytes sequence representing a point on the edwards25519 curve
        ///     - q: `Data` long bytes sequence representing a point on the edwards25519 curve
        ///
        /// - Returns: a point on the edwards25519 curve main order subgroup, represented as a long bytes sequence `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(p.count == ed25519Bytes && q.count == ed25519Bytes, raising: .typeError("Each point must be a \(ed25519Bytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519Bytes))
        let result = crypto_core_ed25519_sub(&r, [UInt8](p), [UInt8](q))
        
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(r.prefix(Int(ed25519Bytes)))
    }
    
    func ed25519ScalarInvert(_ s: Data) throws -> Data {
        /// Return the multiplicative inverse of integer ``s`` modulo ``L``, i.e an integer ``i`` such that ``s * i = 1 (mod L)``, where ``L`` is the order of the main subgroup.
        ///
        /// - Parameters:
        ///     - s: `Data` long bytes sequence representing an integer
        ///
        /// - Returns: an integer represented as a long bytes sequence `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(s.count == ed25519ScalarBytes, raising: .typeError("Integer s must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519ScalarBytes))
        let result = crypto_core_ed25519_scalar_invert(&r, [UInt8](s))
        
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(r.prefix(Int(ed25519ScalarBytes)))
    }
    
    public func ed25519ScalarNegate(_ s: Data) throws -> Data {
        /// Return the integer ``n`` such that ``s + n = 0 (mod L)``, where ``L`` is the order of the main subgroup.
        ///
        /// - Parameters:
        ///     - s: `Data` long bytes sequence representing an integer
        ///
        /// - Returns: an integer represented as a long bytes sequence `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(s.count == ed25519ScalarBytes, raising: .typeError("Integer s must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519ScalarBytes))
        crypto_core_ed25519_scalar_negate(&r, [UInt8](s))
        return Data(r.prefix(Int(ed25519ScalarBytes)))
    }
    
    public func ed25519ScalarComplement(_ s: Data) throws -> Data {
        /// Return the complement of integer ``s`` modulo ``L``, i.e. an integer ``c`` such that ``s + c = 1 (mod L)``, where ``L`` is the order of the main subgroup.
        ///
        /// - Parameters:
        ///     - s: `Data` long bytes sequence representing an integer
        ///
        /// - Returns: an integer represented as a long bytes sequence `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(s.count == ed25519ScalarBytes, raising: .typeError("Integer s must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519ScalarBytes))
        crypto_core_ed25519_scalar_complement(&r, [UInt8](s))
        return Data(r.prefix(Int(ed25519ScalarBytes)))
    }
    
    public func ed25519ScalarAdd(_ p: Data, _ q: Data) throws -> Data {
        /// Add integers ``p`` and ``q`` modulo ``L``, where ``L`` is the order of the main subgroup.
        ///
        /// - Parameters:
        ///     - p: `Data` long bytes sequence representing an integer
        ///     - q: `Data` long bytes sequence representing an integer
        ///
        /// - Returns: an integer represented as a long bytes sequence `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(p.count == ed25519ScalarBytes && q.count == ed25519ScalarBytes, raising: .typeError("Each point must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519ScalarBytes))
        crypto_core_ed25519_scalar_add(&r, [UInt8](p), [UInt8](q))
        return Data(r.prefix(Int(ed25519ScalarBytes)))
    }
    
    public func ed25519ScalarSub(_ p: Data, _ q: Data) throws -> Data {
        /// Subtract integers ``p`` and ``q`` modulo ``L``, where ``L`` is the order of the main subgroup.
        ///
        /// - Parameters:
        ///     - p: `Data` long bytes sequence representing an integer
        ///     - q: `Data` long bytes sequence representing an integer
        ///
        /// - Returns: an integer represented as a long bytes sequence `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(p.count == ed25519ScalarBytes && q.count == ed25519ScalarBytes, raising: .typeError("Each point must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519ScalarBytes))
        crypto_core_ed25519_scalar_sub(&r, [UInt8](p), [UInt8](q))
        return Data(r.prefix(Int(ed25519ScalarBytes)))
    }
    
    public func ed25519ScalarMul(_ p: Data, _ q: Data) throws -> Data {
        /// Multiply integers ``p`` and ``q`` modulo ``L``, where ``L`` is the order of the main subgroup.
        ///
        /// - Parameters:
        ///     - p: `Data` long bytes sequence representing an integer
        ///     - q: `Data` long bytes sequence representing an integer
        ///
        /// - Returns: an integer represented as a long bytes sequence `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(p.count == ed25519ScalarBytes && q.count == ed25519ScalarBytes, raising: .typeError("Each point must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519ScalarBytes))
        crypto_core_ed25519_scalar_mul(&r, [UInt8](p), [UInt8](q))
        return Data(r.prefix(Int(ed25519ScalarBytes)))
    }
    
    public func ed25519ScalarReduce(_ s: Data) throws -> Data {
        /// Reduce integer ``s`` to ``s`` modulo ``L``, where ``L`` is the order of the main subgroup.
        ///
        /// - Parameters:
        ///     - s: `Data` long bytes sequence representing an integer
        ///
        /// - Returns: an integer represented as a long bytes sequence `Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(s.count == ed25519NonReducedScalarBytes, raising: .typeError("Input must be a \(ed25519NonReducedScalarBytes) long bytes sequence"))
        
        var r = [UInt8](repeating: 0, count: Int(ed25519ScalarBytes))
        crypto_core_ed25519_scalar_reduce(&r, [UInt8](s))
        return Data(r.prefix(Int(ed25519ScalarBytes)))
    }
    
}
