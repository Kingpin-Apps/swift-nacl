import Foundation
import Clibsodium

public struct CryptoScalarmult {
    
    public let bytes = crypto_scalarmult_bytes()
    public let scalarBytes = crypto_scalarmult_scalarbytes()
    
    public let ed25519Bytes = crypto_scalarmult_ed25519_bytes()
    public let ed25519ScalarBytes = crypto_scalarmult_ed25519_scalarbytes()
    
    
    public func base(n: Data) throws -> Data {
        /// Computes and returns the scalar product of a standard group element and an integer ``n``.
        ///
        /// - Parameters:
        ///     - n: `Data`
        ///
        /// - Returns:`Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.

        var q = [UInt8](repeating: 0, count: Int(bytes))
        let result = crypto_scalarmult_base(&q, [UInt8](n))
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(q.prefix(Int(scalarBytes)))
    }
    
    public func cryptoScalarmult(n: Data, p: Data) throws -> Data {
        /// Computes and returns the scalar product of a standard group element and an integer ``n``.
        ///
        /// - Parameters:
        ///     - n: `Data`
        ///     - p: `Data`
        ///
        /// - Returns:`Data`.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        var q = [UInt8](repeating: 0, count: Int(bytes))
        let result = crypto_scalarmult(&q, [UInt8](n), [UInt8](p))
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(q.prefix(Int(scalarBytes)))
    }
    
    public func ed25519Base(n: Data) throws -> Data {
        /// Computes and returns the scalar product of a standard group element and an integer ``n`` on the edwards25519 curve.
        ///
        /// - Parameters:
        ///     - n: `Data`
        ///
        /// - Returns:a point on the edwards25519 curve, represented as a `Data` long bytes sequence.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(n.count == ed25519ScalarBytes, raising: .typeError("Input must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var q = [UInt8](repeating: 0, count: Int(ed25519Bytes))
        let result = crypto_scalarmult_ed25519_base(&q, [UInt8](n))
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(q.prefix(Int(ed25519Bytes)))
    }
    
    public func ed25519BaseNoclamp(n: Data) throws -> Data {
        /// Computes and returns the scalar product of a standard group element and an integer ``n`` on the edwards25519 curve. The integer ``n`` is not clamped.
        ///
        /// - Parameters:
        ///     - n: `Data` long bytes sequence representing a scalar
        ///
        /// - Returns:a point on the edwards25519 curve, represented as a `Data` long bytes sequence.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(n.count == ed25519ScalarBytes, raising: .typeError("Input must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var q = [UInt8](repeating: 0, count: Int(ed25519Bytes))
        let result = crypto_scalarmult_ed25519_base_noclamp(&q, [UInt8](n))
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(q.prefix(Int(ed25519Bytes)))
    }
    
    public func ed25519(n: Data, p: Data) throws -> Data {
        /// Computes and returns the scalar product of a *clamped* integer ``n`` and the given group element on the edwards25519 curve.
        /// The scalar is clamped, as done in the public key generation case, by setting to zero the bits in position [0, 1, 2, 255] and setting to one the bit in position 254.
        ///
        /// - Parameters:
        ///     - n: `Data` long bytes sequence representing a scalar
        ///     - p: `Data` long bytes sequence representing a point on the edwards25519 curve
        ///
        /// - Returns:a point on the edwards25519 curve, represented as a `Data` long bytes sequence.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(n.count == ed25519ScalarBytes, raising: .typeError("Input must be a \(ed25519ScalarBytes) long bytes sequence"))
        try ensure(p.count == ed25519Bytes, raising: .typeError("Input must be a \(ed25519Bytes) long bytes sequence"))
        
        var q = [UInt8](repeating: 0, count: Int(ed25519Bytes))
        let result = crypto_scalarmult_ed25519(&q, [UInt8](n), [UInt8](p))
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(q.prefix(Int(ed25519Bytes)))
    }
    
    public func ed25519Noclamp(n: Data, p: Data) throws -> Data {
        /// Computes and returns the scalar product of an integer ``n`` and the given group element on the edwards25519 curve.
        ///  The integer ``n`` is not clamped.
        ///
        /// - Parameters:
        ///     - n: `Data` long bytes sequence representing a scalar
        ///     - p: `Data` long bytes sequence representing a point on the edwards25519 curve
        ///
        /// - Returns:a point on the edwards25519 curve, represented as a `Data` long bytes sequence.
        /// - Throws: Raises a `SodiumError` if input is invalid.
        
        try ensure(n.count == ed25519ScalarBytes, raising: .typeError("Input must be a \(ed25519ScalarBytes) long bytes sequence"))
        try ensure(p.count == ed25519Bytes, raising: .typeError("Input must be a \(ed25519Bytes) long bytes sequence"))
        
        var q = [UInt8](repeating: 0, count: Int(ed25519Bytes))
        let result = crypto_scalarmult_ed25519_noclamp(&q, [UInt8](n), [UInt8](p))
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(q.prefix(Int(ed25519Bytes)))
    }
    
}
