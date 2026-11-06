import Foundation
import Clibsodium

public struct CryptoScalarmult {
    
    public let bytes = crypto_scalarmult_bytes()
    public let scalarBytes = crypto_scalarmult_scalarbytes()
    
    public let ed25519Bytes = crypto_scalarmult_ed25519_bytes()
    public let ed25519ScalarBytes = crypto_scalarmult_ed25519_scalarbytes()
    
    
    /// Computes the Curve25519 public key for the secret scalar `n` (`crypto_scalarmult_base`).
    ///
    /// - Parameter n: A 32-byte secret scalar.
    ///
    /// - Returns: The 32-byte Curve25519 point `n · B`.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func base(n: Data) throws -> Data {
        var q = [UInt8](repeating: 0, count: Int(bytes))
        let result = crypto_scalarmult_base(&q, [UInt8](n))
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(q.prefix(Int(scalarBytes)))
    }
    
    /// Computes the Curve25519 scalar product of the integer `n` and the point `p` (`crypto_scalarmult`).
    ///
    /// - Parameters:
    ///   - n: A 32-byte scalar.
    ///   - p: A 32-byte Curve25519 point.
    ///
    /// - Returns: The 32-byte shared point `n · p`.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func cryptoScalarmult(n: Data, p: Data) throws -> Data {
        var q = [UInt8](repeating: 0, count: Int(bytes))
        let result = crypto_scalarmult(&q, [UInt8](n), [UInt8](p))
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(q.prefix(Int(scalarBytes)))
    }
    
    /// Computes and returns the scalar product of a standard group element and an integer `n` on the edwards25519 curve.
    ///
    /// - Parameters:
    ///   - n: A 32-byte scalar.
    ///
    /// - Returns: A 32-byte point on the edwards25519 curve.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519Base(n: Data) throws -> Data {
        try ensure(n.count == ed25519ScalarBytes, raising: .typeError("Input must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var q = [UInt8](repeating: 0, count: Int(ed25519Bytes))
        let result = crypto_scalarmult_ed25519_base(&q, [UInt8](n))
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(q.prefix(Int(ed25519Bytes)))
    }
    
    /// Computes and returns the scalar product of a standard group element and an integer `n` on the edwards25519 curve. The integer `n` is not clamped.
    ///
    /// - Parameters:
    ///   - n: A 32-byte scalar.
    ///
    /// - Returns: A 32-byte point on the edwards25519 curve.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519BaseNoclamp(n: Data) throws -> Data {
        try ensure(n.count == ed25519ScalarBytes, raising: .typeError("Input must be a \(ed25519ScalarBytes) long bytes sequence"))
        
        var q = [UInt8](repeating: 0, count: Int(ed25519Bytes))
        let result = crypto_scalarmult_ed25519_base_noclamp(&q, [UInt8](n))
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(q.prefix(Int(ed25519Bytes)))
    }
    
    /// Computes and returns the scalar product of a *clamped* integer `n` and the given group element on the edwards25519 curve.
    /// The scalar is clamped, as done in the public key generation case, by setting to zero the bits in position [0, 1, 2, 255] and setting to one the bit in position 254.
    ///
    /// - Parameters:
    ///   - n: A 32-byte scalar.
    ///   - p: A 32-byte point on the edwards25519 curve.
    ///
    /// - Returns: A 32-byte point on the edwards25519 curve.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519(n: Data, p: Data) throws -> Data {
        try ensure(n.count == ed25519ScalarBytes, raising: .typeError("Input must be a \(ed25519ScalarBytes) long bytes sequence"))
        try ensure(p.count == ed25519Bytes, raising: .typeError("Input must be a \(ed25519Bytes) long bytes sequence"))
        
        var q = [UInt8](repeating: 0, count: Int(ed25519Bytes))
        let result = crypto_scalarmult_ed25519(&q, [UInt8](n), [UInt8](p))
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(q.prefix(Int(ed25519Bytes)))
    }
    
    /// Computes and returns the scalar product of an integer `n` and the given group element on the edwards25519 curve.
    ///  The integer `n` is not clamped.
    ///
    /// - Parameters:
    ///   - n: A 32-byte scalar.
    ///   - p: A 32-byte point on the edwards25519 curve.
    ///
    /// - Returns: A 32-byte point on the edwards25519 curve.
    /// - Throws: A ``SodiumError`` if input is invalid.
    public func ed25519Noclamp(n: Data, p: Data) throws -> Data {
        try ensure(n.count == ed25519ScalarBytes, raising: .typeError("Input must be a \(ed25519ScalarBytes) long bytes sequence"))
        try ensure(p.count == ed25519Bytes, raising: .typeError("Input must be a \(ed25519Bytes) long bytes sequence"))
        
        var q = [UInt8](repeating: 0, count: Int(ed25519Bytes))
        let result = crypto_scalarmult_ed25519_noclamp(&q, [UInt8](n), [UInt8](p))
        try ensure(result == 0, raising: .runtimeError("Unexpected library error"))
        return Data(q.prefix(Int(ed25519Bytes)))
    }
    
}
