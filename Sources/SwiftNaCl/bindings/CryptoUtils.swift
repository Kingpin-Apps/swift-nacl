import Foundation
import Clibsodium

public struct CryptoUtils {
    /// Compares two byte buffers in constant time (`sodium_memcmp`).
    ///
    /// - Parameters:
    ///   - inp1: The first buffer.
    ///   - inp2: The second buffer.
    ///
    /// - Returns: `true` if both buffers have the same length and contents.
    public func sodiumMemcmp(_ inp1: Data, _ inp2: Data) -> Bool {
        let ln = max(inp1.count, inp2.count)
        
        var buf1 = [UInt8](repeating: 0, count: ln)
        var buf2 = [UInt8](repeating: 0, count: ln)
        
        buf1.replaceSubrange(0..<inp1.count, with: inp1)
        buf2.replaceSubrange(0..<inp2.count, with: inp2)
        
        let eqL = (inp1.count == inp2.count)
        let eqC = sodium_memcmp(&buf1, &buf2, ln) == 0
        
        return eqL && eqC
    }

    /// Pads `s` to a multiple of `blocksize` using the ISO/IEC 7816-4 algorithm (`sodium_pad`).
    ///
    /// - Parameters:
    ///   - s: The bytes to pad.
    ///   - blocksize: The block size; must be greater than zero.
    ///
    /// - Returns: The padded bytes.
    public func sodiumPad(_ s: Data, blocksize: Int) throws -> Data {
        try ensure(blocksize > 0, raising: .valueError("Block size must be greater than 0"))
        
        let s_len = s.count
        let m_len = s_len + blocksize
        var buf = [UInt8](repeating: 0, count: m_len)
        var p_len: size_t = 0
        
        buf.replaceSubrange(0..<s_len, with: s)
        
        let rc = sodium_pad(&p_len, &buf, s_len, blocksize, m_len)
        try ensure(rc == 0, raising: .cryptoError("Padding failure"))
        return Data(buf[0..<p_len])
    }

    /// Removes ISO/IEC 7816-4 padding from `s` (`sodium_unpad`).
    ///
    /// - Parameters:
    ///   - s: The padded bytes.
    ///   - blocksize: The block size used for padding.
    ///
    /// - Returns: The unpadded bytes.
    public func sodiumUnpad(_ s: Data, blocksize: Int) throws -> Data {
        let s_len = s.count
        var u_len: size_t = 0
        let rc = s.withUnsafeBytes { (sPtr: UnsafeRawBufferPointer) in
            guard let sRawPtr = sPtr.baseAddress else {
                return Int32(-1)
            }
            return sodium_unpad(&u_len, sRawPtr.assumingMemoryBound(to: UInt8.self), s_len, blocksize)
        }
            
        try ensure(rc == 0, raising: .cryptoError("Unpadding failure"))
        return Data(s[0..<u_len])
    }

    /// Increments a byte sequence interpreted as a little-endian unsigned integer (`sodium_increment`).
    ///
    /// - Parameter inp: The little-endian integer to increment.
    ///
    /// - Returns: A byte sequence of the same length holding `inp + 1`, wrapping on overflow.
    public func sodiumIncrement(_ inp: Data) -> Data {
        let ln = inp.count
        var buf = [UInt8](repeating: 0, count: ln)
        
        buf.replaceSubrange(0..<inp.count, with: inp)
        
        sodium_increment(&buf, ln)
        
        return Data(buf.prefix(ln))
    }

    /// Adds two same-sized byte sequences interpreted as little-endian unsigned integers, in
    /// constant time for a given length (`sodium_add`).
    ///
    /// - Parameters:
    ///   - a: The first little-endian integer.
    ///   - b: The second little-endian integer, the same length as `a`.
    ///
    /// - Returns: `(a + b) mod 2^(8 * a.count)` as a little-endian byte sequence.
    public func sodiumAdd(_ a: Data, _ b: Data) -> Data {
        let ln = a.count
        var buf_a = [UInt8](repeating: 0, count: ln)
        var buf_b = [UInt8](repeating: 0, count: ln)
        
        buf_a.replaceSubrange(0..<a.count, with: a)
        buf_b.replaceSubrange(0..<b.count, with: b)
        
        sodium_add(&buf_a, &buf_b, ln)
        
        return Data(buf_a.prefix(ln))
    }

}
