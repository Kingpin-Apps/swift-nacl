import Foundation
import Clibsodium

public struct CryptoUtils {
    public func sodiumMemcmp(_ inp1: Data, _ inp2: Data) -> Bool {
        /// Compare contents of two memory regions in constant time
        ///
        /// - Parameters:
        ///     - inp1: `Data`
        ///     - inp2: `Data`
        ///
        /// - Returns: `Bool`
        
        let ln = max(inp1.count, inp2.count)
        
        var buf1 = [UInt8](repeating: 0, count: ln)
        var buf2 = [UInt8](repeating: 0, count: ln)
        
        buf1.replaceSubrange(0..<inp1.count, with: inp1)
        buf2.replaceSubrange(0..<inp2.count, with: inp2)
        
        let eqL = (inp1.count == inp2.count)
        let eqC = sodium_memcmp(&buf1, &buf2, ln) == 0
        
        return eqL && eqC
    }

    public func sodiumPad(_ s: Data, blocksize: Int) throws -> Data {
        /// Pad the input bytearray ``s`` to a multiple of ``blocksize`` using the ISO/IEC 7816-4 algorithm
        ///
        /// - Parameters:
        ///     - s: Input bytes string `Data`
        ///     - blocksize: `Int`
        ///
        /// - Returns: padded string `Data`
        
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

    public func sodiumUnpad(_ s: Data, blocksize: Int) throws -> Data {
        /// Remove ISO/IEC 7816-4 padding from the input byte array ``s``
        ///
        /// - Parameters:
        ///     - s: Input bytes string `Data`
        ///     - blocksize: `Int`
        ///
        /// - Returns: unpadded string `Data`
        
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

    public func sodiumIncrement(_ inp: Data) -> Data {
        /// Increment the value of a byte-sequence interpreted as the little-endian representation of a unsigned big integer.
        ///
        /// - Parameters:
        ///     - inp: Input bytes buffer `Data`
        ///
        /// - Returns: a byte-sequence representing, as a little-endian unsigned big integer, the value ``to_int(inp)`` incremented by one.
        
        let ln = inp.count
        var buf = [UInt8](repeating: 0, count: ln)
        
        buf.replaceSubrange(0..<inp.count, with: inp)
        
        sodium_increment(&buf, ln)
        
        return Data(buf.prefix(ln))
    }

    public func sodiumAdd(_ a: Data, _ b: Data) -> Data {
        /// Given a couple of *same-sized* byte sequences, interpreted as the little-endian representation of two unsigned integers, compute
        /// the modular addition of the represented values, in constant time for a given common length of the byte sequences.
        ///
        /// - Parameters:
        ///     - a: Input bytes buffer `Data`
        ///     - b: Input bytes buffer `Data`
        ///
        /// - Returns: a byte-sequence representing, as a little-endian big integer, the integer value of ``(to_int(a) + to_int(b)) mod 2^(8*len(a))``
        
        let ln = a.count
        var buf_a = [UInt8](repeating: 0, count: ln)
        var buf_b = [UInt8](repeating: 0, count: ln)
        
        buf_a.replaceSubrange(0..<a.count, with: a)
        buf_b.replaceSubrange(0..<b.count, with: b)
        
        sodium_add(&buf_a, &buf_b, ln)
        
        return Data(buf_a.prefix(ln))
    }

}
