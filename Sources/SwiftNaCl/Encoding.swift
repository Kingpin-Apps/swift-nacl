import Foundation
import Base32

public protocol Encoder {
    static func encode(data: Data) -> Data
    static func decode(data: Data) -> Data
}

public class RawEncoder: Encoder {
    public static func encode(data: Data) -> Data {
        return data
    }

    public static func decode(data: Data) -> Data {
        return data
    }
}

public class HexEncoder: Encoder {
    public static func encode(data: Data) -> Data {
        return data.map { String(format: "%02hhx", $0) }.joined().data(using: .utf8)!
    }

    public static func decode(data: Data) -> Data {
        var bytes = [UInt8]()
        var hexStr = String(data: data, encoding: .utf8)!
        while !hexStr.isEmpty {
            let c = String(hexStr.prefix(2))
            hexStr = String(hexStr.dropFirst(2))
            bytes.append(UInt8(c, radix: 16)!)
        }
        return Data(bytes)
    }
}

/// Encodes and decodes Base16 (RFC 4648), the uppercase hexadecimal alphabet.
///
/// Matches PyNaCl's `Base16Encoder`: ``encode(data:)`` produces uppercase
/// hex digits (`0-9`, `A-F`). ``decode(data:)`` accepts uppercase or lowercase
/// digits. For lowercase output use ``HexEncoder``.
///
/// Like the other encoders, ``decode(data:)`` traps on malformed input (an odd
/// number of characters or a non-hex character).
public class Base16Encoder: Encoder {
    private static let alphabet = Array("0123456789ABCDEF".utf8)

    /// Encodes `data` as uppercase Base16 ASCII bytes.
    ///
    /// - Parameter data: The bytes to encode.
    /// - Returns: Two uppercase hex digits per input byte, as UTF-8 data.
    public static func encode(data: Data) -> Data {
        var output = Data(capacity: data.count * 2)
        for byte in data {
            output.append(alphabet[Int(byte >> 4)])
            output.append(alphabet[Int(byte & 0x0f)])
        }
        return output
    }

    /// Decodes Base16 ASCII bytes back to raw bytes.
    ///
    /// - Parameter data: Hex digits as UTF-8 data; uppercase and lowercase are both accepted.
    /// - Returns: The decoded bytes.
    public static func decode(data: Data) -> Data {
        let digits = Array(data)
        precondition(digits.count % 2 == 0, "Base16 input must have an even number of characters")
        var output = Data(capacity: digits.count / 2)
        var index = 0
        while index < digits.count {
            output.append(nibble(digits[index]) << 4 | nibble(digits[index + 1]))
            index += 2
        }
        return output
    }

    private static func nibble(_ digit: UInt8) -> UInt8 {
        switch digit {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return digit - UInt8(ascii: "0")
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return digit - UInt8(ascii: "A") + 10
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return digit - UInt8(ascii: "a") + 10
        default: preconditionFailure("Invalid Base16 character: \(digit)")
        }
    }
}

public class Base32Encoder: Encoder {
    public static func encode(data: Data) -> Data {
        return data.base32EncodedData
    }

    public static func decode(data: Data) -> Data {
        return data.base32DecodedData!
    }
}

public class Base64Encoder: Encoder {
    public static func encode(data: Data) -> Data {
        return data.base64EncodedData()
    }

    public static func decode(data: Data) -> Data {
        return Data(base64Encoded: data)!
    }
}

public class URLSafeBase64Encoder: Encoder {
    public static func encode(data: Data) -> Data {
        return data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").data(using: .utf8)!
    }

    public static func decode(data: Data) -> Data {
        let base64 = String(data: data, encoding: .utf8)!.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        return Data(base64Encoded: base64)!
    }
}

public protocol Encodable {
    func encode(encoder: Encoder.Type) -> Data
}

public extension Encodable where Self: CustomStringConvertible {
    func encode(encoder: Encoder.Type) -> Data {
        return encoder.encode(data: self.description.data(using: .utf8)!)
    }
}
