import Foundation
import Base32

/// Converts bytes to and from a text encoding.
///
/// ``decode(data:)`` throws ``SodiumError/valueError(_:)`` on malformed input,
/// so decoding untrusted data never terminates the process.
public protocol Encoder {
    static func encode(data: Data) -> Data
    static func decode(data: Data) throws -> Data
}

public class RawEncoder: Encoder {
    public static func encode(data: Data) -> Data {
        return data
    }

    public static func decode(data: Data) throws -> Data {
        return data
    }
}

/// Encodes and decodes lowercase hexadecimal. Decoding accepts either case.
public class HexEncoder: Encoder {
    public static func encode(data: Data) -> Data {
        return data.map { String(format: "%02hhx", $0) }.joined().data(using: .utf8)!
    }

    /// - Throws: ``SodiumError/valueError(_:)`` on an odd number of characters or a non-hex character.
    public static func decode(data: Data) throws -> Data {
        return try decodeHexDigits(data, name: "Hex")
    }
}

/// Encodes and decodes Base16 (RFC 4648), the uppercase hexadecimal alphabet.
///
/// Matches PyNaCl's `Base16Encoder`: ``encode(data:)`` produces uppercase
/// hex digits (`0-9`, `A-F`). ``decode(data:)`` accepts uppercase or lowercase
/// digits. For lowercase output use ``HexEncoder``.
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
    /// - Throws: ``SodiumError/valueError(_:)`` on an odd number of characters or a non-hex character.
    public static func decode(data: Data) throws -> Data {
        return try decodeHexDigits(data, name: "Base16")
    }
}

public class Base32Encoder: Encoder {
    public static func encode(data: Data) -> Data {
        return data.base32EncodedData
    }

    /// - Throws: ``SodiumError/valueError(_:)`` if `data` is not valid Base32.
    public static func decode(data: Data) throws -> Data {
        guard let decoded = data.base32DecodedData else {
            throw SodiumError.valueError("Invalid Base32 input")
        }
        return decoded
    }
}

public class Base64Encoder: Encoder {
    public static func encode(data: Data) -> Data {
        return data.base64EncodedData()
    }

    /// - Throws: ``SodiumError/valueError(_:)`` if `data` is not valid Base64.
    public static func decode(data: Data) throws -> Data {
        guard let decoded = Data(base64Encoded: data) else {
            throw SodiumError.valueError("Invalid Base64 input")
        }
        return decoded
    }
}

public class URLSafeBase64Encoder: Encoder {
    public static func encode(data: Data) -> Data {
        return data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").data(using: .utf8)!
    }

    /// - Throws: ``SodiumError/valueError(_:)`` if `data` is not valid URL-safe Base64.
    public static func decode(data: Data) throws -> Data {
        guard let text = String(data: data, encoding: .utf8),
              let decoded = Data(base64Encoded: text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/"))
        else {
            throw SodiumError.valueError("Invalid URL-safe Base64 input")
        }
        return decoded
    }
}

private func decodeHexDigits(_ data: Data, name: String) throws -> Data {
    let digits = Array(data)
    guard digits.count % 2 == 0 else {
        throw SodiumError.valueError("\(name) input must have an even number of characters")
    }
    func nibble(_ digit: UInt8) throws -> UInt8 {
        switch digit {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return digit - UInt8(ascii: "0")
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return digit - UInt8(ascii: "A") + 10
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return digit - UInt8(ascii: "a") + 10
        default: throw SodiumError.valueError("Invalid \(name) character")
        }
    }
    var output = Data(capacity: digits.count / 2)
    var index = 0
    while index < digits.count {
        output.append(try nibble(digits[index]) << 4 | nibble(digits[index + 1]))
        index += 2
    }
    return output
}

public protocol Encodable {
    func encode(encoder: Encoder.Type) -> Data
}

public extension Encodable where Self: CustomStringConvertible {
    func encode(encoder: Encoder.Type) -> Data {
        return encoder.encode(data: self.description.data(using: .utf8)!)
    }
}
