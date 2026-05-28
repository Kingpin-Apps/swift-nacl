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

public class Base16Encoder: Encoder {
    public static func encode(data: Data) -> Data {
        return data.base64EncodedString(options: .init(rawValue: 0)).data(using: .utf8)!
    }

    public static func decode(data: Data) -> Data {
        return Data(base64Encoded: data, options: .init(rawValue: 0))!
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
