import Clibsodium
import Foundation

/**
 A Data subclass that holds a message that has been encrypted by a `SecretBox`.
 */
public class EncryptedMessage {
    private var nonce: Data
    private var ciphertext: Data
    private var combined: Data

    init(nonce: Data, ciphertext: Data, combined: Data) {
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.combined = combined
    }

    class func fromParts(nonce: Data, ciphertext: Data, combined: Data) -> EncryptedMessage {
        return EncryptedMessage(nonce: nonce, ciphertext: ciphertext, combined: combined)
    }

    /**
     The nonce used during the encryption of the `EncryptedMessage`.
     */
    var getNonce: Data {
        return nonce
    }

    /**
     The ciphertext contained within the `EncryptedMessage`.
     */
    var getCiphertext: Data {
        return ciphertext
    }

    /**
     The combined contained within the `EncryptedMessage`.
     */
    var getMessage: Data {
        return combined
    }
}

public class StringFixer {
    func toString(data: Data) -> String {
        return String(data: data, encoding: .utf8) ?? ""
    }
}

public func bytesAsString(bytesIn: Data) -> String {
    return bytesIn.map { String(format: "%02hhx", $0) }.joined()
}

public func random(size: Int = 32) -> Data {
    return Data((0..<size).map { _ in UInt8.random(in: 0...255) })
}

/**
 Returns `size` number of deterministically generated pseudorandom bytes from a seed

 - parameter size: Int
 - parameter seed: Data
 - parameter encoder: The encoder class used to encode the produced bytes
 - returns: Data
 */
public func randomBytesDeterministic(size: Int, seed: Data, encoder: Encoder.Type = RawEncoder.self) throws -> Data {
    let rawData = try Sodium().randomBytes.bufDeterministic(
        size: size,
        seed: seed
    )
    return encoder.encode(data: rawData)
}
