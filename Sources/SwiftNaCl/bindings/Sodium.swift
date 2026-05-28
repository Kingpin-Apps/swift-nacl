import Clibsodium
import Foundation

// Define UINT64_MAX and SIZE_MAX
let UINT64_MAX: UInt64 = UInt64.max
let SIZE_MAX: UInt64 = {
    UInt64.max
}()

let sodiumSizeMax: UInt64 = {
    return min(UINT64_MAX, SIZE_MAX)
}()

public struct Sodium {

    /// Bindings to the libsodium library
    public let cryptoAead = CryptoAead()
    public let cryptoBox = CryptoBox()
    public let cryptoCore = CryptoCore()
    public let cryptoGenericHash = CryptoGenericHash()
    public let cryptoHash = CryptoHash()
    public let cryptoKx = CryptoKx()
    public let cryptoPwHash = CryptoPwHash()
    public let cryptoScalarmult = CryptoScalarmult()
    public let cryptoSecretBox = CryptoSecretBox()
    public let cryptoSecretStream = CryptoSecretStream()
    public let cryptoShortHash = CryptoShortHash()
    public let cryptoSign = CryptoSign()
    public let randomBytes = RandomBytes()
    public let utils = CryptoUtils()
    public let version = Version()

    public init() {
        _ = Sodium.once
    }
}

extension Sodium {
    private static let once: Void = {
        guard sodium_init() >= 0 else {
            fatalError("Failed to initialize libsodium")
        }
    }()
}
