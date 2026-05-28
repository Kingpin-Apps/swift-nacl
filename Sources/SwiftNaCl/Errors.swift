import Foundation

public enum SodiumError: Error, Equatable {
    case badSignatureError(String)
    case cryptoError(String)
    case cryptPrefixError(String)
    case invalidKeyError(String)
    case invalidSeedLength(String)
    case runtimeError(String)
    case typeError(String)
    case unavailableError(String)
    case valueError(String)
}

public func ensure(_ condition: Bool, raising error: SodiumError) throws {
    if !condition {
        throw error
    }
}
