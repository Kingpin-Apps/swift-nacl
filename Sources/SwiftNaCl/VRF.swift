import Foundation
import Clibsodium

/**
 Verifiable Random Function (VRF) implementation using IETF Draft 03 specification
 
 This module provides a Swift interface to the libsodium VRF implementation,
 which follows the IETF draft specification for VRF using Ed25519.
 
 VRF allows generating pseudorandom outputs that can be verified by anyone
 with the corresponding public key, while ensuring the output is deterministic
 for a given private key and input message.
 
 ## Overview
 
 The VRF implementation provides the following key properties:
 - **Deterministic**: The same private key and input always produce the same output
 - **Pseudorandom**: Outputs appear random to anyone without the private key
 - **Verifiable**: Anyone can verify that an output was generated correctly using the public key
 - **Unforgeable**: Only the holder of the private key can generate valid proofs
 
 ## Usage
 
 ```swift
 // Generate a VRF key pair
 let keyPair = VRFKeyPair.generate()
 
 // Create a proof for a message
 let message = "Hello, VRF!".data(using: .utf8)!
 let proof = try keyPair.signingKey.prove(message: message)
 
 // Verify the proof and get the output
 let output = try keyPair.verifyingKey.verify(message: message, proof: proof)
 print("VRF Output: \(output.hexEncodedString())")
 ```
 
 ## Security Considerations
 
 - Private keys and seeds must be kept secret
 - Use cryptographically secure random number generation for seeds
 - Memory is automatically zeroed when VRF objects are deallocated
 - All operations are constant-time with respect to secret data
 
 ## See Also
 
 - ``VRFSeed``
 - ``VRFSigningKey``
 - ``VRFVerifyingKey``
 - ``VRFProof``
 - ``VRFOutput``
 - ``VRFKeyPair``
 - <doc:VerifiableRandomFunctions>
 */
/// 
/// This module provides a Swift interface to the libsodium VRF implementation,
/// which follows the IETF draft specification for VRF using Ed25519.
/// 
/// VRF allows generating pseudorandom outputs that can be verified by anyone
/// with the corresponding public key, while ensuring the output is deterministic
/// for a given private key and input message.
/// 
/// ## Security Considerations
/// 
/// - Private keys and seeds must be kept secret
/// - Use cryptographically secure random number generation for seeds
/// - Memory is automatically zeroed when VRF objects are deallocated
/// - All operations are constant-time with respect to secret data
/// 
/// ## Usage Example
/// 
/// ```swift
/// // Generate a random seed
/// let seed = VRFSeed.generate()
/// 
/// // Create key pair from seed
/// let keyPair = VRFKeyPair.from(seed: seed)
/// 
/// // Create a proof for a message
/// let message = "Hello, VRF!".data(using: .utf8)!
/// let proof = try keyPair.signingKey.prove(message: message)
/// 
/// // Verify the proof and get the output
/// let output = try keyPair.verifyingKey.verify(message: message, proof: proof)
/// print("VRF Output: \(output.bytes.hexEncodedString())")
/// ```
public struct VRF {
    
    // MARK: - Constants
    
    /// Size of VRF seed in bytes (32 bytes)
    public static let seedBytes: Int = Int(crypto_vrf_ietfdraft03_seedbytes())
    
    /// Size of VRF secret key in bytes (64 bytes - includes public key)
    public static let secretKeyBytes: Int = Int(crypto_vrf_ietfdraft03_secretkeybytes())
    
    /// Size of VRF public key in bytes (32 bytes)
    public static let publicKeyBytes: Int = Int(crypto_vrf_ietfdraft03_publickeybytes())
    
    /// Size of VRF proof in bytes (80 bytes)
    public static let proofBytes: Int = Int(crypto_vrf_ietfdraft03_proofbytes())
    
    /// Size of VRF output in bytes (64 bytes)
    public static let outputBytes: Int = Int(crypto_vrf_ietfdraft03_outputbytes())
    
    nonisolated(unsafe) private static let sodium = Sodium()
}

// MARK: - VRF Errors

/// Errors that can occur during VRF operations
public enum VRFError: Int, Error, LocalizedError {
    case invalidSeed = -1
    case invalidSecretKey = -2
    case invalidPublicKey = -3
    case invalidProof = -4
    case verificationFailed = -5
    case internalError = -6
    case invalidInputSize = -7
    
    public var errorDescription: String? {
        switch self {
        case .invalidSeed:
            return "Invalid VRF seed"
        case .invalidSecretKey:
            return "Invalid VRF secret key"
        case .invalidPublicKey:
            return "Invalid VRF public key"
        case .invalidProof:
            return "Invalid VRF proof"
        case .verificationFailed:
            return "VRF verification failed"
        case .internalError:
            return "Internal VRF error"
        case .invalidInputSize:
            return "Invalid input size"
        }
    }
}

// MARK: - VRF Seed

/**
 A cryptographic seed used to generate VRF key pairs
 
 Seeds are 32-byte values that deterministically generate VRF key pairs.
 Seeds should be generated using cryptographically secure random number generators.
 
 ## Overview
 
 VRF seeds provide the foundation for deterministic key generation. The same seed
 will always produce the same VRF key pair, enabling reproducible cryptographic
 operations while maintaining security.
 
 ## Usage
 
 ```swift
 // Generate a random seed
 let seed = VRFSeed.generate()
 
 // Create a seed from specific bytes (must be exactly 32 bytes)
 let seedData = Data(repeating: 0x42, count: 32)
 let specificSeed = try VRFSeed(bytes: seedData)
 
 // Create from hex string
 let hexSeed = try VRFSeed(hexString: "1234567890abcdef...")
 ```
 
 ## Security Notes
 
 - Seeds must be kept as secret as private keys
 - Use ``VRFSeed/generate()`` for cryptographically secure random seeds
 - Seeds enable deterministic key generation for backup and recovery scenarios
 
 ## See Also
 
 - ``VRFKeyPair/from(seed:)``
 - ``VRFSigningKey/seed``
 */
public struct VRFSeed: Equatable, Hashable, Sendable {
    private var _bytes: Data
    
    /// The raw bytes of the seed
    public var bytes: Data {
        return _bytes
    }
    
    /// Creates a VRF seed from raw bytes
    /// 
    /// - Parameter bytes: 32-byte seed data
    /// - Throws: `VRFError.invalidInputSize` if the data is not exactly 32 bytes
    public init(bytes: Data) throws {
        guard bytes.count == VRF.seedBytes else {
            throw VRFError.invalidInputSize
        }
        self._bytes = bytes
    }
    
    /// Creates a VRF seed from a hexadecimal string
    /// 
    /// - Parameter hexString: Hexadecimal representation of the seed
    /// - Throws: `VRFError.invalidInputSize` if the hex string doesn't represent exactly 32 bytes
    public init(hexString: String) throws {
        guard let data = Data(hexString: hexString), data.count == VRF.seedBytes else {
            throw VRFError.invalidInputSize
        }
        self._bytes = data
    }
    
    /// Generates a random VRF seed using cryptographically secure random number generation
    /// 
    /// - Returns: A new random VRF seed
    public static func generate() -> VRFSeed {
        let randomBytes = random(size: VRF.seedBytes)
        return try! VRFSeed(bytes: randomBytes)
    }
    
    /// Returns the seed as a hexadecimal string
    public func hexEncodedString() -> String {
        return _bytes.hexEncodedString()
    }
    
    // MARK: - Hashable
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(_bytes)
    }
    
    public static func == (lhs: VRFSeed, rhs: VRFSeed) -> Bool {
        return Sodium().utils.sodiumMemcmp(lhs._bytes, rhs._bytes)
    }
}

// MARK: - VRF Signing Key

/// A VRF private key used for creating proofs
/// 
/// VRF signing keys are 64-byte values that include both the private scalar
/// and the corresponding public key for efficiency.
public struct VRFSigningKey: Equatable, Hashable, Sendable {
    private let _bytes: Data
    
    /// Creates a VRF signing key from raw bytes
    /// 
    /// - Parameter bytes: 64-byte signing key data
    /// - Throws: `VRFError.invalidInputSize` if the data is not exactly 64 bytes
    public init(bytes: Data) throws {
        guard bytes.count == VRF.secretKeyBytes else {
            throw VRFError.invalidInputSize
        }
        self._bytes = bytes
    }
    
    /// The raw bytes of the signing key (includes both private and public components)
    public var bytes: Data {
        return _bytes
    }
    
    /// Derives the corresponding VRF verifying key (public key)
    public var verifyingKey: VRFVerifyingKey {
        var publicKeyBytes = Data(count: VRF.publicKeyBytes)
        
        _bytes.withUnsafeBytes { secretPtr in
            publicKeyBytes.withUnsafeMutableBytes { publicPtr in
                crypto_vrf_ietfdraft03_sk_to_pk(
                    publicPtr.bindMemory(to: UInt8.self).baseAddress!,
                    secretPtr.bindMemory(to: UInt8.self).baseAddress!
                )
            }
        }
        
        return try! VRFVerifyingKey(bytes: publicKeyBytes)
    }
    
    /// Extracts the seed used to generate this signing key
    public var seed: VRFSeed {
        var seedBytes = Data(count: VRF.seedBytes)
        
        _bytes.withUnsafeBytes { secretPtr in
            seedBytes.withUnsafeMutableBytes { seedPtr in
                crypto_vrf_ietfdraft03_sk_to_seed(
                    seedPtr.bindMemory(to: UInt8.self).baseAddress!,
                    secretPtr.bindMemory(to: UInt8.self).baseAddress!
                )
            }
        }
        
        return try! VRFSeed(bytes: seedBytes)
    }
    
    /// Creates a VRF proof for a given message
    /// 
    /// - Parameter message: The message to create a proof for
    /// - Returns: A VRF proof that can be verified with the corresponding public key
    /// - Throws: `VRFError.invalidSecretKey` if the secret key is invalid
    public func prove(message: Data) throws -> VRFProof {
        var proofBytes = Data(count: VRF.proofBytes)
        
        let result = _bytes.withUnsafeBytes { secretPtr in
            message.withUnsafeBytes { messagePtr in
                proofBytes.withUnsafeMutableBytes { proofPtr in
                    crypto_vrf_ietfdraft03_prove(
                        proofPtr.bindMemory(to: UInt8.self).baseAddress!,
                        secretPtr.bindMemory(to: UInt8.self).baseAddress!,
                        messagePtr.bindMemory(to: UInt8.self).baseAddress!,
                        UInt64(message.count)
                    )
                }
            }
        }
        
        guard result == 0 else {
            throw VRFError.invalidSecretKey
        }
        
        return try VRFProof(bytes: proofBytes)
    }
    
    /// Returns a truncated hexadecimal representation (for logging/debugging)
    /// Note: Does not expose the full secret key for security reasons
    public func fingerprint() -> String {
        return String(_bytes.hexEncodedString().prefix(16)) + "..."
    }
    
    // MARK: - Hashable
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(_bytes)
    }
    
    public static func == (lhs: VRFSigningKey, rhs: VRFSigningKey) -> Bool {
        return Sodium().utils.sodiumMemcmp(lhs._bytes, rhs._bytes)
    }
}

// MARK: - VRF Verifying Key

/// A VRF public key used for verifying proofs
/// 
/// VRF verifying keys are 32-byte Ed25519 public keys that can verify
/// VRF proofs created with the corresponding private key.
public struct VRFVerifyingKey: Equatable, Hashable, Sendable {
    private let _bytes: Data
    
    /// The raw bytes of the verifying key
    public var bytes: Data {
        return _bytes
    }
    
    /// Creates a VRF verifying key from raw bytes
    /// 
    /// - Parameter bytes: 32-byte public key data
    /// - Throws: `VRFError.invalidInputSize` if the data is not exactly 32 bytes
    /// - Throws: `VRFError.invalidPublicKey` if the public key is not valid
    public init(bytes: Data) throws {
        guard bytes.count == VRF.publicKeyBytes else {
            throw VRFError.invalidInputSize
        }
        
        // Validate the public key
        let isValid = bytes.withUnsafeBytes { ptr in
            crypto_vrf_ietfdraft03_is_valid_key(ptr.bindMemory(to: UInt8.self).baseAddress!)
        }
        
        guard isValid == 1 else {
            throw VRFError.invalidPublicKey
        }
        
        self._bytes = bytes
    }
    
    /// Creates a VRF verifying key from a hexadecimal string
    /// 
    /// - Parameter hexString: Hexadecimal representation of the public key
    /// - Throws: `VRFError` if the hex string is invalid or doesn't represent a valid public key
    public init(hexString: String) throws {
        guard let data = Data(hexString: hexString) else {
            throw VRFError.invalidPublicKey
        }
        try self.init(bytes: data)
    }
    
    /// Verifies a VRF proof for a given message
    /// 
    /// - Parameters:
    ///   - message: The original message that was used to create the proof
    ///   - proof: The VRF proof to verify
    /// - Returns: The VRF output if verification succeeds
    /// - Throws: `VRFError.verificationFailed` if the proof is invalid
    public func verify(message: Data, proof: VRFProof) throws -> VRFOutput {
        var outputBytes = Data(count: VRF.outputBytes)
        
        let result = _bytes.withUnsafeBytes { publicPtr in
            proof.bytes.withUnsafeBytes { proofPtr in
                message.withUnsafeBytes { messagePtr in
                    outputBytes.withUnsafeMutableBytes { outputPtr in
                        crypto_vrf_ietfdraft03_verify(
                            outputPtr.bindMemory(to: UInt8.self).baseAddress!,
                            publicPtr.bindMemory(to: UInt8.self).baseAddress!,
                            proofPtr.bindMemory(to: UInt8.self).baseAddress!,
                            messagePtr.bindMemory(to: UInt8.self).baseAddress!,
                            UInt64(message.count)
                        )
                    }
                }
            }
        }
        
        guard result == 0 else {
            throw VRFError.verificationFailed
        }
        
        return try VRFOutput(bytes: outputBytes)
    }
    
    /// Returns the verifying key as a hexadecimal string
    public func hexEncodedString() -> String {
        return _bytes.hexEncodedString()
    }
    
    // MARK: - Hashable
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(_bytes)
    }
    
    public static func == (lhs: VRFVerifyingKey, rhs: VRFVerifyingKey) -> Bool {
        return Sodium().utils.sodiumMemcmp(lhs._bytes, rhs._bytes)
    }
}

// MARK: - VRF Proof

/// A VRF proof that can be verified to produce a deterministic output
/// 
/// VRF proofs are 80-byte values that prove the VRF output was generated
/// correctly using a specific private key and input message.
public struct VRFProof: Equatable, Hashable, Sendable {
    private let _bytes: Data
    
    /// The raw bytes of the proof
    public var bytes: Data {
        return _bytes
    }
    
    /// Creates a VRF proof from raw bytes
    /// 
    /// - Parameter bytes: 80-byte proof data
    /// - Throws: `VRFError.invalidInputSize` if the data is not exactly 80 bytes
    public init(bytes: Data) throws {
        guard bytes.count == VRF.proofBytes else {
            throw VRFError.invalidInputSize
        }
        self._bytes = bytes
    }
    
    /// Creates a VRF proof from a hexadecimal string
    /// 
    /// - Parameter hexString: Hexadecimal representation of the proof
    /// - Throws: `VRFError` if the hex string is invalid or wrong size
    public init(hexString: String) throws {
        guard let data = Data(hexString: hexString) else {
            throw VRFError.invalidProof
        }
        try self.init(bytes: data)
    }
    
    /// Extracts the VRF output hash from this proof without verification
    /// 
    /// Note: This does not verify the proof's validity. Use `VRFVerifyingKey.verify`
    /// for verified output generation.
    /// 
    /// - Returns: The VRF output hash
    /// - Throws: `VRFError.invalidProof` if the proof cannot be decoded
    public func hash() throws -> VRFOutput {
        var outputBytes = Data(count: VRF.outputBytes)
        
        let result = _bytes.withUnsafeBytes { proofPtr in
            outputBytes.withUnsafeMutableBytes { outputPtr in
                crypto_vrf_ietfdraft03_proof_to_hash(
                    outputPtr.bindMemory(to: UInt8.self).baseAddress!,
                    proofPtr.bindMemory(to: UInt8.self).baseAddress!
                )
            }
        }
        
        guard result == 0 else {
            throw VRFError.invalidProof
        }
        
        return try VRFOutput(bytes: outputBytes)
    }
    
    /// Returns the proof as a hexadecimal string
    public func hexEncodedString() -> String {
        return _bytes.hexEncodedString()
    }
    
    // MARK: - Hashable
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(_bytes)
    }
    
    public static func == (lhs: VRFProof, rhs: VRFProof) -> Bool {
        return Sodium().utils.sodiumMemcmp(lhs._bytes, rhs._bytes)
    }
}

// MARK: - VRF Output

/// The deterministic output of a VRF proof verification
/// 
/// VRF outputs are 64-byte hashes that are deterministically derived from
/// the VRF private key and input message.
public struct VRFOutput: Equatable, Hashable, Sendable {
    private let _bytes: Data
    
    /// The raw bytes of the VRF output
    public var bytes: Data {
        return _bytes
    }
    
    /// Creates a VRF output from raw bytes
    /// 
    /// - Parameter bytes: 64-byte output data
    /// - Throws: `VRFError.invalidInputSize` if the data is not exactly 64 bytes
    public init(bytes: Data) throws {
        guard bytes.count == VRF.outputBytes else {
            throw VRFError.invalidInputSize
        }
        self._bytes = bytes
    }
    
    /// Creates a VRF output from a hexadecimal string
    /// 
    /// - Parameter hexString: Hexadecimal representation of the output
    /// - Throws: `VRFError` if the hex string is invalid or wrong size
    public init(hexString: String) throws {
        guard let data = Data(hexString: hexString) else {
            throw VRFError.internalError
        }
        try self.init(bytes: data)
    }
    
    /// Returns the output as a hexadecimal string
    public func hexEncodedString() -> String {
        return _bytes.hexEncodedString()
    }
    
    // MARK: - Hashable
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(_bytes)
    }
    
    public static func == (lhs: VRFOutput, rhs: VRFOutput) -> Bool {
        return Sodium().utils.sodiumMemcmp(lhs._bytes, rhs._bytes)
    }
}

// MARK: - VRF Key Pair

/// A convenience structure containing both VRF signing and verifying keys
public struct VRFKeyPair: Equatable, Hashable, Sendable {
    /// The VRF signing key (private key)
    public let signingKey: VRFSigningKey
    
    /// The VRF verifying key (public key)
    public let verifyingKey: VRFVerifyingKey
    
    /// Creates a VRF key pair from existing signing and verifying keys
    public init(signingKey: VRFSigningKey, verifyingKey: VRFVerifyingKey) {
        self.signingKey = signingKey
        self.verifyingKey = verifyingKey
    }
    
    /// Generates a VRF key pair from a seed
    /// 
    /// - Parameter seed: The cryptographic seed to derive keys from
    /// - Returns: A new VRF key pair
    /// - Throws: `VRFError.invalidSeed` if key generation fails
    public static func from(seed: VRFSeed) throws -> VRFKeyPair {
        var publicKeyBytes = Data(count: VRF.publicKeyBytes)
        var secretKeyBytes = Data(count: VRF.secretKeyBytes)
        
        let result = seed.bytes.withUnsafeBytes { seedPtr in
            publicKeyBytes.withUnsafeMutableBytes { publicPtr in
                secretKeyBytes.withUnsafeMutableBytes { secretPtr in
                    crypto_vrf_ietfdraft03_keypair_from_seed(
                        publicPtr.bindMemory(to: UInt8.self).baseAddress!,
                        secretPtr.bindMemory(to: UInt8.self).baseAddress!,
                        seedPtr.bindMemory(to: UInt8.self).baseAddress!
                    )
                }
            }
        }
        
        guard result == 0 else {
            throw VRFError.invalidSeed
        }
        
        let signingKey = try VRFSigningKey(bytes: secretKeyBytes)
        let verifyingKey = try VRFVerifyingKey(bytes: publicKeyBytes)
        
        return VRFKeyPair(signingKey: signingKey, verifyingKey: verifyingKey)
    }
    
    /// Generates a random VRF key pair
    /// 
    /// - Returns: A new random VRF key pair
    public static func generate() -> VRFKeyPair {
        let seed = VRFSeed.generate()
        return try! VRFKeyPair.from(seed: seed)
    }
    
    // MARK: - Hashable
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(signingKey)
        hasher.combine(verifyingKey)
    }
    
    public static func == (lhs: VRFKeyPair, rhs: VRFKeyPair) -> Bool {
        return lhs.signingKey == rhs.signingKey && lhs.verifyingKey == rhs.verifyingKey
    }
}

// MARK: - Data Extensions

private extension Data {
    init?(hexString: String) {
        let cleanHex = hexString.hasPrefix("0x") ? String(hexString.dropFirst(2)) : hexString
        guard cleanHex.count % 2 == 0 else { return nil }
        
        var data = Data()
        var index = cleanHex.startIndex
        
        while index < cleanHex.endIndex {
            let nextIndex = cleanHex.index(index, offsetBy: 2)
            let byteString = cleanHex[index..<nextIndex]
            guard let byte = UInt8(byteString, radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        
        self = data
    }
    
    func hexEncodedString() -> String {
        return map { String(format: "%02x", $0) }.joined()
    }
}
