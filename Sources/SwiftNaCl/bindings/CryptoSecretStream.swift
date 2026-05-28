import Clibsodium
import Foundation

/// An object wrapping the crypto_secretstream_xchacha20poly1305 state.
public class CryptoSecretstreamXchacha20poly1305State {
    var statebuf: [UInt8]
    var rawbuf: [UInt8]?
    var tagbuf: [UInt8]?

    init() {
        self.statebuf = [UInt8](
            repeating: 0,
            count: crypto_secretstream_xchacha20poly1305_statebytes()
        )
        self.rawbuf = nil
        self.tagbuf = nil
    }
}

public struct CryptoSecretStream {
    public let xchacha20poly1305Abytes = crypto_secretstream_xchacha20poly1305_abytes()
    public let xchacha20poly1305Headerbytes = crypto_secretstream_xchacha20poly1305_headerbytes()
    public let xchacha20poly1305Keybytes = crypto_secretstream_xchacha20poly1305_keybytes()
    public let xchacha20poly1305MessagebytesMax = crypto_secretstream_xchacha20poly1305_messagebytes_max()
    public let xchacha20poly1305Statebytes = crypto_secretstream_xchacha20poly1305_statebytes()

    public let xchacha20poly1305TagMessage = crypto_secretstream_xchacha20poly1305_tag_message()
    public let xchacha20poly1305TagPush = crypto_secretstream_xchacha20poly1305_tag_push()
    public let xchacha20poly1305TagRekey = crypto_secretstream_xchacha20poly1305_tag_rekey()
    public let xchacha20poly1305TagFinal = crypto_secretstream_xchacha20poly1305_tag_final()

    /**
     Generates a key for use with `cryptoSecretstreamXchacha20poly1305InitPush`.

     - Returns: The generated key as `Data`.
     */
    public func xchacha20poly1305Keygen() -> Data {
        var keybuf = [UInt8](repeating: 0, count: xchacha20poly1305Keybytes)
        crypto_secretstream_xchacha20poly1305_keygen(&keybuf)
        return Data(keybuf)
    }

    /**
     Initializes a crypto_secretstream_xchacha20poly1305 encryption buffer.

     - Parameters:
       - state: A secretstream state object.
       - key: The key to use for encryption.
     - Returns: The header as `Data`.
     - Throws: `CryptoError.invalidKey` if the key length is invalid.
     */
    public func xchacha20poly1305InitPush(state: CryptoSecretstreamXchacha20poly1305State, key: Data) throws -> Data {
        try ensure(key.count == xchacha20poly1305Keybytes, raising: .valueError("Invalid key"))

        var headerbuf = [UInt8](repeating: 0, count: xchacha20poly1305Headerbytes)
        
        let rc = state.statebuf.withUnsafeMutableBytes { statebufPtr in
            headerbuf.withUnsafeMutableBytes { headerPtr in
                guard let statebufRawPtr = statebufPtr.baseAddress,
                      let headerRawPtr = headerPtr.baseAddress else {
                    return Int32(-1)
                }
                return crypto_secretstream_xchacha20poly1305_init_push(
                    statebufRawPtr.assumingMemoryBound(to: crypto_secretstream_xchacha20poly1305_state.self),
                    headerRawPtr.assumingMemoryBound(to: UInt8.self),
                    [UInt8](key)
                )
            }
        }
        
        try ensure(rc == 0, raising: .cryptoError("Encryption failed"))

        return Data(headerbuf)
    }

    /**
     Adds an encrypted message to the secret stream.

     - Parameters:
       - state: A secretstream state object.
       - message: The message to encrypt.
       - additionalData: Additional data to include in the authentication tag.
       - tag: The message tag.
     - Returns: The ciphertext as `Data`.
     - Throws: `CryptoError.encryptionFailed` if encryption fails.
     */
    public func xchacha20poly1305Push(state: CryptoSecretstreamXchacha20poly1305State, message: Data, additionalData: Data? = nil, tag: UInt8? = nil) throws -> Data {
        let tagMessage = tag ?? xchacha20poly1305TagMessage
        let clen = message.count + xchacha20poly1305Abytes
        if state.rawbuf == nil || state.rawbuf!.count < clen {
            state.rawbuf = [UInt8](repeating: 0, count: clen)
        }

        let ad = additionalData ?? Data()
        
        let rc = state.statebuf.withUnsafeMutableBytes { statebufPtr in
            state.rawbuf!.withUnsafeMutableBytes { rawbufPtr in
                guard let statebufRawPtr = statebufPtr.baseAddress,
                      let rawbufRawPtr = rawbufPtr.baseAddress else {
                    return Int32(-1)
                }
                return crypto_secretstream_xchacha20poly1305_push(
                    statebufRawPtr.assumingMemoryBound(to: crypto_secretstream_xchacha20poly1305_state.self),
                    rawbufRawPtr.assumingMemoryBound(to: UInt8.self),
                    nil,
                    [UInt8](message),
                    UInt64(message.count),
                    [UInt8](ad),
                    UInt64(ad.count),
                    tagMessage
                )
            }
        }
        
        try ensure(rc == 0, raising: .cryptoError("Encryption failed"))

        return Data(state.rawbuf!.prefix(clen))
    }

    /**
     Initializes a crypto_secretstream_xchacha20poly1305 decryption buffer.

     - Parameters:
       - state: A secretstream state object.
       - header: The header to use for decryption.
       - key: The key to use for decryption.
     - Throws: `CryptoError.invalidKey` if the key length is invalid.
               `CryptoError.invalidCiphertext` if the header length is invalid.
     */
    public func xchacha20poly1305InitPull(state: CryptoSecretstreamXchacha20poly1305State, header: Data, key: Data) throws {
        try ensure(key.count == xchacha20poly1305Keybytes, raising: .valueError("Invalid key"))
        try ensure(header.count == xchacha20poly1305Headerbytes, raising: .valueError("Invalid Cipher text"))

        if state.tagbuf == nil {
            state.tagbuf = [UInt8](repeating: 0, count: 1)
        }
        
        let rc = state.statebuf.withUnsafeMutableBytes { statebufPtr in
                guard let statebufRawPtr = statebufPtr.baseAddress else {
                    return Int32(-1)
                }
                return crypto_secretstream_xchacha20poly1305_init_pull(
                    statebufRawPtr.assumingMemoryBound(to: crypto_secretstream_xchacha20poly1305_state.self),
                    [UInt8](header),
                    [UInt8](key)
                )
        }
        
        try ensure(rc == 0, raising: .cryptoError("Unexpected failure"))
    }

    /**
     Reads a decrypted message from the secret stream.

     - Parameters:
       - state: A secretstream state object.
       - ciphertext: The ciphertext to decrypt.
       - additionalData: Additional data to include in the authentication tag.
     - Returns: A tuple containing the decrypted message and the tag.
     - Throws: `CryptoError.decryptionFailed` if decryption fails.
     */
    public func xchacha20poly1305Pull(state: CryptoSecretstreamXchacha20poly1305State, ciphertext: Data, additionalData: Data? = nil) throws -> (Data, Int) {
        let mlen = ciphertext.count - xchacha20poly1305Abytes
        if state.rawbuf == nil || state.rawbuf!.count < mlen {
            state.rawbuf = [UInt8](repeating: 0, count: mlen)
        }

        let ad = additionalData ?? Data()
        
        let rc = state.statebuf.withUnsafeMutableBytes { statebufPtr in
            state.rawbuf?.withUnsafeMutableBytes { rawbufPtr in
                state.tagbuf?.withUnsafeMutableBytes { tagbufPtr in
                    guard let statebufRawPtr = statebufPtr.baseAddress,
                          let rawbufRawPtr = rawbufPtr.baseAddress,
                          let tagbufRawPtr = tagbufPtr.baseAddress else {
                        return Int32(-1)
                    }
                    return crypto_secretstream_xchacha20poly1305_pull(
                        statebufRawPtr.assumingMemoryBound(to: crypto_secretstream_xchacha20poly1305_state.self),
                        rawbufRawPtr.assumingMemoryBound(to: UInt8.self),
                        nil,
                        tagbufRawPtr.assumingMemoryBound(to: UInt64.self),
                        [UInt8](ciphertext),
                        UInt64(ciphertext.count),
                        [UInt8](ad),
                        UInt64(ad.count)
                    )
                }
            }
        }
        
        try ensure(rc == 0, raising: .cryptoError("Unexpected failure"))

        return (Data(state.rawbuf!.prefix(mlen)), Int(state.tagbuf![0]))
    }

    /**
     Explicitly changes the encryption key in the stream.
     
      - Note:Normally the stream is re-keyed as needed or an explicit ``tag`` of
     :data:`.crypto_secretstream_xchacha20poly1305_TAG_REKEY` is added to a
     message to ensure forward secrecy, but this method can be used instead
     if the re-keying is controlled without adding the tag.
    
     - Parameters:
       - state: A secretstream state object.
     */
    public func xchacha20poly1305Rekey(state: CryptoSecretstreamXchacha20poly1305State) {
        state.statebuf.withUnsafeMutableBytes { statebufPtr in
            crypto_secretstream_xchacha20poly1305_rekey(
                statebufPtr.baseAddress!
                    .assumingMemoryBound(
                        to: crypto_secretstream_xchacha20poly1305_state.self
                    )
            )
        }
    }
}
