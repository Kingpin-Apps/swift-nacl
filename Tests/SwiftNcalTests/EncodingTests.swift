import Testing

@testable import SwiftNcal

@Suite("Encoding and decoding utilities")
struct EncoderTests {
    let text = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let hexEncodedText = "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67".data(using: .utf8)!
    let base16EncodedText = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==".data(using: .utf8)!
    let base32EncodedText = "KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWO===".data(using: .utf8)!
    let base64EncodedText = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==".data(using: .utf8)!
    let urlSafeBase64EncodedText = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==".data(using: .utf8)!

    @Test("Raw encoder round-trips input data")
    func testRawEncoder() async throws {
        let encoded = RawEncoder.encode(data: text)
        let decoded = RawEncoder.decode(data: encoded)
        #expect(encoded == text, "RawEncoder encode failed")
        #expect(decoded == text, "RawEncoder decode failed")
    }

    @Test("Hex encoder produces expected encoding and decodes back")
    func testHexEncoder() async throws {
        let encoded = HexEncoder.encode(data: text)
        let decoded = HexEncoder.decode(data: encoded)
        #expect(encoded == hexEncodedText, "HexEncoder encode failed")
        #expect(decoded == text, "HexEncoder decode failed")
    }

    @Test("Base16 encoder produces expected encoding and decodes back")
    func testBase16Encoder() async throws {
        let encoded = Base16Encoder.encode(data: text)
        let decoded = Base16Encoder.decode(data: encoded)
        #expect(encoded == base16EncodedText, "Base16Encoder encode failed")
        #expect(decoded == text, "Base16Encoder decode failed")
    }

    @Test("Base32 encoder produces expected encoding and decodes back")
    func testBase32Encoder() async throws {
        let encoded = Base32Encoder.encode(data: text)
        let decoded = Base32Encoder.decode(data: encoded)
        #expect(encoded == base32EncodedText, "Base32Encoder encode failed")
        #expect(decoded == text, "Base32Encoder decode failed")
    }

    @Test("Base64 encoder produces expected encoding and decodes back")
    func testBase64Encoder() async throws {
        let encoded = Base64Encoder.encode(data: text)
        let decoded = Base64Encoder.decode(data: encoded)
        #expect(encoded == base64EncodedText, "Base64Encoder encode failed")
        #expect(decoded == text, "Base64Encoder decode failed")
    }

    @Test("URL-safe Base64 encoder produces expected encoding and decodes back")
    func testURLSafeBase64Encoder() async throws {
        let encoded = URLSafeBase64Encoder.encode(data: text)
        let decoded = URLSafeBase64Encoder.decode(data: encoded)
        #expect(encoded == urlSafeBase64EncodedText, "URLSafeBase64Encoder encode failed")
        #expect(decoded == text, "URLSafeBase64Encoder decode failed")
    }
}
