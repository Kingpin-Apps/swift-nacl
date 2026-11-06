import Foundation
import Testing

@testable import SwiftNaCl

@Suite("Encoding and decoding utilities")
struct EncoderTests {
    let text = "The quick brown fox jumps over the lazy dog".data(using: .utf8)!
    let hexEncodedText = "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67".data(using: .utf8)!
    let base16EncodedText = "54686520717569636B2062726F776E20666F78206A756D7073206F76657220746865206C617A7920646F67".data(using: .utf8)!
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

    @Test("Base16 encoder matches the RFC 4648 test vectors", arguments: [
        ("", ""),
        ("f", "66"),
        ("fo", "666F"),
        ("foo", "666F6F"),
        ("foob", "666F6F62"),
        ("fooba", "666F6F6261"),
        ("foobar", "666F6F626172"),
    ])
    func testBase16RFC4648Vectors(input: String, expected: String) async throws {
        let raw = input.data(using: .utf8)!
        let encoded = Base16Encoder.encode(data: raw)
        #expect(String(data: encoded, encoding: .utf8) == expected)
        #expect(Base16Encoder.decode(data: encoded) == raw)
    }

    @Test("Base16 encoder covers every byte value and decodes lowercase input")
    func testBase16AllBytes() async throws {
        let raw = Data(0...255)
        let encoded = Base16Encoder.encode(data: raw)
        #expect(encoded.count == 512)
        #expect(String(data: encoded.prefix(8), encoding: .utf8) == "00010203")
        #expect(String(data: encoded.suffix(8), encoding: .utf8) == "FCFDFEFF")
        #expect(Base16Encoder.decode(data: encoded) == raw)
        #expect(Base16Encoder.decode(data: HexEncoder.encode(data: raw)) == raw)
        #expect(String(data: encoded, encoding: .utf8) == String(data: HexEncoder.encode(data: raw), encoding: .utf8)!.uppercased())
    }

    @Test("Base16 output is not Base64")
    func testBase16IsNotBase64() async throws {
        #expect(Base16Encoder.encode(data: text) != Base64Encoder.encode(data: text))
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
