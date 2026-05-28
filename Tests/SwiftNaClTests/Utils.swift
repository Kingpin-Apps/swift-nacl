import Foundation

func readCryptoTestVectors(fileName: String, maxElements: Int = 0, delimiter: String) -> [(
    Data, Data, Data
)] {
    var vectors: [(Data, Data, Data)] = []

    // Locate the file in the test bundle
    guard let filePath = Bundle.module.path(forResource: fileName, ofType: "txt", inDirectory: "data") else {
        fatalError("File not found: \(fileName).txt")
    }

    let content = try! String(contentsOfFile: filePath, encoding: .utf8)
    let lines = content.split(separator: "\n")

    for line in lines {
        if !line.isEmpty && !line.hasPrefix("#") {
            let components = line.split(separator: Character(delimiter))
            if components.count >= 2 {
                let seed = Data(hexString: String(components[0]))
                let publicKey = Data(hexString: String(components[1].prefix(64)))
                let secretKey = Data(hexString: String(components[1].suffix(64)))
                vectors.append((seed, publicKey, secretKey))
            }
        }
    }
    return vectors
}

extension Data {
    init(hexString: String) {
        self.init()
        var hex = hexString
        while hex.count > 0 {
            let c = String(hex.prefix(2))
            hex = String(hex.dropFirst(2))
            var ch: UInt64 = 0
            Scanner(string: c).scanHexInt64(&ch)
            var char = UInt8(ch)
            self.append(&char, count: 1)
        }
    }
}
