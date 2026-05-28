import Clibsodium

public struct Lib {
    public let VersionString = String(validatingCString: sodium_version_string())!
    public let Major = Int(sodium_library_version_major())
    public let Minor = Int(sodium_library_version_minor())
}

public struct Version {
    public let lib = Lib()
}
