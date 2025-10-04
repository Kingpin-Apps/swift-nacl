// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription
import Foundation

let clibsodiumTarget: Target
#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
    // Use precompiled binary framework for Apple platforms
    clibsodiumTarget = .binaryTarget(
        name: "Clibsodium",
        path: "Clibsodium.xcframework")
#elseif os(Linux)
    // Use bundled artifact bundle for Linux
    clibsodiumTarget = .binaryTarget(
        name: "Clibsodium",
        path: "Clibsodium.artifactbundle")
#else
    // Fallback to system library for other platforms
    clibsodiumTarget = .systemLibrary(
        name: "Clibsodium",
        path: "Clibsodium",
        pkgConfig: "libsodium",
        providers: [
            .apt(["libsodium-dev"]),
            .yum(["libsodium-devel"]),
            .brew(["libsodium"]),
        ])
#endif

let package = Package(
    name: "SwiftNcal",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "Clibsodium",
            targets: ["Clibsodium"]),
        .library(
            name: "SwiftNcal",
            targets: ["SwiftNcal"]),
    ],
    dependencies: [
        .package(url: "https://github.com/norio-nomura/Base32.git", from: "0.9.0"),
        .package(url: "https://github.com/attaswift/BigInt.git", .upToNextMinor(from: "5.3.0")),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        clibsodiumTarget,
        .target(
            name: "SwiftNcal",
            dependencies: ["Clibsodium", "Base32", "BigInt"],
            exclude: ["libsodium", "Info.plist"]
        ),
        .testTarget(
            name: "SwiftNcalTests",
            dependencies: ["SwiftNcal"],
            exclude: ["Info.plist"],
            resources: [
               .copy("data")
           ]
        ),
    ]
)
