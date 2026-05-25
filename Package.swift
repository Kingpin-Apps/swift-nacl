// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.
//
// This manifest is used for Swift 6.0 and 6.1. Swift 6.2+ uses
// Package@swift-6.2.swift, which delivers libsodium via a SE-0435 staticLibrary
// artifact bundle (Clibsodium.artifactbundle). Pre-6.2 SwiftPM doesn't understand
// that bundle type, so we instead compile IntersectMBO/libsodium from source
// vendored at ClibsodiumLinuxSource/.

import PackageDescription
import Foundation

let clibsodiumTarget: Target
#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
    // Apple: precompiled xcframework slice with the Cardano libsodium fork.
    clibsodiumTarget = .binaryTarget(
        name: "Clibsodium",
        path: "Clibsodium.xcframework")
#else
    // Linux / other: compile IntersectMBO/libsodium from vendored source.
    // The upstream commit is recorded in ClibsodiumLinuxSource/UPSTREAM_COMMIT;
    // refresh via scripts/sync-libsodium-source.sh.
    //
    // Excluded files are CPU-specific SIMD implementations (AVX2, SSSE3,
    // SSE4.1, AVX-512F). libsodium's runtime CPU dispatch in
    // sodium/runtime.c routes to the ref/portable fallback when these
    // aren't compiled in. Building them via SwiftPM would require per-TU
    // compile flags (`-mavx2`, etc.) which SwiftPM doesn't expose per-source.
    clibsodiumTarget = .target(
        name: "Clibsodium",
        path: "ClibsodiumLinuxSource",
        exclude: [
            "UPSTREAM_COMMIT",
            "crypto_generichash/blake2b/ref/blake2b-compress-avx2.c",
            "crypto_generichash/blake2b/ref/blake2b-compress-sse41.c",
            "crypto_generichash/blake2b/ref/blake2b-compress-ssse3.c",
            "crypto_pwhash/argon2/argon2-fill-block-avx2.c",
            "crypto_pwhash/argon2/argon2-fill-block-avx512f.c",
            "crypto_pwhash/argon2/argon2-fill-block-ssse3.c",
            "crypto_stream/chacha20/dolbeau/chacha20_dolbeau-avx2.c",
            "crypto_stream/chacha20/dolbeau/chacha20_dolbeau-ssse3.c",
        ],
        publicHeadersPath: "include",
        cSettings: [
            .headerSearchPath("include"),
            .headerSearchPath("include/sodium"),
            // Match what ./configure --disable-asm --disable-pie would produce.
            .define("CONFIGURED", to: "1"),
            .define("_GNU_SOURCE", to: "1"),
            .define("HAVE_C_VARARRAYS", to: "1"),
            .define("HAVE_ATOMIC_OPS", to: "1"),
            .define("HAVE_TI_MODE", to: "1"),
            .define("HAVE_INLINE_ASM", to: "1"),
            .define("HAVE_SYS_MMAN_H", to: "1"),
            .define("HAVE_SYS_RANDOM_H", to: "1"),
            .define("HAVE_GETPID", to: "1"),
            .define("HAVE_MMAP", to: "1"),
            .define("HAVE_MLOCK", to: "1"),
            .define("HAVE_MADVISE", to: "1"),
            .define("HAVE_MPROTECT", to: "1"),
            .define("HAVE_NANOSLEEP", to: "1"),
            .define("HAVE_POSIX_MEMALIGN", to: "1"),
            .define("HAVE_GETENTROPY", to: "1"),
            .define("HAVE_EXPLICIT_BZERO", to: "1"),
            .define("HAVE_PTHREAD", to: "1"),
            .define("HAVE_CATCHABLE_SEGV", to: "1"),
            .define("HAVE_CATCHABLE_ABRT", to: "1"),
            .define("DEV_MODE", to: "1"),
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
