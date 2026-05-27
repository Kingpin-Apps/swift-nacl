// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.
//
// On Apple platforms we ship a precompiled Clibsodium.xcframework with the
// Cardano libsodium fork. On Linux, Android, and WASI we compile
// IntersectMBO/libsodium from source vendored at ClibsodiumLinuxSource/.

import PackageDescription
import Foundation

let clibsodiumTarget: Target
#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
    // Apple: precompiled xcframework slice with the Cardano libsodium fork.
    clibsodiumTarget = .binaryTarget(
        name: "Clibsodium",
        path: "Clibsodium.xcframework")
#else
    // Linux / Android / WASI: compile IntersectMBO/libsodium from vendored source.
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
            //
            // Universally safe defines (C99 / standard wasi-libc + bionic + glibc):
            .define("CONFIGURED", to: "1"),
            .define("_GNU_SOURCE", to: "1"),
            .define("HAVE_C_VARARRAYS", to: "1"),
            .define("HAVE_ATOMIC_OPS", to: "1"),
            .define("HAVE_TI_MODE", to: "1"),
            .define("HAVE_SYS_RANDOM_H", to: "1"),
            .define("HAVE_NANOSLEEP", to: "1"),
            .define("HAVE_POSIX_MEMALIGN", to: "1"),
            // Android bionic only added getentropy() at API 28; gating here
            // matches the runtime weak-symbol check (`&getentropy == NULL`)
            // in randombytes/internal/randombytes_internal_random.c.
            // Apple platforms use the binary xcframework, so listing them
            // here is cosmetic but documents the intended scope.
            .define("HAVE_GETENTROPY", to: "1", .when(platforms: [.linux, .macOS, .iOS, .tvOS, .watchOS, .visionOS])),
            .define("DEV_MODE", to: "1"),
            // glibc-only — Android NDK's bionic and WASI's wasi-libc lack it
            // (libsodium falls back to a memset_s / OPENSSL_cleanse path).
            .define("HAVE_EXPLICIT_BZERO", to: "1", .when(platforms: [.linux])),
            // POSIX-y features present on Linux/Android but absent on WASI.
            // sys/mman.h and signal.h both #error on WASI without the
            // emulation flags below.
            .define("HAVE_INLINE_ASM", to: "1", .when(platforms: [.linux, .android])),
            .define("HAVE_SYS_MMAN_H", to: "1", .when(platforms: [.linux, .android])),
            .define("HAVE_MMAP", to: "1", .when(platforms: [.linux, .android])),
            .define("HAVE_MLOCK", to: "1", .when(platforms: [.linux, .android])),
            .define("HAVE_MADVISE", to: "1", .when(platforms: [.linux, .android])),
            .define("HAVE_MPROTECT", to: "1", .when(platforms: [.linux, .android])),
            .define("HAVE_GETPID", to: "1", .when(platforms: [.linux, .android])),
            .define("HAVE_PTHREAD", to: "1", .when(platforms: [.linux, .android])),
            .define("HAVE_CATCHABLE_SEGV", to: "1", .when(platforms: [.linux, .android])),
            .define("HAVE_CATCHABLE_ABRT", to: "1", .when(platforms: [.linux, .android])),
            // WASI: sodium/utils.c unconditionally `#include <signal.h>`, and
            // wasi-libc's signal.h `#error`s without _WASI_EMULATED_SIGNAL.
            // Consumers also need `-lwasi-emulated-signal` at link time —
            // see linkerSettings below.
            .define("_WASI_EMULATED_SIGNAL", to: "1", .when(platforms: [.wasi])),
        ],
        linkerSettings: [
            .linkedLibrary("wasi-emulated-signal", .when(platforms: [.wasi])),
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
