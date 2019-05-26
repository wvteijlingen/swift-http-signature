// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftHTTPSignature",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "SwiftHTTPSignature",
            targets: ["SwiftHTTPSignature"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
      .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "1.0.0")),
  		.package(url: "https://github.com/IBM-Swift/BlueRSA", .upToNextMinor(from: "1.0.31"))
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "SwiftHTTPSignature",
            dependencies: ["CryptoSwift", "CryptorRSA"]),
        .testTarget(
            name: "SwiftHTTPSignatureTests",
            dependencies: ["SwiftHTTPSignature"]),
    ]
)
