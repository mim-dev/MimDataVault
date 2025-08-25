// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "MimDataVault",
    platforms: [.iOS(.v15)],
    products: [
        .library(
            name: "MimDataVault", targets: ["MimDataVault"]),
    ],
    targets: [
        .target(name: "MimDataVault"),
        .testTarget(
            name: "MimDataVaultTests", dependencies: ["MimDataVault"]
        ),
    ]
)
