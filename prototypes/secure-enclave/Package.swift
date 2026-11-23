// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SecureEnclavePrototype",
    platforms: [.macOS(.v14)],
    targets: [
        .target(name: "KeysteadDeviceKey"),
        .executableTarget(name: "se-proto", dependencies: ["KeysteadDeviceKey"]),
        .testTarget(name: "KeysteadDeviceKeyTests", dependencies: ["KeysteadDeviceKey"]),
    ]
)
