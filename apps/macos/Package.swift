// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Keystead",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(name: "Keystead", path: "Sources/Keystead")
    ]
)
