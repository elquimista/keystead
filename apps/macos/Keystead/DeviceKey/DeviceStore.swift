import Foundation

/// What this Mac keeps, in the app's Application Support folder inside its sandbox
/// container:
///
/// - `profile.json`: the shared profile format, written by the Rust client (server, pinned
///   owner keys, and the encrypted copy of folders and items).
/// - `device.json`: this Mac's device id, the handles of its two Secure Enclave keys, and
///   the account secret wrapped to one of them.
///
/// None of it is readable on its own. The handles work only in this Mac's Secure Enclave,
/// after Touch ID or the Mac password, and everything secret is encrypted to them.
struct DeviceStore {
    struct Device: Codable {
        var deviceId: String
        /// Handle of the key that unwraps the account secret.
        var agreementKey: Data
        /// Handle of the key that signs in to the server.
        var signingKey: Data
        var accountSecret: WrappedKey
    }

    private let directory = URL.applicationSupportDirectory
        .appending(path: "Keystead", directoryHint: .isDirectory)
    var profileURL: URL { directory.appending(path: "profile.json") }
    private var deviceURL: URL { directory.appending(path: "device.json") }

    var isEnrolled: Bool {
        FileManager.default.fileExists(atPath: profileURL.path)
            && FileManager.default.fileExists(atPath: deviceURL.path)
    }

    func save(_ device: Device) throws {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(device).write(to: deviceURL, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: deviceURL.path)
    }

    func load() throws -> Device {
        try JSONDecoder().decode(Device.self, from: Data(contentsOf: deviceURL))
    }

    /// Forgets a device whose enrollment didn't finish.
    func removeDevice() {
        try? FileManager.default.removeItem(at: deviceURL)
    }

    /// Forgets the account on this Mac, for signing out: the profile and the device file.
    /// The Secure Enclave keys are gone with their handles; nothing else can use them.
    func forgetAccount() {
        try? FileManager.default.removeItem(at: profileURL)
        try? FileManager.default.removeItem(at: deviceURL)
    }
}
