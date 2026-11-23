import Foundation

/// Where this Mac keeps its device key handle and the wrapped account secret: the app's
/// Application Support folder, inside its sandbox container.
///
/// Neither file is secret on its own. The handle only works in this Mac's Secure Enclave,
/// after Touch ID or the Mac password, and the account secret is encrypted to that key.
/// That's why no Keychain entitlement (and so no provisioning profile) is needed yet.
struct DeviceStore {
    struct Saved {
        let handle: Data
        let wrappedSecret: WrappedKey
    }

    private let directory = URL.applicationSupportDirectory
        .appending(path: "Keystead", directoryHint: .isDirectory)
    private var handleURL: URL { directory.appending(path: "device-key.handle") }
    private var wrappedSecretURL: URL { directory.appending(path: "account-secret.json") }

    var hasDeviceKey: Bool {
        FileManager.default.fileExists(atPath: wrappedSecretURL.path)
    }

    func save(handle: Data, wrappedSecret: WrappedKey) throws {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try write(handle, to: handleURL)
        try write(JSONEncoder().encode(wrappedSecret), to: wrappedSecretURL)
    }

    func load() throws -> Saved {
        Saved(
            handle: try Data(contentsOf: handleURL),
            wrappedSecret: try JSONDecoder().decode(
                WrappedKey.self, from: Data(contentsOf: wrappedSecretURL)))
    }

    private func write(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
