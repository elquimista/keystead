import CryptoKit
import Foundation
import KeysteadDeviceKey

let usage = """
    usage: se-proto <command>

      info     Show Secure Enclave and Touch ID availability
      setup    Create a Secure Enclave device key and wrap a new account key to it
      unlock   Approve with Touch ID, then unwrap the account key and time it
      reset    Delete the prototype's stored data
    """

let commands = Commands(store: PrototypeStore())

do {
    switch CommandLine.arguments.dropFirst().first {
    case "info": commands.info()
    case "setup": try commands.setup()
    case "unlock": try commands.unlock()
    case "reset": try commands.reset()
    default:
        print(usage)
        exit(2)
    }
} catch {
    FileHandle.standardError.write(Data("error: \(error)\n".utf8))
    exit(1)
}

struct Commands {
    let store: PrototypeStore

    func info() {
        print("Secure Enclave:  \(SecureEnclaveDeviceKey.isAvailable ? "available" : "not available")")
        print("User check:      \(DeviceAuthentication.biometryDescription())")
        print("Prototype data:  \(store.directory.path)")
        print("Set up:          \(store.isSetUp ? "yes" : "no")")
    }

    func setup() throws {
        guard SecureEnclaveDeviceKey.isAvailable else { throw PrototypeError.noSecureEnclave }
        guard !store.isSetUp else { throw PrototypeError.alreadySetUp }

        let deviceKey = try SecureEnclaveDeviceKey.create()
        let accountKey = SymmetricKey(size: .bits256)
        let wrapped = try AccountKeyWrap.wrap(accountKey, to: deviceKey.publicKey)
        try store.save(
            deviceKey: deviceKey.dataRepresentation, wrapped: wrapped,
            fingerprint: fingerprint(of: accountKey))

        print("Created a Secure Enclave device key and wrapped a new account key to it.")
        print("Account key fingerprint: \(fingerprint(of: accountKey))")
        print("Next: run `se-proto unlock` and approve with Touch ID or your Mac password.")
    }

    func unlock() throws {
        guard store.isSetUp else { throw PrototypeError.notSetUp }
        let saved = try store.load()

        let clock = ContinuousClock()
        let authStart = clock.now
        let context = try DeviceAuthentication.authenticate(
            reason: "unlock the Keystead prototype")
        let authTime = clock.now - authStart

        // Restore and unwrap twice with the same authenticated context: the second run
        // shows that one Touch ID approval covers repeated use without another prompt.
        var accountKey: SymmetricKey?
        var unwrapTimes: [Duration] = []
        for _ in 0..<2 {
            unwrapTimes.append(
                try clock.measure {
                    let deviceKey = try SecureEnclaveDeviceKey.restore(
                        from: saved.deviceKey, context: context)
                    accountKey = try AccountKeyWrap.unwrap(
                        saved.wrapped, with: deviceKey.privateKey)
                })
        }

        guard let accountKey, fingerprint(of: accountKey) == saved.fingerprint else {
            throw PrototypeError.fingerprintMismatch
        }
        print("Approval (Touch ID or password):    \(milliseconds(authTime))")
        print("Restore key and unwrap, 1st run:    \(milliseconds(unwrapTimes[0]))")
        print("Restore key and unwrap, 2nd run:    \(milliseconds(unwrapTimes[1]))")
        print("Account key fingerprint: \(saved.fingerprint) (matches setup)")
    }

    func reset() throws {
        try store.reset()
        print("Deleted \(store.directory.path)")
    }

    /// The first 8 bytes of the key's SHA-256 hash, to compare keys without printing them.
    private func fingerprint(of key: SymmetricKey) -> String {
        let digest = key.withUnsafeBytes { SHA256.hash(data: $0) }
        return digest.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    private func milliseconds(_ duration: Duration) -> String {
        let (seconds, attoseconds) = duration.components
        let ms = Double(seconds) * 1_000 + Double(attoseconds) / 1e15
        return String(format: "%.1f ms", ms)
    }
}

enum PrototypeError: Error, CustomStringConvertible {
    case noSecureEnclave, alreadySetUp, notSetUp, fingerprintMismatch

    var description: String {
        switch self {
        case .noSecureEnclave: "this Mac has no Secure Enclave"
        case .alreadySetUp: "already set up; run `se-proto reset` first"
        case .notSetUp: "not set up; run `se-proto setup` first"
        case .fingerprintMismatch: "unwrapped key doesn't match the one from setup"
        }
    }
}

/// Prototype-only storage in files. The app will keep these in the Keychain, which needs
/// a signed app with entitlements.
struct PrototypeStore {
    let directory: URL

    init() {
        if let override = ProcessInfo.processInfo.environment["KEYSTEAD_PROTO_DIR"] {
            directory = URL(filePath: override, directoryHint: .isDirectory)
        } else {
            directory = URL.applicationSupportDirectory.appending(
                path: "KeysteadPrototype", directoryHint: .isDirectory)
        }
    }

    private var deviceKeyURL: URL { directory.appending(path: "device-key.bin") }
    private var wrappedKeyURL: URL { directory.appending(path: "wrapped-account-key.json") }
    private var fingerprintURL: URL { directory.appending(path: "account-key-fingerprint.txt") }

    var isSetUp: Bool { FileManager.default.fileExists(atPath: wrappedKeyURL.path) }

    func save(deviceKey: Data, wrapped: WrappedAccountKey, fingerprint: String) throws {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try write(deviceKey, to: deviceKeyURL)
        try write(JSONEncoder().encode(wrapped), to: wrappedKeyURL)
        try write(Data(fingerprint.utf8), to: fingerprintURL)
    }

    func load() throws -> (deviceKey: Data, wrapped: WrappedAccountKey, fingerprint: String) {
        (
            try Data(contentsOf: deviceKeyURL),
            try JSONDecoder().decode(WrappedAccountKey.self, from: Data(contentsOf: wrappedKeyURL)),
            try String(contentsOf: fingerprintURL, encoding: .utf8)
        )
    }

    func reset() throws {
        guard FileManager.default.fileExists(atPath: directory.path) else { return }
        try FileManager.default.removeItem(at: directory)
    }

    private func write(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
