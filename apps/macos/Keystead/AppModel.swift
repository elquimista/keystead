import CryptoKit
import Foundation
import Observation

/// What the menu shows. For now the app covers the device side of unlocking: it creates
/// this Mac's Secure Enclave key and an account secret wrapped to it, then unlocks with
/// Touch ID and shows the account fingerprint computed by the Rust core.
@MainActor
@Observable
final class AppModel {
    enum State: Equatable {
        case noDeviceKey
        case locked
        case unlocked(fingerprint: String)
    }

    private(set) var state: State
    private(set) var message: String?
    private let store = DeviceStore()

    init() {
        state = store.hasDeviceKey ? .locked : .noDeviceKey
    }

    /// Creating the key needs no Touch ID; only using it does.
    func createDeviceKey() {
        do {
            let deviceKey = try SecureEnclaveDeviceKey.create()
            let secret = SymmetricKey(size: .bits256)
            let wrapped = try AccountSecretWrap.wrap(secret, to: deviceKey.publicKey)
            try store.save(handle: deviceKey.dataRepresentation, wrappedSecret: wrapped)
            state = .locked
            message = nil
        } catch {
            message = "Couldn't create the device key: \(error.localizedDescription)"
        }
    }

    func unlock() async {
        do {
            let saved = try store.load()
            let context = try await DeviceAuthentication.authenticate(reason: "unlock Keystead")
            let deviceKey = try SecureEnclaveDeviceKey.restore(from: saved.handle, context: context)
            let secret = try AccountSecretWrap.unwrap(saved.wrappedSecret, with: deviceKey.privateKey)
            let fingerprint = try secret.withUnsafeBytes { bytes in
                try accountFingerprint(accountSecret: Data(bytes))
            }
            state = .unlocked(fingerprint: fingerprint)
            message = nil
        } catch {
            message = "Couldn't unlock: \(error.localizedDescription)"
        }
    }

    func lock() {
        state = .locked
    }
}
