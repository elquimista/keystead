import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum DeviceKeyError: Error {
    case accessControlUnavailable
    case authenticationFailed
}

/// Every use of a device key needs Touch ID or the Mac's login password, and the key
/// works only on this Mac while it's unlocked.
private func userPresenceAccessControl() throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    guard
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &error)
    else {
        if let error { throw error.takeRetainedValue() }
        throw DeviceKeyError.accessControlUnavailable
    }
    return accessControl
}

/// The Secure Enclave key that unwraps the account secret. The private key never leaves
/// the chip.
struct SecureEnclaveDeviceKey {
    let privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey

    var publicKey: P256.KeyAgreement.PublicKey { privateKey.publicKey }

    /// An encrypted handle that only this Mac's Secure Enclave can use.
    var dataRepresentation: Data { privateKey.dataRepresentation }

    static func create() throws -> SecureEnclaveDeviceKey {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false, accessControl: userPresenceAccessControl())
        return SecureEnclaveDeviceKey(privateKey: key)
    }

    /// Restores the key from its handle. Pass an already authenticated `context` so that
    /// using the key doesn't prompt a second time.
    static func restore(from handle: Data, context: LAContext) throws -> SecureEnclaveDeviceKey {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: handle, authenticationContext: context)
        return SecureEnclaveDeviceKey(privateKey: key)
    }
}

/// The Secure Enclave key this Mac signs in to the server with.
struct SecureEnclaveSigningKey {
    let privateKey: SecureEnclave.P256.Signing.PrivateKey

    var dataRepresentation: Data { privateKey.dataRepresentation }

    static func create() throws -> SecureEnclaveSigningKey {
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            compactRepresentable: false, accessControl: userPresenceAccessControl())
        return SecureEnclaveSigningKey(privateKey: key)
    }

    static func restore(from handle: Data, context: LAContext) throws -> SecureEnclaveSigningKey {
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: handle, authenticationContext: context)
        return SecureEnclaveSigningKey(privateKey: key)
    }
}

/// Hands the signing key to the Rust client, which signs in with it. The format matches
/// the `ecdsa-p256-sha256` device key scheme in docs/format.md.
final class SecureEnclaveSigner: DeviceSigner, @unchecked Sendable {
    private var key: SecureEnclaveSigningKey
    /// The approval the key was restored with; none for a key used only for its public half.
    private var context: LAContext?
    private let state = NSLock()
    private var neededApproval = false

    init(key: SecureEnclaveSigningKey, context: LAContext? = nil) {
        self.key = key
        self.context = context
    }

    /// From now on, a signature that needs Touch ID or the Mac password again fails at once
    /// instead of macOS asking out of the blue (see `neededYou`). macOS checks this on every
    /// use of the key.
    func stopAsking() {
        state.withLock { context }?.interactionNotAllowed = true
    }

    /// Takes an approval just given with Touch ID or the Mac password, in place of the one
    /// from unlocking, which stopped signing minutes after it (see `stopAsking`).
    func approveAgain(key: SecureEnclaveSigningKey, context: LAContext) {
        state.withLock {
            self.key = key
            self.context = context
            neededApproval = false
        }
    }

    /// Whether a signature failed because macOS would have had to ask.
    var neededYou: Bool {
        state.withLock { neededApproval }
    }

    func publicKey() -> Data {
        state.withLock { key }.privateKey.publicKey.x963Representation
    }

    func sign(message: Data) throws -> Data {
        do {
            return try state.withLock { key }.privateKey.signature(for: message).rawRepresentation
        } catch let error as LAError where error.code == .notInteractive {
            state.withLock { neededApproval = true }
            throw CoreError.Failed(message: "this Mac's key needs Touch ID or your Mac password")
        }
    }
}

enum DeviceAuthentication {
    /// Asks for Touch ID, or the Mac password as a fallback, and returns the
    /// authenticated context. Its approval covers using both keys right after, but not for
    /// as long as Keystead stays unlocked: macOS would ask again for a use minutes later,
    /// which is why sessions are renewed without the key, and why Keystead locks instead
    /// once unlocked (`SecureEnclaveSigner.stopAsking`).
    @MainActor
    static func authenticate(reason: String) async throws -> LAContext {
        let context = LAContext()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) {
                success, error in
                if success {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: error ?? DeviceKeyError.authenticationFailed)
                }
            }
        }
        // macOS may ask again before a later use of a key: signing in afresh when the
        // server has forgotten the session (as after a restart), 24 hours after the last
        // sign-in, or each time with a server too old to renew sessions. Say why instead
        // of "needs to authenticate to continue".
        context.localizedReason = "sign in to your team's server again"
        return context
    }
}
