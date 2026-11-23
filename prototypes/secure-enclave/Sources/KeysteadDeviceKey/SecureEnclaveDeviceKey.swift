import CryptoKit
import Foundation
import LocalAuthentication
import Security

public enum DeviceKeyError: Error {
    case accessControlUnavailable
    case authenticationFailed
}

/// A device key held by the Secure Enclave. The private key never leaves the chip, and
/// every use requires Touch ID or the Mac's login password.
public struct SecureEnclaveDeviceKey {
    public let privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey

    public var publicKey: P256.KeyAgreement.PublicKey { privateKey.publicKey }

    /// An encrypted handle that only this Mac's Secure Enclave can use. It is safe to
    /// store on disk because it is useless on any other machine.
    public var dataRepresentation: Data { privateKey.dataRepresentation }

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// Creates a new key. Creating it needs no authentication; using it does.
    public static func create() throws -> SecureEnclaveDeviceKey {
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
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false, accessControl: accessControl)
        return SecureEnclaveDeviceKey(privateKey: key)
    }

    /// Restores a key from its handle. Pass an already authenticated `context` so that
    /// using the key doesn't prompt a second time.
    public static func restore(
        from dataRepresentation: Data, context: LAContext
    ) throws -> SecureEnclaveDeviceKey {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: dataRepresentation, authenticationContext: context)
        return SecureEnclaveDeviceKey(privateKey: key)
    }
}

public enum DeviceAuthentication {
    /// Asks for Touch ID, or the Mac password as a fallback, and returns the
    /// authenticated context. Blocks the calling thread, which suits the CLI prototype;
    /// the app will use the async version.
    public static func authenticate(reason: String) throws -> LAContext {
        let context = LAContext()
        let outcome = Outcome()
        let done = DispatchSemaphore(value: 0)
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) {
            success, error in
            outcome.error = success ? nil : (error ?? DeviceKeyError.authenticationFailed)
            done.signal()
        }
        done.wait()
        if let error = outcome.error { throw error }
        return context
    }

    /// What this Mac offers for the user check, for diagnostics.
    public static func biometryDescription() -> String {
        let context = LAContext()
        var error: NSError?
        let usable = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: &error)
        guard context.biometryType == .touchID else {
            return "no Touch ID; the Mac password is used instead"
        }
        if usable { return "Touch ID" }
        switch error.map({ LAError.Code(rawValue: $0.code) }) {
        case .biometryNotEnrolled:
            return "Touch ID, but no fingerprint enrolled; the Mac password is used instead"
        case .biometryLockout:
            return "Touch ID locked after failed attempts; the Mac password is used instead"
        default:
            return "Touch ID not available right now (for example, lid closed); "
                + "the Mac password is used instead"
        }
    }

    private final class Outcome: @unchecked Sendable {
        var error: (any Error)?
    }
}
