import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum DeviceKeyError: Error {
    case accessControlUnavailable
    case authenticationFailed
}

/// This Mac's device key, held by the Secure Enclave. The private key never leaves the
/// chip, and every use requires Touch ID or the Mac's login password.
struct SecureEnclaveDeviceKey {
    let privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey

    var publicKey: P256.KeyAgreement.PublicKey { privateKey.publicKey }

    /// An encrypted handle that only this Mac's Secure Enclave can use.
    var dataRepresentation: Data { privateKey.dataRepresentation }

    static var isAvailable: Bool { SecureEnclave.isAvailable }

    static func create() throws -> SecureEnclaveDeviceKey {
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

    /// Restores the key from its handle. Pass an already authenticated `context` so that
    /// using the key doesn't prompt a second time.
    static func restore(from handle: Data, context: LAContext) throws -> SecureEnclaveDeviceKey {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: handle, authenticationContext: context)
        return SecureEnclaveDeviceKey(privateKey: key)
    }
}

enum DeviceAuthentication {
    /// Asks for Touch ID, or the Mac password as a fallback, and returns the
    /// authenticated context. One approval covers several uses of the key.
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
        return context
    }
}
