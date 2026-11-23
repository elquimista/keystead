import CryptoKit
import Foundation

/// An account key encrypted to one device key with HPKE (RFC 9180).
public struct WrappedAccountKey: Codable, Equatable, Sendable {
    public static let currentVersion = 1

    public var version: Int
    /// The sender's ephemeral public key, needed to open `ciphertext`.
    public var encapsulatedKey: Data
    public var ciphertext: Data
}

public enum AccountKeyWrapError: Error, Equatable {
    case unsupportedVersion(Int)
}

/// Wraps and unwraps the account key for a device key.
///
/// Uses CryptoKit's HPKE with P-256, HKDF-SHA256 and AES-256-GCM, so the device key
/// can live in the Secure Enclave, which only supports P-256.
public enum AccountKeyWrap {
    static let ciphersuite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256
    static let info = Data("keystead/account-key-wrap/v1".utf8)

    public static func wrap(
        _ accountKey: SymmetricKey,
        to devicePublicKey: P256.KeyAgreement.PublicKey
    ) throws -> WrappedAccountKey {
        var sender = try HPKE.Sender(
            recipientKey: devicePublicKey, ciphersuite: ciphersuite, info: info)
        let ciphertext = try accountKey.withUnsafeBytes { try sender.seal($0) }
        return WrappedAccountKey(
            version: WrappedAccountKey.currentVersion,
            encapsulatedKey: sender.encapsulatedKey,
            ciphertext: ciphertext)
    }

    /// Unwraps with any P-256 private key: a Secure Enclave key in the app, a software
    /// key in tests.
    public static func unwrap<DeviceKey: HPKEDiffieHellmanPrivateKey>(
        _ wrapped: WrappedAccountKey,
        with deviceKey: DeviceKey
    ) throws -> SymmetricKey {
        guard wrapped.version == WrappedAccountKey.currentVersion else {
            throw AccountKeyWrapError.unsupportedVersion(wrapped.version)
        }
        var recipient = try HPKE.Recipient(
            privateKey: deviceKey, ciphersuite: ciphersuite, info: info,
            encapsulatedKey: wrapped.encapsulatedKey)
        return SymmetricKey(data: try recipient.open(wrapped.ciphertext))
    }
}
