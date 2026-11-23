import CryptoKit
import Foundation

/// A key wrapped with a named scheme, in the same JSON shape as the core's `WrappedKey`
/// (see docs/format.md): unpadded base64url bytes, snake_case names.
struct WrappedKey: Codable, Equatable {
    var scheme: String
    var encapsulatedKey: Data
    var ciphertext: Data

    private enum CodingKeys: String, CodingKey {
        case scheme
        case encapsulatedKey = "encapsulated_key"
        case ciphertext
    }

    init(scheme: String, encapsulatedKey: Data, ciphertext: Data) {
        self.scheme = scheme
        self.encapsulatedKey = encapsulatedKey
        self.ciphertext = ciphertext
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        scheme = try container.decode(String.self, forKey: .scheme)
        encapsulatedKey = try Self.bytes(container, .encapsulatedKey)
        ciphertext = try Self.bytes(container, .ciphertext)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(scheme, forKey: .scheme)
        try container.encode(encapsulatedKey.base64URLEncodedString(), forKey: .encapsulatedKey)
        try container.encode(ciphertext.base64URLEncodedString(), forKey: .ciphertext)
    }

    private static func bytes(
        _ container: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys
    ) throws -> Data {
        let text = try container.decode(String.self, forKey: key)
        guard let data = Data(base64URLEncoded: text) else {
            throw DecodingError.dataCorruptedError(
                forKey: key, in: container, debugDescription: "not base64url")
        }
        return data
    }
}

enum AccountSecretWrapError: Error {
    case unsupportedScheme(String)
}

/// Wraps the 32-byte account secret to this Mac's Secure Enclave key, using CryptoKit's
/// HPKE with P-256, HKDF-SHA256 and AES-256-GCM: the only curve the Secure Enclave offers.
enum AccountSecretWrap {
    static let scheme = "hpke-p256-sha256-aes256gcm"
    static let ciphersuite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256
    static let info = Data("keystead/account-secret/v1".utf8)

    static func wrap(_ secret: SymmetricKey, to publicKey: P256.KeyAgreement.PublicKey) throws -> WrappedKey {
        var sender = try HPKE.Sender(recipientKey: publicKey, ciphersuite: ciphersuite, info: info)
        let ciphertext = try secret.withUnsafeBytes { try sender.seal($0) }
        return WrappedKey(scheme: scheme, encapsulatedKey: sender.encapsulatedKey, ciphertext: ciphertext)
    }

    static func unwrap<Key: HPKEDiffieHellmanPrivateKey>(_ wrapped: WrappedKey, with key: Key) throws -> SymmetricKey {
        guard wrapped.scheme == scheme else {
            throw AccountSecretWrapError.unsupportedScheme(wrapped.scheme)
        }
        var recipient = try HPKE.Recipient(
            privateKey: key, ciphersuite: ciphersuite, info: info,
            encapsulatedKey: wrapped.encapsulatedKey)
        return SymmetricKey(data: try recipient.open(wrapped.ciphertext))
    }
}

extension Data {
    init?(base64URLEncoded text: String) {
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        self.init(base64Encoded: base64)
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
