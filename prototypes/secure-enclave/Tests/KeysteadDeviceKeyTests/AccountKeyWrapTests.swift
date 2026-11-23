import CryptoKit
import Foundation
import Testing

@testable import KeysteadDeviceKey

/// These tests use software P-256 keys, which follow the same code path as Secure
/// Enclave keys but need no Touch ID, so they run anywhere, including CI.
struct AccountKeyWrapTests {
    let deviceKey = P256.KeyAgreement.PrivateKey()
    let accountKey = SymmetricKey(size: .bits256)

    @Test func unwrapsWithTheRightDeviceKey() throws {
        let wrapped = try AccountKeyWrap.wrap(accountKey, to: deviceKey.publicKey)
        let unwrapped = try AccountKeyWrap.unwrap(wrapped, with: deviceKey)
        #expect(bytes(unwrapped) == bytes(accountKey))
    }

    @Test func failsWithAnotherDeviceKey() throws {
        let wrapped = try AccountKeyWrap.wrap(accountKey, to: deviceKey.publicKey)
        let otherKey = P256.KeyAgreement.PrivateKey()
        #expect(throws: (any Error).self) {
            try AccountKeyWrap.unwrap(wrapped, with: otherKey)
        }
    }

    @Test func failsWhenTheCiphertextIsTampered() throws {
        var wrapped = try AccountKeyWrap.wrap(accountKey, to: deviceKey.publicKey)
        wrapped.ciphertext[wrapped.ciphertext.startIndex] ^= 0x01
        #expect(throws: (any Error).self) {
            try AccountKeyWrap.unwrap(wrapped, with: deviceKey)
        }
    }

    @Test func rejectsAnUnknownVersion() throws {
        var wrapped = try AccountKeyWrap.wrap(accountKey, to: deviceKey.publicKey)
        wrapped.version = 2
        #expect(throws: AccountKeyWrapError.unsupportedVersion(2)) {
            try AccountKeyWrap.unwrap(wrapped, with: deviceKey)
        }
    }

    @Test func wrappingTwiceGivesDifferentOutput() throws {
        let first = try AccountKeyWrap.wrap(accountKey, to: deviceKey.publicKey)
        let second = try AccountKeyWrap.wrap(accountKey, to: deviceKey.publicKey)
        #expect(first.encapsulatedKey != second.encapsulatedKey)
        #expect(first.ciphertext != second.ciphertext)
    }

    @Test func survivesAJSONRoundTrip() throws {
        let wrapped = try AccountKeyWrap.wrap(accountKey, to: deviceKey.publicKey)
        let decoded = try JSONDecoder().decode(
            WrappedAccountKey.self, from: JSONEncoder().encode(wrapped))
        let unwrapped = try AccountKeyWrap.unwrap(decoded, with: deviceKey)
        #expect(bytes(unwrapped) == bytes(accountKey))
    }

    private func bytes(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }
}
