//! Account, folder and device keys.
//!
//! A user's account keys come from one 32-byte secret, which each device keeps wrapped
//! by its own hardware key. Folder keys are wrapped for each member's account key, and
//! every wrapped key names the scheme that wrapped it, so each platform can use what its
//! hardware supports.

use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error;
use crate::encoding::{Bytes, Key32, transcript};
use crate::ids::{DeviceId, FolderId};

type Kem = X25519HkdfSha256;
type KemPrivateKey = <Kem as hpke::Kem>::PrivateKey;
type KemPublicKey = <Kem as hpke::Kem>::PublicKey;
type EncappedKey = <Kem as hpke::Kem>::EncappedKey;

const ACCOUNT_ENCRYPTION_INFO: &[u8] = b"keystead/account/encryption/v1";
const ACCOUNT_SIGNING_INFO: &[u8] = b"keystead/account/signing/v1";
const FOLDER_KEY_INFO: &[u8] = b"keystead/folder-key/v1";

/// The 32 random bytes every account key comes from. Devices store it wrapped by their
/// hardware key; it never reaches the server unwrapped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AccountSecret([u8; 32]);

impl AccountSecret {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw secret, for wrapping it to a device key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A user's private keys: one for opening folder keys, one for signing.
pub struct AccountKeys {
    encryption: KemPrivateKey,
    encryption_public: KemPublicKey,
    signing: SigningKey,
}

impl AccountKeys {
    /// Derives both keys from the secret with HKDF-SHA256, using a different `info` for
    /// each, so the same secret always gives the same keys.
    pub fn derive(secret: &AccountSecret) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, &secret.0);
        let mut encryption_seed = Zeroizing::new([0u8; 32]);
        hkdf.expand(ACCOUNT_ENCRYPTION_INFO, &mut *encryption_seed)
            .expect("32 bytes is a valid HKDF output length");
        let mut signing_seed = Zeroizing::new([0u8; 32]);
        hkdf.expand(ACCOUNT_SIGNING_INFO, &mut *signing_seed)
            .expect("32 bytes is a valid HKDF output length");

        let (encryption, encryption_public) = Kem::derive_keypair(&*encryption_seed);
        Self {
            encryption,
            encryption_public,
            signing: SigningKey::from_bytes(&signing_seed),
        }
    }

    pub fn public(&self) -> AccountPublicKeys {
        let mut encryption = [0u8; 32];
        encryption.copy_from_slice(&self.encryption_public.to_bytes());
        AccountPublicKeys {
            encryption: Key32(encryption),
            signing: Key32(self.signing.verifying_key().to_bytes()),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Bytes {
        Bytes(self.signing.sign(message).to_bytes().to_vec())
    }

    pub fn unwrap_folder_key(
        &self,
        wrapped: &WrappedKey,
        folder_id: FolderId,
    ) -> Result<FolderKey, Error> {
        if wrapped.scheme != WrapScheme::HpkeX25519Sha256ChaCha20Poly1305 {
            return Err(Error::UnsupportedScheme(wrapped.scheme));
        }
        let encapped = EncappedKey::from_bytes(wrapped.encapsulated_key.as_slice())
            .map_err(|_| Error::Decrypt)?;
        let plaintext = Zeroizing::new(
            hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
                &OpModeR::Base,
                &self.encryption,
                &encapped,
                FOLDER_KEY_INFO,
                wrapped.ciphertext.as_slice(),
                folder_id.as_bytes(),
            )
            .map_err(|_| Error::Decrypt)?,
        );
        let bytes: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| Error::Decrypt)?;
        Ok(FolderKey(bytes))
    }
}

/// A user's public keys, as published in the directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountPublicKeys {
    /// X25519 public key that folder keys are wrapped to.
    pub encryption: Key32,
    /// Ed25519 public key that checks the user's signatures.
    pub signing: Key32,
}

impl AccountPublicKeys {
    pub fn wrap_folder_key(
        &self,
        key: &FolderKey,
        folder_id: FolderId,
    ) -> Result<WrappedKey, Error> {
        let recipient =
            KemPublicKey::from_bytes(&self.encryption.0).map_err(|_| Error::InvalidKey)?;
        let (encapped, ciphertext) =
            hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
                &OpModeS::Base,
                &recipient,
                FOLDER_KEY_INFO,
                &key.0,
                folder_id.as_bytes(),
                &mut OsRng,
            )
            .map_err(|_| Error::InvalidKey)?;
        Ok(WrappedKey {
            scheme: WrapScheme::HpkeX25519Sha256ChaCha20Poly1305,
            encapsulated_key: Bytes(encapped.to_bytes().to_vec()),
            ciphertext: Bytes(ciphertext),
        })
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let key = VerifyingKey::from_bytes(&self.signing.0).map_err(|_| Error::InvalidKey)?;
        let signature = Signature::from_slice(signature).map_err(|_| Error::BadSignature)?;
        key.verify_strict(message, &signature)
            .map_err(|_| Error::BadSignature)
    }

    /// The short code people compare to confirm they hold the right keys: the first 10
    /// bytes of a SHA-256 hash of both keys, as five groups of four hex digits.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::new()
            .chain_update(b"keystead/fingerprint/v1")
            .chain_update(self.encryption.0)
            .chain_update(self.signing.0)
            .finalize();
        digest[..10]
            .chunks(2)
            .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
            .collect::<Vec<_>>()
            .join("-")
    }
}

/// The symmetric key that encrypts every item in one folder.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FolderKey([u8; 32]);

impl FolderKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub(crate) fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(Key::from_slice(&self.0))
    }
}

/// How a key was wrapped. Stored with every wrapped key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WrapScheme {
    /// HPKE (RFC 9180) base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
    /// ChaCha20-Poly1305. Used for folder keys wrapped to account keys.
    #[serde(rename = "hpke-x25519-sha256-chacha20poly1305")]
    HpkeX25519Sha256ChaCha20Poly1305,
    /// HPKE base mode with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM. Used
    /// by macOS to wrap the account secret to a Secure Enclave key; handled in Swift.
    #[serde(rename = "hpke-p256-sha256-aes256gcm")]
    HpkeP256Sha256Aes256Gcm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    pub scheme: WrapScheme,
    pub encapsulated_key: Bytes,
    pub ciphertext: Bytes,
}

/// How a device signs in to the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceKeyScheme {
    /// Ed25519. Used by the CLI, which keeps a software key.
    #[serde(rename = "ed25519")]
    Ed25519,
    /// ECDSA over P-256 with SHA-256; the key is SEC1-encoded and signatures are the raw
    /// 64-byte r and s. Used by Secure Enclave keys on macOS.
    #[serde(rename = "ecdsa-p256-sha256")]
    EcdsaP256Sha256,
}

/// A device's public sign-in key, registered with the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePublicKey {
    pub scheme: DeviceKeyScheme,
    pub key: Bytes,
}

impl DevicePublicKey {
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        match self.scheme {
            DeviceKeyScheme::Ed25519 => {
                let key: [u8; 32] = self
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?;
                let key = VerifyingKey::from_bytes(&key).map_err(|_| Error::InvalidKey)?;
                let signature =
                    Signature::from_slice(signature).map_err(|_| Error::BadSignature)?;
                key.verify_strict(message, &signature)
                    .map_err(|_| Error::BadSignature)
            }
            DeviceKeyScheme::EcdsaP256Sha256 => {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(self.key.as_slice())
                    .map_err(|_| Error::InvalidKey)?;
                let signature = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| Error::BadSignature)?;
                p256::ecdsa::signature::Verifier::verify(&key, message, &signature)
                    .map_err(|_| Error::BadSignature)
            }
        }
    }
}

/// The bytes a device signs to sign in: the server's random challenge, bound to the
/// device's id.
pub fn sign_in_message(device_id: DeviceId, challenge: &[u8]) -> Vec<u8> {
    transcript("keystead/sign-in/v1", &[device_id.as_bytes(), challenge])
}

/// A device key kept in software, for the CLI. The apps keep theirs in the Secure
/// Enclave or TPM instead.
pub struct SoftwareDeviceKey(SigningKey);

impl SoftwareDeviceKey {
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public(&self) -> DevicePublicKey {
        DevicePublicKey {
            scheme: DeviceKeyScheme::Ed25519,
            key: Bytes(self.0.verifying_key().to_bytes().to_vec()),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Bytes {
        Bytes(self.0.sign(message).to_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_secret_gives_the_same_keys() {
        let secret = AccountSecret::from_bytes([7; 32]);
        assert_eq!(
            AccountKeys::derive(&secret).public(),
            AccountKeys::derive(&secret).public()
        );
        assert_ne!(
            AccountKeys::derive(&secret).public(),
            AccountKeys::derive(&AccountSecret::from_bytes([8; 32])).public()
        );
    }

    #[test]
    fn a_folder_key_opens_only_for_its_member_and_folder() {
        let alice = AccountKeys::derive(&AccountSecret::generate());
        let bob = AccountKeys::derive(&AccountSecret::generate());
        let folder = FolderId::random();
        let key = FolderKey::generate();
        let wrapped = alice.public().wrap_folder_key(&key, folder).unwrap();

        assert_eq!(alice.unwrap_folder_key(&wrapped, folder).unwrap().0, key.0);
        assert!(bob.unwrap_folder_key(&wrapped, folder).is_err());
        assert!(
            alice
                .unwrap_folder_key(&wrapped, FolderId::random())
                .is_err()
        );

        let mut tampered = wrapped.clone();
        tampered.ciphertext.0[0] ^= 1;
        assert!(alice.unwrap_folder_key(&tampered, folder).is_err());
    }

    #[test]
    fn a_scheme_this_build_cant_open_is_reported() {
        let alice = AccountKeys::derive(&AccountSecret::generate());
        let folder = FolderId::random();
        let mut wrapped = alice
            .public()
            .wrap_folder_key(&FolderKey::generate(), folder)
            .unwrap();
        wrapped.scheme = WrapScheme::HpkeP256Sha256Aes256Gcm;
        assert!(matches!(
            alice.unwrap_folder_key(&wrapped, folder),
            Err(Error::UnsupportedScheme(
                WrapScheme::HpkeP256Sha256Aes256Gcm
            ))
        ));
    }

    #[test]
    fn wrap_schemes_have_stable_names() {
        assert_eq!(
            serde_json::to_string(&WrapScheme::HpkeX25519Sha256ChaCha20Poly1305).unwrap(),
            "\"hpke-x25519-sha256-chacha20poly1305\""
        );
        assert!(serde_json::from_str::<WrapScheme>("\"rot13\"").is_err());
    }

    #[test]
    fn account_signatures_verify() {
        let keys = AccountKeys::derive(&AccountSecret::generate());
        let signature = keys.sign(b"hello");
        assert!(keys.public().verify(b"hello", signature.as_slice()).is_ok());
        assert!(
            keys.public()
                .verify(b"hullo", signature.as_slice())
                .is_err()
        );
    }

    #[test]
    fn fingerprints_are_five_groups_of_four() {
        let fingerprint = AccountKeys::derive(&AccountSecret::generate())
            .public()
            .fingerprint();
        assert_eq!(fingerprint.len(), 24);
        assert_eq!(fingerprint.split('-').count(), 5);
    }

    #[test]
    fn software_device_keys_sign_in() {
        let device = SoftwareDeviceKey::generate();
        let message = sign_in_message(DeviceId::random(), b"challenge");
        let signature = device.sign(&message);
        assert!(
            device
                .public()
                .verify(&message, signature.as_slice())
                .is_ok()
        );
        assert!(
            device
                .public()
                .verify(b"other", signature.as_slice())
                .is_err()
        );
    }

    #[test]
    fn secure_enclave_style_p256_keys_sign_in() {
        use p256::ecdsa::signature::Signer as _;

        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let public = DevicePublicKey {
            scheme: DeviceKeyScheme::EcdsaP256Sha256,
            key: Bytes(
                key.verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
            ),
        };
        let message = sign_in_message(DeviceId::random(), b"challenge");
        let signature: p256::ecdsa::Signature = key.sign(&message);
        assert!(public.verify(&message, &signature.to_bytes()).is_ok());
        assert!(public.verify(b"other", &signature.to_bytes()).is_err());
    }
}
