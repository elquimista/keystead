//! Account, folder, item and device keys.
//!
//! A user's account keys come from one 32-byte secret, which each device keeps wrapped
//! by its own hardware key. Folder keys are wrapped for each member's account key; item
//! keys for each person an item is shared with directly. Every wrapped key names the
//! scheme that wrapped it, so each platform can use what its hardware supports.

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
use crate::ids::{DeviceId, FolderId, GroupId, ItemId};

type Kem = X25519HkdfSha256;
type KemPrivateKey = <Kem as hpke::Kem>::PrivateKey;
type KemPublicKey = <Kem as hpke::Kem>::PublicKey;
type EncappedKey = <Kem as hpke::Kem>::EncappedKey;

const ACCOUNT_ENCRYPTION_INFO: &[u8] = b"keystead/account/encryption/v1";
const ACCOUNT_SIGNING_INFO: &[u8] = b"keystead/account/signing/v1";
const ACCOUNT_PERSONAL_INFO: &[u8] = b"keystead/account/personal/v1";
const FOLDER_KEY_INFO: &[u8] = b"keystead/folder-key/v1";
const ITEM_KEY_INFO: &[u8] = b"keystead/item-key/v1";
const GROUP_SECRET_INFO: &[u8] = b"keystead/group-secret/v1";
const GROUP_ENCRYPTION_INFO: &[u8] = b"keystead/group/encryption/v1";
const GROUP_CHAIN_INFO: &[u8] = b"keystead/group/chain/v1";

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

    /// The secret as a recovery kit's 24 words: the BIP 39 English encoding of its 32
    /// bytes, where the last word also carries a checksum.
    pub fn recovery_words(&self) -> Zeroizing<String> {
        let mnemonic =
            bip39::Mnemonic::from_entropy(&self.0).expect("32 bytes is valid BIP 39 entropy");
        Zeroizing::new(mnemonic.to_string())
    }

    /// Reads a recovery kit's words back: exactly the 24 words, in order, separated by
    /// spaces or line breaks, as BIP 39 wallets take them. Capitals read as lowercase;
    /// anything else, such as numbers or punctuation, is refused rather than guessed at.
    pub fn from_recovery_words(text: &str) -> Result<Self, Error> {
        let words: Zeroizing<Vec<String>> =
            Zeroizing::new(text.split_whitespace().map(str::to_lowercase).collect());
        if let Some(index) = words
            .iter()
            .position(|word| !word.chars().all(|c| c.is_ascii_alphabetic()))
        {
            return Err(Error::RecoveryWords(format!(
                "word {} has something other than letters; enter only the 24 words, in order, \
                 with no numbers or punctuation",
                index + 1
            )));
        }
        if words.len() != 24 {
            return Err(Error::RecoveryWords(format!(
                "a recovery kit has 24 words, not {}",
                words.len()
            )));
        }
        Self::from_ordered_words(&words).map_err(recovery_error)
    }

    fn from_ordered_words(words: &[String]) -> Result<Self, bip39::Error> {
        let mnemonic = bip39::Mnemonic::parse_in_normalized(
            bip39::Language::English,
            &Zeroizing::new(words.join(" ")),
        )?;
        let entropy = Zeroizing::new(mnemonic.to_entropy());
        let bytes: [u8; 32] = entropy
            .as_slice()
            .try_into()
            .map_err(|_| bip39::Error::BadWordCount(words.len()))?;
        Ok(Self(bytes))
    }
}

fn recovery_error(error: bip39::Error) -> Error {
    Error::RecoveryWords(match error {
        bip39::Error::UnknownWord(index) => {
            format!("word {} isn't on the recovery kit word list", index + 1)
        }
        bip39::Error::InvalidChecksum => {
            "the words don't check out; one is probably mistyped or out of order".to_owned()
        }
        other => format!("those aren't recovery kit words ({other})"),
    })
}

/// A user's private keys: one for opening wrapped keys, one for signing, and a symmetric
/// personal key for items outside folders.
pub struct AccountKeys {
    encryption: KemPrivateKey,
    encryption_public: KemPublicKey,
    signing: SigningKey,
    personal: Zeroizing<[u8; 32]>,
}

impl AccountKeys {
    /// Derives every key from the secret with HKDF-SHA256, using a different `info` for
    /// each, so the same secret always gives the same keys.
    pub fn derive(secret: &AccountSecret) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, &secret.0);
        let expand = |info: &[u8]| {
            let mut out = Zeroizing::new([0u8; 32]);
            hkdf.expand(info, &mut *out)
                .expect("32 bytes is a valid HKDF output length");
            out
        };
        let encryption_seed = expand(ACCOUNT_ENCRYPTION_INFO);
        let signing_seed = expand(ACCOUNT_SIGNING_INFO);

        let (encryption, encryption_public) = Kem::derive_keypair(&*encryption_seed);
        Self {
            encryption,
            encryption_public,
            signing: SigningKey::from_bytes(&signing_seed),
            personal: expand(ACCOUNT_PERSONAL_INFO),
        }
    }

    /// The personal key's cipher. Only this account can make it, so what it seals opens
    /// for this account alone.
    pub(crate) fn personal_cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(Key::from_slice(&*self.personal))
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
        self.unwrap(wrapped, FOLDER_KEY_INFO, folder_id.as_bytes())
            .map(FolderKey)
    }

    /// Opens an item key that was shared with this account directly.
    pub fn unwrap_item_key(&self, wrapped: &WrappedKey, item_id: ItemId) -> Result<ItemKey, Error> {
        self.unwrap(wrapped, ITEM_KEY_INFO, item_id.as_bytes())
            .map(ItemKey)
    }

    /// Opens a group's secret, wrapped for this account as one of its members.
    pub fn unwrap_group_secret(
        &self,
        wrapped: &WrappedKey,
        group: GroupId,
        generation: u32,
    ) -> Result<GroupSecret, Error> {
        self.unwrap(
            wrapped,
            GROUP_SECRET_INFO,
            &group_secret_aad(group, generation),
        )
        .map(GroupSecret)
    }

    fn unwrap(&self, wrapped: &WrappedKey, info: &[u8], aad: &[u8]) -> Result<[u8; 32], Error> {
        hpke_unwrap(&self.encryption, wrapped, info, aad)
    }
}

fn hpke_unwrap(
    private: &KemPrivateKey,
    wrapped: &WrappedKey,
    info: &[u8],
    aad: &[u8],
) -> Result<[u8; 32], Error> {
    if wrapped.scheme != WrapScheme::HpkeX25519Sha256ChaCha20Poly1305 {
        return Err(Error::UnsupportedScheme(wrapped.scheme));
    }
    let encapped =
        EncappedKey::from_bytes(wrapped.encapsulated_key.as_slice()).map_err(|_| Error::Decrypt)?;
    let plaintext = Zeroizing::new(
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Base,
            private,
            &encapped,
            info,
            wrapped.ciphertext.as_slice(),
            aad,
        )
        .map_err(|_| Error::Decrypt)?,
    );
    plaintext.as_slice().try_into().map_err(|_| Error::Decrypt)
}

fn hpke_wrap(
    recipient: &Key32,
    key: &[u8; 32],
    info: &[u8],
    aad: &[u8],
) -> Result<WrappedKey, Error> {
    let recipient = KemPublicKey::from_bytes(&recipient.0).map_err(|_| Error::InvalidKey)?;
    let (encapped, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        &recipient,
        info,
        key,
        aad,
        &mut OsRng,
    )
    .map_err(|_| Error::InvalidKey)?;
    Ok(WrappedKey {
        scheme: WrapScheme::HpkeX25519Sha256ChaCha20Poly1305,
        encapsulated_key: Bytes(encapped.to_bytes().to_vec()),
        ciphertext: Bytes(ciphertext),
    })
}

fn group_secret_aad(group: GroupId, generation: u32) -> Vec<u8> {
    transcript(
        "keystead/group-secret/v1",
        &[group.as_bytes(), &generation.to_be_bytes()],
    )
}

/// The 32 random bytes a group's keys come from. Each member holds it, wrapped for their
/// account key; it changes when someone leaves the group.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GroupSecret([u8; 32]);

impl GroupSecret {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// A group's keys, derived from its secret with HKDF-SHA256 like an account's: an X25519
/// key that folder and item keys shared with the group are wrapped to, and a symmetric key
/// that seals the group's previous secret into its chain.
pub struct GroupKeys {
    encryption: KemPrivateKey,
    public: Key32,
    chain: Zeroizing<[u8; 32]>,
}

impl GroupKeys {
    pub fn derive(secret: &GroupSecret) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, &secret.0);
        let expand = |info: &[u8]| {
            let mut out = Zeroizing::new([0u8; 32]);
            hkdf.expand(info, &mut *out)
                .expect("32 bytes is a valid HKDF output length");
            out
        };
        let (encryption, public) = Kem::derive_keypair(&*expand(GROUP_ENCRYPTION_INFO));
        let mut key = [0u8; 32];
        key.copy_from_slice(&public.to_bytes());
        Self {
            encryption,
            public: Key32(key),
            chain: expand(GROUP_CHAIN_INFO),
        }
    }

    /// The public key folder and item keys are wrapped to; the owner signs it into the
    /// group's entry.
    pub fn public(&self) -> Key32 {
        self.public
    }

    pub fn unwrap_folder_key(
        &self,
        wrapped: &WrappedKey,
        folder: FolderId,
    ) -> Result<FolderKey, Error> {
        hpke_unwrap(
            &self.encryption,
            wrapped,
            FOLDER_KEY_INFO,
            folder.as_bytes(),
        )
        .map(FolderKey)
    }

    pub fn unwrap_item_key(&self, wrapped: &WrappedKey, item: ItemId) -> Result<ItemKey, Error> {
        hpke_unwrap(&self.encryption, wrapped, ITEM_KEY_INFO, item.as_bytes()).map(ItemKey)
    }

    pub(crate) fn chain_cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(Key::from_slice(&*self.chain))
    }
}

impl Key32 {
    /// Wraps a folder key for the group whose public key this is.
    pub fn wrap_folder_key(&self, key: &FolderKey, folder: FolderId) -> Result<WrappedKey, Error> {
        hpke_wrap(self, &key.0, FOLDER_KEY_INFO, folder.as_bytes())
    }

    /// Wraps an item key for the group whose public key this is.
    pub fn wrap_item_key(&self, key: &ItemKey, item: ItemId) -> Result<WrappedKey, Error> {
        hpke_wrap(self, &key.0, ITEM_KEY_INFO, item.as_bytes())
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
        self.wrap(&key.0, FOLDER_KEY_INFO, folder_id.as_bytes())
    }

    /// Wraps an item key for this account, to share the item with it directly.
    pub fn wrap_item_key(&self, key: &ItemKey, item_id: ItemId) -> Result<WrappedKey, Error> {
        self.wrap(&key.0, ITEM_KEY_INFO, item_id.as_bytes())
    }

    /// Wraps a group's secret for this account, as one of its members.
    pub fn wrap_group_secret(
        &self,
        secret: &GroupSecret,
        group: GroupId,
        generation: u32,
    ) -> Result<WrappedKey, Error> {
        self.wrap(
            &secret.0,
            GROUP_SECRET_INFO,
            &group_secret_aad(group, generation),
        )
    }

    fn wrap(&self, key: &[u8; 32], info: &[u8], aad: &[u8]) -> Result<WrappedKey, Error> {
        hpke_wrap(&self.encryption, key, info, aad)
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

/// The symmetric key of one folder. It seals the folder's info and the keys of the items
/// in it. (Format 1 items were encrypted with it directly.)
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

    /// The key a format 1 item's parts were encrypted with: the folder key itself.
    pub(crate) fn format_1_item_key(&self) -> ItemKey {
        ItemKey(self.0)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// The symmetric key that encrypts one item. It reaches people through the item's folder
/// key, its owner's personal key, or a copy wrapped for each person it's shared with.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ItemKey([u8; 32]);

impl ItemKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
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

impl WrapScheme {
    /// The scheme's name, as it appears in JSON.
    pub fn name(self) -> &'static str {
        match self {
            Self::HpkeX25519Sha256ChaCha20Poly1305 => "hpke-x25519-sha256-chacha20poly1305",
            Self::HpkeP256Sha256Aes256Gcm => "hpke-p256-sha256-aes256gcm",
        }
    }
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

/// The bytes a new device's account signature covers when the account is recovered on
/// it: the server's random challenge, bound to the device's id and public key, so the
/// signature can't enroll any other device.
pub fn recovery_message(
    challenge: &[u8],
    device_id: DeviceId,
    device_key: &DevicePublicKey,
) -> Vec<u8> {
    let scheme: &[u8] = match device_key.scheme {
        DeviceKeyScheme::Ed25519 => b"ed25519",
        DeviceKeyScheme::EcdsaP256Sha256 => b"ecdsa-p256-sha256",
    };
    transcript(
        "keystead/recover/v1",
        &[
            challenge,
            device_id.as_bytes(),
            scheme,
            device_key.key.as_slice(),
        ],
    )
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
    use std::str::FromStr;

    use super::*;

    #[test]
    fn recovery_words_follow_bip_39() {
        // The standard BIP 39 test vector for 32 zero bytes.
        let words = AccountSecret::from_bytes([0; 32]).recovery_words();
        assert_eq!(*words, format!("{}art", "abandon ".repeat(23)));

        let secret = AccountSecret::generate();
        let back = AccountSecret::from_recovery_words(&secret.recovery_words()).unwrap();
        assert_eq!(back.as_bytes(), secret.as_bytes());
    }

    #[test]
    fn recovery_words_may_be_spaced_and_capitalised_freely() {
        let secret = AccountSecret::generate();
        let words = secret.recovery_words();
        // In capitals, four to a line, with extra spaces: as typed from paper.
        let typed: String = words
            .split(' ')
            .enumerate()
            .map(|(index, word)| {
                let separator = if index % 4 == 3 { "\n" } else { "   " };
                format!("{}{separator}", word.to_uppercase())
            })
            .collect();
        let back = AccountSecret::from_recovery_words(&typed).unwrap();
        assert_eq!(back.as_bytes(), secret.as_bytes());
    }

    #[test]
    fn anything_but_the_words_in_order_is_refused() {
        let words = AccountSecret::generate().recovery_words();
        let numbered: String = words
            .split(' ')
            .enumerate()
            .map(|(index, word)| format!("{}. {word}\n", index + 1))
            .collect();
        for text in [numbered, words.replace(' ', ", ")] {
            match AccountSecret::from_recovery_words(&text) {
                Err(Error::RecoveryWords(reason)) => {
                    assert!(reason.contains("only the 24 words"), "{reason}")
                }
                other => panic!("accepted {text:?}: {:?}", other.is_ok()),
            }
        }
    }

    #[test]
    fn mistyped_recovery_words_are_refused_with_a_reason() {
        let reason = |text: &str| match AccountSecret::from_recovery_words(text) {
            Err(Error::RecoveryWords(reason)) => reason,
            other => panic!("expected a refusal, got {:?}", other.is_ok()),
        };
        let words = AccountSecret::from_bytes([0; 32]).recovery_words();
        assert!(reason("abandon abandon").contains("24 words, not 2"));
        assert!(reason(&words.replacen("abandon", "abandn", 1)).contains("word 1 "));
        // Every word valid, but the last one's checksum doesn't match.
        assert!(reason(&words.replace("art", "abandon")).contains("mistyped"));
    }

    #[test]
    fn a_recovery_signature_covers_the_new_device() {
        let device = DeviceId::random();
        let key = SoftwareDeviceKey::generate().public();
        let other_key = SoftwareDeviceKey::generate().public();
        let message = recovery_message(b"challenge", device, &key);
        assert_ne!(message, recovery_message(b"challenge", device, &other_key));
        assert_ne!(
            message,
            recovery_message(b"challenge", DeviceId::random(), &key)
        );
        assert_ne!(message, recovery_message(b"other", device, &key));
    }

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
    fn an_item_key_opens_only_for_its_recipient_and_item() {
        let alice = AccountKeys::derive(&AccountSecret::generate());
        let bob = AccountKeys::derive(&AccountSecret::generate());
        let item = ItemId::random();
        let key = ItemKey::generate();
        let wrapped = bob.public().wrap_item_key(&key, item).unwrap();

        assert_eq!(bob.unwrap_item_key(&wrapped, item).unwrap().0, key.0);
        assert!(alice.unwrap_item_key(&wrapped, item).is_err());
        assert!(bob.unwrap_item_key(&wrapped, ItemId::random()).is_err());
        // A wrapped item key isn't a wrapped folder key, even with the same id bytes.
        let folder = FolderId::from_str(&item.to_string()).unwrap();
        assert!(bob.unwrap_folder_key(&wrapped, folder).is_err());
    }

    #[test]
    fn wrap_schemes_have_stable_names() {
        for scheme in [
            WrapScheme::HpkeX25519Sha256ChaCha20Poly1305,
            WrapScheme::HpkeP256Sha256Aes256Gcm,
        ] {
            assert_eq!(
                serde_json::to_string(&scheme).unwrap(),
                format!("\"{}\"", scheme.name())
            );
        }
        assert_eq!(
            WrapScheme::HpkeX25519Sha256ChaCha20Poly1305.name(),
            "hpke-x25519-sha256-chacha20poly1305"
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
