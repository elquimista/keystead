//! Items and folder metadata, encrypted with the folder key and signed by their author.
//!
//! Each item version has two encrypted parts: the overview (searchable fields, decrypted
//! at unlock) and the details (password and notes, decrypted only when used). Every
//! ciphertext is bound to its item, folder, version and part, and the author signs the
//! whole version, so nothing can be swapped, replayed or altered unnoticed.

use std::fmt;

use chacha20poly1305::aead::{Aead, AeadCore, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error;
use crate::encoding::{Bytes, transcript};
use crate::ids::{FolderId, ItemId, UserId};
use crate::keys::{AccountKeys, AccountPublicKeys, FolderKey};

/// The searchable fields of an item.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overview {
    pub name: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// The sensitive fields of an item. Wiped from memory when dropped.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Details {
    pub password: String,
    #[serde(default)]
    pub notes: String,
}

impl fmt::Debug for Details {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Details(redacted)")
    }
}

/// A nonce and the XChaCha20-Poly1305 ciphertext it goes with.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub nonce: Bytes,
    pub ciphertext: Bytes,
}

/// One version of an item, as stored on the server and sent between devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedItem {
    pub id: ItemId,
    pub folder_id: FolderId,
    /// Starts at 1 and goes up by one with every saved change.
    pub version: u64,
    pub author: UserId,
    /// A deleted item keeps a signed version with empty parts.
    pub deleted: bool,
    pub overview: Sealed,
    pub details: Sealed,
    /// The author's Ed25519 signature over the whole version.
    pub signature: Bytes,
}

/// The fields that identify one item version, for building it.
#[derive(Clone, Copy, Debug)]
pub struct ItemVersion {
    pub id: ItemId,
    pub folder_id: FolderId,
    pub version: u64,
    pub author: UserId,
}

impl EncryptedItem {
    /// Encrypts and signs a version of an item.
    pub fn seal(
        at: ItemVersion,
        folder_key: &FolderKey,
        author_keys: &AccountKeys,
        overview: &Overview,
        details: &Details,
    ) -> Result<Self, Error> {
        let cipher = folder_key.cipher();
        let overview_json = serde_json::to_vec(overview)?;
        let details_json = Zeroizing::new(serde_json::to_vec(details)?);
        let mut item = Self {
            id: at.id,
            folder_id: at.folder_id,
            version: at.version,
            author: at.author,
            deleted: false,
            overview: seal_part(&cipher, &part_aad(at, "overview"), &overview_json),
            details: seal_part(&cipher, &part_aad(at, "details"), &details_json),
            signature: Bytes::default(),
        };
        item.signature = author_keys.sign(&item.signed_message());
        Ok(item)
    }

    /// A signed marker that the item was deleted in this version.
    pub fn tombstone(at: ItemVersion, author_keys: &AccountKeys) -> Self {
        let mut item = Self {
            id: at.id,
            folder_id: at.folder_id,
            version: at.version,
            author: at.author,
            deleted: true,
            overview: Sealed::default(),
            details: Sealed::default(),
            signature: Bytes::default(),
        };
        item.signature = author_keys.sign(&item.signed_message());
        item
    }

    /// Checks the author's signature. Callers must also check that the author was allowed
    /// to edit the folder.
    pub fn verify(&self, author_keys: &AccountPublicKeys) -> Result<(), Error> {
        author_keys.verify(&self.signed_message(), self.signature.as_slice())
    }

    pub fn open_overview(&self, folder_key: &FolderKey) -> Result<Overview, Error> {
        let plaintext = open_part(
            &folder_key.cipher(),
            &part_aad(self.at(), "overview"),
            &self.overview,
        )?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    pub fn open_details(&self, folder_key: &FolderKey) -> Result<Details, Error> {
        let plaintext = Zeroizing::new(open_part(
            &folder_key.cipher(),
            &part_aad(self.at(), "details"),
            &self.details,
        )?);
        Ok(serde_json::from_slice(&plaintext)?)
    }

    fn at(&self) -> ItemVersion {
        ItemVersion {
            id: self.id,
            folder_id: self.folder_id,
            version: self.version,
            author: self.author,
        }
    }

    fn signed_message(&self) -> Vec<u8> {
        transcript(
            "keystead/item-signature/v1",
            &[
                self.id.as_bytes(),
                self.folder_id.as_bytes(),
                &self.version.to_be_bytes(),
                &self.author.to_be_bytes(),
                &[u8::from(self.deleted)],
                self.overview.nonce.as_slice(),
                self.overview.ciphertext.as_slice(),
                self.details.nonce.as_slice(),
                self.details.ciphertext.as_slice(),
            ],
        )
    }
}

/// A folder's own metadata, encrypted with its key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderInfo {
    pub name: String,
}

impl FolderInfo {
    pub fn seal(&self, folder_id: FolderId, folder_key: &FolderKey) -> Result<Sealed, Error> {
        let plaintext = serde_json::to_vec(self)?;
        Ok(seal_part(
            &folder_key.cipher(),
            &folder_aad(folder_id),
            &plaintext,
        ))
    }

    pub fn open(
        sealed: &Sealed,
        folder_id: FolderId,
        folder_key: &FolderKey,
    ) -> Result<Self, Error> {
        let plaintext = open_part(&folder_key.cipher(), &folder_aad(folder_id), sealed)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }
}

fn part_aad(at: ItemVersion, part: &str) -> Vec<u8> {
    transcript(
        "keystead/item/v1",
        &[
            at.id.as_bytes(),
            at.folder_id.as_bytes(),
            &at.version.to_be_bytes(),
            part.as_bytes(),
        ],
    )
}

fn folder_aad(folder_id: FolderId) -> Vec<u8> {
    transcript("keystead/folder-info/v1", &[folder_id.as_bytes()])
}

fn seal_part(cipher: &XChaCha20Poly1305, aad: &[u8], plaintext: &[u8]) -> Sealed {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory data");
    Sealed {
        nonce: Bytes(nonce.to_vec()),
        ciphertext: Bytes(ciphertext),
    }
}

fn open_part(cipher: &XChaCha20Poly1305, aad: &[u8], sealed: &Sealed) -> Result<Vec<u8>, Error> {
    if sealed.nonce.as_slice().len() != 24 {
        return Err(Error::Decrypt);
    }
    let nonce = XNonce::from_slice(sealed.nonce.as_slice());
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: sealed.ciphertext.as_slice(),
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::AccountSecret;

    struct Fixture {
        author: AccountKeys,
        folder_key: FolderKey,
        at: ItemVersion,
        overview: Overview,
        details: Details,
    }

    fn fixture() -> Fixture {
        Fixture {
            author: AccountKeys::derive(&AccountSecret::generate()),
            folder_key: FolderKey::generate(),
            at: ItemVersion {
                id: ItemId::random(),
                folder_id: FolderId::random(),
                version: 1,
                author: UserId(1),
            },
            overview: Overview {
                name: "GitHub".into(),
                username: "alice@example.com".into(),
                url: "https://github.com".into(),
                tags: vec!["engineering".into()],
            },
            details: Details {
                password: "correct horse battery staple".into(),
                notes: String::new(),
            },
        }
    }

    fn seal(f: &Fixture) -> EncryptedItem {
        EncryptedItem::seal(f.at, &f.folder_key, &f.author, &f.overview, &f.details).unwrap()
    }

    #[test]
    fn an_item_opens_and_verifies() {
        let f = fixture();
        let item = seal(&f);
        assert_eq!(item.open_overview(&f.folder_key).unwrap(), f.overview);
        assert_eq!(item.open_details(&f.folder_key).unwrap(), f.details);
        assert!(item.verify(&f.author.public()).is_ok());
    }

    #[test]
    fn another_folder_key_cannot_open_it() {
        let f = fixture();
        let item = seal(&f);
        assert!(item.open_overview(&FolderKey::generate()).is_err());
    }

    #[test]
    fn parts_cannot_be_swapped_or_moved_to_another_version() {
        let f = fixture();
        let item = seal(&f);

        let mut swapped = item.clone();
        std::mem::swap(&mut swapped.overview, &mut swapped.details);
        assert!(swapped.open_overview(&f.folder_key).is_err());

        let mut bumped = item.clone();
        bumped.version = 2;
        assert!(bumped.open_overview(&f.folder_key).is_err());
        assert!(bumped.verify(&f.author.public()).is_err());
    }

    #[test]
    fn tampering_or_a_wrong_author_fails_the_signature() {
        let f = fixture();
        let mut item = seal(&f);
        let stranger = AccountKeys::derive(&AccountSecret::generate());
        assert!(item.verify(&stranger.public()).is_err());

        item.details.ciphertext.0[0] ^= 1;
        assert!(item.verify(&f.author.public()).is_err());
    }

    #[test]
    fn tombstones_are_signed() {
        let f = fixture();
        let tombstone = EncryptedItem::tombstone(f.at, &f.author);
        assert!(tombstone.deleted);
        assert!(tombstone.verify(&f.author.public()).is_ok());

        let mut undeleted = tombstone.clone();
        undeleted.deleted = false;
        assert!(undeleted.verify(&f.author.public()).is_err());
    }

    #[test]
    fn items_survive_json() {
        let f = fixture();
        let item = seal(&f);
        let decoded: EncryptedItem =
            serde_json::from_str(&serde_json::to_string(&item).unwrap()).unwrap();
        assert_eq!(decoded, item);
        assert!(decoded.verify(&f.author.public()).is_ok());
    }

    #[test]
    fn folder_info_is_bound_to_its_folder() {
        let key = FolderKey::generate();
        let folder = FolderId::random();
        let info = FolderInfo {
            name: "Engineering".into(),
        };
        let sealed = info.seal(folder, &key).unwrap();
        assert_eq!(FolderInfo::open(&sealed, folder, &key).unwrap(), info);
        assert!(FolderInfo::open(&sealed, FolderId::random(), &key).is_err());
    }

    #[test]
    fn details_never_print() {
        assert_eq!(format!("{:?}", fixture().details), "Details(redacted)");
    }
}
