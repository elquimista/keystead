//! Items and folder metadata.
//!
//! Each item version has two encrypted parts: the overview (searchable fields, decrypted
//! at unlock) and the details (password and notes, decrypted only when used). Both are
//! encrypted with the item's own key, which travels with the item sealed for each way in:
//! its folder's key, its owner's personal key, and a copy wrapped for each person it's
//! shared with directly. Every ciphertext is bound to its item, version and part, and the
//! author signs the whole version, key copies included, so nothing can be swapped,
//! replayed or altered unnoticed.
//!
//! Items saved by Keystead 0.1 are format 1: encrypted with their folder key directly,
//! with no key of their own. They still open, and become format 2 when next saved.

use std::fmt;

use chacha20poly1305::aead::{Aead, AeadCore, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error;
use crate::encoding::{Bytes, transcript};
use crate::ids::{FolderId, ItemId, UserId};
use crate::keys::{AccountKeys, AccountPublicKeys, FolderKey, ItemKey, WrappedKey};

impl FolderKey {
    /// Seals the folder's previous key with this one, the key of `generation`: one link of
    /// the folder's key chain. Whoever holds the newest key can open every older one.
    pub fn seal_previous(&self, previous: &FolderKey, folder: FolderId, generation: u32) -> Sealed {
        seal_part(
            &self.cipher(),
            &chain_aad(folder, generation),
            previous.as_bytes(),
        )
    }

    /// Opens the previous key from a chain link sealed with this one.
    pub fn open_previous(
        &self,
        sealed: &Sealed,
        folder: FolderId,
        generation: u32,
    ) -> Result<FolderKey, Error> {
        let plaintext = Zeroizing::new(open_part(
            &self.cipher(),
            &chain_aad(folder, generation),
            sealed,
        )?);
        let bytes: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| Error::Decrypt)?;
        Ok(FolderKey::from_bytes(bytes))
    }
}

fn chain_aad(folder: FolderId, generation: u32) -> Vec<u8> {
    transcript(
        "keystead/folder-key-chain/v1",
        &[folder.as_bytes(), &generation.to_be_bytes()],
    )
}

/// The item format this build writes.
pub const ITEM_FORMAT: u8 = 2;

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

/// An item's key, sealed for everyone who can open the item.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemKeys {
    /// Sealed with the folder key, for an item in a folder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<Sealed>,
    /// Sealed with the owner's personal key, for an item outside any folder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Sealed>,
    /// Wrapped for each person the item is shared with directly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub people: Vec<PersonKey>,
}

impl ItemKeys {
    pub fn is_empty(&self) -> bool {
        self.folder.is_none() && self.owner.is_none() && self.people.is_empty()
    }
}

/// An item key wrapped for one person's account key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonKey {
    pub user_id: UserId,
    pub wrapped_key: WrappedKey,
}

/// One version of an item, as stored on the server and sent between devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedItem {
    pub id: ItemId,
    /// 2 for items with their own key. Keystead 0.1's items have no `format`: they're 1.
    #[serde(default = "format_1", skip_serializing_if = "is_format_1")]
    pub format: u8,
    /// The folder the item is in, if any. Every format 1 item is in one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<FolderId>,
    /// Whose item it is, for an item outside any folder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<UserId>,
    /// Starts at 1 and goes up by one with every saved change.
    pub version: u64,
    pub author: UserId,
    /// A deleted item keeps a signed version with empty parts.
    pub deleted: bool,
    /// Format 2: the item's key, sealed for everyone who can open it.
    #[serde(default, skip_serializing_if = "ItemKeys::is_empty")]
    pub keys: ItemKeys,
    pub overview: Sealed,
    pub details: Sealed,
    /// The author's Ed25519 signature over the whole version.
    pub signature: Bytes,
}

fn format_1() -> u8 {
    1
}

fn is_format_1(format: &u8) -> bool {
    *format == 1
}

/// The fields that identify one item version, for building it. An item has a folder or
/// an owner, never both.
#[derive(Clone, Copy, Debug)]
pub struct ItemVersion {
    pub id: ItemId,
    pub folder_id: Option<FolderId>,
    pub owner: Option<UserId>,
    pub version: u64,
    pub author: UserId,
}

impl EncryptedItem {
    /// Encrypts and signs a version of an item with its key. `keys` must already hold the
    /// key's copies: for its folder or owner, and for anyone it's shared with.
    pub fn seal(
        at: ItemVersion,
        key: &ItemKey,
        keys: ItemKeys,
        author_keys: &AccountKeys,
        overview: &Overview,
        details: &Details,
    ) -> Result<Self, Error> {
        Self::seal_format(ITEM_FORMAT, at, key, keys, author_keys, overview, details)
    }

    /// Encrypts and signs a format 1 version, as Keystead 0.1 did: with the folder key
    /// itself. Only for tests that need old data.
    #[doc(hidden)]
    pub fn seal_format_1(
        at: ItemVersion,
        folder_key: &FolderKey,
        author_keys: &AccountKeys,
        overview: &Overview,
        details: &Details,
    ) -> Result<Self, Error> {
        Self::seal_format(
            1,
            at,
            &folder_key.format_1_item_key(),
            ItemKeys::default(),
            author_keys,
            overview,
            details,
        )
    }

    fn seal_format(
        format: u8,
        at: ItemVersion,
        key: &ItemKey,
        keys: ItemKeys,
        author_keys: &AccountKeys,
        overview: &Overview,
        details: &Details,
    ) -> Result<Self, Error> {
        let mut item = Self::unsigned(format, at, keys);
        let cipher = key.cipher();
        let overview_json = serde_json::to_vec(overview)?;
        let details_json = Zeroizing::new(serde_json::to_vec(details)?);
        item.overview = seal_part(&cipher, &item.part_aad("overview"), &overview_json);
        item.details = seal_part(&cipher, &item.part_aad("details"), &details_json);
        item.signature = author_keys.sign(&item.signed_message());
        Ok(item)
    }

    /// A signed marker that the item was deleted in this version. It keeps the key copies,
    /// so everyone who could open the item hears about it.
    pub fn tombstone(at: ItemVersion, keys: ItemKeys, author_keys: &AccountKeys) -> Self {
        let mut item = Self::unsigned(ITEM_FORMAT, at, keys);
        item.deleted = true;
        item.signature = author_keys.sign(&item.signed_message());
        item
    }

    fn unsigned(format: u8, at: ItemVersion, keys: ItemKeys) -> Self {
        Self {
            id: at.id,
            format,
            folder_id: at.folder_id,
            owner: at.owner,
            version: at.version,
            author: at.author,
            deleted: false,
            keys,
            overview: Sealed::default(),
            details: Sealed::default(),
            signature: Bytes::default(),
        }
    }

    /// Checks the author's signature. Callers must also check that the author was allowed
    /// to edit the item.
    pub fn verify(&self, author_keys: &AccountPublicKeys) -> Result<(), Error> {
        author_keys.verify(&self.signed_message(), self.signature.as_slice())
    }

    /// The key that opens this item, through whatever access `me` has: the item's folder
    /// (pass the folder key if `me` is a member), being its owner, or a copy shared with
    /// `me` directly.
    pub fn unlock(
        &self,
        folder_key: Option<&FolderKey>,
        account: &AccountKeys,
        me: UserId,
    ) -> Result<ItemKey, Error> {
        match self.format {
            1 => folder_key
                .map(FolderKey::format_1_item_key)
                .ok_or(Error::Decrypt),
            2 => {
                if let (Some(folder_id), Some(sealed), Some(folder_key)) =
                    (self.folder_id, &self.keys.folder, folder_key)
                {
                    let aad = folder_copy_aad(self.id, folder_id);
                    if let Ok(key) = open_key(&folder_key.cipher(), &aad, sealed) {
                        return Ok(key);
                    }
                }
                if let (Some(sealed), true) = (&self.keys.owner, self.owner == Some(me)) {
                    let aad = owner_copy_aad(self.id, me);
                    if let Ok(key) = open_key(&account.personal_cipher(), &aad, sealed) {
                        return Ok(key);
                    }
                }
                self.keys
                    .people
                    .iter()
                    .find(|person| person.user_id == me)
                    .ok_or(Error::Decrypt)
                    .and_then(|person| account.unwrap_item_key(&person.wrapped_key, self.id))
            }
            other => Err(Error::UnsupportedFormat(other)),
        }
    }

    pub fn open_overview(&self, key: &ItemKey) -> Result<Overview, Error> {
        let plaintext = open_part(&key.cipher(), &self.part_aad("overview"), &self.overview)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    pub fn open_details(&self, key: &ItemKey) -> Result<Details, Error> {
        let plaintext = Zeroizing::new(open_part(
            &key.cipher(),
            &self.part_aad("details"),
            &self.details,
        )?);
        Ok(serde_json::from_slice(&plaintext)?)
    }

    /// Whether `user` can open the item without being in its folder: as its owner, or
    /// because it was shared with them directly.
    pub fn reaches_directly(&self, user: UserId) -> bool {
        self.owner == Some(user) || self.keys.people.iter().any(|person| person.user_id == user)
    }

    fn part_aad(&self, part: &str) -> Vec<u8> {
        let version = self.version.to_be_bytes();
        if self.format == 1 {
            let folder = self.folder_id.map(|id| *id.as_bytes()).unwrap_or_default();
            transcript(
                "keystead/item/v1",
                &[self.id.as_bytes(), &folder, &version, part.as_bytes()],
            )
        } else {
            transcript(
                "keystead/item/v2",
                &[self.id.as_bytes(), &version, part.as_bytes()],
            )
        }
    }

    fn signed_message(&self) -> Vec<u8> {
        if self.format == 1 {
            let folder = self.folder_id.map(|id| *id.as_bytes()).unwrap_or_default();
            return transcript(
                "keystead/item-signature/v1",
                &[
                    self.id.as_bytes(),
                    &folder,
                    &self.version.to_be_bytes(),
                    &self.author.to_be_bytes(),
                    &[u8::from(self.deleted)],
                    self.overview.nonce.as_slice(),
                    self.overview.ciphertext.as_slice(),
                    self.details.nonce.as_slice(),
                    self.details.ciphertext.as_slice(),
                ],
            );
        }
        // Absent fields are empty parts; the length prefixes keep that unambiguous.
        let mut parts: Vec<Vec<u8>> = vec![
            vec![self.format],
            self.id.as_bytes().to_vec(),
            self.folder_id
                .map(|id| id.as_bytes().to_vec())
                .unwrap_or_default(),
            self.owner
                .map(|owner| owner.to_be_bytes().to_vec())
                .unwrap_or_default(),
            self.version.to_be_bytes().to_vec(),
            self.author.to_be_bytes().to_vec(),
            vec![u8::from(self.deleted)],
        ];
        for copy in [&self.keys.folder, &self.keys.owner] {
            parts.push(vec![u8::from(copy.is_some())]);
            let copy = copy.clone().unwrap_or_default();
            parts.push(copy.nonce.0);
            parts.push(copy.ciphertext.0);
        }
        parts.push((self.keys.people.len() as u32).to_be_bytes().to_vec());
        for person in &self.keys.people {
            parts.push(person.user_id.to_be_bytes().to_vec());
            parts.push(person.wrapped_key.scheme.name().as_bytes().to_vec());
            parts.push(person.wrapped_key.encapsulated_key.0.clone());
            parts.push(person.wrapped_key.ciphertext.0.clone());
        }
        for sealed in [&self.overview, &self.details] {
            parts.push(sealed.nonce.0.clone());
            parts.push(sealed.ciphertext.0.clone());
        }
        let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        transcript("keystead/item-signature/v2", &parts)
    }
}

impl ItemKey {
    /// This key's copy for the item's folder, sealed with the folder key.
    pub fn seal_for_folder(
        &self,
        item: ItemId,
        folder: FolderId,
        folder_key: &FolderKey,
    ) -> Sealed {
        seal_part(
            &folder_key.cipher(),
            &folder_copy_aad(item, folder),
            self.as_bytes(),
        )
    }

    /// This key's copy for the item's owner, sealed with their personal key.
    pub fn seal_for_owner(&self, item: ItemId, owner: UserId, owner_keys: &AccountKeys) -> Sealed {
        seal_part(
            &owner_keys.personal_cipher(),
            &owner_copy_aad(item, owner),
            self.as_bytes(),
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

fn folder_aad(folder_id: FolderId) -> Vec<u8> {
    transcript("keystead/folder-info/v1", &[folder_id.as_bytes()])
}

fn folder_copy_aad(item: ItemId, folder: FolderId) -> Vec<u8> {
    transcript(
        "keystead/item-key/folder/v1",
        &[item.as_bytes(), folder.as_bytes()],
    )
}

fn owner_copy_aad(item: ItemId, owner: UserId) -> Vec<u8> {
    transcript(
        "keystead/item-key/personal/v1",
        &[item.as_bytes(), &owner.to_be_bytes()],
    )
}

fn open_key(cipher: &XChaCha20Poly1305, aad: &[u8], sealed: &Sealed) -> Result<ItemKey, Error> {
    let plaintext = Zeroizing::new(open_part(cipher, aad, sealed)?);
    let bytes: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| Error::Decrypt)?;
    Ok(ItemKey::from_bytes(bytes))
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

    const ALICE: UserId = UserId(1);
    const BOB: UserId = UserId(2);

    struct Fixture {
        alice: AccountKeys,
        bob: AccountKeys,
        folder_id: FolderId,
        folder_key: FolderKey,
        overview: Overview,
        details: Details,
    }

    fn fixture() -> Fixture {
        Fixture {
            alice: AccountKeys::derive(&AccountSecret::generate()),
            bob: AccountKeys::derive(&AccountSecret::generate()),
            folder_id: FolderId::random(),
            folder_key: FolderKey::generate(),
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

    /// Alice's item in the folder, or (with `folder` false) her own outside any folder,
    /// shared with Bob directly if `with_bob`.
    fn seal(f: &Fixture, folder: bool, with_bob: bool) -> (EncryptedItem, ItemKey) {
        let id = ItemId::random();
        let key = ItemKey::generate();
        let mut keys = ItemKeys::default();
        let at = if folder {
            keys.folder = Some(key.seal_for_folder(id, f.folder_id, &f.folder_key));
            ItemVersion {
                id,
                folder_id: Some(f.folder_id),
                owner: None,
                version: 1,
                author: ALICE,
            }
        } else {
            keys.owner = Some(key.seal_for_owner(id, ALICE, &f.alice));
            ItemVersion {
                id,
                folder_id: None,
                owner: Some(ALICE),
                version: 1,
                author: ALICE,
            }
        };
        if with_bob {
            keys.people.push(PersonKey {
                user_id: BOB,
                wrapped_key: f.bob.public().wrap_item_key(&key, id).unwrap(),
            });
        }
        let item = EncryptedItem::seal(at, &key, keys, &f.alice, &f.overview, &f.details).unwrap();
        (item, key)
    }

    fn opens(
        item: &EncryptedItem,
        folder_key: Option<&FolderKey>,
        keys: &AccountKeys,
        me: UserId,
    ) -> bool {
        item.unlock(folder_key, keys, me)
            .and_then(|key| item.open_details(&key))
            .is_ok()
    }

    #[test]
    fn an_item_in_a_folder_opens_with_the_folder_key() {
        let f = fixture();
        let (item, key) = seal(&f, true, false);
        let opened = item.unlock(Some(&f.folder_key), &f.bob, BOB).unwrap();
        assert_eq!(item.open_overview(&opened).unwrap(), f.overview);
        assert_eq!(item.open_details(&key).unwrap(), f.details);
        assert!(item.verify(&f.alice.public()).is_ok());

        assert!(!opens(&item, Some(&FolderKey::generate()), &f.bob, BOB));
        assert!(!opens(&item, None, &f.alice, ALICE));
    }

    #[test]
    fn an_item_outside_folders_opens_only_for_its_owner() {
        let f = fixture();
        let (item, _) = seal(&f, false, false);
        assert!(opens(&item, None, &f.alice, ALICE));
        assert!(!opens(&item, None, &f.bob, BOB));
        // Bob claiming to be Alice still lacks her personal key.
        assert!(!opens(&item, None, &f.bob, ALICE));
        assert!(item.reaches_directly(ALICE));
        assert!(!item.reaches_directly(BOB));
    }

    #[test]
    fn a_shared_item_opens_for_the_person_it_was_shared_with() {
        let f = fixture();
        let (item, _) = seal(&f, false, true);
        assert!(opens(&item, None, &f.bob, BOB));
        assert!(opens(&item, None, &f.alice, ALICE));
        assert!(item.reaches_directly(BOB));

        let stranger = AccountKeys::derive(&AccountSecret::generate());
        assert!(!opens(&item, None, &stranger, UserId(3)));
        assert!(!opens(&item, None, &stranger, BOB));

        // An item in a folder can be shared with someone outside it too.
        let (in_folder, _) = seal(&f, true, true);
        assert!(opens(&in_folder, None, &f.bob, BOB));
    }

    #[test]
    fn key_copies_are_bound_to_their_item_and_folder() {
        let f = fixture();
        let (item, _) = seal(&f, true, false);
        let mut moved = item.clone();
        moved.folder_id = Some(FolderId::random());
        assert!(!opens(&moved, Some(&f.folder_key), &f.bob, BOB));

        let (other, _) = seal(&f, true, false);
        let mut swapped = other.clone();
        swapped.keys = item.keys.clone();
        assert!(!opens(&swapped, Some(&f.folder_key), &f.bob, BOB));
    }

    #[test]
    fn the_signature_covers_who_can_open_it() {
        let f = fixture();
        let (item, key) = seal(&f, false, false);
        let mut added = item.clone();
        added.keys.people.push(PersonKey {
            user_id: BOB,
            wrapped_key: f.bob.public().wrap_item_key(&key, item.id).unwrap(),
        });
        assert!(added.verify(&f.alice.public()).is_err());

        let mut moved = item.clone();
        moved.owner = Some(BOB);
        assert!(moved.verify(&f.alice.public()).is_err());
    }

    #[test]
    fn parts_cannot_be_swapped_or_moved_to_another_version() {
        let f = fixture();
        let (item, key) = seal(&f, true, false);

        let mut swapped = item.clone();
        std::mem::swap(&mut swapped.overview, &mut swapped.details);
        assert!(swapped.open_overview(&key).is_err());

        let mut bumped = item.clone();
        bumped.version = 2;
        assert!(bumped.open_overview(&key).is_err());
        assert!(bumped.verify(&f.alice.public()).is_err());
    }

    #[test]
    fn tampering_or_a_wrong_author_fails_the_signature() {
        let f = fixture();
        let (mut item, _) = seal(&f, true, false);
        assert!(item.verify(&f.bob.public()).is_err());

        item.details.ciphertext.0[0] ^= 1;
        assert!(item.verify(&f.alice.public()).is_err());
    }

    #[test]
    fn format_1_items_still_open_and_verify() {
        let f = fixture();
        let at = ItemVersion {
            id: ItemId::random(),
            folder_id: Some(f.folder_id),
            owner: None,
            version: 1,
            author: ALICE,
        };
        let item =
            EncryptedItem::seal_format_1(at, &f.folder_key, &f.alice, &f.overview, &f.details)
                .unwrap();
        assert_eq!(item.format, 1);
        assert!(item.verify(&f.alice.public()).is_ok());
        let key = item.unlock(Some(&f.folder_key), &f.bob, BOB).unwrap();
        assert_eq!(item.open_details(&key).unwrap(), f.details);
        assert!(item.unlock(None, &f.alice, ALICE).is_err());

        // Stored exactly as Keystead 0.1 wrote it: no format, owner or keys.
        let json = serde_json::to_value(&item).unwrap();
        for field in ["format", "owner", "keys"] {
            assert!(json.get(field).is_none(), "{field} was written");
        }
        let decoded: EncryptedItem = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, item);
    }

    #[test]
    fn unknown_formats_are_reported() {
        let f = fixture();
        let (mut item, _) = seal(&f, true, false);
        item.format = 3;
        assert!(matches!(
            item.unlock(Some(&f.folder_key), &f.bob, BOB),
            Err(Error::UnsupportedFormat(3))
        ));
    }

    #[test]
    fn tombstones_are_signed() {
        let f = fixture();
        let (item, _) = seal(&f, false, true);
        let at = ItemVersion {
            id: item.id,
            folder_id: None,
            owner: Some(ALICE),
            version: 2,
            author: BOB,
        };
        let tombstone = EncryptedItem::tombstone(at, item.keys.clone(), &f.bob);
        assert!(tombstone.deleted);
        assert!(tombstone.verify(&f.bob.public()).is_ok());
        assert!(tombstone.reaches_directly(BOB));

        let mut undeleted = tombstone.clone();
        undeleted.deleted = false;
        assert!(undeleted.verify(&f.bob.public()).is_err());
    }

    #[test]
    fn items_survive_json() {
        let f = fixture();
        let (item, _) = seal(&f, false, true);
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["format"], 2);
        assert!(json.get("folder_id").is_none());
        let decoded: EncryptedItem = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, item);
        assert!(decoded.verify(&f.alice.public()).is_ok());
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
    fn a_folder_key_chain_opens_older_keys_only_in_order() {
        let folder = FolderId::random();
        let old = FolderKey::generate();
        let new = FolderKey::generate();
        let link = new.seal_previous(&old, folder, 1);
        let opened = new.open_previous(&link, folder, 1).unwrap();
        assert_eq!(opened.as_bytes(), old.as_bytes());
        assert!(old.open_previous(&link, folder, 1).is_err());
        assert!(new.open_previous(&link, folder, 2).is_err());
        assert!(new.open_previous(&link, FolderId::random(), 1).is_err());
    }

    #[test]
    fn details_never_print() {
        assert_eq!(format!("{:?}", fixture().details), "Details(redacted)");
    }
}
