//! Groups: people shared with as one.
//!
//! A group has a secret that each member holds, wrapped for their account key, and its
//! keys come from that secret (see [`GroupKeys`]). Folder and item keys shared with the
//! group are wrapped to the group's public key, so sharing with a group of any size is one
//! copy, and adding someone to the group is one copy of its secret.
//!
//! Whoever shares with a group needs its real public key: a server that swapped in its own
//! could read whatever was shared. So a group's public facts (its name, current key and
//! managers) form a signed entry with numbered revisions. The team owner signs the first;
//! each later one is signed by the owner or by a manager named in the revision before it.
//! Apps check every revision before using the key.
//!
//! When someone leaves, the group gets a new secret, the next generation, with the previous
//! one sealed under it, so members can still open what was shared with older keys.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::Error;
use crate::api::KeyLink;
use crate::encoding::{Bytes, Key32, transcript};
use crate::ids::{GroupId, UserId};
use crate::items::{Sealed, open_part, seal_part};
use crate::keys::{AccountKeys, AccountPublicKeys, GroupKeys, GroupSecret};

/// One revision of a group's public facts, signed by whoever made it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupEntry {
    pub group_id: GroupId,
    /// 1 for the first, one more for each change.
    pub revision: u32,
    pub name: String,
    /// Which secret the key comes from: 1 at first, one more each time someone leaves.
    pub generation: u32,
    /// The group's public key, that folder and item keys are wrapped to.
    pub encryption: Key32,
    /// Who adds and removes members, besides the owner. Sorted.
    pub managers: Vec<UserId>,
    pub signer: UserId,
    pub signature: Bytes,
}

impl GroupEntry {
    /// The first revision of a new group, for the owner to sign.
    pub fn first(group_id: GroupId, name: &str, keys: &GroupKeys, managers: Vec<UserId>) -> Self {
        let mut entry = Self {
            group_id,
            revision: 1,
            name: name.into(),
            generation: 1,
            encryption: keys.public(),
            managers,
            signer: UserId(0),
            signature: Bytes::default(),
        };
        entry.managers.sort();
        entry.managers.dedup();
        entry
    }

    /// The next revision, unsigned, to change and then sign.
    pub fn next(&self) -> Self {
        Self {
            revision: self.revision + 1,
            signer: UserId(0),
            signature: Bytes::default(),
            ..self.clone()
        }
    }

    /// The next revision with a new key, for after someone left.
    pub fn next_generation(&self, keys: &GroupKeys) -> Self {
        Self {
            generation: self.generation + 1,
            encryption: keys.public(),
            ..self.next()
        }
    }

    pub fn sign(&mut self, signer: UserId, keys: &AccountKeys) {
        self.managers.sort();
        self.managers.dedup();
        self.signer = signer;
        self.signature = keys.sign(&self.signed_message());
    }

    pub fn is_manager(&self, user: UserId) -> bool {
        self.managers.contains(&user)
    }

    /// Checks this revision's signature alone; [`verify_entries`] checks the whole group.
    pub fn verify(&self, signer: &AccountPublicKeys) -> Result<(), Error> {
        signer.verify(&self.signed_message(), self.signature.as_slice())
    }

    fn signed_message(&self) -> Vec<u8> {
        let mut parts: Vec<Vec<u8>> = vec![
            self.group_id.as_bytes().to_vec(),
            self.revision.to_be_bytes().to_vec(),
            self.name.as_bytes().to_vec(),
            self.generation.to_be_bytes().to_vec(),
            self.encryption.0.to_vec(),
            (self.managers.len() as u32).to_be_bytes().to_vec(),
        ];
        parts.extend(self.managers.iter().map(|user| user.to_be_bytes().to_vec()));
        parts.push(self.signer.to_be_bytes().to_vec());
        let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        transcript("keystead/group-entry/v1", &parts)
    }
}

/// Checks every revision of a group, oldest first, and returns the latest. `keys_of` gives
/// the public keys of a signer from the verified directory; `owner` is the team owner.
pub fn verify_entries(
    entries: &[GroupEntry],
    owner: UserId,
    keys_of: impl Fn(UserId) -> Option<AccountPublicKeys>,
) -> Result<&GroupEntry, Error> {
    verify_entries_with(entries, owner, |user| keys_of(user).into_iter().collect())
}

/// Like [`verify_entries`], where each signer may have had several approved keys over
/// time: someone who recovered signed earlier revisions with keys since retired.
pub fn verify_entries_with(
    entries: &[GroupEntry],
    owner: UserId,
    keys_of: impl Fn(UserId) -> Vec<AccountPublicKeys>,
) -> Result<&GroupEntry, Error> {
    let bad = |reason: &str| Err(Error::InvalidGroup(reason.into()));
    let Some(first) = entries.first() else {
        return bad("the group has no entries");
    };
    let mut previous: Option<&GroupEntry> = None;
    for entry in entries {
        if entry.group_id != first.group_id {
            return bad("the entries are for different groups");
        }
        if !entry.managers.is_sorted_by(|a, b| a < b) {
            return bad("the managers aren't in order");
        }
        match previous {
            None => {
                if entry.revision != 1 || entry.generation != 1 || entry.signer != owner {
                    return bad("the group's first entry isn't the owner's");
                }
            }
            Some(previous) => {
                if entry.revision != previous.revision + 1 {
                    return bad("a revision of the group is missing");
                }
                if entry.signer != owner && !previous.is_manager(entry.signer) {
                    return bad("a change to the group was made by someone who doesn't manage it");
                }
                let same_key = entry.generation == previous.generation
                    && entry.encryption == previous.encryption;
                let next_key = entry.generation == previous.generation + 1;
                if !same_key && !next_key {
                    return bad("the group's key changed out of order");
                }
            }
        }
        let signers = keys_of(entry.signer);
        let Some(first_key) = signers.first() else {
            return bad("a change to the group was signed by someone unknown");
        };
        if !signers.iter().any(|keys| entry.verify(keys).is_ok()) {
            entry.verify(first_key)?;
        }
        previous = Some(entry);
    }
    Ok(previous.unwrap_or(first))
}

impl GroupKeys {
    /// Seals the group's previous secret with these keys, those of `generation`: one link
    /// of the group's chain. Whoever holds the newest secret can open every older one.
    pub fn seal_previous(&self, previous: &GroupSecret, group: GroupId, generation: u32) -> Sealed {
        seal_part(
            &self.chain_cipher(),
            &chain_aad(group, generation),
            previous.as_bytes(),
        )
    }

    /// Opens the previous secret from a chain link sealed with these keys.
    pub fn open_previous(
        &self,
        sealed: &Sealed,
        group: GroupId,
        generation: u32,
    ) -> Result<GroupSecret, Error> {
        let plaintext = Zeroizing::new(open_part(
            &self.chain_cipher(),
            &chain_aad(group, generation),
            sealed,
        )?);
        let bytes: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| Error::Decrypt)?;
        Ok(GroupSecret::from_bytes(bytes))
    }
}

fn chain_aad(group: GroupId, generation: u32) -> Vec<u8> {
    transcript(
        "keystead/group-key-chain/v1",
        &[group.as_bytes(), &generation.to_be_bytes()],
    )
}

/// The keys of every group someone is in, each generation of each, to open folder and
/// item keys that were wrapped for a group.
#[derive(Default)]
pub struct GroupKeyring {
    keys: HashMap<(GroupId, u32), GroupKeys>,
}

impl GroupKeyring {
    /// Adds a group's keys: those of its current `secret`, and each older generation's,
    /// opened from the chain. Checks the current key against the group's verified entry,
    /// so a secret the server made up is never used.
    pub fn add(
        &mut self,
        entry: &GroupEntry,
        secret: GroupSecret,
        chain: &[KeyLink],
    ) -> Result<(), Error> {
        let group = entry.group_id;
        let mut keys = GroupKeys::derive(&secret);
        if keys.public() != entry.encryption {
            return Err(Error::InvalidGroup(
                "the group's secret doesn't match its signed key".into(),
            ));
        }
        let mut generation = entry.generation;
        while generation > 1 {
            let Some(link) = chain.iter().find(|link| link.generation == generation) else {
                break;
            };
            let previous = keys.open_previous(&link.previous, group, generation)?;
            let older = GroupKeys::derive(&previous);
            self.keys.insert((group, generation), keys);
            keys = older;
            generation -= 1;
        }
        self.keys.insert((group, generation), keys);
        Ok(())
    }

    pub fn get(&self, group: GroupId, generation: u32) -> Option<&GroupKeys> {
        self.keys.get(&(group, generation))
    }

    pub fn contains(&self, group: GroupId) -> bool {
        self.keys.keys().any(|(id, _)| *id == group)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{AccountSecret, FolderKey, ItemKey};

    struct Person {
        id: UserId,
        keys: AccountKeys,
    }

    fn person(id: i64) -> Person {
        Person {
            id: UserId(id),
            keys: AccountKeys::derive(&AccountSecret::generate()),
        }
    }

    fn directory(people: &[&Person]) -> impl Fn(UserId) -> Option<AccountPublicKeys> + use<> {
        let keys: HashMap<UserId, AccountPublicKeys> =
            people.iter().map(|p| (p.id, p.keys.public())).collect();
        move |user| keys.get(&user).cloned()
    }

    #[test]
    fn a_group_key_opens_what_was_wrapped_for_it() {
        let secret = GroupSecret::generate();
        let keys = GroupKeys::derive(&secret);
        let folder = crate::ids::FolderId::random();
        let item = crate::ids::ItemId::random();
        let folder_key = FolderKey::generate();
        let item_key = ItemKey::generate();

        let wrapped = keys.public().wrap_folder_key(&folder_key, folder).unwrap();
        let opened = keys.unwrap_folder_key(&wrapped, folder).unwrap();
        assert_eq!(opened.as_bytes(), folder_key.as_bytes());
        assert!(
            keys.unwrap_folder_key(&wrapped, crate::ids::FolderId::random())
                .is_err()
        );

        let wrapped = keys.public().wrap_item_key(&item_key, item).unwrap();
        let opened = keys.unwrap_item_key(&wrapped, item).unwrap();
        assert_eq!(opened.as_bytes(), item_key.as_bytes());

        let other = GroupKeys::derive(&GroupSecret::generate());
        assert!(other.unwrap_item_key(&wrapped, item).is_err());
    }

    #[test]
    fn members_open_the_group_secret_for_its_generation_only() {
        let ana = person(2);
        let group = GroupId::random();
        let secret = GroupSecret::generate();
        let wrapped = ana
            .keys
            .public()
            .wrap_group_secret(&secret, group, 1)
            .unwrap();
        let opened = ana.keys.unwrap_group_secret(&wrapped, group, 1).unwrap();
        assert_eq!(opened.as_bytes(), secret.as_bytes());
        assert!(ana.keys.unwrap_group_secret(&wrapped, group, 2).is_err());
        assert!(
            ana.keys
                .unwrap_group_secret(&wrapped, GroupId::random(), 1)
                .is_err()
        );
    }

    #[test]
    fn entries_verify_from_the_owner_through_managers() {
        let owner = person(1);
        let ana = person(2);
        let bob = person(3);
        let keys_of = directory(&[&owner, &ana, &bob]);
        let group = GroupId::random();
        let keys = GroupKeys::derive(&GroupSecret::generate());

        let mut first = GroupEntry::first(group, "Engineering", &keys, vec![ana.id]);
        first.sign(owner.id, &owner.keys);
        let mut renamed = first.next();
        renamed.name = "Platform".into();
        renamed.sign(ana.id, &ana.keys);
        let new_keys = GroupKeys::derive(&GroupSecret::generate());
        let mut rekeyed = renamed.next_generation(&new_keys);
        rekeyed.sign(ana.id, &ana.keys);

        let entries = vec![first.clone(), renamed.clone(), rekeyed.clone()];
        let latest = verify_entries(&entries, owner.id, &keys_of).unwrap();
        assert_eq!(latest, &rekeyed);
        assert_eq!(latest.generation, 2);

        // Bob doesn't manage the group, so his change doesn't count.
        let mut bobs = rekeyed.next();
        bobs.managers.push(bob.id);
        bobs.sign(bob.id, &bob.keys);
        let entries = vec![first.clone(), renamed.clone(), rekeyed.clone(), bobs];
        assert!(verify_entries(&entries, owner.id, &keys_of).is_err());

        // The first revision must be the owner's.
        let mut anas = GroupEntry::first(group, "Engineering", &keys, vec![ana.id]);
        anas.sign(ana.id, &ana.keys);
        assert!(verify_entries(&[anas], owner.id, &keys_of).is_err());

        // A server can't drop a revision, change a key without a new generation, or edit
        // a signed entry.
        assert!(verify_entries(&[first.clone(), rekeyed.clone()], owner.id, &keys_of).is_err());
        let mut swapped = renamed.clone();
        swapped.encryption = new_keys.public();
        swapped.sign(ana.id, &ana.keys);
        assert!(verify_entries(&[first.clone(), swapped], owner.id, &keys_of).is_err());
        let mut edited = renamed.clone();
        edited.name = "Finance".into();
        assert!(verify_entries(&[first, edited], owner.id, &keys_of).is_err());
    }

    #[test]
    fn the_chain_opens_older_generations_for_current_members_only() {
        let owner = person(1);
        let group = GroupId::random();
        let first_secret = GroupSecret::generate();
        let first_keys = GroupKeys::derive(&first_secret);
        let mut first = GroupEntry::first(group, "Ops", &first_keys, vec![owner.id]);
        first.sign(owner.id, &owner.keys);

        let second_secret = GroupSecret::generate();
        let second_keys = GroupKeys::derive(&second_secret);
        let mut second = first.next_generation(&second_keys);
        second.sign(owner.id, &owner.keys);
        let chain = vec![KeyLink {
            generation: 2,
            previous: second_keys.seal_previous(&first_secret, group, 2),
        }];

        let item = crate::ids::ItemId::random();
        let item_key = ItemKey::generate();
        let old_copy = first_keys.public().wrap_item_key(&item_key, item).unwrap();

        let mut keyring = GroupKeyring::default();
        keyring
            .add(
                &second,
                GroupSecret::from_bytes(*second_secret.as_bytes()),
                &chain,
            )
            .unwrap();
        let older = keyring.get(group, 1).unwrap();
        assert_eq!(
            older.unwrap_item_key(&old_copy, item).unwrap().as_bytes(),
            item_key.as_bytes()
        );

        // Someone who only had the first secret can't open the second.
        let mut stale = GroupKeyring::default();
        assert!(stale.add(&second, first_secret, &chain).is_err());
    }
}
