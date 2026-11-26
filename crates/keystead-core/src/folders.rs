//! Who is in a folder, signed.
//!
//! The server keeps each folder's members, but a client hands the folder's key on to them:
//! when it gives the folder a new key, and when someone who recovered needs their copy
//! again. A server that could say who the members are could get the key handed to anyone
//! the owner approved. So a folder's members form signed entries, like a group's: who is in
//! it, which groups it's shared with, and a fingerprint of its key. The first is signed by
//! whoever made the folder; each later one by someone the entry before it names, or
//! someone in a group it names. Clients wrap a folder's key only for whoever its latest
//! entry names.
//!
//! Roles aren't in the entries: the server keeps and enforces them (see `docs/format.md`).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::encoding::{Bytes, Key32, transcript};
use crate::ids::{FolderId, GroupId, UserId};
use crate::keys::{AccountKeys, AccountPublicKeys, FolderKey};

/// One revision of who is in a folder, signed by whoever made it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderEntry {
    pub folder_id: FolderId,
    /// 1 for the first, one more for each change.
    pub revision: u32,
    /// The folder key this entry is for: the folder's current one when it was signed.
    pub generation: u32,
    /// That key's fingerprint ([`FolderKey::pin`]), so a member can tell the key they were
    /// given is the one this entry's signer meant.
    pub key: Key32,
    /// Everyone the folder is shared with directly. Sorted.
    pub members: Vec<UserId>,
    /// The groups it's shared with. Sorted.
    pub groups: Vec<GroupId>,
    /// SHA-256 of the previous entry's signature; empty in the first.
    #[serde(default, skip_serializing_if = "Bytes::is_empty")]
    pub previous: Bytes,
    pub signer: UserId,
    pub signature: Bytes,
}

impl FolderEntry {
    /// The first entry of a folder, for one of its members to sign.
    pub fn first(
        folder_id: FolderId,
        generation: u32,
        key: &FolderKey,
        members: Vec<UserId>,
        groups: Vec<GroupId>,
    ) -> Self {
        Self {
            folder_id,
            revision: 1,
            generation,
            key: key.pin(folder_id),
            members,
            groups,
            previous: Bytes::default(),
            signer: UserId(0),
            signature: Bytes::default(),
        }
    }

    /// The next entry, unsigned, to change and then sign.
    pub fn next(&self) -> Self {
        Self {
            revision: self.revision + 1,
            previous: self.signature_digest(),
            signer: UserId(0),
            signature: Bytes::default(),
            ..self.clone()
        }
    }

    /// The next entry for a new key: for after someone lost access.
    pub fn next_generation(&self, key: &FolderKey) -> Self {
        Self {
            generation: self.generation + 1,
            key: key.pin(self.folder_id),
            ..self.next()
        }
    }

    pub fn sign(&mut self, signer: UserId, keys: &AccountKeys) {
        self.members.sort();
        self.members.dedup();
        self.groups.sort();
        self.groups.dedup();
        self.signer = signer;
        self.signature = keys.sign(&self.signed_message());
    }

    /// Checks this entry's signature alone; [`verify_folder_entries`] checks the folder.
    pub fn verify(&self, signer: &AccountPublicKeys) -> Result<(), Error> {
        signer.verify(&self.signed_message(), self.signature.as_slice())
    }

    /// SHA-256 of the signature: what the next entry names as `previous`, and what goes on
    /// the owner's list of what someone's keys had signed before a recovery.
    pub fn signature_digest(&self) -> Bytes {
        Bytes(Sha256::digest(self.signature.as_slice()).to_vec())
    }

    fn signed_message(&self) -> Vec<u8> {
        let mut parts: Vec<Vec<u8>> = vec![
            self.folder_id.as_bytes().to_vec(),
            self.revision.to_be_bytes().to_vec(),
            self.generation.to_be_bytes().to_vec(),
            self.key.0.to_vec(),
            (self.members.len() as u32).to_be_bytes().to_vec(),
        ];
        parts.extend(self.members.iter().map(|user| user.to_be_bytes().to_vec()));
        parts.push((self.groups.len() as u32).to_be_bytes().to_vec());
        parts.extend(self.groups.iter().map(|group| group.as_bytes().to_vec()));
        parts.push(self.previous.0.clone());
        parts.push(self.signer.to_be_bytes().to_vec());
        let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        transcript("keystead/folder-entry/v1", &parts)
    }
}

/// Checks every entry of a folder, oldest first, and returns the latest.
///
/// `signed` says whether an entry's signer signed it, with keys the owner approved.
/// `in_group` says whether someone is in a group, by the group's own signed entries;
/// `latest` is true for the folder's last entry, where only the group's current members
/// count, and false for earlier ones, signed when its members may have been others.
pub fn verify_folder_entries(
    entries: &[FolderEntry],
    signed: impl Fn(&FolderEntry) -> bool,
    in_group: impl Fn(GroupId, UserId, bool) -> bool,
) -> Result<&FolderEntry, Error> {
    let Some(first) = entries.first() else {
        return Err(Error::InvalidFolder("the folder has no entries"));
    };
    let mut previous: Option<&FolderEntry> = None;
    for (index, entry) in entries.iter().enumerate() {
        let latest = index + 1 == entries.len();
        verify_folder_step(previous, entry, |group, user| in_group(group, user, latest))?;
        if !signed(entry) {
            return Err(Error::InvalidFolder(
                "a change to the folder's members isn't signed by an approved person",
            ));
        }
        previous = Some(entry);
    }
    Ok(previous.unwrap_or(first))
}

/// Checks one entry against the one before it (none for a folder's first): everything but
/// its signature. `in_group` says whether someone is in a group.
pub fn verify_folder_step(
    previous: Option<&FolderEntry>,
    entry: &FolderEntry,
    in_group: impl Fn(GroupId, UserId) -> bool,
) -> Result<(), Error> {
    let bad = |reason: &'static str| Err(Error::InvalidFolder(reason));
    if !entry.members.is_sorted_by(|a, b| a < b) || !entry.groups.is_sorted_by(|a, b| a < b) {
        return bad("the folder's members aren't in order");
    }
    // Whoever signs is in the folder, or in a group it's shared with: as the entry before
    // says, or for the first, as it says itself.
    let allowed = |named: &FolderEntry| {
        named.members.contains(&entry.signer)
            || named
                .groups
                .iter()
                .any(|&group| in_group(group, entry.signer))
    };
    let Some(previous) = previous else {
        if entry.revision != 1 || !entry.previous.is_empty() {
            return bad("the folder's first entry is missing");
        }
        if !allowed(entry) {
            return bad("the folder's first entry isn't by someone in it");
        }
        return Ok(());
    };
    if entry.folder_id != previous.folder_id {
        return bad("the entries are for different folders");
    }
    if entry.revision != previous.revision + 1 || entry.previous != previous.signature_digest() {
        return bad("a change to the folder's members is missing");
    }
    if !allowed(previous) {
        return bad("a change to the folder's members was made by someone outside it");
    }
    let within = |part: &FolderEntry, whole: &FolderEntry| {
        part.members.iter().all(|user| whole.members.contains(user))
            && part.groups.iter().all(|group| whole.groups.contains(group))
    };
    // With the same key, people and groups are only added: whoever holds it keeps it. A
    // new key is for those who stay, and nobody new.
    let added = entry.generation == previous.generation
        && entry.key == previous.key
        && within(previous, entry);
    let rekeyed = entry.generation == previous.generation + 1 && within(entry, previous);
    if !added && !rekeyed {
        return bad("the folder's members changed out of order");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::AccountSecret;

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

    fn check(entries: &[FolderEntry], people: &[&Person], group: &[UserId]) -> Result<u32, Error> {
        verify_folder_entries(
            entries,
            |entry| {
                people
                    .iter()
                    .find(|person| person.id == entry.signer)
                    .is_some_and(|person| entry.verify(&person.keys.public()).is_ok())
            },
            |_, user, _| group.contains(&user),
        )
        .map(|latest| latest.revision)
    }

    #[test]
    fn entries_chain_from_the_folders_maker_through_its_members() {
        let (alice, bob, carol, mallory) = (person(1), person(2), person(3), person(4));
        let people = [&alice, &bob, &carol, &mallory];
        let folder = FolderId::random();
        let key = FolderKey::generate();

        let mut first = FolderEntry::first(folder, 0, &key, vec![alice.id], Vec::new());
        first.sign(alice.id, &alice.keys);
        assert_eq!(check(&[first.clone()], &people, &[]).unwrap(), 1);

        // Alice adds Bob; Bob, now in it, adds a group.
        let mut second = first.next();
        second.members.push(bob.id);
        second.sign(alice.id, &alice.keys);
        let group = GroupId::random();
        let mut third = second.next();
        third.groups.push(group);
        third.sign(bob.id, &bob.keys);
        let chain = [first.clone(), second.clone(), third.clone()];
        assert_eq!(check(&chain, &people, &[]).unwrap(), 3);

        // Carol is in the group, so she can change the folder too: a new key without Bob.
        let new_key = FolderKey::generate();
        let mut fourth = third.next_generation(&new_key);
        fourth.members.retain(|&user| user != bob.id);
        fourth.sign(carol.id, &carol.keys);
        let mut chain = chain.to_vec();
        chain.push(fourth.clone());
        assert_eq!(check(&chain, &people, &[carol.id]).unwrap(), 4);
        // Not if she isn't in the group.
        assert!(check(&chain, &people, &[]).is_err());

        // Someone outside the folder can't add themselves, whoever signs for them.
        let mut forged = second.next();
        forged.members.push(mallory.id);
        forged.sign(mallory.id, &mallory.keys);
        assert!(check(&[first.clone(), second.clone(), forged], &people, &[]).is_err());

        // A new key is for those who stay: nobody joins with it.
        let mut sneaked = second.next_generation(&new_key);
        sneaked.members.push(mallory.id);
        sneaked.sign(alice.id, &alice.keys);
        assert!(check(&[first.clone(), second.clone(), sneaked], &people, &[]).is_err());

        // With the same key nobody is dropped, and the key's fingerprint stays.
        let mut dropped = second.next();
        dropped.members.retain(|&user| user != bob.id);
        dropped.sign(alice.id, &alice.keys);
        assert!(check(&[first.clone(), second.clone(), dropped], &people, &[]).is_err());
        let mut swapped = second.next();
        swapped.key = new_key.pin(folder);
        swapped.sign(alice.id, &alice.keys);
        assert!(check(&[first.clone(), second.clone(), swapped], &people, &[]).is_err());

        // Entries can't be left out, reordered or altered.
        assert!(check(&[first.clone(), third.clone()], &people, &[]).is_err());
        assert!(check(&[second.clone()], &people, &[]).is_err());
        let mut altered = second.clone();
        altered.members.push(mallory.id);
        assert!(check(&[first.clone(), altered], &people, &[]).is_err());

        // A first entry is by one of the members it names.
        let mut foreign = FolderEntry::first(folder, 0, &key, vec![alice.id], Vec::new());
        foreign.sign(mallory.id, &mallory.keys);
        assert!(check(&[foreign], &people, &[]).is_err());
    }
}
