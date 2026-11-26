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
//! From 0.17.0 an entry also says what each of them may do there: their roles, under the
//! same signature. A change is then signed by someone who manages the folder, and the
//! server's own list of roles is no longer what clients go by. The team's owner may sign
//! a change of roles alone, for a folder whose only manager they remove from the team.
//! Apps from before 0.17.0 can't check an entry with roles.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::api::Role;
use crate::encoding::{Bytes, Key32, transcript};
use crate::ids::{FolderId, GroupId, UserId};
use crate::keys::{AccountKeys, AccountPublicKeys, FolderKey};

/// The team's owner: the server's first user.
pub const TEAM_OWNER: UserId = UserId(1);

/// What each member and group named by a folder entry may do in the folder (0.17.0 and
/// later).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryRoles {
    /// The roles of the entry's `members`, in their order.
    pub members: Vec<Role>,
    /// The roles of its `groups`, in their order.
    pub groups: Vec<Role>,
}

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
    /// What each of them may do (0.17.0 and later). Once a folder's entry has roles, every
    /// later one does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<EntryRoles>,
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
            roles: None,
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

    /// Gives an entry that has none its roles, before it's signed: each member's and each
    /// group's.
    pub fn with_roles(
        mut self,
        member: impl Fn(UserId) -> Role,
        group: impl Fn(GroupId) -> Role,
    ) -> Self {
        self.members.sort();
        self.members.dedup();
        self.groups.sort();
        self.groups.dedup();
        self.roles = Some(EntryRoles {
            members: self.members.iter().map(|&user| member(user)).collect(),
            groups: self.groups.iter().map(|&id| group(id)).collect(),
        });
        self
    }

    /// Adds someone, or changes their role. The role is left out of an entry without
    /// roles.
    pub fn put_member(&mut self, user: UserId, role: Role) {
        let roles = self.roles.as_mut().map(|roles| &mut roles.members);
        put(&mut self.members, roles, user, role);
    }

    pub fn drop_member(&mut self, user: UserId) {
        let roles = self.roles.as_mut().map(|roles| &mut roles.members);
        drop_one(&mut self.members, roles, user);
    }

    /// Adds a group, or changes its role.
    pub fn put_group(&mut self, group: GroupId, role: Role) {
        let roles = self.roles.as_mut().map(|roles| &mut roles.groups);
        put(&mut self.groups, roles, group, role);
    }

    pub fn drop_group(&mut self, group: GroupId) {
        let roles = self.roles.as_mut().map(|roles| &mut roles.groups);
        drop_one(&mut self.groups, roles, group);
    }

    /// The role this entry gives someone it names directly; none without roles.
    pub fn member_role(&self, user: UserId) -> Option<Role> {
        let at = self.members.iter().position(|&member| member == user)?;
        self.roles.as_ref()?.members.get(at).copied()
    }

    /// The role this entry gives a group it names; none without roles.
    pub fn group_role(&self, group: GroupId) -> Option<Role> {
        let at = self.groups.iter().position(|&named| named == group)?;
        self.roles.as_ref()?.groups.get(at).copied()
    }

    /// The most `user` may do by this entry: their own role or that of a group they're
    /// in, whichever is higher; none if it doesn't reach them. An entry from before roles
    /// were signed makes everyone it reaches a manager, as everyone was then.
    pub fn role_of(
        &self,
        user: UserId,
        in_group: impl Fn(GroupId, UserId) -> bool,
    ) -> Option<Role> {
        let own = self
            .members
            .contains(&user)
            .then(|| self.member_role(user).unwrap_or_else(Role::before_roles));
        let through = self
            .groups
            .iter()
            .filter(|&&group| in_group(group, user))
            .map(|&group| self.group_role(group).unwrap_or_else(Role::before_roles))
            .max();
        own.max(through)
    }

    /// The next entry for a new key: for after someone lost access.
    pub fn next_generation(&self, key: &FolderKey) -> Self {
        Self {
            generation: self.generation + 1,
            key: key.pin(self.folder_id),
            ..self.next()
        }
    }

    /// Signs the entry, and its roles if it has them. Change who it names with
    /// [`put_member`](Self::put_member) and the like, which keep the roles in step.
    pub fn sign(&mut self, signer: UserId, keys: &AccountKeys) {
        if self.roles.is_none() {
            self.members.sort();
            self.members.dedup();
            self.groups.sort();
            self.groups.dedup();
        }
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
        // With roles: each as one byte, the members' and then the groups', under a
        // domain of its own, so an entry can't pass for one without them.
        let mut domain = "keystead/folder-entry/v1";
        if let Some(roles) = &self.roles {
            let code = |role: &Role| match role {
                Role::View => 1u8,
                Role::Edit => 2,
                Role::Manage => 3,
            };
            parts.push(roles.members.iter().map(code).collect());
            parts.push(roles.groups.iter().map(code).collect());
            domain = "keystead/folder-entry/v2";
        }
        let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        transcript(domain, &parts)
    }
}

/// Adds `id` to a sorted list, with its role in the list beside it, or changes its role.
fn put<T: Ord + Copy>(ids: &mut Vec<T>, roles: Option<&mut Vec<Role>>, id: T, role: Role) {
    match (ids.binary_search(&id), roles) {
        (Ok(at), Some(roles)) => roles[at] = role,
        (Ok(_), None) => {}
        (Err(at), roles) => {
            ids.insert(at, id);
            if let Some(roles) = roles {
                roles.insert(at, role);
            }
        }
    }
}

fn drop_one<T: Ord + Copy>(ids: &mut Vec<T>, roles: Option<&mut Vec<Role>>, id: T) {
    if let Ok(at) = ids.binary_search(&id) {
        ids.remove(at);
        if let Some(roles) = roles {
            roles.remove(at);
        }
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
    if let Some(roles) = &entry.roles {
        if roles.members.len() != entry.members.len() || roles.groups.len() != entry.groups.len() {
            return bad("the folder's roles don't match its members");
        }
        if !roles
            .members
            .iter()
            .chain(&roles.groups)
            .any(|&role| role == Role::Manage)
        {
            return bad("the folder would have no manager");
        }
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
    // And once roles are signed, they manage it.
    let manages =
        |named: &FolderEntry| named.role_of(entry.signer, &in_group) == Some(Role::Manage);
    let Some(previous) = previous else {
        if entry.revision != 1 || !entry.previous.is_empty() {
            return bad("the folder's first entry is missing");
        }
        if !allowed(entry) {
            return bad("the folder's first entry isn't by someone in it");
        }
        if entry.roles.is_some() && !manages(entry) {
            return bad("the folder's first entry isn't by one of its managers");
        }
        return Ok(());
    };
    // The team's owner, who isn't in the folder, may change its roles and nothing else.
    let by_owner = entry.signer == TEAM_OWNER
        && entry.roles.is_some()
        && previous.roles.is_some()
        && (entry.generation, entry.key) == (previous.generation, previous.key)
        && entry.members == previous.members
        && entry.groups == previous.groups;
    if entry.folder_id != previous.folder_id {
        return bad("the entries are for different folders");
    }
    if entry.revision != previous.revision + 1 || entry.previous != previous.signature_digest() {
        return bad("a change to the folder's members is missing");
    }
    if !allowed(previous) && !by_owner {
        return bad("a change to the folder's members was made by someone outside it");
    }
    match (&previous.roles, &entry.roles) {
        (Some(_), None) => return bad("the folder's roles are signed, and this change isn't"),
        (Some(_), Some(_)) if !manages(previous) && !by_owner => {
            return bad("a change to the folder was made by someone who doesn't manage it");
        }
        // The first roles of a folder from before they were signed come from anyone in
        // it, as every change did then.
        _ => {}
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

    #[test]
    fn roles_are_signed_and_only_managers_change_a_folder() {
        let (owner, alice, bob, carol) = (person(1), person(2), person(3), person(4));
        let people = [&owner, &alice, &bob, &carol];
        let folder = FolderId::random();
        let key = FolderKey::generate();
        let group = GroupId::random();

        // Alice makes the folder and manages it; Bob can edit, and a group can view.
        let mut first = FolderEntry::first(folder, 0, &key, vec![alice.id], Vec::new())
            .with_roles(|_| Role::Manage, |_| Role::View);
        first.sign(alice.id, &alice.keys);
        let mut second = first.next();
        second.put_member(bob.id, Role::Edit);
        second.put_group(group, Role::View);
        second.sign(alice.id, &alice.keys);
        let chain = vec![first.clone(), second.clone()];
        assert_eq!(check(&chain, &people, &[carol.id]).unwrap(), 2);
        let in_group = |_, user| user == carol.id;
        assert_eq!(second.role_of(alice.id, in_group), Some(Role::Manage));
        assert_eq!(second.role_of(bob.id, in_group), Some(Role::Edit));
        assert_eq!(second.role_of(carol.id, in_group), Some(Role::View));
        assert_eq!(second.role_of(owner.id, in_group), None);

        // Nobody who doesn't manage it changes it: not Bob, who edits, nor Carol, who
        // views through the group, though both are in it.
        for intruder in [&bob, &carol] {
            let mut raised = second.next();
            raised.put_member(intruder.id, Role::Manage);
            raised.sign(intruder.id, &intruder.keys);
            let chain = [first.clone(), second.clone(), raised];
            assert!(check(&chain, &people, &[carol.id]).is_err());
        }
        // A role nobody signed for doesn't count, nor a change that leaves roles out.
        let mut altered = second.clone();
        altered.roles.as_mut().unwrap().members[1] = Role::Manage;
        assert!(check(&[first.clone(), altered], &people, &[carol.id]).is_err());
        let mut without = second.next();
        without.roles = None;
        without.sign(alice.id, &alice.keys);
        let chain = [first.clone(), second.clone(), without];
        assert!(check(&chain, &people, &[carol.id]).is_err());
        // Every folder keeps a manager.
        let mut none = second.next();
        none.put_member(alice.id, Role::Edit);
        none.sign(alice.id, &alice.keys);
        let chain = [first.clone(), second.clone(), none];
        assert!(check(&chain, &people, &[carol.id]).is_err());

        // The team's owner, who isn't in the folder, may change roles and nothing else:
        // as when the folder's only manager leaves the team.
        let mut promoted = second.next();
        promoted.put_member(bob.id, Role::Manage);
        promoted.sign(owner.id, &owner.keys);
        let mut chain = vec![first.clone(), second.clone(), promoted.clone()];
        assert_eq!(check(&chain, &people, &[carol.id]).unwrap(), 3);
        let mut joined = second.next();
        joined.put_member(owner.id, Role::Manage);
        joined.sign(owner.id, &owner.keys);
        let forged = [first.clone(), second.clone(), joined];
        assert!(check(&forged, &people, &[carol.id]).is_err());
        // Bob, now a manager, gives the folder a new key without Alice.
        let mut fourth = promoted.next_generation(&FolderKey::generate());
        fourth.drop_member(alice.id);
        fourth.sign(bob.id, &bob.keys);
        chain.push(fourth.clone());
        assert_eq!(check(&chain, &people, &[carol.id]).unwrap(), 4);
        assert_eq!(fourth.member_role(bob.id), Some(Role::Manage));
        assert_eq!(fourth.member_role(alice.id), None);

        // A folder from before roles were signed gets them from anyone in it, once.
        let mut old = FolderEntry::first(folder, 0, &key, vec![alice.id, bob.id], Vec::new());
        old.sign(alice.id, &alice.keys);
        assert_eq!(old.role_of(bob.id, in_group), Some(Role::Manage));
        let mut with = old.next().with_roles(
            |user| {
                if user == bob.id {
                    Role::Manage
                } else {
                    Role::View
                }
            },
            |_| Role::View,
        );
        with.sign(bob.id, &bob.keys);
        assert_eq!(
            check(&[old.clone(), with.clone()], &people, &[]).unwrap(),
            2
        );
        let mut back = with.next();
        back.put_member(alice.id, Role::Manage);
        back.sign(alice.id, &alice.keys);
        assert!(check(&[old, with, back], &people, &[]).is_err());
    }
}
