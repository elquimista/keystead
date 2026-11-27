//! The directory of users and their public keys.
//!
//! The server stores the directory but can't be trusted with it: a server that swapped
//! in its own key could read everything shared with that user. So each entry carries the
//! team owner's signature, given after the owner checks the user's fingerprint in person
//! or on a call, or by the owner's app once the user proves their keys with their
//! invite's key (see `crate::invites`), and apps only share with entries whose signature
//! verifies.
//!
//! Someone who recovers with the owner's help gets new keys at the next `revision`. Apps
//! remember the highest revision they've seen for each person and never share with an
//! earlier one. The earlier keys stay listed, `retired`, so what they signed still
//! verifies, but only what they had signed by then: when approving, the owner signs a
//! list of it ([`SignedBefore`]), so whoever has the lost device can't sign anything new.

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::encoding::{Bytes, transcript};
use crate::ids::UserId;
use crate::keys::{AccountKeys, AccountPublicKeys};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub user_id: UserId,
    pub name: String,
    pub keys: AccountPublicKeys,
    /// The owner's signature over the user id, name and keys. `None` until approved.
    pub approval: Option<Bytes>,
    /// The owner removed this person from the team. Their entry stays, so what they
    /// signed still verifies, but nobody shares with them any more. Not signed: it only
    /// ever takes access away.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub removed: bool,
    /// 0 for the keys someone joined with; one more each time the owner approves new keys
    /// for them after a recovery. Signed from 1 on.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub revision: u32,
    /// Earlier keys, each with the owner's approval as given, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired: Vec<RetiredKeys>,
    /// They let the owner recover their own items (escrow), as the server says. Not signed:
    /// apps act on escrow only with `escrow_consent`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub escrow: bool,
    /// Their own signature, with their current keys, agreeing to escrow: the owner may keep
    /// their personal key, and the keys of folders only they are in sealed with it. Apps
    /// act on escrow only with it, so a server can't turn escrow on for anyone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escrow_consent: Option<Bytes>,
    /// The number `escrow_consent` signs (0.18.0 and later), one more each time they turn
    /// escrow on; 0 for an agreement from before, which signs none. Kept when they turn it
    /// off, so the next agreement goes past it. A device that saw escrow turned off takes
    /// only a later agreement, so an old one can't turn it back on.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub escrow_sequence: u64,
    /// The owner has started a recovery for them that isn't approved yet. Not signed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub recovering: bool,
    /// How they joined, if with an invite that carried a key, until the owner approves
    /// them (0.18.0 and later). Not signed: the owner's app checks the proof itself, and
    /// approves them on its own if it holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite: Option<InviteProof>,
}

/// What someone who joined with an invite's key sent (see `crate::invites`): the invite's
/// nonce, as the owner's app made it, and their proof, made with the key, of the keys they
/// joined with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteProof {
    pub nonce: Bytes,
    pub proof: Bytes,
}

impl InviteProof {
    /// Whether the person who joined proved, with the key of the invite `owner` made for
    /// them, that `entry`'s keys are the ones they joined with, under the name the invite
    /// was made for.
    pub fn holds(&self, owner: &AccountKeys, entry: &DirectoryEntry) -> bool {
        owner
            .invite_key(self.nonce.as_slice(), &entry.name)
            .verify(&entry.keys, &self.proof)
    }
}

/// Keys someone had before a recovery, with the owner's approval of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredKeys {
    pub revision: u32,
    pub name: String,
    pub keys: AccountPublicKeys,
    pub approval: Bytes,
    /// Their agreement to escrow, signed with these keys, if it stood when the keys were
    /// replaced (0.15.0 and later). It's how their next device knows they had agreed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escrow_consent: Option<Bytes>,
    /// The number it signs (see [`DirectoryEntry::escrow_sequence`]).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub escrow_sequence: u64,
}

fn is_zero(revision: &u32) -> bool {
    *revision == 0
}

fn is_zero_u64(number: &u64) -> bool {
    *number == 0
}

/// What the owner signs to approve `keys` for a user at a revision: revision 0 as it
/// always was, later ones with the revision in it.
fn approval_message(
    user_id: UserId,
    revision: u32,
    name: &str,
    keys: &AccountPublicKeys,
) -> Vec<u8> {
    if revision == 0 {
        transcript(
            "keystead/directory-entry/v1",
            &[
                &user_id.to_be_bytes(),
                name.as_bytes(),
                &keys.encryption.0,
                &keys.signing.0,
            ],
        )
    } else {
        transcript(
            "keystead/directory-entry/v2",
            &[
                &user_id.to_be_bytes(),
                &revision.to_be_bytes(),
                name.as_bytes(),
                &keys.encryption.0,
                &keys.signing.0,
            ],
        )
    }
}

impl DirectoryEntry {
    /// A new, unapproved entry at revision 0.
    pub fn new(user_id: UserId, name: &str, keys: AccountPublicKeys) -> Self {
        Self {
            user_id,
            name: name.to_owned(),
            keys,
            approval: None,
            removed: false,
            revision: 0,
            retired: Vec::new(),
            escrow: false,
            escrow_consent: None,
            escrow_sequence: 0,
            recovering: false,
            invite: None,
        }
    }

    /// Signs the entry as the team owner. The owner approves their own entry at setup.
    pub fn approve(&mut self, owner: &AccountKeys) {
        self.approval = Some(owner.sign(&self.approval_message()));
    }

    /// Checks the owner's signature. Entries without one are never trusted.
    pub fn verify(&self, owner: &AccountPublicKeys) -> Result<(), Error> {
        let approval = self.approval.as_ref().ok_or(Error::BadSignature)?;
        owner.verify(&self.approval_message(), approval.as_slice())
    }

    pub fn approval_message(&self) -> Vec<u8> {
        approval_message(self.user_id, self.revision, &self.name, &self.keys)
    }

    /// Whether the person agreed to escrow with their current keys.
    pub fn consented_to_escrow(&self) -> bool {
        self.escrow_consent.as_ref().is_some_and(|consent| {
            let at = (self.revision, self.escrow_sequence);
            verify_escrow_consent(&self.keys, self.user_id, at, consent).is_ok()
        })
    }

    /// Whether this person had agreed to escrow with keys they had before their current
    /// ones: keys the owner approved, and their own signature made with them. After a
    /// recovery, that's what lets their new device agree again without asking; nobody
    /// else, the server included, can make that signature. Any earlier keys count, not
    /// just the last: a recovery whose device never finished leaves keys that agreed to
    /// nothing. Turning escrow off drops the agreements kept with earlier keys.
    pub fn earlier_keys_consented(&self, owner: &AccountPublicKeys) -> bool {
        self.retired_keys(owner).into_iter().any(|retired| {
            retired.escrow_consent.as_ref().is_some_and(|consent| {
                let at = (retired.revision, retired.escrow_sequence);
                verify_escrow_consent(&retired.keys, self.user_id, at, consent).is_ok()
            })
        })
    }

    /// The keys the owner approved for this person before their current ones, from
    /// revisions before the current one. What they signed counts only if it's on the
    /// owner's [`SignedBefore`] list for that revision.
    pub fn retired_keys(&self, owner: &AccountPublicKeys) -> Vec<&RetiredKeys> {
        self.retired
            .iter()
            .filter(|retired| {
                retired.revision < self.revision
                    && owner
                        .verify(
                            &approval_message(
                                self.user_id,
                                retired.revision,
                                &retired.name,
                                &retired.keys,
                            ),
                            retired.approval.as_slice(),
                        )
                        .is_ok()
            })
            .collect()
    }
}

/// Someone's agreement to escrow, signed with their keys at `revision`, as the
/// `sequence`th time they turn it on (0.18.0 and later), or with `sequence` 0 as before,
/// signing no number.
pub fn escrow_consent(
    keys: &AccountKeys,
    user_id: UserId,
    (revision, sequence): (u32, u64),
) -> Bytes {
    keys.sign(&escrow_consent_message(user_id, revision, sequence))
}

/// Checks an agreement to escrow made with `keys` at `revision`, signing `sequence`.
pub fn verify_escrow_consent(
    keys: &AccountPublicKeys,
    user_id: UserId,
    (revision, sequence): (u32, u64),
    consent: &Bytes,
) -> Result<(), Error> {
    keys.verify(
        &escrow_consent_message(user_id, revision, sequence),
        consent.as_slice(),
    )
}

fn escrow_consent_message(user_id: UserId, revision: u32, sequence: u64) -> Vec<u8> {
    let (user, revision) = (user_id.to_be_bytes(), revision.to_be_bytes());
    if sequence == 0 {
        return transcript("keystead/escrow-consent/v1", &[&user, &revision]);
    }
    transcript(
        "keystead/escrow-consent/v2",
        &[&user, &revision, &sequence.to_be_bytes()],
    )
}

/// What someone's keys at `revision` had signed when the owner approved new keys for them
/// after a recovery: SHA-256 digests of the signatures, of login versions and group
/// changes, in order. Signed by the owner. Those keys verify nothing else from then on,
/// so whoever has the lost device can't sign anything new in that person's name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBefore {
    pub user_id: UserId,
    pub revision: u32,
    pub digests: Vec<Bytes>,
    pub approval: Bytes,
}

impl SignedBefore {
    /// An unsigned list, in order and without repeats.
    pub fn new(user_id: UserId, revision: u32, digests: impl IntoIterator<Item = Bytes>) -> Self {
        let mut digests: Vec<Bytes> = digests.into_iter().collect();
        digests.sort();
        digests.dedup();
        Self {
            user_id,
            revision,
            digests,
            approval: Bytes::default(),
        }
    }

    /// Signs the list as the team owner.
    pub fn approve(&mut self, owner: &AccountKeys) {
        self.approval = owner.sign(&self.message());
    }

    /// Checks the owner's signature, and that the list is in order without repeats.
    pub fn verify(&self, owner: &AccountPublicKeys) -> Result<(), Error> {
        if !self.digests.is_sorted_by(|a, b| a < b) {
            return Err(Error::BadSignature);
        }
        owner.verify(&self.message(), self.approval.as_slice())
    }

    /// Whether these keys had signed what this digest names. Only for a verified list.
    pub fn contains(&self, digest: &Bytes) -> bool {
        self.digests.binary_search(digest).is_ok()
    }

    fn message(&self) -> Vec<u8> {
        let user = self.user_id.to_be_bytes();
        let revision = self.revision.to_be_bytes();
        let parts: Vec<&[u8]> = [user.as_slice(), revision.as_slice()]
            .into_iter()
            .chain(self.digests.iter().map(Bytes::as_slice))
            .collect();
        transcript("keystead/signed-before-recovery/v1", &parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::AccountSecret;

    fn entry(name: &str) -> (DirectoryEntry, AccountKeys) {
        let keys = AccountKeys::derive(&AccountSecret::generate());
        (DirectoryEntry::new(UserId(2), name, keys.public()), keys)
    }

    #[test]
    fn only_their_own_earlier_keys_say_they_had_agreed_to_escrow() {
        let owner = AccountKeys::derive(&AccountSecret::generate());
        let (mut bob, old) = entry("Bob");
        bob.approve(&owner);
        let new = AccountKeys::derive(&AccountSecret::generate());
        let recovered = |consent: Option<Bytes>, approved: bool| {
            let mut entry = bob.clone();
            entry.retired.push(RetiredKeys {
                revision: 0,
                name: bob.name.clone(),
                keys: bob.keys.clone(),
                approval: if approved {
                    bob.approval.clone().unwrap()
                } else {
                    Bytes(vec![0; 64])
                },
                escrow_consent: consent,
                escrow_sequence: 0,
            });
            entry.keys = new.public();
            entry.revision = 1;
            entry.approve(&owner);
            entry.earlier_keys_consented(&owner.public())
        };
        // Their earlier keys' own signature, for the revision those keys had.
        assert!(recovered(
            Some(escrow_consent(&old, bob.user_id, (0, 0))),
            true
        ));
        assert!(!recovered(None, true));
        // Not someone else's signature, the owner's included; not one for another
        // revision or person; and not from keys the owner never approved.
        assert!(!recovered(
            Some(escrow_consent(&owner, bob.user_id, (0, 0))),
            true
        ));
        assert!(!recovered(
            Some(escrow_consent(&new, bob.user_id, (0, 0))),
            true
        ));
        assert!(!recovered(
            Some(escrow_consent(&old, bob.user_id, (1, 0))),
            true
        ));
        assert!(!recovered(
            Some(escrow_consent(&old, UserId(3), (0, 0))),
            true
        ));
        assert!(!recovered(
            Some(escrow_consent(&old, bob.user_id, (0, 0))),
            false
        ));
    }

    #[test]
    fn new_keys_after_a_recovery_sign_their_revision_and_the_old_ones_still_verify() {
        let owner = AccountKeys::derive(&AccountSecret::generate());
        let (mut bob, old) = entry("Bob");
        bob.approve(&owner);
        let mut recovered = bob.clone();
        let new = AccountKeys::derive(&AccountSecret::generate());
        recovered.retired.push(RetiredKeys {
            revision: 0,
            name: bob.name.clone(),
            keys: bob.keys.clone(),
            approval: bob.approval.clone().unwrap(),
            escrow_consent: None,
            escrow_sequence: 0,
        });
        recovered.keys = new.public();
        recovered.revision = 1;
        recovered.approve(&owner);
        assert!(recovered.verify(&owner.public()).is_ok());
        let retired: Vec<_> = recovered
            .retired_keys(&owner.public())
            .into_iter()
            .map(|retired| retired.keys.clone())
            .collect();
        assert_eq!(retired, [old.public()]);

        // The revision is signed: the same keys can't pass for another revision.
        let mut replayed = recovered.clone();
        replayed.revision = 2;
        assert!(replayed.verify(&owner.public()).is_err());
        // A retired set that wasn't approved doesn't count.
        let mut forged = recovered.clone();
        forged.retired[0].keys = AccountKeys::derive(&AccountSecret::generate()).public();
        assert!(forged.retired_keys(&owner.public()).is_empty());
    }

    #[test]
    fn only_the_person_can_agree_to_escrow_and_only_for_their_current_keys() {
        let (mut bob, keys) = entry("Bob");
        assert!(!bob.consented_to_escrow());
        bob.escrow_consent = Some(escrow_consent(&keys, bob.user_id, (0, 0)));
        assert!(bob.consented_to_escrow());

        let server = AccountKeys::derive(&AccountSecret::generate());
        let mut forged = bob.clone();
        forged.escrow_consent = Some(escrow_consent(&server, bob.user_id, (0, 0)));
        assert!(!forged.consented_to_escrow());
        // Agreement given with earlier keys doesn't carry over to new ones.
        let mut recovered = bob.clone();
        recovered.keys = server.public();
        recovered.revision = 1;
        assert!(!recovered.consented_to_escrow());

        // From 0.18.0 an agreement signs the how-manyth time escrow is turned on, and only
        // that number goes with it: not another, nor none, nor one from before numbers.
        let second = escrow_consent(&keys, bob.user_id, (0, 2));
        let mut numbered = bob.clone();
        numbered.escrow_consent = Some(second.clone());
        numbered.escrow_sequence = 2;
        assert!(numbered.consented_to_escrow());
        for sequence in [0, 1, 3] {
            numbered.escrow_sequence = sequence;
            assert!(!numbered.consented_to_escrow(), "{sequence}");
        }
        let mut before = bob.clone();
        before.escrow_sequence = 1;
        assert!(!before.consented_to_escrow());
    }

    #[test]
    fn the_list_of_what_retired_keys_signed_is_the_owners() {
        let owner = AccountKeys::derive(&AccountSecret::generate());
        let digest = |byte: u8| Bytes(vec![byte; 32]);
        let mut list = SignedBefore::new(UserId(2), 0, [digest(3), digest(1), digest(3)]);
        assert_eq!(list.digests, [digest(1), digest(3)]);
        list.approve(&owner);
        assert!(list.verify(&owner.public()).is_ok());
        assert!(list.contains(&digest(3)));
        assert!(!list.contains(&digest(2)));

        // Nothing can be added, and it holds only for that person and revision.
        let mut added = list.clone();
        added.digests.push(digest(4));
        assert!(added.verify(&owner.public()).is_err());
        let mut other = list.clone();
        other.revision = 1;
        assert!(other.verify(&owner.public()).is_err());
        let mut someone_else = list.clone();
        someone_else.user_id = UserId(3);
        assert!(someone_else.verify(&owner.public()).is_err());
        let mut by_impostor = list.clone();
        by_impostor.approve(&AccountKeys::derive(&AccountSecret::generate()));
        assert!(by_impostor.verify(&owner.public()).is_err());
    }

    #[test]
    fn an_approved_entry_verifies_against_the_owner() {
        let owner = AccountKeys::derive(&AccountSecret::generate());
        let (mut bob, _) = entry("Bob");
        assert!(bob.verify(&owner.public()).is_err());

        bob.approve(&owner);
        assert!(bob.verify(&owner.public()).is_ok());
    }

    #[test]
    fn swapping_the_keys_or_name_breaks_the_approval() {
        let owner = AccountKeys::derive(&AccountSecret::generate());
        let (mut bob, _) = entry("Bob");
        bob.approve(&owner);

        let (mallory, _) = entry("Mallory");
        let mut swapped_keys = bob.clone();
        swapped_keys.keys = mallory.keys;
        assert!(swapped_keys.verify(&owner.public()).is_err());

        let mut renamed = bob.clone();
        renamed.name = "Robert".into();
        assert!(renamed.verify(&owner.public()).is_err());
    }

    #[test]
    fn only_the_owner_can_approve() {
        let owner = AccountKeys::derive(&AccountSecret::generate());
        let impostor = AccountKeys::derive(&AccountSecret::generate());
        let (mut bob, _) = entry("Bob");
        bob.approve(&impostor);
        assert!(bob.verify(&owner.public()).is_err());
    }
}
