//! The directory of users and their public keys.
//!
//! The server stores the directory but can't be trusted with it: a server that swapped
//! in its own key could read everything shared with that user. So each entry carries the
//! team owner's signature, given after the owner checks the user's fingerprint in person
//! or on a call, and apps only share with entries whose signature verifies.
//!
//! Someone who recovers with the owner's help gets new keys at the next `revision`. Apps
//! remember the highest revision they've seen for each person and never share with an
//! earlier one, and the earlier keys stay listed, `retired`, so what they signed still
//! verifies.

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
    /// They let the owner recover their own items (escrow). Not signed: it only informs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub escrow: bool,
    /// The owner has started a recovery for them that isn't approved yet. Not signed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub recovering: bool,
}

/// Keys someone had before a recovery, with the owner's approval of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredKeys {
    pub revision: u32,
    pub name: String,
    pub keys: AccountPublicKeys,
    pub approval: Bytes,
}

fn is_zero(revision: &u32) -> bool {
    *revision == 0
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
            recovering: false,
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

    /// Every set of keys the owner approved for this person, current first, to check what
    /// they signed. Retired keys only count from revisions before the current one.
    pub fn signing_keys(&self, owner: &AccountPublicKeys) -> Vec<AccountPublicKeys> {
        let current = self.verify(owner).is_ok().then(|| self.keys.clone());
        let retired = self.retired.iter().filter(|retired| {
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
        });
        current
            .into_iter()
            .chain(retired.map(|retired| retired.keys.clone()))
            .collect()
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
        });
        recovered.keys = new.public();
        recovered.revision = 1;
        recovered.approve(&owner);
        assert!(recovered.verify(&owner.public()).is_ok());
        assert_eq!(
            recovered.signing_keys(&owner.public()),
            [new.public(), old.public()]
        );

        // The revision is signed: the same keys can't pass for another revision.
        let mut replayed = recovered.clone();
        replayed.revision = 2;
        assert!(replayed.verify(&owner.public()).is_err());
        // A retired set that wasn't approved doesn't count.
        let mut forged = recovered.clone();
        forged.retired[0].keys = AccountKeys::derive(&AccountSecret::generate()).public();
        assert_eq!(forged.signing_keys(&owner.public()), [new.public()]);
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
