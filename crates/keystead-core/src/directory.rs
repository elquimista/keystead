//! The directory of users and their public keys.
//!
//! The server stores the directory but can't be trusted with it: a server that swapped
//! in its own key could read everything shared with that user. So each entry carries the
//! org owner's signature, given after the owner checks the user's fingerprint in person
//! or on a call, and apps only share with entries whose signature verifies.

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
}

impl DirectoryEntry {
    /// Signs the entry as the org owner. The owner approves their own entry at setup.
    pub fn approve(&mut self, owner: &AccountKeys) {
        self.approval = Some(owner.sign(&self.approval_message()));
    }

    /// Checks the owner's signature. Entries without one are never trusted.
    pub fn verify(&self, owner: &AccountPublicKeys) -> Result<(), Error> {
        let approval = self.approval.as_ref().ok_or(Error::BadSignature)?;
        owner.verify(&self.approval_message(), approval.as_slice())
    }

    pub fn approval_message(&self) -> Vec<u8> {
        transcript(
            "keystead/directory-entry/v1",
            &[
                &self.user_id.to_be_bytes(),
                self.name.as_bytes(),
                &self.keys.encryption.0,
                &self.keys.signing.0,
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::AccountSecret;

    fn entry(name: &str) -> (DirectoryEntry, AccountKeys) {
        let keys = AccountKeys::derive(&AccountSecret::generate());
        let entry = DirectoryEntry {
            user_id: UserId(2),
            name: name.into(),
            keys: keys.public(),
            approval: None,
        };
        (entry, keys)
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
