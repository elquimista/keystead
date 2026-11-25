//! Writing logins to a KeePass file (.kdbx) encrypted with a passphrase: a copy that opens
//! in KeePassXC or KeePass, and imports back into Keystead. Folders become groups ("A / B"
//! as B inside A), and a one-time code is kept the way KeePassXC keeps it. The file is
//! built and encrypted in memory; nothing decrypted is written anywhere.

use std::collections::HashMap;

use anyhow::{Result, anyhow};
use keepass::config::{DatabaseConfig, KdfConfig};
use keepass::db::GroupId;
use keepass::{Database, DatabaseKey};
use keystead_core::items::{Details, Overview};

use crate::vault::FOLDER_SEPARATOR;

/// The shortest passphrase an export takes: the file holds every password in it, and
/// anyone with a copy can try passphrases offline for as long as they like.
pub const MIN_EXPORT_PASSPHRASE: usize = 12;

/// Each guess at the passphrase costs Argon2id over 128 MiB, 30 times: about half a
/// second on a recent Mac, near KeePassXC's own default. KeePassXC and KeePass open it.
const KDF: KdfConfig = KdfConfig::Argon2id {
    iterations: 30,
    memory: 128 * 1024 * 1024,
    parallelism: 4,
    version: argon2::Version::Version13,
};

/// A KeePass file being filled.
pub(crate) struct KdbxWriter {
    database: Database,
    /// Groups made so far, by folder name.
    groups: HashMap<String, GroupId>,
    logins: usize,
}

impl KdbxWriter {
    pub(crate) fn new() -> Self {
        let mut config = DatabaseConfig::default();
        config.kdf_config = KDF;
        let mut database = Database::with_config(config);
        database.meta.database_name = Some("Keystead".to_owned());
        Self {
            database,
            groups: HashMap::new(),
            logins: 0,
        }
    }

    /// The group for a folder, made (with the groups it's inside) if it isn't yet.
    pub(crate) fn folder(&mut self, folder: &str) -> GroupId {
        if let Some(&id) = self.groups.get(folder) {
            return id;
        }
        let (parent, name) = match folder.rsplit_once(FOLDER_SEPARATOR) {
            Some((parent, name)) => (self.folder(parent), name),
            None => (self.database.root().id(), folder),
        };
        let mut parent = self
            .database
            .group_mut(parent)
            .expect("the parent group was just found or made");
        let mut group = parent.add_group();
        name.clone_into(&mut group.name);
        let id = group.id();
        self.groups.insert(folder.to_owned(), id);
        id
    }

    /// Adds a login, in a folder's group or at the top.
    pub(crate) fn add(&mut self, folder: Option<&str>, overview: &Overview, details: &Details) {
        let group = match folder {
            Some(folder) => self.folder(folder),
            None => self.database.root().id(),
        };
        let mut group = self
            .database
            .group_mut(group)
            .expect("the group was just found or made");
        let mut entry = group.add_entry();
        entry.set_unprotected("Title", overview.name.as_str());
        entry.set_unprotected("UserName", overview.username.as_str());
        entry.set_protected("Password", details.password.as_str());
        entry.set_unprotected("URL", overview.url.as_str());
        entry.set_unprotected("Notes", details.notes.as_str());
        if !details.otp.is_empty() {
            entry.set_protected("otp", details.otp.as_str());
        }
        entry.tags.clone_from(&overview.tags);
        self.logins += 1;
    }

    pub(crate) fn logins(&self) -> usize {
        self.logins
    }

    /// The file, encrypted with `passphrase`.
    pub(crate) fn finish(self, passphrase: &str) -> Result<Vec<u8>> {
        let mut file = Vec::new();
        self.database
            .save(&mut file, DatabaseKey::new().with_password(passphrase))
            .map_err(|error| anyhow!("couldn't write the KeePass file ({error})"))?;
        Ok(file)
    }
}
