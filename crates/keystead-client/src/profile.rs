//! The profile: everything a device keeps about its account except secrets. That's the
//! server, the pinned owner keys, the feed cursor, and the encrypted copy of folders,
//! items and the directory. Stored as `profile.json`, the same on every platform.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use keystead_core::directory::DirectoryEntry;
use keystead_core::ids::{DeviceId, FolderId, ItemId, UserId};
use keystead_core::items::{EncryptedItem, FolderInfo, Sealed};
use keystead_core::keys::{AccountKeys, AccountPublicKeys, FolderKey, WrappedKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct FolderRecord {
    pub info: Sealed,
    pub wrapped_key: WrappedKey,
}

#[derive(Serialize, Deserialize)]
pub struct Profile {
    pub server: String,
    pub name: String,
    pub user_id: UserId,
    pub device_id: DeviceId,
    /// The owner's keys, pinned when this device enrolled. Directory entries are trusted
    /// only if the owner signed them.
    pub owner: AccountPublicKeys,
    pub cursor: i64,
    pub folders: BTreeMap<FolderId, FolderRecord>,
    pub items: BTreeMap<ItemId, EncryptedItem>,
    pub directory: Vec<DirectoryEntry>,
}

impl Profile {
    pub fn new(
        server: &str,
        name: &str,
        user_id: UserId,
        device_id: DeviceId,
        owner: AccountPublicKeys,
    ) -> Self {
        Self {
            server: server.trim_end_matches('/').to_owned(),
            name: name.to_owned(),
            user_id,
            device_id,
            owner,
            cursor: 0,
            folders: BTreeMap::new(),
            items: BTreeMap::new(),
            directory: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            bail!("no Keystead profile at {}", path.display());
        }
        let text = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&text).with_context(|| format!("reading {}", path.display()))
    }

    /// Writes the profile atomically, readable only by the current user.
    pub fn save(&self, path: &Path) -> Result<()> {
        write_private(path, &serde_json::to_vec_pretty(self)?)
    }

    pub fn folder_key(&self, keys: &AccountKeys, folder_id: FolderId) -> Result<FolderKey> {
        let record = self
            .folders
            .get(&folder_id)
            .context("you don't have access to that folder")?;
        Ok(keys.unwrap_folder_key(&record.wrapped_key, folder_id)?)
    }

    pub fn folder_name(&self, keys: &AccountKeys, folder_id: FolderId) -> Result<String> {
        let record = self
            .folders
            .get(&folder_id)
            .context("you don't have access to that folder")?;
        let key = self.folder_key(keys, folder_id)?;
        Ok(FolderInfo::open(&record.info, folder_id, &key)?.name)
    }

    pub fn find_folder(&self, keys: &AccountKeys, name: &str) -> Result<FolderId> {
        let mut matches = Vec::new();
        for &folder_id in self.folders.keys() {
            if self.folder_name(keys, folder_id)? == name {
                matches.push(folder_id);
            }
        }
        match matches.as_slice() {
            [folder_id] => Ok(*folder_id),
            [] => bail!("no folder named {name:?}"),
            _ => bail!("several folders are named {name:?}"),
        }
    }

    /// A user's keys, if the pinned owner approved their directory entry.
    pub fn trusted_keys(&self, user: UserId) -> Option<AccountPublicKeys> {
        self.directory
            .iter()
            .find(|entry| entry.user_id == user && entry.verify(&self.owner).is_ok())
            .map(|entry| entry.keys.clone())
    }

    pub fn user_name(&self, user: UserId) -> String {
        self.directory
            .iter()
            .find(|entry| entry.user_id == user)
            .map_or_else(|| format!("user {user}"), |entry| entry.name.clone())
    }
}

/// Writes a file atomically, readable only by the current user, creating its folder
/// (readable only by the current user) if needed.
pub fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let folder = path.parent().context("a profile path needs a folder")?;
    fs::create_dir_all(folder).with_context(|| format!("creating {}", folder.display()))?;
    restrict(folder, 0o700)?;
    let temporary = path.with_extension("tmp");
    let mut file = fs::File::create(&temporary)?;
    restrict(&temporary, 0o600)?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}
