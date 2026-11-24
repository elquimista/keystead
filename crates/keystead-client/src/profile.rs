//! The profile: everything a device keeps about its account except secrets. That's the
//! server, the pinned owner keys, the feed cursor, and the encrypted copy of folders,
//! items and the directory. Stored as `profile.json`, the same on every platform.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use keystead_core::api::{KeyLink, Role, Roles};
use keystead_core::directory::DirectoryEntry;
use keystead_core::ids::{DeviceId, FolderId, ItemId, UserId};
use keystead_core::items::{EncryptedItem, FolderInfo, Sealed};
use keystead_core::keys::{AccountKeys, AccountPublicKeys, FolderKey, WrappedKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct FolderRecord {
    pub info: Sealed,
    /// The folder's current key, wrapped for this account.
    pub wrapped_key: WrappedKey,
    /// Which key that is: 0 at first, one more each time someone loses access.
    #[serde(default)]
    pub generation: u32,
    /// Each older key, sealed with the one after it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<KeyLink>,
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
    /// This account's roles, from the last sync. Absent from servers before roles, where
    /// everyone could do everything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Roles>,
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
            roles: None,
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

    /// The folder's current key.
    pub fn folder_key(&self, keys: &AccountKeys, folder_id: FolderId) -> Result<FolderKey> {
        let record = self
            .folders
            .get(&folder_id)
            .context("you don't have access to that folder")?;
        Ok(keys.unwrap_folder_key(&record.wrapped_key, folder_id)?)
    }

    /// Every key the folder has had, newest first, opened through its chain. Items keep
    /// whichever key they were saved with.
    pub fn folder_keys(&self, keys: &AccountKeys, folder_id: FolderId) -> Result<Vec<FolderKey>> {
        let record = self
            .folders
            .get(&folder_id)
            .context("you don't have access to that folder")?;
        let mut all = vec![keys.unwrap_folder_key(&record.wrapped_key, folder_id)?];
        let mut generation = record.generation;
        while generation > 0 {
            let link = record
                .chain
                .iter()
                .find(|link| link.generation == generation)
                .context("the folder's key chain is missing a link")?;
            let newer = all.last().expect("starts with the current key");
            all.push(newer.open_previous(&link.previous, folder_id, generation)?);
            generation -= 1;
        }
        Ok(all)
    }

    /// This account's role in a folder it's in.
    pub fn folder_role(&self, folder_id: FolderId) -> Role {
        self.roles
            .as_ref()
            .and_then(|roles| {
                roles
                    .folders
                    .iter()
                    .find(|role| role.folder_id == folder_id)
            })
            .map_or_else(Role::before_roles, |role| role.role)
    }

    /// What this account may do with an item: the higher of its folder role and its direct
    /// role; an item's owner always manages it.
    pub fn item_role(&self, item: &EncryptedItem) -> Role {
        if self.roles.is_none() || item.owner == Some(self.user_id) {
            return Role::Manage;
        }
        let in_folder = item
            .folder_id
            .filter(|folder_id| self.folders.contains_key(folder_id))
            .map(|folder_id| self.folder_role(folder_id));
        let direct = self.roles.as_ref().and_then(|roles| {
            roles
                .items
                .iter()
                .find(|role| role.item_id == item.id)
                .map(|role| role.role)
        });
        in_folder.max(direct).unwrap_or(Role::View)
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

    /// Whether the owner removed this user from the team.
    pub fn is_removed(&self, user: UserId) -> bool {
        self.directory
            .iter()
            .any(|entry| entry.user_id == user && entry.removed)
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
