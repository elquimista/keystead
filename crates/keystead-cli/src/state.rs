//! What the CLI keeps on disk: its keys, the pinned owner keys, and an encrypted copy of
//! everything it has synced.
//!
//! Slice-only shortcut: the account secret and device key are stored unencrypted in
//! `state.json`, protected only by file permissions (0600). The desktop apps keep these in
//! the Secure Enclave or TPM; the CLI will get a passphrase or hardware key later.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use keystead_core::directory::DirectoryEntry;
use keystead_core::encoding::Bytes;
use keystead_core::ids::{DeviceId, FolderId, ItemId, UserId};
use keystead_core::items::{EncryptedItem, FolderInfo, Sealed};
use keystead_core::keys::{
    AccountKeys, AccountPublicKeys, AccountSecret, FolderKey, SoftwareDeviceKey, WrappedKey,
};
use serde::{Deserialize, Serialize};

const STATE_FILE: &str = "state.json";

/// Where the CLI keeps its state: `KEYSTEAD_HOME`, or `~/.config/keystead`.
pub fn default_home() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("KEYSTEAD_HOME") {
        return Ok(PathBuf::from(home));
    }
    let user_home =
        std::env::var_os("HOME").context("HOME isn't set; set KEYSTEAD_HOME instead")?;
    Ok(PathBuf::from(user_home).join(".config").join("keystead"))
}

#[derive(Serialize, Deserialize)]
pub struct FolderRecord {
    pub info: Sealed,
    pub wrapped_key: WrappedKey,
}

#[derive(Serialize, Deserialize)]
pub struct State {
    pub server: String,
    pub name: String,
    pub user_id: UserId,
    pub device_id: DeviceId,
    device_key: Bytes,
    account_secret: Bytes,
    /// The owner's keys, pinned when this profile was created. Directory entries are
    /// trusted only if the owner signed them.
    pub owner: AccountPublicKeys,
    pub cursor: i64,
    pub folders: BTreeMap<FolderId, FolderRecord>,
    pub items: BTreeMap<ItemId, EncryptedItem>,
    pub directory: Vec<DirectoryEntry>,
}

pub struct NewProfile<'a> {
    pub server: &'a str,
    pub name: &'a str,
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub device_key: &'a SoftwareDeviceKey,
    pub secret: &'a AccountSecret,
    pub owner: AccountPublicKeys,
}

impl State {
    pub fn new(profile: NewProfile<'_>) -> Self {
        Self {
            server: profile.server.trim_end_matches('/').to_owned(),
            name: profile.name.to_owned(),
            user_id: profile.user_id,
            device_id: profile.device_id,
            device_key: Bytes(profile.device_key.to_bytes().to_vec()),
            account_secret: Bytes(profile.secret.as_bytes().to_vec()),
            owner: profile.owner,
            cursor: 0,
            folders: BTreeMap::new(),
            items: BTreeMap::new(),
            directory: Vec::new(),
        }
    }

    pub fn exists(home: &Path) -> bool {
        home.join(STATE_FILE).exists()
    }

    pub fn load(home: &Path) -> Result<Self> {
        let path = home.join(STATE_FILE);
        if !path.exists() {
            bail!(
                "no Keystead profile in {}; run `keystead setup` or `keystead join` first",
                home.display()
            );
        }
        let text = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&text).with_context(|| format!("reading {}", path.display()))
    }

    /// Writes the state atomically, readable only by the current user.
    pub fn save(&self, home: &Path) -> Result<()> {
        fs::create_dir_all(home).with_context(|| format!("creating {}", home.display()))?;
        restrict(home, 0o700)?;
        let path = home.join(STATE_FILE);
        let temporary = home.join(format!("{STATE_FILE}.tmp"));
        let mut file = fs::File::create(&temporary)?;
        restrict(&temporary, 0o600)?;
        file.write_all(&serde_json::to_vec_pretty(self)?)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        Ok(())
    }

    pub fn account_keys(&self) -> Result<AccountKeys> {
        let bytes: [u8; 32] = self
            .account_secret
            .as_slice()
            .try_into()
            .context("stored account secret is damaged")?;
        Ok(AccountKeys::derive(&AccountSecret::from_bytes(bytes)))
    }

    pub fn device_key(&self) -> Result<SoftwareDeviceKey> {
        let bytes: [u8; 32] = self
            .device_key
            .as_slice()
            .try_into()
            .context("stored device key is damaged")?;
        Ok(SoftwareDeviceKey::from_bytes(&bytes))
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
