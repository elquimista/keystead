//! Where the CLI keeps its files: the shared `profile.json`, the same format the apps use,
//! and its keys in `device.json`.
//!
//! For now the keys are stored unencrypted, protected only by file permissions (0600).
//! The desktop apps keep theirs in the Secure Enclave or TPM; the CLI will get a
//! passphrase or hardware key later.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use keystead_client::profile::write_private;
use keystead_core::encoding::Bytes;
use keystead_core::ids::DeviceId;
use keystead_core::keys::{AccountSecret, SoftwareDeviceKey};
use serde::{Deserialize, Serialize};

const DEVICE_FILE: &str = "device.json";

/// `KEYSTEAD_HOME`, or `~/.config/keystead`.
pub fn default_home() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("KEYSTEAD_HOME") {
        return Ok(PathBuf::from(home));
    }
    let user_home =
        std::env::var_os("HOME").context("HOME isn't set; set KEYSTEAD_HOME instead")?;
    Ok(PathBuf::from(user_home).join(".config").join("keystead"))
}

pub fn profile_path(home: &Path) -> PathBuf {
    home.join("profile.json")
}

#[derive(Serialize, Deserialize)]
pub struct DeviceFile {
    device_key: Bytes,
    account_secret: Bytes,
    /// While recovering with the owner's help, before the owner approves: this machine's
    /// device id, so the same keys can be sent again if waiting stops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovering: Option<DeviceId>,
}

impl DeviceFile {
    pub fn new(key: &SoftwareDeviceKey, secret: &AccountSecret) -> Self {
        Self {
            device_key: Bytes(key.to_bytes().to_vec()),
            account_secret: Bytes(secret.as_bytes().to_vec()),
            recovering: None,
        }
    }

    /// New keys for recovering with the owner's help, kept before they're sent, so an
    /// approval isn't lost if waiting for it stops.
    pub fn recovering(key: &SoftwareDeviceKey, secret: &AccountSecret, device: DeviceId) -> Self {
        Self {
            recovering: Some(device),
            ..Self::new(key, secret)
        }
    }

    /// The device id of a recovery this machine started and didn't finish.
    pub fn recovering_device(&self) -> Option<DeviceId> {
        self.recovering
    }

    pub fn exists(home: &Path) -> bool {
        home.join(DEVICE_FILE).exists()
    }

    pub fn load(home: &Path) -> Result<Self> {
        let path = home.join(DEVICE_FILE);
        if !path.exists() {
            bail!(
                "no Keystead profile in {}; run `keystead setup` or `keystead join` first",
                home.display()
            );
        }
        let text = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&text).with_context(|| format!("reading {}", path.display()))
    }

    /// Deletes the device file, if there is one.
    pub fn delete(home: &Path) -> Result<()> {
        let path = home.join(DEVICE_FILE);
        match std::fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                Err(error).with_context(|| format!("deleting {}", path.display()))
            }
            _ => Ok(()),
        }
    }

    pub fn save(&self, home: &Path) -> Result<()> {
        write_private(&home.join(DEVICE_FILE), &serde_json::to_vec_pretty(self)?)
    }

    pub fn key(&self) -> Result<SoftwareDeviceKey> {
        let bytes: [u8; 32] = self
            .device_key
            .as_slice()
            .try_into()
            .context("stored device key is damaged")?;
        Ok(SoftwareDeviceKey::from_bytes(&bytes))
    }

    pub fn secret(&self) -> Result<AccountSecret> {
        let bytes: [u8; 32] = self
            .account_secret
            .as_slice()
            .try_into()
            .context("stored account secret is damaged")?;
        Ok(AccountSecret::from_bytes(bytes))
    }
}
