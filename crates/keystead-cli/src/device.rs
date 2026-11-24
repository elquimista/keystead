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
}

impl DeviceFile {
    pub fn new(key: &SoftwareDeviceKey, secret: &AccountSecret) -> Self {
        Self {
            device_key: Bytes(key.to_bytes().to_vec()),
            account_secret: Bytes(secret.as_bytes().to_vec()),
        }
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
