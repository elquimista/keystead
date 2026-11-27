//! Where the CLI keeps its files: the shared `profile.json`, the same format the apps use,
//! and `device.json`, which says where this machine's keys are.
//!
//! The keys are this machine's sign-in key and the account secret: whoever has them has the
//! account. On a Mac (0.18.0 and later) they're in the login Keychain, which keeps them
//! encrypted and unlocks with the Mac, and `device.json` only names the item. Elsewhere, or
//! if the Keychain can't be used, they're in `device.json` itself, protected only by file
//! permissions (0600). A `device.json` with keys in it, as from before, is moved into the
//! Keychain the next time it's read.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use keystead_client::profile::write_private;
use keystead_core::encoding::Bytes;
use keystead_core::ids::DeviceId;
use keystead_core::keys::{AccountSecret, SoftwareDeviceKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const DEVICE_FILE: &str = "device.json";

static FILES_ONLY: AtomicBool = AtomicBool::new(false);

/// Keeps keys in `device.json` for the rest of this process, even on a Mac: for tests,
/// which make many throwaway accounts and shouldn't fill the login Keychain.
#[doc(hidden)]
pub fn keep_keys_in_files() {
    FILES_ONLY.store(true, Ordering::Relaxed);
}

/// Whether new keys go in the login Keychain: on a Mac, unless tests said otherwise.
#[cfg(target_os = "macos")]
pub fn keys_in_keychain() -> bool {
    !FILES_ONLY.load(Ordering::Relaxed)
}

/// Whether new keys go in the login Keychain: never, without one.
#[cfg(not(target_os = "macos"))]
pub fn keys_in_keychain() -> bool {
    false
}

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

/// This machine's keys, wherever they're kept.
pub struct DeviceFile {
    keys: Keys,
    /// While recovering with the owner's help, before the owner approves: this machine's
    /// device id, so the same keys can be sent again if waiting stops.
    recovering: Option<DeviceId>,
}

/// The two secrets, as a Keychain item holds them.
#[derive(Serialize, Deserialize)]
struct Keys {
    device_key: Bytes,
    account_secret: Bytes,
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.device_key.0.zeroize();
        self.account_secret.0.zeroize();
    }
}

/// `device.json`: the Keychain item that holds the keys, or the keys themselves.
#[derive(Default, Serialize, Deserialize)]
struct Stored {
    /// The Keychain item's account, under the service "Keystead CLI" (0.18.0 and later).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keychain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_key: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_secret: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovering: Option<DeviceId>,
}

impl Drop for Stored {
    fn drop(&mut self) {
        for bytes in [&mut self.device_key, &mut self.account_secret]
            .into_iter()
            .flatten()
        {
            bytes.0.zeroize();
        }
    }
}

/// Where `save` put the keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeptIn {
    Keychain,
    File,
}

impl DeviceFile {
    pub fn new(key: &SoftwareDeviceKey, secret: &AccountSecret) -> Self {
        Self {
            keys: Keys {
                device_key: Bytes(key.to_bytes().to_vec()),
                account_secret: Bytes(secret.as_bytes().to_vec()),
            },
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

    /// Reads the keys from wherever `device.json` says. Keys still in the file are moved
    /// into the login Keychain first, on a Mac.
    pub fn load(home: &Path) -> Result<Self> {
        Self::load_with(home, keys_in_keychain())
    }

    fn load_with(home: &Path, keychain: bool) -> Result<Self> {
        let path = home.join(DEVICE_FILE);
        let Some(mut stored) = read_stored(&path)? else {
            bail!(
                "no Keystead profile in {}; run `keystead setup` or `keystead join` first",
                home.display()
            );
        };
        if let Some(item) = &stored.keychain {
            let secret = keychain::read(item)?;
            let keys: Keys = serde_json::from_slice(&secret)
                .context("the keys in the login Keychain are damaged")?;
            return Ok(Self {
                keys,
                recovering: stored.recovering,
            });
        }
        let (Some(device_key), Some(account_secret)) =
            (stored.device_key.take(), stored.account_secret.take())
        else {
            bail!("{} is damaged: it names no keys", path.display());
        };
        let device = Self {
            keys: Keys {
                device_key,
                account_secret,
            },
            recovering: stored.recovering,
        };
        if keychain && device.save_with(home, true)? == KeptIn::Keychain {
            eprintln!(
                "Moved this machine's keys from {} into your login Keychain.",
                path.display()
            );
        }
        Ok(device)
    }

    /// Deletes the keys and the device file, if there are any.
    pub fn delete(home: &Path) -> Result<()> {
        let path = home.join(DEVICE_FILE);
        if let Some(item) = read_stored(&path)
            .ok()
            .flatten()
            .and_then(|s| s.keychain.clone())
        {
            keychain::delete(&item)?;
        }
        match std::fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                Err(error).with_context(|| format!("deleting {}", path.display()))
            }
            _ => Ok(()),
        }
    }

    /// Keeps the keys: in the login Keychain on a Mac, in `device.json` otherwise. If the
    /// Keychain refuses them, as over SSH while it's locked, they go in the file, with a
    /// warning, rather than being lost: the next command moves them over.
    pub fn save(&self, home: &Path) -> Result<KeptIn> {
        self.save_with(home, keys_in_keychain())
    }

    fn save_with(&self, home: &Path, keychain: bool) -> Result<KeptIn> {
        let path = home.join(DEVICE_FILE);
        let mut stored = Stored::default();
        stored.recovering = self.recovering;
        let mut kept = KeptIn::File;
        if keychain {
            // The item this home already names, if any, so saving again replaces it.
            let item = read_stored(&path)
                .ok()
                .flatten()
                .and_then(|stored| stored.keychain.clone())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let secret = Zeroizing::new(serde_json::to_vec(&self.keys)?);
            match keychain::write(&item, &secret) {
                Ok(()) => {
                    stored.keychain = Some(item);
                    kept = KeptIn::Keychain;
                }
                Err(error) => eprintln!(
                    "warning: {error:#}. This machine's keys are in {} instead, readable only \
                     by you but not encrypted.",
                    path.display()
                ),
            }
        }
        if kept == KeptIn::File {
            stored.device_key = Some(Bytes(self.keys.device_key.0.clone()));
            stored.account_secret = Some(Bytes(self.keys.account_secret.0.clone()));
        }
        write_private(&path, &Zeroizing::new(serde_json::to_vec_pretty(&stored)?))?;
        Ok(kept)
    }

    pub fn key(&self) -> Result<SoftwareDeviceKey> {
        let bytes: [u8; 32] = self
            .keys
            .device_key
            .as_slice()
            .try_into()
            .context("stored device key is damaged")?;
        Ok(SoftwareDeviceKey::from_bytes(&bytes))
    }

    pub fn secret(&self) -> Result<AccountSecret> {
        let bytes: [u8; 32] = self
            .keys
            .account_secret
            .as_slice()
            .try_into()
            .context("stored account secret is damaged")?;
        Ok(AccountSecret::from_bytes(bytes))
    }
}

/// `device.json`, if there is one.
fn read_stored(path: &Path) -> Result<Option<Stored>> {
    let text = match std::fs::read(path) {
        Ok(text) => Zeroizing::new(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    serde_json::from_slice(&text)
        .map(Some)
        .with_context(|| format!("reading {}", path.display()))
}

/// The login Keychain, through Security.framework's generic password items.
#[cfg(target_os = "macos")]
mod keychain {
    use anyhow::{Result, anyhow};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };
    use zeroize::Zeroizing;

    #[cfg(not(test))]
    const SERVICE: &str = "Keystead CLI";
    /// Tests' items, apart from real ones.
    #[cfg(test)]
    const SERVICE: &str = "Keystead CLI test";
    /// `errSecItemNotFound`.
    const NOT_FOUND: i32 = -25300;

    pub fn write(item: &str, secret: &[u8]) -> Result<()> {
        set_generic_password(SERVICE, item, secret).map_err(|error| {
            anyhow!("the login Keychain didn't take this machine's keys ({error})")
        })
    }

    pub fn read(item: &str) -> Result<Zeroizing<Vec<u8>>> {
        get_generic_password(SERVICE, item)
            .map(Zeroizing::new)
            .map_err(|error| {
                if error.code() == NOT_FOUND {
                    anyhow!(
                        "this machine's keys aren't in the login Keychain any more (\"{SERVICE}\", \
                         account {item}). Recover your account with your Recovery Kit"
                    )
                } else {
                    anyhow!("couldn't read this machine's keys from the login Keychain ({error})")
                }
            })
    }

    pub fn delete(item: &str) -> Result<()> {
        match delete_generic_password(SERVICE, item) {
            Err(error) if error.code() != NOT_FOUND => Err(anyhow!(
                "couldn't delete this machine's keys from the login Keychain ({error})"
            )),
            _ => Ok(()),
        }
    }
}

/// No Keychain here: keys stay in `device.json`.
#[cfg(not(target_os = "macos"))]
mod keychain {
    use anyhow::{Result, bail};
    use zeroize::Zeroizing;

    pub fn write(_item: &str, _secret: &[u8]) -> Result<()> {
        bail!("there's no login Keychain here")
    }

    pub fn read(_item: &str) -> Result<Zeroizing<Vec<u8>>> {
        bail!(
            "this machine's device.json keeps its keys in a Mac's login Keychain, which isn't \
             here. Recover your account with your Recovery Kit"
        )
    }

    pub fn delete(_item: &str) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use keystead_core::keys::{AccountSecret, SoftwareDeviceKey};

    use super::{DEVICE_FILE, DeviceFile, KeptIn};

    fn home(name: &str) -> std::path::PathBuf {
        let home = std::env::temp_dir().join(format!(
            "keystead-device-test-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        home
    }

    fn same(a: &DeviceFile, b: &DeviceFile) -> bool {
        a.keys.device_key == b.keys.device_key && a.keys.account_secret == b.keys.account_secret
    }

    #[test]
    fn without_the_keychain_the_keys_are_in_the_file() {
        let home = home("file");
        let device = DeviceFile::new(&SoftwareDeviceKey::generate(), &AccountSecret::generate());
        assert_eq!(device.save_with(&home, false).unwrap(), KeptIn::File);
        let text = std::fs::read_to_string(home.join(DEVICE_FILE)).unwrap();
        assert!(text.contains("account_secret") && !text.contains("keychain"));
        assert!(same(&DeviceFile::load_with(&home, false).unwrap(), &device));
        DeviceFile::delete(&home).unwrap();
        assert!(!DeviceFile::exists(&home));
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Writes to the login Keychain, under "Keystead CLI test", and deletes what it wrote:
    /// run with `cargo test -p keystead-cli --lib -- --ignored` on a Mac.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "uses the login Keychain"]
    fn on_a_mac_the_keys_move_into_the_keychain_and_leave_the_file() {
        let home = home("keychain");
        let device = DeviceFile::new(&SoftwareDeviceKey::generate(), &AccountSecret::generate());
        // A device.json from before 0.18.0, keys and all.
        assert_eq!(device.save_with(&home, false).unwrap(), KeptIn::File);
        let moved = DeviceFile::load_with(&home, true).unwrap();
        assert!(same(&moved, &device));
        let text = std::fs::read_to_string(home.join(DEVICE_FILE)).unwrap();
        assert!(text.contains("keychain"), "{text}");
        assert!(!text.contains("account_secret") && !text.contains("device_key"));

        // Read back from the Keychain; saving again keeps the same item.
        assert!(same(&DeviceFile::load_with(&home, true).unwrap(), &device));
        assert_eq!(device.save_with(&home, true).unwrap(), KeptIn::Keychain);
        assert_eq!(
            std::fs::read_to_string(home.join(DEVICE_FILE)).unwrap(),
            text
        );

        // Deleting takes the item too: a copy of the file opens nothing.
        let copy = std::fs::read(home.join(DEVICE_FILE)).unwrap();
        DeviceFile::delete(&home).unwrap();
        std::fs::write(home.join(DEVICE_FILE), copy).unwrap();
        let error = DeviceFile::load_with(&home, true).err().unwrap();
        assert!(
            format!("{error:#}").contains("aren't in the login Keychain"),
            "{error:#}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}
