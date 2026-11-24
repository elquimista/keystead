//! The Keystead client, exposed to Swift. UniFFI generates the Swift side from the
//! `#[uniffi::export]` items here; `apps/macos/scripts/build-core.sh` runs the generator.
//!
//! Keep this layer thin: it converts types and errors, and the logic stays in
//! `keystead-client` and `keystead-core`. The account keys live inside [`Vault`] and never
//! cross into Swift; only what the user asks to see does.

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use keystead_client::{EditOutcome, InviteInfo, NewAccount};
use keystead_core::encoding::Bytes;
use keystead_core::ids::{DeviceId, ItemId, UserId};
use keystead_core::items::{Details, Overview};
use keystead_core::keys::{AccountSecret, DeviceKeyScheme, DevicePublicKey};

uniffi::setup_scaffolding!();

#[derive(Debug, uniffi::Error)]
pub enum CoreError {
    /// The caller passed something malformed.
    InvalidInput { message: String },
    /// The operation failed: network, server, decryption or storage.
    Failed { message: String },
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { message } | Self::Failed { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<anyhow::Error> for CoreError {
    fn from(error: anyhow::Error) -> Self {
        Self::Failed {
            message: format!("{error:#}"),
        }
    }
}

/// Lets a Swift signer report an error UniFFI didn't expect.
impl From<uniffi::UnexpectedUniFFICallbackError> for CoreError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed {
            message: error.reason,
        }
    }
}

/// The device's sign-in key. The Mac app implements it with a Secure Enclave key.
#[uniffi::export(with_foreign)]
pub trait DeviceSigner: Send + Sync {
    /// The public key, SEC1-encoded (65 bytes, uncompressed).
    fn public_key(&self) -> Vec<u8>;
    /// An ECDSA P-256 signature with SHA-256 over `message`, as raw r‖s (64 bytes).
    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, CoreError>;
}

/// Presents a Swift signer to the client library.
struct SignerAdapter(Arc<dyn DeviceSigner>);

impl keystead_client::DeviceSigner for SignerAdapter {
    fn public_key(&self) -> DevicePublicKey {
        DevicePublicKey {
            scheme: DeviceKeyScheme::EcdsaP256Sha256,
            key: Bytes(self.0.public_key()),
        }
    }

    fn sign(&self, message: &[u8]) -> anyhow::Result<Bytes> {
        Ok(Bytes(self.0.sign(message.to_vec())?))
    }
}

#[derive(uniffi::Record)]
pub struct Identity {
    pub name: String,
    pub user_id: i64,
    pub fingerprint: String,
    pub server: String,
    pub is_owner: bool,
    /// The owner's fingerprint, as this device pinned it. Recovery kits carry it.
    pub owner_fingerprint: String,
}

/// One of the account's devices.
#[derive(uniffi::Record)]
pub struct AccountDevice {
    pub device_id: String,
    /// Empty for devices registered before devices had names.
    pub name: String,
    /// Seconds since the Unix epoch, when known.
    pub added_at: Option<i64>,
    /// The device this app runs on.
    pub current: bool,
}

/// An invite to join a server. `command` is the line to send to the new user.
#[derive(uniffi::Record)]
pub struct Invitation {
    pub server: String,
    pub token: String,
    pub owner_fingerprint: String,
    pub command: String,
}

impl From<InviteInfo> for Invitation {
    fn from(invite: InviteInfo) -> Self {
        Self {
            command: invite.command(),
            server: invite.server,
            token: invite.token,
            owner_fingerprint: invite.owner_fingerprint,
        }
    }
}

/// Someone on the server. Their fingerprint is left out on purpose: the owner approves
/// by typing in the one the user reads out, not by copying the server's.
#[derive(uniffi::Record)]
pub struct User {
    pub user_id: i64,
    pub name: String,
    /// The owner has checked their fingerprint and signed their keys.
    pub approved: bool,
    pub is_owner: bool,
}

#[derive(uniffi::Enum)]
pub enum PasswordChange {
    Saved {
        version: u64,
    },
    /// Someone saved a newer version first; the local copy now holds theirs.
    Conflict {
        version: u64,
        author: String,
    },
}

/// An item's searchable fields. The password stays encrypted until asked for.
#[derive(uniffi::Record)]
pub struct ItemSummary {
    pub id: String,
    pub folder: String,
    pub name: String,
    pub username: String,
    pub url: String,
}

#[derive(uniffi::Record)]
pub struct SyncResult {
    pub received: u32,
    /// Items ignored because no approved user signed them.
    pub rejected: u32,
}

/// An unlocked vault. Every method blocks on the network or disk, so call it off the
/// main thread.
#[derive(uniffi::Object)]
pub struct Vault {
    inner: Mutex<keystead_client::Vault>,
}

#[uniffi::export]
impl Vault {
    /// Claims a new server with the setup code it printed on first start. The caller
    /// becomes the owner.
    // Swift calls this with every argument labeled, so a long list reads fine there.
    #[allow(clippy::too_many_arguments)]
    #[uniffi::constructor]
    pub fn setup(
        profile_path: String,
        server: String,
        setup_code: String,
        name: String,
        account_secret: Vec<u8>,
        device_id: String,
        device_name: String,
        signer: Arc<dyn DeviceSigner>,
    ) -> Result<Arc<Self>, CoreError> {
        let secret = account_secret_from(account_secret)?;
        let vault = keystead_client::setup(
            Path::new(&profile_path),
            NewAccount {
                server: &server,
                secret: &secret,
                device_id: device_id_from(&device_id)?,
                device_name: &device_name,
                signer: Arc::new(SignerAdapter(signer)),
            },
            &setup_code,
            &name,
        )?;
        Ok(Arc::new(Self {
            inner: Mutex::new(vault),
        }))
    }

    /// Joins a server with an invite, checking the owner's fingerprint that came with it.
    /// Saves the profile at `profile_path` only if everything checks out.
    // Swift calls this with every argument labeled, so a long list reads fine there.
    #[allow(clippy::too_many_arguments)]
    #[uniffi::constructor]
    pub fn join(
        profile_path: String,
        server: String,
        token: String,
        owner_fingerprint: String,
        account_secret: Vec<u8>,
        device_id: String,
        device_name: String,
        signer: Arc<dyn DeviceSigner>,
    ) -> Result<Arc<Self>, CoreError> {
        let secret = account_secret_from(account_secret)?;
        let vault = keystead_client::join(
            Path::new(&profile_path),
            NewAccount {
                server: &server,
                secret: &secret,
                device_id: device_id_from(&device_id)?,
                device_name: &device_name,
                signer: Arc::new(SignerAdapter(signer)),
            },
            &token,
            &owner_fingerprint,
        )?;
        Ok(Arc::new(Self {
            inner: Mutex::new(vault),
        }))
    }

    /// Recovers an account onto this device with its secret, from a recovery kit's words
    /// (see `account_secret_from_recovery_words`). Checks the owner's fingerprint from the
    /// kit before registering anything. Sync afterwards to fetch folders and logins.
    #[uniffi::constructor]
    pub fn recover(
        profile_path: String,
        server: String,
        owner_fingerprint: String,
        account_secret: Vec<u8>,
        device_id: String,
        device_name: String,
        signer: Arc<dyn DeviceSigner>,
    ) -> Result<Arc<Self>, CoreError> {
        let secret = account_secret_from(account_secret)?;
        let vault = keystead_client::recover(
            Path::new(&profile_path),
            NewAccount {
                server: &server,
                secret: &secret,
                device_id: device_id_from(&device_id)?,
                device_name: &device_name,
                signer: Arc::new(SignerAdapter(signer)),
            },
            &owner_fingerprint,
        )?;
        Ok(Arc::new(Self {
            inner: Mutex::new(vault),
        }))
    }

    /// Unlocks an enrolled device's vault from its saved profile. Doesn't use the network.
    #[uniffi::constructor]
    pub fn open(
        profile_path: String,
        account_secret: Vec<u8>,
        signer: Arc<dyn DeviceSigner>,
    ) -> Result<Arc<Self>, CoreError> {
        let secret = account_secret_from(account_secret)?;
        let vault = keystead_client::Vault::open(
            Path::new(&profile_path),
            &secret,
            Arc::new(SignerAdapter(signer)),
        )?;
        Ok(Arc::new(Self {
            inner: Mutex::new(vault),
        }))
    }

    pub fn identity(&self) -> Result<Identity, CoreError> {
        let whoami = self.vault()?.whoami();
        Ok(Identity {
            name: whoami.name,
            user_id: whoami.user_id.0,
            fingerprint: whoami.fingerprint,
            server: whoami.server,
            is_owner: whoami.is_owner,
            owner_fingerprint: whoami.owner_fingerprint,
        })
    }

    /// The account's devices, from the server.
    pub fn devices(&self) -> Result<Vec<AccountDevice>, CoreError> {
        Ok(self
            .vault()?
            .devices()?
            .into_iter()
            .map(|device| AccountDevice {
                device_id: device.id.to_string(),
                name: device.name,
                added_at: device.added_at,
                current: device.current,
            })
            .collect())
    }

    /// Removes another of the account's devices, such as a lost Mac.
    pub fn remove_device(&self, device_id: String) -> Result<(), CoreError> {
        Ok(self.vault()?.remove_device(device_id_from(&device_id)?)?)
    }

    /// Fetches changes from the server and saves them.
    pub fn sync(&self) -> Result<SyncResult, CoreError> {
        let summary = self.vault()?.sync()?;
        Ok(SyncResult {
            received: summary.received.try_into().unwrap_or(u32::MAX),
            rejected: summary.rejected.try_into().unwrap_or(u32::MAX),
        })
    }

    /// Every login's searchable fields, from the local copy.
    pub fn items(&self) -> Result<Vec<ItemSummary>, CoreError> {
        Ok(self
            .vault()?
            .list()?
            .into_iter()
            .map(|row| ItemSummary {
                id: row.id.to_string(),
                folder: row.folder,
                name: row.name,
                username: row.username,
                url: row.url,
            })
            .collect())
    }

    /// Decrypts one login's password.
    pub fn password(&self, item_id: String) -> Result<String, CoreError> {
        let (_, details) = self.vault()?.open_item(item_id_from(&item_id)?)?;
        Ok(details.password.clone())
    }

    /// Saves a new password for a login, on top of the latest version this device has.
    pub fn change_password(
        &self,
        item_id: String,
        password: String,
    ) -> Result<PasswordChange, CoreError> {
        Ok(
            match self.vault()?.edit(item_id_from(&item_id)?, &password)? {
                EditOutcome::Saved { version } => PasswordChange::Saved { version },
                EditOutcome::Conflict { version, author } => {
                    PasswordChange::Conflict { version, author }
                }
            },
        )
    }

    /// Everyone on the server, fetched fresh.
    pub fn users(&self) -> Result<Vec<User>, CoreError> {
        Ok(self
            .vault()?
            .users()?
            .into_iter()
            .map(|user| User {
                user_id: user.user_id.0,
                name: user.name,
                approved: user.approved,
                is_owner: user.is_owner,
            })
            .collect())
    }

    /// Creates a single-use invite (owner only). `name` is how the new user will appear.
    pub fn invite(&self, name: String) -> Result<Invitation, CoreError> {
        Ok(self.vault()?.invite(&name)?.into())
    }

    /// Approves a user (owner only) if the fingerprint they read out matches their keys.
    /// Returns their name.
    pub fn approve(&self, user_id: i64, fingerprint: String) -> Result<String, CoreError> {
        Ok(self.vault()?.approve(UserId(user_id), &fingerprint)?)
    }

    pub fn create_folder(&self, name: String) -> Result<(), CoreError> {
        self.vault()?.create_folder(&name)?;
        Ok(())
    }

    /// Shares a folder with an approved user. Returns their name.
    pub fn share_folder(&self, folder: String, user_id: i64) -> Result<String, CoreError> {
        Ok(self.vault()?.share_folder(&folder, UserId(user_id))?)
    }

    pub fn folders(&self) -> Result<Vec<String>, CoreError> {
        Ok(self.vault()?.folders()?)
    }

    pub fn add_login(
        &self,
        folder: String,
        name: String,
        username: String,
        url: String,
        password: String,
    ) -> Result<(), CoreError> {
        let overview = Overview {
            name,
            username,
            url,
            tags: Vec::new(),
        };
        let details = Details {
            password,
            notes: String::new(),
        };
        self.vault()?.add(&folder, overview, details)?;
        Ok(())
    }
}

impl Vault {
    fn vault(&self) -> Result<MutexGuard<'_, keystead_client::Vault>, CoreError> {
        self.inner.lock().map_err(|_| CoreError::Failed {
            message: "the vault stopped working after an earlier error; lock and unlock again"
                .into(),
        })
    }
}

/// The version of the core this app was built with.
#[uniffi::export]
pub fn core_version() -> String {
    keystead_core::VERSION.to_owned()
}

/// A fresh random device id.
#[uniffi::export]
pub fn new_device_id() -> String {
    DeviceId::random().to_string()
}

/// A random 24-character password.
#[uniffi::export]
pub fn generate_password() -> String {
    keystead_client::generate_password()
}

/// The account secret as the 24 words of a recovery kit. The words are as secret as the
/// account itself: show them only for the user to write down or print.
#[uniffi::export]
pub fn recovery_words(account_secret: Vec<u8>) -> Result<String, CoreError> {
    Ok(account_secret_from(account_secret)?
        .recovery_words()
        .to_string())
}

/// Reads the 24 words of a recovery kit back into the account secret. Spacing, case and
/// numbering don't matter; a mistyped word is reported.
#[uniffi::export]
pub fn account_secret_from_recovery_words(words: String) -> Result<Vec<u8>, CoreError> {
    let secret =
        keystead_core::keys::AccountSecret::from_recovery_words(&words).map_err(|error| {
            CoreError::InvalidInput {
                message: error.to_string(),
            }
        })?;
    Ok(secret.as_bytes().to_vec())
}

/// Reads an invite pasted from a message.
#[uniffi::export]
pub fn parse_invite(text: String) -> Result<Invitation, CoreError> {
    InviteInfo::parse(&text)
        .map(Invitation::from)
        .map_err(|error| CoreError::InvalidInput {
            message: format!("{error:#}"),
        })
}

fn account_secret_from(bytes: Vec<u8>) -> Result<AccountSecret, CoreError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid("an account secret is 32 bytes"))?;
    Ok(AccountSecret::from_bytes(bytes))
}

fn device_id_from(text: &str) -> Result<DeviceId, CoreError> {
    text.parse()
        .map_err(|_| invalid("the device id isn't a UUID"))
}

fn item_id_from(text: &str) -> Result<ItemId, CoreError> {
    text.parse()
        .map_err(|_| invalid("the item id isn't a UUID"))
}

fn invalid(message: &str) -> CoreError {
    CoreError::InvalidInput {
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_input_is_rejected_before_anything_runs() {
        assert!(matches!(
            account_secret_from(vec![1, 2, 3]),
            Err(CoreError::InvalidInput { .. })
        ));
        assert!(new_device_id().parse::<DeviceId>().is_ok());
        assert_eq!(generate_password().chars().count(), 24);
        assert!(matches!(
            parse_invite("keystead join nowhere".into()),
            Err(CoreError::InvalidInput { .. })
        ));
        let invite =
            parse_invite("keystead join https://k.example tok --owner ab12".into()).unwrap();
        assert_eq!(
            invite.command,
            "keystead join https://k.example tok --owner ab12"
        );
    }
}
