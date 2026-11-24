//! The Keystead client, exposed to Swift. UniFFI generates the Swift side from the
//! `#[uniffi::export]` items here; `apps/macos/scripts/build-core.sh` runs the generator.
//!
//! Keep this layer thin: it converts types and errors, and the logic stays in
//! `keystead-client` and `keystead-core`. The account keys live inside [`Vault`] and never
//! cross into Swift; only what the user asks to see does.

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use keystead_client::{EditOutcome, GroupShareRow, InviteInfo, MemberRow, NewAccount, SyncSummary};
use keystead_core::api::Role as CoreRole;
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
    /// The owner removed them from the team.
    pub removed: bool,
}

/// What someone may do with a folder or a login.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Open and copy.
    View,
    /// Also change and delete logins.
    Edit,
    /// Also share, change roles and remove people.
    Manage,
}

impl From<CoreRole> for Role {
    fn from(role: CoreRole) -> Self {
        match role {
            CoreRole::View => Self::View,
            CoreRole::Edit => Self::Edit,
            CoreRole::Manage => Self::Manage,
        }
    }
}

impl From<Role> for CoreRole {
    fn from(role: Role) -> Self {
        match role {
            Role::View => Self::View,
            Role::Edit => Self::Edit,
            Role::Manage => Self::Manage,
        }
    }
}

/// Someone who can open a folder or a login, and their role.
#[derive(uniffi::Record)]
pub struct Person {
    pub user_id: i64,
    pub name: String,
    pub role: Role,
    pub is_me: bool,
}

impl From<MemberRow> for Person {
    fn from(row: MemberRow) -> Self {
        Self {
            user_id: row.user_id.0,
            name: row.name,
            role: row.role.into(),
            is_me: row.me,
        }
    }
}

/// A group that can open a folder or a login, and its role there.
#[derive(uniffi::Record)]
pub struct GroupShare {
    pub group_id: String,
    pub name: String,
    pub role: Role,
    /// You're in the group.
    pub is_mine: bool,
}

impl From<GroupShareRow> for GroupShare {
    fn from(row: GroupShareRow) -> Self {
        Self {
            group_id: row.group_id.to_string(),
            name: row.name,
            role: row.role.into(),
            is_mine: row.mine,
        }
    }
}

/// Everyone who can open a folder or a login directly, and the groups it's shared with.
#[derive(uniffi::Record)]
pub struct Sharing {
    pub people: Vec<Person>,
    pub groups: Vec<GroupShare>,
}

/// Someone in a group.
#[derive(uniffi::Record)]
pub struct GroupMember {
    pub user_id: i64,
    pub name: String,
    pub is_manager: bool,
    pub is_me: bool,
}

/// A group on the team, and what you can do with it.
#[derive(uniffi::Record)]
pub struct GroupSummary {
    pub id: String,
    pub name: String,
    /// Managers first, then by name.
    pub members: Vec<GroupMember>,
    /// You're in it.
    pub is_member: bool,
    /// You can rename it, change its managers and remove people: you're the owner, or a
    /// manager in it.
    pub can_manage: bool,
    /// You can add people: you can manage it and you're in it.
    pub can_add: bool,
}

/// A folder and your role in it.
#[derive(uniffi::Record)]
pub struct FolderSummary {
    pub name: String,
    pub role: Role,
}

/// How saving a change to a login went: changing it, or deleting it.
#[derive(uniffi::Enum)]
pub enum SaveOutcome {
    Saved {
        version: u64,
    },
    /// Someone saved a newer version first, so nothing changed; the local copy now holds
    /// theirs.
    Conflict {
        version: u64,
        author: String,
    },
}

impl From<EditOutcome> for SaveOutcome {
    fn from(outcome: EditOutcome) -> Self {
        match outcome {
            EditOutcome::Saved { version } => Self::Saved { version },
            EditOutcome::Conflict { version, author } => Self::Conflict { version, author },
        }
    }
}

/// A login's secret fields, decrypted when asked for.
#[derive(uniffi::Record)]
pub struct LoginDetails {
    pub password: String,
    pub notes: String,
    /// The otpauth:// link one-time codes come from, or empty.
    pub one_time_code: String,
}

/// The fields of a login the app edits, for adding or saving one.
#[derive(uniffi::Record)]
pub struct LoginFields {
    pub name: String,
    pub username: String,
    pub url: String,
    pub password: String,
    pub notes: String,
    /// An otpauth:// link or a site's setup key for one-time codes, or empty for none.
    pub one_time_code: String,
}

/// One version of a login in its history.
#[derive(uniffi::Record)]
pub struct HistoryEntry {
    pub version: u64,
    pub author: String,
    /// When it was saved, in seconds since 1970 (UTC); unknown before 0.7.0.
    pub saved_at: Option<i64>,
    /// The login as it is now.
    pub current: bool,
    /// You can open it; versions from before a login was shared with you directly can't be.
    pub readable: bool,
    /// What it changed from the version before: "name", "username", "website", "password",
    /// "notes", "one-time code", or "created".
    pub changes: Vec<String>,
}

/// A login's current one-time code.
#[derive(uniffi::Record)]
pub struct OneTimeCode {
    pub code: String,
    /// Seconds each code lasts, usually 30.
    pub period: u64,
    /// Seconds this one has left.
    pub remaining: u64,
}

/// An item's searchable fields, and who it's shared with. The password stays encrypted
/// until asked for.
#[derive(uniffi::Record)]
pub struct ItemSummary {
    pub id: String,
    /// Its folder, if it's in one of yours. Without one, it's yours alone or was shared
    /// with you directly.
    pub folder: Option<String>,
    pub name: String,
    pub username: String,
    pub url: String,
    /// Whose it is, for a login outside folders that isn't yours.
    pub owner: Option<String>,
    /// Everyone it's shared with directly, except you.
    pub shared_with: Vec<String>,
    /// The groups it's shared with directly.
    pub shared_with_groups: Vec<String>,
    /// You can open it only because it was shared with you, or a group you're in, directly.
    pub shared_with_me: bool,
    /// What you may do with it.
    pub role: Role,
    /// It has one-time codes.
    pub has_one_time_code: bool,
}

/// A password to change: someone lost access to a login while its password stayed the
/// same, so they may still know it.
#[derive(uniffi::Record)]
pub struct ToChange {
    pub item_id: String,
    pub name: String,
    /// The login's folder, if it's in one of yours.
    pub folder: Option<String>,
    /// Who lost access.
    pub user_id: i64,
    pub user_name: String,
    /// When they lost access, in seconds since 1970 (UTC).
    pub since: i64,
}

#[derive(uniffi::Record)]
pub struct SyncResult {
    pub received: u32,
    /// Items ignored because no approved user signed them.
    pub rejected: u32,
    /// Why a folder or group you manage didn't get the new key it needs; the next sync
    /// retries.
    pub rekey_problems: Vec<String>,
}

impl From<SyncSummary> for SyncResult {
    fn from(summary: SyncSummary) -> Self {
        Self {
            received: summary.received.try_into().unwrap_or(u32::MAX),
            rejected: summary.rejected.try_into().unwrap_or(u32::MAX),
            rekey_problems: summary.rekey_problems,
        }
    }
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
    /// kit before registering anything; the owner can pass none, and their own keys are
    /// checked instead. Sync afterwards to fetch folders and logins.
    #[uniffi::constructor]
    pub fn recover(
        profile_path: String,
        server: String,
        owner_fingerprint: Option<String>,
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
            owner_fingerprint.as_deref(),
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
    /// Signs this device out: the server forgets it and the profile is deleted. Delete the
    /// device's own keys afterwards, and drop this vault. Returns why the server couldn't be
    /// told, if it couldn't; the device then stays listed until it's removed from another
    /// one.
    pub fn sign_out(&self) -> Result<Option<String>, CoreError> {
        Ok(self.vault()?.sign_out()?)
    }

    pub fn remove_device(&self, device_id: String) -> Result<(), CoreError> {
        Ok(self.vault()?.remove_device(device_id_from(&device_id)?)?)
    }

    /// Starts adding another device to this account; returns the setup line to copy to it.
    /// It expires after ten minutes.
    pub fn start_adding_device(&self) -> Result<String, CoreError> {
        Ok(self.vault()?.start_adding_device()?.command())
    }

    /// The new device's name, once it has joined with the setup line.
    pub fn new_device(&self) -> Result<Option<String>, CoreError> {
        Ok(self.vault()?.new_device()?)
    }

    /// Sends this account's secret to the new device, sealed for it, if `code` is the one
    /// it shows. Returns its name.
    pub fn send_account_to_new_device(
        &self,
        code: String,
        account_secret: Vec<u8>,
    ) -> Result<String, CoreError> {
        let secret = account_secret_from(account_secret)?;
        Ok(self.vault()?.send_account_to_new_device(&code, &secret)?)
    }

    /// Stops adding a device; the setup line stops working.
    pub fn cancel_adding_device(&self) -> Result<(), CoreError> {
        self.vault()?.cancel_adding_device();
        Ok(())
    }

    /// Fetches changes from the server and saves them.
    pub fn sync(&self) -> Result<SyncResult, CoreError> {
        Ok(self.vault()?.sync()?.into())
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
                owner: row.owner,
                shared_with: row.shared_with,
                shared_with_groups: row.shared_with_groups,
                shared_with_me: row.shared_with_me,
                role: row.role.into(),
                has_one_time_code: row.has_one_time_code,
            })
            .collect())
    }

    /// How many logins a newer Keystead wrote, in a format this build can't open; `items`
    /// leaves them out.
    pub fn too_new(&self) -> Result<u32, CoreError> {
        Ok(u32::try_from(self.vault()?.too_new()).unwrap_or(u32::MAX))
    }

    /// A login's current one-time code, if it has one-time codes.
    pub fn one_time_code(&self, item_id: String) -> Result<Option<OneTimeCode>, CoreError> {
        Ok(self
            .vault()?
            .one_time_code(item_id_from(&item_id)?)?
            .map(|code| OneTimeCode {
                code: code.code.clone(),
                period: code.period,
                remaining: code.remaining,
            }))
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
    ) -> Result<SaveOutcome, CoreError> {
        Ok(self
            .vault()?
            .edit(item_id_from(&item_id)?, &password)?
            .into())
    }

    /// Decrypts one login's password and notes, for showing or editing them.
    pub fn details(&self, item_id: String) -> Result<LoginDetails, CoreError> {
        let (_, details) = self.vault()?.open_item(item_id_from(&item_id)?)?;
        Ok(LoginDetails {
            password: details.password.clone(),
            notes: details.notes.clone(),
            one_time_code: details.otp.clone(),
        })
    }

    /// Saves all of a login's fields at once, on top of the latest version this device has.
    /// Its folder and who can open it stay as they are.
    pub fn update_login(
        &self,
        item_id: String,
        fields: LoginFields,
    ) -> Result<SaveOutcome, CoreError> {
        let item_id = item_id_from(&item_id)?;
        let mut vault = self.vault()?;
        // Start from the current version, so fields the app doesn't edit, like tags, stay.
        let (mut overview, mut details) = vault.open_item(item_id)?;
        overview.name = fields.name;
        overview.username = fields.username;
        overview.url = fields.url;
        details.password = fields.password;
        details.notes = fields.notes;
        details.otp = fields.one_time_code;
        Ok(vault.update(item_id, &overview, &details)?.into())
    }

    /// A login's history, newest first, fetched fresh (editors and managers).
    pub fn history(&self, item_id: String) -> Result<Vec<HistoryEntry>, CoreError> {
        Ok(self
            .vault()?
            .history(item_id_from(&item_id)?)?
            .into_iter()
            .map(|row| HistoryEntry {
                version: row.version,
                author: row.author,
                saved_at: row.saved_at,
                current: row.current,
                readable: row.readable,
                changes: row.changes,
            })
            .collect())
    }

    /// The password of a version from the history last fetched.
    pub fn history_password(&self, item_id: String, version: u64) -> Result<String, CoreError> {
        let (_, details) = self
            .vault()?
            .history_version(item_id_from(&item_id)?, version)?;
        Ok(details.password.clone())
    }

    /// Brings back a version from the history last fetched, as a new version.
    pub fn restore_version(&self, item_id: String, version: u64) -> Result<SaveOutcome, CoreError> {
        Ok(self
            .vault()?
            .restore(item_id_from(&item_id)?, version)?
            .into())
    }

    /// Deletes a login for everyone who can open it.
    pub fn delete_login(&self, item_id: String) -> Result<SaveOutcome, CoreError> {
        Ok(self.vault()?.delete(item_id_from(&item_id)?)?.into())
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
                removed: user.removed,
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
    /// Shares a folder with an approved user (managers). Returns their name.
    pub fn share_folder(
        &self,
        folder: String,
        user_id: i64,
        role: Role,
    ) -> Result<String, CoreError> {
        Ok(self
            .vault()?
            .share_folder(&folder, UserId(user_id), role.into())?)
    }

    pub fn folders(&self) -> Result<Vec<String>, CoreError> {
        Ok(self.vault()?.folders()?)
    }

    /// Your folders with your role in each, from the local copy.
    pub fn folder_summaries(&self) -> Result<Vec<FolderSummary>, CoreError> {
        Ok(self
            .vault()?
            .folder_roles()?
            .into_iter()
            .map(|(name, role)| FolderSummary {
                name,
                role: role.into(),
            })
            .collect())
    }

    /// Everyone in a folder, with their roles.
    pub fn folder_members(&self, folder: String) -> Result<Vec<Person>, CoreError> {
        Ok(self
            .vault()?
            .folder_members(&folder)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Changes someone's role in a folder (managers).
    pub fn set_folder_role(
        &self,
        folder: String,
        user_id: i64,
        role: Role,
    ) -> Result<(), CoreError> {
        Ok(self
            .vault()?
            .set_folder_role(&folder, UserId(user_id), role.into())?)
    }

    /// Takes someone out of a folder, or you, to leave it. Someone else's removal also
    /// gives the folder a new key.
    pub fn remove_from_folder(&self, folder: String, user_id: i64) -> Result<(), CoreError> {
        Ok(self.vault()?.remove_from_folder(&folder, UserId(user_id))?)
    }

    /// Removes someone from the team (owner only). Returns their name.
    pub fn remove_user(&self, user_id: i64) -> Result<String, CoreError> {
        Ok(self.vault()?.remove_user(UserId(user_id))?)
    }

    /// Passwords to change, from the last sync, most recent first: logins you can change
    /// that someone could open before losing access. Saving a new password, or deleting
    /// the login, takes it off.
    pub fn to_change(&self) -> Result<Vec<ToChange>, CoreError> {
        Ok(self
            .vault()?
            .to_change()?
            .into_iter()
            .map(|row| ToChange {
                item_id: row.item_id.to_string(),
                name: row.name,
                folder: row.folder,
                user_id: row.user_id.0,
                user_name: row.user_name,
                since: row.since,
            })
            .collect())
    }

    /// Takes a login off the list for one person, without changing its password.
    pub fn dismiss_to_change(&self, item_id: String, user_id: i64) -> Result<(), CoreError> {
        Ok(self
            .vault()?
            .dismiss(item_id_from(&item_id)?, UserId(user_id))?)
    }

    /// Takes everything one person could see off the list. Returns how many.
    pub fn dismiss_all_to_change(&self, user_id: i64) -> Result<u32, CoreError> {
        let count = self.vault()?.dismiss_all(UserId(user_id))?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    /// Adds a login to a folder, or with no folder as yours alone until you share it.
    pub fn add_login(&self, folder: Option<String>, fields: LoginFields) -> Result<(), CoreError> {
        let overview = Overview {
            name: fields.name,
            username: fields.username,
            url: fields.url,
            ..Overview::default()
        };
        let details = Details {
            password: fields.password,
            notes: fields.notes,
            otp: fields.one_time_code,
        };
        self.vault()?.add(folder.as_deref(), overview, details)?;
        Ok(())
    }

    /// Shares one login with an approved user, without the rest of its folder. Returns
    /// their name.
    pub fn share_login(
        &self,
        item_id: String,
        user_id: i64,
        role: Role,
    ) -> Result<String, CoreError> {
        Ok(self
            .vault()?
            .share_item(item_id_from(&item_id)?, UserId(user_id), role.into())?)
    }

    /// Who has a login directly: whoever made it and everyone it's shared with, with roles.
    pub fn login_people(&self, item_id: String) -> Result<Vec<Person>, CoreError> {
        Ok(self
            .vault()?
            .item_people(item_id_from(&item_id)?)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Changes the role of someone a login is shared with directly (managers).
    pub fn set_login_role(
        &self,
        item_id: String,
        user_id: i64,
        role: Role,
    ) -> Result<(), CoreError> {
        Ok(self
            .vault()?
            .set_item_role(item_id_from(&item_id)?, UserId(user_id), role.into())?)
    }

    /// Takes away someone's copy of a login (managers). Returns their name.
    pub fn unshare_login(&self, item_id: String, user_id: i64) -> Result<String, CoreError> {
        Ok(self
            .vault()?
            .unshare_item(item_id_from(&item_id)?, UserId(user_id))?)
    }

    // Groups

    /// Every group on the team, from the local copy.
    pub fn groups(&self) -> Result<Vec<GroupSummary>, CoreError> {
        Ok(self
            .vault()?
            .groups()
            .into_iter()
            .map(|group| GroupSummary {
                id: group.id.to_string(),
                name: group.name,
                members: group
                    .members
                    .into_iter()
                    .map(|member| GroupMember {
                        user_id: member.user_id.0,
                        name: member.name,
                        is_manager: member.manager,
                        is_me: member.me,
                    })
                    .collect(),
                is_member: group.member,
                can_manage: group.can_manage,
                can_add: group.can_add,
            })
            .collect())
    }

    /// Makes a group (owner only) with you and these people in it, and you as its manager.
    pub fn create_group(&self, name: String, member_ids: Vec<i64>) -> Result<(), CoreError> {
        let members: Vec<UserId> = member_ids.into_iter().map(UserId).collect();
        self.vault()?.create_group(&name, &members)?;
        Ok(())
    }

    /// Adds someone to a group (its managers in it). Returns their name.
    pub fn add_to_group(&self, group: String, user_id: i64) -> Result<String, CoreError> {
        Ok(self.vault()?.add_to_group(&group, UserId(user_id))?)
    }

    /// Takes someone out of a group, or you, to leave it. The group, and folders shared
    /// with it, then get new keys.
    pub fn remove_from_group(&self, group: String, user_id: i64) -> Result<SyncResult, CoreError> {
        Ok(self
            .vault()?
            .remove_from_group(&group, UserId(user_id))?
            .into())
    }

    pub fn rename_group(&self, group: String, name: String) -> Result<(), CoreError> {
        Ok(self.vault()?.rename_group(&group, &name)?)
    }

    /// Makes someone in a group one of its managers, or not.
    pub fn set_group_manager(
        &self,
        group: String,
        user_id: i64,
        manager: bool,
    ) -> Result<(), CoreError> {
        Ok(self
            .vault()?
            .set_group_manager(&group, UserId(user_id), manager)?)
    }

    /// Everyone in a folder and every group it's shared with, with their roles.
    pub fn folder_sharing(&self, folder: String) -> Result<Sharing, CoreError> {
        let (people, groups) = self.vault()?.folder_sharing(&folder)?;
        Ok(Sharing {
            people: people.into_iter().map(Into::into).collect(),
            groups: groups.into_iter().map(Into::into).collect(),
        })
    }

    /// Shares a folder with a group (managers). Returns the group's name.
    pub fn share_folder_with_group(
        &self,
        folder: String,
        group: String,
        role: Role,
    ) -> Result<String, CoreError> {
        Ok(self
            .vault()?
            .share_folder_with_group(&folder, &group, role.into())?)
    }

    pub fn set_folder_group_role(
        &self,
        folder: String,
        group: String,
        role: Role,
    ) -> Result<(), CoreError> {
        Ok(self
            .vault()?
            .set_folder_group_role(&folder, &group, role.into())?)
    }

    /// Stops sharing a folder with a group (managers); the folder then gets a new key.
    pub fn remove_group_from_folder(
        &self,
        folder: String,
        group: String,
    ) -> Result<SyncResult, CoreError> {
        Ok(self
            .vault()?
            .remove_group_from_folder(&folder, &group)?
            .into())
    }

    /// Who has a login directly, and the groups it's shared with, with roles.
    pub fn login_sharing(&self, item_id: String) -> Result<Sharing, CoreError> {
        let (people, groups) = self.vault()?.item_sharing(item_id_from(&item_id)?)?;
        Ok(Sharing {
            people: people.into_iter().map(Into::into).collect(),
            groups: groups.into_iter().map(Into::into).collect(),
        })
    }

    /// Shares one login with a group. Returns the group's name.
    pub fn share_login_with_group(
        &self,
        item_id: String,
        group: String,
        role: Role,
    ) -> Result<String, CoreError> {
        Ok(self
            .vault()?
            .share_item_with_group(item_id_from(&item_id)?, &group, role.into())?)
    }

    pub fn set_login_group_role(
        &self,
        item_id: String,
        group: String,
        role: Role,
    ) -> Result<(), CoreError> {
        Ok(self
            .vault()?
            .set_item_group_role(item_id_from(&item_id)?, &group, role.into())?)
    }

    /// Takes a group's copy of a login away (managers). Returns the group's name.
    pub fn unshare_login_group(&self, item_id: String, group: String) -> Result<String, CoreError> {
        Ok(self
            .vault()?
            .unshare_item_group(item_id_from(&item_id)?, &group)?)
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

/// Checks a one-time code setup someone pasted or scanned (an otpauth:// link, or a site's
/// setup key) and says who it's for, like "GitHub (octocat)"; empty if it doesn't say.
#[uniffi::export]
pub fn describe_one_time_code(text: String) -> Result<String, CoreError> {
    let link = keystead_core::otp::normalize(&text).map_err(anyhow::Error::from)?;
    Ok(keystead_core::otp::label(&link).map_err(anyhow::Error::from)?)
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

/// This Mac joining its account from a device the account already has: it has sent its
/// one-time key with the setup line, shows the code to type there, and waits for the
/// account secret. Then `Vault::recover`, with the line's server and owner fingerprint,
/// finishes.
#[derive(uniffi::Object)]
pub struct DeviceJoin {
    inner: keystead_client::JoiningDevice,
}

#[uniffi::export]
impl DeviceJoin {
    /// Joins with a setup line pasted from the other device.
    #[uniffi::constructor]
    pub fn start(line: String, device_name: String) -> Result<Arc<Self>, CoreError> {
        let line = keystead_client::DeviceSetupLine::parse(&line).map_err(|error| {
            CoreError::InvalidInput {
                message: format!("{error:#}"),
            }
        })?;
        Ok(Arc::new(Self {
            inner: keystead_client::JoiningDevice::start(line, &device_name)?,
        }))
    }

    /// The code to type on the other device.
    pub fn code(&self) -> String {
        self.inner.code().to_owned()
    }

    pub fn server(&self) -> String {
        self.inner.line().server.clone()
    }

    pub fn owner_fingerprint(&self) -> String {
        self.inner.line().owner_fingerprint.clone()
    }

    /// Asks once for the account secret; empty until the other device sends it.
    pub fn poll(&self) -> Result<Option<Vec<u8>>, CoreError> {
        Ok(self.inner.poll()?.map(|secret| secret.as_bytes().to_vec()))
    }
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
