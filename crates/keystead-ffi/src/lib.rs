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
    /// The owner keeps this account's personal key in escrow, to recover its own logins and
    /// the folders only it is in.
    pub escrow: bool,
    /// The owner has started a recovery for this account; cancel it if it wasn't asked for.
    pub recovering: bool,
    /// False for a server at an http:// address on another machine, which Macs added before
    /// 0.18.0 could use: anyone on the network could read and change what goes to it.
    pub private_connection: bool,
}

/// A recovery the owner started, waiting for approval.
#[derive(uniffi::Record)]
pub struct PendingRecovery {
    /// The person has used the line on their new device. Its fingerprint isn't here: the
    /// owner hears it from them, and approving checks it.
    pub claimed: bool,
    /// Their own logins and folders come back too: their personal key is in escrow.
    pub escrow: bool,
}

/// A recovery the owner approved.
#[derive(uniffi::Record)]
pub struct RecoveryApproval {
    pub name: String,
    /// Their own logins and folders come back: their personal key was in escrow.
    pub own_logins: bool,
}

/// A line from the owner for recovering with their help.
#[derive(uniffi::Record)]
pub struct RecoveryLineInfo {
    pub server: String,
    pub owner_fingerprint: String,
}

/// Whose account a recovery line is for, and the new keys' fingerprint to read to the
/// owner.
#[derive(uniffi::Record)]
pub struct RecoveryClaimInfo {
    pub user_id: i64,
    pub name: String,
    pub fingerprint: String,
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
    /// The invite's key: joining with it, the new person is approved by the owner's app on
    /// its own. None from a server older than 0.18.0, or from a line without one.
    pub key: Option<String>,
    pub command: String,
    /// When it stops working; none from a server older than 0.16.0, whose invites work
    /// until used, and none for an invite read from its line.
    pub expires_at: Option<i64>,
}

/// An invite nobody has used yet, as the owner sees it. The line itself isn't kept.
#[derive(uniffi::Record)]
pub struct PendingInvitation {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
    pub expires_at: i64,
}

impl From<InviteInfo> for Invitation {
    fn from(invite: InviteInfo) -> Self {
        Self {
            command: invite.command(),
            server: invite.server,
            token: invite.token,
            owner_fingerprint: invite.owner_fingerprint,
            key: invite.key,
            expires_at: invite.expires_at,
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
    /// They let the owner recover their own logins and folders (escrow).
    pub escrow: bool,
    /// The owner has started a recovery for them that isn't approved yet.
    pub recovering: bool,
    /// Their keys were replaced after recovering with the owner's help.
    pub keys_replaced: bool,
    /// For the owner: they joined with an invite's key, but it doesn't prove the keys the
    /// server lists for them. Approve them only if the fingerprint they read out matches.
    pub invite_mismatch: bool,
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

/// A login deleted in the last 30 days, which can still be brought back.
#[derive(uniffi::Record)]
pub struct DeletedLogin {
    pub item_id: String,
    pub name: String,
    pub username: String,
    /// Its folder, if it's in one of yours.
    pub folder: Option<String>,
    pub deleted_by: String,
    /// When it was deleted, and until when it can be brought back, in seconds since 1970.
    pub deleted_at: i64,
    pub kept_until: i64,
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

/// A folder made inside another.
#[derive(uniffi::Record)]
pub struct FolderCreated {
    /// Its full name, "Parent / Name".
    pub name: String,
    /// Who it was shared with, like its parent; groups are marked "(group)".
    pub shared_with: Vec<String>,
    /// Anyone it couldn't be shared with, and why.
    pub problems: Vec<String>,
}

/// Logins written to a KeePass file, for the app to save.
#[derive(uniffi::Record)]
pub struct ExportedFile {
    /// The file, encrypted with the passphrase chosen.
    pub data: Vec<u8>,
    pub logins: u32,
    /// Logins left out: ones a newer Keystead saved, or that didn't open.
    pub left_out: u32,
}

/// A folder renamed, with the folders inside it.
#[derive(uniffi::Record)]
pub struct FolderRenamed {
    pub name: String,
    /// Folders inside it that kept their names: you don't manage them.
    pub kept: Vec<String>,
    /// Folders inside it that couldn't be renamed, and why.
    pub problems: Vec<String>,
}

/// What deleting a folder deletes, to ask about first.
#[derive(uniffi::Record)]
pub struct FolderDeletion {
    /// Logins in it, deleted with it for good.
    pub logins: u64,
    /// How many of their passwords are on To Change, which deleting forgets.
    pub to_change: u64,
    /// Folders inside it, which stay.
    pub inside: Vec<String>,
}

/// A folder an import puts logins into, or leaves out.
#[derive(uniffi::Record)]
pub struct ImportFolderSummary {
    pub name: String,
    /// It doesn't exist yet and will be created, for you only.
    pub new: bool,
    pub logins: u32,
}

/// What an import would do.
#[derive(uniffi::Record)]
pub struct ImportPreview {
    pub folders: Vec<ImportFolderSummary>,
    /// Logins that stay your own, in no folder.
    pub own: u32,
    /// Logins already here, left out.
    pub duplicates: u32,
    /// Folders you can only view, whose logins are left out.
    pub view_only: Vec<ImportFolderSummary>,
    pub one_time_codes: u32,
}

/// What an import did.
#[derive(uniffi::Record)]
pub struct ImportResult {
    pub added: u32,
    pub folders_created: u32,
    pub duplicates: u32,
    pub left_out: u32,
}

/// Logins read from an export file (a Passbolt export, or a KeePass or KeePassXC file),
/// held in memory until imported; nothing is saved by reading.
#[derive(uniffi::Object)]
pub struct LoginExport {
    logins: Vec<keystead_client::ImportedLogin>,
}

#[uniffi::export]
impl LoginExport {
    /// Reads a .kdbx file with the passphrase it was exported with.
    #[uniffi::constructor]
    pub fn read(file: Vec<u8>, passphrase: String) -> Result<Arc<Self>, CoreError> {
        let logins = keystead_client::read_kdbx(&file, &passphrase).map_err(|error| {
            CoreError::InvalidInput {
                message: format!("{error:#}"),
            }
        })?;
        Ok(Arc::new(Self { logins }))
    }

    pub fn count(&self) -> u32 {
        count(self.logins.len())
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
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

impl From<keystead_client::UserRow> for User {
    fn from(user: keystead_client::UserRow) -> Self {
        User {
            user_id: user.user_id.0,
            name: user.name,
            approved: user.approved,
            is_owner: user.is_owner,
            removed: user.removed,
            escrow: user.escrow,
            recovering: user.recovering,
            keys_replaced: user.keys_replaced,
            invite_mismatch: user.invite_mismatch,
        }
    }
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

/// A login you can change whose password needs attention.
#[derive(uniffi::Record)]
pub struct HealthLogin {
    pub item_id: String,
    pub name: String,
    pub username: String,
    /// The login's folder, if it's in one of yours.
    pub folder: Option<String>,
    /// Easy to guess.
    pub weak: bool,
    /// The other logins you can open that have the same password, by name.
    pub reused_with: Vec<String>,
    /// When the password was set, if over a year ago, in seconds since 1970 (UTC).
    pub old_since: Option<i64>,
}

/// What a password health check found.
#[derive(uniffi::Record)]
pub struct PasswordHealth {
    /// Logins that need attention, those with most problems first.
    pub logins: Vec<HealthLogin>,
    /// How many logins with a password you can change were checked.
    pub checked: u32,
    /// The server says when passwords were set (0.13.0 and later), so old ones can show.
    pub ages_known: bool,
}

#[derive(uniffi::Record)]
pub struct SyncResult {
    pub received: u32,
    /// Items ignored because no approved user signed them.
    pub rejected: u32,
    /// Why a folder or group you manage didn't get the new key it needs; the next sync
    /// retries.
    pub rekey_problems: Vec<String>,
    /// Logins, folders and groups the server sent older than this Mac had already seen;
    /// it kept its own.
    pub older: u32,
    /// The server's change numbers went back, as when it's restored from a backup.
    pub server_went_back: bool,
    /// People the owner's app approved because they joined with an invite's key.
    pub approved: Vec<String>,
}

impl From<SyncSummary> for SyncResult {
    fn from(summary: SyncSummary) -> Self {
        Self {
            received: summary.received.try_into().unwrap_or(u32::MAX),
            rejected: summary.rejected.try_into().unwrap_or(u32::MAX),
            rekey_problems: summary.rekey_problems,
            older: summary.older.try_into().unwrap_or(u32::MAX),
            server_went_back: summary.server_went_back,
            approved: summary.approved,
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
    /// Saves the profile at `profile_path` only if everything checks out. With the
    /// invite's `key`, the owner's app approves the new account on its own.
    // Swift calls this with every argument labeled, so a long list reads fine there.
    #[allow(clippy::too_many_arguments)]
    #[uniffi::constructor]
    pub fn join(
        profile_path: String,
        server: String,
        token: String,
        owner_fingerprint: String,
        key: Option<String>,
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
            key.as_deref(),
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

    /// Finishes recovering with the owner's help once they approved the new keys (see
    /// `claim_recovery`): signs in and saves the profile, after checking the owner against
    /// the line. Sync afterwards to fetch folders and logins.
    #[uniffi::constructor]
    pub fn finish_recovery(
        profile_path: String,
        line: String,
        account_secret: Vec<u8>,
        device_id: String,
        device_name: String,
        signer: Arc<dyn DeviceSigner>,
    ) -> Result<Arc<Self>, CoreError> {
        let line = recovery_line(&line)?;
        let secret = account_secret_from(account_secret)?;
        let vault = keystead_client::finish_recovery(
            Path::new(&profile_path),
            NewAccount {
                server: &line.server,
                secret: &secret,
                device_id: device_id_from(&device_id)?,
                device_name: &device_name,
                signer: Arc::new(SignerAdapter(signer)),
            },
            &line,
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

    /// Whether the server renews sessions without the device key (0.14.0 and later), as far
    /// as this session has seen; if not, signing in with the key comes every 15 minutes.
    pub fn server_renews_sessions(&self) -> Result<bool, CoreError> {
        Ok(self.vault()?.server_renews_sessions())
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
            escrow: whoami.escrow,
            recovering: whoami.recovering,
            private_connection: whoami.private_connection,
        })
    }

    /// Starts a recovery with the owner's help for someone who lost every device and their
    /// recovery kit (owner only). Returns the line to send them.
    pub fn start_recovery(
        &self,
        user_id: i64,
        sign_out_devices: bool,
    ) -> Result<String, CoreError> {
        Ok(self
            .vault()?
            .start_recovery(UserId(user_id), sign_out_devices)?
            .command())
    }

    /// Someone's recovery waiting for approval, if any (owner only).
    pub fn recovery_request(&self, user_id: i64) -> Result<Option<PendingRecovery>, CoreError> {
        Ok(self
            .vault()?
            .recovery_request(UserId(user_id))?
            .map(|request| PendingRecovery {
                claimed: request.claimed,
                escrow: request.escrow,
            }))
    }

    /// Approves someone's new keys after they read out the fingerprint (owner only).
    pub fn approve_recovery(
        &self,
        user_id: i64,
        fingerprint: String,
    ) -> Result<RecoveryApproval, CoreError> {
        let approved = self
            .vault()?
            .approve_recovery(UserId(user_id), &fingerprint)?;
        Ok(RecoveryApproval {
            name: approved.name,
            own_logins: approved.own_logins,
        })
    }

    /// Cancels a recovery that isn't approved yet: the owner, anyone's; anyone, their own.
    pub fn cancel_recovery(&self, user_id: i64) -> Result<(), CoreError> {
        Ok(self.vault()?.cancel_recovery(UserId(user_id))?)
    }

    /// Lets the owner recover this account's own logins and the folders only it is in
    /// (escrow), or stops it. Turning it on syncs, to put those folders in escrow.
    pub fn set_escrow(&self, on: bool) -> Result<(), CoreError> {
        Ok(self.vault()?.set_escrow(on)?)
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

    /// Fetches changes from the server and saves them. The vault is free while it waits
    /// on the server, so copying a password meanwhile doesn't wait for the sync.
    pub fn sync(&self) -> Result<SyncResult, CoreError> {
        let mut fetch = self.vault()?.begin_sync();
        fetch.fetch();
        Ok(self.vault()?.finish_sync(fetch)?.into())
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

    /// What importing an export would do. Logins in no folder go into `unfiled_folder`, or
    /// stay your own.
    pub fn plan_import(
        &self,
        export: Arc<LoginExport>,
        unfiled_folder: Option<String>,
    ) -> Result<ImportPreview, CoreError> {
        let plan = self
            .vault()?
            .plan_import(&export.logins, unfiled_folder.as_deref())?;
        Ok(ImportPreview {
            folders: plan
                .folders
                .into_iter()
                .map(|folder| ImportFolderSummary {
                    name: folder.name,
                    new: folder.new,
                    logins: count(folder.logins),
                })
                .collect(),
            own: count(plan.own),
            duplicates: count(plan.duplicates),
            view_only: plan
                .view_only
                .into_iter()
                .map(|(name, logins)| ImportFolderSummary {
                    name,
                    new: false,
                    logins: count(logins),
                })
                .collect(),
            one_time_codes: count(plan.one_time_codes),
        })
    }

    /// Imports an export, creating the folders it needs (for you only).
    pub fn import(
        &self,
        export: Arc<LoginExport>,
        unfiled_folder: Option<String>,
    ) -> Result<ImportResult, CoreError> {
        let summary = self
            .vault()?
            .import(&export.logins, unfiled_folder.as_deref())?;
        Ok(ImportResult {
            added: count(summary.added),
            folders_created: count(summary.folders_created),
            duplicates: count(summary.duplicates),
            left_out: count(summary.left_out),
        })
    }

    /// Logins deleted in the last 30 days that you can bring back, newest first, fetched
    /// fresh; empty (`None`) if the server is older than 0.9.0 and keeps none.
    pub fn deleted_logins(&self) -> Result<Option<Vec<DeletedLogin>>, CoreError> {
        Ok(self.vault()?.deleted()?.map(|rows| {
            rows.into_iter()
                .map(|row| DeletedLogin {
                    item_id: row.item_id.to_string(),
                    name: row.name,
                    username: row.username,
                    folder: row.folder,
                    deleted_by: row.deleted_by,
                    deleted_at: row.deleted_at,
                    kept_until: row.kept_until,
                })
                .collect()
        }))
    }

    /// Brings back a login from the list last fetched, for everyone who had it.
    pub fn undelete_login(&self, item_id: String) -> Result<SaveOutcome, CoreError> {
        Ok(self.vault()?.undelete(item_id_from(&item_id)?)?.into())
    }

    /// Deletes a deleted login for good now, instead of after 30 days.
    pub fn purge_login(&self, item_id: String) -> Result<(), CoreError> {
        Ok(self.vault()?.purge(item_id_from(&item_id)?)?)
    }

    /// Moves a login to another folder, or out of folders as yours (`None`). Who had it
    /// only through its old folder loses it.
    pub fn move_login(
        &self,
        item_id: String,
        to_folder: Option<String>,
    ) -> Result<SaveOutcome, CoreError> {
        Ok(self
            .vault()?
            .move_item(item_id_from(&item_id)?, to_folder.as_deref())?
            .into())
    }

    /// Deletes a login for everyone who can open it.
    pub fn delete_login(&self, item_id: String) -> Result<SaveOutcome, CoreError> {
        Ok(self.vault()?.delete(item_id_from(&item_id)?)?.into())
    }

    /// Everyone on the server, fetched fresh.
    pub fn users(&self) -> Result<Vec<User>, CoreError> {
        Ok(self.vault()?.users()?.into_iter().map(User::from).collect())
    }

    /// Everyone as of the last sync, without asking the server again.
    pub fn known_users(&self) -> Result<Vec<User>, CoreError> {
        Ok(self
            .vault()?
            .known_users()
            .into_iter()
            .map(User::from)
            .collect())
    }

    /// Creates a single-use invite (owner only). `name` is how the new user will appear.
    pub fn invite(&self, name: String) -> Result<Invitation, CoreError> {
        Ok(self.vault()?.invite(&name)?.into())
    }

    /// The invites nobody has used yet (owner only), oldest first, fetched fresh; `None`
    /// if the server is older than 0.16.0, which doesn't list them.
    pub fn pending_invites(&self) -> Result<Option<Vec<PendingInvitation>>, CoreError> {
        Ok(self.vault()?.pending_invites()?.map(|invites| {
            invites
                .into_iter()
                .map(|invite| PendingInvitation {
                    id: invite.id,
                    name: invite.name,
                    created_at: invite.created_at,
                    expires_at: invite.expires_at,
                })
                .collect()
        }))
    }

    /// Revokes an invite nobody has used (owner only): its line stops working at once.
    pub fn revoke_invite(&self, id: i64) -> Result<(), CoreError> {
        Ok(self.vault()?.revoke_invite(id)?)
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

    /// Every login you can open, from the local copy, in a KeePass file (.kdbx) encrypted
    /// with `passphrase`.
    pub fn export_logins(&self, passphrase: String) -> Result<ExportedFile, CoreError> {
        let export = self.vault()?.export_kdbx(&passphrase)?;
        Ok(ExportedFile {
            logins: count(export.logins),
            left_out: count(export.left_out),
            data: export.file,
        })
    }

    /// Renames a folder, and the folders inside it you manage (managers).
    pub fn rename_folder(&self, folder: String, name: String) -> Result<FolderRenamed, CoreError> {
        let renamed = self.vault()?.rename_folder(&folder, &name)?;
        Ok(FolderRenamed {
            name: renamed.name,
            kept: renamed.kept,
            problems: renamed.problems,
        })
    }

    /// What deleting a folder would delete, fetched fresh.
    pub fn folder_deletion(&self, folder: String) -> Result<FolderDeletion, CoreError> {
        let plan = self.vault()?.folder_deletion(&folder)?;
        Ok(FolderDeletion {
            logins: plan.logins as u64,
            to_change: plan.to_change as u64,
            inside: plan.inside,
        })
    }

    /// Deletes a folder and its logins for everyone, for good (managers); `logins` is the
    /// number from `folder_deletion` that was agreed to.
    pub fn delete_folder(&self, folder: String, logins: u64) -> Result<SyncResult, CoreError> {
        let logins = usize::try_from(logins).unwrap_or(usize::MAX);
        Ok(self.vault()?.delete_folder(&folder, logins)?.into())
    }

    /// Creates a folder inside another, named "Parent / Name". With `share_like_parent`,
    /// it starts out shared with the parent's people and groups, in the same roles.
    pub fn create_folder_inside(
        &self,
        parent: String,
        name: String,
        share_like_parent: bool,
    ) -> Result<FolderCreated, CoreError> {
        let created = self
            .vault()?
            .create_folder_inside(&parent, &name, share_like_parent)?;
        Ok(FolderCreated {
            name: created.name,
            shared_with: created.shared_with,
            problems: created.problems,
        })
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

    /// Checks the passwords of the logins you can change: weak ones, ones other logins
    /// share, and ones set over a year ago. Passwords are opened in memory only.
    pub fn password_health(&self) -> Result<PasswordHealth, CoreError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs() as i64);
        let health = self.vault()?.password_health(now)?;
        Ok(PasswordHealth {
            logins: health
                .rows
                .into_iter()
                .map(|row| HealthLogin {
                    item_id: row.item_id.to_string(),
                    name: row.name,
                    username: row.username,
                    folder: row.folder,
                    weak: row.weak,
                    reused_with: row.reused_with,
                    old_since: row.old_since,
                })
                .collect(),
            checked: health.checked as u32,
            ages_known: health.ages_known,
        })
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

    /// Deletes a group (the owner, or a manager in it): its members lose what only it gave
    /// them, and folders shared with it get new keys, here if you manage them.
    pub fn delete_group(&self, group: String) -> Result<SyncResult, CoreError> {
        Ok(self.vault()?.delete_group(&group)?.into())
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

/// A newer Keystead, with the Mac app attached to its GitHub release.
#[derive(uniffi::Record)]
pub struct AppUpdate {
    /// "0.14.0".
    pub version: String,
    /// The release's page: what changed, and how to install it.
    pub page: String,
    /// The Mac app's zip.
    pub download: String,
}

/// Asks GitHub whether a newer Keystead than `current` (the app's version) is out with the
/// Mac app, sending only the app's name and version. Blocks on the network.
#[uniffi::export]
pub fn check_for_app_update(current: String) -> Result<Option<AppUpdate>, CoreError> {
    let user_agent = format!("Keystead-macOS/{current}");
    let update = keystead_client::updates::check(&current, &user_agent)?;
    Ok(update.map(|update| AppUpdate {
        version: update.version,
        page: update.page,
        download: update.download,
    }))
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

/// The shortest passphrase an export takes.
#[uniffi::export]
pub fn min_export_passphrase() -> u32 {
    count(keystead_client::MIN_EXPORT_PASSPHRASE)
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

/// Reads a line from the owner for recovering with their help.
#[uniffi::export]
pub fn parse_recovery_line(text: String) -> Result<RecoveryLineInfo, CoreError> {
    let line = recovery_line(&text)?;
    Ok(RecoveryLineInfo {
        server: line.server,
        owner_fingerprint: line.owner_fingerprint,
    })
}

/// Sends this device's new account keys for a recovery the owner started; nothing changes
/// until the owner approves. The signer only gives its public key here.
#[uniffi::export]
pub fn claim_recovery(
    line: String,
    account_secret: Vec<u8>,
    device_id: String,
    device_name: String,
    signer: Arc<dyn DeviceSigner>,
) -> Result<RecoveryClaimInfo, CoreError> {
    let line = recovery_line(&line)?;
    let secret = account_secret_from(account_secret)?;
    let claim = keystead_client::claim_recovery(
        &line,
        &NewAccount {
            server: &line.server,
            secret: &secret,
            device_id: device_id_from(&device_id)?,
            device_name: &device_name,
            signer: Arc::new(SignerAdapter(signer)),
        },
    )?;
    Ok(RecoveryClaimInfo {
        user_id: claim.user_id.0,
        name: claim.name,
        fingerprint: claim.fingerprint,
    })
}

/// Whether the owner has approved a recovery yet; a cancelled or expired one is an error.
#[uniffi::export]
pub fn recovery_approved(line: String) -> Result<bool, CoreError> {
    Ok(keystead_client::recovery_approved(&recovery_line(&line)?)?)
}

/// Where a recovery stands, for the new device waiting on it.
#[derive(uniffi::Enum)]
pub enum RecoveryProgress {
    Waiting,
    Approved,
    /// The owner cancelled it, or it expired.
    Ended,
}

/// Asks whether the owner has approved yet. An error means the server couldn't be asked:
/// keep waiting and ask again.
#[uniffi::export]
pub fn recovery_progress(line: String) -> Result<RecoveryProgress, CoreError> {
    Ok(
        match keystead_client::recovery_progress(&recovery_line(&line)?)? {
            keystead_client::RecoveryProgress::Waiting => RecoveryProgress::Waiting,
            keystead_client::RecoveryProgress::Approved => RecoveryProgress::Approved,
            keystead_client::RecoveryProgress::Ended => RecoveryProgress::Ended,
        },
    )
}

fn recovery_line(text: &str) -> Result<keystead_client::RecoveryLine, CoreError> {
    keystead_client::RecoveryLine::parse(text).map_err(|error| CoreError::InvalidInput {
        message: format!("{error:#}"),
    })
}

/// Why a server address typed in can't be used for a new account or device, or none if it
/// can: https://, or http:// for a server on this Mac.
#[uniffi::export]
pub fn server_address_problem(server: String) -> Option<String> {
    keystead_client::http::check_server_address(&server)
        .err()
        .map(|error| format!("{error:#}"))
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
