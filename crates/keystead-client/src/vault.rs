//! An unlocked vault: the profile plus the account keys, able to sign in and act.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use keystead_core::api::{
    AcceptInviteRequest, AddFolderGroupRequest, AddGroupMemberRequest, AddMemberRequest,
    ApprovalRequest, ClaimDeviceTransferRequest, ClaimedAccountSecret, Conflict,
    CreateFolderRequest, CreateGroupRequest, DeletedItems, DeviceList, DeviceTransfer,
    DeviceTransferState, Directory, Enrolled, Exposures, GroupFolderKey, GroupMemberKey,
    GroupRekeyRequest, GroupShare, Groups, Health, Invite, InviteRequest, Invites, ItemHistory,
    JoinDeviceTransferRequest, KeyLink, Member, MemberKey, Members, PendingInvite, PutItemRequest,
    RecoverRequest, RecoveryChallenge, RecoveryChallengeRequest, RekeyRequest, Removal,
    RemoveUserRequest, Role, RoleRequest, SendAccountSecretRequest, SetupRequest, SyncEntry,
    SyncPage, UpdateGroupRequest,
};
use keystead_core::directory::DirectoryEntry;
use keystead_core::folders::FolderEntry;
use keystead_core::groups::{GroupEntry, GroupKeyring};
use keystead_core::ids::{DeviceId, FolderId, GroupId, ItemId, UserId};
use keystead_core::items::{
    Details, EncryptedItem, FolderInfo, GroupKeyCopy, ITEM_FORMAT, ItemKeys, ItemVersion, Overview,
    PersonKey,
};
use keystead_core::keys::{
    AccountKeys, AccountPublicKeys, AccountSecret, FolderKey, GroupKeys, GroupSecret, ItemKey,
    TransferKey, recovery_message, transfer_code,
};
use keystead_core::otp::{self, OneTimeCode};
use rand::Rng;
use rand::rngs::OsRng;

use crate::DeviceSigner;
use crate::export::{KdbxWriter, MIN_EXPORT_PASSPHRASE};
use crate::http::{Client, Failure};
use crate::import::ImportedLogin;
use crate::profile::{FolderRecord, GroupRecord, OWNER, Profile};

mod health;
mod membership;
mod recovery;

pub use health::{HealthRow, OLD_AFTER_SECONDS, PasswordHealth};
use recovery::RecoveryDuties;
pub use recovery::{
    ApprovedRecovery, RecoveryClaim, RecoveryLine, RecoveryProgress, RecoveryRequest,
    claim_recovery, finish_recovery, recovery_approved, recovery_progress,
};

/// What an older server answers for something it doesn't have yet: 404 on the whole route.
const NEEDS_0_2: &str = "the server is older than Keystead 0.2.0 and can't do this yet; \
                         update it to 0.2.0 or later";
/// Groups came with 0.4.0; an older server doesn't have them.
const NEEDS_0_4: &str = "the server is older than Keystead 0.4.0 and doesn't have groups; \
                         update it to 0.4.0 or later";
/// One-time codes came with 0.6.0 (item format 4); an older server can't store them.
const NEEDS_0_6: &str = "the server is older than Keystead 0.6.0 and can't store one-time \
                         codes; update it to 0.6.0 or later";
/// Recently deleted came with 0.9.0; an older server forgets a deleted login at once.
const NEEDS_0_9: &str = "the server is older than Keystead 0.9.0 and keeps nothing of deleted \
                         logins; update it to 0.9.0 or later";
/// History came with 0.7.0; an older server keeps only each login's latest version.
const NEEDS_0_7: &str = "the server is older than Keystead 0.7.0 and keeps no history; update \
                         it to 0.7.0 or later";
/// Adding a device from another came with 0.8.0.
const NEEDS_0_8: &str = "the server is older than Keystead 0.8.0 and can't add a device from \
                         another; update it, or use your Recovery Kit on the new device";
/// Moving logins came with 0.12.0; an older server refuses any change of folder or owner.
const NEEDS_0_12: &str = "the server is older than Keystead 0.12.0 and can't move logins; \
                          update it to 0.12.0 or later";
/// Revoking invites came with 0.16.0.
const NEEDS_0_16: &str = "the server is older than Keystead 0.16.0 and can't revoke invites; \
                          update it to 0.16.0 or later";
/// Deleting folders came with 0.13.0.
const NEEDS_0_13: &str = "the server is older than Keystead 0.13.0 and can't delete folders; \
                          update it to 0.13.0 or later";
/// What a server answers for sign-out if it's from before sign-out existed.
const NO_SIGN_OUT: &str = "the server is too old to forget a device that signs out; update it";
const PAGE_SIZE: i64 = 500;
/// Sign in again this long before the server's session would expire.
const SESSION_MARGIN: Duration = Duration::from_secs(60);

/// When to renew a session, and when it can't be used any more.
#[derive(Clone, Copy, Debug)]
struct SessionTimes {
    renew_after: Instant,
    valid_until: Instant,
}

#[derive(Debug, PartialEq, Eq)]
enum SessionStep {
    Use,
    Renew,
    SignIn,
}

impl SessionTimes {
    /// For a session the server gave for `seconds`, asked for at `asked`.
    fn new(asked: Instant, seconds: u64) -> Self {
        let lifetime = Duration::from_secs(seconds);
        Self {
            renew_after: asked + lifetime / 2,
            valid_until: asked + lifetime.saturating_sub(SESSION_MARGIN),
        }
    }

    /// The server won't renew this session any more (it renews for a while after signing
    /// in with the key, then wants the key again): use it until it ends, then sign in.
    fn stop_renewing(&mut self) {
        self.renew_after = self.valid_until;
    }

    fn step(&self, now: Instant) -> SessionStep {
        if now >= self.valid_until {
            SessionStep::SignIn
        } else if now >= self.renew_after {
            SessionStep::Renew
        } else {
            SessionStep::Use
        }
    }
}

#[derive(Debug)]
pub struct Whoami {
    pub name: String,
    pub user_id: UserId,
    pub fingerprint: String,
    pub server: String,
    pub is_owner: bool,
    /// The owner's fingerprint, as this device pinned it. A recovery kit carries it.
    pub owner_fingerprint: String,
    /// The owner keeps this account's personal key in escrow, to recover its own logins.
    pub escrow: bool,
    /// The owner has started a recovery for this account. If it wasn't asked for, cancel it.
    pub recovering: bool,
}

/// An invite: everything a new user needs to join, including the owner's fingerprint so
/// they can check they reached the right server.
#[derive(Debug, PartialEq, Eq)]
pub struct InviteInfo {
    pub server: String,
    pub token: String,
    pub owner_fingerprint: String,
    /// When it stops working, in seconds since 1970, for one just made on a server that
    /// says (0.16.0 and later); a line someone pasted doesn't carry it.
    pub expires_at: Option<i64>,
}

impl InviteInfo {
    /// The invite as one line to send: `keystead join <server> <token> --owner <fingerprint>`.
    /// The CLI runs it as a command; the apps accept it pasted whole.
    pub fn command(&self) -> String {
        format!(
            "keystead join {} {} --owner {}",
            self.server, self.token, self.owner_fingerprint
        )
    }

    /// Reads an invite line back, with or without the leading `keystead join`, and
    /// with the parts on separate lines if a mail client wrapped it.
    pub fn parse(text: &str) -> Result<Self> {
        let mut words: Vec<&str> = text.split_whitespace().collect();
        if words.first() == Some(&"keystead") {
            words.remove(0);
        }
        if words.first() == Some(&"join") {
            words.remove(0);
        }
        let owner = words
            .iter()
            .position(|&word| word == "--owner")
            .filter(|&index| index + 1 < words.len())
            .context("an invite ends with --owner and the owner's fingerprint")?;
        let owner_fingerprint = words[owner + 1].to_owned();
        words.drain(owner..=owner + 1);
        match words.as_slice() {
            [server, token] if server.starts_with("http://") || server.starts_with("https://") => {
                Ok(Self {
                    server: (*server).to_owned(),
                    token: (*token).to_owned(),
                    owner_fingerprint,
                    expires_at: None,
                })
            }
            _ => bail!("an invite has a server address starting with http and a token"),
        }
    }
}

/// What a new device needs to join its account from a device the account already has:
/// `keystead add-device <server> <token> --owner <fingerprint>`, as one line to copy over.
/// It holds nothing secret: the code check and the owner's fingerprint protect the rest.
#[derive(Clone, Debug)]
pub struct DeviceSetupLine {
    pub server: String,
    pub token: String,
    pub owner_fingerprint: String,
}

impl DeviceSetupLine {
    pub fn command(&self) -> String {
        format!(
            "keystead add-device {} {} --owner {}",
            self.server, self.token, self.owner_fingerprint
        )
    }

    /// Reads a setup line back, with or without the leading `keystead add-device`.
    pub fn parse(text: &str) -> Result<Self> {
        let mut words: Vec<&str> = text.split_whitespace().collect();
        if words.first() == Some(&"keystead") {
            words.remove(0);
        }
        if words.first() == Some(&"add-device") {
            words.remove(0);
        }
        let owner = words
            .iter()
            .position(|&word| word == "--owner")
            .filter(|&index| index + 1 < words.len())
            .context("a setup line ends with --owner and the owner's fingerprint")?;
        let owner_fingerprint = words[owner + 1].to_owned();
        words.drain(owner..=owner + 1);
        match words.as_slice() {
            [server, token] if server.starts_with("http://") || server.starts_with("https://") => {
                Ok(Self {
                    server: (*server).to_owned(),
                    token: (*token).to_owned(),
                    owner_fingerprint,
                })
            }
            _ => bail!("a setup line has a server address starting with http and a token"),
        }
    }
}

/// A new device waiting to join its account: it has sent its one-time key, shows a code
/// for the person to type on their other device, and asks for the account secret until
/// it arrives. Then [`recover`] finishes, with the line's owner fingerprint.
pub struct JoiningDevice {
    line: DeviceSetupLine,
    key: TransferKey,
    code: String,
}

impl JoiningDevice {
    pub fn start(line: DeviceSetupLine, device_name: &str) -> Result<Self> {
        let key = TransferKey::generate();
        let request = JoinDeviceTransferRequest {
            token: line.token.clone(),
            device_name: device_name.to_owned(),
            transfer_key: key.public(),
        };
        match Client::new(&line.server).post::<_, ()>("/v1/device-transfers/join", &request) {
            Ok(()) => {}
            Err(Failure::Status { code: 404, .. }) => bail!(
                "this setup line has expired or was already used (or the server is older than \
                 0.8.0); start again on your other device"
            ),
            Err(error) => return Err(error.into()),
        }
        let code = transfer_code(&line.token, &key.public());
        Ok(Self { line, key, code })
    }

    /// The code to type on the other device.
    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn line(&self) -> &DeviceSetupLine {
        &self.line
    }

    /// Asks once whether the other device has sent the account secret yet.
    pub fn poll(&self) -> Result<Option<AccountSecret>> {
        let request = ClaimDeviceTransferRequest {
            token: self.line.token.clone(),
        };
        let claimed: ClaimedAccountSecret =
            match Client::new(&self.line.server).post("/v1/device-transfers/claim", &request) {
                Ok(claimed) => claimed,
                Err(Failure::Status { code: 404, .. }) => bail!(
                    "adding this device expired, or was stopped on your other device; start again"
                ),
                Err(error) => return Err(error.into()),
            };
        claimed
            .wrapped_secret
            .map(|wrapped| {
                self.key
                    .open_account_secret(&wrapped, &self.line.token)
                    .context("what arrived wasn't sealed for this device; start again")
            })
            .transpose()
    }
}

#[derive(Debug)]
pub struct UserRow {
    pub user_id: UserId,
    pub name: String,
    pub approved: bool,
    pub is_owner: bool,
    /// The owner removed them from the team.
    pub removed: bool,
    pub fingerprint: String,
    /// They let the owner recover their own logins.
    pub escrow: bool,
    /// The owner has started a recovery for them that isn't approved yet.
    pub recovering: bool,
    /// Their keys were replaced, after recovering with the owner's help.
    pub keys_replaced: bool,
}

/// Someone who can open a folder or a login, with their role.
#[derive(Debug)]
pub struct MemberRow {
    pub user_id: UserId,
    pub name: String,
    pub role: Role,
    /// This account.
    pub me: bool,
}

/// One of this account's devices.
#[derive(Debug)]
pub struct DeviceRow {
    pub id: DeviceId,
    /// Empty for devices registered before devices had names.
    pub name: String,
    /// Seconds since the Unix epoch, when known.
    pub added_at: Option<i64>,
    /// The device this vault runs on.
    pub current: bool,
}

#[derive(Debug)]
pub struct ItemRow {
    pub id: ItemId,
    /// The item's folder, if it's in one of yours.
    pub folder: Option<String>,
    pub name: String,
    pub username: String,
    pub url: String,
    /// Whose item it is, for an item outside folders that isn't yours.
    pub owner: Option<String>,
    /// Everyone it's shared with directly, by name, except you.
    pub shared_with: Vec<String>,
    /// The groups it's shared with directly, by name.
    pub shared_with_groups: Vec<String>,
    /// You can open it only because it was shared with you directly.
    pub shared_with_me: bool,
    /// What you may do with it.
    pub role: Role,
    /// It has one-time codes ([`Vault::one_time_code`]).
    pub has_one_time_code: bool,
}

/// A login deleted in the last 30 days, which can still be brought back.
#[derive(Debug)]
pub struct DeletedRow {
    pub item_id: ItemId,
    pub name: String,
    pub username: String,
    /// Its folder, if it's in one of yours.
    pub folder: Option<String>,
    pub deleted_by: String,
    /// When it was deleted, and until when it can be brought back, in seconds since 1970.
    pub deleted_at: i64,
    pub kept_until: i64,
}

/// What an import would do.
#[derive(Debug, Default)]
pub struct ImportPlan {
    /// The folders logins go into, by name, with whether they're new.
    pub folders: Vec<ImportFolder>,
    /// Logins that stay your own: those without a folder, unless they go into one.
    pub own: usize,
    /// Logins already here (same folder, name and username), left out.
    pub duplicates: usize,
    /// Folders you can only view, so their logins are left out, with how many.
    pub view_only: Vec<(String, usize)>,
    /// Logins that bring a one-time code.
    pub one_time_codes: usize,
}

#[derive(Debug)]
pub struct ImportFolder {
    pub name: String,
    /// It doesn't exist yet and will be created, for you only.
    pub new: bool,
    pub logins: usize,
}

/// What an import did.
#[derive(Debug, Default)]
pub struct ImportSummary {
    pub added: usize,
    pub folders_created: usize,
    pub duplicates: usize,
    /// Logins for folders you can only view.
    pub left_out: usize,
}

/// Logins written to a KeePass file.
pub struct KdbxExport {
    /// The file, encrypted with the passphrase chosen.
    pub file: Vec<u8>,
    pub logins: usize,
    /// Logins left out: ones a newer Keystead wrote, or that didn't open.
    pub left_out: usize,
}

/// Where one imported login goes.
enum Destination {
    Own,
    Folder(FolderId),
    NewFolder(String),
    LeftOut,
}

/// One version of a login in its history.
#[derive(Debug)]
pub struct HistoryRow {
    pub version: u64,
    pub author: String,
    /// When it was saved, in seconds since 1970 (UTC); unknown for versions saved before
    /// 0.7.0.
    pub saved_at: Option<i64>,
    /// The login as it is now.
    pub current: bool,
    /// This account can open it: it holds a key this version was shared with (for example
    /// not a version from before the login was shared with them directly).
    pub readable: bool,
    /// What this version changed from the one before: "name", "username", "website",
    /// "password", "notes" and "one-time code", or "created". Empty if none of those did,
    /// for example when only who has it changed, or if the version before isn't known.
    pub changes: Vec<String>,
}

/// What separates a folder from the one it's inside, in folder names: "Engineering /
/// Databases".
pub const FOLDER_SEPARATOR: &str = " / ";

/// A folder made inside another.
#[derive(Debug, Default)]
pub struct NewFolder {
    /// Its full name, "Parent / Name".
    pub name: String,
    /// Who it was shared with, like its parent; groups are marked "(group)".
    pub shared_with: Vec<String>,
    /// Anyone it couldn't be shared with, and why.
    pub problems: Vec<String>,
}

/// A folder renamed, with the folders inside it.
#[derive(Debug, Default)]
pub struct RenamedFolder {
    /// Its new name.
    pub name: String,
    /// Folders inside it that kept their names: this account doesn't manage them.
    pub kept: Vec<String>,
    /// Folders inside it that couldn't be renamed, and why.
    pub problems: Vec<String>,
}

/// What deleting a folder deletes, to ask about first.
#[derive(Debug)]
pub struct FolderDeletion {
    /// Logins in it, including any this app can't open; they're deleted with it.
    pub logins: usize,
    /// How many of their passwords are on the list to change; deleting forgets that.
    pub to_change: usize,
    /// Folders inside it, which stay.
    pub inside: Vec<String>,
}

/// A password to change: someone lost access to a login while its password stayed the
/// same, so they may still know it.
#[derive(Debug)]
pub struct ToChangeRow {
    pub item_id: ItemId,
    pub name: String,
    /// The login's folder, if it's in one of yours.
    pub folder: Option<String>,
    /// Who lost access.
    pub user_id: UserId,
    pub user_name: String,
    /// When they lost access, in seconds since 1970 (UTC).
    pub since: i64,
}

/// A group on the team.
#[derive(Debug)]
pub struct GroupRow {
    pub id: GroupId,
    pub name: String,
    /// Its members, managers first, then by name.
    pub members: Vec<GroupMemberRow>,
    /// This account is in it.
    pub member: bool,
    /// This account can rename it, change its managers and remove people: the owner, or
    /// a manager in it.
    pub can_manage: bool,
    /// This account can add people: it can manage the group and is in it, as adding
    /// someone means handing them the group's key.
    pub can_add: bool,
}

#[derive(Debug)]
pub struct GroupMemberRow {
    pub user_id: UserId,
    pub name: String,
    pub manager: bool,
    /// This account.
    pub me: bool,
}

/// A group that can open a folder or a login, with its role.
#[derive(Debug)]
pub struct GroupShareRow {
    pub group_id: GroupId,
    pub name: String,
    pub role: Role,
    /// This account is in the group.
    pub mine: bool,
}

#[derive(Debug)]
pub enum EditOutcome {
    Saved {
        version: u64,
    },
    /// Someone saved first. The local copy now holds their version.
    Conflict {
        version: u64,
        author: String,
    },
}

#[derive(Debug, Default)]
pub struct SyncSummary {
    pub received: usize,
    /// Items dropped because their author isn't approved, the signature failed, or the
    /// folder's signed roles never let the author do more than view.
    pub rejected: usize,
    /// Folders this account manages that got a new key after someone lost access.
    pub rekeyed: usize,
    /// Why a folder that needs a new key didn't get one this time; the next sync retries.
    pub rekey_problems: Vec<String>,
    /// Copies made for people who recovered with the owner's help.
    pub restored: usize,
}

/// What enrolling a new device needs, whatever the platform.
pub struct NewAccount<'a> {
    pub server: &'a str,
    pub secret: &'a AccountSecret,
    pub device_id: DeviceId,
    /// How the device shows in the account's device list, like "Ana's MacBook Pro".
    pub device_name: &'a str,
    pub signer: Arc<dyn DeviceSigner>,
}

/// Claims a new server with its setup code. The caller becomes user 1, the owner.
pub fn setup(path: &Path, account: NewAccount<'_>, setup_code: &str, name: &str) -> Result<Vault> {
    let keys = AccountKeys::derive(account.secret);
    let mut entry = DirectoryEntry::new(OWNER, name, keys.public());
    entry.approve(&keys);
    let enrolled: Enrolled = Client::new(account.server).post(
        "/v1/setup",
        &SetupRequest {
            setup_code: setup_code.trim().to_owned(),
            name: name.to_owned(),
            keys: keys.public(),
            device_id: account.device_id,
            device_key: account.signer.public_key(),
            device_name: account.device_name.to_owned(),
            approval: entry.approval.clone().expect("just approved"),
        },
    )?;
    let mut profile = Profile::new(
        account.server,
        name,
        enrolled.user_id,
        account.device_id,
        keys.public(),
    );
    profile.directory = vec![entry];
    Vault::create(path, profile, keys, account.signer)
}

/// Joins with an invite, and pins the owner's keys after checking their fingerprint.
/// Nothing is saved if the fingerprint doesn't match.
pub fn join(
    path: &Path,
    account: NewAccount<'_>,
    token: &str,
    owner_fingerprint: &str,
) -> Result<Vault> {
    let keys = AccountKeys::derive(account.secret);
    let mut client = Client::new(account.server);
    let enrolled: Enrolled = client.post(
        "/v1/invites/accept",
        &AcceptInviteRequest {
            token: token.trim().to_owned(),
            keys: keys.public(),
            device_id: account.device_id,
            device_key: account.signer.public_key(),
            device_name: account.device_name.to_owned(),
        },
    )?;
    client.sign_in(account.device_id, account.signer.as_ref())?;
    let directory: Directory = client.get("/v1/directory", &[])?;

    let owner = owner_entry(&directory)?;
    check_owner(
        owner,
        Owner::Fingerprint(owner_fingerprint),
        "ask the owner for a new invite",
    )?;
    let name = directory
        .entries
        .iter()
        .find(|entry| entry.user_id == enrolled.user_id)
        .map(|entry| entry.name.clone())
        .context("the server didn't list the new account")?;

    let mut profile = Profile::new(
        account.server,
        &name,
        enrolled.user_id,
        account.device_id,
        owner.keys.clone(),
    );
    profile.set_directory(directory.entries);
    Vault::create(path, profile, keys, account.signer)
}

/// Recovers an account onto a new device with its secret, from a recovery kit. The account
/// key signs for the new device; then, as when joining, the owner's keys are pinned only
/// if their fingerprint matches the one on the kit. The owner can leave the fingerprint
/// out: their own keys, from the secret, are checked instead. Nothing is saved unless
/// everything checks out. Call `sync` afterwards to fetch the account's folders and logins.
pub fn recover(
    path: &Path,
    account: NewAccount<'_>,
    owner_fingerprint: Option<&str>,
) -> Result<Vault> {
    const ADVICE: &str = "check the owner's fingerprint on your recovery kit";
    let keys = AccountKeys::derive(account.secret);
    let public = keys.public();
    let expected = match owner_fingerprint
        .map(str::trim)
        .filter(|text| !text.is_empty())
    {
        Some(fingerprint) => Owner::Fingerprint(fingerprint),
        None => Owner::Me(&public),
    };
    let mut client = Client::new(account.server);
    let challenge: RecoveryChallenge = match client.post(
        "/v1/recover/challenge",
        &RecoveryChallengeRequest {
            keys: keys.public(),
        },
    ) {
        Ok(challenge) => challenge,
        Err(Failure::Status { code: 404, .. }) => bail!(NEEDS_0_2),
        Err(error) => return Err(error.into()),
    };
    // Before registering anything, so a mistyped fingerprint leaves no trace.
    check_owner(&challenge.owner, expected, ADVICE)?;
    let device_key = account.signer.public_key();
    let signature = keys.sign(&recovery_message(
        challenge.challenge.as_slice(),
        account.device_id,
        &device_key,
    ));
    let enrolled: Enrolled = client.post(
        "/v1/recover",
        &RecoverRequest {
            challenge: challenge.challenge,
            device_id: account.device_id,
            device_key,
            device_name: account.device_name.to_owned(),
            signature,
        },
    )?;
    client.sign_in(account.device_id, account.signer.as_ref())?;
    let directory: Directory = client.get("/v1/directory", &[])?;

    let owner = owner_entry(&directory)?;
    check_owner(owner, expected, ADVICE)?;
    let me = directory
        .entries
        .iter()
        .find(|entry| entry.user_id == enrolled.user_id)
        .context("the server didn't list the recovered account")?;
    if me.keys != keys.public() {
        bail!("the server lists different keys for this account. Don't trust this server.");
    }
    // The owner vouches for every account but their own. Without that, the secret this
    // device was given proves nothing: a server can register keys from a secret it made
    // up under anyone's name, and would then read what the device saves as its own. The
    // device comes off the account again, so nothing half-added is left behind.
    if me.user_id != owner.user_id && me.verify(&owner.keys).is_err() {
        let _ = client.post_empty::<()>("/v1/sign-out");
        if me.approval.is_none() {
            bail!(
                "the owner hasn't approved this account yet. Ask them to approve you, then \
                 add this device again."
            );
        }
        bail!("the owner's approval of this account doesn't check out. Don't trust this server.");
    }
    let mut profile = Profile::new(
        account.server,
        &me.name,
        enrolled.user_id,
        account.device_id,
        owner.keys.clone(),
    );
    profile.set_directory(directory.entries);
    Vault::create(path, profile, keys, account.signer)
}

fn owner_entry(directory: &Directory) -> Result<&DirectoryEntry> {
    directory
        .entries
        .iter()
        .find(|entry| entry.user_id == OWNER)
        .context("the server has no owner")
}

/// Who the server's owner must be.
#[derive(Clone, Copy)]
enum Owner<'a> {
    /// Whoever has this fingerprint, from an invite or a recovery kit.
    Fingerprint(&'a str),
    /// This account itself: an owner recovering without typing their fingerprint.
    Me(&'a AccountPublicKeys),
}

/// Checks the owner is who `expected` says and their self-approval verifies. `advice` says
/// what to do if not.
fn check_owner(owner: &DirectoryEntry, expected: Owner<'_>, advice: &str) -> Result<()> {
    if owner.user_id != OWNER {
        bail!("the server sent someone else as the owner. Don't trust this server.");
    }
    let self_approved = owner.verify(&owner.keys).is_ok();
    match expected {
        Owner::Fingerprint(fingerprint) => {
            let expected = normalize(fingerprint);
            if owner.keys.fingerprint() != expected || !self_approved {
                bail!(
                    "the owner's fingerprint on this server is {}, not {expected}. Don't trust \
                     this server; {advice}.",
                    owner.keys.fingerprint()
                );
            }
        }
        Owner::Me(keys) => {
            if owner.keys != *keys || !self_approved {
                bail!(
                    "this account isn't the owner of this server. If you're not the owner, \
                     enter the owner's fingerprint from your recovery kit; if you are, check \
                     the server address, and don't trust this server."
                );
            }
        }
    }
    Ok(())
}

/// A random 24-character password.
pub fn generate_password() -> String {
    const CHARACTERS: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_.!@#%^*";
    let mut rng = OsRng;
    (0..24)
        .map(|_| CHARACTERS[rng.gen_range(0..CHARACTERS.len())] as char)
        .collect()
}

pub struct Vault {
    path: PathBuf,
    profile: Profile,
    keys: AccountKeys,
    signer: Arc<dyn DeviceSigner>,
    client: Option<Client>,
    session: Option<SessionTimes>,
    /// Whether the server renews sessions; servers from before that answer 404.
    server_renews: bool,
    /// The server stores this build's item format; checked before the first save.
    server_takes_items: bool,
    /// Whether the server keeps signed members, once asked this session.
    /// What the server says it keeps signed (see `membership_level`), once asked.
    server_membership: Option<u8>,
    /// Whether an author could save into a folder, by its signed roles, while a sync
    /// applies logins (see `apply_item`).
    could_save: HashMap<(FolderId, UserId), bool>,
    /// The keys of the groups this account is in, from the profile.
    groups: GroupKeyring,
    /// Login histories fetched this session, by login, newest first; kept encrypted.
    history: HashMap<ItemId, Vec<EncryptedItem>>,
    /// A device being added from this one: the transfer's id and token.
    adding_device: Option<(String, String)>,
    /// The last version of each recently deleted login fetched this session; encrypted.
    deleted: HashMap<ItemId, EncryptedItem>,
}

impl Vault {
    /// Unlocks an enrolled device's vault. Doesn't touch the network.
    pub fn open(
        path: &Path,
        secret: &AccountSecret,
        signer: Arc<dyn DeviceSigner>,
    ) -> Result<Self> {
        let profile = Profile::load(path)?;
        let keys = AccountKeys::derive(secret);
        Ok(Self {
            path: path.to_owned(),
            groups: profile.group_keyring(&keys),
            profile,
            keys,
            signer,
            client: None,
            session: None,
            server_renews: true,
            server_takes_items: false,
            server_membership: None,
            could_save: HashMap::new(),
            history: HashMap::new(),
            adding_device: None,
            deleted: HashMap::new(),
        })
    }

    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    fn create(
        path: &Path,
        profile: Profile,
        keys: AccountKeys,
        signer: Arc<dyn DeviceSigner>,
    ) -> Result<Self> {
        let vault = Self {
            path: path.to_owned(),
            profile,
            keys,
            signer,
            client: None,
            session: None,
            server_renews: true,
            server_takes_items: false,
            server_membership: None,
            could_save: HashMap::new(),
            history: HashMap::new(),
            adding_device: None,
            deleted: HashMap::new(),
            groups: GroupKeyring::default(),
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Whether the server renews sessions without the device key, as far as this session
    /// has seen. A server from before 0.14.0 doesn't, so the device signs in with its key
    /// each time a session ends, every 15 minutes.
    pub fn server_renews_sessions(&self) -> bool {
        self.server_renews
    }

    pub fn whoami(&self) -> Whoami {
        let me = self
            .profile
            .directory
            .iter()
            .find(|entry| entry.user_id == self.profile.user_id);
        Whoami {
            name: self.profile.name.clone(),
            user_id: self.profile.user_id,
            fingerprint: self.keys.public().fingerprint(),
            server: self.profile.server.clone(),
            is_owner: self.profile.user_id == OWNER,
            owner_fingerprint: self.profile.owner.fingerprint(),
            escrow: self.escrow_on(),
            recovering: me.is_some_and(|entry| entry.recovering),
        }
    }

    /// Pulls feed pages until caught up, then saves. Every item must be signed by an
    /// author the owner approved; anything else is dropped.
    pub fn sync(&mut self) -> Result<SyncSummary> {
        let mut summary = SyncSummary::default();
        let (mut folders, groups, mut duties) = self.pull(&mut summary)?;
        self.sign_members_from_before();
        // Someone left these groups: give each a new key first, as folders shared with them
        // wait for it.
        if !groups.is_empty() {
            for group_id in groups {
                match self.rekey_group(group_id) {
                    Ok(()) => summary.rekeyed += 1,
                    Err(error) => summary.rekey_problems.push(format!("{error:#}")),
                }
            }
            (folders, _, duties) = self.pull(&mut summary)?;
        }
        let rekeyed = self.rekey_folders(folders, &mut summary);
        // This account's own folders came back from escrow after a recovery: take them,
        // give them new keys too, as the lost device had the old ones, and put those in
        // escrow.
        if self.do_recovery_duties(duties, &rekeyed, &mut summary) {
            let (folders, _, duties) = self.pull(&mut summary)?;
            let rekeyed = self.rekey_folders(folders, &mut summary);
            self.put_folders_in_escrow(duties.escrow_folders, &rekeyed, &mut summary);
        }
        Ok(summary)
    }

    /// Someone lost access to these folders: gives each a new key, so what's saved from now
    /// on is out of their reach. If it fails, the next sync asks again. Returns the folders
    /// that got one.
    fn rekey_folders(
        &mut self,
        folders: Vec<FolderId>,
        summary: &mut SyncSummary,
    ) -> Vec<FolderId> {
        let mut rekeyed = Vec::new();
        for folder_id in folders {
            match self.rekey(folder_id) {
                Ok(()) => {
                    summary.rekeyed += 1;
                    rekeyed.push(folder_id);
                }
                Err(error) => summary.rekey_problems.push(format!("{error:#}")),
            }
        }
        rekeyed
    }

    /// The directory, the team's groups, and the feed until caught up; then saves. Returns
    /// the folders and groups this account should give new keys, and what it should do for
    /// people who recovered.
    fn pull(
        &mut self,
        summary: &mut SyncSummary,
    ) -> Result<(Vec<FolderId>, Vec<GroupId>, RecoveryDuties)> {
        let directory: Directory = self.call(|client| client.get("/v1/directory", &[]))??;
        self.profile.set_directory(directory.entries);
        self.fetch_signed_before()?;
        self.could_save.clear();
        // Servers before 0.4.0 have no groups.
        match self.call(|client| client.get::<Groups>("/v1/groups", &[]))? {
            Ok(groups) => {
                self.profile.team_groups = groups.groups;
                self.profile.former_groups = groups.former;
            }
            Err(Failure::Status { code: 404, .. }) => self.profile.team_groups.clear(),
            Err(error) => return Err(error.into()),
        }
        // Servers before 0.5.0 don't keep track of passwords to change.
        match self.call(|client| client.get::<Exposures>("/v1/exposures", &[]))? {
            Ok(list) => self.profile.exposures = list.exposures,
            Err(Failure::Status { code: 404, .. }) => self.profile.exposures.clear(),
            Err(error) => return Err(error.into()),
        }
        // Where the last page stopped inside a folder too big for one page.
        let mut resume: Option<String> = None;
        let rekey_needed = loop {
            // A server on 0.17.0 or later sends a big folder in parts when asked; an
            // older one ignores this and sends it whole.
            let mut query = vec![
                ("cursor", self.profile.cursor.to_string()),
                ("limit", PAGE_SIZE.to_string()),
                ("parts", "true".to_owned()),
            ];
            query.extend(resume.take().map(|resume| ("resume", resume)));
            let page: SyncPage = self.call(|client| client.get("/v1/sync", &query))??;
            summary.received += page.entries.len();
            for entry in page.entries {
                self.apply_entry(entry, summary);
            }
            self.profile.cursor = page.cursor;
            resume = page.resume;
            if !page.more {
                if page.roles.is_some() {
                    self.profile.roles = page.roles;
                }
                let duties = RecoveryDuties {
                    restore: page.restore,
                    recovered_key: page.recovered_key,
                    escrow_needed: page.escrow_needed,
                    escrow_folders: page.escrow_folders,
                };
                break (page.rekey_needed, page.group_rekey_needed, duties);
            }
        };
        self.save()?;
        Ok(rekey_needed)
    }

    /// Everyone on the server, and whether the pinned owner approved them.
    pub fn users(&mut self) -> Result<Vec<UserRow>> {
        let directory: Directory = self.call(|client| client.get("/v1/directory", &[]))??;
        self.profile.set_directory(directory.entries);
        self.save()?;
        Ok(self.known_users())
    }

    /// Everyone as of the last sync or [`Vault::users`], without asking the server.
    pub fn known_users(&self) -> Vec<UserRow> {
        self.profile
            .directory
            .iter()
            .map(|entry| UserRow {
                user_id: entry.user_id,
                name: entry.name.clone(),
                approved: self.profile.trusted_entry(entry.user_id) == Some(entry),
                is_owner: entry.user_id == OWNER,
                removed: entry.removed,
                fingerprint: entry.keys.fingerprint(),
                escrow: entry.consented_to_escrow(),
                recovering: entry.recovering,
                keys_replaced: entry.revision > 0,
            })
            .collect()
    }

    /// Creates a single-use invite (owner only).
    pub fn invite(&mut self, name: &str) -> Result<InviteInfo> {
        let request = InviteRequest {
            name: name.to_owned(),
        };
        let invite: Invite = self.call(|client| client.post("/v1/invites", &request))??;
        Ok(InviteInfo {
            server: self.profile.server.clone(),
            token: invite.token,
            owner_fingerprint: self.profile.owner.fingerprint(),
            expires_at: invite.expires_at,
        })
    }

    /// The invites nobody has used yet (owner only), oldest first, fetched fresh; `None`
    /// if the server is older than 0.16.0, whose invites don't run out and aren't listed.
    pub fn pending_invites(&mut self) -> Result<Option<Vec<PendingInvite>>> {
        match self.call(|client| client.get::<Invites>("/v1/invites", &[]))? {
            Ok(list) => Ok(Some(list.invites)),
            Err(Failure::Status {
                code: 404 | 405, ..
            }) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Revokes an invite nobody has used (owner only): its line stops working at once.
    pub fn revoke_invite(&mut self, id: i64) -> Result<()> {
        let path = format!("/v1/invites/{id}");
        match self.call(|client| client.delete::<()>(&path))? {
            Ok(()) => Ok(()),
            Err(Failure::Status { code: 404, .. }) if self.pending_invites()?.is_some() => {
                bail!("that invite isn't waiting any more: it was used, revoked, or ran out")
            }
            Err(Failure::Status {
                code: 404 | 405, ..
            }) => bail!(NEEDS_0_16),
            Err(error) => Err(error.into()),
        }
    }

    /// Approves a user (owner only), but only if the fingerprint they read out matches. Only
    /// someone this app never saw approved: keys replaced in a recovery are approved with it.
    pub fn approve(&mut self, user: UserId, fingerprint: &str) -> Result<String> {
        let directory: Directory = self.call(|client| client.get("/v1/directory", &[]))??;
        self.profile.set_directory(directory.entries.clone());
        if self.profile.key_revisions.contains_key(&user) {
            bail!(
                "they're approved already. If the server shows them as waiting, don't approve \
                 them again: someone may have tampered with it."
            );
        }
        let shown = directory
            .entries
            .into_iter()
            .find(|entry| entry.user_id == user)
            .with_context(|| format!("no user {user}"))?;
        if shown.keys.fingerprint() != normalize(fingerprint) {
            bail!(
                "that isn't the fingerprint of {}'s keys on the server. Check it with them \
                 again; if it still doesn't match, don't approve: the keys may have been \
                 swapped.",
                shown.name
            );
        }
        // Always their first keys, at revision 0, whatever the server says.
        let mut entry = DirectoryEntry::new(user, &shown.name, shown.keys);
        entry.approve(&self.keys);
        let request = ApprovalRequest {
            approval: entry.approval.clone().expect("just approved"),
        };
        let path = format!("/v1/users/{user}/approval");
        let () = self.call(|client| client.post(&path, &request))??;
        Ok(entry.name)
    }

    /// This account's devices, from the server.
    pub fn devices(&mut self) -> Result<Vec<DeviceRow>> {
        let list: DeviceList = match self.call(|client| client.get("/v1/devices", &[]))? {
            Ok(list) => list,
            Err(Failure::Status { code: 404, .. }) => bail!(NEEDS_0_2),
            Err(error) => return Err(error.into()),
        };
        Ok(list
            .devices
            .into_iter()
            .map(|device| DeviceRow {
                id: device.device_id,
                name: device.name,
                added_at: device.added_at,
                current: device.current,
            })
            .collect())
    }

    /// Removes another of this account's devices, such as a lost one: it can't sign in
    /// any more. The device it runs on can't remove itself this way; see `sign_out`.
    pub fn remove_device(&mut self, device: DeviceId) -> Result<()> {
        let path = format!("/v1/devices/{device}");
        let () = self.call(|client| client.delete(&path))??;
        Ok(())
    }

    /// Signs this device out: the server forgets it, so its key can't sign in again, and
    /// the profile is deleted. Platform code then deletes the keys it keeps. Works offline
    /// too; then the server still lists the device until it's removed from another one.
    /// Returns why the server couldn't be told, if it couldn't. Don't use the vault
    /// afterwards.
    pub fn sign_out(&mut self) -> Result<Option<String>> {
        let not_told = match self.call(|client| client.post_empty::<()>("/v1/sign-out")) {
            Ok(Ok(())) => None,
            Ok(Err(Failure::Status { code: 404, .. })) => Some(NO_SIGN_OUT.to_owned()),
            Ok(Err(error)) => Some(error.to_string()),
            Err(error) => Some(format!("{error:#}")),
        };
        match std::fs::remove_file(&self.path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(error).with_context(|| format!("deleting {}", self.path.display()));
            }
            _ => {}
        }
        self.client = None;
        self.session = None;
        Ok(not_told)
    }

    pub fn create_folder(&mut self, name: &str) -> Result<FolderId> {
        let folder_id = FolderId::random();
        let key = FolderKey::generate();
        let record = FolderRecord {
            info: FolderInfo {
                name: name.to_owned(),
            }
            .seal(folder_id, &key)?,
            wrapped_key: self.keys.public().wrap_folder_key(&key, folder_id)?,
            generation: 0,
            chain: Vec::new(),
            via_group: None,
            entries: Vec::new(),
        };
        let mut record = record;
        if self.membership()? {
            let me = self.profile.user_id;
            let mut entry = FolderEntry::first(folder_id, 0, &key, vec![me], Vec::new());
            if self.signed_roles()? {
                entry = entry.with_roles(|_| Role::Manage, |_| Role::Manage);
            }
            entry.sign(me, &self.keys);
            record.entries.push(entry);
        }
        let request = CreateFolderRequest {
            folder_id,
            info: record.info.clone(),
            wrapped_key: record.wrapped_key.clone(),
            entry: record.entries.first().cloned(),
        };
        let () = self.call(|client| client.post("/v1/folders", &request))??;
        self.profile.folders.insert(folder_id, record);
        self.pin_folder(folder_id);
        self.save()?;
        Ok(folder_id)
    }

    /// Creates a folder inside another: named "Parent / Name", which apps show nested.
    /// Each folder keeps its own sharing; with `share_like_parent` the new one starts out
    /// shared with the same people and groups as its parent, in the same roles. Returns its
    /// full name, who it was shared with, and anyone it couldn't be shared with, and why.
    pub fn create_folder_inside(
        &mut self,
        parent: &str,
        name: &str,
        share_like_parent: bool,
    ) -> Result<NewFolder> {
        let name = name.trim();
        if name.is_empty() {
            bail!("a folder needs a name");
        }
        self.sync()?;
        self.profile.find_folder(&self.keys, &self.groups, parent)?;
        let full = format!("{parent}{FOLDER_SEPARATOR}{name}");
        if self.folders()?.contains(&full) {
            bail!("there's already a folder named {full:?}");
        }
        let (members, groups) = if share_like_parent {
            self.folder_sharing(parent)?
        } else {
            (Vec::new(), Vec::new())
        };
        self.create_folder(&full)?;
        let mut created = NewFolder {
            name: full.clone(),
            ..NewFolder::default()
        };
        for member in members.iter().filter(|member| !member.me) {
            match self.share_folder(&full, member.user_id, member.role) {
                Ok(name) => created.shared_with.push(name),
                Err(error) => created.problems.push(format!("{}: {error:#}", member.name)),
            }
        }
        for group in groups {
            match self.share_folder_with_group(&full, &group.name, group.role) {
                Ok(name) => created.shared_with.push(format!("{name} (group)")),
                Err(error) => created
                    .problems
                    .push(format!("{} (group): {error:#}", group.name)),
            }
        }
        Ok(created)
    }

    /// Renames a folder, and the folders inside it that this account manages ("Old /
    /// Databases" becomes "New / Databases"); the others keep their names. A folder's name
    /// is sealed with its key, so each gets a new key with its new name, which reaches every
    /// device the way new keys do. Managers only.
    pub fn rename_folder(&mut self, folder: &str, name: &str) -> Result<RenamedFolder> {
        let name = name.trim();
        if name.is_empty() {
            bail!("a folder needs a name");
        }
        self.sync()?;
        let folder_id = self.profile.find_folder(&self.keys, &self.groups, folder)?;
        if self.profile.folder_role(folder_id) != Role::Manage {
            bail!("you need manage access to rename {folder:?}");
        }
        if name == folder {
            bail!("it's already named {name:?}");
        }
        let names = self
            .profile
            .folders
            .keys()
            .map(|&id| Ok((id, self.profile.folder_name(&self.keys, &self.groups, id)?)))
            .collect::<Result<Vec<_>>>()?;
        let prefix = format!("{folder}{FOLDER_SEPARATOR}");
        let mut renamed = RenamedFolder {
            name: name.to_owned(),
            ..RenamedFolder::default()
        };
        let mut inside = Vec::new();
        for (id, old) in &names {
            let Some(rest) = old.strip_prefix(&prefix) else {
                continue;
            };
            if self.profile.folder_role(*id) == Role::Manage {
                inside.push((*id, old.clone(), format!("{name}{FOLDER_SEPARATOR}{rest}")));
            } else {
                renamed.kept.push(old.clone());
            }
        }
        // No two folders may end up with one name.
        let moving: HashSet<FolderId> = inside.iter().map(|(id, ..)| *id).collect();
        let targets = std::iter::once(name).chain(inside.iter().map(|(.., new)| new.as_str()));
        for target in targets {
            if names
                .iter()
                .any(|(id, other)| other == target && *id != folder_id && !moving.contains(id))
            {
                bail!("there's already a folder named {target:?}");
            }
        }
        self.rekey_as(folder_id, Some(name))?;
        for (id, old, new) in inside {
            if let Err(error) = self.rekey_as(id, Some(&new)) {
                renamed.problems.push(format!("{old}: {error:#}"));
            }
        }
        renamed.kept.sort();
        Ok(renamed)
    }

    /// What deleting a folder would delete, fetched fresh, to ask about first.
    pub fn folder_deletion(&mut self, folder: &str) -> Result<FolderDeletion> {
        self.sync()?;
        let folder_id = self.profile.find_folder(&self.keys, &self.groups, folder)?;
        let logins: HashSet<ItemId> = self
            .profile
            .items
            .values()
            .filter(|item| item.folder_id == Some(folder_id) && !item.deleted)
            .map(|item| item.id)
            .collect();
        let to_change: HashSet<ItemId> = self
            .profile
            .exposures
            .iter()
            .map(|exposure| exposure.item_id)
            .filter(|item_id| logins.contains(item_id))
            .collect();
        let prefix = format!("{folder}{FOLDER_SEPARATOR}");
        Ok(FolderDeletion {
            logins: logins.len(),
            to_change: to_change.len(),
            inside: self
                .folders()?
                .into_iter()
                .filter(|name| name.starts_with(&prefix))
                .collect(),
        })
    }

    /// Deletes a folder for everyone, with its logins and their history, for good
    /// (managers). `logins` is how many logins the caller agreed to delete with it, from
    /// [`folder_deletion`](Self::folder_deletion); if that's changed, nothing is deleted.
    /// Folders inside it stay.
    pub fn delete_folder(&mut self, folder: &str, logins: usize) -> Result<SyncSummary> {
        let folder_id = self.profile.find_folder(&self.keys, &self.groups, folder)?;
        if self.profile.folder_role(folder_id) != Role::Manage {
            bail!("you need manage access to delete {folder:?}");
        }
        let path = format!("/v1/folders/{folder_id}?logins={logins}");
        match self.call(|client| client.delete::<()>(&path))? {
            Ok(()) => {}
            Err(Failure::Status {
                code: 404 | 405, ..
            }) if self.server_version()? < (0, 13) => bail!(NEEDS_0_13),
            Err(error) => return Err(error.into()),
        }
        self.sync()
    }

    /// Shares a folder with an approved user by wrapping its current key for them.
    pub fn share_folder(&mut self, folder: &str, user: UserId, role: Role) -> Result<String> {
        self.sync()?;
        let folder_id = self.profile.find_folder(&self.keys, &self.groups, folder)?;
        let recipient = self.shareable_keys(user)?;
        let key = self
            .profile
            .folder_key(&self.keys, &self.groups, folder_id)?;
        let entry = self.next_folder_entry(folder_id, |entry| entry.put_member(user, role))?;
        let request = AddMemberRequest {
            user_id: user,
            wrapped_key: recipient.wrap_folder_key(&key, folder_id)?,
            role,
            generation: self.profile.folders[&folder_id].generation,
            entry: entry.clone(),
        };
        let path = format!("/v1/folders/{folder_id}/members");
        let () = self.call(|client| client.post(&path, &request))??;
        if let Some(entry) = entry {
            self.keep_folder_entry(folder_id, entry);
            self.save()?;
        }
        Ok(self.profile.user_name(user))
    }

    /// Everyone in a folder, with their roles.
    pub fn folder_members(&mut self, folder: &str) -> Result<Vec<MemberRow>> {
        Ok(self.folder_sharing(folder)?.0)
    }

    /// Everyone in a folder and every group it's shared with, with their roles.
    pub fn folder_sharing(&mut self, folder: &str) -> Result<(Vec<MemberRow>, Vec<GroupShareRow>)> {
        let folder_id = self.profile.find_folder(&self.keys, &self.groups, folder)?;
        let path = format!("/v1/folders/{folder_id}/members");
        let members: Members = self.call(|client| client.get(&path, &[]))??;
        let groups = self.group_share_rows(&members.groups);
        Ok((self.member_rows(members), groups))
    }

    /// Changes someone's role in a folder (managers only).
    pub fn set_folder_role(&mut self, folder: &str, user: UserId, role: Role) -> Result<()> {
        let folder_id = self.profile.find_folder(&self.keys, &self.groups, folder)?;
        let path = format!("/v1/folders/{folder_id}/members/{user}");
        let entry = self.next_role_entry(folder_id, |entry| entry.put_member(user, role))?;
        let request = RoleRequest {
            role,
            entry: entry.clone(),
        };
        let () = self.call(|client| client.put(&path, &request))??;
        if let Some(entry) = entry {
            self.keep_folder_entry(folder_id, entry);
            self.save()?;
        }
        Ok(())
    }

    /// Takes someone out of a folder (managers), or this account (anyone). Their access
    /// ends at once; then the folder gets a new key, so they can't read what's saved
    /// from now on.
    pub fn remove_from_folder(&mut self, folder: &str, user: UserId) -> Result<()> {
        let folder_id = self.profile.find_folder(&self.keys, &self.groups, folder)?;
        let path = format!("/v1/folders/{folder_id}/members/{user}");
        let () = self.call(|client| client.delete(&path))??;
        if user == self.profile.user_id {
            // The feed says whether this account lost the folder: not if a group of its
            // still gives it.
            self.sync()?;
        } else {
            // If this fails, the next sync of any manager tries again.
            self.rekey(folder_id)?;
        }
        Ok(())
    }

    /// Gives a folder a new key, wrapped for each current member and group, with the old
    /// key sealed under it so older items still open.
    fn rekey(&mut self, folder_id: FolderId) -> Result<()> {
        self.rekey_as(folder_id, None)
    }

    /// Gives a folder a new key, and with `name`, a new name sealed with it.
    fn rekey_as(&mut self, folder_id: FolderId, name: Option<&str>) -> Result<()> {
        let record = self
            .profile
            .folders
            .get(&folder_id)
            .context("you don't have access to that folder")?;
        let generation = record.generation + 1;
        let old = self
            .profile
            .folder_key(&self.keys, &self.groups, folder_id)?;
        let mut info = FolderInfo::open(&record.info, folder_id, &old)?;
        if let Some(name) = name {
            name.clone_into(&mut info.name);
        }
        // Who gets the new key: those the folder's signed entries name, less whoever the
        // server says has left. Its word only ever takes someone off the list; a name it
        // adds is refused, as the key would go to them.
        let signs = self.membership()?;
        if signs && !self.sign_folder_members(folder_id)? {
            bail!(
                "nobody has signed for this folder's members yet, and this account can't: \
                 it needs one of its managers"
            );
        }
        let members: Members = if signs {
            self.folder_members_now(folder_id)?
        } else {
            let path = format!("/v1/folders/{folder_id}/members");
            self.call(|client| client.get(&path, &[]))??
        };
        let roles = signs && self.signed_roles()?;
        let record = &self.profile.folders[&folder_id];
        let key = FolderKey::generate();
        let entry = match record.entries.last() {
            Some(latest) if signs => {
                let users: Vec<UserId> = members.members.iter().map(|m| m.user_id).collect();
                let groups: Vec<GroupId> = members.groups.iter().map(|g| g.group_id).collect();
                if !users.iter().all(|user| latest.members.contains(user))
                    || !groups.iter().all(|group| latest.groups.contains(group))
                {
                    bail!(
                        "the server lists someone in this folder whom its signed members \
                         don't. Don't trust this server"
                    );
                }
                // The new key is for who's in the folder now, each with the role they had.
                let mut entry = latest.next_generation(&key);
                if latest.roles.is_none() && roles {
                    entry = Self::with_listed_roles(entry, &members);
                }
                for &user in latest.members.iter().filter(|user| !users.contains(user)) {
                    entry.drop_member(user);
                }
                for &group in latest.groups.iter().filter(|group| !groups.contains(group)) {
                    entry.drop_group(group);
                }
                entry.sign(self.profile.user_id, &self.keys);
                Some(entry)
            }
            _ => None,
        };
        let mut wrapped_keys = Vec::new();
        for member in &members.members {
            let recipient = self.profile.trusted_keys(member.user_id).with_context(|| {
                format!(
                    "{} isn't approved by the owner",
                    self.profile.user_name(member.user_id)
                )
            })?;
            wrapped_keys.push(MemberKey {
                user_id: member.user_id,
                wrapped_key: recipient.wrap_folder_key(&key, folder_id)?,
            });
        }
        let mut group_keys = Vec::new();
        for share in &members.groups {
            let (_, entry) = self.profile.team_group(share.group_id)?;
            group_keys.push(GroupFolderKey {
                group_id: share.group_id,
                group_generation: entry.generation,
                wrapped_key: entry.encryption.wrap_folder_key(&key, folder_id)?,
            });
        }
        let request = RekeyRequest {
            generation,
            wrapped_keys,
            group_keys,
            previous: key.seal_previous(&old, folder_id, generation),
            info: info.seal(folder_id, &key)?,
            entry,
        };
        let path = format!("/v1/folders/{folder_id}/rekey");
        let () = self.call(|client| client.post(&path, &request))??;
        // Keep it as this account's own copy if it's a member itself, else as the copy for
        // the group it came through.
        let mine = members
            .members
            .iter()
            .any(|member| member.user_id == self.profile.user_id);
        let (wrapped_key, via_group) = if mine {
            (self.keys.public().wrap_folder_key(&key, folder_id)?, None)
        } else {
            let copy = request
                .group_keys
                .iter()
                .find(|copy| {
                    self.groups
                        .get(copy.group_id, copy.group_generation)
                        .is_some()
                })
                .context("this account isn't in the folder or any of its groups")?;
            let via = keystead_core::api::ViaGroup {
                group_id: copy.group_id,
                generation: copy.group_generation,
            };
            (copy.wrapped_key.clone(), Some(via))
        };
        let record = self
            .profile
            .folders
            .get_mut(&folder_id)
            .expect("checked above");
        record.chain.push(KeyLink {
            generation,
            previous: request.previous,
        });
        record.generation = generation;
        record.info = request.info;
        record.wrapped_key = wrapped_key;
        record.via_group = via_group;
        record.entries.extend(request.entry);
        self.save()
    }

    /// Removes someone from the team (owner only): their devices stop working, and they
    /// lose every folder and login. Folders they were in get new keys from their managers.
    pub fn remove_user(&mut self, user: UserId) -> Result<String> {
        let name = self.profile.user_name(user);
        match self.new_managers_after(user)? {
            Some(promotions) => {
                let path = format!("/v1/users/{user}/removal");
                let request = RemoveUserRequest { promotions };
                let () = self.call(|client| client.post(&path, &request))??;
            }
            None => {
                let path = format!("/v1/users/{user}");
                let () = self.call(|client| client.delete(&path))??;
            }
        }
        self.sync()?;
        Ok(name)
    }

    /// For the folders with signed roles that `user` alone manages: the next entry of
    /// each, signed by this account as the team's owner, making someone else in it a
    /// manager. The server's own choice wouldn't count with anyone's app. None with a
    /// server that doesn't keep roles, which picks a manager itself.
    ///
    /// The server says which folders and suggests whom, whoever has been in each longest.
    /// This signs only where the folder's own entries check out and make `user` one of
    /// its managers, and only for someone they name who is still on the team.
    fn new_managers_after(&mut self, user: UserId) -> Result<Option<Vec<FolderEntry>>> {
        if !self.signed_roles()? {
            return Ok(None);
        }
        self.sync()?;
        let path = format!("/v1/users/{user}/removal");
        let removal: Removal = self.call(|client| client.get(&path, &[]))??;
        let me = self.profile.user_id;
        let mut promotions = Vec::new();
        for folder in removal.folders {
            let latest = self
                .profile
                .verify_folder(&folder.entries, 0)
                .ok()
                .filter(|latest| latest.folder_id == folder.folder_id)
                .context("a folder's signed members don't check out. Don't trust this server")?;
            let manages = latest
                .role_of(user, |group, who| self.profile.in_group(group, who, true))
                == Some(Role::Manage);
            let promote = folder.promote;
            if !manages
                || promote == user
                || !latest.members.contains(&promote)
                || self.profile.trusted_keys(promote).is_none()
            {
                bail!(
                    "the server asked for a new manager of a folder that doesn't need one, \
                     or for someone who isn't in it. Don't trust this server"
                );
            }
            let mut entry = latest.next();
            entry.put_member(promote, Role::Manage);
            entry.sign(me, &self.keys);
            promotions.push(entry);
        }
        Ok(Some(promotions))
    }

    // MARK: Groups

    /// Every group on the team whose entries check out, from the last sync, by name.
    pub fn groups(&self) -> Vec<GroupRow> {
        let me = self.profile.user_id;
        let mut rows: Vec<GroupRow> = self
            .profile
            .team_groups
            .iter()
            .filter_map(|info| {
                let entry = self.profile.verify_group(&info.entries).ok()?;
                let mut members: Vec<GroupMemberRow> = info
                    .members
                    .iter()
                    .map(|&user| GroupMemberRow {
                        user_id: user,
                        name: self.profile.user_name(user),
                        manager: entry.is_manager(user),
                        me: user == me,
                    })
                    .collect();
                members.sort_by(|a, b| (!a.manager, &a.name).cmp(&(!b.manager, &b.name)));
                let member = info.members.contains(&me);
                let can_manage = me == OWNER || (member && entry.is_manager(me));
                Some(GroupRow {
                    id: entry.group_id,
                    name: entry.name.clone(),
                    members,
                    member,
                    can_manage,
                    can_add: can_manage && member,
                })
            })
            .collect();
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        rows
    }

    /// Makes a group (owner only) with this account and these people in it, and this
    /// account as its manager.
    pub fn create_group(&mut self, name: &str, members: &[UserId]) -> Result<GroupId> {
        if self.profile.user_id != OWNER {
            bail!("only the owner can make groups");
        }
        if name.trim().is_empty() {
            bail!("a group needs a name");
        }
        self.check_server_has_groups()?;
        self.sync()?;
        if self.profile.find_group(name).is_ok() {
            bail!("there's already a group named {name:?}");
        }
        let me = self.profile.user_id;
        let group_id = GroupId::random();
        let secret = GroupSecret::generate();
        let mut entry = GroupEntry::first(group_id, name, &GroupKeys::derive(&secret), vec![me]);
        if self.membership()? {
            let mut everyone = members.to_vec();
            everyone.push(me);
            entry = entry.with_members(everyone);
        }
        entry.sign(me, &self.keys);
        let mut copies = vec![GroupMemberKey {
            user_id: me,
            wrapped_secret: self.keys.public().wrap_group_secret(&secret, group_id, 1)?,
        }];
        for &user in members {
            if copies.iter().any(|copy| copy.user_id == user) {
                continue;
            }
            let recipient = self.shareable_keys(user)?;
            copies.push(GroupMemberKey {
                user_id: user,
                wrapped_secret: recipient.wrap_group_secret(&secret, group_id, 1)?,
            });
        }
        let request = CreateGroupRequest {
            entry,
            members: copies,
        };
        let () = self.call(|client| client.post("/v1/groups", &request))??;
        self.sync()?;
        Ok(group_id)
    }

    /// Adds someone to a group (its managers in it), with a copy of its key: they get
    /// everything shared with it.
    pub fn add_to_group(&mut self, group: &str, user: UserId) -> Result<String> {
        self.check_server_has_groups()?;
        self.sync()?;
        let group_id = self.profile.find_group(group)?;
        let recipient = self.shareable_keys(user)?;
        let record = self
            .profile
            .groups
            .get(&group_id)
            .context("only people in a group can add others to it")?;
        let secret =
            self.keys
                .unwrap_group_secret(&record.wrapped_secret, group_id, record.generation)?;
        let generation = record.generation;
        let wrapped_secret = recipient.wrap_group_secret(&secret, group_id, generation)?;
        let entry = if self.membership()? {
            if !self.sign_group_members(group_id)? {
                bail!(
                    "nobody has signed for this group's members yet. The owner or one of \
                     its managers needs to open Keystead 0.15 or later first"
                );
            }
            let (_, latest) = self.profile.team_group(group_id)?;
            let mut members = latest.members.clone().unwrap_or_default();
            members.push(user);
            let mut entry = latest.next().with_members(members);
            entry.sign(self.profile.user_id, &self.keys);
            Some(entry)
        } else {
            None
        };
        let request = AddGroupMemberRequest {
            user_id: user,
            generation,
            wrapped_secret,
            entry: entry.clone(),
        };
        let path = format!("/v1/groups/{group_id}/members");
        let () = self.call(|client| client.post(&path, &request))??;
        if let Some(entry) = entry {
            self.keep_group_entry(group_id, entry);
            self.save()?;
        }
        Ok(self.profile.user_name(user))
    }

    /// Takes someone out of a group (the owner and its managers), or this account out of
    /// one (anyone). What the group gave them ends at once; then a manager in it gives the
    /// group a new key, and its folders too, so they can't read what's shared from now on.
    pub fn remove_from_group(&mut self, group: &str, user: UserId) -> Result<SyncSummary> {
        let group_id = self.profile.find_group(group)?;
        let path = format!("/v1/groups/{group_id}/members/{user}");
        let () = self.call(|client| client.delete(&path))??;
        // If this account manages the group, the new keys come from here.
        self.sync()
    }

    /// Deletes a group (the owner, or a manager in it). Its members lose what only it gave
    /// them; folders shared with it get new keys, here if this account manages them.
    pub fn delete_group(&mut self, group: &str) -> Result<SyncSummary> {
        self.check_server_has_groups()?;
        let group_id = self.profile.find_group(group)?;
        let path = format!("/v1/groups/{group_id}");
        match self.call(|client| client.delete::<()>(&path))? {
            Ok(()) => {}
            Err(Failure::Status { code: 405, .. }) => {
                bail!("the server is older than Keystead 0.10.0 and can't delete groups; update it")
            }
            Err(error) => return Err(error.into()),
        }
        self.sync()
    }

    pub fn rename_group(&mut self, group: &str, name: &str) -> Result<()> {
        if name.trim().is_empty() {
            bail!("a group needs a name");
        }
        self.sync()?;
        let group_id = self.profile.find_group(group)?;
        if self
            .profile
            .find_group(name)
            .is_ok_and(|other| other != group_id)
        {
            bail!("there's already a group named {name:?}");
        }
        self.change_group(group_id, |entry| entry.name = name.to_owned())
    }

    /// Makes someone in a group one of its managers, or not (the owner and its managers).
    pub fn set_group_manager(&mut self, group: &str, user: UserId, manager: bool) -> Result<()> {
        self.sync()?;
        let group_id = self.profile.find_group(group)?;
        let (info, _) = self.profile.team_group(group_id)?;
        if !info.members.contains(&user) {
            bail!("{} isn't in the group", self.profile.user_name(user));
        }
        self.change_group(group_id, |entry| {
            entry.managers.retain(|&other| other != user);
            if manager {
                entry.managers.push(user);
            }
        })
    }

    /// Signs and sends the next revision of a group's entry, with the same key.
    fn change_group(
        &mut self,
        group_id: GroupId,
        change: impl FnOnce(&mut GroupEntry),
    ) -> Result<()> {
        let (members, mut entry) = {
            let (info, latest) = self.profile.team_group(group_id)?;
            (info.members.clone(), latest.next())
        };
        // Managers who left the group stop being managers.
        entry.managers.retain(|manager| members.contains(manager));
        change(&mut entry);
        entry.sign(self.profile.user_id, &self.keys);
        let path = format!("/v1/groups/{group_id}");
        let request = UpdateGroupRequest { entry };
        let () = self.call(|client| client.put(&path, &request))??;
        self.sync()?;
        Ok(())
    }

    /// Gives a group a new secret after someone left, wrapped for each current member,
    /// with the old one sealed under it so what was shared with older keys still opens.
    fn rekey_group(&mut self, group_id: GroupId) -> Result<()> {
        let mut record = self
            .profile
            .groups
            .get(&group_id)
            .context("this account isn't in that group")?
            .clone();
        let old =
            self.keys
                .unwrap_group_secret(&record.wrapped_secret, group_id, record.generation)?;
        let signs = self.membership()?;
        let (members, entries) = {
            let (info, _) = self.profile.team_group(group_id)?;
            (info.members.clone(), info.entries.clone())
        };
        let latest = self.profile.verify_group(&entries)?;
        if latest.generation != record.generation {
            bail!("the group's key changed; sync and try again");
        }
        let secret = GroupSecret::generate();
        let group_keys = GroupKeys::derive(&secret);
        let mut entry = latest.next_generation(&group_keys);
        entry.managers.retain(|manager| members.contains(manager));
        // Who gets the new secret: those the group's signed entries name, less whoever
        // the server says has left. A name it adds is refused.
        if signs {
            if let Some(signed) = &latest.members
                && !members.iter().all(|user| signed.contains(user))
            {
                bail!(
                    "the server lists someone in this group whom its signed members don't. \
                     Don't trust this server"
                );
            }
            entry = entry.with_members(members.clone());
        }
        entry.sign(self.profile.user_id, &self.keys);
        let generation = entry.generation;
        let mut copies = Vec::new();
        for &user in &members {
            let recipient = self.profile.trusted_keys(user).with_context(|| {
                format!(
                    "{} isn't approved by the owner",
                    self.profile.user_name(user)
                )
            })?;
            copies.push(GroupMemberKey {
                user_id: user,
                wrapped_secret: recipient.wrap_group_secret(&secret, group_id, generation)?,
            });
        }
        let previous = group_keys.seal_previous(&old, group_id, generation);
        let request = GroupRekeyRequest {
            entry: entry.clone(),
            members: copies,
            previous: previous.clone(),
        };
        let path = format!("/v1/groups/{group_id}/rekey");
        let () = self.call(|client| client.post(&path, &request))??;
        record.entries = entries;
        record.entries.push(entry);
        record.generation = generation;
        record.wrapped_secret = self
            .keys
            .public()
            .wrap_group_secret(&secret, group_id, generation)?;
        record.chain.push(KeyLink {
            generation,
            previous,
        });
        self.profile.groups.insert(group_id, record);
        self.groups = self.profile.group_keyring(&self.keys);
        self.save()
    }

    /// Shares a folder with a group (folder managers): its key wrapped for the group's.
    pub fn share_folder_with_group(
        &mut self,
        folder: &str,
        group: &str,
        role: Role,
    ) -> Result<String> {
        self.check_server_has_groups()?;
        self.sync()?;
        let folder_id = self.profile.find_folder(&self.keys, &self.groups, folder)?;
        let group_id = self.profile.find_group(group)?;
        let key = self
            .profile
            .folder_key(&self.keys, &self.groups, folder_id)?;
        let signed = self.next_folder_entry(folder_id, |entry| entry.put_group(group_id, role))?;
        let (_, entry) = self.profile.team_group(group_id)?;
        let request = AddFolderGroupRequest {
            group_id,
            wrapped_key: entry.encryption.wrap_folder_key(&key, folder_id)?,
            group_generation: entry.generation,
            role,
            generation: self.profile.folders[&folder_id].generation,
            entry: signed.clone(),
        };
        let name = entry.name.clone();
        let path = format!("/v1/folders/{folder_id}/groups");
        let () = self.call(|client| client.post(&path, &request))??;
        if let Some(signed) = signed {
            self.keep_folder_entry(folder_id, signed);
            self.save()?;
        }
        Ok(name)
    }

    /// Changes a group's role in a folder (managers only).
    pub fn set_folder_group_role(&mut self, folder: &str, group: &str, role: Role) -> Result<()> {
        let folder_id = self.profile.find_folder(&self.keys, &self.groups, folder)?;
        let group_id = self.profile.find_group(group)?;
        let path = format!("/v1/folders/{folder_id}/groups/{group_id}");
        let entry = self.next_role_entry(folder_id, |entry| entry.put_group(group_id, role))?;
        let request = RoleRequest {
            role,
            entry: entry.clone(),
        };
        let () = self.call(|client| client.put(&path, &request))??;
        if let Some(entry) = entry {
            self.keep_folder_entry(folder_id, entry);
            self.save()?;
        }
        Ok(())
    }

    /// Stops sharing a folder with a group (managers only). Its members lose the folder,
    /// unless they have it another way; then the folder gets a new key.
    pub fn remove_group_from_folder(&mut self, folder: &str, group: &str) -> Result<SyncSummary> {
        let folder_id = self.profile.find_folder(&self.keys, &self.groups, folder)?;
        let group_id = self.profile.find_group(group)?;
        let path = format!("/v1/folders/{folder_id}/groups/{group_id}");
        let () = self.call(|client| client.delete(&path))??;
        self.sync()
    }

    /// Shares one login with a group, in a new version with a copy of its key for the
    /// group's key.
    pub fn share_item_with_group(
        &mut self,
        item_id: ItemId,
        group: &str,
        role: Role,
    ) -> Result<String> {
        self.check_server_has_groups()?;
        self.check_server_takes_items()?;
        self.sync()?;
        let group_id = self.profile.find_group(group)?;
        let entry = self.profile.team_group(group_id)?.1.clone();
        for _ in 0..3 {
            let current = self.live_item(item_id)?.clone();
            if current
                .keys
                .groups
                .iter()
                .any(|copy| copy.group_id == group_id)
            {
                bail!("this login is already shared with {}", entry.name);
            }
            let key = self.item_key(&current)?;
            let overview = current.open_overview(&key)?;
            let details = current.open_details(&key)?;
            let change = People::AddGroup(&entry, role);
            if let EditOutcome::Saved { .. } =
                self.save_version(&current, &overview, &details, change)?
            {
                self.save()?;
                return Ok(entry.name);
            }
        }
        self.save()?;
        bail!("others kept changing this login; try sharing it again")
    }

    /// Takes a group's copy of a login away (managers only), in a new version with a new
    /// key where possible.
    pub fn unshare_item_group(&mut self, item_id: ItemId, group: &str) -> Result<String> {
        self.check_server_takes_items()?;
        self.sync()?;
        let group_id = self.profile.find_group(group)?;
        let name = self.profile.group_name(group_id);
        for _ in 0..3 {
            let current = self.live_item(item_id)?.clone();
            if !current
                .keys
                .groups
                .iter()
                .any(|copy| copy.group_id == group_id)
            {
                bail!("this login isn't shared with {name}");
            }
            let key = self.item_key(&current)?;
            let overview = current.open_overview(&key)?;
            let details = current.open_details(&key)?;
            let change = People::DropGroup(group_id);
            if let EditOutcome::Saved { .. } =
                self.save_version(&current, &overview, &details, change)?
            {
                self.save()?;
                return Ok(name);
            }
        }
        self.save()?;
        bail!("others kept changing this login; try again")
    }

    /// Changes the role of a group a login is shared with (managers only).
    pub fn set_item_group_role(&mut self, item_id: ItemId, group: &str, role: Role) -> Result<()> {
        let group_id = self.profile.find_group(group)?;
        let path = format!("/v1/items/{item_id}/groups/{group_id}");
        let () = self.call(|client| client.put(&path, &RoleRequest { role, entry: None }))??;
        Ok(())
    }

    fn group_share_rows(&self, shares: &[GroupShare]) -> Vec<GroupShareRow> {
        shares
            .iter()
            .map(|share| GroupShareRow {
                group_id: share.group_id,
                name: self.profile.group_name(share.group_id),
                role: share.role,
                mine: self.profile.groups.contains_key(&share.group_id),
            })
            .collect()
    }

    fn member_rows(&self, members: Members) -> Vec<MemberRow> {
        members
            .members
            .into_iter()
            .map(|member| MemberRow {
                user_id: member.user_id,
                name: self.profile.user_name(member.user_id),
                role: member.role,
                me: member.user_id == self.profile.user_id,
            })
            .collect()
    }

    /// An approved, current member's keys, for sharing with them.
    fn shareable_keys(&self, user: UserId) -> Result<AccountPublicKeys> {
        let name = self.profile.user_name(user);
        if user == self.profile.user_id {
            bail!("that's you");
        }
        if self.profile.is_removed(user) {
            bail!("{name} was removed from the team");
        }
        self.profile
            .trusted_keys(user)
            .with_context(|| format!("{name} isn't approved by the owner yet"))
    }

    fn forget_folder(&mut self, folder_id: FolderId) {
        // Keep the folder's items that were also shared with us, or a group of ours, directly.
        let me = self.profile.user_id;
        // Its first key's fingerprint stays, to recognise the folder if it comes back.
        self.pin_folder(folder_id);
        self.profile.folders.remove(&folder_id);
        let groups = &self.groups;
        self.profile.items.retain(|_, item| {
            item.folder_id != Some(folder_id) || item.reaches_directly(me, groups)
        });
    }

    /// Each folder's name and this account's role in it, from the local copy.
    pub fn folder_roles(&self) -> Result<Vec<(String, Role)>> {
        self.profile
            .folders
            .keys()
            .map(|&folder_id| {
                Ok((
                    self.profile
                        .folder_name(&self.keys, &self.groups, folder_id)?,
                    self.profile.folder_role(folder_id),
                ))
            })
            .collect()
    }

    /// Folder names, from the local copy.
    pub fn folders(&self) -> Result<Vec<String>> {
        let mut names = self
            .profile
            .folders
            .keys()
            .map(|&folder_id| {
                self.profile
                    .folder_name(&self.keys, &self.groups, folder_id)
            })
            .collect::<Result<Vec<_>>>()?;
        names.sort();
        Ok(names)
    }

    /// Every live item's searchable fields, from the local copy. Passwords stay encrypted.
    pub fn list(&self) -> Result<Vec<ItemRow>> {
        let me = self.profile.user_id;
        let mut folders = HashMap::new();
        let mut rows = Vec::new();
        for item in self.openable_items() {
            let folder = match item.folder_id {
                Some(folder_id) if self.profile.folders.contains_key(&folder_id) => {
                    // Each folder key is unwrapped once per listing, not once per item.
                    if let Entry::Vacant(slot) = folders.entry(folder_id) {
                        let keys = self
                            .profile
                            .folder_keys(&self.keys, &self.groups, folder_id)?;
                        let name = self
                            .profile
                            .folder_name(&self.keys, &self.groups, folder_id)?;
                        slot.insert((keys, name));
                    }
                    folders.get(&folder_id)
                }
                _ => None,
            };
            let no_keys = Vec::new();
            let folder_keys = folder.map_or(&no_keys, |(keys, _)| keys);
            // One that can't be opened here (a copy left behind by a move, say) is left
            // out rather than failing the whole list.
            let Ok(key) = unlock_with(item, folder_keys, &self.keys, me, &self.groups)
                .or_else(|error| self.recovered_owner_key(item).ok_or(error))
            else {
                continue;
            };
            let overview = item.open_overview(&key)?;
            rows.push(ItemRow {
                id: item.id,
                folder: folder.map(|(_, name)| name.clone()),
                name: overview.name,
                username: overview.username,
                url: overview.url,
                owner: item
                    .owner
                    .filter(|&owner| owner != me)
                    .map(|owner| self.profile.user_name(owner)),
                shared_with: item
                    .keys
                    .people
                    .iter()
                    .filter(|person| person.user_id != me)
                    .map(|person| self.profile.user_name(person.user_id))
                    .collect(),
                shared_with_groups: item
                    .keys
                    .groups
                    .iter()
                    .filter(|copy| self.profile.group_exists(copy.group_id))
                    .map(|copy| self.profile.group_name(copy.group_id))
                    .collect(),
                shared_with_me: folder.is_none() && item.owner != Some(me),
                role: self.profile.item_role(item),
                has_one_time_code: overview.one_time_code,
            });
        }
        rows.sort_by(|a, b| (&a.folder, &a.name).cmp(&(&b.folder, &b.name)));
        Ok(rows)
    }

    /// Live items this build can open; ones a newer Keystead wrote are left out (see
    /// [`too_new`](Self::too_new)) rather than failing the whole list.
    fn openable_items(&self) -> impl Iterator<Item = &EncryptedItem> {
        self.profile
            .items
            .values()
            .filter(|item| !item.deleted && item.format <= ITEM_FORMAT)
    }

    /// How many logins a newer Keystead wrote, in a format this build can't open. They
    /// show up again after updating.
    pub fn too_new(&self) -> usize {
        self.profile
            .items
            .values()
            .filter(|item| !item.deleted && item.format > ITEM_FORMAT)
            .count()
    }

    /// The login's current one-time code, if it has one codes come from.
    pub fn one_time_code(&self, item_id: ItemId) -> Result<Option<OneTimeCode>> {
        let (_, details) = self.open_item(item_id)?;
        if details.otp.is_empty() {
            return Ok(None);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("the clock is before 1970")?
            .as_secs();
        Ok(Some(otp::code_at(&details.otp, now)?))
    }

    /// Passwords to change, from the last sync: for each login this account can change, the
    /// people who lost access to it while its password stayed the same. Most recent first.
    /// Saving a new password, or deleting the login, takes it off the list.
    pub fn to_change(&self) -> Result<Vec<ToChangeRow>> {
        let mut folders = HashMap::new();
        let mut rows = Vec::new();
        for exposure in &self.profile.exposures {
            let Some(item) = self
                .profile
                .items
                .get(&exposure.item_id)
                .filter(|item| !item.deleted && item.format <= ITEM_FORMAT)
            else {
                continue;
            };
            if self.profile.item_role(item) < Role::Edit {
                continue;
            }
            let folder = match item.folder_id {
                Some(folder_id) if self.profile.folders.contains_key(&folder_id) => {
                    if let Entry::Vacant(slot) = folders.entry(folder_id) {
                        slot.insert(self.profile.folder_name(
                            &self.keys,
                            &self.groups,
                            folder_id,
                        )?);
                    }
                    folders.get(&folder_id).cloned()
                }
                _ => None,
            };
            rows.push(ToChangeRow {
                item_id: item.id,
                name: item.open_overview(&self.item_key(item)?)?.name,
                folder,
                user_id: exposure.user_id,
                user_name: self.profile.user_name(exposure.user_id),
                since: exposure.since,
            });
        }
        rows.sort_by(|a, b| {
            (b.since, &a.user_name, &a.folder, &a.name).cmp(&(
                a.since,
                &b.user_name,
                &b.folder,
                &b.name,
            ))
        });
        Ok(rows)
    }

    /// A login's history: the current version and the earlier ones the server keeps (up to
    /// ten), newest first, fetched fresh. Editors and managers only. Versions whose
    /// signature doesn't check out are left out, so a server can't slip any in.
    pub fn history(&mut self, item_id: ItemId) -> Result<Vec<HistoryRow>> {
        let path = format!("/v1/items/{item_id}/history");
        let list: ItemHistory = match self.call(|client| client.get(&path, &[]))? {
            Ok(list) => list,
            Err(Failure::Status { code: 404, .. }) if self.server_version()? < (0, 7) => {
                bail!(NEEDS_0_7)
            }
            Err(error) => return Err(error.into()),
        };
        let mut versions = Vec::new();
        for saved in list.versions {
            let item = saved.item;
            let signed =
                self.profile.signed_by_author(&item) && self.profile.author_could_save(&item);
            if item.id != item_id || item.deleted || item.format > ITEM_FORMAT || !signed {
                continue;
            }
            let opened = self.open_version(&item).ok();
            versions.push((saved.saved_at, item, opened));
        }
        let rows = versions
            .iter()
            .enumerate()
            .map(|(index, (saved_at, item, opened))| {
                let before = versions
                    .get(index + 1)
                    .and_then(|(_, _, opened)| opened.as_ref());
                let changes = match (opened, before) {
                    (Some(this), Some(before)) => changes(before, this),
                    (Some(_), None) if item.version == 1 => vec!["created".to_owned()],
                    _ => Vec::new(),
                };
                HistoryRow {
                    version: item.version,
                    author: self.profile.user_name(item.author),
                    saved_at: *saved_at,
                    current: index == 0,
                    readable: opened.is_some(),
                    changes,
                }
            })
            .collect();
        self.history.insert(
            item_id,
            versions.into_iter().map(|(_, item, _)| item).collect(),
        );
        Ok(rows)
    }

    /// Logins deleted in the last 30 days that this account can change, newest first,
    /// fetched fresh; `None` if the server is older than 0.9.0 and keeps none. Deletion
    /// markers and last versions whose signatures don't check out are left out.
    pub fn deleted(&mut self) -> Result<Option<Vec<DeletedRow>>> {
        let list: DeletedItems = match self.call(|client| client.get("/v1/deleted", &[]))? {
            Ok(list) => list,
            Err(Failure::Status { code: 404, .. }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let signed = |item: &EncryptedItem| {
            self.profile.signed_by_author(item) && self.profile.author_could_save(item)
        };
        let mut rows = Vec::new();
        let mut kept = HashMap::new();
        for entry in list.items {
            let (deleted, last) = (entry.deleted, entry.last);
            if !deleted.deleted
                || last.deleted
                || last.id != deleted.id
                || last.version >= deleted.version
                || last.format > ITEM_FORMAT
                || !signed(&deleted)
                || !signed(&last)
            {
                continue;
            }
            let Ok((overview, _)) = self.open_version(&last) else {
                continue;
            };
            let folder = last
                .folder_id
                .filter(|folder_id| self.profile.folders.contains_key(folder_id))
                .map(|folder_id| {
                    self.profile
                        .folder_name(&self.keys, &self.groups, folder_id)
                })
                .transpose()?;
            rows.push(DeletedRow {
                item_id: last.id,
                name: overview.name,
                username: overview.username,
                folder,
                deleted_by: self.profile.user_name(deleted.author),
                deleted_at: entry.deleted_at,
                kept_until: entry.deleted_at + DELETED_KEPT_SECONDS,
            });
            kept.insert(last.id, last);
        }
        self.deleted = kept;
        Ok(Some(rows))
    }

    /// Brings back a login from the list last fetched with [`deleted`](Self::deleted): its
    /// last version, saved as a new one, so everyone who had it gets it again.
    pub fn undelete(&mut self, item_id: ItemId) -> Result<EditOutcome> {
        let last = self
            .deleted
            .get(&item_id)
            .cloned()
            .context("that login isn't in Recently Deleted; look at it again")?;
        let (overview, details) = self.open_version(&last)?;
        self.check_server_takes_items()?;
        let details = self.with_one_time_code(details)?;
        self.sync()?;
        let current = self
            .profile
            .items
            .get(&item_id)
            .filter(|item| item.deleted)
            .cloned()
            .context("that login isn't deleted any more")?;
        let outcome = self.save_version_with(&current, &overview, &details, People::Same, false)?;
        self.deleted.remove(&item_id);
        self.save()?;
        Ok(outcome)
    }

    /// Deletes a login for good now, instead of after 30 days: the server forgets its
    /// earlier versions, so it can't be brought back.
    pub fn purge(&mut self, item_id: ItemId) -> Result<()> {
        let path = format!("/v1/deleted/{item_id}");
        match self.call(|client| client.delete::<()>(&path))? {
            Ok(()) => {}
            Err(Failure::Status { code: 404, .. }) if self.server_version()? < (0, 9) => {
                bail!(NEEDS_0_9)
            }
            Err(error) => return Err(error.into()),
        }
        self.deleted.remove(&item_id);
        Ok(())
    }

    /// One version from the history last fetched with [`history`](Self::history), decrypted.
    pub fn history_version(&self, item_id: ItemId, version: u64) -> Result<(Overview, Details)> {
        let item = self
            .history
            .get(&item_id)
            .and_then(|versions| versions.iter().find(|item| item.version == version))
            .context("that version isn't in the history; look at the history again")?;
        self.open_version(item)
    }

    /// Brings back an earlier version's name, username, website, password, notes and
    /// one-time code, as a new version on top of the latest. Who has the login stays as it
    /// is. Passwords to change stay listed, as the old password isn't a new one.
    pub fn restore(&mut self, item_id: ItemId, version: u64) -> Result<EditOutcome> {
        let (overview, details) = self.history_version(item_id, version)?;
        self.check_server_takes_items()?;
        let details = self.with_one_time_code(details)?;
        self.sync()?;
        let current = self.live_item(item_id)?.clone();
        if current.version == version {
            bail!("that's already the current version");
        }
        let outcome = self.save_version_with(&current, &overview, &details, People::Same, false)?;
        self.save()?;
        Ok(outcome)
    }

    fn open_version(&self, item: &EncryptedItem) -> Result<(Overview, Details)> {
        let key = self.item_key(item)?;
        Ok((item.open_overview(&key)?, item.open_details(&key)?))
    }

    /// The server's version, as (major, minor).
    fn server_version(&self) -> Result<(u64, u64)> {
        let health: Health = Client::new(&self.profile.server).get("/v1/health", &[])?;
        let mut parts = health
            .version
            .split('.')
            .map(|part| part.parse().unwrap_or(0));
        Ok((parts.next().unwrap_or(0), parts.next().unwrap_or(0)))
    }

    /// Starts adding a device to this account: returns the line to copy to it. The new
    /// device then shows a code, which goes to [`send_account_to_new_device`](Self::send_account_to_new_device).
    /// It expires after ten minutes.
    pub fn start_adding_device(&mut self) -> Result<DeviceSetupLine> {
        self.cancel_adding_device();
        let transfer: DeviceTransfer =
            match self.call(|client| client.post_empty("/v1/device-transfers"))? {
                Ok(transfer) => transfer,
                Err(Failure::Status { code: 404, .. }) => bail!(NEEDS_0_8),
                Err(error) => return Err(error.into()),
            };
        self.adding_device = Some((transfer.id, transfer.token.clone()));
        Ok(DeviceSetupLine {
            server: self.profile.server.clone(),
            token: transfer.token,
            owner_fingerprint: self.profile.owner.fingerprint(),
        })
    }

    /// The new device's name, once it has joined with the setup line.
    pub fn new_device(&mut self) -> Result<Option<String>> {
        let state = self.transfer_state()?;
        Ok(state.transfer_key.and(state.device_name))
    }

    /// Sends this account's secret to the new device, sealed for its one-time key, if
    /// `code` is the one it shows. Returns its name. The new device then finishes on its
    /// own.
    pub fn send_account_to_new_device(
        &mut self,
        code: &str,
        secret: &AccountSecret,
    ) -> Result<String> {
        let (id, token) = self
            .adding_device
            .clone()
            .context("start adding a device first")?;
        let state = self.transfer_state()?;
        let key = state
            .transfer_key
            .context("the new device hasn't joined yet: paste the setup line into it first")?;
        let tidy = |code: &str| {
            code.chars()
                .filter(char::is_ascii_alphanumeric)
                .collect::<String>()
                .to_ascii_lowercase()
        };
        if tidy(code) != tidy(&transfer_code(&token, &key)) {
            bail!(
                "that isn't the code: check it against your new device. If you typed exactly \
                 what it shows, stop: something between the two devices isn't passing things \
                 on honestly"
            );
        }
        if AccountKeys::derive(secret).public() != self.keys.public() {
            bail!("that secret isn't this account's");
        }
        let request = SendAccountSecretRequest {
            wrapped_secret: secret.seal_for_new_device(&key, &token)?,
        };
        let path = format!("/v1/device-transfers/{id}/secret");
        let () = self.call(|client| client.put(&path, &request))??;
        self.adding_device = None;
        Ok(state.device_name.unwrap_or_else(|| "the new device".into()))
    }

    /// Stops waiting for a new device; the setup line stops working.
    pub fn cancel_adding_device(&mut self) {
        if let Some((id, _)) = self.adding_device.take() {
            let path = format!("/v1/device-transfers/{id}");
            // Best effort: it expires by itself anyway.
            let _ = self.call(|client| client.delete::<()>(&path));
        }
    }

    fn transfer_state(&mut self) -> Result<DeviceTransferState> {
        let (id, _) = self
            .adding_device
            .clone()
            .context("start adding a device first")?;
        let path = format!("/v1/device-transfers/{id}");
        match self.call(|client| client.get(&path, &[]))? {
            Ok(state) => Ok(state),
            Err(Failure::Status { code: 404, .. }) => {
                self.adding_device = None;
                bail!("adding a device expired after ten minutes; start again")
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Takes a login off the list of passwords to change for one person: someone who can
    /// change it decided it doesn't need changing.
    pub fn dismiss(&mut self, item_id: ItemId, user: UserId) -> Result<()> {
        let path = format!("/v1/items/{item_id}/exposures/{user}");
        let () = self.call(|client| client.delete(&path))??;
        self.profile
            .exposures
            .retain(|exposure| (exposure.item_id, exposure.user_id) != (item_id, user));
        self.save()
    }

    /// Takes every login off the list for one person, as when they only moved teams.
    /// Returns how many.
    pub fn dismiss_all(&mut self, user: UserId) -> Result<usize> {
        let items: Vec<ItemId> = self
            .to_change()?
            .into_iter()
            .filter(|row| row.user_id == user)
            .map(|row| row.item_id)
            .collect();
        for &item_id in &items {
            self.dismiss(item_id, user)?;
        }
        Ok(items.len())
    }

    pub fn find_item(&self, name: &str, folder: Option<&str>) -> Result<ItemId> {
        let folder_id = folder
            .map(|folder| self.profile.find_folder(&self.keys, &self.groups, folder))
            .transpose()?;
        let mut matches = Vec::new();
        for item in self.openable_items() {
            if folder_id.is_some_and(|folder_id| Some(folder_id) != item.folder_id) {
                continue;
            }
            let key = self.item_key(item)?;
            if item.open_overview(&key)?.name == name {
                matches.push(item.id);
            }
        }
        match matches.as_slice() {
            [item_id] => Ok(*item_id),
            [] => bail!("no login named {name:?}"),
            _ => bail!("several logins are named {name:?}; add --folder"),
        }
    }

    /// Decrypts one item, details included.
    pub fn open_item(&self, item_id: ItemId) -> Result<(Overview, Details)> {
        let item = self.live_item(item_id)?;
        let key = self.item_key(item)?;
        Ok((item.open_overview(&key)?, item.open_details(&key)?))
    }

    /// Adds a login to a folder, or with no folder as your own: only you can open it until
    /// you share it.
    pub fn add(
        &mut self,
        folder: Option<&str>,
        overview: Overview,
        details: Details,
    ) -> Result<ItemId> {
        self.check_server_takes_items()?;
        let details = self.with_one_time_code(details)?;
        self.sync()?;
        let folder_id = folder
            .map(|folder| self.profile.find_folder(&self.keys, &self.groups, folder))
            .transpose()?;
        let id = self.put_new(folder_id, &overview, &details)?;
        self.save()?;
        Ok(id)
    }

    /// Saves a new login in a folder, or as this account's own; the caller saves the
    /// profile.
    fn put_new(
        &mut self,
        folder_id: Option<FolderId>,
        overview: &Overview,
        details: &Details,
    ) -> Result<ItemId> {
        if let Some(folder_id) = folder_id {
            self.folder_ready(folder_id)?;
        }
        let me = self.profile.user_id;
        let id = ItemId::random();
        let key = ItemKey::generate();
        let mut keys = ItemKeys::default();
        let at = match folder_id {
            Some(folder_id) => {
                let folder_key = self
                    .profile
                    .folder_key(&self.keys, &self.groups, folder_id)?;
                keys.folder = Some(key.seal_for_folder(id, folder_id, &folder_key));
                ItemVersion {
                    id,
                    folder_id: Some(folder_id),
                    owner: None,
                    version: 1,
                    author: me,
                }
            }
            None => {
                keys.owner = Some(key.seal_for_owner(id, me, &self.keys));
                ItemVersion {
                    id,
                    folder_id: None,
                    owner: Some(me),
                    version: 1,
                    author: me,
                }
            }
        };
        let request = PutItemRequest {
            base_version: None,
            item: EncryptedItem::seal(at, &key, keys, &self.keys, overview, details)?,
            roles: Vec::new(),
            group_roles: Vec::new(),
            password_changed: false,
        };
        let path = format!("/v1/items/{id}");
        let saved: EncryptedItem = self.call(|client| client.put(&path, &request))??;
        self.profile.items.insert(id, kept(&request.item, saved)?);
        Ok(id)
    }

    /// Every login this account can open, from the local copy, in a KeePass file (.kdbx)
    /// encrypted with `passphrase`: each folder a group (nested by name, even when empty),
    /// and logins outside folders at the top. It opens in KeePassXC or KeePass and
    /// imports back. Built in memory; the caller saves it.
    pub fn export_kdbx(&self, passphrase: &str) -> Result<KdbxExport> {
        if passphrase.chars().count() < MIN_EXPORT_PASSPHRASE {
            bail!(
                "use a passphrase of at least {MIN_EXPORT_PASSPHRASE} characters: anyone with \
                 the file can try to guess it"
            );
        }
        let mut writer = KdbxWriter::new();
        let mut folders = HashMap::new();
        for &folder_id in self.profile.folders.keys() {
            let name = self
                .profile
                .folder_name(&self.keys, &self.groups, folder_id)?;
            writer.folder(&name);
            folders.insert(folder_id, name);
        }
        let mut left_out = self.too_new();
        for item in self.openable_items() {
            let folder = item
                .folder_id
                .and_then(|folder_id| folders.get(&folder_id))
                .map(String::as_str);
            let opened = self
                .item_key(item)
                .and_then(|key| Ok((item.open_overview(&key)?, item.open_details(&key)?)));
            match opened {
                Ok((overview, details)) => writer.add(folder, &overview, &details),
                Err(_) => left_out += 1,
            }
        }
        let logins = writer.logins();
        Ok(KdbxExport {
            file: writer.finish(passphrase)?,
            logins,
            left_out,
        })
    }

    /// What importing these logins would do, after a sync: which folders they go into
    /// (existing ones you can edit, or new ones), how many stay your own, and what's left
    /// out. Logins without a folder go into `unfiled` if given, or stay your own.
    pub fn plan_import(
        &mut self,
        logins: &[ImportedLogin],
        unfiled: Option<&str>,
    ) -> Result<ImportPlan> {
        self.sync()?;
        Ok(self.plan(logins, unfiled)?.0)
    }

    /// Imports these logins as [`plan_import`](Self::plan_import) says: creates the new
    /// folders and adds every login that isn't left out. Folders are created only for you;
    /// share them afterwards.
    pub fn import(
        &mut self,
        logins: &[ImportedLogin],
        unfiled: Option<&str>,
    ) -> Result<ImportSummary> {
        self.check_server_takes_items()?;
        if logins.iter().any(|login| !login.details.otp.is_empty()) {
            let health: Health = Client::new(&self.profile.server).get("/v1/health", &[])?;
            if health.item_format < 4 {
                bail!(NEEDS_0_6);
            }
        }
        self.sync()?;
        let (plan, destinations) = self.plan(logins, unfiled)?;
        let mut summary = ImportSummary {
            duplicates: plan.duplicates,
            left_out: plan.view_only.iter().map(|(_, count)| count).sum(),
            ..ImportSummary::default()
        };
        let mut folder_ids: HashMap<String, FolderId> = HashMap::new();
        for (login, destination) in logins.iter().zip(destinations) {
            let folder_id = match destination {
                Destination::LeftOut => continue,
                Destination::Own => None,
                Destination::Folder(folder_id) => Some(folder_id),
                Destination::NewFolder(name) => Some(match folder_ids.get(&name) {
                    Some(&folder_id) => folder_id,
                    None => {
                        let folder_id = self.create_folder(&name)?;
                        summary.folders_created += 1;
                        folder_ids.insert(name, folder_id);
                        folder_id
                    }
                }),
            };
            let mut overview = login.overview.clone();
            if overview.name.trim().is_empty() {
                overview.name = "Untitled".to_owned();
            }
            self.put_new(folder_id, &overview, &login.details)?;
            summary.added += 1;
        }
        self.save()?;
        Ok(summary)
    }

    /// Where each login goes, and the plan that adds up to.
    fn plan(
        &self,
        logins: &[ImportedLogin],
        unfiled: Option<&str>,
    ) -> Result<(ImportPlan, Vec<Destination>)> {
        let me = self.profile.user_id;
        // Existing folders by name: one you can edit if there's such a one, else any.
        let mut folders: HashMap<String, (FolderId, Role)> = HashMap::new();
        for &folder_id in self.profile.folders.keys() {
            let name = self
                .profile
                .folder_name(&self.keys, &self.groups, folder_id)?;
            let role = self.profile.folder_role(folder_id);
            let better = folders.get(&name).is_none_or(|&(_, known)| role > known);
            if better {
                folders.insert(name, (folder_id, role));
            }
        }
        // What's already here, to leave out: by folder (or your own), name and username.
        let mut existing: HashSet<(Option<FolderId>, String, String)> = HashSet::new();
        for item in self.openable_items() {
            let mine = item.folder_id.is_none() && item.owner == Some(me);
            if item.folder_id.is_none() && !mine {
                continue;
            }
            let overview = item.open_overview(&self.item_key(item)?)?;
            existing.insert((item.folder_id, overview.name, overview.username));
        }

        let mut plan = ImportPlan::default();
        let mut counts: Vec<(String, bool, usize)> = Vec::new();
        let mut view_only: Vec<(String, usize)> = Vec::new();
        let mut destinations = Vec::with_capacity(logins.len());
        for login in logins {
            let folder = login.folder.as_deref().or(unfiled);
            let destination = match folder {
                None => Destination::Own,
                Some(name) => match folders.get(name) {
                    Some(&(_, Role::View)) => Destination::LeftOut,
                    Some(&(folder_id, _)) => Destination::Folder(folder_id),
                    None => Destination::NewFolder(name.to_owned()),
                },
            };
            let place = match destination {
                Destination::Folder(folder_id) => Some(Some(folder_id)),
                Destination::Own => Some(None),
                _ => None,
            };
            let duplicate = place.is_some_and(|folder_id| {
                existing.contains(&(
                    folder_id,
                    login.overview.name.clone(),
                    login.overview.username.clone(),
                ))
            });
            let destination = if duplicate {
                plan.duplicates += 1;
                Destination::LeftOut
            } else {
                destination
            };
            match (&destination, folder) {
                (Destination::LeftOut, Some(name)) if !duplicate => {
                    match view_only.iter_mut().find(|(known, _)| known == name) {
                        Some((_, count)) => *count += 1,
                        None => view_only.push((name.to_owned(), 1)),
                    }
                }
                (Destination::Own, _) => plan.own += 1,
                (Destination::Folder(_) | Destination::NewFolder(_), Some(name)) => {
                    let new = matches!(destination, Destination::NewFolder(_));
                    match counts.iter_mut().find(|(known, _, _)| known == name) {
                        Some((_, _, count)) => *count += 1,
                        None => counts.push((name.to_owned(), new, 1)),
                    }
                }
                _ => {}
            }
            if !matches!(destination, Destination::LeftOut) && !login.details.otp.is_empty() {
                plan.one_time_codes += 1;
            }
            destinations.push(destination);
        }
        counts.sort();
        plan.folders = counts
            .into_iter()
            .map(|(name, new, logins)| ImportFolder { name, new, logins })
            .collect();
        plan.view_only = view_only;
        Ok((plan, destinations))
    }

    /// Saves new contents for a login (name, username, website, tags, password and notes)
    /// on top of the latest version this device has seen. Its folder and who can open it
    /// stay as they are. Start from `open_item` to keep what isn't changing.
    pub fn update(
        &mut self,
        item_id: ItemId,
        overview: &Overview,
        details: &Details,
    ) -> Result<EditOutcome> {
        if overview.name.trim().is_empty() {
            bail!("a login needs a name");
        }
        self.check_server_takes_items()?;
        let details = self.with_one_time_code(details.clone())?;
        self.sync()?;
        let current = self.live_item(item_id)?.clone();
        let outcome = self.save_version(&current, overview, &details, People::Same)?;
        self.save()?;
        Ok(outcome)
    }

    /// Deletes a login for everyone who can open it: a signed version marked deleted, which
    /// everyone's sync then removes. If someone saved a newer version first, nothing is
    /// deleted and the local copy takes their version, so it can be looked at first.
    pub fn delete(&mut self, item_id: ItemId) -> Result<EditOutcome> {
        self.check_server_takes_items()?;
        self.sync()?;
        let current = self.live_item(item_id)?.clone();
        let (_, keys) = self.next_keys(&current)?;
        let tombstone = EncryptedItem::tombstone(self.next_version(&current), keys, &self.keys);
        let outcome = self.put_version(&current, tombstone, Vec::new(), Vec::new(), false)?;
        self.save()?;
        Ok(outcome)
    }

    /// Saves a new password on top of the latest version this device has seen.
    pub fn edit(&mut self, item_id: ItemId, password: &str) -> Result<EditOutcome> {
        self.check_server_takes_items()?;
        self.sync()?;
        let current = self.live_item(item_id)?.clone();
        let key = self.item_key(&current)?;
        let overview = current.open_overview(&key)?;
        let mut details = current.open_details(&key)?;
        details.password = password.to_owned();
        let outcome = self.save_version(&current, &overview, &details, People::Same)?;
        self.save()?;
        Ok(outcome)
    }

    /// Moves a login to another folder, or out of folders as your own (`None`), in a new
    /// version with a new key. Everyone who had it only through its old folder loses it,
    /// and its password goes on their passwords to change; people and groups it's shared
    /// with directly keep it. A login in no folder can only be moved by its owner.
    pub fn move_item(&mut self, item_id: ItemId, to: Option<&str>) -> Result<EditOutcome> {
        self.check_server_takes_items()?;
        if self.server_version()? < (0, 12) {
            bail!(NEEDS_0_12);
        }
        self.sync()?;
        let current = self.live_item(item_id)?.clone();
        let me = self.profile.user_id;
        if current.owner.is_some_and(|owner| owner != me) {
            bail!("only its owner can move a login that's in no folder");
        }
        let destination = to
            .map(|folder| self.profile.find_folder(&self.keys, &self.groups, folder))
            .transpose()?;
        if destination == current.folder_id && (destination.is_some() || current.owner == Some(me))
        {
            bail!("it's already there");
        }
        if let Some(folder_id) = destination
            && self.profile.folder_role(folder_id) < Role::Edit
        {
            bail!("you can only view that folder, so you can't move logins into it");
        }
        if self.profile.item_role(&current) < Role::Edit {
            bail!("you can only view this login, so you can't move it");
        }
        let old_key = self.item_key(&current)?;
        let overview = current.open_overview(&old_key)?;
        let details = current.open_details(&old_key)?;
        if let Some(folder_id) = destination {
            self.folder_ready(folder_id)?;
        }

        let key = ItemKey::generate();
        let mut keys = ItemKeys::default();
        match destination {
            Some(folder_id) => {
                let folder_key = self
                    .profile
                    .folder_key(&self.keys, &self.groups, folder_id)?;
                keys.folder = Some(key.seal_for_folder(item_id, folder_id, &folder_key));
            }
            None => keys.owner = Some(key.seal_for_owner(item_id, me, &self.keys)),
        }
        // People and groups it's shared with keep it; the new owner needs no copy of their
        // own.
        for person in &current.keys.people {
            if self.profile.is_removed(person.user_id)
                || (destination.is_none() && person.user_id == me)
            {
                continue;
            }
            let recipient = self
                .profile
                .trusted_keys(person.user_id)
                .context("someone this login is shared with isn't approved")?;
            keys.people.push(PersonKey {
                user_id: person.user_id,
                wrapped_key: recipient.wrap_item_key(&key, item_id)?,
            });
        }
        for copy in &current.keys.groups {
            if !self.profile.group_exists(copy.group_id) {
                continue;
            }
            let (_, entry) = self.profile.team_group(copy.group_id)?;
            keys.groups.push(GroupKeyCopy {
                group_id: copy.group_id,
                generation: entry.generation,
                wrapped_key: entry.encryption.wrap_item_key(&key, item_id)?,
            });
        }
        let at = ItemVersion {
            id: item_id,
            folder_id: destination,
            owner: destination.is_none().then_some(me),
            version: current.version + 1,
            author: me,
        };
        let item = EncryptedItem::seal(at, &key, keys, &self.keys, &overview, &details)?;
        let outcome = self.put_version(&current, item, Vec::new(), Vec::new(), false)?;
        self.save()?;
        Ok(outcome)
    }

    /// Shares one login with an approved user by giving them a copy of its key, in a new
    /// version. They see that login only, not the rest of its folder.
    pub fn share_item(&mut self, item_id: ItemId, user: UserId, role: Role) -> Result<String> {
        self.check_server_takes_items()?;
        self.sync()?;
        let name = self.profile.user_name(user);
        let recipient = self.shareable_keys(user)?;
        // Sharing doesn't depend on what the login says, so if someone saved first, share
        // their version instead.
        for _ in 0..3 {
            let current = self.live_item(item_id)?.clone();
            if current.reaches_directly(user, &GroupKeyring::default()) {
                bail!("this login is already shared with {name}");
            }
            let key = self.item_key(&current)?;
            let overview = current.open_overview(&key)?;
            let details = current.open_details(&key)?;
            let change = People::Add(user, &recipient, role);
            if let EditOutcome::Saved { .. } =
                self.save_version(&current, &overview, &details, change)?
            {
                self.save()?;
                return Ok(name);
            }
        }
        self.save()?;
        bail!("others kept changing this login; try sharing it again")
    }

    /// Takes away someone's copy of a login (managers only), in a new version with a new
    /// key where possible, and their devices drop it.
    pub fn unshare_item(&mut self, item_id: ItemId, user: UserId) -> Result<String> {
        self.check_server_takes_items()?;
        self.sync()?;
        let name = self.profile.user_name(user);
        for _ in 0..3 {
            let current = self.live_item(item_id)?.clone();
            if !current
                .keys
                .people
                .iter()
                .any(|person| person.user_id == user)
            {
                bail!("this login isn't shared with {name} directly");
            }
            let key = self.item_key(&current)?;
            let overview = current.open_overview(&key)?;
            let details = current.open_details(&key)?;
            if let EditOutcome::Saved { .. } =
                self.save_version(&current, &overview, &details, People::Drop(user))?
            {
                self.save()?;
                return Ok(name);
            }
        }
        self.save()?;
        bail!("others kept changing this login; try again")
    }

    /// Who has a login directly: its owner and everyone it's shared with, with roles.
    pub fn item_people(&mut self, item_id: ItemId) -> Result<Vec<MemberRow>> {
        Ok(self.item_sharing(item_id)?.0)
    }

    /// Who has a login directly, and the groups it's shared with, with roles.
    pub fn item_sharing(
        &mut self,
        item_id: ItemId,
    ) -> Result<(Vec<MemberRow>, Vec<GroupShareRow>)> {
        let path = format!("/v1/items/{item_id}/people");
        let members: Members = self.call(|client| client.get(&path, &[]))??;
        let groups = self.group_share_rows(&members.groups);
        Ok((self.member_rows(members), groups))
    }

    /// Changes the role of someone a login is shared with directly (managers only).
    pub fn set_item_role(&mut self, item_id: ItemId, user: UserId, role: Role) -> Result<()> {
        let path = format!("/v1/items/{item_id}/people/{user}");
        let () = self.call(|client| client.put(&path, &RoleRequest { role, entry: None }))??;
        Ok(())
    }

    /// Saves the next version of `current` with these contents, adding or dropping one
    /// person's or group's key copy if asked. A format 1 item becomes format 2 here. If
    /// someone else saved first, the local copy takes their version instead.
    ///
    /// Each version gets a new item key when this account can seal every copy, so anyone
    /// who has lost access can't read what's saved from now on. Only an item's owner can
    /// seal the owner's copy, so others saving an item outside folders keep its key.
    fn save_version(
        &mut self,
        current: &EncryptedItem,
        overview: &Overview,
        details: &Details,
        change: People<'_>,
    ) -> Result<EditOutcome> {
        self.save_version_with(current, overview, details, change, true)
    }

    /// Like `save_version`. `password_may_be_new` is false when bringing back an earlier
    /// version: its password isn't one nobody saw, so passwords to change stay listed.
    fn save_version_with(
        &mut self,
        current: &EncryptedItem,
        overview: &Overview,
        details: &Details,
        change: People<'_>,
        password_may_be_new: bool,
    ) -> Result<EditOutcome> {
        let me = self.profile.user_id;
        let fresh = current.owner.is_none() || current.owner == Some(me);
        let (key, mut keys) = if fresh {
            let key = ItemKey::generate();
            let mut keys = ItemKeys::default();
            if let Some(folder_id) = current.folder_id {
                let folder_key = self
                    .profile
                    .folder_key(&self.keys, &self.groups, folder_id)?;
                keys.folder = Some(key.seal_for_folder(current.id, folder_id, &folder_key));
            }
            if let Some(owner) = current.owner {
                keys.owner = Some(key.seal_for_owner(current.id, owner, &self.keys));
            }
            for person in &current.keys.people {
                // People the owner removed from the team are dropped as the item is saved.
                if self.profile.is_removed(person.user_id) {
                    continue;
                }
                let recipient = self
                    .profile
                    .trusted_keys(person.user_id)
                    .context("someone this login is shared with isn't approved")?;
                keys.people.push(PersonKey {
                    user_id: person.user_id,
                    wrapped_key: recipient.wrap_item_key(&key, current.id)?,
                });
            }
            // Groups get the new key at their current generation; deleted ones are dropped.
            for copy in &current.keys.groups {
                if !self.profile.group_exists(copy.group_id) {
                    continue;
                }
                let (_, entry) = self.profile.team_group(copy.group_id)?;
                keys.groups.push(GroupKeyCopy {
                    group_id: copy.group_id,
                    generation: entry.generation,
                    wrapped_key: entry.encryption.wrap_item_key(&key, current.id)?,
                });
            }
            (key, keys)
        } else {
            let key = self.item_key(current)?;
            let mut keys = current.keys.clone();
            keys.people
                .retain(|person| !self.profile.is_removed(person.user_id));
            // Each person's copy is made again for their current keys: someone who recovered
            // with the owner's help gets one for their new keys.
            for person in &mut keys.people {
                if let Some(recipient) = self.profile.trusted_keys(person.user_id) {
                    person.wrapped_key = recipient.wrap_item_key(&key, current.id)?;
                }
            }
            keys.groups
                .retain(|copy| self.profile.group_exists(copy.group_id));
            (key, keys)
        };
        let mut roles = Vec::new();
        let mut group_roles = Vec::new();
        match change {
            People::Same => {}
            People::Add(user_id, recipient, role) => {
                keys.people.push(PersonKey {
                    user_id,
                    wrapped_key: recipient.wrap_item_key(&key, current.id)?,
                });
                roles.push(Member { user_id, role });
            }
            People::Drop(user_id) => keys.people.retain(|person| person.user_id != user_id),
            People::AddGroup(group, role) => {
                keys.groups.push(GroupKeyCopy {
                    group_id: group.group_id,
                    generation: group.generation,
                    wrapped_key: group.encryption.wrap_item_key(&key, current.id)?,
                });
                group_roles.push(GroupShare {
                    group_id: group.group_id,
                    role,
                });
            }
            People::DropGroup(group_id) => keys.groups.retain(|copy| copy.group_id != group_id),
        }
        // Anyone who lost access earlier doesn't know a new password. (A deleted item has
        // no details to compare; bringing it back isn't a new password.)
        let password_changed = password_may_be_new
            && !current.deleted
            && current.open_details(&self.item_key(current)?)?.password != details.password;
        let item = EncryptedItem::seal(
            self.next_version(current),
            &key,
            keys,
            &self.keys,
            overview,
            details,
        )?;
        self.put_version(current, item, roles, group_roles, password_changed)
    }

    /// The key and key copies for a deletion marker after `current`: the same ones, or for
    /// a format 1 item, a new key of its own sealed for its folder.
    fn next_keys(&self, current: &EncryptedItem) -> Result<(ItemKey, ItemKeys)> {
        if current.format < 2 {
            let folder_id = current
                .folder_id
                .context("a format 1 item is always in a folder")?;
            let folder_key = self
                .profile
                .folder_key(&self.keys, &self.groups, folder_id)?;
            let key = ItemKey::generate();
            let keys = ItemKeys {
                folder: Some(key.seal_for_folder(current.id, folder_id, &folder_key)),
                ..ItemKeys::default()
            };
            Ok((key, keys))
        } else {
            Ok((self.item_key(current)?, current.keys.clone()))
        }
    }

    fn next_version(&self, current: &EncryptedItem) -> ItemVersion {
        ItemVersion {
            id: current.id,
            folder_id: current.folder_id,
            owner: current.owner,
            version: current.version + 1,
            author: self.profile.user_id,
        }
    }

    /// Saves `item` as the version after `current`. If someone else saved first, the local
    /// copy takes their version instead.
    fn put_version(
        &mut self,
        current: &EncryptedItem,
        item: EncryptedItem,
        roles: Vec<Member>,
        group_roles: Vec<GroupShare>,
        password_changed: bool,
    ) -> Result<EditOutcome> {
        let request = PutItemRequest {
            base_version: Some(current.version),
            item,
            roles,
            group_roles,
            password_changed,
        };
        let path = format!("/v1/items/{}", current.id);
        Ok(
            match self.call(|client| client.put::<_, EncryptedItem>(&path, &request))? {
                Ok(saved) => {
                    let saved = kept(&request.item, saved)?;
                    let version = saved.version;
                    // The server forgets who could have seen the old password too.
                    if password_changed || saved.deleted {
                        self.profile
                            .exposures
                            .retain(|exposure| exposure.item_id != saved.id);
                    }
                    self.profile.items.insert(saved.id, saved);
                    EditOutcome::Saved { version }
                }
                Err(Failure::Status { code: 409, body }) => {
                    let theirs = serde_json::from_value::<Conflict>(body)?.current;
                    // Another version of this login, by someone approved: not whatever
                    // the server would like kept in its place.
                    if theirs.id != current.id {
                        bail!("the server answered with a different login");
                    }
                    if !self.profile.signed_by_author(&theirs) {
                        bail!("the newer version isn't signed by an approved author");
                    }
                    if !self.profile.author_could_save(&theirs) {
                        bail!(
                            "the newer version is by someone who can only view this \
                             folder. Don't trust this server"
                        );
                    }
                    let outcome = EditOutcome::Conflict {
                        version: theirs.version,
                        author: self.profile.user_name(theirs.author),
                    };
                    self.profile.items.insert(theirs.id, theirs);
                    outcome
                }
                Err(error) => return Err(error.into()),
            },
        )
    }

    /// Whether a folder's record from the server may be kept: its key opens, and it's one
    /// of the folder's own keys. Anyone can wrap a key for an account, the server
    /// included, so for a folder this device has had, opening isn't enough: the record
    /// mustn't go back a generation, and its chain must lead to the folder's first key.
    /// A made-up key can't, as each link is sealed with keys only members hold.
    fn accepts_folder(&mut self, folder_id: FolderId, record: &FolderRecord) -> bool {
        if record
            .open_key(&self.keys, &self.groups, folder_id)
            .is_err()
        {
            return false;
        }
        self.pin_folder(folder_id);
        let held = self.profile.folders.get(&folder_id);
        if held.is_some_and(|held| record.generation < held.generation) {
            return false;
        }
        let first = record
            .key_at(&self.keys, &self.groups, folder_id, 0)
            .map(|key| key.pin(folder_id));
        match (self.profile.folder_pins.get(&folder_id), first) {
            (Some(pin), first) => first.is_ok_and(|first| first == *pin),
            (None, Ok(first)) => {
                self.profile.folder_pins.insert(folder_id, first);
                true
            }
            // Nothing to compare with, here or there: as before pins.
            (None, Err(_)) => true,
        }
    }

    /// Remembers the first key of a folder that's here, for `accepts_folder`.
    fn pin_folder(&mut self, folder_id: FolderId) {
        if self.profile.folder_pins.contains_key(&folder_id) {
            return;
        }
        let first = self
            .profile
            .folders
            .get(&folder_id)
            .and_then(|record| record.key_at(&self.keys, &self.groups, folder_id, 0).ok());
        if let Some(first) = first {
            self.profile
                .folder_pins
                .insert(folder_id, first.pin(folder_id));
        }
    }

    fn live_item(&self, item_id: ItemId) -> Result<&EncryptedItem> {
        self.profile
            .items
            .get(&item_id)
            .filter(|item| !item.deleted)
            .context("no such login")
    }

    /// The key that opens an item, through its folder if it's in one of ours, or directly
    /// (to us or a group of ours).
    fn item_key(&self, item: &EncryptedItem) -> Result<ItemKey> {
        let folder_keys = match item.folder_id {
            Some(folder_id) if self.profile.folders.contains_key(&folder_id) => self
                .profile
                .folder_keys(&self.keys, &self.groups, folder_id)?,
            _ => Vec::new(),
        };
        // In a folder with signed roles, only the copy sealed with the folder's key
        // counts: whoever saved it then knew a key of the folder's, or kept the copy of
        // someone who did. A copy made out to this account alone could be anyone's.
        if item
            .folder_id
            .is_some_and(|folder| self.profile.folder_has_roles(folder))
        {
            return folder_keys
                .iter()
                .find_map(|key| item.unlock_in_folder(key).ok())
                .context("this login doesn't open with its folder's key");
        }
        unlock_with(
            item,
            &folder_keys,
            &self.keys,
            self.profile.user_id,
            &self.groups,
        )
        .or_else(|error| self.recovered_owner_key(item).ok_or(error))
    }

    /// Servers older than 0.2.0 store only format 1 items; saving to one would fail with
    /// a confusing error, so say why up front.
    fn check_server_takes_items(&mut self) -> Result<()> {
        if self.server_takes_items {
            return Ok(());
        }
        let health: Health = Client::new(&self.profile.server).get("/v1/health", &[])?;
        if health.item_format < 2 {
            bail!(NEEDS_0_2);
        }
        self.server_takes_items = true;
        Ok(())
    }

    /// `details` with its one-time code setup, if any, in the form it's kept: a checked
    /// otpauth:// link. Servers before 0.6.0 can't store one.
    fn with_one_time_code(&mut self, mut details: Details) -> Result<Details> {
        if details.otp.trim().is_empty() {
            details.otp.clear();
            return Ok(details);
        }
        details.otp = otp::normalize(&details.otp)?;
        let health: Health = Client::new(&self.profile.server).get("/v1/health", &[])?;
        if health.item_format < 4 {
            bail!(NEEDS_0_6);
        }
        Ok(details)
    }

    /// Servers older than 0.4.0 have no groups, and don't store items shared with them.
    fn check_server_has_groups(&mut self) -> Result<()> {
        let health: Health = Client::new(&self.profile.server).get("/v1/health", &[])?;
        if health.item_format < 3 {
            bail!(NEEDS_0_4);
        }
        Ok(())
    }

    fn apply_entry(&mut self, entry: SyncEntry, summary: &mut SyncSummary) {
        if !matches!(entry, SyncEntry::Item { .. }) {
            // Folders, groups or their members may change with it.
            self.could_save.clear();
        }
        match entry {
            SyncEntry::Item { item, .. } => self.apply_item(item, summary),
            SyncEntry::Joined {
                folder_id,
                info,
                wrapped_key,
                generation,
                chain,
                via_group,
                items,
                entries,
                ..
            } => {
                let record = FolderRecord {
                    info,
                    wrapped_key,
                    generation,
                    chain,
                    via_group,
                    entries,
                };
                if !self.accepts_members(folder_id, &record)
                    || !self.accepts_folder(folder_id, &record)
                {
                    summary.rejected += items.len();
                    return;
                }
                self.profile.folders.insert(folder_id, record);
                self.could_save.clear();
                for item in items {
                    self.apply_item(item, summary);
                }
            }
            SyncEntry::Rekeyed {
                folder_id,
                info,
                wrapped_key,
                generation,
                chain,
                via_group,
                entries,
                ..
            } => {
                // Only for a folder already here, and only one of its own keys, not older
                // than the one here, with members that check out.
                let record = FolderRecord {
                    info,
                    wrapped_key,
                    generation,
                    chain,
                    via_group,
                    entries,
                };
                if self.profile.folders.contains_key(&folder_id)
                    && self.accepts_members(folder_id, &record)
                    && self.accepts_folder(folder_id, &record)
                {
                    self.profile.folders.insert(folder_id, record);
                }
            }
            SyncEntry::Group {
                group_id,
                entries,
                generation,
                wrapped_secret,
                chain,
                ..
            } => {
                // Only a group whose entries check out and whose secret matches them.
                let record = GroupRecord {
                    entries,
                    generation,
                    wrapped_secret,
                    chain,
                };
                let mut keyring = GroupKeyring::default();
                if self
                    .profile
                    .add_group_keys(&mut keyring, &self.keys, group_id, &record)
                    .is_ok()
                {
                    self.profile.groups.insert(group_id, record);
                    self.groups = self.profile.group_keyring(&self.keys);
                } else {
                    summary.rejected += 1;
                }
            }
            SyncEntry::LeftGroup { group_id, .. } => {
                // What the group alone gave arrives as leaves of its own.
                self.profile.groups.remove(&group_id);
                self.groups = self.profile.group_keyring(&self.keys);
            }
            SyncEntry::Left { folder_id, .. } => self.forget_folder(folder_id),
            SyncEntry::LeftItem { item_id, moved, .. } => {
                // Keep it if one of our folders still has it, unless it moved: then the
                // folder on our copy is out of date.
                let in_folder = !moved
                    && self.profile.items.get(&item_id).is_some_and(|item| {
                        item.folder_id
                            .is_some_and(|folder_id| self.profile.folders.contains_key(&folder_id))
                    });
                if !in_folder {
                    self.profile.items.remove(&item_id);
                }
            }
        }
    }

    fn apply_item(&mut self, item: EncryptedItem, summary: &mut SyncSummary) {
        if !self.profile.signed_by_author(&item) {
            summary.rejected += 1;
            return;
        }
        // By the folder's signed roles, not the server's word: worked out once for each
        // author and folder while nothing but logins arrives.
        if let Some(folder_id) = item.folder_id {
            let could = match self.could_save.get(&(folder_id, item.author)) {
                Some(&could) => could,
                None => {
                    let could = self.profile.author_could_save(&item);
                    self.could_save.insert((folder_id, item.author), could);
                    could
                }
            };
            if !could {
                summary.rejected += 1;
                return;
            }
        }
        if self
            .profile
            .items
            .get(&item.id)
            .is_none_or(|local| local.version < item.version)
        {
            self.profile.items.insert(item.id, item);
        }
    }

    /// Runs a request, signing in first when there's no valid session and once more if
    /// the server has forgotten it (for example after a restart). A session half over is
    /// renewed first, so the device key, which may need Touch ID, is used as little as
    /// possible. The outer error is a sign-in failure; the inner one is the request's own.
    fn call<T>(
        &mut self,
        request: impl Fn(&Client) -> Result<T, Failure>,
    ) -> Result<Result<T, Failure>> {
        let step = match (&self.client, self.session) {
            (Some(_), Some(session)) => session.step(Instant::now()),
            _ => SessionStep::SignIn,
        };
        match step {
            SessionStep::Use => {}
            SessionStep::Renew => self.renew(),
            SessionStep::SignIn => self.sign_in()?,
        }
        let result = request(self.client.as_ref().expect("signed in above"));
        if let Err(Failure::Status { code: 401, .. }) = result {
            self.sign_in()?;
            return Ok(request(self.client.as_ref().expect("signed in above")));
        }
        Ok(result)
    }

    fn sign_in(&mut self) -> Result<()> {
        let mut client = Client::new(&self.profile.server);
        let asked = Instant::now();
        let session = client.sign_in(self.profile.device_id, self.signer.as_ref())?;
        self.session = Some(SessionTimes::new(asked, session.expires_in_seconds));
        self.client = Some(client);
        Ok(())
    }

    /// Swaps a session half over for a fresh one, without the device key. If that fails,
    /// the session still works until it ends, and the next request tries again. A server
    /// too old to renew (404) isn't asked again, and its sessions are signed in afresh; a
    /// session the server won't renew any more (403, some hours after signing in) is used
    /// until it ends, then the device signs in with its key.
    fn renew(&mut self) {
        let Some(client) = self.client.as_mut().filter(|_| self.server_renews) else {
            return;
        };
        let asked = Instant::now();
        match client.renew() {
            Ok(session) => {
                self.session = Some(SessionTimes::new(asked, session.expires_in_seconds));
            }
            Err(Failure::Status { code: 404, .. }) => self.server_renews = false,
            Err(Failure::Status { code: 403, .. }) => {
                if let Some(session) = &mut self.session {
                    session.stop_renewing();
                }
            }
            Err(_) => {}
        }
    }

    fn save(&self) -> Result<()> {
        self.profile.save(&self.path)
    }
}

/// What the server answers a save with, if it's the version just sealed here; that's the
/// only thing a save puts in the local copy. A server can't slip another login, or
/// another version of this one, in with its answer.
fn kept(sent: &EncryptedItem, saved: EncryptedItem) -> Result<EncryptedItem> {
    if saved != *sent {
        bail!("the server answered the save with something else than what was saved");
    }
    Ok(saved)
}

/// How a save changes who has a login directly.
enum People<'a> {
    Same,
    Add(UserId, &'a AccountPublicKeys, Role),
    Drop(UserId),
    AddGroup(&'a GroupEntry, Role),
    DropGroup(GroupId),
}

/// Opens an item with whichever of its folder's keys it was saved with, or directly.
/// How long a deleted login can be brought back.
const DELETED_KEPT_SECONDS: i64 = 30 * 86_400;

/// Which of a login's fields differ between two of its versions.
fn changes(before: &(Overview, Details), after: &(Overview, Details)) -> Vec<String> {
    let ((before_overview, before_details), (after_overview, after_details)) = (before, after);
    [
        ("name", before_overview.name != after_overview.name),
        (
            "username",
            before_overview.username != after_overview.username,
        ),
        ("website", before_overview.url != after_overview.url),
        (
            "password",
            before_details.password != after_details.password,
        ),
        ("notes", before_details.notes != after_details.notes),
        ("one-time code", before_details.otp != after_details.otp),
    ]
    .into_iter()
    .filter(|(_, changed)| *changed)
    .map(|(field, _)| field.to_owned())
    .collect()
}

fn unlock_with(
    item: &EncryptedItem,
    folder_keys: &[FolderKey],
    keys: &AccountKeys,
    me: UserId,
    groups: &GroupKeyring,
) -> Result<ItemKey> {
    for folder_key in folder_keys {
        if let Ok(key) = item.unlock_with(Some(folder_key), keys, me, groups) {
            return Ok(key);
        }
    }
    Ok(item.unlock_with(None, keys, me, groups)?)
}

/// Puts a fingerprint typed in by hand into the canonical form, whatever spacing, dashes or
/// case were used: "AB12 cd34ef56 7890-abcd" becomes "ab12-cd34-ef56-7890-abcd". Anything
/// else typed stays in, so it can't match by accident.
fn normalize(fingerprint: &str) -> String {
    let characters: Vec<char> = fingerprint
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    characters
        .chunks(4)
        .map(|group| group.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use keystead_core::keys::{AccountSecret, SoftwareDeviceKey};

    use super::*;

    /// A vault that has never talked to a server, to feed entries a server might send.
    fn offline_vault() -> Vault {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        // A folder of its own: saving a profile makes its folder private.
        let folder = std::env::temp_dir().join(format!(
            "keystead-vault-unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let path = folder.join("profile.json");
        let keys = AccountKeys::derive(&AccountSecret::generate());
        let profile = Profile::new(
            "http://127.0.0.1:9",
            "Olivia",
            OWNER,
            DeviceId::random(),
            keys.public(),
        );
        let vault = Vault::create(
            &path,
            profile,
            keys,
            Arc::new(SoftwareDeviceKey::generate()),
        )
        .unwrap();
        std::fs::remove_dir_all(&folder).unwrap();
        vault
    }

    /// A folder's record as the server sends it: `keys` oldest first, the last one current
    /// and wrapped for the vault's account.
    fn folder_record(vault: &Vault, folder_id: FolderId, keys: &[&FolderKey]) -> FolderRecord {
        let current = keys.last().unwrap();
        FolderRecord {
            info: FolderInfo {
                name: "Production".into(),
            }
            .seal(folder_id, current)
            .unwrap(),
            wrapped_key: vault
                .keys
                .public()
                .wrap_folder_key(current, folder_id)
                .unwrap(),
            generation: keys.len() as u32 - 1,
            chain: keys
                .windows(2)
                .zip(1..)
                .map(|(pair, generation)| KeyLink {
                    generation,
                    previous: pair[1].seal_previous(pair[0], folder_id, generation),
                })
                .collect(),
            via_group: None,
            entries: Vec::new(),
        }
    }

    fn joined(folder_id: FolderId, record: FolderRecord) -> SyncEntry {
        SyncEntry::Joined {
            seq: 1,
            folder_id,
            info: record.info,
            wrapped_key: record.wrapped_key,
            generation: record.generation,
            chain: record.chain,
            via_group: None,
            items: Vec::new(),
            entries: record.entries,
        }
    }

    fn rekeyed(folder_id: FolderId, record: FolderRecord) -> SyncEntry {
        SyncEntry::Rekeyed {
            seq: 1,
            folder_id,
            info: record.info,
            wrapped_key: record.wrapped_key,
            generation: record.generation,
            chain: record.chain,
            via_group: None,
            entries: record.entries,
        }
    }

    /// The generation of the folder's key here, and whether it's `key`.
    fn holds(vault: &Vault, folder_id: FolderId, key: &FolderKey) -> Option<u32> {
        let record = vault.profile.folders.get(&folder_id)?;
        let held = record
            .open_key(&vault.keys, &vault.groups, folder_id)
            .unwrap();
        (held.pin(folder_id) == key.pin(folder_id)).then_some(record.generation)
    }

    #[test]
    fn a_known_folder_only_takes_keys_of_its_own() {
        let mut vault = offline_vault();
        let mut summary = SyncSummary::default();
        let folder_id = FolderId::random();
        let (first, second, third) = (
            FolderKey::generate(),
            FolderKey::generate(),
            FolderKey::generate(),
        );
        // What a server can make without any member's help: a key of its own, wrapped for
        // the account, alone or on top of a chain that doesn't open to the real keys.
        let made_up = FolderKey::generate();

        let record = folder_record(&vault, folder_id, &[&first]);
        vault.apply_entry(joined(folder_id, record), &mut summary);
        assert_eq!(holds(&vault, folder_id, &first), Some(0));

        // The folder again, or a new key for it, with a made-up key: ignored.
        let record = folder_record(&vault, folder_id, &[&made_up]);
        vault.apply_entry(joined(folder_id, record), &mut summary);
        let record = folder_record(&vault, folder_id, &[&made_up]);
        vault.apply_entry(rekeyed(folder_id, record), &mut summary);
        let record = folder_record(&vault, folder_id, &[&FolderKey::generate(), &made_up]);
        vault.apply_entry(rekeyed(folder_id, record), &mut summary);
        assert_eq!(holds(&vault, folder_id, &first), Some(0));

        // A real new key, whose chain leads back to the first: taken.
        let record = folder_record(&vault, folder_id, &[&first, &second]);
        vault.apply_entry(rekeyed(folder_id, record), &mut summary);
        assert_eq!(holds(&vault, folder_id, &second), Some(1));
        // The older key again: ignored.
        let record = folder_record(&vault, folder_id, &[&first]);
        vault.apply_entry(rekeyed(folder_id, record), &mut summary);
        assert_eq!(holds(&vault, folder_id, &second), Some(1));

        // Leaving doesn't forget which folder it was: it can't come back with a made-up
        // key, and does come back with a real one.
        vault.apply_entry(SyncEntry::Left { seq: 2, folder_id }, &mut summary);
        assert!(!vault.profile.folders.contains_key(&folder_id));
        let record = folder_record(&vault, folder_id, &[&made_up]);
        vault.apply_entry(joined(folder_id, record), &mut summary);
        assert!(!vault.profile.folders.contains_key(&folder_id));
        let record = folder_record(&vault, folder_id, &[&first, &second, &third]);
        vault.apply_entry(joined(folder_id, record), &mut summary);
        assert_eq!(holds(&vault, folder_id, &third), Some(2));

        // The fingerprints survive a save and a load.
        let saved = serde_json::to_string(&vault.profile).unwrap();
        let loaded: Profile = serde_json::from_str(&saved).unwrap();
        assert_eq!(
            loaded.folder_pins.get(&folder_id),
            Some(&first.pin(folder_id))
        );
    }

    #[test]
    fn a_folders_members_must_be_signed_by_people_the_owner_approved() {
        let mut vault = offline_vault();
        let mut summary = SyncSummary::default();
        let me = vault.profile.user_id;
        let mut entry = DirectoryEntry::new(me, "Olivia", vault.keys.public());
        entry.approve(&vault.keys);
        vault.profile.set_directory(vec![entry]);
        let stranger = AccountKeys::derive(&AccountSecret::generate());

        let signed = |vault: &Vault, folder_id, key: &FolderKey, by: UserId, keys: &AccountKeys| {
            let mut record = folder_record(vault, folder_id, &[key]);
            let mut entry = FolderEntry::first(folder_id, 0, key, vec![me, by], Vec::new());
            entry.sign(by, keys);
            record.entries.push(entry);
            record
        };
        // A folder whose members someone the owner never approved signed for: what a
        // server, or anyone, can make up. Not taken.
        let (made_up, key) = (FolderId::random(), FolderKey::generate());
        let record = signed(&vault, made_up, &key, UserId(9), &stranger);
        vault.apply_entry(joined(made_up, record), &mut summary);
        assert!(!vault.profile.folders.contains_key(&made_up));

        // One this account signed for is.
        let (folder_id, key) = (FolderId::random(), FolderKey::generate());
        let mut record = folder_record(&vault, folder_id, &[&key]);
        let mut entry = FolderEntry::first(folder_id, 0, &key, vec![me], Vec::new());
        let keys = &vault.keys;
        entry.sign(me, keys);
        record.entries.push(entry.clone());
        vault.apply_entry(joined(folder_id, record), &mut summary);
        assert_eq!(holds(&vault, folder_id, &key), Some(0));

        // Not with entries for another key than the one that came with them.
        let other = FolderId::random();
        let mut record = folder_record(&vault, other, &[&FolderKey::generate()]);
        let mut for_key = FolderEntry::first(other, 0, &key, vec![me], Vec::new());
        for_key.sign(me, &vault.keys);
        record.entries.push(for_key);
        vault.apply_entry(joined(other, record), &mut summary);
        assert!(!vault.profile.folders.contains_key(&other));

        // And a folder that has had signed members doesn't go back to having none, or to
        // others than the ones here.
        let record = folder_record(&vault, folder_id, &[&key]);
        vault.apply_entry(rekeyed(folder_id, record), &mut summary);
        assert_eq!(vault.profile.folders[&folder_id].entries, [entry.clone()]);
        let mut record = folder_record(&vault, folder_id, &[&key]);
        let mut again = FolderEntry::first(folder_id, 0, &key, vec![me], Vec::new());
        again.groups.push(GroupId::random());
        again.sign(me, &vault.keys);
        record.entries.push(again);
        vault.apply_entry(rekeyed(folder_id, record), &mut summary);
        assert_eq!(vault.profile.folders[&folder_id].entries, [entry]);
    }

    #[test]
    fn a_profile_from_before_fingerprints_gets_them_from_the_folders_it_has() {
        let mut vault = offline_vault();
        let mut summary = SyncSummary::default();
        let folder_id = FolderId::random();
        let (first, second) = (FolderKey::generate(), FolderKey::generate());
        let record = folder_record(&vault, folder_id, &[&first, &second]);
        vault.profile.folders.insert(folder_id, record);
        assert!(vault.profile.folder_pins.is_empty());

        let record = folder_record(&vault, folder_id, &[&FolderKey::generate()]);
        vault.apply_entry(joined(folder_id, record), &mut summary);
        let made_up = FolderKey::generate();
        let record = folder_record(&vault, folder_id, &[&first, &second, &made_up]);
        vault.apply_entry(rekeyed(folder_id, record), &mut summary);
        // That last one is a real chain, so it's taken; the one before it wasn't.
        assert_eq!(holds(&vault, folder_id, &made_up), Some(2));
        assert_eq!(
            vault.profile.folder_pins.get(&folder_id),
            Some(&first.pin(folder_id))
        );
    }

    #[test]
    fn a_save_keeps_only_the_version_it_sealed() {
        let keys = AccountKeys::derive(&AccountSecret::generate());
        let seal = |name: &str| {
            let id = ItemId::random();
            let key = ItemKey::generate();
            let item_keys = ItemKeys {
                owner: Some(key.seal_for_owner(id, OWNER, &keys)),
                ..ItemKeys::default()
            };
            let at = ItemVersion {
                id,
                folder_id: None,
                owner: Some(OWNER),
                version: 1,
                author: OWNER,
            };
            let overview = Overview {
                name: name.into(),
                ..Overview::default()
            };
            EncryptedItem::seal(at, &key, item_keys, &keys, &overview, &Details::default()).unwrap()
        };
        let sent = seal("Bank");
        assert_eq!(kept(&sent, sent.clone()).unwrap(), sent);
        // Another login, even one validly signed by this account, isn't what was saved.
        assert!(kept(&sent, seal("Planted")).is_err());
        let mut altered = sent.clone();
        altered.version = 2;
        assert!(kept(&sent, altered).is_err());
    }

    #[test]
    fn a_session_is_renewed_halfway_and_signed_in_again_near_its_end() {
        let asked = Instant::now();
        let session = SessionTimes::new(asked, 15 * 60);
        let at = |seconds| session.step(asked + Duration::from_secs(seconds));
        assert_eq!(at(0), SessionStep::Use);
        assert_eq!(at(449), SessionStep::Use);
        assert_eq!(at(450), SessionStep::Renew);
        assert_eq!(at(839), SessionStep::Renew);
        assert_eq!(at(840), SessionStep::SignIn);
        // Shorter than the margin: signed in afresh each time, never used stale.
        let short = SessionTimes::new(asked, 30);
        assert_eq!(short.step(asked), SessionStep::SignIn);

        // Once the server won't renew it, the session is used to its end.
        let mut refused = session;
        refused.stop_renewing();
        let at = |seconds| refused.step(asked + Duration::from_secs(seconds));
        assert_eq!(at(450), SessionStep::Use);
        assert_eq!(at(839), SessionStep::Use);
        assert_eq!(at(840), SessionStep::SignIn);
    }

    #[test]
    fn invites_survive_the_trip_through_a_message() {
        let invite = InviteInfo {
            server: "https://keys.example.com".into(),
            token: "tok_123".into(),
            owner_fingerprint: "ab12cd34".into(),
            expires_at: None,
        };
        assert_eq!(InviteInfo::parse(&invite.command()).unwrap(), invite);
        // Wrapped by a mail client, without the command name, with stray spaces.
        let wrapped = "  https://keys.example.com\n tok_123\n--owner ab12cd34\n";
        assert_eq!(InviteInfo::parse(wrapped).unwrap(), invite);
    }

    #[test]
    fn fingerprints_typed_by_hand_are_read_leniently() {
        let canonical = "ab12-cd34-ef56-7890-abcd";
        for typed in [
            canonical,
            "AB12-CD34-EF56-7890-ABCD",
            "ab12 cd34 ef56 7890 abcd",
            "ab12cd34ef567890abcd",
            "  ab12-cd34 ef56 7890abcd\n",
        ] {
            assert_eq!(normalize(typed), canonical, "{typed:?}");
        }
        assert_ne!(normalize("ab12-cd34-ef56-7890-abcO"), canonical);
        assert_ne!(normalize("ab12-cd34-ef56-7890"), canonical);
    }

    #[test]
    fn malformed_invites_are_rejected() {
        for text in [
            "",
            "keystead join https://keys.example.com tok_123",
            "keystead join https://keys.example.com tok_123 --owner",
            "keystead join keys.example.com tok_123 --owner ab12",
            "keystead join https://keys.example.com --owner ab12",
            "keystead join https://keys.example.com tok_123 extra --owner ab12",
        ] {
            assert!(InviteInfo::parse(text).is_err(), "accepted {text:?}");
        }
    }
}
