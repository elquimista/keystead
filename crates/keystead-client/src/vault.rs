//! An unlocked vault: the profile plus the account keys, able to sign in and act.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use keystead_core::api::{
    AcceptInviteRequest, AddFolderGroupRequest, AddGroupMemberRequest, AddMemberRequest,
    ApprovalRequest, Conflict, CreateFolderRequest, CreateGroupRequest, DeviceList, Directory,
    Enrolled, Exposures, GroupFolderKey, GroupMemberKey, GroupRekeyRequest, GroupShare, Groups,
    Health, Invite, InviteRequest, ItemHistory, KeyLink, Member, MemberKey, Members,
    PutItemRequest, RecoverRequest, RecoveryChallenge, RecoveryChallengeRequest, RekeyRequest,
    Role, RoleRequest, SetupRequest, SyncEntry, SyncPage, UpdateGroupRequest,
};
use keystead_core::directory::DirectoryEntry;
use keystead_core::groups::{GroupEntry, GroupKeyring};
use keystead_core::ids::{DeviceId, FolderId, GroupId, ItemId, UserId};
use keystead_core::items::{
    Details, EncryptedItem, FolderInfo, GroupKeyCopy, ITEM_FORMAT, ItemKeys, ItemVersion, Overview,
    PersonKey,
};
use keystead_core::keys::{
    AccountKeys, AccountPublicKeys, AccountSecret, FolderKey, GroupKeys, GroupSecret, ItemKey,
    recovery_message,
};
use keystead_core::otp::{self, OneTimeCode};
use rand::Rng;
use rand::rngs::OsRng;

use crate::DeviceSigner;
use crate::http::{Client, Failure};
use crate::profile::{FolderRecord, GroupRecord, OWNER, Profile};

/// What an older server answers for something it doesn't have yet: 404 on the whole route.
const NEEDS_0_2: &str = "the server is older than Keystead 0.2.0 and can't do this yet; \
                         update it to 0.2.0 or later";
/// Groups came with 0.4.0; an older server doesn't have them.
const NEEDS_0_4: &str = "the server is older than Keystead 0.4.0 and doesn't have groups; \
                         update it to 0.4.0 or later";
/// One-time codes came with 0.6.0 (item format 4); an older server can't store them.
const NEEDS_0_6: &str = "the server is older than Keystead 0.6.0 and can't store one-time \
                         codes; update it to 0.6.0 or later";
/// History came with 0.7.0; an older server keeps only each login's latest version.
const NEEDS_0_7: &str = "the server is older than Keystead 0.7.0 and keeps no history; update \
                         it to 0.7.0 or later";
/// What a server answers for sign-out if it's from before sign-out existed.
const NO_SIGN_OUT: &str = "the server is too old to forget a device that signs out; update it";
const PAGE_SIZE: i64 = 500;
/// Sign in again this long before the server's session would expire.
const SESSION_MARGIN: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct Whoami {
    pub name: String,
    pub user_id: UserId,
    pub fingerprint: String,
    pub server: String,
    pub is_owner: bool,
    /// The owner's fingerprint, as this device pinned it. A recovery kit carries it.
    pub owner_fingerprint: String,
}

/// An invite: everything a new user needs to join, including the owner's fingerprint so
/// they can check they reached the right server.
#[derive(Debug, PartialEq, Eq)]
pub struct InviteInfo {
    pub server: String,
    pub token: String,
    pub owner_fingerprint: String,
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
                })
            }
            _ => bail!("an invite has a server address starting with http and a token"),
        }
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
    /// Items dropped because their author isn't approved or the signature failed.
    pub rejected: usize,
    /// Folders this account manages that got a new key after someone lost access.
    pub rekeyed: usize,
    /// Why a folder that needs a new key didn't get one this time; the next sync retries.
    pub rekey_problems: Vec<String>,
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
    let mut entry = DirectoryEntry {
        user_id: OWNER,
        name: name.to_owned(),
        keys: keys.public(),
        approval: None,
        removed: false,
    };
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
    profile.directory = directory.entries;
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
    let mut profile = Profile::new(
        account.server,
        &me.name,
        enrolled.user_id,
        account.device_id,
        owner.keys.clone(),
    );
    profile.directory = directory.entries;
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
    session_valid_until: Option<Instant>,
    /// The server stores this build's item format; checked before the first save.
    server_takes_items: bool,
    /// The keys of the groups this account is in, from the profile.
    groups: GroupKeyring,
    /// Login histories fetched this session, by login, newest first; kept encrypted.
    history: HashMap<ItemId, Vec<EncryptedItem>>,
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
            session_valid_until: None,
            server_takes_items: false,
            history: HashMap::new(),
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
            session_valid_until: None,
            server_takes_items: false,
            history: HashMap::new(),
            groups: GroupKeyring::default(),
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    pub fn whoami(&self) -> Whoami {
        Whoami {
            name: self.profile.name.clone(),
            user_id: self.profile.user_id,
            fingerprint: self.keys.public().fingerprint(),
            server: self.profile.server.clone(),
            is_owner: self.profile.user_id == OWNER,
            owner_fingerprint: self.profile.owner.fingerprint(),
        }
    }

    /// Pulls feed pages until caught up, then saves. Every item must be signed by an
    /// author the owner approved; anything else is dropped.
    pub fn sync(&mut self) -> Result<SyncSummary> {
        let mut summary = SyncSummary::default();
        let (mut folders, groups) = self.pull(&mut summary)?;
        // Someone left these groups: give each a new key first, as folders shared with them
        // wait for it.
        if !groups.is_empty() {
            for group_id in groups {
                match self.rekey_group(group_id) {
                    Ok(()) => summary.rekeyed += 1,
                    Err(error) => summary.rekey_problems.push(format!("{error:#}")),
                }
            }
            (folders, _) = self.pull(&mut summary)?;
        }
        // Someone lost access to these folders: give each a new key, so what's saved from
        // now on is out of their reach. If it fails, the next sync asks again.
        for folder_id in folders {
            match self.rekey(folder_id) {
                Ok(()) => summary.rekeyed += 1,
                Err(error) => summary.rekey_problems.push(format!("{error:#}")),
            }
        }
        Ok(summary)
    }

    /// The directory, the team's groups, and the feed until caught up; then saves. Returns
    /// the folders and groups this account should give new keys.
    fn pull(&mut self, summary: &mut SyncSummary) -> Result<(Vec<FolderId>, Vec<GroupId>)> {
        let directory: Directory = self.call(|client| client.get("/v1/directory", &[]))??;
        self.profile.directory = directory.entries;
        // Servers before 0.4.0 have no groups.
        match self.call(|client| client.get::<Groups>("/v1/groups", &[]))? {
            Ok(groups) => self.profile.team_groups = groups.groups,
            Err(Failure::Status { code: 404, .. }) => self.profile.team_groups.clear(),
            Err(error) => return Err(error.into()),
        }
        // Servers before 0.5.0 don't keep track of passwords to change.
        match self.call(|client| client.get::<Exposures>("/v1/exposures", &[]))? {
            Ok(list) => self.profile.exposures = list.exposures,
            Err(Failure::Status { code: 404, .. }) => self.profile.exposures.clear(),
            Err(error) => return Err(error.into()),
        }
        let rekey_needed = loop {
            let query = [
                ("cursor", self.profile.cursor.to_string()),
                ("limit", PAGE_SIZE.to_string()),
            ];
            let page: SyncPage = self.call(|client| client.get("/v1/sync", &query))??;
            summary.received += page.entries.len();
            for entry in page.entries {
                self.apply_entry(entry, summary);
            }
            self.profile.cursor = page.cursor;
            if !page.more {
                if page.roles.is_some() {
                    self.profile.roles = page.roles;
                }
                break (page.rekey_needed, page.group_rekey_needed);
            }
        };
        self.save()?;
        Ok(rekey_needed)
    }

    /// Everyone on the server, and whether the pinned owner approved them.
    pub fn users(&mut self) -> Result<Vec<UserRow>> {
        let directory: Directory = self.call(|client| client.get("/v1/directory", &[]))??;
        self.profile.directory = directory.entries;
        self.save()?;
        Ok(self
            .profile
            .directory
            .iter()
            .map(|entry| UserRow {
                user_id: entry.user_id,
                name: entry.name.clone(),
                approved: entry.verify(&self.profile.owner).is_ok(),
                is_owner: entry.user_id == OWNER,
                removed: entry.removed,
                fingerprint: entry.keys.fingerprint(),
            })
            .collect())
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
        })
    }

    /// Approves a user (owner only), but only if the fingerprint they read out matches.
    pub fn approve(&mut self, user: UserId, fingerprint: &str) -> Result<String> {
        let directory: Directory = self.call(|client| client.get("/v1/directory", &[]))??;
        let mut entry = directory
            .entries
            .into_iter()
            .find(|entry| entry.user_id == user)
            .with_context(|| format!("no user {user}"))?;
        let expected = normalize(fingerprint);
        if entry.keys.fingerprint() != expected {
            bail!(
                "{}'s fingerprint on the server is {}, not {expected}. Don't approve; the keys \
                 may have been swapped.",
                entry.name,
                entry.keys.fingerprint()
            );
        }
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
        };
        let request = CreateFolderRequest {
            folder_id,
            info: record.info.clone(),
            wrapped_key: record.wrapped_key.clone(),
        };
        let () = self.call(|client| client.post("/v1/folders", &request))??;
        self.profile.folders.insert(folder_id, record);
        self.save()?;
        Ok(folder_id)
    }

    /// Shares a folder with an approved user by wrapping its current key for them.
    pub fn share_folder(&mut self, folder: &str, user: UserId, role: Role) -> Result<String> {
        self.sync()?;
        let folder_id = self.profile.find_folder(&self.keys, &self.groups, folder)?;
        let recipient = self.shareable_keys(user)?;
        let key = self
            .profile
            .folder_key(&self.keys, &self.groups, folder_id)?;
        let request = AddMemberRequest {
            user_id: user,
            wrapped_key: recipient.wrap_folder_key(&key, folder_id)?,
            role,
            generation: self.profile.folders[&folder_id].generation,
        };
        let path = format!("/v1/folders/{folder_id}/members");
        let () = self.call(|client| client.post(&path, &request))??;
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
        let () = self.call(|client| client.put(&path, &RoleRequest { role }))??;
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
            self.forget_folder(folder_id);
            self.save()?;
        } else {
            // If this fails, the next sync of any manager tries again.
            self.rekey(folder_id)?;
        }
        Ok(())
    }

    /// Gives a folder a new key, wrapped for each current member and group, with the old
    /// key sealed under it so older items still open.
    fn rekey(&mut self, folder_id: FolderId) -> Result<()> {
        let record = self
            .profile
            .folders
            .get(&folder_id)
            .context("you don't have access to that folder")?;
        let generation = record.generation + 1;
        let old = self
            .profile
            .folder_key(&self.keys, &self.groups, folder_id)?;
        let info = FolderInfo::open(&record.info, folder_id, &old)?;
        let path = format!("/v1/folders/{folder_id}/members");
        let members: Members = self.call(|client| client.get(&path, &[]))??;
        let key = FolderKey::generate();
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
        self.save()
    }

    /// Removes someone from the team (owner only): their devices stop working, and they
    /// lose every folder and login. Folders they were in get new keys from their managers.
    pub fn remove_user(&mut self, user: UserId) -> Result<String> {
        let name = self.profile.user_name(user);
        let path = format!("/v1/users/{user}");
        let () = self.call(|client| client.delete(&path))??;
        self.sync()?;
        Ok(name)
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
        let request = AddGroupMemberRequest {
            user_id: user,
            generation: record.generation,
            wrapped_secret: recipient.wrap_group_secret(&secret, group_id, record.generation)?,
        };
        let path = format!("/v1/groups/{group_id}/members");
        let () = self.call(|client| client.post(&path, &request))??;
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
        let (_, entry) = self.profile.team_group(group_id)?;
        let request = AddFolderGroupRequest {
            group_id,
            wrapped_key: entry.encryption.wrap_folder_key(&key, folder_id)?,
            group_generation: entry.generation,
            role,
            generation: self.profile.folders[&folder_id].generation,
        };
        let name = entry.name.clone();
        let path = format!("/v1/folders/{folder_id}/groups");
        let () = self.call(|client| client.post(&path, &request))??;
        Ok(name)
    }

    /// Changes a group's role in a folder (managers only).
    pub fn set_folder_group_role(&mut self, folder: &str, group: &str, role: Role) -> Result<()> {
        let folder_id = self.profile.find_folder(&self.keys, &self.groups, folder)?;
        let group_id = self.profile.find_group(group)?;
        let path = format!("/v1/folders/{folder_id}/groups/{group_id}");
        let () = self.call(|client| client.put(&path, &RoleRequest { role }))??;
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
        let () = self.call(|client| client.put(&path, &RoleRequest { role }))??;
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
            let key = unlock_with(item, folder_keys, &self.keys, me, &self.groups)?;
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
            let signed = self
                .profile
                .trusted_keys(item.author)
                .is_some_and(|keys| item.verify(&keys).is_ok());
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
        let me = self.profile.user_id;
        let id = ItemId::random();
        let key = ItemKey::generate();
        let mut keys = ItemKeys::default();
        let at = match folder {
            Some(folder) => {
                let folder_id = self.profile.find_folder(&self.keys, &self.groups, folder)?;
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
            item: EncryptedItem::seal(at, &key, keys, &self.keys, &overview, &details)?,
            roles: Vec::new(),
            group_roles: Vec::new(),
            password_changed: false,
        };
        let path = format!("/v1/items/{id}");
        let saved: EncryptedItem = self.call(|client| client.put(&path, &request))??;
        self.profile.items.insert(saved.id, saved);
        self.save()?;
        Ok(id)
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
        let () = self.call(|client| client.put(&path, &RoleRequest { role }))??;
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
            // Groups get the new key at their current generation.
            for copy in &current.keys.groups {
                let (_, entry) = self.profile.team_group(copy.group_id)?;
                keys.groups.push(GroupKeyCopy {
                    group_id: copy.group_id,
                    generation: entry.generation,
                    wrapped_key: entry.encryption.wrap_item_key(&key, current.id)?,
                });
            }
            (key, keys)
        } else {
            let mut keys = current.keys.clone();
            keys.people
                .retain(|person| !self.profile.is_removed(person.user_id));
            (self.item_key(current)?, keys)
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
        // Anyone who lost access earlier doesn't know a new password.
        let previous = current.open_details(&self.item_key(current)?)?;
        let password_changed = password_may_be_new && previous.password != details.password;
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
                    let author_keys = self
                        .profile
                        .trusted_keys(theirs.author)
                        .context("the newer version's author isn't approved")?;
                    theirs.verify(&author_keys)?;
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
        unlock_with(
            item,
            &folder_keys,
            &self.keys,
            self.profile.user_id,
            &self.groups,
        )
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
                ..
            } => {
                let record = FolderRecord {
                    info,
                    wrapped_key,
                    generation,
                    chain,
                    via_group,
                };
                if record
                    .open_key(&self.keys, &self.groups, folder_id)
                    .is_err()
                {
                    summary.rejected += items.len();
                    return;
                }
                self.profile.folders.insert(folder_id, record);
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
                ..
            } => {
                // Only a key that opens, from a folder already here; a newer one wins.
                let newer = self
                    .profile
                    .folders
                    .get(&folder_id)
                    .is_some_and(|record| record.generation <= generation);
                let record = FolderRecord {
                    info,
                    wrapped_key,
                    generation,
                    chain,
                    via_group,
                };
                if newer && record.open_key(&self.keys, &self.groups, folder_id).is_ok() {
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
            SyncEntry::LeftItem { item_id, .. } => {
                // Keep it if one of our folders still has it.
                let in_folder = self.profile.items.get(&item_id).is_some_and(|item| {
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
        let trusted = self
            .profile
            .trusted_keys(item.author)
            .is_some_and(|keys| item.verify(&keys).is_ok());
        if !trusted {
            summary.rejected += 1;
            return;
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
    /// the server has forgotten it (for example after a restart). The outer error is a
    /// sign-in failure; the inner one is the request's own.
    fn call<T>(
        &mut self,
        request: impl Fn(&Client) -> Result<T, Failure>,
    ) -> Result<Result<T, Failure>> {
        let session_expired = self
            .session_valid_until
            .is_none_or(|until| Instant::now() >= until);
        if self.client.is_none() || session_expired {
            self.sign_in()?;
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
        let session = client.sign_in(self.profile.device_id, self.signer.as_ref())?;
        let lifetime =
            Duration::from_secs(session.expires_in_seconds).saturating_sub(SESSION_MARGIN);
        self.session_valid_until = Some(Instant::now() + lifetime);
        self.client = Some(client);
        Ok(())
    }

    fn save(&self) -> Result<()> {
        self.profile.save(&self.path)
    }
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
    use super::*;

    #[test]
    fn invites_survive_the_trip_through_a_message() {
        let invite = InviteInfo {
            server: "https://keys.example.com".into(),
            token: "tok_123".into(),
            owner_fingerprint: "ab12cd34".into(),
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
