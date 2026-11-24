//! An unlocked vault: the profile plus the account keys, able to sign in and act.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use keystead_core::api::{
    AcceptInviteRequest, AddMemberRequest, ApprovalRequest, Conflict, CreateFolderRequest,
    DeviceList, Directory, Enrolled, Health, Invite, InviteRequest, PutItemRequest, RecoverRequest,
    RecoveryChallenge, RecoveryChallengeRequest, SetupRequest, SyncEntry, SyncPage,
};
use keystead_core::directory::DirectoryEntry;
use keystead_core::ids::{DeviceId, FolderId, ItemId, UserId};
use keystead_core::items::{
    Details, EncryptedItem, FolderInfo, ITEM_FORMAT, ItemKeys, ItemVersion, Overview, PersonKey,
};
use keystead_core::keys::{
    AccountKeys, AccountPublicKeys, AccountSecret, FolderKey, ItemKey, recovery_message,
};
use rand::Rng;
use rand::rngs::OsRng;

use crate::DeviceSigner;
use crate::http::{Client, Failure};
use crate::profile::{FolderRecord, Profile};

const OWNER: UserId = UserId(1);
/// What an older server answers for something it doesn't have yet: 404 on the whole route.
const NEEDS_0_2: &str = "the server is older than Keystead 0.2.0 and can't do this yet; \
                         update it to 0.2.0 or later";
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
    pub fingerprint: String,
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
    /// You can open it only because it was shared with you directly.
    pub shared_with_me: bool,
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
}

impl Vault {
    /// Unlocks an enrolled device's vault. Doesn't touch the network.
    pub fn open(
        path: &Path,
        secret: &AccountSecret,
        signer: Arc<dyn DeviceSigner>,
    ) -> Result<Self> {
        Ok(Self {
            path: path.to_owned(),
            profile: Profile::load(path)?,
            keys: AccountKeys::derive(secret),
            signer,
            client: None,
            session_valid_until: None,
            server_takes_items: false,
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
        let directory: Directory = self.call(|client| client.get("/v1/directory", &[]))??;
        self.profile.directory = directory.entries;
        let mut summary = SyncSummary::default();
        loop {
            let query = [
                ("cursor", self.profile.cursor.to_string()),
                ("limit", PAGE_SIZE.to_string()),
            ];
            let page: SyncPage = self.call(|client| client.get("/v1/sync", &query))??;
            summary.received += page.entries.len();
            for entry in page.entries {
                self.apply_entry(entry, &mut summary);
            }
            self.profile.cursor = page.cursor;
            if !page.more {
                break;
            }
        }
        self.save()?;
        Ok(summary)
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

    /// Shares a folder with an approved user by wrapping its key for them.
    pub fn share_folder(&mut self, folder: &str, user: UserId) -> Result<String> {
        self.sync()?;
        let folder_id = self.profile.find_folder(&self.keys, folder)?;
        let recipient = self
            .profile
            .trusted_keys(user)
            .with_context(|| format!("user {user} isn't approved by the owner yet"))?;
        let key = self.profile.folder_key(&self.keys, folder_id)?;
        let request = AddMemberRequest {
            user_id: user,
            wrapped_key: recipient.wrap_folder_key(&key, folder_id)?,
        };
        let path = format!("/v1/folders/{folder_id}/members");
        let () = self.call(|client| client.post(&path, &request))??;
        Ok(self.profile.user_name(user))
    }

    /// Folder names, from the local copy.
    pub fn folders(&self) -> Result<Vec<String>> {
        let mut names = self
            .profile
            .folders
            .keys()
            .map(|&folder_id| self.profile.folder_name(&self.keys, folder_id))
            .collect::<Result<Vec<_>>>()?;
        names.sort();
        Ok(names)
    }

    /// Every live item's searchable fields, from the local copy. Passwords stay encrypted.
    pub fn list(&self) -> Result<Vec<ItemRow>> {
        let me = self.profile.user_id;
        let mut folders = HashMap::new();
        let mut rows = Vec::new();
        for item in self.profile.items.values().filter(|item| !item.deleted) {
            let folder = match item.folder_id {
                Some(folder_id) if self.profile.folders.contains_key(&folder_id) => {
                    // Each folder key is unwrapped once per listing, not once per item.
                    if let Entry::Vacant(slot) = folders.entry(folder_id) {
                        let key = self.profile.folder_key(&self.keys, folder_id)?;
                        let name = self.profile.folder_name(&self.keys, folder_id)?;
                        slot.insert((key, name));
                    }
                    folders.get(&folder_id)
                }
                _ => None,
            };
            let key = item.unlock(folder.map(|(key, _)| key), &self.keys, me)?;
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
                shared_with_me: folder.is_none() && item.owner != Some(me),
            });
        }
        rows.sort_by(|a, b| (&a.folder, &a.name).cmp(&(&b.folder, &b.name)));
        Ok(rows)
    }

    pub fn find_item(&self, name: &str, folder: Option<&str>) -> Result<ItemId> {
        let folder_id = folder
            .map(|folder| self.profile.find_folder(&self.keys, folder))
            .transpose()?;
        let mut matches = Vec::new();
        for item in self.profile.items.values().filter(|item| !item.deleted) {
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
        self.sync()?;
        let me = self.profile.user_id;
        let id = ItemId::random();
        let key = ItemKey::generate();
        let mut keys = ItemKeys::default();
        let at = match folder {
            Some(folder) => {
                let folder_id = self.profile.find_folder(&self.keys, folder)?;
                let folder_key = self.profile.folder_key(&self.keys, folder_id)?;
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
        self.sync()?;
        let current = self.live_item(item_id)?.clone();
        let outcome = self.save_version(&current, overview, details, None)?;
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
        let outcome = self.put_version(&current, tombstone)?;
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
        let outcome = self.save_version(&current, &overview, &details, None)?;
        self.save()?;
        Ok(outcome)
    }

    /// Shares one login with an approved user by giving them a copy of its key, in a new
    /// version. They see that login only, not the rest of its folder.
    pub fn share_item(&mut self, item_id: ItemId, user: UserId) -> Result<String> {
        self.check_server_takes_items()?;
        self.sync()?;
        let name = self.profile.user_name(user);
        if user == self.profile.user_id {
            bail!("that's you");
        }
        let recipient = self
            .profile
            .trusted_keys(user)
            .with_context(|| format!("{name} isn't approved by the owner yet"))?;
        // Sharing doesn't depend on what the login says, so if someone saved first, share
        // their version instead.
        for _ in 0..3 {
            let current = self.live_item(item_id)?.clone();
            if current.reaches_directly(user) {
                bail!("this login is already shared with {name}");
            }
            let key = self.item_key(&current)?;
            let overview = current.open_overview(&key)?;
            let details = current.open_details(&key)?;
            let outcome =
                self.save_version(&current, &overview, &details, Some((user, &recipient)))?;
            if let EditOutcome::Saved { .. } = outcome {
                self.save()?;
                return Ok(name);
            }
        }
        self.save()?;
        bail!("others kept changing this login; try sharing it again")
    }

    /// Saves the next version of `current` with these contents, sharing it with `add` too
    /// if given. A format 1 item becomes format 2 here, with a key of its own. If someone
    /// else saved first, the local copy takes their version instead.
    fn save_version(
        &mut self,
        current: &EncryptedItem,
        overview: &Overview,
        details: &Details,
        add: Option<(UserId, &AccountPublicKeys)>,
    ) -> Result<EditOutcome> {
        let (key, mut keys) = self.next_keys(current)?;
        if let Some((user_id, recipient)) = add {
            keys.people.push(PersonKey {
                user_id,
                wrapped_key: recipient.wrap_item_key(&key, current.id)?,
            });
        }
        let item = EncryptedItem::seal(
            self.next_version(current),
            &key,
            keys,
            &self.keys,
            overview,
            details,
        )?;
        self.put_version(current, item)
    }

    /// The key and key copies for the next version of `current`: the same ones, or for a
    /// format 1 item, a new key of its own sealed for its folder.
    fn next_keys(&self, current: &EncryptedItem) -> Result<(ItemKey, ItemKeys)> {
        if current.format < ITEM_FORMAT {
            let folder_id = current
                .folder_id
                .context("a format 1 item is always in a folder")?;
            let folder_key = self.profile.folder_key(&self.keys, folder_id)?;
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
    fn put_version(&mut self, current: &EncryptedItem, item: EncryptedItem) -> Result<EditOutcome> {
        let request = PutItemRequest {
            base_version: Some(current.version),
            item,
        };
        let path = format!("/v1/items/{}", current.id);
        Ok(
            match self.call(|client| client.put::<_, EncryptedItem>(&path, &request))? {
                Ok(saved) => {
                    let version = saved.version;
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

    /// The key that opens an item, through its folder if it's in one of ours, or directly.
    fn item_key(&self, item: &EncryptedItem) -> Result<ItemKey> {
        let folder_key = item
            .folder_id
            .filter(|folder_id| self.profile.folders.contains_key(folder_id))
            .map(|folder_id| self.profile.folder_key(&self.keys, folder_id))
            .transpose()?;
        Ok(item.unlock(folder_key.as_ref(), &self.keys, self.profile.user_id)?)
    }

    /// Servers older than 0.2.0 store only format 1 items; saving to one would fail with
    /// a confusing error, so say why up front.
    fn check_server_takes_items(&mut self) -> Result<()> {
        if self.server_takes_items {
            return Ok(());
        }
        let health: Health = Client::new(&self.profile.server).get("/v1/health", &[])?;
        if health.item_format < ITEM_FORMAT {
            bail!(NEEDS_0_2);
        }
        self.server_takes_items = true;
        Ok(())
    }

    fn apply_entry(&mut self, entry: SyncEntry, summary: &mut SyncSummary) {
        match entry {
            SyncEntry::Item { item, .. } => self.apply_item(item, summary),
            SyncEntry::Joined {
                folder_id,
                info,
                wrapped_key,
                items,
                ..
            } => {
                if self
                    .keys
                    .unwrap_folder_key(&wrapped_key, folder_id)
                    .is_err()
                {
                    summary.rejected += items.len();
                    return;
                }
                self.profile
                    .folders
                    .insert(folder_id, FolderRecord { info, wrapped_key });
                for item in items {
                    self.apply_item(item, summary);
                }
            }
            SyncEntry::Left { folder_id, .. } => {
                // Keep the folder's items that were also shared with us directly.
                let me = self.profile.user_id;
                self.profile.folders.remove(&folder_id);
                self.profile.items.retain(|_, item| {
                    item.folder_id != Some(folder_id) || item.reaches_directly(me)
                });
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
