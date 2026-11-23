//! What each `keystead` command does. Every command loads the profile from `home`, talks
//! to the server if it needs to, and saves the profile again.

use std::path::Path;

use anyhow::{Context, Result, bail};
use keystead_core::api::{
    AcceptInviteRequest, AddMemberRequest, ApprovalRequest, Conflict, CreateFolderRequest,
    Directory, Enrolled, Invite, InviteRequest, PutItemRequest, SetupRequest, SyncEntry, SyncPage,
};
use keystead_core::directory::DirectoryEntry;
use keystead_core::ids::{DeviceId, FolderId, ItemId, UserId};
use keystead_core::items::{Details, EncryptedItem, FolderInfo, ItemVersion, Overview};
use keystead_core::keys::{AccountKeys, AccountSecret, FolderKey, SoftwareDeviceKey};
use rand::Rng;
use rand::rngs::OsRng;

use crate::client::{Client, Failure};
use crate::state::{FolderRecord, NewProfile, State};

const OWNER: UserId = UserId(1);
const PAGE_SIZE: i64 = 500;

#[derive(Debug)]
pub struct Whoami {
    pub name: String,
    pub user_id: UserId,
    pub fingerprint: String,
    pub server: String,
}

#[derive(Debug)]
pub struct InviteInfo {
    pub server: String,
    pub token: String,
    pub owner_fingerprint: String,
}

#[derive(Debug)]
pub struct UserRow {
    pub user_id: UserId,
    pub name: String,
    pub approved: bool,
    pub fingerprint: String,
}

#[derive(Debug)]
pub struct ItemRow {
    pub folder: String,
    pub name: String,
    pub username: String,
    pub url: String,
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

/// Claims a new server with its setup code. The caller becomes user 1, the owner.
pub fn setup(home: &Path, server: &str, setup_code: &str, name: &str) -> Result<Whoami> {
    refuse_existing(home)?;
    let secret = AccountSecret::generate();
    let keys = AccountKeys::derive(&secret);
    let device = SoftwareDeviceKey::generate();
    let device_id = DeviceId::random();

    let mut entry = DirectoryEntry {
        user_id: OWNER,
        name: name.to_owned(),
        keys: keys.public(),
        approval: None,
    };
    entry.approve(&keys);
    let client = Client::new(server);
    let enrolled: Enrolled = client.post(
        "/v1/setup",
        &SetupRequest {
            setup_code: setup_code.trim().to_owned(),
            name: name.to_owned(),
            keys: keys.public(),
            device_id,
            device_key: device.public(),
            approval: entry.approval.clone().expect("just approved"),
        },
    )?;

    let mut state = State::new(NewProfile {
        server,
        name,
        user_id: enrolled.user_id,
        device_id,
        device_key: &device,
        secret: &secret,
        owner: keys.public(),
    });
    state.directory = vec![entry];
    state.save(home)?;
    Ok(whoami_of(&state, &keys))
}

/// Creates a single-use invite (owner only).
pub fn invite(home: &Path, name: &str) -> Result<InviteInfo> {
    let state = State::load(home)?;
    let client = connect(&state)?;
    let invite: Invite = client.post(
        "/v1/invites",
        &InviteRequest {
            name: name.to_owned(),
        },
    )?;
    Ok(InviteInfo {
        server: state.server.clone(),
        token: invite.token,
        owner_fingerprint: state.owner.fingerprint(),
    })
}

/// Joins with an invite, and pins the owner's keys after checking their fingerprint.
pub fn join(home: &Path, server: &str, token: &str, owner_fingerprint: &str) -> Result<Whoami> {
    refuse_existing(home)?;
    let secret = AccountSecret::generate();
    let keys = AccountKeys::derive(&secret);
    let device = SoftwareDeviceKey::generate();
    let device_id = DeviceId::random();

    let mut client = Client::new(server);
    let enrolled: Enrolled = client.post(
        "/v1/invites/accept",
        &AcceptInviteRequest {
            token: token.trim().to_owned(),
            keys: keys.public(),
            device_id,
            device_key: device.public(),
        },
    )?;
    client.sign_in(device_id, &device)?;
    let directory: Directory = client.get("/v1/directory", &[])?;

    let owner = directory
        .entries
        .iter()
        .find(|entry| entry.user_id == OWNER)
        .context("the server has no owner")?;
    if owner.keys.fingerprint() != normalize(owner_fingerprint)
        || owner.verify(&owner.keys).is_err()
    {
        bail!(
            "the owner's fingerprint on this server is {}, not {}. Don't trust this server; \
             ask the owner for a new invite.",
            owner.keys.fingerprint(),
            normalize(owner_fingerprint)
        );
    }
    let name = directory
        .entries
        .iter()
        .find(|entry| entry.user_id == enrolled.user_id)
        .map(|entry| entry.name.clone())
        .context("the server didn't list the new account")?;

    let mut state = State::new(NewProfile {
        server,
        name: &name,
        user_id: enrolled.user_id,
        device_id,
        device_key: &device,
        secret: &secret,
        owner: owner.keys.clone(),
    });
    state.directory = directory.entries;
    state.save(home)?;
    Ok(whoami_of(&state, &keys))
}

pub fn whoami(home: &Path) -> Result<Whoami> {
    let state = State::load(home)?;
    let keys = state.account_keys()?;
    Ok(whoami_of(&state, &keys))
}

/// Everyone on the server, and whether the pinned owner approved them.
pub fn users(home: &Path) -> Result<Vec<UserRow>> {
    let mut state = State::load(home)?;
    let client = connect(&state)?;
    refresh_directory(&mut state, &client)?;
    state.save(home)?;
    Ok(state
        .directory
        .iter()
        .map(|entry| UserRow {
            user_id: entry.user_id,
            name: entry.name.clone(),
            approved: entry.verify(&state.owner).is_ok(),
            fingerprint: entry.keys.fingerprint(),
        })
        .collect())
}

/// Approves a user (owner only), but only if the fingerprint they read out matches.
pub fn approve(home: &Path, user: UserId, fingerprint: &str) -> Result<String> {
    let state = State::load(home)?;
    let keys = state.account_keys()?;
    let client = connect(&state)?;
    let directory: Directory = client.get("/v1/directory", &[])?;
    let mut entry = directory
        .entries
        .into_iter()
        .find(|entry| entry.user_id == user)
        .with_context(|| format!("no user {user}"))?;
    if entry.keys.fingerprint() != normalize(fingerprint) {
        bail!(
            "{}'s fingerprint on the server is {}, not {}. Don't approve; the keys may have \
             been swapped.",
            entry.name,
            entry.keys.fingerprint(),
            normalize(fingerprint)
        );
    }
    entry.approve(&keys);
    let _: () = client.post(
        &format!("/v1/users/{user}/approval"),
        &ApprovalRequest {
            approval: entry.approval.clone().expect("just approved"),
        },
    )?;
    Ok(entry.name)
}

pub fn create_folder(home: &Path, name: &str) -> Result<()> {
    let mut state = State::load(home)?;
    let keys = state.account_keys()?;
    let client = connect(&state)?;
    let folder_id = FolderId::random();
    let key = FolderKey::generate();
    let record = FolderRecord {
        info: FolderInfo {
            name: name.to_owned(),
        }
        .seal(folder_id, &key)?,
        wrapped_key: keys.public().wrap_folder_key(&key, folder_id)?,
    };
    let _: () = client.post(
        "/v1/folders",
        &CreateFolderRequest {
            folder_id,
            info: record.info.clone(),
            wrapped_key: record.wrapped_key.clone(),
        },
    )?;
    state.folders.insert(folder_id, record);
    state.save(home)
}

/// Shares a folder with an approved user by wrapping its key for them.
pub fn share_folder(home: &Path, folder: &str, user: UserId) -> Result<String> {
    let mut state = State::load(home)?;
    let keys = state.account_keys()?;
    let client = connect(&state)?;
    sync_with(&mut state, &client)?;
    let folder_id = state.find_folder(&keys, folder)?;
    let recipient = state
        .trusted_keys(user)
        .with_context(|| format!("user {user} isn't approved by the owner yet"))?;
    let key = state.folder_key(&keys, folder_id)?;
    let _: () = client.post(
        &format!("/v1/folders/{folder_id}/members"),
        &AddMemberRequest {
            user_id: user,
            wrapped_key: recipient.wrap_folder_key(&key, folder_id)?,
        },
    )?;
    state.save(home)?;
    Ok(state.user_name(user))
}

pub fn folders(home: &Path) -> Result<Vec<String>> {
    let state = refreshed(home)?;
    let keys = state.account_keys()?;
    let mut names = state
        .folders
        .keys()
        .map(|&folder_id| state.folder_name(&keys, folder_id))
        .collect::<Result<Vec<_>>>()?;
    names.sort();
    Ok(names)
}

pub fn add(home: &Path, folder: &str, overview: Overview, details: Details) -> Result<()> {
    let mut state = State::load(home)?;
    let keys = state.account_keys()?;
    let client = connect(&state)?;
    sync_with(&mut state, &client)?;
    let folder_id = state.find_folder(&keys, folder)?;
    let key = state.folder_key(&keys, folder_id)?;
    let at = ItemVersion {
        id: ItemId::random(),
        folder_id,
        version: 1,
        author: state.user_id,
    };
    let item = EncryptedItem::seal(at, &key, &keys, &overview, &details)?;
    let saved: EncryptedItem = client.put(
        &format!("/v1/items/{}", item.id),
        &PutItemRequest {
            base_version: None,
            item,
        },
    )?;
    state.items.insert(saved.id, saved);
    state.save(home)
}

pub fn list(home: &Path) -> Result<Vec<ItemRow>> {
    let state = refreshed(home)?;
    let keys = state.account_keys()?;
    let mut rows = Vec::new();
    for item in state.items.values().filter(|item| !item.deleted) {
        let key = state.folder_key(&keys, item.folder_id)?;
        let overview = item.open_overview(&key)?;
        rows.push(ItemRow {
            folder: state.folder_name(&keys, item.folder_id)?,
            name: overview.name,
            username: overview.username,
            url: overview.url,
        });
    }
    rows.sort_by(|a, b| (&a.folder, &a.name).cmp(&(&b.folder, &b.name)));
    Ok(rows)
}

pub fn show(home: &Path, name: &str, folder: Option<&str>) -> Result<(Overview, Details)> {
    let state = refreshed(home)?;
    let keys = state.account_keys()?;
    let item = &state.items[&find_item(&state, &keys, name, folder)?];
    let key = state.folder_key(&keys, item.folder_id)?;
    Ok((item.open_overview(&key)?, item.open_details(&key)?))
}

/// Saves a new password on top of the latest version this device has seen.
pub fn edit(home: &Path, name: &str, folder: Option<&str>, password: &str) -> Result<EditOutcome> {
    let mut state = State::load(home)?;
    let keys = state.account_keys()?;
    let client = connect(&state)?;
    sync_with(&mut state, &client)?;
    let current = state.items[&find_item(&state, &keys, name, folder)?].clone();
    let key = state.folder_key(&keys, current.folder_id)?;
    let overview = current.open_overview(&key)?;
    let mut details = current.open_details(&key)?;
    details.password = password.to_owned();
    let at = ItemVersion {
        id: current.id,
        folder_id: current.folder_id,
        version: current.version + 1,
        author: state.user_id,
    };
    let item = EncryptedItem::seal(at, &key, &keys, &overview, &details)?;
    let result: Result<EncryptedItem, Failure> = client.put(
        &format!("/v1/items/{}", item.id),
        &PutItemRequest {
            base_version: Some(current.version),
            item,
        },
    );
    let outcome = match result {
        Ok(saved) => {
            let version = saved.version;
            state.items.insert(saved.id, saved);
            EditOutcome::Saved { version }
        }
        Err(Failure::Status { code: 409, body }) => {
            let conflict: Conflict = serde_json::from_value(body)?;
            let theirs = conflict.current;
            let author_keys = state
                .trusted_keys(theirs.author)
                .context("the newer version's author isn't approved")?;
            theirs.verify(&author_keys)?;
            let outcome = EditOutcome::Conflict {
                version: theirs.version,
                author: state.user_name(theirs.author),
            };
            state.items.insert(theirs.id, theirs);
            outcome
        }
        Err(error) => return Err(error.into()),
    };
    state.save(home)?;
    Ok(outcome)
}

pub fn sync(home: &Path) -> Result<SyncSummary> {
    let mut state = State::load(home)?;
    let client = connect(&state)?;
    let summary = sync_with(&mut state, &client)?;
    state.save(home)?;
    Ok(summary)
}

/// A random 24-character password.
pub fn generate_password() -> String {
    const CHARACTERS: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_.!@#%^*";
    let mut rng = OsRng;
    (0..24)
        .map(|_| CHARACTERS[rng.gen_range(0..CHARACTERS.len())] as char)
        .collect()
}

/// Pulls feed pages until caught up. Every item must be signed by an author the owner
/// approved; anything else is dropped.
fn sync_with(state: &mut State, client: &Client) -> Result<SyncSummary> {
    refresh_directory(state, client)?;
    let keys = state.account_keys()?;
    let mut summary = SyncSummary::default();
    loop {
        let page: SyncPage = client.get(
            "/v1/sync",
            &[
                ("cursor", state.cursor.to_string()),
                ("limit", PAGE_SIZE.to_string()),
            ],
        )?;
        summary.received += page.entries.len();
        for entry in page.entries {
            match entry {
                SyncEntry::Item { item, .. } => apply(state, item, &mut summary),
                SyncEntry::Joined {
                    folder_id,
                    info,
                    wrapped_key,
                    items,
                    ..
                } => {
                    if keys.unwrap_folder_key(&wrapped_key, folder_id).is_err() {
                        eprintln!("warning: couldn't open the key for a shared folder; skipped it");
                        continue;
                    }
                    state
                        .folders
                        .insert(folder_id, FolderRecord { info, wrapped_key });
                    for item in items {
                        apply(state, item, &mut summary);
                    }
                }
                SyncEntry::Left { folder_id, .. } => {
                    state.folders.remove(&folder_id);
                    state.items.retain(|_, item| item.folder_id != folder_id);
                }
            }
        }
        state.cursor = page.cursor;
        if !page.more {
            return Ok(summary);
        }
    }
}

fn apply(state: &mut State, item: EncryptedItem, summary: &mut SyncSummary) {
    let trusted = state
        .trusted_keys(item.author)
        .is_some_and(|keys| item.verify(&keys).is_ok());
    if !trusted {
        summary.rejected += 1;
        return;
    }
    if state
        .items
        .get(&item.id)
        .is_none_or(|local| local.version < item.version)
    {
        state.items.insert(item.id, item);
    }
}

fn refresh_directory(state: &mut State, client: &Client) -> Result<()> {
    let directory: Directory = client.get("/v1/directory", &[])?;
    state.directory = directory.entries;
    Ok(())
}

/// Loads the profile and syncs it. If the server can't be reached, carries on with the
/// local copy after a warning.
fn refreshed(home: &Path) -> Result<State> {
    let mut state = State::load(home)?;
    let synced = connect(&state).and_then(|client| sync_with(&mut state, &client));
    match synced {
        Ok(summary) => {
            warn_rejected(&summary);
            state.save(home)?;
        }
        Err(error) => eprintln!("warning: couldn't sync ({error:#}); showing the local copy"),
    }
    Ok(state)
}

pub fn warn_rejected(summary: &SyncSummary) {
    if summary.rejected > 0 {
        eprintln!(
            "warning: ignored {} item(s) not signed by an approved user",
            summary.rejected
        );
    }
}

fn connect(state: &State) -> Result<Client> {
    let mut client = Client::new(&state.server);
    client.sign_in(state.device_id, &state.device_key()?)?;
    Ok(client)
}

fn find_item(
    state: &State,
    keys: &AccountKeys,
    name: &str,
    folder: Option<&str>,
) -> Result<ItemId> {
    let folder_id = folder
        .map(|folder| state.find_folder(keys, folder))
        .transpose()?;
    let mut matches = Vec::new();
    for item in state.items.values().filter(|item| !item.deleted) {
        if folder_id.is_some_and(|folder_id| folder_id != item.folder_id) {
            continue;
        }
        let key = state.folder_key(keys, item.folder_id)?;
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

fn refuse_existing(home: &Path) -> Result<()> {
    if State::exists(home) {
        bail!(
            "{} already has a profile; set KEYSTEAD_HOME to use another folder",
            home.display()
        );
    }
    Ok(())
}

fn whoami_of(state: &State, keys: &AccountKeys) -> Whoami {
    Whoami {
        name: state.name.clone(),
        user_id: state.user_id,
        fingerprint: keys.public().fingerprint(),
        server: state.server.clone(),
    }
}

fn normalize(fingerprint: &str) -> String {
    fingerprint.trim().to_lowercase()
}
