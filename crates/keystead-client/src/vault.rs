//! An unlocked vault: the profile plus the account keys, able to sign in and act.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use keystead_core::api::{
    AcceptInviteRequest, AddMemberRequest, ApprovalRequest, Conflict, CreateFolderRequest,
    Directory, Enrolled, Invite, InviteRequest, PutItemRequest, SetupRequest, SyncEntry, SyncPage,
};
use keystead_core::directory::DirectoryEntry;
use keystead_core::ids::{DeviceId, FolderId, ItemId, UserId};
use keystead_core::items::{Details, EncryptedItem, FolderInfo, ItemVersion, Overview};
use keystead_core::keys::{AccountKeys, AccountSecret, FolderKey};
use rand::Rng;
use rand::rngs::OsRng;

use crate::DeviceSigner;
use crate::http::{Client, Failure};
use crate::profile::{FolderRecord, Profile};

const OWNER: UserId = UserId(1);
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

#[derive(Debug)]
pub struct ItemRow {
    pub id: ItemId,
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

/// What enrolling a new device needs, whatever the platform.
pub struct NewAccount<'a> {
    pub server: &'a str,
    pub secret: &'a AccountSecret,
    pub device_id: DeviceId,
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
        },
    )?;
    client.sign_in(account.device_id, account.signer.as_ref())?;
    let directory: Directory = client.get("/v1/directory", &[])?;

    let owner = directory
        .entries
        .iter()
        .find(|entry| entry.user_id == OWNER)
        .context("the server has no owner")?;
    let expected = normalize(owner_fingerprint);
    if owner.keys.fingerprint() != expected || owner.verify(&owner.keys).is_err() {
        bail!(
            "the owner's fingerprint on this server is {}, not {expected}. Don't trust this \
             server; ask the owner for a new invite.",
            owner.keys.fingerprint()
        );
    }
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
        let mut rows = Vec::new();
        for item in self.profile.items.values().filter(|item| !item.deleted) {
            let key = self.profile.folder_key(&self.keys, item.folder_id)?;
            let overview = item.open_overview(&key)?;
            rows.push(ItemRow {
                id: item.id,
                folder: self.profile.folder_name(&self.keys, item.folder_id)?,
                name: overview.name,
                username: overview.username,
                url: overview.url,
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
            if folder_id.is_some_and(|folder_id| folder_id != item.folder_id) {
                continue;
            }
            let key = self.profile.folder_key(&self.keys, item.folder_id)?;
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
        let item = self
            .profile
            .items
            .get(&item_id)
            .filter(|item| !item.deleted)
            .context("no such login")?;
        let key = self.profile.folder_key(&self.keys, item.folder_id)?;
        Ok((item.open_overview(&key)?, item.open_details(&key)?))
    }

    pub fn add(&mut self, folder: &str, overview: Overview, details: Details) -> Result<ItemId> {
        self.sync()?;
        let folder_id = self.profile.find_folder(&self.keys, folder)?;
        let key = self.profile.folder_key(&self.keys, folder_id)?;
        let at = ItemVersion {
            id: ItemId::random(),
            folder_id,
            version: 1,
            author: self.profile.user_id,
        };
        let request = PutItemRequest {
            base_version: None,
            item: EncryptedItem::seal(at, &key, &self.keys, &overview, &details)?,
        };
        let path = format!("/v1/items/{}", at.id);
        let saved: EncryptedItem = self.call(|client| client.put(&path, &request))??;
        self.profile.items.insert(saved.id, saved);
        self.save()?;
        Ok(at.id)
    }

    /// Saves a new password on top of the latest version this device has seen.
    pub fn edit(&mut self, item_id: ItemId, password: &str) -> Result<EditOutcome> {
        self.sync()?;
        let current = self
            .profile
            .items
            .get(&item_id)
            .filter(|item| !item.deleted)
            .cloned()
            .context("no such login")?;
        let key = self.profile.folder_key(&self.keys, current.folder_id)?;
        let overview = current.open_overview(&key)?;
        let mut details = current.open_details(&key)?;
        details.password = password.to_owned();
        let at = ItemVersion {
            id: current.id,
            folder_id: current.folder_id,
            version: current.version + 1,
            author: self.profile.user_id,
        };
        let request = PutItemRequest {
            base_version: Some(current.version),
            item: EncryptedItem::seal(at, &key, &self.keys, &overview, &details)?,
        };
        let path = format!("/v1/items/{item_id}");
        let outcome = match self.call(|client| client.put::<_, EncryptedItem>(&path, &request))? {
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
        };
        self.save()?;
        Ok(outcome)
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
                self.profile.folders.remove(&folder_id);
                self.profile
                    .items
                    .retain(|_, item| item.folder_id != folder_id);
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
