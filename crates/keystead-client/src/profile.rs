//! The profile: everything a device keeps about its account except secrets. That's the
//! server, the pinned owner keys, the feed cursor, and the encrypted copy of folders,
//! items, groups and the directory. Stored as `profile.json`, the same on every platform.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use keystead_core::api::{Exposure, GroupInfo, KeyLink, Role, Roles, ViaGroup};
use keystead_core::directory::{DirectoryEntry, SignedBefore};
use keystead_core::encoding::{Bytes, Key32};
use keystead_core::folders::{FolderEntry, verify_folder_entries};
use keystead_core::groups::{GroupEntry, GroupKeyring, verify_entries_with};
use keystead_core::ids::{DeviceId, FolderId, GroupId, ItemId, UserId};
use keystead_core::items::{EncryptedItem, FolderInfo, Sealed};
use keystead_core::keys::{AccountKeys, AccountPublicKeys, FolderKey, WrappedKey};
use serde::{Deserialize, Serialize};

/// [`Profile::item_role`] for many items, with the role lists as maps
/// ([`Profile::role_lookup`]).
pub struct RoleLookup<'a> {
    profile: &'a Profile,
    folders: HashMap<FolderId, Role>,
    items: HashMap<ItemId, Role>,
}

impl RoleLookup<'_> {
    pub fn item_role(&self, item: &EncryptedItem) -> Role {
        self.profile.role_from(
            item,
            |folder_id| {
                self.folders
                    .get(&folder_id)
                    .copied()
                    .unwrap_or_else(Role::before_roles)
            },
            |item_id| self.items.get(&item_id).copied(),
        )
    }
}

/// The owner is always the server's first user.
pub const OWNER: UserId = UserId(1);

#[derive(Serialize, Deserialize)]
pub struct FolderRecord {
    pub info: Sealed,
    /// The folder's current key, wrapped for this account, or for a group it's in.
    pub wrapped_key: WrappedKey,
    /// Which key that is: 0 at first, one more each time someone loses access.
    #[serde(default)]
    pub generation: u32,
    /// Each older key, sealed with the one after it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<KeyLink>,
    /// Set when `wrapped_key` is wrapped for a group's key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_group: Option<ViaGroup>,
    /// Who is in the folder, as its members signed it, oldest entry first and checked.
    /// Empty for a folder nobody has signed for yet (made before 0.15.0).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<FolderEntry>,
}

impl FolderRecord {
    /// The folder's key of an earlier `generation`, opened through the chain from the
    /// current one.
    pub fn key_at(
        &self,
        keys: &AccountKeys,
        groups: &GroupKeyring,
        folder_id: FolderId,
        generation: u32,
    ) -> Result<FolderKey> {
        let mut key = self.open_key(keys, groups, folder_id)?;
        let mut at = self.generation;
        while at > generation {
            let link = self
                .chain
                .iter()
                .find(|link| link.generation == at)
                .context("the folder's key chain is missing a link")?;
            key = key.open_previous(&link.previous, folder_id, at)?;
            at -= 1;
        }
        if at != generation {
            bail!("the folder hasn't had that key yet");
        }
        Ok(key)
    }

    /// The folder's current key, through this account or the group it came through.
    pub fn open_key(
        &self,
        keys: &AccountKeys,
        groups: &GroupKeyring,
        folder_id: FolderId,
    ) -> Result<FolderKey> {
        match self.via_group {
            None => Ok(keys.unwrap_folder_key(&self.wrapped_key, folder_id)?),
            Some(via) => {
                let group_keys = groups
                    .get(via.group_id, via.generation)
                    .context("this folder came through a group whose keys aren't here")?;
                Ok(group_keys.unwrap_folder_key(&self.wrapped_key, folder_id)?)
            }
        }
    }
}

/// A group this account is in: its signed entries, and its secret wrapped for this account
/// with the chain to older ones.
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupRecord {
    pub entries: Vec<GroupEntry>,
    pub generation: u32,
    pub wrapped_secret: WrappedKey,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<KeyLink>,
}

#[derive(Serialize, Deserialize)]
pub struct Profile {
    pub server: String,
    pub name: String,
    pub user_id: UserId,
    pub device_id: DeviceId,
    /// The owner's keys, pinned when this device enrolled. Directory entries are trusted
    /// only if the owner signed them.
    pub owner: AccountPublicKeys,
    pub cursor: i64,
    pub folders: BTreeMap<FolderId, FolderRecord>,
    pub items: BTreeMap<ItemId, EncryptedItem>,
    pub directory: Vec<DirectoryEntry>,
    /// This account's roles, from the last sync. Absent from servers before roles, where
    /// everyone could do everything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Roles>,
    /// The groups this account is in, with their keys.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<GroupId, GroupRecord>,
    /// Every group on the team, to share with, from the last sync. Empty before 0.4.0.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub team_groups: Vec<GroupInfo>,
    /// Passwords to change: people who lost access to items this account can change, from
    /// the last sync. Empty before 0.5.0.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exposures: Vec<Exposure>,
    /// The highest key revision seen for each person, approved by the owner. Keys from an
    /// earlier revision are never trusted again, so a server can't swap them back in.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub key_revisions: BTreeMap<UserId, u32>,
    /// After recovering with the owner's help: this account's earlier personal keys,
    /// wrapped for its current keys, to open its own items sealed with them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovered_personal_keys: Vec<WrappedKey>,
    /// For each set of someone's retired keys, the owner's list of what they had signed by
    /// the recovery, checked against the owner when fetched. Retired keys verify only that.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signed_before: Vec<SignedBefore>,
    /// For each folder this device has had, the fingerprint of its first key
    /// ([`FolderKey::pin`]), which every later key's chain leads back to. Kept after
    /// leaving, so a folder can't change, or come back, with a key that isn't one of its
    /// own: anyone can wrap a key for an account, the server included.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub folder_pins: BTreeMap<FolderId, Key32>,
    /// The server keeps folders' and groups' signed members (0.15.0 and later). Once seen
    /// it stays: a server can't go back to having its own word taken for who they are.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub membership: bool,
    /// The server keeps folders' signed roles too (0.17.0 and later). Once seen it stays.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub signed_roles: bool,
    /// The signed entries of groups since deleted, from the last sync: folder entries
    /// their members signed are still checked against them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub former_groups: Vec<Vec<GroupEntry>>,
    /// How far this device had seen logins, folders and groups it no longer holds.
    #[serde(default, skip_serializing_if = "Seen::is_empty")]
    pub seen: Seen,
    /// The number of the agreement to escrow this account withdrew last, from this device
    /// (0 for one from before numbers). An agreement at or below it doesn't count here, so
    /// the server can't turn escrow back on by showing the old one again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escrow_off_at: Option<u64>,
}

/// The newest this device has seen of what it no longer holds: a login it lost, a folder
/// it left, a group it was taken out of. Every copy the server hands it is signed, but an
/// older copy is signed too. What a device holds says how far it has seen; this keeps
/// that after it's dropped, so the server can't hand back an older copy as the current
/// one if it comes back. Each is dropped again once the device holds something at least
/// that new.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    /// Each login's version.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub items: BTreeMap<ItemId, u64>,
    /// Each folder's key generation and the revision of its latest signed entry.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub folders: BTreeMap<FolderId, (u32, u32)>,
    /// The revision of each group's latest entry.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<GroupId, u32>,
}

impl Seen {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty() && self.folders.is_empty() && self.groups.is_empty()
    }
}

impl FolderRecord {
    /// How far this record goes: its key generation and its latest entry's revision.
    pub fn reach(&self) -> (u32, u32) {
        let revision = self.entries.last().map_or(0, |entry| entry.revision);
        (self.generation, revision)
    }
}

/// The revision of a group's latest entry, in a list of them; 0 for none.
pub fn group_revision(entries: &[GroupEntry]) -> u32 {
    entries.last().map_or(0, |entry| entry.revision)
}

impl Profile {
    pub fn new(
        server: &str,
        name: &str,
        user_id: UserId,
        device_id: DeviceId,
        owner: AccountPublicKeys,
    ) -> Self {
        Self {
            server: server.trim_end_matches('/').to_owned(),
            name: name.to_owned(),
            user_id,
            device_id,
            owner,
            cursor: 0,
            folders: BTreeMap::new(),
            items: BTreeMap::new(),
            directory: Vec::new(),
            roles: None,
            groups: BTreeMap::new(),
            team_groups: Vec::new(),
            exposures: Vec::new(),
            key_revisions: BTreeMap::new(),
            recovered_personal_keys: Vec::new(),
            signed_before: Vec::new(),
            folder_pins: BTreeMap::new(),
            membership: false,
            signed_roles: false,
            former_groups: Vec::new(),
            seen: Seen::default(),
            escrow_off_at: None,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            bail!("no Keystead profile at {}", path.display());
        }
        let text = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&text).with_context(|| format!("reading {}", path.display()))
    }

    /// Writes the profile atomically, readable only by the current user. Compact JSON:
    /// it's about 1 KB per login, and nobody reads it but Keystead.
    pub fn save(&self, path: &Path) -> Result<()> {
        write_private(path, &serde_json::to_vec(self)?)
    }

    /// The folder's current key.
    pub fn folder_key(
        &self,
        keys: &AccountKeys,
        groups: &GroupKeyring,
        folder_id: FolderId,
    ) -> Result<FolderKey> {
        let record = self
            .folders
            .get(&folder_id)
            .context("you don't have access to that folder")?;
        record.open_key(keys, groups, folder_id)
    }

    /// Every key the folder has had, newest first, opened through its chain. Items keep
    /// whichever key they were saved with.
    pub fn folder_keys(
        &self,
        keys: &AccountKeys,
        groups: &GroupKeyring,
        folder_id: FolderId,
    ) -> Result<Vec<FolderKey>> {
        let record = self
            .folders
            .get(&folder_id)
            .context("you don't have access to that folder")?;
        let mut all = vec![record.open_key(keys, groups, folder_id)?];
        let mut generation = record.generation;
        while generation > 0 {
            let link = record
                .chain
                .iter()
                .find(|link| link.generation == generation)
                .context("the folder's key chain is missing a link")?;
            let newer = all.last().expect("starts with the current key");
            all.push(newer.open_previous(&link.previous, folder_id, generation)?);
            generation -= 1;
        }
        Ok(all)
    }

    /// This account's role in a folder it's in.
    pub fn folder_role(&self, folder_id: FolderId) -> Role {
        self.roles
            .as_ref()
            .and_then(|roles| {
                roles
                    .folders
                    .iter()
                    .find(|role| role.folder_id == folder_id)
            })
            .map_or_else(Role::before_roles, |role| role.role)
    }

    /// What this account may do with an item: the higher of its folder role and its direct
    /// role; an item's owner always manages it.
    pub fn item_role(&self, item: &EncryptedItem) -> Role {
        self.role_from(
            item,
            |folder_id| self.folder_role(folder_id),
            |item_id| {
                self.roles.as_ref().and_then(|roles| {
                    roles
                        .items
                        .iter()
                        .find(|role| role.item_id == item_id)
                        .map(|role| role.role)
                })
            },
        )
    }

    /// `item_role` for going through many items: the role lists as maps, built once.
    pub fn role_lookup(&self) -> RoleLookup<'_> {
        let mut folders = HashMap::new();
        let mut items = HashMap::new();
        if let Some(roles) = &self.roles {
            for role in &roles.folders {
                folders.entry(role.folder_id).or_insert(role.role);
            }
            for role in &roles.items {
                items.entry(role.item_id).or_insert(role.role);
            }
        }
        RoleLookup {
            profile: self,
            folders,
            items,
        }
    }

    /// An item's role, from its folder's role and its own, however they're looked up.
    fn role_from(
        &self,
        item: &EncryptedItem,
        folder_role: impl Fn(FolderId) -> Role,
        direct_role: impl Fn(ItemId) -> Option<Role>,
    ) -> Role {
        if self.roles.is_none() || item.owner == Some(self.user_id) {
            return Role::Manage;
        }
        let in_folder = item
            .folder_id
            .filter(|folder_id| self.folders.contains_key(folder_id))
            .map(folder_role);
        in_folder.max(direct_role(item.id)).unwrap_or(Role::View)
    }

    pub fn folder_name(
        &self,
        keys: &AccountKeys,
        groups: &GroupKeyring,
        folder_id: FolderId,
    ) -> Result<String> {
        let record = self
            .folders
            .get(&folder_id)
            .context("you don't have access to that folder")?;
        let key = self.folder_key(keys, groups, folder_id)?;
        Ok(FolderInfo::open(&record.info, folder_id, &key)?.name)
    }

    pub fn find_folder(
        &self,
        keys: &AccountKeys,
        groups: &GroupKeyring,
        name: &str,
    ) -> Result<FolderId> {
        let mut matches = Vec::new();
        for &folder_id in self.folders.keys() {
            if self.folder_name(keys, groups, folder_id)? == name {
                matches.push(folder_id);
            }
        }
        match matches.as_slice() {
            [folder_id] => Ok(*folder_id),
            [] => bail!("no folder named {name:?}"),
            _ => bail!("several folders are named {name:?}"),
        }
    }

    /// Whether the owner removed this user from the team.
    pub fn is_removed(&self, user: UserId) -> bool {
        self.directory
            .iter()
            .any(|entry| entry.user_id == user && entry.removed)
    }

    /// Takes the directory from the server, and remembers the highest key revision the
    /// owner approved for each person.
    pub fn set_directory(&mut self, entries: Vec<DirectoryEntry>) {
        for entry in &entries {
            if entry.verify(&self.owner).is_ok() {
                let pinned = self.key_revisions.entry(entry.user_id).or_insert(0);
                *pinned = (*pinned).max(entry.revision);
            }
        }
        self.directory = entries;
    }

    /// A user's entry, if the pinned owner approved it and it isn't from before keys
    /// they've had since.
    pub fn trusted_entry(&self, user: UserId) -> Option<&DirectoryEntry> {
        let pinned = self.key_revisions.get(&user).copied().unwrap_or(0);
        self.directory.iter().find(|entry| {
            entry.user_id == user && entry.revision >= pinned && entry.verify(&self.owner).is_ok()
        })
    }

    /// A user's keys, if the pinned owner approved their directory entry: the keys to
    /// share with them.
    pub fn trusted_keys(&self, user: UserId) -> Option<AccountPublicKeys> {
        self.trusted_entry(user).map(|entry| entry.keys.clone())
    }

    /// Whether an item version's signature checks out against its author's approved keys.
    pub fn signed_by_author(&self, item: &EncryptedItem) -> bool {
        self.signed_by(item.author, &item.signature_digest(), |keys| {
            item.verify(keys).is_ok()
        })
    }

    /// Whether a version of a login in one of this device's folders could be its author's
    /// to save, by the folder's signed roles: not if the most they ever were there is a
    /// viewer. The server's word that they may edit doesn't count against that.
    ///
    /// Anyone the folder's entries never named passes: someone the login was shared with
    /// directly, whose role only the server keeps. So does anyone in an entry from before
    /// roles were signed, when everyone could do everything.
    pub fn author_could_save(&self, item: &EncryptedItem) -> bool {
        let Some(record) = item.folder_id.and_then(|folder| self.folders.get(&folder)) else {
            return true;
        };
        let latest = record.entries.len();
        let most = record
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                // A group's members now, for the folder's latest entry; anyone it ever
                // had, for the ones before.
                entry.role_of(item.author, |group, user| {
                    self.in_group(group, user, index + 1 == latest)
                })
            })
            .max();
        most != Some(Role::View)
    }

    /// Whether this device's folder has signed roles: then its logins open with the
    /// folder's key and no other copy (see `Vault::item_key`).
    pub fn folder_has_roles(&self, folder_id: FolderId) -> bool {
        self.folders
            .get(&folder_id)
            .and_then(|record| record.entries.last())
            .is_some_and(|latest| latest.roles.is_some())
    }

    /// Whether `user` signed what `digest` names, `verify` checking the signature against a
    /// set of keys: their current keys, or keys since retired after a recovery, but those
    /// only for what's on the owner's list of what they had signed by then.
    fn signed_by(
        &self,
        user: UserId,
        digest: &Bytes,
        verify: impl Fn(&AccountPublicKeys) -> bool,
    ) -> bool {
        let Some(entry) = self.trusted_entry(user) else {
            return false;
        };
        verify(&entry.keys)
            || entry.retired_keys(&self.owner).into_iter().any(|retired| {
                self.signed_before(user, retired.revision)
                    .is_some_and(|list| list.contains(digest))
                    && verify(&retired.keys)
            })
    }

    /// The owner's list of what `user`'s keys at `revision` had signed, if fetched.
    pub fn signed_before(&self, user: UserId, revision: u32) -> Option<&SignedBefore> {
        self.signed_before
            .iter()
            .find(|list| list.user_id == user && list.revision == revision)
    }

    /// Keeps the owner's list of what someone's retired keys had signed, if the owner
    /// signed it.
    pub fn add_signed_before(&mut self, list: SignedBefore) -> Result<()> {
        list.verify(&self.owner)
            .context("the list of what someone's earlier keys signed isn't the owner's")?;
        if self.signed_before(list.user_id, list.revision).is_none() {
            self.signed_before.push(list);
        }
        Ok(())
    }

    /// Retired keys of approved people whose list of what they had signed isn't here yet.
    pub fn missing_signed_before(&self) -> Vec<(UserId, u32)> {
        let mut missing = Vec::new();
        for entry in &self.directory {
            if self.trusted_entry(entry.user_id) != Some(entry) {
                continue;
            }
            for retired in entry.retired_keys(&self.owner) {
                if self
                    .signed_before(entry.user_id, retired.revision)
                    .is_none()
                {
                    missing.push((entry.user_id, retired.revision));
                }
            }
        }
        missing
    }

    pub fn user_name(&self, user: UserId) -> String {
        self.directory
            .iter()
            .find(|entry| entry.user_id == user)
            .map_or_else(|| format!("user {user}"), |entry| entry.name.clone())
    }

    /// Checks a group's entries against the owner and the approved directory, and returns
    /// the latest.
    pub fn verify_group<'a>(&self, entries: &'a [GroupEntry]) -> Result<&'a GroupEntry> {
        Ok(verify_entries_with(entries, OWNER, |entry| {
            self.signed_by(entry.signer, &entry.signature_digest(), |keys| {
                entry.verify(keys).is_ok()
            })
        })?)
    }

    /// Whether `user` is in a group by the group's own signed entries: in its latest one
    /// if `current`, else in any of them, for a folder entry signed when the group's
    /// members may have been others. A group since deleted counts by the entries it had.
    pub fn in_group(&self, group_id: GroupId, user: UserId, current: bool) -> bool {
        let live = self
            .team_groups
            .iter()
            .map(|info| &info.entries)
            .find(|entries| entries.first().is_some_and(|e| e.group_id == group_id));
        let former = self
            .former_groups
            .iter()
            .find(|entries| entries.first().is_some_and(|e| e.group_id == group_id));
        if current {
            // A deleted group's last entry is who was in it to the end.
            return live
                .or(former)
                .and_then(|entries| self.verify_group(entries).ok())
                .is_some_and(|latest| latest.has_member(user));
        }
        live.or(former).is_some_and(|entries| {
            self.verify_group(entries).is_ok() && entries.iter().any(|e| e.has_member(user))
        })
    }

    /// Checks a folder's signed entries, oldest first, and returns the latest: each is
    /// signed by an approved person who was in the folder, or in a group it was shared
    /// with, by the entry before. `known` is how many of them this device has checked
    /// before; a newer last one counts only if its signer is in the folder or one of its
    /// groups now.
    pub fn verify_folder<'a>(
        &self,
        entries: &'a [FolderEntry],
        known: usize,
    ) -> Result<&'a FolderEntry> {
        Ok(verify_folder_entries(
            entries,
            |entry| {
                self.signed_by(entry.signer, &entry.signature_digest(), |keys| {
                    entry.verify(keys).is_ok()
                })
            },
            |group, user, latest| {
                self.in_group(group, user, latest && known > 0 && entries.len() > known)
            },
        )?)
    }

    /// A group on the team, checked, with its latest entry.
    pub fn team_group(&self, group_id: GroupId) -> Result<(&GroupInfo, &GroupEntry)> {
        let info = self
            .team_groups
            .iter()
            .find(|info| info.entries.first().is_some_and(|e| e.group_id == group_id))
            .context("no such group")?;
        Ok((info, self.verify_group(&info.entries)?))
    }

    /// Whether a group is still on the team, as of the last sync; a deleted one isn't.
    pub fn group_exists(&self, group_id: GroupId) -> bool {
        self.team_groups
            .iter()
            .any(|info| info.entries.first().is_some_and(|e| e.group_id == group_id))
    }

    /// A group's name, if it checks out.
    pub fn group_name(&self, group_id: GroupId) -> String {
        self.team_group(group_id)
            .map(|(_, entry)| entry.name.clone())
            .or_else(|_| {
                let record = self.groups.get(&group_id).context("unknown")?;
                Ok::<_, anyhow::Error>(self.verify_group(&record.entries)?.name.clone())
            })
            .unwrap_or_else(|_| "a group".to_owned())
    }

    pub fn find_group(&self, name: &str) -> Result<GroupId> {
        let matches: Vec<GroupId> = self
            .team_groups
            .iter()
            .filter_map(|info| self.verify_group(&info.entries).ok())
            .filter(|entry| entry.name == name)
            .map(|entry| entry.group_id)
            .collect();
        match matches.as_slice() {
            [group_id] => Ok(*group_id),
            [] => bail!("no group named {name:?}"),
            _ => bail!("several groups are named {name:?}"),
        }
    }

    /// The keys of every group this account is in whose entries check out and whose
    /// secret opens, each generation of each.
    pub fn group_keyring(&self, keys: &AccountKeys) -> GroupKeyring {
        let mut keyring = GroupKeyring::default();
        for (&group_id, record) in &self.groups {
            // A group that doesn't check out is left out; whatever it shares stays shut.
            let _ = self.add_group_keys(&mut keyring, keys, group_id, record);
        }
        keyring
    }

    pub fn add_group_keys(
        &self,
        keyring: &mut GroupKeyring,
        keys: &AccountKeys,
        group_id: GroupId,
        record: &GroupRecord,
    ) -> Result<()> {
        let latest = self.verify_group(&record.entries)?;
        if latest.group_id != group_id || latest.generation != record.generation {
            bail!("the group's keys don't match its entries");
        }
        let secret =
            keys.unwrap_group_secret(&record.wrapped_secret, group_id, record.generation)?;
        keyring.add(latest, secret, &record.chain)?;
        Ok(())
    }
}

/// Writes a file atomically, readable only by the current user, creating its folder
/// (readable only by the current user) if needed.
pub fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let folder = path.parent().context("a profile path needs a folder")?;
    fs::create_dir_all(folder).with_context(|| format!("creating {}", folder.display()))?;
    restrict(folder, 0o700)?;
    let temporary = path.with_extension("tmp");
    let mut file = fs::File::create(&temporary)?;
    restrict(&temporary, 0o600)?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}
