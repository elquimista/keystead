//! Who is in a folder or a group, as its members signed it.
//!
//! This device hands keys on: a folder's new key to everyone in it, a folder's or a
//! group's current key to someone who recovered. Whom it hands them to comes from the
//! folder's and the group's signed entries (see `keystead_core::folders` and
//! `keystead_core::groups`), not from the server's word. The server still says who has
//! left, which only ever takes access away.

use anyhow::{Context, Result, bail};
use keystead_core::api::{FolderEntryRequest, Health, Members, Role, UpdateGroupRequest};
use keystead_core::folders::FolderEntry;
use keystead_core::ids::{FolderId, GroupId, UserId};

use super::Vault;
use crate::http::{Client, Failure};
use crate::profile::{FolderRecord, OWNER};

const NOT_SIGNED: &str = "nobody has signed for this folder's members yet. One of its managers \
                          needs to open Keystead 0.15 or later first";

impl Vault {
    /// Whether the server keeps folders' and groups' signed members (0.15.0 and later).
    /// Once a server has, this device never goes back to taking its word for them.
    pub(super) fn membership(&mut self) -> Result<bool> {
        if self.profile.membership {
            return Ok(true);
        }
        if let Some(known) = self.server_membership {
            return Ok(known);
        }
        let health: Health = Client::new(&self.profile.server).get("/v1/health", &[])?;
        let has = health.membership >= 1;
        self.server_membership = Some(has);
        self.profile.membership = has;
        Ok(has)
    }

    /// Whether a folder's record from the server carries members this device can go by:
    /// signed entries that check out, continue the ones it has, are for the record's key,
    /// and name this account or a group it's in. A folder that has had entries never goes
    /// back to having none.
    pub(super) fn accepts_members(&self, folder_id: FolderId, record: &FolderRecord) -> bool {
        let known = self
            .profile
            .folders
            .get(&folder_id)
            .map_or(&[][..], |held| held.entries.as_slice());
        if record.entries.is_empty() {
            return known.is_empty();
        }
        if record.entries.len() < known.len() || record.entries[..known.len()] != *known {
            return false;
        }
        let Ok(latest) = self.profile.verify_folder(&record.entries, known.len()) else {
            return false;
        };
        let me = self.profile.user_id;
        latest.folder_id == folder_id
            && latest.generation == record.generation
            && record
                .open_key(&self.keys, &self.groups, folder_id)
                .is_ok_and(|key| key.pin(folder_id) == latest.key)
            && (latest.members.contains(&me)
                || latest
                    .groups
                    .iter()
                    .any(|&group| self.groups.contains(group)))
    }

    /// The folder's members as the server lists them, with its signed entries brought up
    /// to date here: sharing a folder doesn't reach everyone's feed, so the entries this
    /// device has may be behind.
    pub(super) fn folder_members_now(&mut self, folder_id: FolderId) -> Result<Members> {
        let path = format!("/v1/folders/{folder_id}/members");
        let members: Members = self.call(|client| client.get(&path, &[]))??;
        let record = self
            .profile
            .folders
            .get(&folder_id)
            .context("you don't have access to that folder")?;
        if members.entries != record.entries {
            let candidate = FolderRecord {
                info: record.info.clone(),
                wrapped_key: record.wrapped_key.clone(),
                generation: record.generation,
                chain: record.chain.clone(),
                via_group: record.via_group,
                entries: members.entries.clone(),
            };
            if !self.accepts_members(folder_id, &candidate) {
                bail!(
                    "this folder's signed members don't check out, or it changed since the \
                     last sync. Sync and try again"
                );
            }
            self.profile
                .folders
                .get_mut(&folder_id)
                .expect("checked above")
                .entries = candidate.entries;
        }
        Ok(members)
    }

    /// Makes sure a folder has signed members. For one from before 0.15.0 that nobody has
    /// signed for, this account does, if it manages the folder, naming who the server
    /// lists: the one time its word is taken. Returns false if it's still unsigned.
    pub(super) fn sign_folder_members(&mut self, folder_id: FolderId) -> Result<bool> {
        if !self.membership()? {
            return Ok(false);
        }
        let members = self.folder_members_now(folder_id)?;
        let record = &self.profile.folders[&folder_id];
        if !record.entries.is_empty() {
            return Ok(true);
        }
        let me = self.profile.user_id;
        let users: Vec<UserId> = members.members.iter().map(|m| m.user_id).collect();
        let groups: Vec<GroupId> = members.groups.iter().map(|g| g.group_id).collect();
        let in_it = users.contains(&me)
            || groups
                .iter()
                .any(|&group| self.profile.in_group(group, me, true));
        if self.profile.folder_role(folder_id) != Role::Manage || !in_it {
            return Ok(false);
        }
        let key = record.open_key(&self.keys, &self.groups, folder_id)?;
        let mut entry = FolderEntry::first(folder_id, record.generation, &key, users, groups);
        entry.sign(me, &self.keys);
        let path = format!("/v1/folders/{folder_id}/entries");
        let request = FolderEntryRequest {
            entry: entry.clone(),
        };
        match self.call(|client| client.put::<_, ()>(&path, &request))? {
            Ok(()) => {}
            // Another manager did meanwhile; theirs comes with the next look.
            Err(Failure::Status { code: 409, .. }) => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        self.keep_folder_entry(folder_id, entry);
        self.save()?;
        Ok(true)
    }

    /// The folder's next entry for this account to sign, changed by `change`, or `None`
    /// with a server that doesn't keep entries.
    pub(super) fn next_folder_entry(
        &mut self,
        folder_id: FolderId,
        change: impl FnOnce(&mut FolderEntry),
    ) -> Result<Option<FolderEntry>> {
        if !self.membership()? {
            return Ok(None);
        }
        if !self.sign_folder_members(folder_id)? {
            bail!(NOT_SIGNED);
        }
        let latest = self.profile.folders[&folder_id]
            .entries
            .last()
            .expect("signed above");
        let me = self.profile.user_id;
        let in_it = latest.members.contains(&me)
            || latest
                .groups
                .iter()
                .any(|&group| self.profile.in_group(group, me, true));
        if !in_it {
            bail!(
                "you're in this folder through a group whose members haven't been signed for \
                 yet. One of the group's managers needs to open Keystead 0.15 or later first"
            );
        }
        let mut entry = latest.next();
        change(&mut entry);
        entry.sign(me, &self.keys);
        Ok(Some(entry))
    }

    /// Keeps an entry this account just signed and the server took.
    pub(super) fn keep_folder_entry(&mut self, folder_id: FolderId, entry: FolderEntry) {
        if let Some(record) = self.profile.folders.get_mut(&folder_id) {
            record.entries.push(entry);
        }
    }

    /// Before saving something new into a folder: with a server that keeps signed
    /// members, the folder has them. One that only its key vouches for could be anyone's,
    /// the server's included.
    pub(super) fn folder_ready(&mut self, folder_id: FolderId) -> Result<()> {
        if self.membership()?
            && self
                .profile
                .folders
                .get(&folder_id)
                .is_some_and(|record| record.entries.is_empty())
            && !self.sign_folder_members(folder_id)?
        {
            bail!(NOT_SIGNED);
        }
        Ok(())
    }

    /// Whether `user` is among a folder's signed members: whether this device may give
    /// them the folder's key. Always true with a server that doesn't keep entries, which
    /// is taken at its word as before.
    pub(super) fn folder_names(&mut self, folder_id: FolderId, user: UserId) -> Result<bool> {
        if !self.membership()? {
            return Ok(true);
        }
        let named = |vault: &Self| {
            vault
                .profile
                .folders
                .get(&folder_id)
                .and_then(|record| record.entries.last())
                .is_some_and(|latest| latest.members.contains(&user))
        };
        if named(self) {
            return Ok(true);
        }
        // They may have been added since this device last heard.
        self.sign_folder_members(folder_id)?;
        Ok(named(self))
    }

    /// Makes sure a group's members are signed. For a group from before 0.15.0, the owner
    /// or one of its managers in it signs who the server lists, the one time its word is
    /// taken. Returns false if they're still unsigned.
    pub(super) fn sign_group_members(&mut self, group_id: GroupId) -> Result<bool> {
        if !self.membership()? {
            return Ok(false);
        }
        let me = self.profile.user_id;
        let (info, latest) = self.profile.team_group(group_id)?;
        if latest.members.is_some() {
            return Ok(true);
        }
        let manages = me == OWNER || (latest.is_manager(me) && info.members.contains(&me));
        if !manages {
            return Ok(false);
        }
        let mut entry = latest.next().with_members(info.members.clone());
        entry.sign(me, &self.keys);
        let path = format!("/v1/groups/{group_id}");
        let request = UpdateGroupRequest {
            entry: entry.clone(),
        };
        match self.call(|client| client.put::<_, ()>(&path, &request))? {
            Ok(()) => {}
            Err(Failure::Status { code: 409, .. }) => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        self.keep_group_entry(group_id, entry);
        self.save()?;
        Ok(true)
    }

    /// Keeps a group entry this account just signed and the server took.
    pub(super) fn keep_group_entry(
        &mut self,
        group_id: GroupId,
        entry: keystead_core::groups::GroupEntry,
    ) {
        let of_group =
            |entries: &[keystead_core::groups::GroupEntry]| entries[0].group_id == group_id;
        if let Some(info) = self
            .profile
            .team_groups
            .iter_mut()
            .find(|info| !info.entries.is_empty() && of_group(&info.entries))
        {
            info.entries.push(entry.clone());
        }
        if let Some(record) = self.profile.groups.get_mut(&group_id) {
            record.entries.push(entry);
        }
    }

    /// Whether `user` is among a group's signed members: whether this device may give
    /// them the group's secret. Always true with a server that doesn't keep them.
    pub(super) fn group_names(&mut self, group_id: GroupId, user: UserId) -> Result<bool> {
        if !self.membership()? {
            return Ok(true);
        }
        self.sign_group_members(group_id)?;
        Ok(self
            .profile
            .team_group(group_id)
            .is_ok_and(|(_, latest)| latest.has_member(user)))
    }

    /// Signs for the members of the folders and groups from before 0.15.0 that this
    /// account can sign for, so they stop depending on the server's word. Problems wait
    /// for the next sync.
    pub(super) fn sign_members_from_before(&mut self) {
        if !self.membership().unwrap_or(false) {
            return;
        }
        let groups: Vec<GroupId> = self
            .profile
            .team_groups
            .iter()
            .filter_map(|info| info.entries.last())
            .filter(|latest| latest.members.is_none())
            .map(|latest| latest.group_id)
            .collect();
        for group_id in groups {
            let _ = self.sign_group_members(group_id);
        }
        let folders: Vec<FolderId> = self
            .profile
            .folders
            .iter()
            .filter(|(_, record)| record.entries.is_empty())
            .map(|(&folder_id, _)| folder_id)
            .collect();
        for folder_id in folders {
            let _ = self.sign_folder_members(folder_id);
        }
    }
}
