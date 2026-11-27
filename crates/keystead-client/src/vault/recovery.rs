//! Recovering with the team owner's help, for someone who lost every device and their
//! recovery kit. The owner starts it and sends a one-time line; the new device makes new
//! keys and sends them; the owner approves them after checking their fingerprint with the
//! person. Then everyone's apps make the person copies, for the new keys, of what was
//! shared with them. If they let the owner keep their personal key in escrow, their own
//! logins come back too, and the folders only they could open, whose keys their app kept
//! in escrow sealed with that personal key.

use std::path::Path;

use anyhow::{Context, Result, bail};
use keystead_core::api::{
    ApproveRecoveryRequest, ClaimRecoveryRequest, Directory, EscrowRequest, EscrowedFolder,
    FolderEscrowRequest, Health, RecoveryClaimed, RecoveryInProgress, RecoveryStarted,
    RecoveryState, RecoveryTokenRequest, Restore, RestoreFolderKeyRequest,
    RestoreGroupSecretRequest,
};
use keystead_core::directory::{DirectoryEntry, SignedBefore, escrow_consent};
use keystead_core::groups::GroupEntry;
use keystead_core::ids::{FolderId, GroupId, ItemId, UserId};
use keystead_core::items::{EncryptedItem, ITEM_FORMAT};
use keystead_core::keys::{AccountKeys, ItemKey, WrappedKey};

use super::{
    EditOutcome, NewAccount, Owner, People, SyncSummary, Vault, check_owner, normalize, owner_entry,
};
use crate::http::{Client, Failure, check_server_address};
use crate::profile::{OWNER, Profile};

/// How many earlier personal keys a device keeps after recoveries.
const MAX_RECOVERED_KEYS: usize = 8;

/// Recovering with the owner's help, and escrow, came with 0.13.0.
const NEEDS_0_13: &str = "the server is older than Keystead 0.13.0 and can't help anyone \
                          recover; update it to 0.13.0 or later";

/// What someone recovering gets from the owner, like an invite:
/// `keystead recover-with-help <server> <token> --owner <fingerprint>`. The token works
/// once, for a week, and only until the owner approves new keys with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryLine {
    pub server: String,
    pub token: String,
    pub owner_fingerprint: String,
}

impl RecoveryLine {
    pub fn command(&self) -> String {
        format!(
            "keystead recover-with-help {} {} --owner {}",
            self.server, self.token, self.owner_fingerprint
        )
    }

    /// Reads a recovery line back, with or without the leading `keystead recover-with-help`.
    pub fn parse(text: &str) -> Result<Self> {
        let mut words: Vec<&str> = text.split_whitespace().collect();
        if words.first() == Some(&"keystead") {
            words.remove(0);
        }
        if words.first() == Some(&"recover-with-help") {
            words.remove(0);
        }
        let owner = words
            .iter()
            .position(|&word| word == "--owner")
            .filter(|&index| index + 1 < words.len())
            .context("a recovery line ends with --owner and the owner's fingerprint")?;
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
            _ => bail!("a recovery line has a server address starting with http and a token"),
        }
    }
}

/// Whose account a recovery line is for, and the new keys' fingerprint, for the person to
/// read to the owner.
#[derive(Debug)]
pub struct RecoveryClaim {
    pub user_id: UserId,
    pub name: String,
    pub fingerprint: String,
}

/// A recovery waiting for the owner's approval. The new keys' fingerprint isn't here: the
/// owner hears it from the person and types it in, and approving checks it.
#[derive(Debug)]
pub struct RecoveryRequest {
    /// The person has used the line on their new device.
    pub claimed: bool,
    /// Their personal key is in escrow, so their own logins and the folders only they
    /// could open can come back.
    pub escrow: bool,
}

/// A recovery the owner approved.
#[derive(Debug)]
pub struct ApprovedRecovery {
    pub name: String,
    /// Their own logins and the folders only they could open come back: their personal
    /// key was in escrow, and opened.
    pub own_logins: bool,
}

/// What a sync asked of this device: copies for people who recovered, and, after this
/// account recovered, its earlier personal key and escrow.
#[derive(Default)]
pub(super) struct RecoveryDuties {
    pub restore: Restore,
    pub recovered_key: Option<WrappedKey>,
    pub escrow_needed: bool,
    /// Folders only this account can open, whose current key isn't in escrow yet.
    pub escrow_folders: Vec<FolderId>,
}

/// Sends a new account's keys and this device's key for a recovery the owner started.
/// Nothing changes until the owner approves; sending again from the same device is fine.
pub fn claim_recovery(line: &RecoveryLine, account: &NewAccount<'_>) -> Result<RecoveryClaim> {
    check_server_address(account.server)?;
    let keys = AccountKeys::derive(account.secret);
    let request = ClaimRecoveryRequest {
        token: line.token.trim().to_owned(),
        keys: keys.public(),
        device_id: account.device_id,
        device_key: account.signer.public_key(),
        device_name: account.device_name.to_owned(),
    };
    let claimed: RecoveryClaimed =
        match Client::new(account.server).post("/v1/recovery/claim", &request) {
            Ok(claimed) => claimed,
            Err(Failure::Status {
                code: 404 | 405, ..
            }) => bail!(NEEDS_0_13),
            Err(error) => return Err(error.into()),
        };
    Ok(RecoveryClaim {
        user_id: claimed.user_id,
        name: claimed.name,
        fingerprint: keys.public().fingerprint(),
    })
}

/// Where a recovery stands, for the new device waiting on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryProgress {
    /// The owner hasn't approved the new keys yet.
    Waiting,
    Approved,
    /// The owner cancelled it, or it expired: they need to start again.
    Ended,
}

/// Whether the owner has approved the new keys yet. An error means the server couldn't be
/// asked; keep waiting and ask again.
pub fn recovery_progress(line: &RecoveryLine) -> Result<RecoveryProgress> {
    let request = RecoveryTokenRequest {
        token: line.token.trim().to_owned(),
    };
    match Client::new(&line.server).post::<_, RecoveryState>("/v1/recovery/state", &request) {
        Ok(state) if state.approved => Ok(RecoveryProgress::Approved),
        Ok(_) => Ok(RecoveryProgress::Waiting),
        Err(Failure::Status { code: 404, .. }) => Ok(RecoveryProgress::Ended),
        Err(error) => Err(error.into()),
    }
}

/// Whether the owner has approved the new keys yet. A cancelled or expired recovery is an
/// error.
pub fn recovery_approved(line: &RecoveryLine) -> Result<bool> {
    match recovery_progress(line)? {
        RecoveryProgress::Approved => Ok(true),
        RecoveryProgress::Waiting => Ok(false),
        RecoveryProgress::Ended => {
            bail!("the owner cancelled this recovery, or it expired; ask them to start again")
        }
    }
}

/// Once the owner approved: signs this device in and keeps its profile, after checking
/// the owner against the line's fingerprint, and that the owner approved this account's
/// new keys. Call `sync` afterwards.
pub fn finish_recovery(path: &Path, account: NewAccount<'_>, line: &RecoveryLine) -> Result<Vault> {
    let keys = AccountKeys::derive(account.secret);
    let mut client = Client::new(account.server);
    client.sign_in(account.device_id, account.signer.as_ref())?;
    let directory: Directory = client.get("/v1/directory", &[])?;
    let owner = owner_entry(&directory)?;
    check_owner(
        owner,
        Owner::Fingerprint(&line.owner_fingerprint),
        "ask the owner for a new recovery line",
    )?;
    let me = directory
        .entries
        .iter()
        .find(|entry| entry.keys == keys.public() && entry.verify(&owner.keys).is_ok())
        .context("the owner hasn't approved this device's keys. Don't trust this server.")?;
    let mut profile = Profile::new(
        account.server,
        &me.name,
        me.user_id,
        account.device_id,
        owner.keys.clone(),
    );
    profile.set_directory(directory.entries.clone());
    Vault::create(path, profile, keys, account.signer)
}

impl Vault {
    /// Starts helping someone who lost every device and their recovery kit (owner only).
    /// Returns the line to send them; an earlier one stops working. With
    /// `sign_out_devices`, their devices stop working at once, so a lost one that still
    /// works can't cancel the recovery; if they have one after all, their recovery kit
    /// gets them back in.
    pub fn start_recovery(&mut self, user: UserId, sign_out_devices: bool) -> Result<RecoveryLine> {
        let path = if sign_out_devices {
            format!("/v1/users/{user}/recovery?sign_out_devices=true")
        } else {
            format!("/v1/users/{user}/recovery")
        };
        let started: RecoveryStarted = match self.call(|client| client.post_empty(&path))? {
            Ok(started) => started,
            Err(Failure::Status {
                code: 404 | 405, ..
            }) if self.server_version()? < (0, 13) => bail!(NEEDS_0_13),
            Err(error) => return Err(error.into()),
        };
        Ok(RecoveryLine {
            server: self.profile.server.clone(),
            token: started.token,
            owner_fingerprint: self.profile.owner.fingerprint(),
        })
    }

    /// Someone's recovery waiting for approval, if there is one (owner only).
    pub fn recovery_request(&mut self, user: UserId) -> Result<Option<RecoveryRequest>> {
        let path = format!("/v1/users/{user}/recovery");
        match self.call(|client| client.get::<RecoveryInProgress>(&path, &[]))? {
            Ok(request) => Ok(Some(RecoveryRequest {
                claimed: request.keys.is_some(),
                escrow: request.escrow.is_some(),
            })),
            Err(Failure::Status { code: 404, .. }) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Approves someone's new keys (owner only), but only if the fingerprint they read out
    /// matches. Their old devices stop working, and everything shared with them comes back
    /// as others' apps make them copies. If their personal key was in escrow, it's wrapped
    /// for the new keys too, so their own logins come back. Signs the list of what their
    /// old keys had signed, from the server and this app: those keys verify nothing else.
    pub fn approve_recovery(
        &mut self,
        user: UserId,
        fingerprint: &str,
    ) -> Result<ApprovedRecovery> {
        self.users()?;
        let path = format!("/v1/users/{user}/recovery");
        let request: RecoveryInProgress = match self.call(|client| client.get(&path, &[]))? {
            Ok(request) => request,
            Err(Failure::Status { code: 404, .. }) => {
                bail!("no recovery is waiting for them; start one first")
            }
            Err(error) => return Err(error.into()),
        };
        let keys = request
            .keys
            .context("they haven't used the recovery line on their new device yet")?;
        if keys.fingerprint() != normalize(fingerprint) {
            bail!(
                "that isn't the fingerprint of the keys their new device sent. Check it with \
                 them again; if it still doesn't match, don't approve: someone else may have \
                 used the line. Cancel it and start again."
            );
        }
        let current = self
            .profile
            .trusted_entry(user)
            .cloned()
            .context("they aren't approved; approve them first")?;
        let mut approved = DirectoryEntry::new(user, &current.name, keys.clone());
        approved.revision = current
            .revision
            .checked_add(1)
            .context("their keys can't be replaced again")?;
        approved.approve(&self.keys);
        let personal_key = request.escrow.as_ref().and_then(|escrowed| {
            let key = self.keys.unwrap_personal_key(escrowed, user).ok()?;
            keys.wrap_personal_key(&key, user).ok()
        });
        let own_logins = personal_key.is_some();
        // What this app holds that the old keys signed, in case the server left any out.
        let here = self
            .profile
            .items
            .values()
            .filter(|item| item.author == user && item.verify(&current.keys).is_ok())
            .map(EncryptedItem::signature_digest);
        let groups = self
            .profile
            .team_groups
            .iter()
            .flat_map(|group| &group.entries)
            .filter(|entry| entry.signer == user && entry.verify(&current.keys).is_ok())
            .map(GroupEntry::signature_digest);
        let mut signed_before = SignedBefore::new(
            user,
            current.revision,
            request.signed.into_iter().chain(here).chain(groups),
        );
        signed_before.approve(&self.keys);
        let body = ApproveRecoveryRequest {
            revision: approved.revision,
            approval: approved.approval.clone().expect("just approved"),
            signed_before,
            personal_key,
        };
        let path = format!("/v1/users/{user}/recovery/approval");
        let () = self.call(|client| client.post(&path, &body))??;
        // Never trust their old keys again, whatever the server shows from now on.
        let pinned = self.profile.key_revisions.entry(user).or_insert(0);
        *pinned = (*pinned).max(approved.revision);
        self.save()?;
        self.users()?;
        Ok(ApprovedRecovery {
            name: current.name,
            own_logins,
        })
    }

    /// Stops a recovery that isn't approved yet: the owner, for anyone, or anyone for
    /// their own account, from a device they still have.
    pub fn cancel_recovery(&mut self, user: UserId) -> Result<()> {
        let path = format!("/v1/users/{user}/recovery");
        match self.call(|client| client.delete::<()>(&path))? {
            Ok(()) => Ok(()),
            Err(Failure::Status { code: 404, .. }) => {
                bail!("no recovery is waiting for approval")
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Lets the team owner recover this account's own logins, and the folders only it can
    /// open, after a recovery (escrow), or stops it. The owner could then open them at any
    /// time. Not for the owner. Turning it on syncs, to put those folders in escrow.
    pub fn set_escrow(&mut self, on: bool) -> Result<()> {
        if on {
            self.escrow_personal_key()?;
            self.sync()?;
            return Ok(());
        }
        // From now on the agreement being withdrawn, and any before it, count for nothing
        // here, whatever the server shows. Remembered first: if the server never hears,
        // this device has still stopped putting anything in escrow.
        let withdrawn = self.own_escrow_sequence();
        self.profile.escrow_off_at = Some(withdrawn.max(self.profile.escrow_off_at.unwrap_or(0)));
        self.save()?;
        match self.call(|client| client.delete::<()>("/v1/escrow"))? {
            Ok(()) => {}
            Err(Failure::Status {
                code: 404 | 405, ..
            }) => bail!(NEEDS_0_13),
            Err(error) => return Err(error.into()),
        }
        self.users()?;
        Ok(())
    }

    /// The number of this account's latest agreement to escrow, as the directory says.
    fn own_escrow_sequence(&self) -> u64 {
        self.profile
            .trusted_entry(self.profile.user_id)
            .map_or(0, |entry| entry.escrow_sequence)
    }

    /// Wraps this account's personal key for the owner, and turns escrow on.
    fn escrow_personal_key(&mut self) -> Result<()> {
        if self.profile.user_id == OWNER {
            bail!(
                "the owner's own logins can't be in escrow; the owner's recovery kit is the way \
                 back"
            );
        }
        let revision = self
            .profile
            .trusted_entry(self.profile.user_id)
            .map_or(0, |entry| entry.revision);
        // A server on 0.18.0 or later takes an agreement that signs a number past every
        // one before, so this device can tell it from one it withdrew. An older server
        // takes only one without a number; then this device can't tell them apart, and
        // takes the server's word again, as before.
        let health: Health = Client::new(&self.profile.server).get("/v1/health", &[])?;
        let sequence = if health.escrow >= 2 {
            self.own_escrow_sequence()
                .max(self.profile.escrow_off_at.unwrap_or(0))
                + 1
        } else {
            0
        };
        let me = self.profile.user_id;
        let request = EscrowRequest {
            wrapped_key: self.keys.wrap_personal_key_for(&self.profile.owner, me)?,
            consent: escrow_consent(&self.keys, me, (revision, sequence)),
            sequence,
        };
        match self.call(|client| client.put::<_, ()>("/v1/escrow", &request))? {
            Ok(()) => {}
            Err(Failure::Status {
                code: 404 | 405, ..
            }) => bail!(NEEDS_0_13),
            Err(error) => return Err(error.into()),
        }
        if sequence == 0 {
            self.profile.escrow_off_at = None;
        }
        self.users()?;
        Ok(())
    }

    /// Does what a sync asked: gives people who recovered copies for their new keys, and
    /// after this account recovered, takes its earlier personal key, gives itself back the
    /// folders it had in escrow, seals its own logins with the new key, and puts the new
    /// one in escrow if escrow is on. Then puts folders only this account can open in
    /// escrow: those the sync listed, and those that just got a new key here. Failures are
    /// reported; the next sync asks again. Returns whether any folder came back, which the
    /// next sync brings.
    pub(super) fn do_recovery_duties(
        &mut self,
        duties: RecoveryDuties,
        rekeyed: &[FolderId],
        summary: &mut SyncSummary,
    ) -> bool {
        for share in duties.restore.folders {
            let name = self.profile.user_name(share.user_id);
            match self.restore_folder(share.folder_id, share.user_id) {
                Ok(()) => summary.restored += 1,
                Err(error) => summary
                    .rekey_problems
                    .push(format!("couldn't give {name} a folder back ({error:#})")),
            }
        }
        for share in duties.restore.groups {
            let name = self.profile.user_name(share.user_id);
            match self.restore_group(share.group_id, share.user_id) {
                Ok(()) => summary.restored += 1,
                Err(error) => summary
                    .rekey_problems
                    .push(format!("couldn't give {name} a group back ({error:#})")),
            }
        }
        for item_id in duties.restore.items {
            match self.resave(item_id) {
                Ok(true) => summary.restored += 1,
                Ok(false) => {}
                Err(error) => summary
                    .rekey_problems
                    .push(format!("couldn't give someone a login back ({error:#})")),
            }
        }
        // A server could send any key wrapped for this account; a few are plenty.
        if let Some(wrapped) = duties.recovered_key
            && self.profile.recovered_personal_keys.len() < MAX_RECOVERED_KEYS
            && !self.profile.recovered_personal_keys.contains(&wrapped)
            && self
                .keys
                .unwrap_personal_key(&wrapped, self.profile.user_id)
                .is_ok()
        {
            self.profile.recovered_personal_keys.push(wrapped);
            if let Err(error) = self.save() {
                summary.rekey_problems.push(format!("{error:#}"));
            }
        }
        let mut came_back = false;
        for escrowed in &duties.restore.escrowed {
            match self.restore_own_folder(escrowed) {
                Ok(()) => came_back = true,
                Err(error) => summary.rekey_problems.push(format!(
                    "couldn't get one of your folders back from escrow ({error:#})"
                )),
            }
        }
        let own = self.own_items_under_earlier_keys();
        // After a recovery this account agrees to escrow again, with its new keys, only if
        // its earlier keys had: their signature, kept with them. Not because something
        // came back from escrow, which is the server's say, and a server can make a key
        // that opens for this account and call it one. Otherwise escrow stays off until
        // the person turns it on.
        let agreed_before = self
            .profile
            .trusted_entry(self.profile.user_id)
            .is_some_and(|entry| entry.earlier_keys_consented(&self.profile.owner));
        for item_id in own {
            if let Err(error) = self.resave(item_id) {
                summary.rekey_problems.push(format!(
                    "couldn't seal one of your logins again ({error:#})"
                ));
            }
        }
        if duties.escrow_needed
            && (self.escrow_on() || agreed_before)
            && let Err(error) = self.escrow_personal_key()
        {
            summary.rekey_problems.push(format!(
                "couldn't put your personal key in escrow ({error:#})"
            ));
        }
        self.put_folders_in_escrow(duties.escrow_folders, rekeyed, summary);
        came_back
    }

    /// Puts a copy of each folder's current key, sealed with this account's personal key,
    /// in escrow: the folders a sync listed, and if escrow is on, those that just got a new
    /// key here, whose copy in escrow is for the old one. The server takes it only for a
    /// folder nobody else can open, and says so otherwise; that's not a problem.
    pub(super) fn put_folders_in_escrow(
        &mut self,
        mut folders: Vec<FolderId>,
        rekeyed: &[FolderId],
        summary: &mut SyncSummary,
    ) {
        if !self.escrow_on() {
            return;
        }
        for folder_id in rekeyed {
            if !folders.contains(folder_id) {
                folders.push(*folder_id);
            }
        }
        for folder_id in folders {
            match self.put_folder_in_escrow(folder_id) {
                Ok(()) => {}
                Err(error) => summary
                    .rekey_problems
                    .push(format!("couldn't put a folder's key in escrow ({error:#})")),
            }
        }
    }

    fn put_folder_in_escrow(&mut self, folder_id: FolderId) -> Result<()> {
        let Some(record) = self.profile.folders.get(&folder_id) else {
            // Not here yet; the next sync asks again.
            return Ok(());
        };
        let generation = record.generation;
        // Escrow is for folders nobody else can open. Which those are is the folder's
        // signed members' say, not the server's: only one that names this account alone.
        if self.profile.membership {
            let me = self.profile.user_id;
            let only_mine = record
                .entries
                .last()
                .is_some_and(|latest| latest.members == [me] && latest.groups.is_empty());
            if !only_mine {
                return Ok(());
            }
        }
        let key = self
            .profile
            .folder_key(&self.keys, &self.groups, folder_id)?;
        let request = FolderEscrowRequest {
            generation,
            sealed: key.seal_for_escrow(&self.keys, folder_id, generation, self.profile.user_id),
        };
        let path = format!("/v1/folders/{folder_id}/escrow");
        match self.call(|client| client.put::<_, ()>(&path, &request))? {
            // Someone else can open it, or this account isn't in it itself.
            Ok(())
            | Err(Failure::Status {
                code: 403 | 409, ..
            }) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Whether this account agreed to escrow with its current keys: its own signature, which
    /// a server can't make, and a later one than any this device withdrew. What a sync asks
    /// for escrow is done only then.
    pub(super) fn escrow_on(&self) -> bool {
        self.profile
            .trusted_entry(self.profile.user_id)
            .is_some_and(|entry| {
                entry.consented_to_escrow()
                    && self
                        .profile
                        .escrow_off_at
                        .is_none_or(|withdrawn| entry.escrow_sequence > withdrawn)
            })
    }

    /// Gives this account back a folder only it could open, from the copy of its key it put
    /// in escrow before recovering, sealed with its earlier personal key.
    fn restore_own_folder(&mut self, escrowed: &EscrowedFolder) -> Result<()> {
        let me = self.profile.user_id;
        let key = self
            .profile
            .recovered_personal_keys
            .iter()
            .filter_map(|wrapped| self.keys.unwrap_personal_key(wrapped, me).ok())
            .find_map(|personal| {
                personal
                    .open_escrowed_folder_key(
                        &escrowed.sealed,
                        escrowed.folder_id,
                        escrowed.generation,
                        me,
                    )
                    .ok()
            })
            .context("its key in escrow doesn't open with your earlier personal key")?;
        let request = RestoreFolderKeyRequest {
            generation: escrowed.generation,
            wrapped_key: self
                .keys
                .public()
                .wrap_folder_key(&key, escrowed.folder_id)?,
        };
        let path = format!("/v1/folders/{}/members/{me}/key", escrowed.folder_id);
        let () = self.call(|client| client.put(&path, &request))??;
        Ok(())
    }

    /// Fetches the owner's list of what each approved person's retired keys had signed,
    /// for any not here yet. Retired keys without one verify nothing: a list that's
    /// missing, or isn't the owner's, is left out.
    pub(super) fn fetch_signed_before(&mut self) -> Result<()> {
        for (user, revision) in self.profile.missing_signed_before() {
            let path = format!("/v1/users/{user}/retired/{revision}");
            match self.call(|client| client.get::<SignedBefore>(&path, &[]))? {
                Ok(list) if list.user_id == user && list.revision == revision => {
                    // A list the owner didn't sign stays out; the next sync asks again.
                    let _ = self.profile.add_signed_before(list);
                }
                Ok(_) | Err(Failure::Status { code: 404, .. }) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    /// The key of one of this account's own items whose owner's copy is sealed with an
    /// earlier personal key, from before a recovery.
    pub(super) fn recovered_owner_key(&self, item: &EncryptedItem) -> Option<ItemKey> {
        let me = self.profile.user_id;
        self.profile
            .recovered_personal_keys
            .iter()
            .filter_map(|wrapped| self.keys.unwrap_personal_key(wrapped, me).ok())
            .find_map(|personal| item.unlock_as_owner(&personal, me).ok())
    }

    /// This account's own logins still sealed with an earlier personal key.
    fn own_items_under_earlier_keys(&self) -> Vec<ItemId> {
        if self.profile.recovered_personal_keys.is_empty() {
            return Vec::new();
        }
        let me = self.profile.user_id;
        let current = self.keys.personal_key();
        self.profile
            .items
            .values()
            .filter(|item| {
                item.owner == Some(me)
                    && !item.deleted
                    && item.format <= ITEM_FORMAT
                    && item.unlock_as_owner(&current, me).is_err()
                    && self.recovered_owner_key(item).is_some()
            })
            .map(|item| item.id)
            .collect()
    }

    fn restore_folder(&mut self, folder_id: FolderId, user: UserId) -> Result<()> {
        // The server says who's waiting; whether they get the key is the folder's say.
        if !self.profile.folders.contains_key(&folder_id) {
            bail!("this account doesn't have that folder");
        }
        if !self.folder_names(folder_id, user)? {
            bail!("they aren't among this folder's signed members");
        }
        let recipient = self
            .profile
            .trusted_keys(user)
            .context("they aren't approved")?;
        let record = self
            .profile
            .folders
            .get(&folder_id)
            .context("this account doesn't have that folder")?;
        let generation = record.generation;

        let key = self
            .profile
            .folder_key(&self.keys, &self.groups, folder_id)?;
        let request = RestoreFolderKeyRequest {
            generation,
            wrapped_key: recipient.wrap_folder_key(&key, folder_id)?,
        };
        let path = format!("/v1/folders/{folder_id}/members/{user}/key");
        match self.call(|client| client.put::<_, ()>(&path, &request))? {
            // Not waiting any more: the folder's new key, made a moment ago, went to them
            // too. Or the key changed since; the next sync asks again if it's still needed.
            Ok(()) | Err(Failure::Status { code: 409, .. }) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn restore_group(&mut self, group_id: GroupId, user: UserId) -> Result<()> {
        if !self.profile.groups.contains_key(&group_id) {
            bail!("this account isn't in that group");
        }
        if !self.group_names(group_id, user)? {
            bail!("they aren't among this group's signed members");
        }
        let recipient = self
            .profile
            .trusted_keys(user)
            .context("they aren't approved")?;
        let record = self
            .profile
            .groups
            .get(&group_id)
            .context("this account isn't in that group")?;
        let generation = record.generation;

        let secret = self
            .keys
            .unwrap_group_secret(&record.wrapped_secret, group_id, generation)?;
        let request = RestoreGroupSecretRequest {
            generation,
            wrapped_secret: recipient.wrap_group_secret(&secret, group_id, generation)?,
        };
        let path = format!("/v1/groups/{group_id}/members/{user}/secret");
        match self.call(|client| client.put::<_, ()>(&path, &request))? {
            // As for a folder: the group's new secret already went to them.
            Ok(()) | Err(Failure::Status { code: 409, .. }) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Saves a login again as it is, with every copy made for its people's current keys.
    /// Returns false if it can't be opened here (a newer format), or someone saved first.
    fn resave(&mut self, item_id: ItemId) -> Result<bool> {
        let current = self.live_item(item_id)?.clone();
        if current.format > ITEM_FORMAT {
            return Ok(false);
        }
        let key = self.item_key(&current)?;
        let overview = current.open_overview(&key)?;
        let details = current.open_details(&key)?;
        let outcome = self.save_version_with(&current, &overview, &details, People::Same, false)?;
        self.save()?;
        Ok(matches!(outcome, EditOutcome::Saved { .. }))
    }
}
