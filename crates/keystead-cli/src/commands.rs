//! What each `keystead` command does: load the CLI's keys, unlock the vault from
//! `keystead-client`, and call it.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use keystead_client::{
    ApprovedRecovery, DeviceSetupLine, FolderDeletion, ImportPlan, ImportSummary, ImportedLogin,
    JoiningDevice, KdbxExport, NewAccount, NewFolder, PasswordHealth, RecoveryClaim, RecoveryLine,
    RecoveryProgress, RecoveryRequest, RenamedFolder, Vault, claim_recovery, finish_recovery,
    read_kdbx, recovery_progress,
};
pub use keystead_client::{
    DeletedRow, DeviceRow, EditOutcome, GroupRow, GroupShareRow, HistoryRow, InviteInfo, ItemRow,
    MemberRow, SyncSummary, ToChangeRow, UserRow, Whoami, generate_password,
};
pub use keystead_core::api::{PendingInvite, Role};
use keystead_core::ids::{DeviceId, ItemId, UserId};
use keystead_core::items::{Details, Overview};
use keystead_core::keys::{AccountSecret, SoftwareDeviceKey};
use keystead_core::otp::OneTimeCode;

use crate::device::{DeviceFile, profile_path};

/// Claims a new server with its setup code. The caller becomes user 1, the owner.
pub fn setup(home: &Path, server: &str, setup_code: &str, name: &str) -> Result<Whoami> {
    refuse_existing(home)?;
    let secret = AccountSecret::generate();
    let key = Arc::new(SoftwareDeviceKey::generate());
    let vault = keystead_client::setup(
        &profile_path(home),
        new_account(server, &secret, &key),
        setup_code,
        name,
    )?;
    DeviceFile::new(&key, &secret).save(home)?;
    Ok(vault.whoami())
}

/// Joins with an invite, pinning the owner's keys after checking their fingerprint. With
/// the invite's key, the owner's app approves the account on its own.
pub fn join(
    home: &Path,
    server: &str,
    token: &str,
    owner_fingerprint: &str,
    invite_key: Option<&str>,
) -> Result<Whoami> {
    refuse_existing(home)?;
    let secret = AccountSecret::generate();
    let key = Arc::new(SoftwareDeviceKey::generate());
    let vault = keystead_client::join(
        &profile_path(home),
        new_account(server, &secret, &key),
        token,
        owner_fingerprint,
        invite_key,
    )?;
    DeviceFile::new(&key, &secret).save(home)?;
    Ok(vault.whoami())
}

/// Recovers an account onto this machine with the words from its recovery kit, then
/// fetches its folders and logins. The owner can leave out the owner's fingerprint.
pub fn recover(
    home: &Path,
    server: &str,
    owner_fingerprint: Option<&str>,
    words: &str,
) -> Result<Whoami> {
    refuse_existing(home)?;
    let secret = AccountSecret::from_recovery_words(words)?;
    let key = Arc::new(SoftwareDeviceKey::generate());
    let mut vault = keystead_client::recover(
        &profile_path(home),
        new_account(server, &secret, &key),
        owner_fingerprint,
    )?;
    DeviceFile::new(&key, &secret).save(home)?;
    if let Err(error) = vault.sync() {
        eprintln!("warning: recovered, but couldn't sync yet ({error:#}); run `keystead sync`");
    }
    Ok(vault.whoami())
}

/// Recovers an account onto this machine with the owner's help: makes new keys, sends them
/// with the owner's line, shows their fingerprint to read to the owner, and waits until the
/// owner approves them; then fetches what's there. The keys are kept from the start, so if
/// waiting stops (Ctrl-C, a dropped connection), running it again sends the same keys and
/// picks up where it left off, even after the owner approved.
pub fn recover_with_help(
    home: &Path,
    line: &str,
    device_name: &str,
    show: impl Fn(&RecoveryClaim),
    still_trying: impl Fn(&anyhow::Error),
) -> Result<Whoami> {
    let line = RecoveryLine::parse(line)?;
    let earlier = if profile_path(home).exists() {
        None
    } else {
        DeviceFile::load(home)
            .ok()
            .and_then(|file| Some((file.recovering_device()?, file)))
    };
    let (device_id, secret, key) = match earlier {
        Some((device_id, file)) => (device_id, file.secret()?, Arc::new(file.key()?)),
        None => {
            refuse_existing(home)?;
            let secret = AccountSecret::generate();
            let key = SoftwareDeviceKey::generate();
            let device_id = DeviceId::random();
            DeviceFile::recovering(&key, &secret, device_id).save(home)?;
            (device_id, secret, Arc::new(key))
        }
    };
    let account = NewAccount {
        server: &line.server,
        secret: &secret,
        device_id,
        device_name,
        signer: key.clone(),
    };
    let claim = claim_recovery(&line, &account)?;
    show(&claim);
    loop {
        match recovery_progress(&line) {
            Ok(RecoveryProgress::Approved) => break,
            Ok(RecoveryProgress::Waiting) => {}
            Ok(RecoveryProgress::Ended) => {
                DeviceFile::delete(home)?;
                bail!("the owner cancelled this recovery, or it expired; ask them to start again")
            }
            Err(error) => still_trying(&error),
        }
        std::thread::sleep(RECOVERY_POLL);
    }
    let mut vault = finish_recovery(&profile_path(home), account, &line).context(
        "the owner approved, but this machine couldn't finish; run the same command again",
    )?;
    DeviceFile::new(&key, &secret).save(home)?;
    if let Err(error) = vault.sync() {
        eprintln!("warning: recovered, but couldn't sync yet ({error:#}); run `keystead sync`");
    }
    Ok(vault.whoami())
}

/// How often a machine recovering with the owner's help asks whether they've approved.
const RECOVERY_POLL: Duration = Duration::from_secs(3);

/// Starts a recovery with the owner's help for someone (owner only); returns the line to
/// send them.
pub fn start_recovery(home: &Path, user: UserId, sign_out_devices: bool) -> Result<RecoveryLine> {
    open(home)?.start_recovery(user, sign_out_devices)
}

pub fn recovery_request(home: &Path, user: UserId) -> Result<Option<RecoveryRequest>> {
    open(home)?.recovery_request(user)
}

pub fn approve_recovery(home: &Path, user: UserId, fingerprint: &str) -> Result<ApprovedRecovery> {
    open(home)?.approve_recovery(user, fingerprint)
}

/// Cancels a recovery: someone's (owner), or this account's own.
pub fn cancel_recovery(home: &Path, user: Option<UserId>) -> Result<()> {
    let mut vault = open(home)?;
    let user = user.unwrap_or(vault.whoami().user_id);
    vault.cancel_recovery(user)
}

/// Turns escrow on or off; `None` only says whether it's on.
pub fn escrow(home: &Path, on: Option<bool>) -> Result<bool> {
    let mut vault = refreshed(home)?;
    if let Some(on) = on {
        vault.set_escrow(on)?;
    }
    Ok(vault.whoami().escrow)
}

/// Adds another device to this account from this machine: shows the setup line, waits for
/// the new device to join, asks for the code it shows (three tries), and sends it the
/// account secret, sealed for it. Returns its name.
pub fn add_device(
    home: &Path,
    show_line: impl Fn(&str),
    ask_code: impl Fn(&str) -> Result<String>,
) -> Result<String> {
    let secret = DeviceFile::load(home)?.secret()?;
    let mut vault = open(home)?;
    let line = vault.start_adding_device()?;
    show_line(&line.command());
    let deadline = Instant::now() + TRANSFER_WAIT;
    let name = loop {
        if let Some(name) = vault.new_device()? {
            break name;
        }
        if Instant::now() > deadline {
            vault.cancel_adding_device();
            bail!("no device joined in ten minutes; start again");
        }
        std::thread::sleep(POLL_EVERY);
    };
    let mut tries = 0;
    loop {
        let code = ask_code(&name)?;
        match vault.send_account_to_new_device(&code, &secret) {
            Ok(name) => return Ok(name),
            Err(error) if tries < 2 => {
                tries += 1;
                eprintln!("{error:#}");
            }
            Err(error) => {
                vault.cancel_adding_device();
                return Err(error);
            }
        }
    }
}

/// Adds this machine to an account from a device that already has it: joins with the setup
/// line, shows the code to type there, waits for the account secret, then registers this
/// machine as recovery does, checking the owner's fingerprint from the line.
pub fn add_this_device(
    home: &Path,
    line: &str,
    name: &str,
    show_code: impl Fn(&str),
) -> Result<Whoami> {
    refuse_existing(home)?;
    let joining = JoiningDevice::start(DeviceSetupLine::parse(line)?, name)?;
    show_code(joining.code());
    let deadline = Instant::now() + TRANSFER_WAIT;
    let secret = loop {
        if let Some(secret) = joining.poll()? {
            break secret;
        }
        if Instant::now() > deadline {
            bail!("the other device sent nothing in ten minutes; start again there");
        }
        std::thread::sleep(POLL_EVERY);
    };
    let key = Arc::new(SoftwareDeviceKey::generate());
    let account = NewAccount {
        server: &joining.line().server,
        secret: &secret,
        device_id: DeviceId::random(),
        device_name: name,
        signer: key.clone(),
    };
    let mut vault = keystead_client::recover(
        &profile_path(home),
        account,
        Some(&joining.line().owner_fingerprint),
    )?;
    DeviceFile::new(&key, &secret).save(home)?;
    if let Err(error) = vault.sync() {
        eprintln!("warning: added, but couldn't sync yet ({error:#}); run `keystead sync`");
    }
    Ok(vault.whoami())
}

/// How long either side of adding a device waits for the other, and how often it asks.
const TRANSFER_WAIT: Duration = Duration::from_secs(10 * 60);
const POLL_EVERY: Duration = Duration::from_secs(2);

/// The account's recovery kit: its secret as 24 words, plus who and where it's for.
pub fn recovery_kit(home: &Path) -> Result<(String, Whoami)> {
    let device = DeviceFile::load(home)?;
    let whoami = open(home)?.whoami();
    Ok((device.secret()?.recovery_words().to_string(), whoami))
}

/// Signs this machine out: the server forgets it, and its profile and keys are deleted.
/// Returns why the server couldn't be told, if it couldn't.
pub fn sign_out(home: &Path) -> Result<Option<String>> {
    let not_told = open(home)?.sign_out()?;
    DeviceFile::delete(home)?;
    Ok(not_told)
}

pub fn devices(home: &Path) -> Result<Vec<DeviceRow>> {
    open(home)?.devices()
}

pub fn remove_device(home: &Path, device: DeviceId) -> Result<()> {
    open(home)?.remove_device(device)
}

pub fn invite(home: &Path, name: &str) -> Result<InviteInfo> {
    open(home)?.invite(name)
}

/// The invites nobody has used yet; `None` if the server is too old to list them.
pub fn pending_invites(home: &Path) -> Result<Option<Vec<PendingInvite>>> {
    open(home)?.pending_invites()
}

pub fn revoke_invite(home: &Path, id: i64) -> Result<()> {
    open(home)?.revoke_invite(id)
}

pub fn whoami(home: &Path) -> Result<Whoami> {
    Ok(open(home)?.whoami())
}

pub fn users(home: &Path) -> Result<Vec<UserRow>> {
    open(home)?.users()
}

pub fn approve(home: &Path, user: UserId, fingerprint: &str) -> Result<String> {
    open(home)?.approve(user, fingerprint)
}

pub fn create_folder(home: &Path, name: &str) -> Result<()> {
    open(home)?.create_folder(name).map(|_| ())
}

/// Creates a folder inside another, shared like it unless private.
pub fn create_folder_inside(
    home: &Path,
    parent: &str,
    name: &str,
    share_like_parent: bool,
) -> Result<NewFolder> {
    open(home)?.create_folder_inside(parent, name, share_like_parent)
}

pub fn rename_folder(home: &Path, folder: &str, name: &str) -> Result<RenamedFolder> {
    open(home)?.rename_folder(folder, name)
}

/// What deleting a folder would delete, fetched fresh.
pub fn folder_deletion(home: &Path, folder: &str) -> Result<FolderDeletion> {
    open(home)?.folder_deletion(folder)
}

pub fn delete_folder(home: &Path, folder: &str, logins: usize) -> Result<SyncSummary> {
    open(home)?.delete_folder(folder, logins)
}

pub fn share_folder(home: &Path, folder: &str, user: UserId, role: Role) -> Result<String> {
    open(home)?.share_folder(folder, user, role)
}

/// Everyone in a folder and the groups it's shared with.
pub fn folder_members(home: &Path, folder: &str) -> Result<(Vec<MemberRow>, Vec<GroupShareRow>)> {
    refreshed(home)?.folder_sharing(folder)
}

/// Shares a folder with a group. Returns the group's name.
pub fn share_folder_with_group(
    home: &Path,
    folder: &str,
    group: &str,
    role: Role,
) -> Result<String> {
    open(home)?.share_folder_with_group(folder, group, role)
}

pub fn set_folder_group_role(home: &Path, folder: &str, group: &str, role: Role) -> Result<()> {
    refreshed(home)?.set_folder_group_role(folder, group, role)
}

/// Stops sharing a folder with a group; then the folder gets a new key.
pub fn remove_group_from_folder(home: &Path, folder: &str, group: &str) -> Result<SyncSummary> {
    refreshed(home)?.remove_group_from_folder(folder, group)
}

pub fn groups(home: &Path) -> Result<Vec<GroupRow>> {
    Ok(refreshed(home)?.groups())
}

/// Makes a group (owner only) with the caller and these people in it.
pub fn create_group(home: &Path, name: &str, members: &[UserId]) -> Result<()> {
    open(home)?.create_group(name, members).map(|_| ())
}

/// Adds someone to a group. Returns their name.
pub fn add_to_group(home: &Path, group: &str, user: UserId) -> Result<String> {
    open(home)?.add_to_group(group, user)
}

/// Takes someone out of a group, or the caller; then the group gets a new key.
pub fn remove_from_group(home: &Path, group: &str, user: UserId) -> Result<SyncSummary> {
    refreshed(home)?.remove_from_group(group, user)
}

pub fn delete_group(home: &Path, group: &str) -> Result<SyncSummary> {
    refreshed(home)?.delete_group(group)
}

pub fn leave_group(home: &Path, group: &str) -> Result<SyncSummary> {
    let mut vault = refreshed(home)?;
    let me = vault.whoami().user_id;
    vault.remove_from_group(group, me)
}

pub fn rename_group(home: &Path, group: &str, name: &str) -> Result<()> {
    open(home)?.rename_group(group, name)
}

pub fn set_group_manager(home: &Path, group: &str, user: UserId, manager: bool) -> Result<()> {
    open(home)?.set_group_manager(group, user, manager)
}

pub fn set_folder_role(home: &Path, folder: &str, user: UserId, role: Role) -> Result<()> {
    refreshed(home)?.set_folder_role(folder, user, role)
}

/// Takes someone out of a folder, then gives the folder a new key.
pub fn remove_from_folder(home: &Path, folder: &str, user: UserId) -> Result<()> {
    refreshed(home)?.remove_from_folder(folder, user)
}

pub fn leave_folder(home: &Path, folder: &str) -> Result<()> {
    let mut vault = refreshed(home)?;
    let me = vault.whoami().user_id;
    vault.remove_from_folder(folder, me)
}

/// Removes someone from the team (owner only). Returns their name, and how many of the
/// passwords they could see the caller can change.
pub fn remove_user(home: &Path, user: UserId) -> Result<(String, usize)> {
    let mut vault = open(home)?;
    let name = vault.remove_user(user)?;
    let to_change = vault.to_change()?;
    Ok((
        name,
        to_change.iter().filter(|row| row.user_id == user).count(),
    ))
}

/// Passwords to change, most recent first.
pub fn to_change(home: &Path) -> Result<Vec<ToChangeRow>> {
    refreshed(home)?.to_change()
}

/// The logins you can change whose password is weak, reused or over a year old, after a
/// sync. Worked out here; nothing about the passwords is kept.
pub fn health(home: &Path) -> Result<PasswordHealth> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as i64);
    refreshed(home)?.password_health(now)
}

/// Takes logins off the list of passwords to change: one login (for everyone, or one
/// person), or everything one person could see. Returns how many entries went.
pub fn dismiss(
    home: &Path,
    login: Option<&str>,
    folder: Option<&str>,
    user: Option<UserId>,
) -> Result<usize> {
    let mut vault = open(home)?;
    vault.sync()?;
    let item = login
        .map(|name| vault.find_item(name, folder))
        .transpose()?;
    let entries: Vec<_> = vault
        .to_change()?
        .into_iter()
        .filter(|row| item.is_none_or(|id| id == row.item_id))
        .filter(|row| user.is_none_or(|user| user == row.user_id))
        .map(|row| (row.item_id, row.user_id))
        .collect();
    for &(item_id, user) in &entries {
        vault.dismiss(item_id, user)?;
    }
    Ok(entries.len())
}

pub fn folders(home: &Path) -> Result<Vec<String>> {
    refreshed(home)?.folders()
}

/// Adds a login to a folder, or with no folder as the caller's own.
pub fn add(home: &Path, folder: Option<&str>, overview: Overview, details: Details) -> Result<()> {
    open(home)?.add(folder, overview, details).map(|_| ())
}

/// Shares one login with an approved user. Returns their name.
pub fn share(
    home: &Path,
    name: &str,
    folder: Option<&str>,
    user: UserId,
    role: Role,
) -> Result<String> {
    let mut vault = open(home)?;
    vault.sync()?;
    let item_id = vault.find_item(name, folder)?;
    vault.share_item(item_id, user, role)
}

/// Takes away someone's copy of a login. Returns their name.
pub fn unshare(home: &Path, name: &str, folder: Option<&str>, user: UserId) -> Result<String> {
    let mut vault = open(home)?;
    vault.sync()?;
    let item_id = vault.find_item(name, folder)?;
    vault.unshare_item(item_id, user)
}

/// Shares one login with a group. Returns the group's name.
pub fn share_with_group(
    home: &Path,
    name: &str,
    folder: Option<&str>,
    group: &str,
    role: Role,
) -> Result<String> {
    let mut vault = open(home)?;
    vault.sync()?;
    let item_id = vault.find_item(name, folder)?;
    vault.share_item_with_group(item_id, group, role)
}

/// Takes a group's copy of a login away. Returns the group's name.
pub fn unshare_group(home: &Path, name: &str, folder: Option<&str>, group: &str) -> Result<String> {
    let mut vault = open(home)?;
    vault.sync()?;
    let item_id = vault.find_item(name, folder)?;
    vault.unshare_item_group(item_id, group)
}

pub fn list(home: &Path) -> Result<Vec<ItemRow>> {
    let vault = refreshed(home)?;
    let too_new = vault.too_new();
    if too_new > 0 {
        eprintln!(
            "warning: {too_new} login(s) are from a newer Keystead and don't show; update to see \
             them"
        );
    }
    vault.list()
}

pub fn show(home: &Path, name: &str, folder: Option<&str>) -> Result<(Overview, Details)> {
    let vault = refreshed(home)?;
    vault.open_item(vault.find_item(name, folder)?)
}

pub fn edit(home: &Path, name: &str, folder: Option<&str>, password: &str) -> Result<EditOutcome> {
    let mut vault = open(home)?;
    vault.sync()?;
    let item_id = vault.find_item(name, folder)?;
    vault.edit(item_id, password)
}

/// What to change in a login; `None` keeps the field as it is.
#[derive(Default)]
pub struct Changes {
    pub name: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub password: Option<String>,
    /// A one-time code setup; empty to remove it.
    pub otp: Option<String>,
}

/// Changes some of a login's fields and keeps the rest.
pub fn update(
    home: &Path,
    name: &str,
    folder: Option<&str>,
    changes: Changes,
) -> Result<EditOutcome> {
    let mut vault = open(home)?;
    vault.sync()?;
    let item_id = vault.find_item(name, folder)?;
    let (mut overview, mut details) = vault.open_item(item_id)?;
    if let Some(name) = changes.name {
        overview.name = name;
    }
    if let Some(username) = changes.username {
        overview.username = username;
    }
    if let Some(url) = changes.url {
        overview.url = url;
    }
    if let Some(notes) = changes.notes {
        details.notes = notes;
    }
    if let Some(password) = changes.password {
        details.password = password;
    }
    if let Some(otp) = changes.otp {
        details.otp = otp;
    }
    vault.update(item_id, &overview, &details)
}

/// Every login you can open, after a sync, in a KeePass file encrypted with `passphrase`,
/// saved as `file`: a new file only you can read.
pub fn export(home: &Path, file: &Path, passphrase: &str) -> Result<KdbxExport> {
    let export = refreshed(home)?.export_kdbx(passphrase)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut out = match options.open(file) {
        Ok(out) => out,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("{} already exists; choose another name", file.display())
        }
        Err(error) => bail!("couldn't create {}: {error}", file.display()),
    };
    if let Err(error) =
        std::io::Write::write_all(&mut out, &export.file).and_then(|()| out.sync_all())
    {
        // Encrypted, but half a file is no use to anyone; it goes.
        drop(out);
        let _ = std::fs::remove_file(file);
        bail!("couldn't write {}: {error}", file.display());
    }
    Ok(export)
}

/// Reads the logins in an export file (.kdbx) with its passphrase. Nothing is saved.
pub fn read_export(file: &Path, passphrase: &str) -> Result<Vec<ImportedLogin>> {
    let bytes = std::fs::read(file)
        .map_err(|error| anyhow::anyhow!("couldn't read {}: {error}", file.display()))?;
    read_kdbx(&bytes, passphrase)
}

/// What importing would do.
pub fn plan_import(
    home: &Path,
    logins: &[ImportedLogin],
    unfiled: Option<&str>,
) -> Result<ImportPlan> {
    open(home)?.plan_import(logins, unfiled)
}

/// Imports the logins, creating the folders they need.
pub fn import(
    home: &Path,
    logins: &[ImportedLogin],
    unfiled: Option<&str>,
) -> Result<ImportSummary> {
    open(home)?.import(logins, unfiled)
}

/// Logins deleted in the last 30 days that this account can bring back, newest first.
pub fn deleted(home: &Path) -> Result<Vec<DeletedRow>> {
    open(home)?.deleted()?.ok_or_else(|| {
        anyhow::anyhow!(
            "the server is older than Keystead 0.9.0 and keeps nothing of deleted logins"
        )
    })
}

/// Brings back a recently deleted login.
pub fn undelete(home: &Path, name: &str, folder: Option<&str>) -> Result<EditOutcome> {
    let mut vault = open(home)?;
    let item_id = find_deleted(&mut vault, name, folder)?;
    vault.undelete(item_id)
}

/// Deletes a deleted login for good.
pub fn purge(home: &Path, name: &str, folder: Option<&str>) -> Result<()> {
    let mut vault = open(home)?;
    let item_id = find_deleted(&mut vault, name, folder)?;
    vault.purge(item_id)
}

fn find_deleted(vault: &mut Vault, name: &str, folder: Option<&str>) -> Result<ItemId> {
    let rows = vault.deleted()?.unwrap_or_default();
    let matches: Vec<_> = rows
        .iter()
        .filter(|row| {
            row.name == name && folder.is_none_or(|folder| row.folder.as_deref() == Some(folder))
        })
        .collect();
    match matches.as_slice() {
        [row] => Ok(row.item_id),
        [] => bail!("no login named {name:?} was deleted in the last 30 days"),
        _ => bail!("several deleted logins are named {name:?}; add --folder"),
    }
}

/// A login's history, newest first.
pub fn history(home: &Path, name: &str, folder: Option<&str>) -> Result<Vec<HistoryRow>> {
    let mut vault = open(home)?;
    vault.sync()?;
    let item_id = vault.find_item(name, folder)?;
    vault.history(item_id)
}

/// One earlier version of a login, decrypted.
pub fn history_version(
    home: &Path,
    name: &str,
    folder: Option<&str>,
    version: u64,
) -> Result<(Overview, Details)> {
    let mut vault = open(home)?;
    vault.sync()?;
    let item_id = vault.find_item(name, folder)?;
    vault.history(item_id)?;
    vault.history_version(item_id, version)
}

/// Brings back an earlier version of a login.
pub fn restore(home: &Path, name: &str, folder: Option<&str>, version: u64) -> Result<EditOutcome> {
    let mut vault = open(home)?;
    vault.sync()?;
    let item_id = vault.find_item(name, folder)?;
    vault.history(item_id)?;
    vault.restore(item_id, version)
}

/// A login's current one-time code.
pub fn one_time_code(home: &Path, name: &str, folder: Option<&str>) -> Result<OneTimeCode> {
    let vault = refreshed(home)?;
    vault
        .one_time_code(vault.find_item(name, folder)?)?
        .ok_or_else(|| anyhow::anyhow!("{name} has no one-time codes; add them with edit --otp"))
}

/// Moves a login to another folder, or out of folders as the caller's own.
pub fn move_item(
    home: &Path,
    name: &str,
    folder: Option<&str>,
    to: Option<&str>,
) -> Result<EditOutcome> {
    let mut vault = open(home)?;
    vault.sync()?;
    let item_id = vault.find_item(name, folder)?;
    vault.move_item(item_id, to)
}

/// Deletes a login for everyone who can open it.
pub fn remove(home: &Path, name: &str, folder: Option<&str>) -> Result<EditOutcome> {
    let mut vault = open(home)?;
    vault.sync()?;
    let item_id = vault.find_item(name, folder)?;
    vault.delete(item_id)
}

pub fn sync(home: &Path) -> Result<SyncSummary> {
    open(home)?.sync()
}

pub fn warn_rejected(summary: &SyncSummary) {
    for name in &summary.approved {
        eprintln!("Approved {name}, who joined with your invite.");
    }
    if summary.older > 0 || summary.server_went_back {
        eprintln!("warning: {}", older_note(summary));
    }
    if summary.rejected > 0 {
        eprintln!(
            "warning: ignored {} change(s) by someone who isn't approved, or who can only \
             view the folder",
            summary.rejected
        );
    }
    for problem in &summary.rekey_problems {
        eprintln!("warning: couldn't give a folder or group its new key ({problem}); will retry");
    }
}

/// What to say when the server sent older copies than this device had seen, or its
/// change numbers went back.
pub fn older_note(summary: &SyncSummary) -> String {
    let what = if summary.older > 0 {
        format!(
            "the server sent older copies of {} login(s), folder(s) or group(s) than this \
             device has already seen, and it kept its own",
            summary.older
        )
    } else {
        "the server's changes went back to an earlier point".to_owned()
    };
    format!(
        "{what}. If the server was restored from a backup, save your recent changes again; \
         if not, don't trust it"
    )
}

fn open(home: &Path) -> Result<Vault> {
    let device = DeviceFile::load(home)?;
    Vault::open(
        &profile_path(home),
        &device.secret()?,
        Arc::new(device.key()?),
    )
}

/// Opens and syncs. If the server can't be reached, carries on with the local copy
/// after a warning.
fn refreshed(home: &Path) -> Result<Vault> {
    let mut vault = open(home)?;
    match vault.sync() {
        Ok(summary) => warn_rejected(&summary),
        Err(error) => eprintln!("warning: couldn't sync ({error:#}); showing the local copy"),
    }
    Ok(vault)
}

fn new_account<'a>(
    server: &'a str,
    secret: &'a AccountSecret,
    key: &Arc<SoftwareDeviceKey>,
) -> NewAccount<'a> {
    NewAccount {
        server,
        secret,
        device_id: DeviceId::random(),
        device_name: "Command line",
        signer: key.clone(),
    }
}

fn refuse_existing(home: &Path) -> Result<()> {
    if profile_path(home).exists() || DeviceFile::exists(home) {
        bail!(
            "{} already has a profile; set KEYSTEAD_HOME to use another folder",
            home.display()
        );
    }
    Ok(())
}
