//! What each `keystead` command does: load the CLI's keys, unlock the vault from
//! `keystead-client`, and call it.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, bail};
pub use keystead_client::{
    DeviceRow, EditOutcome, InviteInfo, ItemRow, SyncSummary, UserRow, Whoami, generate_password,
};
use keystead_client::{NewAccount, Vault};
use keystead_core::ids::{DeviceId, UserId};
use keystead_core::items::{Details, Overview};
use keystead_core::keys::{AccountSecret, SoftwareDeviceKey};

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

/// Joins with an invite, pinning the owner's keys after checking their fingerprint.
pub fn join(home: &Path, server: &str, token: &str, owner_fingerprint: &str) -> Result<Whoami> {
    refuse_existing(home)?;
    let secret = AccountSecret::generate();
    let key = Arc::new(SoftwareDeviceKey::generate());
    let vault = keystead_client::join(
        &profile_path(home),
        new_account(server, &secret, &key),
        token,
        owner_fingerprint,
    )?;
    DeviceFile::new(&key, &secret).save(home)?;
    Ok(vault.whoami())
}

/// Recovers an account onto this machine with the words from its recovery kit, then
/// fetches its folders and logins.
pub fn recover(home: &Path, server: &str, owner_fingerprint: &str, words: &str) -> Result<Whoami> {
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

/// The account's recovery kit: its secret as 24 words, plus who and where it's for.
pub fn recovery_kit(home: &Path) -> Result<(String, Whoami)> {
    let device = DeviceFile::load(home)?;
    let whoami = open(home)?.whoami();
    Ok((device.secret()?.recovery_words().to_string(), whoami))
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

pub fn share_folder(home: &Path, folder: &str, user: UserId) -> Result<String> {
    open(home)?.share_folder(folder, user)
}

pub fn folders(home: &Path) -> Result<Vec<String>> {
    refreshed(home)?.folders()
}

pub fn add(home: &Path, folder: &str, overview: Overview, details: Details) -> Result<()> {
    open(home)?.add(folder, overview, details).map(|_| ())
}

pub fn list(home: &Path) -> Result<Vec<ItemRow>> {
    refreshed(home)?.list()
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

pub fn sync(home: &Path) -> Result<SyncSummary> {
    open(home)?.sync()
}

pub fn warn_rejected(summary: &SyncSummary) {
    if summary.rejected > 0 {
        eprintln!(
            "warning: ignored {} item(s) not signed by an approved user",
            summary.rejected
        );
    }
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
