//! Reading logins exported from other password managers: KeePass files (`.kdbx`), which is
//! how Passbolt exports by default, and what KeePass and KeePassXC save. Saving them is
//! [`Vault::plan_import`](crate::Vault::plan_import) and [`Vault::import`](crate::Vault::import).
//!
//! Everything read stays in memory, and the sensitive part ([`Details`]) is wiped when
//! dropped; nothing decrypted is written anywhere.

use anyhow::{Result, anyhow};
use keepass::db::{DatabaseOpenError, GroupRef};
use keepass::{Database, DatabaseKey};
use keystead_core::items::{Details, Overview};
use keystead_core::otp;

/// A login read from an export, not saved yet.
pub struct ImportedLogin {
    /// The folder it was in, nested folders joined with " / "; none at the top level.
    pub folder: Option<String>,
    pub overview: Overview,
    pub details: Details,
}

/// The standard KeePass fields, which map onto a login's own.
const STANDARD: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];
/// How Passbolt's "kdbx (keepassXC & others)" export stores a one-time code: an
/// otpauth:// link.
const KEEPASSXC_OTP: &str = "otp";
/// How its "kdbx (keepass)" export, and KeePass 2, store one: these fields.
const KEEPASS_OTP: [&str; 4] = [
    "TimeOtp-Secret-Base32",
    "TimeOtp-Period",
    "TimeOtp-Length",
    "TimeOtp-Algorithm",
];

/// Every login in a KeePass file, opened with the passphrase chosen when exporting. The
/// recycle bin and earlier versions of entries are left out.
pub fn read_kdbx(file: &[u8], passphrase: &str) -> Result<Vec<ImportedLogin>> {
    let key = DatabaseKey::new().with_password(passphrase);
    let database = Database::open(&mut &file[..], key).map_err(|error| match error {
        DatabaseOpenError::Key(_) => {
            anyhow!("couldn't open the file: the passphrase is wrong, or it isn't a KeePass file")
        }
        DatabaseOpenError::UnsupportedVersion | DatabaseOpenError::VersionParse(_) => {
            anyhow!("that isn't a KeePass file (.kdbx), or it's a version Keystead can't read")
        }
        other => anyhow!("couldn't read the KeePass file ({other})"),
    })?;
    let recycle_bin = database.meta.recyclebin_uuid.map(|id| id.to_string());
    let mut logins = Vec::new();
    walk(database.root(), &[], recycle_bin, &mut logins);
    Ok(logins)
}

fn walk(
    group: GroupRef<'_>,
    path: &[String],
    recycle_bin: Option<String>,
    logins: &mut Vec<ImportedLogin>,
) {
    let folder = (!path.is_empty()).then(|| path.join(" / "));
    for entry in group.entries() {
        if let Some(login) = login(&entry, folder.clone()) {
            logins.push(login);
        }
    }
    for child in group.groups() {
        if recycle_bin.as_deref() == Some(child.id().to_string().as_str()) {
            continue;
        }
        let name = child.name.trim();
        let mut path = path.to_vec();
        path.push(if name.is_empty() {
            "Untitled".to_owned()
        } else {
            name.to_owned()
        });
        walk(child, &path, recycle_bin.clone(), logins);
    }
}

/// One entry as a login, or nothing if it's empty.
fn login(entry: &keepass::db::Entry, folder: Option<String>) -> Option<ImportedLogin> {
    let field = |key: &str| entry.get(key).map(str::trim).unwrap_or_default().to_owned();
    let (title, username, password, url) = (
        field("Title"),
        field("UserName"),
        entry.get("Password").unwrap_or_default().to_owned(),
        field("URL"),
    );
    let mut notes = entry.get("Notes").unwrap_or_default().trim_end().to_owned();
    if title.is_empty() && username.is_empty() && password.is_empty() && url.is_empty() {
        return None;
    }

    // A one-time code, either way it's stored; one that doesn't check out stays in the
    // notes rather than being lost.
    let (code, code_fields) = one_time_code(entry);
    let otp = match code.map(|link| otp::normalize(&link)) {
        Some(Ok(link)) => link,
        _ => String::new(),
    };
    let mut extra: Vec<(&String, &str)> = entry
        .fields
        .iter()
        .filter(|(key, _)| !STANDARD.contains(&key.as_str()))
        .filter(|(key, _)| otp.is_empty() || !code_fields.contains(&key.as_str()))
        .map(|(key, value)| (key, value.get().as_str()))
        .filter(|(_, value)| !value.trim().is_empty())
        .collect();
    extra.sort();
    for (key, value) in extra {
        if !notes.is_empty() {
            notes.push('\n');
        }
        notes.push_str(&format!("{key}: {}", value.trim()));
    }

    let name = [&title, &url, &username]
        .into_iter()
        .find(|text| !text.is_empty())
        .cloned()
        .unwrap_or_default();
    Some(ImportedLogin {
        folder,
        overview: Overview {
            name,
            username,
            url,
            tags: entry.tags.clone(),
            ..Overview::default()
        },
        details: Details {
            password,
            notes,
            otp,
        },
    })
}

/// An entry's one-time code as an otpauth:// link, if it has one, and the fields it came
/// from.
fn one_time_code(entry: &keepass::db::Entry) -> (Option<String>, Vec<&'static str>) {
    if let Some(link) = entry
        .get(KEEPASSXC_OTP)
        .map(str::trim)
        .filter(|link| !link.is_empty())
    {
        return (Some(link.to_owned()), vec![KEEPASSXC_OTP]);
    }
    let Some(secret) = entry
        .get(KEEPASS_OTP[0])
        .map(|secret| secret.replace(' ', ""))
        .filter(|secret| !secret.is_empty())
    else {
        return (None, Vec::new());
    };
    let mut link = format!("otpauth://totp/?secret={secret}");
    if let Some(period) = entry
        .get("TimeOtp-Period")
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        link.push_str(&format!("&period={period}"));
    }
    if let Some(digits) = entry
        .get("TimeOtp-Length")
        .map(str::trim)
        .filter(|d| !d.is_empty())
    {
        link.push_str(&format!("&digits={digits}"));
    }
    if let Some(algorithm) = entry.get("TimeOtp-Algorithm") {
        // KeePass names them HMAC-SHA-1, HMAC-SHA-256 and HMAC-SHA-512.
        let algorithm = algorithm
            .trim()
            .to_ascii_uppercase()
            .replace("HMAC-", "")
            .replace('-', "");
        if !algorithm.is_empty() {
            link.push_str(&format!("&algorithm={algorithm}"));
        }
    }
    (Some(link), KEEPASS_OTP.to_vec())
}
