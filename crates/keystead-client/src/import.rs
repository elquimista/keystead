//! Reading logins exported from other password managers: KeePass files (`.kdbx`), which is
//! how Passbolt exports by default, and what KeePass and KeePassXC save. Saving them is
//! [`Vault::plan_import`](crate::Vault::plan_import) and [`Vault::import`](crate::Vault::import).
//!
//! Everything read stays in memory, and the sensitive part ([`Details`]) is wiped when
//! dropped; nothing decrypted is written anywhere.

use anyhow::{Result, anyhow, bail};
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
    check_kdf(file)?;
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

/// The most memory a KeePass file's key derivation may ask for before Keystead opens it,
/// and the most work: a file made to harm could otherwise ask for more memory than the
/// Mac has, or hours of work. KeePassXC's defaults (64 MB for about a second) and
/// Keystead's own exports (128 MB, 30 times) are well inside these.
const KDF_MAX_MEMORY: u64 = 1 << 30;
/// Argon2's memory times its iterations, in bytes: 1 GB 16 times over.
const KDF_MAX_WORK: u64 = 16 << 30;
const KDF_MAX_PARALLELISM: u64 = 64;
/// AES-KDF rounds: several seconds even with the processor's AES instructions.
const KDF_MAX_ROUNDS: u64 = 100_000_000;

const TOO_COSTLY: &str = "this KeePass file asks for more memory or time to open than Keystead \
                          allows; save it again in KeePassXC with the default encryption \
                          settings, then import that copy";

/// What a KeePass file's key derivation asks for, as its outer header says.
#[derive(Debug, PartialEq, Eq)]
enum KdfCost {
    Argon2 {
        memory: u64,
        iterations: u64,
        parallelism: u64,
    },
    Aes {
        rounds: u64,
    },
}

/// Refuses a KeePass file whose key derivation asks for too much, before anything is
/// derived. A header this can't read is left to the `keepass` crate, which reads it the
/// same way and says what's wrong.
fn check_kdf(file: &[u8]) -> Result<()> {
    let too_costly = match kdf_cost(file) {
        Some(KdfCost::Argon2 {
            memory,
            iterations,
            parallelism,
        }) => {
            memory > KDF_MAX_MEMORY
                || memory.saturating_mul(iterations) > KDF_MAX_WORK
                || parallelism > KDF_MAX_PARALLELISM
        }
        Some(KdfCost::Aes { rounds }) => rounds > KDF_MAX_ROUNDS,
        None => false,
    };
    if too_costly {
        bail!(TOO_COSTLY);
    }
    Ok(())
}

const KDBX_SIGNATURE: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];
const KEEPASS_1: u32 = 0xb54b_fb65;
const KDF_ARGON2D: [u8; 16] = *b"\xef\x63\x6d\xdf\x8c\x29\x44\x4b\x91\xf7\xa9\xa4\x03\xe3\x0a\x0c";
const KDF_ARGON2ID: [u8; 16] = *b"\x9e\x29\x8b\x19\x56\xdb\x47\x73\xb2\x3d\xfc\x3e\xc6\xf0\xa1\xe6";
const KDF_AES_KDBX3: [u8; 16] =
    *b"\xc9\xd9\xf3\x9a\x62\x8a\x44\x60\xbf\x74\x0d\x08\xc1\x8a\x4f\xea";
const KDF_AES_KDBX4: [u8; 16] =
    *b"\x7c\x02\xbb\x82\x79\xa7\x4a\xc0\x92\x7d\x11\x4a\x00\x64\x82\x38";

fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn le_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// The key derivation's settings from a KeePass file's outer header: KeePass 1's fixed
/// header, KDBX 3's transform rounds (field 6), or KDBX 4's KDF parameters (field 11).
/// A field given twice counts as its last, as in the `keepass` crate.
fn kdf_cost(file: &[u8]) -> Option<KdfCost> {
    if file.get(..4)? != KDBX_SIGNATURE {
        return None;
    }
    if le_u32(file, 4)? == KEEPASS_1 {
        return Some(KdfCost::Aes {
            rounds: u64::from(le_u32(file, 120)?),
        });
    }
    let major = le_u16(file, 10)?;
    let mut at = 12;
    let mut cost = None;
    loop {
        let field = *file.get(at)?;
        let (length, start) = match major {
            3 => (usize::from(le_u16(file, at + 1)?), at + 3),
            4 => (le_u32(file, at + 1)? as usize, at + 5),
            _ => return None,
        };
        let data = file.get(start..start.checked_add(length)?)?;
        at = start + length;
        match (major, field) {
            (_, 0) => return cost,
            (3, 6) => {
                cost = Some(KdfCost::Aes {
                    rounds: le_u64(data, 0)?,
                });
            }
            (4, 11) => cost = Some(kdf_parameters(data)?),
            _ => {}
        }
    }
}

/// KDBX 4's KDF parameters: a variant dictionary of typed values by name.
fn kdf_parameters(data: &[u8]) -> Option<KdfCost> {
    let mut at = 2;
    let (mut id, mut memory, mut iterations, mut parallelism, mut rounds) =
        (None, None, None, None, None);
    loop {
        let kind = *data.get(at)?;
        if kind == 0 {
            break;
        }
        let key_length = le_u32(data, at + 1)? as usize;
        let key = data.get(at + 5..(at + 5).checked_add(key_length)?)?;
        let value_at = at + 5 + key_length;
        let value_length = le_u32(data, value_at)? as usize;
        let value = data.get(value_at + 4..(value_at + 4).checked_add(value_length)?)?;
        at = value_at + 4 + value_length;
        let number = match (kind, value.len()) {
            (0x04, 4) => le_u32(value, 0).map(u64::from),
            (0x05, 8) => le_u64(value, 0),
            _ => None,
        };
        match key {
            b"$UUID" => id = Some(value),
            b"M" => memory = number,
            b"I" => iterations = number,
            b"P" => parallelism = number,
            b"R" => rounds = number,
            _ => {}
        }
    }
    let id: [u8; 16] = id?.try_into().ok()?;
    if id == KDF_ARGON2D || id == KDF_ARGON2ID {
        Some(KdfCost::Argon2 {
            memory: memory?,
            iterations: iterations?,
            parallelism: parallelism?,
        })
    } else if id == KDF_AES_KDBX3 || id == KDF_AES_KDBX4 {
        Some(KdfCost::Aes { rounds: rounds? })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::KdbxWriter;

    /// Where a KDBX 4 file's named UInt64 KDF setting is, in its outer header.
    fn setting(file: &[u8], name: u8) -> usize {
        let entry = [0x05, 1, 0, 0, 0, name, 8, 0, 0, 0];
        file.windows(entry.len())
            .position(|window| window == entry)
            .expect("the setting is in the header")
            + entry.len()
    }

    #[test]
    fn a_keepass_file_asking_for_too_much_to_open_is_refused_first() {
        let file = KdbxWriter::new()
            .finish("a long enough passphrase")
            .unwrap();
        assert_eq!(
            kdf_cost(&file),
            Some(KdfCost::Argon2 {
                memory: 128 * 1024 * 1024,
                iterations: 30,
                parallelism: 4,
            })
        );
        assert!(read_kdbx(&file, "a long enough passphrase").is_ok());

        for (name, value) in [(b'M', 64u64 << 30), (b'I', 1_000_000)] {
            let mut costly = file.clone();
            let at = setting(&costly, name);
            costly[at..at + 8].copy_from_slice(&value.to_le_bytes());
            let Err(error) = read_kdbx(&costly, "a long enough passphrase") else {
                panic!("a file asking for too much opened");
            };
            assert!(
                format!("{error}").contains("more memory or time"),
                "{error}"
            );
        }
    }
}
