//! Password health: the logins you can change whose password is weak, used for other
//! logins too, or unchanged for over a year. Worked out on this device from the passwords
//! it can open, in memory; only when each password was last set comes from the server.

use std::collections::HashMap;

use anyhow::Result;
use keystead_core::api::{PasswordAges, Role};
use keystead_core::ids::ItemId;
use sha2::{Digest, Sha256};
use zxcvbn::{Score, zxcvbn};

use super::Vault;
use crate::http::Failure;

/// A password set longer ago than this is old: a year.
pub const OLD_AFTER_SECONDS: i64 = 365 * 24 * 60 * 60;

/// A login you can change whose password needs attention.
#[derive(Debug)]
pub struct HealthRow {
    pub item_id: ItemId,
    pub name: String,
    pub username: String,
    /// Its folder, if it's in one of yours.
    pub folder: Option<String>,
    /// Easy to guess: zxcvbn estimates it falls within 10^10 guesses (a score below 3).
    pub weak: bool,
    /// The other logins you can open that have the same password, by name.
    pub reused_with: Vec<String>,
    /// When the password was set, if that's over a year ago (seconds since 1970, UTC).
    pub old_since: Option<i64>,
}

/// What a password health check found.
#[derive(Debug, Default)]
pub struct PasswordHealth {
    /// Logins you can change that need attention, those with most problems first.
    pub rows: Vec<HealthRow>,
    /// How many logins with a password you can change were checked.
    pub checked: usize,
    /// The server says when passwords were set (0.13.0 and later), so old ones can show.
    pub ages_known: bool,
}

impl Vault {
    /// Checks the passwords of the logins you can change, as of `now` (seconds since 1970):
    /// weak ones, ones that other logins you can open share, and ones set over a year ago.
    /// Passwords are opened in memory only, and nothing about them is kept.
    pub fn password_health(&mut self, now: i64) -> Result<PasswordHealth> {
        // Servers before 0.13.0 don't say when passwords were set.
        let ages: Option<HashMap<ItemId, i64>> =
            match self.call(|client| client.get::<PasswordAges>("/v1/password-ages", &[]))? {
                Ok(ages) => Some(
                    ages.items
                        .into_iter()
                        .filter_map(|age| Some((age.item_id, age.since?)))
                        .collect(),
                ),
                Err(Failure::Status { code: 404, .. }) => None,
                Err(error) => return Err(error.into()),
            };
        let rows = self.list()?;
        // Logins by password, as a digest held only for this check.
        let mut by_password: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
        let mut checked = Vec::new();
        for (index, row) in rows.iter().enumerate() {
            // One saved by a newer app can't be opened here; it's left out.
            let Ok((_, details)) = self.open_item(row.id) else {
                continue;
            };
            if details.password.is_empty() {
                continue;
            }
            let digest: [u8; 32] = Sha256::digest(details.password.as_bytes()).into();
            by_password.entry(digest).or_default().push(index);
            if row.role < Role::Edit {
                continue;
            }
            let inputs = [row.name.as_str(), row.username.as_str(), row.url.as_str()];
            let weak = !matches!(
                zxcvbn(&details.password, &inputs).score(),
                Score::Three | Score::Four
            );
            checked.push((index, weak, digest));
        }

        let mut health = PasswordHealth {
            checked: checked.len(),
            ages_known: ages.is_some(),
            ..PasswordHealth::default()
        };
        for (index, weak, digest) in checked {
            let row = &rows[index];
            let mut reused_with: Vec<String> = by_password[&digest]
                .iter()
                .filter(|&&other| other != index)
                .map(|&other| rows[other].name.clone())
                .collect();
            reused_with.sort();
            let old_since = ages
                .as_ref()
                .and_then(|ages| ages.get(&row.id).copied())
                .filter(|&since| now - since > OLD_AFTER_SECONDS);
            if weak || !reused_with.is_empty() || old_since.is_some() {
                health.rows.push(HealthRow {
                    item_id: row.id,
                    name: row.name.clone(),
                    username: row.username.clone(),
                    folder: row.folder.clone(),
                    weak,
                    reused_with,
                    old_since,
                });
            }
        }
        let problems = |row: &HealthRow| {
            usize::from(row.weak)
                + usize::from(!row.reused_with.is_empty())
                + usize::from(row.old_since.is_some())
        };
        health.rows.sort_by(|a, b| {
            problems(b)
                .cmp(&problems(a))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(health)
    }
}
