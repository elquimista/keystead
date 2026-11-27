//! Password health: the logins you can change whose password is weak, used for other
//! logins too, or unchanged for over a year. Worked out on this device from the passwords
//! it can open, in memory; only when each password was last set comes from the server.

use std::collections::HashMap;

use anyhow::Result;
use keystead_core::api::{PasswordAges, Role};
use keystead_core::ids::{FolderId, ItemId};
use keystead_core::keys::FolderKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zxcvbn::{Score, zxcvbn};

use super::{Connection, ItemRow, Vault};
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

/// A password health check in three steps, so scoring passwords, the slow part, runs with
/// the vault free: `Vault::begin_health` opens the passwords, `score` scores the ones not
/// scored before at their current version and asks the server when each was set, and
/// `Vault::finish_health` puts it together and remembers the scores. Only whether each
/// password is weak is remembered, never the password. `Vault::password_health` does all
/// three.
pub struct HealthCheck {
    connection: Connection,
    connection_generation: u64,
    now: i64,
    rows: Vec<ItemRow>,
    checks: Vec<Check>,
    /// Passwords to score, with what zxcvbn compares them against, by index in `checks`;
    /// held only until scored.
    to_score: Vec<(usize, Zeroizing<String>, [String; 3])>,
    /// When each password was set; `None` inside from a server before 0.13.0.
    ages: Option<Option<HashMap<ItemId, i64>>>,
    failure: Option<anyhow::Error>,
}

/// One login with a password, in a check.
struct Check {
    row: usize,
    /// The password's digest, to find others with the same one; for this check only.
    digest: [u8; 32],
    /// Whether it's a login you can change, the only ones flagged.
    changeable: bool,
    /// A digest of the version's signature, which the score is for.
    version: [u8; 32],
    weak: Option<bool>,
}

impl HealthCheck {
    /// Scores the passwords not scored before at their version, and asks the server when
    /// each was set. Doesn't fail: what goes wrong is kept for `Vault::finish_health`.
    pub fn score(&mut self) {
        if self.ages.is_none() {
            // Servers before 0.13.0 don't say when passwords were set.
            match self
                .connection
                .call(|client| client.get::<PasswordAges>("/v1/password-ages", &[]))
            {
                Ok(Ok(ages)) => {
                    self.ages = Some(Some(
                        ages.items
                            .into_iter()
                            .filter_map(|age| Some((age.item_id, age.since?)))
                            .collect(),
                    ));
                }
                Ok(Err(Failure::Status { code: 404, .. })) => self.ages = Some(None),
                Ok(Err(error)) => self.failure = Some(error.into()),
                Err(error) => self.failure = Some(error),
            }
        }
        for (check, password, inputs) in self.to_score.drain(..) {
            let inputs = [inputs[0].as_str(), inputs[1].as_str(), inputs[2].as_str()];
            let weak = !matches!(
                zxcvbn(&password, &inputs).score(),
                Score::Three | Score::Four
            );
            self.checks[check].weak = Some(weak);
        }
    }
}

impl Vault {
    /// Checks the passwords of the logins you can change, as of `now` (seconds since 1970):
    /// weak ones, ones that other logins you can open share, and ones set over a year ago.
    /// Passwords are opened in memory only, and nothing about them is kept but whether
    /// each is weak.
    pub fn password_health(&mut self, now: i64) -> Result<PasswordHealth> {
        let mut check = self.begin_health(now)?;
        check.score();
        self.finish_health(check)
    }

    /// Starts a password health check: opens every password you can, each folder's key
    /// once, and sets aside the ones to score (see `HealthCheck`).
    pub fn begin_health(&mut self, now: i64) -> Result<HealthCheck> {
        let rows = self.list()?;
        let mut folder_keys: HashMap<FolderId, Vec<FolderKey>> = HashMap::new();
        let mut checks = Vec::new();
        let mut to_score = Vec::new();
        for (index, row) in rows.iter().enumerate() {
            let Ok(item) = self.live_item(row.id) else {
                continue;
            };
            let folder = item
                .folder_id
                .filter(|folder_id| self.profile.folders.contains_key(folder_id));
            if let Some(folder_id) = folder {
                // One that doesn't open leaves its logins out, as each would be on its own.
                folder_keys.entry(folder_id).or_insert_with(|| {
                    self.profile
                        .folder_keys(&self.keys, &self.groups, folder_id)
                        .unwrap_or_default()
                });
            }
            let keys = folder.map_or(&[][..], |folder_id| &folder_keys[&folder_id]);
            // One saved by a newer app can't be opened here; it's left out.
            let Ok(key) = self.item_key_with(item, keys) else {
                continue;
            };
            let Ok(details) = item.open_details(&key) else {
                continue;
            };
            if details.password.is_empty() {
                continue;
            }
            let changeable = row.role >= Role::Edit;
            let version: [u8; 32] = Sha256::digest(item.signature.as_slice()).into();
            let weak = self
                .health_scores
                .get(&row.id)
                .filter(|(scored, _)| *scored == version)
                .map(|&(_, weak)| weak);
            if changeable && weak.is_none() {
                let inputs = [row.name.clone(), row.username.clone(), row.url.clone()];
                to_score.push((
                    checks.len(),
                    Zeroizing::new(details.password.clone()),
                    inputs,
                ));
            }
            checks.push(Check {
                row: index,
                digest: Sha256::digest(details.password.as_bytes()).into(),
                changeable,
                version,
                weak,
            });
        }
        Ok(HealthCheck {
            connection: self.connection.clone(),
            connection_generation: self.connection.generation,
            now,
            rows,
            checks,
            to_score,
            ages: None,
            failure: None,
        })
    }

    /// Finishes a password health check: what needs attention, those with most problems
    /// first. Remembers the scores, for the next check.
    pub fn finish_health(&mut self, mut check: HealthCheck) -> Result<PasswordHealth> {
        // In case it wasn't scored with the vault free.
        check.score();
        let HealthCheck {
            connection,
            connection_generation,
            now,
            rows,
            checks,
            ages,
            failure,
            ..
        } = check;
        if self.connection.generation == connection_generation {
            self.connection = connection;
        }
        if let Some(error) = failure {
            return Err(error);
        }
        let ages = ages.flatten();
        // Logins by password, as a digest held only for this check.
        let mut by_password: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
        for check in &checks {
            by_password.entry(check.digest).or_default().push(check.row);
        }

        let mut health = PasswordHealth {
            ages_known: ages.is_some(),
            ..PasswordHealth::default()
        };
        for check in checks.iter().filter(|check| check.changeable) {
            let index = check.row;
            let row = &rows[index];
            let weak = check.weak.unwrap_or(false);
            self.health_scores.insert(row.id, (check.version, weak));
            health.checked += 1;
            let mut reused_with: Vec<String> = by_password[&check.digest]
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
