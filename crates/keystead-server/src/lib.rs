//! Keystead server: stores and relays encrypted data for one team.
//!
//! It never holds a key that can open what it stores. It checks who may do what, keeps
//! the change feed in order and relays ciphertexts; clients do all encryption and verify
//! everything the server sends. The API is specified in `docs/format.md`.

mod accounts;
mod error;
mod groups;
mod transfers;
mod vault;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use keystead_core::api::Health;
use keystead_core::directory::DirectoryEntry;
use keystead_core::encoding::Key32;
use keystead_core::ids::UserId;
use keystead_core::keys::AccountPublicKeys;
use rand::Rng;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePool, SqlitePoolOptions,
    SqliteSynchronous,
};

pub use error::ApiError;

const SCHEMA: &str = include_str!("schema.sql");

/// Changes to the schema since `schema.sql` (version 0.1.0), in order. A database records
/// how many it has run in SQLite's `user_version`, so each runs once, on new and existing
/// servers alike. Only ever append.
const MIGRATIONS: &[&str] = &[
    // 1 (0.2.0): device names, and when each device was added.
    "ALTER TABLE devices ADD COLUMN name TEXT NOT NULL DEFAULT '';
     ALTER TABLE devices ADD COLUMN added_at INTEGER;",
    // 2 (0.2.0): items outside folders (SQLite can't drop NOT NULL, so the table is
    // rebuilt), and who can open an item without being in its folder.
    "CREATE TABLE items_new (
         id TEXT PRIMARY KEY,
         folder_id TEXT REFERENCES folders (id),
         version INTEGER NOT NULL,
         seq INTEGER NOT NULL,
         body TEXT NOT NULL
     );
     INSERT INTO items_new (id, folder_id, version, seq, body)
         SELECT id, folder_id, version, seq, body FROM items;
     DROP TABLE items;
     ALTER TABLE items_new RENAME TO items;
     CREATE INDEX items_folder_seq ON items (folder_id, seq);
     CREATE TABLE item_access (
         user_id INTEGER NOT NULL REFERENCES users (id),
         item_id TEXT NOT NULL REFERENCES items (id),
         PRIMARY KEY (user_id, item_id)
     ) WITHOUT ROWID;",
    // 3 (0.3.0): roles; removing people from folders, logins and the team; folder keys
    // that change after someone loses access, chained so older items still open. Everyone
    // who already had access could do everything, so they become managers.
    "ALTER TABLE members ADD COLUMN role TEXT NOT NULL DEFAULT 'manage';
     ALTER TABLE item_access ADD COLUMN role TEXT NOT NULL DEFAULT 'manage';
     ALTER TABLE folders ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE folders ADD COLUMN needs_rekey INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE users ADD COLUMN removed_at INTEGER;
     CREATE TABLE folder_keys (
         folder_id TEXT NOT NULL REFERENCES folders (id),
         generation INTEGER NOT NULL,
         previous TEXT NOT NULL,
         PRIMARY KEY (folder_id, generation)
     ) WITHOUT ROWID;
     CREATE TABLE rekey_log (
         seq INTEGER PRIMARY KEY,
         user_id INTEGER NOT NULL,
         folder_id TEXT NOT NULL
     );
     CREATE INDEX rekey_log_user ON rekey_log (user_id, seq);
     CREATE TABLE item_leave_log (
         seq INTEGER PRIMARY KEY,
         user_id INTEGER NOT NULL,
         item_id TEXT NOT NULL
     );
     CREATE INDEX item_leave_log_user ON item_leave_log (user_id, seq);",
    // 4 (0.4.0): groups, sharing folders and items with them, and who can open what
    // whichever way, kept up to date from the rest (`vault::reconcile`). Before groups,
    // that was exactly the folder members and the people items were shared with.
    "CREATE TABLE team_groups (
         id TEXT PRIMARY KEY,
         generation INTEGER NOT NULL,
         needs_rekey INTEGER NOT NULL DEFAULT 0
     );
     CREATE TABLE group_entries (
         group_id TEXT NOT NULL REFERENCES team_groups (id),
         revision INTEGER NOT NULL,
         body TEXT NOT NULL,
         PRIMARY KEY (group_id, revision)
     ) WITHOUT ROWID;
     CREATE TABLE group_members (
         user_id INTEGER NOT NULL REFERENCES users (id),
         group_id TEXT NOT NULL REFERENCES team_groups (id),
         wrapped_secret TEXT NOT NULL,
         PRIMARY KEY (user_id, group_id)
     ) WITHOUT ROWID;
     CREATE INDEX group_members_group ON group_members (group_id);
     CREATE TABLE group_keys (
         group_id TEXT NOT NULL REFERENCES team_groups (id),
         generation INTEGER NOT NULL,
         previous TEXT NOT NULL,
         PRIMARY KEY (group_id, generation)
     ) WITHOUT ROWID;
     CREATE TABLE group_log (
         seq INTEGER PRIMARY KEY,
         user_id INTEGER NOT NULL,
         group_id TEXT NOT NULL,
         joined INTEGER NOT NULL
     );
     CREATE INDEX group_log_user ON group_log (user_id, seq);
     CREATE TABLE folder_groups (
         folder_id TEXT NOT NULL REFERENCES folders (id),
         group_id TEXT NOT NULL REFERENCES team_groups (id),
         role TEXT NOT NULL,
         group_generation INTEGER NOT NULL,
         wrapped_key TEXT NOT NULL,
         PRIMARY KEY (folder_id, group_id)
     ) WITHOUT ROWID;
     CREATE INDEX folder_groups_group ON folder_groups (group_id);
     CREATE TABLE item_groups (
         item_id TEXT NOT NULL REFERENCES items (id),
         group_id TEXT NOT NULL REFERENCES team_groups (id),
         role TEXT NOT NULL,
         PRIMARY KEY (item_id, group_id)
     ) WITHOUT ROWID;
     CREATE INDEX item_groups_group ON item_groups (group_id);
     CREATE TABLE access (
         user_id INTEGER NOT NULL,
         folder_id TEXT NOT NULL,
         joined_seq INTEGER NOT NULL,
         PRIMARY KEY (user_id, folder_id)
     ) WITHOUT ROWID;
     CREATE INDEX access_folder ON access (folder_id);
     INSERT INTO access (user_id, folder_id, joined_seq)
         SELECT user_id, folder_id, joined_seq FROM members;
     CREATE TABLE item_reach (
         user_id INTEGER NOT NULL,
         item_id TEXT NOT NULL,
         PRIMARY KEY (user_id, item_id)
     ) WITHOUT ROWID;
     INSERT INTO item_reach (user_id, item_id) SELECT user_id, item_id FROM item_access;
     CREATE TABLE item_join_log (
         seq INTEGER PRIMARY KEY,
         user_id INTEGER NOT NULL,
         item_id TEXT NOT NULL
     );
     CREATE INDEX item_join_log_user ON item_join_log (user_id, seq);",
    // 5 (0.5.0): passwords to change. Whoever loses access to an item may still know its
    // password, until a version with a new one is saved (`vault::reconcile`, `put_item`).
    // Nothing was recorded before, so it starts empty.
    "CREATE TABLE exposures (
         item_id TEXT NOT NULL,
         user_id INTEGER NOT NULL,
         since INTEGER NOT NULL,
         PRIMARY KEY (item_id, user_id)
     ) WITHOUT ROWID;",
    // 6 (0.7.0): item history. Each item's earlier versions (`vault::HISTORY_KEPT` of them)
    // and when each version was saved. Versions saved before have no time.
    "ALTER TABLE items ADD COLUMN saved_at INTEGER;
     CREATE TABLE item_history (
         item_id TEXT NOT NULL,
         version INTEGER NOT NULL,
         saved_at INTEGER,
         body TEXT NOT NULL,
         PRIMARY KEY (item_id, version)
     ) WITHOUT ROWID;",
    // 7 (0.8.0): adding a device from one the account already has (`transfers`).
    "CREATE TABLE device_transfers (
         id TEXT PRIMARY KEY,
         token_hash BLOB NOT NULL UNIQUE,
         user_id INTEGER NOT NULL REFERENCES users (id),
         expires_at INTEGER NOT NULL,
         device_name TEXT,
         transfer_key TEXT,
         wrapped_secret TEXT
     );",
];

/// Shared by every request. Writes go through one connection so change numbers commit in
/// order (see `prototypes/change-feed`); reads use a pool.
#[derive(Clone)]
pub struct AppState {
    writer: SqlitePool,
    readers: SqlitePool,
    sessions: Arc<Mutex<HashMap<[u8; 32], accounts::SessionInfo>>>,
    challenges: Arc<Mutex<HashMap<Vec<u8>, accounts::PendingChallenge>>>,
    recoveries: Arc<Mutex<HashMap<Vec<u8>, accounts::PendingRecovery>>>,
}

impl AppState {
    /// Opens (or creates) the database. On a new server this also creates the one-time
    /// setup code that whoever runs it uses to claim it.
    pub async fn open(path: &Path) -> Result<Self, sqlx::Error> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let writer = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options.clone())
            .await?;
        sqlx::raw_sql(SCHEMA).execute(&writer).await?;
        migrate(&writer).await?;
        let readers = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await?;

        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&writer)
            .await?;
        if users == 0 {
            sqlx::query("INSERT OR IGNORE INTO settings (name, value) VALUES ('setup_code', ?)")
                .bind(new_setup_code())
                .execute(&writer)
                .await?;
        }

        Ok(Self {
            writer,
            readers,
            sessions: Arc::default(),
            challenges: Arc::default(),
            recoveries: Arc::default(),
        })
    }

    /// The setup code, until someone has used it.
    pub async fn pending_setup_code(&self) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar("SELECT value FROM settings WHERE name = 'setup_code'")
            .fetch_optional(&self.readers)
            .await
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/setup", post(accounts::setup))
        .route("/v1/sign-in/challenge", post(accounts::challenge))
        .route("/v1/sign-in", post(accounts::sign_in))
        .route("/v1/invites", post(accounts::create_invite))
        .route("/v1/invites/accept", post(accounts::accept_invite))
        .route("/v1/recover/challenge", post(accounts::recovery_challenge))
        .route("/v1/recover", post(accounts::recover))
        .route("/v1/devices", get(accounts::devices))
        .route("/v1/devices/{device_id}", delete(accounts::remove_device))
        .route("/v1/sign-out", post(accounts::sign_out))
        .route("/v1/users/{user_id}/approval", post(accounts::approve))
        .route("/v1/users/{user_id}", delete(accounts::remove_user))
        .route("/v1/directory", get(accounts::directory))
        .route("/v1/device-transfers", post(transfers::start))
        .route("/v1/device-transfers/join", post(transfers::join))
        .route("/v1/device-transfers/claim", post(transfers::claim))
        .route(
            "/v1/device-transfers/{id}",
            get(transfers::state).delete(transfers::cancel),
        )
        .route(
            "/v1/device-transfers/{id}/secret",
            put(transfers::send_secret),
        )
        .route("/v1/folders", post(vault::create_folder))
        .route(
            "/v1/folders/{folder_id}/members",
            post(vault::add_member).get(vault::members),
        )
        .route(
            "/v1/folders/{folder_id}/members/{user_id}",
            put(vault::set_member_role).delete(vault::remove_member),
        )
        .route("/v1/folders/{folder_id}/rekey", post(vault::rekey))
        .route(
            "/v1/folders/{folder_id}/groups",
            post(vault::add_folder_group),
        )
        .route(
            "/v1/folders/{folder_id}/groups/{group_id}",
            put(vault::set_folder_group_role).delete(vault::remove_folder_group),
        )
        .route("/v1/groups", post(groups::create_group).get(groups::groups))
        .route("/v1/groups/{group_id}", put(groups::update_group))
        .route(
            "/v1/groups/{group_id}/members",
            post(groups::add_group_member),
        )
        .route(
            "/v1/groups/{group_id}/members/{user_id}",
            delete(groups::remove_group_member),
        )
        .route("/v1/groups/{group_id}/rekey", post(groups::rekey_group))
        .route("/v1/items/{item_id}", put(vault::put_item))
        .route("/v1/items/{item_id}/people", get(vault::item_people))
        .route("/v1/items/{item_id}/history", get(vault::item_history))
        .route(
            "/v1/items/{item_id}/people/{user_id}",
            put(vault::set_item_role),
        )
        .route(
            "/v1/items/{item_id}/groups/{group_id}",
            put(vault::set_item_group_role),
        )
        .route(
            "/v1/items/{item_id}/exposures/{user_id}",
            delete(vault::dismiss_exposure),
        )
        .route("/v1/exposures", get(vault::exposures))
        .route("/v1/sync", get(vault::sync))
        .with_state(state)
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok".into(),
        version: keystead_core::VERSION.into(),
        item_format: keystead_core::items::ITEM_FORMAT,
    })
}

/// Twelve characters in three groups, from an alphabet without look-alikes (about 60 bits).
fn new_setup_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..3)
        .map(|_| {
            (0..4)
                .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Runs the migrations this database hasn't had yet, each in its own transaction.
async fn migrate(writer: &SqlitePool) -> Result<(), sqlx::Error> {
    let applied: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(writer)
        .await?;
    let applied = usize::try_from(applied).unwrap_or(0);
    for (index, migration) in MIGRATIONS.iter().enumerate().skip(applied) {
        let mut tx = writer.begin().await?;
        sqlx::raw_sql(migration).execute(&mut *tx).await?;
        let version = format!("PRAGMA user_version = {}", index + 1);
        sqlx::raw_sql(&version).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    Ok(())
}

async fn next_seq(conn: &mut SqliteConnection) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE feed_counter SET last_seq = last_seq + 1 WHERE id = 1 RETURNING last_seq",
    )
    .fetch_one(conn)
    .await
}

type UserRow = (i64, String, Vec<u8>, Vec<u8>, Option<Vec<u8>>, bool);

const USER_COLUMNS: &str = "SELECT id, name, encryption_key, signing_key, approval, \
                            removed_at IS NOT NULL FROM users";

async fn user_entry(
    conn: &mut SqliteConnection,
    user: UserId,
) -> Result<Option<DirectoryEntry>, ApiError> {
    let row: Option<UserRow> = sqlx::query_as(&format!("{USER_COLUMNS} WHERE id = ?"))
        .bind(user.0)
        .fetch_optional(conn)
        .await?;
    row.map(entry_from_row).transpose()
}

fn entry_from_row(
    (id, name, encryption, signing, approval, removed): UserRow,
) -> Result<DirectoryEntry, ApiError> {
    let key = |bytes: Vec<u8>| -> Result<Key32, ApiError> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ApiError::Internal("stored key has the wrong length".into()))?;
        Ok(Key32(bytes))
    };
    Ok(DirectoryEntry {
        user_id: UserId(id),
        name,
        keys: AccountPublicKeys {
            encryption: key(encryption)?,
            signing: key(signing)?,
        },
        approval: approval.map(Into::into),
        removed,
    })
}
