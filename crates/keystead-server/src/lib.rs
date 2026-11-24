//! Keystead server: stores and relays encrypted data for one organization.
//!
//! It never holds a key that can open what it stores. It checks who may do what, keeps
//! the change feed in order and relays ciphertexts; clients do all encryption and verify
//! everything the server sends. The API is specified in `docs/format.md`.

mod accounts;
mod error;
mod vault;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use keystead_core::directory::DirectoryEntry;
use keystead_core::encoding::Key32;
use keystead_core::ids::{FolderId, UserId};
use keystead_core::keys::AccountPublicKeys;
use rand::Rng;
use serde_json::{Value, json};
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
    /// setup code that the first admin uses to claim it.
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

    /// The setup code, until the first admin has used it.
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
        .route("/v1/users/{user_id}/approval", post(accounts::approve))
        .route("/v1/directory", get(accounts::directory))
        .route("/v1/folders", post(vault::create_folder))
        .route("/v1/folders/{folder_id}/members", post(vault::add_member))
        .route("/v1/items/{item_id}", put(vault::put_item))
        .route("/v1/sync", get(vault::sync))
        .with_state(state)
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "version": keystead_core::VERSION }))
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

async fn is_member(
    conn: &mut SqliteConnection,
    user: UserId,
    folder_id: FolderId,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM members WHERE user_id = ? AND folder_id = ?)")
        .bind(user.0)
        .bind(folder_id.to_string())
        .fetch_one(conn)
        .await
}

type UserRow = (i64, String, Vec<u8>, Vec<u8>, Option<Vec<u8>>);

const USER_COLUMNS: &str = "SELECT id, name, encryption_key, signing_key, approval FROM users";

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
    (id, name, encryption, signing, approval): UserRow,
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
    })
}
