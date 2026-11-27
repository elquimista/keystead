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
use keystead_core::directory::{DirectoryEntry, InviteProof, RetiredKeys};
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
    // 8 (0.12.0): moving items between folders. Members of the folder an item left are
    // told it moved, so their devices drop the copy that still says it's theirs.
    "ALTER TABLE item_leave_log ADD COLUMN moved INTEGER NOT NULL DEFAULT 0;",
    // 9 (0.13.0): recovering with the owner's help. Retired keys keep old signatures
    // checkable; copies wrapped for someone's old keys wait, pending, for new ones.
    "ALTER TABLE users ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE users ADD COLUMN escrow_on INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE users ADD COLUMN escrow TEXT;
     ALTER TABLE users ADD COLUMN recovered_key TEXT;
     CREATE TABLE retired_keys (
         user_id INTEGER NOT NULL REFERENCES users (id),
         revision INTEGER NOT NULL,
         name TEXT NOT NULL,
         encryption_key BLOB NOT NULL,
         signing_key BLOB NOT NULL,
         approval BLOB NOT NULL,
         PRIMARY KEY (user_id, revision)
     ) WITHOUT ROWID;
     CREATE TABLE recoveries (
         user_id INTEGER PRIMARY KEY REFERENCES users (id),
         token_hash BLOB NOT NULL UNIQUE,
         expires_at INTEGER NOT NULL,
         approved INTEGER NOT NULL DEFAULT 0,
         encryption_key BLOB,
         signing_key BLOB,
         device_id TEXT,
         device_key TEXT,
         device_name TEXT
     );
     ALTER TABLE members ADD COLUMN pending INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE group_members ADD COLUMN pending INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE item_access ADD COLUMN pending INTEGER NOT NULL DEFAULT 0;",
    // 10 (0.13.0): escrow of folders only one person can open: their key sealed with that
    // person's personal key. A copy goes when its member leaves the folder.
    "CREATE TABLE folder_escrow (
         user_id INTEGER NOT NULL,
         folder_id TEXT NOT NULL,
         generation INTEGER NOT NULL,
         sealed TEXT NOT NULL,
         PRIMARY KEY (user_id, folder_id),
         FOREIGN KEY (user_id, folder_id) REFERENCES members (user_id, folder_id)
             ON DELETE CASCADE
     ) WITHOUT ROWID;
     CREATE INDEX folder_escrow_folder ON folder_escrow (folder_id);",
    // 11 (0.13.0): what retired keys had signed when they were replaced, the owner's
    // signed list (`SignedBefore`, as JSON). They verify nothing else.
    "ALTER TABLE retired_keys ADD COLUMN signed_before TEXT;",
    // 12 (0.13.0): escrow needs the person's own signed agreement, and an escrowed personal
    // key stays until the account puts one in escrow for its current keys, so a recovery
    // the new device never finished can be done again without losing anything.
    "ALTER TABLE users ADD COLUMN escrow_consent BLOB;
     ALTER TABLE users ADD COLUMN escrow_revision INTEGER NOT NULL DEFAULT 0;",
    // 13 (0.13.0): when each item's password was last set, for password health. Items saved
    // before get the time they were last saved, which is no earlier.
    "ALTER TABLE items ADD COLUMN password_saved_at INTEGER;
     UPDATE items SET password_saved_at = saved_at;",
    // 14 (0.15.0): each folder's members, signed by its members, one entry per change.
    // Clients wrap a folder's key only for who its latest entry names. And the entries of
    // groups since deleted, which folder entries their members signed are checked against.
    // And with someone's retired keys, their agreement to escrow if it stood then: their
    // next device agrees again only on that, not on the server's say.
    "CREATE TABLE folder_entries (
         folder_id TEXT NOT NULL REFERENCES folders (id),
         revision INTEGER NOT NULL,
         body TEXT NOT NULL,
         PRIMARY KEY (folder_id, revision)
     ) WITHOUT ROWID;
     CREATE TABLE former_group_entries (
         group_id TEXT NOT NULL,
         revision INTEGER NOT NULL,
         body TEXT NOT NULL,
         PRIMARY KEY (group_id, revision)
     ) WITHOUT ROWID;
     ALTER TABLE retired_keys ADD COLUMN escrow_consent BLOB;",
    // 15 (0.16.0): invites stop working after seven days, and the owner can list the ones
    // not used yet and take one back. Ones from before get seven days from now.
    "ALTER TABLE invites ADD COLUMN id INTEGER;
     ALTER TABLE invites ADD COLUMN created_at INTEGER;
     ALTER TABLE invites ADD COLUMN expires_at INTEGER;
     UPDATE invites SET id = rowid;
     UPDATE invites SET created_at = CAST(strftime('%s', 'now') AS INTEGER),
         expires_at = CAST(strftime('%s', 'now') AS INTEGER) + 604800
     WHERE used = 0;
     CREATE UNIQUE INDEX invites_id ON invites (id);",
    // 16 (0.18.0): agreements to escrow sign a number that only goes up, kept with the
    // account (also once escrow is off) and with its retired keys.
    "ALTER TABLE users ADD COLUMN escrow_sequence INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE retired_keys ADD COLUMN escrow_sequence INTEGER NOT NULL DEFAULT 0;",
    // 17 (0.18.0): an invite's nonce, from the owner's app, and with whoever joined with
    // it, the nonce and their proof made with the invite's key, so the owner's app can
    // approve them on its own.
    "ALTER TABLE invites ADD COLUMN nonce BLOB;
     ALTER TABLE users ADD COLUMN invite_nonce BLOB;
     ALTER TABLE users ADD COLUMN invite_proof BLOB;",
    // 18 (0.19.0): indexes for what saves, syncs and Recently Deleted look up. Deleted
    // items by when they were deleted, and only those: a query uses it only if it says
    // `COALESCE(json_extract(body, '$.deleted'), 0)` exactly so. A login's direct access
    // and a folder's members, which their primary keys don't lead with. And the copies
    // people who recovered are waiting for, which every sync looks for.
    "CREATE INDEX items_deleted ON items (saved_at)
         WHERE COALESCE(json_extract(body, '$.deleted'), 0);
     CREATE INDEX item_access_item ON item_access (item_id);
     CREATE INDEX members_folder ON members (folder_id);
     CREATE INDEX members_pending ON members (folder_id) WHERE pending;
     CREATE INDEX item_access_pending ON item_access (item_id) WHERE pending;",
];

/// Shared by every request. Writes go through one connection so change numbers commit in
/// order (see `prototypes/change-feed`); reads use a pool.
#[derive(Clone)]
pub struct AppState {
    /// The one connection that writes. A route anyone can call without signing in (with
    /// an invite, a recovery line, a new device's line, the setup code) checks what it
    /// was given on a reader before asking for this one, so a flood of tokens that don't
    /// work never queues ahead of people's saves.
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
        // What SQLite knows about the tables, for its query plans: gathered now for any
        // that need it, which takes a moment at most, then kept up by `tidy`.
        sqlx::query("PRAGMA optimize = 0x10002")
            .execute(&writer)
            .await?;
        let readers = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await?;

        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&writer)
            .await?;
        if users == 0 {
            // A code that ran out is replaced, here at start. One from before codes ran
            // out (0.16.0) gets its day from now.
            let mut tx = writer.begin().await?;
            sqlx::query(&format!(
                "DELETE FROM settings WHERE name IN ('setup_code', 'setup_code_expires')
                   AND EXISTS (SELECT 1 FROM settings WHERE name = 'setup_code_expires'
                               AND CAST(value AS INTEGER) <= {NOW})"
            ))
            .execute(&mut *tx)
            .await?;
            sqlx::query("INSERT OR IGNORE INTO settings (name, value) VALUES ('setup_code', ?)")
                .bind(new_setup_code())
                .execute(&mut *tx)
                .await?;
            sqlx::query(&format!(
                "INSERT OR IGNORE INTO settings (name, value)
                 VALUES ('setup_code_expires', {NOW} + {SETUP_CODE_LASTS})"
            ))
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }

        Ok(Self {
            writer,
            readers,
            sessions: Arc::default(),
            challenges: Arc::default(),
            recoveries: Arc::default(),
        })
    }

    /// The setup code, until someone has used it or it has run out.
    pub async fn pending_setup_code(&self) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar(&format!(
            "SELECT value FROM settings WHERE name = 'setup_code'
               AND EXISTS (SELECT 1 FROM settings WHERE name = 'setup_code_expires'
                           AND CAST(value AS INTEGER) > {NOW})"
        ))
        .fetch_optional(&self.readers)
        .await
    }

    /// Until when the setup code works, like "2026-11-27 14:05 UTC".
    pub async fn setup_code_works_until(&self) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT strftime('%Y-%m-%d %H:%M UTC', CAST(value AS INTEGER), 'unixepoch')
             FROM settings WHERE name = 'setup_code_expires'",
        )
        .fetch_optional(&self.readers)
        .await
    }

    /// Housekeeping, which the server does at start and then every hour: forgets the
    /// history of logins deleted more than 30 days ago, and keeps what SQLite knows about
    /// the tables up to date. Saves and requests don't wait on it.
    pub async fn tidy(&self) -> Result<(), sqlx::Error> {
        let mut tx = self.writer.begin().await?;
        vault::purge_deleted(&mut tx).await?;
        tx.commit().await?;
        sqlx::query("PRAGMA optimize").execute(&self.writer).await?;
        Ok(())
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/setup", post(accounts::setup))
        .route("/v1/sign-in/challenge", post(accounts::challenge))
        .route("/v1/sign-in", post(accounts::sign_in))
        .route("/v1/sign-in/renew", post(accounts::renew))
        .route(
            "/v1/invites",
            post(accounts::create_invite).get(accounts::invites),
        )
        .route("/v1/invites/{id}", delete(accounts::revoke_invite))
        .route("/v1/invites/accept", post(accounts::accept_invite))
        .route("/v1/recover/challenge", post(accounts::recovery_challenge))
        .route("/v1/recover", post(accounts::recover))
        .route("/v1/devices", get(accounts::devices))
        .route("/v1/devices/{device_id}", delete(accounts::remove_device))
        .route("/v1/sign-out", post(accounts::sign_out))
        .route("/v1/users/{user_id}/approval", post(accounts::approve))
        .route("/v1/users/{user_id}", delete(accounts::remove_user))
        .route(
            "/v1/users/{user_id}/removal",
            get(accounts::removal).post(accounts::remove_user_with),
        )
        .route(
            "/v1/users/{user_id}/recovery",
            post(accounts::start_recovery)
                .get(accounts::recovery_in_progress)
                .delete(accounts::cancel_recovery),
        )
        .route(
            "/v1/users/{user_id}/recovery/approval",
            post(accounts::approve_recovery),
        )
        .route(
            "/v1/users/{user_id}/retired/{revision}",
            get(accounts::signed_before),
        )
        .route("/v1/recovery/claim", post(accounts::claim_recovery))
        .route("/v1/recovery/state", post(accounts::recovery_state))
        .route(
            "/v1/escrow",
            put(accounts::put_escrow).delete(accounts::delete_escrow),
        )
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
        .route("/v1/folders/{folder_id}", delete(vault::delete_folder))
        .route(
            "/v1/folders/{folder_id}/members",
            post(vault::add_member).get(vault::members),
        )
        .route(
            "/v1/folders/{folder_id}/members/{user_id}",
            put(vault::set_member_role).delete(vault::remove_member),
        )
        .route(
            "/v1/folders/{folder_id}/members/{user_id}/key",
            put(vault::restore_folder_key),
        )
        .route("/v1/folders/{folder_id}/rekey", post(vault::rekey))
        .route(
            "/v1/folders/{folder_id}/entries",
            put(vault::put_first_folder_entry),
        )
        .route(
            "/v1/folders/{folder_id}/escrow",
            put(vault::put_folder_escrow),
        )
        .route(
            "/v1/folders/{folder_id}/groups",
            post(vault::add_folder_group),
        )
        .route(
            "/v1/folders/{folder_id}/groups/{group_id}",
            put(vault::set_folder_group_role).delete(vault::remove_folder_group),
        )
        .route("/v1/groups", post(groups::create_group).get(groups::groups))
        .route(
            "/v1/groups/{group_id}",
            put(groups::update_group).delete(groups::delete_group),
        )
        .route(
            "/v1/groups/{group_id}/members",
            post(groups::add_group_member),
        )
        .route(
            "/v1/groups/{group_id}/members/{user_id}",
            delete(groups::remove_group_member),
        )
        .route("/v1/groups/{group_id}/rekey", post(groups::rekey_group))
        .route(
            "/v1/groups/{group_id}/members/{user_id}/secret",
            put(groups::restore_group_secret),
        )
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
        .route("/v1/password-ages", get(vault::password_ages))
        .route("/v1/deleted", get(vault::deleted_items))
        .route("/v1/deleted/{item_id}", delete(vault::purge_item))
        .route("/v1/sync", get(vault::sync))
        .with_state(state)
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok".into(),
        version: keystead_core::VERSION.into(),
        item_format: keystead_core::items::ITEM_FORMAT,
        membership: 2,
        escrow: 2,
        invite_keys: true,
    })
}

/// How long a setup code works. A server is claimed right after it's first started, so a
/// code still lying in an old log, or a server left unclaimed, isn't a way to own it for
/// good. Restarting an unclaimed server whose code ran out makes a new one.
const SETUP_CODE_LASTS: i64 = 24 * 60 * 60;
const NOW: &str = "CAST(strftime('%s', 'now') AS INTEGER)";

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

/// The next change number: one more than the last, and never behind the clock, in
/// milliseconds since 1970 (0.17.0 and later). A server restored from a backup then goes
/// on from now, past every number a device saw before the restore, instead of handing out
/// the same numbers again for other changes, which devices would skip.
async fn next_seq(conn: &mut SqliteConnection) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE feed_counter
         SET last_seq = MAX(last_seq + 1,
                            CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER))
         WHERE id = 1 RETURNING last_seq",
    )
    .fetch_one(conn)
    .await
}

type UserRow = (
    i64,
    String,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    bool,
    u32,
    bool,
    Option<Vec<u8>>,
    i64,
    bool,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

const USER_COLUMNS: &str = "SELECT id, name, encryption_key, signing_key, approval, \
                            removed_at IS NOT NULL, revision, escrow_on, escrow_consent, \
                            escrow_sequence, \
                            EXISTS (SELECT 1 FROM recoveries r WHERE r.user_id = users.id \
                                    AND NOT r.approved \
                                    AND r.expires_at > CAST(strftime('%s', 'now') AS INTEGER)), \
                            CASE WHEN approval IS NULL AND removed_at IS NULL \
                                 THEN invite_nonce END, \
                            CASE WHEN approval IS NULL AND removed_at IS NULL \
                                 THEN invite_proof END \
                            FROM users";

type RetiredRow = (
    i64,
    u32,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    i64,
);

async fn user_entry(
    conn: &mut SqliteConnection,
    user: UserId,
) -> Result<Option<DirectoryEntry>, ApiError> {
    let row: Option<UserRow> = sqlx::query_as(&format!("{USER_COLUMNS} WHERE id = ?"))
        .bind(user.0)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let retired: Vec<RetiredRow> = sqlx::query_as(
        "SELECT user_id, revision, name, encryption_key, signing_key, approval, escrow_consent,
                escrow_sequence
         FROM retired_keys WHERE user_id = ? ORDER BY revision",
    )
    .bind(user.0)
    .fetch_all(conn)
    .await?;
    entry_from_row(row, retired).map(Some)
}

/// Everyone's retired keys, by user.
async fn all_retired(
    conn: &mut SqliteConnection,
) -> Result<HashMap<i64, Vec<RetiredRow>>, ApiError> {
    let rows: Vec<RetiredRow> = sqlx::query_as(
        "SELECT user_id, revision, name, encryption_key, signing_key, approval, escrow_consent,
                escrow_sequence
         FROM retired_keys ORDER BY user_id, revision",
    )
    .fetch_all(conn)
    .await?;
    let mut by_user: HashMap<i64, Vec<RetiredRow>> = HashMap::new();
    for row in rows {
        by_user.entry(row.0).or_default().push(row);
    }
    Ok(by_user)
}

fn stored_key(bytes: Vec<u8>) -> Result<Key32, ApiError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ApiError::Internal("stored key has the wrong length".into()))?;
    Ok(Key32(bytes))
}

fn entry_from_row(
    (
        id,
        name,
        encryption,
        signing,
        approval,
        removed,
        revision,
        escrow,
        escrow_consent,
        escrow_sequence,
        recovering,
        invite_nonce,
        invite_proof,
    ): UserRow,
    retired: Vec<RetiredRow>,
) -> Result<DirectoryEntry, ApiError> {
    Ok(DirectoryEntry {
        user_id: UserId(id),
        name,
        keys: AccountPublicKeys {
            encryption: stored_key(encryption)?,
            signing: stored_key(signing)?,
        },
        approval: approval.map(Into::into),
        removed,
        revision,
        retired: retired
            .into_iter()
            .map(
                |(_, revision, name, encryption, signing, approval, consent, sequence)| {
                    Ok(RetiredKeys {
                        revision,
                        name,
                        keys: AccountPublicKeys {
                            encryption: stored_key(encryption)?,
                            signing: stored_key(signing)?,
                        },
                        approval: approval.into(),
                        escrow_consent: consent.map(Into::into),
                        escrow_sequence: sequence as u64,
                    })
                },
            )
            .collect::<Result<_, ApiError>>()?,
        escrow,
        escrow_consent: escrow_consent.map(Into::into),
        escrow_sequence: escrow_sequence as u64,
        recovering,
        invite: invite_nonce
            .zip(invite_proof)
            .map(|(nonce, proof)| InviteProof {
                nonce: nonce.into(),
                proof: proof.into(),
            }),
    })
}
