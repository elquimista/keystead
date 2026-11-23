//! Prototype: the server's change feed on SQLite.
//!
//! Every write takes the next number from one counter. A device asks for everything after
//! the last number it saw and gets one ordered stream: item changes in its folders, plus
//! its own folder joins and leaves. Edits name the version they're based on, and a stale
//! edit is rejected as a conflict that carries the current copy.
//!
//! All writes go through one SQLite connection, so change numbers commit in order and a
//! reader can never see number N+1 before N. Reads use a separate pool in WAL mode.

pub mod simulation;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::time::Duration;

use rand::Rng;
pub use sqlx::sqlite::SqliteSynchronous as Synchronous;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePool, SqlitePoolOptions,
};

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS feed_counter (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        last_seq INTEGER NOT NULL
    );
    INSERT OR IGNORE INTO feed_counter (id, last_seq) VALUES (1, 0);

    CREATE TABLE IF NOT EXISTS folders (id INTEGER PRIMARY KEY);

    CREATE TABLE IF NOT EXISTS members (
        user_id INTEGER NOT NULL,
        folder_id INTEGER NOT NULL REFERENCES folders (id),
        joined_seq INTEGER NOT NULL,
        PRIMARY KEY (user_id, folder_id)
    ) WITHOUT ROWID;

    CREATE TABLE IF NOT EXISTS membership_log (
        seq INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        folder_id INTEGER NOT NULL,
        joined INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS membership_log_user ON membership_log (user_id, seq);

    CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY,
        folder_id INTEGER NOT NULL REFERENCES folders (id),
        version INTEGER NOT NULL,
        seq INTEGER NOT NULL,
        deleted INTEGER NOT NULL DEFAULT 0,
        ciphertext BLOB NOT NULL
    );
    CREATE INDEX IF NOT EXISTS items_folder_seq ON items (folder_id, seq);
";

/// One ordered stream: the latest change of every item in the user's folders, plus the
/// user's own joins and leaves. Each item appears once, at its latest change number.
/// Folders joined after the cursor are left out; their items ride on the join entry.
const SYNC_QUERY: &str = "
    SELECT i.seq AS seq, i.id AS id, i.folder_id AS folder_id, i.version AS version,
           i.deleted AS deleted, i.ciphertext AS ciphertext, NULL AS joined
    FROM items i JOIN members m ON m.folder_id = i.folder_id
    WHERE m.user_id = ?1 AND i.seq > ?2 AND m.joined_seq <= ?2
    UNION ALL
    SELECT seq, NULL, folder_id, NULL, NULL, NULL, joined
    FROM membership_log
    WHERE user_id = ?1 AND seq > ?2
    ORDER BY seq
    LIMIT ?3
";

type FeedRow = (
    i64,
    Option<i64>,
    i64,
    Option<i64>,
    Option<bool>,
    Option<Vec<u8>>,
    Option<bool>,
);

/// An item as the server stores it. The ciphertext is opaque to the server.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct Item {
    pub id: i64,
    pub folder_id: i64,
    pub version: i64,
    pub seq: i64,
    pub deleted: bool,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub enum FeedEntry {
    Item(Item),
    /// The user joined a folder. `items` holds the folder's contents up to the page's
    /// cursor, read from the same snapshot as the page.
    Joined {
        seq: i64,
        folder_id: i64,
        items: Vec<Item>,
    },
    Left {
        seq: i64,
        folder_id: i64,
    },
}

impl FeedEntry {
    pub fn seq(&self) -> i64 {
        match self {
            Self::Item(item) => item.seq,
            Self::Joined { seq, .. } | Self::Left { seq, .. } => *seq,
        }
    }

    fn from_row((seq, id, folder_id, version, deleted, ciphertext, joined): FeedRow) -> Self {
        match (id, joined) {
            (Some(id), _) => Self::Item(Item {
                id,
                folder_id,
                version: version.unwrap_or_default(),
                seq,
                deleted: deleted.unwrap_or_default(),
                ciphertext: ciphertext.unwrap_or_default(),
            }),
            (None, Some(true)) => Self::Joined {
                seq,
                folder_id,
                items: Vec::new(),
            },
            (None, _) => Self::Left { seq, folder_id },
        }
    }
}

pub struct SyncPage {
    pub entries: Vec<FeedEntry>,
    /// Where the next sync should start.
    pub cursor: i64,
    /// More entries are waiting; sync again right away.
    pub more: bool,
}

#[derive(Debug)]
pub enum Error {
    NotFound,
    Forbidden,
    /// Someone saved first; this is their copy.
    Conflict(Box<Item>),
    Database(sqlx::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "not found"),
            Self::Forbidden => write!(f, "not a member of that folder"),
            Self::Conflict(item) => {
                write!(f, "item {} changed to version {}", item.id, item.version)
            }
            Self::Database(error) => write!(f, "database: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Clone)]
pub struct Server {
    writer: SqlitePool,
    readers: SqlitePool,
}

impl Server {
    pub async fn open(path: &Path, synchronous: Synchronous) -> Result<Self, Error> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(synchronous)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let writer = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options.clone())
            .await?;
        sqlx::raw_sql(SCHEMA).execute(&writer).await?;
        let readers = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await?;
        Ok(Self { writer, readers })
    }

    pub async fn create_folder(&self, owner: i64) -> Result<i64, Error> {
        let mut tx = self.writer.begin().await?;
        let folder_id: i64 = sqlx::query_scalar("INSERT INTO folders DEFAULT VALUES RETURNING id")
            .fetch_one(&mut *tx)
            .await?;
        log_membership(&mut tx, owner, folder_id, true).await?;
        tx.commit().await?;
        Ok(folder_id)
    }

    pub async fn add_member(&self, folder_id: i64, user: i64) -> Result<(), Error> {
        let mut tx = self.writer.begin().await?;
        if !member(&mut tx, user, folder_id).await? {
            log_membership(&mut tx, user, folder_id, true).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn remove_member(&self, folder_id: i64, user: i64) -> Result<(), Error> {
        let mut tx = self.writer.begin().await?;
        if member(&mut tx, user, folder_id).await? {
            log_membership(&mut tx, user, folder_id, false).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn is_member(&self, user: i64, folder_id: i64) -> Result<bool, Error> {
        let mut conn = self.readers.acquire().await?;
        Ok(member(&mut conn, user, folder_id).await?)
    }

    pub async fn create_item(
        &self,
        user: i64,
        folder_id: i64,
        ciphertext: &[u8],
    ) -> Result<Item, Error> {
        let mut tx = self.writer.begin().await?;
        if !member(&mut tx, user, folder_id).await? {
            return Err(Error::Forbidden);
        }
        let seq = next_seq(&mut tx).await?;
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO items (folder_id, version, seq, ciphertext) VALUES (?, 1, ?, ?)
             RETURNING id",
        )
        .bind(folder_id)
        .bind(seq)
        .bind(ciphertext)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Item {
            id,
            folder_id,
            version: 1,
            seq,
            deleted: false,
            ciphertext: ciphertext.to_vec(),
        })
    }

    /// Saves a new version of an item, or deletes it when `ciphertext` is `None`.
    /// Fails with a conflict unless `base_version` is still the latest.
    pub async fn update_item(
        &self,
        user: i64,
        item_id: i64,
        base_version: i64,
        ciphertext: Option<&[u8]>,
    ) -> Result<Item, Error> {
        let mut tx = self.writer.begin().await?;
        let current: Item = sqlx::query_as(
            "SELECT id, folder_id, version, seq, deleted, ciphertext FROM items WHERE id = ?",
        )
        .bind(item_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
        if !member(&mut tx, user, current.folder_id).await? {
            return Err(Error::Forbidden);
        }
        if current.deleted || current.version != base_version {
            return Err(Error::Conflict(Box::new(current)));
        }
        let seq = next_seq(&mut tx).await?;
        let deleted = ciphertext.is_none();
        let ciphertext = ciphertext.unwrap_or_default().to_vec();
        sqlx::query(
            "UPDATE items SET version = version + 1, seq = ?, deleted = ?, ciphertext = ?
             WHERE id = ?",
        )
        .bind(seq)
        .bind(deleted)
        .bind(&ciphertext)
        .bind(item_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Item {
            version: current.version + 1,
            seq,
            deleted,
            ciphertext,
            ..current
        })
    }

    /// Returns up to `limit` feed entries after `cursor`, read from one consistent snapshot.
    pub async fn sync(&self, user: i64, cursor: i64, limit: i64) -> Result<SyncPage, Error> {
        let mut tx = self.readers.begin().await?;
        let rows: Vec<FeedRow> = sqlx::query_as(SYNC_QUERY)
            .bind(user)
            .bind(cursor)
            .bind(limit + 1)
            .fetch_all(&mut *tx)
            .await?;
        let high_water: i64 = sqlx::query_scalar("SELECT last_seq FROM feed_counter WHERE id = 1")
            .fetch_one(&mut *tx)
            .await?;

        let more = rows.len() as i64 > limit;
        let mut entries: Vec<FeedEntry> = rows
            .into_iter()
            .take(limit as usize)
            .map(FeedEntry::from_row)
            .collect();
        let next_cursor = match (more, entries.last()) {
            (true, Some(last)) => last.seq(),
            _ => high_water.max(cursor),
        };

        // Folders the user joined within this page: attach their items up to the new
        // cursor. The feed left those items out, and anything newer arrives through it
        // later, so nothing is sent twice and nothing is missed.
        let joined: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT folder_id, joined_seq FROM members
             WHERE user_id = ? AND joined_seq > ? AND joined_seq <= ?",
        )
        .bind(user)
        .bind(cursor)
        .bind(next_cursor)
        .fetch_all(&mut *tx)
        .await?;
        for (folder_id, joined_seq) in joined {
            let snapshot: Vec<Item> = sqlx::query_as(
                "SELECT id, folder_id, version, seq, deleted, ciphertext FROM items
                 WHERE folder_id = ? AND seq <= ?",
            )
            .bind(folder_id)
            .bind(next_cursor)
            .fetch_all(&mut *tx)
            .await?;
            let join = entries
                .iter_mut()
                .find(|entry| matches!(entry, FeedEntry::Joined { seq, .. } if *seq == joined_seq));
            if let Some(FeedEntry::Joined { items, .. }) = join {
                *items = snapshot;
            }
        }
        tx.commit().await?;

        Ok(SyncPage {
            entries,
            cursor: next_cursor,
            more,
        })
    }

    /// What a fully synced device for `user` should show: live items in its folders.
    pub async fn visible_items(&self, user: i64) -> Result<Vec<Item>, Error> {
        Ok(sqlx::query_as(
            "SELECT i.id, i.folder_id, i.version, i.seq, i.deleted, i.ciphertext
             FROM items i JOIN members m ON m.folder_id = i.folder_id
             WHERE m.user_id = ? AND i.deleted = 0
             ORDER BY i.id",
        )
        .bind(user)
        .fetch_all(&self.readers)
        .await?)
    }
}

async fn next_seq(conn: &mut SqliteConnection) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE feed_counter SET last_seq = last_seq + 1 WHERE id = 1 RETURNING last_seq",
    )
    .fetch_one(conn)
    .await
}

async fn member(
    conn: &mut SqliteConnection,
    user: i64,
    folder_id: i64,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM members WHERE user_id = ? AND folder_id = ?)")
        .bind(user)
        .bind(folder_id)
        .fetch_one(conn)
        .await
}

async fn log_membership(
    conn: &mut SqliteConnection,
    user: i64,
    folder_id: i64,
    joined: bool,
) -> Result<(), sqlx::Error> {
    let seq = next_seq(conn).await?;
    if joined {
        sqlx::query("INSERT INTO members (user_id, folder_id, joined_seq) VALUES (?, ?, ?)")
            .bind(user)
            .bind(folder_id)
            .bind(seq)
            .execute(&mut *conn)
            .await?;
    } else {
        sqlx::query("DELETE FROM members WHERE user_id = ? AND folder_id = ?")
            .bind(user)
            .bind(folder_id)
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query("INSERT INTO membership_log (seq, user_id, folder_id, joined) VALUES (?, ?, ?, ?)")
        .bind(seq)
        .bind(user)
        .bind(folder_id)
        .bind(joined)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// A device's local copy, kept up to date from the feed. Applying an entry is idempotent:
/// a copy only replaces an older version, so seeing an item twice is harmless.
pub struct Device {
    pub user: i64,
    cursor: i64,
    last_seq: i64,
    folders: HashSet<i64>,
    items: HashMap<i64, Item>,
    order_violations: u64,
}

impl Device {
    pub fn new(user: i64) -> Self {
        Self {
            user,
            cursor: 0,
            last_seq: 0,
            folders: HashSet::new(),
            items: HashMap::new(),
            order_violations: 0,
        }
    }

    /// Feed entries that arrived out of order. Should always be zero.
    pub fn order_violations(&self) -> u64 {
        self.order_violations
    }

    /// Pulls pages until caught up and returns how many entries arrived.
    pub async fn sync(&mut self, server: &Server, page_size: i64) -> Result<usize, Error> {
        let mut received = 0;
        loop {
            let page = server.sync(self.user, self.cursor, page_size).await?;
            received += page.entries.len();
            for entry in page.entries {
                if entry.seq() <= self.last_seq {
                    self.order_violations += 1;
                }
                self.last_seq = entry.seq();
                match entry {
                    FeedEntry::Item(item) => self.apply(item),
                    FeedEntry::Joined {
                        folder_id, items, ..
                    } => {
                        self.folders.insert(folder_id);
                        received += items.len();
                        items.into_iter().for_each(|item| self.apply(item));
                    }
                    FeedEntry::Left { folder_id, .. } => {
                        self.folders.remove(&folder_id);
                        self.items.retain(|_, item| item.folder_id != folder_id);
                    }
                }
            }
            self.cursor = page.cursor;
            self.last_seq = self.last_seq.max(page.cursor);
            if !page.more {
                return Ok(received);
            }
        }
    }

    pub async fn create(
        &mut self,
        server: &Server,
        folder_id: i64,
        ciphertext: &[u8],
    ) -> Result<(), Error> {
        let item = server.create_item(self.user, folder_id, ciphertext).await?;
        self.apply(item);
        Ok(())
    }

    /// Saves over the local version of an item, or deletes it when `ciphertext` is `None`.
    pub async fn save(
        &mut self,
        server: &Server,
        item_id: i64,
        ciphertext: Option<&[u8]>,
    ) -> Result<(), Error> {
        let base = self.version_of(item_id).ok_or(Error::NotFound)?;
        let item = server
            .update_item(self.user, item_id, base, ciphertext)
            .await?;
        self.apply(item);
        Ok(())
    }

    /// Takes the server's copy, for example after a conflict.
    pub fn accept(&mut self, item: Item) {
        self.apply(item);
    }

    pub fn version_of(&self, item_id: i64) -> Option<i64> {
        self.items
            .get(&item_id)
            .filter(|item| self.is_visible(item))
            .map(|item| item.version)
    }

    pub fn random_folder(&self, rng: &mut impl Rng) -> Option<i64> {
        let folders: Vec<i64> = self.folders.iter().copied().collect();
        (!folders.is_empty()).then(|| folders[rng.gen_range(0..folders.len())])
    }

    /// Live items in this device's folders, sorted by id.
    pub fn visible_items(&self) -> Vec<&Item> {
        let mut items: Vec<&Item> = self
            .items
            .values()
            .filter(|item| self.is_visible(item))
            .collect();
        items.sort_by_key(|item| item.id);
        items
    }

    fn is_visible(&self, item: &Item) -> bool {
        !item.deleted && self.folders.contains(&item.folder_id)
    }

    fn apply(&mut self, item: Item) {
        if self
            .items
            .get(&item.id)
            .is_none_or(|local| local.version < item.version)
        {
            self.items.insert(item.id, item);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    /// A database file in the temp folder, deleted when dropped.
    pub(crate) struct TempDb(PathBuf);

    impl TempDb {
        pub(crate) fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let name = format!(
                "keystead-feed-test-{}-{}.sqlite",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            Self(std::env::temp_dir().join(name))
        }

        pub(crate) async fn server(&self) -> Server {
            Server::open(&self.0, Synchronous::Normal).await.unwrap()
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
            }
        }
    }

    #[tokio::test]
    async fn sync_returns_only_new_changes_in_my_folders() {
        let db = TempDb::new();
        let server = db.server().await;
        let mine = server.create_folder(1).await.unwrap();
        let theirs = server.create_folder(2).await.unwrap();
        server.create_item(1, mine, b"a").await.unwrap();
        server.create_item(2, theirs, b"b").await.unwrap();

        let mut device = Device::new(1);
        assert_eq!(device.sync(&server, 100).await.unwrap(), 2); // join + item
        assert_eq!(device.visible_items().len(), 1);
        assert_eq!(device.sync(&server, 100).await.unwrap(), 0);

        server.create_item(1, mine, b"c").await.unwrap();
        assert_eq!(device.sync(&server, 100).await.unwrap(), 1);
        assert_eq!(device.visible_items().len(), 2);
    }

    #[tokio::test]
    async fn a_stale_edit_is_a_conflict_carrying_the_current_copy() {
        let db = TempDb::new();
        let server = db.server().await;
        let folder = server.create_folder(1).await.unwrap();
        server.add_member(folder, 2).await.unwrap();
        let item = server.create_item(1, folder, b"v1").await.unwrap();

        server
            .update_item(1, item.id, 1, Some(b"alice"))
            .await
            .unwrap();
        match server.update_item(2, item.id, 1, Some(b"bob")).await {
            Err(Error::Conflict(current)) => {
                assert_eq!(current.version, 2);
                assert_eq!(current.ciphertext, b"alice");
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
        let saved = server
            .update_item(2, item.id, 2, Some(b"bob"))
            .await
            .unwrap();
        assert_eq!(saved.version, 3);
    }

    #[tokio::test]
    async fn joining_a_folder_delivers_its_existing_items() {
        let db = TempDb::new();
        let server = db.server().await;
        let folder = server.create_folder(1).await.unwrap();
        for _ in 0..5 {
            server.create_item(1, folder, b"x").await.unwrap();
        }
        let mut device = Device::new(2);
        device.sync(&server, 100).await.unwrap();
        assert!(device.visible_items().is_empty());

        server.add_member(folder, 2).await.unwrap();
        device.sync(&server, 100).await.unwrap();
        assert_eq!(device.visible_items().len(), 5);
    }

    #[tokio::test]
    async fn leaving_a_folder_removes_it_and_blocks_writes() {
        let db = TempDb::new();
        let server = db.server().await;
        let folder = server.create_folder(1).await.unwrap();
        server.add_member(folder, 2).await.unwrap();
        let item = server.create_item(1, folder, b"x").await.unwrap();
        let mut device = Device::new(2);
        device.sync(&server, 100).await.unwrap();
        assert_eq!(device.visible_items().len(), 1);

        server.remove_member(folder, 2).await.unwrap();
        assert!(matches!(
            server.update_item(2, item.id, 1, Some(b"y")).await,
            Err(Error::Forbidden)
        ));
        device.sync(&server, 100).await.unwrap();
        assert!(device.visible_items().is_empty());
    }

    #[tokio::test]
    async fn deletions_reach_other_devices() {
        let db = TempDb::new();
        let server = db.server().await;
        let folder = server.create_folder(1).await.unwrap();
        server.add_member(folder, 2).await.unwrap();
        let item = server.create_item(1, folder, b"x").await.unwrap();
        let mut device = Device::new(2);
        device.sync(&server, 100).await.unwrap();

        server.update_item(1, item.id, 1, None).await.unwrap();
        device.sync(&server, 100).await.unwrap();
        assert!(device.visible_items().is_empty());
    }

    #[tokio::test]
    async fn paging_delivers_everything_in_order() {
        let db = TempDb::new();
        let server = db.server().await;
        let folder = server.create_folder(1).await.unwrap();
        let mut device = Device::new(1);
        device.sync(&server, 40).await.unwrap();
        for _ in 0..250 {
            server.create_item(1, folder, b"x").await.unwrap();
        }
        assert_eq!(device.sync(&server, 40).await.unwrap(), 250);
        assert_eq!(device.visible_items().len(), 250);
        assert_eq!(device.order_violations(), 0);
    }

    #[tokio::test]
    async fn a_join_on_a_later_page_sends_each_item_once() {
        let db = TempDb::new();
        let server = db.server().await;
        let mine = server.create_folder(2).await.unwrap();
        let shared = server.create_folder(1).await.unwrap();
        let mut device = Device::new(2);
        device.sync(&server, 10).await.unwrap();

        // 25 changes in my folder fill the first pages; the join lands after them.
        for _ in 0..25 {
            server.create_item(2, mine, b"m").await.unwrap();
        }
        for _ in 0..30 {
            server.create_item(1, shared, b"s").await.unwrap();
        }
        server.add_member(shared, 2).await.unwrap();

        let received = device.sync(&server, 10).await.unwrap();
        assert_eq!(received, 25 + 1 + 30); // my items, the join, the shared items once
        assert_eq!(device.visible_items().len(), 55);
        assert_eq!(device.order_violations(), 0);
    }
}
