-- Keystead server schema. Everything secret arrives already encrypted; JSON columns hold
-- the core crate's encrypted types exactly as clients sent them.

CREATE TABLE IF NOT EXISTS settings (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- One counter numbers every change, so the feed is a single ordered stream.
CREATE TABLE IF NOT EXISTS feed_counter (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_seq INTEGER NOT NULL
);
INSERT OR IGNORE INTO feed_counter (id, last_seq) VALUES (1, 0);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    encryption_key BLOB NOT NULL,
    signing_key BLOB NOT NULL,
    approval BLOB,
    is_owner INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id),
    public_key TEXT NOT NULL
);

-- Only a hash of each invite token is kept.
CREATE TABLE IF NOT EXISTS invites (
    token_hash BLOB PRIMARY KEY,
    name TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY,
    info TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS members (
    user_id INTEGER NOT NULL REFERENCES users (id),
    folder_id TEXT NOT NULL REFERENCES folders (id),
    joined_seq INTEGER NOT NULL,
    wrapped_key TEXT NOT NULL,
    PRIMARY KEY (user_id, folder_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS membership_log (
    seq INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    folder_id TEXT NOT NULL,
    joined INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS membership_log_user ON membership_log (user_id, seq);

-- Each item keeps only its latest version, stamped with the change number that wrote it.
CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    folder_id TEXT NOT NULL REFERENCES folders (id),
    version INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS items_folder_seq ON items (folder_id, seq);
