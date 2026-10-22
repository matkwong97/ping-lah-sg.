CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL, recovery_hash TEXT UNIQUE, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS friends (user_id TEXT NOT NULL, friend_id TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(user_id,friend_id));
CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, sender_id TEXT NOT NULL, receiver_id TEXT NOT NULL, kind TEXT NOT NULL, body TEXT, object_key TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, read_at INTEGER);
CREATE INDEX IF NOT EXISTS msg_recipient ON messages(receiver_id,created_at);
CREATE INDEX IF NOT EXISTS msg_expiry ON messages(expires_at);

CREATE TABLE IF NOT EXISTS rate_limits (k TEXT PRIMARY KEY,n INTEGER NOT NULL,expires_at INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS voice_blobs (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, data_base64 TEXT NOT NULL, mime TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS voice_expiry ON voice_blobs(expires_at);
