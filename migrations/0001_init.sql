-- segv.sh D1 schema (docs/PROTOCOL.md §4–§5).
-- users / wraps are a DERIVED, idempotently rebuilt index of the public log. The authoritative log lives
-- in the LogDO Durable Object (SQLite); every users / wraps row can be recomputed from it. The blobs
-- registry is the exception: it is server-side bookkeeping that the log does not contain (see 0002).
-- Binary values are stored as base64url TEXT (D1 returns BLOB columns as number[]).

-- kind-1 rows: one per registered account.
CREATE TABLE IF NOT EXISTS users (
  uid TEXT PRIMARY KEY,          -- b64u(16-byte uid)
  handle TEXT NOT NULL UNIQUE,   -- ^[a-z0-9_]{3,20}$
  bundle TEXT NOT NULL,          -- exact signed bundle text
  sig TEXT NOT NULL,             -- b64u(Ed25519 signature)
  seq INTEGER NOT NULL           -- log seq of the kind-1 row
);

-- kind-2 rows: passkey / recovery key wraps (several per id are allowed).
CREATE TABLE IF NOT EXISTS wraps (
  seq INTEGER PRIMARY KEY,       -- log seq of the kind-2 row
  id TEXT NOT NULL,              -- b64u(credential id | recovery id)
  uid TEXT NOT NULL,             -- b64u(owner uid)
  record TEXT NOT NULL,          -- exact signed record text
  sig TEXT NOT NULL              -- b64u(Ed25519 signature)
);
CREATE INDEX IF NOT EXISTS wraps_id ON wraps (id);

-- Encrypted, content-addressed blobs in R2 (key "b/<id>").
CREATE TABLE IF NOT EXISTS blobs (
  id TEXT PRIMARY KEY,           -- b64u(SHA-256(blob))
  size INTEGER NOT NULL,         -- bytes
  created_at INTEGER NOT NULL    -- UTC day of the first upload, as ms at 00:00:00Z (0002)
);
