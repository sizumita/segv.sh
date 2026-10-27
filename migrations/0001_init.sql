-- segv.sh D1 schema: the directory (docs/PROTOCOL-v2.md §9.6). Authoritative: there is no outbox and no log fallback.
-- Binary values are stored as base64url TEXT; dirseq = the dirlog seq of the row.

-- One row per registered account (the exact signed bundle text and its signature).
CREATE TABLE IF NOT EXISTS user (
  uid TEXT PRIMARY KEY,            -- b64u(16 B)
  upre INTEGER NOT NULL,           -- u32, §2.5
  handle TEXT NOT NULL UNIQUE,
  hpre INTEGER NOT NULL,           -- u32
  bundle TEXT NOT NULL, sig TEXT NOT NULL,   -- exact signed text, b64u signature
  reg_era INTEGER NOT NULL,        -- era(server time) at registration
  dirseq INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS user_upre ON user (upre);
CREATE INDEX IF NOT EXISTS user_hpre ON user (hpre);

-- Passkey and recovery wrap records (several uids may share an id; at most 64 per uid).
CREATE TABLE IF NOT EXISTS wrap (
  uid TEXT NOT NULL, id TEXT NOT NULL,       -- b64u
  record TEXT NOT NULL, sig TEXT NOT NULL, dirseq INTEGER NOT NULL,
  PRIMARY KEY (uid, id)
);
CREATE INDEX IF NOT EXISTS wrap_id ON wrap (id, dirseq);

-- The public audit log of the directory: h_seq = H(enc("segv.sh/v2/dirlog", h_{seq-1}, u64 seq, u8 kind, ref)),
-- kind 1 = user, 2 = wrap; ref and h are b64u. Seqs are contiguous from 1 (explicit seqs, optimistic retries).
CREATE TABLE IF NOT EXISTS dirlog (seq INTEGER PRIMARY KEY, kind INTEGER NOT NULL, ref TEXT NOT NULL, h TEXT NOT NULL);

-- 'users': the number of user rows (P is derived from it, never from count(*)).
CREATE TABLE IF NOT EXISTS dirmeta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
INSERT OR IGNORE INTO dirmeta (k, v) VALUES ('users', 0);
