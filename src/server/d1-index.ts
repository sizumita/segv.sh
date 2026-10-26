/**
 * D1 is a derived index of the public log (users = kind-1 rows, wraps = kind-2 rows).
 * Every statement is INSERT OR IGNORE, so re-indexing the same rows is idempotent.
 */
import { b64u, fromUtf8, parseBundle, parseWrap } from "../lib/proto";

/** Builds the D1 statement that indexes one kind-1/2 log row, or null if the row is not indexable. */
export function indexStatement(db: D1Database, seq: number, kind: number, body: Uint8Array): D1PreparedStatement | null {
  try {
    const j = JSON.parse(fromUtf8(body)) as Record<string, unknown>;
    if (kind === 1) {
      const u = parseBundle(j.bundle as string, j.sig as string);
      return db
        .prepare("INSERT OR IGNORE INTO users (uid, handle, bundle, sig, seq) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(u.uid, u.handle, u.bundle, u.bundleSig, seq);
    }
    if (kind === 2) {
      const w = parseWrap(j.record as string, j.sig as string);
      return db
        .prepare("INSERT OR IGNORE INTO wraps (seq, id, uid, record, sig) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(seq, b64u(w.id), w.uid, w.record, w.sig);
    }
  } catch {
    // Unreachable for rows this server built (they were validated before append).
  }
  return null;
}
