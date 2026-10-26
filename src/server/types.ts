/** Shapes shared by the HTTP API (src/server/api.ts) and the log Durable Object (src/server/log-do.ts). */

/** A log row on the wire (JSON): binary fields are base64url. docs/PROTOCOL.md §5. */
export interface WireRow {
  seq: number;
  kind: number;
  tag: string;
  body: string;
  ts: number;
  h: string;
}

export interface WireHead {
  seq: number;
  h: string;
}

/** A row handed to LogDO.append(). `handle` + `uid` (b64u) are present exactly on kind-1 rows. */
export interface AppendRow {
  kind: number;
  tag: Uint8Array;
  body: Uint8Array;
  handle?: string;
  uid?: string;
}

export type Conflict = "tag" | "handle" | "uid";

export type AppendResult =
  | { ok: true; rows: { seq: number; ts: number; h: string }[]; head: WireHead }
  | { ok: false; conflict: Conflict };

export interface SinceResult {
  rows: WireRow[];
  head: WireHead;
}

/**
 * One GET /api/log page as produced by LogDO.page(): `rows` is the JSON text of the WireRow array, `last`
 * the seq + hash of its last row (null for an empty page). The page is immutable (cacheable) iff
 * last.seq < head.seq: every later request for the same (after, limit) returns exactly these rows.
 */
export interface LogPage {
  rows: string;
  head: WireHead;
  last: { seq: number; h: string } | null;
}

/** Current head + the hash of row `seq` (null when there is no such row). Validates a cached page. */
export interface PageCheck {
  head: WireHead;
  h: string | null;
}

/** A registered user straight from the log (fallback when the D1 index lags). */
export interface UserRow {
  uid: string;
  seq: number;
  body: string; // kind-1 row body: JSON text {bundle, sig}
}

/** Max rows per append batch (docs/PROTOCOL.md §4.2). */
export const BATCH_MAX = 40;
/** Max kind-4 rows (message or claim) per /api/append batch: a message, or one claim + its invites. */
export const BATCH_MAX_KIND4 = 1;
/** Max rows per GET /api/log page. */
export const LOG_PAGE_MAX = 1000;
/**
 * Max total body bytes per GET /api/log page (before base64url). At least one row is always returned.
 * A page can therefore hold fewer than `limit` rows while more rows exist: clients keep paging until the
 * last row's seq >= head.seq (or a page is empty).
 */
export const LOG_PAGE_BODY_BUDGET = 4 * 1024 * 1024;
