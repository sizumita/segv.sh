/**
 * The v2 directory in D1 (docs/PROTOCOL-v2.md §2.4–§2.5, §9.6, §10.6).
 *
 * Contract used by the HTTP layer (src/server/api.ts). Every function throws HttpError with the status
 * of §10.1 (400 malformed, 404 unknown, 409 conflict / prefix bits out of range, 503 D1 unavailable).
 * Request bodies arrive already size-checked, proof-of-work-checked and JSON-parsed.
 *
 * The 409 for prefix bits out of range is a `PrefixBitsError` (a subclass of HttpError) whose `extra` holds
 * the fields to merge into the error JSON: the HTTP layer answers `{error: e.message, ...e.extra}`, i.e.
 * `{error, p: P}` (§10.6).
 *
 * D1 is authoritative: there is no outbox and no log fallback. Every write is one atomic D1 `batch()` that
 * appends to the hash-chained `dirlog` with explicit, contiguous seqs (optimistic concurrency: a concurrent
 * writer makes the `dirlog.seq` insert fail, and the write is retried on the new head).
 */
import {
  DIRLOG_USER,
  DIRLOG_WRAP,
  MAX_ID_LEN,
  ZERO32,
  checkUserKeys,
  dirlogH,
  dirlogRefUser,
  dirlogRefWrap,
  era,
  fromB64u,
  hpre,
  parseBundle,
  prefixRange,
  serverP,
  upre,
  type WrapRecord,
} from "../lib/proto";
import { b64Len, dec64, enc64 } from "./b64";
import { HttpError, exactKeys, logErr } from "./http";
import { checkBundleShape, checkRecordShape, verifyBundleSig, verifyRecordSig } from "./validate";

export interface DirUser {
  uid: string;
  handle: string;
  /** exact signed bundle text */
  bundle: string;
  /** b64u signature */
  sig: string;
  regEra: number;
  dirseq: number;
}

export interface DirWrap {
  uid: string;
  record: string;
  sig: string;
  dirseq: number;
}

export interface DirlogEntry {
  seq: number;
  kind: number;
  ref: string;
  h: string;
}

/** Wrap records in one registration (§10.6). */
export const MAX_WRAPS_PER_REGISTER = 4;
/** Wrap records per uid (§9.6). */
export const MAX_WRAPS_PER_UID = 64;
/** Records returned by one wraps-by-id lookup (§10.6). */
export const MAX_WRAPS_PER_ID = 64;
/** Users per prefix page (§9.6). */
export const PREFIX_PAGE = 256;
/** Largest dirlog page (§10.6). */
export const DIRLOG_PAGE_MAX = 1000;
/** Optimistic write attempts before 503 (§9.6). */
export const WRITE_ATTEMPTS = 16;
/** currentP() cache lifetime per isolate. */
export const P_CACHE_MS = 60_000;
/** After a failed dirmeta read, currentP() serves the last good P (0 if none) without asking D1 for this long. */
export const P_RETRY_MS = 5_000;

/**
 * 409 "prefix bits out of range" for a prefix lookup with p > min(32, P + 1). The HTTP layer answers
 * `{error: e.message, ...e.extra}` = `{error, p: P}` (§10.1, §10.6).
 */
export class PrefixBitsError extends HttpError {
  readonly extra: { p: number };
  constructor(readonly P: number) {
    super(409, "prefix bits out of range");
    this.extra = { p: P };
  }
}

// ───────────── D1 helpers ─────────────

const logFailure = (what: string, e: unknown): void =>
  console.error(JSON.stringify({ msg: `directory: ${what} failed`, error: logErr(e) }));

/** 503 "directory unavailable" for any D1 failure that is not a known constraint (§9.6). Logged redacted. */
function unavailable(what: string, e: unknown): HttpError {
  logFailure(what, e);
  return new HttpError(503, "directory unavailable");
}

async function d1<T>(what: string, f: () => Promise<T>): Promise<T> {
  try {
    return await f();
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw unavailable(what, e);
  }
}

/**
 * The `table.column` of a D1 UNIQUE / PRIMARY KEY failure ("UNIQUE constraint failed: dirlog.seq: …"; a
 * composite key reports its first column, e.g. "wrap.uid, wrap.id"), or null for any other error.
 */
export function uniqueFailure(e: unknown): string | null {
  let x: unknown = e;
  for (let i = 0; i < 4 && x !== null && x !== undefined; i++) {
    const msg = x instanceof Error ? x.message : String(x);
    const m = /UNIQUE constraint failed: ([A-Za-z_]+\.[A-Za-z_]+)/.exec(msg);
    if (m) return m[1];
    x = x instanceof Error ? (x as Error & { cause?: unknown }).cause : null;
  }
  return null;
}

const CONFLICTS: Readonly<Record<string, string>> = {
  "user.handle": "handle already taken",
  "user.uid": "uid already registered",
  "wrap.uid": "duplicate wrap record",
  "wrap.id": "duplicate wrap record",
};

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

const HEAD_SQL = "SELECT seq, h FROM dirlog ORDER BY seq DESC LIMIT 1";
const DIRLOG_INSERT_SQL = "INSERT INTO dirlog (seq, kind, ref, h) VALUES (?1, ?2, ?3, ?4)";

interface Entry {
  kind: number;
  ref: Uint8Array;
}

interface AppendOpts {
  /** Statements that need the seqs: the user / wrap inserts (dirseq = their dirlog seq). */
  rows: (seqs: number[]) => D1PreparedStatement[];
  /** Statements run after the dirlog inserts in the same batch (the dirmeta increment). */
  tail?: () => D1PreparedStatement[];
  /** Reads taken in the same snapshot as the head, checked by `check` before writing. */
  reads?: () => D1PreparedStatement[];
  check?: (results: D1Result[]) => void;
}

/**
 * §9.6 writes: read the head, chain `entries` after it, and run one atomic batch (rows, dirlog inserts with
 * explicit seqs, tail). Seqs stay contiguous: a committed batch always takes head + 1, so a writer that read
 * an older head fails on the `dirlog.seq` UNIQUE key; it then waits 5–50 ms × attempt and retries on the new
 * head (16 attempts, then 503). For the same reason, `reads` taken together with the head are still current
 * when the batch commits. Other UNIQUE failures are 409; anything else is 503.
 */
async function appendDir(env: Env, entries: Entry[], opts: AppendOpts): Promise<number[]> {
  const db = env.DB;
  for (let attempt = 1; ; attempt++) {
    const [headRes, ...reads] = await d1("head read", () =>
      db.batch([db.prepare(HEAD_SQL), ...(opts.reads?.() ?? [])]),
    );
    opts.check?.(reads);
    const head = (headRes.results as { seq: number; h: string }[])[0];
    const base = head?.seq ?? 0;
    let prev = head ? dec64(head.h) : ZERO32;
    const seqs = entries.map((_, i) => base + 1 + i);
    const hs = entries.map((en, i) => (prev = dirlogH(prev, seqs[i], en.kind, en.ref)));
    try {
      const log = entries.map((en, i) =>
        db.prepare(DIRLOG_INSERT_SQL).bind(seqs[i], en.kind, enc64(en.ref), enc64(hs[i])),
      );
      await db.batch([...opts.rows(seqs), ...log, ...(opts.tail?.() ?? [])]);
      return seqs;
    } catch (e) {
      const col = uniqueFailure(e);
      if (col === "dirlog.seq") {
        if (attempt >= WRITE_ATTEMPTS) throw unavailable(`write (${WRITE_ATTEMPTS} attempts)`, e);
        await sleep((5 + Math.random() * 45) * attempt);
        continue;
      }
      if (col !== null && CONFLICTS[col]) throw new HttpError(409, CONFLICTS[col]);
      throw unavailable("write", e);
    }
  }
}

// ───────────── parameter checks ─────────────

const UID_B64_LEN = b64Len(16);
const MAX_ID_B64_LEN = b64Len(MAX_ID_LEN);

/** A canonical b64u uid (16 bytes), else 400. */
function checkUid(uid: unknown, what: string): string {
  let ok = false;
  try {
    ok = typeof uid === "string" && uid.length === UID_B64_LEN && dec64(uid).length === 16;
  } catch {
    /* invalid */
  }
  if (!ok) throw new HttpError(400, `invalid ${what}`);
  return uid as string;
}

/** A canonical b64u wrap id (1..1023 bytes), else 400. */
function checkWrapId(id: unknown): string {
  let ok = false;
  try {
    ok = typeof id === "string" && id.length >= 2 && id.length <= MAX_ID_B64_LEN && dec64(id).length >= 1;
  } catch {
    /* invalid */
  }
  if (!ok) throw new HttpError(400, "invalid id");
  return id as string;
}

// ───────────── writes ─────────────

const USER_INSERT_SQL =
  "INSERT INTO user (uid, upre, handle, hpre, bundle, sig, reg_era, dirseq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)";
const WRAP_INSERT_SQL = "INSERT INTO wrap (uid, id, record, sig, dirseq) VALUES (?1, ?2, ?3, ?4, ?5)";
const USERS_INC_SQL = "UPDATE dirmeta SET v = v + 1 WHERE k = 'users'";

const wrapEntry = (r: WrapRecord): Entry => ({ kind: DIRLOG_WRAP, ref: dirlogRefWrap(r.record, fromB64u(r.sig)) });

/**
 * POST /api/v2/register: body `{bundle, sig, wraps: [{record, sig}, …1..4]}` (§10.6). Checks the canonical
 * bundle, sizes, handle, bundleSig and checkUserKeys; for every record canonical form, sizes, uid = the
 * bundle's, recordSig under the bundle key, and distinct ids. Then writes the user, the wraps, their dirlog
 * entries (user first) and the dirmeta.users increment atomically. Returns the user's dirseq.
 */
export async function dirRegister(env: Env, body: Record<string, unknown>, nowMs: number): Promise<{ dirseq: number }> {
  const o = exactKeys(body, ["bundle", "sig", "wraps"], "register");
  const user = checkBundleShape(o.bundle, o.sig);
  const wraps = o.wraps;
  if (!Array.isArray(wraps) || wraps.length < 1 || wraps.length > MAX_WRAPS_PER_REGISTER) {
    throw new HttpError(400, `wraps: expected 1..${MAX_WRAPS_PER_REGISTER} wrap records`);
  }
  const ids = new Set<string>();
  const records = wraps.map((w: unknown, i): WrapRecord => {
    const wo = exactKeys(w, ["record", "sig"], `wraps[${i}]`);
    const rec = checkRecordShape(wo.record, wo.sig);
    if (rec.uid !== user.uid) throw new HttpError(400, `wraps[${i}]: uid does not match the bundle`);
    const id = enc64(rec.id);
    if (ids.has(id)) throw new HttpError(400, `wraps[${i}]: duplicate id`);
    ids.add(id);
    return rec;
  });

  const sigOk = await Promise.all([verifyBundleSig(user), ...records.map((r) => verifyRecordSig(r, user.sigPk))]);
  if (!sigOk[0]) throw new HttpError(400, "bad bundle signature");
  const badWrap = sigOk.indexOf(false, 1);
  if (badWrap > 0) throw new HttpError(400, `wraps[${badWrap - 1}]: bad signature`);
  // After the signatures (cheap, native): rejects a small-order signing key (which WebCrypto may accept with
  // a universal forgery) and a KEM key nobody could encapsulate to (§2.1).
  try {
    checkUserKeys(user.sigPk, user.kemPk);
  } catch (e) {
    throw new HttpError(400, `invalid bundle (${e instanceof Error ? e.message : "unusable keys"})`);
  }

  const regEra = era(nowMs);
  const uidHash = upre(fromB64u(user.uid));
  const handleHash = hpre(user.handle);
  const db = env.DB;
  const entries: Entry[] = [
    { kind: DIRLOG_USER, ref: dirlogRefUser(user.bundle, fromB64u(user.bundleSig)) },
    ...records.map(wrapEntry),
  ];
  const seqs = await appendDir(env, entries, {
    rows: (s) => [
      db
        .prepare(USER_INSERT_SQL)
        .bind(user.uid, uidHash, user.handle, handleHash, user.bundle, user.bundleSig, regEra, s[0]),
      ...records.map((r, i) => db.prepare(WRAP_INSERT_SQL).bind(r.uid, enc64(r.id), r.record, r.sig, s[1 + i])),
    ],
    tail: () => [db.prepare(USERS_INC_SQL)],
  });
  return { dirseq: seqs[0] };
}

/**
 * POST /api/v2/wraps: body `{record, sig}` (§10.6). 404 for an unknown uid, 400 for a bad signature or more
 * than 64 wraps for the uid, 409 for a duplicate (uid, id). Returns the record's dirseq.
 */
export async function dirAddWrap(env: Env, body: Record<string, unknown>): Promise<{ dirseq: number }> {
  const o = exactKeys(body, ["record", "sig"], "wrap");
  const rec = checkRecordShape(o.record, o.sig);
  const db = env.DB;
  const row = await d1("user read", () =>
    db.prepare("SELECT bundle, sig FROM user WHERE uid = ?1").bind(rec.uid).first<{ bundle: string; sig: string }>(),
  );
  if (!row) throw new HttpError(404, "unknown uid");
  const owner = parseBundle(row.bundle, row.sig); // validated at registration
  if (!(await verifyRecordSig(rec, owner.sigPk))) throw new HttpError(400, "bad wrap signature");

  const seqs = await appendDir(env, [wrapEntry(rec)], {
    reads: () => [db.prepare("SELECT count(*) AS n FROM wrap WHERE uid = ?1").bind(rec.uid)],
    check: ([count]) => {
      const n = (count.results as { n: number }[])[0]?.n ?? 0;
      if (n >= MAX_WRAPS_PER_UID) throw new HttpError(400, `too many wraps (at most ${MAX_WRAPS_PER_UID} per uid)`);
    },
    rows: (s) => [db.prepare(WRAP_INSERT_SQL).bind(rec.uid, enc64(rec.id), rec.record, rec.sig, s[0])],
  });
  return { dirseq: seqs[0] };
}

// ───────────── reads ─────────────

interface UserRow {
  uid: string;
  handle: string;
  bundle: string;
  sig: string;
  reg_era: number;
  dirseq: number;
}

const USER_COLS = "uid, handle, bundle, sig, reg_era, dirseq";
const toDirUser = (r: UserRow): DirUser => ({
  uid: r.uid,
  handle: r.handle,
  bundle: r.bundle,
  sig: r.sig,
  regEra: r.reg_era,
  dirseq: r.dirseq,
});

/**
 * The prefix query of §9.6 (exported for the query-plan test): ?1 = lo, ?2 = hi, ?3 = limit, ?4 = after.
 * It fetches PREFIX_PAGE + 1 rows to know whether there are `more`. A `wide` range is read with `+hpre`
 * (`+upre`), which keeps SQLite off the prefix index: it walks the uid primary key and filters by the prefix.
 */
export function prefixSql(kind: "h" | "u", paged: boolean, wide: boolean): string {
  const col = `${wide ? "+" : ""}${kind === "h" ? "hpre" : "upre"}`;
  return `SELECT ${USER_COLS} FROM user WHERE ${col} BETWEEN ?1 AND ?2${paged ? " AND uid > ?4" : ""} ORDER BY uid LIMIT ?3`;
}

/**
 * Plan choice for a prefix page (§9.6 fixes the query, not the plan). The index plan (user_hpre / user_upre)
 * reads every row of the range, about users / 2^p, and sorts them, for each page. Walking the uid key instead
 * reads about (PREFIX_PAGE + 1) · 2^p rows per page (one row in 2^p matches), and the whole rest of the table
 * when fewer rows match. So the walk is used for p = 0 and wherever it reads fewer rows:
 * users / 2^p > (PREFIX_PAGE + 1) · 2^p, i.e. users > 257 · 4^p. A page then reads at most about √(257 · users)
 * rows, instead of `users` for p = 0.
 */
export function widePrefix(users: number, p: number): boolean {
  return p === 0 || users / 2 ** p > (PREFIX_PAGE + 1) * 2 ** p;
}

/**
 * GET /api/v2/dir/{h|u}/{p}/{x}[?after=uid]: users whose hpre (or upre) has the top p bits equal to x, by
 * uid, at most 256 per page. 400 for a bad kind, p, x or after; PrefixBitsError (409 `{error, p: P}`) when
 * p > min(32, P + 1).
 */
export async function dirByPrefix(
  env: Env,
  kind: "h" | "u",
  p: number,
  x: number,
  after: string | null,
): Promise<{ p: number; users: DirUser[]; more: boolean }> {
  if (kind !== "h" && kind !== "u") throw new HttpError(400, "invalid prefix kind");
  if (!Number.isInteger(p) || p < 0 || p > 32) throw new HttpError(400, "invalid p");
  if (!Number.isInteger(x) || x < 0 || x >= 2 ** p) throw new HttpError(400, "invalid x");
  if (after !== null) checkUid(after, "after");
  const size = await dirSize(env);
  if (size === null) throw new HttpError(503, "directory unavailable"); // already logged by dirSize
  if (p > Math.min(32, size.P + 1)) throw new PrefixBitsError(size.P);
  const { lo, hi } = prefixRange(p, x);
  const wide = widePrefix(size.users, p);
  const { results } = await d1("prefix read", () =>
    (after === null
      ? env.DB.prepare(prefixSql(kind, false, wide)).bind(lo, hi, PREFIX_PAGE + 1)
      : env.DB.prepare(prefixSql(kind, true, wide)).bind(lo, hi, PREFIX_PAGE + 1, after)
    ).all<UserRow>(),
  );
  return { p, users: results.slice(0, PREFIX_PAGE).map(toDirUser), more: results.length > PREFIX_PAGE };
}

/** GET /api/v2/dir/uid/{uid}: null when unknown (→ 404); 400 for a malformed uid. */
export async function dirByUid(env: Env, uid: string): Promise<DirUser | null> {
  checkUid(uid, "uid");
  const row = await d1("uid read", () =>
    env.DB.prepare(`SELECT ${USER_COLS} FROM user WHERE uid = ?1`).bind(uid).first<UserRow>(),
  );
  return row ? toDirUser(row) : null;
}

/**
 * GET /api/v2/dir/wraps/{id}[?uid=]: at most 64, oldest (lowest dirseq) first; [] for an unknown id. 400 for an
 * id that is not 1..1023 canonical b64u bytes or a uid that is not 16.
 */
export async function dirWrapsById(env: Env, id: string, uid: string | null): Promise<DirWrap[]> {
  checkWrapId(id);
  if (uid !== null) checkUid(uid, "uid");
  const where = uid === null ? "id = ?1" : "id = ?1 AND uid = ?3";
  const sql = `SELECT uid, record, sig, dirseq FROM wrap WHERE ${where} ORDER BY dirseq LIMIT ?2`;
  const { results } = await d1("wraps read", () => {
    const stmt = env.DB.prepare(sql);
    return (uid === null ? stmt.bind(id, MAX_WRAPS_PER_ID) : stmt.bind(id, MAX_WRAPS_PER_ID, uid)).all<DirWrap>();
  });
  return results.map((r) => ({ uid: r.uid, record: r.record, sig: r.sig, dirseq: r.dirseq }));
}

const emptyHead = (): { seq: number; h: string } => ({ seq: 0, h: enc64(ZERO32) });

/**
 * GET /api/v2/dirlog?after=&limit=: entries with seq > after, ascending, at most `limit` (1..1000), plus the
 * head (`{seq: 0, h: b64u(ZERO32)}` while the log is empty), read in one snapshot. 400 for bad parameters.
 */
export async function dirlogPage(
  env: Env,
  after: number,
  limit: number,
): Promise<{ entries: DirlogEntry[]; head: { seq: number; h: string } }> {
  if (!Number.isSafeInteger(after) || after < 0) throw new HttpError(400, "invalid after");
  if (!Number.isInteger(limit) || limit < 1 || limit > DIRLOG_PAGE_MAX) throw new HttpError(400, "invalid limit");
  const db = env.DB;
  const [page, head] = await d1("dirlog read", () =>
    db.batch([
      db.prepare("SELECT seq, kind, ref, h FROM dirlog WHERE seq > ?1 ORDER BY seq LIMIT ?2").bind(after, limit),
      db.prepare(HEAD_SQL),
    ]),
  );
  const entries = (page.results as DirlogEntry[]).map((r) => ({ seq: r.seq, kind: r.kind, ref: r.ref, h: r.h }));
  const h = (head.results as { seq: number; h: string }[])[0];
  return { entries, head: h ? { seq: h.seq, h: h.h } : emptyHead() };
}

/** The dirlog head `{seq, h}` (b64u h; `{0, b64u(ZERO32)}` while empty), e.g. for the CheckpointDO (§9.5). */
export async function dirlogHead(env: Env): Promise<{ seq: number; h: string }> {
  const row = await d1("head read", () => env.DB.prepare(HEAD_SQL).first<{ seq: number; h: string }>());
  return row ? { seq: row.seq, h: row.h } : emptyHead();
}

/** The last good dirmeta read (kept past `until` as the fallback while D1 fails). */
let pCache: { users: number; P: number; until: number } | null = null;
/** No dirmeta read before this time (set by a failed read). */
let pRetryAt = 0;

/** Test-only: forgets the cached P and any back-off. */
export function _resetDirectoryCacheForTests(): void {
  pCache = null;
  pRetryAt = 0;
}

/**
 * dirmeta.users and P = max(0, ⌊log2(users / 32)⌋) (never count(*)), cached ~60 s per isolate. When the read
 * fails, the failure is logged once, D1 is not asked again for P_RETRY_MS, and meanwhile the last good value is
 * served: null while there is none. /api/v2/params is not rate limited (§10.2), so a D1 outage must not turn it
 * into one D1 query and one log line per request.
 */
async function dirSize(env: Env): Promise<{ users: number; P: number } | null> {
  const now = Date.now();
  if (pCache !== null && now < pCache.until) return pCache;
  if (now < pRetryAt) return pCache;
  try {
    const row = await env.DB.prepare("SELECT v FROM dirmeta WHERE k = 'users'").first<{ v: number }>();
    const users = row?.v ?? 0;
    pCache = { users, P: serverP(users), until: now + P_CACHE_MS };
    return pCache;
  } catch (e) {
    const t = Date.now();
    // Concurrent reads that fail together log once: the first one starts the back-off.
    if (t >= pRetryAt) {
      pRetryAt = t + P_RETRY_MS;
      logFailure("dirmeta read", e);
    }
    return pCache;
  }
}

/**
 * P as /api/v2/params reports it (§10.9). Never throws: while D1 fails it is the last good P, or 0 if there is
 * none, and D1 is asked again only after P_RETRY_MS (see dirSize). Prefix lookups answer 503 instead of using 0.
 */
export async function currentP(env: Env): Promise<number> {
  return (await dirSize(env))?.P ?? 0;
}
