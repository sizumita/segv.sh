/**
 * The v2 directory in D1 (docs/PROTOCOL.md §2.4–§2.5, §9.6, §10.6).
 *
 * Contract used by the HTTP layer (packages/server/src/api.ts). Every function throws HttpError with the status
 * of §10.1 (400 malformed, 404 unknown, 409 conflict / prefix bits out of range, 503 D1 unavailable).
 * Request bodies arrive already size-checked, proof-of-work-checked and JSON-parsed.
 *
 * The 409 for prefix bits out of range is a `PrefixBitsError` (a subclass of HttpError) whose `extra` holds
 * the fields to merge into the error JSON: the HTTP layer answers `{error: e.message, ...e.extra}`, i.e.
 * `{error, p: P}` (§10.6).
 *
 * D1 is authoritative: there is no outbox and no log fallback beyond the DirSeqDO's write-ahead log. The directory is
 * one log database (dirlog, dirmeta) and K user databases (user, wrap), a user's rows in the database of the top bits
 * of its upre (§9.6). Every write goes through the DirSeqDO (dirseq-do.ts), the only writer, which appends to the
 * hash-chained `dirlog` with contiguous seqs in one atomic batch per round of writes and then writes the rows; reads
 * go to D1 from here, asking every user database and merging the answers, so a lookup never depends on where a row
 * is.
 */
import {
  MAX_ID_LEN,
  ZERO32,
  checkUserKeys,
  era,
  fromB64u,
  hpre,
  parseBundle,
  prefixRange,
  serverP,
  upre,
  type WrapRecord,
} from "@segv/protocol/proto";
import { b64Len, dec64, enc64 } from "./b64";
import { logDb, userDbs } from "./env";
import { HttpError, exactKeys, logErr } from "./http";
import { dirSeqStub, type DirWrite, type DirWriteResult } from "./types";
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

/** The 409 of each UNIQUE key a directory write can hit (§9.6); the DirSeqDO maps D1's failures through it. */
export const CONFLICTS: Readonly<Record<string, string>> = {
  "user.handle": "handle already taken",
  "user.uid": "uid already registered",
  "wrap.uid": "duplicate wrap record",
  "wrap.id": "duplicate wrap record",
};

export const HEAD_SQL = "SELECT seq, h FROM dirlog ORDER BY seq DESC LIMIT 1";

/**
 * §9.6 writes: the DirSeqDO appends the write to the dirlog in one atomic D1 batch (with every other write of its
 * round). A refusal (400 over the wrap cap, 409 on a taken handle, uid or wrap) comes back as a result; a failure of
 * the object or of D1 is 503 "directory unavailable".
 */
async function dirWrite(env: Env, write: DirWrite): Promise<number[]> {
  let r: DirWriteResult;
  try {
    r = (await dirSeqStub(env).append(write)) as DirWriteResult;
  } catch (e) {
    throw unavailable("write", e);
  }
  if (!r.ok) throw new HttpError(r.status, r.error);
  return r.seqs;
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

  const seqs = await dirWrite(env, {
    kind: "user",
    uid: user.uid,
    upre: upre(fromB64u(user.uid)),
    handle: user.handle,
    hpre: hpre(user.handle),
    bundle: user.bundle,
    sig: user.bundleSig,
    regEra: era(nowMs),
    wraps: records.map((r) => ({ uid: r.uid, id: enc64(r.id), record: r.record, sig: r.sig })),
  });
  return { dirseq: seqs[0] };
}

/**
 * POST /api/v2/wraps: body `{record, sig}` (§10.6). 404 for an unknown uid, 400 for a bad signature or more
 * than 64 wraps for the uid (the DirSeqDO counts them, §9.6), 409 for a duplicate (uid, id). Returns the record's
 * dirseq.
 */
export async function dirAddWrap(env: Env, body: Record<string, unknown>): Promise<{ dirseq: number }> {
  const o = exactKeys(body, ["record", "sig"], "wrap");
  const rec = checkRecordShape(o.record, o.sig);
  const row = await d1("user read", () => userByUid(env, rec.uid));
  if (!row) throw new HttpError(404, "unknown uid");
  const owner = parseBundle(row.bundle, row.sig); // validated at registration
  if (!(await verifyRecordSig(rec, owner.sigPk))) throw new HttpError(400, "bad wrap signature");

  const seqs = await dirWrite(env, { kind: "wrap", wrap: { uid: rec.uid, id: enc64(rec.id), record: rec.record, sig: rec.sig } });
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

/** The user row of `uid` from whichever user database has it (§9.6 "Reads"), or null. */
async function userByUid(env: Env, uid: string): Promise<UserRow | null> {
  const rows = await Promise.all(
    userDbs(env).map((db) => db.prepare(`SELECT ${USER_COLS} FROM user WHERE uid = ?1`).bind(uid).first<UserRow>()),
  );
  return rows.find((r) => r !== null) ?? null;
}

/** Byte order of b64u uid text (ASCII, so JavaScript's string order is the SQLite BINARY order). */
const byUid = (a: { uid: string }, b: { uid: string }): number => (a.uid < b.uid ? -1 : a.uid > b.uid ? 1 : 0);

/**
 * The pages of every user database merged in uid order, a uid listed twice (a row in its old and its new database
 * while a raise of K moves it, §9.6) once. Each page holds a database's first rows after `after`, so the first n
 * rows of the merge are the first n of the union whenever every page has at least n rows or is complete.
 */
export function mergeByUid<T extends { uid: string }>(pages: T[][]): T[] {
  const out: T[] = [];
  for (const r of pages.flat().sort(byUid)) {
    if (out.length === 0 || out[out.length - 1].uid !== r.uid) out.push(r);
  }
  return out;
}

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
  const dbs = userDbs(env);
  const wide = widePrefix(size.users / dbs.length, p); // each database holds about users / K rows
  const sql = prefixSql(kind, after !== null, wide);
  const pages = await d1("prefix read", () =>
    Promise.all(
      dbs.map((db) =>
        (after === null
          ? db.prepare(sql).bind(lo, hi, PREFIX_PAGE + 1)
          : db.prepare(sql).bind(lo, hi, PREFIX_PAGE + 1, after)
        ).all<UserRow>(),
      ),
    ),
  );
  const rows = mergeByUid(pages.map((pg) => pg.results));
  return { p, users: rows.slice(0, PREFIX_PAGE).map(toDirUser), more: rows.length > PREFIX_PAGE };
}

/** GET /api/v2/dir/uid/{uid}: null when unknown (→ 404); 400 for a malformed uid. */
export async function dirByUid(env: Env, uid: string): Promise<DirUser | null> {
  checkUid(uid, "uid");
  const row = await d1("uid read", () => userByUid(env, uid));
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
  const pages = await d1("wraps read", () =>
    Promise.all(
      userDbs(env).map((db) => {
        const stmt = db.prepare(sql);
        return (uid === null ? stmt.bind(id, MAX_WRAPS_PER_ID) : stmt.bind(id, MAX_WRAPS_PER_ID, uid)).all<DirWrap>();
      }),
    ),
  );
  // Merged by dirseq; a record in two databases (while a raise of K moves its uid, §9.6) once.
  const seen = new Set<number>();
  const out: DirWrap[] = [];
  for (const r of pages.flatMap((pg) => pg.results).sort((a, b) => a.dirseq - b.dirseq)) {
    if (seen.has(r.dirseq)) continue;
    seen.add(r.dirseq);
    out.push({ uid: r.uid, record: r.record, sig: r.sig, dirseq: r.dirseq });
  }
  return out.slice(0, MAX_WRAPS_PER_ID);
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
  const db = logDb(env);
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
  const row = await d1("head read", () => logDb(env).prepare(HEAD_SQL).first<{ seq: number; h: string }>());
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
    const row = await logDb(env).prepare("SELECT v FROM dirmeta WHERE k = 'users'").first<{ v: number }>();
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
