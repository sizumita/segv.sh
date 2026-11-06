/**
 * DirSeqDO — the only writer of the directory (docs/PROTOCOL.md §9.6). One instance, "dirseq/v2", SQLite.
 *
 * The Worker validates a registration or a wrap record (§10.6) and hands it here. The object keeps the dirlog head in
 * memory (read from the log database at start, and again after any failed write) and writes in rounds: every write
 * that arrived since the previous round started, at most ROUND_MAX. A round replays the write-ahead log; reads, from
 * every user database, the registered handles and uids and the wrap rows of its writes' uids (nothing else writes,
 * so what it read holds until it writes) and refuses the writes that conflict (409 / 400); then it assigns contiguous
 * seqs, computes the chain, keeps the round in its write-ahead log, appends the dirlog entries in one atomic batch
 * on the log database, and writes each user database's rows in one atomic batch. Rows whose batch failed stay in the
 * write-ahead log and land at the next replay (the next round, or an alarm), so the dirlog never stays ahead of the
 * user databases, and no row lands without its entries. A DIR_SHARDS above the pinned one places new rows by the new
 * value at once and starts a move of the rows that are no longer in their database, a page per alarm ("Raising K").
 * Rounds, the alarm's replays and the move's pages run one at a time (`exclusive`): an await on D1 lets the alarm in,
 * and a replay must never judge a round whose log batch is in flight, nor a page delete a row a replay just landed.
 * D1 stays authoritative: the storage here holds the write-ahead log, the pinned κ and the move's cursors.
 */
import { DurableObject } from "cloudflare:workers";
import { DIRLOG_USER, DIRLOG_WRAP, ZERO32, dirlogH, dirlogRefUser, dirlogRefWrap, fromB64u, upre, type Bytes } from "@segv/protocol/proto";
import { dec64, enc64 } from "./b64";
import { Meta } from "./batch";
import { CONFLICTS, HEAD_SQL, MAX_WRAPS_PER_UID, uniqueFailure } from "./directory";
import { dirBitsOf, dirShardOf, logDb, userDb, userDbs, v2Params } from "./env";
import { logErr } from "./http";
import type { DirUserWrite, DirWrite, DirWriteResult } from "./types";

/** Writes per round: the round's handles and uids fit one query (D1 binds at most 100 parameters). */
export const ROUND_MAX = 32;
/** Users per page of a move (§9.6 "Raising K"). */
export const MOVE_PAGE = 32;
/** The replay after a failed user-database batch, and then while rows wait (§9.6). */
export const REPLAY_FIRST_MS = 1_000;
export const REPLAY_MS = 5_000;
/** The next page of a move. */
export const MOVE_TICK_MS = 100;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS wal (
  seq INTEGER PRIMARY KEY, last INTEGER NOT NULL, h TEXT NOT NULL, d INTEGER NOT NULL, w TEXT NOT NULL,
  ok INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS mv (s INTEGER PRIMARY KEY, cursor TEXT NOT NULL, done INTEGER NOT NULL);
`;

const USER_COLS = "uid, upre, handle, hpre, bundle, sig, reg_era, dirseq";
const USER_INSERT_SQL = `INSERT INTO user (${USER_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`;
const USER_COPY_SQL = `INSERT OR IGNORE INTO user (${USER_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`;
const WRAP_INSERT_SQL = "INSERT INTO wrap (uid, id, record, sig, dirseq) VALUES (?1, ?2, ?3, ?4, ?5)";
const WRAP_COPY_SQL = "INSERT OR IGNORE INTO wrap (uid, id, record, sig, dirseq) VALUES (?1, ?2, ?3, ?4, ?5)";
const DIRLOG_INSERT_SQL = "INSERT INTO dirlog (seq, kind, ref, h) VALUES (?1, ?2, ?3, ?4)";
const USERS_INC_SQL = "UPDATE dirmeta SET v = v + 1 WHERE k = 'users'";

const UNAVAILABLE: DirWriteResult = { ok: false, status: 503, error: "directory unavailable" };
const MISCONFIGURED: DirWriteResult = { ok: false, status: 503, error: "directory misconfigured" };

interface Pending {
  write: DirWrite;
  resolve: (r: DirWriteResult) => void;
  reject: (e: unknown) => void;
}
interface Head {
  seq: number;
  h: Bytes;
}
/** A write in the write-ahead log: its seqs (the user's first, then its wraps) and its user database. */
interface WalRow {
  seq: number;
  last: number;
  h: string;
  d: number;
  write: DirWrite;
  seqs: number[];
  ok: boolean;
}
/** A write of the round that passed the checks, with its database. */
interface Live {
  p: Pending;
  d: number;
}
interface UserRow {
  uid: string;
  upre: number;
  handle: string;
  hpre: number;
  bundle: string;
  sig: string;
  reg_era: number;
  dirseq: number;
}
interface WrapRow {
  uid: string;
  id: string;
  record: string;
  sig: string;
  dirseq: number;
}
/** A registered user as the round's checks read it. */
interface TakenUser {
  uid: string;
  handle: string;
  bundle: string;
  sig: string;
  dirseq: number;
}
/** What became of a write's rows: landed, lost to another writer's row (its UNIQUE key), or the database is down. */
type Outcome = "landed" | "down" | { col: string };

const isStr = (x: unknown): x is string => typeof x === "string";
const marks = (n: number): string => Array.from({ length: n }, () => "?").join(", ");
const logLine = (msg: string, extra: Record<string, unknown> = {}): void =>
  console.error(JSON.stringify({ msg: `dirseq: ${msg}`, ...extra }));

function checkWrite(w: unknown): asserts w is DirWrite {
  const bad = (): never => {
    throw new TypeError("dirseq: malformed write");
  };
  if (typeof w !== "object" || w === null) bad();
  const o = w as Record<string, unknown>;
  const wrapOk = (x: unknown): boolean =>
    typeof x === "object" && x !== null && ["uid", "id", "record", "sig"].every((k) => isStr((x as Record<string, unknown>)[k]));
  if (o.kind === "wrap") {
    if (!wrapOk(o.wrap)) bad();
    return;
  }
  if (o.kind !== "user") bad();
  if (!isStr(o.uid) || !isStr(o.handle) || !isStr(o.bundle) || !isStr(o.sig)) bad();
  if (!Number.isInteger(o.upre) || !Number.isInteger(o.hpre) || !Number.isInteger(o.regEra)) bad();
  // An alias registers without wraps (§2.6); the Worker checked which registrations may (§10.6).
  if (!Array.isArray(o.wraps) || !o.wraps.every(wrapOk)) bad();
}

/** The dirlog entries of a write, in order (§9.6: a user's entry, then its wraps'; a wrap's entry). */
function entriesOf(w: DirWrite): { kind: number; ref: Bytes }[] {
  return w.kind === "user"
    ? [
        { kind: DIRLOG_USER, ref: dirlogRefUser(w.bundle, fromB64u(w.sig)) },
        ...w.wraps.map((x) => ({ kind: DIRLOG_WRAP, ref: dirlogRefWrap(x.record, fromB64u(x.sig)) })),
      ]
    : [{ kind: DIRLOG_WRAP, ref: dirlogRefWrap(w.wrap.record, fromB64u(w.wrap.sig)) }];
}

/** Whether two registrations carry the same body: bundle, signature and wrap records, in order (§9.6 step 2). */
const sameRegistration = (a: DirUserWrite, b: DirUserWrite): boolean =>
  a.uid === b.uid &&
  a.handle === b.handle &&
  a.bundle === b.bundle &&
  a.sig === b.sig &&
  a.wraps.length === b.wraps.length &&
  a.wraps.every((x, i) => {
    const y = b.wraps[i];
    return x.uid === y.uid && x.id === y.id && x.record === y.record && x.sig === y.sig;
  });

/** The user database of a write under K = 2^bits (§9.6): a wrap goes with its uid's row. */
const databaseOf = (w: DirWrite, bits: number): number =>
  dirShardOf(w.kind === "user" ? w.upre : upre(fromB64u(w.wrap.uid)), bits);

export class DirSeqDO extends DurableObject<Env> {
  private readonly sql: SqlStorage;
  private readonly meta: Meta;
  private queue: Pending[] = [];
  private flushing: Promise<void> | null = null;
  /** The tail of the rounds, replays and move pages: each starts when the previous one has finished. */
  private turn: Promise<void> = Promise.resolve();
  /** The dirlog head, or null when it must be read from the log database before the next round. */
  private head: Head | null = null;
  private misconfiguredLogged = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(SCHEMA);
    this.meta = new Meta(this.sql);
  }

  /** Writes `write` after everything queued before it; resolves with its seqs, or the refusal (400 / 409 / 503). */
  append(write: DirWrite): Promise<DirWriteResult> {
    checkWrite(write);
    return new Promise<DirWriteResult>((resolve, reject) => {
      this.queue.push({ write, resolve, reject });
      this.kick();
    });
  }

  /** Replays the write-ahead log and moves a page of rows while a raise of K runs (§9.6), between rounds. */
  async alarm(): Promise<void> {
    await this.exclusive(async () => {
      const bits = this.placement();
      await this.replay(bits);
      if (bits !== null && (await this.moveStep())) await this.armAlarm(MOVE_TICK_MS);
    });
  }

  /** Runs `f` once every round, replay and move page started before it has finished. */
  private exclusive(f: () => Promise<void>): Promise<void> {
    const run = this.turn.then(f);
    this.turn = run.catch(() => {});
    return run;
  }

  private kick(): void {
    if (this.flushing) return;
    this.flushing = this.flushLoop().finally(() => {
      this.flushing = null;
      if (this.queue.length > 0) this.kick();
    });
  }

  private async flushLoop(): Promise<void> {
    while (this.queue.length > 0) {
      await this.exclusive(async () => {
        // Taken when the round's turn comes: the writes that arrived while an alarm ran go with it.
        const round = this.queue.splice(0, ROUND_MAX);
        try {
          await this.runRound(round, true);
        } catch (e) {
          // Nothing in runRound throws past its own handlers except a broken binding: fail the round, never wedge it.
          this.head = null;
          for (const p of round) p.reject(e);
        }
      });
    }
  }

  private async readHead(): Promise<Head> {
    const row = await logDb(this.env).prepare(HEAD_SQL).first<{ seq: number; h: string }>();
    return row ? { seq: row.seq, h: dec64(row.h) } : { seq: 0, h: ZERO32 };
  }

  // ───────────── a round ─────────────

  /** Every pending write of `round`: the checks, the log batch, the rows (see the file comment for the failures). */
  private async runRound(round: Pending[], retryOnSeq: boolean): Promise<void> {
    const bits = this.placement();
    if (bits === null) {
      for (const p of round) p.resolve(MISCONFIGURED);
      return;
    }
    const down = await this.replay(bits);
    let head: Head;
    try {
      head = this.head ?? (this.head = await this.readHead());
    } catch (e) {
      for (const p of round) p.reject(e);
      return;
    }
    const live = await this.screen(round, bits, down);
    if (live.length === 0) return;

    // Contiguous seqs after the head and the chain; the round goes to the write-ahead log before the dirlog.
    let seq = head.seq;
    let prev = head.h;
    const items = live.map(({ p, d }) => {
      const entries = entriesOf(p.write);
      const seqs: number[] = [];
      const hs: Bytes[] = [];
      for (const en of entries) {
        seq++;
        prev = dirlogH(prev, seq, en.kind, en.ref);
        seqs.push(seq);
        hs.push(prev);
      }
      return { p, d, entries, seqs, hs };
    });
    this.ctx.storage.transactionSync(() => {
      for (const it of items) {
        this.sql.exec(
          "INSERT INTO wal (seq, last, h, d, w, ok) VALUES (?, ?, ?, ?, ?, 0)",
          it.seqs[0],
          it.seqs[it.seqs.length - 1],
          enc64(it.hs[it.hs.length - 1]),
          it.d,
          JSON.stringify({ write: it.p.write, seqs: it.seqs }),
        );
      }
    });
    const log = logDb(this.env);
    const stmts: D1PreparedStatement[] = [];
    for (const it of items) {
      it.entries.forEach((en, i) => stmts.push(log.prepare(DIRLOG_INSERT_SQL).bind(it.seqs[i], en.kind, enc64(en.ref), enc64(it.hs[i]))));
      if (it.p.write.kind === "user") stmts.push(log.prepare(USERS_INC_SQL));
    }
    try {
      await log.batch(stmts);
    } catch (e) {
      this.head = null;
      if (uniqueFailure(e) === "dirlog.seq") {
        // Another writer moved the head (a Worker of the previous release, during a deploy): once more on the new one.
        this.dropWal(items.map((it) => it.seqs[0]));
        if (retryOnSeq) {
          logLine("the dirlog head moved under the writer; retrying once");
          return this.runRound(
            live.map((l) => l.p),
            false,
          );
        }
        for (const it of items) it.p.resolve(UNAVAILABLE);
        return;
      }
      // The batch may still have committed: the round is in the log iff the entry at its last seq carries its h.
      const logged = await this.confirm(seq, enc64(prev));
      if (logged !== true) {
        logLine("dirlog write failed", { error: logErr(e), logged: logged === false ? "no" : "unknown" });
        if (logged === false) this.dropWal(items.map((it) => it.seqs[0]));
        else await this.armAlarm(REPLAY_FIRST_MS);
        for (const it of items) it.p.resolve(UNAVAILABLE);
        return;
      }
    }
    this.head = { seq, h: prev };
    this.sql.exec(`UPDATE wal SET ok = 1 WHERE seq IN (${marks(items.length)})`, ...items.map((it) => it.seqs[0]));

    // The rows, one atomic batch per user database; a failed batch is tried once more at once.
    const byDb = new Map<number, typeof items>();
    for (const it of items) byDb.set(it.d, [...(byDb.get(it.d) ?? []), it]);
    let anyDown = false;
    await Promise.all(
      [...byDb].map(async ([d, its]) => {
        const rows = its.map((it) => ({ seq: it.seqs[0], write: it.p.write, seqs: it.seqs }));
        let res = await this.land(d, rows);
        if ([...res.values()].includes("down")) res = await this.land(d, rows);
        for (const it of its) {
          const r = res.get(it.seqs[0])!;
          if (r === "landed") it.p.resolve({ ok: true, seqs: it.seqs });
          else if (r === "down") {
            anyDown = true;
            it.p.resolve(UNAVAILABLE);
          } else it.p.resolve({ ok: false, status: 409, error: CONFLICTS[r.col] });
        }
      }),
    );
    if (anyDown) await this.armAlarm(REPLAY_FIRST_MS);
  }

  /**
   * The round's writes against what the user databases hold (every database: a row may be anywhere), the rows still
   * in the write-ahead log, and the round's earlier writes: 409 for a registered handle or uid and for an existing
   * (uid, id), 400 above the cap of wraps per uid, 503 for a database that is down. A registration whose body is that
   * of a registration already logged (in the write-ahead log, or landed with all its wrap rows) is that registration
   * sent again: it answers as that one did, with its seqs, and writes nothing (503 while that one's outcome is still
   * unknown). Returns the writes that remain, each with its database.
   */
  private async screen(round: Pending[], bits: number, down: Set<number>): Promise<Live[]> {
    const handles = new Set<string>();
    const uids = new Set<string>();
    const wrapUids = new Set<string>();
    for (const { write: w } of round) {
      if (w.kind === "user") {
        handles.add(w.handle);
        uids.add(w.uid);
      } else wrapUids.add(w.wrap.uid);
    }
    const takenHandles = new Set<string>();
    const takenUids = new Set<string>();
    /** The registered users of the round's handles and uids, and the wrap rows of its registrations' uids. */
    const users = new Map<string, TakenUser>();
    const userWraps = new Map<string, WrapRow>();
    const wraps = new Map<string, Set<string>>();
    const addWrap = (uid: string, id: string): void => {
      let ids = wraps.get(uid);
      if (!ids) wraps.set(uid, (ids = new Set()));
      ids.add(id);
    };
    try {
      await Promise.all(
        userDbs(this.env).map(async (db) => {
          const stmts: D1PreparedStatement[] = [];
          if (uids.size > 0) {
            stmts.push(
              db
                .prepare(
                  `SELECT uid, handle, bundle, sig, dirseq FROM user WHERE handle IN (${marks(handles.size)}) OR uid IN (${marks(uids.size)})`,
                )
                .bind(...handles, ...uids),
            );
          }
          if (wrapUids.size > 0) stmts.push(db.prepare(`SELECT uid, id FROM wrap WHERE uid IN (${marks(wrapUids.size)})`).bind(...wrapUids));
          if (stmts.length === 0) return;
          const res = await db.batch(stmts);
          if (uids.size > 0) {
            for (const r of res.shift()!.results as TakenUser[]) {
              takenHandles.add(r.handle);
              takenUids.add(r.uid);
              users.set(r.uid, r);
            }
          }
          if (wrapUids.size > 0) for (const r of res.shift()!.results as { uid: string; id: string }[]) addWrap(r.uid, r.id);
        }),
      );
      // A registration whose user row is registered with its very bundle may be the same registration sent again:
      // its wrap rows decide (only then are they read).
      const again = [
        ...new Set(
          round.flatMap(({ write: w }) => {
            const u = w.kind === "user" ? users.get(w.uid) : undefined;
            return w.kind === "user" && u && u.handle === w.handle && u.bundle === w.bundle && u.sig === w.sig ? [w.uid] : [];
          }),
        ),
      ];
      if (again.length > 0) {
        const pages = await Promise.all(
          userDbs(this.env).map((db) =>
            db.prepare(`SELECT uid, id, record, sig, dirseq FROM wrap WHERE uid IN (${marks(again.length)})`).bind(...again).all<WrapRow>(),
          ),
        );
        for (const pg of pages) for (const r of pg.results) userWraps.set(`${r.uid}\n${r.id}`, r);
      }
    } catch (e) {
      logLine("directory read failed", { error: logErr(e) });
      for (const p of round) p.resolve(UNAVAILABLE);
      return [];
    }
    const wal = this.walRows();
    /** The seqs of the logged registration that `w` sends again, "unknown" while its log batch's outcome is, or null. */
    const sentAgain = (w: DirUserWrite): number[] | "unknown" | null => {
      for (const r of wal) {
        if (r.write.kind === "user" && sameRegistration(r.write, w)) return r.ok ? r.seqs : "unknown";
      }
      const u = users.get(w.uid);
      if (!u || u.handle !== w.handle || u.bundle !== w.bundle || u.sig !== w.sig) return null;
      const seqs = [u.dirseq];
      for (const x of w.wraps) {
        const row = userWraps.get(`${x.uid}\n${x.id}`);
        if (!row || row.record !== x.record || row.sig !== x.sig) return null;
        seqs.push(row.dirseq);
      }
      return seqs;
    };
    for (const { write: w } of wal) {
      if (w.kind === "user") {
        takenHandles.add(w.handle);
        takenUids.add(w.uid);
        for (const x of w.wraps) addWrap(x.uid, x.id);
      } else addWrap(w.wrap.uid, w.wrap.id);
    }
    const live: Live[] = [];
    for (const p of round) {
      const w = p.write;
      if (w.kind === "user") {
        if (takenHandles.has(w.handle) || takenUids.has(w.uid)) {
          const seqs = sentAgain(w);
          if (seqs === "unknown") {
            p.resolve(UNAVAILABLE);
            continue;
          }
          if (seqs !== null) {
            p.resolve({ ok: true, seqs });
            continue;
          }
        }
        if (takenHandles.has(w.handle)) {
          p.resolve({ ok: false, status: 409, error: CONFLICTS["user.handle"] });
          continue;
        }
        if (takenUids.has(w.uid)) {
          p.resolve({ ok: false, status: 409, error: CONFLICTS["user.uid"] });
          continue;
        }
      } else {
        const ids = wraps.get(w.wrap.uid);
        if (ids && ids.size >= MAX_WRAPS_PER_UID) {
          p.resolve({ ok: false, status: 400, error: `too many wraps (at most ${MAX_WRAPS_PER_UID} per uid)` });
          continue;
        }
        if (ids?.has(w.wrap.id)) {
          p.resolve({ ok: false, status: 409, error: CONFLICTS["wrap.uid"] });
          continue;
        }
      }
      const d = databaseOf(w, bits);
      if (down.has(d)) {
        p.resolve(UNAVAILABLE);
        continue;
      }
      if (w.kind === "user") {
        takenHandles.add(w.handle);
        takenUids.add(w.uid);
        for (const x of w.wraps) addWrap(x.uid, x.id);
      } else addWrap(w.wrap.uid, w.wrap.id);
      live.push({ p, d });
    }
    return live;
  }

  /** Whether the dirlog entry at `last` carries `h` (the round committed); null when the log database did not answer. */
  private async confirm(last: number, h: string): Promise<boolean | null> {
    try {
      const row = await logDb(this.env).prepare("SELECT h FROM dirlog WHERE seq = ?1").bind(last).first<{ h: string }>();
      return row !== null && row.h === h;
    } catch {
      return null;
    }
  }

  // ───────────── the rows and the write-ahead log ─────────────

  private rowStmts(db: D1Database, w: DirWrite, seqs: number[]): D1PreparedStatement[] {
    if (w.kind === "user") {
      return [
        db.prepare(USER_INSERT_SQL).bind(w.uid, w.upre, w.handle, w.hpre, w.bundle, w.sig, w.regEra, seqs[0]),
        ...w.wraps.map((x, i) => db.prepare(WRAP_INSERT_SQL).bind(x.uid, x.id, x.record, x.sig, seqs[1 + i])),
      ];
    }
    return [db.prepare(WRAP_INSERT_SQL).bind(w.wrap.uid, w.wrap.id, w.wrap.record, w.wrap.sig, seqs[0])];
  }

  /** Whether the row that a UNIQUE failure met is the write's own (a replay of a batch that had landed). */
  private async ownRow(db: D1Database, w: DirWrite): Promise<boolean> {
    if (w.kind === "user") {
      const row = await db.prepare("SELECT bundle FROM user WHERE uid = ?1").bind(w.uid).first<{ bundle: string }>();
      return row !== null && row.bundle === w.bundle;
    }
    const row = await db
      .prepare("SELECT record FROM wrap WHERE uid = ?1 AND id = ?2")
      .bind(w.wrap.uid, w.wrap.id)
      .first<{ record: string }>();
    return row !== null && row.record === w.wrap.record;
  }

  /**
   * Writes the rows of `rows` (writes logged already) to user database d in one atomic batch, and drops the ones that
   * landed or can never land from the write-ahead log. On a UNIQUE failure with several rows, each is written alone;
   * one row's UNIQUE failure is its own row (landed) or another writer's (lost: a deploy's race, §9.6).
   */
  private async land(d: number, rows: { seq: number; write: DirWrite; seqs: number[] }[]): Promise<Map<number, Outcome>> {
    const out = new Map<number, Outcome>();
    let db: D1Database;
    try {
      db = userDb(this.env, d);
    } catch (e) {
      logLine("user database missing", { error: logErr(e) });
      for (const r of rows) out.set(r.seq, "down");
      return out;
    }
    try {
      await db.batch(rows.flatMap((r) => this.rowStmts(db, r.write, r.seqs)));
      for (const r of rows) out.set(r.seq, "landed");
      this.dropWal(rows.map((r) => r.seq));
      return out;
    } catch (e) {
      const col = uniqueFailure(e);
      if (col === null || !CONFLICTS[col]) {
        logLine("user database write failed", { error: logErr(e) });
        for (const r of rows) out.set(r.seq, "down");
        return out;
      }
      if (rows.length > 1) {
        for (const r of rows) for (const [k, v] of await this.land(d, [r])) out.set(k, v);
        return out;
      }
      const r = rows[0];
      let ours: boolean;
      try {
        ours = await this.ownRow(db, r.write);
      } catch (e2) {
        logLine("user database read failed", { error: logErr(e2) });
        out.set(r.seq, "down");
        return out;
      }
      if (!ours) logLine("a logged write lost its row to another writer", { key: col });
      out.set(r.seq, ours ? "landed" : { col });
      this.dropWal([r.seq]);
      return out;
    }
  }

  private walRows(): WalRow[] {
    return this.sql
      .exec<{ seq: number; last: number; h: string; d: number; w: string; ok: number }>("SELECT * FROM wal ORDER BY seq")
      .toArray()
      .map((r) => {
        const { write, seqs } = JSON.parse(r.w) as { write: DirWrite; seqs: number[] };
        return { seq: r.seq, last: r.last, h: r.h, d: r.d, write, seqs, ok: r.ok === 1 };
      });
  }

  private dropWal(seqs: number[]): void {
    if (seqs.length > 0) this.sql.exec(`DELETE FROM wal WHERE seq IN (${marks(seqs.length)})`, ...seqs);
  }

  /**
   * Lands the rows of the write-ahead log, per user database, oldest first (§9.6). A row whose log batch's outcome
   * is unknown lands only once the dirlog confirms it, and is dropped once the dirlog refutes it. Runs only between
   * rounds (inside `exclusive`), so no row it judges belongs to a log batch in flight. A row lands in the database of
   * the placement `bits` in force now (a raise of K may have started since it was logged; the one it was logged
   * with when `bits` is null), so a move that walked past its uid never leaves it behind. Returns the databases whose
   * rows did not land; while any row waits, the alarm tries again.
   */
  private async replay(bits: number | null): Promise<Set<number>> {
    const down = new Set<number>();
    const rows = this.walRows();
    if (rows.length === 0) return down;
    const ready: WalRow[] = [];
    for (const r of rows) {
      if (r.ok) {
        ready.push(r);
        continue;
      }
      const logged = await this.confirm(r.last, r.h);
      if (logged === true) {
        this.sql.exec("UPDATE wal SET ok = 1 WHERE seq = ?", r.seq);
        ready.push(r);
      } else if (logged === false) this.dropWal([r.seq]);
    }
    const byDb = new Map<number, WalRow[]>();
    for (const r of ready) {
      const d = bits === null ? r.d : databaseOf(r.write, bits);
      byDb.set(d, [...(byDb.get(d) ?? []), r]);
    }
    await Promise.all(
      [...byDb].map(async ([d, rs]) => {
        const res = await this.land(d, rs);
        for (const r of rs) if (res.get(r.seq) === "down") down.add(d);
      }),
    );
    if (this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM wal").one().n > 0) await this.armAlarm(REPLAY_MS);
    return down;
  }

  private async armAlarm(ms: number): Promise<void> {
    const at = Date.now() + ms;
    const cur = await this.ctx.storage.getAlarm();
    if (cur === null || cur > at) await this.ctx.storage.setAlarm(at);
  }

  // ───────────── the placement of rows and raising K (§9.6) ─────────────

  /**
   * The κ new rows are placed by: the pinned one (pinned from DIR_SHARDS the first time the object runs), or the
   * target of the move that a raised DIR_SHARDS starts here. Null, with one log line, while the deployment's value
   * is below the pinned one (an operator error: lookups would miss rows).
   */
  private placement(): number | null {
    const want = dirBitsOf(v2Params(this.env).dirShards);
    const pinned = this.meta.num("dbits");
    if (pinned === null) {
      this.meta.set("dbits", want);
      return want;
    }
    const to = this.meta.num("tobits");
    const cur = to ?? pinned;
    if (want < cur) {
      if (!this.misconfiguredLogged) {
        logLine("DIR_SHARDS is below the pinned value; refusing writes", { pinned: 2 ** cur, deployment: 2 ** want });
        this.misconfiguredLogged = true;
      }
      return null;
    }
    this.misconfiguredLogged = false;
    if (want > cur && to === null) {
      // New rows go to their new database from now on; the old ones follow, a page per alarm (moveStep).
      this.ctx.storage.transactionSync(() => {
        this.meta.set("tobits", want);
        this.sql.exec("DELETE FROM mv");
        for (let s = 0; s < 2 ** pinned; s++) this.sql.exec("INSERT INTO mv (s, cursor, done) VALUES (?, '', 0)", s);
      });
      logLine("moving the directory's rows", { from: 2 ** pinned, to: 2 ** want });
      void this.armAlarm(MOVE_TICK_MS);
      return want;
    }
    return cur;
  }

  /**
   * One page of the move: up to MOVE_PAGE users of the first old database not yet walked, in uid order from its
   * cursor, copied with their wraps into their new databases (INSERT OR IGNORE: a page may run twice) and then
   * deleted from the old one. Pins the new κ once every old database is walked. Returns whether more remains. Runs
   * between rounds (inside `exclusive`): no row lands in the old database between the page's read and its delete.
   */
  private async moveStep(): Promise<boolean> {
    const to = this.meta.num("tobits");
    if (to === null) return false;
    const src = this.sql.exec<{ s: number; cursor: string }>("SELECT s, cursor FROM mv WHERE done = 0 ORDER BY s LIMIT 1").toArray()[0];
    if (!src) {
      this.ctx.storage.transactionSync(() => {
        this.meta.set("dbits", to);
        this.meta.del("tobits");
        this.sql.exec("DELETE FROM mv");
      });
      logLine("the directory's rows are in their databases", { databases: 2 ** to });
      return false;
    }
    try {
      const db = userDb(this.env, src.s);
      const users = (
        await db.prepare(`SELECT ${USER_COLS} FROM user WHERE uid > ?1 ORDER BY uid LIMIT ?2`).bind(src.cursor, MOVE_PAGE).all<UserRow>()
      ).results;
      if (users.length === 0) {
        this.sql.exec("UPDATE mv SET done = 1 WHERE s = ?", src.s);
        return true;
      }
      const moving = users.filter((u) => dirShardOf(u.upre, to) !== src.s);
      if (moving.length > 0) {
        const uids = moving.map((u) => u.uid);
        const wraps = (await db.prepare(`SELECT uid, id, record, sig, dirseq FROM wrap WHERE uid IN (${marks(uids.length)})`).bind(...uids).all<WrapRow>())
          .results;
        const byDb = new Map<number, D1PreparedStatement[]>();
        for (const u of moving) {
          const t = dirShardOf(u.upre, to);
          const target = userDb(this.env, t);
          const stmts = byDb.get(t) ?? [];
          byDb.set(t, stmts);
          stmts.push(target.prepare(USER_COPY_SQL).bind(u.uid, u.upre, u.handle, u.hpre, u.bundle, u.sig, u.reg_era, u.dirseq));
          for (const w of wraps) if (w.uid === u.uid) stmts.push(target.prepare(WRAP_COPY_SQL).bind(w.uid, w.id, w.record, w.sig, w.dirseq));
        }
        await Promise.all([...byDb].map(([t, stmts]) => userDb(this.env, t).batch(stmts)));
        await db.batch([
          db.prepare(`DELETE FROM wrap WHERE uid IN (${marks(uids.length)})`).bind(...uids),
          db.prepare(`DELETE FROM user WHERE uid IN (${marks(uids.length)})`).bind(...uids),
        ]);
      }
      this.ctx.storage.transactionSync(() => {
        this.sql.exec("UPDATE mv SET cursor = ? WHERE s = ?", users[users.length - 1].uid, src.s);
        if (users.length < MOVE_PAGE) this.sql.exec("UPDATE mv SET done = 1 WHERE s = ?", src.s);
      });
    } catch (e) {
      // The cursor stays: the page runs again at the next alarm.
      logLine("moving rows failed; trying again", { error: logErr(e) });
    }
    return true;
  }
}
