/**
 * InboxDO — one era of the global inbox of sealed invites (docs/PROTOCOL-v2.md §9.3, §10.5).
 * Name "inbox/v2/{E}/{g}" (stage 1: g = 0, bucket 0); (E, g) come from ctx.id.name. SQLite-backed.
 *
 *  - Slot clock: D = Δin·1000 and ms = now − T0. Readers see `closed = max(⌊ms/D⌋, closed_hw)`; a new row gets
 *    `rel = max(⌊(ms + j)/D⌋ + 1, closed_hw + 1)` with a per-row jitter j uniform in [0, D) that is never stored.
 *    `closed_hw` (the largest `closed` ever reported) is persisted before a read or head reports a larger value, so
 *    a row never lands at or below a reported `closed`, even after the clock steps back (a restart elsewhere).
 *  - Δin is pinned per era: closed_hw and every rel are slot numbers in units of D, so the first write (a post that
 *    inserts, or the first persisted closed_hw) stores Δin in meta ('slot') and D always comes from it. A deployment
 *    INBOX_SLOT_S that differs later is logged once per instance and ignored for this era.
 *  - Era end: posts are accepted while start(E) − SKEW ≤ now < end(E). At end(E) + SKEW, prepare() or the alarm
 *    persists `ended`; from then on `closed` is max(largest rel of the era, closed_hw) (it never goes down) and every
 *    response is final.
 *  - Day cap: rows count against cnt(bucket, day); a post in the SKEW window before start(E) counts against the era's
 *    first day, so an era holds at most 7 day caps.
 *  - Slot commitments: before read and head, every closed slot with rows gets a `slot` row
 *    (leaves = leafInbox ordered by eid, chained with t = rel under cid "inbox/{E}/{g}").
 */
import { DurableObject } from "cloudflare:workers";
import {
  INBOX_BODY_LEN,
  T0_MS,
  ZERO32,
  byteCmp,
  equalBytes,
  era,
  eraEnd,
  eraStart,
  inboxCid,
  leafInbox,
  mth,
  nextHead,
  secOf,
} from "../lib/proto";
import { INBOX_READ_MAX_LIMIT } from "../lib/wire";
import { INBOX_BATCH, INBOX_DAY_CAP, v2Params } from "./env";
import { parseEraName, type InboxHead, type InboxPostOut, type InboxReadOut, type InboxRowResult } from "./types";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS inv (id INTEGER PRIMARY KEY, bucket INTEGER NOT NULL, rel INTEGER NOT NULL,
  eid BLOB NOT NULL CHECK (length(eid) = 16), body BLOB NOT NULL CHECK (length(body) = ${INBOX_BODY_LEN}),
  UNIQUE (bucket, eid));
CREATE INDEX IF NOT EXISTS inv_rel ON inv (bucket, rel, eid);
CREATE TABLE IF NOT EXISTS cnt (bucket INTEGER NOT NULL, day INTEGER NOT NULL, n INTEGER NOT NULL,
  PRIMARY KEY (bucket, day)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS slot (rel INTEGER PRIMARY KEY, n INTEGER NOT NULL, root BLOB NOT NULL, head BLOB NOT NULL);
`;

const DAY_S = 86_400;

type InvRow = { bucket: number; rel: number; eid: ArrayBuffer; body: ArrayBuffer };

/** Exact-size ArrayBuffer for SQL binding (a view may sit on a larger buffer). */
function ab(b: Uint8Array): ArrayBuffer {
  return b.byteOffset === 0 && b.byteLength === b.buffer.byteLength && b.buffer instanceof ArrayBuffer
    ? b.buffer
    : (b.slice().buffer as ArrayBuffer);
}

const isU32 = (x: unknown): x is number => Number.isInteger(x) && (x as number) >= 0 && (x as number) <= 0xffffffff;

/** j uniform in [0, D) from 53 random bits (never stored, §9.3). */
function uniformJitter(D: number): number {
  const [a, b] = crypto.getRandomValues(new Uint32Array(2));
  return Math.floor(((a * 2 ** 21 + (b >>> 11)) / 2 ** 53) * D);
}

/** Defensive re-validation of RPC input (the Worker validates too). Returns detached copies. */
function checkRows(input: unknown): { eid: Uint8Array; body: Uint8Array }[] {
  if (!Array.isArray(input) || input.length < 1 || input.length > INBOX_BATCH) throw new TypeError("inbox post: bad row count");
  return input.map((r: unknown) => {
    const { eid, body } = (typeof r === "object" && r !== null ? r : {}) as Record<string, unknown>;
    if (!(eid instanceof Uint8Array) || eid.length !== 16) throw new TypeError("inbox post: bad eid");
    if (!(body instanceof Uint8Array) || body.length !== INBOX_BODY_LEN) throw new TypeError("inbox post: bad body");
    return { eid: eid.slice(), body: body.slice() };
  });
}

export class InboxDO extends DurableObject<Env> {
  /** Time source (Unix ms). An instance field so tests can step the clock. */
  protected clock: () => number = () => Date.now();
  /** Per-row jitter j ∈ [0, D) (never stored). An instance field so tests can fix it. */
  protected jitter: (D: number) => number = uniformJitter;

  private readonly E: number;
  private readonly g: number;
  private readonly cid: string;
  /** Δin of the deployment, seconds. An instance field so tests can change it as a redeploy would. */
  protected inboxSlot: number;
  /** INBOX_DAY_CAP. An instance field so tests can lower it. */
  protected dayCap = INBOX_DAY_CAP;
  /** Δin pinned for this era (meta 'slot', seconds), null until the first write */
  private slotPin: number | null;
  /** a deployment Δin that differs from the pinned one has been logged */
  private slotWarned = false;
  /** SKEW·1000 (instance field so tests can change it; SKEW is fixed for the life of an era, §3.1) */
  private skewMs: number;
  private closedHw: number;
  private ended: boolean;
  private chainHead: Uint8Array;
  /** rel of the newest slot row (0 = none) */
  private lastSlot: number;
  /** buckets that hold rows (from `cnt`), so slot commitments can use the (bucket, rel, eid) index */
  private readonly buckets: Set<number>;
  /** `closed` once `ended` is set (max(largest rel of the era, closed_hw)), computed once */
  private finalClosed: number | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const { E, i } = parseEraName(ctx.id.name, "inbox");
    this.E = E;
    this.g = i;
    this.cid = inboxCid(E, i);
    const p = v2Params(env);
    this.inboxSlot = p.inboxSlot;
    this.skewMs = p.skew * 1000;

    const sql = ctx.storage.sql;
    sql.exec(SCHEMA);
    const meta = new Map<string, ArrayBuffer | string | number | null>();
    for (const r of sql.exec<{ k: string; v: ArrayBuffer | string | number | null }>("SELECT k, v FROM meta")) meta.set(r.k, r.v);
    const head = meta.get("head");
    this.chainHead = head instanceof ArrayBuffer ? new Uint8Array(head) : ZERO32;
    this.closedHw = Number(meta.get("closed_hw") ?? 0);
    const slot = meta.get("slot");
    this.slotPin = typeof slot === "number" && Number.isInteger(slot) && slot >= 1 ? slot : null;
    this.ended = meta.get("ended") === 1;
    this.lastSlot = sql.exec<{ m: number | null }>("SELECT max(rel) AS m FROM slot").one().m ?? 0;
    this.buckets = new Set(sql.exec<{ b: number }>("SELECT DISTINCT bucket AS b FROM cnt").toArray().map((r) => r.b));

    // §9 "Identity and alarms": arm the seal alarm unless the era has already ended (prepare() seals then).
    const due = this.sealAt();
    if (!this.ended && this.clock() < due) {
      void ctx.blockConcurrencyWhile(async () => {
        const cur = await ctx.storage.getAlarm();
        if (cur === null || cur > due) await ctx.storage.setAlarm(due);
      });
    }
  }

  private sealAt(): number {
    return eraEnd(this.E) + this.skewMs;
  }

  /** Δin of this era in seconds: the pinned value, or the deployment's until the first write pins it. */
  private slotS(): number {
    const pin = this.slotPin;
    if (pin === null) return this.inboxSlot;
    if (pin !== this.inboxSlot && !this.slotWarned) {
      this.slotWarned = true;
      const msg = "inbox: INBOX_SLOT_S differs from the value pinned for this era; the pin is kept";
      console.error(JSON.stringify({ msg, E: this.E, pinned: pin, deployed: this.inboxSlot }));
    }
    return pin;
  }

  /** Stores Δin = `s` in meta unless it is pinned already (inside the caller's transaction); true when it wrote. */
  private pinSlot(s: number): boolean {
    if (this.slotPin !== null) return false;
    this.ctx.storage.sql.exec("INSERT INTO meta (k, v) VALUES ('slot', ?) ON CONFLICT (k) DO NOTHING", s);
    return true;
  }

  private checkId(E: number, g: number): void {
    if (E !== this.E || g !== this.g) throw new Error("InboxDO: (E, g) does not match the object name");
  }

  /** Persists `ended` once now ≥ end(E) + SKEW (runs first in every RPC and in the alarm). */
  private prepare(now: number): void {
    if (this.ended || now < this.sealAt()) return;
    this.ctx.storage.sql.exec("INSERT INTO meta (k, v) VALUES ('ended', 1) ON CONFLICT (k) DO UPDATE SET v = excluded.v");
    this.ended = true;
  }

  async alarm(): Promise<void> {
    const now = this.clock();
    this.prepare(now);
    // Fired early (clock differences): try again at the seal time, but never sooner than 1 s from now (§9), so an
    // alarm that fired a few ms early does not re-arm a time that has already passed and fire again at once.
    if (!this.ended) await this.ctx.storage.setAlarm(Math.max(this.sealAt(), now + 1000));
  }

  /**
   * The `closed` to report now. Persists a larger `closed_hw` first (at most one write per slot) and commits
   * every closed slot that has rows, in one transaction.
   */
  private settle(now: number): number {
    let closed: number;
    let slot = 0;
    if (this.ended) {
      if (this.finalClosed === null) {
        // `closed` never goes down: rows end at the largest rel, but a reader may already have seen closed_hw.
        const m = this.ctx.storage.sql.exec<{ m: number | null }>("SELECT max(rel) AS m FROM inv").one().m;
        this.finalClosed = Math.max(m ?? 0, this.closedHw);
      }
      closed = this.finalClosed;
    } else {
      slot = this.slotS();
      closed = Math.max(Math.floor((now - T0_MS) / (slot * 1000)), this.closedHw);
    }
    const raise = !this.ended && closed > this.closedHw;
    const pending = closed > this.lastSlot ? this.unslotted(closed) : [];
    if (!raise && pending.length === 0) return closed;
    const committed = this.ctx.storage.transactionSync(() => {
      let pinned = false;
      if (raise) {
        this.ctx.storage.sql.exec(
          "INSERT INTO meta (k, v) VALUES ('closed_hw', ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v",
          closed,
        );
        pinned = this.pinSlot(slot); // closed_hw is in units of this Δin
      }
      return { pinned, slots: pending.length > 0 ? this.commitSlots(pending) : null };
    });
    // Committed (transactionSync threw otherwise): advance the in-memory copies.
    if (raise) this.closedHw = closed;
    if (committed.pinned) this.slotPin = slot;
    if (committed.slots) {
      this.chainHead = committed.slots.head;
      this.lastSlot = committed.slots.lastSlot;
    }
    return closed;
  }

  /** Rows of closed slots without a slot row yet: lastSlot < rel ≤ closed, every bucket. */
  private unslotted(closed: number): InvRow[] {
    const out: InvRow[] = [];
    for (const b of this.buckets) {
      const cur = this.ctx.storage.sql.exec<InvRow>(
        "SELECT bucket, rel, eid, body FROM inv WHERE bucket = ? AND rel > ? AND rel <= ? ORDER BY rel, eid",
        b,
        this.lastSlot,
        closed,
      );
      for (const r of cur) out.push(r);
    }
    return out;
  }

  /** One slot row per rel (ascending), leaves ordered by eid; runs inside a transaction. */
  private commitSlots(rows: InvRow[]): { head: Uint8Array; lastSlot: number } {
    const sql = this.ctx.storage.sql;
    const groups = new Map<number, InvRow[]>();
    for (const r of rows) {
      const grp = groups.get(r.rel);
      if (grp) grp.push(r);
      else groups.set(r.rel, [r]);
    }
    let head = this.chainHead;
    let lastSlot = this.lastSlot;
    for (const rel of [...groups.keys()].sort((a, b) => a - b)) {
      const grp = groups
        .get(rel)!
        .map((r) => ({ bucket: r.bucket, eid: new Uint8Array(r.eid), body: new Uint8Array(r.body) }))
        .sort((a, b) => byteCmp(a.eid, b.eid) || a.bucket - b.bucket);
      const root = mth(grp.map((r) => leafInbox(this.E, r.bucket, rel, r.eid, r.body)));
      head = nextHead(this.cid, head, rel, grp.length, root);
      sql.exec("INSERT INTO slot (rel, n, root, head) VALUES (?, ?, ?, ?)", rel, grp.length, ab(root), ab(head));
      lastSlot = rel;
    }
    sql.exec("INSERT INTO meta (k, v) VALUES ('head', ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v", ab(head));
    return { head, lastSlot };
  }

  /** §9.3 post: 1..32 invites, one result per row (no atomicity across rows). */
  post(E: number, g: number, bucket: number, rows: { eid: Uint8Array; body: Uint8Array }[]): InboxPostOut {
    this.checkId(E, g);
    if (!isU32(bucket)) throw new TypeError("inbox post: bad bucket");
    const input = checkRows(rows);
    const now = this.clock();
    this.prepare(now);
    if (this.ended || now < eraStart(this.E) - this.skewMs || now >= eraEnd(this.E)) return { s: "wrong_era", era: era(now) };

    const sql = this.ctx.storage.sql;
    const ms = now - T0_MS;
    const slot = this.slotS();
    const D = slot * 1000;
    // A post in the SKEW window before start(E) counts against the era's first day: at most 7 day caps per era.
    const day = Math.max(Math.floor(secOf(now) / DAY_S), Math.floor(secOf(eraStart(this.E)) / DAY_S));
    let inserted = false;
    let pinned = false;
    const results = this.ctx.storage.transactionSync((): InboxRowResult[] => {
      const n0 = sql.exec<{ n: number }>("SELECT n FROM cnt WHERE bucket = ? AND day = ?", bucket, day).toArray()[0]?.n ?? 0;
      let n = n0;
      const out: InboxRowResult[] = [];
      for (const r of input) {
        const o = sql
          .exec<{ rel: number; body: ArrayBuffer }>("SELECT rel, body FROM inv WHERE bucket = ? AND eid = ?", bucket, ab(r.eid))
          .toArray()[0];
        if (o) {
          out.push(equalBytes(new Uint8Array(o.body), r.body) ? { rel: o.rel } : { error: "conflict" });
          continue;
        }
        if (n >= this.dayCap) {
          out.push({ error: "full" });
          continue;
        }
        const j = Math.min(Math.max(Math.floor(this.jitter(D)), 0), D - 1);
        const rel = Math.max(Math.floor((ms + j) / D) + 1, this.closedHw + 1);
        sql.exec("INSERT INTO inv (bucket, rel, eid, body) VALUES (?, ?, ?, ?)", bucket, rel, ab(r.eid), ab(r.body));
        n++;
        out.push({ rel });
      }
      if (n !== n0) {
        sql.exec(
          "INSERT INTO cnt (bucket, day, n) VALUES (?, ?, ?) ON CONFLICT (bucket, day) DO UPDATE SET n = excluded.n",
          bucket,
          day,
          n,
        );
        inserted = true;
        pinned = this.pinSlot(slot); // the new rels are in units of this Δin
      }
      return out;
    });
    if (inserted) this.buckets.add(bucket);
    if (pinned) this.slotPin = slot;
    return { s: "ok", results };
  }

  /**
   * §9.3 read: rows with after < rel ≤ closed, ordered by (rel, eid). Whole rel groups only; once at least
   * `limit` rows are in, the read stops before the next group and reports `more`.
   */
  read(E: number, g: number, bucket: number, after: number, limit: number): InboxReadOut {
    this.checkId(E, g);
    if (!isU32(bucket)) throw new RangeError("inbox read: bad bucket");
    if (!isU32(after)) throw new RangeError("inbox read: bad after");
    if (!Number.isInteger(limit) || limit < 1 || limit > INBOX_READ_MAX_LIMIT) throw new RangeError("inbox read: bad limit");
    const now = this.clock();
    this.prepare(now);
    const closed = this.settle(now);

    const sql = this.ctx.storage.sql;
    type R = { rel: number; eid: ArrayBuffer; body: ArrayBuffer };
    const got = sql
      .exec<R>(
        "SELECT rel, eid, body FROM inv WHERE bucket = ? AND rel > ? AND rel <= ? ORDER BY rel, eid LIMIT ?",
        bucket,
        after,
        closed,
        limit,
      )
      .toArray();
    let more = false;
    if (got.length === limit) {
      const last = got[got.length - 1];
      // Finish the last rel group, then check whether another group follows.
      const rest = sql.exec<R>(
        "SELECT rel, eid, body FROM inv WHERE bucket = ? AND rel = ? AND eid > ? ORDER BY eid",
        bucket,
        last.rel,
        last.eid,
      );
      for (const r of rest) got.push(r);
      const next = sql.exec("SELECT 1 FROM inv WHERE bucket = ? AND rel > ? AND rel <= ? LIMIT 1", bucket, last.rel, closed);
      more = next.toArray().length > 0;
    }
    return {
      closed,
      more,
      rows: got.map((r) => ({ rel: r.rel, eid: new Uint8Array(r.eid), body: new Uint8Array(r.body) })),
      ended: this.ended,
    };
  }

  /** Commitment head over the closed slots; tLast = rel of the newest slot row (0 = none). */
  head(E: number, g: number): InboxHead {
    this.checkId(E, g);
    const now = this.clock();
    this.prepare(now);
    this.settle(now);
    return { head: this.chainHead.slice(), tLast: this.lastSlot, ended: this.ended };
  }
}
