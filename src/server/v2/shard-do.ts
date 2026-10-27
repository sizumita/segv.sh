/**
 * ShardDO — one era's create-only row store (docs/PROTOCOL-v2.md §9.1). Name "shard/v2/{E}/{i}" (stage 1: i = 0).
 *
 *  - put: H(body) of every well-formed row is computed natively (crypto.subtle) first; then one synchronous
 *    transactionSync per call (no await inside): prepare(), the accept window start(E) − SKEW ≤ now < end(E), FULL
 *    above 8 GiB, t = max(tpub(now), last_t, sec(start(E)), closed_t + Δ), roll the open batch, then CAS-insert
 *    every row independently (BAD / CONFLICT(occupant) / OK(t)), storing H(body) next to it as `bh`.
 *  - Rows are committed in Δ batches (batch.ts): leaves ordered by label, root = MTH, head chain per cid
 *    "shard/{E}/{i}". closeBatch reads only (label, cls, bh) per row, never a body, so closing costs O(rows) small objects
 *    whatever the batch holds. The batch alarm (T0 + (open_t + Δ)·1000 + 1000) and the seal alarm (end(E) + SKEW)
 *    share the one DO alarm; the earliest due is always armed, in the same synchronous block as the commit.
 *  - prepare() seals once now ≥ end(E) + SKEW: closes the open batch and persists state = sealed. MISS(sealed)
 *    is only answered once that is persisted.
 *  - get / head / feedBatches / feedRows are the reads. The feed (public enumeration, closed batches only) is two
 *    RPCs so that no RPC result carries more than the caller's budget of bodies, however large one batch is: the
 *    Worker gets a page's batch list (with the rows inline when the page fits) and pulls an oversized batch's rows
 *    in label-ordered chunks; the HTTP page still never splits a batch (§10.9).
 *
 * Time is read through the protected `clock` field and Δ / SKEW through `params`, so tests can override them.
 */
import { DurableObject } from "cloudflare:workers";
import { BODY_LENS, era, eraEnd, eraStart, secOf, shardCid, tpub } from "../../lib/proto2";
import { AlarmSlot, BATCH_SCHEMA, BatchChain, Meta, ab, leafShardFromHash } from "./batch";
import { sha256 } from "../http";
import { v2Params } from "./env";
import {
  parseEraName,
  type ShardFeedBatch,
  type ShardFeedBatches,
  type ShardFeedRow,
  type ShardFeedRows,
  type ShardGetKey,
  type ShardGetResult,
  type ShardHead,
  type ShardPutResult,
  type ShardPutRow,
} from "./types";

/** FULL above this databaseSize (stage 1: no splitting; a DO stores at most 10 GB). */
const FULL_BYTES = 8 * 2 ** 30;
/** Batches read per SQL round trip while building a feed page. */
const FEED_CHUNK = 64;
/** Wire bytes of a feed batch header (u32 t | u32 n | root | head) and per-row overhead (label | u8 cls). */
const FEED_BATCH_HDR = 4 + 4 + 32 + 32;
const FEED_ROW_HDR = 16 + 1;
/** The smallest wire size of a feed row (class 0): bounds how many rows one feedRows call can return. */
const FEED_ROW_MIN = FEED_ROW_HDR + BODY_LENS[0];

/**
 * §9.1's row table plus `bh` = H(body), written with the row (stage-1 deviation, so that closeBatch never reads a
 * body). `bh` sits before `body` so that reading it never touches the body's overflow pages.
 */
const SCHEMA = `${BATCH_SCHEMA}
CREATE TABLE IF NOT EXISTS row (
  id INTEGER PRIMARY KEY,
  v BLOB NOT NULL CHECK (length(v) = 8),
  label BLOB NOT NULL CHECK (length(label) = 16),
  t INTEGER NOT NULL,
  cls INTEGER NOT NULL CHECK (cls BETWEEN 0 AND 3),
  bh BLOB NOT NULL CHECK (length(bh) = 32),
  body BLOB NOT NULL,
  UNIQUE (v, label)
);
CREATE INDEX IF NOT EXISTS row_t ON row (t, label);
`;

const isBytes = (x: unknown, len: number): x is Uint8Array => x instanceof Uint8Array && x.length === len;

/** BAD check of §9.1: len(body) = CLASSES[cls] + 40, len(label) = 16, len(v) = 8. */
function wellFormed(r: unknown): r is ShardPutRow {
  if (typeof r !== "object" || r === null) return false;
  const { v, label, cls, body } = r as Record<string, unknown>;
  return (
    isBytes(v, 8) &&
    isBytes(label, 16) &&
    typeof cls === "number" &&
    Number.isInteger(cls) &&
    cls >= 0 &&
    cls < BODY_LENS.length &&
    isBytes(body, BODY_LENS[cls])
  );
}

export class ShardDO extends DurableObject<Env> {
  /** Instance fields (not constants) so tests can override them with runInDurableObject. */
  protected clock = (): number => Date.now();
  protected params: { delta: number; skew: number };
  protected fullBytes = FULL_BYTES;

  private readonly E: number;
  private readonly i: number;
  private readonly cid: string;
  private readonly sql: SqlStorage;
  private readonly meta: Meta;
  private readonly chain: BatchChain;
  private readonly alarmSlot: AlarmSlot;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const { E, i } = parseEraName(ctx.id.name, "shard");
    this.E = E;
    this.i = i;
    this.cid = shardCid(E, i);
    const p = v2Params(env);
    this.params = { delta: p.delta, skew: p.skew };
    this.sql = ctx.storage.sql;
    this.sql.exec(SCHEMA);
    this.meta = new Meta(this.sql);
    this.chain = new BatchChain(this.sql, this.meta, this.cid, (t) => this.leavesAt(t));
    this.alarmSlot = new AlarmSlot(ctx.storage);
    // §9 "Identity and alarms": arm min(getAlarm(), due) unless the era has ended (then prepare() seals).
    void ctx.blockConcurrencyWhile(async () => {
      await this.alarmSlot.load();
      if (this.sealed() || this.clock() >= this.sealAt()) return;
      this.alarmSlot.arm(this.due());
    });
  }

  // ───────────── RPC ─────────────

  async put(E: number, i: number, rows: ShardPutRow[]): Promise<ShardPutResult[]> {
    this.checkId(E, i);
    if (!Array.isArray(rows)) throw new TypeError("put: rows must be an array");
    // H(body) of every well-formed row, natively and before the transaction (which stays synchronous: no await
    // inside, so CAS atomicity is unchanged). closeBatch then commits from the stored hashes, never the bodies.
    const hashes = await Promise.all(
      rows.map(async (r) => (wellFormed(r) ? await sha256(r.body) : null)),
    );
    const now = this.clock();
    let wrote = false;
    const out = this.ctx.storage.transactionSync((): ShardPutResult[] => {
      this.prepare(now);
      const { skew } = this.params;
      if (this.sealed() || now >= eraEnd(this.E) || now < eraStart(this.E) - skew * 1000) {
        const cur = era(now);
        return rows.map(() => ({ s: "wrong_era", era: cur }));
      }
      if (this.sql.databaseSize > this.fullBytes) return rows.map(() => ({ s: "full" }));
      const delta = this.delta();
      const t = this.chain.nextT(Math.max(tpub(now, delta), secOf(eraStart(this.E))), delta);
      this.chain.rollTo(t);
      const res = rows.map((r, k): ShardPutResult => {
        const bh = hashes[k];
        if (!wellFormed(r) || bh === null) return { s: "bad" };
        const o = this.sql
          .exec<{ t: number; cls: number; body: ArrayBuffer }>(
            "SELECT t, cls, body FROM row WHERE v = ? AND label = ?",
            ab(r.v),
            ab(r.label),
          )
          .toArray()[0];
        if (o) return { s: "conflict", t: o.t, cls: o.cls, body: new Uint8Array(o.body) };
        this.sql.exec(
          "INSERT INTO row (v, label, t, cls, bh, body) VALUES (?, ?, ?, ?, ?, ?)",
          ab(r.v),
          ab(r.label),
          t,
          r.cls,
          ab(bh),
          ab(r.body),
        );
        wrote = true;
        return { s: "ok", t };
      });
      if (wrote) {
        this.chain.noteWrite(t);
        // Δ MUST NOT change within an era: the first write pins it.
        if (this.meta.num("delta") === null) this.meta.set("delta", delta);
      }
      return res;
    });
    // Same synchronous block as the commit: the alarm is committed together with the rows.
    if (wrote) this.alarmSlot.arm(this.due());
    return out;
  }

  get(E: number, i: number, keys: ShardGetKey[]): ShardGetResult[] {
    this.checkId(E, i);
    if (!Array.isArray(keys)) throw new TypeError("get: keys must be an array");
    const now = this.clock();
    this.ctx.storage.transactionSync(() => this.prepare(now));
    const sealed = this.sealed();
    return keys.map((k): ShardGetResult => {
      if (typeof k !== "object" || k === null || !isBytes(k.v, 8) || !isBytes(k.label, 16)) return { s: "miss", sealed };
      if (k.mode === 0) {
        const o = this.sql
          .exec<{ t: number; cls: number; body: ArrayBuffer }>(
            "SELECT t, cls, body FROM row WHERE v = ? AND label = ?",
            ab(k.v),
            ab(k.label),
          )
          .toArray()[0];
        return o ? { s: "hit", t: o.t, cls: o.cls, body: new Uint8Array(o.body) } : { s: "miss", sealed };
      }
      const o = this.sql
        .exec<{ t: number; cls: number }>("SELECT t, cls FROM row WHERE v = ? AND label = ?", ab(k.v), ab(k.label))
        .toArray()[0];
      return o ? { s: "hit", t: o.t, cls: o.cls } : { s: "miss", sealed };
    });
  }

  head(E: number, i: number): ShardHead {
    this.checkId(E, i);
    const now = this.clock();
    this.ctx.storage.transactionSync(() => {
      this.prepare(now);
      if (!this.sealed()) this.chain.closeIfDue(tpub(now, this.delta()));
    });
    const s = this.chain.state();
    return { head: s.head, tLast: s.closedT ?? 0, sealed: this.sealed(), size: this.sql.databaseSize };
  }

  /**
   * The batches of one feed page (§9.1 feed, §10.9): closed batches with t > afterT, ascending, each with its wire
   * size (§10.9 batch encoding). Stops before the first batch that would push the page past `budget` wire bytes,
   * but always returns at least one batch when any exists. When the page fits the budget, every batch carries its
   * rows (one RPC for an ordinary page); a page that is a single oversized batch carries none, and the caller pulls
   * them with feedRows. Either way the result holds at most `budget` bytes of rows (RPC values are capped at
   * 32 MiB), and sizing a batch never reads its bodies.
   */
  feedBatches(E: number, i: number, afterT: number, budget: number): ShardFeedBatches {
    this.checkId(E, i);
    if (!Number.isSafeInteger(afterT) || afterT < 0) throw new RangeError("feedBatches: bad afterT");
    if (!Number.isSafeInteger(budget) || budget < 1) throw new RangeError("feedBatches: bad budget");
    const now = this.clock();
    this.ctx.storage.transactionSync(() => this.prepare(now));
    const batches: ShardFeedBatch[] = [];
    let bytes = 0;
    let more = false;
    let after = afterT;
    page: for (;;) {
      const chunk = this.chain.batchesAfter(after, FEED_CHUNK);
      for (const b of chunk) {
        const size = this.batchBytes(b.t);
        if (batches.length > 0 && bytes + size > budget) {
          more = true;
          break page;
        }
        bytes += size;
        batches.push({ ...b, bytes: size });
        after = b.t;
      }
      if (chunk.length < FEED_CHUNK) break;
    }
    if (bytes <= budget) for (const b of batches) b.rows = this.rowsOf(b.t, null, budget).rows;
    return { batches, more, sealed: this.sealed() };
  }

  /**
   * Rows of the closed batch t with label > afterLabel (null: from the first), ordered by label. Stops before the
   * first row that would push the result past `budget` wire bytes (17 + len(body) per row), but always returns at
   * least one row while any is left; `done` says no row of the batch follows the last one returned. The open
   * batch is never readable here (no arrival order leaks before a batch is committed).
   */
  feedRows(E: number, i: number, t: number, afterLabel: Uint8Array | null, budget: number): ShardFeedRows {
    this.checkId(E, i);
    if (!Number.isSafeInteger(t) || t < 0) throw new RangeError("feedRows: bad t");
    if (afterLabel !== null && !isBytes(afterLabel, 16)) throw new RangeError("feedRows: bad afterLabel");
    if (!Number.isSafeInteger(budget) || budget < 1) throw new RangeError("feedRows: bad budget");
    const now = this.clock();
    this.ctx.storage.transactionSync(() => this.prepare(now));
    const closed = this.sql.exec("SELECT 1 FROM batch WHERE t = ?", t).toArray().length > 0;
    if (!closed) throw new RangeError("feedRows: no closed batch at t");
    return this.rowsOf(t, afterLabel, budget);
  }

  /** Batch close and seal (§9.1): one alarm, always armed at the earliest due. */
  async alarm(): Promise<void> {
    this.alarmSlot.fired();
    const now = this.clock();
    this.ctx.storage.transactionSync(() => {
      this.prepare(now);
      if (!this.sealed()) this.chain.closeIfDue(tpub(now, this.delta()));
    });
    if (this.sealed()) return;
    // Never re-arm in the past (a clock that stepped back would otherwise spin the alarm).
    this.alarmSlot.arm(Math.max(this.due(), now + 1000));
  }

  // ───────────── internals ─────────────

  private checkId(E: number, i: number): void {
    if (E !== this.E || i !== this.i) throw new Error("shard DO: E / i do not match the object name");
  }

  private sealed(): boolean {
    return this.meta.str("state") === "sealed";
  }

  /** Δ of this era: pinned by the first write, the deployment parameter before that. */
  private delta(): number {
    return this.meta.num("delta") ?? this.params.delta;
  }

  private sealAt(): number {
    return eraEnd(this.E) + this.params.skew * 1000;
  }

  /** The earliest of the seal time and the open batch's close time. */
  private due(): number {
    return Math.min(this.sealAt(), this.chain.dueMs(this.delta()) ?? Infinity);
  }

  /** Runs first in every RPC (inside a transaction): seals once now ≥ end(E) + SKEW. */
  private prepare(now: number): void {
    if (now < this.sealAt() || this.sealed()) return;
    this.chain.closeOpen();
    this.meta.set("state", "sealed");
  }

  /**
   * Leaves of batch t0: leaf(enc("segv.sh/v2/leaf", u16 E, label, u32 t0, u8 cls, H(body))), by label, from the
   * H(body) stored at insert. Iterates the cursor over (label, cls, bh) only: no body is read, hashed or held.
   */
  private leavesAt(t0: number): Uint8Array[] {
    const leaves: Uint8Array[] = [];
    const cur = this.sql.exec<{ label: ArrayBuffer; cls: number; bh: ArrayBuffer }>(
      "SELECT label, cls, bh FROM row WHERE t = ? ORDER BY label",
      t0,
    );
    for (const r of cur) {
      leaves.push(leafShardFromHash(this.E, new Uint8Array(r.label), t0, r.cls, new Uint8Array(r.bh)));
    }
    return leaves;
  }

  /** §10.9 wire size of batch t: 72 + Σ (17 + len(body)), from the record headers (length() reads no body). */
  private batchBytes(t: number): number {
    const r = this.sql
      .exec<{ n: number; b: number | null }>("SELECT count(*) AS n, sum(length(body)) AS b FROM row WHERE t = ?", t)
      .one();
    return FEED_BATCH_HDR + r.n * FEED_ROW_HDR + (r.b ?? 0);
  }

  /** Rows of batch t after `after` by label: at least one, then up to `budget` wire bytes (see feedRows). */
  private rowsOf(t: number, after: Uint8Array | null, budget: number): ShardFeedRows {
    // Every row has ≥ FEED_ROW_MIN wire bytes, so this LIMIT never cuts a result short; it only bounds the read.
    const limit = Math.floor(budget / FEED_ROW_MIN) + 2;
    const cur =
      after === null
        ? this.sql.exec<{ label: ArrayBuffer; cls: number; body: ArrayBuffer }>(
            "SELECT label, cls, body FROM row WHERE t = ? ORDER BY label LIMIT ?",
            t,
            limit,
          )
        : this.sql.exec<{ label: ArrayBuffer; cls: number; body: ArrayBuffer }>(
            "SELECT label, cls, body FROM row WHERE t = ? AND label > ? ORDER BY label LIMIT ?",
            t,
            ab(after),
            limit,
          );
    const rows: ShardFeedRow[] = [];
    let bytes = 0;
    let read = 0;
    for (const r of cur) {
      read++;
      const size = FEED_ROW_HDR + r.body.byteLength;
      if (rows.length > 0 && bytes + size > budget) return { rows, done: false };
      bytes += size;
      rows.push({ label: new Uint8Array(r.label), cls: r.cls, body: new Uint8Array(r.body) });
    }
    return { rows, done: read < limit };
  }
}
