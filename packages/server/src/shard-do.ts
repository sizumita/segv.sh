/**
 * ShardDO — one era's create-only row store (docs/PROTOCOL.md §9.1). Name "shard/v2/{E}/{i}".
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
 *  - Paging (§9.1 "Paging"): a sealed shard that holds rows writes itself into R2 (seal.ts: rows, idx, batches, then
 *    the manifest), alarm by alarm in slices of a few parts, with the progress of every part persisted (pager.ts), then
 *    verifies the files the way the Worker reads them, persists state = paged, drops its tables and deleteAll()s its
 *    storage, keeping only the meta it still answers head() from. From then on get and the feed RPCs throw
 *    "shard: paged" and the Worker reads R2. A sealed shard without rows never pages. An ended-era object that finds
 *    no state but its manifest in R2 restores its meta from it.
 *  - s_E (the shard map, §9.1) is pinned in meta 'sbits' by the first put that inserts a row, and for the whole era
 *    by shard 0: a shard i > 0 without a pin of its own asks shard 0 (pinShards) before its first put or get in the
 *    accept window or later, and shard 0 pins the count it is offered when it has none. put, get and the feed RPCs
 *    throw when the deployment's s_E differs from the pin, and put and get throw for a well-formed key that routes to
 *    another shard, so a SHARD_MAP changed for an era that has rows fails loudly (the Worker answers 503) instead of
 *    storing or missing rows. head() and paging use the pin.
 *  - Δ is pinned in meta 'delta' by the first put that inserts a row (§3.1); a deployment Δ that differs later is
 *    logged once per instance and ignored for this era.
 *  - get / head / feedBatches / feedRows are the reads. The feed (public enumeration, closed batches only) is two
 *    RPCs so that no RPC result carries more than the caller's budget of bodies, however large one batch is: the
 *    Worker gets a page's batch list (with the rows inline when the page fits) and pulls an oversized batch's rows
 *    in label-ordered chunks; the HTTP page still never splits a batch (§10.9).
 *
 * Time is read through the protected `clock` field and Δ / SKEW through `params`, so tests can override them, as
 * they can the part size and the parts per paging slice.
 */
import { DurableObject } from "cloudflare:workers";
import {
  BODY_LENS,
  b64u,
  era,
  eraEnd,
  eraStart,
  fromB64u,
  random,
  sealBucketBits,
  sealBucketOf,
  sealSigMsg,
  secOf,
  shardCid,
  shardOf,
  tpub,
  type Bytes,
  type SealSummary,
} from "@segv/protocol/proto";
import { AlarmSlot, BATCH_SCHEMA, BatchChain, Meta, ab, leafShardFromHash } from "./batch";
import { krouteFor, serverKeys, shardBitsOf, srvSign, v2Params } from "./env";
import { ed25519Verify, logErr, sha256 } from "./http";
import { PartSink, type Resume } from "./pager";
import {
  FEED_BATCH_HDR,
  FEED_ROW_HDR,
  SEAL_PART,
  ShardPagedError,
  batchHeader,
  checkManifest,
  dirBytes,
  encodeBatchEntry,
  encodeIdxEntry,
  manifestJson,
  sealBatchTable,
  sealKey,
  sealLookup,
} from "./seal";
import {
  parseEraName,
  shardStub,
  type ShardFeedBatch,
  type ShardFeedBatches,
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
/** The smallest wire size of a feed row (class 0): bounds how many rows one feedRows call can return. */
const FEED_ROW_MIN = FEED_ROW_HDR + BODY_LENS[0];
/** Paging: parts uploaded per alarm, the gap between slices, rows / entries read per SQL round trip. */
const PAGE_PARTS = 4;
const PAGE_STEP_MS = 1000;
const PAGE_ROWS_CHUNK = 256;
const PAGE_ENTRIES_CHUNK = 1024;
/** Rows looked up through the files before a shard trusts them (§9.1 "Paging"). */
const VERIFY_SAMPLES = 16;

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
/** Paging scratch: each row's and each batch's offset in `rows`, filled while `rows` is written, dropped at the end. */
const PAGE_SCHEMA = `
CREATE TABLE IF NOT EXISTS roff (id INTEGER PRIMARY KEY, off INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS boff (t INTEGER PRIMARY KEY, off INTEGER NOT NULL);
`;

const isBytes = (x: unknown, len: number): x is Uint8Array => x instanceof Uint8Array && x.length === len;
/** A routing value (§4.4): 8 bytes below 2^63. Paging sorts rows by v and cuts buckets from its top bits. */
const isRoutingValue = (x: unknown): x is Uint8Array => isBytes(x, 8) && (x[0] & 0x80) === 0;

/** A routing value whose top s bits (below the clear top bit) are i, the rest random (§4.4): shard(E, ·) = i. */
function routingIn(i: number, s: number): Uint8Array {
  const v = random(8);
  const dv = new DataView(v.buffer, v.byteOffset, 8);
  const low = dv.getBigUint64(0) & ((BigInt(1) << BigInt(63 - s)) - BigInt(1));
  dv.setBigUint64(0, (BigInt(i) << BigInt(63 - s)) | low);
  return v;
}

/** BAD check of §9.1: len(body) = CLASSES[cls] + 40, len(label) = 16, v a routing value. */
function wellFormed(r: unknown): r is ShardPutRow {
  if (typeof r !== "object" || r === null) return false;
  const { v, label, cls, body } = r as Record<string, unknown>;
  return (
    isRoutingValue(v) &&
    isBytes(label, 16) &&
    typeof cls === "number" &&
    Number.isInteger(cls) &&
    cls >= 0 &&
    cls < BODY_LENS.length &&
    isBytes(body, BODY_LENS[cls])
  );
}

type Phase = "rows" | "idx" | "batches" | "verify";
type PageFile = "rows" | "idx" | "batches";
/** The persisted progress of one file (meta 'pg:<file>', JSON). */
interface FileProgress {
  uploadId: string;
  parts: { etag: string; sha: string }[];
  size: number;
  resume: Resume<unknown> | null;
}
/** One item of a file: its position (what a resume names), its bytes, and the scratch it writes when committed. */
interface Item<P> {
  pos: P;
  bytes: Bytes;
  /** runs in the commit of the part the item starts in; `fresh` is false when the item is being re-sent */
  side?: (off: number, fresh: boolean) => void;
}
interface RowPos {
  t: number;
  /** null: the batch header */
  label: string | null;
}
interface IdxPos {
  v: string;
  label: string;
}
interface BatchPos {
  t: number;
}

export class ShardDO extends DurableObject<Env> {
  /** Instance fields (not constants) so tests can override them with runInDurableObject. */
  protected clock = (): number => Date.now();
  protected params: { delta: number; skew: number };
  /** s_E of the deployment for this era (§9.1); it must equal the pin in meta 'sbits' once that exists. */
  protected shardBits: number;
  /** Shard 0 confirmed the deployment's s_E for this era (shards i > 0, per instance). */
  private eraPinOk = false;
  protected fullBytes = FULL_BYTES;
  /** Paging: the part size of the files (R2 needs at least 5 MiB) and the parts uploaded per alarm. */
  protected partSize = SEAL_PART;
  protected pageParts = PAGE_PARTS;
  /** The lookup through the paged files that the paging check uses (an instance field so tests can watch it). */
  protected lookup = sealLookup;

  private readonly E: number;
  private readonly i: number;
  private readonly cid: string;
  private readonly sql: SqlStorage;
  private readonly meta: Meta;
  private readonly chain: BatchChain;
  private readonly alarmSlot: AlarmSlot;
  /** The pinned-Δ mismatch has been logged by this instance. */
  private deltaLogged = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const { E, i } = parseEraName(ctx.id.name, "shard");
    this.E = E;
    this.i = i;
    this.cid = shardCid(E, i);
    const p = v2Params(env);
    this.params = { delta: p.delta, skew: p.skew };
    this.shardBits = shardBitsOf(p.shardMap, E);
    this.sql = ctx.storage.sql;
    this.sql.exec(SCHEMA);
    this.meta = new Meta(this.sql);
    this.chain = new BatchChain(this.sql, this.meta, this.cid, (t) => this.leavesAt(t));
    this.alarmSlot = new AlarmSlot(ctx.storage);
    // §9 "Identity and alarms": arm min(getAlarm(), due) unless the era has ended (then prepare() seals); a sealed
    // shard that still holds rows arms its paging; one whose storage was lost after it paged restores its meta.
    void ctx.blockConcurrencyWhile(async () => {
      await this.alarmSlot.load();
      const now = this.clock();
      if (this.state() === null && now >= this.sealAt()) await this.recover();
      if (!this.sealed() && now < this.sealAt()) {
        this.alarmSlot.arm(this.due());
        return;
      }
      this.armPaging(now);
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
    const sbits = await this.routeBits(now);
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
      for (const r of rows) if (wellFormed(r)) this.checkRoute(r.v, sbits);
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
        // Δ and s_E MUST NOT change within an era: the first write pins them.
        if (this.meta.num("delta") === null) this.meta.set("delta", delta);
        if (this.meta.num("sbits") === null) this.meta.set("sbits", sbits);
      }
      return res;
    });
    // Same synchronous block as the commit: the alarm is committed together with the rows.
    if (wrote) this.alarmSlot.arm(this.due());
    else this.armPaging(now);
    return out;
  }

  async get(E: number, i: number, keys: ShardGetKey[]): Promise<ShardGetResult[]> {
    this.checkId(E, i);
    if (!Array.isArray(keys)) throw new TypeError("get: keys must be an array");
    if (this.paged()) throw new ShardPagedError();
    const now = this.clock();
    const sbits = await this.routeBits(now);
    // Paging may have finished while shard 0 answered: its emptied tables must never answer MISS.
    if (this.paged()) throw new ShardPagedError();
    this.ctx.storage.transactionSync(() => this.prepare(now));
    this.armPaging(now);
    const sealed = this.sealed();
    return keys.map((k): ShardGetResult => {
      if (typeof k !== "object" || k === null || !isRoutingValue(k.v) || !isBytes(k.label, 16)) return { s: "miss", sealed };
      this.checkRoute(k.v, sbits);
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

  /**
   * §9.1 "Shard map": the era's count, held by shard 0. Pins `bits` when no count is pinned yet and returns the
   * pinned one; the caller compares it with its deployment's.
   */
  pinShards(E: number, i: number, bits: number): number {
    this.checkId(E, i);
    if (this.i !== 0) throw new Error("shard: only shard 0 holds the era's count");
    if (!Number.isInteger(bits) || bits < 0 || bits > 16) throw new RangeError("pinShards: bad bits");
    return this.ctx.storage.transactionSync((): number => {
      const pinned = this.meta.num("sbits");
      if (pinned !== null) return pinned;
      this.meta.set("sbits", bits);
      return bits;
    });
  }

  head(E: number, i: number): ShardHead {
    this.checkId(E, i);
    const now = this.clock();
    this.ctx.storage.transactionSync(() => {
      this.prepare(now);
      if (!this.sealed()) this.chain.closeIfDue(tpub(now, this.delta()));
    });
    this.armPaging(now);
    const s = this.chain.state();
    const sealed = this.sealed();
    return {
      head: s.head,
      tLast: s.closedT ?? 0,
      sealed,
      size: this.sql.databaseSize,
      paged: this.paged() || (sealed && s.closedT === null),
    };
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
    if (this.paged()) throw new ShardPagedError();
    this.checkPin();
    const now = this.clock();
    this.ctx.storage.transactionSync(() => this.prepare(now));
    this.armPaging(now);
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
    if (this.paged()) throw new ShardPagedError();
    this.checkPin();
    const now = this.clock();
    this.ctx.storage.transactionSync(() => this.prepare(now));
    this.armPaging(now);
    const closed = this.sql.exec("SELECT 1 FROM batch WHERE t = ?", t).toArray().length > 0;
    if (!closed) throw new RangeError("feedRows: no closed batch at t");
    return this.rowsOf(t, afterLabel, budget);
  }

  /** Batch close, seal, and the paging slices (§9.1): one alarm, always armed at the earliest due. */
  async alarm(): Promise<void> {
    this.alarmSlot.fired();
    const now = this.clock();
    const wasSealed = this.sealed();
    this.ctx.storage.transactionSync(() => {
      this.prepare(now);
      if (!this.sealed()) this.chain.closeIfDue(tpub(now, this.delta()));
    });
    if (!this.sealed()) {
      // Never re-arm in the past (a clock that stepped back would otherwise spin the alarm).
      this.alarmSlot.arm(Math.max(this.due(), now + 1000));
      return;
    }
    if (!this.pageable()) return;
    if (!wasSealed) {
      // Sealed by this alarm: the paging starts with the next one.
      await this.alarmSlot.set(now + PAGE_STEP_MS);
      return;
    }
    let done: boolean;
    try {
      done = await this.pageSlice();
    } catch (e) {
      // The runtime retries a failed alarm with back-off; the hourly sweep (§9.5) and every RPC re-arm it after that.
      console.error(JSON.stringify({ msg: "shard: paging step failed", E: this.E, i: this.i, error: logErr(e) }));
      throw e;
    }
    if (!done) await this.alarmSlot.set(now + PAGE_STEP_MS);
  }

  // ───────────── internals ─────────────

  private checkId(E: number, i: number): void {
    if (E !== this.E || i !== this.i) throw new Error("shard DO: E / i do not match the object name");
  }

  private state(): string | null {
    return this.meta.str("state");
  }

  /** Sealed or paged: no write can land any more. */
  private sealed(): boolean {
    const s = this.state();
    return s === "sealed" || s === "paged";
  }

  private paged(): boolean {
    return this.state() === "paged";
  }

  /** s_E of this era for head() and paging: the pinned value, else the deployment's (§9.1 "Shard map"). */
  private sbits(): number {
    return this.meta.num("sbits") ?? this.shardBits;
  }

  /** §9.1 "Shard map": the deployment's s_E, which must equal this object's pin when there is one. */
  private checkPin(): number {
    const pinned = this.meta.num("sbits");
    if (pinned !== null && pinned !== this.shardBits) throw new Error("shard: SHARD_MAP differs from the shard count pinned for this era");
    return this.shardBits;
  }

  /**
   * The s_E that put and get route by: the deployment's, once it agrees with the era's pin. A shard i > 0 without a
   * pin of its own asks shard 0 for the era's count (once per instance while they agree). Before the accept window
   * no row of the era can exist anywhere, so it does not ask.
   */
  private async routeBits(now: number): Promise<number> {
    const s = this.checkPin();
    if (this.i === 0 || this.eraPinOk || this.meta.num("sbits") !== null) return s;
    if (now < eraStart(this.E) - this.params.skew * 1000) return s;
    const pinned = await shardStub(this.env, this.E, 0).pinShards(this.E, 0, s);
    if (pinned !== s) throw new Error("shard: SHARD_MAP differs from the shard count pinned for this era");
    this.eraPinOk = true;
    return s;
  }

  /** §9.1 "Shard map": a well-formed key that routes to another shard is a configuration error, never served. */
  private checkRoute(v: Uint8Array, sbits: number): void {
    if (shardOf(v, sbits) !== this.i) throw new Error("shard: key routed to another shard (SHARD_MAP changed within the era?)");
  }

  /**
   * Δ of this era: pinned by the first write, the deployment parameter before that. A deployment Δ that differs
   * from the pinned one is logged once per instance (§3.1); the pinned value always wins.
   */
  private delta(): number {
    const pinned = this.meta.num("delta");
    if (pinned === null) return this.params.delta;
    if (pinned !== this.params.delta && !this.deltaLogged) {
      this.deltaLogged = true;
      const msg = "shard: DELTA_S differs from the pinned delta; keeping the pinned value";
      console.error(JSON.stringify({ msg, E: this.E, pinned, env: this.params.delta }));
    }
    return pinned;
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

  /**
   * Rows of batch t after `after` by label: at least one, then up to `budget` wire bytes (see feedRows). Two reads,
   * each consumed whole: the record headers (length(body) reads no body) decide how many rows fit, then exactly those
   * rows are read. A cursor left half-read would keep its statement open, and an open statement blocks the DROP
   * TABLE of paging (§9.1) with SQLITE_LOCKED.
   */
  private rowsOf(t: number, after: Uint8Array | null, budget: number): ShardFeedRows {
    // Every row has ≥ FEED_ROW_MIN wire bytes, so this LIMIT never cuts a result short; it only bounds the read.
    const limit = Math.floor(budget / FEED_ROW_MIN) + 2;
    const where = after === null ? "t = ?" : "t = ? AND label > ?";
    const args = after === null ? [t] : [t, ab(after)];
    const heads = this.sql
      .exec<{ len: number }>(`SELECT length(body) AS len FROM row WHERE ${where} ORDER BY label LIMIT ?`, ...args, limit)
      .toArray();
    let bytes = 0;
    let n = 0;
    for (const h of heads) {
      const size = FEED_ROW_HDR + h.len;
      if (n > 0 && bytes + size > budget) break;
      bytes += size;
      n++;
    }
    if (n === 0) return { rows: [], done: true };
    const rows = this.sql
      .exec<{ label: ArrayBuffer; cls: number; body: ArrayBuffer }>(
        `SELECT label, cls, body FROM row WHERE ${where} ORDER BY label LIMIT ?`,
        ...args,
        n,
      )
      .toArray()
      .map((r) => ({ label: new Uint8Array(r.label), cls: r.cls, body: new Uint8Array(r.body) }));
    return { rows, done: n === heads.length && heads.length < limit };
  }

  // ───────────── paging (§9.1 "Paging") ─────────────

  /** Sealed, holding at least one closed batch, not paged yet, and with a bucket to page into. */
  private pageable(): boolean {
    return this.state() === "sealed" && this.meta.num("closed_t") !== null && this.bucket() !== null;
  }

  private bucket(): R2Bucket | null {
    return (this.env as { BLOBS?: R2Bucket }).BLOBS ?? null;
  }

  /** Arms the next paging slice when there is one to run. */
  private armPaging(now: number): void {
    if (this.pageable()) this.alarmSlot.arm(now + PAGE_STEP_MS);
  }

  /** One alarm's worth of paging: at most `pageParts` part uploads. Returns whether the shard is now paged. */
  private async pageSlice(): Promise<boolean> {
    const phase = (this.meta.str("pg:phase") ?? "rows") as Phase;
    switch (phase) {
      case "rows": {
        this.sql.exec(PAGE_SCHEMA);
        // The part size of this paging, for every file and the manifest, whatever a later deploy sets.
        if (this.meta.num("pg:part") === null) this.ctx.storage.transactionSync(() => this.meta.set("pg:part", this.partSize));
        const done = await this.uploadFile("rows", (r) => this.rowItems(r as Resume<RowPos> | null), undefined, () => {
          const n = this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM row").one().n;
          const nb = this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM batch").one().n;
          this.meta.set("pg:n", n);
          this.meta.set("pg:nb", nb);
          this.meta.set("pg:phase", "idx");
        });
        return done ? this.pageSlice() : false;
      }
      case "idx": {
        const n = this.meta.num("pg:n") ?? 0;
        const b = sealBucketBits(n);
        const sbits = this.sbits();
        const counts = this.dirCounts(b);
        const count = (v: Bytes): void => {
          counts[sealBucketOf(v, sbits, b)]++;
        };
        const done = await this.uploadFile(
          "idx",
          (r) => this.idxItems(r as Resume<IdxPos> | null, count),
          () => this.meta.set("pg:dir", dirBytes(counts)),
          () => this.meta.set("pg:phase", "batches"),
        );
        return done ? this.pageSlice() : false;
      }
      case "batches": {
        const done = await this.uploadFile("batches", (r) => this.batchItems(r as Resume<BatchPos> | null), undefined, () =>
          this.meta.set("pg:phase", "verify"),
        );
        return done ? this.pageSlice() : false;
      }
      case "verify":
        await this.verifyAndPublish();
        return true;
      default:
        throw new Error("shard: unknown paging phase");
    }
  }

  /** The part size of the paging in progress (pinned by its first slice), else the instance's. */
  private pagePart(): number {
    return this.meta.num("pg:part") ?? this.partSize;
  }

  private progress(name: PageFile): FileProgress | null {
    const s = this.meta.str(`pg:${name}`);
    return s === null ? null : (JSON.parse(s) as FileProgress);
  }

  /** The bucket counts of the idx phase so far (meta 'pg:dir', big-endian u32 × 2^b), or zeros. */
  private dirCounts(b: number): Uint32Array {
    const counts = new Uint32Array(2 ** b);
    const stored = this.meta.bytes("pg:dir");
    if (stored && stored.length === counts.length * 4) {
      const dv = new DataView(stored.buffer, stored.byteOffset, stored.byteLength);
      for (let k = 0; k < counts.length; k++) counts[k] = dv.getUint32(k * 4);
    }
    return counts;
  }

  /**
   * Writes one file of the shard, resuming where the last slice stopped (pager.ts), at most `pageParts` parts per
   * call. Every part's commit runs the side effects of the items that start in it, `extra`, and persists the
   * progress; `onComplete` runs in the transaction that follows the multipart completion. True once the file is done.
   */
  private async uploadFile<P>(
    name: PageFile,
    items: (resume: Resume<P> | null) => Iterable<Item<P>>,
    extra: (() => void) | undefined,
    onComplete: () => void,
  ): Promise<boolean> {
    const bucket = this.bucket();
    if (!bucket) throw new Error("shard: no bucket to page into");
    const key = sealKey(this.E, this.i, name);
    let prog = this.progress(name);
    let upload: R2MultipartUpload;
    if (prog === null) {
      upload = await bucket.createMultipartUpload(key);
      const fresh: FileProgress = { uploadId: upload.uploadId, parts: [], size: 0, resume: null };
      prog = fresh;
      this.ctx.storage.transactionSync(() => this.meta.set(`pg:${name}`, JSON.stringify(fresh)));
    } else {
      upload = bucket.resumeMultipartUpload(key, prog.uploadId);
    }
    const p = prog;
    const pending: (() => void)[] = [];
    const sink = new PartSink<P>(
      this.pagePart(),
      p.parts.length,
      async (partNumber, bytes) => (await upload.uploadPart(partNumber, bytes as Uint8Array<ArrayBuffer>)).etag,
      (done) => {
        p.parts.push({ etag: done.etag, sha: b64u(done.sha) });
        p.size += done.bytes;
        p.resume = done.resume;
        this.ctx.storage.transactionSync(() => {
          for (const s of pending) s();
          pending.length = 0;
          extra?.();
          this.meta.set(`pg:${name}`, JSON.stringify(p));
        });
      },
    );
    const start = p.resume as Resume<P> | null;
    let first = true;
    for (const it of items(start)) {
      const skip = first && start !== null ? Math.min(start.skip, it.bytes.length) : 0;
      first = false;
      if (it.side) {
        const side = it.side;
        const off = sink.offset - skip;
        const fresh = skip === 0;
        pending.push(() => side(off, fresh));
      }
      await sink.write(it.pos, it.bytes, skip);
      if (sink.uploaded >= this.pageParts) return false;
    }
    await sink.flush();
    try {
      await upload.complete(p.parts.map((x, k) => ({ partNumber: k + 1, etag: x.etag })));
    } catch (e) {
      // Completed by an earlier slice whose commit was lost: the object is there with every byte.
      const h = await bucket.head(key);
      if (!h || h.size !== p.size) throw e;
    }
    this.ctx.storage.transactionSync(() => {
      for (const s of pending) s();
      pending.length = 0;
      onComplete();
    });
    return true;
  }

  /** `rows`: every closed batch ascending by t, its header then its rows by label (§10.9), from `resume` on. */
  private *rowItems(resume: Resume<RowPos> | null): Generator<Item<RowPos>> {
    let fromT = resume?.pos.t ?? 0;
    /** the row to resume at (inclusive) inside batch fromT; null = at that batch's header, or at the start */
    let resumeLabel: Bytes | null = resume?.pos.label ? fromB64u(resume.pos.label) : null;
    for (;;) {
      const bs = this.sql
        .exec<{ t: number; n: number; root: ArrayBuffer; head: ArrayBuffer }>(
          "SELECT t, n, root, head FROM batch WHERE t >= ? ORDER BY t LIMIT ?",
          fromT,
          FEED_CHUNK,
        )
        .toArray();
      if (bs.length === 0) return;
      for (const b of bs) {
        const t = b.t;
        let after: Bytes | null = null;
        let inclusive = false;
        if (resumeLabel !== null && t === fromT) {
          after = resumeLabel;
          inclusive = true;
        } else {
          yield {
            pos: { t, label: null },
            bytes: batchHeader(t, b.n, new Uint8Array(b.root), new Uint8Array(b.head)),
            side: (off) => this.sql.exec("INSERT OR REPLACE INTO boff (t, off) VALUES (?, ?)", t, off),
          };
        }
        resumeLabel = null;
        for (;;) {
          const rows = this.rowsFrom(t, after, inclusive, PAGE_ROWS_CHUNK);
          for (const r of rows) {
            const id = r.id;
            const label = new Uint8Array(r.label);
            const bytes = new Uint8Array(FEED_ROW_HDR + r.body.byteLength);
            bytes.set(label, 0);
            bytes[16] = r.cls;
            bytes.set(new Uint8Array(r.body), FEED_ROW_HDR);
            yield {
              pos: { t, label: b64u(label) },
              bytes,
              side: (off) => this.sql.exec("INSERT OR REPLACE INTO roff (id, off) VALUES (?, ?)", id, off),
            };
          }
          if (rows.length < PAGE_ROWS_CHUNK) break;
          after = new Uint8Array(rows[rows.length - 1].label);
          inclusive = false;
        }
      }
      fromT = bs[bs.length - 1].t + 1;
    }
  }

  private rowsFrom(
    t: number,
    after: Bytes | null,
    inclusive: boolean,
    limit: number,
  ): { id: number; label: ArrayBuffer; cls: number; body: ArrayBuffer }[] {
    type R = { id: number; label: ArrayBuffer; cls: number; body: ArrayBuffer };
    if (after === null) {
      return this.sql.exec<R>("SELECT id, label, cls, body FROM row WHERE t = ? ORDER BY label LIMIT ?", t, limit).toArray();
    }
    return this.sql
      .exec<R>(
        `SELECT id, label, cls, body FROM row WHERE t = ? AND label ${inclusive ? ">=" : ">"} ? ORDER BY label LIMIT ?`,
        t,
        ab(after),
        limit,
      )
      .toArray();
  }

  /** `idx`: every row by (v, label) with its offset from `roff`, from `resume` on; `count` tallies the buckets. */
  private *idxItems(resume: Resume<IdxPos> | null, count: (v: Bytes) => void): Generator<Item<IdxPos>> {
    type R = { v: ArrayBuffer; label: ArrayBuffer; t: number; cls: number; off: number };
    const select = "SELECT r.v, r.label, r.t, r.cls, o.off FROM row r JOIN roff o ON o.id = r.id";
    let v: Bytes | null = resume ? fromB64u(resume.pos.v) : null;
    let label: Bytes | null = resume ? fromB64u(resume.pos.label) : null;
    let inclusive = true;
    for (;;) {
      const rows =
        v === null || label === null
          ? this.sql.exec<R>(`${select} ORDER BY r.v, r.label LIMIT ?`, PAGE_ENTRIES_CHUNK).toArray()
          : this.sql
              .exec<R>(
                `${select} WHERE (r.v, r.label) ${inclusive ? ">=" : ">"} (?, ?) ORDER BY r.v, r.label LIMIT ?`,
                ab(v),
                ab(label),
                PAGE_ENTRIES_CHUNK,
              )
              .toArray();
      for (const r of rows) {
        const rv = new Uint8Array(r.v);
        const rl = new Uint8Array(r.label);
        yield {
          pos: { v: b64u(rv), label: b64u(rl) },
          bytes: encodeIdxEntry(rl, r.t, r.cls, r.off),
          side: (_off, fresh) => {
            if (fresh) count(rv);
          },
        };
      }
      if (rows.length < PAGE_ENTRIES_CHUNK) return;
      v = new Uint8Array(rows[rows.length - 1].v);
      label = new Uint8Array(rows[rows.length - 1].label);
      inclusive = false;
    }
  }

  /** `batches`: every closed batch ascending by t with its offset from `boff`, from `resume` on. */
  private *batchItems(resume: Resume<BatchPos> | null): Generator<Item<BatchPos>> {
    type R = { t: number; n: number; root: ArrayBuffer; head: ArrayBuffer; off: number };
    let fromT = resume?.pos.t ?? 0;
    for (;;) {
      const rows = this.sql
        .exec<R>(
          "SELECT b.t, b.n, b.root, b.head, o.off FROM batch b JOIN boff o ON o.t = b.t WHERE b.t >= ? ORDER BY b.t LIMIT ?",
          fromT,
          PAGE_ENTRIES_CHUNK,
        )
        .toArray();
      for (const r of rows) {
        yield { pos: { t: r.t }, bytes: encodeBatchEntry(r.t, r.n, new Uint8Array(r.root), new Uint8Array(r.head), r.off) };
      }
      if (rows.length < PAGE_ENTRIES_CHUNK) return;
      fromT = rows[rows.length - 1].t + 1;
    }
  }

  /**
   * The last paging step: the manifest is built and signed, the files are checked the way the Worker reads them
   * (sizes, the batch table, a sample of rows by label, a label the shard does not hold), the manifest is written,
   * and the object keeps only its meta: state = paged, the final head, closed_t, last_t, and the Δ and s_E pins.
   */
  private async verifyAndPublish(): Promise<void> {
    const bucket = this.bucket();
    const keys = serverKeys(this.env);
    if (!bucket || !keys) throw new Error("shard: cannot page (no bucket, or the server keys are missing)");
    const s = this.chain.state();
    const n = this.meta.num("pg:n");
    const nb = this.meta.num("pg:nb");
    const files = { rows: this.progress("rows"), idx: this.progress("idx"), batches: this.progress("batches") };
    if (n === null || nb === null || s.closedT === null || !files.rows || !files.idx || !files.batches) {
      throw new Error("shard: paging progress is missing");
    }
    const b = sealBucketBits(n);
    const counts = this.dirCounts(b);
    const dir = new Uint32Array(counts.length + 1);
    for (let k = 0; k < counts.length; k++) dir[k + 1] = dir[k] + counts[k];
    const file = (p: FileProgress): { size: number; sha256: Bytes[] } => ({ size: p.size, sha256: p.parts.map((x) => fromB64u(x.sha)) });
    const summary: SealSummary = {
      era: this.E,
      shard: this.i,
      sbits: this.sbits(),
      kroute: krouteFor(keys, this.E),
      head: s.head,
      tLast: s.closedT,
      part: this.pagePart(),
      n,
      b,
      dir: dirBytes(dir),
      nb,
      rows: file(files.rows),
      idx: file(files.idx),
      batches: file(files.batches),
    };
    const sig = await srvSign(keys, sealSigMsg(summary));
    const text = manifestJson(summary, sig);
    // The round trip through the Worker's parser and verifier: what it will accept is what gets written.
    const m = await checkManifest(text, keys.srvPk, this.E, this.i);
    for (const name of ["rows", "idx", "batches"] as const) {
      const h = await bucket.head(sealKey(this.E, this.i, name));
      if (!h || h.size !== m[name].size) throw new Error(`shard: the paged ${name} file is missing or has another size`);
    }
    await sealBatchTable(bucket, m, false);
    // A sample of rows through the index, and a label the shard does not hold.
    const maxId = this.sql.exec<{ m: number | null }>("SELECT max(id) AS m FROM row").one().m ?? 0;
    type R = { v: ArrayBuffer; label: ArrayBuffer; t: number; cls: number; body: ArrayBuffer };
    const sample = new Map<string, R>();
    for (let k = 0; k < VERIFY_SAMPLES * 2 && sample.size < Math.min(VERIFY_SAMPLES, n); k++) {
      const id = 1 + Math.floor(Math.random() * maxId);
      const r = this.sql.exec<R>("SELECT v, label, t, cls, body FROM row WHERE id >= ? ORDER BY id LIMIT 1", id).toArray()[0];
      if (r) sample.set(b64u(new Uint8Array(r.label)), r);
    }
    const rows = [...sample.values()];
    const found = await this.lookup(
      bucket,
      m,
      rows.map((r) => ({ v: new Uint8Array(r.v), label: new Uint8Array(r.label), mode: 0 as const })),
    );
    rows.forEach((r, k) => {
      const f = found[k];
      const body = new Uint8Array(r.body);
      if (f.s !== "hit" || f.t !== r.t || f.cls !== r.cls || !f.body || f.body.length !== body.length || !f.body.every((x, j) => x === body[j])) {
        throw new Error("shard: a paged row does not read back");
      }
    });
    // A routing value of this shard with a random label: whatever its bucket, the label is not in it.
    const [miss] = await this.lookup(bucket, m, [{ v: routingIn(this.i, summary.sbits), label: random(16), mode: 1 }]);
    if (miss.s !== "miss" || !miss.sealed) throw new Error("shard: an absent label reads back as present");
    await bucket.put(sealKey(this.E, this.i, "manifest"), text, { httpMetadata: { contentType: "application/json" } });
    if (!(await bucket.head(sealKey(this.E, this.i, "manifest")))) throw new Error("shard: the manifest did not persist");
    // From here on the files are the truth: drop the tables, then free the storage and keep the meta head() needs.
    const keep = { head: s.head, closedT: s.closedT, lastT: s.lastT, delta: this.meta.num("delta"), sbits: this.meta.num("sbits") };
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("DROP TABLE IF EXISTS roff");
      this.sql.exec("DROP TABLE IF EXISTS boff");
      this.sql.exec("DROP TABLE IF EXISTS row");
      this.sql.exec("DROP TABLE IF EXISTS batch");
      this.sql.exec("DELETE FROM meta WHERE k LIKE 'pg:%'");
      this.meta.set("state", "paged");
    });
    await this.ctx.storage.deleteAll();
    this.sql.exec(SCHEMA);
    this.ctx.storage.transactionSync(() => {
      this.meta.set("state", "paged");
      this.meta.set("head", keep.head);
      this.meta.set("closed_t", keep.closedT);
      this.meta.set("last_t", keep.lastT);
      if (keep.delta !== null) this.meta.set("delta", keep.delta);
      if (keep.sbits !== null) this.meta.set("sbits", keep.sbits);
    });
    await this.alarmSlot.clear();
    console.error(JSON.stringify({ msg: "shard: paged into R2", E: this.E, i: this.i, rows: n, bytes: summary.rows.size }));
  }

  /**
   * An ended-era object without state: if its manifest exists, its storage was lost after it paged (between
   * deleteAll() and the meta re-write), and head() must keep answering the final head. Restores the meta from it.
   */
  private async recover(): Promise<void> {
    const bucket = this.bucket();
    const keys = serverKeys(this.env);
    if (!bucket || !keys) return;
    let text: string | null = null;
    try {
      const obj = await bucket.get(sealKey(this.E, this.i, "manifest"));
      text = obj ? await obj.text() : null;
    } catch (e) {
      console.error(JSON.stringify({ msg: "shard: could not look for the manifest", E: this.E, i: this.i, error: logErr(e) }));
      return;
    }
    if (text === null) return;
    const m = await checkManifest(text, keys.srvPk, this.E, this.i);
    if (!(await ed25519Verify(keys.srvPk, m.sig, sealSigMsg(m)))) throw new Error("shard: the manifest does not verify");
    this.ctx.storage.transactionSync(() => {
      this.meta.set("state", "paged");
      this.meta.set("head", m.head);
      this.meta.set("closed_t", m.tLast);
      this.meta.set("last_t", m.tLast);
      this.meta.set("sbits", m.sbits);
    });
    console.error(JSON.stringify({ msg: "shard: meta restored from the manifest", E: this.E, i: this.i }));
  }
}
