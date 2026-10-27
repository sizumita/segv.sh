/**
 * Batch commitments and alarm discipline shared by the ShardDO and the BlobRegDO (docs/PROTOCOL.md §9 intro,
 * §9.1 "Batches", §9.2).
 *
 * Both objects keep the same meta keys: 'last_t' (largest t ever assigned), 'open_t' (t of the open batch; absent =
 * none), 'closed_t' (t of the newest closed batch; absent = none) and 'head' (ZERO32 initially), plus the
 * `batch (t, n, root, head)` table. A write gets
 *
 *     t = max(floor, last_t, closed_t + Δ if closed_t exists)
 *
 * where `floor` is the object's own lower bound (tpub(now), sec(start(E)), tpub(hw), …), so t never decreases and
 * never falls into a closed batch even when the clock steps back. Nothing here caches meta in memory: every
 * value is read from SQLite, so a rolled-back transactionSync never leaves stale state behind.
 */
import { T0_MS, ZERO32, enc, leaf, mth, nextHead, u16, u32, u8, type Bytes } from "../lib/proto";
import { logErr } from "./http";

/**
 * The shard leaf of §9.1 from a stored H(body): leaf(enc("segv.sh/v2/leaf", u16 E, label, u32 t, u8 cls, bh)).
 * Byte-identical to proto.leafShard(E, label, t, cls, body) when bh = H(body); closeBatch uses it so that it never
 * has to read (or hash) a row body.
 */
export const leafShardFromHash = (E: number, label: Bytes, t: number, cls: number, bh: Bytes): Bytes =>
  leaf(enc("segv.sh/v2/leaf", u16(E), label, u32(t), u8(cls), bh));

/** Exact-size ArrayBuffer for SQL binding (a view may sit on a larger buffer). */
export function ab(b: Uint8Array): ArrayBuffer {
  return b.byteOffset === 0 && b.byteLength === b.buffer.byteLength && b.buffer instanceof ArrayBuffer
    ? b.buffer
    : (b.slice().buffer as ArrayBuffer);
}

/** The `meta (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID` table: numbers, strings or bytes per key. */
export class Meta {
  constructor(private readonly sql: SqlStorage) {}

  private raw(k: string): SqlStorageValue | undefined {
    return this.sql.exec<{ v: SqlStorageValue }>("SELECT v FROM meta WHERE k = ?", k).toArray()[0]?.v;
  }

  num(k: string): number | null {
    const v = this.raw(k);
    return typeof v === "number" ? v : null;
  }

  str(k: string): string | null {
    const v = this.raw(k);
    return typeof v === "string" ? v : null;
  }

  bytes(k: string): Uint8Array | null {
    const v = this.raw(k);
    return v instanceof ArrayBuffer ? new Uint8Array(v) : null;
  }

  set(k: string, v: number | string | Uint8Array): void {
    this.sql.exec("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)", k, v instanceof Uint8Array ? ab(v) : v);
  }

  del(k: string): void {
    this.sql.exec("DELETE FROM meta WHERE k = ?", k);
  }
}

/** SQL for the batch table both objects share (§9.1, §9.2). */
export const BATCH_SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS batch (t INTEGER PRIMARY KEY, n INTEGER NOT NULL, root BLOB NOT NULL, head BLOB NOT NULL);
`;

export interface ChainState {
  lastT: number;
  openT: number | null;
  closedT: number | null;
  head: Uint8Array;
}

export interface BatchRow {
  t: number;
  n: number;
  root: Uint8Array;
  head: Uint8Array;
}

/**
 * The head chain of one component: head' = H(enc("segv.sh/v2/head", cid, head, u32 t, u32 n, root)).
 * `leavesAt(t)` returns the leaf hashes of the rows stored with that t, already in the component's leaf order.
 * Every mutating method must run inside the caller's transactionSync.
 */
export class BatchChain {
  constructor(
    private readonly sql: SqlStorage,
    private readonly meta: Meta,
    private readonly cid: string,
    private readonly leavesAt: (t: number) => Uint8Array[],
  ) {}

  state(): ChainState {
    return {
      lastT: this.meta.num("last_t") ?? 0,
      openT: this.meta.num("open_t"),
      closedT: this.meta.num("closed_t"),
      head: this.meta.bytes("head") ?? ZERO32,
    };
  }

  /** t for a write now: max(floor, last_t, closed_t + Δ if closed_t exists). */
  nextT(floor: number, delta: number): number {
    const s = this.state();
    return Math.max(floor, s.lastT, s.closedT === null ? 0 : s.closedT + delta);
  }

  /** Before inserting rows at `t`: if open_t exists and t > open_t, closeBatch(open_t). */
  rollTo(t: number): void {
    const openT = this.meta.num("open_t");
    if (openT !== null && t > openT) this.close(openT);
  }

  /** After inserting a row at `t`: open_t = t, last_t = t. */
  noteWrite(t: number): void {
    this.meta.set("open_t", t);
    this.meta.set("last_t", t);
  }

  /** Closes the open batch if tpub(now) > open_t (the batch alarm, head()). Returns whether it closed one. */
  closeIfDue(tpubNow: number): boolean {
    const openT = this.meta.num("open_t");
    if (openT === null || tpubNow <= openT) return false;
    this.close(openT);
    return true;
  }

  /** Closes the open batch, if any, regardless of time (sealing). */
  closeOpen(): void {
    const openT = this.meta.num("open_t");
    if (openT !== null) this.close(openT);
  }

  /** closeBatch(t0): requires t0 > closed_t; commits the rows of t0 and advances the head. */
  close(t0: number): void {
    const closedT = this.meta.num("closed_t");
    if (closedT !== null && t0 <= closedT) throw new Error("closeBatch: t not above closed_t");
    const leaves = this.leavesAt(t0);
    if (leaves.length === 0) {
      // Cannot happen (open_t is only set by an insert). Never wedge the object on it: drop the marker.
      console.error(JSON.stringify({ msg: "closeBatch: empty batch skipped", cid: this.cid, t: t0 }));
      this.meta.del("open_t");
      return;
    }
    const root = mth(leaves);
    const head = nextHead(this.cid, this.meta.bytes("head") ?? ZERO32, t0, leaves.length, root);
    this.sql.exec("INSERT INTO batch (t, n, root, head) VALUES (?, ?, ?, ?)", t0, leaves.length, ab(root), ab(head));
    this.meta.set("head", head);
    this.meta.set("closed_t", t0);
    this.meta.del("open_t");
  }

  /** When the open batch's alarm is due: T0 + (open_t + Δ)·1000 + 1000, or null when no batch is open. */
  dueMs(delta: number): number | null {
    const openT = this.meta.num("open_t");
    return openT === null ? null : T0_MS + (openT + delta) * 1000 + 1000;
  }

  /** Closed batches with t > afterT, ascending, at most `limit`. */
  batchesAfter(afterT: number, limit: number): BatchRow[] {
    return this.sql
      .exec<{ t: number; n: number; root: ArrayBuffer; head: ArrayBuffer }>(
        "SELECT t, n, root, head FROM batch WHERE t > ? ORDER BY t LIMIT ?",
        afterT,
        limit,
      )
      .toArray()
      .map((b) => ({ t: b.t, n: b.n, root: new Uint8Array(b.root), head: new Uint8Array(b.head) }));
  }
}

/**
 * The one DO alarm, shared by every deadline of the object (seal, batch close). `armed` mirrors the scheduled
 * alarm so a synchronous write path can arm min(current alarm, due) without awaiting getAlarm(): it is loaded in
 * the constructor's blockConcurrencyWhile, updated by every arm(), and cleared when the alarm fires.
 */
export class AlarmSlot {
  private armed: number | null = null;

  constructor(private readonly storage: DurableObjectStorage) {}

  /** Reads the scheduled alarm (constructor, inside blockConcurrencyWhile). */
  async load(): Promise<number | null> {
    this.armed = await this.storage.getAlarm();
    return this.armed;
  }

  /** The alarm handler started: the alarm that fired is consumed. */
  fired(): void {
    this.armed = null;
  }

  /**
   * Arms min(current alarm, due). Not awaited on purpose: call it in the same synchronous block as the commit
   * it belongs to, so the alarm is committed together with the rows (write coalescing).
   */
  arm(due: number | null): void {
    if (due === null || !Number.isFinite(due)) return;
    if (this.armed !== null && this.armed <= due) return;
    this.armed = due;
    this.storage.setAlarm(due).catch((e: unknown) => {
      this.armed = null;
      console.error(JSON.stringify({ msg: "setAlarm failed", error: logErr(e) }));
    });
  }
}
