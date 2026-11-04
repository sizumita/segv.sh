/**
 * BlobRegDO — the create-only blob registry (docs/PROTOCOL.md §8.2, §9.2), B shards "blobreg/v2/{j}".
 *
 *  - A blob id lives in shard j = blobShard(id) (§4.4: a keyed hash, so nobody can aim ids at a shard). B = 2^b is
 *    BLOBREG_SHARDS, a constant of the deployment: the first write pins b in meta 'bbits', and a register or meta of
 *    an id that routes elsewhere under the pin throws (the Worker answers 503) instead of answering for the wrong
 *    shard, which could turn a MISS into a lie (§6.4(g)).
 *  - register(id, size): the first registration wins forever. A new one gets
 *    t = max(tpub(now), last_t, tpub(hw), closed_t + Δ) and joins the open Δ batch (batch.ts, like the shard).
 *  - meta(id): HIT {t, size}, or MISS {now: sec(now)} after raising the high-water mark `hw` (at most one write
 *    per Δ). Every later registration therefore gets t ≥ tpub(every now ever reported), even after a clock step
 *    back, which makes a MISS with now ≥ t_row final for §6.4(g).
 *  - Batches commit leaf(enc("segv.sh/v2/leaf/blob", H(id), u32 size, u32 t)) ordered by H(id) under the shard's
 *    cid "blobreg/{j}"; head() closes a due batch and returns the head. There is no enumeration RPC.
 *  - Import: "blobreg/v2", the first release's single registry, is read-only from now on. A shard that runs for the
 *    first time copies, before it answers anything, the rows of that object that route to it (exportShard pages
 *    them by id), raises its hw and last_t to the legacy values, pins b, and marks itself imported. The imported rows
 *    keep their t and join no batch of the shard: the legacy object's chain committed them, and stays.
 *  - Δ is pinned in meta 'delta' by the first write (registration or high-water mark), like the ShardDO's, and the
 *    pinned value is used from then on: the registry spans eras, and mixing Δ granularities would let a later
 *    registration fall below a MISS already reported as final (§6.4(g)). A deployment Δ that differs is logged
 *    once per instance and ignored.
 *
 * Time is read through the protected `clock` field and the deployment Δ and b through `params` / `blobBits`, so
 * tests can override them.
 */
import { DurableObject } from "cloudflare:workers";
import { BLOBREG_CID, H, blobRegCid, blobShardOf, byteCmp, floorDelta, leafBlob, secOf, tpub } from "@segv/protocol/proto";
import { AlarmSlot, BATCH_SCHEMA, BatchChain, Meta, ab } from "./batch";
import { blobBitsOf, serverKeys, v2Params } from "./env";
import { blobRegLegacyStub, parseBlobRegName, type BlobExport, type BlobMeta, type BlobRegistration, type ComponentHead } from "./types";

const SCHEMA = `${BATCH_SCHEMA}
CREATE TABLE IF NOT EXISTS blob (
  id BLOB PRIMARY KEY CHECK (length(id) = 32),
  size INTEGER NOT NULL,
  t INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS blob_t ON blob (t);
`;
/** Rows of the legacy registry scanned per import page. */
const IMPORT_PAGE = 1024;
/** The largest registry shard count (2^12; blobShardOf takes at most 12 bits). */
const BLOB_BITS_MAX = 12;

function checkId(id: unknown): asserts id is Uint8Array {
  if (!(id instanceof Uint8Array) || id.length !== 32) throw new TypeError("blobreg: id must be 32 bytes");
}

export class BlobRegDO extends DurableObject<Env> {
  /** Instance fields (not constants) so tests can override them with runInDurableObject. */
  protected clock = (): number => Date.now();
  protected params: { delta: number };
  /** b of the deployment (B = 2^b shards, §9.2); the pin in meta 'bbits' wins once it exists. */
  protected blobBits: number;

  /** The shard index, or null for the legacy registry "blobreg/v2". */
  private readonly j: number | null;
  private readonly sql: SqlStorage;
  private readonly kv: Meta;
  private readonly chain: BatchChain;
  private readonly alarmSlot: AlarmSlot;
  /** The pinned-Δ / pinned-b mismatches have been logged by this instance. */
  private deltaLogged = false;
  private bitsLogged = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.j = parseBlobRegName(ctx.id.name);
    const p = v2Params(env);
    this.params = { delta: p.delta };
    this.blobBits = blobBitsOf(p.blobShards);
    this.sql = ctx.storage.sql;
    this.sql.exec(SCHEMA);
    this.kv = new Meta(this.sql);
    this.chain = new BatchChain(this.sql, this.kv, this.j === null ? BLOBREG_CID : blobRegCid(this.j), (t) => this.leavesAt(t));
    this.alarmSlot = new AlarmSlot(ctx.storage);
    // A shard imports its rows of the legacy registry once, before it answers anything. An open batch whose alarm
    // went missing (e.g. an older version) still gets closed.
    void ctx.blockConcurrencyWhile(async () => {
      await this.alarmSlot.load();
      if (this.j !== null && this.kv.num("imported") === null) await this.importLegacy(this.j);
      this.alarmSlot.arm(this.chain.dueMs(this.delta()));
    });
  }

  register(id: Uint8Array, size: number): BlobRegistration {
    const j = this.shardOnly("register");
    checkId(id);
    if (!Number.isSafeInteger(size) || size < 0 || size > 0xffffffff) throw new TypeError("blobreg: bad size");
    this.checkRoute(id, j);
    const now = this.clock();
    const delta = this.delta();
    let created = false;
    const out = this.ctx.storage.transactionSync((): BlobRegistration => {
      const o = this.sql.exec<{ t: number; size: number }>("SELECT t, size FROM blob WHERE id = ?", ab(id)).toArray()[0];
      if (o) return { t: o.t, size: o.size, created: false };
      const hw = this.kv.num("hw");
      const t = this.chain.nextT(Math.max(tpub(now, delta), hw === null ? 0 : floorDelta(hw, delta)), delta);
      this.chain.rollTo(t);
      this.sql.exec("INSERT INTO blob (id, size, t) VALUES (?, ?, ?)", ab(id), size, t);
      this.chain.noteWrite(t);
      this.pin(delta);
      created = true;
      return { t, size, created: true };
    });
    // Same synchronous block as the commit: the batch alarm is committed together with the row.
    if (created) this.alarmSlot.arm(this.chain.dueMs(delta));
    return out;
  }

  meta(id: Uint8Array): BlobMeta {
    const j = this.shardOnly("meta");
    checkId(id);
    this.checkRoute(id, j);
    const o = this.sql.exec<{ t: number; size: number }>("SELECT t, size FROM blob WHERE id = ?", ab(id)).toArray()[0];
    if (o) return { hit: true, t: o.t, size: o.size };
    const s = secOf(this.clock());
    const delta = this.delta();
    const hw = this.kv.num("hw");
    // Raise the high-water mark first (at most one write per Δ): no later registration gets t below tpub(s).
    if (hw === null || Math.floor(s / delta) > Math.floor(hw / delta)) {
      this.ctx.storage.transactionSync(() => {
        this.kv.set("hw", s);
        this.pin(delta);
      });
    }
    return { hit: false, now: s };
  }

  head(): ComponentHead {
    const now = this.clock();
    this.ctx.storage.transactionSync(() => this.chain.closeIfDue(tpub(now, this.delta())));
    const s = this.chain.state();
    return { head: s.head, tLast: s.closedT ?? 0 };
  }

  /**
   * §9.2 "Import": the rows of the legacy registry that route to shard j under b bits, scanned by id from `after`
   * (null: the start), `limit` rows per scan; `next` is where the next page starts, null once the scan is complete.
   * Only the legacy registry answers it.
   */
  exportShard(j: number, bits: number, after: Uint8Array | null, limit: number): BlobExport {
    if (this.j !== null) throw new Error("blobreg: only the legacy registry exports");
    if (!Number.isInteger(bits) || bits < 0 || bits > BLOB_BITS_MAX) throw new RangeError("exportShard: bad bits");
    if (!Number.isInteger(j) || j < 0 || j >= 2 ** bits) throw new RangeError("exportShard: bad shard");
    if (after !== null) checkId(after);
    if (!Number.isInteger(limit) || limit < 1 || limit > 4096) throw new RangeError("exportShard: bad limit");
    const keys = serverKeys(this.env);
    if (!keys) throw new Error("server misconfigured: ROUTE_KEY missing or malformed");
    type R = { id: ArrayBuffer; size: number; t: number };
    const scanned =
      after === null
        ? this.sql.exec<R>("SELECT id, size, t FROM blob ORDER BY id LIMIT ?", limit).toArray()
        : this.sql.exec<R>("SELECT id, size, t FROM blob WHERE id > ? ORDER BY id LIMIT ?", ab(after), limit).toArray();
    const rows = scanned.flatMap((r) => {
      const id = new Uint8Array(r.id);
      return blobShardOf(keys.blobKey, id, bits) === j ? [{ id, size: r.size, t: r.t }] : [];
    });
    const next = scanned.length < limit ? null : new Uint8Array(scanned[scanned.length - 1].id);
    return { rows, next, hw: this.kv.num("hw"), lastT: this.kv.num("last_t") };
  }

  /** Batch close (§9.2 "maintain the open batch exactly as the ShardDO does"). */
  async alarm(): Promise<void> {
    this.alarmSlot.fired();
    const now = this.clock();
    const delta = this.delta();
    this.ctx.storage.transactionSync(() => this.chain.closeIfDue(tpub(now, delta)));
    const due = this.chain.dueMs(delta);
    // Never re-arm in the past (a clock that stepped back would otherwise spin the alarm).
    if (due !== null) this.alarmSlot.arm(Math.max(due, now + 1000));
  }

  // ───────────── internals ─────────────

  /** The legacy registry is read-only: the Worker only addresses the shards. */
  private shardOnly(what: string): number {
    if (this.j === null) throw new Error(`blobreg: the legacy registry is read-only (${what})`);
    return this.j;
  }

  /** b of this shard: the pinned value, or the deployment's until the first write pins it. */
  private bits(): number {
    const pinned = this.kv.num("bbits");
    if (pinned === null) return this.blobBits;
    if (pinned !== this.blobBits && !this.bitsLogged) {
      this.bitsLogged = true;
      const msg = "blobreg: BLOBREG_SHARDS differs from the shard count pinned at the first write; keeping the pinned value";
      console.error(JSON.stringify({ msg, pinned, env: this.blobBits }));
    }
    return pinned;
  }

  /** §9.2: an id that routes to another shard is a configuration error (B changed), never answered. */
  private checkRoute(id: Uint8Array, j: number): void {
    const keys = serverKeys(this.env);
    if (!keys) throw new Error("server misconfigured: ROUTE_KEY missing or malformed");
    if (blobShardOf(keys.blobKey, id, this.bits()) !== j) {
      throw new Error("blobreg: id routed to another shard (BLOBREG_SHARDS changed?)");
    }
  }

  /**
   * Δ of the registry: the value pinned by the first write, the deployment parameter before that. A deployment Δ
   * that differs from the pinned one is logged once per instance; the pinned value always wins.
   */
  private delta(): number {
    const pinned = this.kv.num("delta");
    if (pinned === null) return this.params.delta;
    if (pinned !== this.params.delta && !this.deltaLogged) {
      this.deltaLogged = true;
      const msg = "blobreg: DELTA_S differs from the pinned delta; keeping the pinned value";
      console.error(JSON.stringify({ msg, pinned, env: this.params.delta }));
    }
    return pinned;
  }

  /** Pins Δ and b on the first write (inside the write's transaction). */
  private pin(delta: number): void {
    if (this.kv.num("delta") === null) this.kv.set("delta", delta);
    if (this.kv.num("bbits") === null) this.kv.set("bbits", this.blobBits);
  }

  /** The one-time import of this shard's rows from the legacy registry (constructor, inside blockConcurrencyWhile). */
  private async importLegacy(j: number): Promise<void> {
    const legacy = blobRegLegacyStub(this.env);
    const bits = this.blobBits;
    let after: Uint8Array | null = null;
    let n = 0;
    let hw: number | null = null;
    let lastT: number | null = null;
    for (;;) {
      const page = (await legacy.exportShard(j, bits, after, IMPORT_PAGE)) as BlobExport;
      this.ctx.storage.transactionSync(() => {
        for (const r of page.rows) this.sql.exec("INSERT OR IGNORE INTO blob (id, size, t) VALUES (?, ?, ?)", ab(r.id), r.size, r.t);
      });
      n += page.rows.length;
      hw = page.hw;
      lastT = page.lastT;
      if (page.next === null) break;
      after = page.next;
    }
    this.ctx.storage.transactionSync(() => {
      if (hw !== null && (this.kv.num("hw") ?? -1) < hw) this.kv.set("hw", hw);
      if (lastT !== null && (this.kv.num("last_t") ?? -1) < lastT) this.kv.set("last_t", lastT);
      if (this.kv.num("bbits") === null) this.kv.set("bbits", bits);
      this.kv.set("imported", 1);
    });
    if (n > 0) console.error(JSON.stringify({ msg: "blobreg: imported the first release's registrations", shard: j, rows: n }));
  }

  /** Leaves of batch t0, ordered by H(id). */
  private leavesAt(t0: number): Uint8Array[] {
    return this.sql
      .exec<{ id: ArrayBuffer; size: number }>("SELECT id, size FROM blob WHERE t = ?", t0)
      .toArray()
      .map((r) => {
        const id = new Uint8Array(r.id);
        return { h: H(id), leaf: leafBlob(id, r.size, t0) };
      })
      .sort((a, b) => byteCmp(a.h, b.h))
      .map((x) => x.leaf);
  }
}
