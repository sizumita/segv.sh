/**
 * BlobRegDO — the create-only blob registry (docs/PROTOCOL-v2.md §8.2, §9.2). One instance, "blobreg/v2".
 *
 *  - register(id, size): the first registration wins forever. A new one gets
 *    t = max(tpub(now), last_t, tpub(hw), closed_t + Δ) and joins the open Δ batch (batch.ts, like the shard).
 *  - meta(id): HIT {t, size}, or MISS {now: sec(now)} after raising the high-water mark `hw` (at most one write
 *    per Δ). Every later registration therefore gets t ≥ tpub(every now ever reported), even after a clock step
 *    back, which makes a MISS with now ≥ t_row final for §6.4(g).
 *  - Batches commit leaf(enc("segv.sh/v2/leaf/blob", H(id), u32 size, u32 t)) ordered by H(id); head() closes a
 *    due batch and returns the head. There is no enumeration RPC.
 *  - Δ is pinned in meta 'delta' by the first write (registration or high-water mark), like the ShardDO's, and the
 *    pinned value is used from then on: the registry spans eras, and mixing Δ granularities would let a later
 *    registration fall below a MISS already reported as final (§6.4(g)). A deployment Δ that differs is logged
 *    once per instance and ignored.
 *
 * Time is read through the protected `clock` field and the deployment Δ through `params`, so tests can override them.
 */
import { DurableObject } from "cloudflare:workers";
import { BLOBREG_CID, H, byteCmp, floorDelta, leafBlob, secOf, tpub } from "../../lib/proto2";
import { AlarmSlot, BATCH_SCHEMA, BatchChain, Meta, ab } from "./batch";
import { v2Params } from "./env";
import type { BlobMeta, BlobRegistration, ComponentHead } from "./types";

const SCHEMA = `${BATCH_SCHEMA}
CREATE TABLE IF NOT EXISTS blob (
  id BLOB PRIMARY KEY CHECK (length(id) = 32),
  size INTEGER NOT NULL,
  t INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS blob_t ON blob (t);
`;

function checkId(id: unknown): asserts id is Uint8Array {
  if (!(id instanceof Uint8Array) || id.length !== 32) throw new TypeError("blobreg: id must be 32 bytes");
}

export class BlobRegDO extends DurableObject<Env> {
  /** Instance fields (not constants) so tests can override them with runInDurableObject. */
  protected clock = (): number => Date.now();
  protected params: { delta: number };

  private readonly sql: SqlStorage;
  private readonly kv: Meta;
  private readonly chain: BatchChain;
  private readonly alarmSlot: AlarmSlot;
  /** The pinned-Δ mismatch has been logged by this instance. */
  private deltaLogged = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.params = { delta: v2Params(env).delta };
    this.sql = ctx.storage.sql;
    this.sql.exec(SCHEMA);
    this.kv = new Meta(this.sql);
    this.chain = new BatchChain(this.sql, this.kv, BLOBREG_CID, (t) => this.leavesAt(t));
    this.alarmSlot = new AlarmSlot(ctx.storage);
    // An open batch whose alarm went missing (e.g. an older version) still gets closed.
    void ctx.blockConcurrencyWhile(async () => {
      await this.alarmSlot.load();
      this.alarmSlot.arm(this.chain.dueMs(this.delta()));
    });
  }

  register(id: Uint8Array, size: number): BlobRegistration {
    checkId(id);
    if (!Number.isSafeInteger(size) || size < 0 || size > 0xffffffff) throw new TypeError("blobreg: bad size");
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
      this.pinDelta(delta);
      created = true;
      return { t, size, created: true };
    });
    // Same synchronous block as the commit: the batch alarm is committed together with the row.
    if (created) this.alarmSlot.arm(this.chain.dueMs(delta));
    return out;
  }

  meta(id: Uint8Array): BlobMeta {
    checkId(id);
    const o = this.sql.exec<{ t: number; size: number }>("SELECT t, size FROM blob WHERE id = ?", ab(id)).toArray()[0];
    if (o) return { hit: true, t: o.t, size: o.size };
    const s = secOf(this.clock());
    const delta = this.delta();
    const hw = this.kv.num("hw");
    // Raise the high-water mark first (at most one write per Δ): no later registration gets t below tpub(s).
    if (hw === null || Math.floor(s / delta) > Math.floor(hw / delta)) {
      this.ctx.storage.transactionSync(() => {
        this.kv.set("hw", s);
        this.pinDelta(delta);
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

  /** Pins Δ on the first write (inside the write's transaction). */
  private pinDelta(delta: number): void {
    if (this.kv.num("delta") === null) this.kv.set("delta", delta);
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
