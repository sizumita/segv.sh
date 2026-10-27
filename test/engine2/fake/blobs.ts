/**
 * BlobRegDO fake (docs/PROTOCOL-v2.md §8.2, §9.2) and the R2 blob store (§10.7).
 *
 * BlobReg: create-only `id → {t, size}` with `t = max(tpub(now), last_t, tpub(hw), closed_t + Δ)`, the high-water
 * mark `hw` raised by every MISS, and the batch head chain (leaves ordered by H(id)). It reads the world clock
 * (`now`), never the shard clock, so `world.shardLagMs` separates the two.
 *
 * Test controls: `forceT(id, t)` (forge a late registration), `missNow(fn)` (override the `now` a MISS reports),
 * and on the store `failGet(id, n)` (blob GET answers 503 n times).
 */
import {
  H,
  ZERO32,
  b64u,
  byteCmp,
  floorDelta,
  fromB64u,
  leafBlob,
  mth,
  nextHead,
  secOf,
  tpub,
  BLOBREG_CID,
  type Bytes,
} from "../../../src/lib/proto2";
import type { WorldCtx } from "./common";

export interface BlobRegEntry {
  readonly id: Bytes;
  readonly idB: string;
  size: number;
  t: number;
}

export type BlobMeta = { hit: true; t: number; size: number } | { hit: false; now: number };

export class FakeBlobReg {
  private readonly regs = new Map<string, BlobRegEntry>();
  /** high-water mark: the largest `now` (seconds since T0) a MISS ever reported, or null */
  hw: number | null = null;
  private lastT: number | null = null;
  private closedT: number | null = null;
  private headV: Bytes = ZERO32;
  readonly batches: { t: number; n: number; root: Bytes; head: Bytes }[] = [];
  private readonly open = new Map<number, BlobRegEntry[]>();
  private missHook: ((idB: string, now: number) => number | null | undefined) | null = null;

  constructor(private readonly w: WorldCtx) {}

  /** BlobRegDO.register: the first registration wins forever. */
  register(id: Bytes, size: number): { t: number; size: number; created: boolean } {
    this.closeDue();
    const idB = b64u(id);
    const o = this.regs.get(idB);
    if (o) return { t: o.t, size: o.size, created: false };
    const { delta } = this.w.params;
    const t = Math.max(
      tpub(this.w.now(), delta),
      this.lastT ?? 0,
      this.hw !== null ? floorDelta(this.hw, delta) : 0,
      this.closedT !== null ? this.closedT + delta : 0,
    );
    this.closeBefore(t);
    const e: BlobRegEntry = { id: id.slice(), idB, size, t };
    this.regs.set(idB, e);
    let g = this.open.get(t);
    if (!g) this.open.set(t, (g = []));
    g.push(e);
    this.lastT = t;
    this.w.bumpWrites();
    return { t, size, created: true };
  }

  /** BlobRegDO.meta: HIT `{t, size}`, or MISS `{now}` after raising the high-water mark (at most once per Δ). */
  meta(idB: string): BlobMeta {
    this.closeDue();
    const o = this.regs.get(idB);
    if (o) return { hit: true, t: o.t, size: o.size };
    const real = secOf(this.w.now());
    const now = this.missHook?.(idB, real) ?? real;
    const { delta } = this.w.params;
    if (this.hw === null || Math.floor(now / delta) > Math.floor(this.hw / delta)) this.hw = now;
    return { hit: false, now };
  }

  get(idB: string): BlobRegEntry | undefined {
    return this.regs.get(idB);
  }

  /** BlobRegDO.head (closes due batches). */
  head(): { head: Bytes; tLast: number } {
    this.closeDue();
    return { head: this.headV, tLast: this.closedT ?? 0 };
  }

  /**
   * Forge a registration time: from now on `meta` reports `t` for `idB` (registering it with `size`, default the
   * stored blob's length, when it was not registered). Batch commitments are not rewritten.
   */
  forceT(idB: string, t: number, size?: number): void {
    const o = this.regs.get(idB);
    if (o) {
      o.t = t;
      if (size !== undefined) o.size = size;
      return;
    }
    this.regs.set(idB, { id: fromB64u(idB), idB, size: size ?? 0, t });
  }

  /**
   * Overrides the `now` a MISS reports. `fn(id, realNow)` returns the value to report, or null/undefined for the real
   * clock; it is called on every MISS (implement "once" in the callback). Pass null to remove it.
   */
  missNow(fn: ((idB: string, now: number) => number | null | undefined) | null): void {
    this.missHook = fn;
  }

  private closeDue(): void {
    this.closeBefore(tpub(this.w.now(), this.w.params.delta));
  }

  private closeBefore(limit: number): void {
    const due = [...this.open.keys()].filter((t) => t < limit).sort((a, b) => a - b);
    for (const t0 of due) {
      const es = this.open.get(t0)!;
      this.open.delete(t0);
      if (this.closedT !== null && t0 <= this.closedT) continue;
      const leaves = es
        .map((e) => ({ h: H(e.id), e }))
        .sort((a, b) => byteCmp(a.h, b.h))
        .map(({ e }) => leafBlob(e.id, e.size, t0));
      const root = mth(leaves);
      this.headV = nextHead(BLOBREG_CID, this.headV, t0, es.length, root);
      this.batches.push({ t: t0, n: es.length, root, head: this.headV });
      this.closedT = t0;
    }
  }
}

/** The R2 bucket: content-addressed bytes, plus the failGet knob. */
export class FakeBlobs {
  private readonly store = new Map<string, Bytes>();
  private readonly failures = new Map<string, number>();

  has(idB: string): boolean {
    return this.store.has(idB);
  }

  bytes(idB: string): Bytes | undefined {
    return this.store.get(idB);
  }

  /** Stores bytes under their own id (b64u(H(bytes))). Does not register them (see FakeWorld.putBlob). */
  put(bytes: Bytes): string {
    const idB = b64u(H(bytes));
    this.store.set(idB, bytes.slice());
    return idB;
  }

  /** Removes stored bytes (a lost object; the registration stays). */
  drop(idB: string): void {
    this.store.delete(idB);
  }

  /** The next `n` GETs of `idB` answer 503. */
  failGet(idB: string, n = 1): void {
    this.failures.set(idB, (this.failures.get(idB) ?? 0) + n);
  }

  /** Consumes one pending failure of `idB`; true when this GET must fail. */
  takeFailure(idB: string): boolean {
    const n = this.failures.get(idB) ?? 0;
    if (n <= 0) return false;
    if (n === 1) this.failures.delete(idB);
    else this.failures.set(idB, n - 1);
    return true;
  }

  get size(): number {
    return this.store.size;
  }
}
