/**
 * CheckpointDO fake (docs/PROTOCOL.md §9.5, §12.3). There is no alarm: `tick()` stands for the DO's 60 s alarm
 * (tests and `settle` call it). It does nothing until at least CKPT_PERIOD_MS of world clock have passed since the
 * last checkpoint, so q grows at most once per 60 s as in production (§12.3 step 4 relies on it); then it collects
 * the heads and signs a new checkpoint when `hd` changed, with sec = max(secOf(now), previous sec).
 * `tick({force: true})` skips the 60 s floor (an attacker / misbehaving server minting faster).
 *
 * Heads: shard/{E_now}/0 and inbox/{E_now}/0; the previous era's shard and inbox (only when E_now − 1 ≥
 * max(E_FIRST, 0)) until they are sealed / ended and their final head appeared once; blobreg read at most once per
 * UTC hour of the world clock; the dirlog head.
 *
 * `forkAt(q)` makes the server serve a rewritten chain from checkpoint q on (one head of every entry ≥ q changes,
 * `hd`, `C` and the signatures are recomputed); `forkAt(null)` serves the real chain again.
 */
import {
  BLOBREG_CID,
  DIRLOG_CID,
  H,
  ZERO32,
  ckptC,
  ckptHd,
  ckptSigMsg,
  enc,
  equalBytes,
  era,
  inboxCid,
  secOf,
  shardCid,
  sign,
  type Bytes,
} from "../../../src/lib/proto";

export interface CkptHead {
  cid: string;
  head: Bytes;
}

export interface CkptEntry {
  q: number;
  sec: number;
  hd: Bytes;
  C: Bytes;
  sig: Bytes;
  heads: CkptHead[];
}

/** The CheckpointDO's alarm period: at most one new q per this much world clock. */
export const CKPT_PERIOD_MS = 60_000;

/** Where the checkpoint reads its heads from. */
export interface CkptSources {
  now(): number;
  /** E_FIRST (the previous era's components are collected only when E_now − 1 ≥ max(E_FIRST, 0)) */
  efirst(): number;
  shardHead(E: number): { head: Bytes; sealed: boolean };
  inboxHead(E: number): { head: Bytes; ended: boolean };
  blobregHead(): Bytes;
  dirlogHead(): Bytes;
}

export class FakeCheckpoints {
  private readonly real: CkptEntry[] = [];
  private forkFrom: number | null = null;
  private served: CkptEntry[] | null = null;
  private readonly finalSeen = new Set<string>();
  private blobHour = -1;
  private blobHead: Bytes = ZERO32;
  /** world time of the newest real checkpoint */
  private lastAt = 0;

  constructor(
    private readonly src: CkptSources,
    private readonly srvSk: Bytes,
  ) {}

  /**
   * The alarm: builds and signs C_q from the current heads and returns it. Null (no new q) when less than
   * CKPT_PERIOD_MS of world clock passed since the last checkpoint (nothing is collected then), unless `force`, or
   * when `hd` is unchanged.
   */
  tick(opts: { force?: boolean } = {}): CkptEntry | null {
    const now = this.src.now();
    const last = this.real[this.real.length - 1];
    if (last && !opts.force && now - this.lastAt < CKPT_PERIOD_MS) return null;
    const heads = this.collect(now);
    const hd = ckptHd(heads);
    if (last && equalBytes(last.hd, hd)) return null;
    const q = (last?.q ?? 0) + 1;
    const sec = Math.max(secOf(now), last?.sec ?? 0);
    const C = ckptC(last?.C ?? ZERO32, q, sec, hd);
    const entry: CkptEntry = { q, sec, hd, C, sig: sign(ckptSigMsg(q, C), this.srvSk), heads };
    this.real.push(entry);
    this.lastAt = now;
    this.served = null;
    return this.chain()[q - 1];
  }

  /** Serve a rewritten chain from q on (null: the real chain). */
  forkAt(q: number | null): void {
    this.forkFrom = q;
    this.served = null;
  }

  /** The latest served checkpoint, or null when there is none yet. */
  latest(): CkptEntry | null {
    const c = this.chain();
    return c[c.length - 1] ?? null;
  }

  /** The served checkpoint q, or null. */
  get(q: number): CkptEntry | null {
    return Number.isInteger(q) && q >= 1 ? (this.chain()[q - 1] ?? null) : null;
  }

  /** The served C_q (ZERO32 for q = 0). */
  C(q: number): Bytes | null {
    return q === 0 ? ZERO32 : (this.get(q)?.C ?? null);
  }

  /** The real (unforked) chain, for assertions. */
  realChain(): readonly CkptEntry[] {
    return this.real;
  }

  get q(): number {
    return this.real.length;
  }

  private chain(): CkptEntry[] {
    if (this.served) return this.served;
    const from = this.forkFrom;
    if (from === null || from > this.real.length) return (this.served = this.real);
    const out = this.real.slice(0, Math.max(0, from - 1));
    let prevC = out.length ? out[out.length - 1].C : ZERO32;
    for (const e of this.real.slice(Math.max(0, from - 1))) {
      const heads = e.heads.map((h, i) =>
        i === 0 ? { cid: h.cid, head: H(enc("segv.sh/test/fork", h.head)) } : h,
      );
      const hd = ckptHd(heads);
      const C = ckptC(prevC, e.q, e.sec, hd);
      out.push({ q: e.q, sec: e.sec, hd, C, sig: sign(ckptSigMsg(e.q, C), this.srvSk), heads });
      prevC = C;
    }
    return (this.served = out);
  }

  private collect(now: number): CkptHead[] {
    const E = era(now);
    const heads: CkptHead[] = [
      { cid: shardCid(E, 0), head: this.src.shardHead(E).head },
      { cid: inboxCid(E, 0), head: this.src.inboxHead(E).head },
    ];
    if (E - 1 >= Math.max(this.src.efirst(), 0)) {
      const sh = this.src.shardHead(E - 1);
      this.previous(heads, shardCid(E - 1, 0), sh.head, sh.sealed);
      const ib = this.src.inboxHead(E - 1);
      this.previous(heads, inboxCid(E - 1, 0), ib.head, ib.ended);
    }
    const hour = Math.floor(now / 3_600_000);
    if (hour > this.blobHour) {
      this.blobHour = hour;
      this.blobHead = this.src.blobregHead();
    }
    heads.push({ cid: BLOBREG_CID, head: this.blobHead });
    heads.push({ cid: DIRLOG_CID, head: this.src.dirlogHead() });
    // Sorted by cid in byte order (the cids are ASCII, so string order is byte order).
    return heads.sort((a, b) => (a.cid < b.cid ? -1 : a.cid > b.cid ? 1 : 0));
  }

  /** The previous era's component is included until it is final and its final head appeared once. */
  private previous(heads: CkptHead[], cid: string, head: Bytes, final: boolean): void {
    if (final && this.finalSeen.has(cid)) return;
    if (final) this.finalSeen.add(cid);
    heads.push({ cid, head });
  }
}
