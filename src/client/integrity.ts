// Integrity (docs/PROTOCOL.md §12): the checkpoint pinned per browser and verified on every catch-up (rewrite and
// rollback, persisted in localStorage), the session map of verified checkpoints that the `ck` split-view check reads,
// the immutability of every row this session saw, and receipts. Lane omission (`prev` / `prevh`) is checked where
// rows are applied (messaging.ts) with the texts defined here. Every finding is a sticky critical warning; nothing is
// fatal (§12.7).
import * as P from "~/lib/proto";
import type { Api } from "./api";

type Bytes = Uint8Array;

export const CKPT_KEY = "segv.ckpt";
export const KEY_CHANGED = "the server's signing key changed";
export const rolledBack = (stored: number, latest: number): string =>
  `the server's log is shorter than what this device verified before (#${stored} > #${latest}): it was rolled back`;
export const rewritten = (q: number): string =>
  `the server's log differs from what this device verified before at checkpoint #${q}: history was rewritten`;
export const CHANGED_ENTRY = "the server changed a stored entry: history was rewritten";
export const BAD_RECEIPT = "the server returned an invalid receipt";
export const splitView = (who: string): string =>
  `split view: ${who} saw a different log than this device — the server may be lying to one of you`;
export const hiding = (who: string): string => `the server is hiding messages from ${who}`;
export const different = (who: string): string =>
  `the server is showing different messages from ${who} to different members`;

/** Checkpoints are made at most once per minute (§9.5). */
const CKPT_PERIOD_MS = 60_000;
/** A stored checkpoint older than this may be replaced without the range (§12.3 step 4). */
const SKIP_AFTER_MS = 30 * 86_400_000;
/** The session map keeps the verified checkpoints of the last 2 hours (§12.3 step 5). */
const MAP_SECONDS = 7200;
const RANGE_LIMIT = 1440;

/** The persisted pin: `{"k": srvKey, "q": q, "C": b64u(C_q), "at": client ms}` (§12.3). */
interface Stored {
  k: string;
  q: number;
  C: string;
  at: number;
}

export interface CkptLatest {
  q: number;
  sec: number;
  C: Bytes;
  sig: Bytes;
}

export interface CkptRange {
  from: { q: number; C: Bytes };
  entries: { q: number; sec: number; hd: Bytes }[];
  latest: { q: number; C: Bytes; sig: Bytes };
}

export interface IntegrityHost {
  api: Api;
  /** the browser's localStorage, or null where it cannot be used */
  storage(): Storage | null;
  /** the client's wall clock (ms) */
  wall(): number;
  critical(text: string): void;
  /** the verified head moved */
  onHead(q: number, C: Bytes): void;
}

function readStored(s: Storage | null): Stored | null {
  try {
    const raw = s?.getItem(CKPT_KEY);
    if (!raw) return null;
    const x = JSON.parse(raw) as Partial<Stored>;
    if (
      typeof x.k !== "string" ||
      !Number.isSafeInteger(x.q) ||
      typeof x.C !== "string" ||
      !Number.isFinite(x.at)
    )
      return null;
    P.fromB64u(x.C);
    return x as Stored;
  } catch {
    return null;
  }
}

function writeStored(s: Storage | null, x: Stored): void {
  try {
    s?.setItem(CKPT_KEY, JSON.stringify(x));
  } catch {
    /* a browser that refuses storage keeps the session's verification only */
  }
}

/** The checkpoint chain as this session verified it (§12.3), and the split-view check of §12.4. */
export class Checkpoints {
  /** verified checkpoints of the last 2 hours: q → {C, sec} */
  private readonly map = new Map<number, { C: Bytes; sec: number }>();
  latest: { q: number; C: Bytes } | null = null;
  /** a rewrite was found: the stored value is kept and never advanced again in this session */
  private stuck = false;
  private readonly splitWarned = new Set<string>();
  /** rows whose `ckq` is above the latest verified q: checked again after the next verification */
  private waiting: { who: string; ckq: number; ck16: Bytes }[] = [];
  private running: Promise<void> | null = null;

  constructor(private readonly h: IntegrityHost) {}

  /** The `ck` fields of a row this device writes: the latest verified checkpoint, or (0, ZERO16). */
  ck(): { ckq: number; ck16: Bytes } {
    return this.latest
      ? { ckq: this.latest.q, ck16: P.t16(this.latest.C) }
      : { ckq: 0, ck16: P.ZERO16 };
  }

  /** §12.3 steps 1–5, once at a time. */
  verify(): Promise<void> {
    this.running ??= this.run().finally(() => {
      this.running = null;
    });
    return this.running;
  }

  private remember(q: number, C: Bytes, sec: number): void {
    this.map.set(q, { C, sec });
    const floor = sec - MAP_SECONDS;
    for (const [k, v] of this.map) if (v.sec < floor && k !== q) this.map.delete(k);
  }

  private setHead(q: number, C: Bytes): void {
    if (this.latest && this.latest.q === q && P.equalBytes(this.latest.C, C)) return;
    this.latest = { q, C };
    this.h.onHead(q, C);
  }

  private async run(): Promise<void> {
    const p = await this.h.api.params();
    const storage = this.h.storage();
    const stored = readStored(storage);
    if (stored && stored.k !== p.srvKey) {
      this.h.critical(KEY_CHANGED);
      return; // nothing signed under another key is verified
    }
    const key = P.fromB64u(stored?.k ?? p.srvKey);
    const latest = await this.h.api.ckptLatest();
    if (!latest) return; // no checkpoint yet
    if (!P.verify(latest.sig, P.ckptSigMsg(latest.q, latest.C), key)) return;
    const now = this.h.wall();
    if (!stored) {
      writeStored(storage, { k: P.b64u(key), q: latest.q, C: P.b64u(latest.C), at: now });
      this.remember(latest.q, latest.C, latest.sec);
      this.setHead(latest.q, latest.C);
      this.recheck();
      return;
    }
    const storedC = P.fromB64u(stored.C);
    if (latest.q < stored.q) {
      this.h.critical(rolledBack(stored.q, latest.q));
      return;
    }
    if (latest.q === stored.q) {
      if (!P.equalBytes(latest.C, storedC)) {
        this.h.critical(rewritten(stored.q));
        this.stuck = true;
        return;
      }
      this.remember(latest.q, latest.C, latest.sec);
      this.setHead(latest.q, latest.C);
      this.recheck();
      return;
    }
    if (this.stuck) return;
    if (latest.q - stored.q > (now - stored.at) / CKPT_PERIOD_MS + 60) {
      this.h.critical(rewritten(stored.q));
      this.stuck = true;
      return;
    }
    if (now - stored.at > SKIP_AFTER_MS) {
      writeStored(storage, { k: stored.k, q: latest.q, C: P.b64u(latest.C), at: now });
      this.remember(latest.q, latest.C, latest.sec);
      this.setHead(latest.q, latest.C);
      this.recheck();
      return;
    }
    // The range from the stored checkpoint, recomputed forward; its end must be the (signed) latest.
    let after = stored.q;
    let C = storedC;
    let end: { q: number; C: Bytes } | null = null;
    for (let page = 0; page < 1000 && !end; page++) {
      const r = await this.h.api.ckptRange(after, RANGE_LIMIT);
      if (!r || r.from.q !== after || !P.equalBytes(r.from.C, C)) {
        this.h.critical(rewritten(stored.q));
        this.stuck = true;
        return;
      }
      if (!P.verify(r.latest.sig, P.ckptSigMsg(r.latest.q, r.latest.C), key)) return;
      for (const e of r.entries) {
        if (e.q !== after + 1) {
          this.h.critical(rewritten(stored.q));
          this.stuck = true;
          return;
        }
        C = P.ckptC(C, e.q, e.sec, e.hd);
        after = e.q;
        this.remember(e.q, C, e.sec);
      }
      if (after >= r.latest.q) {
        if (after !== r.latest.q || !P.equalBytes(C, r.latest.C)) {
          this.h.critical(rewritten(stored.q));
          this.stuck = true;
          return;
        }
        end = { q: after, C };
      } else if (r.entries.length === 0) return; // a range that does not move: try again at the next catch-up
    }
    if (!end) return;
    writeStored(storage, { k: stored.k, q: end.q, C: P.b64u(end.C), at: now });
    this.setHead(end.q, end.C);
    this.recheck();
  }

  /**
   * §12.4 for a valid row of `who` (its "@handle") with `ckq > 0`: a checkpoint in the session map whose t16 differs
   * from `ck16` is a split view (one warning per sender); one above the latest is checked after the next
   * verification; one older than the map is not compared.
   */
  checkCk(who: string, ckq: number, ck16: Bytes): void {
    if (ckq === 0) return;
    if (!this.latest || ckq > this.latest.q) {
      if (this.waiting.length < 256) this.waiting.push({ who, ckq, ck16 });
      void this.verify().catch(() => {});
      return;
    }
    const x = this.map.get(ckq);
    if (!x || P.equalBytes(P.t16(x.C), ck16) || this.splitWarned.has(who)) return;
    this.splitWarned.add(who);
    this.h.critical(splitView(who));
  }

  private recheck(): void {
    const w = this.waiting;
    this.waiting = [];
    for (const x of w)
      if (this.latest && x.ckq <= this.latest.q) this.checkCk(x.who, x.ckq, x.ck16);
  }
}

/**
 * §12.1: `(H(body), t, cls)` of every row this session fetched, received or wrote, by `(E, label)`; a different body,
 * `t` or class later is the critical "changed a stored entry" warning (once).
 */
export class RowMemory {
  private readonly rows = new Map<string, { h: Bytes | null; t: number; cls: number }>();
  private warned = false;

  constructor(private readonly critical: (text: string) => void) {}

  observe(E: number, label: Bytes, t: number, cls: number, body: Bytes | null): void {
    const k = `${E}:${P.b64u(label)}`;
    const h = body ? P.H(body) : null;
    const had = this.rows.get(k);
    if (!had) {
      this.rows.set(k, { h, t, cls });
      return;
    }
    const changed =
      had.t !== t || had.cls !== cls || (h !== null && had.h !== null && !P.equalBytes(h, had.h));
    if (changed) {
      if (!this.warned) this.critical(CHANGED_ENTRY);
      this.warned = true;
      return;
    }
    if (h && !had.h) had.h = h;
  }
}
