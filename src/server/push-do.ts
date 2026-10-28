/**
 * PushDO (`push/v2`, one instance; docs/PROTOCOL.md §9.8): the registrations of the devices that turned notifications
 * on, and the pushes they get.
 *
 * - Durable storage holds the registrations only (`sub`, `tok`), keyed and sealed under PUSH_KEY, and only the daily
 *   pass writes them, a change only after its UTC day has ended: the platform keeps a 30-day point-in-time history of
 *   the storage, which must not date anything finer than a day, nor show which devices a message reached.
 * - Memory holds the day's registration changes (in effect at once) and everything a ring causes (due pushes, windows,
 *   the dedup of rings). A restart loses both; devices register again at their next start (§11.13).
 * - The alarm ticks every PUSH_TICK seconds of Unix time whatever happens, so its stored time follows the clock alone.
 *
 * Bells are never held in Maps keyed by strings: a day's changes may hold 2 000 endpoints of 256 bells, so the index
 * from a bell to the changed endpoints is open addressing over typed arrays (§9.8 "Memory").
 */
import { DurableObject } from "cloudflare:workers";
import { H, HMAC, aeadOpen, aeadSeal, concat, dec, enc, hex, t16, u16 } from "../lib/proto";
import { pushConfig, pushHostAllowed, v2Params, type PushConfig } from "./env";
import { logErr } from "./http";
import type { PushSubResult } from "./types";
import { PUSH_BELLS, VapidSigner, encryptPayload, pushPayload } from "./webpush";

type Bytes = Uint8Array;

/** Bells per endpoint (params `push.maxTokens`). */
export const PUSH_TOKENS = 256;
/** Endpoints per bell: the first ones keep their places; a ninth is left out, never evicting. */
export const PUSH_PER_BELL = 8;
/** At most one push per endpoint per this many seconds (params `push.window`). */
export const PUSH_WINDOW = 60;
/** The alarm's cadence, seconds. */
export const PUSH_TICK = 10;
/** Registrations not refreshed for more than this many days are deleted. */
export const PUSH_EXPIRY = 30;
/** Rows one alarm run's part of the daily pass may read, write or delete. */
export const PUSH_ROWS = 20_000;
/** Seconds a ring (its row and bells) is remembered, so that a retry changes nothing. */
export const RING_DEDUP = 120;

const TICK_MS = PUSH_TICK * 1000;
const WINDOW_MS = PUSH_WINDOW * 1000;
const DAY_MS = 86_400_000;
const PUSH_BATCH = 50;
const PUSH_TIMEOUT_MS = 10_000;
const RETRY_MS = 10_000;

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS sub (ep BLOB PRIMARY KEY CHECK (length(ep) = 16), box BLOB NOT NULL, day INTEGER NOT NULL) WITHOUT ROWID",
  "CREATE INDEX IF NOT EXISTS sub_day ON sub (day)",
  "CREATE TABLE IF NOT EXISTS tok (tk BLOB NOT NULL CHECK (length(tk) = 16), ep BLOB NOT NULL, PRIMARY KEY (tk, ep)) WITHOUT ROWID",
  "CREATE INDEX IF NOT EXISTS tok_ep ON tok (ep)",
];

export const dayOf = (ms: number): number => Math.floor(ms / DAY_MS);
/** The next multiple of PUSH_TICK strictly after `ms`: never the past. */
export const nextTick = (ms: number): number => (Math.floor(ms / TICK_MS) + 1) * TICK_MS;

function cmp(a: Bytes, b: Bytes): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}
const same = (a: Bytes, b: Bytes): boolean => cmp(a, b) === 0;
const key32 = (b: Bytes): number => ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
const bytes = (x: ArrayBuffer | Bytes): Bytes => (x instanceof Uint8Array ? x : new Uint8Array(x));

/** Distinct 16-byte values in ascending byte order. */
function sortedDistinct(xs: readonly Bytes[]): Bytes[] {
  const out = [...xs].sort(cmp);
  return out.filter((x, i) => i === 0 || !same(x, out[i - 1]));
}

/** Binary search for `tk` in a sorted concatenation of 16-byte values. */
function hasTk(tks: Bytes, tk: Bytes): boolean {
  let lo = 0;
  let hi = tks.length / 16 - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const c = cmp(tks.subarray(mid * 16, mid * 16 + 16), tk);
    if (c === 0) return true;
    if (c < 0) lo = mid + 1;
    else hi = mid - 1;
  }
  return false;
}

/** Open addressing from a 16-byte `ep` (a keyed hash, so uniform) to an int32, over typed arrays. */
class EpTable {
  private cap = 64;
  private keys = new Uint8Array(64 * 16);
  private vals = new Int32Array(64);
  /** 0 empty, 1 used, 2 deleted */
  private st = new Uint8Array(64);
  size = 0;
  private tombs = 0;

  private slotOf(ep: Bytes): number {
    let i = key32(ep) & (this.cap - 1);
    for (;;) {
      const s = this.st[i];
      if (s === 0) return -1;
      if (s === 1 && same(this.keys.subarray(i * 16, i * 16 + 16), ep)) return i;
      i = (i + 1) & (this.cap - 1);
    }
  }

  get(ep: Bytes): number | undefined {
    const i = this.slotOf(ep);
    return i < 0 ? undefined : this.vals[i];
  }

  set(ep: Bytes, v: number): void {
    const i = this.slotOf(ep);
    if (i >= 0) {
      this.vals[i] = v;
      return;
    }
    if ((this.size + this.tombs + 1) * 2 > this.cap) this.rehash();
    this.insert(ep, v);
  }

  delete(ep: Bytes): void {
    const i = this.slotOf(ep);
    if (i < 0) return;
    this.st[i] = 2;
    this.size--;
    this.tombs++;
  }

  /** Copies of the keys (safe to mutate the table while using them). */
  keyList(): Bytes[] {
    const out: Bytes[] = [];
    for (let i = 0; i < this.cap; i++) if (this.st[i] === 1) out.push(this.keys.slice(i * 16, i * 16 + 16));
    return out;
  }

  private insert(ep: Bytes, v: number): void {
    let i = key32(ep) & (this.cap - 1);
    while (this.st[i] === 1) i = (i + 1) & (this.cap - 1);
    if (this.st[i] === 2) this.tombs--;
    this.keys.set(ep, i * 16);
    this.vals[i] = v;
    this.st[i] = 1;
    this.size++;
  }

  private rehash(): void {
    const { keys, vals, st, cap } = this;
    let n = 64;
    while (n < (this.size + 1) * 4) n *= 2;
    this.cap = n;
    this.keys = new Uint8Array(n * 16);
    this.vals = new Int32Array(n);
    this.st = new Uint8Array(n);
    this.size = 0;
    this.tombs = 0;
    for (let i = 0; i < cap; i++) if (st[i] === 1) this.insert(keys.subarray(i * 16, i * 16 + 16), vals[i]);
  }
}

const TOMB = 0xffffffff;

/**
 * A multimap from the first 4 bytes of a bell's keyed hash to the changed registrations that hold it: (key, id + 1)
 * pairs in one Uint32Array at load ≤ 0.5. A hit is confirmed against the record's sorted hashes.
 */
class BellIndex {
  private cap = 256;
  private s = new Uint32Array(512);
  private used = 0;
  private tombs = 0;

  add(k: number, id: number): void {
    if ((this.used + this.tombs + 1) * 2 > this.cap) this.rehash();
    this.put(k, id);
  }

  remove(k: number, id: number): void {
    let i = k & (this.cap - 1);
    for (;;) {
      const v = this.s[2 * i + 1];
      if (v === 0) return;
      if (v !== TOMB && v === id + 1 && this.s[2 * i] === k) {
        this.s[2 * i + 1] = TOMB;
        this.used--;
        this.tombs++;
        return;
      }
      i = (i + 1) & (this.cap - 1);
    }
  }

  forEach(k: number, f: (id: number) => void): void {
    let i = k & (this.cap - 1);
    for (;;) {
      const v = this.s[2 * i + 1];
      if (v === 0) return;
      if (v !== TOMB && this.s[2 * i] === k) f(v - 1);
      i = (i + 1) & (this.cap - 1);
    }
  }

  private put(k: number, id: number): void {
    let i = k & (this.cap - 1);
    for (;;) {
      const v = this.s[2 * i + 1];
      if (v === 0 || v === TOMB) {
        if (v === TOMB) this.tombs--;
        this.s[2 * i] = k;
        this.s[2 * i + 1] = id + 1;
        this.used++;
        return;
      }
      i = (i + 1) & (this.cap - 1);
    }
  }

  private rehash(): void {
    const old = this.s;
    const oldCap = this.cap;
    let n = 256;
    while (n < (this.used + 1) * 4) n *= 2;
    this.cap = n;
    this.s = new Uint32Array(2 * n);
    this.used = 0;
    this.tombs = 0;
    for (let i = 0; i < oldCap; i++) {
      const v = old[2 * i + 1];
      if (v !== 0 && v !== TOMB) this.put(old[2 * i], v - 1);
    }
  }
}

/** A registration, or a change of keys or bells, made today or on a day whose pass has not written it yet. */
interface RegRecord {
  ep: Bytes;
  day: number;
  endpoint: string;
  p256dh: Bytes;
  auth: Bytes;
  /** the kept bells' keyed hashes, sorted, 16 bytes each */
  tks: Bytes;
  /** whether a stored row exists for `ep` (it then gets replaced) */
  stored: boolean;
}

type Change = { kind: "reg"; id: number; rec: RegRecord; day: number } | { kind: "refresh" | "del"; day: number };

/** Per endpoint with a push in flight. Never written. */
interface PushState {
  ep: Bytes;
  /** when its last push was sent (or first attempted, when dropped) */
  last: number | null;
  due: number | null;
  tries: number;
  /** the first attempt of the current push */
  first: number;
  /** the endpoint's bells that rang it since its last push, newest first, at most PUSH_BELLS (§9.8 `rang`) */
  rang: Bytes[];
}

/** `fresh` in front of `rang`, without repeats, at most PUSH_BELLS (§9.8 `ring` step 2). */
function rangWith(fresh: readonly Bytes[], rang: readonly Bytes[]): Bytes[] {
  const out: Bytes[] = [];
  const seen = new Set<string>();
  for (const b of [...fresh, ...rang]) {
    const k = hex(b);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(b);
    if (out.length === PUSH_BELLS) break;
  }
  return out;
}

interface SubRow {
  ep: ArrayBuffer;
  box: ArrayBuffer;
  day: number;
  [k: string]: SqlStorageValue;
}

interface Target {
  endpoint: string;
  p256dh: Bytes;
  auth: Bytes;
}

type PassOp =
  | { k: "delete"; ep: Bytes; stored: boolean }
  | { k: "day"; ep: Bytes; day: number }
  | { k: "write"; ep: Bytes; rec: RegRecord; stored: boolean }
  | { k: "forget"; ep: Bytes };

/** One committed part of a daily pass (kept for tests and logs: rows only, never an endpoint). */
export interface PassPart {
  rows: number;
  endpoints: number;
  first: string | null;
  last: string | null;
}

const epOf = (key: Bytes, endpoint: string): Bytes => t16(HMAC(key, enc("segv.sh/v2/push/ep", endpoint)));
const tkOf = (key: Bytes, bell: Bytes): Bytes => t16(HMAC(key, enc("segv.sh/v2/push/bell", bell)));
const boxAad = (ep: Bytes): Bytes => enc("segv.sh/v2/push/sub", ep);
const sealBox = (key: Bytes, ep: Bytes, t: Target): Bytes => aeadSeal(key, enc(t.endpoint, t.p256dh, t.auth), boxAad(ep));

function openBox(key: Bytes, ep: Bytes, box: Bytes): Target | null {
  try {
    const [e, p, a] = dec(aeadOpen(key, box, boxAad(ep)), 3);
    if (p.length !== 65 || a.length !== 16) return null;
    return { endpoint: new TextDecoder("utf-8", { fatal: true }).decode(e), p256dh: p.slice(), auth: a.slice() };
  } catch {
    return null;
  }
}

/** retry-after in delta-seconds (an HTTP date counts as absent). */
function retryAfterS(v: string | null): number | null {
  return v !== null && /^\d{1,6}$/.test(v.trim()) ? Number(v.trim()) : null;
}

export class PushDO extends DurableObject<Env> {
  // Test hooks (instance fields, overridable with runInDurableObject).
  clock = (): number => Date.now();
  rand = (): number => Math.random();
  sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
  fetcher = (url: string, init: RequestInit): Promise<Response> => fetch(url, init);
  pushRows = PUSH_ROWS;
  /** Runs inside each part's transaction, before its writes (a test injects a failure here). */
  beforeCommit: (() => void) | null = null;
  /** The parts committed since the object started (the last 64). */
  readonly parts: PassPart[] = [];

  private readonly sql: SqlStorage;
  private storedCount: number;

  // The day's changes: ep → reg record id (≥ 0), or −1 − (day·2 + kind) for a refresh (kind 0) or deletion (kind 1).
  private readonly changes = new EpTable();
  private readonly regs: (RegRecord | null)[] = [];
  private readonly freeIds: number[] = [];
  private readonly bells = new BellIndex();
  private regCount = 0;
  private newRegs = 0;
  private dels = 0;

  private readonly pushes = new Map<string, PushState>();
  private readonly dedup = new Map<string, number>();

  // The daily pass: the day it started, the last committed ep, and whether it went through every endpoint.
  private passDay: number | null = null;
  private passPos: Bytes | null = null;
  private passDone = false;

  private signer: { cfg: PushConfig; s: VapidSigner } | null = null;
  private running: Promise<void> | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    for (const s of SCHEMA) this.sql.exec(s);
    this.storedCount = this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM sub").one().n;
    // The only write at the time of an event: re-arm a lost alarm (or arm the first one). Otherwise nothing.
    void ctx.blockConcurrencyWhile(async () => {
      if ((await ctx.storage.getAlarm()) === null) await ctx.storage.setAlarm(nextTick(this.clock()));
    });
  }

  private config(): PushConfig | null {
    return pushConfig(this.env);
  }

  // ───────────── the day's changes ─────────────

  private changeOf(ep: Bytes): Change | undefined {
    const v = this.changes.get(ep);
    if (v === undefined) return undefined;
    if (v >= 0) {
      const rec = this.regs[v];
      if (!rec) throw new Error("push: dangling change");
      return { kind: "reg", id: v, rec, day: rec.day };
    }
    const x = -1 - v;
    return { kind: x & 1 ? "del" : "refresh", day: x >> 1 };
  }

  /** Replaces ep's change (null: none), keeping the counters and the bell index in step. */
  private setChange(ep: Bytes, next: { kind: "refresh" | "del"; day: number } | { kind: "reg"; rec: RegRecord } | null): void {
    const prev = this.changeOf(ep);
    if (prev) {
      if (prev.kind === "reg") {
        for (let i = 0; i < prev.rec.tks.length; i += 16) this.bells.remove(key32(prev.rec.tks.subarray(i, i + 4)), prev.id);
        this.regs[prev.id] = null;
        this.freeIds.push(prev.id);
        this.regCount--;
        if (!prev.rec.stored) this.newRegs--;
      } else if (prev.kind === "del") this.dels--;
      this.changes.delete(ep);
    }
    if (!next) return;
    if (next.kind === "reg") {
      const id = this.freeIds.pop() ?? this.regs.length;
      this.regs[id] = next.rec;
      for (let i = 0; i < next.rec.tks.length; i += 16) this.bells.add(key32(next.rec.tks.subarray(i, i + 4)), id);
      this.regCount++;
      if (!next.rec.stored) this.newRegs++;
      this.changes.set(ep, id);
    } else {
      this.changes.set(ep, -1 - (next.day * 2 + (next.kind === "del" ? 1 : 0)));
      if (next.kind === "del") this.dels++;
    }
  }

  /** Endpoints registered now: stored ones minus those deleted in memory, plus new ones in memory. */
  private registeredCount(): number {
    return this.storedCount - this.dels + this.newRegs;
  }

  private storedRow(ep: Bytes): { box: Bytes; day: number } | null {
    const r = this.sql.exec<SubRow>("SELECT ep, box, day FROM sub WHERE ep = ?", ep).toArray()[0];
    return r ? { box: bytes(r.box), day: r.day } : null;
  }

  private storedTks(ep: Bytes): Bytes {
    const rows = this.sql.exec<{ tk: ArrayBuffer }>("SELECT tk FROM tok WHERE ep = ? ORDER BY tk", ep).toArray();
    return concat(...rows.map((r) => bytes(r.tk)));
  }

  private tokCount(ep: Bytes): number {
    return this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM tok WHERE ep = ?", ep).one().n;
  }

  /** The endpoints registered now under `tk` (stored with changes applied), except `except`. */
  private holders(tk: Bytes, except?: Bytes): Bytes[] {
    const out = new Map<string, Bytes>();
    for (const r of this.sql.exec<{ ep: ArrayBuffer }>("SELECT ep FROM tok WHERE tk = ?", tk)) {
      const ep = bytes(r.ep);
      if (except && same(ep, except)) continue;
      const ch = this.changeOf(ep);
      if (ch && ch.kind !== "refresh") continue;
      out.set(hex(ep), ep);
    }
    this.bells.forEach(key32(tk), (id) => {
      const rec = this.regs[id];
      if (rec && hasTk(rec.tks, tk) && !(except && same(rec.ep, except))) out.set(hex(rec.ep), rec.ep);
    });
    return [...out.values()];
  }

  // ───────────── RPC ─────────────

  /**
   * Replaces an endpoint's registration as a whole, in memory, at once (§9.8 `sub`). The Worker has checked every
   * field (§10.10); `tokens` are bells. Empty `tokens` delete the registration.
   */
  async sub(endpoint: string, p256dh: Bytes, auth: Bytes, tokens: Bytes[]): Promise<PushSubResult> {
    const cfg = this.config();
    if (!cfg) throw new Error("push is off");
    const now = this.clock();
    const day = dayOf(now);
    const ep = epOf(cfg.pushKey, endpoint);
    const ch = this.changeOf(ep);
    const row = this.storedRow(ep);
    if (tokens.length === 0) {
      this.pushes.delete(hex(ep));
      this.setChange(ep, row ? { kind: "del", day } : null);
      return "ok";
    }
    const registered = ch ? ch.kind !== "del" : row !== null;
    if (!registered && this.registeredCount() >= cfg.maxSubs) return "full";
    const kept = sortedDistinct(tokens.map((b) => tkOf(cfg.pushKey, b))).filter((tk) => this.holders(tk, ep).length < PUSH_PER_BELL);
    const tks = concat(...kept);
    if (row) {
      const o = openBox(cfg.pushKey, ep, row.box);
      if (o && o.endpoint === endpoint && same(o.p256dh, p256dh) && same(o.auth, auth) && same(this.storedTks(ep), tks)) {
        this.setChange(ep, { kind: "refresh", day });
        return "ok";
      }
    }
    if (this.regCount - (ch?.kind === "reg" ? 1 : 0) >= cfg.daySubs) return "full";
    this.setChange(ep, { kind: "reg", rec: { ep, day, endpoint, p256dh: p256dh.slice(), auth: auth.slice(), tks, stored: row !== null } });
    return "ok";
  }

  /** Schedules the pushes of a fresh row's ring (§9.8 `ring`). Writes nothing, not even the alarm. */
  async ring(E: number, label: Bytes, tokens: Bytes[]): Promise<void> {
    const cfg = this.config();
    if (!cfg) return;
    const now = this.clock();
    const bellsSorted = sortedDistinct(tokens);
    const id = hex(t16(H(enc("segv.sh/v2/push/ring", u16(E), label, concat(...bellsSorted)))));
    const seen = this.dedup.get(id);
    if (seen !== undefined && seen > now) return;
    this.dedup.set(id, now + RING_DEDUP * 1000);
    // Each endpoint's registered bells among `tokens`, in their order there.
    const eps = new Map<string, { ep: Bytes; bells: Bytes[] }>();
    const order = new Set<string>();
    for (const b of tokens) {
      if (order.has(hex(b))) continue;
      order.add(hex(b));
      for (const ep of this.holders(tkOf(cfg.pushKey, b))) {
        const k = hex(ep);
        const e = eps.get(k) ?? { ep, bells: [] };
        e.bells.push(b);
        eps.set(k, e);
      }
    }
    const jitter = v2Params(this.env).delta * 1000;
    for (const [k, { ep, bells }] of eps) {
      const st = this.pushes.get(k);
      const rang = rangWith(bells, st?.rang ?? []);
      if (st && st.due !== null) {
        st.rang = rang;
        continue;
      }
      const last = st?.last ?? null;
      const due = (last === null ? now : Math.max(now, last + WINDOW_MS)) + Math.floor(this.rand() * (jitter + 1));
      this.pushes.set(k, { ep, last, due, tries: 0, first: 0, rang });
    }
  }

  // ───────────── alarm ─────────────

  async alarm(): Promise<void> {
    await this.run();
  }

  /** One alarm run (public for tests). Single-flight; never throws; always leaves the next tick armed. */
  run(): Promise<void> {
    this.running ??= this.tick().finally(() => {
      this.running = null;
    });
    return this.running;
  }

  private async tick(): Promise<void> {
    const now = this.clock();
    const next = nextTick(now);
    try {
      await this.ctx.storage.setAlarm(next);
    } catch (e) {
      console.error(JSON.stringify({ msg: "push alarm arm failed", error: logErr(e) }));
    }
    try {
      this.passPart(now);
    } catch (e) {
      console.error(JSON.stringify({ msg: "push pass failed", error: logErr(e) }));
    }
    try {
      await this.sendDue(next);
    } catch (e) {
      console.error(JSON.stringify({ msg: "push send failed", error: logErr(e) }));
    }
    this.cleanup(this.clock());
  }

  private cleanup(now: number): void {
    for (const [k, exp] of this.dedup) if (exp <= now) this.dedup.delete(k);
    for (const [k, st] of this.pushes) if (st.due === null && (st.last === null || st.last + WINDOW_MS <= now)) this.pushes.delete(k);
  }

  // ───────────── the daily pass ─────────────

  /**
   * This run's part of the daily pass (§9.8): in ascending `ep` order after the last committed one, at most
   * `pushRows` rows read, written or deleted, never splitting an endpoint, in one transaction. On failure nothing
   * changes and the next run tries the same part again.
   */
  private passPart(now: number): void {
    const today = dayOf(now);
    if (this.passDay !== today) {
      this.passDay = today;
      this.passPos = null;
      this.passDone = false;
    }
    if (this.passDone) return;
    const cfg = this.config();
    const budget = this.pushRows;
    const pos = this.passPos;
    const stored = (
      pos
        ? this.sql.exec<SubRow>("SELECT ep, box, day FROM sub WHERE ep > ? ORDER BY ep LIMIT ?", pos, budget)
        : this.sql.exec<SubRow>("SELECT ep, box, day FROM sub ORDER BY ep LIMIT ?", budget)
    )
      .toArray()
      .map((r) => ({ ep: bytes(r.ep).slice(), box: bytes(r.box).slice(), day: r.day }));
    const storedMore = stored.length === budget;
    const lastStored = stored.length > 0 ? stored[stored.length - 1].ep : null;
    // With more stored rows beyond this window, changes past its last row wait for a later part.
    const mem = this.changes
      .keyList()
      .filter((ep) => (!pos || cmp(ep, pos) > 0) && (!storedMore || (lastStored !== null && cmp(ep, lastStored) <= 0)))
      .sort(cmp);

    const ops: PassOp[] = [];
    let used = 0;
    let count = 0;
    let first: Bytes | null = null;
    let last: Bytes | null = null;
    let stopped = false;
    let i = 0;
    let j = 0;
    while (i < stored.length || j < mem.length) {
      let ep: Bytes;
      let st: { box: Bytes; day: number } | null = null;
      if (j >= mem.length || (i < stored.length && cmp(stored[i].ep, mem[j]) <= 0)) {
        ep = stored[i].ep;
        st = stored[i];
        if (j < mem.length && same(mem[j], ep)) j++;
        i++;
      } else {
        ep = mem[j++];
      }
      const ch = this.changeOf(ep);
      let cost = st ? 1 : 0;
      let op: PassOp | null = null;
      const effDay = ch ? ch.day : (st as { day: number }).day;
      const del = (): PassOp => {
        cost += 1 + this.tokCount(ep);
        return { k: "delete", ep, stored: true };
      };
      if (today - effDay > PUSH_EXPIRY) op = st ? del() : { k: "forget", ep };
      else if (ch && ch.day < today) {
        if (ch.kind === "del") op = st ? del() : { k: "forget", ep };
        else if (ch.kind === "refresh") {
          if (!st) op = { k: "forget", ep };
          else if (cfg && !openBox(cfg.pushKey, ep, st.box)) op = del();
          else {
            cost += 1;
            op = { k: "day", ep, day: ch.day };
          }
        } else if (ch.kind === "reg" && cfg) {
          cost += 1 + (st ? this.tokCount(ep) : 0) + ch.rec.tks.length / 16;
          op = { k: "write", ep, rec: ch.rec, stored: st !== null };
        }
        // While push is off a registration cannot be sealed: it stays in memory.
      } else if (!ch && st && cfg && !openBox(cfg.pushKey, ep, st.box)) op = del();
      if (used + cost > budget && count > 0) {
        stopped = true;
        break;
      }
      used += cost;
      count++;
      first ??= ep;
      last = ep;
      if (op) ops.push(op);
    }

    if (ops.length > 0) {
      try {
        this.ctx.storage.transactionSync(() => {
          this.beforeCommit?.();
          for (const op of ops) {
            if (op.k === "delete") {
              this.sql.exec("DELETE FROM tok WHERE ep = ?", op.ep);
              this.sql.exec("DELETE FROM sub WHERE ep = ?", op.ep);
            } else if (op.k === "day") {
              this.sql.exec("UPDATE sub SET day = ? WHERE ep = ?", op.day, op.ep);
            } else if (op.k === "write") {
              const r = op.rec;
              if (op.stored) this.sql.exec("DELETE FROM tok WHERE ep = ?", op.ep);
              this.sql.exec(
                "INSERT OR REPLACE INTO sub (ep, box, day) VALUES (?, ?, ?)",
                op.ep,
                sealBox((cfg as PushConfig).pushKey, op.ep, r),
                r.day,
              );
              for (let k = 0; k < r.tks.length; k += 16) this.sql.exec("INSERT INTO tok (tk, ep) VALUES (?, ?)", r.tks.subarray(k, k + 16), op.ep);
            }
          }
        });
      } catch (e) {
        console.error(JSON.stringify({ msg: "push pass part failed", error: logErr(e) }));
        return;
      }
    }
    for (const op of ops) {
      if (op.k === "delete") {
        this.storedCount--;
        this.pushes.delete(hex(op.ep));
        this.setChange(op.ep, null);
      } else if (op.k === "write") {
        if (!op.stored) this.storedCount++;
        this.setChange(op.ep, null);
      } else this.setChange(op.ep, null);
    }
    this.passPos = last ?? pos;
    if (!stopped && !storedMore) this.passDone = true;
    if (count > 0) {
      this.parts.push({ rows: used, endpoints: count, first: first && hex(first), last: last && hex(last) });
      if (this.parts.length > 64) this.parts.shift();
    }
  }

  // ───────────── sending ─────────────

  /** Sends the due pushes, earliest first, 50 at a time and at most 50 a second, until none is due or `deadline`. */
  private async sendDue(deadline: number): Promise<void> {
    const cfg = this.config();
    if (!cfg) {
      // While push is off nothing is sent, and what is due is dropped.
      for (const st of this.pushes.values()) Object.assign(st, { due: null, rang: [] });
      return;
    }
    const tally = { sent: 0, retried: 0, dropped: 0, deleted: 0 };
    for (;;) {
      const start = this.clock();
      if (start >= deadline) break;
      const due = [...this.pushes.values()]
        .filter((s) => s.due !== null && s.due <= start)
        .sort((a, b) => (a.due as number) - (b.due as number))
        .slice(0, PUSH_BATCH);
      if (due.length === 0) break;
      // Their `due` stays set while they are sent: a ring meanwhile coalesces into them (§9.8 `ring` step 2).
      const results = await Promise.all(due.map((s) => this.sendOne(cfg, s)));
      for (const r of results) if (r) tally[r]++;
      const more = [...this.pushes.values()].some((s) => s.due !== null && s.due <= this.clock());
      const wait = start + 1000 - this.clock();
      if (more && wait > 0) await this.sleep(Math.min(wait, Math.max(0, deadline - this.clock())));
    }
    if (tally.dropped + tally.deleted + tally.retried > 0) console.error(JSON.stringify({ msg: "push results", ...tally }));
  }

  /** The endpoint and keys to push to; null when it is no longer registered, "bad" when its box does not open. */
  private target(cfg: PushConfig, ep: Bytes): Target | "bad" | null {
    const ch = this.changeOf(ep);
    if (ch?.kind === "del") return null;
    if (ch?.kind === "reg") return ch.rec;
    const row = this.storedRow(ep);
    if (!row) return null;
    return openBox(cfg.pushKey, ep, row.box) ?? "bad";
  }

  /** A deletion at a push: in memory at once, written by the next pass (§9.8). */
  private deleteAtPush(ep: Bytes, seen: number | undefined): void {
    this.pushes.delete(hex(ep));
    if (this.changes.get(ep) !== seen) return; // re-registered meanwhile: keep the new registration
    this.setChange(ep, this.storedRow(ep) ? { kind: "del", day: dayOf(this.clock()) } : null);
  }

  private async sendOne(cfg: PushConfig, s: PushState): Promise<"sent" | "retried" | "dropped" | "deleted" | null> {
    const ep = s.ep;
    const seen = this.changes.get(ep);
    const t = this.target(cfg, ep);
    if (t === null) {
      this.pushes.delete(hex(ep));
      return null;
    }
    let url: URL | null = null;
    try {
      if (t !== "bad") url = new URL(t.endpoint);
    } catch {
      url = null;
    }
    if (t === "bad" || !url || !pushHostAllowed(cfg, url.hostname)) {
      this.deleteAtPush(ep, seen);
      return "deleted";
    }
    const at = this.clock();
    if (s.tries === 0) s.first = at;
    let status: number | "error";
    let retryAfter: string | null = null;
    // A timer cleared as soon as the answer is in (AbortSignal.timeout would stay pending for the full 10 s).
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), PUSH_TIMEOUT_MS);
    try {
      this.signer = this.signer?.cfg === cfg ? this.signer : { cfg, s: new VapidSigner(cfg.vapidSk, cfg.vapidSub) };
      const body = await encryptPayload(pushPayload(cfg.appHost, s.rang), t.p256dh, t.auth);
      const authorization = await this.signer.s.authorization(url.origin, at);
      const res = await this.fetcher(t.endpoint, {
        method: "POST",
        headers: {
          TTL: "86400",
          Urgency: "normal",
          Topic: "segv",
          "Content-Encoding": "aes128gcm",
          "Content-Type": "application/octet-stream",
          Authorization: authorization,
        },
        body: body as BodyInit,
        redirect: "manual",
        signal: abort.signal,
      });
      status = res.status;
      retryAfter = res.headers.get("retry-after");
      await res.body?.cancel().catch(() => {});
    } catch (e) {
      if (e instanceof RangeError) {
        // Keys that cannot be encrypted to: no push service would ever take this endpoint.
        this.deleteAtPush(ep, seen);
        return "deleted";
      }
      status = "error";
    } finally {
      clearTimeout(timer);
    }
    if (typeof status === "number" && status >= 200 && status < 300) {
      Object.assign(s, { last: at, due: null, tries: 0, rang: [] });
      return "sent";
    }
    if (status === "error" || status === 429 || status >= 500) {
      if (s.tries === 0) {
        const ra = retryAfterS(retryAfter);
        Object.assign(s, { tries: 1, due: this.clock() + (ra !== null && ra <= 60 ? ra * 1000 : RETRY_MS) });
        return "retried";
      }
      Object.assign(s, { last: s.first, due: null, tries: 0, rang: [] });
      return "dropped";
    }
    // A 3xx (never followed) or any other 4xx: no push service accepts this endpoint any more.
    this.deleteAtPush(ep, seen);
    return "deleted";
  }
}
