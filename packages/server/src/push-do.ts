/**
 * PushDO (`push/v2`, one instance; docs/PROTOCOL.md §9.8): the registrations of the devices that turned notifications
 * on, and the pushes they get.
 *
 * - Durable storage holds the registrations (`sub`, `tok`), keyed and sealed under PUSH_KEY, which only the daily pass
 *   writes, a change only after its UTC day has ended; the journal (`jr`) of the changes no pass has written yet; and
 *   the day of the last completed pass (`meta`). The platform keeps a 30-day point-in-time history of the storage,
 *   which must not date anything finer than a day, nor show which devices a message reached: so the journal gets one
 *   sealed row of fixed length at the first run of every minute, whatever changed, and nothing else is ever written
 *   at the time of an event.
 * - Memory holds the day's registration changes (in effect at once), everything a ring causes (due pushes, windows,
 *   the dedup of rings) and the rows each account marked seen. A restart loses the last two; the first call or run
 *   after it reads the changes back from the journal, all but those of the last minute, which devices send again at
 *   their next start (§11.13). `sub` answers BUSY to a change that the journal's next row could not hold with those
 *   already waiting, so that bound holds however many changes come at once. A push that a lost mark would have
 *   prevented is sent.
 * - Only a pass that ran with push on, after the journal was read back, records its day in `meta`: a later start reads
 *   back the records of that day and after, so a day recorded without them would lose them.
 * - Every push waits at least PUSH_HOLD after its ring, so that a device of the account in use can mark its row seen
 *   first (`seen`, §9.8): a push whose rows were all marked is cancelled.
 * - `ring` answers how long until the push it made due; the Worker waits that long, where waiting costs nothing, and
 *   calls `flush`, which sends it on time. The alarm sends what no flush sent.
 * - The alarm ticks every PUSH_TICK seconds of Unix time whatever happens, so its stored time follows the clock alone.
 *
 * Bells are never held in Maps keyed by strings: a day's changes may hold 2 000 endpoints of 256 bells, so the index
 * from a bell to the changed endpoints is open addressing over typed arrays (§9.8 "Memory").
 */
import { DurableObject } from "cloudflare:workers";
import { H, HMAC, aeadOpen, aeadSeal, concat, dec, enc, hex, t16, u16, u32 } from "@segv/protocol/proto";
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
/** Seconds a push waits at least after the ring that made it due, for a mark of its row (§9.8 `ring`). */
export const PUSH_HOLD = 5;
/** Rows remembered per waiting push; once more ring it, it can no longer be cancelled. */
export const PUSH_PENDING = 16;
/** Seconds a row marked seen is remembered per endpoint. */
export const SEEN_TTL = 120;
/** Rows marked seen kept per endpoint (a mark beyond them drops the one that expires first). */
export const PUSH_SEEN = 64;
/** The journal's cadence, seconds: one row at the first run of each minute of Unix time. */
export const PUSH_JOURNAL = 60;
/** Journal rows: one per minute of 48 hours, so that a day's changes stay until the next day's pass has written them. */
export const JR_SLOTS = (2 * 86_400) / PUSH_JOURNAL;
/** Bytes of a journal row before it is sealed: room for the largest change (an endpoint of 1 024 bytes, 258 tk). */
export const JR_BYTES = 5_376;
/** `ring` answers a wait only for a push due within this many ms (the Worker waits inside `waitUntil`, ≤ 30 s). */
export const RING_WAIT = 20_000;
/** A flush sends for at most this long; what it leaves goes out at the next run. */
export const FLUSH_MS = 5_000;

const TICK_MS = PUSH_TICK * 1000;
const WINDOW_MS = PUSH_WINDOW * 1000;
const HOLD_MS = PUSH_HOLD * 1000;
const SEEN_MS = SEEN_TTL * 1000;
const JR_MS = PUSH_JOURNAL * 1000;
const DAY_MS = 86_400_000;
const PUSH_BATCH = 50;
const PUSH_TIMEOUT_MS = 10_000;
const RETRY_MS = 10_000;

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS sub (ep BLOB PRIMARY KEY CHECK (length(ep) = 16), box BLOB NOT NULL, day INTEGER NOT NULL) WITHOUT ROWID",
  "CREATE INDEX IF NOT EXISTS sub_day ON sub (day)",
  "CREATE TABLE IF NOT EXISTS tok (tk BLOB NOT NULL CHECK (length(tk) = 16), ep BLOB NOT NULL, PRIMARY KEY (tk, ep)) WITHOUT ROWID",
  "CREATE INDEX IF NOT EXISTS tok_ep ON tok (ep)",
  "CREATE TABLE IF NOT EXISTS jr (slot INTEGER PRIMARY KEY, box BLOB NOT NULL)",
  "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL) WITHOUT ROWID",
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
  /** the rows that rang it since its last push and that its account has not marked seen; null: too many to cancel */
  rows: Set<string> | null;
  /** its request is in flight: a mark no longer cancels it */
  sending: boolean;
  /**
   * The rings that came while its current attempt was out, which that attempt does not carry (§9.8 `later`): their
   * bells, newest first, and their rows not marked seen since (null: too many to cancel). Null: none came.
   */
  later: { rang: Bytes[]; rows: Set<string> | null } | null;
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

/** `rows` with `row` added; null once more than PUSH_PENDING rows rang (§9.8 `rows`). */
function rowsWith(rows: Set<string> | null, row: string): Set<string> | null {
  if (!rows) return null;
  rows.add(row);
  return rows.size > PUSH_PENDING ? null : rows;
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
/** The `tk` of a quiet tag: another label than a bell's, so neither ever matches the other. */
const qkOf = (key: Bytes, quiet: Bytes): Bytes => t16(HMAC(key, enc("segv.sh/v2/push/quiet", quiet)));
/** A row as rings and marks name it. */
const rowIdOf = (E: number, label: Bytes): string => hex(t16(H(enc("segv.sh/v2/push/row", u16(E), label))));
const boxAad = (ep: Bytes): Bytes => enc("segv.sh/v2/push/sub", ep);
const sealBox = (key: Bytes, ep: Bytes, t: Target): Bytes => aeadSeal(key, enc(t.endpoint, t.p256dh, t.auth), boxAad(ep));

function openBox(key: Bytes, ep: Bytes, box: Bytes): Target | null {
  try {
    const [e, p, a] = dec(aeadOpen(key, box, boxAad(ep)), 3);
    if (p.length !== 65 || a.length !== 16) return null;
    return { endpoint: new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(e), p256dh: p.slice(), auth: a.slice() };
  } catch {
    return null;
  }
}

/** retry-after in delta-seconds (an HTTP date counts as absent). */
function retryAfterS(v: string | null): number | null {
  return v !== null && /^\d{1,6}$/.test(v.trim()) ? Number(v.trim()) : null;
}

// ───────────── the journal (§9.8 "The journal") ─────────────

/** Record kinds: a registration (whole), a refresh (the day alone), a deletion. */
const JR_REG = 1;
const JR_REFRESH = 2;
const JR_DEL = 3;

/** `u8 kind ‖ u32 day ‖ ep`, and for a registration `enc(endpoint, p256dh, auth, tks)`. */
function jrRecord(kind: number, ep: Bytes, day: number, rec?: RegRecord): Bytes {
  const head = concat(Uint8Array.of(kind), u32(day), ep);
  return rec ? concat(head, enc(rec.endpoint, rec.p256dh, rec.auth, rec.tks)) : head;
}

interface JrChange {
  kind: number;
  day: number;
  ep: Bytes;
  reg: (Target & { tks: Bytes }) | null;
}

/** A record read back, or null when it is not one (never thrown on). */
function jrRead(b: Bytes): JrChange | null {
  if (b.length < 21) return null;
  const kind = b[0];
  const day = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(1);
  const ep = b.slice(5, 21);
  if (kind === JR_REFRESH || kind === JR_DEL) return b.length === 21 ? { kind, day, ep, reg: null } : null;
  if (kind !== JR_REG) return null;
  try {
    const [e, p, a, tks] = dec(b.subarray(21), 4);
    if (p.length !== 65 || a.length !== 16 || tks.length % 16 !== 0) return null;
    const endpoint = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(e);
    return { kind, day, ep, reg: { endpoint, p256dh: p.slice(), auth: a.slice(), tks: tks.slice() } };
  } catch {
    return null;
  }
}

/** A row's plaintext: `u32 prev ‖ (u16 len ‖ record)* ‖ zero bytes`, exactly JR_BYTES long. */
function jrPayload(prev: number, recs: readonly Bytes[]): Bytes {
  const out = new Uint8Array(JR_BYTES);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, prev);
  let o = 4;
  for (const r of recs) {
    dv.setUint16(o, r.length);
    out.set(r, o + 2);
    o += 2 + r.length;
  }
  return out;
}

function jrParse(p: Bytes): { prev: number; recs: Bytes[] } | null {
  if (p.length !== JR_BYTES) return null;
  const dv = new DataView(p.buffer, p.byteOffset, p.byteLength);
  const recs: Bytes[] = [];
  let o = 4;
  while (o + 2 <= p.length) {
    const n = dv.getUint16(o);
    if (n === 0 || o + 2 + n > p.length) break;
    recs.push(p.subarray(o + 2, o + 2 + n));
    o += 2 + n;
  }
  return { prev: dv.getUint32(0), recs };
}

/** The minute a row belongs to is bound into it: a row of another minute never opens as this one. */
const jrAad = (m: number): Bytes => enc("segv.sh/v2/push/jr", u32(m));
const minuteOf = (ms: number): number => Math.floor(ms / JR_MS);

function sameReg(a: RegRecord, b: RegRecord): boolean {
  return a.day === b.day && a.endpoint === b.endpoint && same(a.p256dh, b.p256dh) && same(a.auth, b.auth) && same(a.tks, b.tks);
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
  /** per endpoint: the rows its account marked seen, each with when it expires, in that order */
  private readonly marks = new Map<string, Map<string, number>>();

  // The daily pass: the day it started, the last committed ep, and whether it went through every endpoint.
  private passDay: number | null = null;
  private passPos: Bytes | null = null;
  private passDone = false;

  // The journal: the changes waiting for its next row (by ep, oldest first, each an encoded record), the minute of the
  // latest row written (by this start of the object or an earlier one) and that of the latest row holding a record.
  private readonly jq = new Map<string, Bytes>();
  /** What the waiting changes take in a row: 2 + length each. */
  private jqBytes = 0;
  private jLast = 0;
  private jHead = 0;
  /** The journal and the pass's state have been read back since the object started (tried, at least). */
  private rebuilt = false;
  /** The journal was read back in full, with push on: only then may a completed pass record its day in `meta`. */
  private recovered = false;

  private signer: { cfg: PushConfig; s: VapidSigner } | null = null;
  private running: Promise<void> | null = null;
  private sending: Promise<void> | null = null;
  /** No batch of pushes begins before this time: a second after the last one began, whichever loop sent it. */
  private nextBatch = 0;

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

  private hasStored(ep: Bytes): boolean {
    return this.sql.exec("SELECT 1 FROM sub WHERE ep = ?", ep).toArray().length > 0;
  }

  /** Queues a change for the journal's next row, in place of one of the same endpoint still waiting. */
  private journalLater(ep: Bytes, record: Bytes): void {
    const k = hex(ep);
    this.unqueue(k);
    this.jq.set(k, record);
    this.jqBytes += 2 + record.length;
  }

  /** Takes an endpoint's change off the journal's queue: a row or the daily pass holds it now. */
  private unqueue(k: string): void {
    const r = this.jq.get(k);
    if (r === undefined) return;
    this.jq.delete(k);
    this.jqBytes -= 2 + r.length;
  }

  /**
   * Whether `record`, queued for `ep`, would go into the journal's next row along with every change waiting (§9.8
   * `sub`, BUSY), so that a change `sub` accepts is in the next row.
   */
  private fitsNext(ep: Bytes, record: Bytes): boolean {
    const old = this.jq.get(hex(ep));
    return 4 + this.jqBytes - (old ? 2 + old.length : 0) + 2 + record.length <= JR_BYTES;
  }

  /** The record that deleting ep now queues: null when there is nothing to delete, or the deletion already waits. */
  private delRecord(ep: Bytes, ch: Change | undefined, stored: boolean, day: number): Bytes | null {
    return (stored || ch) && !(ch?.kind === "del" && ch.day === day) ? jrRecord(JR_DEL, ep, day) : null;
  }

  /** Deletes ep's registration in memory, at once (§9.8), and queues the deletion for the journal. */
  private deleteNow(ep: Bytes, day: number): void {
    const stored = this.hasStored(ep);
    const r = this.delRecord(ep, this.changeOf(ep), stored, day);
    if (r) this.journalLater(ep, r);
    this.setChange(ep, stored ? { kind: "del", day } : null);
  }

  /** Before the first call or run after a start: the pass's state and the day's changes, read back. Never throws. */
  private ready(): void {
    if (this.rebuilt) return;
    this.rebuilt = true;
    try {
      this.rebuild();
    } catch (e) {
      console.error(JSON.stringify({ msg: "push journal read failed", error: logErr(e) }));
    }
  }

  /**
   * §9.8 "The journal": the latest row of the last 48 hours that opens, then the rows its `prev` chain names, back to
   * the start of the day of the last completed pass; their records applied oldest first, except those of a day before
   * that pass, which it has written.
   */
  private rebuild(): void {
    const done = this.sql.exec<{ v: number }>("SELECT v FROM meta WHERE k = 'pass'").toArray()[0]?.v ?? null;
    const now = this.clock();
    if (done === dayOf(now)) {
      this.passDay = done;
      this.passDone = true;
    }
    const cfg = this.config();
    if (!cfg) return;
    const mNow = minuteOf(now);
    const lo = Math.max(mNow - JR_SLOTS + 1, done === null ? 0 : (done * DAY_MS) / JR_MS);
    const open = (m: number): { prev: number; recs: Bytes[] } | null => {
      const r = this.sql.exec<{ box: ArrayBuffer }>("SELECT box FROM jr WHERE slot = ?", m % JR_SLOTS).toArray()[0];
      if (!r) return null;
      try {
        return jrParse(aeadOpen(cfg.pushKey, bytes(r.box), jrAad(m)));
      } catch {
        return null;
      }
    };
    let latest = mNow;
    let row: { prev: number; recs: Bytes[] } | null = null;
    for (; latest >= lo; latest--) {
      row = open(latest);
      if (row) break;
    }
    if (!row) {
      this.recovered = true;
      return;
    }
    this.jLast = latest;
    this.jHead = row.recs.length > 0 ? latest : row.prev;
    const chain: Bytes[][] = row.recs.length > 0 ? [row.recs] : [];
    for (let at = latest, p = row.prev; p >= lo && p > 0 && p < at; ) {
      const x = open(p);
      if (!x) break;
      if (x.recs.length > 0) chain.push(x.recs);
      at = p;
      p = x.prev;
    }
    for (let i = chain.length - 1; i >= 0; i--) for (const r of chain[i]) this.replay(r, done);
    this.recovered = true;
  }

  /** One record read back: applied as `sub` or a deletion applied it, unless a completed pass has written it. */
  private replay(r: Bytes, done: number | null): void {
    const x = jrRead(r);
    if (!x || (done !== null && x.day < done)) return;
    const stored = this.hasStored(x.ep);
    if (x.reg) {
      this.setChange(x.ep, { kind: "reg", rec: { ep: x.ep, day: x.day, ...x.reg, stored } });
    } else if (x.kind === JR_REFRESH) {
      if (stored) this.setChange(x.ep, { kind: "refresh", day: x.day });
    } else {
      this.setChange(x.ep, stored ? { kind: "del", day: x.day } : null);
    }
  }

  // ───────────── RPC ─────────────

  /**
   * Replaces an endpoint's registration as a whole, in memory, at once (§9.8 `sub`). The Worker has checked every
   * field (§10.10); `tokens` are bells, `quiet` the account's quiet tag (or null). Empty `tokens` delete the
   * registration. A change that the journal's next row could not hold, with the changes already waiting for it, is
   * refused ("busy") and changes nothing: the device sends it again later (§11.13).
   */
  async sub(endpoint: string, p256dh: Bytes, auth: Bytes, tokens: Bytes[], quiet: Bytes | null = null): Promise<PushSubResult> {
    this.ready();
    const cfg = this.config();
    if (!cfg) throw new Error("push is off");
    const now = this.clock();
    const day = dayOf(now);
    const ep = epOf(cfg.pushKey, endpoint);
    const ch = this.changeOf(ep);
    const row = this.storedRow(ep);
    if (tokens.length === 0) {
      const r = this.delRecord(ep, ch, row !== null, day);
      if (r && !this.fitsNext(ep, r)) return "busy";
      this.pushes.delete(hex(ep));
      this.marks.delete(hex(ep));
      this.deleteNow(ep, day);
      return "ok";
    }
    const registered = ch ? ch.kind !== "del" : row !== null;
    if (!registered && this.registeredCount() >= cfg.maxSubs) return "full";
    const tks0 = tokens.map((b) => tkOf(cfg.pushKey, b));
    if (quiet) tks0.push(qkOf(cfg.pushKey, quiet));
    const kept = sortedDistinct(tks0).filter((tk) => this.holders(tk, ep).length < PUSH_PER_BELL);
    const tks = concat(...kept);
    if (row) {
      const o = openBox(cfg.pushKey, ep, row.box);
      if (o && o.endpoint === endpoint && same(o.p256dh, p256dh) && same(o.auth, auth) && same(this.storedTks(ep), tks)) {
        if (!(ch?.kind === "refresh" && ch.day === day)) {
          const r = jrRecord(JR_REFRESH, ep, day);
          if (!this.fitsNext(ep, r)) return "busy";
          this.journalLater(ep, r);
        }
        this.setChange(ep, { kind: "refresh", day });
        return "ok";
      }
    }
    if (this.regCount - (ch?.kind === "reg" ? 1 : 0) >= cfg.daySubs) return "full";
    const rec: RegRecord = { ep, day, endpoint, p256dh: p256dh.slice(), auth: auth.slice(), tks, stored: row !== null };
    if (!(ch?.kind === "reg" && sameReg(ch.rec, rec))) {
      const r = jrRecord(JR_REG, ep, day, rec);
      if (!this.fitsNext(ep, r)) return "busy";
      this.journalLater(ep, r);
    }
    this.setChange(ep, { kind: "reg", rec });
    return "ok";
  }

  /**
   * Schedules the pushes of a fresh row's ring (§9.8 `ring`). Writes nothing, not even the alarm. Answers how many ms
   * until the earliest push due to an endpoint it rang, when that is at most RING_WAIT away (else null): the Worker
   * waits that long and calls `flush`.
   */
  async ring(E: number, label: Bytes, tokens: Bytes[]): Promise<number | null> {
    this.ready();
    const cfg = this.config();
    if (!cfg) return null;
    const now = this.clock();
    const bellsSorted = sortedDistinct(tokens);
    const id = hex(t16(H(enc("segv.sh/v2/push/ring", u16(E), label, concat(...bellsSorted)))));
    const seen = this.dedup.get(id);
    if (seen !== undefined && seen > now) return null;
    this.dedup.set(id, now + RING_DEDUP * 1000);
    const row = rowIdOf(E, label);
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
    let first = Infinity;
    for (const [k, { ep, bells }] of eps) {
      // A device of its account has shown this row while in use (§9.8 `seen`).
      if ((this.marks.get(k)?.get(row) ?? 0) > now) continue;
      const st = this.pushes.get(k);
      const rang = rangWith(bells, st?.rang ?? []);
      if (st && st.due !== null) {
        st.rang = rang;
        st.rows = rowsWith(st.rows, row);
        // The attempt out now was built without this ring: whatever its answer, this ring is not lost with it.
        if (st.sending) {
          const l = st.later ?? { rang: [], rows: new Set<string>() };
          st.later = { rang: rangWith(bells, l.rang), rows: rowsWith(l.rows, row) };
        }
        first = Math.min(first, st.due);
        continue;
      }
      const last = st?.last ?? null;
      const due = this.dueAfter(now, last);
      this.pushes.set(k, { ep, last, due, tries: 0, first: 0, rang, rows: new Set([row]), sending: false, later: null });
      first = Math.min(first, due);
    }
    return first - now <= RING_WAIT ? Math.max(0, first - now) : null;
  }

  /** The `due` of a push that rings make due at `now` (§9.8 `ring` step 2), j drawn afresh. */
  private dueAfter(now: number, last: number | null): number {
    const jitter = v2Params(this.env).delta * 1000;
    return Math.max(now + HOLD_MS, last === null ? 0 : last + WINDOW_MS) + Math.floor(this.rand() * (jitter + 1));
  }

  /**
   * Sends the pushes that are due now (§9.8 `flush`), as an alarm run does, for at most FLUSH_MS. The Worker calls it
   * when the wait that `ring` answered has passed. Writes nothing.
   */
  async flush(): Promise<void> {
    this.ready();
    await this.sendNow(this.clock() + FLUSH_MS);
  }

  /**
   * A device of the account whose quiet tag is `Q` has shown `rows` while in use (§9.8 `seen`): its endpoints get no
   * push for them. Cancels a waiting push all of whose rows are now marked. Writes nothing, not even the alarm.
   */
  async seen(Q: Bytes, rows: { E: number; label: Bytes }[]): Promise<void> {
    this.ready();
    const cfg = this.config();
    if (!cfg || rows.length === 0) return;
    const eps = this.holders(qkOf(cfg.pushKey, Q));
    if (eps.length === 0) return;
    const now = this.clock();
    const ids = [...new Set(rows.map((r) => rowIdOf(r.E, r.label)))];
    for (const ep of eps) {
      const k = hex(ep);
      const m = this.marks.get(k) ?? new Map<string, number>();
      for (const id of ids) {
        // Deleted and set again, so the map stays in the order in which its marks expire.
        m.delete(id);
        m.set(id, now + SEEN_MS);
      }
      while (m.size > PUSH_SEEN) m.delete(m.keys().next().value as string);
      this.marks.set(k, m);
      const st = this.pushes.get(k);
      if (!st || st.due === null) continue;
      for (const id of ids) st.later?.rows?.delete(id);
      if (!st.rows) continue;
      for (const id of ids) st.rows.delete(id);
      if (st.rows.size === 0 && !st.sending) Object.assign(st, { due: null, tries: 0, rang: [], rows: new Set() });
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
    this.ready();
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
      this.journal(now);
    } catch (e) {
      console.error(JSON.stringify({ msg: "push journal failed", error: logErr(e) }));
    }
    await this.sendNow(next);
    this.cleanup(this.clock());
  }

  /** The send loop, one at a time: a flush during a run (or a run during a flush) waits for the loop under way. */
  private sendNow(deadline: number): Promise<void> {
    this.sending ??= this.sendDue(deadline)
      .catch((e: unknown) => {
        console.error(JSON.stringify({ msg: "push send failed", error: logErr(e) }));
      })
      .finally(() => {
        this.sending = null;
      });
    return this.sending;
  }

  /**
   * The journal's row for this minute (§9.8 "The journal"), at its first run, while push is on: the waiting changes
   * that fit, oldest first, and zero bytes; sealed, so every row is as long as every other.
   */
  private journal(now: number): void {
    const cfg = this.config();
    const m = minuteOf(now);
    if (!cfg || m <= this.jLast) return;
    const recs: Bytes[] = [];
    const taken: string[] = [];
    let used = 4;
    for (const [k, r] of this.jq) {
      if (6 + r.length > JR_BYTES) {
        // Larger than any row (not possible for a change that the Worker checked): it would hold up the rest.
        this.unqueue(k);
        console.error(JSON.stringify({ msg: "push journal dropped a change" }));
        continue;
      }
      if (used + 2 + r.length > JR_BYTES) break;
      recs.push(r);
      taken.push(k);
      used += 2 + r.length;
    }
    const box = aeadSeal(cfg.pushKey, jrPayload(this.jHead, recs), jrAad(m));
    this.sql.exec("INSERT INTO jr (slot, box) VALUES (?, ?) ON CONFLICT (slot) DO UPDATE SET box = excluded.box", m % JR_SLOTS, box);
    this.jLast = m;
    if (recs.length > 0) this.jHead = m;
    for (const k of taken) this.unqueue(k);
  }

  private cleanup(now: number): void {
    for (const [k, exp] of this.dedup) if (exp <= now) this.dedup.delete(k);
    for (const [k, m] of this.marks) {
      // In expiry order: stop at the first mark still in force.
      for (const [id, exp] of m) {
        if (exp > now) break;
        m.delete(id);
      }
      if (m.size === 0) this.marks.delete(k);
    }
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

    const completes = !stopped && !storedMore;
    // A pass that could not see the journal's changes (push off, or the journal not read back) leaves `meta` as it
    // is: the day it would record would make a later start skip the records of the days before, which it never wrote.
    const mark = completes && cfg !== null && this.recovered;
    if (ops.length > 0 || mark) {
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
          // The day whose pass is complete: a restart then neither starts it again nor reads back what it wrote.
          if (mark) this.sql.exec("INSERT INTO meta (k, v) VALUES ('pass', ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v", today);
        });
      } catch (e) {
        console.error(JSON.stringify({ msg: "push pass part failed", error: logErr(e) }));
        return;
      }
    }
    for (const op of ops) {
      // Written: it no longer waits for the journal.
      this.unqueue(hex(op.ep));
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
    if (completes) this.passDone = true;
    if (count > 0) {
      this.parts.push({ rows: used, endpoints: count, first: first && hex(first), last: last && hex(last) });
      if (this.parts.length > 64) this.parts.shift();
    }
  }

  // ───────────── sending ─────────────

  /**
   * Sends the due pushes, earliest first, 50 at a time and at most one batch a second, until none is due or
   * `deadline`. The second is kept across loops (`nextBatch`), so that runs and flushes close together share it.
   */
  private async sendDue(deadline: number): Promise<void> {
    const cfg = this.config();
    if (!cfg) {
      // While push is off nothing is sent, and what is due is dropped.
      for (const st of this.pushes.values()) Object.assign(st, { due: null, rang: [], rows: new Set(), later: null });
      return;
    }
    const tally = { sent: 0, retried: 0, dropped: 0, deleted: 0 };
    const isDue = (s: PushState, at: number): boolean => s.due !== null && s.due <= at;
    for (;;) {
      let start = this.clock();
      if (start >= deadline) break;
      if (start < this.nextBatch) {
        // The last batch, of this loop or an earlier one, began less than a second ago. Past the deadline the next
        // run or flush sends what is due.
        if (this.nextBatch >= deadline || ![...this.pushes.values()].some((s) => isDue(s, start))) break;
        await this.sleep(this.nextBatch - start);
        start = this.clock();
      }
      // Each turn of the loop sends a batch or ends it.
      const due = [...this.pushes.values()]
        .filter((s) => isDue(s, start))
        .sort((a, b) => (a.due as number) - (b.due as number))
        .slice(0, PUSH_BATCH);
      if (due.length === 0) break;
      this.nextBatch = start + 1000;
      // Their `due` stays set while they are sent: a ring meanwhile coalesces into them, so that a retry carries it,
      // and is also kept apart in `later`, which their answer leaves due (§9.8 `ring` step 2); a mark no longer
      // cancels them.
      const results = await Promise.all(
        due.map(async (s) => {
          s.sending = true;
          try {
            return await this.sendOne(cfg, s);
          } finally {
            s.sending = false;
          }
        }),
      );
      for (const r of results) if (r) tally[r]++;
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
    this.deleteNow(ep, dayOf(this.clock()));
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
      // What this attempt carries: rings from here on go to `later` as well.
      s.later = null;
      const body = await encryptPayload(pushPayload(cfg.appHost, s.rang), t.p256dh, t.auth);
      const authorization = await this.signer.s.authorization(url.origin, at);
      const res = await this.fetcher(t.endpoint, {
        method: "POST",
        headers: {
          TTL: "86400",
          // Push services deliver other values when it suits the device's battery; Apple's service only `high` at once.
          Urgency: "high",
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
      this.ended(s, at);
      return "sent";
    }
    if (status === "error" || status === 429 || status >= 500) {
      if (s.rows?.size === 0) {
        // Every row that rang it was marked seen while this attempt was out: cancelled rather than retried.
        Object.assign(s, { due: null, tries: 0, rang: [], rows: new Set(), later: null });
        return null;
      }
      if (s.tries === 0) {
        const ra = retryAfterS(retryAfter);
        // The retry carries the rings that came meanwhile: they are in `rang` and `rows` already.
        Object.assign(s, { tries: 1, due: this.clock() + (ra !== null && ra <= 60 ? ra * 1000 : RETRY_MS), later: null });
        return "retried";
      }
      this.ended(s, s.first);
      return "dropped";
    }
    // A 3xx (never followed) or any other 4xx: no push service accepts this endpoint any more.
    this.deleteAtPush(ep, seen);
    return "deleted";
  }

  /**
   * A push sent or dropped, its window counted from `last`: what its attempts carried is gone, and the rings that came
   * during its last one are due as if they came now (§9.8), unless every row of them was marked seen meanwhile.
   */
  private ended(s: PushState, last: number): void {
    const l = s.later;
    Object.assign(s, { last, due: null, tries: 0, rang: [], rows: new Set(), later: null });
    if (l && l.rows?.size !== 0) Object.assign(s, { due: this.dueAfter(this.clock(), last), rang: l.rang, rows: l.rows });
  }
}
