/**
 * QuietDO — one of PUSH_SHARDS objects that own the push registrations of their endpoints (docs/PROTOCOL.md §9.8).
 * Name "quiet/v2/{k}"; an endpoint's object is quietShard(owner), the owner being its account's quiet tag (keyed hash):
 * all endpoints of one account are here. It has no storage of its own.
 *
 *  - The records (`e/<ep>` of the push store) and the bells (`b/<tk>`): each read into a cache bounded by an estimate
 *    of its bytes the first time the object touches it, kept as the stored value itself (one buffer per key), and
 *    written by this object alone (a bell's secret is the account's, so every endpoint under a bell is one of its
 *    account's), one change of an endpoint at a time. One writer per key: a write waits at least a second after the
 *    previous one of its key (the store's limit), and the changes made meanwhile go into it; a write that fails twice
 *    puts the cache back to what the store holds and fails every change it carried, so that `sub` answers 503 and
 *    writes no record claiming a bell that the store lacks. A key with a change not yet written is never evicted.
 *    sub() applies a registration: it takes the endpoint out of the bells it leaves and puts it under those it takes
 *    (a bell whose 8 places the account's other endpoints hold is left out), and writes the record when anything in it
 *    changed (the day included). A record whose owner is another object's is never acted on here: sub() first has
 *    that object drop it. drop() deletes one; expire() deletes those the daily expiry names, if still expired.
 *  - Everything a ring causes, never written: per endpoint `last`, `due`, `tries`, `rang`, `rows`, the rings that came
 *    while its push was in flight (`later`), the rows that rang it recently (so that a sender's repeat changes nothing)
 *    and the push in flight; and the rows each account marked seen. ring() makes pushes due (the hold, the window, the
 *    jitter), due() hands the Worker a bounded batch of those due now, sent() takes its reports, seen() marks rows and
 *    cancels waiting pushes. Due pushes are kept in time order, pushes in flight and idle states in the order in which
 *    they expire, and the states by account, so that no call looks at more than it changes; the expired ones are
 *    swept at most once a second.
 */
import { DurableObject } from "cloudflare:workers";
import { concat, hex, u16, type Bytes } from "@segv/protocol/proto";
import { pushConfig, pushShardsOf, v2Params } from "./env";
import { logErr } from "./http";
import {
  DUE_BATCH,
  INFLIGHT_MS,
  PUSH_EXPIRY,
  PUSH_HOLD,
  PUSH_PENDING,
  PUSH_PER_BELL,
  PUSH_SEEN,
  PUSH_WINDOW,
  RETRY_MS,
  RING_DEDUP,
  SEEN_TTL,
  dayOf,
  decodeEntries,
  decodeRecord,
  encodeRecord,
  epOf,
  fromHex,
  isZero,
  keyBell,
  keyEp,
  khOf,
  ownerOf,
  qkOf,
  quietShard,
  rowIdOf,
  sameBytes,
  sealBox,
  sortedDistinct,
  tkOf,
  type BellEntry,
  type DueBatch,
  type DuePush,
  type EpRecord,
  type RingTarget,
  type SentReport,
} from "./push";
import { parseIndexName, quietStub } from "./types";
import { PUSH_BELLS } from "./webpush";

/** The estimated bytes each cache (records, bells) holds at most; the least recently used go first. */
const CACHE_BYTES = 32 * 1024 * 1024;
/** What an entry of a cache costs beyond its value and its key: the map's slot, the array object, its buffer. */
const ENTRY_OVERHEAD = 200;
/** Rows remembered per endpoint as having rung it (RING_DEDUP). */
const RECENT_ROWS = 64;
/** Accounts whose marks are held at once; beyond it the account marked longest ago goes (marks expire anyway). */
const MARK_ACCOUNTS = 65_536;
/** Push states held at once; beyond it an idle one goes, or, when none is idle, a ring reaches no new endpoint. */
const MAX_PUSHES = 32_768;
const WRITE_SPACING_MS = 1_000;
const SWEEP_MS = 1_000;
/** How long an answered time for the Worker to come back is trusted to be kept; after it, another call answers it. */
const WAKE_GRACE_MS = 30_000;
const WINDOW_MS = PUSH_WINDOW * 1000;
const HOLD_MS = PUSH_HOLD * 1000;
const SEEN_MS = SEEN_TTL * 1000;
const DEDUP_MS = RING_DEDUP * 1000;
/** A state untouched for this long has nothing left to remember unless a push of it is due or in flight. */
const IDLE_MS = Math.max(DEDUP_MS, WINDOW_MS);

/** Per endpoint with a push in flight or recently sent. Never written. */
export interface PushState {
  ep: Bytes;
  qh: Bytes | null;
  kh: Bytes;
  box: Bytes;
  /** when its last push was sent (or first attempted, when dropped) */
  last: number | null;
  due: number | null;
  tries: number;
  /** the first attempt of the current push */
  first: number;
  /** the endpoint's bells that rang it since its last push, newest first, at most PUSH_BELLS */
  rang: Bytes[];
  /** the rows that rang it since its last push and that its account has not marked seen; null: too many to cancel */
  rows: Set<string> | null;
  /** when `due` handed the push to a Worker; null when none is in flight */
  inflight: number | null;
  /** the rings that came while the push was in flight, which that attempt does not carry: due after it */
  later: { rang: Bytes[]; rows: Set<string> | null } | null;
  /** the rows that rang it in the last RING_DEDUP, each with when that expires, in that order */
  recent: Map<string, number>;
}

const isBytes = (x: unknown, len: number): x is Bytes => x instanceof Uint8Array && x.length === len;
const same = (a: Bytes | null, b: Bytes | null): boolean => (a === null && b === null) || (a !== null && b !== null && sameBytes(a, b));
const EMPTY: Bytes = new Uint8Array(0);

/** `fresh` in front of `rang`, without repeats, at most PUSH_BELLS (§9.8 `ring` step 1). */
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

/** `rows` with `row`, or null once it would hold more than PUSH_PENDING (the push can then no longer be cancelled). */
function rowsWith(rows: Set<string> | null, row: string): Set<string> | null {
  if (!rows) return null;
  rows.add(row);
  return rows.size > PUSH_PENDING ? null : rows;
}

function checkTarget(x: unknown): RingTarget {
  const { ep, qh, kh, box, bells } = (typeof x === "object" && x !== null ? x : {}) as Record<string, unknown>;
  if (!isBytes(ep, 16) || !isBytes(kh, 16)) throw new TypeError("ring: bad target");
  if (qh !== null && !isBytes(qh, 16)) throw new TypeError("ring: bad target");
  if (!(box instanceof Uint8Array) || box.length === 0 || box.length > 2048) throw new TypeError("ring: bad target");
  if (!Array.isArray(bells) || bells.length === 0 || bells.length > 64 || !bells.every((b) => isBytes(b, 16))) throw new TypeError("ring: bad target");
  return { ep, qh: qh as Bytes | null, kh, box, bells: bells as Bytes[] };
}

// ───────────── stored values, as the caches keep them (§9.8 "The store") ─────────────

/** A record, `u32 day ‖ u8 notes ‖ qh[16] ‖ kh[16] ‖ tk[16] × n`; EMPTY stands for none. */
const validRecord = (b: Bytes): boolean => b.length >= 37 && (b.length - 37) % 16 === 0;
const recDay = (r: Bytes): number => new DataView(r.buffer, r.byteOffset, 4).getUint32(0);
function recQh(r: Bytes): Bytes | null {
  const q = r.subarray(5, 21);
  return isZero(q) ? null : q;
}
const recKh = (r: Bytes): Bytes => r.subarray(21, 37);
function recTks(r: Bytes): Bytes[] {
  const out: Bytes[] = [];
  for (let o = 37; o < r.length; o += 16) out.push(r.subarray(o, o + 16));
  return out;
}

/** A bell's value, `(ep[16] ‖ qh[16] ‖ kh[16] ‖ u16 len ‖ box) × m`: the offsets of its entries, or null when malformed. */
function entryOffsets(v: Bytes): number[] | null {
  const out: number[] = [];
  let o = 0;
  while (o < v.length) {
    if (o + 50 > v.length) return null;
    const end = o + 50 + ((v[o + 48] << 8) | v[o + 49]);
    if (end > v.length) return null;
    out.push(o);
    o = end;
  }
  return out;
}
const entryEnd = (v: Bytes, o: number): number => o + 50 + ((v[o + 48] << 8) | v[o + 49]);
const validBell = (v: Bytes): boolean => entryOffsets(v) !== null;

function findEntry(v: Bytes, ep: Bytes): { o: number; end: number; n: number } | null {
  const offs = entryOffsets(v) ?? [];
  for (const o of offs) if (sameBytes(v.subarray(o, o + 16), ep)) return { o, end: entryEnd(v, o), n: offs.length };
  return null;
}

/**
 * The bell's value with the endpoint's entry, replacing its own earlier one; when 8 other endpoints hold the bell it is
 * left out ("full") and takes no other endpoint's place. `value` is null when nothing changed.
 */
function placeEntry(v: Bytes, entry: Bytes): { value: Bytes | null; held: boolean } {
  const at = findEntry(v, entry.subarray(0, 16));
  if (at) {
    if (sameBytes(v.subarray(at.o, at.end), entry)) return { value: null, held: true };
    return { value: concat(v.subarray(0, at.o), entry, v.subarray(at.end)), held: true };
  }
  if ((entryOffsets(v) ?? []).length >= PUSH_PER_BELL) return { value: null, held: false };
  return { value: concat(v, entry), held: true };
}

/** The bell's value without the endpoint's entry, or null when it holds none. */
function leaveEntry(v: Bytes, ep: Bytes): Bytes | null {
  const at = findEntry(v, ep);
  return at ? concat(v.subarray(0, at.o), v.subarray(at.end)) : null;
}

// ───────────── the caches ─────────────

/**
 * A cache of stored values by key, bounded by an estimate of its bytes, least recently used first. Each entry keeps its
 * current value `v` and the value the store holds `s` (the same buffer unless a change waits for its write). A pinned
 * key (a change under way, or a write waiting) is never evicted.
 */
class ByteCache {
  private readonly map = new Map<string, { v: Bytes; s: Bytes }>();
  private readonly pins = new Map<string, number>();
  private readonly loading = new Map<string, Promise<Bytes>>();
  private bytes = 0;

  constructor(
    private readonly budget: number,
    private readonly read: (key: string) => Promise<Bytes>,
  ) {}

  private cost(key: string, e: { v: Bytes; s: Bytes }): number {
    return ENTRY_OVERHEAD + key.length * 2 + e.v.length + (e.s === e.v ? 0 : e.s.length);
  }

  /** The current value, without touching the recency order. */
  peek(key: string): Bytes | undefined {
    return this.map.get(key)?.v;
  }

  /** The value, from the cache or the store; the key stays where it is in the recency order only when cached. */
  async load(key: string): Promise<Bytes> {
    const hit = this.map.get(key);
    if (hit) {
      this.map.delete(key);
      this.map.set(key, hit);
      return hit.v;
    }
    let p = this.loading.get(key);
    if (!p) {
      p = this.read(key).finally(() => this.loading.delete(key));
      this.loading.set(key, p);
    }
    const v = await p;
    const again = this.map.get(key);
    if (again) return again.v;
    this.insert(key, { v, s: v });
    return v;
  }

  /** Pins every key, then loads them all at once; on a failure the pins are released again. */
  async loadAll(keys: readonly string[]): Promise<void> {
    for (const k of keys) this.pin(k);
    try {
      await Promise.all(keys.map((k) => this.load(k)));
    } catch (e) {
      for (const k of keys) this.unpin(k);
      throw e;
    }
  }

  /** A change of a pinned key: the store does not hold it yet. */
  set(key: string, v: Bytes): void {
    const e = this.map.get(key);
    if (!e) throw new Error("push cache: change of an absent key");
    this.bytes -= this.cost(key, e);
    e.v = v;
    this.bytes += this.cost(key, e);
    this.evict();
  }

  /** A value the store holds (written, or known to be so). */
  stored(key: string, v: Bytes): void {
    const e = this.map.get(key);
    if (!e) {
      this.insert(key, { v, s: v });
      return;
    }
    this.bytes -= this.cost(key, e);
    e.s = v;
    if (sameBytes(e.v, v)) e.v = v;
    this.bytes += this.cost(key, e);
  }

  /** Back to what the store holds: the changes that waited for a write that failed are gone. */
  revert(key: string): void {
    const e = this.map.get(key);
    if (!e) return;
    this.bytes -= this.cost(key, e);
    e.v = e.s;
    this.bytes += this.cost(key, e);
  }

  /** Drops the key's entry (its value is read from the store again when next needed). */
  forget(key: string): void {
    const e = this.map.get(key);
    if (!e) return;
    this.map.delete(key);
    this.bytes -= this.cost(key, e);
  }

  pin(key: string): void {
    this.pins.set(key, (this.pins.get(key) ?? 0) + 1);
  }

  unpin(key: string): void {
    const n = (this.pins.get(key) ?? 0) - 1;
    if (n > 0) this.pins.set(key, n);
    else this.pins.delete(key);
    this.evict();
  }

  private insert(key: string, e: { v: Bytes; s: Bytes }): void {
    this.map.set(key, e);
    this.bytes += this.cost(key, e);
    this.evict();
  }

  private evict(): void {
    if (this.bytes <= this.budget) return;
    for (const [k, e] of this.map) {
      if (this.bytes <= this.budget) break;
      if (this.pins.has(k)) continue;
      this.map.delete(k);
      this.bytes -= this.cost(k, e);
    }
  }
}

/** A min-heap of due times; an entry is current while its state's `due` is still that time and nothing is in flight. */
class DueHeap {
  private a: { at: number; k: string }[] = [];

  get size(): number {
    return this.a.length;
  }

  peek(): { at: number; k: string } | undefined {
    return this.a[0];
  }

  push(at: number, k: string): void {
    const a = this.a;
    a.push({ at, k });
    let i = a.length - 1;
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (a[p].at <= a[i].at) break;
      [a[p], a[i]] = [a[i], a[p]];
      i = p;
    }
  }

  pop(): void {
    const a = this.a;
    const last = a.pop();
    if (!last || a.length === 0) return;
    a[0] = last;
    let i = 0;
    for (;;) {
      const l = 2 * i + 1;
      const r = l + 1;
      let m = i;
      if (l < a.length && a[l].at < a[m].at) m = l;
      if (r < a.length && a[r].at < a[m].at) m = r;
      if (m === i) break;
      [a[m], a[i]] = [a[i], a[m]];
      i = m;
    }
  }

  clear(): void {
    this.a = [];
  }
}

interface Deferred {
  promise: Promise<void>;
  resolve: () => void;
  reject: (e: unknown) => void;
}
function deferred(): Deferred {
  let resolve: () => void = () => {};
  let reject: (e: unknown) => void = () => {};
  const promise = new Promise<void>((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
}

/** A key's writes: one under way at most, and the one that takes the changes made meanwhile. */
interface WriteSlot {
  running: boolean;
  next: Deferred | null;
  last: number;
}

export class QuietDO extends DurableObject<Env> {
  /** Time, randomness and sleep: instance fields so tests can replace them. */
  protected clock: () => number = () => Date.now();
  protected rand: () => number = () => Math.random();
  protected sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms));

  private readonly k: number;
  /** keyEp → the record's value (EMPTY: the store has none) */
  private readonly records: ByteCache;
  /** keyBell → the bell's value (EMPTY: no entries) */
  private readonly bells: ByteCache;
  /** ep (hex) → the change of its registration under way (one at a time per endpoint) */
  private readonly chains = new Map<string, Promise<void>>();
  /** store key → its writes */
  private readonly slots = new Map<string, WriteSlot>();
  /** store key → when its slot can go (its last write plus the spacing), in that order */
  private readonly slotIdle = new Map<string, number>();
  /** ep (hex) → its push state */
  private readonly pushes = new Map<string, PushState>();
  /** qh (hex) → the endpoints (hex) of that account with a push state */
  private readonly byQh = new Map<string, Set<string>>();
  /** the due pushes, earliest first */
  private readonly heap = new DueHeap();
  /** ep (hex) → when its push was handed out, in that order */
  private readonly inflightQ = new Map<string, number>();
  /** ep (hex) → when its state is to be looked at again, in that order */
  private readonly idle = new Map<string, number>();
  /** qh (hex) → the rows its account marked seen, each with when it expires, in that order, and when the last expires */
  private readonly marks = new Map<string, { rows: Map<string, number>; until: number }>();
  /** when `due` or `sent` last told a Worker to come back, until a `due` comes */
  private wakeAt: number | null = null;
  /** a push in flight was given up and made due again: the next ring answers its time */
  private orphans = false;
  private lastSweep = -Infinity;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.k = parseIndexName(ctx.id.name, "quiet");
    this.records = new ByteCache(CACHE_BYTES, (key) => this.readStore(key, validRecord));
    this.bells = new ByteCache(CACHE_BYTES, (key) => this.readStore(key, validBell));
  }

  // ───────────── registrations (§9.8 `sub`) ─────────────

  /**
   * Replaces an endpoint's registration as a whole (§9.8 `sub`). The Worker has checked every field (§10.10):
   * `bells` are the bells of the request's secrets, `quiet` the account's quiet tag (null only for a deletion, which
   * a tab on the first release sends without one). Empty `bells` delete the registration.
   */
  async sub(endpoint: string, p256dh: Bytes, auth: Bytes, bells: Bytes[], quiet: Bytes | null = null): Promise<void> {
    const cfg = pushConfig(this.env);
    if (!cfg) throw new Error("push is off");
    if (typeof endpoint !== "string" || !isBytes(p256dh, 65) || !isBytes(auth, 16)) throw new TypeError("sub: bad endpoint");
    if (!Array.isArray(bells) || bells.length > 256 || !bells.every((t) => isBytes(t, 16))) throw new TypeError("sub: bad bells");
    if (quiet !== null && !isBytes(quiet, 16)) throw new TypeError("sub: bad quiet tag");
    if (quiet === null && bells.length > 0) throw new TypeError("sub: quiet tag required");
    const ep = epOf(cfg.pushKey, endpoint);
    // Registered for an account whose QuietDO is another object (the Worker hands such an endpoint over, but its read
    // of the record may be a stale one): that object, the writer of its bells, takes the endpoint out of them and
    // deletes the record first. Called outside this endpoint's chain, so that two objects never wait on each other.
    const pre = await this.loadRecord(ep);
    if (pre && !this.owns(ep, pre)) await quietStub(this.env, this.ownerK(ep, pre)).drop(ep);
    await this.serial(ep, async () => {
      let old = await this.loadRecord(ep);
      if (old && !this.owns(ep, old)) {
        // Another object's record is never acted on here: replaced as a whole, or, for a deletion, left to its owner.
        old = null;
      }
      if (bells.length === 0 || quiet === null) {
        await this.remove(ep, old);
        return;
      }
      const qh = qkOf(cfg.pushKey, quiet);
      const kh = khOf(cfg.pushKey, p256dh, auth);
      const box = sealBox(cfg.pushKey, ep, { endpoint, p256dh: p256dh.slice(), auth: auth.slice() });
      const want = sortedDistinct(bells.map((b) => tkOf(cfg.pushKey, b)));
      const had = old ? recTks(old) : [];
      // New keys or another quiet tag: every kept bell is placed again, so that its entry carries them.
      const changed = !old || !sameBytes(recKh(old), kh) || !same(recQh(old), qh);
      const hadSet = new Set(had.map(hex));
      const wantSet = new Set(want.map(hex));
      const removed = had.filter((t) => !wantSet.has(hex(t)));
      const added = want.filter((t) => changed || !hadSet.has(hex(t)));
      const held: Bytes[] = changed ? [] : want.filter((t) => hadSet.has(hex(t)));
      const entry = concat(ep, qh, kh, u16(box.length), box);
      held.push(...(await this.editBells(ep, removed, added, entry)));
      const rec = encodeRecord({ day: dayOf(this.clock()), notes: false, qh, kh, tks: sortedDistinct(held) });
      if (!old || !sameBytes(old, rec)) {
        this.records.set(keyEp(ep), rec);
        await this.flush(keyEp(ep));
      }
      // A push in flight to it goes to the newest keys.
      const k = hex(ep);
      const st = this.pushes.get(k);
      if (st) {
        Object.assign(st, { box, kh });
        this.setQh(k, st, qh);
      }
    });
  }

  /** Deletes an endpoint's registration (§9.8 `sub` step 1): `gone` at a push, and a hand-over to another owner. */
  async drop(ep: Bytes): Promise<void> {
    if (!isBytes(ep, 16)) throw new TypeError("drop: bad endpoint");
    await this.serial(ep, async () => {
      await this.remove(ep, await this.loadRecord(ep));
    });
  }

  /**
   * The daily expiry of `day` (§9.8 "Expiry"): deletes each of these endpoints whose record, as this object holds it,
   * still lies more than PUSH_EXPIRY days back. Answers how many it deleted.
   */
  async expire(eps: Bytes[], day: number): Promise<number> {
    if (!Array.isArray(eps) || eps.length > 256 || !eps.every((e) => isBytes(e, 16))) throw new TypeError("expire: bad endpoints");
    if (!Number.isInteger(day) || day < 0) throw new TypeError("expire: bad day");
    let n = 0;
    const res = await Promise.allSettled(
      eps.map((ep) =>
        this.serial(ep, async () => {
          const rec = await this.loadRecord(ep);
          // Registered again since the listing, or now another object's: kept.
          if (!rec || !this.owns(ep, rec) || day - recDay(rec) <= PUSH_EXPIRY) return;
          await this.remove(ep, rec);
          n++;
        }),
      ),
    );
    const failed = res.find((r): r is PromiseRejectedResult => r.status === "rejected");
    if (failed) throw failed.reason;
    return n;
  }

  /** The endpoint's record as this object holds it (tests). */
  async recordOf(ep: Bytes): Promise<EpRecord | null> {
    if (!isBytes(ep, 16)) throw new TypeError("recordOf: bad endpoint");
    let out: EpRecord | null = null;
    await this.serial(ep, async () => {
      const v = await this.loadRecord(ep);
      out = v ? decodeRecord(v) : null;
    });
    return out;
  }

  /** The entries under a bell as this object holds them (tests). */
  async entriesOf(tk: Bytes): Promise<BellEntry[]> {
    if (!isBytes(tk, 16)) throw new TypeError("entriesOf: bad bell");
    return decodeEntries(await this.bells.load(keyBell(tk))) ?? [];
  }

  // ───────────── rings and pushes ─────────────

  /**
   * §9.8 `ring`: the pushes that a fresh row's ring makes due to this object's endpoints. Answers the time until the
   * earliest of them that is not in flight (or until a push that a stopped Worker left, made due again), or null.
   * Writes nothing.
   */
  ring(targets: RingTarget[], row: string): number | null {
    if (!Array.isArray(targets) || targets.length > 4096) throw new TypeError("ring: bad targets");
    if (typeof row !== "string" || !/^[0-9a-f]{32}$/.test(row)) throw new TypeError("ring: bad row");
    const list = targets.map(checkTarget);
    const now = this.clock();
    this.sweep(now);
    let first = Infinity;
    let full = 0;
    for (const t of list) {
      const k = hex(t.ep);
      // A device of its account has shown this row while in use (§9.8 `seen`).
      if (t.qh && (this.marks.get(hex(t.qh))?.rows.get(row) ?? 0) > now) continue;
      let st = this.pushes.get(k);
      if (!st) {
        if (this.pushes.size >= MAX_PUSHES && !this.evictIdle()) {
          full++;
          continue;
        }
        st = { ep: t.ep, qh: null, kh: t.kh, box: t.box, last: null, due: null, tries: 0, first: 0, rang: [], rows: null, inflight: null, later: null, recent: new Map() };
        this.pushes.set(k, st);
      } else Object.assign(st, { kh: t.kh, box: t.box });
      this.setQh(k, st, t.qh);
      this.touch(k, now);
      for (const [id, exp] of st.recent) {
        if (exp > now) break;
        st.recent.delete(id);
      }
      // The row rang it recently: a sender's repeat of the ring changes nothing.
      if (st.recent.has(row)) {
        if (st.due !== null && st.inflight === null) first = Math.min(first, st.due);
        continue;
      }
      st.recent.set(row, now + DEDUP_MS);
      while (st.recent.size > RECENT_ROWS) st.recent.delete(st.recent.keys().next().value as string);
      st.rang = rangWith(t.bells, st.rang);
      if (st.due !== null) {
        st.rows = rowsWith(st.rows, row);
        if (st.inflight !== null) {
          // The attempt out now was made without this ring: whatever its answer, this ring stays due after it.
          const l = st.later ?? { rang: [], rows: new Set<string>() };
          st.later = { rang: rangWith(t.bells, l.rang), rows: rowsWith(l.rows, row) };
        } else first = Math.min(first, st.due);
        continue;
      }
      Object.assign(st, { tries: 0, rows: new Set([row]), later: null });
      const due = this.dueAfter(now, st.last);
      this.setDue(st, due);
      first = Math.min(first, due);
    }
    if (full > 0) console.error(JSON.stringify({ msg: "push states full", skipped: full }));
    if (this.orphans) {
      this.orphans = false;
      const top = this.topDue();
      if (top) first = Math.min(first, top.at);
    }
    return first === Infinity ? null : Math.max(0, first - now);
  }

  /**
   * §9.8 `due`: the pushes due now, earliest first, at most `max`, from then on in flight (a mark no longer cancels
   * them), and the time until the Worker is to ask again: at once when more are due now, or when the next is due.
   */
  due(max: number = DUE_BATCH): DueBatch {
    if (!Number.isInteger(max) || max < 1 || max > DUE_BATCH) throw new TypeError("due: bad max");
    const now = this.clock();
    this.sweep(now);
    this.wakeAt = null;
    const pushes: DuePush[] = [];
    while (pushes.length < max) {
      const top = this.topDue();
      if (!top || top.at > now) break;
      this.heap.pop();
      const st = this.pushes.get(top.k) as PushState;
      st.inflight = now;
      if (st.tries === 0) st.first = now;
      // What this attempt carries: rings from here on go to `later` as well.
      st.later = null;
      this.inflightQ.delete(top.k);
      this.inflightQ.set(top.k, now);
      this.touch(top.k, now);
      pushes.push({ ep: st.ep, kh: st.kh, box: st.box, rang: [...st.rang] });
    }
    return { pushes, next: this.comeBack(now) };
  }

  /**
   * §9.8 `sent`: the Worker's reports. Answers the time until the Worker is to ask again (a retry, the rings that came
   * while the pushes were out, or another push due), or null. A `gone` deletes the registration unless the device
   * registered other keys meanwhile.
   */
  async sent(reports: SentReport[]): Promise<number | null> {
    if (!Array.isArray(reports) || reports.length > 4096) throw new TypeError("sent: bad reports");
    const now = this.clock();
    const gone: { ep: Bytes; kh: Bytes }[] = [];
    for (const r of reports) {
      const { ep, kh, outcome, retryAfterS } = (typeof r === "object" && r !== null ? r : {}) as Record<string, unknown>;
      if (!isBytes(ep, 16) || !isBytes(kh, 16)) throw new TypeError("sent: bad report");
      if (outcome !== "sent" && outcome !== "retry" && outcome !== "gone") throw new TypeError("sent: bad report");
      const k = hex(ep);
      const st = this.pushes.get(k);
      if (!st) continue;
      // A late report of an attempt already given up (its retry is under way) changes nothing but a `gone`.
      if (st.inflight === null && outcome !== "gone") continue;
      st.inflight = null;
      this.inflightQ.delete(k);
      this.touch(k, now);
      if (outcome === "sent") this.ended(st, now, now);
      else if (outcome === "retry") {
        const ra = typeof retryAfterS === "number" && Number.isFinite(retryAfterS) && retryAfterS >= 0 && retryAfterS <= 60 ? retryAfterS * 1000 : RETRY_MS;
        this.failed(st, now, ra);
      } else {
        this.forgetPush(k);
        gone.push({ ep, kh });
      }
    }
    for (const g of gone) {
      await this.serial(g.ep, async () => {
        const rec = await this.loadRecord(g.ep);
        // Registered again with other keys since the push was made: that registration stays.
        if (rec && sameBytes(recKh(rec), g.kh)) await this.remove(g.ep, rec);
      });
    }
    return this.comeBack(now);
  }

  /** §9.8 `seen`: rows an account's device has shown while in use. Writes nothing. */
  seen(qh: Bytes, rows: { E: number; label: Bytes }[]): void {
    if (!isBytes(qh, 16)) throw new TypeError("seen: bad quiet tag");
    if (!Array.isArray(rows) || rows.length === 0 || rows.length > 16) throw new TypeError("seen: bad rows");
    const ids = new Set<string>();
    for (const r of rows) {
      const { E, label } = (typeof r === "object" && r !== null ? r : {}) as Record<string, unknown>;
      if (!Number.isInteger(E) || (E as number) < 0 || (E as number) > 0xffff || !isBytes(label, 16)) throw new TypeError("seen: bad row");
      ids.add(rowIdOf(E as number, label));
    }
    const now = this.clock();
    this.sweep(now);
    const key = hex(qh);
    const m = this.marks.get(key) ?? { rows: new Map<string, number>(), until: 0 };
    for (const [id, exp] of m.rows) {
      if (exp > now) break;
      m.rows.delete(id);
    }
    for (const id of ids) {
      // Deleted and set again, so the map stays in the order in which its marks expire.
      m.rows.delete(id);
      m.rows.set(id, now + SEEN_MS);
    }
    while (m.rows.size > PUSH_SEEN) m.rows.delete(m.rows.keys().next().value as string);
    m.until = now + SEEN_MS;
    // Deleted and set again, so the accounts stay in the order in which their last marks expire.
    this.marks.delete(key);
    this.marks.set(key, m);
    while (this.marks.size > MARK_ACCOUNTS) this.marks.delete(this.marks.keys().next().value as string);
    for (const k of this.byQh.get(key) ?? []) {
      const st = this.pushes.get(k);
      if (!st || st.due === null) continue;
      if (st.later?.rows) for (const id of ids) st.later.rows.delete(id);
      if (!st.rows) continue;
      for (const id of ids) st.rows.delete(id);
      if (st.rows.size === 0 && st.inflight === null) this.cancel(st);
    }
  }

  /** An endpoint's push state (tests). */
  stateOf(ep: Bytes): (Omit<PushState, "box" | "recent"> & { recent: string[] }) | null {
    if (!isBytes(ep, 16)) throw new TypeError("stateOf: bad endpoint");
    const st = this.pushes.get(hex(ep));
    if (!st) return null;
    const { box: _box, recent, ...rest } = st;
    const now = this.clock();
    return {
      ...rest,
      rang: [...st.rang],
      rows: st.rows ? new Set(st.rows) : null,
      later: st.later ? { rang: [...st.later.rang], rows: st.later.rows ? new Set(st.later.rows) : null } : null,
      recent: [...recent].filter(([, exp]) => exp > now).map(([id]) => id),
    };
  }

  /** The number of rows an account has marked seen (tests). */
  marksOf(qh: Bytes): number {
    if (!isBytes(qh, 16)) throw new TypeError("marksOf: bad quiet tag");
    const now = this.clock();
    this.sweep(now);
    let n = 0;
    for (const exp of this.marks.get(hex(qh))?.rows.values() ?? []) if (exp > now) n++;
    return n;
  }

  // ───────────── push states ─────────────

  /** The `due` of a push that rings make due at `now` (§9.8 `ring` step 1), j drawn afresh. */
  private dueAfter(now: number, last: number | null): number {
    const jitter = v2Params(this.env).delta * 1000;
    return Math.max(now + HOLD_MS, last === null ? 0 : last + WINDOW_MS) + Math.floor(this.rand() * (jitter + 1));
  }

  private setDue(st: PushState, due: number | null): void {
    st.due = due;
    if (due === null) return;
    this.heap.push(due, hex(st.ep));
    // Entries of pushes no longer due at that time wait in the heap until they come up; never more than this many.
    if (this.heap.size > 2 * this.pushes.size + 1024) {
      this.heap.clear();
      for (const [k, s] of this.pushes) if (s.due !== null && s.inflight === null) this.heap.push(s.due, k);
    }
  }

  /** The earliest due push not in flight; stale heap entries are dropped on the way. */
  private topDue(): { at: number; k: string } | undefined {
    for (;;) {
      const top = this.heap.peek();
      if (!top) return undefined;
      const st = this.pushes.get(top.k);
      if (st && st.due === top.at && st.inflight === null) return top;
      this.heap.pop();
    }
  }

  /**
   * The time until a Worker is to call `due` again, answered by `due` and `sent`: null when nothing is due, or when an
   * earlier answer already brings a Worker back by then.
   */
  private comeBack(now: number): number | null {
    this.orphans = false;
    const top = this.topDue();
    if (!top) return null;
    const at = Math.max(top.at, now);
    if (this.wakeAt !== null && this.wakeAt <= at && this.wakeAt + WAKE_GRACE_MS >= now) return null;
    this.wakeAt = at;
    return at - now;
  }

  /** A push sent or dropped: the rings that came while its attempt was out are due after it. */
  private ended(st: PushState, last: number, now: number): void {
    const l = st.later;
    Object.assign(st, { last, tries: 0, rang: [], rows: new Set(), later: null });
    this.setDue(st, null);
    if (l && l.rows?.size !== 0) {
      Object.assign(st, { rang: l.rang, rows: l.rows });
      this.setDue(st, this.dueAfter(now, last));
    }
  }

  /** A failed attempt: cancelled when every row of it was marked seen, retried once, or else dropped. */
  private failed(st: PushState, now: number, retryMs: number): void {
    if (st.rows?.size === 0) this.cancel(st);
    else if (st.tries === 0) {
      // The retry carries the rings that came meanwhile: they are in `rang` and `rows` already.
      Object.assign(st, { tries: 1, later: null });
      this.setDue(st, now + retryMs);
    } else this.ended(st, st.first, now);
  }

  private cancel(st: PushState): void {
    Object.assign(st, { tries: 0, rang: [], rows: new Set(), later: null });
    this.setDue(st, null);
  }

  private setQh(k: string, st: PushState, qh: Bytes | null): void {
    if (same(st.qh, qh) && (qh === null || this.byQh.get(hex(qh))?.has(k))) return;
    if (st.qh) this.unindex(k, st.qh);
    st.qh = qh;
    if (qh) {
      const q = hex(qh);
      const set = this.byQh.get(q) ?? new Set<string>();
      set.add(k);
      this.byQh.set(q, set);
    }
  }

  private unindex(k: string, qh: Bytes): void {
    const q = hex(qh);
    const set = this.byQh.get(q);
    if (!set) return;
    set.delete(k);
    if (set.size === 0) this.byQh.delete(q);
  }

  private forgetPush(k: string): void {
    const st = this.pushes.get(k);
    if (!st) return;
    if (st.qh) this.unindex(k, st.qh);
    this.pushes.delete(k);
    this.inflightQ.delete(k);
    this.idle.delete(k);
  }

  /** Puts the state at the end of the idle order: looked at again IDLE_MS from now. */
  private touch(k: string, now: number): void {
    this.idle.delete(k);
    this.idle.set(k, now + IDLE_MS);
  }

  /** Makes room for a state: forgets the least recently touched one that has no push due or in flight, if any. */
  private evictIdle(): boolean {
    let looked = 0;
    for (const k of this.idle.keys()) {
      if (++looked > 64) break;
      const st = this.pushes.get(k);
      if (!st || (st.due === null && st.inflight === null)) {
        this.forgetPush(k);
        this.idle.delete(k);
        return true;
      }
    }
    return false;
  }

  /**
   * At most once a second: drops the accounts whose marks have all expired, gives up the pushes in flight too long
   * (made due again once, as a failed attempt is retried), forgets the states with nothing left to remember, and the
   * write slots no longer needed for spacing. Each list is in the order in which its entries expire, so each pass stops
   * at the first entry that has not.
   */
  private sweep(now: number): void {
    if (now >= this.lastSweep && now - this.lastSweep < SWEEP_MS) return;
    this.lastSweep = now;
    for (const [q, m] of this.marks) {
      if (m.until > now) break;
      this.marks.delete(q);
    }
    for (const [k, at] of this.inflightQ) {
      if (at + INFLIGHT_MS > now) break;
      this.inflightQ.delete(k);
      const st = this.pushes.get(k);
      if (!st || st.inflight !== at) continue;
      // The Worker that took it never reported back (it was stopped): as a failed attempt, retried once.
      st.inflight = null;
      this.failed(st, now, 0);
      this.touch(k, now);
      this.orphans = true;
    }
    for (const [k, at] of this.idle) {
      if (at > now) break;
      this.idle.delete(k);
      const st = this.pushes.get(k);
      if (!st) continue;
      for (const [id, exp] of st.recent) {
        if (exp > now) break;
        st.recent.delete(id);
      }
      if (st.due === null && st.inflight === null && st.recent.size === 0 && (st.last === null || st.last + WINDOW_MS <= now)) this.forgetPush(k);
      else this.idle.set(k, now + IDLE_MS);
    }
    for (const [key, at] of this.slotIdle) {
      if (at > now) break;
      this.slotIdle.delete(key);
      const s = this.slots.get(key);
      if (s && !s.running && !s.next) this.slots.delete(key);
    }
  }

  // ───────────── registrations: internals ─────────────

  /**
   * One change of an endpoint's registration at a time; its record stays cached meanwhile, and afterwards only when it
   * is this object's own: no record, or another object's, is read from the store again at the next change, since that
   * object may write it meanwhile.
   */
  private serial(ep: Bytes, fn: () => Promise<void>): Promise<void> {
    const k = hex(ep);
    const key = keyEp(ep);
    const run = async (): Promise<void> => {
      this.records.pin(key);
      try {
        await fn();
      } finally {
        this.records.unpin(key);
        const v = this.records.peek(key);
        if (v !== undefined && (v.length === 0 || !this.owns(ep, v))) this.records.forget(key);
      }
    };
    const prev = this.chains.get(k) ?? Promise.resolve();
    const next = prev.then(run, run).finally(() => {
      if (this.chains.get(k) === next) this.chains.delete(k);
    });
    this.chains.set(k, next);
    return next;
  }

  private async loadRecord(ep: Bytes): Promise<Bytes | null> {
    const v = await this.records.load(keyEp(ep));
    return v.length > 0 ? v : null;
  }

  /** The QuietDO of a record's owner under the current PUSH_SHARDS. */
  private ownerK(ep: Bytes, rec: Bytes): number {
    return quietShard(ownerOf(ep, recQh(rec)), pushShardsOf(this.env) ?? 1);
  }

  /** Whether this object writes the record's keys (one writer per key: its owner's QuietDO). */
  private owns(ep: Bytes, rec: Bytes): boolean {
    return this.ownerK(ep, rec) === this.k;
  }

  /** Takes the endpoint out of every bell its record holds, deletes the record, and forgets its pushes. */
  private async remove(ep: Bytes, old: Bytes | null): Promise<void> {
    this.forgetPush(hex(ep));
    // Another object's record is never acted on here (sub() hands it over first).
    if (!old || !this.owns(ep, old)) return;
    await this.editBells(ep, recTks(old), [], null);
    this.records.set(keyEp(ep), EMPTY);
    await this.flush(keyEp(ep));
  }

  /**
   * Takes the endpoint out of the bells `leave` and puts `entry` under the bells `place` (§9.8 `sub` step 2): every
   * bell read at once, each change made in the cache and its write queued at once, and all of them awaited. Answers the
   * bells of `place` that the endpoint holds. Throws when a write failed for good.
   */
  private async editBells(ep: Bytes, leave: readonly Bytes[], place: readonly Bytes[], entry: Bytes | null): Promise<Bytes[]> {
    const keys = [...new Set([...leave, ...place].map(keyBell))];
    if (keys.length === 0) return [];
    await this.bells.loadAll(keys);
    const writes: Promise<void>[] = [];
    const held: Bytes[] = [];
    const current = (key: string): Bytes => {
      const v = this.bells.peek(key);
      if (v === undefined) throw new Error("push cache: a pinned bell is absent");
      return v;
    };
    try {
      for (const t of leave) {
        const key = keyBell(t);
        const v = leaveEntry(current(key), ep);
        if (v === null) continue;
        this.bells.set(key, v);
        writes.push(this.flush(key));
      }
      if (entry) {
        for (const t of place) {
          const key = keyBell(t);
          const r = placeEntry(current(key), entry);
          if (r.held) held.push(t);
          if (r.value === null) continue;
          this.bells.set(key, r.value);
          writes.push(this.flush(key));
        }
      }
    } finally {
      for (const key of keys) this.bells.unpin(key);
    }
    await Promise.all(writes);
    return held;
  }

  // ───────────── the store writer ─────────────

  private cacheOf(key: string): ByteCache {
    return key.startsWith("e/") ? this.records : this.bells;
  }

  /**
   * Writes the key's current cached value to the store: one write per key at a time, at least WRITE_SPACING_MS after
   * the previous one; a change made while a write is under way goes into the next one, which every change made before
   * it starts shares. A write that fails is tried once more; when that fails as well, the cache goes back to what the
   * store holds and the write rejects, as does the next one, whose changes went with it.
   */
  private flush(key: string): Promise<void> {
    let s = this.slots.get(key);
    if (!s) {
      s = { running: false, next: null, last: -Infinity };
      this.slots.set(key, s);
    }
    if (s.next) return s.next.promise;
    this.cacheOf(key).pin(key);
    const d = deferred();
    if (s.running) s.next = d;
    else this.run(key, s, d);
    return d.promise;
  }

  private run(key: string, s: WriteSlot, d: Deferred): void {
    s.running = true;
    const cache = this.cacheOf(key);
    void (async () => {
      try {
        const wait = s.last + WRITE_SPACING_MS - this.clock();
        if (wait > 0) await this.sleep(wait);
        const v = cache.peek(key);
        if (v === undefined) throw new Error("push cache: a pending value is absent");
        try {
          await this.storeWrite(key, v);
        } catch (e) {
          console.error(JSON.stringify({ msg: "push store write failed", error: logErr(e) }));
          await this.sleep(WRITE_SPACING_MS + 100);
          await this.storeWrite(key, v);
        }
        cache.stored(key, v);
        d.resolve();
      } catch (e) {
        console.error(JSON.stringify({ msg: "push store write failed", error: logErr(e) }));
        cache.revert(key);
        d.reject(e);
        if (s.next) {
          s.next.reject(e);
          s.next = null;
          cache.unpin(key);
        }
      } finally {
        s.last = this.clock();
        s.running = false;
        cache.unpin(key);
        this.slotIdle.delete(key);
        this.slotIdle.set(key, s.last + WRITE_SPACING_MS);
        const n = s.next;
        if (n) {
          s.next = null;
          this.run(key, s, n);
        }
      }
    })();
  }

  private async storeWrite(key: string, v: Bytes): Promise<void> {
    if (v.length === 0) await this.env.PUSH_KV.delete(key);
    else if (key.startsWith("e/")) {
      const owner = ownerOf(fromHex(key.slice(2)), recQh(v));
      await this.env.PUSH_KV.put(key, v, { metadata: { d: recDay(v), o: hex(owner) } });
    } else await this.env.PUSH_KV.put(key, v);
  }

  private async readStore(key: string, valid: (b: Bytes) => boolean): Promise<Bytes> {
    try {
      const raw = await this.env.PUSH_KV.get(key, "arrayBuffer");
      if (!raw) return EMPTY;
      const b = new Uint8Array(raw);
      return valid(b) ? b : EMPTY;
    } catch (e) {
      console.error(JSON.stringify({ msg: "push store read failed", error: logErr(e) }));
      throw e;
    }
  }
}

