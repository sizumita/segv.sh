/**
 * QuietDO — one of PUSH_SHARDS objects that own the push registrations of their endpoints (docs/PROTOCOL.md §9.8).
 * Name "quiet/v2/{k}"; an endpoint's object is quietShard(owner), the owner being its account's quiet tag (keyed hash)
 * or, for an endpoint that registered none, its own hash: all endpoints of one account are here. It has no storage of
 * its own.
 *
 *  - The records (`e/<ep>` of the push store): read into a bounded cache, written by this object alone, one change of
 *    an endpoint at a time. sub() applies a registration: it tells the BellDOs which bells the endpoint leaves and
 *    takes, and writes the record when anything in it changed (the day included). drop() deletes one.
 *  - Everything a ring causes, never written: per endpoint `last`, `due`, `tries`, `rang`, `rows`, the rows that rang
 *    it recently (so that a sender's repeat changes nothing) and the push in flight; and the rows each account marked
 *    seen. ring() makes pushes due (the hold, the window, the jitter), due() hands the Worker those due now, sent()
 *    takes its reports, seen() marks rows and cancels waiting pushes.
 */
import { DurableObject } from "cloudflare:workers";
import { hex, type Bytes } from "@segv/protocol/proto";
import { pushConfig, pushShardsOf, v2Params } from "./env";
import { logErr } from "./http";
import {
  INFLIGHT_MS,
  PUSH_HOLD,
  PUSH_PENDING,
  PUSH_SEEN,
  PUSH_WINDOW,
  RETRY_MS,
  RING_DEDUP,
  SEEN_TTL,
  bellShard,
  dayOf,
  decodeRecord,
  encodeRecord,
  epOf,
  keyEp,
  khOf,
  ownerOf,
  qkOf,
  rowIdOf,
  sameBytes,
  sealBox,
  sortedDistinct,
  tkOf,
  type DuePush,
  type EpRecord,
  type RingTarget,
  type SentReport,
} from "./push";
import { PUSH_BELLS } from "./webpush";
import { bellStub, parseIndexName } from "./types";

/** Records kept in memory; the least recently used go first (the store keeps them). */
const CACHE_RECORDS = 32_768;
/** Rows remembered per endpoint as having rung it (RING_DEDUP). */
const RECENT_ROWS = 64;
/** Accounts whose marks are held at once; beyond it the account marked longest ago goes (marks expire anyway). */
const MARK_ACCOUNTS = 65_536;
const WRITE_SPACING_MS = 1_000;
const WINDOW_MS = PUSH_WINDOW * 1000;
const HOLD_MS = PUSH_HOLD * 1000;
const SEEN_MS = SEEN_TTL * 1000;
const DEDUP_MS = RING_DEDUP * 1000;

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
  /** the rows that rang it in the last RING_DEDUP, each with when that expires, in that order */
  recent: Map<string, number>;
}

const isBytes = (x: unknown, len: number): x is Bytes => x instanceof Uint8Array && x.length === len;
const same = (a: Bytes | null, b: Bytes | null): boolean => (a === null && b === null) || (a !== null && b !== null && sameBytes(a, b));

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

function sameRecord(a: EpRecord, b: EpRecord): boolean {
  return (
    a.day === b.day &&
    a.notes === b.notes &&
    same(a.qh, b.qh) &&
    sameBytes(a.kh, b.kh) &&
    a.tks.length === b.tks.length &&
    a.tks.every((t, i) => sameBytes(t, b.tks[i]))
  );
}

function checkTarget(x: unknown): RingTarget {
  const { ep, qh, kh, box, bells } = (typeof x === "object" && x !== null ? x : {}) as Record<string, unknown>;
  if (!isBytes(ep, 16) || !isBytes(kh, 16)) throw new TypeError("ring: bad target");
  if (qh !== null && !isBytes(qh, 16)) throw new TypeError("ring: bad target");
  if (!(box instanceof Uint8Array) || box.length === 0 || box.length > 2048) throw new TypeError("ring: bad target");
  if (!Array.isArray(bells) || bells.length === 0 || bells.length > 64 || !bells.every((b) => isBytes(b, 16))) throw new TypeError("ring: bad target");
  return { ep, qh: qh as Bytes | null, kh, box, bells: bells as Bytes[] };
}

export class QuietDO extends DurableObject<Env> {
  /** Time, randomness and sleep: instance fields so tests can replace them. */
  protected clock: () => number = () => Date.now();
  protected rand: () => number = () => Math.random();
  protected sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms));

  private readonly k: number;
  /** ep (hex) → its record, or null when the store has none; insertion order is the recency order */
  private readonly records = new Map<string, EpRecord | null>();
  /** ep (hex) → the change of its registration under way (one at a time per endpoint) */
  private readonly chains = new Map<string, Promise<void>>();
  /** ep (hex) → when its record was last written */
  private readonly lastWrite = new Map<string, number>();
  private readonly pushes = new Map<string, PushState>();
  /** qh (hex) → the rows its account marked seen, each with when it expires, in that order */
  private readonly marks = new Map<string, Map<string, number>>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.k = parseIndexName(ctx.id.name, "quiet");
  }

  // ───────────── registrations (§9.8 `sub`) ─────────────

  /**
   * Replaces an endpoint's registration as a whole (§9.8 `sub`). The Worker has checked every field (§10.10):
   * `tokens` are bells, `quiet` the account's quiet tag (or null). Empty `tokens` delete the registration.
   */
  async sub(endpoint: string, p256dh: Bytes, auth: Bytes, tokens: Bytes[], quiet: Bytes | null = null): Promise<void> {
    const cfg = pushConfig(this.env);
    if (!cfg) throw new Error("push is off");
    if (typeof endpoint !== "string" || !isBytes(p256dh, 65) || !isBytes(auth, 16)) throw new TypeError("sub: bad endpoint");
    if (!Array.isArray(tokens) || tokens.length > 256 || !tokens.every((t) => isBytes(t, 16))) throw new TypeError("sub: bad tokens");
    if (quiet !== null && !isBytes(quiet, 16)) throw new TypeError("sub: bad quiet tag");
    const ep = epOf(cfg.pushKey, endpoint);
    await this.serial(ep, async () => {
      const old = await this.loadRecord(ep);
      if (tokens.length === 0) {
        await this.remove(ep, old);
        return;
      }
      const qh = quiet ? qkOf(cfg.pushKey, quiet) : null;
      const kh = khOf(cfg.pushKey, p256dh, auth);
      const box = sealBox(cfg.pushKey, ep, { endpoint, p256dh: p256dh.slice(), auth: auth.slice() });
      const want = sortedDistinct(tokens.map((b) => tkOf(cfg.pushKey, b)));
      const had = old?.tks ?? [];
      // New keys or another quiet tag: every kept bell is placed again, so that its entry carries them.
      const changed = !old || !sameBytes(old.kh, kh) || !same(old.qh, qh);
      const hadSet = new Set(had.map(hex));
      const wantSet = new Set(want.map(hex));
      const removed = had.filter((t) => !wantSet.has(hex(t)));
      const added = want.filter((t) => changed || !hadSet.has(hex(t)));
      const held: Bytes[] = changed ? [] : want.filter((t) => hadSet.has(hex(t)));
      const shards = cfg.shards;
      const per = new Map<number, { add: Bytes[]; remove: Bytes[] }>();
      const group = (j: number): { add: Bytes[]; remove: Bytes[] } => {
        let g = per.get(j);
        if (!g) per.set(j, (g = { add: [], remove: [] }));
        return g;
      };
      for (const t of removed) group(bellShard(t, shards)).remove.push(t);
      for (const t of added) group(bellShard(t, shards)).add.push(t);
      await Promise.all(
        [...per].map(async ([j, g]) => {
          const r = await bellStub(this.env, j).apply(ep, qh, kh, box, g.add, g.remove);
          held.push(...r.held);
        }),
      );
      const rec: EpRecord = { day: dayOf(this.clock()), notes: false, qh, kh, tks: sortedDistinct(held) };
      if (!old || !sameRecord(old, rec)) await this.writeRecord(ep, rec);
      // A push in flight to it goes to the newest keys.
      const st = this.pushes.get(hex(ep));
      if (st) Object.assign(st, { box, kh, qh });
    });
  }

  /** Deletes an endpoint's registration (§9.8 `sub` step 1): the daily expiry, and `gone` at a push. */
  async drop(ep: Bytes): Promise<void> {
    if (!isBytes(ep, 16)) throw new TypeError("drop: bad endpoint");
    await this.serial(ep, async () => {
      await this.remove(ep, await this.loadRecord(ep));
    });
  }

  /** The endpoint's record as this object holds it (tests). */
  async recordOf(ep: Bytes): Promise<EpRecord | null> {
    if (!isBytes(ep, 16)) throw new TypeError("recordOf: bad endpoint");
    return this.loadRecord(ep);
  }

  // ───────────── rings and pushes ─────────────

  /**
   * §9.8 `ring`: the pushes that a fresh row's ring makes due to this object's endpoints. Answers the time until the
   * earliest of them, or null when it made none due. Writes nothing.
   */
  ring(targets: RingTarget[], row: string): number | null {
    if (!Array.isArray(targets) || targets.length > 4096) throw new TypeError("ring: bad targets");
    if (typeof row !== "string" || !/^[0-9a-f]{32}$/.test(row)) throw new TypeError("ring: bad row");
    const list = targets.map(checkTarget);
    const now = this.clock();
    this.cleanup(now);
    const jitter = v2Params(this.env).delta * 1000;
    let first = Infinity;
    for (const t of list) {
      const k = hex(t.ep);
      // A device of its account has shown this row while in use (§9.8 `seen`).
      if (t.qh && (this.marks.get(hex(t.qh))?.get(row) ?? 0) > now) continue;
      let st = this.pushes.get(k);
      if (!st) {
        st = { ep: t.ep, qh: t.qh, kh: t.kh, box: t.box, last: null, due: null, tries: 0, first: 0, rang: [], rows: null, inflight: null, recent: new Map() };
        this.pushes.set(k, st);
      } else Object.assign(st, { qh: t.qh, kh: t.kh, box: t.box });
      // The row rang it recently: a sender's repeat of the ring changes nothing.
      if ((st.recent.get(row) ?? 0) > now) {
        if (st.due !== null) first = Math.min(first, st.due);
        continue;
      }
      st.recent.delete(row);
      st.recent.set(row, now + DEDUP_MS);
      while (st.recent.size > RECENT_ROWS) st.recent.delete(st.recent.keys().next().value as string);
      st.rang = rangWith(t.bells, st.rang);
      if (st.due !== null) {
        if (st.rows) {
          st.rows.add(row);
          if (st.rows.size > PUSH_PENDING) st.rows = null;
        }
        first = Math.min(first, st.due);
        continue;
      }
      const due = Math.max(now + HOLD_MS, st.last === null ? 0 : st.last + WINDOW_MS) + Math.floor(this.rand() * (jitter + 1));
      Object.assign(st, { due, tries: 0, rows: new Set([row]) });
      first = Math.min(first, due);
    }
    return first === Infinity ? null : Math.max(0, first - now);
  }

  /** §9.8 `due`: the pushes due now, earliest first, from then on in flight (a mark no longer cancels them). */
  due(): DuePush[] {
    const now = this.clock();
    this.cleanup(now);
    const out: PushState[] = [];
    for (const st of this.pushes.values()) {
      if (st.due === null || st.due > now || st.inflight !== null) continue;
      out.push(st);
    }
    out.sort((a, b) => (a.due as number) - (b.due as number));
    return out.map((st) => {
      st.inflight = now;
      if (st.tries === 0) st.first = now;
      return { ep: st.ep, kh: st.kh, box: st.box, rang: [...st.rang] };
    });
  }

  /**
   * §9.8 `sent`: the Worker's reports. Answers the time until the earliest retry it made due, or null. A `gone`
   * deletes the registration unless the device registered other keys meanwhile.
   */
  async sent(reports: SentReport[]): Promise<number | null> {
    if (!Array.isArray(reports) || reports.length > 4096) throw new TypeError("sent: bad reports");
    const now = this.clock();
    let earliest = Infinity;
    const gone: { ep: Bytes; kh: Bytes }[] = [];
    for (const r of reports) {
      const { ep, kh, outcome, retryAfterS } = (typeof r === "object" && r !== null ? r : {}) as Record<string, unknown>;
      if (!isBytes(ep, 16) || !isBytes(kh, 16)) throw new TypeError("sent: bad report");
      if (outcome !== "sent" && outcome !== "retry" && outcome !== "gone") throw new TypeError("sent: bad report");
      const st = this.pushes.get(hex(ep));
      if (!st) continue;
      st.inflight = null;
      if (outcome === "sent") {
        Object.assign(st, { last: now, due: null, tries: 0, rang: [], rows: new Set() });
      } else if (outcome === "retry") {
        if (st.rows?.size === 0) {
          // Every row that rang it was marked seen while this attempt was out: cancelled rather than retried.
          Object.assign(st, { due: null, tries: 0, rang: [], rows: new Set() });
        } else if (st.tries === 0) {
          const ra = typeof retryAfterS === "number" && Number.isFinite(retryAfterS) ? retryAfterS : null;
          const due = now + (ra !== null && ra >= 0 && ra <= 60 ? ra * 1000 : RETRY_MS);
          Object.assign(st, { tries: 1, due });
          earliest = Math.min(earliest, due);
        } else {
          Object.assign(st, { last: st.first, due: null, tries: 0, rang: [], rows: new Set() });
        }
      } else {
        this.pushes.delete(hex(ep));
        gone.push({ ep, kh });
      }
    }
    for (const g of gone) {
      await this.serial(g.ep, async () => {
        const rec = await this.loadRecord(g.ep);
        // Registered again with other keys since the push was made: that registration stays.
        if (rec && sameBytes(rec.kh, g.kh)) await this.remove(g.ep, rec);
      });
    }
    return earliest === Infinity ? null : Math.max(0, earliest - now);
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
    this.cleanup(now);
    const key = hex(qh);
    const m = this.marks.get(key) ?? new Map<string, number>();
    for (const id of ids) {
      // Deleted and set again, so the map stays in the order in which its marks expire.
      m.delete(id);
      m.set(id, now + SEEN_MS);
    }
    while (m.size > PUSH_SEEN) m.delete(m.keys().next().value as string);
    this.marks.delete(key);
    this.marks.set(key, m);
    while (this.marks.size > MARK_ACCOUNTS) this.marks.delete(this.marks.keys().next().value as string);
    for (const st of this.pushes.values()) {
      if (!st.qh || !sameBytes(st.qh, qh) || st.due === null || !st.rows) continue;
      for (const id of ids) st.rows.delete(id);
      if (st.rows.size === 0 && st.inflight === null) Object.assign(st, { due: null, tries: 0, rang: [], rows: new Set() });
    }
  }

  /** An endpoint's push state (tests). */
  stateOf(ep: Bytes): Omit<PushState, "box" | "recent"> & { recent: string[] } | null {
    if (!isBytes(ep, 16)) throw new TypeError("stateOf: bad endpoint");
    const st = this.pushes.get(hex(ep));
    if (!st) return null;
    const { box: _box, recent, ...rest } = st;
    return { ...rest, rang: [...st.rang], rows: st.rows ? new Set(st.rows) : null, recent: [...recent.keys()] };
  }

  /** The number of rows an account has marked seen (tests). */
  marksOf(qh: Bytes): number {
    if (!isBytes(qh, 16)) throw new TypeError("marksOf: bad quiet tag");
    this.cleanup(this.clock());
    return this.marks.get(hex(qh))?.size ?? 0;
  }

  // ───────────── internals ─────────────

  /** One change of an endpoint's registration at a time. */
  private serial(ep: Bytes, fn: () => Promise<void>): Promise<void> {
    const k = hex(ep);
    const prev = this.chains.get(k) ?? Promise.resolve();
    const next = prev.then(fn, fn).finally(() => {
      if (this.chains.get(k) === next) this.chains.delete(k);
    });
    this.chains.set(k, next);
    return next;
  }

  /** Takes the endpoint out of every bell its record holds, deletes the record, and forgets its pushes. */
  private async remove(ep: Bytes, old: EpRecord | null): Promise<void> {
    this.pushes.delete(hex(ep));
    if (!old) return;
    const shards = pushShardsOf(this.env) ?? 1;
    const per = new Map<number, Bytes[]>();
    for (const t of old.tks) {
      const j = bellShard(t, shards);
      const list = per.get(j);
      if (list) list.push(t);
      else per.set(j, [t]);
    }
    await Promise.all([...per].map(([j, tks]) => bellStub(this.env, j).leave(ep, tks)));
    await this.deleteRecord(ep);
  }

  private async loadRecord(ep: Bytes): Promise<EpRecord | null> {
    const k = hex(ep);
    if (this.records.has(k)) {
      const hit = this.records.get(k) ?? null;
      this.records.delete(k);
      this.records.set(k, hit);
      return hit;
    }
    let rec: EpRecord | null = null;
    try {
      const raw = await this.env.PUSH_KV.get(keyEp(ep), "arrayBuffer");
      if (raw) rec = decodeRecord(new Uint8Array(raw));
    } catch (e) {
      console.error(JSON.stringify({ msg: "push store read failed", error: logErr(e) }));
      throw e;
    }
    this.remember(k, rec);
    return rec;
  }

  private remember(k: string, rec: EpRecord | null): void {
    this.records.delete(k);
    this.records.set(k, rec);
    while (this.records.size > CACHE_RECORDS) this.records.delete(this.records.keys().next().value as string);
  }

  /** Writes the record: at most one write of a key per second (the store's limit), one more try after a failure. */
  private async writeRecord(ep: Bytes, rec: EpRecord): Promise<void> {
    const k = hex(ep);
    await this.spaced(k);
    const key = keyEp(ep);
    const value = encodeRecord(rec);
    const metadata = { d: rec.day, o: hex(ownerOf(ep, rec.qh)) };
    try {
      await this.env.PUSH_KV.put(key, value, { metadata });
    } catch (e) {
      console.error(JSON.stringify({ msg: "push store write failed", error: logErr(e) }));
      await this.sleep(WRITE_SPACING_MS + 100);
      await this.env.PUSH_KV.put(key, value, { metadata });
    }
    this.lastWrite.set(k, this.clock());
    this.remember(k, rec);
  }

  private async deleteRecord(ep: Bytes): Promise<void> {
    const k = hex(ep);
    await this.spaced(k);
    try {
      await this.env.PUSH_KV.delete(keyEp(ep));
    } catch (e) {
      console.error(JSON.stringify({ msg: "push store write failed", error: logErr(e) }));
      await this.sleep(WRITE_SPACING_MS + 100);
      await this.env.PUSH_KV.delete(keyEp(ep));
    }
    this.lastWrite.set(k, this.clock());
    this.remember(k, null);
  }

  private async spaced(k: string): Promise<void> {
    const wait = (this.lastWrite.get(k) ?? 0) + WRITE_SPACING_MS - this.clock();
    if (wait > 0) await this.sleep(wait);
  }

  /** Drops expired marks and recent rows, pushes in flight too long, and states with nothing left to remember. */
  private cleanup(now: number): void {
    for (const [k, m] of this.marks) {
      for (const [id, exp] of m) {
        if (exp > now) break;
        m.delete(id);
      }
      if (m.size === 0) this.marks.delete(k);
    }
    for (const [k, st] of this.pushes) {
      for (const [id, exp] of st.recent) {
        if (exp > now) break;
        st.recent.delete(id);
      }
      if (st.inflight !== null && now - st.inflight > INFLIGHT_MS) {
        // The Worker that took it never reported back: given up, as a failed retry is.
        Object.assign(st, { inflight: null, last: st.first, due: null, tries: 0, rang: [], rows: new Set() });
      }
      if (st.due === null && st.inflight === null && st.recent.size === 0 && (st.last === null || st.last + WINDOW_MS <= now)) this.pushes.delete(k);
    }
  }
}
