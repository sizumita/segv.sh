/**
 * InboxDO fake (docs/PROTOCOL-v2.md §9.3), one per era, bucket 0 only (β = 0). It reads the world's *inbox* clock
 * (`now − inboxLagMs`); the Worker's checks in front of it (era bounds, 410) read the world clock.
 *
 * With `D = Δin · 1000`, `ms = now − T0` and a per-row jitter j ∈ [0, D) (0 unless `inboxJitter` sets it):
 *   rel    = max(⌊(ms + j) / D⌋ + 1, closed_hw + 1)
 *   closed = max(⌊ms / D⌋, closed_hw)               (after `ended`: max(max rel, closed_hw), so it never falls)
 * Δin is pinned per era by the era's first write (a persisted closed_hw or an inserted row); before that it is
 * `params.inboxSlot`, so changing the parameter mid-era does not freeze `closed`.
 * Posts are accepted while `start(E) − SKEW ≤ now < end(E)` and the era has not ended (`ended` is set once
 * `now ≥ end(E) + SKEW`); otherwise the whole post is WRONG_ERA(era(now)), which the Worker answers with 409
 * `{error: "wrong era", era}`. Each post row gets `rel`, `conflict` (eid reused with another body) or `full` (the
 * day cap; posts in the SKEW window before start(E) count against the era's first day, so an era holds at most
 * 7 · dayCap rows). Reads return whole rel groups and persist `closed_hw`. Slots with rows are committed (head
 * chain, t = rel) once closed.
 *
 * Test controls: `dayCap` (default 2000), `rollDay()` (a new cap day), `inboxJitter(fn)` (the per-row j),
 * `wrongEraOnce(era?)` (refuse the next post with WRONG_ERA), and `post()` (an attacker post that bypasses the
 * era window, rate limits and PoW).
 */
import {
  T0_MS,
  ZERO32,
  b64u,
  byteCmp,
  equalBytes,
  era,
  eraEnd,
  eraStart,
  inboxCid,
  leafInbox,
  mth,
  nextHead,
  secOf,
  type Bytes,
} from "../../../src/lib/proto";
import type { WorldCtx } from "./common";

export interface InboxStoredRow {
  readonly rel: number;
  readonly eid: Bytes;
  readonly body: Bytes;
}

export type InboxRowResult = { rel: number } | { error: "conflict" } | { error: "full" };

/**
 * An `inboxJitter` callback: the jitter j (ms) of one row being inserted, given `D = Δin · 1000` of its era (the
 * pinned value) and the row. Called once per inserted row (never for an idempotent retry, a conflict or a full
 * row); the result is floored and clamped into [0, D), as the InboxDO clamps its own.
 */
export type InboxJitterFn = (D: number, row: { E: number; eid: Bytes }) => number;

class InboxEra {
  /** every row, kept sorted by (rel, eid) */
  readonly rows: InboxStoredRow[] = [];
  readonly byEid = new Map<string, InboxStoredRow>();
  closedHw = 0;
  /** D = Δin · 1000 pinned by the era's first write (null: not pinned yet, the deployment parameter applies) */
  slotMs: number | null = null;
  ended = false;
  /** day → rows accepted that day (bucket 0) */
  readonly cnt = new Map<number, number>();
  head: Bytes = ZERO32;
  /** rel of the newest committed slot, or −1 */
  lastSlot = -1;
  readonly slots: { rel: number; n: number; root: Bytes; head: Bytes }[] = [];
  constructor(readonly E: number) {}
}

export const INBOX_DAY_CAP = 2000;

export class FakeInbox {
  /** INBOX_DAY_CAP (rows per era, bucket and day). */
  dayCap = INBOX_DAY_CAP;
  private dayOffset = 0;
  private readonly eras = new Map<number, InboxEra>();
  private jitterFn: InboxJitterFn | null = null;
  /** wrongEraOnce(): the eras the next posts are refused with (undefined: the era of the inbox clock) */
  private readonly forcedWrongEra: (number | undefined)[] = [];

  constructor(private readonly w: WorldCtx) {}

  // ───────────── DO semantics ─────────────

  /** InboxDO.post: `wrong_era` for the whole call when the era does not accept posts, else one result per row. */
  accept(
    E: number,
    rows: readonly { eid: Bytes; body: Bytes }[],
  ): { s: "wrong_era"; era: number } | { s: "ok"; results: InboxRowResult[] } {
    const now = this.w.inboxNow();
    const s = this.prepare(E, now);
    if (this.forcedWrongEra.length > 0)
      return { s: "wrong_era", era: this.forcedWrongEra.shift() ?? era(now) };
    if (s.ended || now < eraStart(E) - this.w.params.skew * 1000 || now >= eraEnd(E))
      return { s: "wrong_era", era: era(now) };
    return { s: "ok", results: rows.map((r) => this.insert(s, r, now, false)) };
  }

  /** InboxDO.read: rows with after < rel ≤ closed, ordered by (rel, eid), whole rel groups, `more` past `limit`. */
  read(
    E: number,
    after: number,
    limit: number,
  ): { closed: number; more: boolean; rows: InboxStoredRow[]; ended: boolean } {
    const now = this.w.inboxNow();
    const s = this.prepare(E, now);
    const closed = this.report(s, now);
    const out: InboxStoredRow[] = [];
    let more = false;
    for (let i = firstAbove(s.rows, after); i < s.rows.length && s.rows[i].rel <= closed;) {
      if (out.length >= limit) {
        more = true;
        break;
      }
      const rel = s.rows[i].rel;
      while (i < s.rows.length && s.rows[i].rel === rel) out.push(s.rows[i++]);
    }
    return { closed, more, rows: out, ended: s.ended };
  }

  /** InboxDO.head: commits every closed slot, then `{head, tLast, ended}`. */
  head(E: number): { head: Bytes; tLast: number; ended: boolean } {
    const now = this.w.inboxNow();
    const s = this.prepare(E, now);
    this.report(s, now);
    return { head: s.head, tLast: Math.max(0, s.lastSlot), ended: s.ended };
  }

  /** `closed` as a read would report it now (without persisting anything). */
  closedNow(E: number): number {
    const now = this.w.inboxNow();
    return this.closed(this.prepare(E, now), now);
  }

  // ───────────── test / attacker controls ─────────────

  /**
   * The per-row jitter j of the rel formula (default 0): `fn(D, row)` is called once per inserted row and its
   * result is clamped into [0, D) (see InboxJitterFn). `(D) => D - 1` is the maximum, the latest slot a row can
   * get. Applies to `post()` too, unless it forces `rel`. null restores j = 0.
   */
  inboxJitter(fn: InboxJitterFn | null): void {
    this.jitterFn = fn;
  }

  /**
   * The next post that reaches the InboxDO (one that passed the Worker's checks: rate limit, length, bucket, era
   * bounds) is refused as a whole with WRONG_ERA, which the Worker answers with 409 `{error: "wrong era", era}`.
   * Nothing is stored or counted against the day cap. `reported` is the era the refusal names; by default the era
   * of the inbox clock, as InboxDO.post reports it. Calls queue up: n calls refuse the next n posts.
   */
  wrongEraOnce(reported?: number): void {
    this.forcedWrongEra.push(reported);
  }

  /**
   * An attacker post straight into era E's inbox: no era window, rate limit or PoW. Conflicts still apply, and the
   * day cap unless `ignoreCap`. `rel` forces the slot (default: the formula above, with the `inboxJitter` j).
   */
  post(
    E: number,
    rows: readonly { eid: Bytes; body: Bytes }[],
    opts: { rel?: number; ignoreCap?: boolean } = {},
  ): InboxRowResult[] {
    const now = this.w.inboxNow();
    const s = this.prepare(E, now);
    return rows.map((r) => this.insert(s, r, now, opts.ignoreCap ?? false, opts.rel));
  }

  /** Every stored row of era E in (rel, eid) order. */
  rowsOf(E: number): InboxStoredRow[] {
    return [...this.eraState(E).rows];
  }

  /** Rows of era E posted but not yet visible to readers (rel > closed). */
  pending(E: number): number {
    const now = this.w.inboxNow();
    const s = this.prepare(E, now);
    return s.rows.length - firstAbove(s.rows, this.closed(s, now));
  }

  /** Rows of every era posted but not yet visible to readers (settle waits for 0). */
  pendingTotal(): number {
    return [...this.eras.keys()].reduce((n, E) => n + this.pending(E), 0);
  }

  /** Eras that hold rows. */
  eraList(): number[] {
    return [...this.eras.keys()]
      .filter((E) => this.eras.get(E)!.rows.length > 0)
      .sort((a, b) => a - b);
  }

  /** Starts a new cap day: every era's day counter restarts. */
  rollDay(): void {
    this.dayOffset++;
  }

  // ───────────── internals ─────────────

  private eraState(E: number): InboxEra {
    let s = this.eras.get(E);
    if (!s) this.eras.set(E, (s = new InboxEra(E)));
    return s;
  }

  /** The DO's prepare(): persists `ended` once `now ≥ end(E) + SKEW` by the inbox clock. */
  private prepare(E: number, now: number): InboxEra {
    const s = this.eraState(E);
    if (!s.ended && now >= eraEnd(E) + this.w.params.skew * 1000) s.ended = true;
    return s;
  }

  /** D of era `s`: pinned by its first write, the deployment parameter before that. */
  private slotMs(s: InboxEra): number {
    return s.slotMs ?? this.w.params.inboxSlot * 1000;
  }

  /** Pins D on the era's first write (Δin must not change within an era). */
  private pin(s: InboxEra): void {
    s.slotMs ??= this.slotMs(s);
  }

  private closed(s: InboxEra, now: number): number {
    if (s.ended) return Math.max(s.closedHw, s.rows.length ? s.rows[s.rows.length - 1].rel : 0);
    return Math.max(Math.floor((now - T0_MS) / this.slotMs(s)), s.closedHw);
  }

  /** Reports `closed`: persists it as closed_hw and commits every closed slot first. */
  private report(s: InboxEra, now: number): number {
    const c = this.closed(s, now);
    if (c > s.closedHw) {
      this.pin(s);
      s.closedHw = c;
    }
    this.commitSlots(s, c);
    return c;
  }

  private commitSlots(s: InboxEra, closed: number): void {
    // Rows are sorted by (rel, eid), so each slot is a contiguous run already in leaf order.
    for (let i = firstAbove(s.rows, s.lastSlot); i < s.rows.length && s.rows[i].rel <= closed;) {
      const rel = s.rows[i].rel;
      const leaves: Bytes[] = [];
      for (; i < s.rows.length && s.rows[i].rel === rel; i++)
        leaves.push(leafInbox(s.E, 0, rel, s.rows[i].eid, s.rows[i].body));
      const root = mth(leaves);
      s.head = nextHead(inboxCid(s.E, 0), s.head, rel, leaves.length, root);
      s.slots.push({ rel, n: leaves.length, root, head: s.head });
      s.lastSlot = rel;
    }
  }

  private insert(
    s: InboxEra,
    r: { eid: Bytes; body: Bytes },
    now: number,
    ignoreCap: boolean,
    rel?: number,
  ): InboxRowResult {
    const eidB = b64u(r.eid);
    const o = s.byEid.get(eidB);
    if (o) return equalBytes(o.body, r.body) ? { rel: o.rel } : { error: "conflict" };
    // A post in the SKEW window before start(E) counts against the era's first day.
    const day =
      Math.max(Math.floor(secOf(now) / 86400), Math.floor(secOf(eraStart(s.E)) / 86400)) +
      this.dayOffset;
    const n = s.cnt.get(day) ?? 0;
    if (!ignoreCap && n >= this.dayCap) return { error: "full" };
    const D = this.slotMs(s);
    const row: InboxStoredRow = {
      rel:
        rel ??
        Math.max(Math.floor((now - T0_MS + this.jitter(D, s.E, r.eid)) / D) + 1, s.closedHw + 1),
      eid: r.eid.slice(),
      body: r.body.slice(),
    };
    this.pin(s);
    s.rows.splice(insertAt(s.rows, row), 0, row);
    s.byEid.set(eidB, row);
    s.cnt.set(day, n + 1);
    this.w.bumpWrites();
    return { rel: row.rel };
  }

  /** j for one inserted row: 0 without `inboxJitter`, else the callback's value floored and clamped into [0, D). */
  private jitter(D: number, E: number, eid: Bytes): number {
    if (!this.jitterFn) return 0;
    const j = this.jitterFn(D, { E, eid: eid.slice() });
    if (!Number.isFinite(j)) throw new RangeError(`inboxJitter returned ${j}`);
    return Math.min(Math.max(Math.floor(j), 0), D - 1);
  }
}

const cmpRow = (a: InboxStoredRow, b: InboxStoredRow): number =>
  a.rel - b.rel || byteCmp(a.eid, b.eid);

/** Index of the first row with rel > x (rows sorted by rel). */
function firstAbove(rows: readonly InboxStoredRow[], x: number): number {
  let lo = 0;
  let hi = rows.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (rows[mid].rel <= x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** Insertion index that keeps rows sorted by (rel, eid). */
function insertAt(rows: readonly InboxStoredRow[], row: InboxStoredRow): number {
  let lo = 0;
  let hi = rows.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (cmpRow(rows[mid], row) <= 0) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}
