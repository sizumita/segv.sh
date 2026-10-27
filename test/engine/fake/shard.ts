/**
 * ShardDO fake (docs/PROTOCOL-v2.md §9.1): one in-memory shard per era, keyed by (E, label).
 *
 * Mirrors the DO's rules: create-only rows, the accept window `start(E) − SKEW ≤ now < end(E)`, sealing at
 * `end(E) + SKEW` (plus the test knob `sealDelayMs`, or `sealPrevious()`), `t = max(tpub(now), last_t,
 * sec(start(E)), closed_t + Δ)`, batches closed lazily once `tpub(now) > t` (what the DO's alarm and `head()` do),
 * and the head chain over closed batches. Δ is pinned per era by its first write (`params.delta` before that), as the
 * DO's 'delta' meta key does. The shard reads the world's *shard* clock (`now − shardLagMs`).
 *
 * Attacker / test controls: `rows()`, `row()`, `commit()` (unvalidated write), `hasLabel()`, `hide()` (omit a
 * row for one client), `retime()` / `rewrite()` (serve different stored values), `hits()`.
 */
import {
  BODY_LENS,
  ZERO32,
  b64u,
  byteCmp,
  era,
  eraEnd,
  eraStart,
  floorDelta,
  leafShard,
  mth,
  nextHead,
  secOf,
  shardCid,
  tpub,
  type Bytes,
} from "../../../src/lib/proto";
import { rowKey, type WorldCtx } from "./common";

/** A stored row. The object is live: mutating it (an attacker rewriting history) changes what is served. */
export interface ShardRow {
  readonly E: number;
  readonly label: Bytes;
  t: number;
  cls: number;
  body: Bytes;
  /** get HITs served for this row (either mode) */
  hits: number;
}

export interface ShardBatch {
  t: number;
  n: number;
  root: Bytes;
  head: Bytes;
  /** The batch's rows ordered by label (live objects, so a rewritten row shows its new body in the feed). */
  rows: ShardRow[];
}

export type ShardPutResult =
  | { s: "ok"; t: number }
  | { s: "conflict"; t: number; cls: number; body: Bytes }
  | { s: "wrong_era"; era: number }
  | { s: "bad" };

export type ShardGetResult =
  | { s: "hit"; t: number; cls: number; body?: Bytes }
  | { s: "miss"; sealed: boolean };

class ShardEra {
  sealed = false;
  lastT: number | null = null;
  closedT: number | null = null;
  /** Δ pinned by the era's first write (null: the deployment parameter applies) */
  delta: number | null = null;
  head: Bytes = ZERO32;
  readonly batches: ShardBatch[] = [];
  /** rows not yet in a closed batch, by t */
  readonly open = new Map<number, ShardRow[]>();
  bytes = 0;
  constructor(readonly E: number) {}
}

export class FakeShard {
  private readonly eras = new Map<number, ShardEra>();
  private readonly byKey = new Map<string, ShardRow>();
  /** row key → clients the row is hidden from */
  private readonly hidden = new Map<string, Set<string>>();
  /** sealPrevious(): eras below this seal regardless of the clock. */
  private sealBelow = 0;

  constructor(private readonly w: WorldCtx) {}

  // ───────────── DO semantics ─────────────

  /** ShardDO.put for one era (one DO call): one result per row, in order. */
  put(E: number, rows: readonly { label: Bytes; cls: number; body: Bytes }[]): ShardPutResult[] {
    const s = this.prepare(E);
    const now = this.w.shardNow();
    if (s.sealed || now >= eraEnd(E) || now < eraStart(E) - this.w.params.skew * 1000) {
      const cur = era(now);
      return rows.map(() => ({ s: "wrong_era", era: cur }));
    }
    const t = this.nextT(s, now);
    this.closeBefore(s, t); // "if open_t exists and t > open_t: closeBatch(open_t)"
    return rows.map((r): ShardPutResult => {
      if (
        r.label.length !== 16 ||
        BODY_LENS[r.cls] === undefined ||
        r.body.length !== BODY_LENS[r.cls]
      )
        return { s: "bad" };
      const o = this.byKey.get(rowKey(E, b64u(r.label)));
      if (o) return { s: "conflict", t: o.t, cls: o.cls, body: o.body };
      this.insert(s, r.label, t, r.cls, r.body);
      s.lastT = t;
      return { s: "ok", t };
    });
  }

  /** ShardDO.get for one era. `who` is the requesting client (rows hidden from it answer MISS). */
  get(
    E: number,
    keys: readonly { label: Bytes; mode: 0 | 1 }[],
    who: string | null = null,
  ): ShardGetResult[] {
    const s = this.prepare(E);
    return keys.map((k): ShardGetResult => {
      const key = rowKey(E, b64u(k.label));
      const o = this.byKey.get(key);
      if (!o || this.isHiddenKey(key, who)) return { s: "miss", sealed: s.sealed };
      o.hits++;
      return k.mode === 0
        ? { s: "hit", t: o.t, cls: o.cls, body: o.body }
        : { s: "hit", t: o.t, cls: o.cls };
    });
  }

  /** ShardDO.head: closes due batches, then `{head, tLast, sealed, size}`. */
  head(E: number): { head: Bytes; tLast: number; sealed: boolean; size: number } {
    const s = this.prepare(E);
    return { head: s.head, tLast: s.closedT ?? 0, sealed: s.sealed, size: s.bytes };
  }

  /** ShardDO.feed: closed batches with t > after, ascending; stops before the batch that would exceed `budget` (≥ 1 batch). */
  feed(
    E: number,
    after: number,
    budget = 4 * 1024 * 1024,
  ): { batches: ShardBatch[]; more: boolean; sealed: boolean } {
    const s = this.prepare(E);
    const all = s.batches.filter((b) => b.t > after);
    const out: ShardBatch[] = [];
    let bytes = 0;
    for (const b of all) {
      const size = 72 + b.rows.reduce((n, r) => n + 17 + r.body.length, 0);
      if (out.length > 0 && bytes + size > budget) break;
      out.push(b);
      bytes += size;
    }
    return { batches: out, more: out.length < all.length, sealed: s.sealed };
  }

  /** Whether era E is sealed now (runs the DO's prepare()). */
  sealed(E: number): boolean {
    return this.prepare(E).sealed;
  }

  // ───────────── test / attacker controls ─────────────

  /** Every stored row (live objects), optionally of one era. */
  rows(E?: number): ShardRow[] {
    const all = [...this.byKey.values()];
    return E === undefined ? all : all.filter((r) => r.E === E);
  }

  row(E: number, label: Bytes): ShardRow | undefined {
    return this.byKey.get(rowKey(E, b64u(label)));
  }

  hasLabel(E: number, label: Bytes): boolean {
    return this.byKey.has(rowKey(E, b64u(label)));
  }

  /** get HITs served for (E, label) so far. */
  hits(E: number, label: Bytes): number {
    return this.row(E, label)?.hits ?? 0;
  }

  /**
   * An attacker write without any validation (no era window, no class or length check, no rate limit). Create-only
   * still holds: returns null when the label is taken. `t` defaults to the time the DO would assign (clamped into
   * the era); `topic` publishes the row to the realtime feed like a put would.
   */
  commit(
    E: number,
    label: Bytes,
    cls: number,
    body: Bytes,
    opts: { t?: number; topic?: Bytes } = {},
  ): ShardRow | null {
    const s = this.prepare(E);
    if (this.byKey.has(rowKey(E, b64u(label)))) return null;
    let t = opts.t;
    if (t === undefined) {
      const lastSec = secOf(eraEnd(E)) - 1;
      t = Math.min(this.nextT(s, this.w.shardNow()), floorDelta(lastSec, this.deltaOf(s)));
      this.closeBefore(s, t);
      s.lastT = Math.max(s.lastT ?? 0, t);
    }
    const row = this.insert(s, label, t, cls, body);
    if (opts.topic && opts.topic.some((x) => x !== 0))
      this.w.publish([{ topic: opts.topic, E, label, t, cls, body }]);
    return row;
  }

  /** Omit (E, label) from `forUser`'s gets and realtime frames (the row stays stored for everyone else). */
  hide(E: number, label: Bytes, forUser: string): void {
    const key = rowKey(E, b64u(label));
    let set = this.hidden.get(key);
    if (!set) this.hidden.set(key, (set = new Set()));
    set.add(forUser);
  }

  /** Undo hide() for one client, or for everyone when `forUser` is omitted. */
  unhide(E: number, label: Bytes, forUser?: string): void {
    const key = rowKey(E, b64u(label));
    if (forUser === undefined) this.hidden.delete(key);
    else this.hidden.get(key)?.delete(forUser);
  }

  isHidden(E: number, label: Bytes, who: string | null): boolean {
    return this.isHiddenKey(rowKey(E, b64u(label)), who);
  }

  /** Serve a different `t` for a stored row from now on (closed batch commitments keep the original). */
  retime(E: number, label: Bytes, t: number): void {
    this.mustRow(E, label).t = t;
  }

  /** Serve a different body / class / t for a stored row from now on (a history rewrite by the server). */
  rewrite(E: number, label: Bytes, patch: { body?: Bytes; cls?: number; t?: number }): void {
    const r = this.mustRow(E, label);
    if (patch.body) r.body = patch.body;
    if (patch.cls !== undefined) r.cls = patch.cls;
    if (patch.t !== undefined) r.t = patch.t;
  }

  /** Seal every era before the shard clock's current era now, whatever `sealDelayMs` says. */
  sealPrevious(): void {
    this.sealBelow = Math.max(this.sealBelow, era(this.w.shardNow()));
  }

  // ───────────── internals ─────────────

  private mustRow(E: number, label: Bytes): ShardRow {
    const r = this.row(E, label);
    if (!r) throw new Error(`no row at era ${E} label ${b64u(label)}`);
    return r;
  }

  private isHiddenKey(key: string, who: string | null): boolean {
    return who !== null && (this.hidden.get(key)?.has(who) ?? false);
  }

  private eraState(E: number): ShardEra {
    let s = this.eras.get(E);
    if (!s) this.eras.set(E, (s = new ShardEra(E)));
    return s;
  }

  /** The DO's prepare(): seal once the era is over (+ SKEW + sealDelayMs), else close every batch with t < tpub(now). */
  private prepare(E: number): ShardEra {
    const s = this.eraState(E);
    if (s.sealed) return s;
    const now = this.w.shardNow();
    if (E < this.sealBelow || now >= eraEnd(E) + this.w.params.skew * 1000 + this.w.sealDelayMs) {
      this.closeBefore(s, Infinity);
      s.sealed = true;
    } else this.closeBefore(s, tpub(now, this.deltaOf(s)));
    return s;
  }

  /** Δ of era `s`: pinned by its first write, the deployment parameter before that. */
  private deltaOf(s: ShardEra): number {
    return s.delta ?? this.w.params.delta;
  }

  private nextT(s: ShardEra, now: number): number {
    const delta = this.deltaOf(s);
    return Math.max(
      tpub(now, delta),
      s.lastT ?? 0,
      secOf(eraStart(s.E)),
      s.closedT !== null ? s.closedT + delta : 0,
    );
  }

  /** Closes the open batches with t < limit, in ascending t. */
  private closeBefore(s: ShardEra, limit: number): void {
    const due = [...s.open.keys()].filter((t) => t < limit).sort((a, b) => a - b);
    for (const t of due) this.closeBatch(s, t);
  }

  private closeBatch(s: ShardEra, t0: number): void {
    const rows = s.open.get(t0) ?? [];
    s.open.delete(t0);
    // closeBatch requires t0 > closed_t: rows an attacker planted into a closed batch's time are never committed.
    if (rows.length === 0 || (s.closedT !== null && t0 <= s.closedT)) return;
    rows.sort((a, b) => byteCmp(a.label, b.label));
    const root = mth(rows.map((r) => leafShard(s.E, r.label, t0, r.cls, r.body)));
    s.head = nextHead(shardCid(s.E, 0), s.head, t0, rows.length, root);
    s.batches.push({ t: t0, n: rows.length, root, head: s.head, rows });
    s.closedT = t0;
  }

  private insert(s: ShardEra, label: Bytes, t: number, cls: number, body: Bytes): ShardRow {
    const row: ShardRow = { E: s.E, label: label.slice(), t, cls, body: body.slice(), hits: 0 };
    s.delta ??= this.deltaOf(s); // Δ must not change within an era: the first write pins it
    this.byKey.set(rowKey(s.E, b64u(label)), row);
    let group = s.open.get(t);
    if (!group) s.open.set(t, (group = []));
    group.push(row);
    s.bytes += 16 + body.length;
    this.w.bumpWrites();
    return row;
  }
}
