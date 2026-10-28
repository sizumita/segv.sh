// The self lane (docs/PROTOCOL.md §7): the fold of the account's device-state records (§7.3), with the legacy skip
// records of the first release kept apart and read as the joins of separate copies (§7.2), the dense probe that reads
// the lane at restore and catch-up (§11.4 step 4), and CAS writes at the first empty slot (§7.3).
import * as P from "~/lib/proto";
import type * as W from "~/lib/wire";
import { ApiError, type Api } from "./api";

type Bytes = Uint8Array;

/** Lane lookahead and gallop chunk (§11). */
export const W_SLOTS = 8;
/** At most this many REQUEST records are live (§7.3, §11.5). */
export const MAX_REQUESTS = 64;
/** A REQUEST whose row was stored more than this many eras ago is dropped (§7.3). */
export const REQUEST_MAX_AGE_ERAS = 4;

export const CONFIRMED_COPY_WARNING =
  "ignored a conversation key that does not match the conversation history";
export const keysChangedWarning = (handle: string) => `the public keys of @${handle} changed`;

/** The fold key of a copy (§7.2): (conv, root). */
export const copyKey = (x: { conv: Bytes; root: Bytes }): string =>
  `${P.b64u(x.conv)}.${P.b64u(x.root)}`;

/** A row of the self lane as this device last saw it: what the next write's prev fields point to. */
export interface SelfHead {
  E: number;
  n: number;
  label: Bytes;
  body: Bytes;
  /** the stored time of the row (seconds since T0) */
  t: number;
}

/** The order of LEFT sources (§6.9 "Several sources"): (t, position), NONE after every real position. */
export function leftKeyCmp(a: { t: number; row: P.Pos }, b: { t: number; row: P.Pos }): number {
  if (a.t !== b.t) return a.t - b.t;
  const an = P.isNone(a.row);
  const bn = P.isNone(b.row);
  if (an || bn) return an === bn ? 0 : an ? 1 : -1;
  return P.posCmp(a.row, b.row);
}

/** The key of a join's epoch material, (conv, e, EK, bundleId): one J, whichever record or tab took it (§7.3). */
export const materialKey = (x: { conv: Bytes; e: number; EK: Bytes; bundleId: Bytes }): string =>
  `${P.b64u(x.conv)}|${x.e}|${P.b64u(x.EK)}|${P.b64u(x.bundleId)}`;

/**
 * A legacy skip record (an EPOCH with flag bit1, which the first release wrote for a skip re-add), as applied: the join
 * of a separate copy `(conv, H(D_{e′}))` at epoch e′ (§7.2 "Legacy skip records").
 */
export interface LegacySkip {
  /** its index in `SelfFold.skips` */
  id: number;
  rec: P.EpochRec;
  /** the stored time of its row (the age of a request it starts) and its place in lane order */
  t: number;
  order: number;
  /** the fold key of the legacy copy it came from: the record's own (conv, root) */
  from: string;
  /** the view key it was numbered with at its place (§7.3 "Copy keys") */
  viewKey: string;
  /**
   * The fold key of the copy it starts, once known: the CONV_JOIN or REQUEST it matches by `(e, EK, bundleId)`, or
   * `(conv, H(D_{e′}))` from its bundle (`bindSkip`). Null until then.
   */
  copy: string | null;
}

export interface FoldHooks {
  /** a warning (critical: kept until sign-out) */
  warn(text: string, critical?: boolean): void;
}

/**
 * The state of the self lane: the fold of its records in lane order, by `(E, n)` and within a row by record order
 * (§7.3). Every rule is idempotent, so applying a row twice changes nothing.
 */
export class SelfFold {
  /** the inbox cursor (Ein, relIn): the maximum seen */
  cursor: { E: number; rel: number } | null = null;
  /** CONV_JOIN per copy (the first wins); a first-release tab's via-5 CONV_JOIN after a bit1 record is in `skipAccepted` */
  readonly joins = new Map<string, P.ConvJoinRec>();
  /** REQUEST per copy (the first wins), with the stored time of its row and its lane order */
  private readonly requestRecs = new Map<string, { rec: P.RequestRec; t: number; order: number }>();
  /** the view key of every copy, assigned in lane order of its first CONV_JOIN, REQUEST or bit1 record (§7.3) */
  readonly viewKeys = new Map<string, string>();
  private readonly copiesOfConv = new Map<string, number>();
  /** the first join material per (conv, e, EK, bundleId): the copy it started, when known, and its view key */
  private readonly byMaterial = new Map<string, { copy: string | null; viewKey: string }>();
  /** EPOCH per (copy, e), flag 0 only: the first wins */
  readonly epochs = new Map<string, P.EpochRec>();
  /** every legacy skip record (flag bit1), kept apart from the flag-0 records, in lane order (§7.2) */
  readonly skips: LegacySkip[] = [];
  /** a CONFIRMED of a legacy key in a row without HEADS after one of its bit1 records: confirms that record's copy */
  readonly skipConfirmed = new Set<number>();
  /** a via-5 CONV_JOIN of a legacy key after one of its bit1 records: accepts that record's copy (§7.2) */
  readonly skipAccepted = new Map<number, P.ConvJoinRec>();
  /** ENDED per copy: the first wins (§7.3) */
  readonly ended = new Map<string, P.EndedRec>();
  /** every EPOCH_PENDING record, with the stored time of its row (the resume rule of §6.11 reads it) */
  readonly pending: { rec: P.EpochPendingRec; t: number }[] = [];
  /** DELIVERED uids per (copy, e, bundleId), united */
  readonly delivered = new Map<string, Set<string>>();
  /** DESC per (copy, e): the first wins */
  readonly desc = new Map<string, P.DescRec>();
  /** MEMBER per uid: the first wins */
  readonly members = new Map<string, P.MemberRec>();
  /** CONTACT per uid: the first wins */
  readonly contacts = new Map<string, P.ContactRec>();
  /** every LEAVE record per copy key */
  readonly leaves = new Map<string, P.LeaveRec[]>();
  /** LEFT per (copy, e, uid): the least (t, position) */
  readonly lefts = new Map<string, P.LeftRec>();
  /** TREG per bundleId (b64u): the bundle's t_reg; the first wins */
  readonly tregs = new Map<string, number>();
  /** LINK per s: the first, with later flags OR-ed */
  readonly links = new Map<string, P.LinkRec>();
  /** copies with a CONFIRMED record */
  readonly confirmed = new Set<string>();
  /** the latest HEADS entry per copy key and epoch, with its lane order (§7.2 assigns a legacy key's by epoch) */
  private readonly headsAt = new Map<string, Map<number, { entry: P.HeadsEntry; order: number }>>();
  /** PREFS: the latest value per key */
  readonly prefs = new Map<number, Bytes>();
  /** records applied so far (rows count once each) */
  applied = 0;
  private order = 0;

  constructor(private readonly hooks: FoldHooks) {}

  /** The live REQUESTs at era `Enow`: at most 64, the newest in lane order, none stored more than 4 eras ago. */
  requests(Enow: number): Map<string, P.RequestRec> {
    const live = [...this.requestRecs.entries()]
      .filter(([k, x]) => !this.joins.has(k) && liveAt(x.t, Enow))
      .sort((a, b) => a[1].order - b[1].order)
      .slice(-MAX_REQUESTS);
    return new Map(live.map(([k, x]) => [k, x.rec]));
  }

  /** A REQUEST record of a copy, live or not (it names its bundle's t_reg, §4.2), with its row's time and order. */
  requestOf(k: string): { rec: P.RequestRec; t: number; order: number } | undefined {
    return this.requestRecs.get(k);
  }

  /**
   * The latest HEADS entry of a copy key among those for an epoch in `[lo, hi)` (all of them by default), with its
   * lane order: a legacy key's entries belong to the copies that §7.2 assigns their epochs to.
   */
  headsIn(k: string, lo = 0, hi = Infinity): { entry: P.HeadsEntry; order: number } | null {
    let best: { entry: P.HeadsEntry; order: number } | null = null;
    for (const [e, x] of this.headsAt.get(k) ?? [])
      if (e >= lo && e < hi && (!best || x.order > best.order)) best = x;
    return best;
  }

  /** The latest HEADS entry of a copy key (the fold of §7.3 for a key without bit1 records). */
  headsOf(k: string): P.HeadsEntry | null {
    return this.headsIn(k)?.entry ?? null;
  }

  /** The bit1 records of a legacy copy key, by e′ (and lane order). */
  skipsOf(k: string): LegacySkip[] {
    return this.skips
      .filter((s) => s.from === k)
      .sort((a, b) => a.rec.e - b.rec.e || a.order - b.order);
  }

  /**
   * The bundle of a bit1 record showed the copy it starts, `(conv, H(D_{e′}))`: a later CONV_JOIN or REQUEST of that
   * key belongs to it. When that key already has a view key (the same D in another bundle), the record's number stays
   * unused (§7.3 "Copy keys").
   */
  bindSkip(s: LegacySkip, k: string): string {
    s.copy = k;
    const had = this.viewKeys.get(k);
    if (had) return had;
    this.viewKeys.set(k, s.viewKey);
    return s.viewKey;
  }

  /** Applies the records of one row, stored at time `t` (seconds since T0). */
  apply(records: readonly P.SelfRecord[], t: number): void {
    const withHeads = records.some((r) => r.rtype === P.RT.HEADS);
    for (const r of records) {
      this.applied++;
      this.order++;
      this.applyOne(r, t, withHeads);
    }
  }

  private nextViewKey(conv: Bytes): string {
    const c = P.b64u(conv);
    const i = this.copiesOfConv.get(c) ?? 0;
    this.copiesOfConv.set(c, i + 1);
    return i === 0 ? c : `${c}~${i}`;
  }

  /**
   * The view key of a copy's first CONV_JOIN or REQUEST: the number of an earlier bit1 record of the same J when one
   * came first (the copy it starts is this one), else the next number of its conversation (§7.3 "Copy keys").
   */
  private assignViewKey(k: string, r: P.ConvJoinRec | P.RequestRec): void {
    if (this.viewKeys.has(k)) return;
    const mk = materialKey(r);
    const had = this.byMaterial.get(mk);
    if (had && had.copy === null) {
      had.copy = k;
      for (const s of this.skips) if (s.copy === null && materialKey(s.rec) === mk) s.copy = k;
      this.viewKeys.set(k, had.viewKey);
      return;
    }
    const viewKey = this.nextViewKey(r.conv);
    this.viewKeys.set(k, viewKey);
    if (!had) this.byMaterial.set(mk, { copy: k, viewKey });
  }

  /** The latest bit1 record of a legacy key applied so far, or null (§7.2: a first-release tab's records after it). */
  private latestSkipOf(k: string): LegacySkip | null {
    for (let i = this.skips.length - 1; i >= 0; i--)
      if (this.skips[i].from === k) return this.skips[i];
    return null;
  }

  private pinCheck(uid: Bytes, pin: Bytes, handle: string | null): void {
    const u = P.b64u(uid);
    const m = this.members.get(u);
    const c = this.contacts.get(u);
    if ((m && !P.equalBytes(m.pin, pin)) || (c && !P.equalBytes(c.pin, pin)))
      this.hooks.warn(keysChangedWarning(handle ?? m?.handle ?? `?${u.slice(0, 8)}`), true);
  }

  private applyOne(r: P.SelfRecord, t: number, withHeads: boolean): void {
    switch (r.rtype) {
      case P.RT.CONV_JOIN: {
        const k = copyKey(r);
        // A first-release tab's acceptance of a copy it continued by a skip (§7.2): it accepts that skip's copy.
        const skip = r.via === P.VIA.REQUEST_ACCEPTED ? this.latestSkipOf(k) : null;
        if (skip) {
          if (!this.skipAccepted.has(skip.id)) this.skipAccepted.set(skip.id, r);
          return;
        }
        if (this.joins.has(k)) return;
        this.joins.set(k, r);
        this.assignViewKey(k, r);
        return;
      }
      case P.RT.REQUEST: {
        const k = copyKey(r);
        if (this.joins.has(k) || this.requestRecs.has(k)) return;
        this.requestRecs.set(k, { rec: r, t, order: this.order });
        this.assignViewKey(k, r);
        return;
      }
      case P.RT.EPOCH: {
        if (r.flags & P.EPOCH_SKIP) {
          const from = copyKey(r);
          const mk = materialKey(r);
          // The same J in the same legacy copy (two tabs, or the same row read twice) counts once.
          if (this.skips.some((s) => s.from === from && materialKey(s.rec) === mk)) return;
          const had = this.byMaterial.get(mk);
          const viewKey = had ? had.viewKey : this.nextViewKey(r.conv);
          if (!had) this.byMaterial.set(mk, { copy: null, viewKey });
          this.skips.push({
            id: this.skips.length,
            rec: { ...r },
            t,
            order: this.order,
            from,
            viewKey,
            copy: had?.copy ?? null,
          });
          return;
        }
        const k = `${copyKey(r)}:${r.e}`;
        if (!this.epochs.has(k)) this.epochs.set(k, { ...r });
        return;
      }
      case P.RT.EPOCH_PENDING:
        this.pending.push({ rec: r, t });
        return;
      case P.RT.DELIVERED: {
        const k = `${copyKey(r)}:${r.e}:${P.b64u(r.bundleId)}`;
        const s = this.delivered.get(k) ?? new Set<string>();
        for (const u of r.uids) s.add(P.b64u(u));
        this.delivered.set(k, s);
        return;
      }
      case P.RT.DESC: {
        const k = `${copyKey(r)}:${r.e}`;
        if (!this.desc.has(k)) this.desc.set(k, r);
        return;
      }
      case P.RT.MEMBER: {
        const u = P.b64u(r.uid);
        this.pinCheck(r.uid, r.pin, r.handle);
        if (!this.members.has(u)) this.members.set(u, r);
        return;
      }
      case P.RT.CONTACT: {
        const u = P.b64u(r.uid);
        this.pinCheck(r.uid, r.pin, null);
        if (!this.contacts.has(u)) this.contacts.set(u, r);
        return;
      }
      case P.RT.LEAVE: {
        const k = copyKey(r);
        const list = this.leaves.get(k) ?? [];
        if (!list.some((x) => x.e === r.e)) list.push(r);
        this.leaves.set(k, list);
        return;
      }
      case P.RT.LEFT: {
        const k = `${copyKey(r)}:${r.e}:${P.b64u(r.uid)}`;
        const had = this.lefts.get(k);
        if (!had || leftKeyCmp(r, had) < 0) this.lefts.set(k, r);
        return;
      }
      case P.RT.TREG: {
        const k = P.b64u(r.bundleId);
        if (!this.tregs.has(k)) this.tregs.set(k, r.tReg);
        return;
      }
      case P.RT.ENDED: {
        const k = copyKey(r);
        if (!this.ended.has(k)) this.ended.set(k, r);
        return;
      }
      case P.RT.LINK: {
        const k = P.b64u(r.s);
        const had = this.links.get(k);
        if (had) had.flags |= r.flags;
        else this.links.set(k, { ...r });
        return;
      }
      case P.RT.CONFIRMED: {
        const k = copyKey(r);
        // A first-release tab's confirmation of a copy it continued by a skip, in a row of its own (§7.2).
        const skip = withHeads ? null : this.latestSkipOf(k);
        if (skip) this.skipConfirmed.add(skip.id);
        else this.confirmed.add(k);
        return;
      }
      case P.RT.HEADS: {
        const c = this.cursor;
        if (!c || r.Ein > c.E || (r.Ein === c.E && r.relIn > c.rel))
          this.cursor = { E: r.Ein, rel: r.relIn };
        for (const x of r.entries) {
          const k = copyKey(x);
          let m = this.headsAt.get(k);
          if (!m) this.headsAt.set(k, (m = new Map()));
          m.set(x.e, { entry: x, order: this.order });
        }
        return;
      }
      case P.RT.PREFS:
        this.prefs.set(r.key, r.value);
        return;
      case P.RT.SNAP:
        return; // never at Lself (the codec refuses it)
    }
  }
}

/** A request whose row was stored at `t` (seconds since T0) is live at era `Enow` for 4 eras (§7.3). */
export const liveAt = (t: number, Enow: number): boolean =>
  Math.floor(t / (P.ERA_MS / 1000)) >= Enow - REQUEST_MAX_AGE_ERAS;

export interface SelfLaneHooks extends FoldHooks {
  /** called after every applied row (the engine's change counter) */
  applied(): void;
}

/** Reads and writes one account's self lane. */
export class SelfLane {
  /** the last row of the lane this device knows of, or null for an empty lane */
  head: SelfHead | null = null;
  /**
   * Eras below the head's whose dense-prefix end was not yet observed `MISS(sealed = 1)`, with the slot after their last
   * known row: a sibling may still write there around an era boundary (§7.2, §11.7), so it is probed until sealed, a
   * row found there is applied, and no position in a later era is recorded before that.
   */
  readonly tails = new Map<number, number>();
  /** writes never go below this era: the account's registration era (§7.3), set after the account check */
  floorEra = 0;
  readonly fold: SelfFold;

  constructor(
    private readonly api: Api,
    private readonly id: P.Identity,
    private readonly hooks: SelfLaneHooks,
  ) {
    this.fold = new SelfFold(hooks);
  }

  /**
   * Opens and applies one row; a row that does not open or parse is rejected as a whole but occupies its slot. A row
   * below the head is applied only at the dense-prefix end of an earlier era that is still probed (`tails`).
   */
  private applyRow(E: number, n: number, label: Bytes, body: Bytes, t: number): void {
    const before = this.head;
    if (before && (E < before.E || (E === before.E && n <= before.n))) {
      if (this.tails.get(E) !== n) return;
      this.tails.set(E, n + 1);
    } else {
      if (before && E > before.E) this.tails.set(before.E, before.n + 1);
      this.head = { E, n, label, body, t };
    }
    let row: P.ParsedSelfRow;
    try {
      row = P.openSelf(this.id.kS, E, label, body);
    } catch {
      return;
    }
    this.fold.apply(row.records, t);
    this.hooks.applied();
  }

  /**
   * §11.4 step 4: probes `Lself` densely from the position after the head (or from `from` on an empty lane) and
   * applies every row in order: W slots of the first era and slot 0 of each later era up to `E_now` (an idle era
   * costs one key), galloping by W while every slot hits.
   */
  async catchUp(from: { E: number; n: number }): Promise<void> {
    const Enow = P.era(this.api.serverNow());
    const start = this.head ? { E: this.head.E, n: this.head.n + 1 } : from;
    type Probe = { E: number; n0: number; count: number };
    let probes: Probe[] = [{ E: start.E, n0: start.n, count: W_SLOTS }];
    for (let E = start.E + 1; E <= Enow; E++) probes.push({ E, n0: 0, count: 1 });
    // The dense-prefix end of each earlier era not yet observed sealed (a sibling's late row, §11.7).
    for (const [E, n] of this.tails) if (E < start.E) probes.push({ E, n0: n, count: 1 });
    const hits = new Map<number, { n: number; label: Bytes; body: Bytes; t: number }[]>();
    while (probes.length > 0) {
      const keys: W.GetKey[] = [];
      const labels: Bytes[][] = probes.map((p) =>
        Array.from({ length: p.count }, (_, i) => P.Lself(this.id.rS, p.E, p.n0 + i)),
      );
      probes.forEach((p, k) => labels[k].forEach((label) => keys.push({ E: p.E, label, mode: 0 })));
      const st = await this.api.get(keys);
      const next: Probe[] = [];
      let o = 0;
      probes.forEach((p, k) => {
        let dense = true;
        for (let i = 0; i < p.count; i++) {
          const s = st[o++];
          if (!dense) continue;
          if (s.s !== "hit" || !s.body) {
            dense = false;
            if (s.s === "miss" && s.sealed && this.tails.get(p.E) === p.n0 + i)
              this.tails.delete(p.E);
            continue;
          }
          const list = hits.get(p.E) ?? [];
          list.push({ n: p.n0 + i, label: labels[k][i], body: s.body, t: s.t });
          hits.set(p.E, list);
        }
        if (dense) next.push({ E: p.E, n0: p.n0 + p.count, count: W_SLOTS });
      });
      probes = next;
    }
    for (const E of [...hits.keys()].sort((a, b) => a - b))
      for (const r of hits.get(E)!.sort((a, b) => a.n - b.n))
        this.applyRow(E, r.n, r.label, r.body, r.t);
  }

  /**
   * The last self-lane position whose effects a snapshot may claim (§7.2 era rule): the head, or, while an earlier
   * era's dense-prefix end is still probed, the last row before the lowest such end.
   */
  position(): P.Pos {
    if (!this.head) return P.NONE;
    if (this.tails.size === 0) return { E: this.head.E, n: this.head.n };
    const E = Math.min(...this.tails.keys());
    return { E, n: this.tails.get(E)! - 1 };
  }

  /**
   * Writes one row (§7.3): CAS at the first empty slot of era `max(E_now, head era, regEra)` (a device whose estimate
   * lags must not write below the registration era, where a restore never looks). On CONFLICT the occupant is
   * applied (if it opens) and the write moves to the next slot; `onConflict` then sees the occupant's records and may
   * change what is written (§7.3: a J that a sibling's records now make a duplicate, rejected or parked is taken out;
   * nothing left writes nothing). On WRONG_ERA it moves to the era the server names.
   */
  async write(
    rows: P.SelfRecord[],
    onConflict?: (occupant: readonly P.SelfRecord[]) => Promise<P.SelfRecord[]>,
  ): Promise<SelfHead> {
    let records = rows;
    let E = Math.max(P.era(this.api.serverNow()), this.head?.E ?? 0, this.floorEra);
    let n = this.head && this.head.E === E ? this.head.n + 1 : 0;
    for (let attempt = 0; attempt < 256; attempt++) {
      const head = this.head;
      const label = P.Lself(this.id.rS, E, n);
      const row: P.SelfRow = {
        prev: head ? { E: head.E, n: head.n } : P.NONE,
        prevh: head ? P.prevh(head.label, head.body) : P.ZERO16,
        ts: Math.max(0, Math.floor(this.api.serverNow())),
        records,
      };
      const { cls, body } = P.sealSelf(this.id.kS, E, label, row);
      const [r] = await this.api.put([{ E, label, cls, topic: P.topicSelf(this.id.nS), body }]);
      if (r.s === "ok") {
        this.applyRow(E, n, label, body, r.t);
        return this.head!;
      }
      if (r.s === "conflict") {
        this.applyRow(E, n, label, r.body, r.t);
        n++;
        if (onConflict) {
          let occupant: readonly P.SelfRecord[] = [];
          try {
            occupant = P.openSelf(this.id.kS, E, label, r.body).records;
          } catch {
            occupant = [];
          }
          records = await onConflict(occupant);
          if (records.length === 0) return this.head!;
        }
        continue;
      }
      if (r.s === "wrong_era") {
        if (r.era < Math.max(this.head?.E ?? 0, this.floorEra))
          throw new ApiError(0, "self-lane write: the server's era is behind the lane");
        E = r.era;
        n = this.head && this.head.E === E ? this.head.n + 1 : 0;
        continue;
      }
      throw new ApiError(0, `self-lane write refused (${r.s})`);
    }
    throw new ApiError(0, "self-lane write: too many conflicts");
  }
}
