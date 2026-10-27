// The self lane (docs/PROTOCOL-v2.md §7): the fold of the account's device-state records (§7.3), the dense probe
// that reads the lane at restore and catch-up (§11.4 step 4), and CAS writes at the first empty slot (§7.3).
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
  /** CONV_JOIN per copy (the first wins) */
  readonly joins = new Map<string, P.ConvJoinRec>();
  /** REQUEST per copy (the first wins), with the stored time of its row and its lane order */
  private readonly requestRecs = new Map<string, { rec: P.RequestRec; t: number; order: number }>();
  /** the view key of every copy, assigned in lane order of its first CONV_JOIN or REQUEST (§7.3 "Copy keys") */
  readonly viewKeys = new Map<string, string>();
  private readonly copiesOfConv = new Map<string, number>();
  /** EPOCH per (copy, e): the first wins, flags OR-ed */
  readonly epochs = new Map<string, P.EpochRec>();
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
  /** every LEAVE record per copy */
  readonly leaves = new Map<string, P.LeaveRec[]>();
  /** LEFT per (copy, e, uid): the least (t, position) */
  readonly lefts = new Map<string, P.LeftRec>();
  /** LINK per s: the first, with later flags OR-ed */
  readonly links = new Map<string, P.LinkRec>();
  /** copies with a CONFIRMED record */
  readonly confirmed = new Set<string>();
  /** the latest HEADS entry per copy */
  readonly heads = new Map<string, P.HeadsEntry>();
  /** PREFS: the latest value per key */
  readonly prefs = new Map<number, Bytes>();
  /** records applied so far (rows count once each) */
  applied = 0;
  private order = 0;

  constructor(private readonly hooks: FoldHooks) {}

  /** The live REQUESTs at era `Enow`: at most 64, the newest in lane order, none stored more than 4 eras ago. */
  requests(Enow: number): Map<string, P.RequestRec> {
    const live = [...this.requestRecs.entries()]
      .filter(
        ([k, x]) =>
          !this.joins.has(k) && Math.floor(x.t / (P.ERA_MS / 1000)) >= Enow - REQUEST_MAX_AGE_ERAS,
      )
      .sort((a, b) => a[1].order - b[1].order)
      .slice(-MAX_REQUESTS);
    return new Map(live.map(([k, x]) => [k, x.rec]));
  }

  /** Applies the records of one row, stored at time `t` (seconds since T0). */
  apply(records: readonly P.SelfRecord[], t: number): void {
    for (const r of records) {
      this.applied++;
      this.order++;
      this.applyOne(r, t);
    }
  }

  private assignViewKey(k: string, conv: Bytes): void {
    if (this.viewKeys.has(k)) return;
    const c = P.b64u(conv);
    const i = this.copiesOfConv.get(c) ?? 0;
    this.copiesOfConv.set(c, i + 1);
    this.viewKeys.set(k, i === 0 ? c : `${c}~${i}`);
  }

  private otherConfirmedCopy(k: string, conv: Bytes): boolean {
    const c = P.b64u(conv);
    for (const x of this.confirmed) if (x !== k && x.startsWith(`${c}.`)) return true;
    return false;
  }

  private pinCheck(uid: Bytes, pin: Bytes, handle: string | null): void {
    const u = P.b64u(uid);
    const m = this.members.get(u);
    const c = this.contacts.get(u);
    if ((m && !P.equalBytes(m.pin, pin)) || (c && !P.equalBytes(c.pin, pin)))
      this.hooks.warn(keysChangedWarning(handle ?? m?.handle ?? `?${u.slice(0, 8)}`), true);
  }

  private applyOne(r: P.SelfRecord, t: number): void {
    switch (r.rtype) {
      case P.RT.CONV_JOIN: {
        const k = copyKey(r);
        if (this.joins.has(k)) return;
        if (this.otherConfirmedCopy(k, r.conv)) {
          this.hooks.warn(CONFIRMED_COPY_WARNING, true);
          return;
        }
        this.joins.set(k, r);
        this.assignViewKey(k, r.conv);
        return;
      }
      case P.RT.REQUEST: {
        const k = copyKey(r);
        if (this.joins.has(k) || this.requestRecs.has(k)) return;
        this.requestRecs.set(k, { rec: r, t, order: this.order });
        this.assignViewKey(k, r.conv);
        return;
      }
      case P.RT.EPOCH: {
        const k = `${copyKey(r)}:${r.e}`;
        const had = this.epochs.get(k);
        if (had) had.flags |= r.flags;
        else this.epochs.set(k, { ...r });
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
        list.push(r);
        this.leaves.set(k, list);
        return;
      }
      case P.RT.LEFT: {
        const k = `${copyKey(r)}:${r.e}:${P.b64u(r.uid)}`;
        const had = this.lefts.get(k);
        if (!had || leftKeyCmp(r, had) < 0) this.lefts.set(k, r);
        return;
      }
      case P.RT.LINK: {
        const k = P.b64u(r.s);
        const had = this.links.get(k);
        if (had) had.flags |= r.flags;
        else this.links.set(k, { ...r });
        return;
      }
      case P.RT.CONFIRMED:
        this.confirmed.add(copyKey(r));
        return;
      case P.RT.HEADS: {
        const c = this.cursor;
        if (!c || r.Ein > c.E || (r.Ein === c.E && r.relIn > c.rel))
          this.cursor = { E: r.Ein, rel: r.relIn };
        for (const x of r.entries) this.heads.set(copyKey(x), x);
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

export interface SelfLaneHooks extends FoldHooks {
  /** called after every applied row (the engine's change counter) */
  applied(): void;
}

/** Reads and writes one account's self lane. */
export class SelfLane {
  /** the last row of the lane this device knows of, or null for an empty lane */
  head: SelfHead | null = null;
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

  /** Opens and applies one row; a row that does not open or parse is rejected as a whole but occupies its slot. */
  private applyRow(E: number, n: number, label: Bytes, body: Bytes, t: number): void {
    const before = this.head;
    if (before && (E < before.E || (E === before.E && n <= before.n))) return;
    this.head = { E, n, label, body, t };
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
   * Writes one row (§7.3): CAS at the first empty slot of era `max(E_now, head era, regEra)` (a device whose estimate
   * lags must not write below the registration era, where a restore never looks). On CONFLICT the occupant is
   * applied (if it opens) and the write moves to the next slot; on WRONG_ERA it moves to the era the server names.
   */
  async write(records: P.SelfRecord[]): Promise<SelfHead> {
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
