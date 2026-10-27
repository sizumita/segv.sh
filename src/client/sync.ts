// Probing and processing conversation lanes (docs/PROTOCOL.md §4.2, §6.5, §11.2, §11.4 step 5, §11.6): one batched
// `get` per round over every lane asked for, dense prefixes from each lane's processed position, galloping by W on
// full hits, one key per idle era, and the slot after an earlier era's prefix kept until it is observed sealed.
import * as P from "~/lib/proto";
import type * as W from "~/lib/wire";
import type { Api } from "./api";
import {
  P0,
  W_SLOTS,
  acceptedOld,
  clampTs,
  insertMessage,
  removeMessage,
  rowKey,
  type Copy,
  type Epoch,
  type Lane,
  type Slot,
} from "./conv";
import type { MessageView } from "./types";

type Bytes = Uint8Array;

/** What the probing needs from the engine. */
export interface SyncCtx {
  api: Api;
  selfUid: Bytes;
  /** Δ in seconds */
  delta(): number;
  /** rows applied now count as unread (after the restore) */
  live(): boolean;
  mono(): number;
  /** the next local application counter (MessageView.seq) */
  seq(): number;
  warn(text: string, critical?: boolean): void;
  /** a row or line was applied */
  changed(): void;
  /** the displayed handle of member j of an epoch */
  handleOf(c: Copy, ep: Epoch, j: number): string;
  /** a WELCOME's J, found on a lane (§5.2: accepted whenever the row is processed) */
  onWelcome(c: Copy, ep: Epoch, j: number, J: P.Join): void;
  /** a valid row of member j (corroboration and request acceptance, §6.7 step 6, §11.5) */
  onValidRow(c: Copy, ep: Epoch, j: number): void;
  /** the local echo waiting for this row (rowKey), if any */
  takeEcho(key: string): { c: Copy; echoKey: string } | undefined;
  /**
   * §12.2 and §12.4 for a valid row of lane j: its `ck` against the verified checkpoints, and its `prev` against the
   * row this session holds there (checked later when it holds none).
   */
  checkRow(c: Copy, ep: Epoch, j: number, row: FoundRow, msg: P.Msg, quiet: boolean): void;
  /** a row above this one named it with another prevh (§12.2) */
  prevMismatch(c: Copy, ep: Epoch, j: number): void;
  /** a valid LEAVE row of member j at `row`, stored at `t` (§6.9) */
  onLeave(
    c: Copy,
    ep: Epoch,
    j: number,
    src: { t: number; row: Slot; key: string; order: number[] },
  ): void;
}

export const UNDECRYPTABLE = "ignored an undecryptable message";

// ───────────────────────── walking one lane ─────────────────────────

/** A stored row found by a walk. */
export interface FoundRow {
  E: number;
  n: number;
  label: Bytes;
  t: number;
  body: Bytes;
}

/**
 * The walk of one lane from its processed position: per round, the keys to probe; fed the statuses, the rows of
 * its dense prefixes in lane order. `label(E, n)` gives the slot's label.
 */
class LaneWalk {
  cur: Slot;
  tail: Slot | null;
  done = false;
  /** eras whose dense-prefix end this walk observed MISS(sealed = 1), with that end */
  readonly sealedAt = new Map<number, number>();
  private first = true;
  private eras: number[] = [];
  private tailKey = false;
  private main = 0;

  constructor(
    start: Slot,
    tail: Slot | null,
    private readonly Enow: number,
    private readonly label: (E: number, n: number) => Bytes,
  ) {
    this.cur = { ...start };
    this.tail = tail ? { ...tail } : null;
  }

  keys(): W.GetKey[] {
    const out: W.GetKey[] = [];
    this.tailKey = this.tail !== null;
    if (this.tail)
      out.push({ E: this.tail.E, label: this.label(this.tail.E, this.tail.n), mode: 0 });
    this.main = this.first ? P0 : W_SLOTS;
    for (let i = 0; i < this.main; i++)
      out.push({ E: this.cur.E, label: this.label(this.cur.E, this.cur.n + i), mode: 0 });
    this.eras = [];
    for (let E = this.cur.E + 1; E <= this.Enow; E++) {
      this.eras.push(E);
      out.push({ E, label: this.label(E, 0), mode: 0 });
    }
    this.first = false;
    return out;
  }

  /** Statuses for `keys()`, in order; returns the rows found, in lane order. */
  feed(st: W.GetStatus[], keys: W.GetKey[]): FoundRow[] {
    const rows: FoundRow[] = [];
    let o = 0;
    if (this.tailKey && this.tail) {
      const s = st[o];
      if (s.s === "hit" && s.body) {
        rows.push({ E: this.tail.E, n: this.tail.n, label: keys[o].label, t: s.t, body: s.body });
        this.tail = { E: this.tail.E, n: this.tail.n + 1 };
      } else if (s.s === "miss" && s.sealed) this.tail = null;
      o++;
    }
    let ended = false;
    let sealedEnd = false;
    for (let i = 0; i < this.main; i++, o++) {
      const s = st[o];
      if (ended) continue;
      if (s.s === "hit" && s.body) {
        rows.push({ E: this.cur.E, n: this.cur.n, label: keys[o].label, t: s.t, body: s.body });
        this.cur = { E: this.cur.E, n: this.cur.n + 1 };
      } else {
        ended = true;
        sealedEnd = s.s === "miss" && s.sealed;
        if (sealedEnd) this.sealedAt.set(this.cur.E, this.cur.n);
      }
    }
    if (!ended) return rows; // every slot hit: gallop by W next round
    // The prefix of cur.E ended. A later era with a row at slot 0 continues the lane there. While every era so far
    // is observed sealed at its prefix end, the processed position moves past the empty ones (an idle era costs one
    // key once, §6.5, §11.2); otherwise the slot after the last prefix stays to probe (`tail`, §11.2).
    let movable = sealedEnd;
    if (movable && this.cur.E < this.Enow) this.cur = { E: this.cur.E + 1, n: 0 };
    for (let k = 0; k < this.eras.length; k++, o++) {
      const s = st[o];
      const E = this.eras[k];
      if (s.s === "hit" && s.body) {
        if (!movable && !this.tail) this.tail = { ...this.cur };
        rows.push({ E, n: 0, label: keys[o].label, t: s.t, body: s.body });
        this.cur = { E, n: 1 };
        return rows; // probe the rest of E (and later eras) next round
      }
      if (s.s === "miss" && s.sealed) this.sealedAt.set(E, 0);
      if (movable && s.s === "miss" && s.sealed && E < this.Enow) this.cur = { E: E + 1, n: 0 };
      else movable = false;
    }
    this.done = true;
    return rows;
  }
}

// ───────────────────────── one sync over many lanes ─────────────────────────

/** A lane to walk: member lane j of an epoch, or its control lane. */
export interface LaneTarget {
  c: Copy;
  ep: Epoch;
  lane: number | "ctl";
}

/**
 * The lanes to walk for each copy (§11.2): every lane of its current epoch (not once removed: the removal swept them),
 * its control lane until a winner is found (finality and processing are claims.ts's), and the lanes of epoch c−1
 * not yet swept: the followed lanes (each member of both epochs, other than self, silent in c), and lanes to sweep
 * once more before they leave.
 */
export function targetsOf(copies: Iterable<Copy>): LaneTarget[] {
  const out: LaneTarget[] = [];
  for (const c of copies) {
    const ep = c.epochs.get(c.current);
    if (!ep || ep.Estart === null) continue;
    if (ep.lanesOn && !c.removed) ep.lanes.forEach((_, j) => out.push({ c, ep, lane: j }));
    if (!ep.ctl.winner && !c.removed) out.push({ c, ep, lane: "ctl" });
    const prev = ep.viaSkip ? undefined : c.epochs.get(c.current - 1);
    if (prev && prev.Estart !== null)
      prev.lanes.forEach((l, j) => {
        if (!l.swept) out.push({ c, ep: prev, lane: j });
      });
  }
  return out;
}

/** Lane j of an older epoch is followed: its member is in the next epoch, is not self, and is silent there (§11.2). */
export function followed(c: Copy, prev: Epoch, j: number): boolean {
  const next = prev.viaSkip ? undefined : c.epochs.get(prev.e + 1);
  if (!next || next.viaSkip || c.current !== next.e) return false;
  const k = P.memberIndex(next.D, prev.D.members[j].uid);
  return k >= 0 && k !== next.myIndex && !next.lanes[k].seen;
}

/**
 * Walks every target to its head with batched gets (§11.6 catch-up, §11.4 step 5) and applies the rows found, in
 * lane order. `quiet`: rows applied never count as unread (a restore).
 */
export async function syncLanes(
  ctx: SyncCtx,
  targets: readonly LaneTarget[],
  quiet = false,
): Promise<void> {
  const Enow = P.era(ctx.api.serverNow());
  const walks = targets.map((x) => {
    if (x.lane === "ctl") {
      const ctl = x.ep.ctl;
      return new LaneWalk(ctl.next, null, Enow, (E, n) => P.Lctl(x.ep.keys.rk, E, n));
    }
    const lane = x.ep.lanes[x.lane];
    const j = x.lane;
    return new LaneWalk(lane.next, lane.tail, Enow, (E, n) => P.Lmsg(x.ep.keys.rk, j, E, n));
  });
  for (let round = 0; round < 64 && walks.some((w) => !w.done); round++) {
    const batch: { k: number; keys: W.GetKey[] }[] = [];
    walks.forEach((w, k) => {
      if (!w.done) batch.push({ k, keys: w.keys() });
    });
    const st = await ctx.api.get(batch.flatMap((b) => b.keys));
    let o = 0;
    for (const b of batch) {
      const w = walks[b.k];
      const x = targets[b.k];
      const rows = w.feed(st.slice(o, o + b.keys.length), b.keys);
      o += b.keys.length;
      if (x.lane === "ctl") {
        // Control rows wait in lane order to be decided (claims.ts); the eras seen sealed serve finality (§6.5).
        const ctl = x.ep.ctl;
        for (const r of rows) {
          ctl.counts.set(r.E, Math.max(ctl.counts.get(r.E) ?? 0, r.n + 1));
          if (P.posCmp(r, ctl.next) >= 0 && !ctl.queue.some((q) => q.E === r.E && q.n === r.n))
            ctl.queue.push(r);
        }
        ctl.queue.sort((a, b) => P.posCmp(a, b));
        for (const [E, n] of w.sealedAt) {
          ctl.sealed.add(E);
          ctl.counts.set(E, n);
        }
      } else {
        const lane = x.ep.lanes[x.lane];
        for (const r of rows) {
          if (
            !lane.head ||
            P.posCmp({ E: r.E, n: r.n + 1 }, { E: lane.head.E, n: lane.head.cnt }) > 0
          )
            lane.head = { E: r.E, cnt: r.n + 1 };
          applyLaneRow(ctx, x.c, x.ep, x.lane, r, quiet);
        }
        lane.next = { ...w.cur };
        lane.tail = w.tail;
      }
    }
  }
  // A lane of an older epoch walked to its head that is no longer followed leaves (§11.2 "Sweeping").
  targets.forEach((x, k) => {
    if (x.lane === "ctl" || x.ep.e === x.c.current || !walks[k].done) return;
    const lane = x.ep.lanes[x.lane];
    if (!lane.tail && !followed(x.c, x.ep, x.lane)) lane.swept = true;
  });
}

// ───────────────────────── applying a lane row ─────────────────────────

/** The order key of a row (§11.8): (clamped ts, epoch, E, lane, n). */
export const rowOrder = (ts: number, e: number, E: number, lane: number, n: number): number[] => [
  ts,
  e,
  E,
  lane,
  n,
];

/**
 * Processes one stored row of lane j at (E, n) (§3.3, §11.6): junk occupies its slot (an undecryptable row gives the
 * noise warning); a valid row updates the lane and is shown (TEXT, IMAGE), joined (WELCOME), or kept for M7 (LEAVE).
 */
export function applyLaneRow(
  ctx: SyncCtx,
  c: Copy,
  ep: Epoch,
  j: number,
  r: FoundRow,
  quiet: boolean,
): void {
  const lane: Lane = ep.lanes[j];
  const key = rowKey(r.E, r.label);
  if (c.order.has(key)) return;
  const v = P.acceptRow(
    { keys: ep.keys, conv: ep.D.conv, e: ep.e, members: ep.D.members },
    r.E,
    r.label,
    r.body,
  );
  if (!v.ok) {
    if (v.why === "decrypt") ctx.warn(UNDECRYPTABLE);
    return;
  }
  const m = v.msg;
  if (m.from !== j || m.lane !== j) return; // the label pins the lane; a row of another lane is junk here
  if (!lane.last || P.posCmp({ E: r.E, n: r.n }, lane.last) > 0)
    lane.last = { E: r.E, n: r.n, label: r.label, body: r.body };
  if (!lane.oldest || P.posCmp({ E: r.E, n: r.n }, lane.oldest) < 0)
    lane.oldest = { E: r.E, n: r.n, prev: { ...m.prev } };
  lane.seen = true;
  const here = `${r.E}:${r.n}`;
  const ph = P.prevh(r.label, r.body);
  lane.prevhs.set(here, ph);
  const expected = lane.expect.get(here);
  lane.expect.delete(here);
  ctx.checkRow(c, ep, j, r, m, quiet);
  if (expected && !P.equalBytes(expected, ph)) ctx.prevMismatch(c, ep, j);
  ctx.onValidRow(c, ep, j);
  const mine = P.equalBytes(ep.D.members[j].uid, ctx.selfUid);
  const ts = clampTs(m.ts, r.t, ctx.delta());
  const order = rowOrder(ts, ep.e, r.E, j, r.n);
  if (m.type === P.MT.WELCOME) {
    ctx.onWelcome(c, ep, j, m.join);
    c.order.set(key, order);
    return;
  }
  if (m.type === P.MT.LEAVE) {
    c.order.set(key, order);
    ctx.onLeave(c, ep, j, { t: r.t, row: { E: r.E, n: r.n }, key, order });
    return;
  }
  if (m.type !== P.MT.TEXT && m.type !== P.MT.IMAGE) return;
  // A leaver processes its lanes for WELCOMEs only (§6.9); a row §6.8 drops is not shown, and an echo of it fails.
  const accepted = !c.left && acceptedOld(c, ep.e, j, { E: r.E, n: r.n }, r.t);
  if (!accepted) {
    c.order.set(key, order);
    ep.rows.set(key, { j, E: r.E, n: r.n, t: r.t, unread: false, shown: false });
    ctx.takeEcho(key); // the echo stays as it is; the send reports the failure (§11.3 step 7)
    return;
  }
  const view: MessageView = {
    key,
    seq: ctx.seq(),
    from: P.b64u(ep.D.members[j].uid),
    fromHandle: ctx.handleOf(c, ep, j),
    mine,
    ts,
    kind: m.type === P.MT.TEXT ? "text" : "image",
    status: "sent",
    ...(m.type === P.MT.TEXT
      ? { text: m.text }
      : {
          image: {
            id: P.b64u(m.image.id),
            k: P.b64u(m.image.k),
            mime: P.MIME[m.image.mime as P.MimeCode],
            w: m.image.w,
            h: m.image.h,
          },
        }),
  };
  const echo = ctx.takeEcho(key);
  if (echo) removeMessage(echo.c, echo.echoKey);
  if (!insertMessage(c, view, order)) return;
  const unread = !mine && !quiet && ctx.live();
  if (unread) c.unread++;
  ep.rows.set(key, { j, E: r.E, n: r.n, t: r.t, unread, shown: true });
  ctx.changed();
}

/** Re-labels the handles of applied messages (after a lookup resolved a member). */
export function refreshHandles(c: Copy, handleOf: (uidB: string) => string | null): void {
  for (let i = 0; i < c.messages.length; i++) {
    const m = c.messages[i];
    if (!m.from) continue;
    const h = handleOf(m.from);
    if (h !== null && h !== m.fromHandle) c.messages[i] = { ...m, fromHandle: h };
  }
}
