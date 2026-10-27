// Probing and processing conversation lanes (docs/PROTOCOL-v2.md §4.2, §6.5, §11.2, §11.4 step 5, §11.6): one batched
// `get` per round over every lane asked for, dense prefixes from each lane's processed position, galloping by W on
// full hits, one key per idle era, and the slot after an earlier era's prefix kept until it is observed sealed.
import * as P from "~/lib/proto";
import type * as W from "~/lib/wire";
import type { Api } from "./api";
import {
  P0,
  W_SLOTS,
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

/** Every lane of the current epoch of each copy, and its control lane. */
export function targetsOf(copies: Iterable<Copy>): LaneTarget[] {
  const out: LaneTarget[] = [];
  for (const c of copies) {
    const ep = c.epochs.get(c.current);
    if (!ep || ep.Estart === null) continue;
    ep.lanes.forEach((_, j) => out.push({ c, ep, lane: j }));
    out.push({ c, ep, lane: "ctl" });
  }
  return out;
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
      if (x.lane === "ctl") applyControl(ctx, x.ep, w, rows);
      else {
        for (const r of rows) applyLaneRow(ctx, x.c, x.ep, x.lane, r, quiet);
        const lane = x.ep.lanes[x.lane];
        lane.next = { ...w.cur };
        lane.tail = w.tail;
      }
    }
  }
}

/**
 * The control lane before claims are processed (M7): a row that opens as a claim of this epoch makes membership
 * pending (a send waits, §11.3 step 2) and stays the control position; a row that does not is not e-valid and the
 * position moves past it (§6.4, §6.5).
 */
function applyControl(ctx: SyncCtx, ep: Epoch, w: LaneWalk, rows: FoundRow[]): void {
  for (const r of rows) {
    const v = P.acceptRow(
      { keys: ep.keys, conv: ep.D.conv, e: ep.e, members: ep.D.members },
      r.E,
      r.label,
      r.body,
    );
    if (v.ok && v.msg.type === P.MT.CLAIM) {
      if (!ep.ctl.claimSeen) {
        ep.ctl.claimSeen = true;
        ep.ctl.claimSince = ctx.mono();
        ctx.changed();
      }
      ep.ctl.next = { E: r.E, n: r.n };
      w.done = true;
      return;
    }
    ep.ctl.next = { E: r.E, n: r.n + 1 };
  }
  if (!ep.ctl.claimSeen) ep.ctl.next = { ...w.cur };
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
    c.leaves.add(P.b64u(ep.D.members[j].uid)); // the leave itself (lines, rotation) lands with M7
    c.order.set(key, order);
    return;
  }
  if (m.type !== P.MT.TEXT && m.type !== P.MT.IMAGE) return;
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
  if (!mine && !quiet && ctx.live()) c.unread++;
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
