// Processing a copy's membership (docs/PROTOCOL.md §6.6, §6.8, §6.9, §11.2, §11.9): the final winning claim of an
// epoch (removed, frozen, or the switch to e+1 with its sweep and carried leaves), the leave sources of others, the
// §6.8 decisions taken again whenever a claim is learned, and the system lines, of which the removal, rotation and
// "@x left" lines follow the current leave state.
import * as P from "~/lib/proto";
import { frozenInvalid, frozenNoKey } from "./claims";
import {
  acceptedOld,
  clampTs,
  displayName,
  insertMessage,
  leftIn,
  newEpoch,
  removeMessage,
  sourceCmp,
  systemLine,
  type Copy,
  type Epoch,
  type LeaveSource,
  type Slot,
  type Winner,
} from "./conv";
import type { LaneTarget } from "./sync";

type Bytes = Uint8Array;

/** The control lane's lane number in order keys (§11.8: claims sort by their slot like rows). */
const CTL_LANE = 0xffff;

export const YOU_LEFT = "you left the conversation";

export interface MembershipHost {
  kemSk: Bytes;
  selfUid: Bytes;
  /** Δ in seconds */
  delta(): number;
  /** lines and claims applied now count as unread (after the restore) */
  live(): boolean;
  warn(text: string, critical?: boolean): void;
  changed(): void;
  /** the displayed handle of member j of an epoch */
  handleOf(c: Copy, ep: Epoch, j: number): string;
  /** walks these lanes to their heads now (a sweep, §11.2) */
  sweep(targets: LaneTarget[]): Promise<void>;
  /** the copy now follows epoch `ep`: its topic, the subscriptions, HEADS (§6.6 step 4) */
  onSwitch(c: Copy, ep: Epoch): void;
  /**
   * A restore met a claim that removed self from epoch k: the skip re-add that continues the copy, from an EPOCH
   * record with flag bit1 above k (§11.4 step 5), or null.
   */
  skipAfter(c: Copy, k: number): Promise<Epoch | null>;
  /** the copy enters the epoch of its restore's HEADS entry (§11.4 step 5) */
  applyHeads(c: Copy, ep: Epoch): void;
  /** an own LEAVE row was applied in epoch e: write its LEAVE record if the account has none (§6.9) */
  ownLeave(c: Copy, e: number): void;
  /** a member's kept leave source changed in this epoch (its LEFT record rides in the next HEADS row, §7.3) */
  leftChanged(c: Copy, ep: Epoch): void;
  /** an own row's message: mark it failed (§11.3 step 7) */
  failOwn(c: Copy, key: string): void;
  /** the copy's own leave is current: a LEAVE record and no skip re-add above the latest one (§6.9) */
  leaveCurrent(c: Copy): boolean;
  /** self had left in epoch k: the copy is left now, or a LEAVE record at or below k with no skip re-add between */
  leftAt(c: Copy, k: number): boolean;
}

const who = (h: MembershipHost, c: Copy, ep: Epoch, j: number): string =>
  P.equalBytes(ep.D.members[j].uid, h.selfUid) ? "you" : "@" + h.handleOf(c, ep, j);

// ───────────────────────── lines ─────────────────────────

/** Like putLine, but a line already shown moves to `order` when that sorts earlier (one line at its earliest row). */
function putLineEarliest(c: Copy, key: string, order: number[], render: () => string): void {
  const had = c.order.get(key);
  if (had && cmpOrder(had, order) <= 0) return;
  if (had) dropLine(c, key);
  putLine(c, key, order, render);
}

function cmpOrder(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? -1) - (b[i] ?? -1);
    if (d !== 0) return d;
  }
  return 0;
}

/** Inserts a system line whose text is rendered again later (handles resolve, leave state changes). */
function putLine(c: Copy, key: string, order: number[], render: () => string): void {
  c.lines.set(key, render);
  const text = render();
  const at = c.messages.findIndex((m) => m.key === key);
  if (at >= 0) {
    if (c.messages[at].text !== text) c.messages[at] = { ...c.messages[at], text };
    return;
  }
  insertMessage(c, systemLine(key, order[0], text), order);
}

function dropLine(c: Copy, key: string): void {
  if (!c.lines.has(key) && !c.order.has(key)) return;
  c.lines.delete(key);
  removeMessage(c, key);
}

/** Renders every system line again (after a lookup resolved a member, §11.2). */
export function relabel(c: Copy): boolean {
  let changed = false;
  for (const [key, render] of c.lines) {
    const at = c.messages.findIndex((m) => m.key === key);
    if (at < 0) continue;
    const text = render();
    if (c.messages[at].text !== text) {
      c.messages[at] = { ...c.messages[at], text };
      changed = true;
    }
  }
  return changed;
}

const claimOrder = (h: MembershipHost, ep: Epoch, w: Winner, sub: number): number[] => [
  clampTs(w.ts, w.t, h.delta()),
  ep.e,
  w.E,
  CTL_LANE,
  w.n,
  sub,
];

/**
 * The lines that follow the leave state (§6.6 step 5, §11.9), derived again from scratch: per processed claim the
 * "removed" and "keys rotated" lines, and per LEAVE row held the "@x left" line while it is the kept source of x's
 * leave in its epoch, §6.8 accepts it, and x is not recorded as left in the epoch below.
 */
export function deriveLines(h: MembershipHost, c: Copy): void {
  const want = new Map<string, { order: number[]; render: () => string }>();
  for (const ep of c.epochs.values()) {
    const prev = ep.viaSkip ? undefined : c.epochs.get(ep.e - 1);
    for (const [uidB, s] of ep.left) {
      if (s.key === null || s.order === null || !leftIn(c, ep, uidB)) continue;
      if (prev && leftIn(c, prev, uidB)) continue;
      const j = ep.D.members.findIndex((m) => P.b64u(m.uid) === uidB);
      want.set(`left:${s.key}`, { order: s.order, render: () => `${who(h, c, ep, j)} left` });
    }
    const w = ep.ctl.winner;
    if (!ep.ended || !w || ep.myIndex < 0 || P.rmHas(w.claim.rm, ep.myIndex)) continue;
    const removed: number[] = [];
    const rotated: number[] = [];
    ep.D.members.forEach((m, j) => {
      if (!P.rmHas(w.claim.rm, j)) return;
      (leftIn(c, ep, P.b64u(m.uid)) ? rotated : removed).push(j);
    });
    if (removed.length)
      want.set(`sys:${ep.e}:rm`, {
        order: claimOrder(h, ep, w, 0),
        render: () =>
          `${who(h, c, ep, w.from)} removed ${removed.map((j) => who(h, c, ep, j)).join(", ")}`,
      });
    if (rotated.length)
      want.set(`sys:${ep.e}:rot`, {
        order: claimOrder(h, ep, w, 1),
        render: () => `keys rotated after ${rotated.map((j) => who(h, c, ep, j)).join(", ")} left`,
      });
  }
  for (const key of c.lines.keys())
    if ((key.startsWith("left:") || /^sys:\d+:(rm|rot)$/.test(key)) && !want.has(key))
      dropLine(c, key);
  for (const [key, x] of want) putLine(c, key, x.order, x.render);
}

// ───────────────────────── §6.8 again ─────────────────────────

/**
 * Decides every shown row again with the claims now held (§6.8): a row that is now dropped leaves the view and
 * `unread`; an own row's message is marked failed (§11.3 step 7).
 */
export function retract(h: MembershipHost, c: Copy): void {
  for (const ep of c.epochs.values())
    for (const [key, r] of ep.rows) {
      if (!r.shown || acceptedOld(c, ep.e, r.j, { E: r.E, n: r.n }, r.t)) continue;
      r.shown = false;
      if (r.unread && c.unread > 0) c.unread--;
      if (P.equalBytes(ep.D.members[r.j].uid, h.selfUid)) h.failOwn(c, key);
      else {
        removeMessage(c, key);
        c.order.set(key, []); // still processed: never applied again
      }
    }
}

// ───────────────────────── leaves (§6.9) ─────────────────────────

/**
 * A valid LEAVE row of member j of epoch ep. Self's: the copy's own leave (its record, "you left the conversation"
 * once). Another member's: recorded in ep and the consecutive later epochs held that still list it, keeping per epoch
 * the source with the least key (a carried leave's position is NONE).
 */
export function onLeave(
  h: MembershipHost,
  c: Copy,
  ep: Epoch,
  j: number,
  src: { t: number; row: Slot; key: string; order: number[] },
): void {
  const uid = ep.D.members[j].uid;
  const uidB = P.b64u(uid);
  if (P.equalBytes(uid, h.selfUid)) {
    const skipAbove = [...c.epochs.values()].some((x) => x.viaSkip && x.e > ep.e);
    if (!skipAbove) {
      c.left = true;
      // One line per leave, at the earliest own LEAVE row held (a repeated LEAVE adds none).
      const since = Math.max(0, ...[...c.epochs.values()].filter((x) => x.viaSkip).map((x) => x.e));
      putLineEarliest(c, `sys:you-left:${since}`, src.order, () => YOU_LEFT);
    }
    h.ownLeave(c, ep.e);
    h.changed();
    return;
  }
  c.leaves.add(uidB); // never a WELCOME channel to this member again (§6.12 step 1)
  for (let k = ep.e; ; k++) {
    const x = c.epochs.get(k);
    if (!x || (k > ep.e && x.viaSkip) || P.memberIndex(x.D, uid) < 0) break;
    const s: LeaveSource =
      k === ep.e
        ? { t: src.t, row: { ...src.row }, key: src.key, order: src.order }
        : { t: src.t, row: { ...P.NONE }, key: null, order: null };
    const had = x.left.get(uidB);
    if (had && sourceCmp(s, had) >= 0) continue;
    x.left.set(uidB, s);
    h.leftChanged(c, x);
  }
  deriveLines(h, c);
  h.changed();
}

/** The leaves of `from` carried into the next epoch `to` for the members it still lists (§6.6 step 4). */
function carryLeaves(from: Epoch, to: Epoch): void {
  for (const [uidB, s] of from.left) {
    if (!to.D.members.some((m) => P.b64u(m.uid) === uidB)) continue;
    const carried: LeaveSource = { t: s.t, row: { ...P.NONE }, key: null, order: null };
    const had = to.left.get(uidB);
    if (!had || sourceCmp(carried, had) < 0) to.left.set(uidB, carried);
  }
}

// ───────────────────────── the final winning claim (§6.6) ─────────────────────────

/** The lanes of epoch e−1 not swept yet: they leave the expected-label map when the copy switches past e (§11.2). */
function unsweptBelow(c: Copy, ep: Epoch): LaneTarget[] {
  const prev = ep.viaSkip ? undefined : c.epochs.get(ep.e - 1);
  if (!prev) return [];
  return prev.lanes.flatMap((l, j) => (l.swept ? [] : [{ c, ep: prev, lane: j }]));
}

/**
 * Processes the final winning claim `w` of epoch `ep` (§6.6): self removed (rm bit 1; a restore continues at a
 * recorded skip re-add), frozen (the own entry does not open, or a D′ check fails), or the switch to e+1. In every
 * case the claim is kept as the one that ended e (§6.8), rows are decided again, and the leave-dependent lines are
 * derived again.
 */
export async function processWinner(
  h: MembershipHost,
  c: Copy,
  ep: Epoch,
  w: Winner,
): Promise<void> {
  const claim = w.claim;
  ep.ended = { t: w.t, rm: claim.rm, cuts: claim.cuts, at: { E: w.E, n: w.n } };
  const i = ep.myIndex;
  const byOthers = w.from !== i;
  if (i < 0) return;
  if (P.rmHas(claim.rm, i)) {
    // Removed, or dropped after a leave: the lanes are swept once more (WELCOMEs, §6.9), then the copy stops here.
    if (ep.lanesOn)
      await h.sweep([...ep.lanes.map((_, j) => ({ c, ep, lane: j })), ...unsweptBelow(c, ep)]);
    for (const l of ep.lanes) l.swept = true;
    for (const t of unsweptBelow(c, ep)) t.ep.lanes[t.lane as number].swept = true;
    // "@by removed you" is decided at k (a self-leaver gets none) and stays when a skip re-add follows.
    if (!h.leftAt(c, ep.e))
      putLine(
        c,
        `sys:${ep.e}:rmyou`,
        claimOrder(h, ep, w, 0),
        () => `@${h.handleOf(c, ep, w.from)} removed you`,
      );
    const skip = await h.skipAfter(c, ep.e);
    if (skip) {
      skip.viaSkip = true;
      enterEpoch(h, c, skip);
      c.left = h.leaveCurrent(c); // a skip re-add above the latest LEAVE record ends the leave (§6.9)
    } else {
      c.removed = true;
      if (h.live() && byOthers) c.unread++;
    }
    retract(h, c);
    deriveLines(h, c);
    h.changed();
    return;
  }
  const out = P.processClaim({ kemSk: h.kemSk, De: ep.D, i, from: w.from, claim, blob: w.blob });
  if (out.kind === "nokey" || out.kind === "invalid" || out.kind === "removed") {
    c.frozen = out.kind === "invalid" ? "invalid" : "nokey";
    const by = "@" + h.handleOf(c, ep, w.from);
    h.warn(out.kind === "invalid" ? frozenInvalid(by) : frozenNoKey(by), true);
    retract(h, c);
    deriveLines(h, c);
    h.changed();
    return;
  }
  // Accept e+1. The lanes of e−1 still followed are swept before they leave; the lanes of e stay in the map until
  // the next walk (followed ones until their member posts in e+1, the others swept once more).
  const below = unsweptBelow(c, ep);
  if (below.length) await h.sweep(below);
  for (const t of below) t.ep.lanes[t.lane as number].swept = true;
  if (!ep.lanesOn) for (const l of ep.lanes) l.swept = true;
  const next = newEpoch({
    e: ep.e + 1,
    EK: out.EK,
    D: out.D,
    dsig: out.dsig,
    bundleId: claim.bundleId,
    bundleSize: claim.bundleSize,
    tReg: w.tReg,
    pks: out.pks,
    self: h.selfUid,
  });
  carryLeaves(ep, next);
  enterEpoch(h, c, next);
  claimLines(h, c, ep, next, w);
  if (h.live() && byOthers) c.unread++;
  retract(h, c);
  deriveLines(h, c);
  h.changed();
}

/** The copy continues at `next` (a switch, or a skip re-add): held, current, its lanes, HEADS, topic. */
export function enterEpoch(h: MembershipHost, c: Copy, next: Epoch): void {
  next.lanesOn = c.heads === null || next.e >= c.heads.e;
  if (!next.lanesOn) for (const l of next.lanes) l.swept = true;
  c.epochs.set(next.e, next);
  c.current = next.e;
  if (c.heads && c.heads.e === next.e) h.applyHeads(c, next);
  h.onSwitch(c, next);
}

/** The lines of an accepted claim that do not depend on leaves: added members, the name, a plain rotation (§11.9). */
function claimLines(h: MembershipHost, c: Copy, ep: Epoch, next: Epoch, w: Winner): void {
  const by = () => who(h, c, ep, w.from);
  const added = next.D.members
    .map((m, j) => (P.memberIndex(ep.D, m.uid) < 0 ? j : -1))
    .filter((j) => j >= 0);
  if (added.length)
    putLine(
      c,
      `sys:${ep.e}:add`,
      claimOrder(h, ep, w, 2),
      () => `${by()} added ${added.map((j) => who(h, c, next, j)).join(", ")}`,
    );
  const before = displayName(ep.D);
  const after = displayName(next.D);
  if (before !== after)
    putLine(c, `sys:${ep.e}:name`, claimOrder(h, ep, w, 3), () =>
      after === null
        ? `${by()} removed the conversation name`
        : `${by()} renamed the conversation to “${after}”`,
    );
  if (!added.length && w.claim.rm === 0 && before === after)
    putLine(
      c,
      `sys:${ep.e}:keys`,
      claimOrder(h, ep, w, 4),
      () => `${by()} rotated the conversation keys`,
    );
}
