// Reactions (docs/PROTOCOL.md §11.12): which REACTION rows react to which TEXT or IMAGE row, and the state per target,
// member and emoji, walked in lane order with the 8-emoji rule. Pure functions of the rows a copy holds and accepts,
// computed again whenever a row arrives or a §6.8 decision changes, so devices holding the same rows agree.
import * as P from "~/lib/proto";
import { acceptedOld, rowKey, type Copy, type ReactionRow } from "./conv";
import type { ReactionView } from "./types";

/** At most this many emoji are on per member and target (§11.12 `MAX_REACTIONS`). */
export const MAX_REACTIONS = 8;

/**
 * The message key of the row a REACTION row reacts to (§11.12 "Target"): a TEXT or IMAGE row the copy holds and
 * accepts, in an epoch `te ≤ e` that the copy holds, on a lane `tl < |D_te|`, whose label and stored body `th` names.
 * Null while the target is not loaded or not decided, and for a row that reacts to nothing.
 */
export function targetOf(c: Copy, r: ReactionRow): string | null {
  const x = r.reaction;
  if (x.te > r.e || x.te < c.rootE) return null;
  const ep = c.epochs.get(x.te);
  if (!ep || x.tl >= ep.D.members.length) return null;
  const key = rowKey(x.tE, P.Lmsg(ep.keys.rk, x.tl, x.tE, x.tn));
  const t = ep.rows.get(key);
  if (!t || !t.shown || !P.equalBytes(t.th, x.th)) return null;
  return key;
}

/**
 * Each member's emoji that are on, per target (§11.12 "State"): the member's accepted REACTION rows for the target in
 * lane order (by the row's epoch, then (E, n)), from an empty set; an add puts its emoji in unless it is there or 8 are
 * on, a remove takes it out.
 */
export function reactionSets(c: Copy): Map<string, Map<string, Set<string>>> {
  const rows = [...c.reactions.values()]
    .filter((r) => r.shown && acceptedOld(c, r.e, r.j, { E: r.E, n: r.n }, r.t))
    .sort((a, b) => a.e - b.e || a.E - b.E || a.n - b.n);
  const out = new Map<string, Map<string, Set<string>>>();
  for (const r of rows) {
    const key = targetOf(c, r);
    if (!key) continue;
    let byUid = out.get(key);
    if (!byUid) out.set(key, (byUid = new Map()));
    let on = byUid.get(r.uid);
    if (!on) byUid.set(r.uid, (on = new Set()));
    const emoji = r.reaction.emoji;
    if (r.reaction.op === 1) {
      if (!on.has(emoji) && on.size < MAX_REACTIONS) on.add(emoji);
    } else on.delete(emoji);
  }
  return out;
}

/** The emoji on for at least one member, with how many and whether self is one of them, most first (§11.12). */
export function reactionViews(byUid: Map<string, Set<string>>, selfUidB: string): ReactionView[] {
  const count = new Map<string, number>();
  for (const on of byUid.values()) for (const e of on) count.set(e, (count.get(e) ?? 0) + 1);
  const mine = byUid.get(selfUidB) ?? new Set<string>();
  return [...count.entries()]
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([emoji, n]) => ({ emoji, count: n, mine: mine.has(emoji) }));
}

/** Writes the reactions of every TEXT and IMAGE message of the copy into its views; true when one changed. */
export function refreshReactions(c: Copy, selfUidB: string): boolean {
  c.reactionsDirty = false;
  const sets = reactionSets(c);
  let changed = false;
  for (let i = 0; i < c.messages.length; i++) {
    const m = c.messages[i];
    if (m.kind !== "text" && m.kind !== "image") continue;
    const byUid = sets.get(m.key);
    const next = byUid ? reactionViews(byUid, selfUidB) : [];
    const same =
      next.length === m.reactions.length &&
      next.every(
        (x, k) =>
          x.emoji === m.reactions[k].emoji &&
          x.count === m.reactions[k].count &&
          x.mine === m.reactions[k].mine,
      );
    if (same) continue;
    c.messages[i] = { ...m, reactions: next };
    changed = true;
  }
  return changed;
}
