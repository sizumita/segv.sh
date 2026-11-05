// Reactions (docs/PROTOCOL.md §11.12): which REACTION rows react to which TEXT, IMAGE, FILE or REPLY row, and the state
// per target, member and emoji, walked in lane order with the 8-emoji rule. Replies (§11.17) and edits (§11.18) name
// their target by the same rule; an edit counts only for its sender's own text, and the latest in lane order decides.
// Pure functions of the rows a copy holds and accepts, computed again whenever a row arrives or a §6.8 decision
// changes, so devices holding the same rows agree.
import * as P from "@segv/protocol/proto";
import { acceptedOld, rowKey, type Copy, type EditRow, type ReactionRow } from "./conv";
import {
  MAX_REACTIONS,
  type EditedView,
  type EditVersion,
  type MessageView,
  type ReactionView,
  type ReplyView,
} from "./types";

/** The target fields of a REACTION or a REPLY (§3.3). */
type TargetFields = Pick<P.ReplyTo, "te" | "tl" | "tE" | "tn" | "th">;

/**
 * The row that a REACTION or REPLY of epoch `e` names (§11.12 "Target", §11.17): a TEXT, IMAGE, FILE or REPLY row the
 * copy holds and accepts, in an epoch `te ≤ e` that the copy holds, on a lane `tl < |D_te|`, whose label and stored body
 * `th` names. `waiting` while no decided row is held at that position; `none` when it names no row the copy can show.
 */
export function targetState(c: Copy, e: number, x: TargetFields): ReplyView {
  const none: ReplyView = { key: "", state: "none" };
  if (x.te > e || x.te < c.rootE) return none;
  const ep = c.epochs.get(x.te);
  if (!ep) return { key: "", state: "waiting" };
  if (x.tl >= ep.D.members.length) return none;
  const key = rowKey(x.tE, P.Lmsg(ep.keys.rk, x.tl, x.tE, x.tn));
  const t = ep.rows.get(key);
  // The slot holds a row of another type (a reaction, a leave …): never a message.
  if (!t) return c.order.has(key) ? none : { key: "", state: "waiting" };
  if (!t.shown || !P.equalBytes(t.th, x.th)) return none;
  return { key, state: "shown" };
}

/**
 * The message key of the row a REACTION row reacts to (§11.12 "Target"). Null while the target is not loaded or not
 * decided, and for a row that reacts to nothing.
 */
export function targetOf(c: Copy, r: ReactionRow): string | null {
  const t = targetState(c, r.e, r.reaction);
  return t.state === "shown" ? t.key : null;
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

/**
 * The message key of the row an EDIT row edits (§11.18 "Target"): the row the rule of §11.12 names, when its sender is
 * the EDIT's sender (by uid: a member's index changes across epochs). Whether that row holds a text is decided on its
 * view (`editLists` callers). Null while the target is not loaded or not decided, and for a row that edits nothing.
 */
export function editTargetOf(c: Copy, r: EditRow): string | null {
  const t = targetState(c, r.e, r.to);
  if (t.state !== "shown") return null;
  const sender = c.epochs.get(r.to.te)?.D.members[r.to.tl];
  return sender && P.b64u(sender.uid) === r.uid ? t.key : null;
}

/**
 * The EDIT rows that edit each message, in lane order (by the row's epoch, then (E, n)), by message key (§11.18
 * "State"): only accepted rows count, and the last one decides the message's text.
 */
export function editLists(c: Copy): Map<string, EditRow[]> {
  const rows = [...c.edits.values()]
    .filter((r) => r.shown && acceptedOld(c, r.e, r.j, { E: r.E, n: r.n }, r.t))
    .sort((a, b) => a.e - b.e || a.E - b.E || a.n - b.n);
  const out = new Map<string, EditRow[]>();
  for (const r of rows) {
    const key = editTargetOf(c, r);
    if (!key) continue;
    let list = out.get(key);
    if (!list) out.set(key, (list = []));
    list.push(r);
  }
  return out;
}

/** A message whose text an edit can replace (§11.18 "Target"): a TEXT, or a REPLY carrying one, held as a row. */
const editable = (m: MessageView): boolean => m.kind === "text" && !m.key.startsWith("local:");

/**
 * The text and edits a message shows (§11.18 "Display"): an edit this device is sending, else the latest edit that
 * counts, else the text it was sent with (`original`).
 */
function editState(
  c: Copy,
  m: MessageView,
  list: EditRow[] | undefined,
  original: string,
): { text: string; edited?: EditedView } {
  const local = c.localEdits.get(m.key);
  const last = list?.length ? list[list.length - 1] : undefined;
  if (!local && !last) return { text: original };
  const count = list?.length ?? 0;
  if (local) return { text: local.text, edited: { ts: local.ts, count, sending: true } };
  return { text: last!.text, edited: { ts: last!.ts, count, sending: false } };
}

const sameEdited = (a: EditedView | undefined, b: EditedView | undefined): boolean =>
  a === b || (!!a && !!b && a.ts === b.ts && a.count === b.count && a.sending === b.sending);

/**
 * The text a message shows by the rows this device holds (§11.18 "State"), leaving out an edit it is still sending:
 * its latest edit's, or the one it was sent with. Null for a key that names no message whose text can be edited.
 */
export function decidedText(c: Copy, key: string): string | null {
  const m = c.messages.find((x) => x.key === key);
  if (!m || !editable(m)) return null;
  const list = c.edits.size ? editLists(c).get(key) : undefined;
  if (list?.length) return list[list.length - 1].text;
  return c.originals.get(key) ?? m.text ?? "";
}

/**
 * The versions of an edited message (§11.18 "Display"): the text it was sent with at its own time, then each edit that
 * counts, in lane order, at the time it was made. Empty for a message that no edit counts for, or an unknown key.
 */
export function editVersions(c: Copy, key: string): EditVersion[] {
  const m = c.messages.find((x) => x.key === key);
  if (!m || !editable(m) || !c.edits.size) return [];
  const list = editLists(c).get(key);
  if (!list?.length) return [];
  return [
    { text: c.originals.get(key) ?? m.text ?? "", ts: m.ts },
    ...list.map((r) => ({ text: r.text, ts: r.ts })),
  ];
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

/**
 * Writes the reactions of every TEXT, IMAGE, FILE and REPLY message of the copy, the target of every REPLY (§11.17),
 * and the text and edits of every message an edit counts for (§11.18), into its views; true when one changed. A view
 * that changes is a new object (the UI tells messages apart by object). A local echo keeps the target it was sent with.
 */
export function refreshRefs(c: Copy, selfUidB: string): boolean {
  c.refsDirty = false;
  const sets = c.reactions.size ? reactionSets(c) : null;
  const edits = c.edits.size ? editLists(c) : null;
  let changed = false;
  for (let i = 0; i < c.messages.length; i++) {
    const m = c.messages[i];
    if (m.kind !== "text" && m.kind !== "image" && m.kind !== "file") continue;
    const byUid = sets?.get(m.key);
    const next = byUid ? reactionViews(byUid, selfUidB) : [];
    const same =
      next.length === m.reactions.length &&
      next.every(
        (x, k) =>
          x.emoji === m.reactions[k].emoji &&
          x.count === m.reactions[k].count &&
          x.mine === m.reactions[k].mine,
      );
    const r = c.replies.get(m.key);
    const reply = r ? targetState(c, r.e, r.to) : m.reply;
    const sameReply = reply?.key === m.reply?.key && reply?.state === m.reply?.state;
    // The text it was sent with is kept aside while an edit replaces it, so that it comes back when none counts.
    let ed: { text: string; edited?: EditedView } | null = null;
    if (editable(m)) {
      const original = c.originals.get(m.key) ?? m.text ?? "";
      ed = editState(c, m, edits?.get(m.key), original);
      if (ed.edited) c.originals.set(m.key, original);
      else c.originals.delete(m.key);
    }
    const sameEdit = !ed || (ed.text === m.text && sameEdited(ed.edited, m.edited));
    if (same && sameReply && sameEdit) continue;
    const { edited: _old, ...rest } = m;
    c.messages[i] = {
      ...(sameEdit ? m : rest),
      reactions: same ? m.reactions : next,
      ...(reply ? { reply } : {}),
      ...(ed && !sameEdit ? { text: ed.text, ...(ed.edited ? { edited: ed.edited } : {}) } : {}),
    };
    changed = true;
  }
  // a message that left the view (trimmed, or dropped by §6.8) keeps no original
  if (c.originals.size) {
    const held = new Set(c.messages.map((m) => m.key));
    for (const key of c.originals.keys()) if (!held.has(key)) c.originals.delete(key);
  }
  return changed;
}
