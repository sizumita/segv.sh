// Scrollback (docs/PROTOCOL.md §11.10): when a conversation is opened, older rows of each lane are loaded until
// the view holds VIEW_MESSAGES messages or the history is exhausted, once per copy and session; below the first row
// of an epoch the walk continues in the copy's previous held epoch, whose lane heads are found first (never from the
// cuts of the claim that ended it). The initial history of a restore (§11.4 step 6) takes its rows the same way.
// Rows found here are processed like any other and never count as unread.
import * as P from "@segv/protocol/proto";
import type * as W from "@segv/protocol/wire";
import { HISTORY_INITIAL, VIEW_MESSAGES, W_SLOTS, type Copy, type Epoch, type Slot } from "./conv";
import { applyLaneRow, type SyncCtx } from "./sync";

/** Slots probed below the oldest loaded row of a lane per round (§11.10: (E, n−32..n−1)). */
const STEP = 32;

/**
 * The dense-prefix end of the highest earlier era of lane j with rows, at or above `floor` and below `E`: slot 0 of
 * each era (one key per idle era), then the prefix length in exists mode. Null when none of them has rows.
 */
async function earlierEnd(
  ctx: SyncCtx,
  ep: Epoch,
  j: number,
  E: number,
  floor: number,
): Promise<Slot | null> {
  if (E <= floor) return null;
  const eras = Array.from({ length: E - floor }, (_, k) => E - 1 - k);
  const st = await ctx.api.get(
    eras.map((Ex) => ({ E: Ex, label: P.Lmsg(ep.keys.rk, j, Ex, 0), mode: 1 as const })),
  );
  const k = st.findIndex((s) => s.s === "hit");
  if (k < 0) return null;
  const Ex = eras[k];
  const [n] = await prefixLengths(ctx, [{ ep, j, E: Ex }]);
  return { E: Ex, n };
}

/**
 * The dense-prefix length of each lane j in its era E, whose slot 0 holds a row, all lanes in lockstep: one batched
 * get of the slots 2^i (i < 32), which brackets each length, then batched gets of 32 evenly spaced slots per lane that
 * narrow the brackets, in exists mode; so the end of a long lane costs a few requests, not one per 32 rows.
 */
async function prefixLengths(
  ctx: SyncCtx,
  lanes: readonly { ep: Epoch; j: number; E: number }[],
): Promise<number[]> {
  const exist = async (asks: { k: number; n: number }[]): Promise<boolean[]> =>
    (
      await ctx.api.get(
        asks.map(({ k, n }) => {
          const { ep, j, E } = lanes[k];
          return { E, label: P.Lmsg(ep.keys.rk, j, E, n), mode: 1 as const };
        }),
      )
    ).map((s) => s.s === "hit");
  if (lanes.length === 0) return [];
  const pows = Array.from({ length: 32 }, (_, i) => 2 ** i);
  const first = await exist(lanes.flatMap((_, k) => pows.map((n) => ({ k, n }))));
  // every slot below `lo` holds a row, slot `hi` holds none: the length lies in [lo, hi]
  const lo: number[] = [];
  const hi: number[] = [];
  lanes.forEach((_, k) => {
    const m = first.slice(k * 32, k * 32 + 32).findIndex((x) => !x);
    lo.push(m < 0 ? pows[31] + 1 : m === 0 ? 1 : pows[m - 1] + 1);
    hi.push(m < 0 ? pows[31] + 1 : pows[m]);
  });
  for (let round = 0; round < 64; round++) {
    const open = lanes.map((_, k) => k).filter((k) => lo[k] < hi[k]);
    if (open.length === 0) break;
    const asks: { k: number; n: number }[] = [];
    for (const k of open) {
      const step = Math.max(1, Math.ceil((hi[k] - lo[k]) / STEP));
      for (let n = lo[k]; n < hi[k]; n += step) asks.push({ k, n });
    }
    const got = await exist(asks);
    for (const k of open) {
      const mine = asks.map((a, x) => ({ ...a, hit: got[x] })).filter((a) => a.k === k);
      const miss = mine.findIndex((a) => !a.hit);
      if (miss < 0) lo[k] = mine[mine.length - 1].n + 1;
      else {
        hi[k] = mine[miss].n;
        if (miss > 0) lo[k] = mine[miss - 1].n + 1;
      }
    }
  }
  return lo;
}

/**
 * The slot after each lane's last row at or before its processed position (§11.4 step 6 "the last slots of each
 * lane"): the position itself when its era holds rows before it, else the dense-prefix end of the latest earlier era
 * with rows down to E_start. Every lane is searched at once: one batched get of slot 0 of each idle era (one key per
 * lane and era), then the prefix lengths in lockstep (a few batched gets in exists mode). Null for a lane with no row.
 */
export async function lanesEnd(
  ctx: SyncCtx,
  lanes: readonly { ep: Epoch; j: number }[],
): Promise<(Slot | null)[]> {
  const out: (Slot | null)[] = lanes.map(() => null);
  const keys: W.GetKey[] = [];
  const owner: { i: number; E: number }[] = [];
  lanes.forEach(({ ep, j }, i) => {
    const l = ep.lanes[j];
    const at = l.tail ?? l.next;
    if (at.n > 0) out[i] = at;
    else if (l.head && l.head.cnt > 0 && P.posCmp({ E: l.head.E, n: l.head.cnt }, at) <= 0)
      out[i] = { E: l.head.E, n: l.head.cnt };
    else
      for (let E = at.E - 1; E >= (ep.Estart ?? at.E); E--) {
        keys.push({ E, label: P.Lmsg(ep.keys.rk, j, E, 0), mode: 1 });
        owner.push({ i, E });
      }
  });
  if (keys.length === 0) return out;
  const st = await ctx.api.get(keys);
  const era = new Map<number, number>();
  st.forEach((s, k) => {
    const { i, E } = owner[k];
    if (s.s === "hit" && (era.get(i) ?? -1) < E) era.set(i, E);
  });
  const found = await prefixLengths(
    ctx,
    [...era].map(([i, E]) => ({ ep: lanes[i].ep, j: lanes[i].j, E })),
  );
  [...era].forEach(([i, E], k) => (out[i] = { E, n: found[k] }));
  return out;
}

/**
 * The copy's previous held epoch below `ep` (§11.10): e−1, loaded from the account's records when a restore did not
 * materialize it; the history ends below the copy's root epoch.
 */
export async function previousHeld(ctx: SyncCtx, c: Copy, ep: Epoch): Promise<Epoch | undefined> {
  return c.epochs.get(ep.e - 1) ?? (await ctx.older?.(c, ep.e - 1));
}

/**
 * The lane heads of an older epoch (§11.10), as the slot after each lane's last row: from the processed position of
 * an epoch this session swept, or from E_start for one it never processed, to the era after the era of the claim
 * that ended it (at most E_now), one key per idle era and a gallop on hits.
 */
async function olderHeads(ctx: SyncCtx, ep: Epoch): Promise<(Slot | null)[]> {
  const Es = ep.Estart!;
  const Enow = P.era(ctx.api.serverNow());
  const Emax = Math.min(Enow, (ep.ended?.at.E ?? Enow) + 1);
  const starts = ep.lanes.map((l) => (ep.lanesOn ? { ...(l.tail ?? l.next) } : { E: Es, n: 0 }));
  // The dense-prefix end of each (lane, era), found by probing forward from its first slot.
  const ends = new Map<string, number>();
  let probes = ep.lanes.flatMap((_, j) => {
    const s = starts[j];
    const out: { j: number; E: number; n: number; w: number }[] = [];
    for (let E = Math.max(s.E, Es); E <= Emax; E++)
      out.push({ j, E, n: E === s.E ? s.n : 0, w: 1 });
    return out;
  });
  for (let round = 0; round < 256 && probes.length; round++) {
    const keys = probes.flatMap((p) =>
      Array.from({ length: p.w }, (_, i) => ({
        E: p.E,
        label: P.Lmsg(ep.keys.rk, p.j, p.E, p.n + i),
        mode: 1 as const,
      })),
    );
    const st = await ctx.api.get(keys);
    let o = 0;
    const next: typeof probes = [];
    for (const p of probes) {
      const part = st.slice(o, o + p.w);
      o += p.w;
      const miss = part.findIndex((s) => s.s !== "hit");
      if (miss >= 0) ends.set(`${p.j}:${p.E}`, p.n + miss);
      else next.push({ ...p, n: p.n + p.w, w: W_SLOTS });
    }
    probes = next;
  }
  return ep.lanes.map((_, j) => {
    for (let E = Emax; E >= Es; E--) {
      const end = ends.get(`${j}:${E}`) ?? (E === starts[j].E ? starts[j].n : 0);
      if (end > 0) return { E, n: end };
    }
    return null;
  });
}

/**
 * The backward walk over one epoch's lanes from `start` (the slot after each lane's last row to consider): probes
 * (E, n−32..n−1), and at n = 0 moves to the previous era with rows (the oldest loaded row's prev, or the dense-prefix
 * end of an earlier era down to E_start). Stops when `enough()` holds or every lane is exhausted, or after `rounds`.
 */
async function walkBack(
  ctx: SyncCtx,
  c: Copy,
  ep: Epoch,
  start: (Slot | null)[],
  enough: () => boolean,
  rounds = 10_000,
): Promise<void> {
  const Estart = ep.Estart!;
  const below: Slot[] = start.map((s) => s ?? { E: Estart, n: 0 });
  const done = start.map((s) => s === null);
  for (let round = 0; round < rounds && !enough() && done.some((d) => !d); round++) {
    const want: { j: number; E: number; n: number; label: Uint8Array }[] = [];
    for (let j = 0; j < ep.lanes.length; j++) {
      if (done[j]) continue;
      const b = below[j];
      if (b.n === 0) {
        // At the start of an era: the oldest loaded row's prev names the previous era with rows (NONE: the lane's
        // first row in this epoch); with nothing loaded in this era, probe the earlier eras down to E_start.
        const o = ep.lanes[j].oldest;
        if (o && o.E === b.E) {
          if (P.isNone(o.prev) || o.prev.E >= b.E) {
            done[j] = true;
            continue;
          }
          below[j] = { E: o.prev.E, n: o.prev.n + 1 };
        } else {
          const end = await earlierEnd(ctx, ep, j, b.E, Estart);
          if (!end) {
            done[j] = true;
            continue;
          }
          below[j] = end;
        }
      }
      const at = below[j];
      for (let n = Math.max(0, at.n - STEP); n < at.n; n++)
        want.push({ j, E: at.E, n, label: P.Lmsg(ep.keys.rk, j, at.E, n) });
      below[j] = { E: at.E, n: Math.max(0, at.n - STEP) };
    }
    if (want.length === 0) continue;
    const st = await ctx.api.get(want.map((x) => ({ E: x.E, label: x.label, mode: 0 as const })));
    for (let i = want.length - 1; i >= 0; i--) {
      const s = st[i];
      const x = want[i];
      if (s.s === "hit" && s.body)
        applyLaneRow(
          ctx,
          c,
          ep,
          x.j,
          { E: x.E, n: x.n, label: x.label, t: s.t, body: s.body },
          true,
        );
    }
  }
}

/** Loads older rows of the copy, epoch by epoch down to its root (§11.10); once per copy and session. */
export async function scrollback(ctx: SyncCtx, c: Copy): Promise<void> {
  if (c.scrolled) return;
  c.scrolled = true;
  const enough = () => c.messages.length >= VIEW_MESSAGES;
  for (let ep = c.epochs.get(c.current); ep && !enough(); ep = await previousHeld(ctx, c, ep)) {
    if (ep.Estart === null) break;
    const start =
      ep.e === c.current
        ? ep.lanes.map((l) =>
            l.oldest ? { E: l.oldest.E, n: l.oldest.n } : { ...(l.tail ?? l.next) },
          )
        : await olderHeads(ctx, ep);
    await walkBack(ctx, c, ep, start, enough);
  }
}

/**
 * §11.4 step 6 for an epoch with fewer than HISTORY_INITIAL rows loaded: the last HISTORY_INITIAL slots of each lane
 * of the copy's previous held epoch (its heads found as for an epoch never swept).
 */
export async function olderInitialHistory(ctx: SyncCtx, c: Copy): Promise<void> {
  const cur = c.epochs.get(c.current);
  if (!cur) return;
  // every row of the epoch that was loaded counts, REACTION rows included, so the cost never depends on content
  const prev = cur.loaded < HISTORY_INITIAL ? await previousHeld(ctx, c, cur) : undefined;
  if (!prev || prev.Estart === null) return;
  const heads = await olderHeads(ctx, prev);
  await walkBack(ctx, c, prev, heads, () => false, 1);
}
