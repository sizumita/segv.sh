// Scrollback (docs/PROTOCOL-v2.md §11.10): when a conversation is opened, older rows of each lane are loaded until
// the view holds VIEW_MESSAGES messages or the history is exhausted, once per copy and session. Rows found here are
// processed like any other and never count as unread. This walks the current epoch; the epochs below a claim come
// with M7 (their heads found from the sweep or from E_start, never from the claim's cuts).
import * as P from "~/lib/proto";
import type * as W from "~/lib/wire";
import { VIEW_MESSAGES, type Copy, type Epoch, type Slot } from "./conv";
import { applyLaneRow, type SyncCtx } from "./sync";

/** Slots probed below the oldest loaded row of a lane per round (§11.10: (E, n−32..n−1)). */
const STEP = 32;

/**
 * The dense-prefix end of the highest earlier era of lane j with rows, at or above `floor` and below `E`: slot 0 of
 * each era (one key per idle era), then a gallop in exists mode. Null when none of them has rows.
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
  for (let base = 1; ; base += STEP) {
    const keys: W.GetKey[] = Array.from({ length: STEP }, (_, i) => ({
      E: Ex,
      label: P.Lmsg(ep.keys.rk, j, Ex, base + i),
      mode: 1 as const,
    }));
    const s2 = await ctx.api.get(keys);
    const miss = s2.findIndex((s) => s.s !== "hit");
    if (miss >= 0) return { E: Ex, n: base + miss };
  }
}

/** Loads older rows of the copy's current epoch (§11.10); once per copy and session. */
export async function scrollback(ctx: SyncCtx, c: Copy): Promise<void> {
  if (c.scrolled) return;
  c.scrolled = true;
  const ep = c.epochs.get(c.current);
  if (!ep || ep.Estart === null) return;
  const Estart = ep.Estart;
  // Per lane, the slot below which nothing is loaded yet, and whether the lane's history is exhausted.
  const below: Slot[] = ep.lanes.map((l) =>
    l.oldest ? { E: l.oldest.E, n: l.oldest.n } : { ...(l.tail ?? l.next) },
  );
  const done = ep.lanes.map(() => false);
  for (
    let round = 0;
    round < 10_000 && c.messages.length < VIEW_MESSAGES && done.some((d) => !d);
    round++
  ) {
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
            done[j] = true; // the lane's first row in this epoch (or a prev that points nowhere new)
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
