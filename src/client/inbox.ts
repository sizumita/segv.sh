// The inbox (docs/PROTOCOL-v2.md §10.5, §11.5): the cursor rules. The poll and trial decryption land with M6b.
import * as P from "~/lib/proto";

/** An inbox cursor (Ein, relIn): every row of era E with rel ≤ relIn has been processed (§7.2 HEADS, §11.5). */
export interface InboxCursor {
  E: number;
  rel: number;
}

/**
 * The cursor for an account registered at server time `tr` (§11.1, §11.5 step 1): `(era(t), ⌊(t − T0)/D⌋)` with
 * `t = tr − SKEW·1000`, so an invite posted after the registration lands above it however far the InboxDO's clock
 * lags (§9.3); here one slot and one more `D` earlier, a margin (an earlier cursor only re-reads rows, which are
 * duplicates, §6.7 step 3). Below `(max(E_FIRST, E_now − 3), 0)` it is that position instead (§10.5: older eras are
 * gone). `tr` is the registration response's `x-segv-now` on the registering device, and `start(regEra)` on a
 * device without a cursor.
 */
export function cursorAt(
  tr: number,
  p: { skew: number; inboxSlot: number; efirst: number },
  Enow: number,
): InboxCursor {
  const D = p.inboxSlot * 1000;
  const t = tr - p.skew * 1000 - D;
  const lo = Math.max(p.efirst, Enow - 3);
  const E = P.era(t);
  if (E < lo) return { E: lo, rel: 0 };
  return { E, rel: Math.max(Math.floor((t - P.T0_MS) / D) - 1, 0) };
}

/** An invite that opened to a J, with its position. */
export interface FoundJoin {
  E: number;
  rel: number;
  J: P.Join;
}

export interface InboxScan {
  joins: FoundJoin[];
  /**
   * The cursor after this read (§11.5 step 3): `(E, closed)` of the first era read that is not complete. An era is
   * complete once a read of it returned `more = 0` and was issued at an estimated server time of at least
   * `end(E) + (2·SKEW + 2·Δin)·1000`; the current era never is.
   */
  cursor: InboxCursor;
}

export const MALFORMED_INVITE = "ignored a malformed conversation key";

/** Rows trial-decrypted between two yields to the event loop (§11.5 step 2, same thread). */
const DECRYPT_CHUNK = 8;

/**
 * Reads the inbox from `cursor` (or, without one, from the registration rule with `t_r = start(regEra)`, R9-1) up
 * to the current era and trial-decrypts every row (§11.5 steps 1–2, §5.3). Rows with `rel ≤ after` or above the
 * reported `closed` are ignored (§10.5). Errors are thrown (the caller retries later); a 410 skips that era.
 */
export async function scanInbox(
  api: {
    serverNow(): number;
    readInbox(
      E: number,
      after: number,
    ): Promise<{
      closed: number;
      more: boolean;
      rows: { rel: number; eid: Uint8Array; body: Uint8Array }[];
    }>;
  },
  kemSk: Uint8Array,
  cursor: InboxCursor | null,
  p: { skew: number; inboxSlot: number; efirst: number },
  regEra: number,
  warn: (text: string) => void,
): Promise<InboxScan> {
  const Enow = P.era(api.serverNow());
  const start = cursor ?? cursorAt(P.eraStart(regEra), p, Enow);
  const lo = Math.max(p.efirst, Enow - 3);
  const from = start.E < lo ? { E: lo, rel: 0 } : start;
  const joins: FoundJoin[] = [];
  let next: InboxCursor | null = null;
  let decrypted = 0;
  for (let E = from.E; E <= Enow; E++) {
    let after = E === from.E ? from.rel : 0;
    const issued = api.serverNow();
    let page: Awaited<ReturnType<typeof api.readInbox>>;
    let closed = after;
    try {
      for (;;) {
        page = await api.readInbox(E, after);
        for (const r of page.rows) {
          if (r.rel <= after || r.rel > page.closed) continue;
          const opened = P.tryOpenInvite(kemSk, E, 0, r.eid, r.body);
          if (++decrypted % DECRYPT_CHUNK === 0) await new Promise((res) => setTimeout(res, 0));
          if (!opened) continue;
          if (opened.kind === "malformed") warn(MALFORMED_INVITE);
          else joins.push({ E, rel: r.rel, J: opened.join });
        }
        closed = Math.max(closed, page.closed);
        if (!page.more) break;
        after = page.rows[page.rows.length - 1].rel;
      }
    } catch (e) {
      if ((e as { status?: number }).status === 410) continue; // older than E_now − 3: gone (§10.5)
      throw e;
    }
    const complete = E < Enow && issued >= P.eraEnd(E) + (2 * p.skew + 2 * p.inboxSlot) * 1000;
    if (!complete && next === null) next = { E, rel: closed };
  }
  return { joins, cursor: next ?? { E: Enow, rel: from.E === Enow ? from.rel : 0 } };
}

/** The earlier of two cursors. */
export const minCursor = (a: InboxCursor, b: InboxCursor): InboxCursor =>
  a.E < b.E || (a.E === b.E && a.rel <= b.rel) ? a : b;
