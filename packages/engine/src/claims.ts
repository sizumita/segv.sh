// The control lane (docs/PROTOCOL.md §6.4–§6.6): three-valued e-validity in the order of requests of §6.4, the
// winner (the first e-valid row with every earlier slot decided), its finality across eras (§6.5), and the state
// machine that drives a copy's control lane to a processed final winner. Processing the winner (removed, frozen, or
// the switch to e+1) is the caller's (messaging.ts), which needs the sweep, the lines and the topics.
import * as P from "@segv/protocol/proto";
import { ApiError, type Api } from "./api";
import { eraOfSec, type Copy, type Epoch, type StoredRow, type Winner } from "./conv";
import { UNDECRYPTABLE } from "./sync";

type Bytes = Uint8Array;

export const INVALID_CHANGE = "ignored an invalid membership change";
export const frozenNoKey = (by: string): string =>
  `${by}'s membership change was never delivered to you; the members of this conversation can no longer change`;
export const frozenInvalid = (by: string): string =>
  `${by} made an invalid membership change; the members of this conversation can no longer change`;

export type Verdict =
  | { kind: "valid"; claim: P.Claim; from: number; ts: number; tReg: number; blob: Bytes }
  | { kind: "invalid"; warning: string }
  | { kind: "undecided"; retryMs: number };

const invalid = (warning = INVALID_CHANGE): Verdict => ({ kind: "invalid", warning });
const undecided = (retryMs = 0): Verdict => ({ kind: "undecided", retryMs });

/** E_start(e) of an epoch, from its t_reg, learnt once from `blob/meta` when unknown (§4.2, §6.4(f)). */
async function eStartOf(api: Api, ep: Epoch): Promise<number | null> {
  if (ep.Estart !== null) return ep.Estart;
  const m = await api.blobMetaOrNow(ep.bundleId);
  if (!("t" in m)) return null;
  ep.tReg = m.t;
  ep.Estart = eraOfSec(m.t);
  return ep.Estart;
}

/**
 * §6.4 for one control row of epoch `ep` at `(row.E, row.n)` with stored time `row.t`. The local rules (a)–(e), the
 * `bundleSize` clause of (g) and `B ≥ |D_e|` of (h) come first, with no request; then (f)'s `meta` when E_start is
 * unknown, (g)'s `meta`, and (h)'s blob only after (g) holds. Network errors, timeouts, 429, 5xx, a blob 404 after a
 * HIT, or a MISS whose `now` is below `t_row` leave the row undecided.
 */
export async function evaluate(api: Api, ep: Epoch, row: StoredRow): Promise<Verdict> {
  const m = ep.D.members.length;
  const v = P.acceptRow(
    { keys: ep.keys, conv: ep.D.conv, e: ep.e, members: ep.D.members },
    row.E,
    row.label,
    row.body,
  );
  if (!v.ok) return invalid(v.why === "decrypt" ? UNDECRYPTABLE : INVALID_CHANGE);
  const msg = v.msg;
  if (msg.type !== P.MT.CLAIM || msg.lane !== P.CTL_LANE || msg.n !== row.n) return invalid();
  const claim = msg.claim;
  if (!P.equalBytes(claim.prevD, ep.D.hash)) return invalid(); // (d)
  if (P.claimShapeValid(claim, m, msg.from, 0, row.E) !== null) return invalid(); // local rules, cuts' upper bound
  try {
    const Es = await eStartOf(api, ep);
    if (Es === null) return undecided();
    if (P.claimShapeValid(claim, m, msg.from, Es, row.E) !== null) return invalid(); // (f)
    const meta = await api.blobMetaOrNow(claim.bundleId); // (g)
    if (!("t" in meta)) return meta.now >= row.t ? invalid() : undecided((row.t - meta.now) * 1000);
    if (meta.size !== claim.bundleSize || !(meta.t < row.t)) return invalid();
    const got = await api.getBlob(claim.bundleId, claim.bundleSize); // (h)
    if (!got) return undecided();
    if (!got.sizeOk || P.bundleShapeValid(got.bytes, claim.bundleSize, claim.bundleId, m) !== null)
      return invalid();
    return { kind: "valid", claim, from: msg.from, ts: msg.ts, tReg: meta.t, blob: got.bytes };
  } catch (e) {
    if (e instanceof ApiError && !e.transient && e.status !== 404) return invalid();
    return undecided();
  }
}

/** The back-off of an undecided row (§6.4 Outcomes: 1 s doubling to 60 s, no sooner than a hint). */
const backoff = (attempt: number, hint: number): number =>
  Math.max(hint, Math.min(60_000, 1000 * 2 ** attempt));

export interface ControlHost {
  api: Api;
  mono(): number;
  warn(text: string): void;
  /** processes the final winner of the copy's current epoch (§6.6) */
  onFinal(c: Copy, ep: Epoch, w: Winner): Promise<void>;
}

/**
 * Drives the copy's current control lane as far as its fetched rows allow (the caller walks the lane first): decides
 * rows in order, makes the first e-valid one the winner, checks its finality (§6.5: every earlier era of the epoch
 * observed sealed at its prefix end, probed here when it was not), and processes it once final. Undecided rows and
 * unfinal winners set `pendingSince` (the 30 s wait of §11.3 step 2). Returns true when the copy switched epochs.
 */
export async function settleControl(h: ControlHost, c: Copy): Promise<boolean> {
  for (let guard = 0; guard < 64; guard++) {
    if (c.removed) return false;
    const ep = c.epochs.get(c.current);
    if (!ep) return false;
    const ctl = ep.ctl;
    if (ctl.winner?.processed) {
      ctl.pendingSince = null;
      return false;
    }
    if (!ctl.winner) {
      const row = ctl.queue[0];
      if (!row) {
        ctl.pendingSince = null;
        return false;
      }
      if (h.mono() < ctl.retryAt) {
        ctl.pendingSince ??= h.mono();
        return false;
      }
      const v = await evaluate(h.api, ep, row);
      if (v.kind === "undecided") {
        ctl.pendingSince ??= h.mono();
        ctl.retryAt = h.mono() + backoff(ctl.attempt++, v.retryMs);
        return false;
      }
      ctl.attempt = 0;
      ctl.retryAt = 0;
      ctl.queue.shift();
      if (v.kind === "invalid") {
        h.warn(v.warning);
        ctl.next = { E: row.E, n: row.n + 1 };
        continue;
      }
      ctl.winner = {
        ...row,
        claim: v.claim,
        from: v.from,
        ts: v.ts,
        tReg: v.tReg,
        blob: v.blob,
        final: false,
        processed: false,
      };
      ctl.queue.length = 0;
      ctl.next = { E: row.E, n: row.n };
      ctl.pendingSince ??= h.mono();
    }
    const w = ctl.winner;
    if (!w.final) {
      const Es = ep.Estart ?? w.E;
      const missing: number[] = [];
      for (let E = Es; E < w.E; E++) if (!ctl.sealed.has(E)) missing.push(E);
      if (missing.length) {
        if (h.mono() < ctl.retryAt) return false;
        const keys = missing.map((E) => {
          const n = ctl.counts.get(E) ?? 0;
          return { E, n, label: P.Lctl(ep.keys.rk, E, n) };
        });
        let st: Awaited<ReturnType<Api["get"]>>;
        try {
          st = await h.api.get(keys.map((k) => ({ E: k.E, label: k.label, mode: 0 as const })));
        } catch {
          return false; // still pending; probed again at the next catch-up
        }
        let reopened = false;
        keys.forEach((k, i) => {
          const s = st[i];
          if (s.s === "miss" && s.sealed) ctl.sealed.add(k.E);
          else if (s.s === "hit" && s.body && !reopened) {
            ctl.counts.set(k.E, k.n + 1);
            // A row before the winner (a later write within SKEW of the era's end): it is decided first.
            reopened = true;
            ctl.winner = null;
            ctl.next = { E: k.E, n: k.n };
            ctl.queue = [
              { E: k.E, n: k.n, label: k.label, t: s.t, body: s.body },
              { E: w.E, n: w.n, label: w.label, t: w.t, body: w.body },
            ];
          }
        });
        if (reopened) continue;
        if (missing.some((E) => !ctl.sealed.has(E))) {
          ctl.retryAt = h.mono() + backoff(ctl.attempt++, 0);
          return false;
        }
      }
      w.final = true;
      ctl.attempt = 0;
      ctl.retryAt = 0;
    }
    await h.onFinal(c, ep, w);
    w.processed = true;
    ctl.pendingSince = null;
    return c.current !== ep.e;
  }
  return false;
}

/** The control lane is settled: nothing undecided, and no winner that is not final or processed (§11.3 step 2). */
export const controlSettled = (ep: Epoch): boolean =>
  ep.ctl.queue.length === 0 && (!ep.ctl.winner || ep.ctl.winner.processed);
