// Sending a row on one's own lane (docs/PROTOCOL-v2.md §11.3): the control probe before every send, the processing
// wait, the refusals (removed, left, frozen with a removal, a WELCOME that no longer qualifies), the rotation after a
// leave, the slot (never below the lane head's era), the fresh-probe check after the proof of work, and the handling
// of OK, CONFLICT, WRONG_ERA and lost answers, with the late-row rule. TEXT, IMAGE, LEAVE and WELCOME use this path.
import * as P from "~/lib/proto";
import * as W from "~/lib/wire";
import { ApiError, type Api, type Params } from "./api";
import { controlSettled } from "./claims";
import {
  CHANGING,
  NOT_DELIVERED,
  NOT_MEMBER,
  SEND_ATTEMPTS,
  frozenWithRemoval,
  leftIn,
  rowKey,
  type Copy,
  type Epoch,
} from "./conv";
import { UserError } from "./errors";
import type { EngineClock } from "./options";
import type { FoundRow } from "./sync";

type Bytes = Uint8Array;

/** Probe the slots after junk with exists mode, this far (§11.3 step 6, CONFLICT with junk). */
const JUNK_PROBE = 64;
/** Re-probes of a slot whose put answer was lost (§11.3 step 6, FULL / network / 5xx). */
const SLOT_PROBES = 3;

export interface SendCtx {
  api: Api;
  clock: EngineClock;
  params(): Params;
  selfUid: Bytes;
  sigSk: Bytes;
  processingWait: number;
  /** throws once the session ended */
  check(): void;
  /** step 1: probe and process the control lane of the copy's current epoch (throws when the get fails) */
  probeControl(c: Copy): Promise<void>;
  /** step 2's wait: decides the control lane's rows again (no new probe of the lane) */
  settle(c: Copy): Promise<void>;
  /** step 3: commits a rotation that drops the members who left (§6.9) */
  rotate?: (c: Copy) => Promise<void>;
  /** a LEAVE repeated by §6.9: step 2's "you left" refusal does not apply */
  repeatLeave?: boolean;
  /** waits on a protocol timer */
  wait(ms: number): Promise<void>;
  /** applies a row of this device's own lane (or a sibling's) found by the send */
  applyOwn(c: Copy, ep: Epoch, row: FoundRow): void;
  /** the local echo for a row about to be put (so the row replaces it when it arrives first) */
  expectEcho(key: string): void;
  beforePutAttempt?: () => void | Promise<void>;
  progress(text: string): void;
  /**
   * A WELCOME to this uid: step 2 checks the §6.12 step 1 conditions for the epoch the row would be built in
   * (`qualifies`), and a failure is `WelcomeRefused` (the recipient gets an inbox invite instead), never the
   * "removed" or "you left" refusal.
   */
  welcomeTo?: Bytes;
  qualifies?: (c: Copy, ep: Epoch, uid: Bytes) => boolean;
}

/** §11.3 step 2 refused a WELCOME: the epoch no longer qualifies (§6.12 step 1); send an inbox invite instead. */
export class WelcomeRefused extends Error {
  constructor() {
    super("the conversation no longer qualifies for a WELCOME");
    this.name = "WelcomeRefused";
  }
}

/** Times of the latest step-1 probe on the three clocks (§11.3 steps 6 and 8). */
interface Stamp {
  mono: number;
  wall: number;
  server: number;
}

const stamp = (ctx: SendCtx): Stamp => ({
  mono: ctx.clock.mono(),
  wall: ctx.clock.wall(),
  server: ctx.api.serverNow(),
});

/** The largest elapsed time since `s` by any of the three clocks; a wall clock that stepped back counts as none. */
function elapsed(ctx: SendCtx, s: Stamp): number {
  const now = stamp(ctx);
  return Math.max(now.mono - s.mono, Math.max(0, now.wall - s.wall), now.server - s.server);
}

export const YOU_LEFT_REFUSAL = "you left this conversation";
export const FROZEN_REMOVAL =
  "a removed member could still read this conversation; start a new conversation";

/** The epoch lists a member other than self who has left, and a rotation may drop it (§6.9, §11.3 step 3). */
export function needsRotation(c: Copy, ep: Epoch): boolean {
  if (c.frozen !== null || ep.e >= P.E_MAX - 1) return false;
  return ep.D.members.some((m, j) => j !== ep.myIndex && leftIn(c, ep, P.b64u(m.uid)));
}

/**
 * Step 1 and step 2's wait: probe the control lane (again for each epoch a claim moves the copy to), then wait, at
 * most the processing wait, while it has an undecided slot or a winner not yet final or processed.
 */
async function probeAndWait(
  ctx: SendCtx,
  c: Copy,
): Promise<{ ep: Epoch; sent: Stamp; answered: Stamp; timedOut: boolean }> {
  for (;;) {
    ctx.check();
    const e = c.current;
    const sent = stamp(ctx);
    try {
      await ctx.probeControl(c);
    } catch {
      throw new UserError(NOT_DELIVERED);
    }
    const answered = stamp(ctx);
    ctx.check();
    if (c.current !== e) continue; // a claim switched the copy: probe its new epoch (§11.3 step 1)
    const ep = c.epochs.get(e)!;
    let timedOut = false;
    if (!controlSettled(ep)) {
      const deadline = (ep.ctl.pendingSince ?? ctx.clock.mono()) + ctx.processingWait;
      while (!controlSettled(ep) && c.current === e) {
        const left = deadline - ctx.clock.mono();
        if (left <= 0) {
          timedOut = true;
          break;
        }
        const due = ep.ctl.retryAt - ctx.clock.mono();
        await ctx.wait(Math.min(left, due > 0 ? due : 1000));
        ctx.check();
        await ctx.settle(c);
        ctx.check();
      }
      if (c.current !== e) continue;
    }
    return { ep, sent, answered, timedOut };
  }
}

/**
 * Steps 1–3: probe, wait, apply the refusals of step 2 and the rotation of step 3. Returns the send's epoch and when
 * the latest probe was sent and answered.
 */
async function steps12(
  ctx: SendCtx,
  c: Copy,
  type: number,
): Promise<{ ep: Epoch; sent: Stamp; answered: Stamp }> {
  for (let rotations = 0; ;) {
    const { ep, sent, answered, timedOut } = await probeAndWait(ctx, c);
    const visible = type === P.MT.TEXT || type === P.MT.IMAGE;
    if (ctx.welcomeTo) {
      if (timedOut) throw new UserError(CHANGING);
      if (!ctx.qualifies?.(c, ep, ctx.welcomeTo)) throw new WelcomeRefused();
      return { ep, sent, answered };
    }
    if (c.removed) throw new UserError(NOT_MEMBER);
    if (c.left && !ctx.repeatLeave) throw new UserError(YOU_LEFT_REFUSAL);
    if (timedOut) throw new UserError(CHANGING);
    if (visible && frozenWithRemoval(c, ep)) throw new UserError(FROZEN_REMOVAL);
    if (visible && ctx.rotate && needsRotation(c, ep) && rotations < 4) {
      rotations++;
      await ctx.rotate(c); // then step 1 again: step 2 decides whether e still takes the send
      continue;
    }
    return { ep, sent, answered };
  }
}

/** A row sent on self's lane: its slot, label, sealed body and order data. */
export interface SentRow extends FoundRow {
  e: number;
}

/**
 * Sends one TEXT or IMAGE row (§11.3). Resolves with the stored row once it counts as delivered; throws a UserError
 * with the "not delivered" text (or a step-2 refusal) otherwise.
 */
export async function sendRow(ctx: SendCtx, c: Copy, content: P.MBody): Promise<SentRow> {
  await c.ready; // a creation's own sends wait for its decoy (§6.1)
  let { ep, sent, answered } = await steps12(ctx, c, content.type);
  const triedEras = new Set<number>();
  let EnowOverride: number | null = null;
  for (let attempt = 0; attempt < SEND_ATTEMPTS;) {
    // Step 4: the slot, never below the lane head's era.
    const lane = ep.lanes[ep.myIndex];
    const Enow = EnowOverride ?? P.era(ctx.api.serverNow());
    const Estar = Math.max(Enow, lane.next.E, lane.tail?.E ?? 0);
    const n = lane.next.E === Estar ? lane.next.n : 0;
    const last = lane.last;
    // Step 5: build, sign, seal.
    const msg = {
      from: ep.myIndex,
      lane: ep.myIndex,
      n,
      prev: last ? { E: last.E, n: last.n } : P.NONE,
      prevh: last ? P.prevh(last.label, last.body) : P.ZERO16,
      ts: Math.max(0, Math.floor(ctx.clock.wall())),
      ckq: 0,
      ck16: P.ZERO16,
      ...content,
    } as P.Msg;
    let row: ReturnType<typeof P.buildRow>;
    try {
      row = P.buildRow({ keys: ep.keys, conv: c.conv, e: ep.e, sigSk: ctx.sigSk }, Estar, msg);
    } catch {
      throw new UserError("message is too long");
    }
    ctx.expectEcho(rowKey(Estar, row.label));
    const req = W.encodePutRequest([
      { E: Estar, label: row.label, cls: row.cls, topic: ep.topic, body: row.body },
    ]);
    const pow = await ctx.api.putPow(req, (m) => ctx.progress(m));
    await ctx.beforePutAttempt?.();
    // Step 6, fresh probe: after the proof of work, before the put.
    const params = ctx.params();
    if (elapsed(ctx, answered) > ((params.delta + params.skew) / 2) * 1000 || c.current !== ep.e) {
      const again = await steps12(ctx, c, content.type);
      sent = again.sent;
      answered = again.answered;
      if (again.ep.e !== ep.e) {
        ep = again.ep;
        continue; // build the row for the new epoch (a new signature and proof of work)
      }
    }
    ctx.check();
    let res: W.PutResult;
    try {
      [res] = await ctx.api.sendPut(req, pow, 1, (m) => ctx.progress(m));
    } catch (e) {
      if (e instanceof ApiError && !e.transient) throw new UserError(e.message);
      // A lost answer: probe the slot (step 6, FULL / network / 5xx).
      res = await probeSlot(ctx, Estar, row.label);
      if (res.s === "full") throw new UserError(NOT_DELIVERED);
    }
    ctx.check();
    const found: FoundRow = { E: Estar, n, label: row.label, t: 0, body: row.body };
    if (res.s === "ok" || (res.s === "conflict" && P.equalBytes(res.body, row.body))) {
      found.t = res.t;
      ctx.applyOwn(c, ep, found);
      // Step 8: a late row counts as delivered only while the copy is still in its epoch, or in e+1 with no own row
      // there (the others still follow self's lane of e).
      if (elapsed(ctx, sent) >= (params.delta + params.skew) * 1000) {
        const r = await probeAndWait(ctx, c).catch(() => null);
        const next = c.epochs.get(ep.e + 1);
        const stillFollowed =
          c.current === ep.e ||
          (c.current === ep.e + 1 &&
            next !== undefined &&
            !next.viaSkip &&
            next.myIndex >= 0 &&
            !next.lanes[next.myIndex].seen);
        if (!r || r.timedOut || !stillFollowed) throw new UserError(NOT_DELIVERED);
      }
      return { ...found, e: ep.e };
    }
    if (res.s === "conflict") {
      const v = P.acceptRow(
        { keys: ep.keys, conv: c.conv, e: ep.e, members: ep.D.members },
        Estar,
        row.label,
        res.body,
      );
      if (v.ok && v.msg.from === ep.myIndex) {
        ctx.applyOwn(c, ep, { E: Estar, n, label: row.label, t: res.t, body: res.body }); // a sibling's row
        attempt++;
        continue;
      }
      // Junk in our slot: skip to the first free slot (does not count against SEND_ATTEMPTS).
      lane.next = { E: Estar, n: await firstFree(ctx, ep, Estar, n + 1) };
      continue;
    }
    if (res.s === "wrong_era") {
      attempt++;
      if (triedEras.has(res.era)) {
        const until = P.eraEnd(Math.min(Estar, res.era)) + params.skew * 1000;
        const left = until - ctx.api.serverNow();
        if (left > 0) await ctx.wait(left);
      }
      triedEras.add(Estar);
      EnowOverride = res.era;
      continue;
    }
    throw new UserError(NOT_DELIVERED);
  }
  throw new UserError("could not send: too many conflicts, try again");
}

/** Probes a slot whose put answer was lost, up to 3 times with back-off; a stored body is CONFLICT-like. */
async function probeSlot(ctx: SendCtx, E: number, label: Bytes): Promise<W.PutResult> {
  for (let k = 0; k < SLOT_PROBES; k++) {
    try {
      const [s] = await ctx.api.get([{ E, label, mode: 0 }]);
      if (s.s === "hit" && s.body) return { s: "conflict", t: s.t, cls: s.cls, body: s.body };
      if (s.s === "miss") return { s: "full" };
    } catch {
      /* try again */
    }
    await ctx.wait(500 * 2 ** k);
  }
  return { s: "full" };
}

/** The first free slot at or after `n` in era E of self's lane (exists-mode probes of 64 slots). */
async function firstFree(ctx: SendCtx, ep: Epoch, E: number, n: number): Promise<number> {
  for (let base = n; ; base += JUNK_PROBE) {
    const keys = Array.from({ length: JUNK_PROBE }, (_, i) => ({
      E,
      label: P.Lmsg(ep.keys.rk, ep.myIndex, E, base + i),
      mode: 1 as const,
    }));
    const st = await ctx.api.get(keys);
    const k = st.findIndex((s) => s.s !== "hit");
    if (k >= 0) return base + k;
  }
}
