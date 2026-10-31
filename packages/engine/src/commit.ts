// Committing epoch e+1 (docs/PROTOCOL.md §6.3): an add, a removal, a rotation after a leave, or a rename. The
// blob first (continuing members' kemPk from the previous bundle, never from the directory), EPOCH_PENDING, the wait
// for the commit time, the re-check and cuts, the CAS loop with every outcome, the decide step, the switch, and the
// first delivery of J to the added members.
import * as P from "@segv/protocol/proto";
import * as W from "@segv/protocol/wire";
import { ApiError, type Api, type DirUser, type Params } from "./api";
import { controlSettled } from "./claims";
import { CHANGING, NOT_MEMBER, cleanName, type Copy, type Epoch, type Slot } from "./conv";
import { UserError } from "./errors";
import type { EngineClock } from "./options";

type Bytes = Uint8Array;

export const CANNOT_CHANGE =
  "the members of this conversation can no longer change; start a new conversation";
const CAS_ATTEMPTS = 8;

/** What a commit changes, decided against the epoch it builds on. */
export interface Change {
  /** indices in D_e of the members kept (self among them) */
  keep: number[];
  /** members added, with their verified directory bundles */
  add: DirUser[];
  /** a new name (null removes it); undefined carries the name over byte for byte */
  name?: string | null;
}

/** Decides the change against epoch `ep`, or null when nothing is left to do (a conflict did it already). */
export type Plan = (c: Copy, ep: Epoch, round: number) => Change | null;

export interface CommitHost {
  api: Api;
  clock: EngineClock;
  params(): Params;
  self: { uid: Bytes; id: P.Identity };
  check(): void;
  /** waits on a protocol timer */
  wait(ms: number): Promise<void>;
  progress(text: string): void;
  /** catches up the control lane and every lane of the copy's current epoch, and settles the control lane */
  sync(c: Copy): Promise<void>;
  /** decides the control lane's rows again (no probe) */
  settle(c: Copy): Promise<void>;
  /** writes the EPOCH_PENDING record in a class-1 self row (§6.3 step 4) */
  writePending(rec: P.EpochPendingRec): Promise<void>;
  /** pks_e of the epoch: held, or from its bundle (fetched once) */
  pksOf(c: Copy, ep: Epoch): Promise<Bytes>;
  /** §6.3 step 10: the first delivery attempt of J (the rest in the background) */
  deliver(c: Copy, J: P.Join, to: DirUser[]): Promise<void>;
  /** the `ck` fields of the claim: the latest verified checkpoint (§6.2, §12.4) */
  ck(): { ckq: number; ck16: Bytes };
}

/** The refusals before a commit: removed, left, frozen, or the last epoch (§6.3, §6.6 step 6, §6.10). */
function refuse(c: Copy, ep: Epoch): void {
  if (c.removed) throw new UserError(NOT_MEMBER);
  if (c.left) throw new UserError("you left this conversation");
  if (c.frozen !== null || ep.e + 1 >= P.E_MAX || ep.myIndex < 0)
    throw new UserError(CANNOT_CHANGE);
}

/**
 * Waits until the control lane of the copy's current epoch is settled (commits wait for it, §6.6); re-probes it while
 * it is not. Gives up with CHANGING after `limitMs` of monotonic time.
 */
async function settled(h: CommitHost, c: Copy, limitMs: number): Promise<void> {
  const start = h.clock.mono();
  await h.sync(c);
  for (;;) {
    h.check();
    const ep = c.epochs.get(c.current)!;
    if (controlSettled(ep)) return;
    if (h.clock.mono() - start > limitMs) throw new UserError(CHANGING);
    const due = ep.ctl.retryAt - h.clock.mono();
    await h.wait(due > 0 ? due : 1000);
    h.check();
    await h.sync(c);
  }
}

/** §6.3 step 5: at least Δ + SKEW of monotonic time since the PUT answer, and server time ≥ t_reg + Δ + SKEW. */
export async function waitCommitTime(
  h: {
    clock: EngineClock;
    api: Api;
    params(): Params;
    wait(ms: number): Promise<void>;
    check(): void;
  },
  since: number,
  tReg: number,
): Promise<void> {
  for (;;) {
    const p = h.params();
    const left = Math.max(
      since + (p.delta + p.skew) * 1000 - h.clock.mono(),
      P.T0_MS + (tReg + p.delta + p.skew) * 1000 - h.api.serverNow(),
    );
    if (left <= 0) return;
    await h.wait(left);
    h.check();
  }
}

/** Everything step 2 builds: D′, dsig′, rm, the blob and the claim fields that do not depend on the cuts. */
interface Built {
  EK: Bytes;
  D: P.Descriptor;
  blob: Bytes;
  bundleId: Bytes;
  bundleSize: number;
  rm: number;
  ekc: Bytes;
  added: DirUser[];
}

function build(h: CommitHost, c: Copy, ep: Epoch, change: Change, pks: Bytes): Built {
  const me = h.self;
  const kept = change.keep.map((i) => ep.D.members[i]);
  if (!kept.some((m) => P.equalBytes(m.uid, me.uid))) throw new Error("commit: self must stay");
  const members: P.Member[] = [
    ...kept.map((m) => ({ uid: m.uid, sigPk: m.sigPk, kh: m.kh })),
    ...change.add.map((u) => ({ uid: u.uidBytes, sigPk: u.sigPk, kh: P.kemHash(u.kemPk) })),
  ];
  if (members.length > P.MAX_MEMBERS) throw new UserError(`at most ${P.MAX_MEMBERS} members`);
  const kemPks = [...change.keep.map((i) => P.pksAt(pks, i)), ...change.add.map((u) => u.kemPk)];
  const name =
    change.name === undefined
      ? ep.D.name
      : change.name === null
        ? null
        : (cleanName(change.name) ?? null);
  const EK = P.random(32);
  const e1 = ep.e + 1;
  const keys = P.epochKeys(EK, c.conv, e1);
  const Dbytes = P.encodeD({
    conv: c.conv,
    e: e1,
    prev: ep.D.hash,
    by: me.uid,
    ts: Math.max(0, Math.floor(h.clock.wall())),
    members,
    name,
  });
  const D = P.parseD(Dbytes);
  const dsig = P.signD(Dbytes, keys.kc, me.id.sigSk);
  const rm = P.rmBits(ep.D, D);
  const b = P.buildBundle({
    conv: c.conv,
    e: e1,
    D: Dbytes,
    dsig,
    EK,
    pks: kemPks,
    prevMembers: ep.D.members.map((m) => m.uid),
    rm,
  });
  return {
    EK,
    D,
    blob: b.blob,
    bundleId: b.id,
    bundleSize: b.size,
    rm,
    ekc: P.ekc(c.conv, e1, EK),
    added: change.add,
  };
}

/** The cuts of §6.2 from the observed lane heads: (era of the head, its dense-prefix length), or (E_start, 0). */
export function cutsOf(ep: Epoch): P.Cut[] {
  const Es = ep.Estart ?? 0;
  return ep.lanes.map((l) => (l.head ? { E: l.head.E, cnt: l.head.cnt } : { E: Es, cnt: 0 }));
}

/**
 * Commits one change on top of the copy's current epoch (§6.3). Returns true once the copy switched to the epoch
 * this device committed and the first delivery attempt ran; false when the plan found nothing to do. A claim of
 * another member that wins first is followed, and the plan is tried again on top of it.
 */
export async function commit(h: CommitHost, c: Copy, plan: Plan): Promise<boolean> {
  for (let round = 0; round < 6; round++) {
    h.progress("checking the conversation…");
    await settled(h, c, 60_000);
    const ep = c.epochs.get(c.current)!;
    refuse(c, ep);
    const change = plan(c, ep, round);
    if (!change) return false;
    const pks = ep.pks ?? (await h.pksOf(c, ep));
    h.check();
    const b = build(h, c, ep, change, pks);
    h.progress("uploading conversation keys…");
    const { t: tReg } = await h.api.putBlob(b.bundleId, b.blob, (m) => h.progress(m));
    const putAt = h.clock.mono();
    h.check();
    await h.writePending({
      rtype: P.RT.EPOCH_PENDING,
      conv: c.conv,
      root: c.root,
      e: ep.e + 1,
      EK: b.EK,
      bundleId: b.bundleId,
      bundleSize: b.bundleSize,
      tReg,
      uids: b.added.map((u) => u.uidBytes),
    });
    h.check();
    h.progress("changing members…");
    const won = await claimAndDecide(h, c, ep, b, tReg, putAt);
    if (won) {
      const J: P.Join = {
        conv: c.conv,
        e: ep.e + 1,
        EK: b.EK,
        bundleId: b.bundleId,
        bundleSize: b.bundleSize,
      };
      await h.deliver(c, J, b.added);
      return true;
    }
    // Another claim won (and was processed by the sync): build again on top of it.
  }
  throw new UserError(CHANGING);
}

/**
 * Steps 5–9: wait for the commit time, re-check and compute the cuts, CAS the claim at the first empty control slot
 * of the era, then decide. True when this device's claim is the final winner and the copy switched to e+1.
 */
async function claimAndDecide(
  h: CommitHost,
  c: Copy,
  ep: Epoch,
  b: Built,
  tReg: number,
  putAt: number,
): Promise<boolean> {
  await waitCommitTime(h, putAt, tReg);
  const tried = new Set<number>();
  let override: number | null = null;
  let mine: Slot | null = null;
  for (let attempt = 0; attempt < CAS_ATTEMPTS && !mine;) {
    h.check();
    // Step 6: catch up the control lane and every lane head of e; a winner (another's) ends this commit.
    await settled(h, c, 60_000);
    if (c.current !== ep.e || c.removed || c.frozen !== null) return false;
    const p = h.params();
    const ctl = ep.ctl;
    const E = Math.max(override ?? P.era(h.api.serverNow()), ctl.next.E);
    const k = ctl.next.E === E ? ctl.next.n : 0;
    override = null;
    const msg = {
      type: P.MT.CLAIM,
      from: ep.myIndex,
      lane: P.CTL_LANE,
      n: k,
      prev: P.NONE,
      prevh: P.ZERO16,
      ts: Math.max(0, Math.floor(h.clock.wall())),
      ...h.ck(),
      claim: {
        prevD: ep.D.hash,
        hD: b.D.hash,
        ekc: b.ekc,
        bundleId: b.bundleId,
        bundleSize: b.bundleSize,
        rm: b.rm,
        cuts: cutsOf(ep),
      },
    } as P.Msg;
    const row = P.buildRow(
      { keys: ep.keys, conv: c.conv, e: ep.e, sigSk: h.self.id.sigSk },
      E,
      msg,
    );
    const req = W.encodePutRequest([
      { E, label: row.label, cls: row.cls, topic: ep.topic, body: row.body },
    ]);
    const pow = await h.api.putPow(req, (m) => h.progress(m));
    h.check();
    let res: W.PutResult;
    try {
      [res] = await h.api.sendPut(req, pow, 1, (m) => h.progress(m));
    } catch (e) {
      if (e instanceof ApiError && !e.transient) throw new UserError(e.message);
      res = await probe(h, E, row.label);
    }
    h.check();
    attempt++;
    if (res.s === "ok" || (res.s === "conflict" && P.equalBytes(res.body, row.body))) {
      if (res.t <= tReg) {
        // Not e-valid by (g): the slot is occupied and ignored; wait for the commit time again from now (step 7).
        await waitCommitTime(h, h.clock.mono(), Math.max(tReg, res.t));
        continue;
      }
      mine = { E, n: k };
      ctl.queue.push({ E, n: k, label: row.label, t: res.t, body: row.body });
      ctl.queue.sort((x, y) => P.posCmp(x, y));
      break;
    }
    if (res.s === "conflict") continue; // the occupant is decided at the next catch-up (step 7)
    if (res.s === "wrong_era") {
      if (tried.has(res.era)) {
        const left = P.eraEnd(Math.min(E, res.era)) + p.skew * 1000 - h.api.serverNow();
        if (left > 0) await h.wait(left);
      }
      tried.add(E);
      override = res.era;
      continue;
    }
    // full: retry the CAS at the same slot after the next catch-up
  }
  if (!mine) throw new UserError(CHANGING);
  // Step 8: decide every earlier slot and wait for finality; step 9 (the switch) runs when the sync processes it.
  const start = h.clock.mono();
  for (;;) {
    h.check();
    await h.settle(c);
    const w = ep.ctl.winner;
    if (w?.processed) return w.E === mine.E && w.n === mine.n && c.current === ep.e + 1;
    if (h.clock.mono() - start > 120_000) throw new UserError(CHANGING);
    const due = ep.ctl.retryAt - h.clock.mono();
    await h.wait(due > 0 ? due : 1000);
    h.check();
    await h.sync(c);
    const w2 = ep.ctl.winner;
    if (w2?.processed) return w2.E === mine.E && w2.n === mine.n && c.current === ep.e + 1;
  }
}

/** A lost put answer: probe the slot (ours: OK; another body: CONFLICT; a MISS: retry the CAS there). */
async function probe(h: CommitHost, E: number, label: Bytes): Promise<W.PutResult> {
  for (let k = 0; k < 3; k++) {
    try {
      const [s] = await h.api.get([{ E, label, mode: 0 }]);
      if (s.s === "hit" && s.body) return { s: "conflict", t: s.t, cls: s.cls, body: s.body };
      if (s.s === "miss") return { s: "full" };
    } catch {
      /* again */
    }
    await h.wait(500 * 2 ** k);
  }
  return { s: "full" };
}
