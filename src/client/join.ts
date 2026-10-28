// Accepting a join (docs/PROTOCOL.md §6.7) from an inbox invite, a WELCOME or a link hello: the bundle checks in their
// order (size, meta, then the blob), duplicates, settling the held copies (a pending claim parks the join), the one fit
// ("Claimed" is ignored), and otherwise a first contact (a re-add after a removal included) or a separate copy. A copy
// that has ended fits no J and counts only for a J that contradicts its history; a J below the root of every live copy
// has its own copy settled first, and is kept as an ended copy when that copy ends early enough.
import * as P from "~/lib/proto";
import { ApiError, type Api } from "./api";
import { copyKeyOf, newEpoch, rootEpoch, type Copy, type Epoch, type KnownUser } from "./conv";
import { CONFIRMED_COPY_WARNING } from "./selflane";

type Bytes = Uint8Array;

export const MALFORMED_KEY = "ignored a malformed conversation key";
export const INVALID_SIG_KEY = "ignored a conversation key with an invalid signature";
export const secondCopyWarning = (handle: string): string =>
  `@${handle} sent you a second, different copy of a conversation you were added to; both are shown marked ⚠ — only one can be genuine`;

/** Where a join came from: its `via` (§7.2) and, for an inbox invite, its position. */
export type JoinSource =
  | { via: typeof P.VIA.INBOX; E: number; rel: number }
  | { via: typeof P.VIA.WELCOME }
  | { via: typeof P.VIA.HELLO };

/** A join that passed §6.7 and became a new copy, before it is written to the self lane. */
export interface NewCopy {
  conv: Bytes;
  root: Bytes;
  rootBy: Bytes;
  request: boolean;
  /** the critical "second copy" warning applies */
  second: boolean;
  epoch: Epoch;
  /** what to write (in this order): CONV_JOIN and its TREG, or REQUEST + MEMBER of D.by */
  records: P.SelfRecord[];
  /** the MEMBER of D.by when it is new and rides in the next HEADS row (an accepted copy) */
  member: P.MemberRec | null;
  dby: KnownUser;
  /** an overtaken J's own copy, settled to its end before step 6 and kept as an ended copy (§6.7 step 6) */
  ended: Copy | null;
  /** the join itself (a CONFLICT with a sibling's rows runs steps 3–6 again for it, §7.3) */
  J: P.Join;
}

export type JoinOutcome =
  | { kind: "new"; copy: NewCopy }
  | { kind: "duplicate" }
  | { kind: "dropped" }
  | { kind: "parked"; why: string };

/** How the copy that an overtaken J would start came out of its settle (§6.7 step 6). */
export type SettleOwn =
  /** a final winning claim of an epoch below r − 1 removed self: kept as an ended copy, without a warning */
  | { kind: "ended"; copy: Copy }
  /** it reached r − 1, or stopped below it without ending (frozen, or no winning claim) */
  | { kind: "reached" }
  /** a held copy holds an epoch it reached with another H(D) */
  | { kind: "fork"; of: Copy }
  | { kind: "parked"; why: string };

export interface JoinCtx {
  api: Api;
  self: { uid: Bytes; sigPk: Bytes; kh: Bytes };
  /** the held copies of a conversation (by b64u conv), with those created earlier in this poll (no key yet) */
  copiesOf(convB: string): readonly Copy[];
  /** the MEMBER record of a uid, or null */
  member(uidB: string): P.MemberRec | null;
  /** the CONTACT record of a uid, or null */
  contact(uidB: string): P.ContactRec | null;
  warn(text: string, critical?: boolean): void;
  /**
   * §6.7 step 4: catches up the control lane of a held copy's current epoch; true once its winner is final and
   * processed, or every slot is decided not e-valid, or the copy has ended (throws on a transient failure).
   */
  settle(c: Copy): Promise<boolean>;
  /**
   * §6.7 step 6, an overtaken J: settles the copy the J would start, from its control lane of e under the J's EK and on
   * through the epochs its own entries reach, stopping at `stopAt` (r − 1); `forkOf` names a held copy that holds a
   * reached epoch with another H(D). Throws on a transient failure.
   */
  settleOwn(x: {
    J: P.Join;
    D: P.Descriptor;
    dsig: Bytes;
    pks: Bytes;
    tReg: number;
    stopAt: number;
    forkOf(e: number, hD: Bytes): Copy | null;
  }): Promise<SettleOwn>;
}

const park = (why: string): JoinOutcome => ({ kind: "parked", why });

/**
 * The `D.by` key check (§6.7 step 6): D's sigPk for D.by must equal the sigPk of D.by's verified directory bundle
 * (its MEMBER record, or a lookup by uid prefix) and agree with any CONTACT pin. Returns the user and, when it was
 * looked up, the MEMBER to write; null when the check fails; throws on a transient lookup failure.
 */
async function dbyCheck(
  ctx: JoinCtx,
  D: P.Descriptor,
): Promise<{ user: KnownUser; member: P.MemberRec | null } | null> {
  const listed = D.members[P.memberIndex(D, D.by)];
  const uidB = P.b64u(D.by);
  const m = ctx.member(uidB);
  if (m) {
    if (!P.equalBytes(m.sigPk, listed.sigPk)) return null;
    return { user: { handle: m.handle, sigPk: m.sigPk, kh: m.kh, kemPk: null }, member: null };
  }
  const u = await ctx.api.userByUidPrefix(D.by);
  if (!u || !P.equalBytes(u.sigPk, listed.sigPk)) return null;
  const c = ctx.contact(uidB);
  if (c && !P.equalBytes(c.pin, u.pin)) return null;
  const member: P.MemberRec = {
    rtype: P.RT.MEMBER,
    uid: D.by,
    sigPk: u.sigPk,
    kh: P.kemHash(u.kemPk),
    pin: u.pin,
    handle: u.handle,
  };
  return { user: { handle: u.handle, sigPk: u.sigPk, kh: member.kh, kemPk: u.kemPk }, member };
}

/**
 * A J for epoch e contradicts the history of an ended copy (§6.7 step 6 "Forks of an ended copy"): the copy holds e
 * with another H(D) (the same one is a duplicate, step 3), or e is the epoch after its last, whose final claim removed
 * self.
 */
function contradicts(c: Copy, e: number, hD: Bytes): boolean {
  const x = c.epochs.get(e);
  return x ? !P.equalBytes(x.D.hash, hD) : e === c.current + 1;
}

/**
 * §6.7 for one J. Transient failures (a network error, a timeout, a 429 or a 5xx, or a blob 404 while `meta` is a
 * HIT) park the join; definitive failures drop it with a noise warning; nothing is written here.
 */
export async function acceptJoin(ctx: JoinCtx, J: P.Join, src: JoinSource): Promise<JoinOutcome> {
  const drop = (text: string, critical = false): JoinOutcome => {
    ctx.warn(text, critical);
    return { kind: "dropped" };
  };
  const parkOn = (e: unknown): JoinOutcome => park(e instanceof Error ? e.message : String(e));
  // Step 1, in this order, so that a J naming a large blob costs no download.
  if (P.sgb2BOfSize(J.bundleSize) === null) return drop(MALFORMED_KEY);
  let meta: { t: number; size: number } | null;
  let got: { bytes: Bytes; sizeOk: boolean } | null;
  try {
    meta = await ctx.api.blobMeta(J.bundleId);
    if (!meta || meta.size !== J.bundleSize) return drop(MALFORMED_KEY);
    got = await ctx.api.getBlob(J.bundleId, J.bundleSize);
  } catch (e) {
    if (e instanceof ApiError && !e.transient) return drop(MALFORMED_KEY);
    return parkOn(e);
  }
  if (!got) return park("blob not found yet");
  if (!got.sizeOk) return drop(MALFORMED_KEY);
  // Step 2.
  const chk = P.checkJoinBundle(J, got.bytes, ctx.self);
  if (!chk.ok) return drop(chk.failed === "dsig" ? INVALID_SIG_KEY : MALFORMED_KEY);
  const D = chk.D;
  const held = ctx.copiesOf(P.b64u(J.conv));
  // Step 3: a copy, ended or not, already holds (conv, e) with this H(D).
  const duplicate = () =>
    held.some((c) => {
      const x = c.epochs.get(J.e);
      return !!x && P.equalBytes(x.D.hash, D.hash);
    });
  if (duplicate()) return { kind: "duplicate" };
  // Step 4: settle the held copies. A copy created earlier in this poll is not held yet: park until it is.
  for (const c of held) {
    if (!c.key) return park("an earlier join of this conversation is being recorded");
    try {
      if (!(await ctx.settle(c))) return park("a membership change is pending");
    } catch (e) {
      return parkOn(e);
    }
  }
  // Step 3 again: the settle can move a copy to e through its own entry.
  if (duplicate()) return { kind: "duplicate" };
  // Step 5: "Claimed". An ended copy fits no J.
  for (const c of held) {
    if (c.removed) continue;
    const ep = c.epochs.get(c.current);
    const w = ep?.ctl.winner;
    if (ep && w?.processed && J.e === ep.e + 1 && P.equalBytes(w.claim.hD, D.hash))
      return { kind: "duplicate" };
  }
  // Step 6, no fit. An ended copy counts only for a J that contradicts its history (a fork).
  const live = held.filter((c) => !c.removed);
  const forks = held.filter((c) => c.removed && contradicts(c, J.e, D.hash));
  const counted = new Set<Copy>([...live, ...forks]);
  let ended: Copy | null = null;
  if (forks.length === 0 && live.every((c) => J.e < rootEpoch(c))) {
    const above = held.map(rootEpoch).filter((r) => r > J.e);
    if (above.length) {
      // An overtaken J: its own copy is settled first, never into r − 1 (r the lowest root above e).
      const r = Math.min(...above);
      let out: SettleOwn = { kind: "reached" };
      if (J.e < r - 1) {
        try {
          out = await ctx.settleOwn({
            J,
            D,
            dsig: chk.dsig,
            pks: chk.pks,
            tReg: meta.t,
            stopAt: r - 1,
            forkOf: (e, hD) =>
              held.find((c) => {
                const x = c.epochs.get(e);
                return !!x && !P.equalBytes(x.D.hash, hD);
              }) ?? null,
          });
        } catch (e) {
          return parkOn(e);
        }
      }
      if (out.kind === "parked") return park(out.why);
      if (out.kind === "ended") ended = out.copy;
      else if (out.kind === "fork") counted.add(out.of);
      else for (const c of held) if (rootEpoch(c) === r) counted.add(c);
    }
  }
  if (!ended && [...counted].some((c) => c.confirmed)) return drop(CONFIRMED_COPY_WARNING, true);
  // A first contact (a re-add after a removal included), a separate copy, or an overtaken J kept as an ended copy:
  // after the D.by key check, a request unless D.by is a contact.
  let by: Awaited<ReturnType<typeof dbyCheck>>;
  try {
    by = await dbyCheck(ctx, D);
  } catch (e) {
    return parkOn(e);
  }
  if (!by) return drop(INVALID_SIG_KEY);
  const request = !ctx.contact(P.b64u(D.by));
  const root = D.hash;
  const epoch =
    ended?.epochs.get(J.e) ??
    newEpoch({
      e: J.e,
      EK: J.EK,
      D,
      dsig: chk.dsig,
      bundleId: J.bundleId,
      bundleSize: J.bundleSize,
      tReg: meta.t,
      pks: chk.pks,
      self: ctx.self.uid,
    });
  const material = { e: J.e, EK: J.EK, bundleId: J.bundleId, bundleSize: J.bundleSize };
  const records: P.SelfRecord[] = request
    ? [
        {
          rtype: P.RT.REQUEST,
          conv: J.conv,
          root,
          ...material,
          tReg: meta.t,
          rootBy: D.by,
          via: src.via,
          desc: P.concat(D.bytes, chk.dsig),
        },
        ...(by.member ? [by.member] : []),
      ]
    : [
        { rtype: P.RT.CONV_JOIN, conv: J.conv, root, ...material, rootBy: D.by, via: src.via },
        // the bundle's t_reg in the same row, so a restore needs no blob/meta for E_start (§7.2)
        { rtype: P.RT.TREG, bundleId: J.bundleId, tReg: meta.t },
      ];
  return {
    kind: "new",
    copy: {
      conv: J.conv,
      root,
      rootBy: D.by,
      request,
      second: !ended && counted.size > 0,
      epoch,
      records,
      member: request ? null : by.member,
      dby: by.user,
      ended,
      J,
    },
  };
}

/** The fold key of a new copy. */
export const newCopyKey = (x: NewCopy): string => copyKeyOf(x);
