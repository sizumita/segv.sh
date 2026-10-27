// Accepting a join (docs/PROTOCOL-v2.md §6.7) from an inbox invite or a WELCOME: the bundle checks in their order
// (size, meta, then the blob), duplicates, settling the held copies (a pending claim parks the join), the fits
// ("Claimed" is ignored, "Skip" re-adds a removed copy), and otherwise a first contact or a separate copy.
import * as P from "~/lib/proto";
import { ApiError, type Api } from "./api";
import { copyKeyOf, newEpoch, type Copy, type Epoch, type KnownUser } from "./conv";
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
  /** what to write (in this order): CONV_JOIN, or REQUEST + MEMBER of D.by */
  records: P.SelfRecord[];
  /** the MEMBER of D.by when it is new and rides in the next HEADS row (an accepted copy) */
  member: P.MemberRec | null;
  dby: KnownUser;
}

/** A skip re-add of a held copy (§6.7 step 5): the epoch it continues at and its EPOCH record. */
export interface SkipJoin {
  copy: Copy;
  epoch: Epoch;
  record: P.EpochRec;
  member: P.MemberRec | null;
  dby: KnownUser;
}

export type JoinOutcome =
  | { kind: "new"; copy: NewCopy }
  | { kind: "skip"; skip: SkipJoin }
  | { kind: "duplicate" }
  | { kind: "dropped" }
  | { kind: "parked"; why: string };

export interface JoinCtx {
  api: Api;
  self: { uid: Bytes; sigPk: Bytes; kh: Bytes };
  /** the held copies of a conversation (by b64u conv) */
  copiesOf(convB: string): readonly Copy[];
  /** the MEMBER record of a uid, or null */
  member(uidB: string): P.MemberRec | null;
  /** the CONTACT record of a uid, or null */
  contact(uidB: string): P.ContactRec | null;
  warn(text: string, critical?: boolean): void;
  /**
   * §6.7 step 4: catches up the control lane of a held copy's current epoch; true once its winner is final and
   * processed, or every slot is decided not e-valid (throws on a transient failure).
   */
  settle(c: Copy): Promise<boolean>;
}

const park = (why: string): JoinOutcome => ({ kind: "parked", why });

/**
 * The `D.by` key check (§6.7 step 5): D's sigPk for D.by must equal the sigPk of D.by's verified directory bundle
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
 * §6.7 for one J. Transient failures (a network error, a timeout, a 429 or a 5xx, or a blob 404 while `meta` is a
 * HIT) park the join; definitive failures drop it with a noise warning; nothing is written here.
 */
export async function acceptJoin(ctx: JoinCtx, J: P.Join, src: JoinSource): Promise<JoinOutcome> {
  const drop = (text: string, critical = false): JoinOutcome => {
    ctx.warn(text, critical);
    return { kind: "dropped" };
  };
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
    return park(e instanceof Error ? e.message : String(e));
  }
  if (!got) return park("blob not found yet");
  if (!got.sizeOk) return drop(MALFORMED_KEY);
  // Step 2.
  const chk = P.checkJoinBundle(J, got.bytes, ctx.self);
  if (!chk.ok) return drop(chk.failed === "dsig" ? INVALID_SIG_KEY : MALFORMED_KEY);
  const D = chk.D;
  const convB = P.b64u(J.conv);
  // Step 3: a copy already holds (conv, e) with this H(D).
  const held = ctx.copiesOf(convB);
  if (
    held.some((c) => c.epochs.get(J.e)?.D.hash && P.equalBytes(c.epochs.get(J.e)!.D.hash, D.hash))
  )
    return { kind: "duplicate" };
  // Step 4: settle the held copies. A copy accepted earlier in this poll is not held yet: park until it is.
  for (const c of held) {
    if (!c.key) return park("an earlier join of this conversation is being recorded");
    try {
      if (!(await ctx.settle(c))) return park("a membership change is pending");
    } catch (e) {
      return park(e instanceof Error ? e.message : String(e));
    }
  }
  // Step 5: the fits.
  for (const c of held) {
    const ep = c.epochs.get(c.current);
    const w = ep?.ctl.winner;
    if (!ep || !w?.processed) continue;
    if (J.e === ep.e + 1 && P.equalBytes(w.claim.hD, D.hash)) return { kind: "duplicate" }; // Claimed
    if (J.e > ep.e + 1 && ep.myIndex >= 0 && P.rmHas(w.claim.rm, ep.myIndex)) {
      let by: Awaited<ReturnType<typeof dbyCheck>>;
      try {
        by = await dbyCheck(ctx, D);
      } catch (e) {
        return park(e instanceof Error ? e.message : String(e));
      }
      if (!by) return drop(INVALID_SIG_KEY);
      const epoch = newEpoch({
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
      epoch.viaSkip = true;
      const record: P.EpochRec = {
        rtype: P.RT.EPOCH,
        conv: J.conv,
        root: c.root,
        e: J.e,
        EK: J.EK,
        bundleId: J.bundleId,
        bundleSize: J.bundleSize,
        claim: { E: w.E, n: w.n },
        flags: P.EPOCH_SKIP,
      };
      return { kind: "skip", skip: { copy: c, epoch, record, member: by.member, dby: by.user } };
    }
  }
  // Step 6, no fit.
  if (held.some((c) => c.confirmed)) return drop(CONFIRMED_COPY_WARNING, true);
  let by: Awaited<ReturnType<typeof dbyCheck>>;
  try {
    by = await dbyCheck(ctx, D);
  } catch (e) {
    return park(e instanceof Error ? e.message : String(e));
  }
  if (!by) return drop(INVALID_SIG_KEY);
  const request = !ctx.contact(P.b64u(D.by));
  const root = D.hash;
  const epoch = newEpoch({
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
    : [{ rtype: P.RT.CONV_JOIN, conv: J.conv, root, ...material, rootBy: D.by, via: src.via }];
  return {
    kind: "new",
    copy: {
      conv: J.conv,
      root,
      rootBy: D.by,
      request,
      second: held.length > 0,
      epoch,
      records,
      member: request ? null : by.member,
      dby: by.user,
    },
  };
}

/** The fold key of a new copy. */
export const newCopyKey = (x: NewCopy): string => copyKeyOf(x);
