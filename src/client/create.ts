// Creating a conversation (docs/PROTOCOL.md §6.1) and delivering J by inbox invites (§6.12 steps 2–4): handle
// resolution, the epoch-0 descriptor and bundle, and batched invites with the 409 rebuild. WELCOMEs, retries with
// back-off and resume are deliver.ts's.
import * as P from "~/lib/proto";
import { ApiError, isTransient, type Api, type DirUser, type Params } from "./api";
import { cleanName } from "./conv";
import { UserError } from "./errors";

type Bytes = Uint8Array;

/** A recipient of J: its uid, its kemPk from the bundle's pks, and its handle (for warnings). */
export interface Recipient {
  uid: Bytes;
  kemPk: Bytes;
  handle: string;
}

/** Splits, normalises and deduplicates the handles typed for a creation or an add. */
export function parseHandleList(handles: readonly string[]): string[] {
  return [
    ...new Set(
      handles
        .flatMap((h) => h.split(/[\s,]+/))
        .map((h) => h.trim().toLowerCase().replace(/^@/, ""))
        .filter(Boolean),
    ),
  ];
}

/**
 * Resolves handles by prefix lookups (§10.6). Only a complete answer without a handle makes it unknown; a transient
 * failure fails with its error (never "unknown: @x").
 */
export async function resolveHandles(api: Api, names: readonly string[]): Promise<DirUser[]> {
  if (names.length === 0) throw new UserError("enter at least one handle");
  const found = await Promise.all(
    names.map((h) => (P.HANDLE_RE.test(h) ? api.userByHandle(h) : Promise.resolve(null))),
  );
  const missing = names.filter((_, i) => !found[i]);
  if (missing.length) throw new UserError(`unknown: ${missing.map((h) => "@" + h).join(", ")}`);
  return found as DirUser[];
}

/** Everything a creation builds before its blob is uploaded (§6.1 steps 1–3). */
export interface Creation {
  conv: Bytes;
  EK: Bytes;
  D: P.Descriptor;
  dsig: Bytes;
  blob: Bytes;
  bundleId: Bytes;
  bundleSize: number;
  pks: Bytes;
  others: DirUser[];
}

/** §6.1 steps 1–3: D_0 with (uid, sigPk, kh) members, dsig_0 and the SGB2 blob (pks_0, every entry a dummy). */
export function buildCreation(
  self: { uid: Bytes; id: P.Identity },
  others: DirUser[],
  name: string | undefined,
  now: number,
): Creation {
  const members = [self.uid, ...others.map((u) => u.uidBytes)];
  if (members.length < 2) throw new UserError("add at least one other person");
  if (members.length > P.MAX_MEMBERS) throw new UserError(`at most ${P.MAX_MEMBERS} members`);
  const cleaned = cleanName(name);
  const conv = P.random(16);
  const EK = P.random(32);
  const keys = P.epochKeys(EK, conv, 0);
  const kemPks = [self.id.kemPk, ...others.map((u) => u.kemPk)];
  const Dbytes = P.encodeD({
    conv,
    e: 0,
    prev: P.ZERO32,
    by: self.uid,
    ts: now,
    members: [
      { uid: self.uid, sigPk: self.id.sigPk, kh: P.kemHash(self.id.kemPk) },
      ...others.map((u) => ({ uid: u.uidBytes, sigPk: u.sigPk, kh: P.kemHash(u.kemPk) })),
    ],
    name: cleaned ?? null,
  });
  const D = P.parseD(Dbytes);
  const dsig = P.signD(Dbytes, keys.kc, self.id.sigSk);
  const b = P.buildBundle({ conv, e: 0, D: Dbytes, dsig, EK, pks: kemPks, prevMembers: [], rm: 0 });
  return {
    conv,
    EK,
    D,
    dsig,
    blob: b.blob,
    bundleId: b.id,
    bundleSize: b.size,
    pks: P.concat(...kemPks),
    others,
  };
}

/** Fisher–Yates with the CSPRNG (§6.12 step 2: invites go in random order). */
export function shuffle<T>(xs: readonly T[]): T[] {
  const out = xs.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const r = new DataView(P.random(4).buffer).getUint32(0) % (i + 1);
    [out[i], out[r]] = [out[r], out[i]];
  }
  return out;
}

export interface DeliverCtx {
  api: Api;
  params(): Params;
  /** waits on a protocol timer */
  wait(ms: number): Promise<void>;
  check(): void;
  progress(text: string): void;
}

/** The outcome of one round of invites: who got one, and the longest `retry-after` a refusal asked for (s). */
export interface InviteResult {
  delivered: Bytes[];
  retryAfter: number;
}

/**
 * §6.12 steps 2 and 4 for one J: inbox invites sealed to each recipient's kemPk, posted in random order in batches
 * of up to 32. A 409 `wrong era` rebuilds the batch for the returned era (fresh eid, AAD with the new E) and posts
 * again at once, or, when that era was already tried, after `end(min(E, E')) + SKEW`. Only an OK row result counts
 * as delivered; a 429, a per-row FULL, a network error or a 5xx leaves the uids pending (the caller retries).
 */
export async function deliverInvites(
  ctx: DeliverCtx,
  J: P.Join,
  recipients: readonly Recipient[],
): Promise<InviteResult> {
  const delivered: Bytes[] = [];
  let retryAfter = 0;
  const order = shuffle(recipients);
  for (let i = 0; i < order.length; i += 32) {
    const batch = order.slice(i, i + 32);
    let E = P.era(ctx.api.serverNow());
    const tried = new Set<number>();
    for (let attempt = 0; attempt < 4; attempt++) {
      ctx.check();
      const rows = batch.map((r) => P.makeInvite(r.kemPk, E, 0, J));
      try {
        const results = await ctx.api.postInbox(E, rows, (m) => ctx.progress(m));
        results.forEach((x, k) => {
          if ("rel" in x) delivered.push(batch[k].uid);
        });
        break;
      } catch (e) {
        const era = e instanceof ApiError && e.status === 409 ? e.body?.era : undefined;
        if (typeof era !== "number" || !Number.isInteger(era)) {
          if (e instanceof ApiError && e.retryAfter !== null)
            retryAfter = Math.max(retryAfter, e.retryAfter);
          if (isTransient(e)) break; // pending: the delivery queue retries
          throw e;
        }
        tried.add(E);
        if (tried.has(era)) {
          const left = P.eraEnd(Math.min(E, era)) + ctx.params().skew * 1000 - ctx.api.serverNow();
          if (left > 0) await ctx.wait(left);
        }
        E = era;
      }
    }
  }
  return { delivered, retryAfter };
}
