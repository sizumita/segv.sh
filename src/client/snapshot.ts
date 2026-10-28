// Self-lane snapshots (docs/PROTOCOL.md §7.4, §11.4 steps 2–3 and 10): finding the latest pointer at `Lsnap`, reading
// its blob, and writing a new snapshot blob and its pointer. What a snapshot holds is the engine's (messaging.ts).
import * as P from "~/lib/proto";
import type * as W from "~/lib/wire";
import { ApiError, isTransient, type Api } from "./api";

type Bytes = Uint8Array;

/** Pointer slots probed per era at restore (§11.4 step 2). */
export const SNAP_PROBE = 16;
/** A device writes a snapshot once it has applied more than this many self records since the latest one (§7.4). */
export const SNAP_RECORDS = 200;

/** A snapshot read at restore: where its pointer is, the self position it covers, and its records. */
export interface SnapshotRead {
  E: number;
  j: number;
  pos: P.Pos;
  /** S2 `ts` (ms) */
  ts: number;
  records: P.SelfRecord[];
}

/** One pointer slot as probed: its era, slot, label and body (null for a miss). */
interface Slot {
  E: number;
  j: number;
  label: Bytes;
  body: Bytes | null;
}

/** Probes `Lsnap(E, from..from+count−1)` in body mode. */
async function probe(api: Api, rS: Bytes, E: number, from: number, count: number): Promise<Slot[]> {
  const labels = Array.from({ length: count }, (_, i) => P.Lsnap(rS, E, from + i));
  const keys: W.GetKey[] = labels.map((label) => ({ E, label, mode: 0 }));
  const st = await api.get(keys);
  return st.map((s, i) => ({
    E,
    j: from + i,
    label: labels[i],
    body: s.s === "hit" && s.body ? s.body : null,
  }));
}

/** The dense prefix of pointer slots of era E: slots 0..15, then 16 more while every slot hits (a gallop). */
async function densePrefix(api: Api, rS: Bytes, E: number): Promise<Slot[]> {
  const out: Slot[] = [];
  for (let from = 0; ; from += SNAP_PROBE) {
    const got = await probe(api, rS, E, from, SNAP_PROBE);
    const miss = got.findIndex((s) => s.body === null);
    out.push(...(miss < 0 ? got : got.slice(0, miss)));
    if (miss >= 0) return out;
  }
}

/**
 * §11.4 steps 2–3: the pointers of `E_now` and `E_now − 1`, or else the first era with one from `E_now − 2` down to
 * `regEra`; the first pointer, from the highest `(E, j)` down, that opens as a pointer row and whose blob is a HIT,
 * hashes to its blobId, decrypts with its key and parses as S2. Null when none qualifies (restore runs from the lane).
 * A transient failure throws (the restore is retried, never run without a snapshot that exists).
 */
export async function readSnapshot(
  api: Api,
  id: P.Identity,
  regEra: number,
): Promise<SnapshotRead | null> {
  const Enow = P.era(api.serverNow());
  let found: Slot[] = [];
  for (const E of [Enow, Enow - 1])
    if (E >= regEra) found.push(...(await densePrefix(api, id.rS, E)));
  for (let E = Enow - 2; found.length === 0 && E >= regEra; E--) {
    const [first] = await probe(api, id.rS, E, 0, 1);
    if (first.body) found = await densePrefix(api, id.rS, E);
  }
  found.sort((a, b) => b.E - a.E || b.j - a.j);
  for (const s of found) {
    let snap: P.SnapRec;
    try {
      const row = P.openSelf(id.kS, s.E, s.label, s.body!, "snap");
      snap = row.records[0] as P.SnapRec;
    } catch {
      continue; // not a pointer row of this account
    }
    let got: { bytes: Bytes; sizeOk: boolean } | null;
    try {
      got = await api.getBlob(snap.blobId, snap.size);
    } catch (e) {
      if (isTransient(e)) throw e;
      continue;
    }
    if (!got?.sizeOk) continue;
    try {
      const s2 = P.decryptSnapshot(got.bytes, P.b64u(snap.blobId), snap.key);
      return { E: s.E, j: s.j, pos: s2.pos, ts: s2.ts, records: s2.records };
    } catch {
      continue;
    }
  }
  return null;
}

/** The first empty pointer slot of era E. */
export async function firstFreePointer(api: Api, rS: Bytes, E: number): Promise<number> {
  return (await densePrefix(api, rS, E)).length;
}

/**
 * §7.4: uploads the snapshot blob, then puts its pointer `SNAP{blobId, skey, size, Eh, nh}` (prev fields NONE /
 * ZERO16) at the first empty slot of `Lsnap(E, ·)`, `E = max(E_now, regEra)`; the first writer of a slot wins, so a
 * CONFLICT moves to the next slot. Returns the pointer's position.
 */
export async function writeSnapshot(
  api: Api,
  id: P.Identity,
  regEra: number,
  snap: P.Snapshot,
): Promise<{ E: number; j: number }> {
  const { blob, id: blobId, key } = P.encryptSnapshot(snap);
  const bid = P.fromB64u(blobId);
  await api.putBlob(bid, blob);
  let E = Math.max(P.era(api.serverNow()), regEra);
  let j = await firstFreePointer(api, id.rS, E);
  for (let attempt = 0; attempt < 64; attempt++) {
    const label = P.Lsnap(id.rS, E, j);
    const rec: P.SnapRec = {
      rtype: P.RT.SNAP,
      blobId: bid,
      key,
      size: blob.length,
      pos: snap.pos,
    };
    const { cls, body } = P.sealSelf(id.kS, E, label, {
      prev: P.NONE,
      prevh: P.ZERO16,
      ts: Math.max(0, Math.floor(api.serverNow())),
      records: [rec],
    });
    const [r] = await api.put([{ E, label, cls, topic: new Uint8Array(16), body }]);
    if (r.s === "ok") return { E, j };
    if (r.s === "conflict") {
      j++;
      continue;
    }
    if (r.s === "wrong_era" && r.era >= regEra) {
      E = r.era;
      j = await firstFreePointer(api, id.rS, E);
      continue;
    }
    throw new ApiError(0, `snapshot pointer refused (${r.s})`);
  }
  throw new ApiError(0, "snapshot pointer: too many conflicts");
}
