/**
 * Sealed shards in R2 (docs/PROTOCOL.md §9.1 "Paging", §10.4 "Paged shards", §10.9): the file formats, the manifest,
 * and the reads that the Worker (and the ShardDO's own verification before it empties itself) make against them.
 *
 *   seal/v2/{E}/{i}/rows      the closed batches, ascending t, each in the §10.9 batch encoding: the feed, end to end
 *   seal/v2/{E}/{i}/batches   (u32 t | u32 n | root | head | u64 off) × nb
 *   seal/v2/{E}/{i}/idx       (label | u32 t | u8 cls | u8 0 | u48 off) × n, sorted by (v, label), read in buckets of v
 *   seal/v2/{E}/{i}/manifest  JSON: s_E, kroute_E, the final head, the sizes and part hashes, the bucket directory, a
 *                             signature under SRV_SK; its existence is what "paged" means
 *
 * A point lookup costs one Range read of idx (the key's bucket) and, in body mode, one of rows; a feed page is one
 * Range of rows. The Worker keeps, per isolate, the manifests it verified (immutable) and, for a while, which shards
 * had none; a ShardDO that answers "shard: paged" ends that grace at once (sealForget).
 */
import {
  BODY_LENS,
  SEAL_BATCH_ENTRY,
  SEAL_IDX_ENTRY,
  b64u,
  equalBytes,
  fromB64u,
  sealBucketOf,
  sealSigMsg,
  shardOf,
  type Bytes,
  type SealFile,
  type SealSummary,
} from "@segv/protocol/proto";
import { ed25519Verify } from "./http";
import type { ShardGetKey, ShardGetResult } from "./types";

/** Parts of this many bytes (R2 multipart: uniform parts of at least 5 MiB, the last one shorter). */
export const SEAL_PART = 16 * 1024 * 1024;
/** Wire bytes of a feed batch header (u32 t | u32 n | root | head) and of a row's header (label | u8 cls). */
export const FEED_BATCH_HDR = 72;
export const FEED_ROW_HDR = 17;

/** What a paged ShardDO throws from get / feedBatches / feedRows (§9.1): the Worker then reads R2. */
export const PAGED_MESSAGE = "shard: paged";
export class ShardPagedError extends Error {
  constructor() {
    super(PAGED_MESSAGE);
    this.name = "ShardPaged";
  }
}
/** True for the paged error, also once it crossed the RPC boundary (only the message survives). */
export const isPagedError = (e: unknown): boolean => e instanceof Error && e.message.includes(PAGED_MESSAGE);

export type SealFileName = "rows" | "idx" | "batches" | "manifest";
export const sealKey = (E: number, i: number, f: SealFileName): string => `seal/v2/${E}/${i}/${f}`;

/** The manifest of a paged shard, parsed and checked (§9.1 "Paging"). `dir` holds the 2^b + 1 cumulative counts. */
export interface SealManifest extends SealSummary {
  bucketDir: Uint32Array;
  sig: Bytes;
}

/** One closed batch of a paged shard: its commitment, and where its §10.9 encoding sits in `rows`. */
export interface SealBatch {
  t: number;
  n: number;
  root: Bytes;
  head: Bytes;
  off: number;
  /** its encoded length (72 + Σ (17 + len(body))) */
  len: number;
}

// ───────────── encodings ─────────────

/** §10.9 batch header: u32 t | u32 n | root[32] | head[32]. */
export function batchHeader(t: number, n: number, root: Bytes, head: Bytes): Bytes {
  if (root.length !== 32 || head.length !== 32) throw new Error("seal: malformed batch commitment");
  const out = new Uint8Array(FEED_BATCH_HDR);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, t);
  dv.setUint32(4, n);
  out.set(root, 8);
  out.set(head, 40);
  return out;
}

/** §10.9 feed page header: u8 more | u32 nb. */
export function feedPageHeader(more: boolean, nb: number): Bytes {
  const out = new Uint8Array(5);
  out[0] = more ? 1 : 0;
  new DataView(out.buffer).setUint32(1, nb);
  return out;
}

const U48 = 2 ** 48;

/** An `idx` entry: label[16] | u32 t | u8 cls | u8 0 | u48 off. */
export function encodeIdxEntry(label: Bytes, t: number, cls: number, off: number): Bytes {
  if (label.length !== 16 || !Number.isSafeInteger(off) || off < 0 || off >= U48) throw new Error("seal: bad idx entry");
  const out = new Uint8Array(SEAL_IDX_ENTRY);
  const dv = new DataView(out.buffer);
  out.set(label, 0);
  dv.setUint32(16, t);
  out[20] = cls;
  dv.setUint16(22, Math.floor(off / 2 ** 32));
  dv.setUint32(24, off >>> 0);
  return out;
}

export interface IdxEntry {
  label: Bytes;
  t: number;
  cls: number;
  off: number;
}

/** The entry at byte offset `o` of an `idx` slice. */
export function decodeIdxEntry(b: Bytes, o: number): IdxEntry {
  if (o + SEAL_IDX_ENTRY > b.length) throw new Error("seal: truncated idx entry");
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const cls = b[o + 20];
  if (cls >= BODY_LENS.length || b[o + 21] !== 0) throw new Error("seal: malformed idx entry");
  return {
    label: b.slice(o, o + 16),
    t: dv.getUint32(o + 16),
    cls,
    off: dv.getUint16(o + 22) * 2 ** 32 + dv.getUint32(o + 24),
  };
}

/** A `batches` entry: u32 t | u32 n | root[32] | head[32] | u64 off. */
export function encodeBatchEntry(t: number, n: number, root: Bytes, head: Bytes, off: number): Bytes {
  if (!Number.isSafeInteger(off) || off < 0) throw new Error("seal: bad batch entry");
  const out = new Uint8Array(SEAL_BATCH_ENTRY);
  out.set(batchHeader(t, n, root, head), 0);
  new DataView(out.buffer).setBigUint64(72, BigInt(off));
  return out;
}

/** Decodes a whole `batches` file and checks it against the manifest (count, order, offsets, the final head). */
export function decodeBatches(b: Bytes, m: Pick<SealManifest, "nb" | "head" | "rows">): SealBatch[] {
  if (b.length !== m.nb * SEAL_BATCH_ENTRY) throw new Error("seal: batches size differs from the manifest");
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const out: SealBatch[] = [];
  for (let k = 0; k < m.nb; k++) {
    const o = k * SEAL_BATCH_ENTRY;
    const off = Number(dv.getBigUint64(o + 72));
    out.push({ t: dv.getUint32(o), n: dv.getUint32(o + 4), root: b.slice(o + 8, o + 40), head: b.slice(o + 40, o + 72), off, len: 0 });
  }
  for (let k = 0; k < out.length; k++) {
    const cur = out[k];
    const end = k + 1 < out.length ? out[k + 1].off : m.rows.size;
    cur.len = end - cur.off;
    const prev = k > 0 ? out[k - 1] : null;
    if (
      (prev === null ? cur.off !== 0 : cur.t <= prev.t) ||
      cur.n < 1 ||
      cur.len < FEED_BATCH_HDR + cur.n * (FEED_ROW_HDR + BODY_LENS[0]) ||
      !Number.isSafeInteger(cur.len)
    ) {
      throw new Error("seal: malformed batches table");
    }
  }
  if (out.length > 0 && !equalBytes(out[out.length - 1].head, m.head)) throw new Error("seal: the batches table does not end at the head");
  return out;
}

// ───────────── the manifest ─────────────

/** The big-endian u32 bytes of the bucket directory. */
export function dirBytes(dir: Uint32Array): Bytes {
  const out = new Uint8Array(dir.length * 4);
  const dv = new DataView(out.buffer);
  dir.forEach((x, k) => dv.setUint32(k * 4, x));
  return out;
}

/** The manifest JSON of §9.1 "Paging" for a summary and its signature. */
export function manifestJson(m: SealSummary, sig: Bytes): string {
  const file = (f: SealFile, extra: Record<string, unknown>): Record<string, unknown> => ({
    size: f.size,
    ...extra,
    sha256: f.sha256.map(b64u),
  });
  return JSON.stringify({
    v: 1,
    era: m.era,
    shard: m.shard,
    sbits: m.sbits,
    kroute: b64u(m.kroute),
    head: b64u(m.head),
    tLast: m.tLast,
    part: m.part,
    rows: file(m.rows, { n: m.n }),
    idx: file(m.idx, { b: m.b, dir: b64u(m.dir) }),
    batches: file(m.batches, { nb: m.nb }),
    sig: b64u(sig),
  });
}

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);
const isInt = (x: unknown, min: number, max: number): x is number =>
  typeof x === "number" && Number.isSafeInteger(x) && x >= min && x <= max;

function bytesField(x: unknown, len: number, what: string): Bytes {
  if (typeof x !== "string") throw new Error(`seal manifest: ${what}`);
  let b: Bytes;
  try {
    b = fromB64u(x);
  } catch {
    throw new Error(`seal manifest: ${what}`);
  }
  if (b.length !== len) throw new Error(`seal manifest: ${what}`);
  return b;
}

function fileField(x: unknown, part: number, what: string): SealFile {
  if (!isObj(x) || !isInt(x.size, 0, Number.MAX_SAFE_INTEGER) || !Array.isArray(x.sha256)) throw new Error(`seal manifest: ${what}`);
  const parts = Math.ceil(x.size / part);
  if (x.sha256.length !== parts) throw new Error(`seal manifest: ${what} parts`);
  return { size: x.size, sha256: x.sha256.map((s, k) => bytesField(s, 32, `${what} sha256[${k}]`)) };
}

/** Parses and checks a manifest's JSON (shape, lengths, the directory, the sizes); the signature is checked apart. */
export function parseManifest(text: string): SealManifest {
  let j: unknown;
  try {
    j = JSON.parse(text);
  } catch {
    throw new Error("seal manifest: not JSON");
  }
  if (!isObj(j) || j.v !== 1) throw new Error("seal manifest: version");
  if (!isInt(j.era, 0, 0xfffe) || !isInt(j.shard, 0, 0xffff) || !isInt(j.sbits, 0, 16) || j.shard >= 2 ** j.sbits) {
    throw new Error("seal manifest: era / shard");
  }
  if (!isInt(j.tLast, 0, 0xffffffff) || !isInt(j.part, 1, 0xffffffff)) throw new Error("seal manifest: tLast / part");
  const kroute = bytesField(j.kroute, 32, "kroute");
  const head = bytesField(j.head, 32, "head");
  const sig = bytesField(j.sig, 64, "sig");
  const rows = fileField(j.rows, j.part, "rows");
  const idx = fileField(j.idx, j.part, "idx");
  const batches = fileField(j.batches, j.part, "batches");
  if (!isObj(j.rows) || !isInt(j.rows.n, 1, 0xffffffff)) throw new Error("seal manifest: n");
  if (!isObj(j.batches) || !isInt(j.batches.nb, 1, 0xffffffff)) throw new Error("seal manifest: nb");
  if (!isObj(j.idx) || !isInt(j.idx.b, 0, 16)) throw new Error("seal manifest: b");
  const n = j.rows.n;
  const nb = j.batches.nb;
  const b = j.idx.b;
  const dir = bytesField(j.idx.dir, 4 * (2 ** b + 1), "dir");
  const dv = new DataView(dir.buffer, dir.byteOffset, dir.byteLength);
  const bucketDir = new Uint32Array(2 ** b + 1);
  for (let k = 0; k < bucketDir.length; k++) {
    bucketDir[k] = dv.getUint32(k * 4);
    if ((k === 0 && bucketDir[0] !== 0) || (k > 0 && bucketDir[k] < bucketDir[k - 1])) throw new Error("seal manifest: dir");
  }
  if (bucketDir[bucketDir.length - 1] !== n) throw new Error("seal manifest: dir total");
  if (idx.size !== n * SEAL_IDX_ENTRY || batches.size !== nb * SEAL_BATCH_ENTRY) throw new Error("seal manifest: sizes");
  if (rows.size < nb * FEED_BATCH_HDR + n * (FEED_ROW_HDR + BODY_LENS[0])) throw new Error("seal manifest: rows size");
  return { era: j.era, shard: j.shard, sbits: j.sbits, kroute, head, tLast: j.tLast, part: j.part, n, b, dir, nb, rows, idx, batches, bucketDir, sig };
}

/** Parses a manifest and requires it to name shard (E, i) and to verify under `srvPk`. */
export async function checkManifest(text: string, srvPk: Bytes, E: number, i: number): Promise<SealManifest> {
  const m = parseManifest(text);
  if (m.era !== E || m.shard !== i) throw new Error("seal manifest: names another shard");
  if (!(await ed25519Verify(srvPk, m.sig, sealSigMsg(m)))) throw new Error("seal manifest: bad signature");
  return m;
}

// ───────────── reads ─────────────

/** Range read of an R2 object; the bytes must be exactly `length` (the manifest sizes every read). */
export async function r2Range(bucket: R2Bucket, key: string, offset: number, length: number): Promise<Bytes> {
  if (length === 0) return new Uint8Array(0);
  const obj = await bucket.get(key, { range: { offset, length } });
  if (!obj) throw new Error("seal: object missing");
  const b = new Uint8Array(await obj.arrayBuffer());
  if (b.length !== length) throw new Error("seal: short read");
  return b;
}

/** Runs the jobs with at most `n` in flight (R2 reads of one request). */
async function pool<T>(jobs: readonly (() => Promise<T>)[], n: number): Promise<T[]> {
  const out = Array.from({ length: jobs.length }) as T[];
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < jobs.length) {
      const k = next++;
      out[k] = await jobs[k]();
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, jobs.length) }, worker));
  return out;
}
const READS_IN_FLIGHT = 16;

/** The entry of `label` in a bucket's slice of idx, or null. */
function findEntry(slice: Bytes, label: Bytes): IdxEntry | null {
  for (let o = 0; o + SEAL_IDX_ENTRY <= slice.length; o += SEAL_IDX_ENTRY) {
    let same = true;
    for (let k = 0; k < 16; k++) {
      if (slice[o + k] !== label[k]) {
        same = false;
        break;
      }
    }
    if (same) return decodeIdxEntry(slice, o);
  }
  return null;
}

/**
 * §10.4 "Paged shards": each key's bucket is one Range read of idx (keys of one bucket share it), a body one of
 * rows; a label missing from its bucket is MISS(sealed = 1). A key that routes to another shard is a programming
 * or configuration error and throws, as the ShardDO would.
 */
export async function sealLookup(bucket: R2Bucket, m: SealManifest, keys: readonly ShardGetKey[]): Promise<ShardGetResult[]> {
  const byBucket = new Map<number, number[]>();
  keys.forEach((k, idx) => {
    if (shardOf(k.v, m.sbits) !== m.shard) throw new Error("seal: key routed to another shard");
    const bk = sealBucketOf(k.v, m.sbits, m.b);
    const list = byBucket.get(bk);
    if (list) list.push(idx);
    else byBucket.set(bk, [idx]);
  });
  const out = Array.from({ length: keys.length }) as ShardGetResult[];
  const idxKey = sealKey(m.era, m.shard, "idx");
  const rowsKey = sealKey(m.era, m.shard, "rows");
  const bodies: (() => Promise<void>)[] = [];
  await pool(
    [...byBucket].map(([bk, idxs]) => async () => {
      const from = m.bucketDir[bk];
      const to = m.bucketDir[bk + 1];
      const slice = await r2Range(bucket, idxKey, from * SEAL_IDX_ENTRY, (to - from) * SEAL_IDX_ENTRY);
      for (const idx of idxs) {
        const k = keys[idx];
        const e = findEntry(slice, k.label);
        if (!e) out[idx] = { s: "miss", sealed: true };
        else if (k.mode !== 0) out[idx] = { s: "hit", t: e.t, cls: e.cls };
        else {
          bodies.push(async () => {
            const row = await r2Range(bucket, rowsKey, e.off, FEED_ROW_HDR + BODY_LENS[e.cls]);
            if (!equalBytes(row.subarray(0, 16), k.label) || row[16] !== e.cls) throw new Error("seal: row differs from its idx entry");
            out[idx] = { s: "hit", t: e.t, cls: e.cls, body: row.slice(FEED_ROW_HDR) };
          });
        }
      }
    }),
    READS_IN_FLIGHT,
  );
  await pool(bodies, READS_IN_FLIGHT);
  return out;
}

const tables = new Map<string, SealBatch[]>();
const TABLES_MAX = 8;

/** The decoded `batches` table of a paged shard (cached per isolate: a few at a time). */
export async function sealBatchTable(bucket: R2Bucket, m: SealManifest, cache = true): Promise<SealBatch[]> {
  const k = `${m.era}/${m.shard}`;
  const hit = cache ? tables.get(k) : undefined;
  if (hit) return hit;
  const obj = await bucket.get(sealKey(m.era, m.shard, "batches"));
  if (!obj) throw new Error("seal: batches missing");
  const table = decodeBatches(new Uint8Array(await obj.arrayBuffer()), m);
  if (cache) {
    if (tables.size >= TABLES_MAX) tables.delete(tables.keys().next().value!);
    tables.set(k, table);
  }
  return table;
}

/** A feed page of a paged shard (§10.9): its batches by the page rule, and the Range of `rows` that holds them. */
export interface SealPage {
  batches: SealBatch[];
  more: boolean;
  /** the first batch's offset in rows */
  from: number;
  /** the sum of the batches' encodings */
  bytes: number;
}

/**
 * Composes the page with t > after: whole batches while their encodings total ≤ budget, always at least one
 * (§10.9), exactly as the ShardDO's feedBatches does.
 */
export function sealPage(table: readonly SealBatch[], after: number, budget: number): SealPage {
  let lo = 0;
  let hi = table.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (table[mid].t > after) hi = mid;
    else lo = mid + 1;
  }
  const batches: SealBatch[] = [];
  let bytes = 0;
  let k = lo;
  for (; k < table.length; k++) {
    const b = table[k];
    if (batches.length > 0 && bytes + b.len > budget) break;
    batches.push(b);
    bytes += b.len;
  }
  return { batches, more: k < table.length, from: batches.length > 0 ? batches[0].off : 0, bytes };
}

// ───────────── the Worker's per-isolate memory of manifests ─────────────

const manifests = new Map<string, SealManifest>();
const MANIFESTS_MAX = 1024;
/** Shards found without a manifest, until when (ms). A paged answer from the ShardDO forgets the entry at once. */
const noManifest = new Map<string, number>();
const NO_MANIFEST_MAX = 4096;
const NO_MANIFEST_TTL_MS = 600_000;

/**
 * The manifest of shard (E, i) if it is paged: cached once verified (it is immutable); a shard found unpaged is not
 * asked again for NO_MANIFEST_TTL_MS unless `force`. Throws on a manifest that does not verify, and on R2 errors.
 */
export async function sealManifest(
  bucket: R2Bucket,
  srvPk: Bytes,
  E: number,
  i: number,
  nowMs: number,
  force = false,
): Promise<SealManifest | null> {
  const k = `${E}/${i}`;
  const hit = manifests.get(k);
  if (hit) return hit;
  if (!force) {
    const until = noManifest.get(k);
    if (until !== undefined && until > nowMs) return null;
  }
  const obj = await bucket.get(sealKey(E, i, "manifest"));
  if (!obj) {
    if (noManifest.size >= NO_MANIFEST_MAX) noManifest.clear();
    noManifest.set(k, nowMs + NO_MANIFEST_TTL_MS);
    return null;
  }
  const m = await checkManifest(await obj.text(), srvPk, E, i);
  noManifest.delete(k);
  if (manifests.size >= MANIFESTS_MAX) manifests.clear();
  manifests.set(k, m);
  return m;
}

/** A ShardDO answered "shard: paged": its manifest is looked for at the next call, whatever was remembered. */
export function sealForget(E: number, i: number): void {
  noManifest.delete(`${E}/${i}`);
}

/** Test hook: forget every manifest and batch table. */
export function _resetSealForTests(): void {
  manifests.clear();
  noManifest.clear();
  tables.clear();
}
