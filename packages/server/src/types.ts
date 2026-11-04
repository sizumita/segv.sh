/**
 * RPC contracts of the v2 Durable Objects (docs/PROTOCOL.md §9) and the stubs the Worker uses to reach
 * them. Everything crosses the RPC boundary by structured clone (Uint8Array included).
 *
 * Object names (the DO derives (E, i) from ctx.id.name, §9):
 *   ShardDO      "shard/v2/{E}/{i}"   (stage 1: i = 0)
 *   InboxDO      "inbox/v2/{E}/{g}"   (stage 1: g = 0)
 *   BlobRegDO    "blobreg/v2/{j}"     (j = blobShard(id) of the blob id, §4.4; B of them; "blobreg/v2" is the first
 *                                     release's single registry, read-only, which the shards import from, §9.2)
 *   DirSeqDO     "dirseq/v2"          (the only writer of the directory, §9.6)
 *   KeyDO        "keys/v2"            (the per-era inbox bucket keys kbucket_E, §9.3)
 *   ConnDO       "conn/v2/{c}"        (c = conn(ck) of the client, §4.4; C of them)
 *   FeedDO       "feed/v2/{j}"        (j = feed(T) of the topic, §4.4; F of them)
 *   CheckpointDO "ckpt/v2"
 *   QuietDO      "quiet/v2/{k}"       (k = quietShard(owner) of an endpoint, §9.8; PUSH_SHARDS of them)
 */
import { BODY_LENS } from "@segv/protocol/proto";
import type { BlobRegDO } from "./blobreg-do";
import type { CheckpointDO } from "./ckpt-do";
import type { ConnDO } from "./conn-do";
import type { DirSeqDO } from "./dirseq-do";
import type { FeedDO } from "./feed-do";
import type { InboxDO } from "./inbox-do";
import type { KeyDO } from "./key-do";
import type { QuietDO } from "./quiet-do";
import type { ShardDO } from "./shard-do";

type Bytes = Uint8Array;

// ───────────── ShardDO (§9.1) ─────────────

export interface ShardPutRow {
  /** 8-byte routing value v(E, label) */
  v: Bytes;
  label: Bytes;
  cls: number;
  body: Bytes;
}

export type ShardPutResult =
  | { s: "ok"; t: number }
  | { s: "conflict"; t: number; cls: number; body: Bytes }
  | { s: "wrong_era"; era: number }
  | { s: "full" }
  | { s: "bad" };

export interface ShardGetKey {
  v: Bytes;
  label: Bytes;
  /** 0 = body, 1 = exists */
  mode: 0 | 1;
}

export type ShardGetResult = { s: "hit"; t: number; cls: number; body?: Bytes } | { s: "miss"; sealed: boolean };

export interface ShardHead {
  head: Bytes;
  /** closed_t, or 0 when no batch was ever closed */
  tLast: number;
  sealed: boolean;
  /** storage.sql.databaseSize */
  size: number;
  /** nothing is left to page (§9.1 "Paging"): the shard is paged into R2, or sealed without rows */
  paged: boolean;
}

/** One row of a closed batch, as the feed carries it (§10.9). */
export interface ShardFeedRow {
  label: Bytes;
  cls: number;
  body: Bytes;
}

/** A closed batch of a feed page: its commitment, its §10.9 wire size, and (only when the page fits) its rows. */
export interface ShardFeedBatch {
  t: number;
  n: number;
  root: Bytes;
  head: Bytes;
  /** wire bytes of the batch in the §10.9 encoding: 72 + Σ (17 + len(body)) */
  bytes: number;
  /**
   * The batch's rows by label, present on every batch when the page's total `bytes` is within the budget. A page
   * that is one oversized batch carries none: the Worker pulls its rows with feedRows.
   */
  rows?: ShardFeedRow[];
}

/** feedBatches: closed batches with t > after, ascending, at most `budget` wire bytes (always ≥ 1 batch if any). */
export interface ShardFeedBatches {
  batches: ShardFeedBatch[];
  /** more closed batches with a larger t exist */
  more: boolean;
  /** the era is sealed (every page is then immutable) */
  sealed: boolean;
}

/** feedRows: rows of one closed batch with label > after, by label, at most `budget` wire bytes (always ≥ 1 row). */
export interface ShardFeedRows {
  rows: ShardFeedRow[];
  /** no row of the batch follows the last one returned */
  done: boolean;
}

// ───────────── BlobRegDO (§9.2) ─────────────

export interface BlobRegistration {
  t: number;
  size: number;
  created: boolean;
}

/** HIT {t, size} or MISS {now = BlobReg clock in seconds since T0}. */
export type BlobMeta = { hit: true; t: number; size: number } | { hit: false; now: number };

/** One page of the first release's registry, as a shard imports it (§9.2 "Import"): the rows that route to it. */
export interface BlobExport {
  rows: { id: Bytes; size: number; t: number }[];
  /** the last id scanned (the next page starts after it), or null when the scan is complete */
  next: Bytes | null;
  /** the legacy registry's high-water mark and last_t (null when it never wrote them) */
  hw: number | null;
  lastT: number | null;
}

export interface ComponentHead {
  head: Bytes;
  tLast: number;
}

// ───────────── InboxDO (§9.3) ─────────────

export type InboxRowResult = { rel: number } | { error: "conflict" } | { error: "full" };

/** wrong_era: the whole call was refused (era(now) of the DO's clock). */
export type InboxPostOut = { s: "wrong_era"; era: number } | { s: "ok"; results: InboxRowResult[] };

export interface InboxReadOut {
  closed: number;
  more: boolean;
  rows: { rel: number; eid: Bytes; body: Bytes }[];
  /** `ended` is persisted: every row of the era is final (responses may be immutable when more = false) */
  ended: boolean;
}

export interface InboxHead extends ComponentHead {
  ended: boolean;
}

// ───────────── ConnDO / FeedDO (§9.4) ─────────────

export interface RtPublishRow {
  topic: Bytes;
  E: number;
  label: Bytes;
  t: number;
  cls: number;
  body: Bytes;
}

// ───────────── DirSeqDO (§9.6) ─────────────

/** A registration as the DirSeqDO writes it: the validated user row and its wrap rows (§10.6). */
export interface DirUserWrite {
  kind: "user";
  uid: string;
  upre: number;
  handle: string;
  hpre: number;
  bundle: string;
  sig: string;
  regEra: number;
  wraps: DirWrapRow[];
}
export interface DirWrapRow {
  uid: string;
  id: string;
  record: string;
  sig: string;
}
/** One wrap record added to a registered uid (§10.6). */
export interface DirWrapWrite {
  kind: "wrap";
  wrap: DirWrapRow;
}
export type DirWrite = DirUserWrite | DirWrapWrite;

/**
 * The write landed with these dirlog seqs (the user's first, then its wraps), or it was refused (400 / 409), or a
 * database it needs is unavailable or misconfigured (503).
 */
export type DirWriteResult = { ok: true; seqs: number[] } | { ok: false; status: 400 | 409 | 503; error: string };

// ───────────── CheckpointDO (§9.5) ─────────────

export interface CkptRecord {
  q: number;
  sec: number;
  hd: Bytes;
  C: Bytes;
  sig: Bytes;
  heads: { cid: string; head: Bytes }[];
}

export interface CkptRange {
  from: { q: number; C: Bytes };
  entries: { q: number; sec: number; hd: Bytes }[];
  latest: { q: number; C: Bytes; sig: Bytes };
}

// ───────────── PushDO (§9.8) ─────────────

// ───────────── stubs ─────────────

const ns = <T extends Rpc.DurableObjectBranded | undefined>(env: Env, name: string): DurableObjectNamespace<T> =>
  (env as unknown as Record<string, DurableObjectNamespace<T>>)[name];

export const shardName = (E: number, i: number): string => `shard/v2/${E}/${i}`;
export const inboxName = (E: number, g: number): string => `inbox/v2/${E}/${g}`;
export const blobRegName = (j: number): string => `blobreg/v2/${j}`;
/** The first release's single registry: read-only, the source of each shard's import (§9.2). */
export const BLOBREG_LEGACY_NAME = "blobreg/v2";
export const DIRSEQ_NAME = "dirseq/v2";
export const KEYS_NAME = "keys/v2";
export const connName = (c: number): string => `conn/v2/${c}`;
export const feedName = (j: number): string => `feed/v2/${j}`;
export const CKPT_NAME = "ckpt/v2";
export const quietName = (k: number): string => `quiet/v2/${k}`;

export const shardStub = (env: Env, E: number, i: number): DurableObjectStub<ShardDO> =>
  ns<ShardDO>(env, "SHARD").getByName(shardName(E, i));
export const inboxStub = (env: Env, E: number, g: number): DurableObjectStub<InboxDO> =>
  ns<InboxDO>(env, "INBOX").getByName(inboxName(E, g));
export const blobRegStub = (env: Env, j: number): DurableObjectStub<BlobRegDO> =>
  ns<BlobRegDO>(env, "BLOBREG").getByName(blobRegName(j));
export const blobRegLegacyStub = (env: Env): DurableObjectStub<BlobRegDO> =>
  ns<BlobRegDO>(env, "BLOBREG").getByName(BLOBREG_LEGACY_NAME);
export const dirSeqStub = (env: Env): DurableObjectStub<DirSeqDO> => ns<DirSeqDO>(env, "DIRSEQ").getByName(DIRSEQ_NAME);
export const keyStub = (env: Env): DurableObjectStub<KeyDO> => ns<KeyDO>(env, "KEYS").getByName(KEYS_NAME);
export const connStub = (env: Env, c: number): DurableObjectStub<ConnDO> => ns<ConnDO>(env, "CONN").getByName(connName(c));
export const feedStub = (env: Env, j: number): DurableObjectStub<FeedDO> => ns<FeedDO>(env, "FEED").getByName(feedName(j));
export const ckptStub = (env: Env): DurableObjectStub<CheckpointDO> => ns<CheckpointDO>(env, "CKPT").getByName(CKPT_NAME);
export const quietStub = (env: Env, k: number): DurableObjectStub<QuietDO> => ns<QuietDO>(env, "QUIET").getByName(quietName(k));

/** Parses "blobreg/v2/{j}" (decimal, no padding, j ≤ 4095) to j, and the legacy "blobreg/v2" to null (§9.2). */
export function parseBlobRegName(name: string | undefined): number | null {
  if (name === BLOBREG_LEGACY_NAME) return null;
  const m = name ? /^blobreg\/v2\/(0|[1-9]\d{0,3})$/.exec(name) : null;
  if (!m || Number(m[1]) > 4095) throw new Error("blobreg DO: unexpected name");
  return Number(m[1]);
}

/** Parses "conn/v2/{c}" / "feed/v2/{j}" / "quiet/v2/{k}" (decimal, no padding, below 2^31). */
export function parseIndexName(name: string | undefined, kind: "conn" | "feed" | "quiet"): number {
  const m = name ? new RegExp(`^${kind}/v2/(0|[1-9]\\d{0,9})$`).exec(name) : null;
  if (!m) throw new Error(`${kind} DO: unexpected name`);
  const c = Number(m[1]);
  if (c >= 2 ** 31) throw new Error(`${kind} DO: unexpected name`);
  return c;
}

/** Validates the (E, g, rel) of an inbox notice (§9.3): E a u16 below 0xFFFF, g and rel u32s. */
export function checkNotice(E: unknown, g: unknown, rel: unknown): void {
  if (!Number.isInteger(E) || (E as number) < 0 || (E as number) > 0xfffe) throw new TypeError("notice: bad era");
  for (const x of [g, rel]) {
    if (!Number.isInteger(x) || (x as number) < 0 || (x as number) > 0xffffffff) throw new TypeError("notice: bad number");
  }
}

/**
 * Validates realtime rows (§9.4 publish / deliver) as they cross an RPC boundary; `what` prefixes the error message.
 * The Worker validates them before the first call; the FeedDO and the ConnDO check them again.
 */
export function checkRtRows(input: unknown, what: string): RtPublishRow[] {
  if (!Array.isArray(input)) throw new TypeError(`${what}: bad rows`);
  return input.map((r: unknown) => {
    const { topic, E, label, t, cls, body } = (typeof r === "object" && r !== null ? r : {}) as Record<string, unknown>;
    if (!(topic instanceof Uint8Array) || topic.length !== 16) throw new TypeError(`${what}: bad topic`);
    if (!Number.isInteger(E) || (E as number) < 0 || (E as number) > 0xffff) throw new TypeError(`${what}: bad era`);
    if (!(label instanceof Uint8Array) || label.length !== 16) throw new TypeError(`${what}: bad label`);
    if (!Number.isInteger(t) || (t as number) < 0 || (t as number) > 0xffffffff) throw new TypeError(`${what}: bad t`);
    if (!Number.isInteger(cls) || BODY_LENS[cls as number] === undefined) throw new TypeError(`${what}: bad class`);
    if (!(body instanceof Uint8Array) || body.length !== BODY_LENS[cls as number]) throw new TypeError(`${what}: bad body`);
    return { topic, E: E as number, label, t: t as number, cls: cls as number, body };
  });
}

/** Parses "shard/v2/{E}/{i}" / "inbox/v2/{E}/{g}" (decimal, no padding). */
export function parseEraName(name: string | undefined, kind: "shard" | "inbox"): { E: number; i: number } {
  const m = name ? new RegExp(`^${kind}/v2/(0|[1-9]\\d{0,4})/(0|[1-9]\\d{0,4})$`).exec(name) : null;
  if (!m) throw new Error(`${kind} DO: unexpected name`);
  const E = Number(m[1]);
  const i = Number(m[2]);
  if (E >= 0xffff || i > 0xffff) throw new Error(`${kind} DO: unexpected name`);
  return { E, i };
}
