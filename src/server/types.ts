/**
 * RPC contracts of the v2 Durable Objects (docs/PROTOCOL.md §9) and the stubs the Worker uses to reach
 * them. Everything crosses the RPC boundary by structured clone (Uint8Array included).
 *
 * Object names (the DO derives (E, i) from ctx.id.name, §9):
 *   ShardDO      "shard/v2/{E}/{i}"   (stage 1: i = 0)
 *   InboxDO      "inbox/v2/{E}/{g}"   (stage 1: g = 0)
 *   BlobRegDO    "blobreg/v2"
 *   RealtimeDO   "rt/v2/0"
 *   CheckpointDO "ckpt/v2"
 *   PushDO       "push/v2"            (only while push is on, §9.8)
 */
import type { BlobRegDO } from "./blobreg-do";
import type { CheckpointDO } from "./ckpt-do";
import type { InboxDO } from "./inbox-do";
import type { PushDO } from "./push-do";
import type { RealtimeDO } from "./realtime-do";
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

// ───────────── RealtimeDO (§9.4) ─────────────

export interface RtPublishRow {
  topic: Bytes;
  E: number;
  label: Bytes;
  t: number;
  cls: number;
  body: Bytes;
}

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

/** PushDO.sub: "full" when PUSH_MAX_SUBS endpoints are stored, or PUSH_DAY_SUBS others changed today. */
export type PushSubResult = "ok" | "full";

// ───────────── stubs ─────────────

const ns = <T extends Rpc.DurableObjectBranded | undefined>(env: Env, name: string): DurableObjectNamespace<T> =>
  (env as unknown as Record<string, DurableObjectNamespace<T>>)[name];

export const shardName = (E: number, i: number): string => `shard/v2/${E}/${i}`;
export const inboxName = (E: number, g: number): string => `inbox/v2/${E}/${g}`;
export const BLOBREG_NAME = "blobreg/v2";
export const RT_NAME = "rt/v2/0";
export const CKPT_NAME = "ckpt/v2";
export const PUSH_NAME = "push/v2";

export const shardStub = (env: Env, E: number, i: number): DurableObjectStub<ShardDO> =>
  ns<ShardDO>(env, "SHARD").getByName(shardName(E, i));
export const inboxStub = (env: Env, E: number, g: number): DurableObjectStub<InboxDO> =>
  ns<InboxDO>(env, "INBOX").getByName(inboxName(E, g));
export const blobRegStub = (env: Env): DurableObjectStub<BlobRegDO> => ns<BlobRegDO>(env, "BLOBREG").getByName(BLOBREG_NAME);
export const rtStub = (env: Env): DurableObjectStub<RealtimeDO> => ns<RealtimeDO>(env, "RT").getByName(RT_NAME);
export const ckptStub = (env: Env): DurableObjectStub<CheckpointDO> => ns<CheckpointDO>(env, "CKPT").getByName(CKPT_NAME);
export const pushStub = (env: Env): DurableObjectStub<PushDO> => ns<PushDO>(env, "PUSH").getByName(PUSH_NAME);

/** Parses "shard/v2/{E}/{i}" / "inbox/v2/{E}/{g}" (decimal, no padding). */
export function parseEraName(name: string | undefined, kind: "shard" | "inbox"): { E: number; i: number } {
  const m = name ? new RegExp(`^${kind}/v2/(0|[1-9]\\d{0,4})/(0|[1-9]\\d{0,4})$`).exec(name) : null;
  if (!m) throw new Error(`${kind} DO: unexpected name`);
  const E = Number(m[1]);
  const i = Number(m[2]);
  if (E >= 0xffff || i > 0xffff) throw new Error(`${kind} DO: unexpected name`);
  return { E, i };
}
