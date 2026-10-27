/**
 * Shared types of the FakeWorld components (test/engine/fake/*). Each component models one server part of
 * docs/PROTOCOL-v2.md §9 and talks to the rest of the world only through `WorldCtx`.
 */
import type { Bytes } from "../../../src/lib/proto";

export type { Bytes };

/** Deployment parameters the fake reports in /api/v2/params (tests may change them; spec §3.1 says never within an era). */
export interface FakeParams {
  /** Δ, seconds. Tests: 1. */
  delta: number;
  /** SKEW, seconds. Tests: 0 (raise it to exercise early acceptance). */
  skew: number;
  /** Δin = INBOX_SLOT, seconds. Tests: 1. */
  inboxSlot: number;
  /** E_FIRST: reads of lower eras are "sealed" / 404 without touching a component. */
  efirst: number;
}

/** A row the Worker hands to the RealtimeDO after a successful put (spec §10.3 step 6). */
export interface PublishRow {
  topic: Bytes;
  E: number;
  label: Bytes;
  t: number;
  cls: number;
  body: Bytes;
}

/** What a component needs from the world: the clocks, the parameters and a few cross-component calls. */
export interface WorldCtx {
  /** Server time of the Worker, BlobReg, Inbox, Realtime and Checkpoint components: Date.now() + offsetMs. */
  now(): number;
  /** The ShardDO clock: now() − shardLagMs. */
  shardNow(): number;
  readonly params: FakeParams;
  /** Extra delay before an ended era's shard seals itself (0 = at end(E) + SKEW, as in production). */
  readonly sealDelayMs: number;
  /** Counts every accepted write of any component (used by `settle`). */
  bumpWrites(): void;
  /** RealtimeDO.publish (rows with a zero topic must not be passed). */
  publish(rows: PublishRow[]): void;
}

/** A fake HTTP response before the world adds the common headers. */
export interface Res {
  status: number;
  json?: unknown;
  bytes?: Bytes;
  /** cache-control; "no-store" when absent (spec §10.1). */
  cache?: string;
  headers?: Record<string, string>;
}

export const NO_STORE = "no-store";
export const IMMUTABLE = "public, max-age=31536000, immutable";

export const json = (status: number, j: unknown, extra?: Partial<Res>): Res => ({
  status,
  json: j,
  ...extra,
});
export const err = (
  status: number,
  error: string,
  more?: Record<string, unknown>,
  headers?: Record<string, string>,
): Res => ({
  status,
  json: { error, ...more },
  headers,
});
export const bin = (bytes: Bytes, extra?: Partial<Res>): Res => ({ status: 200, bytes, ...extra });

/** Map key of an (E, label) pair. */
export const rowKey = (E: number, labelB64: string): string => `${E}:${labelB64}`;
