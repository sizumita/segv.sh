// Binary request / response layouts of the v2 API (docs/PROTOCOL-v2.md §10.3–§10.5, §10.8, §10.9).
// Shared by the Worker, the client and the engine test fake, so none of them can drift from the spec.
// Every decoder is strict: exact lengths, known enums, counts within limits, no trailing bytes.
// Keep this file free of DOM / Workers APIs.
import { BODY_LENS, INBOX_BODY_LEN, MAX_CLS } from "./proto2";

export type Bytes = Uint8Array;

export class WireError extends Error {}

const fail = (what: string): never => {
  throw new WireError(what);
};

// ───────────────────────── reader / writer ─────────────────────────

class Reader {
  private o = 0;
  private readonly dv: DataView;
  constructor(private readonly b: Bytes) {
    this.dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  }
  private need(n: number): void {
    if (this.o + n > this.b.length) fail("truncated");
  }
  u8(): number {
    this.need(1);
    return this.b[this.o++];
  }
  u16(): number {
    this.need(2);
    const v = this.dv.getUint16(this.o);
    this.o += 2;
    return v;
  }
  u32(): number {
    this.need(4);
    const v = this.dv.getUint32(this.o);
    this.o += 4;
    return v;
  }
  /** u64 limited to safe integers (sequence numbers and Unix ms). */
  u64(): number {
    this.need(8);
    const v = this.dv.getBigUint64(this.o);
    this.o += 8;
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) fail("u64 too large");
    return Number(v);
  }
  bytes(n: number): Bytes {
    this.need(n);
    const v = this.b.slice(this.o, this.o + n);
    this.o += n;
    return v;
  }
  get left(): number {
    return this.b.length - this.o;
  }
  end(): void {
    if (this.o !== this.b.length) fail("trailing bytes");
  }
}

class Writer {
  private parts: Bytes[] = [];
  private n = 0;
  private push(b: Bytes): this {
    this.parts.push(b);
    this.n += b.length;
    return this;
  }
  u8(x: number): this {
    if (!Number.isInteger(x) || x < 0 || x > 0xff) fail("u8 out of range");
    return this.push(Uint8Array.of(x));
  }
  u16(x: number): this {
    if (!Number.isInteger(x) || x < 0 || x > 0xffff) fail("u16 out of range");
    return this.push(Uint8Array.of(x >>> 8, x & 0xff));
  }
  u32(x: number): this {
    if (!Number.isInteger(x) || x < 0 || x > 0xffffffff) fail("u32 out of range");
    return this.push(Uint8Array.of(x >>> 24, (x >>> 16) & 0xff, (x >>> 8) & 0xff, x & 0xff));
  }
  u64(x: number): this {
    if (!Number.isSafeInteger(x) || x < 0) fail("u64 out of range");
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(x));
    return this.push(b);
  }
  bytes(b: Bytes, len?: number): this {
    if (len !== undefined && b.length !== len) fail(`expected ${len} bytes`);
    return this.push(b);
  }
  done(): Bytes {
    const out = new Uint8Array(this.n);
    let o = 0;
    for (const p of this.parts) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  }
}

const bodyLen = (cls: number): number => {
  if (!Number.isInteger(cls) || cls < 0 || cls > MAX_CLS) fail("bad class");
  return BODY_LENS[cls];
};

// ───────────────────────── POST /api/v2/put (§10.3) ─────────────────────────

export const PUT_MAX_ROWS = 16;
/** 1 + 16 × (2 + 16 + 1 + 16 + 16 424): exactly the largest valid request. */
export const PUT_MAX_BYTES = 1 + PUT_MAX_ROWS * (2 + 16 + 1 + 16 + BODY_LENS[MAX_CLS]); // 263 345

export interface PutRow {
  E: number;
  label: Bytes;
  cls: number;
  /** ZERO16 ⇒ no realtime publish */
  topic: Bytes;
  body: Bytes;
}

export function encodePutRequest(rows: readonly PutRow[]): Bytes {
  if (rows.length < 1 || rows.length > PUT_MAX_ROWS) fail("bad row count");
  const w = new Writer().u8(rows.length);
  for (const r of rows) {
    w.u16(r.E).bytes(r.label, 16).u8(r.cls).bytes(r.topic, 16).bytes(r.body, bodyLen(r.cls));
  }
  return w.done();
}

export function decodePutRequest(b: Bytes): PutRow[] {
  const r = new Reader(b);
  const count = r.u8();
  if (count < 1 || count > PUT_MAX_ROWS) fail("bad row count");
  const rows: PutRow[] = [];
  for (let i = 0; i < count; i++) {
    const E = r.u16();
    const label = r.bytes(16);
    const cls = r.u8();
    const topic = r.bytes(16);
    rows.push({ E, label, cls, topic, body: r.bytes(bodyLen(cls)) });
  }
  r.end();
  return rows;
}

export const PUT_OK = 0;
export const PUT_CONFLICT = 1;
export const PUT_WRONG_ERA = 2;
export const PUT_FULL = 3;
/** 4 (MOVED) is reserved for stage 2. */
export const PUT_BAD = 5;

export type PutResult =
  | { s: "ok"; t: number; receipt: Bytes }
  | { s: "conflict"; t: number; cls: number; body: Bytes }
  | { s: "wrong_era"; era: number }
  | { s: "full" }
  | { s: "bad" };

export function encodePutResponse(results: readonly PutResult[]): Bytes {
  if (results.length < 1 || results.length > PUT_MAX_ROWS) fail("bad result count");
  const w = new Writer().u8(results.length);
  for (const x of results) {
    switch (x.s) {
      case "ok":
        w.u8(PUT_OK).u32(x.t).bytes(x.receipt, 64);
        break;
      case "conflict":
        w.u8(PUT_CONFLICT).u32(x.t).u8(x.cls).bytes(x.body, bodyLen(x.cls));
        break;
      case "wrong_era":
        w.u8(PUT_WRONG_ERA).u16(x.era);
        break;
      case "full":
        w.u8(PUT_FULL);
        break;
      case "bad":
        w.u8(PUT_BAD);
        break;
      default:
        fail("bad result");
    }
  }
  return w.done();
}

export function decodePutResponse(b: Bytes): PutResult[] {
  const r = new Reader(b);
  const count = r.u8();
  if (count < 1 || count > PUT_MAX_ROWS) fail("bad result count");
  const out: PutResult[] = [];
  for (let i = 0; i < count; i++) {
    const s = r.u8();
    if (s === PUT_OK) out.push({ s: "ok", t: r.u32(), receipt: r.bytes(64) });
    else if (s === PUT_CONFLICT) {
      const t = r.u32();
      const cls = r.u8();
      out.push({ s: "conflict", t, cls, body: r.bytes(bodyLen(cls)) });
    } else if (s === PUT_WRONG_ERA) out.push({ s: "wrong_era", era: r.u16() });
    else if (s === PUT_FULL) out.push({ s: "full" });
    else if (s === PUT_BAD) out.push({ s: "bad" });
    else fail("bad put status");
  }
  r.end();
  return out;
}

// ───────────────────────── POST /api/v2/get (§10.4) ─────────────────────────

export const GET_MAX_KEYS = 256;
export const GET_MAX_BYTES = 8 * 1024;
/** Response budget: body-mode keys after 4 MiB of bodies are answered SKIPPED. */
export const GET_BODY_BUDGET = 4 * 1024 * 1024;

export const MODE_BODY = 0;
export const MODE_EXISTS = 1;

export interface GetKey {
  E: number;
  label: Bytes;
  mode: 0 | 1;
}

export function encodeGetRequest(keys: readonly GetKey[]): Bytes {
  if (keys.length < 1 || keys.length > GET_MAX_KEYS) fail("bad key count");
  const w = new Writer().u16(keys.length);
  for (const k of keys) {
    if (k.mode !== 0 && k.mode !== 1) fail("bad mode");
    w.u16(k.E).bytes(k.label, 16).u8(k.mode);
  }
  return w.done();
}

export function decodeGetRequest(b: Bytes): GetKey[] {
  const r = new Reader(b);
  const count = r.u16();
  if (count < 1 || count > GET_MAX_KEYS) fail("bad key count");
  const keys: GetKey[] = [];
  for (let i = 0; i < count; i++) {
    const E = r.u16();
    const label = r.bytes(16);
    const mode = r.u8();
    if (mode !== 0 && mode !== 1) fail("bad mode");
    keys.push({ E, label, mode: mode as 0 | 1 });
  }
  r.end();
  return keys;
}

export const GET_HIT = 0;
export const GET_MISS = 1;
export const GET_SKIPPED = 2;
export const GET_NO_ERA = 3;

export type GetStatus =
  | { s: "hit"; t: number; cls: number; body?: Bytes }
  | { s: "miss"; sealed: boolean }
  | { s: "skipped" }
  | { s: "no_era" };

/** `modes[i]` is the mode of request key i: a HIT carries a body exactly when the mode was 0. */
export function encodeGetResponse(statuses: readonly GetStatus[], modes: readonly number[]): Bytes {
  if (statuses.length !== modes.length || statuses.length < 1 || statuses.length > GET_MAX_KEYS) fail("bad status count");
  const w = new Writer().u16(statuses.length);
  statuses.forEach((x, i) => {
    switch (x.s) {
      case "hit":
        w.u8(GET_HIT).u32(x.t).u8(x.cls);
        if (modes[i] === MODE_BODY) {
          if (!x.body) fail("hit without body");
          w.bytes(x.body!, bodyLen(x.cls));
        } else bodyLen(x.cls);
        break;
      case "miss":
        w.u8(GET_MISS).u8(x.sealed ? 1 : 0);
        break;
      case "skipped":
        w.u8(GET_SKIPPED);
        break;
      case "no_era":
        w.u8(GET_NO_ERA);
        break;
      default:
        fail("bad status");
    }
  });
  return w.done();
}

export function decodeGetResponse(b: Bytes, modes: readonly number[]): GetStatus[] {
  const r = new Reader(b);
  const count = r.u16();
  if (count !== modes.length) fail("status count does not match the request");
  const out: GetStatus[] = [];
  for (let i = 0; i < count; i++) {
    const s = r.u8();
    if (s === GET_HIT) {
      const t = r.u32();
      const cls = r.u8();
      const len = bodyLen(cls);
      out.push(modes[i] === MODE_BODY ? { s: "hit", t, cls, body: r.bytes(len) } : { s: "hit", t, cls });
    } else if (s === GET_MISS) {
      const sealed = r.u8();
      if (sealed > 1) fail("bad sealed flag");
      out.push({ s: "miss", sealed: sealed === 1 });
    } else if (s === GET_SKIPPED) out.push({ s: "skipped" });
    else if (s === GET_NO_ERA) out.push({ s: "no_era" });
    else fail("bad get status");
  }
  r.end();
  return out;
}

// ───────────────────────── inbox (§10.5) ─────────────────────────

export const INBOX_MAX_ROWS = 32;
export const INBOX_ROW_LEN = 16 + INBOX_BODY_LEN; // 1432
/** 7 + 1432 · 32 = 45 831 */
export const INBOX_MAX_BYTES = 7 + INBOX_MAX_ROWS * INBOX_ROW_LEN;
export const INBOX_READ_MAX_LIMIT = 1024;

export interface InboxPostRow {
  eid: Bytes;
  body: Bytes;
}

export interface InboxPost {
  E: number;
  bucket: number;
  rows: InboxPostRow[];
}

export function encodeInboxPost(p: InboxPost): Bytes {
  if (p.rows.length < 1 || p.rows.length > INBOX_MAX_ROWS) fail("bad invite count");
  const w = new Writer().u16(p.E).u32(p.bucket).u8(p.rows.length);
  for (const x of p.rows) w.bytes(x.eid, 16).bytes(x.body, INBOX_BODY_LEN);
  return w.done();
}

export function decodeInboxPost(b: Bytes): InboxPost {
  const r = new Reader(b);
  const E = r.u16();
  const bucket = r.u32();
  const count = r.u8();
  if (count < 1 || count > INBOX_MAX_ROWS) fail("bad invite count");
  if (b.length !== 7 + INBOX_ROW_LEN * count) fail("bad inbox post length");
  const rows: InboxPostRow[] = [];
  for (let i = 0; i < count; i++) rows.push({ eid: r.bytes(16), body: r.bytes(INBOX_BODY_LEN) });
  r.end();
  return { E, bucket, rows };
}

/** JSON results of a post, in request order. */
export type InboxPostResult = { rel: number } | { error: "conflict" } | { error: "full" };

export function parseInboxPostResults(json: unknown, count: number): InboxPostResult[] {
  const res = (json as { results?: unknown } | null)?.results;
  if (!Array.isArray(res) || res.length !== count) fail("bad inbox results");
  return (res as unknown[]).map((x) => {
    const o = x as Record<string, unknown> | null;
    if (o && typeof o === "object" && Object.keys(o).length === 1) {
      if (Number.isInteger(o.rel) && (o.rel as number) >= 0 && (o.rel as number) <= 0xffffffff) return { rel: o.rel as number };
      if (o.error === "conflict" || o.error === "full") return { error: o.error };
    }
    return fail("bad inbox result");
  });
}

export interface InboxRow {
  rel: number;
  eid: Bytes;
  body: Bytes;
}

export interface InboxRead {
  closed: number;
  more: boolean;
  rows: InboxRow[];
}

export function encodeInboxRead(x: InboxRead): Bytes {
  const w = new Writer().u32(x.closed).u8(x.more ? 1 : 0).u32(x.rows.length);
  for (const row of x.rows) w.u32(row.rel).bytes(row.eid, 16).bytes(row.body, INBOX_BODY_LEN);
  return w.done();
}

export function decodeInboxRead(b: Bytes): InboxRead {
  const r = new Reader(b);
  const closed = r.u32();
  const more = r.u8();
  if (more > 1) fail("bad more flag");
  const count = r.u32();
  if (r.left !== count * (4 + INBOX_ROW_LEN)) fail("bad inbox read length");
  const rows: InboxRow[] = [];
  let prevRel = -1;
  for (let i = 0; i < count; i++) {
    const rel = r.u32();
    if (rel < prevRel) fail("inbox rows out of order");
    prevRel = rel;
    rows.push({ rel, eid: r.bytes(16), body: r.bytes(INBOX_BODY_LEN) });
  }
  r.end();
  return { closed, more: more === 1, rows };
}

// ───────────────────────── GET /api/v2/feed/{E}/{i} (§10.9) ─────────────────────────

export interface FeedRow {
  label: Bytes;
  cls: number;
  body: Bytes;
}

export interface FeedBatch {
  t: number;
  n: number;
  root: Bytes;
  head: Bytes;
  rows: FeedRow[];
}

export interface FeedPage {
  more: boolean;
  batches: FeedBatch[];
}

export function encodeFeed(p: FeedPage): Bytes {
  const w = new Writer().u8(p.more ? 1 : 0).u32(p.batches.length);
  for (const b of p.batches) {
    if (b.rows.length !== b.n || b.n < 1) fail("bad batch");
    w.u32(b.t).u32(b.n).bytes(b.root, 32).bytes(b.head, 32);
    for (const x of b.rows) w.bytes(x.label, 16).u8(x.cls).bytes(x.body, bodyLen(x.cls));
  }
  return w.done();
}

export function decodeFeed(b: Bytes): FeedPage {
  const r = new Reader(b);
  const more = r.u8();
  if (more > 1) fail("bad more flag");
  const nb = r.u32();
  const batches: FeedBatch[] = [];
  for (let i = 0; i < nb; i++) {
    const t = r.u32();
    const n = r.u32();
    if (n < 1) fail("empty batch");
    const root = r.bytes(32);
    const head = r.bytes(32);
    const rows: FeedRow[] = [];
    for (let j = 0; j < n; j++) {
      const label = r.bytes(16);
      const cls = r.u8();
      rows.push({ label, cls, body: r.bytes(bodyLen(cls)) });
    }
    batches.push({ t, n, root, head, rows });
  }
  r.end();
  return { more: more === 1, batches };
}

// ───────────────────────── realtime frames (§10.8) ─────────────────────────

export const RT_MAX_CLIENT_FRAME = 8 * 1024;
export const RT_MAX_TOPICS = 256;

export const RT_SUB = 0x01;
export const RT_UNSUB = 0x02;
export const RT_RESUME = 0x03;
export const RT_HELLO = 0x80;
export const RT_ROWS = 0x81;
export const RT_GAP = 0x82;
export const RT_RESUMED = 0x83;

export type ClientFrame =
  | { f: "sub"; topics: Bytes[] }
  | { f: "unsub"; topics: Bytes[] }
  | { f: "resume"; boot: Bytes; since: number; topics: Bytes[] };

export function encodeClientFrame(x: ClientFrame): Bytes {
  const w = new Writer();
  if (x.f === "resume") {
    if (x.topics.length > RT_MAX_TOPICS) fail("bad topic count");
    w.u8(RT_RESUME).bytes(x.boot, 8).u64(x.since).u16(x.topics.length);
  } else {
    if (x.topics.length < 1 || x.topics.length > RT_MAX_TOPICS) fail("bad topic count");
    w.u8(x.f === "sub" ? RT_SUB : RT_UNSUB).u16(x.topics.length);
  }
  for (const t of x.topics) w.bytes(t, 16);
  return w.done();
}

export function decodeClientFrame(b: Bytes): ClientFrame {
  if (b.length > RT_MAX_CLIENT_FRAME) fail("frame too large");
  const r = new Reader(b);
  const op = r.u8();
  const topics = (n: number): Bytes[] => Array.from({ length: n }, () => r.bytes(16));
  let out: ClientFrame;
  if (op === RT_SUB || op === RT_UNSUB) {
    const n = r.u16();
    if (n < 1 || n > RT_MAX_TOPICS) fail("bad topic count");
    out = { f: op === RT_SUB ? "sub" : "unsub", topics: topics(n) };
  } else if (op === RT_RESUME) {
    const boot = r.bytes(8);
    const since = r.u64();
    const n = r.u16();
    if (n > RT_MAX_TOPICS) fail("bad topic count");
    out = { f: "resume", boot, since, topics: topics(n) };
  } else return fail("bad frame type");
  r.end();
  return out;
}

export interface RtRow {
  seq: number;
  topic: Bytes;
  E: number;
  label: Bytes;
  t: number;
  cls: number;
  body: Bytes;
}

export type ServerFrame =
  | { f: "hello"; boot: Bytes; now: number; seq: number }
  | { f: "rows"; rows: RtRow[] }
  | { f: "gap"; since: number }
  | { f: "resumed" };

export function encodeServerFrame(x: ServerFrame): Bytes {
  const w = new Writer();
  switch (x.f) {
    case "hello":
      return w.u8(RT_HELLO).bytes(x.boot, 8).u64(x.now).u64(x.seq).done();
    case "rows":
      if (x.rows.length < 1 || x.rows.length > 0xffff) fail("bad row count");
      w.u8(RT_ROWS).u16(x.rows.length);
      for (const r of x.rows) {
        w.u64(r.seq).bytes(r.topic, 16).u16(r.E).bytes(r.label, 16).u32(r.t).u8(r.cls).bytes(r.body, bodyLen(r.cls));
      }
      return w.done();
    case "gap":
      return w.u8(RT_GAP).u64(x.since).done();
    case "resumed":
      return w.u8(RT_RESUMED).done();
    default:
      return fail("bad frame");
  }
}

export function decodeServerFrame(b: Bytes): ServerFrame {
  const r = new Reader(b);
  const op = r.u8();
  let out: ServerFrame;
  if (op === RT_HELLO) out = { f: "hello", boot: r.bytes(8), now: r.u64(), seq: r.u64() };
  else if (op === RT_ROWS) {
    const n = r.u16();
    if (n < 1) fail("empty rows frame");
    const rows: RtRow[] = [];
    for (let i = 0; i < n; i++) {
      const seq = r.u64();
      const topic = r.bytes(16);
      const E = r.u16();
      const label = r.bytes(16);
      const t = r.u32();
      const cls = r.u8();
      rows.push({ seq, topic, E, label, t, cls, body: r.bytes(bodyLen(cls)) });
    }
    out = { f: "rows", rows };
  } else if (op === RT_GAP) out = { f: "gap", since: r.u64() };
  else if (op === RT_RESUMED) out = { f: "resumed" };
  else return fail("bad frame type");
  r.end();
  return out;
}
