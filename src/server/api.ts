/**
 * HTTP + WebSocket API (docs/PROTOCOL.md §10). Plain fetch, no Qwik; the Worker entry routes every /api/*
 * path here. Every endpoint is under /api/v2/; any other /api/* path is a 404.
 *
 * Everything the server stores is public and writes are anonymous: abuse control is proof of work plus
 * per-IP rate limits (src/server/abuse.ts). Durable Objects get only what they need (never client
 * addresses or headers). Hardening of §9.7:
 *  - era bounds are checked with the Worker's clock before any per-era DO is addressed, so nobody can
 *    instantiate (and arm alarms in) arbitrary era objects;
 *  - immutable responses and the short-lived inbox tail are served from caches.default before the rate
 *    limiter; a feed page takes one RL_READ token per started 4 MiB;
 *  - every response except the 101 WebSocket upgrade carries a fresh `x-segv-now` (never stored in
 *    caches.default, §10.1), nosniff, no-referrer and HSTS (https), stamped on the object actually returned.
 */
import {
  BLOB_MAX,
  BLOB_MIN,
  BODY_LENS,
  ERA_MS,
  INBOX_BODY_LEN,
  MAX_ID_LEN,
  T0_MS,
  eraEnd,
  eraStart,
  era,
  hex,
  quietTag,
  receiptMsg,
  routeV,
  secOf,
  shardOf,
  type Bytes,
} from "../lib/proto";
import {
  GET_BODY_BUDGET,
  GET_MAX_BYTES,
  GET_MAX_KEYS,
  INBOX_MAX_BYTES,
  INBOX_READ_MAX_LIMIT,
  PUT_MAX_BYTES,
  PUT_MAX_ROWS,
  RT_MAX_TOPICS,
  WireError,
  decodeGetRequest,
  decodeInboxPost,
  decodePutRequest,
  encodeFeed,
  encodeGetResponse,
  encodeInboxRead,
  encodePutResponse,
  type GetStatus,
  type PutResult,
} from "../lib/wire";
import { checkPow, clientTag, powParams, rateLimit } from "./abuse";
import { dec64, enc64 } from "./b64";
import {
  HttpError,
  SECURITY_HEADERS,
  contentLength,
  errorResponse,
  exactKeys,
  intParam,
  json,
  logErr,
  parseJsonObject,
  readBody,
  sha256,
  HSTS,
} from "./http";
import {
  _resetDirectoryCacheForTests,
  currentP,
  dirAddWrap,
  dirByPrefix,
  dirByUid,
  dirRegister,
  dirWrapsById,
  dirlogPage,
} from "./directory";
import {
  INBOX_BATCH,
  INBOX_DAY_CAP,
  INBOX_RETENTION,
  eraBounds,
  kcommitFor,
  krouteFor,
  pushConfig,
  pushHostAllowed,
  serverKeys,
  srvSign,
  v2Params,
  v2ParamsValid,
  type PushConfig,
  type ServerKeys,
  type V2Params,
} from "./env";
import { PUSH_TOKENS, PUSH_WINDOW } from "./push-do";
import {
  blobRegStub,
  ckptStub,
  inboxStub,
  pushStub,
  rtStub,
  shardStub,
  type BlobMeta,
  type CkptRecord,
  type RtPublishRow,
  type ShardFeedBatches,
  type ShardFeedRow,
  type ShardFeedRows,
  type ShardGetKey,
  type ShardGetResult,
  type ShardPutResult,
  type ShardPutRow,
} from "./types";
import { isP256Point } from "./webpush";

/** Request body caps (bytes, §10.3–§10.6). */
export const MAX_REGISTER_BODY = 64 * 1024;
export const MAX_WRAP_BODY = 16 * 1024;
/** Page budget of the public feed (§10.9), and the page size that one RL_READ token pays for. */
const FEED_BUDGET = 4 * 1024 * 1024;
/** The most RL_READ tokens one feed page takes (§10.9). */
const FEED_MAX_TOKENS = 64;

/**
 * RL_READ tokens of a feed page: one per started FEED_BUDGET of the page's batch encodings (`bytes`, without the page
 * header), at least 1 and at most 64 (§9.1, §10.2, §10.9). The cap keeps every page readable by an address that has
 * not spent its window.
 */
export function feedTokens(bytes: number): number {
  return Math.min(Math.max(1, Math.ceil(bytes / FEED_BUDGET)), FEED_MAX_TOKENS);
}
const TEXT_MAX = 12_000;
/** Stage 1 runs one shard per era (s_E = 0). */
const SHARD_BITS = 0;
const SHARDS = 1;

const IMMUTABLE = "public, max-age=31536000, immutable";
const OCTET = "application/octet-stream";

interface Ctx {
  request: Request;
  env: Env;
  ctx: ExecutionContext;
  url: URL;
  now: number;
  params: V2Params;
  keys: ServerKeys;
}

/** An HttpError whose JSON body carries extra fields (e.g. `{error, era}`, `{error, p}`, `{error, now}`). */
export class ApiError extends HttpError {
  constructor(
    status: number,
    message: string,
    readonly extra: Record<string, unknown>,
    headers?: Record<string, string>,
  ) {
    super(status, message, headers);
  }
}

const rl = (env: Env, name: "RL_WRITE" | "RL_BLOB" | "RL_READ" | "RL_INBOX" | "RL_RING" | "RL_SEEN"): RateLimit | undefined =>
  (env as unknown as Record<string, RateLimit | undefined>)[name];

const readLimit = (c: Ctx) => rateLimit(rl(c.env, "RL_READ"), "read", c.request);
const writeLimit = (c: Ctx) => rateLimit(rl(c.env, "RL_WRITE"), "write", c.request);

function methods(c: Ctx, allowed: string[]): void {
  if (!allowed.includes(c.request.method)) {
    throw new HttpError(405, "method not allowed", { allow: allowed.join(", ") });
  }
}

function binary(body: Bytes, cacheControl = "no-store"): Response {
  return new Response(body as BodyInit, {
    headers: { "content-type": OCTET, "cache-control": cacheControl, ...SECURITY_HEADERS },
  });
}

/** caches.default when the runtime has it (Workers; it only stores anything on custom domains). */
function edgeCache(): Cache | null {
  const c = (globalThis as { caches?: { default?: Cache } }).caches;
  return c?.default ?? null;
}

/** The cache-control a cached response was stored with (§9.7). */
const STORED_CC = "x-segv-cache-control";

/**
 * A caches.default entry, with the cache-control it was stored with. On a custom domain the zone's "Browser Cache
 * TTL" rewrites the stored entry's cache-control (to 4 hours by default), which would let browsers keep the
 * short-lived inbox tail for hours and miss new invites.
 */
async function cacheGet(key: string): Promise<Response | null> {
  const cache = edgeCache();
  if (!cache) return null;
  const hit = (await cache.match(key).catch(() => undefined)) ?? null;
  if (!hit) return null;
  const cc = hit.headers.get(STORED_CC);
  const res = new Response(hit.body, hit);
  res.headers.delete(STORED_CC);
  if (cc) res.headers.set("cache-control", cc);
  return res;
}

/** Stores a copy (without x-segv-now: it is stamped later, on the returned object only). */
function cachePut(c: Ctx, key: string, res: Response): void {
  const cache = edgeCache();
  if (!cache || res.status !== 200) return;
  const copy = res.clone();
  copy.headers.delete("x-segv-now");
  const cc = res.headers.get("cache-control");
  if (cc) copy.headers.set(STORED_CC, cc);
  c.ctx.waitUntil(
    cache.put(key, copy).catch((e: unknown) => {
      console.error(JSON.stringify({ msg: "cache put failed", error: logErr(e) }));
    }),
  );
}

function decimal(s: string, max: number, what: string): number {
  if (!/^(0|[1-9]\d{0,9})$/.test(s)) throw new HttpError(400, `invalid ${what}`);
  const n = Number(s);
  if (n > max) throw new HttpError(400, `invalid ${what}`);
  return n;
}

function b64uParam(s: string | null, minLen: number, maxLen: number, what: string): Bytes {
  let b: Bytes;
  try {
    b = dec64(s);
  } catch {
    throw new HttpError(400, `invalid ${what}`);
  }
  if (b.length < minLen || b.length > maxLen) throw new HttpError(400, `invalid ${what}`);
  return b;
}

// ───────────── params, eras ─────────────

/** CheckpointDO.ensure() at most once per isolate, never per request (§9.5). */
let ckptEnsured = false;

async function params(c: Ctx): Promise<Response> {
  if (!ckptEnsured) {
    ckptEnsured = true;
    c.ctx.waitUntil(
      ckptStub(c.env)
        .ensure()
        .catch((e: unknown) => {
          ckptEnsured = false;
          console.error(JSON.stringify({ msg: "ckpt ensure failed", error: logErr(e) }));
        }),
    );
  }
  // Never throws: while D1 fails this is the last good P (or 0), logged and retried by currentP itself.
  const p = await currentP(c.env);
  const E = eraBounds(c.now, c.params.skew).now;
  const push = pushConfig(c.env);
  return json({
    v: 2,
    now: c.now,
    T0: T0_MS,
    eraMs: ERA_MS,
    era: E,
    delta: c.params.delta,
    skew: c.params.skew,
    inboxSlot: c.params.inboxSlot,
    inboxRetention: INBOX_RETENTION,
    inboxDayCap: INBOX_DAY_CAP,
    inboxBatch: INBOX_BATCH,
    shards: SHARDS,
    p,
    efirst: c.params.eFirst,
    kcommit: enc64(kcommitFor(c.keys, E)),
    srvKey: enc64(c.keys.srvPk),
    pow: powParams(c.env, push !== null),
    limits: {
      putRows: PUT_MAX_ROWS,
      putBytes: PUT_MAX_BYTES,
      getKeys: GET_MAX_KEYS,
      topics: RT_MAX_TOPICS,
      blobMax: BLOB_MAX,
      textMax: TEXT_MAX,
    },
    // Only while push is on (§9.8), and then always with pow.push.
    ...(push ? { push: { vapid: enc64(push.vapidPk), window: PUSH_WINDOW, maxTokens: PUSH_TOKENS } } : {}),
  });
}

function sealedByClock(c: Ctx, E: number): boolean {
  return c.now >= eraEnd(E) + c.params.skew * 1000;
}

async function eraInfo(c: Ctx, E: number): Promise<Response> {
  await readLimit(c);
  const { hi } = eraBounds(c.now, c.params.skew);
  if (E > hi || E < c.params.eFirst) throw new HttpError(404, "no such era");
  const sealed = sealedByClock(c, E);
  return json(
    {
      era: E,
      start: eraStart(E),
      end: eraEnd(E),
      delta: c.params.delta,
      shards: SHARDS,
      kcommit: enc64(kcommitFor(c.keys, E)),
      sealed,
    },
    200,
    sealed ? { "cache-control": IMMUTABLE } : undefined,
  );
}

// ───────────── rows: put / get (§10.3, §10.4) ─────────────

interface Routed<T> {
  E: number;
  i: number;
  idx: number[];
  items: T[];
}

function group<T>(entries: { E: number; i: number; idx: number; item: T }[]): Routed<T>[] {
  const m = new Map<string, Routed<T>>();
  for (const e of entries) {
    const k = `${e.E}/${e.i}`;
    let g = m.get(k);
    if (!g) m.set(k, (g = { E: e.E, i: e.i, idx: [], items: [] }));
    g.idx.push(e.idx);
    g.items.push(e.item);
  }
  return [...m.values()];
}

async function publish(c: Ctx, rows: RtPublishRow[]): Promise<void> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await rtStub(c.env).publish(rows);
      return;
    } catch (e) {
      if (attempt === 1) console.error(JSON.stringify({ msg: "realtime publish failed", error: logErr(e) }));
    }
  }
}

async function put(c: Ctx): Promise<Response> {
  await writeLimit(c);
  const bytes = await readBody(c.request, PUT_MAX_BYTES);
  checkPow(c.request, c.env, "put", await sha256(bytes), bytes.length, c.now);
  let rows;
  try {
    rows = decodePutRequest(bytes);
  } catch (e) {
    if (e instanceof WireError) throw new HttpError(400, `bad put request: ${e.message}`);
    throw e;
  }
  const { now: Enow, lo, hi } = eraBounds(c.now, c.params.skew);
  const results: (ShardPutResult | null)[] = rows.map((r) => (r.E < lo || r.E > hi ? { s: "wrong_era", era: Enow } : null));
  const routed = group(
    rows.flatMap((r, idx) => {
      if (results[idx] !== null) return [];
      const v = routeV(krouteFor(c.keys, r.E), r.label);
      return [{ E: r.E, i: shardOf(v, SHARD_BITS), idx, item: { v, label: r.label, cls: r.cls, body: r.body } as ShardPutRow }];
    }),
  );
  await Promise.all(
    routed.map(async (g) => {
      let out: ShardPutResult[];
      try {
        out = (await shardStub(c.env, g.E, g.i).put(g.E, g.i, g.items)) as ShardPutResult[];
      } catch (e) {
        console.error(JSON.stringify({ msg: "shard put failed", error: logErr(e) }));
        throw new HttpError(503, "storage unavailable", { "retry-after": "5" });
      }
      g.idx.forEach((idx, k) => (results[idx] = out[k]));
    }),
  );
  const wire: PutResult[] = await Promise.all(
    results.map(async (r, idx): Promise<PutResult> => {
      if (r === null) throw new Error("unrouted row");
      if (r.s !== "ok") return r;
      const row = rows[idx];
      return { s: "ok", t: r.t, receipt: await srvSign(c.keys, receiptMsg(row.E, row.label, row.body, r.t)) };
    }),
  );
  const pub: RtPublishRow[] = [];
  wire.forEach((r, idx) => {
    const row = rows[idx];
    if (r.s === "ok" && row.topic.some((b) => b !== 0)) {
      pub.push({ topic: row.topic, E: row.E, label: row.label, t: r.t, cls: row.cls, body: row.body });
    }
  });
  if (pub.length > 0) c.ctx.waitUntil(publish(c, pub));
  return binary(encodePutResponse(wire));
}

async function get(c: Ctx): Promise<Response> {
  await readLimit(c);
  const bytes = await readBody(c.request, GET_MAX_BYTES);
  let keys;
  try {
    keys = decodeGetRequest(bytes);
  } catch (e) {
    if (e instanceof WireError) throw new HttpError(400, `bad get request: ${e.message}`);
    throw e;
  }
  const { hi } = eraBounds(c.now, c.params.skew);
  const out: (GetStatus | null)[] = keys.map((k) =>
    k.E > hi ? { s: "no_era" } : k.E < c.params.eFirst ? { s: "miss", sealed: true } : null,
  );
  const routed = group(
    keys.flatMap((k, idx) => {
      if (out[idx] !== null) return [];
      const v = routeV(krouteFor(c.keys, k.E), k.label);
      return [{ E: k.E, i: shardOf(v, SHARD_BITS), idx, item: { v, label: k.label, mode: k.mode } as ShardGetKey }];
    }),
  );
  await Promise.all(
    routed.map(async (g) => {
      let res: ShardGetResult[];
      try {
        res = (await shardStub(c.env, g.E, g.i).get(g.E, g.i, g.items)) as ShardGetResult[];
      } catch (e) {
        console.error(JSON.stringify({ msg: "shard get failed", error: logErr(e) }));
        throw new HttpError(503, "storage unavailable", { "retry-after": "5" });
      }
      g.idx.forEach((idx, k) => (out[idx] = res[k]));
    }),
  );
  // Response budget: every body-mode key after 4 MiB of bodies is SKIPPED (the client asks again).
  let budget = GET_BODY_BUDGET;
  let exhausted = false;
  const statuses = out.map((s, idx): GetStatus => {
    if (s === null) throw new Error("unrouted key");
    if (keys[idx].mode !== 0) return s;
    if (exhausted) return { s: "skipped" };
    if (s.s === "hit" && s.body) {
      if (s.body.length > budget) {
        exhausted = true;
        return { s: "skipped" };
      }
      budget -= s.body.length;
    }
    return s;
  });
  return binary(
    encodeGetResponse(
      statuses,
      keys.map((k) => k.mode),
    ),
  );
}

// ───────────── inbox (§10.5) ─────────────

async function inboxPost(c: Ctx): Promise<Response> {
  await rateLimit(rl(c.env, "RL_INBOX"), "inbox", c.request);
  const bytes = await readBody(c.request, INBOX_MAX_BYTES);
  checkPow(c.request, c.env, "inbox", await sha256(bytes), bytes.length, c.now);
  let post;
  try {
    post = decodeInboxPost(bytes);
  } catch (e) {
    if (e instanceof WireError) throw new HttpError(400, `bad inbox post: ${e.message}`);
    throw e;
  }
  if (post.bucket !== 0) throw new HttpError(400, "unknown bucket");
  const { now: Enow, lo, hi } = eraBounds(c.now, c.params.skew);
  if (post.E < lo || post.E > hi) throw new ApiError(409, "wrong era", { era: Enow });
  const res = await inboxStub(c.env, post.E, 0).post(post.E, 0, post.bucket, post.rows);
  if (res.s === "wrong_era") throw new ApiError(409, "wrong era", { era: res.era });
  return json({ results: res.results });
}

async function inboxRead(c: Ctx, E: number, bucket: number): Promise<Response> {
  if (bucket !== 0) throw new HttpError(400, "unknown bucket");
  const { now: Enow, hi } = eraBounds(c.now, c.params.skew);
  if (E > hi) throw new HttpError(400, "era is in the future");
  if (E < Enow - (INBOX_RETENTION - 1)) throw new HttpError(410, "inbox era no longer served");
  if (E < c.params.eFirst) throw new HttpError(404, "no such era");
  const q = c.url.searchParams;
  const after = intParam(q.get("after"), 0, 0, 0xffffffff, "after");
  const limit = intParam(q.get("limit"), INBOX_READ_MAX_LIMIT, 1, INBOX_READ_MAX_LIMIT, "limit");
  // Canonical key: junk / reordered query parameters cannot multiply cache entries.
  const key = `${c.url.origin}/api/v2/inbox/${E}/${bucket}?after=${after}&limit=${limit}`;
  const hit = await cacheGet(key);
  if (hit) return hit;
  await readLimit(c);
  const r = await inboxStub(c.env, E, 0).read(E, 0, bucket, after, limit);
  for (const row of r.rows) if (row.body.length !== INBOX_BODY_LEN) throw new Error("inbox: bad stored body");
  const cc = r.ended && !r.more ? IMMUTABLE : `public, max-age=${c.params.inboxSlot}`;
  const res = binary(encodeInboxRead({ closed: r.closed, more: r.more, rows: r.rows }), cc);
  cachePut(c, key, res);
  return res;
}

// ───────────── blobs (§10.7, §8.2) ─────────────

/** R2's error when the `sha256` put option does not match the bytes received (code 10037, BadDigest). */
const R2_BAD_DIGEST = /checksum you specified did not match|BadDigest|\(10037\)/i;
/** FixedLengthStream's errors for a body shorter / longer than the Content-Length it was made with (workerd). */
const SHORT_BODY = /did not see all expected bytes/i;
const LONG_BODY = /too many bytes/i;
const LENGTH_MISMATCH = "body length does not match content-length";
/** workerd's error when the client went away while its request body was being read. */
const CLIENT_GONE = /client disconnected|read from request stream/i;
const BODY_NOT_RECEIVED = "request body was not received";

const errText = (e: unknown): string => String((e as Error)?.message ?? e);

/**
 * The client's error when an R2 put failed because the body did not have its declared length (§9.7: bodies are
 * capped by both lengths): 413 for too many bytes, 400 for too few; null for any other failure. A long body fails
 * both the put and the pipe into the FixedLengthStream, a short one only the put.
 */
function bodyLengthError(putErr: unknown, pipeErr: unknown): HttpError | null {
  if (LONG_BODY.test(errText(putErr)) || (pipeErr !== null && LONG_BODY.test(errText(pipeErr)))) {
    return new HttpError(413, LENGTH_MISMATCH);
  }
  if (SHORT_BODY.test(errText(putErr))) return new HttpError(400, LENGTH_MISMATCH);
  // The client disconnected mid-upload: not an internal error (and nobody is left to read the answer).
  if (CLIENT_GONE.test(errText(putErr)) || (pipeErr !== null && CLIENT_GONE.test(errText(pipeErr)))) {
    return new HttpError(400, BODY_NOT_RECEIVED);
  }
  return null;
}

function sameDigest(obj: R2Object, idBytes: Bytes): boolean {
  const d = obj.checksums.sha256;
  return d !== undefined && enc64(new Uint8Array(d)) === enc64(idBytes);
}

/**
 * PUT /api/v2/blob/{id}: registered ids answer at once without reading the body. Otherwise the body is
 * streamed into R2 (which checks it against the id) and registered only after R2 stored it, so a
 * registered id always has its object; re-uploading after a crash in between registers it.
 */
async function putBlob(c: Ctx, id: string, idBytes: Bytes): Promise<Response> {
  await rateLimit(rl(c.env, "RL_BLOB"), "blob", c.request);
  const declared = contentLength(c.request);
  if (declared === null) throw new HttpError(411, "content-length required");
  if (declared > BLOB_MAX) throw new HttpError(413, "blob too large");
  if (declared < BLOB_MIN) throw new HttpError(400, "blob too small");
  checkPow(c.request, c.env, "blob", idBytes, declared, c.now);

  const reg = blobRegStub(c.env);
  const meta = (await reg.meta(idBytes)) as BlobMeta;
  if (meta.hit) {
    await c.request.body?.cancel().catch(() => {});
    return json({ id, size: meta.size, t: meta.t }, 201);
  }
  const key = `b/${id}`;
  let size = declared;
  const existing = await c.env.BLOBS.head(key);
  if (existing && sameDigest(existing, idBytes)) {
    await c.request.body?.cancel().catch(() => {});
    size = existing.size;
  } else {
    if (c.request.body === null) throw new HttpError(400, "blob too small");
    const fixed = new FixedLengthStream(declared);
    // The pipe's failure is kept (a body longer than declared fails it), but the pipe is never awaited: it may
    // be waiting on reads the failed put will not make.
    let pipeErr: unknown = null;
    c.ctx.waitUntil(c.request.body.pipeTo(fixed.writable).catch((e: unknown) => void (pipeErr = e ?? "pipe failed")));
    try {
      await c.env.BLOBS.put(key, fixed.readable, {
        httpMetadata: { contentType: OCTET },
        sha256: idBytes.slice().buffer as ArrayBuffer,
      });
    } catch (e) {
      if (R2_BAD_DIGEST.test(errText(e))) throw new HttpError(400, "blob id does not match its content");
      // A concurrent upload of the same content may have won: only an object whose hash is the id counts.
      const now = await c.env.BLOBS.head(key);
      if (!now || !sameDigest(now, idBytes)) throw bodyLengthError(e, pipeErr) ?? e;
      size = now.size;
    }
  }
  const r = await reg.register(idBytes, size);
  return json({ id, size: r.size, t: r.t }, 201);
}

/** RFC 9110 If-None-Match: "*" or a list of entity-tags, empty list elements allowed (§13.1.2, §5.6.1); ASCII etagc. */
const ETAG = String.raw`(?:W/)?"[\x21\x23-\x7e]*"`;
const IF_NONE_MATCH = new RegExp(String.raw`^(?:\*|(?:,[ \t]*)*${ETAG}(?:[ \t]*,(?:[ \t]*${ETAG})?)*)$`);

/**
 * R2 get options for a blob GET: only If-None-Match is honoured (304); other conditionals are ignored
 * rather than mis-answered. An If-None-Match that is not valid RFC 9110 syntax is ignored as well (unconditional
 * get), since the R2 binding throws on it.
 */
export function blobGetOptions(inm: string | null): R2GetOptions | undefined {
  return inm !== null && IF_NONE_MATCH.test(inm) ? { onlyIf: new Headers({ "if-none-match": inm }) } : undefined;
}

function blobHeaders(etag: string): Headers {
  return new Headers({
    ...SECURITY_HEADERS,
    "content-type": OCTET,
    "cache-control": IMMUTABLE,
    etag,
    "content-disposition": "attachment",
    "content-security-policy": "default-src 'none'; sandbox",
    "cross-origin-resource-policy": "same-origin",
  });
}

async function getBlob(c: Ctx, id: string): Promise<Response> {
  const key = `${c.url.origin}/api/v2/blob/${id}`;
  const inm = c.request.headers.get("if-none-match");
  const hit = await cacheGet(key);
  if (hit) {
    const etag = hit.headers.get("etag");
    if (inm !== null && etag !== null && inm === etag) {
      await hit.body?.cancel().catch(() => {});
      return new Response(null, { status: 304, headers: blobHeaders(etag) });
    }
    return hit;
  }
  await readLimit(c);
  const obj = await c.env.BLOBS.get(`b/${id}`, blobGetOptions(inm));
  if (!obj) throw new HttpError(404, "no such blob");
  const headers = blobHeaders(obj.httpEtag);
  if (!("body" in obj)) return new Response(null, { status: 304, headers });
  headers.set("content-length", String(obj.size));
  const res = new Response(obj.body, { status: 200, headers });
  cachePut(c, key, res);
  return res;
}

async function blobMeta(c: Ctx, idBytes: Bytes): Promise<Response> {
  await readLimit(c);
  const m = (await blobRegStub(c.env).meta(idBytes)) as BlobMeta;
  if (!m.hit) throw new ApiError(404, "unregistered", { now: m.now });
  return json({ t: m.t, size: m.size });
}

// ───────────── realtime (§10.8) ─────────────

/** The RealtimeDO's client-tag key, cached per isolate (the value, never a cross-request promise). */
let wsKey: Bytes | null = null;

async function rt(c: Ctx): Promise<Response> {
  if (c.request.headers.get("upgrade")?.toLowerCase() !== "websocket") throw new HttpError(426, "expected websocket");
  // Browsers always send Origin on WebSocket handshakes: refuse pages on other sites.
  const origin = c.request.headers.get("origin");
  if (origin !== null) {
    let host: string | null = null;
    try {
      host = new URL(origin).host;
    } catch {
      /* "null" or garbage */
    }
    if (host !== c.url.host) throw new HttpError(403, "cross-origin websocket refused");
  }
  await readLimit(c);
  const stub = rtStub(c.env);
  wsKey ??= new Uint8Array(await stub.wsTagKey());
  // Hand the DO a minimal request: the upgrade plus an opaque per-client tag, never client headers / IPs.
  const res = await stub.fetch("https://rt.internal/rt", {
    headers: { upgrade: "websocket", "x-segv-client": clientTag(wsKey, c.request) },
  });
  if (res.status === 101) return res;
  let error = "websocket refused";
  try {
    const j = (await res.json()) as { error?: unknown };
    if (typeof j.error === "string") error = j.error;
  } catch {
    /* not JSON */
  }
  const retry = res.headers.get("retry-after");
  throw new HttpError(res.status, error, retry === null ? undefined : { "retry-after": retry });
}

// ───────────── checkpoints, feed (§10.9) ─────────────

function ckptJson(r: CkptRecord) {
  return {
    q: r.q,
    sec: r.sec,
    hd: enc64(r.hd),
    C: enc64(r.C),
    sig: enc64(r.sig),
    heads: r.heads.map((h) => ({ cid: h.cid, head: enc64(h.head) })),
  };
}

async function ckptLatest(c: Ctx): Promise<Response> {
  await readLimit(c);
  const r = await ckptStub(c.env).latest();
  if (!r) throw new HttpError(404, "no checkpoint yet");
  return json(ckptJson(r));
}

async function ckptAt(c: Ctx, q: number): Promise<Response> {
  const key = `${c.url.origin}/api/v2/ckpt/${q}`;
  const hit = await cacheGet(key);
  if (hit) return hit;
  await readLimit(c);
  const r = await ckptStub(c.env).get(q);
  if (!r) throw new HttpError(404, "no such checkpoint");
  const res = json(ckptJson(r), 200, { "cache-control": IMMUTABLE });
  cachePut(c, key, res);
  return res;
}

async function ckptRange(c: Ctx): Promise<Response> {
  await readLimit(c);
  const q = c.url.searchParams;
  const after = intParam(q.get("after"), 0, 0, 0xffffffff, "after");
  const limit = intParam(q.get("limit"), 1440, 1, 1440, "limit");
  const r = await ckptStub(c.env).range(after, limit);
  if (!r) throw new HttpError(404, "no such checkpoint range");
  return json({
    from: { q: r.from.q, C: enc64(r.from.C) },
    entries: r.entries.map((e) => ({ q: e.q, sec: e.sec, hd: enc64(e.hd) })),
    latest: { q: r.latest.q, C: enc64(r.latest.C), sig: enc64(r.latest.sig) },
  });
}

async function feed(c: Ctx, E: number, i: number): Promise<Response> {
  const { hi } = eraBounds(c.now, c.params.skew);
  if (E > hi || E < c.params.eFirst || i >= SHARDS) throw new HttpError(404, "no such shard");
  const after = intParam(c.url.searchParams.get("after"), 0, 0, 0xffffffff, "after");
  const key = `${c.url.origin}/api/v2/feed/${E}/${i}?after=${after}`;
  const hit = await cacheGet(key);
  if (hit) return hit;
  await readLimit(c);
  const shard = shardStub(c.env, E, i);
  const page = await shard.feedBatches(E, i, after, FEED_BUDGET);
  const immutable = page.more || page.sealed;
  const cacheControl = immutable ? IMMUTABLE : "no-store";
  const inline = page.batches.flatMap((b) => (b.rows ? [{ ...b, rows: b.rows }] : []));
  if (inline.length === page.batches.length) {
    // The page fits FEED_BUDGET: the shard sent every row with the batch list.
    const res = binary(encodeFeed({ more: page.more, batches: inline }), cacheControl);
    if (immutable) cachePut(c, key, res);
    return res;
  }
  // A batch larger than the page budget: still one whole batch on the wire (§10.9), streamed, with its rows pulled
  // from the shard ≤ FEED_BUDGET per RPC. The first pull happens before the 200 so that a shard failure is a 5xx.
  // Not stored in caches.default: a tee of the stream would buffer the whole batch for the slower reader.
  const big = page.batches.find((b) => !b.rows)!;
  // feedTokens(page) RL_READ tokens (§10.2, §10.9): the first was taken above, the others are taken here, before any
  // row is read, so a refused one is a 429 that cost the shard no feedRows call. The page is this one batch.
  for (let k = feedTokens(big.bytes) - 1; k > 0; k--) await readLimit(c);
  const first = await shard.feedRows(E, i, big.t, null, FEED_BUDGET);
  return new Response(feedStream(shard, E, i, page, first), {
    headers: { "content-type": OCTET, "cache-control": cacheControl, ...SECURITY_HEADERS },
  });
}

/** §10.9 batch header: u32 t | u32 n | root[32] | head[32]. */
function feedBatchHeader(t: number, n: number, root: Bytes, head: Bytes): Bytes {
  if (root.length !== 32 || head.length !== 32) throw new Error("feed: malformed batch from the shard");
  const out = new Uint8Array(72);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, t);
  dv.setUint32(4, n);
  out.set(root, 8);
  out.set(head, 40);
  return out;
}

/** §10.9 rows: (label[16] | u8 cls | body[CLASSES[cls] + 40]) × rows, in the order given. */
function feedRowBytes(rows: ShardFeedRow[]): Bytes {
  let len = 0;
  for (const r of rows) {
    if (r.label.length !== 16 || r.body.length !== BODY_LENS[r.cls]) {
      throw new Error("feed: malformed row from the shard");
    }
    len += 17 + r.body.length;
  }
  const out = new Uint8Array(len);
  let o = 0;
  for (const r of rows) {
    out.set(r.label, o);
    out[o + 16] = r.cls;
    out.set(r.body, o + 17);
    o += 17 + r.body.length;
  }
  return out;
}

/**
 * Streams a feed page (§10.9: u8 more | u32 nb | batch × nb) whose batches are not all inline. Inline batches are
 * encoded as they are; any other batch's rows are pulled with repeated feedRows calls (`first` is the first pull of
 * the first such batch), so the Worker holds about one FEED_BUDGET chunk at a time. Every batch is sent whole and
 * its row count is checked against n; a failure mid-way errors the stream (a truncated body, never a wrong one).
 */
function feedStream(
  shard: ReturnType<typeof shardStub>,
  E: number,
  i: number,
  page: ShardFeedBatches,
  first: ShardFeedRows,
): ReadableStream<Uint8Array> {
  let pending: ShardFeedRows | null = first;
  async function* chunks(): AsyncGenerator<Bytes> {
    const top = new Uint8Array(5);
    top[0] = page.more ? 1 : 0;
    new DataView(top.buffer).setUint32(1, page.batches.length);
    yield top;
    for (const b of page.batches) {
      yield feedBatchHeader(b.t, b.n, b.root, b.head);
      if (b.rows) {
        if (b.rows.length !== b.n) throw new Error("feed: batch row count mismatch");
        yield feedRowBytes(b.rows);
        continue;
      }
      let sent = 0;
      let afterLabel: Bytes | null = null;
      for (;;) {
        const part: ShardFeedRows = pending ?? (await shard.feedRows(E, i, b.t, afterLabel, FEED_BUDGET));
        pending = null;
        if (part.rows.length > 0) {
          yield feedRowBytes(part.rows);
          sent += part.rows.length;
          afterLabel = part.rows[part.rows.length - 1].label;
        }
        if (part.done) break;
        if (part.rows.length === 0) throw new Error("feed: no progress from the shard");
      }
      if (sent !== b.n) throw new Error("feed: batch row count mismatch");
    }
  }
  const it = chunks();
  return new ReadableStream<Uint8Array>({
    async pull(ctrl) {
      try {
        const r = await it.next();
        if (r.done) ctrl.close();
        else ctrl.enqueue(r.value);
      } catch (e) {
        console.error(JSON.stringify({ msg: "feed stream failed", error: logErr(e) }));
        ctrl.error(e);
      }
    },
    async cancel() {
      await it.return(undefined);
    },
  });
}

// ───────────── directory (§10.6) ─────────────

async function register(c: Ctx): Promise<Response> {
  await writeLimit(c);
  const bytes = await readBody(c.request, MAX_REGISTER_BODY);
  checkPow(c.request, c.env, "register", await sha256(bytes), bytes.length, c.now);
  return json(await dirRegister(c.env, parseJsonObject(bytes), c.now));
}

async function postWrap(c: Ctx): Promise<Response> {
  await writeLimit(c);
  const bytes = await readBody(c.request, MAX_WRAP_BODY);
  checkPow(c.request, c.env, "wrap", await sha256(bytes), bytes.length, c.now);
  return json(await dirAddWrap(c.env, parseJsonObject(bytes)));
}

async function dirPrefix(c: Ctx, kind: "h" | "u", pS: string, xS: string): Promise<Response> {
  await readLimit(c);
  const p = decimal(pS, 32, "prefix bits");
  const x = decimal(xS, 2 ** p - 1, "prefix value");
  const afterS = c.url.searchParams.get("after");
  if (afterS !== null) b64uParam(afterS, 16, 16, "after");
  return json(await dirByPrefix(c.env, kind, p, x, afterS));
}

async function dirUid(c: Ctx, uid: string): Promise<Response> {
  await readLimit(c);
  b64uParam(uid, 16, 16, "uid");
  const user = await dirByUid(c.env, uid);
  if (!user) throw new HttpError(404, "no such user");
  return json({ user });
}

async function dirWraps(c: Ctx, id: string): Promise<Response> {
  await readLimit(c);
  b64uParam(id, 1, MAX_ID_LEN, "id");
  const uid = c.url.searchParams.get("uid");
  if (uid !== null) b64uParam(uid, 16, 16, "uid");
  return json({ wraps: await dirWrapsById(c.env, id, uid) });
}

async function dirlog(c: Ctx): Promise<Response> {
  await readLimit(c);
  const q = c.url.searchParams;
  const after = intParam(q.get("after"), 0, 0, Number.MAX_SAFE_INTEGER, "after");
  const limit = intParam(q.get("limit"), 1000, 1, 1000, "limit");
  return json(await dirlogPage(c.env, after, limit));
}

// ───────────── Web Push (§10.10) ─────────────

export const MAX_PUSH_SUB_BODY = 16 * 1024;
/** 20 + 16·64 bytes. */
export const MAX_RING_BODY = 1044;
/** A ring is for a row stored in the last RING_FRESH seconds. */
export const RING_FRESH = 60;
/** The most rows one `seen` marks. */
export const SEEN_ROWS = 16;
/** 18 + 18·16 bytes. */
export const MAX_SEEN_BODY = 18 + 18 * SEEN_ROWS;

const noContent = (): Response =>
  new Response(null, { status: 204, headers: { "cache-control": "no-store", ...SECURITY_HEADERS } });

function b64uField(v: unknown, len: number, what: string): Bytes {
  let b: Bytes;
  try {
    b = dec64(v);
  } catch {
    throw new HttpError(400, `invalid ${what}`);
  }
  if (b.length !== len) throw new HttpError(400, `invalid ${what}`);
  return b;
}

/** An absolute https URL equal to its serialization, without userinfo or port, on a PUSH_HOSTS host. */
function pushEndpoint(cfg: PushConfig, v: unknown): string {
  if (typeof v !== "string" || new TextEncoder().encode(v).length > 1024) throw new HttpError(400, "invalid endpoint");
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    throw new HttpError(400, "invalid endpoint");
  }
  if (u.href !== v || u.protocol !== "https:" || u.username !== "" || u.password !== "" || u.port !== "") {
    throw new HttpError(400, "invalid endpoint");
  }
  if (!pushHostAllowed(cfg, u.hostname)) throw new HttpError(400, "endpoint host is not a known push service");
  return v;
}

async function pushSub(c: Ctx, cfg: PushConfig): Promise<Response> {
  await writeLimit(c);
  const bytes = await readBody(c.request, MAX_PUSH_SUB_BODY);
  checkPow(c.request, c.env, "push", await sha256(bytes), bytes.length, c.now);
  const raw = parseJsonObject(bytes);
  // `quiet` may be absent: a tab still open on an earlier release registers without one (§10.10).
  const keys = ["endpoint", "p256dh", "auth", "tokens"];
  if (Object.prototype.hasOwnProperty.call(raw, "quiet")) keys.push("quiet");
  const o = exactKeys(raw, keys, "push subscription");
  const endpoint = pushEndpoint(cfg, o.endpoint);
  const p256dh = b64uField(o.p256dh, 65, "p256dh");
  if (!isP256Point(p256dh)) throw new HttpError(400, "invalid p256dh");
  const auth = b64uField(o.auth, 16, "auth");
  if (!Array.isArray(o.tokens)) throw new HttpError(400, "invalid tokens");
  const seen = new Map<string, Bytes>();
  for (const t of o.tokens as unknown[]) {
    const b = b64uField(t, 16, "token");
    seen.set(enc64(b), b);
  }
  if (seen.size > PUSH_TOKENS) throw new HttpError(400, `at most ${PUSH_TOKENS} tokens`);
  const quiet = o.quiet === undefined ? null : b64uField(o.quiet, 16, "quiet");
  let r: string;
  try {
    r = await pushStub(c.env).sub(endpoint, p256dh, auth, [...seen.values()], quiet);
  } catch (e) {
    console.error(JSON.stringify({ msg: "push sub failed", error: logErr(e) }));
    throw new HttpError(503, "storage unavailable", { "retry-after": "5" });
  }
  if (r === "full") throw new HttpError(503, "push full", { "retry-after": "3600" });
  return noContent();
}

/**
 * POST /api/v2/ring: 204 as soon as the request parses, whatever happens next, so the answer never tells whether a
 * bell is registered, the row exists or was rung before (§10.10). The rest runs after the answer.
 */
async function ring(c: Ctx): Promise<Response> {
  await rateLimit(rl(c.env, "RL_RING"), "ring", c.request);
  const b = await readBody(c.request, MAX_RING_BODY);
  if (b.length < 20 || b[0] !== 1) throw new HttpError(400, "bad ring request");
  const n = b[19];
  if (n < 1 || n > 64 || b.length !== 20 + 16 * n) throw new HttpError(400, "bad ring request");
  const E = (b[1] << 8) | b[2];
  const label = b.slice(3, 19);
  const seen = new Map<string, Bytes>();
  for (let i = 0; i < n; i++) {
    const t = b.slice(20 + 16 * i, 36 + 16 * i);
    seen.set(enc64(t), t);
  }
  c.ctx.waitUntil(ringAfter(c, E, label, [...seen.values()]));
  return noContent();
}

/** §10.10 step 1: the eras a row stored in the last RING_FRESH seconds can be in. */
export function ringEraOk(E: number, nowMs: number, p: Pick<V2Params, "delta" | "skew" | "eFirst">): boolean {
  const lo = Math.max(p.eFirst, era(nowMs - (RING_FRESH + p.delta + p.skew) * 1000));
  return E >= lo && E <= era(nowMs + p.skew * 1000);
}

/** §10.10 step 2: `t` is rounded down to Δ, so a row stored RING_FRESH seconds ago may carry a t up to Δ older. */
export const ringRowFresh = (t: number, nowMs: number, delta: number): boolean => t + delta >= secOf(nowMs) - RING_FRESH;

async function ringAfter(c: Ctx, E: number, label: Bytes, tokens: Bytes[]): Promise<void> {
  try {
    if (!ringEraOk(E, c.now, c.params)) return;
    const v = routeV(krouteFor(c.keys, E), label);
    const [r] = (await shardStub(c.env, E, 0).get(E, 0, [{ v, label, mode: 1 } as ShardGetKey])) as ShardGetResult[];
    if (!r || r.s !== "hit" || !ringRowFresh(r.t, c.now, c.params.delta)) return;
    await pushStub(c.env).ring(E, label, tokens);
  } catch (e) {
    console.error(JSON.stringify({ msg: "ring failed", error: logErr(e) }));
  }
}

/**
 * POST /api/v2/seen: a device of an account in use has shown these rows, so no device of the account is pushed for them
 * (§10.10). The request carries the account's quiet secret, whose hash is the tag the account's endpoints registered:
 * only its own devices know it. 204 as soon as the request parses, so the answer never tells whether the tag is
 * registered; the rest runs after the answer.
 */
async function seen(c: Ctx): Promise<Response> {
  await rateLimit(rl(c.env, "RL_SEEN"), "seen", c.request);
  const b = await readBody(c.request, MAX_SEEN_BODY);
  if (b.length < 18 || b[0] !== 1) throw new HttpError(400, "bad seen request");
  const n = b[17];
  if (n < 1 || n > SEEN_ROWS || b.length !== 18 + 18 * n) throw new HttpError(400, "bad seen request");
  const Q = quietTag(b.subarray(1, 17));
  const rows = new Map<string, { E: number; label: Bytes }>();
  for (let i = 0; i < n; i++) {
    const o = 18 + 18 * i;
    const row = { E: (b[o] << 8) | b[o + 1], label: b.slice(o + 2, o + 18) };
    rows.set(hex(b.subarray(o, o + 18)), row);
  }
  c.ctx.waitUntil(seenAfter(c, Q, [...rows.values()]));
  return noContent();
}

async function seenAfter(c: Ctx, Q: Bytes, rows: { E: number; label: Bytes }[]): Promise<void> {
  try {
    await pushStub(c.env).seen(Q, rows);
  } catch (e) {
    console.error(JSON.stringify({ msg: "seen failed", error: logErr(e) }));
  }
}

// ───────────── router ─────────────

const P = "/api/v2";
const ERA_PATH = /^\/api\/v2\/era\/(\d{1,6})$/;
const INBOX_PATH = /^\/api\/v2\/inbox\/(\d{1,6})\/(\d{1,10})$/;
const BLOB_PATH = /^\/api\/v2\/blob\/([A-Za-z0-9_-]{43})(\/meta)?$/;
const CKPT_PATH = /^\/api\/v2\/ckpt\/(\d{1,10})$/;
const FEED_PATH = /^\/api\/v2\/feed\/(\d{1,6})\/(\d{1,6})$/;
const DIR_PREFIX_PATH = /^\/api\/v2\/dir\/(h|u)\/(\d{1,2})\/(\d{1,10})$/;
const DIR_UID_PATH = /^\/api\/v2\/dir\/uid\/([^/]{1,64})$/;
const DIR_WRAPS_PATH = /^\/api\/v2\/dir\/wraps\/([^/]{1,1400})$/;

async function route(c: Ctx): Promise<Response> {
  const path = c.url.pathname;
  switch (path) {
    case `${P}/params`:
      methods(c, ["GET"]);
      return params(c);
    case `${P}/put`:
      methods(c, ["POST"]);
      return put(c);
    case `${P}/get`:
      methods(c, ["POST"]);
      return get(c);
    case `${P}/inbox`:
      methods(c, ["POST"]);
      return inboxPost(c);
    case `${P}/rt`:
      methods(c, ["GET"]);
      return rt(c);
    case `${P}/ckpt/latest`:
      methods(c, ["GET"]);
      return ckptLatest(c);
    case `${P}/ckpt/range`:
      methods(c, ["GET"]);
      return ckptRange(c);
    case `${P}/register`:
      methods(c, ["POST"]);
      return register(c);
    case `${P}/wraps`:
      methods(c, ["POST"]);
      return postWrap(c);
    case `${P}/dirlog`:
      methods(c, ["GET"]);
      return dirlog(c);
    case `${P}/push/sub`:
    case `${P}/ring`:
    case `${P}/seen`: {
      // While push is off these paths match no route (§10.1 step 3, §10.10).
      const cfg = pushConfig(c.env);
      if (!cfg) break;
      methods(c, ["POST"]);
      if (path === `${P}/ring`) return ring(c);
      if (path === `${P}/seen`) return seen(c);
      return pushSub(c, cfg);
    }
  }
  let m = ERA_PATH.exec(path);
  if (m) {
    methods(c, ["GET"]);
    return eraInfo(c, decimal(m[1], 0xfffe, "era"));
  }
  m = INBOX_PATH.exec(path);
  if (m) {
    methods(c, ["GET"]);
    return inboxRead(c, decimal(m[1], 0xfffe, "era"), decimal(m[2], 0xffffffff, "bucket"));
  }
  if (path.startsWith(`${P}/blob/`)) {
    m = BLOB_PATH.exec(path);
    const isMeta = m?.[2] !== undefined;
    methods(c, isMeta ? ["GET"] : ["GET", "PUT"]);
    let idBytes: Bytes | null = null;
    try {
      if (m) idBytes = dec64(m[1]);
    } catch {
      /* non-canonical */
    }
    if (!m || !idBytes || idBytes.length !== 32) throw new HttpError(400, "invalid blob id");
    if (isMeta) return blobMeta(c, idBytes);
    return c.request.method === "PUT" ? putBlob(c, m[1], idBytes) : getBlob(c, m[1]);
  }
  m = CKPT_PATH.exec(path);
  if (m) {
    methods(c, ["GET"]);
    const q = decimal(m[1], 0xffffffff, "checkpoint");
    if (q < 1) throw new HttpError(404, "no such checkpoint");
    return ckptAt(c, q);
  }
  m = FEED_PATH.exec(path);
  if (m) {
    methods(c, ["GET"]);
    return feed(c, decimal(m[1], 0xfffe, "era"), decimal(m[2], 0xffff, "shard"));
  }
  m = DIR_PREFIX_PATH.exec(path);
  if (m) {
    methods(c, ["GET"]);
    return dirPrefix(c, m[1] as "h" | "u", m[2], m[3]);
  }
  m = DIR_UID_PATH.exec(path);
  if (m) {
    methods(c, ["GET"]);
    return dirUid(c, m[1]);
  }
  m = DIR_WRAPS_PATH.exec(path);
  if (m) {
    methods(c, ["GET"]);
    return dirWraps(c, m[1]);
  }
  throw new HttpError(404, "not found");
}

/** Path for logs without ids, handles, prefixes or eras in it. */
export function routeLabel(path: string): string {
  if (ERA_PATH.test(path)) return `${P}/era/:E`;
  if (INBOX_PATH.test(path)) return `${P}/inbox/:E/:bucket`;
  if (path.startsWith(`${P}/blob/`)) return path.endsWith("/meta") ? `${P}/blob/:id/meta` : `${P}/blob/:id`;
  if (CKPT_PATH.test(path)) return `${P}/ckpt/:q`;
  if (FEED_PATH.test(path)) return `${P}/feed/:E/:i`;
  if (DIR_PREFIX_PATH.test(path)) return `${P}/dir/:kind/:p/:x`;
  if (DIR_UID_PATH.test(path)) return `${P}/dir/uid/:uid`;
  if (DIR_WRAPS_PATH.test(path)) return `${P}/dir/wraps/:id`;
  const fixed = ["params", "put", "get", "inbox", "rt", "ckpt/latest", "ckpt/range", "register", "wraps", "dirlog", "push/sub", "ring"];
  return fixed.some((f) => path === `${P}/${f}`) ? path : `${P}/*`;
}

/**
 * Stamps `x-segv-now`, `nosniff`, `no-referrer` and HSTS (https only) on the response actually returned (after any
 * cache lookup), whoever built it: JSON, binary, streamed, or a caches.default entry (whose stored headers are not
 * trusted to carry them). Responses from caches.default have immutable headers, so they are copied. The 101
 * WebSocket upgrade gets none of these headers: it is returned exactly as the RealtimeDO built it (its headers are
 * immutable, and its HELLO frame carries the server time; §9.7, §10.1). The Worker entries also apply it to the 421
 * of host pinning on /api/v2/* paths, which never reaches handleApi (§10.1: every /api/v2/* response carries
 * x-segv-now).
 */
export function stampResponse(res: Response, url: URL, now = Date.now()): Response {
  if (res.status === 101) return res;
  const stamp = (r: Response): Response => {
    r.headers.set("x-segv-now", String(now));
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) r.headers.set(k, v);
    if (url.protocol === "https:") r.headers.set("strict-transport-security", HSTS);
    return r;
  };
  try {
    return stamp(res);
  } catch {
    return stamp(new Response(res.body, res));
  }
}

/** The extra JSON fields of an HttpError subclass (`extra: {…}`), or null. `error` cannot be overridden. */
function errorExtra(e: HttpError): Record<string, unknown> | null {
  const x = (e as { extra?: unknown }).extra;
  return typeof x === "object" && x !== null && !Array.isArray(x) ? (x as Record<string, unknown>) : null;
}

export async function handleApi(request: Request, env: Env, ctx: ExecutionContext, url: URL): Promise<Response> {
  const now = Date.now();
  let res: Response;
  try {
    const keys = serverKeys(env);
    // Missing secrets, or a deployment var that is present but invalid (e.g. a Δ that does not divide 604 800).
    if (!keys || !v2ParamsValid(env)) throw new HttpError(503, "server misconfigured");
    res = await route({ request, env, ctx, url, now, params: v2Params(env), keys });
  } catch (e) {
    if (e instanceof HttpError) {
      // Any HttpError with an object `extra` (ApiError here, PrefixBitsError in the directory) answers
      // {error, ...extra}, e.g. {error, era} or {error, p}.
      const extra = errorExtra(e);
      res = extra
        ? json(Object.assign({ error: e.message }, extra, { error: e.message }), e.status, e.headers)
        : errorResponse(e.status, e.message, e.headers);
      // Refused before the body was read (PoW, size, rate limit): release it instead of leaving it pending.
      if (request.body !== null && !request.bodyUsed) ctx.waitUntil(request.body.cancel().catch(() => {}));
    } else {
      // Never log request bodies, ids or client addresses.
      console.error(JSON.stringify({ msg: "api error", method: request.method, route: routeLabel(url.pathname), error: logErr(e) }));
      res = errorResponse(500, "internal error");
    }
  }
  return stampResponse(res, url, now);
}

/** Test hook: forget the per-isolate caches (ckpt ensure flag, client-tag key, the directory's cached P). */
export function _resetApiForTests(): void {
  ckptEnsured = false;
  wsKey = null;
  _resetDirectoryCacheForTests();
}

