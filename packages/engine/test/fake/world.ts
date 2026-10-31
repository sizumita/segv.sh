/**
 * FakeWorld: an in-memory stand-in for the segv.sh v2 Worker and its components (docs/PROTOCOL.md §9–§10), served
 * through `fetch` and `FakeWebSocket`. Binary bodies are decoded and encoded with the same
 * `packages/protocol/src/wire.ts` codecs as the Worker, and commitments come from `packages/protocol/src/proto.ts`, so
 * the fake cannot drift from the wire format.
 *
 * Clocks. Server time is `Date.now() + offsetMs` (the Worker, BlobReg, Realtime and Checkpoint components); the
 * shard reads `now − shardLagMs` and the inbox `now − inboxLagMs`. Δ = 1, SKEW = 0, Δin = 1 by default; PoW is 0 for
 * every scope and any (or no) `x-segv-pow` header is accepted. `srvKey` / `SRV_SK` and `ROUTE_KEY` are fixed test
 * keys. `/era/{E}` answers from the world clock alone (`sealed = now ≥ end(E) + SKEW`), as the Worker does.
 *
 * Headers. Every response carries `x-segv-now` (the world clock), `nosniff`, `no-referrer`, and HSTS when the
 * request URL is https, as the Worker stamps them (§9.7, §10.1); the one exception is the 101 of a WebSocket upgrade,
 * which carries none of them (see `FakeWebSocket.upgradeHeaders`). Blob GETs carry `content-length`.
 *
 * Request attribution. Every request and socket may carry a client name `who` (by convention the user's handle):
 *  - `world.fetchAs(who)` / `world.WebSocketAs(who)` / `world.transport(who)` give one client its own fetch and
 *    WebSocket (the engine takes them through its options, so each engine is a separate client), or
 *  - a request carries the header `x-fake-who: <who>` (useful with the global fetch).
 * Unattributed traffic has `who = null`. `who` keys `shard.hide()`, the rate limiter (it stands for the client IP),
 * the per-client socket cap, and `requests[].who` (per-user counters).
 *
 * Worker order (packages/server/src/api.ts). Inbox reads, feed pages, blob routes, /ckpt/{q} and /era/{E} validate
 * their path and query before the rate limiter, as the Worker does; the other routes are rate-limited first. With
 * `cache(true)` the routes the Worker serves from `caches.default` (the inbox tail and ended inbox eras, blob GETs,
 * /ckpt/{q}, immutable feed pages) are answered from a response cache, keyed as the Worker keys them and fresh for the
 * stored response's max-age on the world clock, before the rate limiter (§9.7).
 */
import {
  BLOB_MAX,
  BLOB_MIN,
  ERA_MS,
  H,
  T0_MS,
  b64u,
  era,
  eraEnd,
  eraStart,
  fromB64u,
  kcommit,
  kroute,
  receiptMsg,
  sigPub,
  sign,
  utf8,
  type Bytes,
} from "@segv/protocol/proto";
import {
  GET_BODY_BUDGET,
  GET_MAX_BYTES,
  GET_MAX_KEYS,
  INBOX_MAX_BYTES,
  INBOX_MAX_ROWS,
  INBOX_READ_MAX_LIMIT,
  PUT_MAX_BYTES,
  PUT_MAX_ROWS,
  RT_MAX_TOPICS,
  decodeGetRequest,
  decodeInboxPost,
  decodePutRequest,
  encodeFeed,
  encodeGetResponse,
  encodeInboxRead,
  encodePutResponse,
  type GetKey,
  type GetStatus,
  type PutResult,
  type PutRow,
} from "@segv/protocol/wire";
import { FakeBlobReg, FakeBlobs } from "./blobs";
import { FakeCheckpoints, type CkptEntry } from "./ckpt";
import {
  HSTS,
  IMMUTABLE,
  NO_STORE,
  SECURITY_HEADERS,
  bin,
  err,
  json,
  type FakeParams,
  type PublishRow,
  type Res,
  type WorldCtx,
} from "./common";
import { FakeDirectory } from "./dir";
import { FakeInbox } from "./inbox";
import { FAKE_VAPID, FakePush } from "./push";
import { FakeRealtime, FakeWebSocket, type RtHost } from "./rt";
import { FakeShard } from "./shard";

// ───────────────────────── constants ─────────────────────────

/** Fixed test secrets (ROUTE_KEY and the SRV_SK Ed25519 seed). */
export const TEST_ROUTE_KEY: Bytes = H(utf8("segv.sh/test/route-key"));
export const TEST_SRV_SK: Bytes = H(utf8("segv.sh/test/srv-key"));
/** Header naming the client of a request (see "Request attribution" above). */
export const WHO_HEADER = "x-fake-who";
/** Age of the `x-segv-now` that `staleNow` puts on cacheable responses (three weeks). */
export const STALE_NOW_MS = 21 * 86_400_000;
export const TEXT_MAX = 12000;

export type RlName = "RL_WRITE" | "RL_INBOX" | "RL_BLOB" | "RL_READ";
export interface RateLimit {
  limit: number;
  periodMs: number;
}
/** Production per-IP limits (spec §10.2). */
export const RATE_LIMITS: Readonly<Record<RlName, RateLimit>> = {
  RL_WRITE: { limit: 60, periodMs: 60_000 },
  RL_INBOX: { limit: 10, periodMs: 60_000 },
  RL_BLOB: { limit: 20, periodMs: 60_000 },
  RL_READ: { limit: 600, periodMs: 60_000 },
};

// ───────────────────────── types ─────────────────────────

/** One request as the fake saw it. status 0 = never reached the server (hooks.fail 'before'). */
export interface FakeRequest {
  method: string;
  path: string;
  /** url.search, e.g. "?after=12" */
  query: string;
  who: string | null;
  status: number;
  /** request body bytes */
  reqBytes: number;
  /** response body bytes */
  resBytes: number;
  /** POST /api/v2/put: the per-row results */
  putResults?: PutResult[];
  /** POST /api/v2/get: the keys and their statuses */
  getKeys?: GetKey[];
  getStatuses?: GetStatus[];
  /** served from the response cache (`cache(true)`), before the rate limiter */
  cached?: boolean;
  /** the response was thrown away after the server handled the request (`hooks.afterPut` "lose") */
  lost?: boolean;
}

export type FailMode = "before" | "after" | null | undefined;

export interface FakeHooks {
  /** Runs after a put request parsed, before any row is stored. May await (hold the request) or commit other rows first. */
  beforePut?: (rows: PutRow[], who: string | null) => void | Promise<void>;
  /** After a put was handled: "lose" throws its response away (the rows stay stored), as `fail` "after" does. */
  afterPut?: (rows: PutRow[], results: PutResult[], who: string | null) => "lose" | void;
  /** Network failure: 'before' = never reached the server; 'after' = handled, response lost. */
  fail?: (method: string, path: string, who: string | null) => FailMode;
  /** Runs before any HTTP request is handled (may await to hold it). */
  beforeRequest?: (method: string, path: string, who: string | null) => void | Promise<void>;
}

export interface FakeWorldOptions {
  delta?: number;
  skew?: number;
  inboxSlot?: number;
  efirst?: number;
  /** offer Web Push: params `push` and `pow.push`, and the two endpoints of §10.10 (FakePush) */
  push?: boolean;
}

interface Req {
  method: string;
  url: URL;
  path: string;
  headers: Headers;
  body: Bytes;
  who: string | null;
}

type Handler = (req: Req, m: RegExpExecArray, log: FakeRequest) => Res | Promise<Res>;

interface Route {
  method: string;
  re: RegExp;
  rl: RlName | null;
  h: Handler;
}

// ───────────────────────── small parsers ─────────────────────────

const DEC = /^(0|[1-9]\d{0,15})$/;
/** Query integers as the Worker's intParam reads them (leading zeros allowed). */
const QUERY_INT = /^\d{1,16}$/;
/** A decimal without padding, or null. */
function decimal(s: string | null | undefined): number | null {
  if (s === null || s === undefined || !DEC.test(s)) return null;
  const n = Number(s);
  return Number.isSafeInteger(n) ? n : null;
}
/** An era number (u16 below the reserved 0xFFFF), or null. */
const eraParam = (s: string): number | null => {
  const n = decimal(s);
  return n !== null && n < 0xffff ? n : null;
};
/** Canonical b64u of `len` bytes (or a length within [min, max]), or null. */
function b64Param(s: string | null, min: number, max = min): Bytes | null {
  if (s === null) return null;
  try {
    const b = fromB64u(s);
    return b.length >= min && b.length <= max && b64u(b) === s ? b : null;
  } catch {
    return null;
  }
}
/** Optional query integer in [min, max] with a default; undefined when malformed. */
function queryInt(
  url: URL,
  name: string,
  dflt: number,
  min: number,
  max: number,
): number | undefined {
  const raw = url.searchParams.get(name);
  if (raw === null) return dflt;
  if (!QUERY_INT.test(raw)) return undefined;
  const n = Number(raw);
  return Number.isSafeInteger(n) && n >= min && n <= max ? n : undefined;
}

async function toBytes(body: unknown): Promise<Bytes> {
  if (body === null || body === undefined) return new Uint8Array(0);
  if (typeof body === "string") return utf8(body);
  if (body instanceof ArrayBuffer) return new Uint8Array(body.slice(0));
  if (ArrayBuffer.isView(body))
    return new Uint8Array(body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength));
  if (body instanceof Blob) return new Uint8Array(await body.arrayBuffer());
  if (body instanceof URLSearchParams) return utf8(body.toString());
  throw new TypeError("FakeWorld: unsupported request body");
}

const abortError = (signal: AbortSignal): unknown =>
  signal.reason ?? new DOMException("The operation was aborted.", "AbortError");

function raceAbort<T>(p: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(abortError(signal));
    signal.addEventListener("abort", onAbort, { once: true });
    p.then(
      (v) => {
        signal.removeEventListener("abort", onAbort);
        resolve(v);
      },
      (e) => {
        signal.removeEventListener("abort", onAbort);
        reject(e);
      },
    );
  });
}

/** A request URL the Worker would see as https (a `wss:` upgrade arrives as https). */
const isHttps = (url: string): boolean => {
  try {
    return /^(https|wss):$/.test(new URL(url, "http://segv.test/").protocol);
  } catch {
    return false;
  }
};

const blobHeaders = (etag: string): Record<string, string> => ({
  "content-type": "application/octet-stream",
  etag,
  "content-disposition": "attachment",
  "content-security-policy": "default-src 'none'; sandbox",
  "cross-origin-resource-policy": "same-origin",
});

const ckptJson = (e: CkptEntry) => ({
  q: e.q,
  sec: e.sec,
  hd: b64u(e.hd),
  C: b64u(e.C),
  sig: b64u(e.sig),
  heads: e.heads.map((h) => ({ cid: h.cid, head: b64u(h.head) })),
});

// ───────────────────────── the world ─────────────────────────

export class FakeWorld implements WorldCtx, RtHost {
  // ── clocks and parameters ──
  /** Server time = Date.now() + offsetMs. */
  offsetMs = 0;
  /** The shard clock lags the rest of the server by this much. */
  shardLagMs = 0;
  /**
   * The inbox clock lags the rest of the server by this much: the InboxDO's era window, `ended`, `closed`, `rel` and
   * day index read `now − inboxLagMs`, while the Worker's era bounds and 410 in front of it read the world clock.
   */
  inboxLagMs = 0;
  /** An ended era's shard seals at end(E) + SKEW + sealDelayMs (see also sealPrevious()). */
  sealDelayMs = 0;
  /** Cacheable (`public`) responses carry an `x-segv-now` `staleNowAgeMs` old, as a browser cache would replay it. */
  staleNow = false;
  staleNowAgeMs = STALE_NOW_MS;
  readonly params: FakeParams;

  // ── keys ──
  readonly routeKey: Bytes = TEST_ROUTE_KEY;
  readonly srvSk: Bytes = TEST_SRV_SK;
  readonly srvKey: Bytes = sigPub(TEST_SRV_SK);

  // ── components ──
  readonly shard: FakeShard;
  readonly blobreg: FakeBlobReg;
  readonly blobs = new FakeBlobs();
  readonly inbox: FakeInbox;
  readonly rt: FakeRealtime;
  readonly dir: FakeDirectory;
  readonly ckpt: FakeCheckpoints;
  /** Web Push (only routed while `pushOn`) */
  readonly push = new FakePush();
  pushOn: boolean;

  // ── observation and hooks ──
  /** Every HTTP request and WebSocket upgrade, in arrival order. */
  readonly requests: FakeRequest[] = [];
  hooks: FakeHooks = {};
  /** Accepted writes of every component (rows, invites, registrations, directory entries). */
  writeCount = 0;

  private limits: Record<RlName, RateLimit> | null = null;
  private readonly rlLog = new Map<string, number[]>();
  /** caches.default (null: off) */
  private respCache: Map<string, { res: Res; at: number; ttlMs: number }> | null = null;
  private readonly routes: Route[];

  constructor(opts: FakeWorldOptions = {}) {
    this.params = {
      delta: opts.delta ?? 1,
      skew: opts.skew ?? 0,
      inboxSlot: opts.inboxSlot ?? 1,
      efirst: opts.efirst ?? 0,
    };
    this.pushOn = opts.push ?? false;
    this.shard = new FakeShard(this);
    this.blobreg = new FakeBlobReg(this);
    this.inbox = new FakeInbox(this);
    this.rt = new FakeRealtime(this);
    this.dir = new FakeDirectory(this);
    this.ckpt = new FakeCheckpoints(
      {
        now: () => this.now(),
        efirst: () => this.params.efirst,
        shardHead: (E) => this.shard.head(E),
        inboxHead: (E) => this.inbox.head(E),
        blobregHead: () => this.blobreg.head().head,
        dirlogHead: () => this.dir.head().h,
      },
      this.srvSk,
    );
    this.routes = this.routeTable();
  }

  // ───────────── clock ─────────────

  now(): number {
    return Date.now() + this.offsetMs;
  }

  shardNow(): number {
    return this.now() - this.shardLagMs;
  }

  inboxNow(): number {
    return this.now() - this.inboxLagMs;
  }

  /** era(server now) */
  get era(): number {
    return era(this.now());
  }

  /**
   * Moves server time by `ms` (negative = a clock step back). Closes every FakeWebSocket (code 1001) so engines
   * reconnect and see a fresh HELLO, unless `keepSockets`.
   */
  advance(ms: number, opts: { keepSockets?: boolean } = {}): void {
    this.offsetMs += ms;
    if (!opts.keepSockets) this.rt.closeAll(1001, "clock moved");
  }

  /**
   * Clocks that `tick` moves with the world: the engines' clocks (packages/engine/test/harness.ts registers each
   * engine's TestClock here). `advance` and `advanceEra` leave them alone.
   */
  readonly clocks = new Set<{ advance(ms: number): void }>();

  /**
   * Moves the world **and** every registered engine clock (monotonic and wall) by `ms`, firing the engine timers
   * that fall due; sockets stay open. This is what settle uses.
   */
  tick(ms: number): void {
    if (!Number.isFinite(ms) || ms < 0) throw new RangeError("tick: ms must be ≥ 0");
    this.offsetMs += ms;
    for (const c of this.clocks) c.advance(ms);
  }

  /** Moves server time to the start of era `E_now + n`, plus 1 s; closes every FakeWebSocket. Returns the new era. */
  advanceEra(n = 1, opts: { keepSockets?: boolean } = {}): number {
    const now = this.now();
    this.offsetMs += eraStart(era(now) + n) + 1000 - now;
    if (!opts.keepSockets) this.rt.closeAll(1001, "new era");
    return this.era;
  }

  /** Seals every shard era before the shard clock's current era (use with a large `sealDelayMs`). */
  sealPrevious(): void {
    this.shard.sealPrevious();
  }

  // ───────────── knobs ─────────────

  /**
   * Per-client rate limits answering 429 with `retry-after` (off by default). `true` = the production limits of
   * spec §10.2; an object overrides some of them. Windows slide on the server clock.
   */
  rateLimits(on: boolean | Partial<Record<RlName, { limit: number; periodMs?: number }>>): void {
    this.rlLog.clear();
    if (on === false) {
      this.limits = null;
      return;
    }
    const l = { ...RATE_LIMITS };
    if (on !== true) {
      for (const [k, v] of Object.entries(on) as [RlName, { limit: number; periodMs?: number }][])
        l[k] = { limit: v.limit, periodMs: v.periodMs ?? 60_000 };
    }
    this.limits = l;
  }

  /**
   * The Worker's `caches.default` (off by default). `cache(true)` empties and enables it, `cache(false)` disables
   * it. While on, 200 responses of the inbox read (`public, max-age=Δin`, or immutable once the era ended), blob
   * GET, /ckpt/{q} and immutable feed routes are stored under the Worker's keys and served, without counting toward
   * the rate limiter, until their max-age has passed on the world clock. Served hits are logged with `cached: true`.
   */
  cache(on: boolean): void {
    this.respCache = on ? new Map() : null;
  }

  /** false: new realtime sockets fail to connect and every publish is lost. */
  get wsEnabled(): boolean {
    return this.rt.enabled;
  }
  set wsEnabled(on: boolean) {
    this.rt.enabled = on;
  }

  /** Stores and registers a blob, like `PUT /api/v2/blob/{id}` without the HTTP layer. */
  putBlob(bytes: Bytes): { id: string; size: number; t: number } {
    const id = this.blobs.put(bytes);
    const r = this.blobreg.register(fromB64u(id), bytes.length);
    return { id, size: r.size, t: r.t };
  }

  kcommitOf(E: number): Bytes {
    return kcommit(kroute(this.routeKey, E));
  }

  /** Closes every socket (end of a test). */
  close(): void {
    this.rt.closeAll(1001, "world closed");
  }

  // ───────────── transports ─────────────

  /** A fetch whose requests are attributed to `who`. */
  fetchAs(who: string | null): typeof fetch {
    return ((input: RequestInfo | URL, init?: RequestInit) =>
      this.fetch(input, init, who)) as typeof fetch;
  }

  /** A WebSocket class whose sockets connect to this world as `who`. */
  WebSocketAs(who: string | null): typeof FakeWebSocket {
    return FakeWebSocket.bind(this, who);
  }

  /** fetch + WebSocket for one client (what the engine's options take). */
  transport(who: string | null): { fetch: typeof fetch; WebSocket: typeof FakeWebSocket } {
    return { fetch: this.fetchAs(who), WebSocket: this.WebSocketAs(who) };
  }

  // ───────────── WorldCtx / RtHost plumbing ─────────────

  /** (internal) WorldCtx */
  bumpWrites(): void {
    this.writeCount++;
  }

  /** (internal) WorldCtx: RealtimeDO.publish. */
  publish(rows: PublishRow[]): void {
    this.rt.publish(rows);
  }

  /**
   * (internal) RtHost: the Worker's handling of `GET /api/v2/rt` with an upgrade. A 101 is the RealtimeDO's response
   * passed on unchanged, so it carries none of the per-response headers (§9.7, §10.1: HELLO carries the time); a
   * refusal is an error response like any other: 404 for another path, 429 from RL_READ or the per-client cap, 503
   * at the global cap or while `wsEnabled` is false.
   */
  rtUpgrade(ws: FakeWebSocket): { status: number; headers: Headers | null } {
    const entry: FakeRequest = {
      method: "GET",
      path: ws.path,
      query: "",
      who: ws.who,
      status: 0,
      reqBytes: 0,
      resBytes: 0,
    };
    this.requests.push(entry);
    const fail = this.hooks.fail?.("GET", ws.path, ws.who);
    if (fail === "before") return { status: 0, headers: null };
    const refusal =
      ws.path !== "/api/v2/rt"
        ? err(404, `not found: GET ${ws.path}`)
        : (this.rateLimit("RL_READ", ws.who) ?? this.admitRefusal(this.rt.admit(ws)));
    let out: { status: number; headers: Headers };
    if (refusal) {
      out = {
        status: refusal.status,
        headers: this.respond(refusal, entry, isHttps(ws.url)).headers,
      };
    } else {
      entry.status = 101;
      out = { status: 101, headers: new Headers() };
    }
    return fail === "after" ? { status: 0, headers: null } : out;
  }

  /** The Worker's answer to a RealtimeDO refusal (the DO's status, error and `retry-after`); null for a 101. */
  private admitRefusal(status: number): Res | null {
    if (status === 101) return null;
    const retry = { "retry-after": "60" };
    if (status === 429) return err(429, "too many connections from this client", undefined, retry);
    return this.rt.enabled
      ? err(503, "too many connections", undefined, retry)
      : err(503, "realtime unavailable");
  }

  /** (internal) RtHost */
  isHidden(E: number, label: Bytes, who: string | null): boolean {
    return this.shard.isHidden(E, label, who);
  }

  // ───────────── HTTP ─────────────

  /** The fake Worker. `who` (or the `x-fake-who` header) attributes the request to a client. */
  async fetch(
    input: RequestInfo | URL,
    init: RequestInit = {},
    who?: string | null,
  ): Promise<Response> {
    const isReq = typeof Request !== "undefined" && input instanceof Request;
    const url = new URL(isReq ? (input as Request).url : String(input), "http://segv.test/");
    const method = (init.method ?? (isReq ? (input as Request).method : "GET")).toUpperCase();
    const headers = new Headers(isReq ? (input as Request).headers : undefined);
    new Headers(init.headers).forEach((v, k) => headers.set(k, v));
    const body = await toBytes(
      init.body ?? (isReq ? await (input as Request).arrayBuffer() : null),
    );
    const req: Req = {
      method,
      url,
      path: url.pathname,
      headers,
      body,
      who: who !== undefined ? who : headers.get(WHO_HEADER),
    };
    const entry: FakeRequest = {
      method,
      path: req.path,
      query: url.search,
      who: req.who,
      status: 0,
      reqBytes: body.length,
      resBytes: 0,
    };
    this.requests.push(entry);
    const signal = init.signal ?? (isReq ? (input as Request).signal : undefined);
    if (signal?.aborted) throw abortError(signal);
    const fail = this.hooks.fail?.(method, req.path, req.who);
    if (fail === "before") throw new TypeError("Failed to fetch");
    const run = (async () => {
      await this.hooks.beforeRequest?.(method, req.path, req.who);
      await Promise.resolve();
      // The Worker takes x-segv-now when it starts handling the request (§10.1), not when it answers.
      const startNow = this.now();
      let res: Res;
      try {
        res = await this.handle(req, entry);
      } catch (e) {
        res = err(500, `fake server error: ${e instanceof Error ? e.message : String(e)}`);
      }
      return this.respond(res, entry, url.protocol === "https:", startNow);
    })();
    const response = signal ? await raceAbort(run, signal) : await run;
    if (fail === "after" || entry.lost)
      throw new TypeError("Failed to fetch (response lost after the server handled the request)");
    return response;
  }

  private async handle(req: Req, entry: FakeRequest): Promise<Res> {
    const matched = this.routes.filter((r) => r.re.test(req.path));
    if (matched.length === 0) return err(404, `not found: ${req.method} ${req.path}`);
    const route = matched.find((r) => r.method === req.method);
    if (!route)
      return err(405, "method not allowed", undefined, {
        allow: [...new Set(matched.map((r) => r.method))].join(", "),
      });
    if (route.rl) {
      const limited = this.rateLimit(route.rl, req.who);
      if (limited) return limited;
    }
    return route.h(req, route.re.exec(req.path)!, entry);
  }

  /**
   * The Response actually returned, with the headers the Worker puts on every response but the 101 upgrade:
   * `cache-control`, `nosniff`, `no-referrer`, HSTS on https, and `x-segv-now` = `nowMs`, the world time when the
   * request started being handled (§9.7, §10.1).
   */
  private respond(res: Res, entry: FakeRequest, https: boolean, nowMs = this.now()): Response {
    const cache = res.cache ?? NO_STORE;
    const headers = new Headers({ "cache-control": cache, ...SECURITY_HEADERS });
    if (https) headers.set("strict-transport-security", HSTS);
    let body: Bytes | null = null;
    if (res.bytes) {
      body = res.bytes;
      headers.set("content-type", "application/octet-stream");
    } else if (res.json !== undefined) {
      body = utf8(JSON.stringify(res.json));
      headers.set("content-type", "application/json; charset=utf-8");
    }
    for (const [k, v] of Object.entries(res.headers ?? {})) headers.set(k, v);
    // Stamped on the response actually returned; a cacheable response may be a stale replay (spec §10.1).
    const stale = this.staleNow && cache.startsWith("public");
    headers.set("x-segv-now", String(nowMs - (stale ? this.staleNowAgeMs : 0)));
    entry.status = res.status;
    entry.resBytes = body?.length ?? 0;
    const nullBody = res.status === 204 || res.status === 304;
    return new Response(nullBody ? null : (body as BodyInit | null), {
      status: res.status,
      headers,
    });
  }

  /** null when allowed (and counted), else the 429 response. */
  private rateLimit(name: RlName, who: string | null): Res | null {
    if (!this.limits) return null;
    const { limit, periodMs } = this.limits[name];
    const key = `${name}|${who ?? ""}`;
    const now = this.now();
    const log = (this.rlLog.get(key) ?? []).filter((t) => now - t < periodMs);
    this.rlLog.set(key, log);
    if (log.length >= limit) {
      // With limit 0 nothing was counted: a whole window.
      const freeAt = (log.length > 0 ? log[0] : now) + periodMs;
      const retry = Math.max(1, Math.ceil((freeAt - now) / 1000));
      return err(429, "rate limited", undefined, { "retry-after": String(retry) });
    }
    log.push(now);
    return null;
  }

  /** A fresh response-cache entry under `key`, or null (a stale one is dropped). */
  private cacheGet(key: string, log: FakeRequest): Res | null {
    const e = this.respCache?.get(key);
    if (!e) return null;
    const age = this.now() - e.at;
    if (age < 0 || age >= e.ttlMs) {
      this.respCache!.delete(key);
      return null;
    }
    log.cached = true;
    return e.res;
  }

  /** Stores a 200 whose cache-control has a max-age (when the cache is on). */
  private cachePut(key: string, res: Res): void {
    if (!this.respCache || res.status !== 200) return;
    const m = /(?:^|[\s,])max-age=(\d+)/.exec(res.cache ?? "");
    if (m) this.respCache.set(key, { res, at: this.now(), ttlMs: Number(m[1]) * 1000 });
  }

  /**
   * The Worker's cacheable read (§9.7 "cache before limits"): a cache hit under `key`, else RL_READ, then
   * `compute()`, whose response is stored when `store(res)` holds.
   */
  private cachedRead(
    req: Req,
    log: FakeRequest,
    key: string,
    compute: () => Res,
    store: (res: Res) => boolean = () => true,
  ): Res {
    const hit = this.cacheGet(key, log);
    if (hit) return hit;
    const limited = this.rateLimit("RL_READ", req.who);
    if (limited) return limited;
    const res = compute();
    if (store(res)) this.cachePut(key, res);
    return res;
  }

  /** The Worker's era bounds (§9.7): lo = era(now − SKEW), hi = era(now + SKEW). */
  private bounds(now = this.now()): { cur: number; lo: number; hi: number } {
    const s = this.params.skew * 1000;
    return { cur: era(now), lo: era(now - s), hi: era(now + s) };
  }

  // ───────────── routes ─────────────

  private routeTable(): Route[] {
    const r = (method: string, re: RegExp, rl: RlName | null, h: Handler): Route => ({
      method,
      re,
      rl,
      h,
    });
    return [
      r("GET", /^\/api\/v2\/params$/, null, () => this.getParams()),
      r("GET", /^\/api\/v2\/era\/(\d{1,6})$/, null, (q, m) => this.getEra(q, m[1])),
      r("POST", /^\/api\/v2\/put$/, "RL_WRITE", (q, _m, log) => this.postPut(q, log)),
      r("POST", /^\/api\/v2\/get$/, "RL_READ", (q, _m, log) => this.postGet(q, log)),
      r("POST", /^\/api\/v2\/inbox$/, "RL_INBOX", (q) => this.postInbox(q)),
      r("GET", /^\/api\/v2\/inbox\/(\d{1,6})\/(\d{1,10})$/, null, (q, m, log) =>
        this.getInbox(q, m[1], m[2], log),
      ),
      r("PUT", /^\/api\/v2\/blob\/([^/]+)$/, null, (q, m) => this.putBlobRoute(q, m[1])),
      r("GET", /^\/api\/v2\/blob\/([^/]+)$/, null, (q, m, log) => this.getBlob(q, m[1], log)),
      r("GET", /^\/api\/v2\/blob\/([^/]+)\/meta$/, null, (q, m) => this.getBlobMeta(q, m[1])),
      r("GET", /^\/api\/v2\/rt$/, "RL_READ", () => err(426, "expected a WebSocket upgrade")),
      r("GET", /^\/api\/v2\/ckpt\/latest$/, "RL_READ", () => this.getCkptLatest()),
      r("GET", /^\/api\/v2\/ckpt\/range$/, "RL_READ", (q) => this.getCkptRange(q)),
      r("GET", /^\/api\/v2\/ckpt\/(\d{1,10})$/, null, (q, m, log) => this.getCkpt(q, m[1], log)),
      r("GET", /^\/api\/v2\/feed\/(\d{1,6})\/(\d{1,6})$/, null, (q, m, log) =>
        this.getFeed(q, m[1], m[2], log),
      ),
      r("POST", /^\/api\/v2\/register$/, "RL_WRITE", (q) =>
        this.jsonBody(q, 64 * 1024, (b) => this.dir.register(b)),
      ),
      r("POST", /^\/api\/v2\/wraps$/, "RL_WRITE", (q) =>
        this.jsonBody(q, 16 * 1024, (b) => this.dir.postWrap(b)),
      ),
      r("GET", /^\/api\/v2\/dir\/(h|u)\/([^/]+)\/([^/]+)$/, "RL_READ", (q, m) =>
        this.getDirPrefix(q, m[1] as "h" | "u", m[2], m[3]),
      ),
      r("GET", /^\/api\/v2\/dir\/uid\/([^/]+)$/, "RL_READ", (_q, m) => this.getDirUid(m[1])),
      r("GET", /^\/api\/v2\/dir\/wraps\/([^/]+)$/, "RL_READ", (q, m) => this.getDirWraps(q, m[1])),
      r("GET", /^\/api\/v2\/dirlog$/, "RL_READ", (q) => this.getDirlog(q)),
      r("POST", /^\/api\/v2\/push\/sub$/, "RL_WRITE", (q) => this.postPushSub(q)),
      r("POST", /^\/api\/v2\/ring$/, null, (q) => this.postRing(q)),
      r("POST", /^\/api\/v2\/seen$/, null, (q) => this.postSeen(q)),
    ];
  }

  /** GET /api/v2/params (§10.9; not rate limited). */
  private getParams(): Res {
    const now = this.now();
    const E = era(now);
    const p = this.params;
    return json(200, {
      v: 2,
      now,
      T0: T0_MS,
      eraMs: ERA_MS,
      era: E,
      delta: p.delta,
      skew: p.skew,
      inboxSlot: p.inboxSlot,
      inboxRetention: 4,
      inboxDayCap: this.inbox.dayCap,
      inboxBatch: INBOX_MAX_ROWS,
      shards: 1,
      p: this.dir.P,
      efirst: p.efirst,
      kcommit: b64u(this.kcommitOf(E)),
      srvKey: b64u(this.srvKey),
      pow: { register: 0, wrap: 0, put: 0, inbox: 0, blob: 0, ...(this.pushOn ? { push: 0 } : {}) },
      limits: {
        putRows: PUT_MAX_ROWS,
        putBytes: PUT_MAX_BYTES,
        getKeys: GET_MAX_KEYS,
        topics: RT_MAX_TOPICS,
        blobMax: BLOB_MAX,
        textMax: TEXT_MAX,
      },
      ...(this.pushOn ? { push: { vapid: b64u(FAKE_VAPID), window: 60, maxTokens: 256 } } : {}),
    });
  }

  /** POST /api/v2/push/sub (§10.10): the body's shape only; 404 while push is off. */
  private postPushSub(req: Req): Res {
    if (!this.pushOn) return err(404, `not found: ${req.method} ${req.path}`);
    return this.jsonBody(req, 16 * 1024, (b) => {
      const o = b as { endpoint?: unknown; tokens?: unknown; quiet?: unknown };
      if (typeof o.endpoint !== "string" || !Array.isArray(o.tokens))
        return err(400, "bad push subscription");
      if (o.quiet !== undefined && (typeof o.quiet !== "string" || fromB64u(o.quiet).length !== 16))
        return err(400, "bad quiet tag");
      this.push.sub(o.endpoint, o.tokens as string[], (o.quiet as string | undefined) ?? null);
      return { status: 204 };
    });
  }

  /** POST /api/v2/ring (§10.10): 204 for any well-formed body; only a row stored in the last minute pushes. */
  private postRing(req: Req): Res {
    if (!this.pushOn) return err(404, `not found: ${req.method} ${req.path}`);
    const b = req.body;
    const n = b[19];
    if (b.length < 20 || b[0] !== 1 || n < 1 || n > 64 || b.length !== 20 + 16 * n)
      return err(400, "bad ring");
    const E = (b[1] << 8) | b[2];
    const label = b.slice(3, 19);
    const tokens = Array.from({ length: n }, (_, i) => b.slice(20 + 16 * i, 36 + 16 * i));
    const row = this.shard.row(E, label);
    const fresh =
      row !== undefined &&
      row.t + this.params.delta >= Math.floor((this.now() - T0_MS) / 1000) - 60;
    this.push.ring(E, label, tokens, fresh);
    return { status: 204 };
  }

  /** POST /api/v2/seen (§10.10): 204 for any well-formed body; marks rows for the account whose tag the secret hashes to. */
  private postSeen(req: Req): Res {
    if (!this.pushOn) return err(404, `not found: ${req.method} ${req.path}`);
    const b = req.body;
    const n = b[17];
    if (b.length < 18 || b[0] !== 1 || n < 1 || n > 16 || b.length !== 18 + 18 * n)
      return err(400, "bad seen");
    const rows = Array.from({ length: n }, (_, i) => {
      const o = 18 + 18 * i;
      return { E: (b[o] << 8) | b[o + 1], label: b.slice(o + 2, o + 18) };
    });
    this.push.seen(b.slice(1, 17), rows);
    return { status: 204 };
  }

  /**
   * GET /api/v2/era/{E} (§10.9), answered from the world clock alone, as the Worker does (it addresses no Durable
   * Object): `sealed = now ≥ end(E) + SKEW·1000`, immutable once sealed. It does not follow the shard fake
   * (`sealDelayMs`, `sealPrevious()`, `shardLagMs`). The era is parsed before RL_READ, as the Worker does.
   */
  private getEra(req: Req, s: string): Res {
    const E = eraParam(s);
    if (E === null) return err(400, "bad era");
    const limited = this.rateLimit("RL_READ", req.who);
    if (limited) return limited;
    const now = this.now();
    if (E > this.bounds(now).hi || E < this.params.efirst) return err(404, "unknown era");
    const sealed = now >= eraEnd(E) + this.params.skew * 1000;
    return json(
      200,
      {
        era: E,
        start: eraStart(E),
        end: eraEnd(E),
        delta: this.params.delta,
        shards: 1,
        kcommit: b64u(this.kcommitOf(E)),
        sealed,
      },
      { cache: sealed ? IMMUTABLE : NO_STORE },
    );
  }

  /** POST /api/v2/put (§10.3). */
  private async postPut(req: Req, log: FakeRequest): Promise<Res> {
    if (req.body.length > PUT_MAX_BYTES) return err(413, "request body too large");
    let rows: PutRow[];
    try {
      rows = decodePutRequest(req.body);
    } catch (e) {
      return err(400, `bad put request (${(e as Error).message})`);
    }
    await this.hooks.beforePut?.(rows, req.who);
    const { cur, lo, hi } = this.bounds();
    const results = Array.from({ length: rows.length }) as PutResult[];
    const groups = new Map<number, number[]>();
    rows.forEach((r, i) => {
      if (r.E < lo || r.E > hi) results[i] = { s: "wrong_era", era: cur };
      else {
        const g = groups.get(r.E);
        if (g) g.push(i);
        else groups.set(r.E, [i]);
      }
    });
    for (const [E, idx] of groups) {
      const out = this.shard.put(
        E,
        idx.map((i) => rows[i]),
      );
      idx.forEach((i, j) => {
        const o = out[j];
        results[i] =
          o.s === "ok"
            ? {
                s: "ok",
                t: o.t,
                receipt: sign(receiptMsg(E, rows[i].label, rows[i].body, o.t), this.srvSk),
              }
            : o;
      });
    }
    // The Worker publishes OK rows that carry a topic (through waitUntil: never delays or changes the response).
    const pub: PublishRow[] = [];
    rows.forEach((r, i) => {
      const x = results[i];
      if (x.s === "ok" && r.topic.some((b) => b !== 0))
        pub.push({ topic: r.topic, E: r.E, label: r.label, t: x.t, cls: r.cls, body: r.body });
    });
    this.rt.publish(pub);
    log.putResults = results;
    if (this.hooks.afterPut?.(rows, results, req.who) === "lose") log.lost = true;
    return bin(encodePutResponse(results));
  }

  /** POST /api/v2/get (§10.4). */
  private postGet(req: Req, log: FakeRequest): Res {
    if (req.body.length > GET_MAX_BYTES) return err(413, "request body too large");
    let keys: GetKey[];
    try {
      keys = decodeGetRequest(req.body);
    } catch (e) {
      return err(400, `bad get request (${(e as Error).message})`);
    }
    const { hi } = this.bounds();
    const statuses = Array.from({ length: keys.length }) as GetStatus[];
    const groups = new Map<number, number[]>();
    keys.forEach((k, i) => {
      if (k.E > hi) statuses[i] = { s: "no_era" };
      else if (k.E < this.params.efirst) statuses[i] = { s: "miss", sealed: true };
      else {
        const g = groups.get(k.E);
        if (g) g.push(i);
        else groups.set(k.E, [i]);
      }
    });
    for (const [E, idx] of groups) {
      const out = this.shard.get(
        E,
        idx.map((i) => keys[i]),
        req.who,
      );
      idx.forEach((i, j) => (statuses[i] = out[j]));
    }
    // Response budget: body-mode keys whose body would pass 4 MiB of bodies are SKIPPED.
    let bytes = 0;
    keys.forEach((k, i) => {
      const x = statuses[i];
      if (k.mode !== 0 || x.s !== "hit" || !x.body) return;
      if (bytes + x.body.length > GET_BODY_BUDGET) statuses[i] = { s: "skipped" };
      else bytes += x.body.length;
    });
    log.getKeys = keys;
    log.getStatuses = statuses;
    return bin(
      encodeGetResponse(
        statuses,
        keys.map((k) => k.mode),
      ),
    );
  }

  /** POST /api/v2/inbox (§10.5). */
  private postInbox(req: Req): Res {
    if (req.body.length > INBOX_MAX_BYTES) return err(413, "request body too large");
    let p;
    try {
      p = decodeInboxPost(req.body);
    } catch (e) {
      return err(400, `bad inbox post (${(e as Error).message})`);
    }
    if (p.bucket !== 0) return err(400, "bad bucket");
    const { cur, lo, hi } = this.bounds();
    if (p.E < lo || p.E > hi) return err(409, "wrong era", { era: cur });
    const out = this.inbox.accept(p.E, p.rows);
    if (out.s === "wrong_era") return err(409, "wrong era", { era: out.era });
    return json(200, { results: out.results });
  }

  /**
   * GET /api/v2/inbox/{E}/{bucket}?after=&limit= (§10.5), in the Worker's order: bucket, era bounds, 410, E_FIRST,
   * query; then the cache (keyed by E, bucket, after, limit), RL_READ and the read.
   */
  private getInbox(req: Req, eS: string, bS: string, log: FakeRequest): Res {
    const E = eraParam(eS);
    const bucket = decimal(bS);
    if (E === null || bucket === null) return err(400, "bad era or bucket");
    if (bucket !== 0) return err(400, "unknown bucket");
    const { cur, hi } = this.bounds();
    if (E > hi) return err(400, "era is in the future");
    if (E < cur - 3) return err(410, "inbox era no longer served");
    if (E < this.params.efirst) return err(404, "unknown era");
    const after = queryInt(req.url, "after", 0, 0, 0xffffffff);
    const limit = queryInt(req.url, "limit", INBOX_READ_MAX_LIMIT, 1, INBOX_READ_MAX_LIMIT);
    if (after === undefined || limit === undefined) return err(400, "bad after or limit");
    const key = `${req.url.origin}/api/v2/inbox/${E}/${bucket}?after=${after}&limit=${limit}`;
    return this.cachedRead(req, log, key, () => {
      const r = this.inbox.read(E, after, limit);
      const cache = r.ended && !r.more ? IMMUTABLE : `public, max-age=${this.params.inboxSlot}`;
      return bin(encodeInboxRead({ closed: r.closed, more: r.more, rows: r.rows }), { cache });
    });
  }

  /** PUT /api/v2/blob/{id} (§10.7). The id is checked before RL_BLOB, as the Worker does. */
  private putBlobRoute(req: Req, idS: string): Res {
    const id = b64Param(idS, 32);
    if (!id) return err(400, "bad blob id");
    const limited = this.rateLimit("RL_BLOB", req.who);
    if (limited) return limited;
    const declared = decimal(req.headers.get("content-length"));
    if (declared !== null && declared > BLOB_MAX) return err(413, "blob too large");
    const reg = this.blobreg.get(idS);
    if (reg) return json(201, { id: idS, size: reg.size, t: reg.t });
    if (req.body.length > BLOB_MAX) return err(413, "blob too large");
    if (req.body.length < BLOB_MIN) return err(400, "blob too small");
    if (b64u(H(req.body)) !== idS) return err(400, "content does not match the id");
    this.blobs.put(req.body);
    const r = this.blobreg.register(id, req.body.length);
    return json(201, { id: idS, size: r.size, t: r.t });
  }

  /**
   * GET /api/v2/blob/{id}: raw bytes, `public, immutable`, with `content-length` = the byte length (the Worker sets
   * it from the R2 object's size; `new Response(Uint8Array)` adds none). Id check, then the cache (If-None-Match
   * answered from a hit with 304), RL_READ, the bucket.
   */
  private getBlob(req: Req, idS: string, log: FakeRequest): Res {
    if (!b64Param(idS, 32)) return err(400, "bad blob id");
    const key = `${req.url.origin}/api/v2/blob/${idS}`;
    const inm = req.headers.get("if-none-match");
    const hit = this.cacheGet(key, log);
    if (hit) {
      const etag = hit.headers?.etag;
      if (inm !== null && etag !== undefined && inm === etag)
        return { status: 304, cache: IMMUTABLE, headers: blobHeaders(etag) };
      return hit;
    }
    const limited = this.rateLimit("RL_READ", req.who);
    if (limited) return limited;
    if (this.blobs.takeFailure(idS)) return err(503, "storage unavailable");
    const bytes = this.blobs.bytes(idS);
    if (!bytes) return err(404, "no such blob");
    const etag = `"${idS}"`;
    if (inm === etag) return { status: 304, cache: IMMUTABLE, headers: blobHeaders(etag) };
    const res = bin(bytes, {
      cache: IMMUTABLE,
      headers: { ...blobHeaders(etag), "content-length": String(bytes.length) },
    });
    this.cachePut(key, res);
    return res;
  }

  /**
   * GET /api/v2/blob/{id}/meta: `{t, size}` or 404 `{error: "unregistered", now}` (no-store); id check, then RL_READ,
   * then the BlobReg call (503 while `blobreg.failMeta` holds failures for the id).
   */
  private getBlobMeta(req: Req, idS: string): Res {
    if (!b64Param(idS, 32)) return err(400, "bad blob id");
    const limited = this.rateLimit("RL_READ", req.who);
    if (limited) return limited;
    if (this.blobreg.takeMetaFailure(idS)) return err(503, "storage unavailable");
    const m = this.blobreg.meta(idS);
    return m.hit ? json(200, { t: m.t, size: m.size }) : err(404, "unregistered", { now: m.now });
  }

  private getCkptLatest(): Res {
    const e = this.ckpt.latest();
    return e ? json(200, ckptJson(e)) : err(404, "no checkpoint yet");
  }

  /** GET /api/v2/ckpt/{q}: q is checked (400, q = 0 → 404), then the cache, RL_READ, the checkpoint. */
  private getCkpt(req: Req, qS: string, log: FakeRequest): Res {
    const q = decimal(qS);
    if (q === null || q > 0xffffffff) return err(400, "invalid checkpoint");
    if (q < 1) return err(404, "unknown checkpoint");
    return this.cachedRead(req, log, `${req.url.origin}/api/v2/ckpt/${q}`, () => {
      const e = this.ckpt.get(q);
      return e ? json(200, ckptJson(e), { cache: IMMUTABLE }) : err(404, "unknown checkpoint");
    });
  }

  /** GET /api/v2/ckpt/range?after=&limit=1..1440 (§10.9). */
  private getCkptRange(req: Req): Res {
    const after = queryInt(req.url, "after", 0, 0, 0xffffffff);
    const limit = queryInt(req.url, "limit", 1440, 1, 1440);
    if (after === undefined || limit === undefined) return err(400, "bad after or limit");
    const latest = this.ckpt.latest();
    const fromC = this.ckpt.C(after);
    if (!latest || !fromC || after > latest.q) return err(404, "unknown checkpoint");
    const entries: { q: number; sec: number; hd: string }[] = [];
    for (let q = after + 1; q <= Math.min(latest.q, after + limit); q++) {
      const e = this.ckpt.get(q)!;
      entries.push({ q, sec: e.sec, hd: b64u(e.hd) });
    }
    return json(200, {
      from: { q: after, C: b64u(fromC) },
      entries,
      latest: { q: latest.q, C: b64u(latest.C), sig: b64u(latest.sig) },
    });
  }

  /** GET /api/v2/feed/{E}/{i}?after=<t> (§10.9): checks, then the cache (immutable pages only), RL_READ, the page. */
  private getFeed(req: Req, eS: string, iS: string, log: FakeRequest): Res {
    const E = eraParam(eS);
    const i = decimal(iS);
    if (E === null || i === null || i > 0xffff) return err(400, "bad era or shard");
    if (i !== 0 || E > this.bounds().hi || E < this.params.efirst) return err(404, "unknown shard");
    const after = queryInt(req.url, "after", 0, 0, 0xffffffff);
    if (after === undefined) return err(400, "bad after");
    const key = `${req.url.origin}/api/v2/feed/${E}/${i}?after=${after}`;
    return this.cachedRead(
      req,
      log,
      key,
      () => {
        const page = this.shard.feed(E, after);
        const bytes = encodeFeed({
          more: page.more,
          batches: page.batches.map((b) => ({
            t: b.t,
            n: b.n,
            root: b.root,
            head: b.head,
            rows: b.rows.map((x) => ({ label: x.label, cls: x.cls, body: x.body })),
          })),
        });
        return bin(bytes, { cache: page.more || page.sealed ? IMMUTABLE : NO_STORE });
      },
      (res) => res.cache === IMMUTABLE,
    );
  }

  private jsonBody(req: Req, max: number, h: (body: unknown) => Res): Res {
    if (req.body.length > max) return err(413, "request body too large");
    let body: unknown;
    try {
      body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(req.body));
    } catch {
      return err(400, "malformed JSON");
    }
    return h(body);
  }

  /**
   * GET /api/v2/dir/{h|u}/{p}/{x}[?after=uid] (§10.6): RL_READ, the path and query checks, then D1 (503 while a
   * `dir.failDir` rule matches), then the prefix-bits check (409) and the page.
   */
  private getDirPrefix(req: Req, kind: "h" | "u", pS: string, xS: string): Res {
    const p = decimal(pS);
    const x = decimal(xS);
    if (p === null || p > 32 || x === null || x >= 2 ** p) return err(400, "bad prefix");
    const afterS = req.url.searchParams.get("after");
    if (afterS !== null && !b64Param(afterS, 16)) return err(400, "bad after");
    if (this.dir.takeDirFailure({ kind, p, x, after: afterS, who: req.who }))
      return err(503, "directory unavailable");
    return this.dir.byPrefix(kind, p, x, afterS);
  }

  /** GET /api/v2/dir/uid/{uid}: the exact own-account lookup. */
  private getDirUid(uidS: string): Res {
    if (!b64Param(uidS, 16)) return err(400, "bad uid");
    const u = this.dir.byUid(uidS);
    return u
      ? json(200, {
          user: {
            uid: u.uid,
            handle: u.handle,
            bundle: u.bundle,
            sig: u.sig,
            regEra: u.regEra,
            dirseq: u.dirseq,
          },
        })
      : err(404, "unknown uid");
  }

  /** GET /api/v2/dir/wraps/{id}[?uid=]. */
  private getDirWraps(req: Req, idS: string): Res {
    if (!b64Param(idS, 1, 1023)) return err(400, "bad id");
    const uidS = req.url.searchParams.get("uid");
    if (uidS !== null && !b64Param(uidS, 16)) return err(400, "bad uid");
    const rows = this.dir.wrapsById(idS, uidS);
    return json(200, {
      wraps: rows.map((w) => ({ uid: w.uid, record: w.record, sig: w.sig, dirseq: w.dirseq })),
    });
  }

  /** GET /api/v2/dirlog?after=&limit=1..1000. */
  private getDirlog(req: Req): Res {
    const after = queryInt(req.url, "after", 0, 0, Number.MAX_SAFE_INTEGER);
    const limit = queryInt(req.url, "limit", 1000, 1, 1000);
    if (after === undefined || limit === undefined) return err(400, "bad after or limit");
    return json(200, this.dir.dirlog(after, limit));
  }
}
