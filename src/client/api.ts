// HTTP client for the v2 API (docs/PROTOCOL-v2.md §10): params with their §3.1 bounds, the server-time estimate
// from clock samples (§10.1), proof of work (§10.2), the binary put and get (§10.3, §10.4), and the directory (§10.6).
// One instance per engine: the transport and the clock come from the engine's options.
import * as P from "~/lib/proto";
import { BAD_RECEIPT, RowMemory, type CkptLatest, type CkptRange } from "./integrity";
import * as W from "~/lib/wire";
import type { EngineClock } from "./options";

export type Bytes = Uint8Array;
export type Progress = (msg: string) => void;

/**
 * A failed API call. `status` is the HTTP status, or 0 when no usable answer arrived (network error, timeout,
 * malformed response). `body` is the JSON error object when there is one.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly body: Record<string, unknown> | null;
  /** seconds from `retry-after`, or null */
  readonly retryAfter: number | null;
  constructor(
    status: number,
    message: string,
    body: Record<string, unknown> | null = null,
    retryAfter: number | null = null,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    this.retryAfter = retryAfter;
  }
  /** a network error, a timeout, a malformed answer, a 429 or a 5xx: retry later, never conclude anything */
  get transient(): boolean {
    return this.status === 0 || this.status === 429 || this.status >= 500;
  }
}

/** True for errors after which an operation may be retried (§10.1, §10.6 "Transient failures"). */
export const isTransient = (e: unknown): boolean => !(e instanceof ApiError) || e.transient;

// ───────────────────────── params (§10.9, §3.1) ─────────────────────────

export interface Params {
  v: 2;
  now: number;
  T0: number;
  eraMs: number;
  era: number;
  /** Δ in seconds */
  delta: number;
  /** SKEW in seconds */
  skew: number;
  /** Δin in seconds */
  inboxSlot: number;
  inboxRetention: number;
  inboxDayCap: number;
  inboxBatch: number;
  shards: number;
  /** the directory's P (§9.6) */
  p: number;
  efirst: number;
  kcommit: string;
  srvKey: string;
  pow: Record<P.PowScope, number>;
  limits: {
    putRows: number;
    putBytes: number;
    getKeys: number;
    topics: number;
    blobMax: number;
    textMax: number;
  };
}

const POW_SCOPES: readonly P.PowScope[] = ["register", "wrap", "put", "inbox", "blob"];
/** Clients refuse a PoW base above 26 (§10.2). */
export const MAX_POW_BASE = 26;
const PARAMS_TTL_MS = 5 * 60_000;

const isInt = (x: unknown, lo: number, hi: number): x is number =>
  typeof x === "number" && Number.isSafeInteger(x) && x >= lo && x <= hi;
const isObj = (x: unknown): x is Record<string, unknown> =>
  typeof x === "object" && x !== null && !Array.isArray(x);

function isB64u(x: unknown, len: number): x is string {
  if (typeof x !== "string") return false;
  try {
    return P.fromB64u(x).length === len;
  } catch {
    return false;
  }
}

/**
 * Checks a params answer. A `delta`, `skew` or `inboxSlot` outside the bounds of §3.1 (or any other malformed field)
 * makes it a failed request, which the caller retries with back-off.
 */
export function checkParams(x: unknown): Params {
  const bad = (what: string): never => {
    throw new ApiError(0, `the server sent invalid parameters (${what})`);
  };
  if (!isObj(x) || x.v !== 2) return bad("version");
  if (x.T0 !== P.T0_MS || x.eraMs !== P.ERA_MS) bad("era layout");
  if (!isInt(x.now, 0, Number.MAX_SAFE_INTEGER) || !isInt(x.era, 0, 0xfffe)) bad("now");
  if (!isInt(x.delta, 1, 3600) || 604_800 % x.delta !== 0) bad("delta");
  if (!isInt(x.skew, 0, 60)) bad("skew");
  if (!isInt(x.inboxSlot, 1, 3600)) bad("inboxSlot");
  if (!isInt(x.p, 0, 32)) bad("p");
  if (!isInt(x.efirst, 0, 0xfffe)) bad("efirst");
  if (!isInt(x.shards, 1, 1) || !isInt(x.inboxBatch, 1, 32) || !isInt(x.inboxRetention, 0, 0xfffe))
    bad("layout");
  if (!isInt(x.inboxDayCap, 0, Number.MAX_SAFE_INTEGER)) bad("inboxDayCap");
  if (!isB64u(x.srvKey, 32) || typeof x.kcommit !== "string") bad("keys");
  const pow = x.pow;
  if (!isObj(pow) || POW_SCOPES.some((s) => !isInt(pow[s], 0, 64))) bad("pow");
  const l = x.limits;
  if (
    !isObj(l) ||
    ["putRows", "putBytes", "getKeys", "topics", "blobMax", "textMax"].some(
      (k) => !isInt(l[k], 1, 2 ** 40),
    )
  )
    bad("limits");
  return x as unknown as Params;
}

// ───────────────────────── server time (§10.1) ─────────────────────────

/** A clock sample: server time `s`, the monotonic midpoint `mid` and the round trip `rtt` (ms). */
export interface TimeSample {
  s: number;
  mid: number;
  rtt: number;
}

const SAMPLE_WINDOW_MS = 10 * 60_000;
const GOOD_RTT_MS = 2000;
const MAX_SAMPLES = 64;

/**
 * The server-time estimate of §10.1: samples from `no-store` responses and HELLO, anchored on the monotonic clock.
 * A new sample discards every older one whose estimate at its midpoint differs from it by more than
 * `(rtt_old + rtt_new)/2 + SKEW + 1 s`. Among the samples of the last 10 minutes the one with the smallest rtt wins
 * (the newest among equal ones; one with rtt > 2 s only when no better one is that young); with none that young, the
 * newest. The estimate never reads the wall clock.
 */
export class ServerClock {
  private samples: TimeSample[] = [];
  skewMs = 0;
  constructor(private readonly clock: EngineClock) {}

  add(s: number, sentMono: number, recvMono: number): void {
    const rtt = Math.max(0, recvMono - sentMono);
    const mid = sentMono + rtt / 2;
    const fresh: TimeSample = { s, mid, rtt };
    this.samples = this.samples.filter(
      (o) => Math.abs(o.s + (mid - o.mid) - s) <= (o.rtt + rtt) / 2 + this.skewMs + 1000,
    );
    this.samples.push(fresh);
    if (this.samples.length > MAX_SAMPLES)
      this.samples.splice(0, this.samples.length - MAX_SAMPLES);
  }

  /** The sample the estimate uses, or null before the first one. */
  get sample(): TimeSample | null {
    if (this.samples.length === 0) return null;
    const now = this.clock.mono();
    const young = this.samples.filter((x) => now - x.mid <= SAMPLE_WINDOW_MS);
    if (young.length === 0) return this.samples[this.samples.length - 1];
    const good = young.filter((x) => x.rtt <= GOOD_RTT_MS);
    const pool = good.length > 0 ? good : young;
    let best = pool[0];
    for (const x of pool)
      if (x.rtt < best.rtt || (x.rtt === best.rtt && x.mid >= best.mid)) best = x;
    return best;
  }

  /** The estimated server time (ms). Throws before the first sample. */
  now(): number {
    const x = this.sample;
    if (!x) throw new Error("no server time sample yet");
    return x.s + (this.clock.mono() - x.mid);
  }
}

// ───────────────────────── directory shapes (§10.6) ─────────────────────────

export interface UserJson {
  uid: string;
  handle: string;
  bundle: string;
  sig: string;
  regEra: number;
  dirseq: number;
}

export interface WrapJson {
  record: string;
  sig: string;
}

export interface DirWrapJson extends WrapJson {
  uid: string;
  dirseq: number;
}

/** A directory user whose bundle verified (§10.6: `verifyBundle`, `checkUserKeys`, uid and handle match). */
export interface DirUser {
  uid: string;
  uidBytes: Bytes;
  handle: string;
  sigPk: Bytes;
  kemPk: Bytes;
  bundle: string;
  sig: string;
  regEra: number;
  dirseq: number;
  /** pin(u) (§2.2) */
  pin: Bytes;
}

function isUserJson(x: unknown): x is UserJson {
  return (
    isObj(x) &&
    typeof x.uid === "string" &&
    typeof x.handle === "string" &&
    typeof x.bundle === "string" &&
    typeof x.sig === "string" &&
    isInt(x.regEra, 0, 0xfffe) &&
    isInt(x.dirseq, 0, Number.MAX_SAFE_INTEGER)
  );
}

/** Verifies a directory user; null when its bundle does not verify or does not match the row. */
export function verifyUser(u: UserJson): DirUser | null {
  try {
    const b = P.verifyBundle(u.bundle, u.sig);
    P.checkUserKeys(b.sigPk, b.kemPk);
    if (b.uid !== u.uid || b.handle !== u.handle) return null;
    return {
      uid: u.uid,
      uidBytes: P.fromB64u(u.uid),
      handle: u.handle,
      sigPk: b.sigPk,
      kemPk: b.kemPk,
      bundle: u.bundle,
      sig: u.sig,
      regEra: u.regEra,
      dirseq: u.dirseq,
      pin: P.pin(u.bundle, P.fromB64u(u.sig)),
    };
  } catch {
    return null;
  }
}

/** Users per prefix page (§10.6). */
const PREFIX_PAGE = 256;
const MAX_PREFIX_PAGES = 4096;
/** Fewer users than this on a page for p ≥ 1 gives a noise warning (§10.6). */
const MIN_PREFIX_USERS = 8;
export const FEW_USERS_WARNING = "the directory answered fewer accounts than expected";

// ───────────────────────── the client ─────────────────────────

export interface ApiOptions {
  fetch: typeof fetch;
  clock: EngineClock;
  /** noise warnings (the directory's short answers) */
  warn?: (text: string) => void;
  /** critical warnings (a changed stored row, an invalid receipt, §12.1, §12.5) */
  critical?: (text: string) => void;
}

async function readError(res: Response): Promise<ApiError> {
  let msg = `${res.status} ${res.statusText}`.trim();
  let body: Record<string, unknown> | null = null;
  try {
    const j = (await res.json()) as unknown;
    if (isObj(j)) {
      body = j;
      if (typeof j.error === "string") msg = j.error;
    }
  } catch {
    /* not JSON */
  }
  const ra = Number(res.headers.get("retry-after"));
  return new ApiError(res.status, msg, body, Number.isFinite(ra) && ra >= 0 ? ra : null);
}

export class Api {
  readonly time: ServerClock;
  /** every row this session fetched, received or wrote (§12.1) */
  readonly rows: RowMemory;
  private readonly fetchFn: typeof fetch;
  private readonly clock: EngineClock;
  private readonly warn: (text: string) => void;
  private readonly critical: (text: string) => void;
  private receiptWarned = false;
  private paramsCache: { p: Params; at: number } | null = null;
  private paramsPending: Promise<Params> | null = null;
  private dirSeqPending: Promise<number> | null = null;
  private readonly prefixCache = new Map<string, Promise<UserJson[]>>();

  constructor(opts: ApiOptions) {
    this.fetchFn = opts.fetch;
    this.clock = opts.clock;
    this.time = new ServerClock(opts.clock);
    this.warn = opts.warn ?? (() => {});
    this.critical = opts.critical ?? (() => {});
    this.rows = new RowMemory(this.critical);
  }

  /** The estimated server time (ms); call `params()` once before. */
  serverNow(): number {
    return this.time.now();
  }

  /**
   * One HTTP request. Network failures become `ApiError(0)`. Every `no-store` response with a valid `x-segv-now`
   * adds a clock sample (§10.1); cacheable responses never do.
   */
  async request(path: string, init: RequestInit = {}): Promise<Response> {
    const sent = this.clock.mono();
    let res: Response;
    try {
      res = await this.fetchFn(path, init);
    } catch (e) {
      throw new ApiError(0, `network error: ${e instanceof Error ? e.message : String(e)}`);
    }
    const recv = this.clock.mono();
    const cc = res.headers.get("cache-control") ?? "";
    const now = res.headers.get("x-segv-now");
    if (/\bno-store\b/.test(cc) && now !== null && /^\d{1,16}$/.test(now)) {
      const s = Number(now);
      if (Number.isSafeInteger(s)) this.time.add(s, sent, recv);
    }
    return res;
  }

  private async json<T>(res: Response): Promise<T> {
    try {
      return (await res.json()) as T;
    } catch {
      throw new ApiError(0, "malformed response from the server");
    }
  }

  private async getJson<T>(path: string): Promise<T> {
    const res = await this.request(path, { cache: "no-store" });
    if (!res.ok) throw await readError(res);
    return this.json<T>(res);
  }

  // ── params ──

  /** Params, cached for 5 minutes (`force` refetches). A malformed answer is a failed request. */
  async params(force = false): Promise<Params> {
    const c = this.paramsCache;
    if (!force && c && this.clock.mono() - c.at < PARAMS_TTL_MS) return c.p;
    this.paramsPending ??= (async () => {
      try {
        const p = checkParams(await this.getJson<unknown>("/api/v2/params"));
        this.paramsCache = { p, at: this.clock.mono() };
        this.time.skewMs = p.skew * 1000;
        return p;
      } finally {
        this.paramsPending = null;
      }
    })();
    return this.paramsPending;
  }

  /** The params last fetched, or null. */
  get cachedParams(): Params | null {
    return this.paramsCache?.p ?? null;
  }

  // ── proof of work (§10.2) ──

  /**
   * `x-segv-pow` for `digest`. The search uses the window that is current by the estimated server time, and is
   * stopped and restarted with the new window when that one stops being current before a nonce is found, so a stale
   * proof is never sent.
   */
  async powHeader(
    scope: P.PowScope,
    digest: Bytes,
    bytes: number,
    onProgress?: Progress,
  ): Promise<string> {
    const p = await this.params();
    const base = p.pow[scope];
    if (base > MAX_POW_BASE)
      throw new ApiError(0, `the server requested an unreasonable proof of work (${base} bits)`);
    const bits = P.powDifficulty(scope, base, bytes);
    if (bits > 0) onProgress?.("solving proof of work…");
    for (;;) {
      const now = this.serverNow();
      const window = Math.floor(now / P.POW_WINDOW_MS);
      const stop = new AbortController();
      const timer = this.clock.setTimer(() => stop.abort(), (window + 1) * P.POW_WINDOW_MS - now);
      try {
        const nonce = await P.powSolve(P.powPre(scope, window, digest), bits, {
          signal: stop.signal,
        });
        if (nonce !== null && Math.floor(this.serverNow() / P.POW_WINDOW_MS) === window)
          return `${window}.${nonce}`;
      } finally {
        timer.cancel();
      }
    }
  }

  /** POSTs `body` with a proof of work; on 403 retries once with fresh params (§10.2). */
  private async postPow(
    path: string,
    scope: P.PowScope,
    body: Bytes,
    type: string,
    onProgress?: Progress,
  ): Promise<Response> {
    const digest = P.H(body);
    for (let attempt = 0; ; attempt++) {
      const pow = await this.powHeader(scope, digest, body.length, onProgress);
      const res = await this.request(path, {
        method: "POST",
        headers: { "content-type": type, "x-segv-pow": pow },
        body: body as BodyInit,
      });
      if (res.ok) return res;
      const err = await readError(res);
      if (res.status === 403 && attempt === 0) {
        await this.params(true);
        continue;
      }
      throw err;
    }
  }

  private async postPowJson<T>(
    path: string,
    scope: P.PowScope,
    body: unknown,
    onProgress?: Progress,
  ): Promise<T> {
    const res = await this.postPow(
      path,
      scope,
      P.utf8(JSON.stringify(body)),
      "application/json",
      onProgress,
    );
    return this.json<T>(res);
  }

  // ── rows (§10.3, §10.4) ──

  /** One put request (1..16 rows); per-row results in request order. */
  async put(rows: readonly W.PutRow[], onProgress?: Progress): Promise<W.PutResult[]> {
    const body = W.encodePutRequest(rows);
    return this.sendPut(body, await this.putPow(body, onProgress), rows.length, onProgress);
  }

  /** The proof of work of a put request body (§10.2), computed before the request is sent (§11.3 step 6). */
  putPow(body: Bytes, onProgress?: Progress): Promise<string> {
    return this.powHeader("put", P.H(body), body.length, onProgress);
  }

  /**
   * Sends a put request with its proof of work. On 403 (a window that ended meanwhile) it refreshes params and
   * sends once more with a new proof.
   */
  async sendPut(
    body: Bytes,
    pow: string,
    count: number,
    onProgress?: Progress,
  ): Promise<W.PutResult[]> {
    let res: Response;
    for (let attempt = 0; ; attempt++) {
      res = await this.request("/api/v2/put", {
        method: "POST",
        headers: { "content-type": "application/octet-stream", "x-segv-pow": pow },
        body: body as BodyInit,
      });
      if (res.ok) break;
      const err = await readError(res);
      if (res.status !== 403 || attempt > 0) throw err;
      await this.params(true);
      pow = await this.putPow(body, onProgress);
    }
    let out: W.PutResult[];
    try {
      out = W.decodePutResponse(new Uint8Array(await res.arrayBuffer()));
    } catch {
      throw new ApiError(0, "malformed put response");
    }
    if (out.length !== count) throw new ApiError(0, "malformed put response");
    this.checkPut(body, out);
    return out;
  }

  /** §12.5 receipts of OK rows under the server key, and §12.1 for every stored row the answer names. */
  private checkPut(body: Bytes, out: W.PutResult[]): void {
    let rows: W.PutRow[];
    try {
      rows = W.decodePutRequest(body);
    } catch {
      return;
    }
    const key = this.cachedParams ? P.fromB64u(this.cachedParams.srvKey) : null;
    out.forEach((r, i) => {
      const row = rows[i];
      if (!row) return;
      if (r.s === "ok") {
        if (key && !P.verify(r.receipt, P.receiptMsg(row.E, row.label, row.body, r.t), key)) {
          if (!this.receiptWarned) this.critical(BAD_RECEIPT);
          this.receiptWarned = true;
        }
        this.rows.observe(row.E, row.label, r.t, row.cls, row.body);
      } else if (r.s === "conflict") this.rows.observe(row.E, row.label, r.t, r.cls, r.body);
    });
  }

  /**
   * Gets any number of keys: requests of at most 256 keys, and SKIPPED keys asked again until each has a status
   * (§10.4: SKIPPED says nothing about a key).
   */
  async get(keys: readonly W.GetKey[]): Promise<W.GetStatus[]> {
    const out: (W.GetStatus | undefined)[] = Array.from({ length: keys.length });
    let todo = keys.map((_, i) => i);
    while (todo.length > 0) {
      const batch = todo.slice(0, W.GET_MAX_KEYS);
      const modes = batch.map((i) => keys[i].mode);
      const res = await this.request("/api/v2/get", {
        method: "POST",
        headers: { "content-type": "application/octet-stream" },
        body: W.encodeGetRequest(batch.map((i) => keys[i])) as BodyInit,
      });
      if (!res.ok) throw await readError(res);
      let st: W.GetStatus[];
      try {
        st = W.decodeGetResponse(new Uint8Array(await res.arrayBuffer()), modes);
      } catch {
        throw new ApiError(0, "malformed get response");
      }
      const skipped: number[] = [];
      batch.forEach((i, k) => {
        const x = st[k];
        if (x.s === "skipped") skipped.push(i);
        else out[i] = x;
        if (x.s === "hit") this.rows.observe(keys[i].E, keys[i].label, x.t, x.cls, x.body ?? null);
      });
      if (skipped.length === batch.length) throw new ApiError(0, "the server skipped every key");
      todo = [...skipped, ...todo.slice(batch.length)];
    }
    return out as W.GetStatus[];
  }

  // ── checkpoints (§10.9) ──

  /** `GET /api/v2/ckpt/latest`: the latest checkpoint, or null while there is none (404). */
  async ckptLatest(): Promise<CkptLatest | null> {
    const res = await this.request("/api/v2/ckpt/latest", { cache: "no-store" });
    if (res.status === 404) return null;
    if (!res.ok) throw await readError(res);
    const j = await this.json<Record<string, unknown>>(res);
    if (
      !isInt(j.q, 1, 0xffffffff) ||
      !isInt(j.sec, 0, 0xffffffff) ||
      !isB64u(j.C, 32) ||
      !isB64u(j.sig, 64)
    )
      throw new ApiError(0, "malformed checkpoint");
    return { q: j.q, sec: j.sec, C: P.fromB64u(j.C), sig: P.fromB64u(j.sig) };
  }

  /** `GET /api/v2/ckpt/range?after=…&limit=…`; null on 404 (none yet, or `after` above the latest). */
  async ckptRange(after: number, limit: number): Promise<CkptRange | null> {
    const res = await this.request(`/api/v2/ckpt/range?after=${after}&limit=${limit}`, {
      cache: "no-store",
    });
    if (res.status === 404) return null;
    if (!res.ok) throw await readError(res);
    const j = await this.json<Record<string, unknown>>(res);
    const from = j.from as Record<string, unknown> | undefined;
    const latest = j.latest as Record<string, unknown> | undefined;
    const entries = j.entries;
    if (
      !isObj(from) ||
      !isObj(latest) ||
      !Array.isArray(entries) ||
      !isInt(from.q, 0, 0xffffffff) ||
      !isB64u(from.C, 32) ||
      !isInt(latest.q, 1, 0xffffffff) ||
      !isB64u(latest.C, 32) ||
      !isB64u(latest.sig, 64)
    )
      throw new ApiError(0, "malformed checkpoint range");
    const es = entries.map((e: unknown) => {
      if (
        !isObj(e) ||
        !isInt(e.q, 1, 0xffffffff) ||
        !isInt(e.sec, 0, 0xffffffff) ||
        !isB64u(e.hd, 32)
      )
        throw new ApiError(0, "malformed checkpoint range");
      return { q: e.q, sec: e.sec, hd: P.fromB64u(e.hd) };
    });
    return {
      from: { q: from.q, C: P.fromB64u(from.C) },
      entries: es,
      latest: { q: latest.q, C: P.fromB64u(latest.C), sig: P.fromB64u(latest.sig) },
    };
  }

  // ── blobs (§10.7) ──

  /** `PUT /api/v2/blob/{id}` with its proof of work; resolves with the registration time `t` (seconds since T0). */
  async putBlob(
    id: Bytes,
    blob: Bytes,
    onProgress?: Progress,
  ): Promise<{ t: number; size: number }> {
    const pow = await this.powHeader("blob", id, blob.length, onProgress);
    const res = await this.request(`/api/v2/blob/${P.b64u(id)}`, {
      method: "PUT",
      headers: { "content-type": "application/octet-stream", "x-segv-pow": pow },
      body: blob as BodyInit,
    });
    if (!res.ok) throw await readError(res);
    const j = await this.json<{ t?: unknown; size?: unknown }>(res);
    if (!isInt(j.t, 0, 0xffffffff) || j.size !== blob.length)
      throw new ApiError(0, "malformed blob response");
    return { t: j.t, size: j.size };
  }

  /** `GET /api/v2/blob/{id}/meta`: the registration `{t, size}`, or null when unregistered (§6.4(g)). */
  async blobMeta(id: Bytes): Promise<{ t: number; size: number } | null> {
    const res = await this.request(`/api/v2/blob/${P.b64u(id)}/meta`, { cache: "no-store" });
    if (res.status === 404) return null;
    if (!res.ok) throw await readError(res);
    const j = await this.json<{ t?: unknown; size?: unknown }>(res);
    if (!isInt(j.t, 0, 0xffffffff) || !isInt(j.size, 0, P.BLOB_MAX))
      throw new ApiError(0, "malformed blob meta");
    return { t: j.t, size: j.size };
  }

  /**
   * `GET /api/v2/blob/{id}/meta` with the MISS answer's BlobReg clock (§6.4(g)): `{t, size}`, or `{now}` (seconds
   * since T0) when unregistered.
   */
  async blobMetaOrNow(id: Bytes): Promise<{ t: number; size: number } | { now: number }> {
    const res = await this.request(`/api/v2/blob/${P.b64u(id)}/meta`, { cache: "no-store" });
    if (res.status === 404) {
      const j = await this.json<{ now?: unknown }>(res);
      if (!isInt(j.now, 0, 0xffffffff)) throw new ApiError(0, "malformed blob meta");
      return { now: j.now };
    }
    if (!res.ok) throw await readError(res);
    const j = await this.json<{ t?: unknown; size?: unknown }>(res);
    if (!isInt(j.t, 0, 0xffffffff) || !isInt(j.size, 0, P.BLOB_MAX))
      throw new ApiError(0, "malformed blob meta");
    return { t: j.t, size: j.size };
  }

  /**
   * `GET /api/v2/blob/{id}`, reading at most `max + 1` bytes: null for 404. A `content-length` other than `max`, or a
   * body longer than `max`, is a size mismatch (the caller decides; §6.7 step 1).
   */
  async getBlob(id: Bytes, max: number): Promise<{ bytes: Bytes; sizeOk: boolean } | null> {
    const res = await this.request(`/api/v2/blob/${P.b64u(id)}`);
    if (res.status === 404) return null;
    if (!res.ok) throw await readError(res);
    const cl = res.headers.get("content-length");
    if (cl !== null && Number(cl) !== max) {
      await res.body?.cancel().catch(() => {});
      return { bytes: new Uint8Array(0), sizeOk: false };
    }
    const chunks: Bytes[] = [];
    let n = 0;
    const reader = res.body?.getReader();
    if (!reader) return { bytes: new Uint8Array(0), sizeOk: max === 0 };
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        n += value.length;
        if (n > max) {
          await reader.cancel().catch(() => {});
          return { bytes: new Uint8Array(0), sizeOk: false };
        }
      }
    } catch (e) {
      throw new ApiError(0, `blob read failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    return { bytes: P.concat(...chunks), sizeOk: n === max };
  }

  /** `GET /api/v2/blob/{id}` of unknown size, at most `cap` bytes: null for 404; a longer body is refused. */
  async getBlobUpTo(id: Bytes, cap: number): Promise<Bytes | null> {
    const res = await this.request(`/api/v2/blob/${P.b64u(id)}`);
    if (res.status === 404) return null;
    if (!res.ok) throw await readError(res);
    const cl = Number(res.headers.get("content-length") ?? "0");
    if (cl > cap) {
      await res.body?.cancel().catch(() => {});
      throw new ApiError(0, "blob too large");
    }
    const b = new Uint8Array(await res.arrayBuffer());
    if (b.length > cap) throw new ApiError(0, "blob too large");
    return b;
  }

  // ── inbox (§10.5) ──

  /**
   * Posts 1..32 invites of era E (one burst, §6.12). A 409 `wrong era` throws an ApiError whose body names `era`.
   */
  async postInbox(
    E: number,
    rows: readonly W.InboxPostRow[],
    onProgress?: Progress,
  ): Promise<W.InboxPostResult[]> {
    const body = W.encodeInboxPost({ E, bucket: 0, rows: [...rows] });
    const res = await this.postPow(
      "/api/v2/inbox",
      "inbox",
      body,
      "application/octet-stream",
      onProgress,
    );
    try {
      return W.parseInboxPostResults(await res.json(), rows.length);
    } catch {
      throw new ApiError(0, "malformed inbox response");
    }
  }

  /**
   * One page of `GET /api/v2/inbox/{E}/0?after=` (§10.5). A malformed page (decreasing rel, or `more = 1` without a
   * row above `after`) is a failed read.
   */
  async readInbox(E: number, after: number): Promise<W.InboxRead> {
    const res = await this.request(`/api/v2/inbox/${E}/0?after=${after}`);
    if (!res.ok) throw await readError(res);
    let page: W.InboxRead;
    try {
      page = W.decodeInboxRead(new Uint8Array(await res.arrayBuffer()));
    } catch {
      throw new ApiError(0, "malformed inbox page");
    }
    if (page.more && !page.rows.some((r) => r.rel > after))
      throw new ApiError(0, "inbox page without progress");
    return page;
  }

  // ── directory (§10.6) ──

  /**
   * `POST /api/v2/register`. `now` is the response's `x-segv-now`: the server time of the registration, from which
   * the first inbox cursor is computed (§11.1), or null when absent.
   */
  async register(
    body: { bundle: string; sig: string; wraps: WrapJson[] },
    onProgress?: Progress,
  ): Promise<{ dirseq: number; now: number | null }> {
    const res = await this.postPow(
      "/api/v2/register",
      "register",
      P.utf8(JSON.stringify(body)),
      "application/json",
      onProgress,
    );
    const h = res.headers.get("x-segv-now");
    const j = await this.json<{ dirseq: number }>(res);
    const now = h !== null && /^\d{1,16}$/.test(h) ? Number(h) : null;
    return { dirseq: j.dirseq, now: now !== null && Number.isSafeInteger(now) ? now : null };
  }

  postWrap(body: WrapJson, onProgress?: Progress): Promise<{ dirseq: number }> {
    return this.postPowJson("/api/v2/wraps", "wrap", body, onProgress);
  }

  /** The wrap records filed under `id` (and `uid`), oldest first; an unknown id gives an empty list. */
  async wraps(id: Bytes, uid: Bytes | null = null): Promise<DirWrapJson[]> {
    const q = uid ? `?uid=${P.b64u(uid)}` : "";
    const j = await this.getJson<{ wraps?: unknown }>(`/api/v2/dir/wraps/${P.b64u(id)}${q}`);
    if (!Array.isArray(j.wraps)) throw new ApiError(0, "malformed wraps response");
    return j.wraps.filter(
      (w): w is DirWrapJson =>
        isObj(w) &&
        typeof w.uid === "string" &&
        typeof w.record === "string" &&
        typeof w.sig === "string",
    );
  }

  /** The exact lookup of one's own account (§10.6); null for 404. */
  async userByUid(uid: Bytes): Promise<UserJson | null> {
    const res = await this.request(`/api/v2/dir/uid/${P.b64u(uid)}`, { cache: "no-store" });
    if (res.status === 404) return null;
    if (!res.ok) throw await readError(res);
    const j = await this.json<{ user?: unknown }>(res);
    if (!isUserJson(j.user)) throw new ApiError(0, "malformed directory response");
    return j.user;
  }

  /** The dirlog head seq, read once per session before the first prefix lookup (§10.6). */
  dirSeq(): Promise<number> {
    this.dirSeqPending ??= this.getJson<{ head?: { seq?: unknown } }>(
      "/api/v2/dirlog?limit=1",
    ).then(
      (j) => {
        const seq = j.head?.seq;
        if (!isInt(seq, 0, Number.MAX_SAFE_INTEGER))
          throw new ApiError(0, "malformed dirlog response");
        return seq;
      },
      (e: unknown) => {
        this.dirSeqPending = null;
        throw e;
      },
    );
    return this.dirSeqPending;
  }

  /** p for a lookup: clientP(P*, dirSeq), or with min(P*, P′) after a 409 naming P′ (§10.6). */
  async prefixBits(P409: number | null = null): Promise<number> {
    const [params, dirSeq] = await Promise.all([this.params(), this.dirSeq()]);
    const Pstar = P.clientPStar(params.p, dirSeq);
    return P.clientP(P409 === null ? Pstar : Math.min(Pstar, P409), dirSeq);
  }

  /**
   * Every user whose `hpre` (kind "h") or `upre` (kind "u") shares the top p bits of `pre`: a complete answer (every
   * page, the last with `more = false`), cached for the session unless `fresh`. A 409 `{p}` recomputes p once and
   * retries; any other failure is transient and never means "no such user".
   */
  async prefixUsers(kind: "h" | "u", pre: number, fresh = false): Promise<UserJson[]> {
    const p = await this.prefixBits();
    const key = `${kind}/${p}/${P.topBits(pre, p)}`;
    const cached = this.prefixCache.get(key);
    if (cached && !fresh) return cached;
    const run = (async () => {
      try {
        return await this.prefixPages(kind, p, P.topBits(pre, p));
      } catch (e) {
        const P409 = e instanceof ApiError && e.status === 409 ? e.body?.p : undefined;
        if (!isInt(P409, 0, 32)) throw e;
        const p2 = await this.prefixBits(P409);
        try {
          return await this.prefixPages(kind, p2, P.topBits(pre, p2));
        } catch (e2) {
          if (e2 instanceof ApiError && !e2.transient)
            throw new ApiError(0, `directory lookup failed: ${e2.message}`);
          throw e2;
        }
      }
    })();
    this.prefixCache.set(key, run);
    run.catch(() => this.prefixCache.delete(key));
    return run;
  }

  private async prefixPages(kind: "h" | "u", p: number, x: number): Promise<UserJson[]> {
    const users: UserJson[] = [];
    let after: string | null = null;
    for (let page = 0; page < MAX_PREFIX_PAGES; page++) {
      const q: string = after ? `?after=${after}` : "";
      const j = await this.getJson<{ p?: unknown; users?: unknown; more?: unknown }>(
        `/api/v2/dir/${kind}/${p}/${x}${q}`,
      );
      if (j.p !== p || !Array.isArray(j.users) || typeof j.more !== "boolean")
        throw new ApiError(0, "malformed directory page");
      const rows = j.users.filter(isUserJson);
      if (rows.length !== j.users.length || rows.length > PREFIX_PAGE)
        throw new ApiError(0, "malformed directory page");
      users.push(...rows);
      if (!j.more) {
        if (p >= 1 && users.length < MIN_PREFIX_USERS) this.warn(FEW_USERS_WARNING);
        return users;
      }
      const last = rows.at(-1);
      if (rows.length !== PREFIX_PAGE || !last || last.uid === after)
        throw new ApiError(0, "malformed directory page");
      after = last.uid;
    }
    throw new ApiError(0, "directory answer did not complete");
  }

  /** The verified user registered under `handle`, or null on a complete answer without it (§10.6). */
  /**
   * The verified user registered under `uid`, by uid prefix; null on a complete answer without it (§10.6). An answer
   * from the session cache that lacks it is asked for again once (the user may have registered since).
   */
  userByUidPrefix(uid: Bytes, fresh = false): Promise<DirUser | null> {
    const uidB = P.b64u(uid);
    return this.findUser("u", P.upre(uid), (r) => r.uid === uidB, fresh);
  }

  /** The verified user registered under `handle`, or null on a complete answer without it (§10.6). */
  userByHandle(handle: string, fresh = false): Promise<DirUser | null> {
    return this.findUser("h", P.hpre(handle), (r) => r.handle === handle, fresh);
  }

  private async findUser(
    kind: "h" | "u",
    pre: number,
    match: (r: UserJson) => boolean,
    fresh: boolean,
  ): Promise<DirUser | null> {
    const pick = (rows: UserJson[]): DirUser | null => {
      for (const r of rows) {
        if (!match(r)) continue;
        const u = verifyUser(r);
        if (u) return u;
      }
      return null;
    };
    const found = pick(await this.prefixUsers(kind, pre, fresh));
    if (found || fresh) return found;
    return pick(await this.prefixUsers(kind, pre, true));
  }
}
