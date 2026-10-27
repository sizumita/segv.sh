/**
 * Shared helpers for the v2 Workers-runtime tests (docs/PROTOCOL-v2.md §10). Binary bodies are built and
 * parsed with the production codecs of src/lib/wire.ts, so the tests cannot drift from the Worker.
 */
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { expect } from "vitest";
import * as P from "../../../src/lib/proto2";
import * as W from "../../../src/lib/wire";
import { handleApiV2 } from "../../../src/server/v2/api";

export type Bytes = Uint8Array;

/** Base difficulties: must match "vars" in ../wrangler.test.jsonc. */
export const DIFF2: Readonly<Record<P.PowScope, number>> = {
  register: 6,
  wrap: 5,
  put: 4,
  inbox: 4,
  blob: 5,
};
/** Deployment parameters of ../wrangler.test.jsonc (Δ, SKEW, Δin, E_FIRST). */
export const DELTA = 1;
export const SKEW = 0;
export const INBOX_SLOT = 1;
export const E_FIRST = 1;
/** The host the tests talk to (listed in APP_HOSTS in ../wrangler.test.jsonc). */
export const ORIGIN = "https://segv.test";
export const IMMUTABLE = "public, max-age=31536000, immutable";
export const HSTS = "max-age=63072000; includeSubDomains";

/** srvKey of the fixed test SRV_KEY (receipts and checkpoints verify under it). */
export const testSrvKey = (): Bytes => P.sigPub(P.fromB64u(env.SRV_KEY));
/** kroute_E of the fixed test ROUTE_KEY. */
export const testKroute = (E: number): Bytes => P.kroute(P.fromB64u(env.ROUTE_KEY), E);

export const eraNow = (): number => P.era(Date.now());
export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

let ipSeq = Math.floor(Math.random() * 0xffff) << 8;
/** A distinct client IPv4 per call, so rate limits only bite where a test wants them to. */
export const freshIp = (): string => {
  ipSeq = (ipSeq + 1) & 0xffffff;
  return `10.${ipSeq >> 16}.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
};

export type ApiInit = Omit<RequestInit, "body"> & {
  body?: BodyInit | Uint8Array | null;
  ip?: string;
  origin?: string;
};

function buildRequest(path: string, init: ApiInit): Request {
  const { ip, body, origin = ORIGIN, ...rest } = init;
  const headers = new Headers(rest.headers);
  if (!headers.has("cf-connecting-ip")) headers.set("cf-connecting-ip", ip ?? freshIp());
  return new Request(`${origin}${path}`, {
    ...rest,
    headers,
    body: body as BodyInit | null | undefined,
  });
}

/**
 * Calls the test Worker (../entry.ts). Every request gets a client IP (fresh unless `ip` is given).
 * `origin` replaces the scheme + host of the request URL (default ORIGIN).
 *
 * The response body is read before returning (a buffered copy is returned): tests often look at the status
 * only, and in workerd an unread response body keeps the request open (it can stall later work such as
 * evictDurableObject).
 */
export async function api(path: string, init: ApiInit = {}): Promise<Response> {
  const worker = (exports as unknown as { default: Fetcher }).default;
  const res = await worker.fetch(buildRequest(path, init));
  if (res.webSocket) return res;
  const nullBody = [101, 204, 205, 304].includes(res.status);
  const body = nullBody ? null : await res.arrayBuffer();
  if (nullBody) await res.body?.cancel();
  return new Response(body, {
    status: res.status,
    statusText: res.statusText,
    headers: res.headers,
  });
}

/** `env` with some bindings replaced (the rest read through to the real env). */
export function envWith(overrides: Record<string, unknown>): Env {
  return new Proxy(env, {
    get: (t, k) =>
      typeof k === "string" && Object.prototype.hasOwnProperty.call(overrides, k)
        ? overrides[k]
        : Reflect.get(t, k),
  });
}

/** Wraps a Durable Object namespace and records every method called on it (getByName, idFromName, get, …). */
export function spyNamespace(ns: unknown, calls: string[]): DurableObjectNamespace {
  return new Proxy(ns as DurableObjectNamespace, {
    get(t, k) {
      const v = Reflect.get(t, k) as unknown;
      if (typeof v !== "function") return v;
      return (...args: unknown[]) => {
        calls.push(
          `${String(k)}(${args.map((a) => (typeof a === "string" ? a : typeof a)).join(",")})`,
        );
        return (v as (...a: unknown[]) => unknown).apply(t, args);
      };
    },
  });
}

/**
 * Calls handleApiV2 directly (no entry, no host pinning) with an env whose bindings may be replaced, and
 * waits for its waitUntil work.
 */
export async function direct(
  path: string,
  init: ApiInit = {},
  overrides: Record<string, unknown> = {},
): Promise<Response> {
  const req = buildRequest(path, init);
  const ctx = createExecutionContext();
  const res = await handleApiV2(req, envWith(overrides), ctx, new URL(req.url));
  await waitOnExecutionContext(ctx);
  return res;
}

export async function errorOf(res: Response): Promise<string> {
  const j = (await res.json()) as { error?: unknown };
  expect(typeof j.error).toBe("string");
  return j.error as string;
}

/** The `x-segv-now` stamp of a response (asserted present and decimal). */
export function nowOf(res: Response): number {
  const v = res.headers.get("x-segv-now");
  expect(v, `x-segv-now on ${res.status}`).toMatch(/^\d{13}$/);
  return Number(v);
}

export const bytesOf = async (res: Response): Promise<Bytes> =>
  new Uint8Array(await res.arrayBuffer());

/** Polls `pred` (sync or async) every 20 ms until it holds; throws after `ms`. */
export async function until(
  pred: () => boolean | Promise<boolean>,
  what = "condition",
  ms = 8000,
): Promise<void> {
  const end = Date.now() + ms;
  for (;;) {
    if (await pred()) return;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await sleep(20);
  }
}

// ───────────── proof of work (§10.2) ─────────────

export const currentWindow = (): number => Math.floor(Date.now() / P.POW_WINDOW_MS);

/** Difficulty the server requires for `bytes` (the request body; blobs: Content-Length). */
export const needV2 = (scope: P.PowScope, bytes: number): number =>
  P.powDifficulty(scope, DIFF2[scope], bytes);

/** A PoW header for (scope, digest). `bytes` prices it like the server does; `difficulty` overrides. */
export async function powHeaderV2(
  scope: P.PowScope,
  digest: Bytes,
  opts: { bytes?: number; window?: number; difficulty?: number } = {},
): Promise<string> {
  const window = opts.window ?? currentWindow();
  const nonce = await P.powSolve(
    P.powPre(scope, window, digest),
    opts.difficulty ?? needV2(scope, opts.bytes ?? 0),
  );
  return `${window}.${nonce}`;
}

/** A nonce that does NOT satisfy `difficulty` for (scope, window, digest). */
export function badNonceV2(
  scope: P.PowScope,
  window: number,
  digest: Bytes,
  difficulty = DIFF2[scope],
): number {
  const pre = P.powPre(scope, window, digest);
  for (let n = 0; n < 1e7; n++) if (!P.powCheck(pre, n, difficulty)) return n;
  throw new Error("badNonceV2: none found");
}

/** A nonce that satisfies `atLeast` but not `below` bits for (scope, window, digest). */
export function nonceBetweenV2(
  scope: P.PowScope,
  window: number,
  digest: Bytes,
  atLeast: number,
  below: number,
): number {
  const pre = P.powPre(scope, window, digest);
  for (let n = 0; n < 1e7; n++)
    if (P.powCheck(pre, n, atLeast) && !P.powCheck(pre, n, below)) return n;
  throw new Error("nonceBetweenV2: none found");
}

export const jsonBytes = (body: unknown): Bytes => P.utf8(JSON.stringify(body));

/** POST `bytes` with a valid proof of work over them (priced by their length). */
export async function postPowV2(
  path: string,
  scope: P.PowScope,
  bytes: Bytes,
  opts: { ip?: string; headers?: Record<string, string>; contentType?: string } = {},
): Promise<Response> {
  return api(path, {
    method: "POST",
    ip: opts.ip,
    headers: {
      "content-type": opts.contentType ?? "application/octet-stream",
      "x-segv-pow": await powHeaderV2(scope, P.H(bytes), { bytes: bytes.length }),
      ...opts.headers,
    },
    body: bytes,
  });
}

/** POST a JSON body (exact bytes of JSON.stringify, or the given bytes) with a valid proof of work. */
export const postJsonPow = (
  path: string,
  scope: P.PowScope,
  body: unknown,
  opts: { ip?: string } = {},
): Promise<Response> =>
  postPowV2(path, scope, body instanceof Uint8Array ? body : jsonBytes(body), {
    ...opts,
    contentType: "application/json",
  });

// ───────────── params (§10.9) ─────────────

export interface ParamsV2 {
  v: number;
  now: number;
  T0: number;
  eraMs: number;
  era: number;
  delta: number;
  skew: number;
  inboxSlot: number;
  inboxRetention: number;
  inboxDayCap: number;
  inboxBatch: number;
  shards: number;
  p: number;
  efirst: number;
  kcommit: string;
  srvKey: string;
  pow: Record<P.PowScope, number>;
  limits: Record<string, number>;
}

export async function paramsV2(): Promise<ParamsV2> {
  const res = await api("/api/v2/params");
  expect(res.status).toBe(200);
  return (await res.json()) as ParamsV2;
}

// ───────────── rows: put / get (§10.3, §10.4) ─────────────

export const randomLabel = (): Bytes => P.random(16);
/** A random topic (never ZERO16). */
export const randomTopic = (): Bytes => {
  const t = P.random(16);
  t[0] |= 1;
  return t;
};
/** Random bytes of any length (getRandomValues is limited to 64 KiB per call). */
export function bigRandom(n: number): Bytes {
  const out = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) out.set(P.random(Math.min(65536, n - o)), o);
  return out;
}
/** A random "ciphertext" body of class `cls`. */
export const randomBody = (cls = 0): Bytes => bigRandom(P.BODY_LENS[cls]);

/** A syntactically valid row in the current era (random label and body, no topic unless given). */
export function makeRow(opts: Partial<W.PutRow> = {}): W.PutRow {
  const cls = opts.cls ?? 0;
  return {
    E: opts.E ?? eraNow(),
    label: opts.label ?? randomLabel(),
    cls,
    topic: opts.topic ?? P.ZERO16,
    body: opts.body ?? randomBody(cls),
  };
}

/** POST /api/v2/put with a valid PoW; returns the raw response. */
export const putRaw = (
  rows: readonly W.PutRow[] | Bytes,
  opts: { ip?: string } = {},
): Promise<Response> =>
  postPowV2(
    "/api/v2/put",
    "put",
    rows instanceof Uint8Array ? rows : W.encodePutRequest(rows),
    opts,
  );

/** POST /api/v2/put (200 expected); returns the per-row results. */
export async function putRows(rows: readonly W.PutRow[]): Promise<W.PutResult[]> {
  const res = await putRaw(rows);
  expect(res.status, res.status === 200 ? "" : await res.clone().text()).toBe(200);
  expect(res.headers.get("content-type")).toBe("application/octet-stream");
  expect(res.headers.get("cache-control")).toBe("no-store");
  const out = W.decodePutResponse(await bytesOf(res));
  expect(out).toHaveLength(rows.length);
  return out;
}

/** putRows that requires every row OK; returns the OK results. */
export async function putOk(rows: readonly W.PutRow[]): Promise<{ t: number; receipt: Bytes }[]> {
  const out = await putRows(rows);
  return out.map((r, i) => {
    expect(r.s, `row ${i}`).toBe("ok");
    return r as { s: "ok"; t: number; receipt: Bytes };
  });
}

export const getRaw = (
  keys: readonly W.GetKey[] | Bytes,
  opts: { ip?: string } = {},
): Promise<Response> =>
  api("/api/v2/get", {
    method: "POST",
    ip: opts.ip,
    headers: { "content-type": "application/octet-stream" },
    body: keys instanceof Uint8Array ? keys : W.encodeGetRequest(keys),
  });

/** POST /api/v2/get (200 expected); returns the per-key statuses. */
export async function getKeys(keys: readonly W.GetKey[]): Promise<W.GetStatus[]> {
  const res = await getRaw(keys);
  expect(res.status, res.status === 200 ? "" : await res.clone().text()).toBe(200);
  expect(res.headers.get("cache-control")).toBe("no-store");
  return W.decodeGetResponse(
    await bytesOf(res),
    keys.map((k) => k.mode),
  );
}

// ───────────── inbox (§10.5) ─────────────

export const randomInvite = (): W.InboxPostRow => ({
  eid: P.random(16),
  body: bigRandom(P.INBOX_BODY_LEN),
});

export const inboxPostRaw = (
  post: W.InboxPost | Bytes,
  opts: { ip?: string } = {},
): Promise<Response> =>
  postPowV2(
    "/api/v2/inbox",
    "inbox",
    post instanceof Uint8Array ? post : W.encodeInboxPost(post),
    opts,
  );

/** POST /api/v2/inbox in the current era (200 expected); returns the per-row results. */
export async function inboxPostOk(
  rows: W.InboxPostRow[],
  E = eraNow(),
): Promise<W.InboxPostResult[]> {
  const res = await inboxPostRaw({ E, bucket: 0, rows });
  expect(res.status, res.status === 200 ? "" : await res.clone().text()).toBe(200);
  return W.parseInboxPostResults(await res.json(), rows.length);
}

export const inboxReadRaw = (
  E: number,
  query = "",
  bucket = 0,
  opts: { ip?: string } = {},
): Promise<Response> => api(`/api/v2/inbox/${E}/${bucket}${query}`, { ip: opts.ip });

// ───────────── accounts and the directory (§2, §10.6) ─────────────

export const uniqueHandle = (): string => `t_${P.hex(P.random(6))}`;

export interface AccountV2 {
  AK: Bytes;
  ident: P.Identity;
  uid: Bytes;
  uidB64: string;
  handle: string;
  bundle: string;
  sig: string;
  credId: Bytes;
  /** Passkey unlock key (what the PRF output derives). */
  cred: P.UnlockKey;
  recId: Bytes;
  /** Recovery-code unlock key. */
  rec: P.UnlockKey & { id: Bytes };
  passkey: { record: string; sig: string };
  recovery: { record: string; sig: string };
}

export function makeAccountV2(handle = uniqueHandle(), uid = P.random(16)): AccountV2 {
  const AK = P.random(32);
  const ident = P.deriveIdentity(AK);
  const ts = Date.now();
  const { bundle, sig } = P.makeBundle(uid, handle, ident, ts);
  const credId = P.random(32);
  const cred = P.credKem(P.random(32), credId);
  const rec = P.recoveryKem(P.newRecoveryCode());
  return {
    AK,
    ident,
    uid,
    uidB64: P.b64u(uid),
    handle,
    bundle,
    sig,
    credId,
    cred,
    recId: rec.id,
    rec,
    passkey: P.makeWrap(uid, "passkey", credId, cred, AK, ident, ts),
    recovery: P.makeWrap(uid, "recovery", rec.id, rec, AK, ident, ts),
  };
}

export const registerBodyV2 = (a: AccountV2, wraps = [a.passkey, a.recovery]) => ({
  bundle: a.bundle,
  sig: a.sig,
  wraps,
});

/** POST /api/v2/register (200 expected); returns `dirseq`. */
export async function registerOkV2(a: AccountV2): Promise<number> {
  const res = await postJsonPow("/api/v2/register", "register", registerBodyV2(a));
  expect(res.status, await res.clone().text()).toBe(200);
  const { dirseq } = (await res.json()) as { dirseq: number };
  expect(Number.isSafeInteger(dirseq) && dirseq >= 1).toBe(true);
  return dirseq;
}

export interface DirUserV2 {
  uid: string;
  handle: string;
  bundle: string;
  sig: string;
  regEra: number;
  dirseq: number;
}

export interface DirlogEntryV2 {
  seq: number;
  kind: number;
  ref: string;
  h: string;
}

// ───────────── realtime (§10.8) ─────────────

/** GET /api/v2/rt with an upgrade (and an Origin of ORIGIN unless `origin` is given or null). */
export function rtUpgrade(opts: { ip?: string; origin?: string | null } = {}): Promise<Response> {
  const headers: Record<string, string> = { upgrade: "websocket" };
  if (opts.origin !== null) headers.origin = opts.origin ?? ORIGIN;
  return api("/api/v2/rt", { headers, ip: opts.ip });
}

export interface RtClient {
  ws: WebSocket;
  /** decoded binary frames, in arrival order */
  frames: W.ServerFrame[];
  /** raw binary frames that failed to decode */
  bad: Bytes[];
  texts: string[];
  hello: { boot: Bytes; now: number; seq: number } | null;
  closed: () => { code: number; reason: string } | null;
  /** every ROWS entry received so far */
  rows: () => W.RtRow[];
  send: (f: W.ClientFrame | Bytes | string) => void;
  until: (pred: () => boolean, what?: string, ms?: number) => Promise<void>;
  close: () => void;
}

/** Accepts a 101 response's socket and records every frame and the close event. */
export function rtClient(ws: WebSocket): RtClient {
  const c: RtClient = {
    ws,
    frames: [],
    bad: [],
    texts: [],
    hello: null,
    closed: () => closeEv,
    rows: () => c.frames.flatMap((f) => (f.f === "rows" ? f.rows : [])),
    send: (f) =>
      ws.send(typeof f === "string" || f instanceof Uint8Array ? f : W.encodeClientFrame(f)),
    until: (pred, what, ms) => until(pred, what, ms),
    close: () => {
      try {
        ws.close(1000, "done");
      } catch {
        /* already closed */
      }
    },
  };
  let closeEv: { code: number; reason: string } | null = null;
  ws.addEventListener("message", (e) => {
    if (typeof e.data === "string") {
      c.texts.push(e.data);
      return;
    }
    const b = new Uint8Array(e.data as ArrayBuffer);
    try {
      const f = W.decodeServerFrame(b);
      c.frames.push(f);
      if (f.f === "hello" && !c.hello) c.hello = { boot: f.boot, now: f.now, seq: f.seq };
    } catch {
      c.bad.push(b);
    }
  });
  ws.addEventListener("close", (e) => {
    closeEv = { code: e.code, reason: e.reason };
  });
  ws.binaryType = "arraybuffer"; // the default is "blob" at this compatibility date
  ws.accept();
  return c;
}

/** Opens /api/v2/rt through the Worker (101 expected) and waits for HELLO. */
export async function openRt(
  opts: { ip?: string; origin?: string | null; waitHello?: boolean } = {},
): Promise<RtClient> {
  const res = await rtUpgrade(opts);
  expect(res.status, res.status === 101 ? "" : await res.clone().text()).toBe(101);
  const c = rtClient(res.webSocket!);
  if (opts.waitHello !== false) await c.until(() => c.hello !== null, "HELLO");
  return c;
}
