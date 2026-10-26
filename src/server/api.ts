/**
 * HTTP API (docs/PROTOCOL.md §5). Plain fetch, no Qwik; runs before Qwik Router in the Worker entry.
 *
 * Everything the server stores is public. Writes are anonymous and gated by proof of work + per-IP rate
 * limits. The LogDO Durable Object is the authoritative log; D1 is a derived index for lookups.
 */
import { BLOB_MAX, HANDLE_RE, MAX_ID_LEN, NONCE_LEN, POW_WINDOW_MS, TAG_LEN, fromB64u, parseBundle, utf8, userTag, wrapTag } from "../lib/proto";
import { checkPow, clientTag, powParams, rateLimit } from "./abuse";
import { dec64, enc64 } from "./b64";
import {
  HttpError,
  SECURITY_HEADERS,
  contentLength,
  errorResponse,
  exactKeys,
  finalize,
  intParam,
  joinStreams,
  json,
  logErr,
  parseJsonObject,
  readBody,
  sha256,
} from "./http";
import type { LogDO } from "./log-do";
import { BATCH_MAX, LOG_PAGE_MAX, type AppendResult, type AppendRow, type Conflict, type LogPage, type PageCheck } from "./types";
import {
  checkAppendRows,
  checkBundleShape,
  checkRecordShape,
  userBody,
  verifyBundleSig,
  verifyRecordSig,
  wrapBody,
} from "./validate";

/** Request body caps (bytes). */
export const MAX_REGISTER_BODY = 64 * 1024;
export const MAX_WRAP_BODY = 16 * 1024;
/** The largest legal batch (one 16 KiB-class kind-4 row + 39 invites) is ~192 KB of JSON. */
export const MAX_APPEND_BODY = 256 * 1024;
const MAX_WRAPS_PER_REGISTER = 4;
const MAX_WRAPS_PER_ID = 64;
/** Smallest possible encrypted blob: nonce + AEAD tag + at least one padded byte. */
const BLOB_MIN = NONCE_LEN + TAG_LEN + 1;

type Ctx = { request: Request; env: Env; ctx: ExecutionContext; url: URL };

/** The single, global log sequencer. */
export function logStub(env: Env): DurableObjectStub<LogDO> {
  // `wrangler types` cannot see the class (wrangler.jsonc "main" is the build output): narrow here.
  return (env.LOG as unknown as DurableObjectNamespace<LogDO>).getByName("global");
}

const rl = (env: Env, name: "RL_WRITE" | "RL_BLOB" | "RL_READ"): RateLimit | undefined =>
  (env as unknown as Record<string, RateLimit | undefined>)[name];

function methods(c: Ctx, allowed: string[]): void {
  if (!allowed.includes(c.request.method)) {
    throw new HttpError(405, "method not allowed", { allow: allowed.join(", ") });
  }
}

const CONFLICT_MESSAGES: Record<Conflict, string> = {
  tag: "tag already used",
  handle: "handle already taken",
  uid: "uid already registered",
};

async function append(env: Env, rows: AppendRow[]): Promise<Extract<AppendResult, { ok: true }>> {
  const res = (await logStub(env).append(rows)) as AppendResult;
  if (!res.ok) throw new HttpError(409, CONFLICT_MESSAGES[res.conflict] ?? "conflict");
  return res;
}

// ───────────── handlers ─────────────

function params(c: Ctx): Response {
  const now = Date.now();
  return json({
    now,
    window: Math.floor(now / POW_WINDOW_MS),
    pow: powParams(c.env),
    limits: { batch: BATCH_MAX, blobMax: BLOB_MAX },
  });
}

async function register(c: Ctx): Promise<Response> {
  await rateLimit(rl(c.env, "RL_WRITE"), "write", c.request);
  const bytes = await readBody(c.request, MAX_REGISTER_BODY);
  checkPow(c.request, c.env, "register", await sha256(bytes), bytes.length);
  const body = exactKeys(parseJsonObject(bytes), ["bundle", "sig", "wraps"], "register");

  const user = checkBundleShape(body.bundle, body.sig);
  const wraps = body.wraps;
  if (!Array.isArray(wraps) || wraps.length < 1 || wraps.length > MAX_WRAPS_PER_REGISTER) {
    throw new HttpError(400, `wraps: expected 1..${MAX_WRAPS_PER_REGISTER} wrap records`);
  }
  const records = wraps.map((w: unknown, i) => {
    const o = exactKeys(w, ["record", "sig"], `wraps[${i}]`);
    const rec = checkRecordShape(o.record, o.sig);
    if (rec.uid !== user.uid) throw new HttpError(400, `wraps[${i}]: uid does not match the bundle`);
    return rec;
  });
  const sigOk = await Promise.all([verifyBundleSig(user), ...records.map((r) => verifyRecordSig(r, user.sigPk))]);
  if (!sigOk[0]) throw new HttpError(400, "bad bundle signature");
  const badWrap = sigOk.indexOf(false, 1);
  if (badWrap > 0) throw new HttpError(400, `wraps[${badWrap - 1}]: bad signature`);

  const rows: AppendRow[] = [
    { kind: 1, tag: userTag(fromB64u(user.uid)), body: userBody(user), handle: user.handle, uid: user.uid },
    ...records.map((r) => ({ kind: 2, tag: wrapTag(r.record), body: wrapBody(r) })),
  ];
  const tags = new Set(rows.map((r) => enc64(r.tag)));
  if (tags.size !== rows.length) throw new HttpError(400, "duplicate wrap records");

  const res = await append(c.env, rows);
  return json({ seq: res.rows[0].seq });
}

/** Looks up a registered user's bundle: D1 index first, the authoritative log as fallback. */
async function findUser(env: Env, uid: string) {
  let text: { bundle: string; sig: string } | null = null;
  try {
    text = await env.DB.prepare("SELECT bundle, sig FROM users WHERE uid = ?1").bind(uid).first<{ bundle: string; sig: string }>();
  } catch (e) {
    console.error(JSON.stringify({ msg: "d1 users lookup failed; using log", error: logErr(e) }));
  }
  if (!text) {
    const row = await logStub(env).userRow(uid);
    if (row === null) return null;
    text = JSON.parse(row) as { bundle: string; sig: string };
  }
  return parseBundle(text.bundle, text.sig); // server-validated at registration
}

async function postWrap(c: Ctx): Promise<Response> {
  await rateLimit(rl(c.env, "RL_WRITE"), "write", c.request);
  const bytes = await readBody(c.request, MAX_WRAP_BODY);
  checkPow(c.request, c.env, "wrap", await sha256(bytes), bytes.length);
  const body = exactKeys(parseJsonObject(bytes), ["record", "sig"], "wrap");
  const rec = checkRecordShape(body.record, body.sig);
  const owner = await findUser(c.env, rec.uid);
  if (!owner) throw new HttpError(404, "unknown uid");
  if (!(await verifyRecordSig(rec, owner.sigPk))) throw new HttpError(400, "bad wrap signature");
  const res = await append(c.env, [{ kind: 2, tag: wrapTag(rec.record), body: wrapBody(rec) }]);
  return json({ seq: res.rows[0].seq });
}

async function postAppend(c: Ctx): Promise<Response> {
  await rateLimit(rl(c.env, "RL_WRITE"), "write", c.request);
  const bytes = await readBody(c.request, MAX_APPEND_BODY);
  // Priced by size: every client downloads every row forever (proto.powDifficulty).
  checkPow(c.request, c.env, "append", await sha256(bytes), bytes.length);
  const body = exactKeys(parseJsonObject(bytes), ["rows"], "append");
  const rows = checkAppendRows(body.rows);
  const res = await append(c.env, rows);
  return json({ seqs: res.rows.map((r) => r.seq) });
}

/** A page that can never change (it ends below the head) may be cached by anyone, forever. */
const IMMUTABLE = "public, max-age=31536000, immutable";

/** caches.default when the runtime has it (Workers; it only stores anything on custom domains). */
function edgeCache(): Cache | null {
  const c = (globalThis as { caches?: { default?: Cache } }).caches;
  return c?.default ?? null;
}

function logResponse(body: BodyInit, immutable: boolean): Response {
  return new Response(body, {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": immutable ? IMMUTABLE : "no-store",
      ...SECURITY_HEADERS,
    },
  });
}

/**
 * GET /api/log?after=&limit= → {rows, head}. A page may hold fewer than `limit` rows while more exist (byte
 * budget): clients page until the last row's seq >= head.seq. `head` is always the current head.
 *
 * Pages that end below the head never change, so their rows are kept in the edge cache (keyed by the
 * canonical URL) and answered without making the sequencer read and encode megabytes again; the live head
 * is spliced in from a cheap lookup that also checks the cached rows still belong to this log (hash of
 * the page's last row). Tail pages are never cached (no-store).
 */
async function getLog(c: Ctx): Promise<Response> {
  await rateLimit(rl(c.env, "RL_READ"), "read", c.request);
  const q = c.url.searchParams;
  const after = intParam(q.get("after"), 0, 0, Number.MAX_SAFE_INTEGER, "after");
  const limit = intParam(q.get("limit"), LOG_PAGE_MAX, 1, LOG_PAGE_MAX, "limit");
  const stub = logStub(c.env);
  const cache = edgeCache();
  // Canonical key: junk / reordered query parameters cannot multiply cache entries.
  const key = `${c.url.origin}/api/log?after=${after}&limit=${limit}`;

  if (cache) {
    const hit = await cache.match(key).catch(() => undefined);
    if (hit?.body) {
      const lastSeq = Number(hit.headers.get("x-segv-last-seq"));
      const lastH = hit.headers.get("x-segv-last-h");
      const check = (await stub.pageCheck(lastSeq)) as PageCheck;
      if (check.h !== null && check.h === lastH && lastSeq < check.head.seq) {
        const body = joinStreams([utf8('{"rows":'), hit.body, utf8(`,"head":${JSON.stringify(check.head)}}`)]);
        return logResponse(body, true);
      }
      await hit.body.cancel().catch(() => {}); // stale (another log, e.g. a wiped dev database): rebuild
    }
  }

  const page = (await stub.page(after, limit)) as LogPage;
  const immutable = page.last !== null && page.last.seq < page.head.seq;
  if (immutable && cache) {
    const entry = new Response(page.rows, {
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": IMMUTABLE,
        "x-segv-last-seq": String(page.last!.seq),
        "x-segv-last-h": page.last!.h,
      },
    });
    c.ctx.waitUntil(
      cache.put(key, entry).catch((e: unknown) => {
        console.error(JSON.stringify({ msg: "log page cache put failed", error: logErr(e) }));
      }),
    );
  }
  return logResponse(`{"rows":${page.rows},"head":${JSON.stringify(page.head)}}`, immutable);
}

async function getUser(c: Ctx, handle: string): Promise<Response> {
  await rateLimit(rl(c.env, "RL_READ"), "read", c.request);
  if (!HANDLE_RE.test(handle)) throw new HttpError(400, "invalid handle");
  let row: { uid: string; handle: string; bundle: string; sig: string; seq: number } | null = null;
  try {
    row = await c.env.DB.prepare("SELECT uid, handle, bundle, sig, seq FROM users WHERE handle = ?1")
      .bind(handle)
      .first<{ uid: string; handle: string; bundle: string; sig: string; seq: number }>();
  } catch (e) {
    console.error(JSON.stringify({ msg: "d1 users lookup failed; using log", error: logErr(e) }));
  }
  if (!row) {
    // The D1 index can lag the log (outbox not drained yet): the log is authoritative.
    const u = await logStub(c.env).userByHandle(handle);
    if (!u) throw new HttpError(404, "no such user");
    const text = JSON.parse(u.body) as { bundle: string; sig: string };
    row = { uid: u.uid, handle, bundle: text.bundle, sig: text.sig, seq: u.seq };
  }
  return json({ uid: row.uid, handle: row.handle, bundle: row.bundle, sig: row.sig, seq: row.seq });
}

async function getWraps(c: Ctx, id: string): Promise<Response> {
  await rateLimit(rl(c.env, "RL_READ"), "read", c.request);
  let len: number;
  try {
    len = dec64(id).length;
  } catch {
    throw new HttpError(400, "invalid id");
  }
  if (len < 1 || len > MAX_ID_LEN) throw new HttpError(400, "invalid id");
  // Credential ids are public, so anyone can file wraps under a victim's id with their own uid.
  // Clients that know the uid (the WebAuthn userHandle) filter by it to skip that noise.
  const uid = c.url.searchParams.get("uid");
  if (uid !== null) {
    let uidLen = 0;
    try {
      uidLen = dec64(uid).length;
    } catch {
      /* invalid */
    }
    if (uidLen !== 16) throw new HttpError(400, "invalid uid");
  }
  const stmt =
    uid === null
      ? c.env.DB.prepare("SELECT seq, uid, record, sig FROM wraps WHERE id = ?1 ORDER BY seq LIMIT ?2").bind(id, MAX_WRAPS_PER_ID)
      : c.env.DB.prepare("SELECT seq, uid, record, sig FROM wraps WHERE id = ?1 AND uid = ?3 ORDER BY seq LIMIT ?2").bind(
          id,
          MAX_WRAPS_PER_ID,
          uid,
        );
  const { results } = await stmt.all<{ seq: number; uid: string; record: string; sig: string }>();
  return json({ wraps: results.map((r) => ({ seq: r.seq, uid: r.uid, record: r.record, sig: r.sig })) });
}

/** R2's error when the `sha256` put option does not match the bytes received (code 10037, BadDigest). */
const R2_BAD_DIGEST = /checksum you specified did not match|BadDigest|\(10037\)/i;

/**
 * PUT /api/blob/:id. The body is streamed straight into R2 (never buffered): R2 checks it against the id
 * (`sha256` option) and stores nothing on a mismatch. The PoW is over the id and priced by Content-Length.
 */
async function putBlob(c: Ctx, id: string, idBytes: Uint8Array): Promise<Response> {
  await rateLimit(rl(c.env, "RL_BLOB"), "blob", c.request);
  const declared = contentLength(c.request);
  if (declared === null) throw new HttpError(411, "content-length required");
  if (declared > BLOB_MAX) throw new HttpError(413, "blob too large");
  if (declared < BLOB_MIN) throw new HttpError(400, "blob too small");
  checkPow(c.request, c.env, "blob", idBytes, declared);

  const key = `b/${id}`;
  const existing = await c.env.BLOBS.head(key);
  if (existing) {
    await c.request.body?.cancel().catch(() => {});
    await recordBlob(c.env, id, existing.size);
    return json({ id, size: existing.size }, 201);
  }
  if (c.request.body === null) throw new HttpError(400, "blob too small");
  // Known-length stream of exactly `declared` bytes (R2 needs the length up front; a body that is
  // shorter or longer than its Content-Length errors the stream and the put).
  const fixed = new FixedLengthStream(declared);
  // Not awaited inline: if R2 rejects early the pipe settles on its own (the readable gets cancelled).
  c.ctx.waitUntil(c.request.body.pipeTo(fixed.writable).catch(() => {}));
  try {
    await c.env.BLOBS.put(key, fixed.readable, {
      httpMetadata: { contentType: "application/octet-stream" },
      sha256: idBytes.slice().buffer as ArrayBuffer,
    });
  } catch (e) {
    if (R2_BAD_DIGEST.test(String((e as Error)?.message ?? e))) throw new HttpError(400, "blob id does not match its content");
    // A concurrent upload of the same content may have won (R2 allows ~1 write/s per key): only an
    // object whose hash is the id counts. Anything else (client went away, R2 failure) is an error.
    const now = await c.env.BLOBS.head(key);
    if (!now || !sameDigest(now, idBytes)) throw e;
  }
  await recordBlob(c.env, id, declared);
  return json({ id, size: declared }, 201);
}

function sameDigest(obj: R2Object, idBytes: Uint8Array): boolean {
  const d = obj.checksums.sha256;
  return d !== undefined && enc64(new Uint8Array(d)) === enc64(idBytes);
}

const DAY_MS = 86_400_000;

/**
 * Blob registry in D1 (for quotas / GC later). Best effort: the R2 object is what matters. Not public data
 * and not derivable from the log: only the day of the upload is kept, so the registry cannot be matched
 * to the (second-precise) kind-4 row that references the blob.
 */
async function recordBlob(env: Env, id: string, size: number): Promise<void> {
  try {
    const day = Math.floor(Date.now() / DAY_MS) * DAY_MS;
    await env.DB.prepare("INSERT OR IGNORE INTO blobs (id, size, created_at) VALUES (?1, ?2, ?3)").bind(id, size, day).run();
  } catch (e) {
    console.error(JSON.stringify({ msg: "d1 blob registry insert failed", error: logErr(e) }));
  }
}

async function getBlob(c: Ctx, id: string): Promise<Response> {
  await rateLimit(rl(c.env, "RL_READ"), "read", c.request);
  // Only If-None-Match is honoured (304); other conditionals are ignored rather than mis-answered.
  const inm = c.request.headers.get("if-none-match");
  const obj = await c.env.BLOBS.get(`b/${id}`, inm === null ? undefined : { onlyIf: new Headers({ "if-none-match": inm }) });
  if (!obj) throw new HttpError(404, "no such blob");
  const headers = new Headers({
    ...SECURITY_HEADERS,
    "content-type": "application/octet-stream",
    "cache-control": "public, max-age=31536000, immutable",
    etag: obj.httpEtag,
    "content-disposition": "attachment",
    "content-security-policy": "default-src 'none'; sandbox",
    "cross-origin-resource-policy": "same-origin",
  });
  if (!("body" in obj)) return new Response(null, { status: 304, headers }); // If-None-Match hit
  headers.set("content-length", String(obj.size));
  return new Response(obj.body, { status: 200, headers });
}

/** The LogDO's WebSocket tag key, cached per isolate (the value, never a cross-request promise). */
let wsKey: Uint8Array | null = null;

async function ws(c: Ctx): Promise<Response> {
  if (c.request.headers.get("upgrade")?.toLowerCase() !== "websocket") throw new HttpError(426, "expected websocket");
  // Browsers always send Origin on WebSocket handshakes: refuse pages on other sites (they could otherwise
  // recruit their visitors to hold sockets). Non-browser clients send none.
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
  await rateLimit(rl(c.env, "RL_READ"), "read", c.request);
  const stub = logStub(c.env);
  wsKey ??= new Uint8Array(await stub.wsTagKey());
  // Hand the DO a minimal request: the upgrade plus an opaque per-client tag, never client headers / IPs.
  const res = await stub.fetch("https://log.internal/ws", {
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

// ───────────── router ─────────────

const BLOB_PATH = /^\/api\/blob\/([A-Za-z0-9_-]{43})$/;
const USER_PATH = /^\/api\/users\/([^/]{1,64})$/;
const WRAPS_PATH = /^\/api\/wraps\/([^/]{1,1400})$/;

async function route(c: Ctx): Promise<Response> {
  const path = c.url.pathname;
  switch (path) {
    case "/api/params":
      methods(c, ["GET"]);
      return params(c);
    case "/api/register":
      methods(c, ["POST"]);
      return register(c);
    case "/api/wraps":
      methods(c, ["POST"]);
      return postWrap(c);
    case "/api/append":
      methods(c, ["POST"]);
      return postAppend(c);
    case "/api/log":
      methods(c, ["GET"]);
      return getLog(c);
    case "/api/ws":
      methods(c, ["GET"]);
      return ws(c);
  }
  let m = USER_PATH.exec(path);
  if (m) {
    methods(c, ["GET"]);
    return getUser(c, m[1]);
  }
  m = WRAPS_PATH.exec(path);
  if (m) {
    methods(c, ["GET"]);
    return getWraps(c, m[1]);
  }
  if (path.startsWith("/api/blob/")) {
    methods(c, ["GET", "PUT"]);
    m = BLOB_PATH.exec(path);
    let idBytes: Uint8Array | null = null;
    try {
      if (m) idBytes = dec64(m[1]);
    } catch {
      /* non-canonical */
    }
    if (!m || !idBytes || idBytes.length !== 32) throw new HttpError(400, "invalid blob id");
    return c.request.method === "PUT" ? putBlob(c, m[1], idBytes) : getBlob(c, m[1]);
  }
  throw new HttpError(404, "not found");
}

/** Path for logs without the ids / handles in it. */
function routeLabel(path: string): string {
  if (path.startsWith("/api/blob/")) return "/api/blob/:id";
  if (USER_PATH.test(path)) return "/api/users/:handle";
  if (WRAPS_PATH.test(path)) return "/api/wraps/:id";
  return ["/api/params", "/api/register", "/api/wraps", "/api/append", "/api/log", "/api/ws"].includes(path) ? path : "/api/*";
}

export async function handleApi(request: Request, env: Env, ctx: ExecutionContext, url: URL): Promise<Response> {
  let res: Response;
  try {
    res = await route({ request, env, ctx, url });
  } catch (e) {
    if (e instanceof HttpError) {
      res = errorResponse(e.status, e.message, e.headers);
      // Refused before the body was read (PoW, size, rate limit): release it instead of leaving it pending.
      if (request.body !== null && !request.bodyUsed) ctx.waitUntil(request.body.cancel().catch(() => {}));
    } else {
      // Never log request bodies, ids or client addresses.
      console.error(JSON.stringify({ msg: "api error", method: request.method, route: routeLabel(url.pathname), error: logErr(e) }));
      res = errorResponse(500, "internal error");
    }
  }
  return finalize(res, url);
}
