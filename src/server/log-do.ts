/**
 * LogDO — the single sequencer of the public, append-only, hash-chained log (docs/PROTOCOL.md §4).
 * One instance: env.LOG.getByName("global"). SQLite-backed.
 *
 *  - append(rows): one synchronous transaction checks every tag / handle / uid, assigns consecutive
 *    seqs, chains h_seq = rowHash(h_{seq-1}, ...) and inserts. All-or-nothing.
 *  - since(after, limit) / page(after, limit): rows ascending + current head. A page holds at most `limit`
 *    rows and ~LOG_PAGE_BODY_BUDGET body bytes, so it can be short while more rows exist.
 *  - fetch(): WebSocket upgrade (hibernation API). Every successful append is broadcast to every socket.
 *    Sockets are capped globally and per client (opaque tag), live at most WS_MAX_AGE_MS, and are closed
 *    when they send anything but "ping".
 *  - D1 (derived index of kind-1/2 rows) is fed through a transactional outbox: rows are queued in the
 *    same transaction as the append, the retry alarm is armed in that same commit, and the outbox is
 *    drained to D1 afterwards (the alarm is cleared once it is empty). A D1 failure or stall never undoes
 *    or blocks an append for long.
 */
import { DurableObject } from "cloudflare:workers";
import { HANDLE_RE, ZERO32, fromUtf8, rowHash, userTag } from "../lib/proto";
import { dec64, enc64 } from "./b64";
import { indexStatement } from "./d1-index";
import { logErr } from "./http";
import {
  BATCH_MAX,
  BATCH_MAX_KIND4,
  LOG_PAGE_BODY_BUDGET,
  LOG_PAGE_MAX,
  type AppendResult,
  type AppendRow,
  type Conflict,
  type LogPage,
  type PageCheck,
  type SinceResult,
  type UserRow,
  type WireHead,
  type WireRow,
} from "./types";

/** Upper bound for any row body (the largest legal body is a 16 KiB-class message, 16424 bytes). */
const MAX_ROW_BODY = 64 * 1024;
const INDEX_CHUNK = 50;
const INDEX_RETRY_MS = 60_000;
/** How long append() waits for the D1 index before answering anyway (the alarm finishes the job). */
const INDEX_WAIT_MS = 2_000;
/** A D1 batch that takes longer counts as failed (retried by the alarm; INSERT OR IGNORE is idempotent). */
const INDEX_BATCH_TIMEOUT_MS = 30_000;

/** WebSocket limits. The runtime allows 32,768 hibernatable sockets per object; stay well below. */
const WS_MAX_TOTAL = 20_000;
const WS_MAX_PER_CLIENT = 8;
/** Sockets are closed after this age (checked on broadcast and when a cap is hit); clients reconnect + backfill. */
const WS_MAX_AGE_MS = 60 * 60_000;
const WS_CLIENT_TAG_RE = /^[0-9a-f]{32}$/;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS log (
  seq INTEGER PRIMARY KEY,
  kind INTEGER NOT NULL,
  tag BLOB NOT NULL UNIQUE,
  body BLOB NOT NULL,
  ts INTEGER NOT NULL,
  h BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS handles (
  handle TEXT PRIMARY KEY,
  uid TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS d1_outbox (
  seq INTEGER PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v BLOB NOT NULL
);
`;

type LogRow = { seq: number; kind: number; tag: ArrayBuffer; body: ArrayBuffer; ts: number; h: ArrayBuffer };

/** Exact-size ArrayBuffer for SQL binding (a view may sit on a larger buffer). */
function ab(b: Uint8Array): ArrayBuffer {
  return b.byteOffset === 0 && b.byteLength === b.buffer.byteLength && b.buffer instanceof ArrayBuffer
    ? b.buffer
    : (b.slice().buffer as ArrayBuffer);
}

/** Defensive re-validation of RPC input (the API layer validates too). Returns detached copies. */
function checkRows(input: unknown): AppendRow[] {
  if (!Array.isArray(input) || input.length < 1 || input.length > BATCH_MAX) throw new TypeError("append: bad batch size");
  let users = 0;
  let kind4 = 0;
  const rows = input.map((r: unknown): AppendRow => {
    if (typeof r !== "object" || r === null) throw new TypeError("append: bad row");
    const { kind, tag, body, handle, uid } = r as Record<string, unknown>;
    if (kind !== 1 && kind !== 2 && kind !== 3 && kind !== 4) throw new TypeError("append: bad kind");
    if (!(tag instanceof Uint8Array) || tag.length !== 16) throw new TypeError("append: bad tag");
    if (!(body instanceof Uint8Array) || body.length < 1 || body.length > MAX_ROW_BODY) throw new TypeError("append: bad body");
    if (kind === 4) kind4++;
    if (kind === 1) {
      if (typeof handle !== "string" || !HANDLE_RE.test(handle)) throw new TypeError("append: bad handle");
      if (typeof uid !== "string" || dec64(uid).length !== 16) throw new TypeError("append: bad uid");
      users++;
      return { kind, tag: tag.slice(), body: body.slice(), handle, uid };
    }
    if (handle !== undefined || uid !== undefined) throw new TypeError("append: handle/uid only on kind 1");
    return { kind, tag: tag.slice(), body: body.slice() };
  });
  if (users > 1) throw new TypeError("append: at most one user row per batch");
  if (kind4 > BATCH_MAX_KIND4) throw new TypeError("append: at most one kind-4 row per batch");
  return rows;
}

/**
 * Waits for `p` at most `ms` (and does not leave the timer behind when `p` wins). On timeout it resolves,
 * or rejects with `timeoutError` when one is given.
 */
async function waitAtMost<T>(p: Promise<T>, ms: number, timeoutError?: Error): Promise<T | void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      p,
      new Promise<void>((resolve, reject) => (timer = setTimeout(() => (timeoutError ? reject(timeoutError) : resolve()), ms))),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export class LogDO extends DurableObject<Env> {
  private head: { seq: number; h: Uint8Array };
  private indexing: Promise<void> | null = null;
  private indexAgain = false;
  private tagKey: Uint8Array | null = null;
  /** Instance fields (not constants) so tests can lower them. */
  protected wsLimits = { total: WS_MAX_TOTAL, perClient: WS_MAX_PER_CLIENT, maxAgeMs: WS_MAX_AGE_MS };
  protected indexTimeouts = { waitMs: INDEX_WAIT_MS, batchMs: INDEX_BATCH_TIMEOUT_MS };

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const sql = ctx.storage.sql;
    sql.exec(SCHEMA);
    const last = sql.exec<{ seq: number; h: ArrayBuffer }>("SELECT seq, h FROM log ORDER BY seq DESC LIMIT 1").toArray()[0];
    this.head = last ? { seq: last.seq, h: new Uint8Array(last.h) } : { seq: 0, h: ZERO32 };
    // Answered by the runtime without waking the object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    // Outbox rows left behind without an alarm (e.g. by an older version): make sure they get drained.
    if (sql.exec("SELECT 1 FROM d1_outbox LIMIT 1").toArray().length > 0) {
      void ctx.blockConcurrencyWhile(async () => {
        if ((await ctx.storage.getAlarm()) === null) await ctx.storage.setAlarm(Date.now() + 1000);
      });
    }
  }

  private wireHead(): WireHead {
    return { seq: this.head.seq, h: enc64(this.head.h) };
  }

  /** Appends a batch atomically. Never awaits between the checks and the inserts. */
  async append(input: AppendRow[]): Promise<AppendResult> {
    const rows = checkRows(input);
    const sql = this.ctx.storage.sql;
    const ts = Math.floor(Date.now() / 1000) * 1000;
    const hashes: Uint8Array[] = [];
    let next = this.head;

    const conflict = this.ctx.storage.transactionSync((): Conflict | null => {
      const seen = new Set<string>();
      for (const r of rows) {
        const key = enc64(r.tag);
        if (seen.has(key)) return "tag";
        seen.add(key);
        if (sql.exec("SELECT 1 FROM log WHERE tag = ?", ab(r.tag)).toArray().length > 0) return "tag";
        if (r.handle !== undefined) {
          if (sql.exec("SELECT 1 FROM handles WHERE handle = ?", r.handle).toArray().length > 0) return "handle";
          if (sql.exec("SELECT 1 FROM handles WHERE uid = ?", r.uid!).toArray().length > 0) return "uid";
        }
      }
      let { seq, h } = this.head;
      for (const r of rows) {
        seq += 1;
        h = rowHash(h, seq, r.kind, r.tag, r.body, ts);
        sql.exec("INSERT INTO log (seq, kind, tag, body, ts, h) VALUES (?, ?, ?, ?, ?, ?)", seq, r.kind, ab(r.tag), ab(r.body), ts, ab(h));
        if (r.handle !== undefined) sql.exec("INSERT INTO handles (handle, uid) VALUES (?, ?)", r.handle, r.uid!);
        if (r.kind === 1 || r.kind === 2) sql.exec("INSERT INTO d1_outbox (seq) VALUES (?)", seq);
        hashes.push(h);
      }
      next = { seq, h };
      return null;
    });
    if (conflict) return { ok: false, conflict };

    // Committed (the transaction threw otherwise): advance the in-memory head.
    this.head = next;
    const indexed = rows.some((r) => r.kind === 1 || r.kind === 2);
    // Arm the index retry before any await, so it is committed together with the outbox rows (write
    // coalescing): if the object is reset while flushing, the alarm still drains them. Cleared once drained.
    if (indexed) this.armIndexAlarm(INDEX_RETRY_MS);
    const first = next.seq - rows.length + 1;
    const wire: WireRow[] = rows.map((r, i) => ({
      seq: first + i,
      kind: r.kind,
      tag: enc64(r.tag),
      body: enc64(r.body),
      ts,
      h: enc64(hashes[i]),
    }));
    this.broadcast(wire);
    // Give callers read-your-writes on /api/users and /api/wraps when D1 is healthy, but never hold the
    // response hostage to a stalled D1: the flush continues in the background and the alarm retries.
    // flushIndex() never throws.
    if (indexed) await waitAtMost(this.flushIndex(), this.indexTimeouts.waitMs);
    return { ok: true, rows: wire.map(({ seq, h }) => ({ seq, ts, h })), head: this.wireHead() };
  }

  /** Rows with seq > after, ascending, at most `limit` rows and ~LOG_PAGE_BODY_BUDGET body bytes. */
  since(after: number, limit: number): SinceResult {
    if (!Number.isSafeInteger(after) || after < 0) throw new RangeError("since: bad after");
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > LOG_PAGE_MAX) throw new RangeError("since: bad limit");
    const rows: WireRow[] = [];
    let bytes = 0;
    const cur = this.ctx.storage.sql.exec<LogRow>(
      "SELECT seq, kind, tag, body, ts, h FROM log WHERE seq > ? ORDER BY seq LIMIT ?",
      after,
      limit,
    );
    for (const r of cur) {
      if (rows.length > 0 && bytes + r.body.byteLength > LOG_PAGE_BODY_BUDGET) break;
      bytes += r.body.byteLength;
      rows.push({
        seq: r.seq,
        kind: r.kind,
        tag: enc64(new Uint8Array(r.tag)),
        body: enc64(new Uint8Array(r.body)),
        ts: r.ts,
        h: enc64(new Uint8Array(r.h)),
      });
    }
    // Read synchronously with the rows: the head is the current one and always >= the last row's seq.
    return { rows, head: this.wireHead() };
  }

  /**
   * since() with the rows serialised here, so the Worker forwards one string instead of structured-cloning
   * and re-serialising up to ~5 MB of rows (Workers CPU budget). See LogPage for `last`.
   */
  page(after: number, limit: number): LogPage {
    const { rows, head } = this.since(after, limit);
    const l = rows[rows.length - 1];
    return { rows: JSON.stringify(rows), head, last: l ? { seq: l.seq, h: l.h } : null };
  }

  /** Current head and the hash of row `seq` (cheap PK lookup): lets the Worker validate a cached page. */
  pageCheck(seq: number): PageCheck {
    if (!Number.isSafeInteger(seq) || seq < 1) return { head: this.wireHead(), h: null };
    const r = this.ctx.storage.sql.exec<{ h: ArrayBuffer }>("SELECT h FROM log WHERE seq = ?", seq).toArray()[0];
    return { head: this.wireHead(), h: r ? enc64(new Uint8Array(r.h)) : null };
  }

  /** The kind-1 row body (JSON text {bundle, sig}) of `uid` (b64u), or null. Authoritative user lookup. */
  userRow(uid: string): string | null {
    const tag = userTag(dec64(uid));
    const r = this.ctx.storage.sql
      .exec<{ body: ArrayBuffer }>("SELECT body FROM log WHERE tag = ? AND kind = 1", ab(tag))
      .toArray()[0];
    return r ? fromUtf8(new Uint8Array(r.body)) : null;
  }

  /** The registration row of `handle` straight from the log, or null (fallback for a lagging D1 index). */
  userByHandle(handle: string): UserRow | null {
    if (typeof handle !== "string" || !HANDLE_RE.test(handle)) return null;
    const sql = this.ctx.storage.sql;
    const u = sql.exec<{ uid: string }>("SELECT uid FROM handles WHERE handle = ?", handle).toArray()[0];
    if (!u) return null;
    const r = sql
      .exec<{ seq: number; body: ArrayBuffer }>("SELECT seq, body FROM log WHERE tag = ? AND kind = 1", ab(userTag(dec64(u.uid))))
      .toArray()[0];
    return r ? { uid: u.uid, seq: r.seq, body: fromUtf8(new Uint8Array(r.body)) } : null;
  }

  /**
   * Random 32-byte secret (created once, kept in this object's storage) that the Worker uses to turn a
   * client's rate-limit key into an opaque WebSocket tag. Client addresses never reach this object.
   */
  wsTagKey(): Uint8Array {
    if (this.tagKey) return this.tagKey;
    const sql = this.ctx.storage.sql;
    const row = sql.exec<{ v: ArrayBuffer }>("SELECT v FROM meta WHERE k = 'ws-tag-key'").toArray()[0];
    if (row) {
      this.tagKey = new Uint8Array(row.v);
    } else {
      const k = crypto.getRandomValues(new Uint8Array(32));
      sql.exec("INSERT INTO meta (k, v) VALUES ('ws-tag-key', ?)", ab(k));
      this.tagKey = k;
    }
    return this.tagKey;
  }

  // ───────────── WebSocket feed (hibernation API) ─────────────

  /**
   * Upgrade from the Worker (api.ts). The only client-derived input is `x-segv-client`: an opaque tag
   * (HMAC of the rate-limit key under wsTagKey()). Never client headers / IPs.
   */
  async fetch(request: Request): Promise<Response> {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return Response.json({ error: "expected websocket" }, { status: 426 });
    }
    const raw = request.headers.get("x-segv-client") ?? "";
    const tag = `c:${WS_CLIENT_TAG_RE.test(raw) ? raw : "none"}`;
    const now = Date.now();
    const { total, perClient } = this.wsLimits;
    if (this.liveCount(this.ctx.getWebSockets(tag), now) >= perClient) {
      return Response.json({ error: "too many connections from this client" }, { status: 429, headers: { "retry-after": "60" } });
    }
    if (this.liveCount(this.ctx.getWebSockets(), now) >= total) {
      return Response.json({ error: "too many connections" }, { status: 503, headers: { "retry-after": "60" } });
    }
    const [client, server] = Object.values(new WebSocketPair());
    try {
      this.ctx.acceptWebSocket(server, [tag]);
      server.serializeAttachment({ t: now });
    } catch (e) {
      console.error(JSON.stringify({ msg: "ws accept failed", error: logErr(e) }));
      return Response.json({ error: "too many connections" }, { status: 503, headers: { "retry-after": "60" } });
    }
    return new Response(null, { status: 101, webSocket: client });
  }

  /** Clients only ever send "ping" (normally auto-answered without waking us). Anything else: close. */
  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (message === "ping") {
      ws.send("pong");
      return;
    }
    this.closeSocket(ws, 1008, 'only "ping" is accepted');
  }
  // With compatibility_date >= 2026-04-07 the runtime completes the close handshake itself.
  async webSocketClose(): Promise<void> {}
  async webSocketError(): Promise<void> {}

  private expired(ws: WebSocket, now: number): boolean {
    let t: unknown;
    try {
      t = (ws.deserializeAttachment() as { t?: unknown } | null)?.t;
    } catch {
      /* no / unreadable attachment */
    }
    return typeof t !== "number" || now - t > this.wsLimits.maxAgeMs;
  }

  private closeSocket(ws: WebSocket, code: number, reason: string): void {
    try {
      ws.close(code, reason);
    } catch {
      // already closing
    }
  }

  /** Closes expired sockets in `sockets` and returns how many are left. */
  private liveCount(sockets: WebSocket[], now: number): number {
    let n = 0;
    for (const ws of sockets) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      if (this.expired(ws, now)) this.closeSocket(ws, 4000, "max age");
      else n++;
    }
    return n;
  }

  private broadcast(rows: WireRow[]): void {
    const sockets = this.ctx.getWebSockets();
    if (sockets.length === 0) return;
    const msg = JSON.stringify({ type: "rows", rows });
    const now = Date.now();
    for (const ws of sockets) {
      if (this.expired(ws, now)) {
        this.closeSocket(ws, 4000, "max age"); // the client reconnects and backfills via GET /api/log
        continue;
      }
      try {
        ws.send(msg);
      } catch {
        // socket is closing; the client reconnects and backfills via GET /api/log
      }
    }
  }

  // ───────────── D1 index (transactional outbox) ─────────────

  async alarm(): Promise<void> {
    await this.flushIndex();
  }

  /** Not awaited on purpose: called in the same synchronous block as the commit it belongs to. */
  private armIndexAlarm(delayMs: number): void {
    this.ctx.storage.setAlarm(Date.now() + delayMs).catch((e: unknown) => {
      console.error(JSON.stringify({ msg: "setAlarm failed", error: logErr(e) }));
    });
  }

  /** Single-flight drain of the outbox into D1. Never throws. */
  private flushIndex(): Promise<void> {
    if (this.indexing) {
      this.indexAgain = true;
      return this.indexing;
    }
    const run = async (): Promise<void> => {
      try {
        do {
          this.indexAgain = false;
          await this.drainOutbox();
        } while (this.indexAgain);
      } catch (e) {
        console.error(JSON.stringify({ msg: "d1 index failed; retrying via alarm", error: logErr(e) }));
        this.armIndexAlarm(INDEX_RETRY_MS);
      }
    };
    this.indexing = run().finally(() => {
      this.indexing = null;
    });
    return this.indexing;
  }

  private async drainOutbox(): Promise<void> {
    const sql = this.ctx.storage.sql;
    for (;;) {
      const batch = sql
        .exec<{ seq: number; kind: number; body: ArrayBuffer }>(
          "SELECT o.seq AS seq, l.kind AS kind, l.body AS body FROM d1_outbox o JOIN log l ON l.seq = o.seq ORDER BY o.seq LIMIT ?",
          INDEX_CHUNK,
        )
        .toArray();
      if (batch.length === 0) {
        // Empty, checked synchronously: an append that queues more rows after this point arms a new alarm.
        this.ctx.storage.deleteAlarm().catch((e: unknown) => {
          console.error(JSON.stringify({ msg: "deleteAlarm failed", error: logErr(e) }));
        });
        return;
      }
      const stmts: D1PreparedStatement[] = [];
      for (const r of batch) {
        const s = indexStatement(this.env.DB, r.seq, r.kind, new Uint8Array(r.body));
        if (s) stmts.push(s);
        else console.error(JSON.stringify({ msg: "d1 index: unindexable row skipped", seq: r.seq }));
      }
      if (stmts.length > 0) await waitAtMost(this.env.DB.batch(stmts), this.indexTimeouts.batchMs, new Error("d1 batch timed out"));
      // Rows appended meanwhile have larger seqs and stay queued.
      sql.exec("DELETE FROM d1_outbox WHERE seq <= ?", batch[batch.length - 1].seq);
    }
  }
}
