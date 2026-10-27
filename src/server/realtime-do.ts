/**
 * RealtimeDO — topic-filtered delivery of published rows over hibernatable WebSockets (docs/PROTOCOL.md §9.4,
 * §10.8). One instance, "rt/v2/0". Storage holds only `meta` ('ws-tag-key'); nothing about topics, subscriptions
 * or rows is ever persisted (§13.1).
 *
 *  - fetch(): upgrade from the Worker. The only client-derived input is `x-segv-client`, an opaque tag. Sockets
 *    carry the tags [clientTag, "h:" + accept hour] and the attachment {t, topics, win, frames, changes}; caps
 *    are counted with getWebSockets(tag) only (attachments are never deserialised to count).
 *  - In memory: `boot` (8 random bytes per construction) and `seq` (u64 per boot); a mirror of the attachments
 *    with an index 8-byte topic prefix → sockets (full 16-byte compare on delivery), rebuilt lazily after a wake;
 *    the (topic, socket) pair count; a ring of the last 10 min / 8192 rows / 16 MiB of published rows for RESUME.
 *  - webSocketMessage(): "ping" (normally auto-answered), SUB / UNSUB / RESUME. Anything else, or a limit
 *    exceeded, closes with 1008; a SUB beyond the global pair budget closes with 1013.
 *  - RESUME: GAP(since) unless the boot is current, `since` ≤ the last assigned seq and the ring still holds every
 *    row after it; also GAP when the rows to replay exceed `replayBytes` (the client catches up instead).
 *  - publish(): assigns seqs, appends to the ring, sends one ROWS frame per subscribed socket; sockets that get the
 *    same rows share one encoding.
 *  - Sockets older than 1 h are closed with 4000 (hour tags older than the previous hour whenever sockets are
 *    counted or sent to, and the exact age before sending).
 */
import { DurableObject } from "cloudflare:workers";
import { BODY_LENS, byteCmp, equalBytes } from "../lib/proto";
import { RT_MAX_CLIENT_FRAME, RT_MAX_TOPICS, decodeClientFrame, encodeServerFrame, type ClientFrame, type RtRow } from "../lib/wire";
import { logErr } from "./http";
import type { RtPublishRow } from "./types";

const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const CLIENT_TAG_RE = /^[0-9a-f]{32}$/;
/** Bytes of one row in a ROWS frame besides the body: seq, topic, E, label, t, cls. */
const ROW_WIRE_OVERHEAD = 8 + 16 + 2 + 16 + 4 + 1;
/** A ROWS frame holds at most this many bytes of rows (replays are split; one row always fits). */
const ROWS_FRAME_BUDGET = 512 * 1024;
const ROWS_FRAME_MAX_ROWS = 0xffff;

export interface RtLimits {
  /** live sockets per client tag */
  perClient: number;
  /** live sockets in total (the runtime allows 32 768 hibernatable sockets per object) */
  total: number;
  /** sockets older than this are closed with 4000 */
  maxAgeMs: number;
  /** topics per socket */
  topics: number;
  /** (topic, socket) pairs in total; a SUB beyond it closes with 1013 */
  pairs: number;
  /** SUB / UNSUB frames per socket per minute */
  framesPerMin: number;
  /** topics carried by SUB / UNSUB frames per socket per minute */
  changesPerMin: number;
  /** largest client frame */
  frameBytes: number;
  /** the RESUME ring keeps rows at most this old, */
  ringMs: number;
  /** at most this many rows, */
  ringRows: number;
  /** and at most this many bytes (rows as encoded in ROWS frames) */
  ringBytes: number;
  /** a RESUME whose replay would exceed this many bytes (rows as encoded in ROWS frames) gets GAP instead */
  replayBytes: number;
}

const RT_LIMITS: Readonly<RtLimits> = {
  perClient: 8,
  total: 20_000,
  maxAgeMs: HOUR_MS,
  topics: RT_MAX_TOPICS,
  pairs: 250_000,
  framesPerMin: 30,
  changesPerMin: 2048,
  frameBytes: RT_MAX_CLIENT_FRAME,
  ringMs: 10 * MINUTE_MS,
  ringRows: 8192,
  ringBytes: 16 * 1024 * 1024,
  replayBytes: 2 * 1024 * 1024,
};

/**
 * Per-socket attachment (§9.4). `topics` is 16·n bytes, sorted and without duplicates. `win` is the minute of the
 * rate window and stays 0 until the first binary frame, which is how "RESUME only as the first binary frame"
 * survives hibernation.
 */
interface Att {
  t: number;
  topics: Uint8Array;
  win: number;
  frames: number;
  changes: number;
}

interface RingRow extends RtRow {
  /** publish time (ms) */
  at: number;
  /** encoded size in a ROWS frame */
  size: number;
}

const prefixOf = (t: Uint8Array, off = 0): bigint => new DataView(t.buffer, t.byteOffset + off, 8).getBigUint64(0);
const topicAt = (topics: Uint8Array, i: number): Uint8Array => topics.subarray(16 * i, 16 * i + 16);
const countOf = (topics: Uint8Array): number => topics.length / 16;

/** Binary search in a sorted topic list (full 16-byte compare). */
function hasTopic(topics: Uint8Array, t: Uint8Array): boolean {
  let lo = 0;
  let hi = countOf(topics) - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const c = byteCmp(topicAt(topics, mid), t);
    if (c === 0) return true;
    if (c < 0) lo = mid + 1;
    else hi = mid - 1;
  }
  return false;
}

/** Sorted, de-duplicated topic list (16·n bytes). */
function topicList(list: Uint8Array[]): Uint8Array {
  const sorted = [...list].sort(byteCmp);
  const out = new Uint8Array(16 * sorted.length);
  let n = 0;
  for (const t of sorted) {
    if (n > 0 && byteCmp(topicAt(out, n - 1), t) === 0) continue;
    out.set(t, 16 * n++);
  }
  return out.slice(0, 16 * n);
}

const split = (topics: Uint8Array): Uint8Array[] => Array.from({ length: countOf(topics) }, (_, i) => topicAt(topics, i));

/** ROWS frames for `rows`, split by size (one row always fits). */
function rowFrames(rows: RingRow[]): Uint8Array[] {
  const out: Uint8Array[] = [];
  let i = 0;
  while (i < rows.length) {
    let bytes = 0;
    let j = i;
    while (j < rows.length && j - i < ROWS_FRAME_MAX_ROWS && (j === i || bytes + rows[j].size <= ROWS_FRAME_BUDGET)) {
      bytes += rows[j].size;
      j++;
    }
    out.push(encodeServerFrame({ f: "rows", rows: rows.slice(i, j) }));
    i = j;
  }
  return out;
}

function openCount(sockets: WebSocket[]): number {
  let n = 0;
  for (const ws of sockets) if (ws.readyState === WebSocket.OPEN) n++;
  return n;
}

function refuse(status: 429 | 503, error: string): Response {
  return Response.json({ error }, { status, headers: { "retry-after": "60" } });
}

/** Validates an attachment read back after a wake; null when it is not one of ours. */
function asAtt(x: unknown): Att | null {
  if (typeof x !== "object" || x === null) return null;
  const { t, topics, win, frames, changes } = x as Record<string, unknown>;
  if (typeof t !== "number" || !(topics instanceof Uint8Array) || topics.length % 16 !== 0) return null;
  if (typeof win !== "number" || typeof frames !== "number" || typeof changes !== "number") return null;
  return { t, topics, win, frames, changes };
}

/** Defensive re-validation of publish() input (the Worker validates too). */
function checkPublish(input: unknown): RtPublishRow[] {
  if (!Array.isArray(input)) throw new TypeError("publish: bad rows");
  return input.map((r: unknown) => {
    const { topic, E, label, t, cls, body } = (typeof r === "object" && r !== null ? r : {}) as Record<string, unknown>;
    if (!(topic instanceof Uint8Array) || topic.length !== 16) throw new TypeError("publish: bad topic");
    if (!Number.isInteger(E) || (E as number) < 0 || (E as number) > 0xffff) throw new TypeError("publish: bad era");
    if (!(label instanceof Uint8Array) || label.length !== 16) throw new TypeError("publish: bad label");
    if (!Number.isInteger(t) || (t as number) < 0 || (t as number) > 0xffffffff) throw new TypeError("publish: bad t");
    if (!Number.isInteger(cls) || BODY_LENS[cls as number] === undefined) throw new TypeError("publish: bad class");
    if (!(body instanceof Uint8Array) || body.length !== BODY_LENS[cls as number]) throw new TypeError("publish: bad body");
    return { topic, E: E as number, label, t: t as number, cls: cls as number, body };
  });
}

export class RealtimeDO extends DurableObject<Env> {
  /** Time source (Unix ms). An instance field so tests can step the clock. */
  protected clock: () => number = () => Date.now();
  /** Instance field (not constants) so tests can lower the caps, the pair budget and the ring. */
  protected limits: RtLimits = { ...RT_LIMITS };

  private readonly boot: Uint8Array = crypto.getRandomValues(new Uint8Array(8));
  /** last assigned seq (per boot) */
  private seq = 0;
  private tagKey: Uint8Array | null = null;

  /** Attachments of the open sockets, rebuilt lazily after a wake (null until then). */
  private socks: Map<WebSocket, Att> | null = null;
  /** 8-byte topic prefix → sockets with a topic of that prefix */
  private readonly index = new Map<bigint, Set<WebSocket>>();
  /** (topic, socket) pairs over every open socket */
  private pairs = 0;
  /** accept hours that may still have sockets (null until enumerated after a wake) */
  private hours: Set<number> | null = null;

  /** RESUME ring: ring[ringStart..] are live, ascending and contiguous in seq. */
  private ring: (RingRow | undefined)[] = [];
  private ringStart = 0;
  private ringSize = 0;
  /** highest seq dropped from the ring (0 = none): the ring holds every row with seq > evicted */
  private evicted = 0;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID");
    // Answered by the runtime without waking the object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  /**
   * Random 32-byte secret (created once, kept in storage) that the Worker uses to turn a client's rate-limit
   * key into the opaque client tag. Client addresses never reach this object.
   */
  wsTagKey(): Uint8Array {
    if (this.tagKey) return this.tagKey;
    const sql = this.ctx.storage.sql;
    const row = sql.exec<{ v: ArrayBuffer }>("SELECT v FROM meta WHERE k = 'ws-tag-key'").toArray()[0];
    if (row) {
      this.tagKey = new Uint8Array(row.v);
    } else {
      const k = crypto.getRandomValues(new Uint8Array(32));
      sql.exec("INSERT INTO meta (k, v) VALUES ('ws-tag-key', ?)", k.buffer);
      this.tagKey = k;
    }
    return this.tagKey;
  }

  // ───────────── accept ─────────────

  /** Upgrade from the Worker (§9.4 fetch). Only `upgrade` and `x-segv-client` are read. */
  async fetch(request: Request): Promise<Response> {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return Response.json({ error: "expected websocket" }, { status: 426 });
    }
    const raw = request.headers.get("x-segv-client") ?? "";
    const clientTag = CLIENT_TAG_RE.test(raw) ? raw : "none";
    const now = this.clock();
    this.sweep(now);
    if (openCount(this.ctx.getWebSockets(clientTag)) >= this.limits.perClient) {
      return refuse(429, "too many connections from this client");
    }
    if (openCount(this.ctx.getWebSockets()) >= this.limits.total) return refuse(503, "too many connections");

    const hour = Math.floor(now / HOUR_MS);
    const [client, server] = Object.values(new WebSocketPair());
    const att: Att = { t: now, topics: new Uint8Array(0), win: 0, frames: 0, changes: 0 };
    try {
      this.ctx.acceptWebSocket(server, [clientTag, `h:${hour}`]);
      server.serializeAttachment(att);
      server.send(encodeServerFrame({ f: "hello", boot: this.boot, now, seq: this.seq }));
    } catch (e) {
      console.error(JSON.stringify({ msg: "rt accept failed", error: logErr(e) }));
      this.close(server, 1011, "accept failed");
      return refuse(503, "too many connections");
    }
    this.hours?.add(hour);
    this.socks?.set(server, att);
    return new Response(null, { status: 101, webSocket: client });
  }

  // ───────────── client frames ─────────────

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message === "string") {
      if (message === "ping") this.trySend(ws, "pong");
      else this.drop(ws, 1008, "unexpected text frame");
      return;
    }
    const att = this.mirror().get(ws);
    if (!att) return; // not open any more
    const now = this.clock();
    if (now - att.t > this.limits.maxAgeMs) return this.drop(ws, 4000, "max age");
    const m: unknown = message; // ArrayBuffer from the hibernation API; a view is accepted too
    const bytes: Uint8Array | null =
      m instanceof ArrayBuffer ? new Uint8Array(m) : ArrayBuffer.isView(m) ? new Uint8Array(m.buffer, m.byteOffset, m.byteLength) : null;
    if (!bytes) return this.drop(ws, 1008, "unexpected frame");
    if (bytes.length > this.limits.frameBytes) return this.drop(ws, 1008, "frame too large");
    let f: ClientFrame;
    try {
      f = decodeClientFrame(bytes);
    } catch {
      return this.drop(ws, 1008, "malformed frame");
    }
    const minute = Math.floor(now / MINUTE_MS);
    const L = this.limits;

    if (f.f === "resume") {
      if (att.win !== 0) return this.drop(ws, 1008, "RESUME must be the first binary frame");
      att.win = minute;
      const next = topicList(f.topics);
      if (countOf(next) > L.topics) return this.drop(ws, 1008, "too many topics");
      if (this.pairs - countOf(att.topics) + countOf(next) > L.pairs) return this.drop(ws, 1013, "subscription budget exhausted");
      this.setTopics(ws, att, next);
      if (!this.save(ws, att)) return;
      this.replay(ws, att, f.boot, f.since, now);
      return;
    }

    if (att.win !== minute) {
      att.win = minute;
      att.frames = 0;
      att.changes = 0;
    }
    att.frames += 1;
    att.changes += f.topics.length;
    if (att.frames > L.framesPerMin || att.changes > L.changesPerMin) return this.drop(ws, 1008, "control frame rate");
    if (f.f === "sub") {
      const next = topicList([...split(att.topics), ...f.topics]);
      if (countOf(next) > L.topics) return this.drop(ws, 1008, "too many topics");
      if (this.pairs - countOf(att.topics) + countOf(next) > L.pairs) return this.drop(ws, 1013, "subscription budget exhausted");
      this.setTopics(ws, att, next);
    } else {
      const gone = topicList(f.topics);
      this.setTopics(ws, att, topicList(split(att.topics).filter((t) => !hasTopic(gone, t))));
    }
    this.save(ws, att);
  }

  // With compatibility_date >= 2026-04-07 the runtime completes the close handshake itself.
  async webSocketClose(ws: WebSocket): Promise<void> {
    this.forget(ws);
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    this.forget(ws);
  }

  /**
   * RESUME: replay ring rows with seq > since on the socket's topics, then RESUMED. GAP(since) when the ring cannot
   * cover it (another boot, rows after `since` evicted, or a `since` above the last assigned seq, e.g. one kept from
   * another boot), or when the replay would exceed `replayBytes`: the client then catches up (§11.6) instead.
   */
  private replay(ws: WebSocket, att: Att, boot: Uint8Array, since: number, now: number): void {
    this.trimRing(now);
    let gap = !equalBytes(boot, this.boot) || since < this.evicted || since > this.seq;
    const rows: RingRow[] = [];
    let bytes = 0;
    for (let i = this.ringStart; i < this.ring.length && !gap; i++) {
      const r = this.ring[i]!;
      if (r.seq <= since || !hasTopic(att.topics, r.topic)) continue;
      bytes += r.size;
      if (bytes > this.limits.replayBytes) gap = true;
      else rows.push(r);
    }
    if (gap) this.trySend(ws, encodeServerFrame({ f: "gap", since }));
    else if (this.sendFrames(ws, rowFrames(rows))) this.trySend(ws, encodeServerFrame({ f: "resumed" }));
  }

  // ───────────── publish ─────────────

  /**
   * §9.4 publish: next seq per row, append to the ring, one ROWS frame per subscribed socket. Each distinct row list
   * is encoded once and its bytes are sent to every socket that gets it.
   */
  publish(rows: RtPublishRow[]): void {
    const input = checkPublish(rows);
    if (input.length === 0) return;
    const now = this.clock();
    const out: RingRow[] = input.map((r) => ({ seq: ++this.seq, ...r, at: now, size: ROW_WIRE_OVERHEAD + r.body.length }));
    for (const r of out) {
      this.ring.push(r);
      this.ringSize += r.size;
    }
    this.trimRing(now);

    this.sweep(now);
    const socks = this.mirror();
    const per = new Map<WebSocket, RingRow[]>();
    for (const r of out) {
      const cands = this.index.get(prefixOf(r.topic));
      if (!cands) continue;
      for (const ws of cands) {
        const att = socks.get(ws);
        if (!att || !hasTopic(att.topics, r.topic)) continue;
        const list = per.get(ws);
        if (list) list.push(r);
        else per.set(ws, [r]);
      }
    }
    const encoded = new Map<string, Uint8Array[]>();
    for (const [ws, list] of per) {
      if (now - socks.get(ws)!.t > this.limits.maxAgeMs) {
        this.drop(ws, 4000, "max age");
        continue;
      }
      const key = list.length === 1 ? String(list[0].seq) : list.map((r) => r.seq).join(",");
      let frames = encoded.get(key);
      if (!frames) encoded.set(key, (frames = rowFrames(list)));
      this.sendFrames(ws, frames);
    }
  }

  /** Drops rows older than ringMs and beyond ringRows / ringBytes, oldest first. */
  private trimRing(now: number): void {
    const L = this.limits;
    while (this.ringStart < this.ring.length) {
      const r = this.ring[this.ringStart]!;
      const live = this.ring.length - this.ringStart;
      if (live <= L.ringRows && this.ringSize <= L.ringBytes && now - r.at <= L.ringMs) break;
      this.ring[this.ringStart++] = undefined;
      this.ringSize -= r.size;
      this.evicted = r.seq;
    }
    if (this.ringStart === this.ring.length) {
      this.ring = [];
      this.ringStart = 0;
    } else if (this.ringStart > 1024 && this.ringStart * 2 > this.ring.length) {
      this.ring = this.ring.slice(this.ringStart);
      this.ringStart = 0;
    }
  }

  // ───────────── sockets ─────────────

  /**
   * Closes every socket under an hour tag older than the previous hour (§9.4). After a wake the hour tags are
   * enumerated once with getTags(): attachments are never deserialised for this.
   */
  private sweep(now: number): void {
    const h = Math.floor(now / HOUR_MS);
    if (this.hours === null) {
      const hours = new Set<number>();
      for (const ws of this.ctx.getWebSockets()) {
        for (const tag of this.ctx.getTags(ws)) if (tag.startsWith("h:")) hours.add(Number(tag.slice(2)));
      }
      this.hours = hours;
    }
    for (const x of this.hours) {
      if (x >= h - 1) continue;
      for (const ws of this.ctx.getWebSockets(`h:${x}`)) this.drop(ws, 4000, "max age");
      this.hours.delete(x);
    }
  }

  /** The attachment mirror and topic index, rebuilt from the attachments on first use after a wake. */
  private mirror(): Map<WebSocket, Att> {
    if (this.socks) return this.socks;
    const socks = new Map<WebSocket, Att>();
    this.socks = socks;
    this.index.clear();
    this.pairs = 0;
    for (const ws of this.ctx.getWebSockets()) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      let att: Att | null = null;
      try {
        att = asAtt(ws.deserializeAttachment());
      } catch {
        /* unreadable attachment */
      }
      if (!att) {
        this.close(ws, 4000, "max age"); // the client reconnects
        continue;
      }
      socks.set(ws, att);
      this.indexAdd(ws, split(att.topics));
      this.pairs += countOf(att.topics);
    }
    return socks;
  }

  private indexAdd(ws: WebSocket, topics: Uint8Array[]): void {
    for (const t of topics) {
      const k = prefixOf(t);
      const set = this.index.get(k);
      if (set) set.add(ws);
      else this.index.set(k, new Set([ws]));
    }
  }

  /**
   * Removes `ws` under the prefixes of `topics` unless one of its `remaining` topics shares the prefix.
   * O(removed + remaining): the kept prefixes are collected once.
   */
  private indexRemove(ws: WebSocket, topics: Uint8Array[], remaining: Uint8Array): void {
    if (topics.length === 0) return;
    const keep = new Set<bigint>();
    const dv = new DataView(remaining.buffer, remaining.byteOffset, remaining.byteLength);
    for (let off = 0; off < remaining.length; off += 16) keep.add(dv.getBigUint64(off));
    for (const t of topics) {
      const k = prefixOf(t);
      if (keep.has(k)) continue;
      const set = this.index.get(k);
      if (!set) continue;
      set.delete(ws);
      if (set.size === 0) this.index.delete(k);
    }
  }

  /** Installs a new sorted topic list on a socket and keeps the index and the pair count in step. */
  private setTopics(ws: WebSocket, att: Att, next: Uint8Array): void {
    const old = att.topics;
    const removed = split(old).filter((t) => !hasTopic(next, t));
    const added = split(next).filter((t) => !hasTopic(old, t));
    this.indexRemove(ws, removed, next);
    this.indexAdd(ws, added);
    this.pairs += countOf(next) - countOf(old);
    att.topics = next;
  }

  private save(ws: WebSocket, att: Att): boolean {
    try {
      ws.serializeAttachment(att);
      return true;
    } catch (e) {
      console.error(JSON.stringify({ msg: "rt attachment failed", error: logErr(e) }));
      this.drop(ws, 1011, "internal error");
      return false;
    }
  }

  /** Sends encoded frames in order. Drops the socket and returns false when it fails to receive. */
  private sendFrames(ws: WebSocket, frames: Uint8Array[]): boolean {
    for (const f of frames) if (!this.trySend(ws, f)) return false;
    return true;
  }

  private trySend(ws: WebSocket, msg: string | Uint8Array): boolean {
    try {
      ws.send(msg);
      return true;
    } catch {
      this.drop(ws, 1011, "send failed");
      return false;
    }
  }

  private close(ws: WebSocket, code: number, reason: string): void {
    try {
      ws.close(code, reason);
    } catch {
      // already closing
    }
  }

  /** Closes a socket and forgets its topics. */
  private drop(ws: WebSocket, code: number, reason: string): void {
    this.close(ws, code, reason);
    this.forget(ws);
  }

  private forget(ws: WebSocket): void {
    const att = this.socks?.get(ws);
    if (!att) return;
    this.indexRemove(ws, split(att.topics), new Uint8Array(0));
    this.pairs -= countOf(att.topics);
    this.socks!.delete(ws);
  }
}
