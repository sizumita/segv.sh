/**
 * ConnDO — one of the C objects that hold the realtime WebSockets (docs/PROTOCOL.md §9.4, §10.8). Name
 * "conn/v2/{c}"; the Worker sends every socket of a client to conn(ck) of its tag (§4.4). It has no storage of its
 * own: nothing about topics, subscriptions or rows is ever written (§13.1); the alarm is its only use of storage.
 *
 *  - fetch(): upgrade from the Worker. The only client-derived input is `x-segv-client`, an opaque tag. Sockets
 *    carry the tags [clientTag, "h:" + accept hour, "t:" + accept ms] and the attachment {t, topics, feeds, win,
 *    frames, changes}, `feeds` holding h(T) of each topic (§4.4) so that a topic's FeedDO is known after a wake
 *    without an HMAC; caps are counted with getWebSockets(tag) only (attachments are never deserialised to count).
 *    A client at its cap first loses the sockets that showed no sign of life for 90 s: neither accepted nor had a
 *    "ping" auto-answered since (the runtime keeps the time of the last auto-answer), closed with 4001.
 *  - In memory: `boot` (8 random bytes per construction) and `seq` (u64 per boot); a mirror of the attachments with
 *    an index 8-byte topic prefix → sockets (full 16-byte compare on delivery), the (topic, socket) pair count and,
 *    per FeedDO, the interest (the distinct topics with their socket counts), all rebuilt lazily after a wake; a
 *    ring of the last 10 min / 8192 rows / 16 MiB of delivered rows for RESUME.
 *  - webSocketMessage(): "ping" (normally auto-answered), SUB / UNSUB / RESUME. Anything else, or a limit
 *    exceeded, closes with 1008; a SUB beyond the global pair budget closes with 1013.
 *  - Interest (§9.4): a change of the distinct-topic set at a FeedDO is reported with interest(c, added, removed),
 *    the calls to one FeedDO made one after the other; every RT_RESYNC while any socket has a topic, and after a
 *    failed call (1 s, doubling to 60 s), replace(c, topics) with the full set; topicsFor(j) answers the full set to
 *    a FeedDO that starts. The calls go through `feeds`, an instance field that tests can replace.
 *  - RESUME: GAP(since) unless the boot is current, `since` ≤ the last assigned seq and the ring still holds every
 *    row after it; also GAP when the rows to replay exceed `replayBytes` (the client catches up instead).
 *  - deliver(): from a FeedDO: assigns seqs, appends to the ring, sends one ROWS frame per subscribed socket;
 *    sockets that get the same rows share one encoding.
 *  - deliverInbox(): from a FeedDO (§9.3): one INBOX frame to each socket subscribed to Tinbox(E, g); no seq, no ring,
 *    no replay.
 *  - Sockets older than 1 h are closed with 4000 (hour tags older than the previous hour whenever sockets are
 *    counted or sent to, and the exact age before sending).
 */
import { DurableObject } from "cloudflare:workers";
import { BODY_LENS, byteCmp, equalBytes, feedBits, feedHash, feedOf, hex, topicInbox } from "@segv/protocol/proto";
import { RT_MAX_CLIENT_FRAME, RT_MAX_TOPICS, decodeClientFrame, encodeServerFrame, type ClientFrame, type RtRow } from "@segv/protocol/wire";
import { AlarmSlot } from "./batch";
import { serverKeys, v2Params } from "./env";
import { logErr } from "./http";
import { checkNotice, feedStub, parseIndexName, type RtPublishRow } from "./types";

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
  /**
   * a client at its cap first loses (4001) the sockets neither accepted nor auto-answered a "ping" within this long:
   * three ping periods, so a client that vanished without a close frame does not hold its places for an hour
   */
  staleMs: number;
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
  /** RT_RESYNC: the full interest set is sent to every FeedDO this often while any socket has a topic */
  resyncMs: number;
  /** the first retry after a failed FeedDO call comes this soon, */
  retryMinMs: number;
  /** doubling up to this */
  retryMaxMs: number;
}

const RT_LIMITS: Readonly<RtLimits> = {
  perClient: 8,
  staleMs: 90_000,
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
  resyncMs: 300_000,
  retryMinMs: 1_000,
  retryMaxMs: 60_000,
};

/** The calls a ConnDO makes to the FeedDOs (§9.4 "Interest"); replaced in tests. */
export interface FeedLink {
  interest(j: number, c: number, added: Uint8Array[], removed: Uint8Array[]): Promise<void>;
  replace(j: number, c: number, topics: Uint8Array[]): Promise<void>;
}

/**
 * Per-socket attachment (§9.4). `topics` is 16·n bytes, sorted and without duplicates, and `feeds` the 8-byte feed
 * hash of each topic in the same order. `win` is the minute of the rate window and stays 0 until the first binary
 * frame, which is how "RESUME only as the first binary frame" survives hibernation.
 */
interface Att {
  t: number;
  topics: Uint8Array;
  feeds: Uint8Array;
  win: number;
  frames: number;
  changes: number;
}

/** A topic with its feed hash h(T). */
interface Entry {
  t: Uint8Array;
  h: Uint8Array;
}

/** A socket's topics as stored: `topics` sorted and deduplicated, `feeds` aligned. */
interface TopicList {
  topics: Uint8Array;
  feeds: Uint8Array;
}

/** The added and removed topics per FeedDO after a change of this object's distinct-topic set. */
type Deltas = Map<number, { added: Uint8Array[]; removed: Uint8Array[] }>;

interface RingRow extends RtRow {
  /** delivery time (ms) */
  at: number;
  /** encoded size in a ROWS frame */
  size: number;
}

const EMPTY_LIST: TopicList = { topics: new Uint8Array(0), feeds: new Uint8Array(0) };

const prefixOf = (t: Uint8Array, off = 0): bigint => new DataView(t.buffer, t.byteOffset + off, 8).getBigUint64(0);
const topicAt = (topics: Uint8Array, i: number): Uint8Array => topics.subarray(16 * i, 16 * i + 16);
const feedAt = (feeds: Uint8Array, i: number): Uint8Array => feeds.subarray(8 * i, 8 * i + 8);
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

/** The entries of a stored list. */
const entriesOf = (l: TopicList): Entry[] =>
  Array.from({ length: countOf(l.topics) }, (_, i) => ({ t: topicAt(l.topics, i), h: feedAt(l.feeds, i) }));

/** A stored list from entries: sorted by topic, the first entry of a repeated topic kept. */
function listOf(entries: Entry[]): TopicList {
  const sorted = [...entries].sort((a, b) => byteCmp(a.t, b.t));
  const topics = new Uint8Array(16 * sorted.length);
  const feeds = new Uint8Array(8 * sorted.length);
  let n = 0;
  for (const e of sorted) {
    if (n > 0 && byteCmp(topicAt(topics, n - 1), e.t) === 0) continue;
    topics.set(e.t, 16 * n);
    feeds.set(e.h, 8 * n);
    n++;
  }
  return { topics: topics.slice(0, 16 * n), feeds: feeds.slice(0, 8 * n) };
}

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

/** Accept time from a socket's "t:" tag; 0 for a socket accepted before the tag existed (judged by its pings alone). */
function acceptedAt(tags: string[]): number {
  for (const tag of tags) {
    if (!tag.startsWith("t:")) continue;
    const t = Number(tag.slice(2));
    return Number.isFinite(t) ? t : 0;
  }
  return 0;
}

function refuse(status: 429 | 503, error: string): Response {
  return Response.json({ error }, { status, headers: { "retry-after": "60" } });
}

/** Validates an attachment read back after a wake; null when it is not one of ours. */
function asAtt(x: unknown): Att | null {
  if (typeof x !== "object" || x === null) return null;
  const { t, topics, feeds, win, frames, changes } = x as Record<string, unknown>;
  if (typeof t !== "number" || !(topics instanceof Uint8Array) || topics.length % 16 !== 0) return null;
  if (!(feeds instanceof Uint8Array) || feeds.length * 2 !== topics.length) return null;
  if (typeof win !== "number" || typeof frames !== "number" || typeof changes !== "number") return null;
  return { t, topics, feeds, win, frames, changes };
}

/** The attachment of a socket, or null when it cannot be read or is not one of ours. */
function readAtt(ws: WebSocket): Att | null {
  try {
    return asAtt(ws.deserializeAttachment());
  } catch {
    return null;
  }
}

/** Defensive re-validation of deliver() input (the Worker and the FeedDO validate too). */
function checkRows(input: unknown): RtPublishRow[] {
  if (!Array.isArray(input)) throw new TypeError("deliver: bad rows");
  return input.map((r: unknown) => {
    const { topic, E, label, t, cls, body } = (typeof r === "object" && r !== null ? r : {}) as Record<string, unknown>;
    if (!(topic instanceof Uint8Array) || topic.length !== 16) throw new TypeError("deliver: bad topic");
    if (!Number.isInteger(E) || (E as number) < 0 || (E as number) > 0xffff) throw new TypeError("deliver: bad era");
    if (!(label instanceof Uint8Array) || label.length !== 16) throw new TypeError("deliver: bad label");
    if (!Number.isInteger(t) || (t as number) < 0 || (t as number) > 0xffffffff) throw new TypeError("deliver: bad t");
    if (!Number.isInteger(cls) || BODY_LENS[cls as number] === undefined) throw new TypeError("deliver: bad class");
    if (!(body instanceof Uint8Array) || body.length !== BODY_LENS[cls as number]) throw new TypeError("deliver: bad body");
    return { topic, E: E as number, label, t: t as number, cls: cls as number, body };
  });
}

function deltaOf(d: Deltas, j: number): { added: Uint8Array[]; removed: Uint8Array[] } {
  let x = d.get(j);
  if (!x) d.set(j, (x = { added: [], removed: [] }));
  return x;
}

export class ConnDO extends DurableObject<Env> {
  /** Time source (Unix ms). An instance field so tests can step the clock. */
  protected clock: () => number = () => Date.now();
  /** Instance field (not constants) so tests can lower the caps, the pair budget and the ring. */
  protected limits: RtLimits = { ...RT_LIMITS };
  /** The FeedDO calls (§9.4 "Interest"); tests replace it to observe or fail them. */
  protected feeds: FeedLink = {
    interest: (j, c, added, removed) => feedStub(this.env, j).interest(c, added, removed),
    replace: (j, c, topics) => feedStub(this.env, j).replace(c, topics),
  };

  /** This object's index c (its name is "conn/v2/{c}"). */
  private readonly c: number;
  /** kfeed (§4.4) and the f of F = 2^f FeedDOs. */
  private readonly kfeed: Uint8Array;
  private readonly fbits: number;
  private readonly alarmSlot: AlarmSlot;

  private readonly boot: Uint8Array = crypto.getRandomValues(new Uint8Array(8));
  /** last assigned seq (per boot) */
  private seq = 0;

  /** Attachments of the open sockets, rebuilt lazily after a wake (null until then). */
  private socks: Map<WebSocket, Att> | null = null;
  /** 8-byte topic prefix → sockets with a topic of that prefix */
  private readonly index = new Map<bigint, Set<WebSocket>>();
  /** (topic, socket) pairs over every open socket */
  private pairs = 0;
  /** accept hours that may still have sockets (null until enumerated after a wake) */
  private hours: Set<number> | null = null;
  /** Per FeedDO j: topic (hex) → the topic and the number of open sockets that hold it (the interest, §9.4). */
  private readonly interest = new Map<number, Map<string, { t: Uint8Array; n: number }>>();
  /** Per FeedDO: the chain of its calls (one after the other, in order). */
  private readonly queue = new Map<number, Promise<void>>();
  /** FeedDOs at which a failed call left a change unreported: they get the full set at the next alarm. */
  private readonly dirty = new Set<number>();
  /** The current retry delay after failed calls (0 = none pending). */
  private retryMs = 0;

  /** RESUME ring: ring[ringStart..] are live, ascending and contiguous in seq. */
  private ring: (RingRow | undefined)[] = [];
  private ringStart = 0;
  private ringSize = 0;
  /** highest seq dropped from the ring (0 = none): the ring holds every row with seq > evicted */
  private evicted = 0;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.c = parseIndexName(ctx.id.name, "conn");
    const keys = serverKeys(env);
    if (!keys) throw new Error("conn DO: server misconfigured");
    this.kfeed = keys.feedKey;
    this.fbits = feedBits(v2Params(env).rtFeeds);
    this.alarmSlot = new AlarmSlot(ctx.storage);
    // Answered by the runtime without waking the object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    void ctx.blockConcurrencyWhile(async () => {
      await this.alarmSlot.load();
    });
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
    const mine = this.ctx.getWebSockets(clientTag);
    if (openCount(mine) >= this.limits.perClient) {
      this.dropStale(mine, now);
      if (openCount(mine) >= this.limits.perClient) return refuse(429, "too many connections from this client");
    }
    if (openCount(this.ctx.getWebSockets()) >= this.limits.total) return refuse(503, "too many connections");

    const hour = Math.floor(now / HOUR_MS);
    const [client, server] = Object.values(new WebSocketPair());
    const att: Att = { t: now, topics: new Uint8Array(0), feeds: new Uint8Array(0), win: 0, frames: 0, changes: 0 };
    try {
      this.ctx.acceptWebSocket(server, [clientTag, `h:${hour}`, `t:${now}`]);
      server.serializeAttachment(att);
      server.send(encodeServerFrame({ f: "hello", boot: this.boot, now, seq: this.seq }));
    } catch (e) {
      console.error(JSON.stringify({ msg: "rt accept failed", error: logErr(e) }));
      this.close(server, 1011, "accept failed");
      return refuse(503, "too many connections");
    }
    this.hours?.add(hour);
    this.socks?.set(server, att);
    await this.settle(); // the sockets the sweep closed are withdrawn before the object may rest
    return new Response(null, { status: 101, webSocket: client });
  }

  // ───────────── client frames ─────────────

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    try {
      this.handle(ws, message);
    } finally {
      await this.settle();
    }
  }

  /** One client frame (§10.8); whatever it does to the interest is reported by the caller's settle(). */
  private handle(ws: WebSocket, message: string | ArrayBuffer): void {
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
      const next = listOf(f.topics.map((t) => this.entry(t)));
      if (countOf(next.topics) > L.topics) return this.drop(ws, 1008, "too many topics");
      if (this.pairs - countOf(att.topics) + countOf(next.topics) > L.pairs) return this.drop(ws, 1013, "subscription budget exhausted");
      this.report(this.setTopics(ws, att, next));
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
      // The socket's own entries first: a topic it already holds keeps its stored hash, and no HMAC is recomputed.
      const have = entriesOf(att);
      const fresh = f.topics.filter((t) => !hasTopic(att.topics, t)).map((t) => this.entry(t));
      const next = listOf([...have, ...fresh]);
      if (countOf(next.topics) > L.topics) return this.drop(ws, 1008, "too many topics");
      if (this.pairs - countOf(att.topics) + countOf(next.topics) > L.pairs) return this.drop(ws, 1013, "subscription budget exhausted");
      this.report(this.setTopics(ws, att, next));
    } else {
      const gone = listOf(f.topics.map((t) => ({ t, h: new Uint8Array(8) }))).topics;
      this.report(this.setTopics(ws, att, listOf(entriesOf(att).filter((e) => !hasTopic(gone, e.t)))));
    }
    this.save(ws, att);
  }

  // With compatibility_date >= 2026-04-07 the runtime completes the close handshake itself.
  async webSocketClose(ws: WebSocket): Promise<void> {
    this.forget(ws);
    await this.settle();
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    this.forget(ws);
    await this.settle();
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

  // ───────────── delivery ─────────────

  /**
   * §9.4 deliver (from a FeedDO): next seq per row, append to the ring, one ROWS frame per subscribed socket. Each
   * distinct row list is encoded once and its bytes are sent to every socket that gets it.
   */
  async deliver(rows: RtPublishRow[]): Promise<void> {
    const input = checkRows(rows);
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
    await this.settle(); // sockets dropped here (max age, a failed send) are withdrawn before the call returns
  }

  /**
   * §9.4 deliverInbox (from a FeedDO, §9.3): one INBOX frame to each socket subscribed to Tinbox(E, g). A notice gets
   * no seq, enters no ring and is never replayed.
   */
  async deliverInbox(E: number, g: number, rel: number): Promise<void> {
    checkNotice(E, g, rel);
    const T = topicInbox(E, g);
    const now = this.clock();
    this.sweep(now);
    const socks = this.mirror();
    const cands = this.index.get(prefixOf(T));
    if (cands) {
      const frame = encodeServerFrame({ f: "inbox", E, g, rel });
      for (const ws of cands) {
        const att = socks.get(ws);
        if (!att || !hasTopic(att.topics, T)) continue;
        if (now - att.t > this.limits.maxAgeMs) this.drop(ws, 4000, "max age");
        else this.trySend(ws, frame);
      }
    }
    await this.settle(); // sockets dropped here are withdrawn before the call returns
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

  // ───────────── interest (§9.4) ─────────────

  /** The distinct topics of the open sockets at FeedDO j (RPC from a FeedDO that starts). */
  topicsFor(j: number): Uint8Array[] {
    if (!Number.isInteger(j) || j < 0) throw new TypeError("topicsFor: bad feed");
    this.mirror();
    return [...(this.interest.get(j)?.values() ?? [])].map((e) => e.t);
  }

  /**
   * Every RT_RESYNC while any socket has a topic, and after a failed call: the full set to every FeedDO at which this
   * object has topics, and to every FeedDO a failed call left behind (§9.4).
   */
  async alarm(): Promise<void> {
    this.alarmSlot.fired();
    const now = this.clock();
    this.sweep(now);
    this.mirror();
    const js = new Set([...this.interest.keys(), ...this.dirty]);
    this.dirty.clear();
    for (const j of js) this.enqueue(j, () => this.feeds.replace(j, this.c, this.topicsFor(j)));
    await this.settle();
    if (this.dirty.size === 0) this.retryMs = 0;
    if (this.interest.size > 0) this.alarmSlot.arm(now + this.limits.resyncMs);
  }

  /** Waits for every FeedDO call made so far (handlers end with it, so the object stays up until they are answered). */
  protected async settle(): Promise<void> {
    await Promise.all(this.queue.values());
  }

  /** A topic with its feed hash. */
  private entry(t: Uint8Array): Entry {
    return { t, h: feedHash(this.kfeed, t) };
  }

  private jOf(h: Uint8Array): number {
    return feedOf(h, this.fbits);
  }

  /** Counts a socket's hold on a topic; true when it is the first (the topic enters the interest). */
  private hold(e: Entry): boolean {
    const j = this.jOf(e.h);
    let m = this.interest.get(j);
    if (!m) this.interest.set(j, (m = new Map()));
    const k = hex(e.t);
    const cur = m.get(k);
    if (cur) {
      cur.n++;
      return false;
    }
    m.set(k, { t: e.t.slice(), n: 1 });
    return true;
  }

  /** Releases a socket's hold on a topic; true when it was the last (the topic leaves the interest). */
  private release(e: Entry): boolean {
    const j = this.jOf(e.h);
    const m = this.interest.get(j);
    const k = hex(e.t);
    const cur = m?.get(k);
    if (!m || !cur) return false;
    if (--cur.n > 0) return false;
    m.delete(k);
    if (m.size === 0) this.interest.delete(j);
    return true;
  }

  /** Sends the deltas of a change to their FeedDOs (one call at a time per FeedDO) and keeps the resync alarm armed. */
  private report(d: Deltas): void {
    for (const [j, { added, removed }] of d) {
      if (added.length === 0 && removed.length === 0) continue;
      this.enqueue(j, () => this.feeds.interest(j, this.c, added, removed));
    }
    if (this.interest.size > 0) this.alarmSlot.arm(this.clock() + this.limits.resyncMs);
  }

  /** Appends a call to FeedDO j's chain; a failure marks j dirty and arms the retry alarm. */
  private enqueue(j: number, call: () => Promise<void>): void {
    const run = async (): Promise<void> => {
      try {
        await call();
      } catch (e) {
        this.dirty.add(j);
        this.armRetry();
        console.error(JSON.stringify({ msg: "feed interest failed", error: logErr(e) }));
      }
    };
    const prev = this.queue.get(j) ?? Promise.resolve();
    this.queue.set(j, prev.then(run));
  }

  private armRetry(): void {
    const L = this.limits;
    this.retryMs = this.retryMs === 0 ? L.retryMinMs : Math.min(this.retryMs * 2, L.retryMaxMs);
    this.alarmSlot.arm(this.clock() + this.retryMs);
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

  /**
   * Closes with 4001 the open sockets of `list` that showed no sign of life within `staleMs` (§9.4): neither accepted
   * (the "t:" tag) nor had a "ping" auto-answered since. Clients ping every 30 s, so these are almost always sockets
   * whose client vanished without a close frame. Reads only tags and the runtime's auto-answer time.
   */
  private dropStale(list: WebSocket[], now: number): void {
    for (const ws of list) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      const pinged = this.ctx.getWebSocketAutoResponseTimestamp(ws)?.getTime() ?? 0;
      if (Math.max(acceptedAt(this.ctx.getTags(ws)), pinged) >= now - this.limits.staleMs) continue;
      this.drop(ws, 4001, "no ping");
    }
  }

  /** The attachment mirror, the topic index and the interest, rebuilt from the attachments on first use after a wake. */
  private mirror(): Map<WebSocket, Att> {
    if (this.socks) return this.socks;
    const socks = new Map<WebSocket, Att>();
    this.socks = socks;
    this.index.clear();
    this.interest.clear();
    this.pairs = 0;
    for (const ws of this.ctx.getWebSockets()) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      const att = readAtt(ws);
      if (!att) {
        this.close(ws, 4000, "max age"); // the client reconnects
        continue;
      }
      socks.set(ws, att);
      const entries = entriesOf(att);
      this.indexAdd(
        ws,
        entries.map((e) => e.t),
      );
      for (const e of entries) this.hold(e);
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

  /**
   * Installs a new topic list on a socket and keeps the index, the pair count and the interest in step. Returns the
   * topics that entered or left the interest, per FeedDO.
   */
  private setTopics(ws: WebSocket, att: Att, next: TopicList): Deltas {
    const removed = entriesOf(att).filter((e) => !hasTopic(next.topics, e.t));
    const added = entriesOf(next).filter((e) => !hasTopic(att.topics, e.t));
    this.indexRemove(
      ws,
      removed.map((e) => e.t),
      next.topics,
    );
    this.indexAdd(
      ws,
      added.map((e) => e.t),
    );
    this.pairs += countOf(next.topics) - countOf(att.topics);
    att.topics = next.topics;
    att.feeds = next.feeds;
    const d: Deltas = new Map();
    for (const e of removed) if (this.release(e)) deltaOf(d, this.jOf(e.h)).removed.push(e.t.slice());
    for (const e of added) if (this.hold(e)) deltaOf(d, this.jOf(e.h)).added.push(e.t.slice());
    return d;
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

  /**
   * Takes a socket out of the index and the interest, and reports to the FeedDOs the topics that no open socket holds
   * any more. A socket that closed before the mirror was rebuilt is already out of both; its attachment still says
   * which topics it held, and those absent from the rebuilt interest are withdrawn.
   */
  private forget(ws: WebSocket): void {
    const socks = this.mirror();
    const att = socks.get(ws);
    if (att) {
      const d = this.setTopics(ws, att, EMPTY_LIST);
      socks.delete(ws);
      this.report(d);
      return;
    }
    const gone = readAtt(ws);
    if (!gone) return;
    const d: Deltas = new Map();
    for (const e of entriesOf(gone)) {
      const j = this.jOf(e.h);
      if (!this.interest.get(j)?.has(hex(e.t))) deltaOf(d, j).removed.push(e.t.slice());
    }
    this.report(d);
  }
}
