/**
 * RealtimeDO fake (docs/PROTOCOL.md §9.4, §10.8) and the browser-side `FakeWebSocket` bound to a world.
 *
 * - On open the server sends HELLO {boot, now, seq = last assigned}.
 * - SUB / UNSUB / RESUME (by seq; only as the first binary frame; installs its topic set even on GAP). RESUME gets
 *   GAP for another boot, a `since` whose rows left the ring, a `since` above the last assigned seq, or a replay
 *   above `replayBytes` (2 MiB of rows as encoded in ROWS frames).
 * - publish(): each row gets the next seq and enters the ring (last 10 min, ≤ 8192 rows, ≤ 16 MiB of encoded rows);
 *   every OPEN socket subscribed to a row's topic gets the matching rows of that publish (ROWS frames split at
 *   512 KiB, as the DO does), delivered with setTimeout(0).
 * - Limits: 256 topics per socket, 30 SUB/UNSUB frames and 2048 topic changes per minute (RESUME counts toward
 *   neither), frames ≤ 8 KiB, a second RESUME, an unknown text or a bad frame → close 1008; the pair budget → close
 *   1013; 8 sockets per client → the upgrade is refused (429). "ping" → "pong".
 * - Max age: a socket older than 1 h is closed with 4000 on its next binary frame or when next sent to, and every
 *   socket accepted before the previous UTC hour is closed whenever sockets are counted (an upgrade) or sent to
 *   (a publish), as the DO's hour-tag sweep does.
 *
 * - The handshake: `FakeWebSocket.upgradeStatus` and `upgradeHeaders` hold the Worker's answer to the upgrade. A 101
 *   is passed on exactly as the RealtimeDO built it, with none of the per-response headers (`x-segv-now`, HSTS,
 *   `nosniff`, `no-referrer`; §9.7, §10.1): HELLO carries the server time instead. A refusal (404, 429, 503) is an
 *   ordinary error response with all of them.
 *
 * Test controls: `restart()` (new boot and empty ring, so the next RESUME gets GAP), `enabled` (false: new sockets
 * fail to connect and publishes are lost), `dropPublish(pred)` (lose matching publishes), `closeAll()`.
 */
import { b64u, random, type Bytes } from "@segv/protocol/proto";
import {
  RT_MAX_CLIENT_FRAME,
  RT_MAX_TOPICS,
  decodeClientFrame,
  encodeServerFrame,
  type RtRow,
} from "@segv/protocol/wire";
import type { PublishRow } from "./common";

/** What the realtime fake needs from its world. */
export interface RtHost {
  now(): number;
  readonly rt: FakeRealtime;
  /**
   * The Worker side of `GET /api/v2/rt` with an upgrade (logs the request, RL_READ, then `rt.admit`). Returns the
   * status (101 = accept, 0 = no answer) and the response headers: empty on a 101, the Worker's error headers on a
   * refusal, null when no answer arrived (`hooks.fail`).
   */
  rtUpgrade(ws: FakeWebSocket): { status: number; headers: Headers | null };
  /** shard.hide(): rows hidden from `who` are not delivered to its sockets. */
  isHidden(E: number, label: Bytes, who: string | null): boolean;
}

export interface RtLimits {
  perClient: number;
  total: number;
  topicsPerSocket: number;
  pairs: number;
  framesPerMinute: number;
  changesPerMinute: number;
  ringMs: number;
  ringRows: number;
  ringBytes: number;
  /** a RESUME whose replay would exceed this many bytes (rows as encoded in ROWS frames) gets GAP */
  replayBytes: number;
  maxAgeMs: number;
}

export const RT_LIMITS: Readonly<RtLimits> = {
  perClient: 8,
  total: 20_000,
  topicsPerSocket: RT_MAX_TOPICS,
  pairs: 250_000,
  framesPerMinute: 30,
  changesPerMinute: 2048,
  ringMs: 10 * 60_000,
  ringRows: 8192,
  ringBytes: 16 * 1024 * 1024,
  replayBytes: 2 * 1024 * 1024,
  maxAgeMs: 3_600_000,
};

const HOUR_MS = 3_600_000;
/** Bytes of one row in a ROWS frame besides the body: seq, topic, E, label, t, cls. */
const ROW_WIRE_OVERHEAD = 8 + 16 + 2 + 16 + 4 + 1;
/** A ROWS frame holds at most this many bytes of rows (one row always fits) and at most 0xFFFF rows. */
const ROWS_FRAME_BUDGET = 512 * 1024;
const ROWS_FRAME_MAX_ROWS = 0xffff;

interface RingRow extends RtRow {
  at: number;
}

const rowSize = (r: RtRow): number => ROW_WIRE_OVERHEAD + r.body.length;

/** ROWS frames for `rows`, split as the DO splits them (by encoded size). */
function rowFrames(rows: readonly RingRow[]): Bytes[] {
  const out: Bytes[] = [];
  for (let i = 0; i < rows.length;) {
    let bytes = 0;
    let j = i;
    while (
      j < rows.length &&
      j - i < ROWS_FRAME_MAX_ROWS &&
      (j === i || bytes + rowSize(rows[j]) <= ROWS_FRAME_BUDGET)
    ) {
      bytes += rowSize(rows[j]);
      j++;
    }
    out.push(encodeServerFrame({ f: "rows", rows: rows.slice(i, j).map(stripAt) }));
    i = j;
  }
  return out;
}

let socketIds = 0;

export class FakeRealtime {
  boot: Bytes = random(8);
  /** last assigned seq of this boot */
  seq = 0;
  readonly ring: RingRow[] = [];
  private ringBytes = 0;
  /** OPEN sockets */
  readonly sockets = new Set<FakeWebSocket>();
  /** false: new sockets fail to connect and every publish is lost (open sockets stay open). */
  enabled = true;
  limits: RtLimits = { ...RT_LIMITS };
  private dropPred: ((row: PublishRow) => boolean) | null = null;
  /** Rows published (accepted into the ring) and dropped, for assertions. */
  readonly stats = { published: 0, dropped: 0 };

  constructor(private readonly host: RtHost) {}

  // ───────────── RealtimeDO.publish ─────────────

  publish(rows: readonly PublishRow[]): void {
    if (rows.length === 0) return;
    const now = this.host.now();
    const accepted: RingRow[] = [];
    for (const r of rows) {
      if (!this.enabled || this.dropPred?.(r)) {
        this.stats.dropped++;
        continue;
      }
      const row: RingRow = {
        seq: ++this.seq,
        at: now,
        topic: r.topic,
        E: r.E,
        label: r.label,
        t: r.t,
        cls: r.cls,
        body: r.body,
      };
      this.ring.push(row);
      this.ringBytes += rowSize(row);
      accepted.push(row);
      this.stats.published++;
    }
    // Every publish row was lost before reaching the DO.
    if (accepted.length === 0) return;
    this.pruneRing(now);
    this.sweep(now);
    for (const ws of this.sockets) {
      const match = accepted.filter(
        (r) => ws.topics.has(b64u(r.topic)) && !this.host.isHidden(r.E, r.label, ws.who),
      );
      if (match.length === 0 || !this.checkAge(ws, now)) continue;
      for (const frame of rowFrames(match)) setTimeout(() => ws._deliver(frame), 0);
    }
  }

  // ───────────── test controls ─────────────

  /** A new boot (the ring and seq are lost). By default every socket is closed with 1012, so clients RESUME → GAP. */
  restart(closeSockets = true): void {
    this.boot = random(8);
    this.seq = 0;
    this.ring.length = 0;
    this.ringBytes = 0;
    if (closeSockets) this.closeAll(1012, "restart");
  }

  /** Lose every publish row matching `pred` (null removes the filter). */
  dropPublish(pred: ((row: PublishRow) => boolean) | null): void {
    this.dropPred = pred;
  }

  /** Server-side close of every open socket. */
  closeAll(code = 1001, reason = ""): void {
    for (const ws of this.sockets) ws._serverClose(code, reason);
  }

  /** Total (topic, socket) pairs. */
  pairs(): number {
    let n = 0;
    for (const ws of this.sockets) n += ws.topics.size;
    return n;
  }

  // ───────────── socket lifecycle (called by FakeWebSocket) ─────────────

  /**
   * The RealtimeDO's fetch(upgrade): 101, or 503 while disabled, 429 when the client already has `perClient` live
   * sockets (the client is `who`; every unattributed socket counts as its own client), 503 at the global cap.
   */
  admit(ws: FakeWebSocket): number {
    if (!this.enabled) return 503;
    this.sweep(this.host.now());
    const tag = (s: FakeWebSocket) => s.who ?? `anon:${s.id}`;
    const mine = tag(ws);
    if ([...this.sockets].filter((s) => tag(s) === mine).length >= this.limits.perClient)
      return 429;
    if (this.sockets.size >= this.limits.total) return 503;
    return 101;
  }

  /** Runs the upgrade one tick after `new WebSocket()`: HELLO on success, error + close 1006 on refusal. */
  _connect(ws: FakeWebSocket): void {
    setTimeout(() => {
      if (ws.readyState !== FakeWebSocket.CONNECTING) return;
      const { status, headers } = this.host.rtUpgrade(ws);
      ws.upgradeStatus = status;
      ws.upgradeHeaders = headers;
      if (status !== 101) {
        ws._fail();
        return;
      }
      ws.acceptedAt = this.host.now();
      this.sockets.add(ws);
      ws._open();
      ws._deliver(
        encodeServerFrame({ f: "hello", boot: this.boot, now: this.host.now(), seq: this.seq }),
      );
    }, 0);
  }

  _closed(ws: FakeWebSocket): void {
    this.sockets.delete(ws);
  }

  /** A client frame, as the DO's webSocketMessage sees it. */
  _message(ws: FakeWebSocket, data: string | Bytes): void {
    if (ws.readyState !== FakeWebSocket.OPEN) return;
    if (typeof data === "string") {
      if (data === "ping") ws._deliver("pong");
      else ws._serverClose(1008, "unexpected text frame");
      return;
    }
    const now = this.host.now();
    if (!this.checkAge(ws, now)) return;
    if (data.length > RT_MAX_CLIENT_FRAME) return ws._serverClose(1008, "frame too large");
    let f;
    try {
      f = decodeClientFrame(data);
    } catch {
      return ws._serverClose(1008, "malformed frame");
    }
    const first = !ws.sawBinary;
    ws.sawBinary = true;
    const minute = Math.floor(now / 60_000);
    if (ws.win !== minute) {
      ws.win = minute;
      ws.frames = 0;
      ws.changes = 0;
    }
    // RESUME counts toward neither limit (it is allowed once, as the first binary frame).
    if (f.f !== "resume") {
      ws.frames++;
      ws.changes += f.topics.length;
    }
    if (ws.frames > this.limits.framesPerMinute || ws.changes > this.limits.changesPerMinute)
      return ws._serverClose(1008, "control frame rate");
    if (f.f === "sub") {
      for (const t of f.topics) ws.topics.set(b64u(t), t);
      if (ws.topics.size > this.limits.topicsPerSocket)
        return ws._serverClose(1008, "too many topics");
      if (this.pairs() > this.limits.pairs) return ws._serverClose(1013, "subscription budget");
    } else if (f.f === "unsub") {
      for (const t of f.topics) ws.topics.delete(b64u(t));
    } else {
      if (!first) return ws._serverClose(1008, "second RESUME");
      if (new Set(f.topics.map(b64u)).size > this.limits.topicsPerSocket)
        return ws._serverClose(1008, "too many topics");
      ws.topics.clear();
      for (const t of f.topics) ws.topics.set(b64u(t), t);
      if (this.pairs() > this.limits.pairs) return ws._serverClose(1013, "subscription budget");
      this.resume(ws, f.boot, f.since);
    }
  }

  // ───────────── internals ─────────────

  private resume(ws: FakeWebSocket, boot: Bytes, since: number): void {
    this.pruneRing(this.host.now()); // the clock may have jumped since the last publish
    const sameBoot = boot.length === this.boot.length && boot.every((x, i) => x === this.boot[i]);
    // The ring must still hold every row with seq > since.
    const covered =
      sameBoot &&
      since <= this.seq &&
      (since === this.seq || (this.ring.length > 0 && this.ring[0].seq <= since + 1));
    const rows = covered
      ? this.ring.filter(
          (r) =>
            r.seq > since &&
            ws.topics.has(b64u(r.topic)) &&
            !this.host.isHidden(r.E, r.label, ws.who),
        )
      : [];
    // A replay above the byte budget gets GAP too (the client catches up instead).
    const gap = !covered || rows.reduce((n, r) => n + rowSize(r), 0) > this.limits.replayBytes;
    const frames: Bytes[] = gap
      ? [encodeServerFrame({ f: "gap", since })]
      : [...rowFrames(rows), encodeServerFrame({ f: "resumed" })];
    for (const b of frames) setTimeout(() => ws._deliver(b), 0);
  }

  /** Closes `ws` with 4000 when it is older than maxAgeMs; false when closed. */
  private checkAge(ws: FakeWebSocket, now: number): boolean {
    if (now - ws.acceptedAt <= this.limits.maxAgeMs) return true;
    ws._serverClose(4000, "max age");
    return false;
  }

  /** The DO's hour-tag sweep: closes every socket accepted before the previous UTC hour. */
  private sweep(now: number): void {
    const h = Math.floor(now / HOUR_MS);
    for (const ws of this.sockets)
      if (Math.floor(ws.acceptedAt / HOUR_MS) < h - 1) ws._serverClose(4000, "max age");
  }

  private pruneRing(now: number): void {
    const L = this.limits;
    while (
      this.ring.length > 0 &&
      (this.ring.length > L.ringRows ||
        this.ringBytes > L.ringBytes ||
        now - this.ring[0].at > L.ringMs)
    ) {
      this.ringBytes -= rowSize(this.ring.shift()!);
    }
  }
}

const stripAt = ({ at: _at, ...r }: RingRow): RtRow => r;

type Listener = (ev: never) => void;

/**
 * A browser-like WebSocket connected to a FakeWorld's realtime component. `FakeWebSocket.bind(host, who)` makes a
 * class bound to one world and client (the per-engine transport); the plain class connects to
 * `FakeWebSocket.resolveHost()` (the harness's current world) as an anonymous client.
 */
export class FakeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  readonly CONNECTING = 0;
  readonly OPEN = 1;
  readonly CLOSING = 2;
  readonly CLOSED = 3;

  /** The world unbound sockets connect to (set by the harness). */
  static resolveHost: (() => RtHost) | null = null;
  static boundHost: RtHost | null = null;
  static boundWho: string | null = null;

  /** A FakeWebSocket class whose instances connect to `host` as client `who`. */
  static bind(host: RtHost, who: string | null): typeof FakeWebSocket {
    return class extends FakeWebSocket {
      static override boundHost: RtHost | null = host;
      static override boundWho: string | null = who;
    };
  }

  readyState = 0;
  binaryType: "blob" | "arraybuffer" = "blob";
  readonly url: string;
  readonly protocol = "";
  readonly extensions = "";
  readonly bufferedAmount = 0;
  onopen: ((ev: { type: "open" }) => void) | null = null;
  onmessage: ((ev: { type: "message"; data: unknown }) => void) | null = null;
  onerror: ((ev: { type: "error" }) => void) | null = null;
  onclose:
    | ((ev: { type: "close"; code: number; reason: string; wasClean: boolean }) => void)
    | null = null;
  private readonly listeners = new Map<string, Set<Listener>>();

  readonly id = ++socketIds;
  /** The client this socket belongs to (FakeWorld request attribution), or null. */
  readonly who: string | null;
  readonly host: RtHost;

  // server-side state (owned by FakeRealtime)
  /** subscribed topics, by b64u */
  readonly topics = new Map<string, Bytes>();
  sawBinary = false;
  acceptedAt = 0;
  win = -1;
  frames = 0;
  changes = 0;
  /** Status of the upgrade response: 101 = accepted, 0 = not answered yet (or the answer was lost). */
  upgradeStatus = 0;
  /**
   * Headers of the upgrade response (null until answered, or when the answer was lost). Empty on a 101: the Worker
   * passes the RealtimeDO's 101 on unchanged, without `x-segv-now`, HSTS, `nosniff` or `no-referrer` (§9.7, §10.1).
   * A refusal carries them all, as every other response does. (A browser exposes neither; this is for tests.)
   */
  upgradeHeaders: Headers | null = null;
  /** close code and reason once closed */
  closeCode: number | null = null;
  closeReason = "";
  /** Frames and bytes this socket received from the server (ROWS entries counted in `rows`). */
  readonly rx = { frames: 0, bytes: 0, rows: 0 };
  /** Frames and bytes this socket sent. */
  readonly tx = { frames: 0, bytes: 0 };

  constructor(url: string | URL, _protocols?: string | string[]) {
    const ctor = new.target as typeof FakeWebSocket;
    const host = ctor.boundHost ?? FakeWebSocket.resolveHost?.();
    if (!host) throw new Error("FakeWebSocket: no FakeWorld to connect to");
    this.host = host;
    this.who = ctor.boundWho;
    this.url = String(url);
    host.rt._connect(this);
  }

  /** The request path of `url` (the world refuses anything but /api/v2/rt). */
  get path(): string {
    try {
      return new URL(this.url, "http://segv.test/").pathname;
    } catch {
      return "";
    }
  }

  send(data: string | ArrayBuffer | ArrayBufferView | Blob): void {
    if (this.readyState === FakeWebSocket.CONNECTING)
      throw new DOMException("WebSocket is still connecting", "InvalidStateError");
    if (this.readyState !== FakeWebSocket.OPEN) return;
    let payload: string | Bytes;
    if (typeof data === "string") payload = data;
    else if (data instanceof ArrayBuffer) payload = new Uint8Array(data.slice(0));
    else if (ArrayBuffer.isView(data))
      payload = new Uint8Array(
        data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength),
      );
    else throw new Error("FakeWebSocket: Blob frames are not supported");
    this.tx.frames++;
    this.tx.bytes += typeof payload === "string" ? payload.length : payload.length;
    setTimeout(() => this.host.rt._message(this, payload), 0);
  }

  close(code?: number, reason = ""): void {
    if (this.readyState === FakeWebSocket.CLOSING || this.readyState === FakeWebSocket.CLOSED)
      return;
    if (this.readyState === FakeWebSocket.CONNECTING) {
      // Closing before the handshake fails the connection: error, then close 1006 (as browsers do).
      this.readyState = FakeWebSocket.CLOSED;
      setTimeout(() => {
        this.emit("error", { type: "error" });
        this.finish(1006, "", false);
      }, 0);
      return;
    }
    this.readyState = FakeWebSocket.CLOSING;
    this.host.rt._closed(this);
    setTimeout(() => {
      this.readyState = FakeWebSocket.CLOSED;
      this.finish(code ?? 1005, reason, true);
    }, 0);
  }

  addEventListener(type: string, fn: Listener): void {
    let set = this.listeners.get(type);
    if (!set) this.listeners.set(type, (set = new Set()));
    set.add(fn);
  }

  removeEventListener(type: string, fn: Listener): void {
    this.listeners.get(type)?.delete(fn);
  }

  // ───────────── driven by FakeRealtime ─────────────

  _open(): void {
    this.readyState = FakeWebSocket.OPEN;
    this.emit("open", { type: "open" });
  }

  _deliver(data: string | Bytes): void {
    if (this.readyState !== FakeWebSocket.OPEN) return;
    this.rx.frames++;
    if (typeof data === "string") {
      this.rx.bytes += data.length;
      this.emit("message", { type: "message", data });
      return;
    }
    this.rx.bytes += data.length;
    if (data[0] === 0x81) this.rx.rows += (data[1] << 8) | data[2];
    const ab = data.slice().buffer;
    this.emit("message", {
      type: "message",
      data: this.binaryType === "arraybuffer" ? ab : new Blob([ab]),
    });
  }

  _fail(): void {
    if (this.readyState === FakeWebSocket.CLOSED) return;
    this.readyState = FakeWebSocket.CLOSED;
    this.emit("error", { type: "error" });
    this.finish(1006, "", false);
  }

  _serverClose(code: number, reason: string): void {
    if (this.readyState === FakeWebSocket.CLOSED || this.readyState === FakeWebSocket.CLOSING)
      return;
    this.readyState = FakeWebSocket.CLOSED;
    this.host.rt._closed(this);
    setTimeout(() => this.finish(code, reason, true), 0);
  }

  private finish(code: number, reason: string, wasClean: boolean): void {
    this.closeCode = code;
    this.closeReason = reason;
    this.emit("close", { type: "close", code, reason, wasClean });
  }

  private emit(type: string, ev: { type: string; [k: string]: unknown }): void {
    const h = (this as unknown as Record<string, unknown>)[`on${type}`];
    if (typeof h === "function") (h as (e: unknown) => void).call(this, ev);
    for (const fn of this.listeners.get(type) ?? []) (fn as (e: unknown) => void).call(this, ev);
  }
}
