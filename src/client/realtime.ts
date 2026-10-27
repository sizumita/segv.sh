// The realtime socket (docs/PROTOCOL.md §10.8, §11.6): SUB / UNSUB / RESUME by seq, HELLO (a clock sample),
// ROWS, GAP and RESUMED; ping every 30 s; reconnect with back-off and jitter, at least 60 s after a 1008 or 1013.
// One socket of up to 256 topics (the second socket of §10.8 is for more than 256 topics, M6c).
import * as P from "~/lib/proto";
import * as W from "~/lib/wire";
import type { EngineClock, EngineTimer, WebSocketCtor } from "./options";

type Bytes = Uint8Array;

export interface RealtimeHandlers {
  /** rows of subscribed topics, in seq order */
  onRows(rows: W.RtRow[]): void;
  /** rows may have been missed (GAP, or a reconnect without RESUMED): run a catch-up */
  onMissed(): void;
  /** newly subscribed topics: probe their expected slots once (rows published before the SUB are not replayed) */
  onSubscribed(topics: Bytes[]): void;
  /** a HELLO's server time, with the socket's upgrade-to-HELLO interval on the monotonic clock (§10.1) */
  onHello(s: number, sentMono: number, recvMono: number): void;
  onState(connected: boolean): void;
}

const PING_MS = 30_000;
const BACKOFF_MIN = 1000;
const BACKOFF_MAX = 30_000;
const POLICY_WAIT = 60_000;

export class Realtime {
  private ws: WebSocket | null = null;
  private stopped = true;
  private boot: Bytes | null = null;
  private seq = 0;
  /** topics wanted, by b64u */
  private readonly want = new Map<string, Bytes>();
  /** topics the server has for the open socket */
  private readonly sent = new Map<string, Bytes>();
  private resumed = false;
  private openedAt = 0;
  private backoff = BACKOFF_MIN;
  private timer: EngineTimer | null = null;
  private ping: EngineTimer | null = null;

  constructor(
    private readonly WS: WebSocketCtor,
    private readonly clock: EngineClock,
    private readonly h: RealtimeHandlers,
  ) {}

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    this.timer?.cancel();
    this.ping?.cancel();
    this.timer = this.ping = null;
    const ws = this.ws;
    this.ws = null;
    if (ws) {
      ws.onopen = ws.onmessage = ws.onclose = ws.onerror = null;
      try {
        ws.close();
      } catch {
        /* already closed */
      }
    }
  }

  /** Replaces the wanted topic set (at most 256 kept, in the given priority order). */
  setTopics(topics: readonly Bytes[]): void {
    this.want.clear();
    for (const t of topics.slice(0, W.RT_MAX_TOPICS)) this.want.set(P.b64u(t), t);
    this.sync();
  }

  get connected(): boolean {
    return this.ws?.readyState === 1;
  }

  private connect(): void {
    if (this.stopped) return;
    const url = new URL(
      "/api/v2/rt",
      typeof location === "undefined" ? "http://localhost/" : location.href,
    );
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    let ws: WebSocket;
    try {
      ws = new this.WS(url);
    } catch {
      return this.retry(false);
    }
    this.ws = ws;
    this.sent.clear();
    this.resumed = false;
    this.openedAt = this.clock.mono();
    ws.binaryType = "arraybuffer";
    ws.onopen = () => {
      this.backoff = BACKOFF_MIN;
      const topics = [...this.want.values()];
      if (this.boot) {
        ws.send(W.encodeClientFrame({ f: "resume", boot: this.boot, since: this.seq, topics }));
        for (const [k, t] of this.want) this.sent.set(k, t);
      } else this.sync();
      this.ping = this.clock.setTimer(() => this.pingNow(), PING_MS);
      this.h.onState(true);
      if (!this.boot) this.h.onMissed(); // a first connection: whatever came before was not seen live
    };
    ws.onmessage = (ev) => this.message(ev.data);
    ws.onclose = (ev) => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.ping?.cancel();
      this.ping = null;
      this.h.onState(false);
      this.retry(ev.code === 1008 || ev.code === 1013);
    };
    ws.onerror = () => {
      try {
        ws.close();
      } catch {
        /* closing */
      }
    };
  }

  private retry(policy: boolean): void {
    if (this.stopped) return;
    const jitter = Math.floor(Math.random() * 0.3 * this.backoff);
    const wait = policy ? POLICY_WAIT + jitter : this.backoff + jitter;
    this.backoff = Math.min(this.backoff * 2, BACKOFF_MAX);
    this.timer = this.clock.setTimer(() => {
      this.timer = null;
      this.connect();
    }, wait);
  }

  private pingNow(): void {
    if (this.ws?.readyState === 1) this.ws.send("ping");
    if (!this.stopped) this.ping = this.clock.setTimer(() => this.pingNow(), PING_MS);
  }

  /** Sends SUB for wanted topics the server lacks and UNSUB for the others. */
  private sync(): void {
    const ws = this.ws;
    if (!ws || ws.readyState !== 1) return;
    const add = [...this.want].filter(([k]) => !this.sent.has(k)).map(([, t]) => t);
    const drop = [...this.sent].filter(([k]) => !this.want.has(k)).map(([, t]) => t);
    if (drop.length) {
      ws.send(W.encodeClientFrame({ f: "unsub", topics: drop }));
      for (const t of drop) this.sent.delete(P.b64u(t));
    }
    if (add.length) {
      ws.send(W.encodeClientFrame({ f: "sub", topics: add }));
      for (const t of add) this.sent.set(P.b64u(t), t);
      this.h.onSubscribed(add);
    }
  }

  private message(data: unknown): void {
    if (typeof data === "string") return; // "pong"
    let f: W.ServerFrame;
    try {
      f = W.decodeServerFrame(new Uint8Array(data as ArrayBuffer));
    } catch {
      this.ws?.close(); // a frame we cannot parse: close and reconnect (§10.8)
      return;
    }
    switch (f.f) {
      case "hello": {
        const fresh = !this.boot || !P.equalBytes(this.boot, f.boot);
        this.h.onHello(f.now, this.openedAt, this.clock.mono());
        if (fresh) this.seq = f.seq;
        this.boot = f.boot;
        return;
      }
      case "rows":
        for (const r of f.rows) this.seq = Math.max(this.seq, r.seq);
        this.h.onRows(f.rows);
        return;
      case "gap":
        this.h.onMissed();
        this.sync();
        return;
      case "resumed":
        this.resumed = true;
        this.sync();
        return;
    }
  }
}
