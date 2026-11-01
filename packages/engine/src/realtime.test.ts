// Liveness and reconnecting (realtime.ts): pings that get no answer, connection attempts that hang, and a page
// shown again or a network that comes back (`wake`), with a fake socket, a fake clock and a minimal document / window.
import * as W from "@segv/protocol/wire";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import type { EngineClock, EngineTimer } from "./options";
import { Realtime } from "./realtime";

class FakeSocket {
  static all: FakeSocket[] = [];
  readyState = 0;
  binaryType = "blob";
  sent: unknown[] = [];
  closed = false;
  /** the server answers each "ping" with "pong" at once (false: a socket that died silently) */
  answers = true;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: { code: number }) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(readonly url: string | URL) {
    FakeSocket.all.push(this);
  }
  send(data: unknown): void {
    this.sent.push(data);
    if (data === "ping" && this.answers && this.readyState === 1)
      this.onmessage?.({ data: "pong" });
  }
  close(): void {
    this.closed = true;
    this.readyState = 3;
  }
  open(): void {
    this.readyState = 1;
    this.onopen?.();
  }
  /** The server or the network closes the socket. */
  drop(code: number): void {
    this.readyState = 3;
    this.onclose?.({ code });
  }
}

class FakeClock implements EngineClock {
  t = 0;
  private timers: { at: number; fn: () => void; live: boolean }[] = [];
  mono = (): number => this.t;
  wall = (): number => this.t;
  setTimer(fn: () => void, ms: number): EngineTimer {
    const timer = { at: this.t + Math.max(0, ms), fn, live: true };
    this.timers.push(timer);
    return { cancel: () => void (timer.live = false) };
  }
  advance(ms: number): void {
    const end = this.t + ms;
    for (;;) {
      const next = this.timers.filter((x) => x.live && x.at <= end).sort((a, b) => a.at - b.at)[0];
      if (!next) break;
      next.live = false;
      this.t = next.at;
      next.fn();
    }
    this.t = end;
  }
}

type Doc = EventTarget & { visibilityState: string };
const g = globalThis as unknown as { document?: Doc; window?: EventTarget };

describe("realtime: liveness and reconnect", () => {
  let clock: FakeClock;
  let states: boolean[];
  let doc: Doc;
  let win: EventTarget;
  let rt: Realtime;

  const show = (state: "visible" | "hidden") => {
    doc.visibilityState = state;
    doc.dispatchEvent(new Event("visibilitychange"));
  };
  const last = () => FakeSocket.all[FakeSocket.all.length - 1];

  beforeEach(() => {
    FakeSocket.all = [];
    clock = new FakeClock();
    states = [];
    doc = Object.assign(new EventTarget(), { visibilityState: "visible" });
    win = new EventTarget();
    g.document = doc;
    g.window = win;
    rt = new Realtime(FakeSocket as unknown as ConstructorParameters<typeof Realtime>[0], clock, {
      onRows: () => {},
      onMissed: () => {},
      onSubscribed: () => {},
      onHello: () => {},
      onState: (c) => states.push(c),
    });
    rt.start();
  });

  afterEach(() => {
    rt.stop();
    delete g.document;
    delete g.window;
  });

  it("connects at once when the page is shown again, instead of after the back-off", () => {
    last().open();
    last().drop(1006);
    expect(FakeSocket.all).toHaveLength(1);
    show("hidden");
    expect(FakeSocket.all).toHaveLength(1);
    show("visible");
    expect(FakeSocket.all).toHaveLength(2);
    last().open();
    // The back-off timer was cancelled: no third socket appears later.
    clock.advance(120_000);
    expect(FakeSocket.all).toHaveLength(2);
  });

  it("connects at once when the network comes back", () => {
    last().drop(1006);
    win.dispatchEvent(new Event("online"));
    expect(FakeSocket.all).toHaveLength(2);
  });

  it("keeps the wait of at least 60 s after a 1008", () => {
    last().open();
    last().drop(1008);
    show("visible");
    win.dispatchEvent(new Event("online"));
    clock.advance(59_000);
    expect(FakeSocket.all).toHaveLength(1);
    clock.advance(2_000);
    expect(FakeSocket.all).toHaveLength(2);
  });

  it("pings an open socket and replaces it when nothing answers", () => {
    const first = last();
    first.open();
    first.answers = false;
    first.sent = [];
    show("visible");
    expect(first.sent).toEqual(["ping"]);
    clock.advance(9_000);
    expect(FakeSocket.all).toHaveLength(1);
    clock.advance(1_000);
    expect(first.closed).toBe(true);
    expect(FakeSocket.all).toHaveLength(2);
    expect(states).toEqual([true, false]);
  });

  it("keeps an open socket that answers the ping", () => {
    last().open();
    last().answers = false;
    show("visible");
    clock.advance(1_000);
    last().onmessage?.({ data: "pong" });
    clock.advance(20_000);
    expect(FakeSocket.all).toHaveLength(1);
    expect(last().closed).toBe(false);
  });

  it("replaces an open socket at once when a periodic ping gets no answer within 10 s", () => {
    const first = last();
    first.open();
    clock.advance(5 * 60_000); // answered pings keep it
    expect(first.sent.filter((x) => x === "ping")).toHaveLength(10);
    expect(FakeSocket.all).toHaveLength(1);
    first.answers = false; // it dies without a close event
    clock.advance(30_000);
    expect(first.sent.filter((x) => x === "ping")).toHaveLength(11);
    clock.advance(9_999);
    expect(FakeSocket.all).toHaveLength(1);
    expect(states).toEqual([true]);
    clock.advance(1);
    expect(first.closed).toBe(true);
    expect(FakeSocket.all).toHaveLength(2); // no back-off
    expect(states).toEqual([true, false]);
    last().open();
    clock.advance(5 * 60_000);
    expect(FakeSocket.all).toHaveLength(2);
    expect(states).toEqual([true, false, true]);
  });

  it("takes any frame after a ping as its answer", () => {
    const s = last();
    s.open();
    s.answers = false;
    clock.advance(34_000); // the ping at 30 s
    s.onmessage?.({ data: W.encodeServerFrame({ f: "resumed" }).slice().buffer }); // a frame, but not the pong
    clock.advance(16_000); // past the check at 40 s
    expect(s.closed).toBe(false);
    expect(FakeSocket.all).toHaveLength(1);
    // A frame from before a ping does not answer it: the ping at 60 s goes unanswered.
    clock.advance(19_999);
    expect(s.closed).toBe(false);
    clock.advance(1);
    expect(s.closed).toBe(true);
    expect(FakeSocket.all).toHaveLength(2);
  });

  it("gives up an attempt that has not opened within 15 s and retries it with the back-off", () => {
    const noJitter = vi.spyOn(Math, "random").mockReturnValue(0);
    try {
      const first = last();
      clock.advance(5_000);
      show("visible"); // a wake leaves a connecting socket alone
      expect(FakeSocket.all).toHaveLength(1);
      clock.advance(9_999);
      expect(first.closed).toBe(false);
      clock.advance(1);
      expect(first.closed).toBe(true);
      expect(FakeSocket.all).toHaveLength(1); // not at once: 1 s of back-off
      clock.advance(999);
      expect(FakeSocket.all).toHaveLength(1);
      clock.advance(1);
      expect(FakeSocket.all).toHaveLength(2);
      // The next attempt hangs too, and the back-off has doubled.
      clock.advance(15_000);
      expect(last().closed).toBe(true);
      clock.advance(1_999);
      expect(FakeSocket.all).toHaveLength(2);
      clock.advance(1);
      expect(FakeSocket.all).toHaveLength(3);
      // An attempt that opens in time is kept.
      clock.advance(14_000);
      last().open();
      clock.advance(10 * 60_000);
      expect(FakeSocket.all).toHaveLength(3);
      expect(last().closed).toBe(false);
      expect(states).toEqual([false, false, true]); // the attempts that never opened report no connection
    } finally {
      noJitter.mockRestore();
    }
  });

  it("stops listening once stopped", () => {
    last().drop(1006);
    rt.stop();
    show("visible");
    win.dispatchEvent(new Event("online"));
    expect(FakeSocket.all).toHaveLength(1);
  });
});
