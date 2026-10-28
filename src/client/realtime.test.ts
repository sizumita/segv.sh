// Reconnecting when the page is shown again or the network comes back (realtime.ts `wake`), with a fake socket,
// a fake clock and a minimal document / window.
import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";
import type { EngineClock, EngineTimer } from "./options";
import { Realtime } from "./realtime";

class FakeSocket {
  static all: FakeSocket[] = [];
  readyState = 0;
  binaryType = "blob";
  sent: unknown[] = [];
  closed = false;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: { code: number }) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(readonly url: string | URL) {
    FakeSocket.all.push(this);
  }
  send(data: unknown): void {
    this.sent.push(data);
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

describe("realtime: wake on resume", () => {
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
    show("visible");
    clock.advance(1_000);
    last().onmessage?.({ data: "pong" });
    clock.advance(20_000);
    expect(FakeSocket.all).toHaveLength(1);
    expect(last().closed).toBe(false);
  });

  it("stops listening once stopped", () => {
    last().drop(1006);
    rt.stop();
    show("visible");
    win.dispatchEvent(new Event("online"));
    expect(FakeSocket.all).toHaveLength(1);
  });
});
