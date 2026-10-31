// "Quiet my other devices while I use this one" (quiet.ts; docs/PROTOCOL.md §11.13 "Seen elsewhere"): when a page is in
// use, and which rows it marks seen, how often and with what, against a fake transport and a manual clock.
import { describe, expect, it } from "vite-plus/test";
import * as P from "@segv/protocol/proto";
import type { EngineClock, EngineTimer } from "./options";
import {
  IN_USE_MS,
  QuietClient,
  RING_FRESH_S,
  SEEN_EVERY_MS,
  SEEN_ROWS,
  localQuietStore,
  pageInUse,
  type PageLike,
} from "./quiet";

class ManualClock implements EngineClock {
  t = 0;
  private timers: { at: number; fn: () => void; dead: boolean }[] = [];
  mono = () => this.t;
  wall = () => this.t;
  setTimer(fn: () => void, ms: number): EngineTimer {
    const x = { at: this.t + Math.max(0, ms), fn, dead: false };
    this.timers.push(x);
    return { cancel: () => (x.dead = true) };
  }
  async advance(ms: number): Promise<void> {
    const end = this.t + ms;
    for (;;) {
      const next = this.timers.filter((x) => !x.dead && x.at <= end).sort((a, b) => a.at - b.at)[0];
      if (!next) break;
      this.t = next.at;
      next.dead = true;
      next.fn();
      await settle();
    }
    this.t = end;
  }
}

const settle = async () => {
  for (let i = 0; i < 20; i++) await Promise.resolve();
};

/** A page whose visibility, focus and input the test sets. */
class FakePage implements PageLike {
  visibilityState: DocumentVisibilityState = "visible";
  focused = true;
  private readonly fns = new Map<string, ((ev: Event) => void)[]>();
  hasFocus(): boolean {
    return this.focused;
  }
  addEventListener(type: string, f: (ev: Event) => void): void {
    this.fns.set(type, [...(this.fns.get(type) ?? []), f]);
  }
  fire(type: string, ev: Partial<PointerEvent> = {}): void {
    for (const f of this.fns.get(type) ?? []) f(ev as Event);
  }
}

describe("pageInUse", () => {
  it("is in use while visible and focused, for IN_USE_MS after the last input; focus alone is not input", () => {
    let now = 1_000;
    const page = new FakePage();
    const inUse = pageInUse(page, () => now);
    expect(inUse()).toBe(false); // focused, but no input yet
    for (const t of ["keydown", "pointerdown", "pointermove", "touchstart", "wheel"]) {
      now += IN_USE_MS + 1;
      expect(inUse()).toBe(false);
      page.fire(t, { screenX: now, screenY: 1 });
      expect(inUse()).toBe(true);
    }
    now += IN_USE_MS;
    expect(inUse()).toBe(true);
    now += 1;
    expect(inUse()).toBe(false);
    page.fire("focus");
    expect(inUse()).toBe(false);
    page.fire("keydown");
    page.focused = false;
    expect(inUse()).toBe(false);
    page.focused = true;
    page.visibilityState = "hidden";
    expect(inUse()).toBe(false);
  });

  it("a scroll, which the page makes itself to follow new rows, and a pointer move in place are not input", () => {
    let now = 1_000;
    const page = new FakePage();
    const inUse = pageInUse(page, () => now);
    page.fire("pointermove", { screenX: 10, screenY: 20 });
    expect(inUse()).toBe(true);
    // Left alone: rows keep coming, the list scrolls to them, and content moves under the still pointer.
    for (let i = 0; i < 5; i++) {
      now += IN_USE_MS / 2;
      page.fire("scroll");
      page.fire("pointermove", { screenX: 10, screenY: 20 });
    }
    expect(inUse()).toBe(false);
    page.fire("pointermove", { screenX: 11, screenY: 20 });
    expect(inUse()).toBe(true);
  });

  it("is never in use without a page", () => {
    expect(pageInUse(null)()).toBe(false);
  });
});

describe("localQuietStore", () => {
  it("reads as on without storage, and keeps a choice for the page where storage cannot", () => {
    const g = globalThis as { localStorage?: unknown };
    const saved = g.localStorage;
    try {
      g.localStorage = undefined;
      const s = localQuietStore("segv.quiet.test");
      expect(s.load()).toBe(true);
      s.save(false);
      expect(s.load()).toBe(false);
      s.save(true);
      expect(s.load()).toBe(true);
      // Storage that reads but refuses writes (a full quota) does not bring the old value back either.
      const items = new Map<string, string>();
      g.localStorage = {
        getItem: (k: string) => items.get(k) ?? null,
        setItem: () => {
          throw new Error("QuotaExceededError");
        },
        removeItem: (k: string) => void items.delete(k),
      };
      const t = localQuietStore("segv.quiet.test");
      t.save(false);
      expect(t.load()).toBe(false);
      // Working storage keeps it, and the page follows what storage holds.
      const kept = new Map<string, string>();
      g.localStorage = {
        getItem: (k: string) => kept.get(k) ?? null,
        setItem: (k: string, v: string) => void kept.set(k, v),
        removeItem: (k: string) => void kept.delete(k),
      };
      const u = localQuietStore("segv.quiet.test");
      u.save(false);
      expect(kept.get("segv.quiet.test")).toBe("off");
      kept.delete("segv.quiet.test"); // another tab turned it back on
      expect(u.load()).toBe(true);
    } finally {
      g.localStorage = saved;
    }
  });
});

describe("QuietClient", () => {
  const DELTA = 10;
  function make(
    o: { inUse?: boolean; offered?: boolean; fail?: (n: number) => number | null } = {},
  ) {
    const clock = new ManualClock();
    const qS = P.random(16);
    const sent: { at: number; qS: Uint8Array; rows: { E: number; label: string }[] }[] = [];
    let on = true;
    const state = {
      inUse: o.inUse ?? true,
      offered: o.offered ?? true,
      secret: qS as Uint8Array | null,
    };
    const serverNow = P.T0_MS + 1_000_000_000;
    const c = new QuietClient({
      transport: {
        seen: async (k, rows) => {
          sent.push({
            at: clock.t,
            qS: k,
            rows: rows.map((r) => ({ E: r.E, label: P.b64u(r.label) })),
          });
          const s = o.fail?.(sent.length) ?? null;
          if (s !== null) throw Object.assign(new Error("failed"), { status: s });
        },
      },
      store: { load: () => on, save: (x) => void (on = x) },
      clock,
      inUse: () => state.inUse,
      offered: () => state.offered,
      secret: () => state.secret,
      delta: () => DELTA,
      serverNow: () => serverNow + clock.t,
    });
    const nowS = () => P.secOf(serverNow + clock.t);
    return { c, clock, qS, sent, state, nowS };
  }

  it("marks a fresh row at once, with the account's secret, and gathers the next ones for SEEN_EVERY_MS", async () => {
    const x = make();
    const [l1, l2, l3] = [P.random(16), P.random(16), P.random(16)];
    x.c.shown(7, l1, x.nowS());
    x.c.shown(7, l1, x.nowS()); // the same row again: once
    await x.clock.advance(0);
    expect(x.sent).toHaveLength(1);
    expect(P.equalBytes(x.sent[0].qS, x.qS)).toBe(true);
    expect(x.sent[0].rows).toEqual([{ E: 7, label: P.b64u(l1) }]);
    await x.clock.advance(100);
    x.c.shown(7, l2, x.nowS());
    x.c.shown(8, l3, x.nowS());
    await x.clock.advance(SEEN_EVERY_MS - 101);
    expect(x.sent).toHaveLength(1);
    await x.clock.advance(1);
    expect(x.sent).toHaveLength(2);
    expect(x.sent[1].at).toBe(SEEN_EVERY_MS);
    expect(x.sent[1].rows).toEqual([
      { E: 7, label: P.b64u(l2) },
      { E: 8, label: P.b64u(l3) },
    ]);
  });

  it("sends at most SEEN_ROWS rows a request, the rest a second later", async () => {
    const x = make();
    for (let i = 0; i < SEEN_ROWS + 3; i++) x.c.shown(1, P.random(16), x.nowS());
    await x.clock.advance(0);
    expect(x.sent.map((s) => s.rows.length)).toEqual([SEEN_ROWS]);
    await x.clock.advance(SEEN_EVERY_MS);
    expect(x.sent.map((s) => s.rows.length)).toEqual([SEEN_ROWS, 3]);
  });

  it("marks nothing while not in use, with the setting off, without push, or for a row too old to have rung", async () => {
    for (const set of [
      (x: ReturnType<typeof make>) => (x.state.inUse = false),
      (x: ReturnType<typeof make>) => x.c.set(false),
      (x: ReturnType<typeof make>) => (x.state.offered = false),
    ]) {
      const x = make();
      set(x);
      x.c.shown(1, P.random(16), x.nowS());
      await x.clock.advance(SEEN_EVERY_MS * 3);
      expect(x.sent).toHaveLength(0);
    }
    const x = make();
    x.c.shown(1, P.random(16), x.nowS() - RING_FRESH_S - DELTA - 1);
    x.c.shown(1, P.random(16), x.nowS() - RING_FRESH_S - DELTA);
    await x.clock.advance(SEEN_EVERY_MS);
    expect(x.sent.map((s) => s.rows.length)).toEqual([1]);
  });

  it("turning the setting off, or a session's end, drops what is queued", async () => {
    const x = make();
    x.c.shown(1, P.random(16), x.nowS());
    await x.clock.advance(0);
    x.c.shown(1, P.random(16), x.nowS());
    x.c.set(false);
    await x.clock.advance(SEEN_EVERY_MS * 2);
    expect(x.sent).toHaveLength(1);
    x.c.set(true);
    x.c.shown(1, P.random(16), x.nowS());
    x.state.secret = null;
    await x.clock.advance(SEEN_EVERY_MS * 2);
    expect(x.sent).toHaveLength(1);
  });

  it("a retry still waiting is never sent once the setting turns off, the session ends, or another session starts", async () => {
    for (const end of [
      (x: ReturnType<typeof make>) => x.c.set(false),
      (x: ReturnType<typeof make>) => x.c.stop(), // logout
      (x: ReturnType<typeof make>) => (x.state.secret = P.random(16)), // another account signed in
      (x: ReturnType<typeof make>) => (x.state.offered = false),
    ]) {
      const x = make({ fail: () => 0 });
      x.c.shown(1, P.random(16), x.nowS());
      await x.clock.advance(0);
      expect(x.sent).toHaveLength(1);
      end(x);
      await x.clock.advance(SEEN_EVERY_MS * 5);
      expect(x.sent).toHaveLength(1);
    }
  });

  it("retries once after a network error or a 5xx, never after a 4xx", async () => {
    for (const [status, want] of [
      [0, 2],
      [503, 2],
      [429, 1],
      [400, 1],
    ] as const) {
      const x = make({ fail: () => status });
      x.c.shown(1, P.random(16), x.nowS());
      await x.clock.advance(SEEN_EVERY_MS * 5);
      expect(x.sent).toHaveLength(want);
      if (want === 2) expect(x.sent[1].rows).toEqual(x.sent[0].rows);
    }
  });
});
