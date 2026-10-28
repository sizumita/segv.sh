// The device's notification setting, subscription and registration (push.ts; docs/PROTOCOL.md §11.13), with a fake
// browser, a fake transport and a manual clock.
import { describe, expect, it } from "vite-plus/test";
import * as P from "~/lib/proto";
import type { EngineClock, EngineTimer } from "./options";
import {
  PushClient,
  type PushManagerLike,
  type PushParams,
  type PushSetting,
  type PushSubBody,
  type PushSubscriptionLike,
} from "./push";

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
  /** Advances time, running due timers in order (and awaiting what they start). */
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
  pending(): number[] {
    return this.timers.filter((x) => !x.dead).map((x) => x.at - this.t);
  }
}

const settle = async () => {
  for (let i = 0; i < 20; i++) await Promise.resolve();
};

class FakeSub implements PushSubscriptionLike {
  ended = false;
  constructor(
    readonly endpoint: string,
    readonly key: Uint8Array,
    private readonly log: string[],
  ) {}
  readonly p256dh = P.random(65);
  readonly auth = P.random(16);
  get options() {
    return { applicationServerKey: this.key.slice().buffer as ArrayBuffer };
  }
  getKey(name: "p256dh" | "auth"): ArrayBuffer {
    return (name === "p256dh" ? this.p256dh : this.auth).slice().buffer as ArrayBuffer;
  }
  async unsubscribe(): Promise<boolean> {
    this.ended = true;
    this.log.push(`unsubscribe ${this.endpoint}`);
    return true;
  }
}

function world(
  opts: {
    params?: PushParams | null;
    permission?: NotificationPermission;
    subscribeThrows?: boolean;
  } = {},
) {
  const log: string[] = [];
  const clock = new ManualClock();
  let seq = 0;
  const vapid = P.random(65);
  let params: PushParams | null =
    opts.params === undefined ? { vapid, window: 60, maxTokens: 256 } : opts.params;
  let current: FakeSub | null = null;
  let permission: NotificationPermission = opts.permission ?? "default";
  const failures: { status: number; retryAfter: number | null }[] = [];
  const subs: PushSubBody[] = [];
  const rings: { E: number; tokens: Uint8Array[] }[] = [];
  const ringFailures: number[] = [];
  let setting: PushSetting = { on: false, endpoint: null };
  let bells: Uint8Array[] = [P.random(16), P.random(16)];
  let subscribeThrows = opts.subscribeThrows ?? false;
  let offs = 0;
  const manager: PushManagerLike = {
    getSubscription: async () => (current && !current.ended ? current : null),
    subscribe: async (o) => {
      if (subscribeThrows) throw new DOMException("needs a gesture", "NotAllowedError");
      current = new FakeSub(
        `https://push.test/e${seq++}`,
        new Uint8Array(o.applicationServerKey as ArrayBuffer),
        log,
      );
      log.push(`subscribe ${current.endpoint}`);
      return current;
    },
  };
  const client = new PushClient({
    transport: {
      pushSub: async (b) => {
        log.push(`sub ${b.endpoint} ${b.tokens.length}`);
        const f = failures.shift();
        if (f) throw Object.assign(new Error("failed"), f);
        subs.push(b);
      },
      ring: async (E, _label, tokens) => {
        rings.push({ E, tokens });
        const f = ringFailures.shift();
        if (f !== undefined) throw Object.assign(new Error("failed"), { status: f });
      },
    },
    platform: {
      permission: () => permission,
      requestPermission: async () => {
        log.push("permission");
        if (permission === "default") permission = "granted";
        return permission;
      },
      manager: async () => manager,
      existing: async () => manager,
    },
    store: { load: () => setting, save: (s) => (setting = s) },
    clock,
    params: () => params,
    deltaMs: () => 10_000,
    bells: () => bells,
    onOff: () => offs++,
    random: () => 0.5,
  });
  return {
    client,
    clock,
    log,
    subs,
    rings,
    vapid,
    get setting() {
      return setting;
    },
    get current() {
      return current;
    },
    set bells(b: Uint8Array[]) {
      bells = b;
    },
    set params(p: PushParams | null) {
      params = p;
    },
    set subscribeThrows(v: boolean) {
      subscribeThrows = v;
    },
    set permission(p: NotificationPermission) {
      permission = p;
    },
    get offs() {
      return offs;
    },
    fail: (status: number, retryAfter: number | null = null) =>
      failures.push({ status, retryAfter }),
    failRing: (status: number) => ringFailures.push(status),
  };
}

describe("PushClient", () => {
  it("enable asks for permission in the click, subscribes with params.vapid, and registers the set", async () => {
    const w = world();
    expect(w.client.available).toBe(true);
    await w.client.enable();
    expect(w.log.slice(0, 2)).toEqual(["permission", "subscribe https://push.test/e0"]);
    expect(P.equalBytes(w.current!.key, w.vapid)).toBe(true);
    expect(w.subs).toHaveLength(1);
    expect(w.subs[0].endpoint).toBe("https://push.test/e0");
    expect(w.subs[0].tokens).toHaveLength(2);
    expect(w.subs[0].p256dh).toBe(P.b64u(w.current!.p256dh));
    expect(w.setting).toEqual({ on: true, endpoint: "https://push.test/e0" });
  });

  it("enable fails, and stays off, when notifications are not allowed", async () => {
    const w = world({ permission: "denied" });
    await expect(w.client.enable()).rejects.toThrow(/not allowed/);
    expect(w.setting.on).toBe(false);
    expect(w.subs).toEqual([]);
  });

  it("is not available without params.push", () => {
    expect(world({ params: null }).client.available).toBe(false);
  });

  it("keeps at most maxTokens bells, newest first, each once", async () => {
    const w = world();
    const bs = Array.from({ length: 5 }, () => P.random(16));
    w.bells = [bs[0], bs[0], ...bs.slice(1)];
    w.params = { vapid: w.vapid, window: 60, maxTokens: 3 };
    await w.client.enable();
    expect(w.subs[0].tokens).toEqual(bs.slice(0, 3).map(P.b64u));
  });

  it("batches changes over Δ, sends only a changed set, re-sends after a restore and at least every 24 hours", async () => {
    const w = world();
    await w.client.enable();
    w.client.changed(); // nothing changed: nothing is sent
    await w.clock.advance(10_000);
    expect(w.subs).toHaveLength(1);
    w.bells = [P.random(16)];
    w.client.changed();
    await w.clock.advance(5_000);
    w.client.changed();
    w.client.changed();
    await w.clock.advance(4_999);
    expect(w.subs).toHaveLength(1);
    await w.clock.advance(1);
    expect(w.subs).toHaveLength(2);
    expect(w.subs[1].tokens).toHaveLength(1);
    w.client.restored();
    await w.clock.advance(0);
    expect(w.subs).toHaveLength(3);
    await w.clock.advance(86_400_000);
    expect(w.subs).toHaveLength(4);
  });

  it("a new endpoint deletes the old registration first; a new VAPID key subscribes again", async () => {
    const w = world();
    await w.client.enable();
    await w.current!.unsubscribe(); // the browser rotated the subscription
    w.client.restored();
    await w.clock.advance(0);
    expect(w.log.slice(-3)).toEqual([
      "subscribe https://push.test/e1",
      "sub https://push.test/e0 0",
      "sub https://push.test/e1 2",
    ]);
    const newKey = P.random(65);
    w.params = { vapid: newKey, window: 60, maxTokens: 256 };
    w.client.restored();
    await w.clock.advance(0);
    expect(w.log.slice(-4)).toEqual([
      "unsubscribe https://push.test/e1",
      "sub https://push.test/e1 0",
      "subscribe https://push.test/e2",
      "sub https://push.test/e2 2",
    ]);
    expect(P.equalBytes(w.current!.key, newKey)).toBe(true);
    expect(w.setting.endpoint).toBe("https://push.test/e2");
  });

  it("a lost subscription that needs a click turns the setting off", async () => {
    const w = world();
    await w.client.enable();
    await w.current!.unsubscribe();
    w.subscribeThrows = true;
    w.client.restored();
    await w.clock.advance(0);
    expect(w.setting.on).toBe(false);
    expect(w.offs).toBe(1);
  });

  it("push full is retried no sooner than retry-after; other failures back off from 1 s doubling to 10 min", async () => {
    const w = world();
    w.fail(503, 3600);
    await w.client.enable();
    expect(w.subs).toHaveLength(0);
    await w.clock.advance(3_599_999);
    expect(w.subs).toHaveLength(0);
    await w.clock.advance(1);
    expect(w.subs).toHaveLength(1);
    for (let i = 0; i < 12; i++) w.fail(0);
    w.client.restored();
    await w.clock.advance(0);
    const waits: number[] = [];
    for (let i = 0; i < 11; i++) {
      waits.push(Math.min(...w.clock.pending()));
      await w.clock.advance(waits[i]);
    }
    expect(waits).toEqual([
      1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000, 256000, 512000, 600000,
    ]);
  });

  it("a 404 ends the subscription and turns the setting off", async () => {
    const w = world();
    w.fail(404);
    await w.client.enable();
    expect(w.current!.ended).toBe(true);
    expect(w.setting.on).toBe(false);
    expect(w.offs).toBe(1);
  });

  it("turning off and logout end the subscription first, then send the empty set, and leave the setting off", async () => {
    for (const how of ["disable", "logout"] as const) {
      const w = world();
      await w.client.enable();
      const ep = w.current!.endpoint;
      await w.client[how]();
      expect(w.log.slice(-2)).toEqual([`unsubscribe ${ep}`, `sub ${ep} 0`]);
      expect(w.setting).toEqual({ on: false, endpoint: null });
      w.client.restored();
      await w.clock.advance(86_400_000);
      expect(w.log.at(-1)).toBe(`sub ${ep} 0`); // nothing more
    }
  });

  it("rings once after a put, retries once within Δ after a network error or a 5xx, never after a 4xx", async () => {
    const w = world();
    const bs = [P.random(16)];
    w.client.ring(7, P.random(16), []);
    expect(w.rings).toEqual([]);
    w.client.ring(7, P.random(16), bs);
    await settle();
    expect(w.rings).toHaveLength(1);
    w.failRing(0);
    w.client.ring(7, P.random(16), bs);
    await settle();
    expect(w.clock.pending()).toEqual([5_000]);
    await w.clock.advance(5_000);
    expect(w.rings).toHaveLength(3);
    w.failRing(503);
    w.failRing(503);
    w.client.ring(7, P.random(16), bs);
    await settle();
    await w.clock.advance(10_000);
    expect(w.rings).toHaveLength(5);
    expect(w.clock.pending()).toEqual([]);
    w.failRing(429);
    w.client.ring(7, P.random(16), bs);
    await settle();
    expect(w.clock.pending()).toEqual([]);
    w.params = null;
    w.client.ring(7, P.random(16), bs);
    await settle();
    expect(w.rings).toHaveLength(6);
  });
});
