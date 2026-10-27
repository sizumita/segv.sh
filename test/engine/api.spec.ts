// The client API module (src/client/api.ts) at unit level: params bounds (§3.1), the server-time estimate (§10.1),
// the PoW window restart (§10.2), and the prefix bits of directory lookups (§10.6).
import { describe, expect, it } from "vite-plus/test";
import { Api, ApiError, ServerClock, checkParams, isTransient } from "../../src/client/api";
import { I, P, TestClock, engineFor, freshWorldPerTest, makeUser, server } from "./harness";

freshWorldPerTest();

/** A params answer as the fake world gives it. */
const PARAMS = {
  v: 2,
  now: P.T0_MS + 10 * P.ERA_MS,
  T0: P.T0_MS,
  eraMs: P.ERA_MS,
  era: 10,
  delta: 10,
  skew: 2,
  inboxSlot: 10,
  inboxRetention: 4,
  inboxDayCap: 2000,
  inboxBatch: 32,
  shards: 1,
  p: 0,
  efirst: 0,
  kcommit: P.b64u(new Uint8Array(32)),
  srvKey: P.b64u(new Uint8Array(32)),
  pow: { register: 20, wrap: 18, put: 16, inbox: 18, blob: 18 },
  limits: { putRows: 16, putBytes: 263345, getKeys: 256, topics: 256, blobMax: 12582912, textMax: 12000 },
};

type Route = (path: string) => { status?: number; json: unknown } | null;

/** A fetch that answers `no-store` JSON with `x-segv-now = now()`, and records the paths asked. */
function stubFetch(now: () => number, route: Route, seen: string[] = []): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = new URL(String(input), "http://segv.test/");
    const path = url.pathname + url.search;
    seen.push(path);
    const r = route(path) ?? { status: 404, json: { error: "not found" } };
    return new Response(JSON.stringify(r.json), {
      status: r.status ?? 200,
      headers: { "content-type": "application/json", "cache-control": "no-store", "x-segv-now": String(now()) },
    });
  }) as typeof fetch;
}

describe("params bounds (§3.1)", () => {
  it("accepts the deployment shape and refuses a delta, skew or inboxSlot outside its bounds", () => {
    expect(checkParams(PARAMS).delta).toBe(10);
    for (const [k, v] of [
      ["delta", 0],
      ["delta", 3601],
      ["delta", 11], // does not divide 604 800
      ["delta", 1.5],
      ["skew", 61],
      ["skew", -1],
      ["inboxSlot", 0],
      ["inboxSlot", 3601],
      ["T0", P.T0_MS + 1],
      ["v", 1],
    ] as const) {
      const bad = { ...PARAMS, [k]: v };
      expect(() => checkParams(bad), `${k} = ${v}`).toThrow(ApiError);
      expect(isTransient(catchErr(() => checkParams(bad))), "a failed request, retried").toBe(true);
    }
    expect(checkParams({ ...PARAMS, delta: 1, skew: 0, inboxSlot: 1 }).delta).toBe(1);
    expect(checkParams({ ...PARAMS, delta: 3600 }).delta).toBe(3600);
  });

  it("the engine retries a malformed params answer instead of using it", async () => {
    let bad = 2;
    const orig = server().params.delta;
    server().hooks.beforeRequest = (_m, p) => {
      if (p === "/api/v2/params") server().params.delta = bad-- > 0 ? 7 * 3 + 2 : orig; // 23 does not divide 604 800
    };
    const R = await engineFor(makeUser("bounds"));
    expect(R.getState().phase).toBe("ready");
    expect(R.getState().error).toBe("");
    expect(bad).toBeLessThan(0);
    expect(server().requests.filter((r) => r.path === "/api/v2/params").length).toBeGreaterThanOrEqual(3);
  });
});

const catchErr = (f: () => unknown): unknown => {
  try {
    f();
  } catch (e) {
    return e;
  }
  return null;
};

describe("the server-time estimate (§10.1)", () => {
  it("takes the sample with the smallest rtt, the newest among equal ones, and estimates by the monotonic clock", () => {
    const c = new TestClock();
    c.pauseMono();
    const t = new ServerClock(c);
    const m0 = Math.floor(c.mono()); // integral, so the rtts below are exact
    t.add(1_000_000, m0, m0 + 300); // rtt 300
    t.add(1_000_250, m0 + 200, m0 + 300); // rtt 100, consistent
    expect(t.sample!.rtt).toBe(100);
    t.add(1_000_400, m0 + 350, m0 + 450); // rtt 100 again, newer
    expect(t.sample!.mid).toBe(m0 + 400);
    const est = () => 1_000_400 + (c.mono() - (m0 + 400));
    c.advance(1000, { mono: true, wall: false });
    expect(t.now()).toBeCloseTo(est(), 6);
    // the wall clock never moves the estimate
    const before = t.now();
    c.advance(5 * 60_000, { mono: false, wall: true });
    expect(t.now()).toBe(before);
  });

  it("a disagreeing sample discards every older one, even with a larger rtt", () => {
    const c = new TestClock();
    c.pauseMono();
    const t = new ServerClock(c);
    t.skewMs = 2000;
    const m0 = Math.floor(c.mono());
    t.add(5_000_000, m0, m0 + 10);
    // a week later by the server, but the monotonic clock barely moved (it stopped while the system slept)
    t.add(5_000_000 + P.ERA_MS, m0 + 20, m0 + 1020); // rtt 1000
    expect(t.sample).toEqual({ s: 5_000_000 + P.ERA_MS, mid: m0 + 520, rtt: 1000 });
    // within (rtt_old + rtt_new)/2 + SKEW + 1 s the older sample stays and wins by rtt
    const t2 = new ServerClock(c);
    t2.skewMs = 2000;
    t2.add(5_000_000, m0, m0 + 10);
    t2.add(5_000_000 + 20 + 2900, m0 + 20, m0 + 1020);
    expect(t2.sample!.rtt).toBe(10);
  });

  it("uses an rtt above 2 s only when no better sample is younger than 10 minutes; with none that young, the newest", () => {
    const c = new TestClock();
    c.pauseMono();
    const t = new ServerClock(c);
    const m0 = Math.floor(c.mono());
    t.add(1_000_000, m0, m0 + 3000); // poor
    expect(t.sample!.rtt).toBe(3000);
    t.add(1_003_500, m0 + 3000, m0 + 4000); // good
    expect(t.sample!.rtt).toBe(1000);
    c.advance(11 * 60_000, { mono: true, wall: false });
    t.add(1_003_500 + 11 * 60_000 + 1000, m0 + 11 * 60_000 + 1000, m0 + 11 * 60_000 + 4000); // poor, but the only young one
    expect(t.sample!.rtt).toBe(3000);
    c.advance(11 * 60_000, { mono: true, wall: false });
    expect(t.sample!.mid).toBe(m0 + 11 * 60_000 + 2500); // nothing young: the newest
  });

  it("cacheable responses never give a sample", async () => {
    const c = new TestClock();
    const api = new Api({
      clock: c,
      fetch: (async () =>
        new Response("{}", { headers: { "cache-control": "public, max-age=10", "x-segv-now": "123" } })) as typeof fetch,
    });
    await api.request("/api/v2/blob/x");
    expect(api.time.sample).toBeNull();
  });
});

describe("proof of work (§10.2)", () => {
  it("restarts the search with the new window when the window it searches in stops being current", async () => {
    const c = new TestClock();
    c.pauseMono();
    const w = 4_700_000;
    let serverMs = (w + 1) * P.POW_WINDOW_MS - 1; // 1 ms before window w ends
    const api = new Api({
      clock: c,
      fetch: stubFetch(() => serverMs, (p) => (p === "/api/v2/params" ? { json: { ...PARAMS, pow: { ...PARAMS.pow, register: 12 } } } : null)),
    });
    await api.params();
    // A digest whose first search chunk (nonces 0..4095) fails in window w, so the search must still run when the
    // window ends; the restarted search then uses window w + 1.
    let digest = P.H(P.utf8("x"));
    for (let k = 0; ; k++) {
      const pre = P.powPre("register", w, digest);
      let hit = false;
      for (let n = 0; n < 4096 && !hit; n++) hit = P.powCheck(pre, n, 12);
      if (!hit) break;
      digest = P.H(P.utf8(`x${k}`));
    }
    const header = api.powHeader("register", digest, 100);
    setTimeout(() => {
      c.advance(5, { mono: true, wall: false }); // the window ends while the first search runs
      serverMs += 5;
    }, 0);
    const [win, nonce] = (await header).split(".").map(Number);
    expect(win).toBe(w + 1);
    expect(P.powCheck(P.powPre("register", w + 1, digest), nonce, 12)).toBe(true);
  });

  it("refuses a base above 26", async () => {
    const c = new TestClock();
    const api = new Api({
      clock: c,
      fetch: stubFetch(() => PARAMS.now, (p) => (p === "/api/v2/params" ? { json: { ...PARAMS, pow: { ...PARAMS.pow, wrap: 27 } } } : null)),
    });
    await expect(api.powHeader("wrap", new Uint8Array(32), 10)).rejects.toThrow(/unreasonable/);
  });
});

describe("directory prefix bits (§10.6)", () => {
  const users = (n: number) => ({ p: 0, users: [], more: false, n });

  it("with P = 0 and dirSeq = 20 000 a lookup asks p = 2 (P* = 3); a 409 {p: 0} retry asks p = 0 and is not raised again", async () => {
    const seen: string[] = [];
    const api = new Api({
      clock: new TestClock(),
      fetch: stubFetch(
        () => PARAMS.now,
        (path) => {
          if (path === "/api/v2/params") return { json: PARAMS };
          if (path.startsWith("/api/v2/dirlog")) return { json: { entries: [], head: { seq: 20_000, h: "" } } };
          if (path.startsWith("/api/v2/dir/h/2/")) return { status: 409, json: { error: "prefix bits out of range", p: 0 } };
          if (path === "/api/v2/dir/h/0/0") return { json: users(0) };
          return null;
        },
        seen,
      ),
    });
    expect(await api.userByHandle("bob")).toBeNull();
    const dir = seen.filter((p) => p.startsWith("/api/v2/dir/"));
    expect(dir.slice(0, 2)).toEqual([`/api/v2/dir/h/2/${P.topBits(P.hpre("bob"), 2)}`, "/api/v2/dir/h/0/0"]);
    expect(dir.slice(2).every((p) => p === dir[0] || p === dir[1])).toBe(true); // the one fresh re-ask
    expect(seen.filter((p) => p.startsWith("/api/v2/dirlog"))).toHaveLength(1); // read once per session
  });

  it("a second 409 fails the lookup as transient: it never makes a handle unknown", async () => {
    const api = new Api({
      clock: new TestClock(),
      fetch: stubFetch(
        () => PARAMS.now,
        (path) => {
          if (path === "/api/v2/params") return { json: { ...PARAMS, p: 3 } };
          if (path.startsWith("/api/v2/dirlog")) return { json: { entries: [], head: { seq: 20_000, h: "" } } };
          if (path.startsWith("/api/v2/dir/h/")) return { status: 409, json: { error: "prefix bits out of range", p: 1 } };
          return null;
        },
      ),
    });
    const e = await api.userByHandle("bob").catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect(isTransient(e)).toBe(true);
  });

  it("a page for p ≥ 1 with fewer than 8 users gives the noise warning", async () => {
    const warnings: string[] = [];
    const api = new Api({
      clock: new TestClock(),
      warn: (t) => warnings.push(t),
      fetch: stubFetch(
        () => PARAMS.now,
        (path) => {
          if (path === "/api/v2/params") return { json: { ...PARAMS, p: 2 } };
          if (path.startsWith("/api/v2/dirlog")) return { json: { entries: [], head: { seq: 300, h: "" } } };
          if (path.startsWith("/api/v2/dir/h/1/")) return { json: { p: 1, users: [], more: false } };
          return null;
        },
      ),
    });
    expect(await api.userByHandle("bob")).toBeNull();
    expect(warnings.length).toBeGreaterThanOrEqual(1); // once per short answer (the engine counts repeats)
    expect([...new Set(warnings)]).toEqual(["the directory answered fewer accounts than expected"]);
  });

  it("an engine's requests are attributed to it, and its estimate follows the world", async () => {
    const R = await engineFor(makeUser("sampler"));
    const s = I(R).timeSample!;
    expect(s.rtt).toBeGreaterThanOrEqual(0);
    expect(Math.abs(s.s + (I(R).clock.mono() - s.mid) - server().now())).toBeLessThan(1000);
    expect(server().requests.filter((r) => r.who === "sampler").length).toBeGreaterThan(3);
  });
});
