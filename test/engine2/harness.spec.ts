/**
 * Self-tests of the FakeWorld (test/engine2/fake/) through `fetch` / `WebSocket` with the src/lib/wire.ts codecs,
 * against the semantics of docs/PROTOCOL-v2.md §9–§10 (docs/STAGE1-PLAN.md M5).
 */
import { describe, expect, it } from "vite-plus/test";
import {
  CKPT_PERIOD_MS,
  FakeWebSocket,
  FakeWorld,
  P,
  W,
  freshWorldPerTest,
  RT_LIMITS,
  installBrowserGlobals,
  junkBody,
  junkRow,
  localStore,
  makeUser,
  newTestUser,
  registrationOf,
  server,
  sleep,
  uninstallBrowserGlobals,
  waitFor,
} from "./harness";

freshWorldPerTest();

// ───────────────────────── helpers ─────────────────────────

const ZERO16 = P.ZERO16;
const bytesOf = async (res: Response) => new Uint8Array(await res.arrayBuffer());
const whoHeader = (who?: string): Record<string, string> => (who ? { "x-fake-who": who } : {});
const nowHeader = (res: Response) => Number(res.headers.get("x-segv-now"));

const putRow = (E: number, label: Uint8Array, opts: { cls?: number; topic?: Uint8Array; body?: Uint8Array } = {}): W.PutRow => {
  const cls = opts.cls ?? 0;
  return { E, label, cls, topic: opts.topic ?? ZERO16, body: opts.body ?? junkBody(cls) };
};

async function put(rows: W.PutRow[], who?: string): Promise<W.PutResult[]> {
  const res = await fetch("/api/v2/put", { method: "POST", body: W.encodePutRequest(rows) as BodyInit, headers: whoHeader(who) });
  expect(res.status).toBe(200);
  return W.decodePutResponse(await bytesOf(res));
}

async function get(keys: W.GetKey[], who?: string): Promise<W.GetStatus[]> {
  const res = await fetch("/api/v2/get", { method: "POST", body: W.encodeGetRequest(keys) as BodyInit, headers: whoHeader(who) });
  expect(res.status).toBe(200);
  return W.decodeGetResponse(
    await bytesOf(res),
    keys.map((k) => k.mode),
  );
}

const invite = (): W.InboxPostRow => ({ eid: P.random(16), body: P.random(P.INBOX_BODY_LEN) });

const inboxPost = (E: number, rows: W.InboxPostRow[], who?: string) =>
  fetch("/api/v2/inbox", { method: "POST", body: W.encodeInboxPost({ E, bucket: 0, rows }) as BodyInit, headers: whoHeader(who) });

async function inboxRead(E: number, after = 0, limit?: number) {
  const res = await fetch(`/api/v2/inbox/${E}/0?after=${after}${limit ? `&limit=${limit}` : ""}`);
  return { res, r: res.status === 200 ? W.decodeInboxRead(await bytesOf(res)) : null };
}

const getJson = async (path: string) => {
  const res = await fetch(path);
  return { res, j: (await res.json()) as Record<string, any> };
};

const postJson = (path: string, body: unknown) =>
  fetch(path, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });

/** Moves the world clock to ~20 ms after a whole second, so the next steps stay inside one inbox slot / Δ. */
function alignToSecond(world: FakeWorld): void {
  world.advance(1000 - (world.now() % 1000) + 20, { keepSockets: true });
}

/** Opens a FakeWebSocket as `who` and decodes everything it receives. */
function openRt(who: string | null) {
  const WS = server().WebSocketAs(who);
  const ws = new WS("ws://segv.test/api/v2/rt");
  ws.binaryType = "arraybuffer";
  const frames: (W.ServerFrame | string)[] = [];
  const state: { closed: number | null } = { closed: null };
  ws.onmessage = (ev) => frames.push(typeof ev.data === "string" ? ev.data : W.decodeServerFrame(new Uint8Array(ev.data as ArrayBuffer)));
  ws.onclose = (ev) => {
    state.closed = ev.code;
  };
  const rows = () => frames.flatMap((f) => (typeof f !== "string" && f.f === "rows" ? f.rows : []));
  const kinds = () => frames.map((f) => (typeof f === "string" ? f : f.f));
  return { ws, frames, state, rows, kinds, send: (f: W.ClientFrame) => ws.send(W.encodeClientFrame(f)) };
}

async function hello(c: ReturnType<typeof openRt>) {
  await waitFor(() => c.frames.length > 0, "HELLO");
  const h = c.frames[0];
  if (typeof h === "string" || h.f !== "hello") throw new Error("expected HELLO first");
  return h;
}

// ───────────────────────── clock and headers ─────────────────────────

describe("clock and response headers", () => {
  it("stamps x-segv-now on every response, with the Worker's cache-control", async () => {
    const world = server();
    const E = world.era;
    const blob = P.random(200);
    const id = P.b64u(P.H(blob));
    const cases: [string, () => Promise<Response>, number, string][] = [
      ["params", () => fetch("/api/v2/params"), 200, "no-store"],
      ["put", () => fetch("/api/v2/put", { method: "POST", body: W.encodePutRequest([putRow(E, P.random(16))]) as BodyInit }), 200, "no-store"],
      ["get", () => fetch("/api/v2/get", { method: "POST", body: W.encodeGetRequest([{ E, label: P.random(16), mode: 0 }]) as BodyInit }), 200, "no-store"],
      ["blob meta miss", () => fetch(`/api/v2/blob/${id}/meta`), 404, "no-store"],
      ["blob put", () => fetch(`/api/v2/blob/${id}`, { method: "PUT", body: blob as BodyInit }), 201, "no-store"],
      ["blob meta hit", () => fetch(`/api/v2/blob/${id}/meta`), 200, "no-store"],
      ["blob get", () => fetch(`/api/v2/blob/${id}`), 200, "public, max-age=31536000, immutable"],
      ["inbox post", () => inboxPost(E, [invite()]), 200, "no-store"],
      ["inbox read", () => fetch(`/api/v2/inbox/${E}/0`), 200, "public, max-age=1"],
      ["dir uid 404", () => fetch(`/api/v2/dir/uid/${P.b64u(P.random(16))}`), 404, "no-store"],
      ["dirlog", () => fetch("/api/v2/dirlog"), 200, "no-store"],
      ["ckpt latest 404", () => fetch("/api/v2/ckpt/latest"), 404, "no-store"],
      ["era", () => fetch(`/api/v2/era/${E}`), 200, "no-store"],
      ["feed", () => fetch(`/api/v2/feed/${E}/0`), 200, "no-store"],
      ["rt without upgrade", () => fetch("/api/v2/rt"), 426, "no-store"],
      ["unknown path", () => fetch("/api/v2/nope"), 404, "no-store"],
      ["wrong method", () => fetch("/api/v2/put"), 405, "no-store"],
    ];
    for (const [what, call, status, cache] of cases) {
      const before = world.now();
      const res = await call();
      const after = world.now();
      expect(res.status, what).toBe(status);
      expect(res.headers.get("cache-control"), what).toBe(cache);
      const t = nowHeader(res);
      expect(t, what).toBeGreaterThanOrEqual(before);
      expect(t, what).toBeLessThanOrEqual(after);
      if (status >= 400) expect(typeof ((await res.json()) as { error?: unknown }).error, what).toBe("string");
    }
    const res405 = await fetch("/api/v2/put");
    expect(res405.headers.get("allow")).toBe("POST");
    world.ckpt.tick();
    const c1 = await fetch("/api/v2/ckpt/1");
    expect(c1.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
  });

  it("staleNow: cacheable responses carry an x-segv-now weeks old, no-store responses the current time", async () => {
    const world = server();
    const blob = P.random(100);
    const { id } = world.putBlob(blob);
    world.staleNow = true;
    const weeks3 = 21 * 86_400_000;
    for (const path of [`/api/v2/blob/${id}`, `/api/v2/inbox/${world.era}/0`]) {
      const res = await fetch(path);
      expect(res.headers.get("cache-control")!.startsWith("public")).toBe(true);
      expect(Math.abs(world.now() - weeks3 - nowHeader(res))).toBeLessThan(1000);
    }
    for (const path of ["/api/v2/params", `/api/v2/blob/${id}/meta`, "/api/v2/dirlog"]) {
      const res = await fetch(path);
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(Math.abs(world.now() - nowHeader(res))).toBeLessThan(1000);
    }
  });

  it("params report the test deployment", async () => {
    const world = server();
    const { j } = await getJson("/api/v2/params");
    expect(j).toMatchObject({
      v: 2,
      T0: P.T0_MS,
      eraMs: P.ERA_MS,
      era: world.era,
      delta: 1,
      skew: 0,
      inboxSlot: 1,
      inboxRetention: 4,
      inboxDayCap: 2000,
      inboxBatch: 32,
      shards: 1,
      p: 0,
      pow: { register: 0, wrap: 0, put: 0, inbox: 0, blob: 0 },
      limits: { putRows: 16, putBytes: 263345, getKeys: 256, topics: 256, blobMax: 12582912, textMax: 12000 },
    });
    expect(j.srvKey).toBe(P.b64u(world.srvKey));
    expect(j.kcommit).toBe(P.b64u(P.kcommit(P.kroute(world.routeKey, world.era))));
    expect(Math.abs(j.now - world.now())).toBeLessThan(1000);
  });

  it("advanceEra() moves to the next era start + 1 s; advance() moves by ms", async () => {
    const world = server();
    const E = world.era;
    expect(world.advanceEra()).toBe(E + 1);
    expect(world.now() - P.eraStart(E + 1)).toBeGreaterThanOrEqual(1000);
    expect(world.now() - P.eraStart(E + 1)).toBeLessThan(2000);
    const { j } = await getJson("/api/v2/params");
    expect(j.era).toBe(E + 1);
    world.advanceEra(3);
    expect(world.era).toBe(E + 4);
    const t = world.now();
    world.advance(-60_000);
    expect(t - world.now()).toBeGreaterThanOrEqual(59_990);
  });

  it("separate clocks: shardLagMs moves the shard's t but not BlobReg's t_reg", async () => {
    const world = server();
    alignToSecond(world);
    world.shardLagMs = 5000;
    const reg = world.putBlob(P.random(64));
    expect(reg.t).toBe(P.tpub(world.now(), 1));
    const [r] = await put([putRow(world.era, P.random(16))]);
    if (r.s !== "ok") throw new Error("expected OK");
    expect(r.t).toBe(P.tpub(world.now() - 5000, 1));
    expect(reg.t - r.t).toBe(5);
  });
});

// ───────────────────────── shard ─────────────────────────

describe("shard", () => {
  it("CAS: the first write wins; later writes get CONFLICT with the occupant; receipts verify", async () => {
    const world = server();
    const E = world.era;
    const L = P.random(16);
    const a = junkBody(1);
    const [ok] = await put([putRow(E, L, { cls: 1, body: a })]);
    if (ok.s !== "ok") throw new Error("expected OK");
    expect(Math.abs(ok.t - P.tpub(world.now(), 1))).toBeLessThanOrEqual(1);
    expect(P.verify(ok.receipt, P.receiptMsg(E, L, a, ok.t), world.srvKey)).toBe(true);

    const [c] = await put([putRow(E, L, { cls: 0 })]);
    expect(c).toEqual({ s: "conflict", t: ok.t, cls: 1, body: a });

    // A duplicate label inside one put: CONFLICT with the first copy; rows are independent.
    const L2 = P.random(16);
    const first = junkBody(0);
    const res = await put([putRow(E, L2, { body: first }), putRow(E, L2), putRow(E, P.random(16))]);
    expect(res.map((x) => x.s)).toEqual(["ok", "conflict", "ok"]);
    expect(res[1]).toMatchObject({ s: "conflict", body: first });
    expect(world.requests[world.requests.length - 1].putResults?.map((x) => x.s)).toEqual(["ok", "conflict", "ok"]);

    const st = await get([
      { E, label: L, mode: 0 },
      { E, label: L, mode: 1 },
      { E, label: P.random(16), mode: 0 },
    ]);
    expect(st[0]).toEqual({ s: "hit", t: ok.t, cls: 1, body: a });
    expect(st[1]).toEqual({ s: "hit", t: ok.t, cls: 1 });
    expect(st[2]).toEqual({ s: "miss", sealed: false });
    expect(world.shard.hits(E, L)).toBe(2);
  });

  it("WRONG_ERA after advanceEra(), early acceptance within SKEW, NO_ERA beyond it", async () => {
    const world = server();
    const E0 = world.era;
    world.advanceEra();
    const [w] = await put([putRow(E0, P.random(16))]);
    expect(w).toEqual({ s: "wrong_era", era: E0 + 1 });
    const [ok] = await put([putRow(E0 + 1, P.random(16))]);
    expect(ok.s).toBe("ok");

    // SKEW = 2 s: era E+1 accepts writes from start(E+1) − 2 s, with t = sec(start(E+1)).
    world.params.skew = 2;
    const E = world.era;
    world.advance(P.eraStart(E + 1) - 1000 - world.now(), { keepSockets: true });
    expect(world.era).toBe(E);
    const early = await put([putRow(E + 1, P.random(16)), putRow(E, P.random(16)), putRow(E + 2, P.random(16))]);
    expect(early[0]).toMatchObject({ s: "ok", t: P.secOf(P.eraStart(E + 1)) });
    expect(early[1].s).toBe("ok");
    expect(early[2]).toEqual({ s: "wrong_era", era: E });
    const reads = await get([
      { E: E + 1, label: P.random(16), mode: 1 },
      { E: E + 2, label: P.random(16), mode: 1 },
    ]);
    expect(reads).toEqual([{ s: "miss", sealed: false }, { s: "no_era" }]);

    // Outside SKEW the Worker's bounds refuse E + 1.
    world.advance(-1500, { keepSockets: true });
    const [late] = await put([putRow(E + 1, P.random(16))]);
    expect(late).toEqual({ s: "wrong_era", era: E });
    // Below E_FIRST: MISS(sealed = 1) without touching a shard.
    world.params.efirst = E;
    expect(await get([{ E: E - 1, label: P.random(16), mode: 0 }])).toEqual([{ s: "miss", sealed: true }]);
  });

  it("sealing: MISS(sealed) only once the era is sealed (sealDelayMs, sealPrevious)", async () => {
    const world = server();
    const E0 = world.era;
    const L = P.random(16);
    await put([putRow(E0, L)]);
    world.advanceEra();
    // Default: sealed at end(E) + SKEW.
    expect(await get([{ E: E0, label: P.random(16), mode: 1 }])).toEqual([{ s: "miss", sealed: true }]);

    world.sealDelayMs = 3_600_000;
    const E1 = world.era;
    await put([putRow(E1, L)]);
    world.advanceEra();
    expect(await get([{ E: E1, label: P.random(16), mode: 1 }])).toEqual([{ s: "miss", sealed: false }]);
    expect((await get([{ E: E1, label: L, mode: 1 }]))[0].s).toBe("hit");
    expect((await put([putRow(E1, P.random(16))]))[0]).toEqual({ s: "wrong_era", era: E1 + 1 });
    const info0 = await getJson(`/api/v2/era/${E1}`);
    expect(info0.j.sealed).toBe(false);
    expect(info0.res.headers.get("cache-control")).toBe("no-store");

    world.sealPrevious();
    expect(await get([{ E: E1, label: P.random(16), mode: 1 }])).toEqual([{ s: "miss", sealed: true }]);
    const info = await getJson(`/api/v2/era/${E1}`);
    expect(info.j).toMatchObject({ era: E1, start: P.eraStart(E1), end: P.eraEnd(E1), delta: 1, shards: 1, sealed: true });
    expect(info.j.kcommit).toBe(P.b64u(world.kcommitOf(E1)));
    expect(info.res.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
    expect((await fetch(`/api/v2/era/${world.era + 1}`)).status).toBe(404);
  });

  it("batches close lazily; the feed's roots and head chain recompute; t never falls into a closed batch", async () => {
    const world = server();
    const E = world.era;
    alignToSecond(world);
    await put([putRow(E, P.random(16)), putRow(E, P.random(16), { cls: 2 })]);
    world.advance(1000, { keepSockets: true });
    await put([putRow(E, P.random(16), { cls: 3 })]);
    world.advance(1000, { keepSockets: true });

    const res = await fetch(`/api/v2/feed/${E}/0`);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const page = W.decodeFeed(await bytesOf(res));
    expect(page.more).toBe(false);
    expect(page.batches.map((b) => b.n)).toEqual([2, 1]);
    let head: Uint8Array = P.ZERO32;
    for (const b of page.batches) {
      const root = P.mth(b.rows.map((r) => P.leafShard(E, r.label, b.t, r.cls, r.body)));
      expect(root).toEqual(b.root);
      head = P.nextHead(P.shardCid(E, 0), head, b.t, b.n, root);
      expect(head).toEqual(b.head);
    }
    const h = world.shard.head(E);
    expect(h.head).toEqual(head);
    expect(h.tLast).toBe(page.batches[1].t);
    const after = W.decodeFeed(await bytesOf(await fetch(`/api/v2/feed/${E}/0?after=${page.batches[0].t}`)));
    expect(after.batches.map((b) => b.t)).toEqual([page.batches[1].t]);

    // The clock steps back 3 s: the next row gets t = closed_t + Δ, not a t inside a closed batch.
    world.advance(-3000, { keepSockets: true });
    const [r] = await put([putRow(E, P.random(16))]);
    expect(r).toMatchObject({ s: "ok", t: page.batches[1].t + 1 });
  });

  it("Δ is pinned per era by its first write: a DELTA change applies from the next era on", async () => {
    const world = server();
    const E = world.era;
    alignToSecond(world);
    const [a] = await put([putRow(E, P.random(16))]);
    world.params.delta = 10;
    world.advance(1000, { keepSockets: true });
    const [b] = await put([putRow(E, P.random(16))]);
    if (a.s !== "ok" || b.s !== "ok") throw new Error("expected OK");
    expect(b.t - a.t).toBe(1);
    world.advanceEra();
    world.advance(1000, { keepSockets: true });
    const [c] = await put([putRow(world.era, P.random(16))]);
    if (c.s !== "ok") throw new Error("expected OK");
    expect(c.t % 10).toBe(0);
  });

  it("attacker controls: commit, hasLabel, hide (per client), retime, rewrite", async () => {
    const world = server();
    const E = world.era;
    const L = P.random(16);
    const body = junkBody(0);
    const row = world.shard.commit(E, L, 0, body);
    expect(row).not.toBeNull();
    expect(world.shard.commit(E, L, 0, junkBody(0))).toBeNull();
    expect(world.shard.hasLabel(E, L)).toBe(true);
    expect(world.shard.hasLabel(E, P.random(16))).toBe(false);

    world.shard.hide(E, L, "bob");
    expect((await get([{ E, label: L, mode: 0 }], "bob"))[0]).toEqual({ s: "miss", sealed: false });
    expect((await get([{ E, label: L, mode: 0 }], "alice"))[0]).toMatchObject({ s: "hit", body });
    // The per-client transport attributes requests the same way as the header.
    const bobFetch = world.fetchAs("bob");
    const res = await bobFetch("/api/v2/get", { method: "POST", body: W.encodeGetRequest([{ E, label: L, mode: 1 }]) as BodyInit });
    expect(W.decodeGetResponse(await bytesOf(res), [1])[0].s).toBe("miss");
    expect(world.requests[world.requests.length - 1].who).toBe("bob");
    world.shard.unhide(E, L, "bob");
    expect((await get([{ E, label: L, mode: 1 }], "bob"))[0].s).toBe("hit");

    const t0 = row!.t;
    world.shard.retime(E, L, t0 + 7);
    expect((await get([{ E, label: L, mode: 1 }]))[0]).toEqual({ s: "hit", t: t0 + 7, cls: 0 });
    const other = junkBody(1);
    world.shard.rewrite(E, L, { cls: 1, body: other });
    expect((await get([{ E, label: L, mode: 0 }]))[0]).toEqual({ s: "hit", t: t0 + 7, cls: 1, body: other });
    const [c] = await put([putRow(E, L)]);
    expect(c).toMatchObject({ s: "conflict", cls: 1, body: other });
  });

  it("hooks: fail before / after, beforePut, beforeRequest, aborts; request sizes are logged", async () => {
    const world = server();
    const E = world.era;
    const L1 = P.random(16);
    world.hooks.fail = (m, p) => (m === "POST" && p === "/api/v2/put" ? "after" : null);
    const body1 = W.encodePutRequest([putRow(E, L1)]);
    await expect(fetch("/api/v2/put", { method: "POST", body: body1 as BodyInit })).rejects.toThrow(TypeError);
    expect(world.shard.hasLabel(E, L1)).toBe(true);
    const lost = world.requests[world.requests.length - 1];
    expect(lost).toMatchObject({ status: 200, reqBytes: body1.length, resBytes: 1 + 1 + 4 + 64 });

    const L2 = P.random(16);
    world.hooks.fail = () => "before";
    await expect(fetch("/api/v2/put", { method: "POST", body: W.encodePutRequest([putRow(E, L2)]) as BodyInit })).rejects.toThrow(TypeError);
    expect(world.shard.hasLabel(E, L2)).toBe(false);
    expect(world.requests[world.requests.length - 1].status).toBe(0);
    world.hooks.fail = undefined;

    // beforePut may commit another row first: the request then meets a CONFLICT.
    const squat = junkBody(0);
    world.hooks.beforePut = (rows) => {
      world.shard.commit(rows[0].E, rows[0].label, 0, squat);
    };
    const [c] = await put([putRow(E, L2)]);
    expect(c).toMatchObject({ s: "conflict", body: squat });
    world.hooks.beforePut = undefined;

    // beforeRequest can hold a request; an abort rejects the fetch.
    let release!: () => void;
    world.hooks.beforeRequest = () => new Promise<void>((r) => (release = r));
    const ctl = new AbortController();
    const held = fetch("/api/v2/params", { signal: ctl.signal });
    await sleep(5);
    ctl.abort();
    await expect(held).rejects.toMatchObject({ name: "AbortError" });
    release();
    world.hooks.beforeRequest = undefined;
  });
});

// ───────────────────────── blobs ─────────────────────────

describe("blobs", () => {
  it("PUT is create-only with H = id; GET is public, immutable, with etag / 304; failGet", async () => {
    const world = server();
    const blob = P.random(1000);
    const id = P.b64u(P.H(blob));
    const r1 = await fetch(`/api/v2/blob/${id}`, { method: "PUT", body: blob as BodyInit });
    expect(r1.status).toBe(201);
    const j1 = (await r1.json()) as { id: string; size: number; t: number };
    expect(j1).toEqual({ id, size: 1000, t: P.tpub(world.now(), 1) });
    world.advance(5000);
    const r2 = await fetch(`/api/v2/blob/${id}`, { method: "PUT", body: blob as BodyInit });
    expect(await r2.json()).toEqual(j1);

    const other = P.random(100);
    expect((await fetch(`/api/v2/blob/${id.slice(0, -2)}AA`, { method: "PUT", body: other as BodyInit })).status).toBe(400);
    const tiny = P.random(40);
    expect((await fetch(`/api/v2/blob/${P.b64u(P.H(tiny))}`, { method: "PUT", body: tiny as BodyInit })).status).toBe(400);
    expect((await fetch("/api/v2/blob/not-an-id", { method: "PUT", body: tiny as BodyInit })).status).toBe(400);

    const g = await fetch(`/api/v2/blob/${id}`);
    expect(g.status).toBe(200);
    expect(await bytesOf(g)).toEqual(blob);
    expect(g.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
    expect(g.headers.get("etag")).toBe(`"${id}"`);
    const nm = await fetch(`/api/v2/blob/${id}`, { headers: { "if-none-match": `"${id}"` } });
    expect(nm.status).toBe(304);
    expect((await fetch(`/api/v2/blob/${P.b64u(P.random(32))}`)).status).toBe(404);

    world.blobs.failGet(id, 2);
    expect((await fetch(`/api/v2/blob/${id}`)).status).toBe(503);
    expect((await fetch(`/api/v2/blob/${id}`)).status).toBe(503);
    expect((await fetch(`/api/v2/blob/${id}`)).status).toBe(200);
  });

  it("meta: HIT {t, size}; MISS reports now and raises the high-water mark; missNow and forceT", async () => {
    const world = server();
    alignToSecond(world);
    const blob = P.random(500);
    const id = P.b64u(P.H(blob));
    const miss = await fetch(`/api/v2/blob/${id}/meta`);
    expect(miss.status).toBe(404);
    const mj = (await miss.json()) as { error: string; now: number };
    expect(mj.error).toBe("unregistered");
    expect(mj.now).toBe(P.secOf(world.now()));
    expect(world.blobreg.hw).toBe(mj.now);

    // The BlobReg clock steps back 5 s: a later registration still gets t ≥ every now ever reported.
    world.advance(-5000);
    const put1 = (await (await fetch(`/api/v2/blob/${id}`, { method: "PUT", body: blob as BodyInit })).json()) as { t: number };
    expect(put1.t).toBe(mj.now);
    expect(put1.t).toBeGreaterThan(P.tpub(world.now(), 1));
    expect(await (await fetch(`/api/v2/blob/${id}/meta`)).json()).toEqual({ t: put1.t, size: 500 });

    world.blobreg.missNow((_id, now) => now - 30);
    const m2 = (await (await fetch(`/api/v2/blob/${P.b64u(P.random(32))}/meta`)).json()) as { now: number };
    expect(m2.now).toBe(P.secOf(world.now()) - 30);
    world.blobreg.missNow(null);

    world.blobreg.forceT(id, put1.t + 100);
    expect(await (await fetch(`/api/v2/blob/${id}/meta`)).json()).toEqual({ t: put1.t + 100, size: 500 });
  });
});

// ───────────────────────── inbox ─────────────────────────

describe("inbox", () => {
  it("rel = ⌊ms/1000⌋ + 1: a row is invisible until its slot closes", async () => {
    const world = server();
    const E = world.era;
    alignToSecond(world);
    const slot = Math.floor((world.now() - P.T0_MS) / 1000);
    const inv = invite();
    const res = await inboxPost(E, [inv]);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ results: [{ rel: slot + 1 }] });

    const a = await inboxRead(E);
    expect(a.res.headers.get("cache-control")).toBe("public, max-age=1");
    expect(a.r).toEqual({ closed: slot, more: false, rows: [] });
    expect(world.inbox.pending(E)).toBe(1);

    world.advance(1000, { keepSockets: true });
    const b = await inboxRead(E);
    expect(b.r!.closed).toBe(slot + 1);
    expect(b.r!.rows).toEqual([{ rel: slot + 1, eid: inv.eid, body: inv.body }]);
    expect(world.inbox.pending(E)).toBe(0);
    expect((await inboxRead(E, slot + 1)).r!.rows).toEqual([]);
  });

  it("closed_hw: after a read reported closed = c, a clock step back still gives new rows rel > c", async () => {
    const world = server();
    const E = world.era;
    alignToSecond(world);
    const c = (await inboxRead(E)).r!.closed;
    world.advance(-5000, { keepSockets: true });
    const res = (await (await inboxPost(E, [invite()])).json()) as { results: { rel: number }[] };
    expect(res.results[0].rel).toBe(c + 1);
    const r = (await inboxRead(E)).r!;
    expect(r.closed).toBe(c);
    expect(r.rows).toEqual([]);
    world.advance(6000, { keepSockets: true });
    expect((await inboxRead(E)).r!.rows.map((x) => x.rel)).toEqual([c + 1]);
  });

  it("batched posts: one result per row, the day cap turns rows past it into full, idempotent retries, rollDay", async () => {
    const world = server();
    const E = world.era;
    world.inbox.dayCap = 5;
    const rows = Array.from({ length: 32 }, invite);
    const res = (await (await inboxPost(E, rows)).json()) as { results: W.InboxPostResult[] };
    expect(res.results).toHaveLength(32);
    expect(res.results.slice(0, 5).every((x) => "rel" in x)).toBe(true);
    expect(res.results.slice(5).every((x) => "error" in x && x.error === "full")).toBe(true);
    expect(W.parseInboxPostResults(res, 32)).toHaveLength(32);

    const again = (await (await inboxPost(E, [rows[0], { eid: rows[1].eid, body: P.random(P.INBOX_BODY_LEN) }])).json()) as {
      results: W.InboxPostResult[];
    };
    expect(again.results).toEqual([res.results[0], { error: "conflict" }]);

    world.inbox.rollDay();
    const later = (await (await inboxPost(E, [rows[5]])).json()) as { results: W.InboxPostResult[] };
    expect("rel" in later.results[0]).toBe(true);

    expect((await fetch("/api/v2/inbox", { method: "POST", body: P.random(10) as BodyInit })).status).toBe(400);
    const bad = W.encodeInboxPost({ E, bucket: 0, rows: [invite()] });
    bad[5] = 1; // bucket 1
    expect((await fetch("/api/v2/inbox", { method: "POST", body: bad as BodyInit })).status).toBe(400);
  });

  it("reads return whole rel groups and page with more", async () => {
    const world = server();
    const E = world.era;
    alignToSecond(world);
    await inboxPost(E, Array.from({ length: 5 }, invite));
    world.advance(1000, { keepSockets: true });
    await inboxPost(E, [invite()]);
    world.advance(1000, { keepSockets: true });
    const p1 = (await inboxRead(E, 0, 2)).r!;
    expect(p1.rows).toHaveLength(5);
    expect(p1.more).toBe(true);
    const rel1 = p1.rows[0].rel;
    const sorted = [...p1.rows].sort((a, b) => P.byteCmp(a.eid, b.eid));
    expect(p1.rows).toEqual(sorted);
    const p2 = (await inboxRead(E, rel1, 2)).r!;
    expect(p2.rows.map((r) => r.rel)).toEqual([rel1 + 1]);
    expect(p2.more).toBe(false);
  });

  it("after the era ended, closed = max(max rel, closed_hw): never below a closed already reported", async () => {
    const world = server();
    world.advanceEra();
    const E = world.era;
    const posted = (await (await inboxPost(E, [invite()])).json()) as { results: { rel: number }[] };
    const rel = posted.results[0].rel;
    // A read near the end of the era reports a closed far above rel and persists it as closed_hw.
    world.advance(P.eraEnd(E) - 1000 - world.now(), { keepSockets: true });
    const late = (await inboxRead(E, rel)).r!;
    expect(late.closed).toBeGreaterThan(rel + 1000);
    world.advanceEra();
    const ended = await inboxRead(E, late.closed);
    expect(ended.res.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
    expect(ended.r).toEqual({ closed: late.closed, more: false, rows: [] });
    expect((await inboxRead(E)).r!.rows.map((r) => r.rel)).toEqual([rel]);
  });

  it("Δin is pinned per era by its first write: raising INBOX_SLOT mid-era does not freeze closed", async () => {
    const world = server();
    const E = world.era;
    alignToSecond(world);
    const c = (await inboxRead(E)).r!.closed; // the era's first write (closed_hw) pins Δin = 1 s
    world.params.inboxSlot = 3;
    const res = (await (await inboxPost(E, [invite()])).json()) as { results: { rel: number }[] };
    expect(res.results[0].rel).toBe(c + 1);
    world.advance(1000, { keepSockets: true });
    const r = await inboxRead(E, c);
    expect(r.r!.closed).toBe(c + 1);
    expect(r.r!.rows.map((x) => x.rel)).toEqual([c + 1]);
    expect(r.res.headers.get("cache-control")).toBe("public, max-age=3"); // the Worker's max-age is the deployment's Δin

    // The next era pins the new Δin on its first write.
    world.advanceEra();
    world.advance(3000 - ((world.now() - P.T0_MS) % 3000) + 20, { keepSockets: true });
    const E2 = world.era;
    const expected = Math.floor((world.now() - P.T0_MS) / 3000);
    expect((await inboxRead(E2)).r!.closed).toBe(expected);
    world.params.inboxSlot = 1;
    expect(world.inbox.closedNow(E2)).toBe(expected);
  });

  it("posts in the SKEW window before start(E) count against the era's first day", async () => {
    const world = new FakeWorld({ skew: 2 });
    const post = async (E: number, rows: W.InboxPostRow[]) => {
      const res = await world.fetch("/api/v2/inbox", { method: "POST", body: W.encodeInboxPost({ E, bucket: 0, rows }) as BodyInit });
      expect(res.status).toBe(200);
      return ((await res.json()) as { results: W.InboxPostResult[] }).results;
    };
    world.inbox.dayCap = 3;
    const E = world.era + 1;
    world.advance(P.eraStart(E) - 1000 - world.now(), { keepSockets: true });
    expect((await post(E, [invite(), invite(), invite()])).every((x) => "rel" in x)).toBe(true);
    world.advance(2000, { keepSockets: true });
    expect(world.era).toBe(E);
    expect(await post(E, [invite()])).toEqual([{ error: "full" }]);
    world.advance(86_400_000, { keepSockets: true });
    expect("rel" in (await post(E, [invite()]))[0]).toBe(true);
  });

  it("era rules: wrong era 409, ended eras immutable, 410 below E_now − 3, 400 above", async () => {
    const world = server();
    const E0 = world.era;
    const posted = (await (await inboxPost(E0, [invite(), invite()])).json()) as { results: { rel: number }[] };
    world.advanceEra();
    const ended = await inboxRead(E0);
    expect(ended.r!.closed).toBe(posted.results[0].rel);
    expect(ended.r!.rows).toHaveLength(2);
    expect(ended.res.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");

    const wrong = await inboxPost(E0, [invite()]);
    expect(wrong.status).toBe(409);
    expect(await wrong.json()).toEqual({ error: "wrong era", era: E0 + 1 });

    expect((await inboxRead(world.era + 1)).res.status).toBe(400);
    world.advanceEra(3);
    expect((await inboxRead(E0)).res.status).toBe(410);
    expect((await inboxRead(E0 + 1)).res.status).toBe(200);

    // An attacker post ignores the era window.
    expect(world.inbox.post(E0, [invite()], { rel: 5 })).toEqual([{ rel: 5 }]);
  });
});

// ───────────────────────── realtime ─────────────────────────

describe("realtime", () => {
  it("HELLO with seq, SUB-filtered ROWS, RESUME by seq, GAP after restart()", async () => {
    const world = server();
    const E = world.era;
    const T1 = P.random(16);
    const T2 = P.random(16);
    const a = openRt("alice");
    const b = openRt("bob");
    const ha = await hello(a);
    await hello(b);
    expect(ha.seq).toBe(0);
    expect(Math.abs(ha.now - world.now())).toBeLessThan(1000);
    a.send({ f: "sub", topics: [T1] });
    b.send({ f: "sub", topics: [T2] });
    await sleep(5);

    // Two rows in the same put (same millisecond) for T1, one for T2, one without a topic.
    await put([putRow(E, P.random(16), { topic: T1 }), putRow(E, P.random(16), { topic: T1 }), putRow(E, P.random(16), { topic: T2 }), putRow(E, P.random(16))]);
    await waitFor(() => a.rows().length === 2 && b.rows().length === 1, "ROWS");
    expect(a.rows().map((r) => r.seq)).toEqual([1, 2]);
    expect(a.rows().every((r) => P.equalBytes(r.topic, T1))).toBe(true);
    expect(b.rows()[0].seq).toBe(3);
    expect(world.rt.seq).toBe(3);
    expect(a.frames.filter((f) => typeof f !== "string" && f.f === "rows")).toHaveLength(1);

    // Alice disconnects; two more T1 rows are published; she reconnects and RESUMEs from seq 1.
    a.ws.close();
    await waitFor(() => a.state.closed !== null, "close");
    await put([putRow(E, P.random(16), { topic: T1 })]);
    await put([putRow(E, P.random(16), { topic: T1 })]);
    const a2 = openRt("alice");
    const h2 = await hello(a2);
    expect(h2.seq).toBe(5);
    a2.send({ f: "resume", boot: ha.boot, since: 1, topics: [T1] });
    await waitFor(() => a2.kinds().includes("resumed"), "RESUMED");
    expect(a2.rows().map((r) => r.seq)).toEqual([2, 4, 5]);
    expect(a2.kinds()).toEqual(["hello", "rows", "resumed"]);

    // A restart loses the ring: RESUME gets GAP, but its topics are installed.
    world.rt.restart();
    await waitFor(() => a2.state.closed === 1012 && b.state.closed === 1012, "restart close");
    const a3 = openRt("alice");
    const h3 = await hello(a3);
    expect(h3.seq).toBe(0);
    expect(P.equalBytes(h3.boot, ha.boot)).toBe(false);
    a3.send({ f: "resume", boot: ha.boot, since: 5, topics: [T1] });
    await waitFor(() => a3.frames.length >= 2, "GAP");
    expect(a3.frames[1]).toEqual({ f: "gap", since: 5 });
    await put([putRow(E, P.random(16), { topic: T1 })]);
    await waitFor(() => a3.rows().length === 1, "row after GAP");
    // A stale `since` older than the ring also gets GAP.
    world.rt.limits.ringRows = 1;
    await put([putRow(E, P.random(16), { topic: T1 })]);
    const a4 = openRt("alice");
    const h4 = await hello(a4);
    a4.send({ f: "resume", boot: h4.boot, since: 0, topics: [T1] });
    await waitFor(() => a4.frames.length >= 2, "GAP");
    expect(a4.frames[1]).toEqual({ f: "gap", since: 0 });
  });

  it("protocol errors close with 1008; ping; hidden rows; wsEnabled; dropPublish; clock jumps close sockets", async () => {
    const world = server();
    const E = world.era;
    const T = P.random(16);
    const a = openRt("alice");
    await hello(a);
    a.ws.send("ping");
    await waitFor(() => a.frames.includes("pong"), "pong");
    a.send({ f: "sub", topics: [T] });
    a.send({ f: "resume", boot: P.random(8), since: 0, topics: [] });
    await waitFor(() => a.state.closed !== null, "close");
    expect(a.state.closed).toBe(1008);

    const t = openRt(null);
    await hello(t);
    t.ws.send("hello");
    await waitFor(() => t.state.closed === 1008, "close on text");
    const big = openRt(null);
    await hello(big);
    big.ws.send(new Uint8Array(8193));
    await waitFor(() => big.state.closed === 1008, "close on a large frame");
    const many = openRt(null);
    await hello(many);
    many.send({ f: "sub", topics: Array.from({ length: 200 }, () => P.random(16)) });
    many.send({ f: "sub", topics: Array.from({ length: 57 }, () => P.random(16)) });
    await waitFor(() => many.state.closed === 1008, "close on 257 topics");

    // A row hidden from bob is not delivered to bob's sockets.
    const b = openRt("bob");
    const c = openRt("carol");
    await hello(b);
    await hello(c);
    b.send({ f: "sub", topics: [T] });
    c.send({ f: "sub", topics: [T] });
    await sleep(5);
    const L = P.random(16);
    world.shard.hide(E, L, "bob");
    await put([putRow(E, L, { topic: T })]);
    await waitFor(() => c.rows().length === 1, "carol's row");
    await sleep(10);
    expect(b.rows()).toHaveLength(0);

    // dropPublish loses matching rows (not in the ring either).
    world.rt.dropPublish((r) => r.cls === 1);
    await put([putRow(E, P.random(16), { topic: T, cls: 1 }), putRow(E, P.random(16), { topic: T })]);
    await waitFor(() => c.rows().length === 2, "the undropped row");
    expect(c.rows()[1].cls).toBe(0);
    expect(world.rt.stats.dropped).toBe(1);
    world.rt.dropPublish(null);

    // wsEnabled = false: new sockets fail; publishes are lost.
    world.wsEnabled = false;
    const d = openRt("dave");
    await waitFor(() => d.state.closed !== null, "refused socket");
    expect(d.state.closed).toBe(1006);
    expect(d.ws.upgradeStatus).toBe(503);
    await put([putRow(E, P.random(16), { topic: T })]);
    await sleep(10);
    expect(c.rows()).toHaveLength(2);
    world.wsEnabled = true;

    // Clock jumps close every socket, so engines reconnect and see a fresh HELLO.
    world.advanceEra();
    await waitFor(() => c.state.closed === 1001 && b.state.closed === 1001, "close on advanceEra");
    const e = openRt("carol");
    const h = await hello(e);
    expect(h.now).toBeGreaterThanOrEqual(P.eraStart(world.era));
    expect(world.requests.filter((r) => r.path === "/api/v2/rt").length).toBeGreaterThanOrEqual(8);
  });

  it("refuses a ninth socket of one client (429); the plain WebSocket global connects anonymously", async () => {
    const world = server();
    const socks = Array.from({ length: 9 }, () => openRt("alice"));
    await waitFor(() => socks.every((s) => s.frames.length > 0 || s.state.closed !== null), "upgrades");
    expect(socks.filter((s) => s.state.closed === 1006)).toHaveLength(1);
    expect(socks.map((s) => s.ws.upgradeStatus).sort()).toEqual([...Array(8).fill(101), 429].sort());

    const g = new WebSocket("ws://segv.test/api/v2/rt") as unknown as FakeWebSocket;
    expect(g).toBeInstanceOf(FakeWebSocket);
    await waitFor(() => g.readyState === FakeWebSocket.OPEN, "global socket");
    expect(g.who).toBeNull();
    expect(world.rt.sockets.has(g)).toBe(true);
  });

  it("RESUME gets GAP for a since above the last seq and for a replay over replayBytes; the ring counts encoded rows", async () => {
    const world = server();
    const E = world.era;
    const T = P.random(16);
    expect(RT_LIMITS.replayBytes).toBe(2 * 1024 * 1024);
    await put([putRow(E, P.random(16), { topic: T })]);

    // A since above the last assigned seq with the current boot (e.g. a seq kept from another boot): GAP.
    const a = openRt("alice");
    const h = await hello(a);
    expect(h.seq).toBe(1);
    a.send({ f: "resume", boot: h.boot, since: h.seq + 500, topics: [T] });
    await waitFor(() => a.frames.length >= 2, "GAP");
    expect(a.frames[1]).toEqual({ f: "gap", since: h.seq + 500 });

    // A replay above replayBytes (rows as encoded in ROWS frames: 47 B + body) gets GAP; at the budget it replays.
    const size = 47 + P.BODY_LENS[0];
    world.rt.limits.replayBytes = 2 * size;
    await put([putRow(E, P.random(16), { topic: T }), putRow(E, P.random(16), { topic: T })]);
    const b = openRt("alice");
    const hb = await hello(b);
    b.send({ f: "resume", boot: hb.boot, since: 1, topics: [T] });
    await waitFor(() => b.kinds().includes("resumed"), "RESUMED");
    expect(b.rows().map((r) => r.seq)).toEqual([2, 3]);
    const c = openRt("alice");
    const hc = await hello(c);
    c.send({ f: "resume", boot: hc.boot, since: 0, topics: [T] });
    await waitFor(() => c.frames.length >= 2, "GAP");
    expect(c.kinds()).toEqual(["hello", "gap"]);
    expect(c.frames[1]).toEqual({ f: "gap", since: 0 });

    // The ring's byte budget counts encoded rows as well.
    world.rt.limits.ringBytes = 2 * size - 1;
    await put([putRow(E, P.random(16), { topic: T })]);
    expect(world.rt.ring.map((r) => r.seq)).toEqual([4]);
  });

  it("RESUME topics do not count toward the 2048 topic changes per minute", async () => {
    const world = server();
    world.advance(60_000 - (world.now() % 60_000) + 50); // the start of a minute (no socket is open yet)
    const topics = Array.from({ length: 256 }, () => P.random(16));
    const a = openRt("alice");
    const h = await hello(a);
    a.send({ f: "resume", boot: h.boot, since: h.seq, topics });
    for (let i = 0; i < 7; i++) a.send({ f: i % 2 === 0 ? "unsub" : "sub", topics });
    a.send({ f: "sub", topics: [topics[0]] }); // 7 · 256 + 1 = 1793 changes
    a.send({ f: "sub", topics: topics.slice(1) }); // 2048: the limit, still allowed
    await sleep(30);
    expect(a.state.closed).toBeNull();
    expect(a.ws.topics.size).toBe(256);
    a.send({ f: "unsub", topics: [topics[0]] }); // 2049
    await waitFor(() => a.state.closed !== null, "close");
    expect(a.state.closed).toBe(1008);
  });

  it("max age: 4000 on a client frame past 1 h; the hour sweep on upgrades and publishes closes quiet sockets", async () => {
    const world = server();
    const T = P.random(16);
    // The exact age is checked on every binary client frame.
    const a = openRt("alice");
    await hello(a);
    world.advance(RT_LIMITS.maxAgeMs + 1000, { keepSockets: true });
    a.send({ f: "sub", topics: [T] });
    await waitFor(() => a.state.closed !== null, "close on a frame");
    expect(a.state.closed).toBe(4000);

    // An upgrade sweeps sockets accepted before the previous hour, so 8 quiet old sockets no longer count toward the cap.
    const old = Array.from({ length: 8 }, () => openRt("bob"));
    await waitFor(() => old.every((s) => s.frames.length > 0), "HELLOs");
    world.advance(2 * 3_600_000, { keepSockets: true });
    const fresh = openRt("bob");
    await hello(fresh);
    expect(fresh.ws.upgradeStatus).toBe(101);
    await waitFor(() => old.every((s) => s.state.closed === 4000), "swept on upgrade");

    // A publish sweeps too, also sockets that get none of its rows.
    const c = openRt("carol");
    await hello(c);
    c.send({ f: "sub", topics: [T] });
    await sleep(5);
    world.advance(2 * 3_600_000, { keepSockets: true });
    await put([putRow(world.era, P.random(16), { topic: P.random(16) })]);
    await waitFor(() => c.state.closed !== null && fresh.state.closed !== null, "swept on publish");
    expect([c.state.closed, fresh.state.closed]).toEqual([4000, 4000]);
  });
});

// ───────────────────────── rate limits ─────────────────────────

describe("rate limits", () => {
  it("are off by default; rateLimits(true) answers 429 with retry-after per client (RL_INBOX 10 / 60 s)", async () => {
    const world = server();
    const E = world.era;
    for (let i = 0; i < 12; i++) expect((await inboxPost(E, [invite()], "alice")).status).toBe(200);

    world.rateLimits(true);
    for (let i = 0; i < 10; i++) expect((await inboxPost(E, [invite()], "alice")).status).toBe(200);
    const limited = await inboxPost(E, [invite()], "alice");
    expect(limited.status).toBe(429);
    const retry = Number(limited.headers.get("retry-after"));
    expect(retry).toBeGreaterThanOrEqual(59);
    expect(retry).toBeLessThanOrEqual(60);
    expect(nowHeader(limited)).toBeGreaterThan(0);
    // Another client, another route class, and params are not affected.
    expect((await inboxPost(E, [invite()], "bob")).status).toBe(200);
    expect((await fetch("/api/v2/get", { method: "POST", body: W.encodeGetRequest([{ E, label: P.random(16), mode: 1 }]) as BodyInit, headers: whoHeader("alice") })).status).toBe(200);
    for (let i = 0; i < 20; i++) expect((await fetch("/api/v2/params", { headers: whoHeader("alice") })).status).toBe(200);

    world.advance(60_000, { keepSockets: true });
    expect((await inboxPost(E, [invite()], "alice")).status).toBe(200);

    world.rateLimits({ RL_READ: { limit: 2 } });
    await fetch("/api/v2/dirlog");
    await fetch("/api/v2/dirlog");
    expect((await fetch("/api/v2/dirlog")).status).toBe(429);
    world.rateLimits(false);
    expect((await fetch("/api/v2/dirlog")).status).toBe(200);
  });
});

// ───────────────────────── Worker order and response cache ─────────────────────────

describe("Worker order and response cache", () => {
  it("validates the path and query before the rate limiter on inbox reads, feed, blob routes, /ckpt/{q} and /era/{E}", async () => {
    const world = server();
    const E = world.era;
    world.rateLimits({ RL_READ: { limit: 0 }, RL_BLOB: { limit: 0 } });
    const id = P.b64u(P.random(32));
    const cases: [string, RequestInit | undefined, number][] = [
      [`/api/v2/inbox/${E}/1`, undefined, 400],
      [`/api/v2/inbox/${E - 5}/1`, undefined, 400], // the bucket is checked before the 410
      [`/api/v2/inbox/${E - 5}/0`, undefined, 410],
      [`/api/v2/inbox/${E + 1}/0`, undefined, 400],
      [`/api/v2/inbox/${E}/0?after=x`, undefined, 400],
      [`/api/v2/feed/${E}/1`, undefined, 404],
      [`/api/v2/feed/${E}/0?after=-1`, undefined, 400],
      ["/api/v2/blob/not-an-id", undefined, 400],
      ["/api/v2/blob/not-an-id/meta", undefined, 400],
      ["/api/v2/blob/not-an-id", { method: "PUT", body: P.random(100) as BodyInit }, 400],
      ["/api/v2/ckpt/0", undefined, 404],
      ["/api/v2/ckpt/01", undefined, 400],
      ["/api/v2/ckpt/4294967296", undefined, 400],
      ["/api/v2/era/65535", undefined, 400],
      [`/api/v2/feed/${E}/70000`, undefined, 400],
    ];
    for (const [path, init, status] of cases) expect((await fetch(path, init)).status, path).toBe(status);
    // Past the checks the limiter answers.
    for (const path of [`/api/v2/inbox/${E}/0`, `/api/v2/feed/${E}/0`, `/api/v2/blob/${id}`, `/api/v2/blob/${id}/meta`, "/api/v2/ckpt/1", `/api/v2/era/${E}`]) {
      expect((await fetch(path)).status, path).toBe(429);
    }
    expect((await fetch(`/api/v2/blob/${id}`, { method: "PUT", body: P.random(100) as BodyInit })).status).toBe(429);
    // Query integers parse as the Worker's intParam does (leading zeros allowed).
    world.rateLimits(false);
    expect((await fetch(`/api/v2/inbox/${E}/0?after=007`)).status).toBe(200);
  });

  it("cache(true): the inbox tail is served from the cache for max-age = Δin of world clock, keyed by (E, bucket, after, limit)", async () => {
    const world = server();
    const E = world.era;
    world.cache(true);
    alignToSecond(world);
    world.advance(780, { keepSockets: true }); // ~0.8 s into slot s
    const s = Math.floor((world.now() - P.T0_MS) / 1000);
    const inv = invite();
    expect(await (await inboxPost(E, [inv])).json()).toEqual({ results: [{ rel: s + 1 }] });
    expect((await inboxRead(E)).r).toEqual({ closed: s, more: false, rows: [] });

    // Slot s + 1 has closed, but a poll with the same key within Δin gets the cached response (§10.5).
    world.advance(400, { keepSockets: true });
    expect(world.inbox.closedNow(E)).toBe(s + 1);
    const n = world.requests.length;
    const b = await fetch(`/api/v2/inbox/${E}/0?limit=1024&after=0&junk=1`);
    expect(world.requests[n].cached).toBe(true);
    expect(W.decodeInboxRead(await bytesOf(b))).toEqual({ closed: s, more: false, rows: [] });
    expect(b.headers.get("cache-control")).toBe("public, max-age=1");
    expect(Math.abs(nowHeader(b) - world.now())).toBeLessThan(1000); // x-segv-now is stamped after the lookup
    // Another key is read fresh.
    expect((await inboxRead(E, 0, 10)).r!.rows.map((r) => r.rel)).toEqual([s + 1]);

    // Once max-age (1 s) has passed on the world clock the entry is stale.
    world.advance(700, { keepSockets: true });
    const c = await inboxRead(E);
    expect(world.requests[world.requests.length - 1].cached).toBeUndefined();
    expect(c.r!.rows).toEqual([{ rel: s + 1, eid: inv.eid, body: inv.body }]);
    world.cache(false);
    await inboxRead(E);
    expect(world.requests[world.requests.length - 1].cached).toBeUndefined();
  });

  it("cache hits skip the rate limiter: blob GETs (with If-None-Match), /ckpt/{q} and immutable feed pages", async () => {
    const world = server();
    const E0 = world.era;
    world.cache(true);
    const { id } = world.putBlob(P.random(500));
    world.ckpt.tick();
    const label = P.random(16);
    await put([putRow(E0, label)]);
    world.advanceEra(); // era E0 seals, so its feed page is immutable
    world.rateLimits({ RL_READ: { limit: 3 } });
    for (const path of [`/api/v2/blob/${id}`, "/api/v2/ckpt/1", `/api/v2/feed/${E0}/0`]) expect((await fetch(path)).status, path).toBe(200);
    const page = await bytesOf(await fetch(`/api/v2/feed/${E0}/0`));
    // Every further read of those keys is a cache hit, which the limiter does not count.
    for (let i = 0; i < 5; i++) {
      for (const path of [`/api/v2/blob/${id}`, "/api/v2/ckpt/1", `/api/v2/feed/${E0}/0?after=0`]) {
        expect((await fetch(path)).status, path).toBe(200);
        expect(world.requests[world.requests.length - 1].cached, path).toBe(true);
      }
    }
    const nm = await fetch(`/api/v2/blob/${id}`, { headers: { "if-none-match": `"${id}"` } });
    expect(nm.status).toBe(304);
    expect(nm.headers.get("etag")).toBe(`"${id}"`);
    expect((await fetch(`/api/v2/feed/${world.era}/0`)).status).toBe(429); // uncached reads still count
    world.rateLimits(false);

    // A cached page survives a rewrite at the origin, as an edge cache would; a no-store page is never cached.
    world.shard.rewrite(E0, label, { body: junkBody() });
    expect(await bytesOf(await fetch(`/api/v2/feed/${E0}/0`))).toEqual(page);
    for (let i = 0; i < 2; i++) {
      const res = await fetch(`/api/v2/feed/${world.era}/0`);
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(world.requests[world.requests.length - 1].cached).toBeUndefined();
    }
  });
});

// ───────────────────────── directory ─────────────────────────

describe("directory", () => {
  it("register and look up: uid, handle prefix, wraps, conflicts and validation", async () => {
    const world = server();
    const u = newTestUser("alice");
    const body = registrationOf(u);
    const r = await postJson("/api/v2/register", body);
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ dirseq: 1 });

    const { j: byUid } = await getJson(`/api/v2/dir/uid/${u.uidB}`);
    const user = P.verifyBundle(byUid.user.bundle, byUid.user.sig);
    expect(user).toMatchObject({ uid: u.uidB, handle: "alice" });
    expect(user.sigPk).toEqual(u.id.sigPk);
    expect(byUid.user).toMatchObject({ uid: u.uidB, handle: "alice", regEra: world.era, dirseq: 1 });
    expect((await fetch(`/api/v2/dir/uid/${P.b64u(P.random(16))}`)).status).toBe(404);
    expect((await fetch("/api/v2/dir/uid/xyz")).status).toBe(400);

    // Handle prefixes: P = 0 with one user, so p ≤ 1 is accepted.
    const top = Math.floor(P.hpre("alice") / 2 ** 31);
    const p0 = await getJson("/api/v2/dir/h/0/0");
    expect(p0.j).toMatchObject({ p: 0, more: false });
    expect(p0.j.users.map((x: { uid: string }) => x.uid)).toEqual([u.uidB]);
    expect((await getJson(`/api/v2/dir/h/1/${top}`)).j.users).toHaveLength(1);
    expect((await getJson(`/api/v2/dir/h/1/${1 - top}`)).j.users).toHaveLength(0);
    const utop = Math.floor(P.upre(u.uid) / 2 ** 31);
    expect((await getJson(`/api/v2/dir/u/1/${utop}`)).j.users).toHaveLength(1);
    const tooMany = await getJson("/api/v2/dir/h/2/0");
    expect(tooMany.res.status).toBe(409);
    expect(tooMany.j.p).toBe(0);
    expect((await fetch("/api/v2/dir/h/1/2")).status).toBe(400);
    expect((await getJson(`/api/v2/dir/h/0/0?after=${u.uidB}`)).j.users).toHaveLength(0);

    const { j: wr } = await getJson(`/api/v2/dir/wraps/${P.b64u(u.rk.id)}`);
    expect(wr.wraps).toHaveLength(1);
    expect(P.verifyWrap(wr.wraps[0].record, wr.wraps[0].sig, u.id.sigPk).kind).toBe("recovery");
    expect((await getJson(`/api/v2/dir/wraps/${P.b64u(u.rk.id)}?uid=${P.b64u(P.random(16))}`)).j.wraps).toEqual([]);
    expect((await getJson(`/api/v2/dir/wraps/${P.b64u(P.random(20))}`)).j.wraps).toEqual([]);

    // Conflicts: the same handle with other keys, the same uid with another handle.
    expect((await postJson("/api/v2/register", registrationOf(newTestUser("alice")))).status).toBe(409);
    const sameUid = { ...newTestUser("alice2"), uid: u.uid, uidB: u.uidB };
    expect((await postJson("/api/v2/register", registrationOf(sameUid))).status).toBe(409);

    // Validation: a bad signature, non-canonical JSON, a wrap of another uid, extra keys.
    const v = newTestUser("victor");
    const vb = registrationOf(v);
    const badSig = { ...vb, sig: registrationOf(newTestUser("victor")).sig };
    expect((await postJson("/api/v2/register", badSig)).status).toBe(400);
    const spaced = { ...vb, bundle: vb.bundle.replace(",", ", ") };
    expect((await postJson("/api/v2/register", spaced)).status).toBe(400);
    const foreign = { ...vb, wraps: registrationOf(newTestUser("mallory")).wraps };
    expect((await postJson("/api/v2/register", foreign)).status).toBe(400);
    expect((await postJson("/api/v2/register", { ...vb, extra: 1 })).status).toBe(400);
    expect((await postJson("/api/v2/register", vb)).status).toBe(200);

    // POST /api/v2/wraps: another wrap for alice; duplicates 409; unknown uids 404; bad signatures 400.
    const credId = P.random(32);
    const pk = P.credKem(P.random(32), credId);
    const wrap = P.makeWrap(u.uid, "passkey", credId, pk, u.AK, u.id, Date.now());
    const w1 = await postJson("/api/v2/wraps", wrap);
    expect(w1.status).toBe(200);
    expect(await w1.json()).toEqual({ dirseq: 5 });
    expect((await postJson("/api/v2/wraps", wrap)).status).toBe(409);
    const stranger = newTestUser("nobody");
    expect((await postJson("/api/v2/wraps", P.makeWrap(stranger.uid, "passkey", credId, pk, stranger.AK, stranger.id, 1))).status).toBe(404);
    const forged = P.makeWrap(u.uid, "passkey", P.random(32), pk, u.AK, v.id, 1);
    expect((await postJson("/api/v2/wraps", forged)).status).toBe(400);
    // Anyone may file a record under someone else's id with their own uid (ids are public).
    expect(world.dir.postWrap(P.makeWrap(v.uid, "recovery", u.rk.id, v.rk, v.AK, v.id, 1)).status).toBe(200);
    expect((await getJson(`/api/v2/dir/wraps/${P.b64u(u.rk.id)}`)).j.wraps.map((x: { uid: string }) => x.uid)).toEqual([u.uidB, v.uidB]);
  });

  it("the dirlog chain recomputes with dirlogH; p grows with the users", async () => {
    const world = server();
    const users = Array.from({ length: 64 }, (_, i) => makeUser(`user_${i}`));
    expect(world.dir.P).toBe(1);
    expect((await getJson("/api/v2/params")).j.p).toBe(1);
    expect((await fetch("/api/v2/dir/h/2/3")).status).toBe(200);
    expect((await fetch("/api/v2/dir/h/3/3")).status).toBe(409);

    const { j } = await getJson("/api/v2/dirlog?after=0&limit=1000");
    expect(j.entries).toHaveLength(128);
    expect(j.head.seq).toBe(128);
    let h: Uint8Array = P.ZERO32;
    for (const e of j.entries as { seq: number; kind: number; ref: string; h: string }[]) {
      h = P.dirlogH(h, e.seq, e.kind, P.fromB64u(e.ref));
      expect(P.b64u(h)).toBe(e.h);
    }
    expect(P.b64u(h)).toBe(j.head.h);
    const u0 = world.dir.byUid(users[0].uidB)!;
    expect(j.entries[0]).toMatchObject({ seq: 1, kind: P.DIRLOG_USER, ref: P.b64u(P.dirlogRefUser(u0.bundle, P.fromB64u(u0.sig))) });
    expect(j.entries[1].kind).toBe(P.DIRLOG_WRAP);
    const page = (await getJson("/api/v2/dirlog?after=120&limit=5")).j;
    expect(page.entries.map((e: { seq: number }) => e.seq)).toEqual([121, 122, 123, 124, 125]);
    expect((await fetch("/api/v2/dirlog?limit=0")).status).toBe(400);
  });
});

// ───────────────────────── checkpoints ─────────────────────────

describe("checkpoints", () => {
  it("tick() signs C_q over the fake heads; the range recomputes to latest.C; forkAt rewrites the chain", async () => {
    const world = server();
    const E = world.era;
    const srvKey = P.fromB64u((await getJson("/api/v2/params")).j.srvKey);
    expect((await fetch("/api/v2/ckpt/latest")).status).toBe(404);

    const verifyEntry = (j: Record<string, any>, prevC: Uint8Array) => {
      const heads = (j.heads as { cid: string; head: string }[]).map((x) => ({ cid: x.cid, head: P.fromB64u(x.head) }));
      const hd = P.ckptHd(heads);
      expect(P.b64u(hd)).toBe(j.hd);
      const C = P.ckptC(prevC, j.q, j.sec, hd);
      expect(P.b64u(C)).toBe(j.C);
      expect(P.verify(P.fromB64u(j.sig), P.ckptSigMsg(j.q, C), srvKey)).toBe(true);
      return C;
    };

    // q = 1 includes the previous era's shard and inbox once, as final (sealed / ended); q = 2 drops them.
    expect(world.ckpt.tick()?.q).toBe(1);
    const l1 = (await getJson("/api/v2/ckpt/latest")).j;
    const C1 = verifyEntry(l1, P.ZERO32);
    expect(l1.heads.map((x: { cid: string }) => x.cid)).toEqual(["blobreg", "dirlog", `inbox/${E - 1}/0`, `inbox/${E}/0`, `shard/${E - 1}/0`, `shard/${E}/0`]);
    expect(world.ckpt.tick()).toBeNull(); // the 60 s alarm has not fired again yet
    world.advance(CKPT_PERIOD_MS, { keepSockets: true });
    expect(world.ckpt.tick()?.q).toBe(2);
    const l2 = (await getJson("/api/v2/ckpt/latest")).j;
    const C2 = verifyEntry(l2, C1);
    expect(l2.heads.map((x: { cid: string }) => x.cid)).toEqual(["blobreg", "dirlog", `inbox/${E}/0`, `shard/${E}/0`]);
    world.advance(CKPT_PERIOD_MS, { keepSockets: true });
    expect(world.ckpt.tick()).toBeNull(); // unchanged heads: no new q

    alignToSecond(world);
    await put([putRow(E, P.random(16))]);
    makeUser("alice");
    world.advance(1000, { keepSockets: true });
    expect(world.ckpt.tick()?.q).toBe(3); // the last q was minted more than 60 s ago
    const l3 = (await getJson("/api/v2/ckpt/latest")).j;
    const C3 = verifyEntry(l3, C2);
    const shardHead = l3.heads.find((x: { cid: string }) => x.cid === `shard/${E}/0`).head;
    expect(shardHead).toBe(P.b64u(world.shard.head(E).head));
    expect(shardHead).not.toBe(P.b64u(P.ZERO32));
    expect(l3.heads.find((x: { cid: string }) => x.cid === "dirlog").head).toBe(P.b64u(world.dir.head().h));

    const one = await getJson("/api/v2/ckpt/1");
    expect(one.j).toEqual(l1);
    expect((await fetch("/api/v2/ckpt/99")).status).toBe(404);

    const range = (await getJson("/api/v2/ckpt/range?after=0")).j;
    expect(range.from).toEqual({ q: 0, C: P.b64u(P.ZERO32) });
    expect(range.entries.map((e: { q: number }) => e.q)).toEqual([1, 2, 3]);
    let C = P.fromB64u(range.from.C);
    for (const e of range.entries as { q: number; sec: number; hd: string }[]) C = P.ckptC(C, e.q, e.sec, P.fromB64u(e.hd));
    expect(P.b64u(C)).toBe(range.latest.C);
    expect(P.verify(P.fromB64u(range.latest.sig), P.ckptSigMsg(range.latest.q, C), srvKey)).toBe(true);
    expect((await getJson("/api/v2/ckpt/range?after=1&limit=1")).j.entries.map((e: { q: number }) => e.q)).toEqual([2]);
    expect((await fetch("/api/v2/ckpt/range?after=4")).status).toBe(404);

    // A fork from q = 3: equal q with a different C (what a client that stored C_3 detects); C_2 unchanged.
    world.ckpt.forkAt(3);
    const f = (await getJson("/api/v2/ckpt/latest")).j;
    expect(f.q).toBe(3);
    expect(f.C).not.toBe(P.b64u(C3));
    verifyEntry(f, C2);
    expect((await getJson("/api/v2/ckpt/2")).j.C).toBe(P.b64u(C2));
    const fr = (await getJson("/api/v2/ckpt/range?after=2")).j;
    expect(fr.from.C).toBe(P.b64u(C2));
    expect(fr.latest.C).toBe(f.C);
    world.ckpt.forkAt(null);
    expect((await getJson("/api/v2/ckpt/latest")).j.C).toBe(P.b64u(C3));
  });

  it("tick() mints at most one q per 60 s of world clock; tick({force: true}) skips the floor; sec never falls", async () => {
    const world = server();
    for (let i = 0; i < 100; i++) {
      junkRow(world.era); // its batch closes a second later, so the shard head changes on every tick
      world.advance(1000, { keepSockets: true });
      world.ckpt.tick();
    }
    expect(world.ckpt.q).toBe(2);
    const [c1, c2] = world.ckpt.realChain();
    expect(c2.sec - c1.sec).toBeGreaterThanOrEqual(60);

    // After a clock step back: no tick until 60 s past the last checkpoint; a forced one gets sec = the previous sec.
    world.advance(-120_000, { keepSockets: true });
    makeUser("late"); // the dirlog head changes at once
    expect(world.ckpt.tick()).toBeNull();
    const f = world.ckpt.tick({ force: true })!;
    expect(f.q).toBe(3);
    expect(f.sec).toBe(c2.sec);
    expect(f.sec).toBeGreaterThan(P.secOf(world.now()));
  });

  it("collects the previous era's heads only when E_now − 1 ≥ max(E_FIRST, 0)", () => {
    const E = server().era;
    const cids = (w: FakeWorld) => w.ckpt.tick()!.heads.map((h) => h.cid);
    expect(cids(new FakeWorld({ efirst: E }))).toEqual(["blobreg", "dirlog", `inbox/${E}/0`, `shard/${E}/0`]);
    expect(cids(new FakeWorld({ efirst: E - 1 }))).toEqual(["blobreg", "dirlog", `inbox/${E - 1}/0`, `inbox/${E}/0`, `shard/${E - 1}/0`, `shard/${E}/0`]);
  });
});

// ───────────────────────── browser globals ─────────────────────────

describe("browser globals", () => {
  it("fetch, WebSocket, location, localStorage and a failing indexedDB are bound to the current world", async () => {
    const world = server();
    localStorage.setItem("segv.ckpt", "x");
    expect(localStore.get("segv.ckpt")).toBe("x");
    expect(location.origin).toBe("http://segv.test");
    expect(WebSocket).toBe(FakeWebSocket);
    const before = world.requests.length;
    expect((await fetch("/api/v2/params")).status).toBe(200);
    expect(world.requests.length).toBe(before + 1);
    expect(world.requests[before].who).toBeNull();
    const failed = await new Promise<boolean>((resolve) => {
      const req = indexedDB.open("x") as unknown as { onerror?: () => void };
      req.onerror = () => resolve(true);
    });
    expect(failed).toBe(true);

    const fake = globalThis.fetch;
    uninstallBrowserGlobals();
    try {
      expect(globalThis.fetch).not.toBe(fake);
      expect(globalThis.WebSocket).not.toBe(FakeWebSocket);
    } finally {
      installBrowserGlobals();
    }
    expect(globalThis.fetch).toBe(fake);
  });
});
