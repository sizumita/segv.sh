/**
 * HTTP + WebSocket API v2 tests (docs/PROTOCOL.md §9.7, §10, §12.5) against ../entry.ts inside workerd
 * Tests that need to observe or replace a binding call handleApi directly
 * (helpers.direct) with a spied or fake namespace.
 */
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import * as P from "@segv/protocol/proto";
import * as W from "@segv/protocol/wire";
import { MAX_REGISTER_BODY, MAX_WRAP_BODY, _resetApiForTests, feedTokens, routeLabel } from "../src/api";
import type { CheckpointDO } from "../src/ckpt-do";
import type { RealtimeDO, RtLimits } from "../src/realtime-do";
import type { ShardDO } from "../src/shard-do";
import { shardStub, type ShardPutRow } from "../src/types";
import {
  DIFF2,
  E_FIRST,
  HSTS,
  IMMUTABLE,
  ORIGIN,
  api,
  badNonce,
  bigRandom,
  bytesOf,
  currentWindow,
  direct,
  eraNow,
  errorOf,
  freshIp,
  getKeys,
  getRaw,
  inOneRateWindow,
  inboxPostOk,
  inboxPostRaw,
  inboxReadRaw,
  jsonBytes,
  makeAccount,
  makeRow,
  mixedOrderRegistration,
  needBits,
  nonceBetween,
  nowOf,
  openRt,
  fetchParams,
  postJsonPow,
  powHeader,
  putOk,
  putRaw,
  putRows,
  randomBody,
  randomInvite,
  randomLabel,
  randomTopic,
  registerBody,
  registerOk,
  rtClient,
  rtUpgrade,
  sleep,
  spyNamespace,
  testKroute,
  testSrvKey,
  until,
  type ApiInit,
  type Bytes,
  type DirUserJson,
  type DirlogEntryJson,
  type RtClient,
} from "./helpers";

/** workerd's caches.default (the DOM lib typing does not know it). */
const edgeCache = (): Cache => (caches as unknown as { default: Cache }).default;
const ckpt = () => (env.CKPT as unknown as DurableObjectNamespace<CheckpointDO>).getByName("ckpt/v2");
const eq = P.equalBytes;
const tpub = (ms: number) => P.tpub(ms, 1);

/** Headers on every /api/v2 response (ORIGIN is https). */
function expectApiHeaders(res: Response): void {
  expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  expect(res.headers.get("referrer-policy")).toBe("no-referrer");
  expect(res.headers.get("strict-transport-security")).toBe(HSTS);
  nowOf(res);
}

/** A POST init with a valid PoW over `bytes` (digest = H(bytes) unless given). */
async function powInit(scope: P.PowScope, bytes: Bytes, digest = P.H(bytes), size = bytes.length): Promise<ApiInit> {
  return {
    method: "POST",
    headers: { "content-type": "application/octet-stream", "x-segv-pow": await powHeader(scope, digest, { bytes: size }) },
    body: bytes,
  };
}

/** A request body containing raw rows after a count byte (to build counts the encoder refuses). */
const rawPut = (count: number, rows: W.PutRow[]): Bytes =>
  P.concat(Uint8Array.of(count), ...rows.map((r) => W.encodePutRequest([r]).subarray(1)));

const okOf = (r: W.PutResult) => {
  expect(r.s).toBe("ok");
  return r as { s: "ok"; t: number; receipt: Bytes };
};

async function waitCached(key: string): Promise<Response> {
  let cached: Response | undefined;
  await until(async () => (cached = await edgeCache().match(key)) !== undefined, `cache entry ${key}`, 3000);
  return cached!;
}

// ───────────────────────────── params ─────────────────────────────

describe("GET /api/v2/params", () => {
  it("reports the clock, era fields, kcommit, srvKey, p, difficulties and limits", async () => {
    const before = Date.now();
    const res = await api("/api/v2/params");
    const after = Date.now();
    expect(res.status).toBe(200);
    expectApiHeaders(res);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("content-type")).toMatch(/^application\/json/);
    const p = (await res.json()) as Record<string, unknown>;
    expect(Object.keys(p)).toEqual([
      "v",
      "now",
      "T0",
      "eraMs",
      "era",
      "delta",
      "skew",
      "inboxSlot",
      "inboxRetention",
      "inboxDayCap",
      "inboxBatch",
      "shards",
      "p",
      "efirst",
      "kcommit",
      "srvKey",
      "pow",
      "limits",
      "push",
    ]);
    const now = p.now as number;
    expect(now).toBeGreaterThanOrEqual(before);
    expect(now).toBeLessThanOrEqual(after);
    expect(nowOf(res)).toBe(now);
    const E = P.era(now);
    expect(p).toMatchObject({
      v: 2,
      T0: 1767639600000,
      eraMs: 604800000,
      era: E,
      delta: 1,
      skew: 0,
      inboxSlot: 1,
      inboxRetention: 4,
      inboxDayCap: 2000,
      inboxBatch: 32,
      shards: 1,
      efirst: E_FIRST,
      kcommit: P.b64u(P.kcommit(testKroute(E))),
      srvKey: P.b64u(testSrvKey()),
    });
    expect(Number.isInteger(p.p) && (p.p as number) >= 0 && (p.p as number) <= 32).toBe(true);
    expect(p.pow).toEqual(DIFF2);
    expect(p.limits).toEqual({ putRows: 16, putBytes: 263345, getKeys: 256, topics: 256, blobMax: 12582912, textMax: 12000 });
    // The test config turns Web Push on (packages/server/test/push.spec.ts covers it).
    expect(Object.keys(p.push as object)).toEqual(["vapid", "window", "maxTokens"]);
  });

  it("405 with allow on wrong methods; 404 on unknown /api/v2 paths", async () => {
    const id = P.b64u(P.random(32));
    const cases: [string, string, string][] = [
      ["/api/v2/params", "POST", "GET"],
      ["/api/v2/put", "GET", "POST"],
      ["/api/v2/get", "GET", "POST"],
      ["/api/v2/inbox", "GET", "POST"],
      [`/api/v2/inbox/${eraNow()}/0`, "POST", "GET"],
      ["/api/v2/rt", "POST", "GET"],
      [`/api/v2/era/${eraNow()}`, "POST", "GET"],
      ["/api/v2/ckpt/latest", "POST", "GET"],
      ["/api/v2/ckpt/1", "DELETE", "GET"],
      ["/api/v2/ckpt/range", "POST", "GET"],
      [`/api/v2/feed/${eraNow()}/0`, "POST", "GET"],
      ["/api/v2/register", "GET", "POST"],
      ["/api/v2/wraps", "PUT", "POST"],
      ["/api/v2/dirlog", "POST", "GET"],
      ["/api/v2/dir/h/0/0", "POST", "GET"],
      [`/api/v2/dir/uid/${P.b64u(P.random(16))}`, "DELETE", "GET"],
      [`/api/v2/dir/wraps/${id}`, "POST", "GET"],
      [`/api/v2/blob/${id}`, "POST", "GET, PUT"],
      [`/api/v2/blob/${id}/meta`, "PUT", "GET"],
    ];
    for (const [path, method, allow] of cases) {
      const res = await api(path, { method, body: method === "GET" ? undefined : new Uint8Array(1) });
      expect(res.status, `${method} ${path}`).toBe(405);
      expect(res.headers.get("allow"), path).toBe(allow);
      expectApiHeaders(res);
      expect(await errorOf(res)).toMatch(/method/);
    }
    for (const path of ["/api/v2/nope", "/api/v2/", "/api/v2/params/", "/api/v2/era/abc", "/api/v2/feed/1", "/api/v2/dir/x/0/0", "/api/v2/ckpt/x"]) {
      const res = await api(path);
      expect(res.status, path).toBe(404);
      expectApiHeaders(res);
      expect(await errorOf(res)).toBe("not found");
    }
  });

  it("100 params requests make at most one CheckpointDO.ensure() call (module-level flag)", async () => {
    _resetApiForTests();
    const names: string[] = [];
    let ensures = 0;
    const CKPT = {
      getByName: (n: string) => {
        names.push(n);
        return { ensure: async () => void ensures++ };
      },
    };
    for (let i = 0; i < 100; i++) {
      const res = await direct("/api/v2/params", {}, { CKPT });
      expect(res.status).toBe(200);
    }
    expect(ensures).toBe(1);
    expect(names).toEqual(["ckpt/v2"]);
    // The real namespace is never reached per request either (flag already set).
    const calls: string[] = [];
    for (let i = 0; i < 10; i++) expect((await direct("/api/v2/params", {}, { CKPT: spyNamespace(env.CKPT, calls) })).status).toBe(200);
    expect(calls).toEqual([]);
  });

  it("while D1 fails, params answer p = 0 (no good P yet) from one D1 read and one log line per back-off", async () => {
    _resetApiForTests(); // no cached P, no back-off
    let reads = 0;
    const stmt = { bind: () => stmt, first: () => Promise.reject(new Error("D1_ERROR: Network connection lost.")) };
    const DB = new Proxy(env.DB, { get: (t, k) => (k === "prepare" ? () => (reads++, stmt) : Reflect.get(t, k)) });
    const CKPT = { getByName: () => ({ ensure: async () => {} }) };
    const logs: unknown[][] = [];
    const consoleError = console.error;
    console.error = (...a: unknown[]) => void logs.push(a);
    try {
      for (let i = 0; i < 5; i++) {
        const res = await direct("/api/v2/params", {}, { DB, CKPT });
        expect(res.status).toBe(200);
        expect(((await res.json()) as { p: number }).p).toBe(0);
      }
    } finally {
      console.error = consoleError;
      _resetApiForTests(); // drop the back-off: later tests read P from the real D1
    }
    expect(reads).toBe(1);
    expect(logs).toHaveLength(1);
    expect(String(logs[0][0])).toMatch(/directory: dirmeta read failed/);
  });
});

describe("GET /api/v2/era/{E}", () => {
  it("current era: start, end, delta, shards, kcommit; no kroute; no-store while open", async () => {
    const E = eraNow();
    const res = await api(`/api/v2/era/${E}`);
    expect(res.status).toBe(200);
    expectApiHeaders(res);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const body = (await res.json()) as Record<string, unknown>;
    // Exactly the §10.9 keys, in order (no kroute).
    expect(Object.keys(body)).toEqual(["era", "start", "end", "delta", "shards", "kcommit", "sealed"]);
    expect(body).toEqual({
      era: E,
      start: P.eraStart(E),
      end: P.eraEnd(E),
      delta: 1,
      shards: 1,
      kcommit: P.b64u(P.kcommit(testKroute(E))),
      sealed: false,
    });
    expect((await fetchParams()).kcommit).toBe(body.kcommit);
  });

  it("a past era is sealed and immutable; 404 above era(now + SKEW) and below E_FIRST; 400 on bad numbers", async () => {
    const E = eraNow() - 1;
    expect(E).toBeGreaterThanOrEqual(E_FIRST);
    const res = await api(`/api/v2/era/${E}`);
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe(IMMUTABLE);
    expectApiHeaders(res);
    // A sealed era has the same keys: kroute_E is not published in stage 1 (§10.9).
    const body = (await res.json()) as Record<string, unknown>;
    expect(Object.keys(body)).toEqual(["era", "start", "end", "delta", "shards", "kcommit", "sealed"]);
    expect(body).toEqual({
      era: E,
      start: P.eraStart(E),
      end: P.eraEnd(E),
      delta: 1,
      shards: 1,
      kcommit: P.b64u(P.kcommit(testKroute(E))),
      sealed: true,
    });
    for (const e of [eraNow() + 1, 65000, 0]) {
      const r = await api(`/api/v2/era/${e}`);
      expect(r.status, String(e)).toBe(404);
      expectApiHeaders(r);
    }
    for (const e of ["65535", "01", "999999"]) expect((await api(`/api/v2/era/${e}`)).status, e).toBe(400);
  });
});

// ───────────────────────────── put ─────────────────────────────

describe("POST /api/v2/put", () => {
  it("stores rows; OK receipts verify under params srvKey over receiptMsg", async () => {
    const srvKey = P.fromB64u((await fetchParams()).srvKey);
    expect(srvKey).toEqual(testSrvKey());
    const rows = [makeRow({ cls: 0 }), makeRow({ cls: 1 }), makeRow({ cls: 2 })];
    const before = Date.now();
    const out = await putOk(rows);
    const after = Date.now();
    const t = out[0].t;
    for (const [i, r] of out.entries()) {
      expect(r.t, `row ${i}`).toBe(t); // one t per put
      expect(r.receipt).toHaveLength(64);
      expect(P.verify(r.receipt, P.receiptMsg(rows[i].E, rows[i].label, rows[i].body, r.t), srvKey), `receipt ${i}`).toBe(true);
      // bound to E, label, body and t
      expect(P.verify(r.receipt, P.receiptMsg(rows[i].E, rows[i].label, rows[i].body, r.t + 1), srvKey)).toBe(false);
      expect(P.verify(r.receipt, P.receiptMsg(rows[i].E, randomLabel(), rows[i].body, r.t), srvKey)).toBe(false);
    }
    expect(t).toBeGreaterThanOrEqual(tpub(before));
    expect(t).toBeLessThanOrEqual(tpub(after) + 1);

    const keys = rows.flatMap((r) => [
      { E: r.E, label: r.label, mode: 0 as const },
      { E: r.E, label: r.label, mode: 1 as const },
    ]);
    const got = await getKeys(keys);
    rows.forEach((r, i) => {
      expect(got[2 * i]).toEqual({ s: "hit", t, cls: r.cls, body: r.body });
      expect(got[2 * i + 1]).toEqual({ s: "hit", t, cls: r.cls });
    });
  });

  it("CONFLICT returns the occupying row; a duplicate label inside one put conflicts with the first copy", async () => {
    const a = makeRow();
    const [{ t }] = await putOk([a]);
    const [c1, c2] = await putRows([{ ...a, cls: 1, body: randomBody(1) }, a]);
    expect(c1).toEqual({ s: "conflict", t, cls: 0, body: a.body });
    expect(c2).toEqual({ s: "conflict", t, cls: 0, body: a.body }); // create-only: even the same bytes

    const b = makeRow({ cls: 2 });
    const [ok, dup] = await putRows([b, { ...b, cls: 0, body: randomBody(0) }]);
    const tb = okOf(ok).t;
    expect(dup).toEqual({ s: "conflict", t: tb, cls: 2, body: b.body });
    // The stored row is the first copy.
    expect(await getKeys([{ E: b.E, label: b.label, mode: 0 }])).toEqual([{ s: "hit", t: tb, cls: 2, body: b.body }]);
  });

  it("WRONG_ERA(E_now) for rows outside [era(now − SKEW), era(now + SKEW)]; the other rows land; only the in-range shard is addressed", async () => {
    const E = eraNow();
    const good = makeRow();
    const rows = [makeRow({ E: E + 1 }), good, makeRow({ E: E - 1 }), makeRow({ E: 65000 }), makeRow({ E: 0 })];
    const bytes = W.encodePutRequest(rows);
    const calls: string[] = [];
    const res = await direct("/api/v2/put", await powInit("put", bytes), { SHARD: spyNamespace(env.SHARD, calls) });
    expect(res.status, await res.clone().text()).toBe(200);
    const out = W.decodePutResponse(await bytesOf(res));
    expect(out.map((r) => r.s)).toEqual(["wrong_era", "ok", "wrong_era", "wrong_era", "wrong_era"]);
    for (const i of [0, 2, 3, 4]) expect(out[i]).toEqual({ s: "wrong_era", era: E });
    expect(calls).toEqual([`getByName(shard/v2/${E}/0)`]);
    expect((await getKeys([{ E, label: good.label, mode: 1 }]))[0].s).toBe("hit");
  });

  it("400 on layout errors (strict parse); nothing is stored", async () => {
    const rows = [makeRow(), makeRow({ cls: 1 })];
    const valid = W.encodePutRequest(rows);
    const badCls = valid.slice();
    badCls[1 + 2 + 16] = 4; // cls of row 0
    const wrongClsLen = valid.slice();
    wrongClsLen[1 + 2 + 16] = 1; // body of class 0 announced as class 1
    const cases: [string, Bytes][] = [
      ["empty body", new Uint8Array(0)],
      ["count 0", Uint8Array.of(0)],
      ["count 0 with a row", rawPut(0, [makeRow()])],
      ["count 17", rawPut(17, Array.from({ length: 17 }, () => makeRow()))],
      ["count larger than the rows", rawPut(3, rows)],
      ["count smaller than the rows", rawPut(1, rows)],
      ["truncated", valid.subarray(0, valid.length - 1)],
      ["trailing byte", P.concat(valid, Uint8Array.of(0))],
      ["class 4", badCls],
      ["class does not match the body length", wrongClsLen],
      ["short label", valid.subarray(0, 1 + 2 + 10)],
    ];
    for (const [name, bytes] of cases) {
      const res = await putRaw(bytes);
      expect(res.status, name).toBe(400);
      expectApiHeaders(res);
      expect(await errorOf(res), name).toMatch(/bad put request/);
    }
    const got = await getKeys(rows.map((r) => ({ E: r.E, label: r.label, mode: 1 as const })));
    expect(got).toEqual([
      { s: "miss", sealed: false },
      { s: "miss", sealed: false },
    ]);
  });

  it("16 class-3 rows (263 345 B, the exact cap) are accepted; 263 346 B → 413, declared or streamed", async () => {
    const rows = Array.from({ length: 16 }, () => makeRow({ cls: 3 }));
    const bytes = W.encodePutRequest(rows);
    expect(bytes.length).toBe(263345);
    expect(bytes.length).toBe(W.PUT_MAX_BYTES);
    const out = await putOk(rows);
    expect(out).toHaveLength(16);

    const over = P.concat(bytes, Uint8Array.of(0));
    const res = await api("/api/v2/put", { method: "POST", body: over, headers: { "x-segv-pow": await powHeader("put", P.H(over), { bytes: over.length }) } });
    expect(res.status).toBe(413);
    expectApiHeaders(res);
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        for (let o = 0; o < over.length; o += 65536) c.enqueue(over.slice(o, o + 65536));
        c.close();
      },
    });
    const res2 = await api("/api/v2/put", { method: "POST", body: stream, headers: { "x-segv-pow": "0.0" } });
    expect(res2.status).toBe(413);
  });

  it("proof of work is priced by the request size; params keep reporting the base", async () => {
    const rows = Array.from({ length: 16 }, () => makeRow({ cls: 3 }));
    const bytes = W.encodePutRequest(rows);
    const required = needBits("put", bytes.length);
    expect(required).toBe(DIFF2.put + Math.ceil(Math.log2(bytes.length / 4096)));
    expect(required).toBe(DIFF2.put + 7);
    const w = currentWindow();
    const cheap = await api("/api/v2/put", {
      method: "POST",
      body: bytes,
      headers: { "x-segv-pow": `${w}.${nonceBetween("put", w, P.H(bytes), DIFF2.put, required)}` },
    });
    expect(cheap.status).toBe(403);
    expect(await errorOf(cheap)).toMatch(new RegExp(`insufficient.*${required} bits`));
    expect((await getKeys([{ E: rows[0].E, label: rows[0].label, mode: 1 }]))[0]).toEqual({ s: "miss", sealed: false });
    expect((await putRaw(bytes)).status).toBe(200);
    // A request of at most 4096 bytes costs the base difficulty.
    expect(needBits("put", 4096)).toBe(DIFF2.put);
    expect(W.encodePutRequest([makeRow({ cls: 2 })]).length).toBeGreaterThan(4096);
    expect(W.encodePutRequest([makeRow({ cls: 1 })]).length).toBeLessThanOrEqual(4096);
    expect((await fetchParams()).pow).toEqual(DIFF2);
  });

  it("a row with a topic is published to a subscribed socket; a row with a zero topic is not", async () => {
    const T = randomTopic();
    const rt = await openRt();
    try {
      await subscribed(rt, [T, P.ZERO16]);
      const zero = makeRow({ cls: 1 });
      const live = makeRow({ cls: 1, topic: T });
      const [okZero, okLive] = await putOk([zero, live]);
      await rt.until(() => rt.rows().some((r) => eq(r.label, live.label)), "published row");
      const got = rt.rows().find((r) => eq(r.label, live.label))!;
      expect(got).toMatchObject({ topic: T, E: live.E, label: live.label, t: okLive.t, cls: 1, body: live.body });
      expect(got.seq).toBeGreaterThan(rt.hello!.seq);
      // The zero-topic row of the same put is never published (even to a socket subscribed to ZERO16).
      await sleep(200);
      expect(okZero.t).toBe(okLive.t);
      expect(rt.rows().some((r) => eq(r.label, zero.label))).toBe(false);
      expect(rt.closed()).toBeNull();
    } finally {
      rt.close();
    }
  });
});

// ───────────────────────────── get ─────────────────────────────

describe("POST /api/v2/get", () => {
  it("modes: HIT with the body (0) or without (1); MISS(sealed = 0) in the current era; order is preserved", async () => {
    const rows = [makeRow({ cls: 3 }), makeRow({ cls: 0 })];
    const [{ t }] = await putOk(rows);
    const E = eraNow();
    const missing = randomLabel();
    const got = await getKeys([
      { E, label: missing, mode: 0 },
      { E, label: rows[1].label, mode: 1 },
      { E, label: rows[0].label, mode: 0 },
      { E, label: missing, mode: 1 },
      { E, label: rows[1].label, mode: 0 },
    ]);
    expect(got).toEqual([
      { s: "miss", sealed: false },
      { s: "hit", t, cls: 0 },
      { s: "hit", t, cls: 3, body: rows[0].body },
      { s: "miss", sealed: false },
      { s: "hit", t, cls: 0, body: rows[1].body },
    ]);
  });

  it("MISS(sealed = 1) below E_FIRST and NO_ERA above era(now + SKEW), without a DO call; a past era's shard answers sealed", async () => {
    const E = eraNow();
    const row = makeRow();
    await putOk([row]);
    const calls: string[] = [];
    const keys: W.GetKey[] = [
      { E: 0, label: row.label, mode: 0 },
      { E: 65000, label: row.label, mode: 0 },
      { E: E + 1, label: row.label, mode: 1 },
      { E, label: row.label, mode: 1 },
      { E: 0xffff, label: row.label, mode: 1 },
    ];
    const res = await direct("/api/v2/get", { method: "POST", body: W.encodeGetRequest(keys) }, { SHARD: spyNamespace(env.SHARD, calls) });
    expect(res.status).toBe(200);
    const got = W.decodeGetResponse(
      await bytesOf(res),
      keys.map((k) => k.mode),
    );
    expect(got.map((s) => s.s)).toEqual(["miss", "no_era", "no_era", "hit", "no_era"]);
    expect(got[0]).toEqual({ s: "miss", sealed: true });
    expect(calls).toEqual([`getByName(shard/v2/${E}/0)`]);
    // Only out-of-range keys: no DO at all.
    calls.length = 0;
    const res2 = await direct(
      "/api/v2/get",
      {
        method: "POST",
        body: W.encodeGetRequest([
          { E: 0, label: row.label, mode: 1 },
          { E: 65000, label: row.label, mode: 1 },
        ]),
      },
      { SHARD: spyNamespace(env.SHARD, calls) },
    );
    expect(W.decodeGetResponse(await bytesOf(res2), [1, 1])).toEqual([{ s: "miss", sealed: true }, { s: "no_era" }]);
    expect(calls).toEqual([]);
    // E_now − 1 is past its end: the shard seals itself and answers final MISSes.
    expect(await getKeys([{ E: E - 1, label: randomLabel(), mode: 0 }])).toEqual([{ s: "miss", sealed: true }]);
  });

  it("SKIPPED for body-mode keys past the 4 MiB budget; exists-mode keys are not counted", async () => {
    const rows = Array.from({ length: 16 }, () => makeRow({ cls: 3 }));
    const ok = await putOk(rows);
    const key = (i: number, mode: 0 | 1): W.GetKey => ({ E: rows[i % 16].E, label: rows[i % 16].label, mode });
    // 255 × 16 424 B ≤ 4 MiB < 256 × 16 424 B
    expect(255 * 16424).toBeLessThanOrEqual(W.GET_BODY_BUDGET);
    expect(256 * 16424).toBeGreaterThan(W.GET_BODY_BUDGET);
    const all = await getKeys(Array.from({ length: 256 }, (_, i) => key(i, 0)));
    // (byte comparisons by hand: deep equality over 4 MiB of bodies is slow)
    const bad = all
      .slice(0, 255)
      .map((s, i) => (s.s === "hit" && s.t === ok[i % 16].t && s.cls === 3 && s.body !== undefined && eq(s.body, rows[i % 16].body) ? -1 : i))
      .filter((i) => i >= 0);
    expect(bad, "keys not answered HIT with the body").toEqual([]);
    expect(all[255]).toEqual({ s: "skipped" });
    const mixed = await getKeys([...Array.from({ length: 255 }, (_, i) => key(i, 0)), key(255, 1)]);
    expect(mixed.filter((s) => s.s === "skipped")).toHaveLength(0);
    expect(mixed[255]).toEqual({ s: "hit", t: ok[15].t, cls: 3 });
  });

  it("400 on layout errors; 413 above 8 KiB", async () => {
    const k = { E: eraNow(), label: randomLabel(), mode: 0 as const };
    const one = W.encodeGetRequest([k]);
    const badMode = one.slice();
    badMode[2 + 2 + 16] = 2;
    const many = P.concat(Uint8Array.of(0x01, 0x01), ...Array.from({ length: 257 }, () => one.subarray(2))); // 257 keys
    const cases: [string, Bytes][] = [
      ["empty", new Uint8Array(0)],
      ["count 0", Uint8Array.of(0, 0)],
      ["count 257", many],
      ["mode 2", badMode],
      ["truncated", one.subarray(0, one.length - 1)],
      ["trailing", P.concat(one, Uint8Array.of(0))],
      ["count 2, one key", P.concat(Uint8Array.of(0, 2), one.subarray(2))],
    ];
    for (const [name, bytes] of cases) {
      const res = await getRaw(bytes);
      expect(res.status, name).toBe(400);
      expectApiHeaders(res);
      expect(await errorOf(res), name).toMatch(/bad get request/);
    }
    expect(W.encodeGetRequest(Array.from({ length: 256 }, () => k)).length).toBeLessThanOrEqual(W.GET_MAX_BYTES);
    expect((await getRaw(new Uint8Array(8 * 1024 + 1))).status).toBe(413);
  });
});

// ───────────────────────────── feed and checkpoints ─────────────────────────────

interface CkptJson {
  q: number;
  sec: number;
  hd: string;
  C: string;
  sig: string;
  heads: { cid: string; head: string }[];
}

/** Verifies a checkpoint's hd and signature. */
function verifyCkpt(c: CkptJson, srvKey: Bytes): void {
  expect(Object.keys(c)).toEqual(["q", "sec", "hd", "C", "sig", "heads"]);
  const heads = c.heads.map((h) => ({ cid: h.cid, head: P.fromB64u(h.head) }));
  for (const h of heads) expect(h.head).toHaveLength(32);
  expect(P.b64u(P.ckptHd(heads))).toBe(c.hd);
  expect(P.verify(P.fromB64u(c.sig), P.ckptSigMsg(c.q, P.fromB64u(c.C)), srvKey)).toBe(true);
}

/** Pages through GET /api/v2/feed/{E}/0, verifying every batch root and the head chain from ZERO32. */
async function feedVerified(E: number, sealed: boolean): Promise<{ batches: W.FeedBatch[]; head: Bytes }> {
  const cid = P.shardCid(E, 0);
  let after = 0;
  let head: Bytes = P.ZERO32;
  const batches: W.FeedBatch[] = [];
  for (let page = 0; page < 10_000; page++) {
    const res = await api(`/api/v2/feed/${E}/0?after=${after}`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/octet-stream");
    const f = W.decodeFeed(await bytesOf(res));
    expect(res.headers.get("cache-control")).toBe(f.more || sealed ? IMMUTABLE : "no-store");
    if (f.more) expect(f.batches.length).toBeGreaterThan(0);
    for (const b of f.batches) {
      expect(b.t).toBeGreaterThan(after);
      for (let k = 1; k < b.rows.length; k++) expect(P.byteCmp(b.rows[k - 1].label, b.rows[k].label)).toBeLessThan(0);
      expect(eq(P.mth(b.rows.map((r) => P.leafShard(E, r.label, b.t, r.cls, r.body))), b.root), `root of batch t=${b.t}`).toBe(true);
      head = P.nextHead(cid, head, b.t, b.n, b.root);
      expect(eq(b.head, head), `head of batch t=${b.t}`).toBe(true);
      after = b.t;
      batches.push(b);
    }
    if (!f.more) return { batches, head };
  }
  throw new Error("feed never ended");
}

describe("GET /api/v2/feed and /api/v2/ckpt", () => {
  it("feed roots and the head chain verify, and the last head equals the shard head in /ckpt/latest after a tick", async () => {
    const E = eraNow();
    const srvKey = testSrvKey();
    const first = [makeRow({ cls: 0 }), makeRow({ cls: 2 }), makeRow({ cls: 1 })];
    const [{ t: t1 }] = await putOk(first);
    await sleep(1100); // the next put lands in a later batch (Δ = 1)
    const second = [makeRow({ cls: 3 })];
    const [{ t: t2 }] = await putOk(second);
    expect(t2).toBeGreaterThan(t1);

    let verified = false;
    for (let attempt = 0; attempt < 20 && !verified; attempt++) {
      if (attempt > 0) await sleep(400);
      await ckpt().tick();
      const res = await api("/api/v2/ckpt/latest");
      if (res.status !== 200) continue;
      expect(res.headers.get("cache-control")).toBe("no-store");
      const latest = (await res.json()) as CkptJson;
      verifyCkpt(latest, srvKey);
      const { batches, head } = await feedVerified(E, false);
      const labels = batches.flatMap((b) => b.rows.map((r) => P.b64u(r.label)));
      if (![...first, ...second].every((r) => labels.includes(P.b64u(r.label)))) continue; // batch not closed yet
      const shardHead = latest.heads.find((h) => h.cid === P.shardCid(E, 0));
      expect(shardHead, "shard head in the checkpoint").toBeDefined();
      if (shardHead!.head !== P.b64u(head)) continue; // a write landed between the tick and the feed read
      verified = true;
      // Our rows sit in the batches of their put's t, with their class and body.
      for (const [rows, t] of [
        [first, t1],
        [second, t2],
      ] as const) {
        const b = batches.find((x) => x.t === t)!;
        expect(b, `batch t=${t}`).toBeDefined();
        for (const r of rows) expect(b.rows.find((x) => eq(x.label, r.label))).toEqual({ label: r.label, cls: r.cls, body: r.body });
      }
      // /ckpt/{q} has the same content and is immutable; the range recomputes C up to latest.
      const at = await api(`/api/v2/ckpt/${latest.q}`);
      expect(at.status).toBe(200);
      expect(at.headers.get("cache-control")).toBe(IMMUTABLE);
      expect(await at.json()).toEqual(latest);
      let C: Bytes = P.ZERO32;
      let q = 0;
      for (;;) {
        const rr = await api(`/api/v2/ckpt/range?after=${q}&limit=1440`);
        expect(rr.status).toBe(200);
        const range = (await rr.json()) as {
          from: { q: number; C: string };
          entries: { q: number; sec: number; hd: string }[];
          latest: { q: number; C: string; sig: string };
        };
        expect(range.from).toEqual({ q, C: P.b64u(C) });
        for (const e of range.entries) {
          expect(e.q).toBe(q + 1);
          C = P.ckptC(C, e.q, e.sec, P.fromB64u(e.hd));
          q = e.q;
        }
        expect(P.verify(P.fromB64u(range.latest.sig), P.ckptSigMsg(range.latest.q, P.fromB64u(range.latest.C)), srvKey)).toBe(true);
        if (q >= range.latest.q) {
          expect(P.b64u(C)).toBe(range.latest.C);
          break;
        }
        expect(range.entries.length).toBeGreaterThan(0);
      }
      expect(q).toBeGreaterThanOrEqual(latest.q);
    }
    expect(verified, "feed head never matched the checkpoint").toBe(true);
  });

  it("feed: the tail page is no-store, a sealed era's pages are immutable; 404 outside the eras and shards; 400 on bad after", async () => {
    const E = eraNow();
    const tail = await api(`/api/v2/feed/${E}/0?after=4294967295`);
    expect(tail.status).toBe(200);
    expect(tail.headers.get("cache-control")).toBe("no-store");
    expect(W.decodeFeed(await bytesOf(tail))).toEqual({ more: false, batches: [] });
    await feedVerified(E - 1, true);
    for (const path of [`/api/v2/feed/${E + 1}/0`, "/api/v2/feed/65000/0", "/api/v2/feed/0/0", `/api/v2/feed/${E}/1`]) {
      const res = await api(path);
      expect(res.status, path).toBe(404);
      expectApiHeaders(res);
    }
    for (const q of ["after=-1", "after=x", "after=4294967296", "after="]) expect((await api(`/api/v2/feed/${E}/0?${q}`)).status, q).toBe(400);
  });

  it("feed: one batch above the 32 MiB RPC limit comes back whole over HTTP, root and head chain verified", async () => {
    const E = eraNow() - 9; // a past era no other test touches; its shard runs on a clock set inside the era
    expect(E).toBeGreaterThanOrEqual(E_FIRST);
    const shard = shardStub(env, E, 0);
    const shardClock = (ms: number) =>
      runInDurableObject(shard, (inst: ShardDO) => {
        (inst as unknown as { clock: () => number }).clock = () => ms;
      });
    await shardClock(P.eraStart(E) + 60_000);
    const N = 2100; // one Δ batch of 2100 class-3 rows: 2100 × (17 + 16 424) B ≈ 34.5 MB on the wire
    const sent = new Map<string, ShardPutRow>();
    for (let k = 0; k < N; k += 300) {
      const part = Array.from({ length: 300 }, () => ({ v: P.random(8), label: randomLabel(), cls: 3, body: randomBody(3) }));
      for (const r of await shard.put(E, 0, part)) expect(r.s).toBe("ok");
      for (const r of part) sent.set(P.b64u(r.label), r);
    }
    await shardClock(P.eraEnd(E) + 1000); // the next RPC seals the era, closing the batch
    const { batches, head } = await feedVerified(E, true);
    expect(batches).toHaveLength(1);
    const [b] = batches;
    expect(b.n).toBe(N);
    expect(5 + 72 + b.rows.reduce((n, r) => n + 17 + r.body.length, 0)).toBeGreaterThan(32 * 1024 * 1024);
    for (const r of b.rows) expect(eq(r.body, sent.get(P.b64u(r.label))!.body)).toBe(true);
    expect(new Set(b.rows.map((r) => P.b64u(r.label))).size).toBe(N);
    expect(eq(head, (await shard.head(E, 0)).head)).toBe(true);
  }, 120_000);

  it("ckpt: 404 for q = 0 and unknown q; 400 on bad range parameters", async () => {
    await ckpt().tick();
    const latest = (await (await api("/api/v2/ckpt/latest")).json()) as CkptJson;
    expect((await api("/api/v2/ckpt/0")).status).toBe(404);
    expect((await api(`/api/v2/ckpt/${latest.q + 100000}`)).status).toBe(404);
    for (const q of ["limit=0", "limit=1441", "after=-1", "after=x"]) expect((await api(`/api/v2/ckpt/range?${q}`)).status, q).toBe(400);
  });
});

// ───────────────────────────── inbox ─────────────────────────────

/** Reads the current-era inbox until every eid in `want` is final; varies `limit` to bypass the 1 s cache. */
async function readUntil(E: number, after: number, want: W.InboxPostRow[]): Promise<{ read: W.InboxRead; res: Response }> {
  for (let i = 0; i < 100; i++) {
    const res = await inboxReadRaw(E, `?after=${after}&limit=${1024 - i}`);
    expect(res.status).toBe(200);
    const read = W.decodeInboxRead(await bytesOf(res.clone()));
    if (want.every((w) => read.rows.some((r) => eq(r.eid, w.eid)))) return { read, res };
    await sleep(100);
  }
  throw new Error("invites never became readable");
}

describe("inbox", () => {
  it("posts invites with per-row results (rel, idempotent retry, conflict); reads return them once their slot is closed", async () => {
    const E = eraNow();
    const [i1, i2, i3] = [randomInvite(), randomInvite(), randomInvite()];
    const before = Date.now() - P.T0_MS;
    const r1 = await inboxPostOk([i1, i2]);
    const after = Date.now() - P.T0_MS;
    const rels = r1.map((r) => (r as { rel: number }).rel);
    for (const rel of rels) {
      expect(rel).toBeGreaterThanOrEqual(Math.floor(before / 1000) + 1); // rel > ⌊ms / D⌋
      expect(rel).toBeLessThanOrEqual(Math.floor(after / 1000) + 2);
    }
    const r2 = await inboxPostOk([i1, { eid: i2.eid, body: bigRandom(P.INBOX_BODY_LEN) }, i3]);
    expect(r2[0]).toEqual({ rel: rels[0] }); // same eid, same body: idempotent
    expect(r2[1]).toEqual({ error: "conflict" });
    expect(Object.keys(r2[2])).toEqual(["rel"]);

    const lo = Math.min(...rels, (r2[2] as { rel: number }).rel) - 1;
    const { read, res } = await readUntil(E, lo, [i1, i2, i3]);
    expect(res.headers.get("cache-control")).toBe("public, max-age=1");
    expect(res.headers.get("content-type")).toBe("application/octet-stream");
    expectApiHeaders(res);
    for (const r of read.rows) {
      expect(r.rel).toBeGreaterThan(lo);
      expect(r.rel).toBeLessThanOrEqual(read.closed);
    }
    for (let k = 1; k < read.rows.length; k++) {
      const [a, b] = [read.rows[k - 1], read.rows[k]];
      expect(a.rel < b.rel || (a.rel === b.rel && P.byteCmp(a.eid, b.eid) < 0)).toBe(true);
    }
    for (const [inv, rel] of [
      [i1, rels[0]],
      [i2, rels[1]],
      [i3, (r2[2] as { rel: number }).rel],
    ] as const) {
      expect(read.rows.find((r) => eq(r.eid, inv.eid))).toEqual({ rel, eid: inv.eid, body: inv.body }); // i2 keeps its first body
    }
    // limit: whole rel groups, more = 1 when cut.
    const one = W.decodeInboxRead(await bytesOf(await inboxReadRaw(E, `?after=${lo}&limit=1`)));
    expect(one.rows.length).toBeGreaterThanOrEqual(1);
    if (read.rows.length > one.rows.length) expect(one.more).toBe(true);
  });

  it("409 {error, era} for a post outside the current era; 400 for bucket ≠ 0, a bad count or length; 413 above 45 831 B", async () => {
    const E = eraNow();
    for (const e of [E + 1, E - 1]) {
      const res = await inboxPostRaw({ E: e, bucket: 0, rows: [randomInvite()] });
      expect(res.status, String(e)).toBe(409);
      expectApiHeaders(res);
      expect(await res.json()).toEqual({ error: "wrong era", era: E });
    }
    const one = W.encodeInboxPost({ E, bucket: 0, rows: [randomInvite()] });
    const bucket1 = one.slice();
    bucket1[5] = 1;
    const count0 = one.slice(0, 7);
    count0[6] = 0;
    const count33 = W.encodeInboxPost({ E, bucket: 0, rows: Array.from({ length: 32 }, randomInvite) }).slice(0, 7 + 31 * 1432);
    count33[6] = 33;
    const count2 = one.slice();
    count2[6] = 2;
    const cases: [string, Bytes][] = [
      ["bucket 1", bucket1],
      ["count 0", count0],
      ["count 33", count33],
      ["count 2, one row", count2],
      ["short row", one.subarray(0, one.length - 1)],
      ["trailing byte", P.concat(one, Uint8Array.of(0))],
      ["empty", new Uint8Array(0)],
    ];
    for (const [name, bytes] of cases) {
      const res = await inboxPostRaw(bytes);
      expect(res.status, name).toBe(400);
      expectApiHeaders(res);
    }
    expect(W.INBOX_MAX_BYTES).toBe(45831);
    const full = W.encodeInboxPost({ E, bucket: 0, rows: Array.from({ length: 32 }, randomInvite) });
    expect(full.length).toBe(45831);
    const big = P.concat(full, Uint8Array.of(0));
    expect((await api("/api/v2/inbox", { method: "POST", body: big, headers: { "x-segv-pow": "0.0" } })).status).toBe(413);
    // 32 invites are one request (and one PoW priced by its size).
    const res = await inboxPostOk(Array.from({ length: 32 }, randomInvite));
    expect(res.every((r) => "rel" in r)).toBe(true);
  });

  it("reads: 410 below E_now − 3, 400 for a future era or bucket ≠ 0 or bad parameters; an ended era is immutable", async () => {
    const E = eraNow();
    const gone = await inboxReadRaw(E - 4);
    expect(gone.status).toBe(410);
    expectApiHeaders(gone);
    for (const [name, res] of [
      ["future", await inboxReadRaw(E + 1)],
      ["bucket 1", await inboxReadRaw(E, "", 1)],
      ["limit 0", await inboxReadRaw(E, "?limit=0")],
      ["limit 1025", await inboxReadRaw(E, "?limit=1025")],
      ["after -1", await inboxReadRaw(E, "?after=-1")],
      ["after 2^32", await inboxReadRaw(E, "?after=4294967296")],
      ["era 01", await api(`/api/v2/inbox/0${E}/0`)],
    ] as const) {
      expect(res.status, name).toBe(400);
    }
    // E_now − 1 is within retention and has ended: its (empty, more = 0) answer is final.
    const ended = await inboxReadRaw(E - 1, "?after=0");
    expect(ended.status).toBe(200);
    expect(ended.headers.get("cache-control")).toBe(IMMUTABLE);
    expect(W.decodeInboxRead(await bytesOf(ended)).more).toBe(false);
  });

  it("current-era reads are cached for Δin under the canonical (E, bucket, after, limit) key, without x-segv-now", async () => {
    const E = eraNow();
    const after = 7 + Math.floor(Math.random() * 1e6);
    const res = await inboxReadRaw(E, `?after=${after}&limit=9`);
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("public, max-age=1");
    const key = `${ORIGIN}/api/v2/inbox/${E}/0?after=${after}&limit=9`;
    const cached = await waitCached(key);
    expect(cached.headers.get("x-segv-now")).toBeNull();
    await cached.arrayBuffer();
    // Replace the entry with a marker: a request with reordered / junk parameters is served from it, without an
    // RL_READ token or an InboxDO call, and with a fresh x-segv-now.
    const marker = W.encodeInboxRead({ closed: 4242, more: false, rows: [] });
    await edgeCache().put(key, new Response(marker as BodyInit, { headers: { "cache-control": "public, max-age=60", "content-type": "application/octet-stream" } }));
    const t0 = Date.now();
    const rl = countingLimiter();
    const names: string[] = [];
    const hit = await direct(`/api/v2/inbox/${E}/0?limit=9&junk=1&after=${after}`, {}, { RL_READ: rl, INBOX: fakeNs({}, names) });
    expect(hit.status).toBe(200);
    expect(W.decodeInboxRead(await bytesOf(hit)).closed).toBe(4242);
    expect(nowOf(hit)).toBeGreaterThanOrEqual(t0);
    expectApiHeaders(hit);
    expect(rl.calls).toBe(0);
    expect(names).toEqual([]);
    await edgeCache().delete(key);
  });
});

// ───────────────────────────── directory ─────────────────────────────

async function dirlogHead(): Promise<{ seq: number; h: string }> {
  const res = await api("/api/v2/dirlog?after=0&limit=1");
  expect(res.status).toBe(200);
  return ((await res.json()) as { head: { seq: number; h: string } }).head;
}

/** Pages a prefix lookup until `uid` is found (or the pages end); checks every user's prefix and the order. */
async function prefixFind(kind: "h" | "u", p: number, x: number, uid: string): Promise<DirUserJson | null> {
  let after: string | null = null;
  for (let page = 0; page < 1000; page++) {
    const res = await api(`/api/v2/dir/${kind}/${p}/${x}${after === null ? "" : `?after=${after}`}`);
    expect(res.status, await res.clone().text()).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const body = (await res.json()) as { p: number; users: DirUserJson[]; more: boolean };
    expect(Object.keys(body)).toEqual(["p", "users", "more"]);
    expect(body.p).toBe(p);
    expect(body.users.length).toBeLessThanOrEqual(256);
    let prev = after;
    for (const u of body.users) {
      const pre = kind === "h" ? P.hpre(u.handle) : P.upre(P.fromB64u(u.uid));
      expect(P.topBits(pre, p)).toBe(x);
      if (prev !== null) expect(u.uid > prev).toBe(true);
      prev = u.uid;
    }
    const hit = body.users.find((u) => u.uid === uid);
    if (hit) return hit;
    if (!body.more || body.users.length === 0) return null;
    after = body.users[body.users.length - 1].uid;
  }
  return null;
}

describe("directory: POST /api/v2/register and /api/v2/wraps", () => {
  it("registers a user with passkey and recovery wraps; the user, wraps and dirlog entries are readable and unlock", async () => {
    const a = makeAccount();
    const dirseq = await registerOk(a);

    const u = await api(`/api/v2/dir/uid/${a.uidB64}`);
    expect(u.status).toBe(200);
    expectApiHeaders(u);
    expect(u.headers.get("cache-control")).toBe("no-store");
    const { user } = (await u.json()) as { user: DirUserJson };
    expect(user).toEqual({ uid: a.uidB64, handle: a.handle, bundle: a.bundle, sig: a.sig, regEra: eraNow(), dirseq });

    const w = await api(`/api/v2/dir/wraps/${P.b64u(a.credId)}`);
    expect(w.status).toBe(200);
    const { wraps } = (await w.json()) as { wraps: { uid: string; record: string; sig: string; dirseq: number }[] };
    expect(wraps).toHaveLength(1);
    expect(wraps[0]).toMatchObject({ uid: a.uidB64, record: a.passkey.record, sig: a.passkey.sig });
    const bundle = P.verifyBundle(user.bundle, user.sig);
    const rec = P.verifyWrap(wraps[0].record, wraps[0].sig, bundle.sigPk);
    expect(eq(P.unwrapAK(rec, a.cred, bundle.sigPk), a.AK)).toBe(true);
    // Recovery: by recId, no uid.
    const r = (await (await api(`/api/v2/dir/wraps/${P.b64u(a.recId)}`)).json()) as { wraps: { uid: string; record: string; sig: string; dirseq: number }[] };
    expect(r.wraps).toHaveLength(1);
    expect(eq(P.unwrapAK(P.verifyWrap(r.wraps[0].record, r.wraps[0].sig, bundle.sigPk), a.rec, bundle.sigPk), a.AK)).toBe(true);
    // uid filter.
    expect(((await (await api(`/api/v2/dir/wraps/${P.b64u(a.credId)}?uid=${a.uidB64}`)).json()) as { wraps: unknown[] }).wraps).toHaveLength(1);
    expect(((await (await api(`/api/v2/dir/wraps/${P.b64u(a.credId)}?uid=${P.b64u(P.random(16))}`)).json()) as { wraps: unknown[] }).wraps).toHaveLength(0);

    // The dirlog holds the user and both wraps, at the dirseqs reported.
    const seqs = [dirseq, wraps[0].dirseq, r.wraps[0].dirseq];
    const lo = Math.min(...seqs);
    const page = (await (await api(`/api/v2/dirlog?after=${lo - 1}&limit=3`)).json()) as { entries: DirlogEntryJson[] };
    const bySeq = new Map(page.entries.map((e) => [e.seq, e]));
    expect(bySeq.get(dirseq)).toMatchObject({ kind: 1, ref: P.b64u(P.dirlogRefUser(a.bundle, P.fromB64u(a.sig))) });
    expect(bySeq.get(wraps[0].dirseq)).toMatchObject({ kind: 2, ref: P.b64u(P.dirlogRefWrap(a.passkey.record, P.fromB64u(a.passkey.sig))) });
    expect(bySeq.get(r.wraps[0].dirseq)).toMatchObject({ kind: 2, ref: P.b64u(P.dirlogRefWrap(a.recovery.record, P.fromB64u(a.recovery.sig))) });
  });

  it("409 on a taken handle or uid; the dirlog does not move", async () => {
    const a = makeAccount();
    await registerOk(a);
    const h0 = await dirlogHead();
    let res = await postJsonPow("/api/v2/register", "register", registerBody(makeAccount(a.handle)));
    expect(res.status).toBe(409);
    expectApiHeaders(res);
    expect(await errorOf(res)).toMatch(/handle|taken/);
    res = await postJsonPow("/api/v2/register", "register", registerBody(makeAccount(undefined, a.uid)));
    expect(res.status).toBe(409);
    expect(await errorOf(res)).toMatch(/uid|taken/);
    expect(await dirlogHead()).toEqual(h0);
  });

  it("400 on bad signatures, unusable keys, foreign wraps and malformed bodies", async () => {
    const a = makeAccount();
    const b = makeAccount();
    const badSig = P.fromB64u(a.sig);
    badSig[0] ^= 1;
    const raw = JSON.parse(a.bundle) as Record<string, unknown>;
    const resign = (over: Record<string, unknown>) => {
      const bundle = JSON.stringify({ ...raw, ...over });
      return { bundle, sig: P.b64u(P.sign(P.bundleSigMsg(bundle), a.ident.sigSk)) };
    };
    const forged = P.makeWrap(a.uid, "passkey", P.random(16), P.credKem(P.random(32), P.random(16)), a.AK, b.ident, Date.now());
    const cases: [string, unknown][] = [
      ["bad bundle signature", { ...registerBody(a), sig: P.b64u(badSig) }],
      ["unusable KEM key", { ...resign({ kem: P.b64u(new Uint8Array(1216).fill(0xff)) }), wraps: [a.passkey] }],
      ["extra bundle field", { ...resign({ x: 1 }), wraps: [a.passkey] }],
      ["bad handle", { ...resign({ handle: "Bad-Handle" }), wraps: [a.passkey] }],
      ["wrap of another uid", registerBody(a, [a.passkey, b.passkey])],
      ["wrap signed by another key", registerBody(a, [forged])],
      ["no wraps", registerBody(a, [])],
      ["5 wraps", registerBody(a, [a.passkey, a.recovery, a.passkey, a.recovery, a.passkey])],
      ["duplicate wrap ids", registerBody(a, [a.passkey, a.passkey])],
      ["unknown field", { ...registerBody(a), extra: 1 }],
      ["missing wraps", { bundle: a.bundle, sig: a.sig }],
      ["non-canonical bundle JSON", { ...registerBody(a), bundle: a.bundle.replace('{"v":2,', '{"v":2, ') }],
      ["extra wrap key", { ...registerBody(a), wraps: [{ ...a.passkey, x: 1 }] }],
      ["sig not a string", { ...registerBody(a), sig: 42 }],
      ["array body", [registerBody(a)]],
    ];
    for (const [name, body] of cases) {
      const res = await postJsonPow("/api/v2/register", "register", body);
      expect(res.status, name).toBe(400);
      expectApiHeaders(res);
    }
    const notJson = await postJsonPow("/api/v2/register", "register", P.utf8("{not json"));
    expect(notJson.status).toBe(400);
    expect(await errorOf(notJson)).toBe("invalid JSON");
    expect((await api(`/api/v2/dir/uid/${a.uidB64}`)).status).toBe(404);
  });

  it("400 on a mixed-order signing key whose signatures all verify; nothing is registered", async () => {
    const a = makeAccount();
    const h0 = await dirlogHead();
    const res = await postJsonPow("/api/v2/register", "register", mixedOrderRegistration(a).body);
    expect(res.status).toBe(400);
    expectApiHeaders(res);
    expect(await errorOf(res)).toMatch(/signing key/);
    expect(await dirlogHead()).toEqual(h0);
    expect((await api(`/api/v2/dir/uid/${a.uidB64}`)).status).toBe(404);
  });

  it("413 above the body caps (register 64 KiB, wraps 16 KiB), declared or streamed", async () => {
    expect(MAX_REGISTER_BODY).toBe(64 * 1024);
    expect(MAX_WRAP_BODY).toBe(16 * 1024);
    for (const [path, scope, cap] of [
      ["/api/v2/register", "register", MAX_REGISTER_BODY],
      ["/api/v2/wraps", "wrap", MAX_WRAP_BODY],
    ] as const) {
      const big = new Uint8Array(cap + 1).fill(0x20);
      const res = await postJsonPow(path, scope, big);
      expect(res.status, path).toBe(413);
      expectApiHeaders(res);
      const stream = new ReadableStream<Uint8Array>({
        start(c) {
          for (let o = 0; o <= cap; o += 4096) c.enqueue(new Uint8Array(4096).fill(0x20));
          c.close();
        },
      });
      expect((await api(path, { method: "POST", body: stream, headers: { "x-segv-pow": "0.0" } })).status, path).toBe(413);
      // At the cap the body is read (and here fails as JSON).
      const atCap = await postJsonPow(path, scope, new Uint8Array(cap).fill(0x20));
      expect(atCap.status, path).toBe(400);
    }
  });

  it("wraps: adds a wrap for an existing user; 409 duplicate; 404 unknown uid; 400 bad signature", async () => {
    const a = makeAccount();
    await registerOk(a);
    const credId = P.random(20);
    const cred = P.credKem(P.random(32), credId);
    const w = P.makeWrap(a.uid, "passkey", credId, cred, a.AK, a.ident, Date.now());
    const res = await postJsonPow("/api/v2/wraps", "wrap", w);
    expect(res.status, await res.clone().text()).toBe(200);
    expectApiHeaders(res);
    const { dirseq } = (await res.json()) as { dirseq: number };
    const got = (await (await api(`/api/v2/dir/wraps/${P.b64u(credId)}`)).json()) as { wraps: { dirseq: number; record: string }[] };
    expect(got.wraps.map((x) => [x.dirseq, x.record])).toEqual([[dirseq, w.record]]);
    expect(eq(P.unwrapAK(P.verifyWrap(w.record, w.sig, a.ident.sigPk), cred, a.ident.sigPk), a.AK)).toBe(true);
    const again = await postJsonPow("/api/v2/wraps", "wrap", w);
    expect(again.status).toBe(409);

    const ghost = makeAccount();
    const unknown = await postJsonPow("/api/v2/wraps", "wrap", ghost.passkey);
    expect(unknown.status).toBe(404);
    const other = makeAccount();
    const forged = P.makeWrap(a.uid, "recovery", P.random(16), P.credKem(P.random(32), P.random(16)), a.AK, other.ident, Date.now());
    const bad = await postJsonPow("/api/v2/wraps", "wrap", forged);
    expect(bad.status).toBe(400);
    expect((await postJsonPow("/api/v2/wraps", "wrap", { ...w, x: 1 })).status).toBe(400);
  });
});

describe("directory lookups", () => {
  it("dir/h and dir/u return the users whose prefix matches, ordered by uid and paged with after", async () => {
    const a = makeAccount();
    const dirseq = await registerOk(a);
    const { p: Pnow } = await fetchParams();
    const want: DirUserJson = { uid: a.uidB64, handle: a.handle, bundle: a.bundle, sig: a.sig, regEra: eraNow(), dirseq };
    for (const p of [0, 1, Math.min(32, Pnow + 1)]) {
      expect(await prefixFind("h", p, P.topBits(P.hpre(a.handle), p), a.uidB64), `h p=${p}`).toEqual(want);
      expect(await prefixFind("u", p, P.topBits(P.upre(a.uid), p), a.uidB64), `u p=${p}`).toEqual(want);
    }
    // The other half of the space does not hold it.
    expect(await prefixFind("h", 1, 1 - P.topBits(P.hpre(a.handle), 1), a.uidB64)).toBeNull();
  });

  it("409 {error, p: P} above P + 1 prefix bits; 400 on bad p, x or after", async () => {
    const { p: Pnow } = await fetchParams();
    if (Pnow + 2 <= 32) {
      const res = await api(`/api/v2/dir/h/${Pnow + 2}/0`);
      expect(res.status).toBe(409);
      expectApiHeaders(res);
      const body = (await res.json()) as { error: unknown; p: unknown };
      expect(Object.keys(body)).toEqual(["error", "p"]);
      expect(body).toEqual({ error: "prefix bits out of range", p: Pnow });
      expect((await api(`/api/v2/dir/u/32/0`)).status).toBe(Pnow + 1 >= 32 ? 200 : 409);
    }
    // P + 1 bits are accepted.
    expect((await api(`/api/v2/dir/h/${Math.min(32, Pnow + 1)}/0`)).status).toBe(200);
    for (const path of ["/api/v2/dir/h/33/0", "/api/v2/dir/h/1/2", "/api/v2/dir/u/0/1", "/api/v2/dir/h/01/0", "/api/v2/dir/h/0/00", "/api/v2/dir/h/0/0?after=xyz", `/api/v2/dir/u/0/0?after=${P.b64u(P.random(15))}`]) {
      const res = await api(path);
      expect(res.status, path).toBe(400);
    }
  });

  it("dir/uid: 404 for unknown uids, 400 for malformed ones", async () => {
    const res = await api(`/api/v2/dir/uid/${P.b64u(P.random(16))}`);
    expect(res.status).toBe(404);
    expectApiHeaders(res);
    for (const uid of [P.b64u(P.random(15)), P.b64u(P.random(17)), "a+b", `${"A".repeat(21)}B`]) {
      expect((await api(`/api/v2/dir/uid/${uid}`)).status, uid).toBe(400);
    }
  });

  it("dir/wraps: empty list for unknown ids; 400 on invalid ids or uid", async () => {
    const res = await api(`/api/v2/dir/wraps/${P.b64u(P.random(32))}`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ wraps: [] });
    expect((await api("/api/v2/dir/wraps/a+b")).status).toBe(400);
    expect((await api(`/api/v2/dir/wraps/${P.b64u(P.random(1024))}`)).status).toBe(400); // > 1023 bytes
    expect((await api(`/api/v2/dir/wraps/${P.b64u(P.random(1023))}`)).status).toBe(200);
    expect((await api(`/api/v2/dir/wraps/${P.b64u(P.random(32))}?uid=xyz`)).status).toBe(400);
    expect((await api(`/api/v2/dir/wraps/${P.b64u(P.random(32))}?uid=${P.b64u(P.random(15))}`)).status).toBe(400);
  });

  it("dirlog: the chain recomputes from h_0 = ZERO32 and ends at the head; 400 on bad parameters", async () => {
    await registerOk(makeAccount());
    let after = 0;
    let h: Bytes = P.ZERO32;
    for (let page = 0; page < 10_000; page++) {
      const res = await api(`/api/v2/dirlog?after=${after}&limit=1000`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as { entries: DirlogEntryJson[]; head: { seq: number; h: string } };
      expect(Object.keys(body)).toEqual(["entries", "head"]);
      for (const e of body.entries) {
        expect(e.seq).toBe(after + 1);
        expect([1, 2]).toContain(e.kind);
        h = P.dirlogH(h, e.seq, e.kind, P.fromB64u(e.ref));
        expect(e.h).toBe(P.b64u(h));
        after = e.seq;
      }
      if (body.entries.length === 0 || after >= body.head.seq) {
        expect(body.head).toEqual({ seq: after, h: P.b64u(h) });
        break;
      }
    }
    expect(after).toBeGreaterThanOrEqual(3);
    for (const q of ["limit=0", "limit=1001", "after=-1", "after=x"]) expect((await api(`/api/v2/dirlog?${q}`)).status, q).toBe(400);
  });
});

// ───────────────────────────── blobs ─────────────────────────────

const putBlob = (id: string, blob: BodyInit | Uint8Array | null, headers: Record<string, string> = {}, ip?: string) =>
  api(`/api/v2/blob/${id}`, { method: "PUT", body: blob, headers: { "content-type": "application/octet-stream", ...headers }, ip });

describe("blobs", () => {
  it("PUT then GET; meta HIT; an idempotent PUT returns the original t without reading the body", async () => {
    const { blob, id, key } = P.encryptBlob(P.utf8("pretend this is a webp"));
    const pow = await powHeader("blob", P.fromB64u(id), { bytes: blob.length });
    const before = Date.now();
    const res = await putBlob(id, blob, { "x-segv-pow": pow });
    const after = Date.now();
    expect(res.status, await res.clone().text()).toBe(201);
    expectApiHeaders(res);
    const first = (await res.json()) as { id: string; size: number; t: number };
    expect(Object.keys(first)).toEqual(["id", "size", "t"]);
    expect(first).toMatchObject({ id, size: blob.length });
    expect(first.t).toBeGreaterThanOrEqual(tpub(before));
    expect(first.t).toBeLessThanOrEqual(tpub(after) + 1);

    const meta = await api(`/api/v2/blob/${id}/meta`);
    expect(meta.status).toBe(200);
    expect(meta.headers.get("cache-control")).toBe("no-store");
    expect(await meta.json()).toEqual({ t: first.t, size: blob.length });

    await sleep(1100); // a new registration would get a later t (Δ = 1)
    const again = await putBlob(id, blob, { "x-segv-pow": pow });
    expect(again.status).toBe(201);
    expect(await again.json()).toEqual(first);
    // Registered ids answer without reading the body: other bytes of the same length change nothing.
    const junk = await putBlob(id, P.random(blob.length), { "x-segv-pow": pow });
    expect(junk.status).toBe(201);
    expect(await junk.json()).toEqual(first);

    const get = await api(`/api/v2/blob/${id}`);
    expect(get.status).toBe(200);
    expectApiHeaders(get);
    expect(get.headers.get("content-type")).toBe("application/octet-stream");
    expect(get.headers.get("cache-control")).toBe(IMMUTABLE);
    expect(get.headers.get("content-disposition")).toBe("attachment");
    expect(get.headers.get("content-security-policy")).toBe("default-src 'none'; sandbox");
    expect(get.headers.get("cross-origin-resource-policy")).toBe("same-origin");
    const etag = get.headers.get("etag");
    expect(etag).toBeTruthy();
    const got = await bytesOf(get);
    expect(P.decryptBlob(got, id, key)).toEqual(P.utf8("pretend this is a webp"));

    const notModified = await api(`/api/v2/blob/${id}`, { headers: { "if-none-match": etag! } });
    expect(notModified.status).toBe(304);
    expectApiHeaders(notModified);
    expect((await api(`/api/v2/blob/${id}`, { headers: { "if-none-match": '"other"' } })).status).toBe(200);
    expect((await api(`/api/v2/blob/${id}`, { headers: { "if-match": '"other"' } })).status).toBe(200);
  });

  it("meta: 404 {error: \"unregistered\", now} for an unknown id (no-store)", async () => {
    const before = P.secOf(Date.now());
    const res = await api(`/api/v2/blob/${P.b64u(P.random(32))}/meta`);
    const after = P.secOf(Date.now());
    expect(res.status).toBe(404);
    expectApiHeaders(res);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const body = (await res.json()) as { error: string; now: number };
    expect(Object.keys(body)).toEqual(["error", "now"]);
    expect(body.error).toBe("unregistered");
    expect(body.now).toBeGreaterThanOrEqual(before - 1);
    expect(body.now).toBeLessThanOrEqual(after + 1);
    expect((await api(`/api/v2/blob/${"A".repeat(42)}B/meta`)).status).toBe(400);
  });

  it("400 when the id does not match the content; nothing is stored or registered", async () => {
    const { blob } = P.encryptBlob(P.utf8("a"));
    const wrongId = P.b64u(P.H(P.utf8("something else")));
    const res = await putBlob(wrongId, blob, { "x-segv-pow": await powHeader("blob", P.fromB64u(wrongId), { bytes: blob.length }) });
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toMatch(/does not match/);
    expect((await api(`/api/v2/blob/${wrongId}`)).status).toBe(404);
    expect(await env.BLOBS.head(`b/${wrongId}`)).toBeNull();
    expect((await api(`/api/v2/blob/${wrongId}/meta`)).status).toBe(404);
  });

  it("streams large bodies into R2: a mismatching 3 MiB body is rejected and nothing is stored", async () => {
    const good = bigRandom(3 * 1024 * 1024);
    const id = P.b64u(P.H(good));
    const bad = good.slice();
    bad[bad.length - 1] ^= 1; // differs only in the last byte: the mismatch shows only at the end
    const pow = await powHeader("blob", P.fromB64u(id), { bytes: bad.length });
    const res = await putBlob(id, bad, { "x-segv-pow": pow });
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toMatch(/does not match/);
    expect(await env.BLOBS.head(`b/${id}`)).toBeNull();
    expect((await api(`/api/v2/blob/${id}`)).status).toBe(404);
    expect((await api(`/api/v2/blob/${id}/meta`)).status).toBe(404);
    // The right body with the same PoW goes through.
    const ok = await putBlob(id, good, { "x-segv-pow": pow });
    expect(ok.status, await ok.clone().text()).toBe(201);
    expect((await env.BLOBS.head(`b/${id}`))?.size).toBe(good.length);
    expect(await (await api(`/api/v2/blob/${id}/meta`)).json()).toMatchObject({ size: good.length });
  });

  it("re-uploading registers an object that reached R2 before a crash", async () => {
    const { blob, id } = P.encryptBlob(P.utf8("stored, never registered"));
    await env.BLOBS.put(`b/${id}`, blob, { sha256: P.fromB64u(id).slice().buffer as ArrayBuffer });
    expect((await api(`/api/v2/blob/${id}/meta`)).status).toBe(404);
    const res = await putBlob(id, blob, { "x-segv-pow": await powHeader("blob", P.fromB64u(id), { bytes: blob.length }) });
    expect(res.status, await res.clone().text()).toBe(201);
    const { t } = (await res.json()) as { t: number };
    expect(await (await api(`/api/v2/blob/${id}/meta`)).json()).toEqual({ t, size: blob.length });
  });

  it("blob proof of work is priced by Content-Length above 1 MiB", async () => {
    const data = bigRandom(3 * 1024 * 1024 + 5);
    const id = P.b64u(P.H(data));
    const required = needBits("blob", data.length);
    expect(required).toBe(DIFF2.blob + 2);
    const w = currentWindow();
    const cheap = await putBlob(id, data, { "x-segv-pow": `${w}.${nonceBetween("blob", w, P.fromB64u(id), DIFF2.blob, required)}` });
    expect(cheap.status).toBe(403);
    expect(await errorOf(cheap)).toMatch(new RegExp(`insufficient.*${required} bits`));
    expect(needBits("blob", 1024 * 1024)).toBe(DIFF2.blob);
  });

  it("411 without Content-Length, 413 above BLOB_MAX, 400 below 41 bytes or on bad ids, 404 when absent", async () => {
    const { blob, id } = P.encryptBlob(P.utf8("b"));
    const pow = await powHeader("blob", P.fromB64u(id), { bytes: blob.length });
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(blob);
        c.close();
      },
    });
    const noLen = await putBlob(id, stream, { "x-segv-pow": pow });
    expect(noLen.status).toBe(411);
    expectApiHeaders(noLen);

    const huge = new Uint8Array(P.BLOB_MAX + 1);
    const hugeId = P.b64u(P.H(huge));
    expect((await putBlob(hugeId, huge, { "x-segv-pow": "0.0" })).status).toBe(413);
    const tiny = P.random(P.BLOB_MIN - 1);
    expect(P.BLOB_MIN).toBe(41);
    expect((await putBlob(P.b64u(P.H(tiny)), tiny, { "x-segv-pow": "0.0" })).status).toBe(400);

    expect((await putBlob("short", blob)).status).toBe(400);
    expect((await api(`/api/v2/blob/${"A".repeat(42)}B`)).status).toBe(400); // non-canonical 43 chars
    expect((await api(`/api/v2/blob/${P.b64u(P.random(32))}x`)).status).toBe(400);
    const absent = await api(`/api/v2/blob/${P.b64u(P.random(32))}`);
    expect(absent.status).toBe(404);
    expectApiHeaders(absent);
  });

  it("If-None-Match on an uncached blob: a malformed value is ignored (200), never a 500", async () => {
    /** A fresh object in R2 only (not in caches.default, so the GET reaches R2). */
    const fresh = async () => {
      const { blob, id } = P.encryptBlob(P.random(16));
      await env.BLOBS.put(`b/${id}`, blob, { sha256: P.fromB64u(id).slice().buffer as ArrayBuffer });
      return { id, etag: (await env.BLOBS.head(`b/${id}`))!.httpEtag };
    };
    const cases: [inm: (etag: string) => string, status: number][] = [
      [() => "garbage", 200],
      [() => "\u0001", 200],
      [() => 'w/"a"', 200],
      [() => 'W/ "a"', 200],
      [() => '"a" "b"', 200],
      [(e) => `* , ${e}`, 200],
      [() => '"other"', 200],
      [() => '"a", W/"b"', 200],
      [(e) => e, 304],
      [(e) => `W/${e}`, 304],
      [(e) => `"a",\t${e}`, 304],
      [(e) => `, "a", , ${e},`, 304],
      [() => "*", 304],
    ];
    const logs: unknown[][] = [];
    const consoleError = console.error;
    console.error = (...a: unknown[]) => void logs.push(a);
    try {
      for (const [inm, status] of cases) {
        const { id, etag } = await fresh();
        const res = await api(`/api/v2/blob/${id}`, { headers: { "if-none-match": inm(etag) } });
        expect(res.status, JSON.stringify(inm(etag))).toBe(status);
        if (status === 304) expect(res.headers.get("etag")).toBe(etag);
      }
    } finally {
      console.error = consoleError;
    }
    expect(logs).toEqual([]);
  });

  it("a body shorter or longer than its Content-Length is 400 / 413 (not an internal error); nothing is stored", async () => {
    const logs: unknown[][] = [];
    const consoleError = console.error;
    console.error = (...a: unknown[]) => void logs.push(a);
    try {
      for (const [extra, status] of [
        [-10, 400],
        [10, 413],
        [-1000, 400],
      ] as const) {
        const blob = P.random(1000);
        const id = P.b64u(P.H(blob));
        const sent = extra < 0 ? blob.slice(0, blob.length + extra) : P.concat(blob, P.random(extra));
        const body = new ReadableStream<Uint8Array>({
          start(c) {
            if (sent.length > 0) c.enqueue(sent);
            c.close();
          },
        });
        const pow = await powHeader("blob", P.fromB64u(id), { bytes: blob.length });
        const res = await direct(`/api/v2/blob/${id}`, {
          method: "PUT",
          body,
          headers: { "content-type": "application/octet-stream", "content-length": String(blob.length), "x-segv-pow": pow },
        });
        expect(res.status, `${extra} bytes`).toBe(status);
        expectApiHeaders(res);
        expect(await errorOf(res)).toBe("body length does not match content-length");
        expect(await env.BLOBS.head(`b/${id}`)).toBeNull();
        expect((await api(`/api/v2/blob/${id}/meta`)).status).toBe(404);
      }
    } finally {
      console.error = consoleError;
    }
    expect(logs).toEqual([]);
  });

  it("a client that disconnects mid-upload gets 400 (not an internal error); nothing is stored or logged", async () => {
    const logs: unknown[][] = [];
    const consoleError = console.error;
    console.error = (...a: unknown[]) => void logs.push(a);
    try {
      const blob = P.random(1000);
      const id = P.b64u(P.H(blob));
      const body = new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(blob.slice(0, 500));
          // workerd's message when the client goes away while the body is being read
          c.error(new TypeError("Can't read from request stream because client disconnected."));
        },
      });
      const pow = await powHeader("blob", P.fromB64u(id), { bytes: blob.length });
      const res = await direct(`/api/v2/blob/${id}`, {
        method: "PUT",
        body,
        headers: { "content-type": "application/octet-stream", "content-length": String(blob.length), "x-segv-pow": pow },
      });
      expect(res.status).toBe(400);
      expect(await errorOf(res)).toBe("request body was not received");
      expect(await env.BLOBS.head(`b/${id}`)).toBeNull();
    } finally {
      console.error = consoleError;
    }
    expect(logs).toEqual([]);
  });
});

// ───────────────────────────── proof of work ─────────────────────────────

interface PowTarget {
  scope: P.PowScope;
  path: string;
  method: string;
  bytes: Bytes;
  digest: Bytes;
}

async function powTargets(): Promise<PowTarget[]> {
  const put = W.encodePutRequest([makeRow()]);
  const inbox = W.encodeInboxPost({ E: eraNow(), bucket: 0, rows: [randomInvite()] });
  const register = jsonBytes(registerBody(makeAccount()));
  const wrap = jsonBytes(makeAccount().passkey);
  const { blob, id } = P.encryptBlob(P.utf8("pow"));
  return [
    { scope: "put", path: "/api/v2/put", method: "POST", bytes: put, digest: P.H(put) },
    { scope: "inbox", path: "/api/v2/inbox", method: "POST", bytes: inbox, digest: P.H(inbox) },
    { scope: "register", path: "/api/v2/register", method: "POST", bytes: register, digest: P.H(register) },
    { scope: "wrap", path: "/api/v2/wraps", method: "POST", bytes: wrap, digest: P.H(wrap) },
    { scope: "blob", path: `/api/v2/blob/${id}`, method: "PUT", bytes: blob, digest: P.fromB64u(id) },
  ];
}

/** A nonce valid at `difficulty` for `pre` but not for `notPre`. */
function nonceFor(pre: Bytes, notPre: Bytes, difficulty: number): number {
  if (P.equalBytes(pre, notPre)) throw new Error("nonceFor: identical prefixes");
  for (let n = 0; n < 1e7; n++) if (P.powCheck(pre, n, difficulty) && !P.powCheck(notPre, n, difficulty)) return n;
  throw new Error("nonceFor: none found");
}

describe("proof of work", () => {
  it("403 when missing, malformed, stale, future, insufficient, for another scope or another body (every scope)", async () => {
    for (const t of await powTargets()) {
      const w = currentWindow();
      const need = needBits(t.scope, t.bytes.length);
      const pre = P.powPre(t.scope, w, t.digest);
      const otherScope = t.scope === "put" ? "inbox" : "put";
      const cases: [string, string | undefined, RegExp][] = [
        ["missing", undefined, /missing/],
        ["malformed", "abc", /malformed/],
        ["no nonce", `${w}.`, /malformed/],
        ["negative", `${w}.-1`, /malformed/],
        ["three parts", `${w}.1.2`, /malformed/],
        ["17-digit nonce", `${w}.${"1".repeat(17)}`, /malformed/],
        ["stale", await powHeader(t.scope, t.digest, { window: w - 2, difficulty: need }), /stale/],
        ["future", await powHeader(t.scope, t.digest, { window: w + 1, difficulty: need }), /stale/],
        ["insufficient", `${w}.${badNonce(t.scope, w, t.digest, need)}`, /insufficient/],
        ["wrong scope", `${w}.${nonceFor(P.powPre(otherScope, w, t.digest), pre, need)}`, /insufficient/],
        ["wrong body", `${w}.${nonceFor(P.powPre(t.scope, w, P.H(P.random(32))), pre, need)}`, /insufficient/],
      ];
      for (const [name, pow, msg] of cases) {
        const res = await api(t.path, {
          method: t.method,
          body: t.bytes,
          headers: pow === undefined ? { "content-type": "application/octet-stream" } : { "content-type": "application/octet-stream", "x-segv-pow": pow },
        });
        expect(res.status, `${t.scope}: ${name}`).toBe(403);
        expectApiHeaders(res);
        expect(await errorOf(res), `${t.scope}: ${name}`).toMatch(msg);
      }
    }
  });

  it("blob PoW is over the raw 32-byte id (= H(blob)), not over H(id) or the id's text", async () => {
    const { blob, id } = P.encryptBlob(P.utf8("c"));
    const w = currentWindow();
    const raw = P.powPre("blob", w, P.fromB64u(id));
    expect(eq(P.H(blob), P.fromB64u(id))).toBe(true);
    for (const digest of [P.H(P.fromB64u(id)), P.utf8(id)]) {
      const n = nonceFor(P.powPre("blob", w, digest), raw, DIFF2.blob);
      const res = await putBlob(id, blob, { "x-segv-pow": `${w}.${n}` });
      expect(res.status).toBe(403);
      expect(await errorOf(res)).toMatch(/insufficient/);
    }
    const ok = await putBlob(id, blob, { "x-segv-pow": await powHeader("blob", P.fromB64u(id), { bytes: blob.length }) });
    expect(ok.status).toBe(201);
  });

  it("accepts the previous window (put and inbox)", async () => {
    const put = W.encodePutRequest([makeRow()]);
    const res = await api("/api/v2/put", {
      method: "POST",
      body: put,
      headers: { "x-segv-pow": await powHeader("put", P.H(put), { window: currentWindow() - 1, bytes: put.length }) },
    });
    expect(res.status).toBe(200);
    expect(W.decodePutResponse(await bytesOf(res))[0].s).toBe("ok");
    const inbox = W.encodeInboxPost({ E: eraNow(), bucket: 0, rows: [randomInvite()] });
    const res2 = await api("/api/v2/inbox", {
      method: "POST",
      body: inbox,
      headers: { "x-segv-pow": await powHeader("inbox", P.H(inbox), { window: currentWindow() - 1, bytes: inbox.length }) },
    });
    expect(res2.status).toBe(200);
  });

  it("nothing is stored after a refused put", async () => {
    const row = makeRow();
    const bytes = W.encodePutRequest([row]);
    expect((await api("/api/v2/put", { method: "POST", body: bytes })).status).toBe(403);
    expect(await getKeys([{ E: row.E, label: row.label, mode: 1 }])).toEqual([{ s: "miss", sealed: false }]);
  });
});

// ───────────────────────────── rate limiting ─────────────────────────────

describe("rate limiting", () => {
  it("429 once an IP exceeds the blob budget (20/min); other IPs are unaffected", async () => {
    const id = P.b64u(P.random(32));
    const { statuses, last } = await inOneRateWindow(async () => {
      const ip = freshIp();
      const statuses: number[] = [];
      for (let i = 0; i < 21; i++) statuses.push((await putBlob(id, new Uint8Array(64), {}, ip)).status);
      return { statuses, last: await putBlob(id, new Uint8Array(64), {}, ip) };
    });
    expect(statuses.slice(0, 20).every((s) => s === 403)).toBe(true); // no PoW
    expect(statuses[20]).toBe(429);
    expect(last.status).toBe(429);
    expect(last.headers.get("retry-after")).toBe("60");
    expectApiHeaders(last);
    expect((await putBlob(id, new Uint8Array(64))).status).toBe(403);
  });

  it("IPv6 clients share a budget per /64", async () => {
    const id = P.b64u(P.random(32));
    const statuses = await inOneRateWindow(async () => {
      const prefix = `2001:db8:${((Math.random() * 0xffff) | 0).toString(16)}:1`;
      const statuses: number[] = [];
      for (let i = 0; i < 21; i++) statuses.push((await putBlob(id, new Uint8Array(64), {}, `${prefix}::${(i + 1).toString(16)}`)).status);
      return statuses;
    });
    expect(statuses[20]).toBe(429);
  });

  it("RL_INBOX: 10 posts per minute per IP, one token per request", async () => {
    const body = W.encodeInboxPost({ E: eraNow(), bucket: 0, rows: Array.from({ length: 2 }, randomInvite) });
    const statuses = await inOneRateWindow(async () => {
      const ip = freshIp();
      const statuses: number[] = [];
      for (let i = 0; i < 11; i++) statuses.push((await api("/api/v2/inbox", { method: "POST", body, ip })).status);
      return statuses;
    });
    expect(statuses.slice(0, 10).every((s) => s === 403)).toBe(true);
    expect(statuses[10]).toBe(429);
    expect((await api("/api/v2/inbox", { method: "POST", body })).status).toBe(403);
  });

  it("RL_WRITE is shared by put, register and wraps (60/min)", async () => {
    const put = W.encodePutRequest([makeRow()]);
    const { statuses, over } = await inOneRateWindow(async () => {
      const ip = freshIp();
      const statuses: number[] = [];
      for (let i = 0; i < 60; i++) {
        const path = ["/api/v2/put", "/api/v2/register", "/api/v2/wraps"][i % 3];
        statuses.push((await api(path, { method: "POST", body: put, ip })).status);
      }
      return { statuses, over: (await api("/api/v2/register", { method: "POST", body: put, ip })).status };
    });
    expect(statuses.every((s) => s === 403)).toBe(true);
    expect(over).toBe(429);
    expect((await api("/api/v2/put", { method: "POST", body: put })).status).toBe(403);
  });

  it("RL_READ: 600 reads per minute per IP; params are never rate limited", async () => {
    const E = eraNow();
    const { ip, statuses, dir } = await inOneRateWindow(async () => {
      const ip = freshIp();
      const statuses: number[] = [];
      for (let i = 0; i < 601; i++) statuses.push((await api(`/api/v2/era/${E}`, { ip })).status);
      return { ip, statuses, dir: (await api(`/api/v2/dir/uid/${P.b64u(P.random(16))}`, { ip })).status };
    });
    expect(statuses.slice(0, 600).every((s) => s === 200)).toBe(true);
    expect(statuses[600]).toBe(429);
    expect(dir).toBe(429);
    expect((await api("/api/v2/params", { ip })).status).toBe(200);
  });

  it("a failing rate limiter fails closed with 503", async () => {
    const broken = { limit: async () => Promise.reject(new Error("limiter down")) };
    const res = await direct("/api/v2/put", { method: "POST", body: W.encodePutRequest([makeRow()]) }, { RL_WRITE: broken });
    expect(res.status).toBe(503);
    expect(res.headers.get("retry-after")).toBe("10");
    expect(await errorOf(res)).toMatch(/rate limiter/);
  });
});

// ───────────────────────────── realtime ─────────────────────────────

/** SUB, then put probe rows on topics[0] until one is delivered (there is no SUB acknowledgement). */
async function subscribed(c: RtClient, topics: Bytes[]): Promise<void> {
  expect(eq(topics[0], P.ZERO16)).toBe(false);
  c.send({ f: "sub", topics });
  for (let i = 0; i < 20; i++) {
    const probe = makeRow({ topic: topics[0] });
    await putOk([probe]);
    try {
      await c.until(() => c.rows().some((r) => eq(r.label, probe.label)), "probe", 500);
      return;
    } catch {
      /* the SUB was not processed yet: try again */
    }
  }
  throw new Error("subscription never took effect");
}

/** Runs `fn` inside the production RealtimeDO instance ("rt/v2/0"), with its test-visible fields. */
type RtInner = { clock: () => number; limits: RtLimits };
const rtInside = (fn: (i: RtInner, state: DurableObjectState) => void) =>
  runInDurableObject((env.RT as unknown as DurableObjectNamespace<RealtimeDO>).getByName("rt/v2/0"), (inst: RealtimeDO, state) =>
    fn(inst as unknown as RtInner, state),
  );

const expectClosedWith = async (c: RtClient, code: number) => {
  await c.until(() => c.closed() !== null, "close");
  expect(c.closed()!.code).toBe(code);
};

describe("GET /api/v2/rt", () => {
  it("426 without an upgrade", async () => {
    const res = await api("/api/v2/rt");
    expect(res.status).toBe(426);
    expectApiHeaders(res);
    expect(await errorOf(res)).toMatch(/websocket/);
  });

  it("checks Origin: same host or none (non-browser clients) only", async () => {
    for (const origin of ["https://evil.example", "null", "https://segv.test.evil.example", "http://segv.test:8080", "garbage"]) {
      const res = await rtUpgrade({ origin });
      expect(res.status, origin).toBe(403);
      expectApiHeaders(res);
      expect(await errorOf(res)).toMatch(/cross-origin/);
    }
    for (const origin of [ORIGIN, "http://segv.test", null]) {
      const c = await openRt({ origin });
      c.close();
    }
  });

  it("sends HELLO first; answers ping with pong", async () => {
    const before = Date.now();
    const c = await openRt();
    try {
      expect(c.frames[0].f).toBe("hello");
      expect(c.hello!.boot).toHaveLength(8);
      expect(c.hello!.now).toBeGreaterThanOrEqual(before - 1000);
      expect(c.hello!.now).toBeLessThanOrEqual(Date.now() + 1000);
      c.send("ping");
      await c.until(() => c.texts.includes("pong"), "pong");
      expect(c.closed()).toBeNull();
    } finally {
      c.close();
    }
  });

  it("closes with 1008 on any other frame (text, malformed, oversized, > 256 topics, misplaced or repeated RESUME)", async () => {
    const topics = (n: number) => Array.from({ length: n }, randomTopic);
    const sub = (n: number) => P.concat(Uint8Array.of(0x01, n >> 8, n & 0xff), ...topics(n));
    const cases: [string, (c: RtClient) => void][] = [
      ["text", (c) => c.send("hello")],
      ["unknown op", (c) => c.send(Uint8Array.of(0x09))],
      ["server frame", (c) => c.send(Uint8Array.of(0x83))],
      ["SUB of 0 topics", (c) => c.send(Uint8Array.of(0x01, 0, 0))],
      ["truncated UNSUB", (c) => c.send(Uint8Array.of(0x02, 0, 1, 1, 2, 3))],
      ["SUB with a trailing byte", (c) => c.send(P.concat(sub(1), Uint8Array.of(0)))],
      ["SUB of 257 topics", (c) => c.send(sub(257))],
      ["frame over 8 KiB", (c) => c.send(P.concat(sub(256), new Uint8Array(8 * 1024 + 1 - sub(256).length + 16)))],
      [
        "257 topics on the socket",
        (c) => {
          c.send({ f: "sub", topics: topics(200) });
          c.send({ f: "sub", topics: topics(57) });
        },
      ],
      [
        "RESUME after SUB",
        (c) => {
          c.send({ f: "sub", topics: topics(1) });
          c.send({ f: "resume", boot: c.hello!.boot, since: c.hello!.seq, topics: [] });
        },
      ],
      [
        "second RESUME",
        (c) => {
          c.send({ f: "resume", boot: c.hello!.boot, since: c.hello!.seq, topics: topics(1) });
          c.send({ f: "resume", boot: c.hello!.boot, since: c.hello!.seq, topics: topics(1) });
        },
      ],
    ];
    for (const [name, act] of cases) {
      const c = await openRt();
      act(c);
      await c.until(() => c.closed() !== null, `close after ${name}`);
      expect(c.closed()!.code, name).toBe(1008);
    }
  });

  it("caps sockets per client (opaque tag; IPv6 by /64); closing frees a slot", async () => {
    for (const ipOf of [() => "10.250.1.7".replace("1.7", `${(Math.random() * 250) | 0}.${(Math.random() * 250) | 0}`), () => `2001:db8:77:${((Math.random() * 0xffff) | 0).toString(16)}::`]) {
      const base = ipOf();
      const ip = (i: number) => (base.endsWith("::") ? `${base}${(i + 1).toString(16)}` : base);
      const open: RtClient[] = [];
      try {
        for (let i = 0; i < 8; i++) open.push(await openRt({ ip: ip(i) }));
        const ninth = await rtUpgrade({ ip: ip(8) });
        expect(ninth.status).toBe(429);
        expect(ninth.headers.get("retry-after")).toBe("60");
        expectApiHeaders(ninth);
        const other = await openRt();
        other.close();
      } finally {
        for (const c of open) c.close();
      }
      let again = 0;
      for (let i = 0; i < 100 && again !== 101; i++) {
        const res = await rtUpgrade({ ip: ip(9) });
        again = res.status;
        if (again === 101) {
          const c = rtClient(res.webSocket!);
          c.close();
        } else await sleep(20);
      }
      expect(again).toBe(101);
    }
  });

  it("relays the global socket cap as 503 with retry-after", async () => {
    const keep = await openRt();
    try {
      await rtInside((i, state) => void (i.limits.total = state.getWebSockets().filter((w) => w.readyState === WebSocket.OPEN).length));
      const full = await rtUpgrade();
      expect(full.status).toBe(503);
      expect(full.headers.get("retry-after")).toBe("60");
      expectApiHeaders(full);
      expect(typeof (await errorOf(full))).toBe("string");
    } finally {
      await rtInside((i) => void (i.limits.total = 20_000));
      keep.close();
    }
    (await openRt()).close();
  });

  it("closes sockets older than 1 h with 4000 before delivering to them", async () => {
    const T = randomTopic();
    const old = await openRt();
    try {
      await subscribed(old, [T]);
      const later = Date.now() + 2 * 3_600_000;
      await rtInside((i) => void (i.clock = () => later));
      const row = makeRow({ topic: T });
      await putOk([row]);
      await expectClosedWith(old, 4000);
      expect(old.rows().some((r) => eq(r.label, row.label))).toBe(false);
    } finally {
      await rtInside((i) => void (i.clock = () => Date.now()));
      old.close();
    }
    // A fresh socket gets the next row.
    const fresh = await openRt();
    try {
      await subscribed(fresh, [T]);
      expect(fresh.closed()).toBeNull();
    } finally {
      fresh.close();
    }
  });

  it("SUB-filtered delivery end to end through put; UNSUB stops it", async () => {
    const [Ta, Tb, Tc] = [randomTopic(), randomTopic(), randomTopic()];
    const a = await openRt();
    const b = await openRt();
    try {
      await subscribed(a, [Ta, Tc]);
      await subscribed(b, [Tb]);
      const rows = [makeRow({ topic: Ta }), makeRow({ topic: Tb, cls: 2 }), makeRow({ topic: Tc }), makeRow({ topic: randomTopic() }), makeRow()];
      const out = await putOk(rows);
      await a.until(() => [0, 2].every((i) => a.rows().some((r) => eq(r.label, rows[i].label))), "a's rows");
      await b.until(() => b.rows().some((r) => eq(r.label, rows[1].label)), "b's row");
      await sleep(200);
      const labels = (c: RtClient) => c.rows().map((r) => P.b64u(r.label));
      for (const i of [1, 3, 4]) expect(labels(a)).not.toContain(P.b64u(rows[i].label));
      for (const i of [0, 2, 3, 4]) expect(labels(b)).not.toContain(P.b64u(rows[i].label));
      const got = b.rows().find((r) => eq(r.label, rows[1].label))!;
      expect(got).toMatchObject({ topic: Tb, E: rows[1].E, t: out[1].t, cls: 2, body: rows[1].body });
      // Sequence numbers strictly increase on each socket.
      for (const c of [a, b]) {
        const seqs = c.rows().map((r) => r.seq);
        for (let k = 1; k < seqs.length; k++) expect(seqs[k]).toBeGreaterThan(seqs[k - 1]);
      }
      // UNSUB Ta: later Ta rows are no longer delivered, Tc rows still are.
      a.send({ f: "unsub", topics: [Ta] });
      for (let i = 0; i < 20; i++) {
        const [ra, rc] = [makeRow({ topic: Ta }), makeRow({ topic: Tc })];
        await putOk([ra, rc]);
        await a.until(() => a.rows().some((r) => eq(r.label, rc.label)), "Tc row");
        if (!a.rows().some((r) => eq(r.label, ra.label))) break; // the UNSUB took effect
        expect(i, "UNSUB never took effect").toBeLessThan(19);
      }
      expect(a.closed()).toBeNull();
      expect(b.closed()).toBeNull();
    } finally {
      a.close();
      b.close();
    }
  });

  it("RESUME replays the rows of its topics published since `since`, then RESUMED; an unknown boot gets GAP", async () => {
    const T = randomTopic();
    const first = await openRt();
    const since = first.hello!.seq;
    const boot = first.hello!.boot;
    let row: W.PutRow;
    try {
      await subscribed(first, [T]);
      row = makeRow({ topic: T, cls: 1 });
      const [{ t }] = await putOk([row, makeRow({ topic: randomTopic() })]);
      await first.until(() => first.rows().some((r) => eq(r.label, row.label)), "live row");
      expect(first.rows().find((r) => eq(r.label, row.label))!.t).toBe(t);
    } finally {
      first.close();
    }
    const second = await openRt();
    try {
      second.send({ f: "resume", boot, since, topics: [T] });
      await second.until(() => second.frames.some((f) => f.f === "resumed"), "RESUMED");
      const replay = second.rows();
      expect(replay.some((r) => eq(r.label, row.label))).toBe(true);
      expect(replay.every((r) => eq(r.topic, T) && r.seq > since)).toBe(true);
      const iResumed = second.frames.findIndex((f) => f.f === "resumed");
      expect(second.frames.slice(iResumed + 1).some((f) => f.f === "rows" && f.rows.some((r) => eq(r.label, row.label)))).toBe(false);
    } finally {
      second.close();
    }
    const third = await openRt();
    try {
      const otherBoot = boot.slice();
      otherBoot[0] ^= 0xff;
      third.send({ f: "resume", boot: otherBoot, since: 5, topics: [T] });
      await third.until(() => third.frames.some((f) => f.f === "gap"), "GAP");
      expect(third.frames.find((f) => f.f === "gap")).toEqual({ f: "gap", since: 5 });
      expect(third.closed()).toBeNull();
    } finally {
      third.close();
    }
  });
});

// ───────────────────────────── hosts, HSTS, secrets ─────────────────────────────

describe("hosts, HSTS and server secrets", () => {
  it("other hosts: 421 on /api/v2/*; listed hosts are served", async () => {
    const before = Date.now();
    const res = await api("/api/v2/params", { origin: "https://segv-sh.someone.workers.dev" });
    expect(res.status).toBe(421);
    // §10.1: the 421 carries x-segv-now like every /api/v2/* response (and HSTS over https).
    expect(nowOf(res)).toBeGreaterThanOrEqual(before);
    expect(nowOf(res)).toBeLessThanOrEqual(Date.now());
    expect(res.headers.get("strict-transport-security")).toBe(HSTS);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await errorOf(res)).toMatch(/segv\.test/);
    const put = await api("/api/v2/put", { method: "POST", origin: "http://evil.example", body: new Uint8Array(3) });
    expect(put.status).toBe(421);
    nowOf(put);
    expect(put.headers.get("strict-transport-security")).toBeNull();
    expect((await api("/api/v2/params", { origin: "http://localhost:8787" })).status).toBe(200);
    // Every /api/* path is answered by the same router (a non-v2 path is a 404 on a listed host).
    const other = await api("/api/log", { origin: "https://evil.example" });
    expect(other.status).toBe(421);
    nowOf(other);
    const nf = await api("/api/log");
    expect(nf.status).toBe(404);
    expect(await errorOf(nf)).toBe("not found");
    nowOf(nf);
  });

  it("HSTS only over https; nosniff and no-referrer on every response", async () => {
    expectApiHeaders(await api("/api/v2/params"));
    expectApiHeaders(await api("/api/v2/nope"));
    const http = await api("/api/v2/params", { origin: "http://localhost:8787" });
    expect(http.headers.get("strict-transport-security")).toBeNull();
    expect(http.headers.get("x-content-type-options")).toBe("nosniff");
    expect(http.headers.get("referrer-policy")).toBe("no-referrer");
    nowOf(http);
  });

  it("503 \"server misconfigured\" when ROUTE_KEY or SRV_KEY is missing or malformed", async () => {
    const bad = [{ ROUTE_KEY: undefined }, { SRV_KEY: undefined }, { ROUTE_KEY: "" }, { SRV_KEY: P.b64u(P.random(31)) }, { ROUTE_KEY: `${env.ROUTE_KEY}=` }];
    for (const over of bad) {
      for (const [path, init] of [
        ["/api/v2/params", {}],
        ["/api/v2/put", { method: "POST", body: W.encodePutRequest([makeRow()]) }],
        ["/api/v2/nope", {}],
      ] as const) {
        const res = await direct(path, init as ApiInit, over);
        expect(res.status, `${JSON.stringify(over)} ${path}`).toBe(503);
        expectApiHeaders(res);
        expect(await errorOf(res)).toBe("server misconfigured");
      }
    }
    expect((await direct("/api/v2/params")).status).toBe(200);
  });

  it("503 \"server misconfigured\" when a deployment var is present but invalid; DELTA_S must divide 604 800", async () => {
    const bad: Record<string, unknown>[] = [
      { DELTA_S: "11" }, // 604 800 mod 11 = 9: the first rows of an era would not sit on a Δ boundary (§6.4(g))
      { DELTA_S: "3599" },
      { DELTA_S: "0" },
      { DELTA_S: "3601" },
      { DELTA_S: "ten" },
      { DELTA_S: "" },
      { DELTA_S: 2.5 },
      { SKEW_S: "61" },
      { INBOX_SLOT_S: "0" },
      { E_FIRST: "65535" },
      { E_FIRST: "-1" },
    ];
    for (const over of bad) {
      for (const [path, init] of [
        ["/api/v2/params", {}],
        ["/api/v2/put", { method: "POST", body: W.encodePutRequest([makeRow()]) }],
      ] as const) {
        const res = await direct(path, init as ApiInit, over);
        expect(res.status, `${JSON.stringify(over)} ${path}`).toBe(503);
        expectApiHeaders(res);
        expect(await errorOf(res)).toBe("server misconfigured");
      }
    }
    const good: [Record<string, unknown>, number][] = [
      [{ DELTA_S: "7" }, 7],
      [{ DELTA_S: "3600" }, 3600],
      [{ DELTA_S: 60 }, 60],
      [{ DELTA_S: undefined }, 10], // absent: the default
    ];
    for (const [over, delta] of good) {
      const res = await direct("/api/v2/params", {}, over);
      expect(res.status, JSON.stringify(over)).toBe(200);
      expect(((await res.json()) as { delta: number }).delta).toBe(delta);
    }
    // The Durable Objects never run with an invalid var either: v2Params falls back to the default.
    const { v2Params, v2ParamsValid } = await import("../src/env");
    const fallback = { ...env, DELTA_S: "11", SKEW_S: "61" } as unknown as Env;
    expect(v2ParamsValid(fallback)).toBe(false);
    expect(v2Params(fallback)).toMatchObject({ delta: 10, skew: 2 });
    expect(v2ParamsValid(env)).toBe(true);
  });
});

// ───────────────────────────── era bounds ─────────────────────────────

describe("era bounds (§9.7): no Durable Object for out-of-range eras", () => {
  it("put and inbox posts with E = 65000 or E = 0 are answered without creating a DO", async () => {
    const E = eraNow();
    const calls: string[] = [];
    const spies = { SHARD: spyNamespace(env.SHARD, calls), INBOX: spyNamespace(env.INBOX, calls), RT: spyNamespace(env.RT, calls) };
    const put = W.encodePutRequest([makeRow({ E: 65000, topic: randomTopic() }), makeRow({ E: 0, topic: randomTopic() })]);
    const res = await direct("/api/v2/put", await powInit("put", put), spies);
    expect(res.status).toBe(200);
    expect(W.decodePutResponse(await bytesOf(res))).toEqual([
      { s: "wrong_era", era: E },
      { s: "wrong_era", era: E },
    ]);
    // Inbox posts: 409 {error: "wrong era", era} outside [era(now − SKEW), era(now + SKEW)] (SKEW = 0 here).
    for (const e of [65000, 0, E + 1, E - 1]) {
      const post = W.encodeInboxPost({ E: e, bucket: 0, rows: [randomInvite()] });
      const r = await direct("/api/v2/inbox", await powInit("inbox", post), spies);
      expect(r.status, String(e)).toBe(409);
      expect(await r.json()).toEqual({ error: "wrong era", era: E });
    }
    expect(calls).toEqual([]);
  });

  it("get, feed, era and inbox reads outside the bounds are answered without creating a DO", async () => {
    const calls: string[] = [];
    const spies = { SHARD: spyNamespace(env.SHARD, calls), INBOX: spyNamespace(env.INBOX, calls) };
    const label = randomLabel();
    const get = await direct(
      "/api/v2/get",
      {
        method: "POST",
        body: W.encodeGetRequest([
          { E: 0, label, mode: 0 },
          { E: 65000, label, mode: 0 },
        ]),
      },
      spies,
    );
    expect(W.decodeGetResponse(await bytesOf(get), [0, 0])).toEqual([{ s: "miss", sealed: true }, { s: "no_era" }]);
    const expectStatus = async (path: string, status: number) => expect((await direct(path, {}, spies)).status, path).toBe(status);
    await expectStatus("/api/v2/feed/65000/0", 404);
    await expectStatus("/api/v2/feed/0/0", 404);
    await expectStatus("/api/v2/era/65000", 404);
    await expectStatus("/api/v2/era/0", 404);
    await expectStatus("/api/v2/inbox/65000/0", 400);
    await expectStatus("/api/v2/inbox/0/0", 410); // below E_now − 3 (and E_FIRST)
    expect(calls).toEqual([]);
  });
});

// ───────────────────────────── server time and caching ─────────────────────────────

describe("server time (x-segv-now) and cache before limits", () => {
  it("every v2 response except the 101 upgrade carries x-segv-now, nosniff, no-referrer and HSTS (JSON and binary, every route family)", async () => {
    const E = eraNow();
    const before = Date.now();
    const responses: [string, Response][] = [
      ["params", await api("/api/v2/params")],
      ["era", await api(`/api/v2/era/${E}`)],
      ["200 put (binary)", await putRaw([makeRow()])],
      ["200 get (binary)", await getRaw([{ E, label: randomLabel(), mode: 1 }])],
      ["200 inbox read (binary, public)", await inboxReadRaw(E, `?after=${Math.floor(Math.random() * 1e9)}`)],
      ["200 feed (binary)", await api(`/api/v2/feed/${E}/0?after=4294967295`)],
      ["421", await api("/api/v2/params", { origin: "https://elsewhere.example" })],
      ["404", await api("/api/v2/nope")],
      ["405", await api("/api/v2/params", { method: "POST", body: new Uint8Array(1) })],
      ["403 put", await api("/api/v2/put", { method: "POST", body: new Uint8Array(3) })],
      ["400 get", await getRaw(new Uint8Array(1))],
      ["413 put", await api("/api/v2/put", { method: "POST", body: new Uint8Array(W.PUT_MAX_BYTES + 1) })],
      ["426 rt", await api("/api/v2/rt")],
      ["410 inbox", await inboxReadRaw(E - 4)],
      ["400 inbox", await inboxReadRaw(E + 1)],
      ["409 inbox", await direct("/api/v2/inbox", await powInit("inbox", W.encodeInboxPost({ E: 65000, bucket: 0, rows: [randomInvite()] })))],
      ["400 dir", await api("/api/v2/dir/h/33/0")],
      ["404 blob", await api(`/api/v2/blob/${P.b64u(P.random(32))}`)],
      ["404 feed", await api("/api/v2/feed/0/0")],
      ["429", await direct(`/api/v2/era/${E}`, {}, { RL_READ: { limit: async () => ({ success: false }) } })],
      ["503", await direct("/api/v2/params", {}, { SRV_KEY: undefined })],
    ];
    const after = Date.now();
    for (const [name, res] of responses) {
      const now = nowOf(res);
      expect(now, name).toBeGreaterThanOrEqual(before);
      expect(now, name).toBeLessThanOrEqual(after);
      expect(res.headers.get("x-content-type-options"), name).toBe("nosniff");
      expect(res.headers.get("referrer-policy"), name).toBe("no-referrer");
      expect(res.headers.get("strict-transport-security"), name).toBe(HSTS);
      if (res.status >= 400) expect(res.headers.get("cache-control"), name).toBe("no-store");
      await res.body?.cancel();
    }
  });

  it("the 101 upgrade is returned exactly as the RealtimeDO built it: no x-segv-now, HSTS, nosniff or no-referrer", async () => {
    const PER_RESPONSE = ["x-segv-now", "strict-transport-security", "x-content-type-options", "referrer-policy"];
    // Through the Worker entry and the real RealtimeDO: HELLO carries the server time instead.
    const res = await rtUpgrade();
    expect(res.status).toBe(101);
    for (const h of PER_RESPONSE) expect(res.headers.get(h), h).toBeNull();
    const c = rtClient(res.webSocket!);
    try {
      await c.until(() => c.hello !== null, "HELLO");
      expect(c.hello!.now).toBeGreaterThan(0);
    } finally {
      c.close();
    }
    // handleApi hands back the very Response object the RealtimeDO returned, its headers untouched.
    _resetApiForTests();
    let built: Response | undefined;
    const RT = fakeNs({
      wsTagKey: async () => new Uint8Array(32).fill(9),
      fetch: async () => {
        const pair = new WebSocketPair();
        pair[1].accept();
        built = new Response(null, { status: 101, webSocket: pair[0], headers: { "x-from-the-do": "1" } });
        return built;
      },
    });
    try {
      const r = await direct("/api/v2/rt", { headers: { upgrade: "websocket", origin: ORIGIN } }, { RT });
      expect(r.status).toBe(101);
      expect(r).toBe(built);
      expect([...r.headers]).toEqual([["x-from-the-do", "1"]]);
      r.webSocket!.accept();
      r.webSocket!.close(1000);
    } finally {
      _resetApiForTests();
    }
  });

  it("a blob GET served from caches.default carries a fresh x-segv-now; the stored entry has none", async () => {
    const { blob, id } = P.encryptBlob(P.utf8("cached"));
    const put = await putBlob(id, blob, { "x-segv-pow": await powHeader("blob", P.fromB64u(id), { bytes: blob.length }) });
    expect(put.status, await put.clone().text()).toBe(201);
    const g1 = await api(`/api/v2/blob/${id}`);
    expect(g1.status).toBe(200);
    const n1 = nowOf(g1);
    expect(await bytesOf(g1)).toEqual(blob);
    const key = `${ORIGIN}/api/v2/blob/${id}`;
    const cached = await waitCached(key);
    expect(cached.headers.get("x-segv-now")).toBeNull();
    expect(cached.headers.get("cache-control")).toBe(IMMUTABLE);
    expect(await bytesOf(cached)).toEqual(blob);
    // Gone from R2: only the cache can answer now.
    await env.BLOBS.delete(`b/${id}`);
    await sleep(10);
    const t0 = Date.now();
    const g2 = await api(`/api/v2/blob/${id}`);
    expect(g2.status).toBe(200);
    expect(await bytesOf(g2)).toEqual(blob);
    const n2 = nowOf(g2);
    expect(n2).toBeGreaterThan(n1);
    expect(n2).toBeGreaterThanOrEqual(t0);
    expectApiHeaders(g2);
    // Still nothing stamped into the stored entry, and a conditional GET is answered from it.
    const again = await edgeCache().match(key);
    expect(again?.headers.get("x-segv-now")).toBeNull();
    await again?.arrayBuffer();
    const nm = await api(`/api/v2/blob/${id}`, { headers: { "if-none-match": g2.headers.get("etag")! } });
    expect(nm.status).toBe(304);
    nowOf(nm);
  });

  it("cached immutable responses and the inbox tail are served before the rate limiter", async () => {
    const deny = { limit: async () => ({ success: false }) };
    const E = eraNow();
    const id = P.b64u(P.random(32));
    const entries: [string, string, Response][] = [
      [`/api/v2/blob/${id}`, `${ORIGIN}/api/v2/blob/${id}`, new Response("blob!", { headers: { "cache-control": IMMUTABLE, etag: '"e"' } })],
      [
        `/api/v2/inbox/${E}/0?after=99&limit=5`,
        `${ORIGIN}/api/v2/inbox/${E}/0?after=99&limit=5`,
        new Response(W.encodeInboxRead({ closed: 100, more: false, rows: [] }) as BodyInit, { headers: { "cache-control": "public, max-age=60" } }),
      ],
      ["/api/v2/ckpt/987654321", `${ORIGIN}/api/v2/ckpt/987654321`, new Response('{"q":987654321}', { headers: { "cache-control": IMMUTABLE } })],
      [`/api/v2/feed/${E}/0?after=4294967295`, `${ORIGIN}/api/v2/feed/${E}/0?after=4294967295`, new Response(W.encodeFeed({ more: false, batches: [] }) as BodyInit, { headers: { "cache-control": IMMUTABLE } })],
    ];
    try {
      for (const [path, key, entry] of entries) {
        await edgeCache().put(key, entry);
        const res = await direct(path, {}, { RL_READ: deny });
        expect(res.status, path).toBe(200);
        // The stored entries carry none of the per-response headers: all of them are stamped on the way out.
        expectApiHeaders(res);
        await res.arrayBuffer();
      }
      // Uncached reads are rate limited.
      expect((await direct(`/api/v2/blob/${id}/meta`, {}, { RL_READ: deny })).status).toBe(429);
      expect((await direct(`/api/v2/inbox/${E}/0?after=98&limit=5`, {}, { RL_READ: deny })).status).toBe(429);
    } finally {
      for (const [, key] of entries) await edgeCache().delete(key);
    }
  });
});

// ───────────────────────────── Worker logic with fake Durable Objects ─────────────────────────────

/** A fake namespace whose every stub is `stub` (records the names asked for). */
function fakeNs(stub: Record<string, unknown>, names: string[] = []) {
  return { getByName: (n: string) => (names.push(n), stub) };
}

/** A rate-limit binding that grants `left` tokens and refuses every later one; `calls` counts every limit() call. */
function countingLimiter(left = Number.POSITIVE_INFINITY) {
  const l = { calls: 0, limit: async (): Promise<{ success: boolean }> => ({ success: ++l.calls <= left }) };
  return l;
}

describe("Worker logic (fake Durable Objects)", () => {
  it("publishes OK rows that carry a topic in one publish call (one retry), never delaying or changing the response", async () => {
    const shardRows: unknown[] = [];
    const SHARD = fakeNs({
      put: async (_E: number, _i: number, rows: { v: Bytes; label: Bytes }[]) => {
        shardRows.push(...rows);
        return rows.map((_, k) => (k === 3 ? { s: "conflict", t: 5, cls: 0, body: new Uint8Array(296) } : { s: "ok", t: 1234 }));
      },
    });
    const published: unknown[][] = [];
    let failures = 1;
    const RT = fakeNs({
      publish: async (rows: unknown[]) => {
        published.push(rows);
        if (failures-- > 0) throw new Error("rt down");
      },
    });
    const E = eraNow();
    const T = randomTopic();
    const rows = [makeRow(), makeRow({ topic: T }), makeRow({ topic: T, cls: 1 }), makeRow({ topic: T }), makeRow({ E: E + 1, topic: T })];
    const bytes = W.encodePutRequest(rows);
    const res = await direct("/api/v2/put", await powInit("put", bytes), { SHARD, RT });
    expect(res.status).toBe(200);
    const out = W.decodePutResponse(await bytesOf(res));
    expect(out.map((r) => r.s)).toEqual(["ok", "ok", "ok", "conflict", "wrong_era"]);
    for (const i of [0, 1, 2]) expect(P.verify(okOf(out[i]).receipt, P.receiptMsg(E, rows[i].label, rows[i].body, 1234), testSrvKey())).toBe(true);
    // v is the routing value under kroute_E.
    expect(shardRows.map((r) => P.b64u((r as { v: Bytes }).v))).toEqual(rows.slice(0, 4).map((r) => P.b64u(P.routeV(testKroute(E), r.label))));
    // One publish of the two OK rows with a topic, retried once after a failure.
    expect(published).toHaveLength(2);
    const want = [1, 2].map((i) => ({ topic: T, E, label: rows[i].label, t: 1234, cls: rows[i].cls, body: rows[i].body }));
    expect(published[0]).toEqual(want);
    expect(published[1]).toEqual(want);

    // At most one retry; the response is unchanged.
    failures = 5;
    published.length = 0;
    const b2 = W.encodePutRequest([makeRow({ topic: T })]);
    const r2 = await direct("/api/v2/put", await powInit("put", b2), { SHARD, RT });
    expect(r2.status).toBe(200);
    expect(W.decodePutResponse(await bytesOf(r2))[0].s).toBe("ok");
    expect(published).toHaveLength(2);

    // Only zero topics: RealtimeDO is not addressed at all.
    const rtNames: string[] = [];
    const b3 = W.encodePutRequest([makeRow(), makeRow()]);
    const r3 = await direct("/api/v2/put", await powInit("put", b3), { SHARD, RT: fakeNs({ publish: async () => {} }, rtNames) });
    expect(r3.status).toBe(200);
    expect(rtNames).toEqual([]);
  });

  it("passes FULL and BAD through; 503 when a shard fails", async () => {
    const SHARD = fakeNs({ put: async (_E: number, _i: number, rows: unknown[]) => rows.map((_, k) => (k === 0 ? { s: "full" } : { s: "bad" })) });
    const bytes = W.encodePutRequest([makeRow(), makeRow()]);
    const res = await direct("/api/v2/put", await powInit("put", bytes), { SHARD });
    expect(W.decodePutResponse(await bytesOf(res))).toEqual([{ s: "full" }, { s: "bad" }]);
    const broken = fakeNs({
      put: async () => Promise.reject(new Error("boom")),
      get: async () => Promise.reject(new Error("boom")),
    });
    const r2 = await direct("/api/v2/put", await powInit("put", bytes), { SHARD: broken });
    expect(r2.status).toBe(503);
    expect(r2.headers.get("retry-after")).toBe("5");
    const r3 = await direct("/api/v2/get", { method: "POST", body: W.encodeGetRequest([{ E: eraNow(), label: randomLabel(), mode: 0 }]) }, { SHARD: broken });
    expect(r3.status).toBe(503);
  });

  it("inbox: the DO's WRONG_ERA becomes 409 {error, era}; per-row results pass through; read cache-control follows `ended`", async () => {
    const E = eraNow();
    let post: unknown = { s: "wrong_era", era: E + 1 };
    let read = { closed: 7, more: false, rows: [] as unknown[], ended: false };
    const names: string[] = [];
    const INBOX = fakeNs(
      {
        post: async () => post,
        read: async () => read,
      },
      names,
    );
    const body = W.encodeInboxPost({ E, bucket: 0, rows: [randomInvite(), randomInvite(), randomInvite()] });
    let res = await direct("/api/v2/inbox", await powInit("inbox", body), { INBOX });
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "wrong era", era: E + 1 });
    post = { s: "ok", results: [{ rel: 3 }, { error: "conflict" }, { error: "full" }] };
    res = await direct("/api/v2/inbox", await powInit("inbox", body), { INBOX });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ results: [{ rel: 3 }, { error: "conflict" }, { error: "full" }] });
    expect(names).toEqual([`inbox/v2/${E}/0`, `inbox/v2/${E}/0`]);

    const q = () => `?after=${Math.floor(Math.random() * 1e9)}`;
    res = await direct(`/api/v2/inbox/${E}/0${q()}`, {}, { INBOX });
    expect(res.headers.get("cache-control")).toBe("public, max-age=1");
    expect(W.decodeInboxRead(await bytesOf(res))).toEqual({ closed: 7, more: false, rows: [] });
    read = { ...read, ended: true, more: true };
    res = await direct(`/api/v2/inbox/${E - 1}/0${q()}`, {}, { INBOX });
    expect(res.headers.get("cache-control")).toBe("public, max-age=1");
    read = { ...read, ended: true, more: false };
    res = await direct(`/api/v2/inbox/${E - 1}/0${q()}`, {}, { INBOX });
    expect(res.headers.get("cache-control")).toBe(IMMUTABLE);
  });

  it("feed: a page with more = 1 or of a sealed era is immutable, the tail no-store; ckpt 404s when the DO has none", async () => {
    const E = eraNow();
    const batch = { t: 9, n: 1, root: P.random(32), head: P.random(32), rows: [{ label: randomLabel(), cls: 0, body: randomBody(0) }] };
    let feed: { batches: (typeof batch)[]; more: boolean; sealed: boolean } = { batches: [batch], more: true, sealed: false };
    // feedBatches with every row inline (the page fits the budget): one RPC, no feedRows.
    const SHARD = fakeNs({
      feedBatches: async () => ({ ...feed, batches: feed.batches.map((b) => ({ ...b, bytes: 72 + 17 + b.rows[0].body.length })) }),
    });
    const after = () => `?after=${Math.floor(Math.random() * 1e9)}`;
    let res = await direct(`/api/v2/feed/${E}/0${after()}`, {}, { SHARD });
    expect(res.headers.get("cache-control")).toBe(IMMUTABLE);
    expect(W.decodeFeed(await bytesOf(res))).toEqual({ more: true, batches: [batch] });
    feed = { batches: [batch], more: false, sealed: false };
    res = await direct(`/api/v2/feed/${E}/0${after()}`, {}, { SHARD });
    expect(res.headers.get("cache-control")).toBe("no-store");
    feed = { batches: [], more: false, sealed: true };
    res = await direct(`/api/v2/feed/${E - 1}/0${after()}`, {}, { SHARD });
    expect(res.headers.get("cache-control")).toBe(IMMUTABLE);

    const CKPT = fakeNs({ latest: async () => null, get: async () => null, range: async () => null, ensure: async () => {} });
    for (const path of ["/api/v2/ckpt/latest", "/api/v2/ckpt/12345678", "/api/v2/ckpt/range?after=5"]) {
      const r = await direct(path, {}, { CKPT });
      expect(r.status, path).toBe(404);
    }
  });

  it("feed: a batch above the page budget is streamed whole from feedRows chunks; a short or failing shard never yields a wrong page", async () => {
    const E = eraNow();
    const rows = Array.from({ length: 5 }, () => ({ label: randomLabel(), cls: 3, body: randomBody(3) })).sort((a, b) => P.byteCmp(a.label, b.label));
    const batch = { t: 77, n: 5, root: P.random(32), head: P.random(32), rows };
    let served = rows;
    let failAt = -1;
    const calls: [number, string | null, number][] = [];
    const SHARD = fakeNs({
      // The page is one batch larger than the budget: sent without its rows.
      feedBatches: async () => ({ batches: [{ t: 77, n: 5, root: batch.root, head: batch.head, bytes: 64 << 20 }], more: true, sealed: false }),
      feedRows: async (_E: number, _i: number, t: number, afterLabel: Bytes | null, budget: number) => {
        if (calls.push([t, afterLabel && P.b64u(afterLabel), budget]) === failAt) throw new Error("shard down");
        const from = afterLabel ? served.findIndex((r) => eq(r.label, afterLabel)) + 1 : 0;
        return { rows: served.slice(from, from + 2), done: from + 2 >= served.length };
      },
    });
    const path = () => `/api/v2/feed/${E}/0?after=${Math.floor(Math.random() * 1e9)}`;
    const p1 = path();
    const res = await direct(p1, {}, { SHARD });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/octet-stream");
    expect(res.headers.get("cache-control")).toBe(IMMUTABLE);
    expectApiHeaders(res);
    expect(W.decodeFeed(await bytesOf(res))).toEqual({ more: true, batches: [batch] });
    expect(calls).toEqual([
      [77, null, 4 << 20],
      [77, P.b64u(rows[1].label), 4 << 20],
      [77, P.b64u(rows[3].label), 4 << 20],
    ]);
    // Streamed pages are not stored in caches.default (a tee would buffer the whole batch).
    expect(await edgeCache().match(`${ORIGIN}${p1}`)).toBeUndefined();

    // Fewer rows than n, or a shard failure after the first chunk: the body errors (truncated), never a wrong page.
    served = rows.slice(0, 4);
    const short = await direct(path(), {}, { SHARD });
    expect(short.status).toBe(200);
    await expect(short.arrayBuffer()).rejects.toThrow();
    served = rows;
    calls.length = 0;
    failAt = 2;
    const broken = await direct(path(), {}, { SHARD });
    expect(broken.status).toBe(200);
    await expect(broken.arrayBuffer()).rejects.toThrow();
    // A failure on the first chunk happens before the status line: an error status, not a broken 200.
    calls.length = 0;
    failAt = 1;
    expect((await direct(path(), {}, { SHARD })).status).toBeGreaterThanOrEqual(500);
  });

  it("feedTokens: one per started 4 MiB of the page's batches, at least 1 and at most 64 (§10.9)", () => {
    const MiB = 1 << 20;
    for (const [bytes, tokens] of [
      [0, 1],
      [1, 1],
      [4 * MiB, 1],
      [4 * MiB + 1, 2],
      [8 * MiB, 2],
      [8 * MiB + 1, 3],
      [63 * 4 * MiB + 1, 64],
      [600 * 4 * MiB + 1, 64],
      [300 * MiB, 64],
      [2.6e9, 64],
    ])
      expect(feedTokens(bytes), `${bytes} B`).toBe(tokens);
  });

  it("feed tokens: one RL_READ token per started 4 MiB of the page's batches (at most 64), all taken before feedRows; cached pages take none", async () => {
    const E = eraNow();
    const rows = Array.from({ length: 3 }, () => ({ label: randomLabel(), cls: 0, body: randomBody(0) })).sort((a, b) => P.byteCmp(a.label, b.label));
    const batch = { t: 5, n: 3, root: P.random(32), head: P.random(32) };
    const want = { more: false, batches: [{ ...batch, rows }] };
    let bytes = 9 << 20; // the batch size feedBatches reports (the rows themselves stay small)
    let inline = false;
    let feedRows = 0;
    const SHARD = fakeNs({
      feedBatches: async () => ({ batches: [inline ? { ...batch, bytes, rows } : { ...batch, bytes }], more: false, sealed: true }),
      feedRows: async () => (feedRows++, { rows, done: true }),
    });
    const path = () => `/api/v2/feed/${E}/0?after=${Math.floor(Math.random() * 1e9)}`;

    // A page of one 9 MiB batch: ⌈9 MiB / 4 MiB⌉ = 3 tokens.
    let rl = countingLimiter(3);
    let res = await direct(path(), {}, { SHARD, RL_READ: rl });
    expect(res.status).toBe(200);
    expect(W.decodeFeed(await bytesOf(res))).toEqual(want);
    expect(rl.calls).toBe(3);
    expect(feedRows).toBe(1);
    // With fewer tokens left: 429 with retry-after, before the shard is asked for any row.
    for (const left of [2, 1, 0]) {
      rl = countingLimiter(left);
      feedRows = 0;
      res = await direct(path(), {}, { SHARD, RL_READ: rl });
      expect(res.status, `${left} left`).toBe(429);
      expect(res.headers.get("retry-after")).toBe("60");
      expectApiHeaders(res);
      expect(await errorOf(res)).toBe("rate limited");
      expect(rl.calls).toBe(left + 1);
      expect(feedRows).toBe(0);
    }
    for (const [size, tokens] of [
      [8 << 20, 2],
      [(8 << 20) + 1, 3],
      [(4 << 20) + 1, 2],
      [64 << 20, 16],
      [600 * (4 << 20) + 1, 64],
      [2.6e9, 64],
    ]) {
      bytes = size;
      rl = countingLimiter();
      res = await direct(path(), {}, { SHARD, RL_READ: rl });
      expect(res.status).toBe(200);
      await res.arrayBuffer();
      expect(rl.calls, `${size} B`).toBe(tokens);
    }
    // At most 64: a 2.6 GB batch with 63 tokens left is a 429 after 64 limiter calls, before any feedRows call.
    bytes = 2.6e9;
    rl = countingLimiter(63);
    feedRows = 0;
    res = await direct(path(), {}, { SHARD, RL_READ: rl });
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("60");
    expect(rl.calls).toBe(64);
    expect(feedRows).toBe(0);

    // An inline page (its rows came with feedBatches; it fits 4 MiB) takes one token and makes no feedRows call.
    inline = true;
    bytes = 72 + rows.reduce((n, r) => n + 17 + r.body.length, 0);
    rl = countingLimiter();
    feedRows = 0;
    res = await direct(path(), {}, { SHARD, RL_READ: rl });
    expect(W.decodeFeed(await bytesOf(res))).toEqual(want);
    expect(rl.calls).toBe(1);
    expect(feedRows).toBe(0);

    // A page served from caches.default takes none, and reaches no shard.
    const p = path();
    const key = `${ORIGIN}${p}`;
    await edgeCache().put(key, new Response(W.encodeFeed(want) as BodyInit, { headers: { "cache-control": IMMUTABLE } }));
    try {
      rl = countingLimiter();
      const names: string[] = [];
      res = await direct(p, {}, { SHARD: fakeNs({}, names), RL_READ: rl });
      expect(res.status).toBe(200);
      expect(W.decodeFeed(await bytesOf(res))).toEqual(want);
      expectApiHeaders(res);
      expect(rl.calls).toBe(0);
      expect(names).toEqual([]);
    } finally {
      await edgeCache().delete(key);
    }
  });

  it("rt: forwards only the upgrade and an opaque client tag to the RealtimeDO, and relays its refusals", async () => {
    _resetApiForTests();
    const seen: Request[] = [];
    const RT = fakeNs({
      wsTagKey: async () => new Uint8Array(32).fill(7),
      fetch: async (url: string, init: RequestInit) => {
        seen.push(new Request(url, init));
        return new Response(JSON.stringify({ error: "too many sockets" }), { status: 429, headers: { "retry-after": "60" } });
      },
    });
    try {
      const ip = freshIp();
      const res = await direct("/api/v2/rt", { ip, headers: { upgrade: "websocket", origin: ORIGIN, cookie: "x=1", "user-agent": "ua" } }, { RT });
      expect(res.status).toBe(429);
      expect(res.headers.get("retry-after")).toBe("60");
      expect(await errorOf(res)).toBe("too many sockets");
      await direct("/api/v2/rt", { ip, headers: { upgrade: "websocket" } }, { RT });
      expect(seen).toHaveLength(2);
      const h = [...seen[0].headers.keys()].sort();
      expect(h).toEqual(["upgrade", "x-segv-client"]);
      const tag = seen[0].headers.get("x-segv-client")!;
      expect(tag).toMatch(/^[0-9a-f]{32}$/);
      expect(seen[1].headers.get("x-segv-client")).toBe(tag); // same client, same tag
      expect(tag).not.toContain(ip);
    } finally {
      _resetApiForTests();
    }
  });
});

describe("routeLabel", () => {
  it("redacts ids, handles, prefixes and eras from log labels", () => {
    const id = P.b64u(P.random(32));
    expect(routeLabel(`/api/v2/blob/${id}`)).toBe("/api/v2/blob/:id");
    expect(routeLabel(`/api/v2/blob/${id}/meta`)).toBe("/api/v2/blob/:id/meta");
    expect(routeLabel("/api/v2/era/42")).toBe("/api/v2/era/:E");
    expect(routeLabel("/api/v2/inbox/42/0")).toBe("/api/v2/inbox/:E/:bucket");
    expect(routeLabel("/api/v2/feed/42/0")).toBe("/api/v2/feed/:E/:i");
    expect(routeLabel("/api/v2/dir/h/5/17")).toBe("/api/v2/dir/:kind/:p/:x");
    expect(routeLabel(`/api/v2/dir/uid/${P.b64u(P.random(16))}`)).toBe("/api/v2/dir/uid/:uid");
    expect(routeLabel(`/api/v2/dir/wraps/${id}`)).toBe("/api/v2/dir/wraps/:id");
    expect(routeLabel("/api/v2/put")).toBe("/api/v2/put");
    expect(routeLabel("/api/v2/whatever/secret")).toBe("/api/v2/*");
  });
});
