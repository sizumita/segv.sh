/**
 * Web Push (docs/PROTOCOL.md §9.8, §10.10): the configuration, both endpoints, and PushDO's registrations, pushes,
 * daily pass and alarm.
 *
 * PushDO is one instance ("push/v2"). Each test that drives it starts from empty tables and a new instance (reset()),
 * whose clock, randomness, sleep and fetch are replaced: its clock runs days ahead of real time, so the alarm it arms
 * never fires on its own, and the tests run it by hand (run()). Pushes go to *.push.test hosts through the fake fetch.
 */
import { gcm } from "@noble/ciphers/aes.js";
import { p256 } from "@noble/curves/nist.js";
import { evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as P from "../../src/lib/proto";
import * as W from "../../src/lib/wire";
import { MAX_RING_BODY, RING_FRESH, ringEraOk, ringRowFresh } from "../../src/server/api";
import { _resetPushConfigForTests } from "../../src/server/env";
import { PUSH_TICK, PUSH_WINDOW, dayOf, nextTick, type PassPart, type PushDO } from "../../src/server/push-do";
import { pushStub } from "../../src/server/types";
import { vapidPublicKey } from "../../src/server/webpush";
import { DELTA, DIFF2, direct, errorOf, freshIp, makeRow, powHeader, putOk, type Bytes } from "./helpers";

const ENV = env as unknown as Record<string, string>;
const PUSH_KEY = P.fromB64u(ENV.PUSH_KEY);
const VAPID_PK = vapidPublicKey(P.fromB64u(ENV.VAPID_SK));
const DAY = 86_400_000;
const N = p256.Point.Fn.ORDER;
const scalarB64 = (x: bigint): string => P.b64u(Uint8Array.from(x.toString(16).padStart(64, "0").match(/../g)!.map((h) => parseInt(h, 16))));

const epOf = (endpoint: string): Bytes => P.t16(P.HMAC(PUSH_KEY, P.enc("segv.sh/v2/push/ep", endpoint)));
const tkOf = (bell: Bytes): Bytes => P.t16(P.HMAC(PUSH_KEY, P.enc("segv.sh/v2/push/bell", bell)));
const bells = (n: number): Bytes[] => Array.from({ length: n }, () => P.random(16));

/** A browser's push subscription: its endpoint and its keys. */
interface Dev {
  endpoint: string;
  ep: Bytes;
  sk: Bytes;
  p256dh: Bytes;
  auth: Bytes;
}
let devSeq = 0;
function dev(host = "fcm.push.test"): Dev {
  const endpoint = `https://${host}/send/${P.hex(P.random(6))}${devSeq++}`;
  const sk = p256.utils.randomSecretKey();
  return { endpoint, ep: epOf(endpoint), sk, p256dh: p256.getPublicKey(sk, false), auth: P.random(16) };
}

/** RFC 8291's receiving side (one record). */
function decrypt(body: Bytes, d: Dev): Bytes {
  const salt = body.subarray(0, 16);
  expect(new DataView(body.buffer, body.byteOffset).getUint32(16)).toBe(4096);
  expect(body[20]).toBe(65);
  const asPublic = body.subarray(21, 86);
  const ecdh = p256.getSharedSecret(d.sk, asPublic, true).subarray(1);
  const one = Uint8Array.of(1);
  const ikm = P.HMAC(P.HMAC(d.auth, ecdh), P.concat(P.utf8("WebPush: info\0"), d.p256dh, asPublic, one));
  const prk = P.HMAC(salt, ikm);
  const cek = P.HMAC(prk, P.concat(P.utf8("Content-Encoding: aes128gcm\0"), one)).slice(0, 16);
  const nonce = P.HMAC(prk, P.concat(P.utf8("Content-Encoding: nonce\0"), one)).slice(0, 12);
  const padded = gcm(cek, nonce).decrypt(body.subarray(86));
  expect(padded[padded.length - 1]).toBe(2);
  return padded.slice(0, -1);
}

// ───────────── driving PushDO ─────────────

interface Call {
  url: string;
  init: RequestInit;
  headers: Headers;
  body: Bytes;
  at: number;
}
interface PushState {
  ep?: Bytes;
  due: number | null;
  last: number | null;
  tries: number;
  first?: number;
  rang?: Bytes[];
}
interface Hooks {
  clock: () => number;
  rand: () => number;
  sleep: (ms: number) => Promise<void>;
  fetcher: (url: string, init: RequestInit) => Promise<Response>;
  pushRows: number;
  beforeCommit: (() => void) | null;
  parts: PassPart[];
  env: Env;
  pushes: Map<string, PushState>;
}

/** The fake world PushDO sees: its time (null: real time), its randomness and the push services' answers. */
const fake = {
  now: null as number | null,
  rand: 0,
  calls: [] as Call[],
  respond: ((): Response => new Response(null, { status: 201 })) as (c: Call) => Response | Promise<Response>,
};
const nowOf = (): number => fake.now ?? Date.now();
/** A UTC midnight well after real time. */
const BASE = (dayOf(Date.now()) + 5) * DAY;

const DO = () => pushStub(env);
const inDO = <T>(fn: (h: Hooks, state: DurableObjectState) => T | Promise<T>): Promise<T> =>
  runInDurableObject(DO(), (inst: PushDO, state) => fn(inst as unknown as Hooks, state));

/** Replaces the instance's hooks and removes the alarm its constructor armed in real time. */
async function install(): Promise<void> {
  await inDO(async (h, state) => {
    h.clock = nowOf;
    h.rand = () => fake.rand;
    h.sleep = async (ms) => {
      if (fake.now !== null) fake.now += ms;
    };
    h.fetcher = async (url, init) => {
      const call: Call = { url, init, headers: new Headers(init.headers), body: new Uint8Array(init.body as ArrayBuffer), at: nowOf() };
      fake.calls.push(call);
      return fake.respond(call);
    };
    await state.storage.deleteAlarm();
  });
}

/** Empty tables, a new instance (empty memory), fresh fakes. */
async function reset(now: number | null = BASE): Promise<void> {
  await inDO(async (_h, state) => {
    state.storage.sql.exec("DELETE FROM tok");
    state.storage.sql.exec("DELETE FROM sub");
    await state.storage.deleteAlarm();
  });
  await evictDurableObject(DO());
  Object.assign(fake, { now, rand: 0, calls: [], respond: () => new Response(null, { status: 201 }) });
  await install();
}

/** A restart of the object (an eviction): memory is lost, storage stays. */
async function restart(): Promise<void> {
  await evictDurableObject(DO());
  await install();
}

const setEnv = (patch: Record<string, unknown>): Promise<void> =>
  inDO((h) => {
    h.env = new Proxy(env, {
      get: (t, k) => (typeof k === "string" && Object.prototype.hasOwnProperty.call(patch, k) ? patch[k] : Reflect.get(t, k)),
    });
  });

const sub = (d: Dev, bs: Bytes[]) => DO().sub(d.endpoint, d.p256dh, d.auth, bs);
const ring = (bs: Bytes[], label: Bytes = P.random(16), E = 1) => DO().ring(E, label, bs);
async function run(at?: number): Promise<void> {
  if (at !== undefined) fake.now = at;
  await DO().run();
}
const dueOf = (d: Dev): Promise<number | null> => inDO((h) => h.pushes.get(P.hex(d.ep))?.due ?? null);
const stateOf = (d: Dev): Promise<PushState> => inDO((h) => ({ ...(h.pushes.get(P.hex(d.ep)) ?? { due: null, last: null, tries: 0 }) }));
const callsTo = (d: Dev): Call[] => fake.calls.filter((c) => c.url === d.endpoint);

/** The stored tables, as hex. */
const tables = (): Promise<{ sub: { ep: string; day: number }[]; tok: { tk: string; ep: string }[] }> =>
  inDO((_h, state) => ({
    sub: state.storage.sql
      .exec<{ ep: ArrayBuffer; day: number }>("SELECT ep, day FROM sub ORDER BY ep")
      .toArray()
      .map((r) => ({ ep: P.hex(new Uint8Array(r.ep)), day: r.day })),
    tok: state.storage.sql
      .exec<{ tk: ArrayBuffer; ep: ArrayBuffer }>("SELECT tk, ep FROM tok ORDER BY tk, ep")
      .toArray()
      .map((r) => ({ tk: P.hex(new Uint8Array(r.tk)), ep: P.hex(new Uint8Array(r.ep)) })),
  }));
const storedDay = async (d: Dev): Promise<number | null> => (await tables()).sub.find((r) => r.ep === P.hex(d.ep))?.day ?? null;

/** Is `d` reached by a ring of `bs` now? (A fresh row each time, so the dedup never interferes.) */
async function reaches(d: Dev, bs: Bytes[]): Promise<boolean> {
  await inDO((h) => h.pushes.delete(P.hex(d.ep)));
  await ring(bs);
  return (await dueOf(d)) !== null;
}

// ───────────── 1. params and configuration ─────────────

describe("params and configuration (§9.8, §10.9)", () => {
  beforeEach(() => _resetPushConfigForTests());

  it("reports push and pow.push while push is on", async () => {
    const p = (await (await direct("/api/v2/params")).json()) as { push: unknown; pow: Record<string, number> };
    expect(p.push).toEqual({ vapid: P.b64u(VAPID_PK), window: 60, maxTokens: 256 });
    expect(p.pow).toEqual(DIFF2);
    const dflt = (await (await direct("/api/v2/params", {}, { POW_PUSH: undefined })).json()) as { pow: Record<string, number> };
    expect(dflt.pow.push).toBe(20);
  });

  const OFF: [string, string | null, Record<string, unknown>][] = [
    ["VAPID_SK unset", null, { VAPID_SK: undefined }],
    ["VAPID_SK = 0", "VAPID_SK", { VAPID_SK: scalarB64(0n) }],
    ["VAPID_SK = n", "VAPID_SK", { VAPID_SK: scalarB64(N) }],
    ["VAPID_SK of 31 bytes", "VAPID_SK", { VAPID_SK: P.b64u(P.random(31)) }],
    ["PUSH_KEY missing", "PUSH_KEY", { PUSH_KEY: undefined }],
    ["PUSH_KEY of 31 bytes", "PUSH_KEY", { PUSH_KEY: P.b64u(P.random(31)) }],
    ["VAPID_SUB missing", "VAPID_SUB", { VAPID_SUB: undefined }],
    ["VAPID_SUB not mailto:/https:", "VAPID_SUB", { VAPID_SUB: "http://operator.example/" }],
    ["PUSH_HOSTS malformed", "PUSH_HOSTS", { PUSH_HOSTS: "push.test,,not a host" }],
    ["POW_PUSH 65", "POW_PUSH", { POW_PUSH: "65" }],
    ["PUSH_MAX_SUBS malformed", "PUSH_MAX_SUBS", { PUSH_MAX_SUBS: "1e5" }],
    ["PUSH_DAY_SUBS malformed", "PUSH_DAY_SUBS", { PUSH_DAY_SUBS: "-1" }],
    ["APP_HOSTS empty", "APP_HOSTS", { APP_HOSTS: "" }],
  ];

  it.each(OFF)("%s: push is off exactly as unconfigured, and the rest of the API works", async (_name, setting, patch) => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const params = await direct("/api/v2/params", {}, patch);
      expect(params.status).toBe(200);
      const p = (await params.json()) as Record<string, unknown> & { pow: Record<string, number> };
      expect("push" in p).toBe(false);
      expect("push" in p.pow).toBe(false);
      const unknown = await errorOf(await direct("/api/v2/nope", { method: "POST", body: "x" }, patch));
      for (const path of ["/api/v2/push/sub", "/api/v2/ring"]) {
        const r = await direct(path, { method: "POST", body: "x" }, patch);
        expect(r.status).toBe(404);
        expect(await errorOf(r)).toBe(unknown);
      }
      // A put, a get and a directory lookup answer as usual (never 503 "server misconfigured").
      const row = makeRow();
      const put = W.encodePutRequest([row]);
      const putRes = await direct(
        "/api/v2/put",
        { method: "POST", headers: { "x-segv-pow": await powHeader("put", P.H(put), { bytes: put.length }) }, body: put },
        patch,
      );
      expect(putRes.status).toBe(200);
      const get = W.encodeGetRequest([{ E: row.E, label: row.label, mode: 1 }]);
      expect((await direct("/api/v2/get", { method: "POST", body: get }, patch)).status).toBe(200);
      expect((await direct(`/api/v2/dir/uid/${P.b64u(P.random(16))}`, {}, patch)).status).toBe(404);
      const lines = log.mock.calls.map((c) => String(c[0])).filter((l) => l.includes("push is off"));
      if (setting === null) expect(lines).toEqual([]);
      else {
        expect(lines).toHaveLength(1); // once per isolate, however many requests
        expect(JSON.parse(lines[0])).toEqual({ msg: "push is off: invalid setting", setting });
        for (const v of Object.values(patch)) if (typeof v === "string" && v.length > 0) expect(lines[0]).not.toContain(v);
      }
    } finally {
      log.mockRestore();
    }
  });

  it("a PushDO whose push is off sends nothing, and its pass deletes only what expired", async () => {
    await reset(BASE);
    const old = dev();
    const fresh = dev();
    const bo = bells(1);
    await sub(old, bo);
    await run(BASE + DAY + 1000); // writes `old` with day D
    fake.now = BASE + 32 * DAY;
    await sub(fresh, bells(1));
    await ring(bo);
    expect(await dueOf(old)).not.toBeNull();
    await setEnv({ PUSH_KEY: undefined });
    await run(BASE + 32 * DAY + 5000);
    expect(fake.calls).toEqual([]);
    expect(await storedDay(old)).toBeNull(); // 32 days old
  });

  it("while push is off the pass deletes by day only; a registration it cannot open comes back with the key", async () => {
    await reset(BASE);
    const old = dev();
    const recent = dev();
    const br = bells(1);
    await sub(old, bells(1));
    fake.now = BASE + 29 * DAY;
    await sub(recent, br);
    await run(BASE + 30 * DAY + 1000); // writes `recent` (day D+29); `old` is 30 days old, not yet expired
    expect(await storedDay(old)).toBe(dayOf(BASE));
    await setEnv({ PUSH_KEY: undefined });
    await run(BASE + 31 * DAY + 1000);
    expect(await storedDay(old)).toBeNull();
    expect(await storedDay(recent)).toBe(dayOf(BASE) + 29); // its box cannot be opened without the key: kept
    await setEnv({});
    await ring(br);
    await run(BASE + 31 * DAY + 2000);
    expect(callsTo(recent)).toHaveLength(1);
  });
});

// ───────────── 2. push/sub ─────────────

describe("POST /api/v2/push/sub (§10.10)", () => {
  beforeEach(async () => {
    _resetPushConfigForTests();
    await reset(null);
  });
  /** The default PUSH_HOSTS list, for the host rules. */
  const DEF = { PUSH_HOSTS: undefined };
  const body = (over: Record<string, unknown> = {}): Record<string, unknown> => {
    const d = dev();
    return { endpoint: "https://fcm.googleapis.com/fcm/send/abc", p256dh: P.b64u(d.p256dh), auth: P.b64u(d.auth), tokens: [P.b64u(P.random(16))], ...over };
  };
  async function post(b: unknown, opts: { pow?: boolean; ip?: string; raw?: Bytes } = {}): Promise<Response> {
    const bytes = opts.raw ?? P.utf8(JSON.stringify(b));
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (opts.pow !== false) headers["x-segv-pow"] = await powHeader("push", P.H(bytes), { bytes: bytes.length });
    return direct("/api/v2/push/sub", { method: "POST", headers, body: bytes, ip: opts.ip }, DEF);
  }

  it("accepts a valid registration (204, no body), also on a real *.notify.windows.com host", async () => {
    for (const endpoint of ["https://fcm.googleapis.com/fcm/send/abc", "https://wns2-par02p.notify.windows.com/w/?token=AbC"]) {
      const r = await post(body({ endpoint }));
      expect(r.status).toBe(204);
      expect(await r.text()).toBe("");
      expect(r.headers.get("cache-control")).toBe("no-store");
    }
    expect((await post(body({ tokens: [] }))).status).toBe(204);
  });

  const BAD: [string, Record<string, unknown>][] = [
    ["an http: endpoint", { endpoint: "http://fcm.googleapis.com/fcm/send/abc" }],
    ["a port", { endpoint: "https://fcm.googleapis.com:8443/fcm/send/abc" }],
    ["userinfo", { endpoint: "https://u:p@fcm.googleapis.com/fcm/send/abc" }],
    ["a host outside PUSH_HOSTS", { endpoint: "https://push.example.com/send/abc" }],
    ["a host that only resembles *.notify.windows.com", { endpoint: "https://notify.windows.com.example/w/abc" }],
    ["xnotify.windows.com", { endpoint: "https://xnotify.windows.com/w/abc" }],
    ["the bare notify.windows.com", { endpoint: "https://notify.windows.com/w/abc" }],
    ["a non-canonical URL", { endpoint: "https://FCM.googleapis.com/fcm/send/abc" }],
    ["a non-canonical path", { endpoint: "https://fcm.googleapis.com/fcm/../send/abc" }],
    ["1025 bytes", { endpoint: `https://fcm.googleapis.com/${"a".repeat(1025 - 27)}` }],
    ["a p256dh off the curve", { p256dh: P.b64u(Uint8Array.of(4, ...new Uint8Array(64).fill(1))) }],
    ["a 64-byte p256dh", { p256dh: P.b64u(P.random(64)) }],
    ["a 15-byte auth", { auth: P.b64u(P.random(15)) }],
    ["257 tokens", { tokens: bells(257).map(P.b64u) }],
    ["a 15-byte token", { tokens: [P.b64u(P.random(15))] }],
    ["tokens not an array", { tokens: P.b64u(P.random(16)) }],
    ["an extra key", { extra: 1 }],
  ];
  it.each(BAD)("400 for %s", async (_name, over) => {
    expect(`https://fcm.googleapis.com/${"a".repeat(1025 - 27)}`.length).toBe(1025);
    const r = await post(body(over));
    expect(r.status).toBe(400);
  });

  it("a repeated token counts once; 256 distinct ones are accepted", async () => {
    const t = P.b64u(P.random(16));
    expect((await post(body({ tokens: [t, t, t] }))).status).toBe(204);
    expect((await post(body({ tokens: bells(256).map(P.b64u) }))).status).toBe(204);
  });

  it("403 without proof of work, 413 above 16 KiB, 429 from RL_WRITE", async () => {
    expect((await post(body(), { pow: false })).status).toBe(403);
    const big = P.utf8(JSON.stringify(body({ pad: "x".repeat(16 * 1024) })));
    expect((await post(null, { raw: big, pow: false })).status).toBe(413);
    const ip = freshIp();
    for (let i = 0; i < 60; i++) expect((await post(body(), { pow: false, ip })).status).toBe(403);
    expect((await post(body(), { ip })).status).toBe(429);
  });
});

// ───────────── 3. replace ─────────────

describe("PushDO sub replaces a registration as a whole (§9.8)", () => {
  it("a second registration replaces the set, an empty one deletes it, and each refreshes the day", async () => {
    await reset(BASE);
    const d = dev();
    const [b1, b2, b3] = bells(3);
    await sub(d, [b1, b2]);
    expect(await reaches(d, [b1])).toBe(true);
    expect(await reaches(d, [b2])).toBe(true);
    await sub(d, [b3]);
    expect(await reaches(d, [b1])).toBe(false);
    expect(await reaches(d, [b3])).toBe(true);
    await run(BASE + DAY + 1000);
    expect(await storedDay(d)).toBe(dayOf(BASE));
    fake.now = BASE + 3 * DAY;
    await sub(d, [b3, b1]);
    await run(BASE + 4 * DAY + 1000);
    expect(await storedDay(d)).toBe(dayOf(BASE) + 3);
    await sub(d, []);
    expect(await reaches(d, [b3])).toBe(false);
    await run(BASE + 5 * DAY + 1000);
    expect(await storedDay(d)).toBeNull();
    expect((await tables()).tok.filter((r) => r.ep === P.hex(d.ep))).toEqual([]);
  });
});

// ───────────── 4. caps ─────────────

describe("PushDO limits (§9.8)", () => {
  it("a bell's 8 places go to the first endpoints; a ninth is left out without evicting, and takes a freed place", async () => {
    await reset(BASE);
    const b = P.random(16);
    const eight = Array.from({ length: 8 }, () => dev());
    for (const d of eight) expect(await sub(d, [b])).toBe("ok");
    const ninth = dev();
    const own = P.random(16);
    expect(await sub(ninth, [b, own])).toBe("ok");
    await ring([b]);
    for (const d of eight) expect(await dueOf(d)).not.toBeNull();
    expect(await dueOf(ninth)).toBeNull();
    expect(await reaches(ninth, [own])).toBe(true); // its other bells work
    // Stored or in memory alike: after the pass the places hold.
    await run(BASE + DAY + 1000);
    expect((await tables()).tok.filter((r) => r.tk === P.hex(tkOf(b)))).toHaveLength(8);
    await sub(eight[0], []);
    await sub(ninth, [b, own]);
    expect(await reaches(ninth, [b])).toBe(true);
  });

  it("PUSH_MAX_SUBS: a new endpoint at the cap gets 503 push full; an existing one still replaces its set", async () => {
    _resetPushConfigForTests();
    await reset(null);
    await setEnv({ PUSH_MAX_SUBS: "2" });
    const regs = [dev(), dev(), dev()];
    const post = async (d: Dev, tokens: Bytes[]) => {
      const bytes = P.utf8(JSON.stringify({ endpoint: d.endpoint, p256dh: P.b64u(d.p256dh), auth: P.b64u(d.auth), tokens: tokens.map(P.b64u) }));
      return direct("/api/v2/push/sub", { method: "POST", headers: { "x-segv-pow": await powHeader("push", P.H(bytes), { bytes: bytes.length }) }, body: bytes });
    };
    expect((await post(regs[0], bells(1))).status).toBe(204);
    expect((await post(regs[1], bells(1))).status).toBe(204);
    const full = await post(regs[2], bells(1));
    expect(full.status).toBe(503);
    expect(full.headers.get("retry-after")).toBe("3600");
    expect(await errorOf(full)).toBe("push full");
    expect((await post(regs[1], bells(2))).status).toBe(204);
    expect((await post(regs[0], [])).status).toBe(204);
    expect((await post(regs[2], bells(1))).status).toBe(204);
  });

  it("PUSH_DAY_SUBS: after the day's changes of 2 endpoints a third change is full, while deletions, refreshes and further changes of the two pass", async () => {
    await reset(BASE);
    const stored = dev();
    const bs = bells(1);
    await sub(stored, bs);
    await run(BASE + DAY + 1000); // `stored` is now in the tables
    await setEnv({ PUSH_DAY_SUBS: "2" });
    const [a, b, c] = [dev(), dev(), dev()];
    expect(await sub(a, bells(1))).toBe("ok");
    expect(await sub(b, bells(1))).toBe("ok");
    expect(await sub(c, bells(1))).toBe("full");
    expect(await sub(stored, bells(1))).toBe("full"); // a changed set
    expect(await sub(stored, bs)).toBe("ok"); // a refresh
    expect(await sub(a, bells(2))).toBe("ok"); // a further change of one of the two
    expect(await sub(b, [])).toBe("ok"); // a deletion
    expect(await sub(c, bells(1))).toBe("ok"); // b's change left memory
    await run(BASE + 2 * DAY + 1000);
    expect(await sub(stored, bells(1))).toBe("ok"); // the pass freed the cap
  });
});

// ───────────── 5. ring answers ─────────────

describe("POST /api/v2/ring (§10.10)", () => {
  beforeEach(async () => {
    _resetPushConfigForTests();
    await reset(null);
  });
  const ringBody = (E: number, label: Bytes, tokens: Bytes[], ver = 1): Bytes =>
    P.concat(Uint8Array.of(ver), P.u16(E), label, Uint8Array.of(tokens.length), ...tokens);
  const post = (b: Bytes, ip?: string) => direct("/api/v2/ring", { method: "POST", body: b, ip });

  it("answers 204 with no body whatever the bell, the row or a repeat, and pushes only for a fresh row of a registered bell", async () => {
    const d = dev();
    const b = P.random(16);
    await sub(d, [b]);
    const row = makeRow();
    await putOk([row]);
    const cases = [
      ringBody(row.E, row.label, [b]), // registered, fresh
      ringBody(row.E, row.label, [b]), // a repeat
      ringBody(row.E, row.label, [P.random(16)]), // unregistered
      ringBody(row.E, P.random(16), [b]), // a missing row
      ringBody(row.E + 5, row.label, [b]), // outside the era bound
    ];
    const answers: string[] = [];
    for (const c of cases) {
      const r = await post(c);
      answers.push(`${r.status}|${await r.text()}|${r.headers.get("content-type")}`);
    }
    expect(new Set(answers)).toEqual(new Set(["204||null"]));
    expect(await dueOf(d)).not.toBeNull();
  });

  it("400 for ver 2, n 0, n 65 or a length mismatch; 413 above 1044 bytes; 429 from RL_RING; no proof of work", async () => {
    const l = P.random(16);
    expect((await post(ringBody(1, l, [P.random(16)], 2))).status).toBe(400);
    expect((await post(P.concat(Uint8Array.of(1), P.u16(1), l, Uint8Array.of(0)))).status).toBe(400);
    expect((await post(P.concat(Uint8Array.of(1), P.u16(1), l, Uint8Array.of(65), ...bells(65)))).status).toBe(413);
    expect((await post(P.concat(ringBody(1, l, bells(2)), P.random(1)))).status).toBe(400);
    expect((await post(ringBody(1, l, bells(2)).subarray(0, 40))).status).toBe(400);
    expect(MAX_RING_BODY).toBe(20 + 16 * 64);
    const ip = freshIp();
    for (let i = 0; i < 60; i++) expect((await post(ringBody(1, P.random(16), [P.random(16)]), ip)).status).toBe(204);
    expect((await post(ringBody(1, P.random(16), [P.random(16)]), ip)).status).toBe(429);
  });
});

// ───────────── 6. freshness and dedup ─────────────

describe("ring freshness and dedup (§10.10, §9.8)", () => {
  const p = { delta: 10, skew: 2, eFirst: 1 };

  it("a row is fresh while t + Δ ≥ sec(now) − 60, t being rounded down to Δ", () => {
    const now = P.eraStart(50) + 3 * DAY + 123_456;
    const s = P.secOf(now);
    expect(ringRowFresh(s - RING_FRESH - p.delta, now, p.delta)).toBe(true);
    expect(ringRowFresh(s - RING_FRESH - p.delta - 1, now, p.delta)).toBe(false);
    expect(ringRowFresh(s, now, p.delta)).toBe(true);
  });

  it("the era bound reaches back RING_FRESH + Δ + SKEW, so a row stored just before an era boundary rings", () => {
    const start = P.eraStart(50);
    expect(ringEraOk(49, start + 30_000, p)).toBe(true);
    expect(ringEraOk(49, start + (RING_FRESH + p.delta + p.skew) * 1000 - 1, p)).toBe(true);
    expect(ringEraOk(49, start + (RING_FRESH + p.delta + p.skew) * 1000, p)).toBe(false);
    expect(ringEraOk(51, start + 30_000, p)).toBe(false);
    expect(ringEraOk(51, P.eraStart(51) - 1000, p)).toBe(true); // within SKEW of the next era
    expect(ringEraOk(0, P.eraStart(1) + 1000, { ...p, eFirst: 1 })).toBe(false);
  });

  it("the same row rung twice with the same bells pushes once; other bells rung first do not stop the sender's", async () => {
    await reset(BASE);
    const d = dev();
    const other = dev();
    const [b, bo] = bells(2);
    await sub(d, [b]);
    await sub(other, [bo]);
    const label = P.random(16);
    await ring([bo], label); // a third party rings the row first, with other bells
    await ring([b], label);
    expect(await dueOf(d)).not.toBeNull();
    await run(BASE + 1000);
    expect(callsTo(d)).toHaveLength(1);
    fake.now = BASE + (PUSH_WINDOW + 5) * 1000; // past the window, within RING_DEDUP
    await ring([b], label);
    expect(await dueOf(d)).toBeNull();
    await ring([b], P.random(16)); // another row
    expect(await dueOf(d)).not.toBeNull();
  });
});

// ───────────── 7. coalescing and jitter ─────────────

describe("one push per endpoint per PUSH_WINDOW, with jitter (§9.8)", () => {
  it("two rings 10 s apart give two pushes at least PUSH_WINDOW apart; more rings within the window add nothing", async () => {
    await reset(BASE);
    const d = dev();
    const b = P.random(16);
    await sub(d, [b]);
    fake.rand = 0.5;
    await ring([b]);
    const due1 = (await dueOf(d))!;
    expect(due1 - BASE).toBeGreaterThanOrEqual(0);
    expect(due1 - BASE).toBeLessThanOrEqual(DELTA * 1000); // PUSH_JITTER = Δ
    await run(BASE + 1000); // the first run at or after due1
    expect(callsTo(d)).toHaveLength(1);
    const sent1 = callsTo(d)[0].at;
    fake.now = BASE + 10_000;
    await ring([b]);
    const due2 = (await dueOf(d))!;
    expect(due2).toBeGreaterThanOrEqual(sent1 + PUSH_WINDOW * 1000);
    expect(due2).toBeLessThanOrEqual(sent1 + PUSH_WINDOW * 1000 + DELTA * 1000);
    fake.now = BASE + 20_000;
    await ring([b]);
    await ring([b]);
    expect(await dueOf(d)).toBe(due2);
    await run(BASE + 30_000);
    expect(callsTo(d)).toHaveLength(1);
    await run(due2);
    expect(callsTo(d)).toHaveLength(2);
    expect(callsTo(d)[1].at - sent1).toBeGreaterThanOrEqual(PUSH_WINDOW * 1000);
  });
});

// ───────────── 8. the push request ─────────────

describe("the push request (§9.8)", () => {
  it("carries the Web Push headers, an ES256 VAPID JWT, no redirects, and the payload encrypted to the subscription", async () => {
    await reset(BASE);
    const d = dev("updates.push.test");
    const b = P.random(16);
    await sub(d, [b]);
    await ring([b]);
    await run(BASE + 1000);
    const [c] = callsTo(d);
    expect(c.init.method).toBe("POST");
    expect(c.init.redirect).toBe("manual");
    expect(c.headers.get("ttl")).toBe("86400");
    expect(c.headers.get("urgency")).toBe("normal");
    expect(c.headers.get("topic")).toBe("segv");
    expect(c.headers.get("content-encoding")).toBe("aes128gcm");
    expect(c.headers.get("content-type")).toBe("application/octet-stream");
    const m = /^vapid t=([\w-]+\.[\w-]+\.[\w-]+), k=([\w-]+)$/.exec(c.headers.get("authorization") ?? "");
    expect(m).not.toBeNull();
    expect(m![2]).toBe(P.b64u(VAPID_PK));
    const [h, claims, sig] = m![1].split(".");
    expect(JSON.parse(new TextDecoder().decode(P.fromB64u(h)))).toEqual({ typ: "JWT", alg: "ES256" });
    const cl = JSON.parse(new TextDecoder().decode(P.fromB64u(claims))) as { aud: string; exp: number; sub: string };
    expect(cl.aud).toBe("https://updates.push.test");
    expect(cl.sub).toBe(ENV.VAPID_SUB);
    expect(cl.exp).toBeGreaterThan(Math.floor((BASE + 1000) / 1000));
    expect(cl.exp).toBeLessThanOrEqual(Math.floor((BASE + 1000) / 1000) + 12 * 3600);
    expect(p256.verify(P.fromB64u(sig), P.utf8(`${h}.${claims}`), VAPID_PK, { lowS: false })).toBe(true);
    expect(new TextDecoder().decode(decrypt(c.body, d))).toBe(
      `{"web_push":8030,"mutable":true,"notification":{"title":"segv.sh","body":"new messages","navigate":"https://segv.test/","tag":"segv","data":{"bells":"${P.b64u(P.concat(b, new Uint8Array(48)))}"}}}`,
    );
  });
});

// ───────────── 8b. the bells a push names ─────────────

describe("the bells a push names (§9.8 `rang`)", () => {
  /** The bells named by the payload of a call, without the zero padding. */
  const named = (c: Call, d: Dev): string[] => {
    const j = JSON.parse(new TextDecoder().decode(decrypt(c.body, d))) as { notification: { data: { bells: string } } };
    const raw = P.fromB64u(j.notification.data.bells);
    expect(raw.length).toBe(64);
    const out: string[] = [];
    for (let i = 0; i < 64; i += 16) {
      const b = raw.subarray(i, i + 16);
      if (b.some((x) => x !== 0)) out.push(P.hex(b));
    }
    return out;
  };

  it("names the endpoint's bells that rang since its last push, newest first, at most 4, and only its own", async () => {
    await reset(BASE);
    const d = dev();
    const bs = bells(5);
    const other = P.random(16);
    await sub(d, bs);
    await sub(dev(), [other]);
    for (const b of bs) await ring([other, b]);
    await ring([bs[1]]); // a repeat moves to the front
    await run(BASE + DELTA * 1000);
    expect(callsTo(d)).toHaveLength(1);
    expect(named(callsTo(d)[0], d)).toEqual([bs[1], bs[4], bs[3], bs[2]].map(P.hex));
  });

  it("starts again after a push is sent, and after one is dropped", async () => {
    await reset(BASE);
    const d = dev();
    const [b1, b2, b3] = bells(3);
    await sub(d, [b1, b2, b3]);
    await ring([b1]);
    await run(BASE + DELTA * 1000);
    expect(named(callsTo(d)[0], d)).toEqual([P.hex(b1)]);
    await ring([b2]);
    await run(BASE + (PUSH_WINDOW + 2 * DELTA) * 1000);
    expect(callsTo(d)).toHaveLength(2);
    expect(named(callsTo(d)[1], d)).toEqual([P.hex(b2)]);
    expect((await stateOf(d)).rang).toEqual([]);

    fake.respond = () => new Response(null, { status: 500 });
    await ring([b3]);
    const t = BASE + (2 * PUSH_WINDOW + 3 * DELTA) * 1000;
    await run(t);
    await run(t + 10_000); // the retry fails too: dropped
    expect(callsTo(d)).toHaveLength(4);
    expect(named(callsTo(d)[3], d)).toEqual([P.hex(b3)]);
    expect((await stateOf(d)).rang).toEqual([]);
  });

  it("a push with no bell is as long as one with four", async () => {
    await reset(BASE);
    const d = dev();
    const e = dev();
    const bs = bells(4);
    await sub(d, bs);
    await sub(e, [P.random(16)]);
    for (const b of bs) await ring([b]);
    await inDO((h) => h.pushes.set(P.hex(e.ep), { ep: e.ep, last: null, due: BASE, tries: 0, first: 0, rang: [] }));
    await run(BASE + DELTA * 1000);
    expect(named(callsTo(d)[0], d)).toHaveLength(4);
    expect(named(callsTo(e)[0], e)).toHaveLength(0);
    expect(callsTo(d)[0].body.length).toBe(callsTo(e)[0].body.length);
  });
});

// ───────────── 9. push service answers ─────────────

describe("push service answers (§9.8)", () => {
  async function pushed(status: number | "throw", headers: Record<string, string> = {}): Promise<{ d: Dev; b: Bytes }> {
    const d = dev();
    const b = P.random(16);
    await sub(d, [b]);
    await run(fake.now! + DAY); // stored, so a deletion shows in the next pass
    fake.respond = () => {
      if (status === "throw") throw new TypeError("network");
      return new Response(null, { status, headers });
    };
    await ring([b]);
    await run(fake.now! + 1000);
    return { d, b };
  }

  it("201 ends it", async () => {
    await reset(BASE);
    const { d } = await pushed(201);
    expect(callsTo(d)).toHaveLength(1);
    expect(await stateOf(d)).toMatchObject({ due: null, last: fake.now });
  });

  it("429 with retry-after 5 is retried once after 5 s; 500 twice drops the push and keeps the endpoint", async () => {
    await reset(BASE);
    const { d, b } = await pushed(429, { "retry-after": "5" });
    expect(callsTo(d)).toHaveLength(1);
    expect((await stateOf(d)).due).toBe(callsTo(d)[0].at + 5000);
    fake.respond = () => new Response(null, { status: 201 });
    await run(callsTo(d)[0].at + 5000);
    expect(callsTo(d)).toHaveLength(2);

    const { d: e, b: be } = await pushed(500);
    expect((await stateOf(e)).due).toBe(callsTo(e)[0].at + 10_000);
    await run(callsTo(e)[0].at + 10_000);
    expect(callsTo(e)).toHaveLength(2);
    expect(await stateOf(e)).toMatchObject({ due: null, last: callsTo(e)[0].at });
    fake.now! += PUSH_WINDOW * 1000;
    expect(await reaches(e, [be])).toBe(true);
    expect(await reaches(d, [b])).toBe(true);
  });

  it("a network error is retried once, then dropped", async () => {
    await reset(BASE);
    const { d } = await pushed("throw");
    expect((await stateOf(d)).tries).toBe(1);
    await run(fake.now! + 10_000);
    expect(callsTo(d)).toHaveLength(2);
    expect((await stateOf(d)).due).toBeNull();
  });

  it.each([301, 302, 400, 401, 403, 404, 410, 413])("%d deletes the endpoint (redirects are never followed)", async (status) => {
    await reset(BASE);
    const { d, b } = await pushed(status, status < 400 ? { location: "https://elsewhere.push.test/x" } : {});
    expect(callsTo(d)).toHaveLength(1);
    expect(callsTo(d)[0].init.redirect).toBe("manual");
    fake.now! += PUSH_WINDOW * 1000;
    expect(await reaches(d, [b])).toBe(false);
    await run(fake.now! + DAY);
    expect(await storedDay(d)).toBeNull();
  });

  it("an endpoint whose host left PUSH_HOSTS is deleted without a request", async () => {
    await reset(BASE);
    const d = dev();
    const b = P.random(16);
    await sub(d, [b]);
    await setEnv({ PUSH_HOSTS: "other.push.test" });
    await ring([b]);
    await run(BASE + 1000);
    expect(fake.calls).toEqual([]);
    await setEnv({});
    expect(await reaches(d, [b])).toBe(false);
  });
});

// ───────────── 10. expiry and storage ─────────────

describe("expiry and what is stored (§9.8)", () => {
  it("deletes endpoints not refreshed for more than 30 days, and every endpoint after PUSH_KEY changes", async () => {
    await reset(BASE);
    const a = dev();
    const b = dev();
    await sub(a, bells(1));
    fake.now = BASE + 2 * DAY;
    await sub(b, bells(1));
    await run(BASE + 30 * DAY + 1000);
    expect(await storedDay(a)).toBe(dayOf(BASE));
    await run(BASE + 31 * DAY + 1000);
    expect(await storedDay(a)).toBeNull();
    expect(await storedDay(b)).toBe(dayOf(BASE) + 2);
    // A new PUSH_KEY: the old registration no longer opens; until the pass it counts toward PUSH_MAX_SUBS.
    await setEnv({ PUSH_KEY: P.b64u(P.random(32)), PUSH_MAX_SUBS: "2" });
    const again = dev();
    expect(await sub(again, bells(1))).toBe("ok");
    expect(await sub(dev(), bells(1))).toBe("full");
    await run(BASE + 32 * DAY + 1000);
    expect(await storedDay(b)).toBeNull();
    expect(await sub(dev(), bells(1))).toBe("ok");
  });

  it("stores only sub and tok: keyed hashes, a sealed box, no bell in the clear, nothing per ring, and logs nothing identifying", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await reset(BASE);
      const d = dev();
      const bs = bells(3);
      await sub(d, bs);
      await run(BASE + DAY + 1000);
      fake.respond = () => new Response(null, { status: 500 });
      await ring(bs);
      await run(BASE + DAY + 2000);
      await run(BASE + DAY + 20_000);
      const { names, kv, sub: subs, tok } = await inDO(async (_h, state) => ({
        names: state.storage.sql
          .exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite_%'")
          .toArray()
          .map((r) => r.name)
          .sort(),
        kv: (await state.storage.list()).size,
        sub: state.storage.sql.exec<{ ep: ArrayBuffer; box: ArrayBuffer; day: number }>("SELECT ep, box, day FROM sub").toArray(),
        tok: state.storage.sql.exec<{ tk: ArrayBuffer; ep: ArrayBuffer }>("SELECT tk, ep FROM tok").toArray(),
      }));
      expect(names).toEqual(["sub", "tok"]);
      expect(kv).toBe(0);
      expect(subs).toHaveLength(1);
      expect(P.hex(new Uint8Array(subs[0].ep))).toBe(P.hex(d.ep));
      const [e, k, a] = P.dec(P.aeadOpen(PUSH_KEY, new Uint8Array(subs[0].box), P.enc("segv.sh/v2/push/sub", d.ep)), 3);
      expect(new TextDecoder().decode(e)).toBe(d.endpoint);
      expect(P.hex(k)).toBe(P.hex(d.p256dh));
      expect(P.hex(a)).toBe(P.hex(d.auth));
      expect(() => P.aeadOpen(P.random(32), new Uint8Array(subs[0].box), P.enc("segv.sh/v2/push/sub", d.ep))).toThrow();
      expect(tok.map((r) => P.hex(new Uint8Array(r.tk))).sort()).toEqual(bs.map((x) => P.hex(tkOf(x))).sort());
      const all = P.hex(P.concat(...subs.flatMap((r) => [new Uint8Array(r.ep), new Uint8Array(r.box)]), ...tok.flatMap((r) => [new Uint8Array(r.tk), new Uint8Array(r.ep)])));
      for (const x of bs) expect(all).not.toContain(P.hex(x));
      const lines = log.mock.calls.map((c) => c.map(String).join(" ")).join("\n");
      expect(lines).toContain("push results");
      for (const s of [d.endpoint, P.b64u(d.p256dh), P.b64u(d.auth), ...bs.map(P.b64u), ...bs.map(P.hex), P.hex(d.ep)]) expect(lines).not.toContain(s);
    } finally {
      log.mockRestore();
    }
  });

  it("a restart loses the pushes due", async () => {
    await reset(BASE);
    const d = dev();
    const b = P.random(16);
    await sub(d, [b]);
    await run(BASE + DAY + 1000);
    await ring([b]);
    expect(await dueOf(d)).not.toBeNull();
    await restart();
    await run(BASE + DAY + 5000);
    expect(fake.calls).toEqual([]);
  });
});

// ───────────── 11. daily persistence and the fixed tick ─────────────

describe("only the daily pass writes, and the alarm follows the clock (§9.8)", () => {
  /** A stored, B new, A changed, C deleted by an empty set, D deleted by a 410 — all on day D+1. */
  async function dayOfChanges() {
    await reset(BASE);
    const [A, B, C, D] = [dev(), dev(), dev(), dev()];
    const [a1, a2, b1, c1, d1] = bells(5);
    await sub(A, [a1]);
    await sub(C, [c1]);
    await sub(D, [d1]);
    await run(BASE + DAY); // the 00:00 pass of D+1 writes A, C, D
    const before = await tables();
    fake.now = BASE + DAY + 3600_000;
    await sub(B, [b1]);
    await sub(A, [a2]);
    await sub(C, []);
    fake.respond = (c) => new Response(null, { status: c.url === D.endpoint ? 410 : 201 });
    await ring([d1]);
    await run(fake.now + 1000);
    return { A, B, C, D, a1, a2, b1, c1, d1, before };
  }

  it("(a) changes take effect at once in memory; the tables change only at the next 00:00 pass, in one transaction", async () => {
    const x = await dayOfChanges();
    expect(await reaches(x.B, [x.b1])).toBe(true);
    expect(await reaches(x.A, [x.a1])).toBe(false);
    expect(await reaches(x.A, [x.a2])).toBe(true);
    expect(await reaches(x.C, [x.c1])).toBe(false);
    expect(await reaches(x.D, [x.d1])).toBe(false);
    expect(await tables()).toEqual(x.before);
    await run(BASE + 2 * DAY - 1); // 23:59:59.999: still the same day
    expect(await tables()).toEqual(x.before);
    const partsBefore = (await inDO((h) => h.parts.length)) as number;
    await run(BASE + 2 * DAY);
    expect((await inDO((h) => h.parts.length)) - partsBefore).toBe(1);
    const t = await tables();
    expect(t.sub.map((r) => r.ep).sort()).toEqual([P.hex(x.A.ep), P.hex(x.B.ep)].sort());
    expect(t.tok.map((r) => r.tk).sort()).toEqual([P.hex(tkOf(x.a2)), P.hex(tkOf(x.b1))].sort());
  });

  it("(b) a restart before the pass brings back the stored registrations; the device's next sub restores its own", async () => {
    const x = await dayOfChanges();
    await restart();
    expect(await reaches(x.A, [x.a1])).toBe(true);
    expect(await reaches(x.D, [x.d1])).toBe(true);
    expect(await reaches(x.B, [x.b1])).toBe(false);
    await sub(x.B, [x.b1]);
    expect(await reaches(x.B, [x.b1])).toBe(true);
    // The next pass writes B's re-sent registration; a restart after it keeps everything.
    await run(BASE + 2 * DAY);
    await restart();
    expect(await reaches(x.B, [x.b1])).toBe(true);
    expect(await reaches(x.A, [x.a1])).toBe(true);
  });

  it("(c) rings write nothing: not the alarm, not the tables; the alarm keeps the PUSH_TICK grid", async () => {
    await reset(BASE);
    const d = dev();
    const b = P.random(16);
    await sub(d, [b]);
    await run(BASE + DAY);
    const alarm = () => inDO((_h, state) => state.storage.getAlarm());
    expect(await alarm()).toBe(nextTick(BASE + DAY));
    const t0 = await tables();
    for (const off of [1, 2500, 7000, 9999]) {
      fake.now = BASE + DAY + off;
      await ring([b]);
      expect(await alarm()).toBe(BASE + DAY + PUSH_TICK * 1000);
      expect(await tables()).toEqual(t0);
    }
    // A push due 700 ms after a run goes out at the next run, not earlier.
    await reset(BASE);
    await sub(d, [b]);
    fake.rand = 0.7;
    await ring([b]);
    const due = (await dueOf(d))!;
    await run(BASE + 500);
    expect(callsTo(d)).toHaveLength(0);
    await run(BASE + 10_000);
    expect(callsTo(d)).toHaveLength(1);
    expect(due).toBeLessThanOrEqual(BASE + 10_000);
    // With nothing registered and push off, the cadence is the same.
    await reset(BASE + 3_000);
    await setEnv({ VAPID_SK: undefined });
    await run();
    expect(await alarm()).toBe(BASE + 10_000);
    await run(BASE + 10_000);
    expect(await alarm()).toBe(BASE + 20_000);
  });

  it("(c) 120 due pushes go out within one run, 50 a second", async () => {
    await reset(BASE);
    const devs = Array.from({ length: 120 }, () => dev());
    const bs = devs.map(() => P.random(16));
    for (let i = 0; i < devs.length; i++) await sub(devs[i], [bs[i]]);
    await ring(bs.slice(0, 60));
    await ring(bs.slice(60));
    await run(BASE + 1000);
    expect(fake.calls).toHaveLength(120);
    const at = [...new Set(fake.calls.map((c) => c.at))].sort((p, q) => p - q);
    expect(at).toEqual([BASE + 1000, BASE + 2000, BASE + 3000]);
    expect(fake.calls.filter((c) => c.at === BASE + 1000)).toHaveLength(50);
  });

  it("(d) after a restart at noon the first pass writes nothing; a change at 23:59:59 is written at 00:00, never earlier", async () => {
    await reset(BASE);
    const d = dev();
    await sub(d, bells(1));
    await run(BASE + DAY);
    const t0 = await tables();
    fake.now = BASE + DAY + 12 * 3600_000;
    await restart();
    const e = dev();
    await sub(e, bells(1)); // the call that starts the object
    await run();
    expect(await tables()).toEqual(t0);
    fake.now = BASE + 2 * DAY - 1000;
    const f = dev();
    await sub(f, bells(1));
    await run(BASE + 2 * DAY - 500);
    expect(await storedDay(f)).toBeNull();
    await run(BASE + 2 * DAY);
    expect(await storedDay(e)).toBe(dayOf(BASE) + 1);
    expect(await storedDay(f)).toBe(dayOf(BASE) + 1);
  });

  it("(e) a refresh on the registration's last day, or just after midnight, keeps it; a restart losing it does not", async () => {
    await reset(BASE);
    const D = dayOf(BASE);
    const x = dev();
    const bx = bells(2);
    await sub(x, bx);
    await run(BASE + DAY);
    fake.now = BASE + 30 * DAY + 5000;
    await sub(x, bx); // an unchanged re-send on D+30
    await run(BASE + 31 * DAY);
    expect(await storedDay(x)).toBe(D + 30);

    const y = dev();
    const by = bells(1);
    fake.now = BASE + 40 * DAY;
    await sub(y, by);
    await run(BASE + 41 * DAY); // stored with day D+40
    fake.now = BASE + 71 * DAY + 5000; // 00:00:05 on D+71, before the pass reaches it
    await sub(y, by);
    await run(BASE + 71 * DAY + 10_000);
    expect(await storedDay(y)).toBe(D + 40); // kept, not yet rewritten
    await run(BASE + 72 * DAY);
    expect(await storedDay(y)).toBe(D + 71);

    const z = dev();
    const bz = bells(1);
    fake.now = BASE + 80 * DAY;
    await sub(z, bz);
    await run(BASE + 81 * DAY);
    fake.now = BASE + 111 * DAY + 5000;
    await sub(z, bz);
    await restart(); // the refresh is lost
    await run(BASE + 111 * DAY + 10_000);
    expect(await storedDay(z)).toBeNull();
    await sub(z, bz); // the device's next re-send registers it again
    expect(await reaches(z, bz)).toBe(true);
  });

  it("(e) a same-day re-send of a changed set keeps the change; a re-send equal to the stored set is a refresh", async () => {
    await reset(BASE);
    const x = dev();
    const [x1, x2] = bells(2);
    await sub(x, [x1]);
    await run(BASE + DAY);
    fake.now = BASE + DAY + 1000;
    await sub(x, [x2]);
    await sub(x, [x2]);
    await run(BASE + 2 * DAY);
    expect((await tables()).tok.map((r) => r.tk)).toEqual([P.hex(tkOf(x2))]);
    fake.now = BASE + 2 * DAY + 1000;
    await sub(x, [x1]);
    await sub(x, [x2]); // equal to what is stored: a refresh
    await run(BASE + 3 * DAY);
    expect((await tables()).tok.map((r) => r.tk)).toEqual([P.hex(tkOf(x2))]);
    expect(await storedDay(x)).toBe(dayOf(BASE) + 2);
  });

  it("(f) the constructor re-arms a lost alarm at the next PUSH_TICK, and writes nothing when one is set", async () => {
    await reset(BASE);
    await inDO((_h, state) => state.storage.deleteAlarm());
    await evictDurableObject(DO());
    const t0 = Date.now();
    const armed = await inDO((_h, state) => state.storage.getAlarm());
    expect(armed).not.toBeNull();
    expect(armed! % (PUSH_TICK * 1000)).toBe(0);
    expect(armed!).toBeGreaterThan(t0 - PUSH_TICK * 1000);
    expect(armed!).toBeLessThanOrEqual(nextTick(Date.now()));
    const later = nextTick(Date.now()) + 3 * DAY;
    await inDO((_h, state) => state.storage.setAlarm(later));
    await evictDurableObject(DO());
    expect(await inDO((_h, state) => state.storage.getAlarm())).toBe(later);
    await install(); // removes the alarm: set it again for the platform's run below
    await inDO((_h, state) => state.storage.setAlarm(later));
    // The platform's alarm runs the same tick.
    fake.now = later;
    expect(await runDurableObjectAlarm(DO())).toBe(true);
    expect(await inDO((_h, state) => state.storage.getAlarm())).toBe(later + PUSH_TICK * 1000);
  });
});

// ───────────── 12. the pass in parts ─────────────

describe("the daily pass works in bounded parts (§9.8)", () => {
  it("never reads, writes or deletes more than PUSH_ROWS rows in a run, never splits an endpoint, goes in ep order, resumes and retries", async () => {
    await reset(BASE);
    const old = Array.from({ length: 40 }, () => dev());
    for (const d of old) await sub(d, bells(256));
    const sender = dev();
    const sb = P.random(16);
    fake.now = BASE + 29 * DAY;
    await sub(sender, [sb]);
    await run(BASE + 30 * DAY); // writes all of them (default PUSH_ROWS) and expires nothing yet
    expect((await tables()).sub).toHaveLength(41);
    fake.now = BASE + 30 * DAY + 3600_000;
    const changed = Array.from({ length: 10 }, () => dev());
    for (const d of changed) await sub(d, bells(10));
    await inDO((h) => {
      h.pushRows = 600;
    });
    const partsAt = (await inDO((h) => h.parts.length)) as number;
    const tokCounts = async () => {
      const t = await tables();
      return old.map((d) => t.tok.filter((r) => r.ep === P.hex(d.ep)).length);
    };
    // The first part fails once (an injected storage error): nothing changes, and the next run tries it again.
    await inDO((h) => {
      let once = true;
      h.beforeCommit = () => {
        if (once) {
          once = false;
          throw new Error("injected");
        }
      };
    });
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    await ring([sb]);
    await run(BASE + 31 * DAY);
    log.mockRestore();
    expect((await tables()).sub).toHaveLength(41);
    expect(callsTo(sender)).toHaveLength(1); // sending goes on during the pass
    let runs = 0;
    for (let at = BASE + 31 * DAY + 10_000; runs < 4; at += 10_000, runs++) {
      await run(at);
      expect((await tokCounts()).every((n) => n === 0 || n === 256)).toBe(true);
    }
    const firstPass = (await inDO((h) => h.parts.slice(partsAt))) as PassPart[];
    // A restart in the middle: the next pass starts from the lowest ep and finds the committed parts done.
    const mid = await tables();
    expect(mid.sub.length).toBeLessThan(41 + 10);
    await restart();
    await inDO((h) => {
      h.pushRows = 600;
    });
    for (let at = BASE + 31 * DAY + 100_000; runs < 40; at += 10_000, runs++) await run(at);
    const end = await tables();
    // The 40 expired. Of the 10 changes, those that parts before the restart reached were written; the rest were lost.
    const written = changed.map((d) => P.hex(d.ep)).filter((h) => h <= firstPass[firstPass.length - 1].last!);
    expect(end.sub.map((r) => r.ep).sort()).toEqual([P.hex(sender.ep), ...written].sort());
    const secondPass = (await inDO((h) => h.parts)) as PassPart[];
    expect(firstPass).toHaveLength(4);
    expect(secondPass.length).toBeGreaterThan(5);
    for (const pass of [firstPass, secondPass]) {
      for (const p of pass) expect(p.rows).toBeLessThanOrEqual(600);
      // Each pass goes through the endpoints in ascending ep order.
      for (let i = 1; i < pass.length; i++) expect(pass[i].first! > pass[i - 1].last!).toBe(true);
    }
    // After the restart the pass started again from the lowest ep stored.
    expect(secondPass[0].first).toBe(mid.sub[0].ep);
  });

  it("writes the day's changes in parts too, in ascending ep whatever the order of the changes", async () => {
    await reset(BASE);
    const devs = Array.from({ length: 12 }, () => dev());
    for (const d of devs) await sub(d, bells(100));
    await inDO((h) => {
      h.pushRows = 300;
    });
    for (let i = 0; i < 12; i++) await run(BASE + DAY + i * 10_000);
    const t = await tables();
    expect(t.sub).toHaveLength(12);
    expect(t.tok).toHaveLength(1200);
    const parts = (await inDO((h) => h.parts)) as PassPart[];
    expect(parts.length).toBeGreaterThanOrEqual(6);
    for (const p of parts) expect(p.rows).toBeLessThanOrEqual(300);
    for (let i = 1; i < parts.length; i++) expect(parts[i].first! > parts[i - 1].last!).toBe(true);
  });
});
