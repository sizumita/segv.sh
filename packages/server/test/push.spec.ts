/**
 * Push (docs/PROTOCOL.md §9.8, §10.10): the configuration, the three endpoints, the registrations in the push store
 * through the QuietDOs and BellDOs, rings, the hold, the window, the pushes the Worker sends, marks of rows seen, the
 * queue for pushes due later, and the daily expiry.
 *
 * The objects hold nothing durable: each test starts from an empty store and evicted objects (reset()), replaces the
 * objects' clocks, randomness and sleeps, the Worker's wait and its push fetch. The objects' clock runs days ahead of
 * real time, so nothing of theirs depends on the wall clock; pushes go to *.push.test hosts through the fake fetch.
 */
import { gcm } from "@noble/ciphers/aes.js";
import { p256 } from "@noble/curves/nist.js";
import { createMessageBatch, evictDurableObject, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as P from "@segv/protocol/proto";
import * as W from "@segv/protocol/wire";
import { MAX_RING_BODY, MAX_SEEN_BODY, RING_FRESH, ringEraOk, ringRowFresh } from "../src/api";
import type { BellDO } from "../src/bell-do";
import { _resetPushConfigForTests } from "../src/env";
import {
  PUSH_EXPIRY,
  PUSH_HOLD,
  PUSH_PENDING,
  PUSH_SEEN,
  PUSH_WINDOW,
  RING_WAIT,
  SEEN_TTL,
  _setPushFetchForTests,
  _setRingSleepForTests,
  bellShard,
  dayOf,
  decodeEntries,
  decodeRecord,
  epOf,
  keyBell,
  keyEp,
  ownerOf,
  pushCleanup,
  pushQueue,
  qkOf,
  quietShard,
  rowIdOf,
  tkOf,
  type BellEntry,
  type EpRecord,
  type RingTarget,
} from "../src/push";
import type { PushState, QuietDO } from "../src/quiet-do";
import { bellStub, quietStub } from "../src/types";
import { vapidPublicKey } from "../src/webpush";
import {
  DELTA,
  DIFF2,
  direct,
  errorOf,
  freshIp,
  inOneRateWindow,
  makeRow,
  powHeader,
  putOk,
  type Bytes,
} from "./helpers";

const ENV = env as unknown as Record<string, string>;
const PUSH_KEY = P.fromB64u(ENV.PUSH_KEY);
const VAPID_PK = vapidPublicKey(P.fromB64u(ENV.VAPID_SK));
const SHARDS = Number(ENV.PUSH_SHARDS);
const DAY = 86_400_000;
/** Every push waits at least this long after its ring (§9.8 `ring`). */
const HOLD = PUSH_HOLD * 1000;
const N = p256.Point.Fn.ORDER;
const scalarB64 = (x: bigint): string =>
  P.b64u(
    Uint8Array.from(
      x
        .toString(16)
        .padStart(64, "0")
        .match(/../g)!
        .map((h) => parseInt(h, 16)),
    ),
  );

const tk = (bell: Bytes): Bytes => tkOf(PUSH_KEY, bell);
const qk = (Q: Bytes): Bytes => qkOf(PUSH_KEY, Q);
const bells = (n: number): Bytes[] => Array.from({ length: n }, () => P.random(16));

/** A browser's push subscription: its endpoint and its keys, and the quiet tag it last registered with. */
interface Dev {
  endpoint: string;
  ep: Bytes;
  sk: Bytes;
  p256dh: Bytes;
  auth: Bytes;
  quiet: Bytes | null;
}
let devSeq = 0;
function dev(host = "fcm.push.test"): Dev {
  const endpoint = `https://${host}/send/${P.hex(P.random(6))}${devSeq++}`;
  const sk = p256.utils.randomSecretKey();
  return {
    endpoint,
    ep: epOf(PUSH_KEY, endpoint),
    sk,
    p256dh: p256.getPublicKey(sk, false),
    auth: P.random(16),
    quiet: null,
  };
}
/** The QuietDO of a device: its owner is its account's quiet tag, or itself (§9.8). */
const kOf = (d: Dev): number => quietShard(ownerOf(d.ep, d.quiet ? qk(d.quiet) : null), SHARDS);
const quiet = (k: number) => quietStub(env, k);
const bell = (j: number) => bellStub(env, j);

/** RFC 8291's receiving side (one record). */
function decrypt(body: Bytes, d: Dev): Bytes {
  const salt = body.subarray(0, 16);
  expect(new DataView(body.buffer, body.byteOffset).getUint32(16)).toBe(4096);
  expect(body[20]).toBe(65);
  const asPublic = body.subarray(21, 86);
  const ecdh = p256.getSharedSecret(d.sk, asPublic, true).subarray(1);
  const one = Uint8Array.of(1);
  const ikm = P.HMAC(
    P.HMAC(d.auth, ecdh),
    P.concat(P.utf8("WebPush: info\0"), d.p256dh, asPublic, one),
  );
  const prk = P.HMAC(salt, ikm);
  const cek = P.HMAC(prk, P.concat(P.utf8("Content-Encoding: aes128gcm\0"), one)).slice(0, 16);
  const nonce = P.HMAC(prk, P.concat(P.utf8("Content-Encoding: nonce\0"), one)).slice(0, 12);
  const padded = gcm(cek, nonce).decrypt(body.subarray(86));
  expect(padded[padded.length - 1]).toBe(2);
  return padded.slice(0, -1);
}

// ───────────── the fake world ─────────────

interface Call {
  url: string;
  init: RequestInit;
  headers: Headers;
  body: Bytes;
  at: number;
}
const fake = {
  now: null as number | null,
  rand: 0,
  calls: [] as Call[],
  respond: ((): Response => new Response(null, { status: 201 })) as (
    c: Call,
  ) => Response | Promise<Response>,
  /** the messages the Worker put on the push queue */
  queued: [] as { k: number; delaySeconds: number }[],
};
const nowOf = (): number => fake.now ?? Date.now();
/** A UTC midnight well after real time. */
const BASE = (dayOf(Date.now()) + 5) * DAY;

type Hooks = { clock: () => number; rand: () => number; sleep: (ms: number) => Promise<void> };
const hook = async (): Promise<void> => {
  // The objects sleep only to space their writes to the store, which the local store does not need: no time passes.
  const h = { clock: nowOf, rand: () => fake.rand, sleep: async () => {} };
  for (let i = 0; i < SHARDS; i++) {
    await runInDurableObject(
      quiet(i),
      (inst: QuietDO) => void Object.assign(inst as unknown as Hooks, h),
    );
    await runInDurableObject(
      bell(i),
      (inst: BellDO) => void Object.assign(inst as unknown as Hooks, h),
    );
  }
};

/** The fake queue binding the tests give the Worker: it records, and the tests run the consumer by hand. */
const QUEUE = {
  send: async (body: { k: number }, opts?: { delaySeconds?: number }) => {
    fake.queued.push({ k: body.k, delaySeconds: opts?.delaySeconds ?? 0 });
  },
};
const OVER = { PUSH_QUEUE: QUEUE };

/** Evicts an object; one that is not running is already as evicted. */
async function evict(stub: DurableObjectStub): Promise<void> {
  try {
    await evictDurableObject(stub);
  } catch {
    /* not running */
  }
}

/** Empties the store (every key), evicts every object, resets the fakes and hooks the objects and the Worker again. */
async function reset(now: number | null = BASE): Promise<void> {
  let cursor: string | undefined;
  do {
    const page = await env.PUSH_KV.list({ cursor });
    for (const k of page.keys) await env.PUSH_KV.delete(k.name);
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  for (let i = 0; i < SHARDS; i++) {
    await evict(quiet(i));
    await evict(bell(i));
  }
  Object.assign(fake, {
    now,
    rand: 0,
    calls: [],
    queued: [],
    respond: () => new Response(null, { status: 201 }),
  });
  await hook();
  _setRingSleepForTests(async (ms) => {
    if (fake.now !== null) fake.now += ms;
  });
  _setPushFetchForTests(async (url, init) => {
    const call: Call = {
      url,
      init,
      headers: new Headers(init.headers),
      body: new Uint8Array(init.body as ArrayBuffer),
      at: nowOf(),
    };
    fake.calls.push(call);
    return fake.respond(call);
  });
}

/** A restart of the objects (an eviction): memory is lost, the store stays. */
async function restart(): Promise<void> {
  for (let i = 0; i < SHARDS; i++) {
    await evict(quiet(i));
    await evict(bell(i));
  }
  await hook();
}

// ───────────── driving the endpoints ─────────────

async function subApi(
  d: Dev,
  bs: Bytes[],
  q: Bytes | null = null,
  over: Record<string, unknown> = {},
): Promise<Response> {
  d.quiet = bs.length === 0 ? d.quiet : q;
  const body: Record<string, unknown> = {
    endpoint: d.endpoint,
    p256dh: P.b64u(d.p256dh),
    auth: P.b64u(d.auth),
    tokens: bs.map(P.b64u),
  };
  if (q) body.quiet = P.b64u(q);
  const bytes = P.utf8(JSON.stringify(body));
  return direct(
    "/api/v2/push/sub",
    {
      method: "POST",
      headers: { "x-segv-pow": await powHeader("push", P.H(bytes), { bytes: bytes.length }) },
      body: bytes,
    },
    { ...OVER, ...over },
  );
}
const sub = async (d: Dev, bs: Bytes[], q: Bytes | null = null): Promise<void> => {
  expect((await subApi(d, bs, q)).status).toBe(204);
};

interface RowRef {
  E: number;
  label: Bytes;
}
/** A row stored just now: the kind a ring can name (§10.10). */
async function freshRow(): Promise<RowRef> {
  const row = makeRow();
  await putOk([row]);
  return { E: row.E, label: row.label };
}
const ringBody = (r: RowRef, tokens: Bytes[], ver = 1): Bytes =>
  P.concat(Uint8Array.of(ver), P.u16(r.E), r.label, Uint8Array.of(tokens.length), ...tokens);
/** `POST /api/v2/ring`: the Worker looks the bells up, calls `ring`, waits and sends (or queues). */
async function ringApi(
  bs: Bytes[],
  row?: RowRef,
  over: Record<string, unknown> = {},
): Promise<RowRef> {
  const r = row ?? (await freshRow());
  const res = await direct(
    "/api/v2/ring",
    { method: "POST", body: ringBody(r, bs) },
    { ...OVER, ...over },
  );
  expect(res.status).toBe(204);
  return r;
}
/** `ring` alone, as the Worker calls it, without the wait and the send: what it makes due. */
async function ringState(bs: Bytes[], row?: RowRef): Promise<RowRef> {
  const r = row ?? { E: 1, label: P.random(16) };
  const byJ = new Map<number, Bytes[]>();
  for (const b of bs) {
    const j = bellShard(tk(b), SHARDS);
    byJ.set(j, [...(byJ.get(j) ?? []), tk(b)]);
  }
  const found = new Map<string, BellEntry[]>();
  for (const [j, tks] of byJ)
    for (const x of await bell(j).lookup(tks)) found.set(P.hex(x.tk), x.entries);
  const targets = new Map<string, RingTarget>();
  for (const b of bs) {
    for (const e of found.get(P.hex(tk(b))) ?? []) {
      const t = targets.get(P.hex(e.ep)) ?? { ep: e.ep, qh: e.qh, kh: e.kh, box: e.box, bells: [] };
      t.bells.push(b);
      targets.set(P.hex(e.ep), t);
    }
  }
  const byK = new Map<number, RingTarget[]>();
  for (const t of targets.values()) {
    const k = quietShard(ownerOf(t.ep, t.qh), SHARDS);
    byK.set(k, [...(byK.get(k) ?? []), t]);
  }
  for (const [k, list] of byK) await quiet(k).ring(list, rowIdOf(r.E, r.label));
  return r;
}
const seenBody = (qS: Bytes, rows: RowRef[], ver = 1): Bytes =>
  P.concat(
    Uint8Array.of(ver),
    qS,
    Uint8Array.of(rows.length),
    ...rows.flatMap((r) => [P.u16(r.E), r.label]),
  );
/** Runs the queue consumer for the messages queued so far (or the given ones), as the platform would when they come. */
async function drainQueue(ks?: number[]): Promise<void> {
  const list = ks ?? fake.queued.map((m) => m.k);
  fake.queued = [];
  const batch = createMessageBatch(
    "segv-push-test",
    list.map((k, i) => ({ id: `m${i}`, timestamp: new Date(nowOf()), attempts: 1, body: { k } })),
  );
  await pushQueue(batch, envOf(OVER));
}
/** `env` with the fake queue (and more), for the consumer and the expiry. */
function envOf(over: Record<string, unknown>): Env {
  return new Proxy(env, {
    get: (t, k) =>
      typeof k === "string" && Object.prototype.hasOwnProperty.call(over, k)
        ? over[k]
        : Reflect.get(t, k),
  });
}

const stateOf = (
  d: Dev,
): Promise<(Omit<PushState, "box" | "recent"> & { recent: string[] }) | null> =>
  quiet(kOf(d)).stateOf(d.ep);
const dueOf = async (d: Dev): Promise<number | null> => (await stateOf(d))?.due ?? null;
const callsTo = (d: Dev): Call[] => fake.calls.filter((c) => c.url === d.endpoint);
const marked = (q: Bytes): Promise<number> => quiet(quietShard(qk(q), SHARDS)).marksOf(qk(q));
/** The device's record in the store. */
async function record(d: Dev): Promise<EpRecord | null> {
  const raw = await env.PUSH_KV.get(keyEp(d.ep), "arrayBuffer");
  return raw ? decodeRecord(new Uint8Array(raw)) : null;
}
/** The endpoints under a bell in the store. */
async function holders(b: Bytes): Promise<string[]> {
  const raw = await env.PUSH_KV.get(keyBell(tk(b)), "arrayBuffer");
  return raw ? (decodeEntries(new Uint8Array(raw)) ?? []).map((e) => P.hex(e.ep)) : [];
}
/** Does a ring of `bs` (of a fresh row, or `row`) reach `d`? Reached rows enter the endpoint's recent rows. */
async function reaches(d: Dev, bs: Bytes[], row?: RowRef): Promise<boolean> {
  const r = await ringState(bs, row);
  return (await stateOf(d))?.recent.includes(rowIdOf(r.E, r.label)) ?? false;
}

// ───────────── 1. params and configuration ─────────────

describe("params and configuration (§9.8, §10.9)", () => {
  beforeEach(() => _resetPushConfigForTests());

  it("reports push and pow.push while push is on", async () => {
    const p = (await (await direct("/api/v2/params")).json()) as {
      push: unknown;
      pow: Record<string, number>;
    };
    expect(p.push).toEqual({ vapid: P.b64u(VAPID_PK), window: 60, maxTokens: 256 });
    expect(p.pow).toEqual(DIFF2);
    const dflt = (await (await direct("/api/v2/params", {}, { POW_PUSH: undefined })).json()) as {
      pow: Record<string, number>;
    };
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
    ["PUSH_SHARDS malformed", "PUSH_SHARDS", { PUSH_SHARDS: "4097" }],
    ["PUSH_SHARDS 0", "PUSH_SHARDS", { PUSH_SHARDS: "0" }],
    ["APP_HOSTS empty", "APP_HOSTS", { APP_HOSTS: "" }],
  ];

  it.each(OFF)(
    "%s: push is off exactly as unconfigured, and the rest of the API works",
    async (_name, setting, patch) => {
      const log = vi.spyOn(console, "error").mockImplementation(() => {});
      try {
        const params = await direct("/api/v2/params", {}, patch);
        expect(params.status).toBe(200);
        const p = (await params.json()) as Record<string, unknown> & {
          pow: Record<string, number>;
        };
        expect("push" in p).toBe(false);
        expect("push" in p.pow).toBe(false);
        const unknown = await errorOf(
          await direct("/api/v2/nope", { method: "POST", body: "x" }, patch),
        );
        for (const path of ["/api/v2/push/sub", "/api/v2/ring", "/api/v2/seen"]) {
          const r = await direct(path, { method: "POST", body: "x" }, patch);
          expect(r.status).toBe(404);
          expect(await errorOf(r)).toBe(unknown);
        }
        // A put, a get and a directory lookup answer as usual (never 503 "server misconfigured").
        const row = makeRow();
        const put = W.encodePutRequest([row]);
        const putRes = await direct(
          "/api/v2/put",
          {
            method: "POST",
            headers: { "x-segv-pow": await powHeader("put", P.H(put), { bytes: put.length }) },
            body: put,
          },
          patch,
        );
        expect(putRes.status).toBe(200);
        const get = W.encodeGetRequest([{ E: row.E, label: row.label, mode: 1 }]);
        expect((await direct("/api/v2/get", { method: "POST", body: get }, patch)).status).toBe(
          200,
        );
        expect((await direct(`/api/v2/dir/uid/${P.b64u(P.random(16))}`, {}, patch)).status).toBe(
          404,
        );
        const lines = log.mock.calls
          .map((c) => String(c[0]))
          .filter((l) => l.includes("push is off"));
        if (setting === null) expect(lines).toEqual([]);
        else {
          expect(lines).toHaveLength(1); // once per isolate, however many requests
          expect(JSON.parse(lines[0])).toEqual({ msg: "push is off: invalid setting", setting });
          for (const v of Object.values(patch))
            if (typeof v === "string" && v.length > 0) expect(lines[0]).not.toContain(v);
        }
      } finally {
        log.mockRestore();
      }
    },
  );
});

// ───────────── 2. push/sub ─────────────

describe("POST /api/v2/push/sub (§10.10)", () => {
  beforeEach(async () => {
    _resetPushConfigForTests();
    await reset(null);
  });
  /** The default PUSH_HOSTS list, for the host rules. */
  const DEF = { PUSH_HOSTS: undefined, ...OVER };
  const body = (over: Record<string, unknown> = {}): Record<string, unknown> => {
    const d = dev();
    return {
      endpoint: "https://fcm.googleapis.com/fcm/send/abc",
      p256dh: P.b64u(d.p256dh),
      auth: P.b64u(d.auth),
      tokens: [P.b64u(P.random(16))],
      ...over,
    };
  };
  async function post(
    b: unknown,
    opts: { pow?: boolean; ip?: string; raw?: Bytes } = {},
  ): Promise<Response> {
    const bytes = opts.raw ?? P.utf8(JSON.stringify(b));
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (opts.pow !== false)
      headers["x-segv-pow"] = await powHeader("push", P.H(bytes), { bytes: bytes.length });
    return direct("/api/v2/push/sub", { method: "POST", headers, body: bytes, ip: opts.ip }, DEF);
  }

  it("accepts a valid registration (204, no body), also on a real *.notify.windows.com host", async () => {
    for (const endpoint of [
      "https://fcm.googleapis.com/fcm/send/abc",
      "https://wns2-par02p.notify.windows.com/w/?token=AbC",
    ]) {
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
    [
      "a host that only resembles *.notify.windows.com",
      { endpoint: "https://notify.windows.com.example/w/abc" },
    ],
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
    ["a 15-byte quiet tag", { quiet: P.b64u(P.random(15)) }],
    ["a quiet tag that is not a string", { quiet: 1 }],
  ];
  it.each(BAD)("400 for %s", async (_name, over) => {
    expect(`https://fcm.googleapis.com/${"a".repeat(1025 - 27)}`.length).toBe(1025);
    expect((await post(body(over))).status).toBe(400);
  });

  it("takes the account's quiet tag, or none; a repeated token counts once; 256 distinct ones are accepted", async () => {
    expect((await post(body({ quiet: P.b64u(P.random(16)) }))).status).toBe(204);
    expect((await post(body())).status).toBe(204);
    const t = P.b64u(P.random(16));
    expect((await post(body({ tokens: [t, t, t] }))).status).toBe(204);
    expect((await post(body({ tokens: bells(256).map(P.b64u) }))).status).toBe(204);
  });

  it("403 without proof of work, 413 above 16 KiB, 429 from RL_WRITE", async () => {
    expect((await post(body(), { pow: false })).status).toBe(403);
    const big = P.utf8(JSON.stringify(body({ pad: "x".repeat(16 * 1024) })));
    expect((await post(null, { raw: big, pow: false })).status).toBe(413);
    const { statuses, over } = await inOneRateWindow(async () => {
      const ip = freshIp();
      const statuses: number[] = [];
      for (let i = 0; i < 60; i++) statuses.push((await post(body(), { pow: false, ip })).status);
      return { statuses, over: (await post(body(), { ip })).status };
    });
    expect(statuses.every((s) => s === 403)).toBe(true);
    expect(over).toBe(429);
  });

  it("503 storage unavailable when the QuietDO fails", async () => {
    const r = await direct(
      "/api/v2/push/sub",
      await (async () => {
        const bytes = P.utf8(JSON.stringify(body()));
        return {
          method: "POST" as const,
          headers: { "x-segv-pow": await powHeader("push", P.H(bytes), { bytes: bytes.length }) },
          body: bytes,
        };
      })(),
      {
        ...DEF,
        QUIET: {
          getByName: () => ({
            sub: async () => {
              throw new Error("down");
            },
          }),
        },
      },
    );
    expect(r.status).toBe(503);
    expect(r.headers.get("retry-after")).toBe("5");
    expect(await errorOf(r)).toBe("storage unavailable");
  });
});

// ───────────── 3. the registrations in the store ─────────────

describe("registrations in the store (§9.8 `sub`)", () => {
  beforeEach(async () => {
    _resetPushConfigForTests();
    await reset(BASE);
  });

  it("a registration writes the record and the bells at once; a second one replaces the set; an empty one deletes it", async () => {
    const d = dev();
    const [b1, b2, b3] = bells(3);
    await sub(d, [b1, b2]);
    const r1 = await record(d);
    expect(r1).not.toBeNull();
    expect(r1!.day).toBe(dayOf(BASE));
    expect(r1!.qh).toBeNull();
    expect(r1!.tks.map(P.hex).sort()).toEqual([tk(b1), tk(b2)].map(P.hex).sort());
    expect(await holders(b1)).toEqual([P.hex(d.ep)]);
    expect(await reaches(d, [b1])).toBe(true);
    expect(await reaches(d, [b2])).toBe(true);
    // The metadata the expiry reads: the day and the owner (the endpoint itself, without a quiet tag).
    const meta = (await env.PUSH_KV.getWithMetadata<{ d: number; o: string }>(keyEp(d.ep)))
      .metadata;
    expect(meta).toEqual({ d: dayOf(BASE), o: P.hex(d.ep) });

    await sub(d, [b3]);
    expect((await record(d))!.tks.map(P.hex)).toEqual([P.hex(tk(b3))]);
    expect(await holders(b1)).toEqual([]);
    expect(await env.PUSH_KV.get(keyBell(tk(b1)))).toBeNull(); // a bell with nobody left loses its key
    expect(await holders(b3)).toEqual([P.hex(d.ep)]);
    expect(await reaches(d, [b1])).toBe(false);
    expect(await reaches(d, [b3])).toBe(true);

    // A refresh three days later writes the day alone.
    fake.now = BASE + 3 * DAY;
    await sub(d, [b3]);
    expect((await record(d))!.day).toBe(dayOf(BASE) + 3);

    await sub(d, []);
    expect(await record(d)).toBeNull();
    expect(await holders(b3)).toEqual([]);
    expect(await reaches(d, [b3])).toBe(false);
  });

  it("the quiet tag makes the account's devices share a QuietDO, and new keys place the kept bells again", async () => {
    const q = P.random(16);
    const [phone, laptop] = [dev(), dev()];
    const b = P.random(16);
    await sub(phone, [b], q);
    await sub(laptop, [b], q);
    expect(kOf(phone)).toBe(kOf(laptop));
    expect((await record(phone))!.qh).toEqual(qk(q));
    expect((await env.PUSH_KV.getWithMetadata<{ o: string }>(keyEp(phone.ep))).metadata?.o).toBe(
      P.hex(qk(q)),
    );
    const entry = async (): Promise<BellEntry> =>
      (await bell(bellShard(tk(b), SHARDS)).entriesOf(tk(b))).find(
        (e) => P.hex(e.ep) === P.hex(phone.ep),
      )!;
    const before = await entry();
    // New keys under the same endpoint: the bell's entry carries the new box and kh.
    const sk = p256.utils.randomSecretKey();
    Object.assign(phone, { sk, p256dh: p256.getPublicKey(sk, false), auth: P.random(16) });
    await sub(phone, [b], q);
    const after = await entry();
    expect(P.hex(after.kh)).not.toBe(P.hex(before.kh));
    expect(P.hex(after.box)).not.toBe(P.hex(before.box));
    expect(await holders(b)).toHaveLength(2);
  });

  it("a bell's 8 places go to the first endpoints; a ninth is left out without evicting, and takes a freed place", async () => {
    const b = P.random(16);
    const eight = Array.from({ length: 8 }, () => dev());
    for (const d of eight) await sub(d, [b]);
    const ninth = dev();
    const own = P.random(16);
    await sub(ninth, [b, own]);
    expect((await record(ninth))!.tks.map(P.hex)).toEqual([P.hex(tk(own))]); // b was left out
    await ringState([b]);
    for (const d of eight) expect(await dueOf(d)).not.toBeNull();
    expect(await dueOf(ninth)).toBeNull();
    expect(await reaches(ninth, [own])).toBe(true); // its other bells work
    expect(await holders(b)).toHaveLength(8);
    await sub(eight[0], []);
    await sub(ninth, [b, own]);
    expect(await reaches(ninth, [b])).toBe(true);
  });

  it("a restart keeps every registration: the objects read the store back", async () => {
    const d = dev();
    const b = P.random(16);
    await sub(d, [b], P.random(16));
    await restart();
    expect(await reaches(d, [b])).toBe(true);
    await sub(d, []);
    await restart();
    expect(await reaches(d, [b])).toBe(false);
  });
});

// ───────────── 4. ring ─────────────

describe("POST /api/v2/ring (§10.10)", () => {
  beforeEach(async () => {
    _resetPushConfigForTests();
    await reset(null);
  });
  const post = (b: Bytes, ip?: string) =>
    direct("/api/v2/ring", { method: "POST", body: b, ip }, OVER);

  it("answers 204 with no body whatever the bell, the row or a repeat, and pushes only for a fresh row of a registered bell", async () => {
    const d = dev();
    const b = P.random(16);
    await sub(d, [b]);
    const row = await freshRow();
    const cases = [
      ringBody(row, [b]), // registered, fresh
      ringBody(row, [b]), // a repeat
      ringBody(row, [P.random(16)]), // unregistered
      ringBody({ E: row.E, label: P.random(16) }, [b]), // a missing row
      ringBody({ E: row.E + 5, label: row.label }, [b]), // outside the era bound
    ];
    const answers: string[] = [];
    for (const c of cases) {
      const r = await post(c);
      answers.push(`${r.status}|${await r.text()}|${r.headers.get("content-type")}`);
    }
    expect(new Set(answers)).toEqual(new Set(["204||null"]));
    // The first case made a push due (the Worker's wait is instant here, and in real time nothing is due yet).
    expect(await dueOf(d)).not.toBeNull();
    expect((await stateOf(d))!.recent).toHaveLength(1);
  });

  it("after the answer, the Worker waits as long as the QuietDO says and sends: the push goes out at its due time", async () => {
    const slept: number[] = [];
    _setRingSleepForTests(async (ms) => {
      slept.push(ms);
      fake.now! += ms;
    });
    fake.now = BASE;
    fake.rand = 0.5;
    const d = dev();
    const b = P.random(16);
    await sub(d, [b]);
    await ringApi([b]);
    expect(slept).toHaveLength(1);
    expect(slept[0]).toBeGreaterThanOrEqual(HOLD);
    expect(slept[0]).toBeLessThanOrEqual(HOLD + DELTA * 1000);
    expect(callsTo(d).map((c) => c.at)).toEqual([BASE + slept[0]]);
    // The next push waits for the end of PUSH_WINDOW, beyond RING_WAIT: a queue message, no wait in place.
    slept.length = 0;
    await ringApi([b]);
    expect(slept).toEqual([]);
    const due = (await dueOf(d))!;
    expect(due - fake.now!).toBeGreaterThan(RING_WAIT);
    expect(fake.queued).toEqual([{ k: kOf(d), delaySeconds: Math.ceil((due - fake.now!) / 1000) }]);
    expect(callsTo(d)).toHaveLength(1);
    // The consumer, when the message comes, sends it.
    fake.now = due;
    await drainQueue();
    expect(callsTo(d)).toHaveLength(2);
    expect(callsTo(d)[1].at).toBe(due);
  });

  it("400 for ver 2, n 0, n 65 or a length mismatch; 413 above 1044 bytes; 429 from RL_RING; no proof of work", async () => {
    const l = { E: 1, label: P.random(16) };
    expect((await post(ringBody(l, [P.random(16)], 2))).status).toBe(400);
    expect(
      (await post(P.concat(Uint8Array.of(1), P.u16(1), l.label, Uint8Array.of(0)))).status,
    ).toBe(400);
    expect(
      (await post(P.concat(Uint8Array.of(1), P.u16(1), l.label, Uint8Array.of(65), ...bells(65))))
        .status,
    ).toBe(413);
    expect((await post(P.concat(ringBody(l, bells(2)), P.random(1)))).status).toBe(400);
    expect((await post(ringBody(l, bells(2)).subarray(0, 40))).status).toBe(400);
    expect(MAX_RING_BODY).toBe(20 + 16 * 64);
    const { statuses, over } = await inOneRateWindow(async () => {
      const ip = freshIp();
      const statuses: number[] = [];
      for (let i = 0; i < 60; i++)
        statuses.push(
          (await post(ringBody({ E: 1, label: P.random(16) }, [P.random(16)]), ip)).status,
        );
      return {
        statuses,
        over: (await post(ringBody({ E: 1, label: P.random(16) }, [P.random(16)]), ip)).status,
      };
    });
    expect(statuses.every((s) => s === 204)).toBe(true);
    expect(over).toBe(429);
  });
});

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

  it("the same row rung twice reaches an endpoint once; another row reaches it again", async () => {
    await reset(BASE);
    const d = dev();
    const b = P.random(16);
    await sub(d, [b]);
    const row = { E: 1, label: P.random(16) };
    await ringState([b], row);
    const due = await dueOf(d);
    expect(due).not.toBeNull();
    fake.now = BASE + 1000;
    await ringState([b], row); // the sender's retry
    expect((await stateOf(d))!.rows?.size).toBe(1);
    expect(await dueOf(d)).toBe(due);
    await ringState([b]); // another row joins the same push
    expect((await stateOf(d))!.rows?.size).toBe(2);
  });
});

// ───────────── 5. coalescing and jitter ─────────────

describe("one push per endpoint per PUSH_WINDOW, with jitter (§9.8)", () => {
  it("two rings 10 s apart give two pushes at least PUSH_WINDOW apart; more rings within the window add nothing", async () => {
    await reset(BASE);
    fake.rand = 0.5;
    const d = dev();
    const b = P.random(16);
    await sub(d, [b]);
    await ringApi([b]);
    expect(callsTo(d)).toHaveLength(1);
    const sent1 = callsTo(d)[0].at;
    expect(sent1 - BASE).toBeGreaterThanOrEqual(HOLD);
    expect(sent1 - BASE).toBeLessThanOrEqual(HOLD + DELTA * 1000); // PUSH_HOLD, then PUSH_JITTER = Δ
    fake.now = BASE + 10_000;
    await ringApi([b]);
    const due2 = (await dueOf(d))!;
    expect(due2).toBeGreaterThanOrEqual(sent1 + PUSH_WINDOW * 1000);
    expect(due2).toBeLessThanOrEqual(sent1 + PUSH_WINDOW * 1000 + DELTA * 1000);
    fake.now = BASE + 20_000;
    await ringApi([b]);
    await ringApi([b]);
    expect(await dueOf(d)).toBe(due2);
    expect(callsTo(d)).toHaveLength(1);
    expect(fake.queued).toHaveLength(3); // one message per ring; the consumer finds the push once
    fake.now = due2;
    await drainQueue();
    expect(callsTo(d)).toHaveLength(2);
    expect(callsTo(d)[1].at - sent1).toBeGreaterThanOrEqual(PUSH_WINDOW * 1000);
    await drainQueue([kOf(d)]); // a stray message finds nothing due
    expect(callsTo(d)).toHaveLength(2);
  });
});

// ───────────── 6. the push request ─────────────

describe("the push request (§9.8)", () => {
  it("carries the Web Push headers, an ES256 VAPID JWT, no redirects, and the payload encrypted to the subscription", async () => {
    await reset(BASE);
    const d = dev("updates.push.test");
    const b = P.random(16);
    await sub(d, [b]);
    const real = Date.now();
    await ringApi([b]);
    const [c] = callsTo(d);
    expect(c.init.method).toBe("POST");
    expect(c.init.redirect).toBe("manual");
    expect(c.headers.get("ttl")).toBe("86400");
    expect(c.headers.get("urgency")).toBe("high");
    expect(c.headers.get("topic")).toBe("segv");
    expect(c.headers.get("content-encoding")).toBe("aes128gcm");
    expect(c.headers.get("content-type")).toBe("application/octet-stream");
    const m = /^vapid t=([\w-]+\.[\w-]+\.[\w-]+), k=([\w-]+)$/.exec(
      c.headers.get("authorization") ?? "",
    );
    expect(m).not.toBeNull();
    expect(m![2]).toBe(P.b64u(VAPID_PK));
    const [h, claims, sig] = m![1].split(".");
    expect(JSON.parse(new TextDecoder().decode(P.fromB64u(h)))).toEqual({
      typ: "JWT",
      alg: "ES256",
    });
    const cl = JSON.parse(new TextDecoder().decode(P.fromB64u(claims))) as {
      aud: string;
      exp: number;
      sub: string;
    };
    expect(cl.aud).toBe("https://updates.push.test");
    expect(cl.sub).toBe(ENV.VAPID_SUB);
    expect(cl.exp).toBeGreaterThan(Math.floor(real / 1000));
    expect(cl.exp).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 12 * 3600);
    expect(p256.verify(P.fromB64u(sig), P.utf8(`${h}.${claims}`), VAPID_PK, { lowS: false })).toBe(
      true,
    );
    expect(new TextDecoder().decode(decrypt(c.body, d))).toBe(
      `{"web_push":8030,"mutable":true,"notification":{"title":"segv.sh","body":"new messages","navigate":"https://segv.test/","tag":"segv","data":{"bells":"${P.b64u(P.concat(b, new Uint8Array(48)))}"}}}`,
    );
  });
});

// ───────────── 7. the bells a push names ─────────────

describe("the bells a push names (§9.8 `rang`)", () => {
  /** The bells named by the payload of a call, without the zero padding. */
  const named = (c: Call, d: Dev): string[] => {
    const j = JSON.parse(new TextDecoder().decode(decrypt(c.body, d))) as {
      notification: { data: { bells: string } };
    };
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
    for (const b of bs) await ringState([other, b]);
    await ringState([bs[1]]); // a repeat moves to the front
    fake.now = BASE + HOLD + DELTA * 1000;
    await drainQueue([kOf(d)]);
    expect(callsTo(d)).toHaveLength(1);
    expect(named(callsTo(d)[0], d)).toEqual([bs[1], bs[4], bs[3], bs[2]].map(P.hex));
    expect((await stateOf(d))!.rang).toEqual([]);
  });

  it("a push with no bell is as long as one with four", async () => {
    await reset(BASE);
    const d = dev();
    const bs = bells(4);
    await sub(d, bs);
    for (const b of bs) await ringState([b]);
    const e = dev();
    await sub(e, [P.random(16)]);
    await ringState([P.random(16)]); // nobody
    fake.now = BASE + HOLD + DELTA * 1000;
    await drainQueue([kOf(d)]);
    expect(named(callsTo(d)[0], d)).toHaveLength(4);
    // A push naming no bell: made by hand through a ring whose bells are not the endpoint's own? None reaches it; so
    // compare with the payload of a device whose single ring bell is zero-padded to the same 64 bytes.
    const f = dev();
    const fb = P.random(16);
    await sub(f, [fb]);
    await ringApi([fb]);
    expect(callsTo(f)[0].body.length).toBe(callsTo(d)[0].body.length);
  });
});

// ───────────── 8. push service answers ─────────────

describe("push service answers (§9.8)", () => {
  async function pushed(
    status: number | "throw",
    headers: Record<string, string> = {},
  ): Promise<{ d: Dev; b: Bytes }> {
    const d = dev();
    const b = P.random(16);
    await sub(d, [b]);
    fake.respond = () => {
      if (status === "throw") throw new TypeError("network");
      return new Response(null, { status, headers });
    };
    await ringApi([b]);
    return { d, b };
  }

  it("201 ends it", async () => {
    await reset(BASE);
    const { d } = await pushed(201);
    expect(callsTo(d)).toHaveLength(1);
    expect(await stateOf(d)).toMatchObject({ due: null, last: fake.now, inflight: null });
    expect(fake.queued).toEqual([]);
  });

  it("429 with retry-after 5 is retried once after 5 s through the queue; 500 twice drops the push and keeps the endpoint", async () => {
    await reset(BASE);
    const { d, b } = await pushed(429, { "retry-after": "5" });
    expect(callsTo(d)).toHaveLength(1);
    expect((await stateOf(d))!.due).toBe(callsTo(d)[0].at + 5000);
    expect(fake.queued).toEqual([{ k: kOf(d), delaySeconds: 5 }]);
    fake.respond = () => new Response(null, { status: 201 });
    fake.now = callsTo(d)[0].at + 5000;
    await drainQueue();
    expect(callsTo(d)).toHaveLength(2);
    expect(await stateOf(d)).toMatchObject({ due: null, last: fake.now, tries: 0 });

    const { d: e, b: be } = await pushed(500);
    expect((await stateOf(e))!.due).toBe(callsTo(e)[0].at + 10_000);
    fake.now = callsTo(e)[0].at + 10_000;
    await drainQueue();
    expect(callsTo(e)).toHaveLength(2);
    expect(await stateOf(e)).toMatchObject({ due: null, last: callsTo(e)[0].at });
    expect(await record(e)).not.toBeNull(); // kept
    fake.now! += PUSH_WINDOW * 1000;
    expect(await reaches(e, [be])).toBe(true);
    expect(await reaches(d, [b])).toBe(true);
  });

  it("a network error is retried once, then dropped", async () => {
    await reset(BASE);
    const { d } = await pushed("throw");
    expect((await stateOf(d))!.tries).toBe(1);
    fake.now! += 10_000;
    await drainQueue();
    expect(callsTo(d)).toHaveLength(2);
    expect((await stateOf(d))!.due).toBeNull();
  });

  it.each([301, 302, 400, 401, 403, 404, 410, 413])(
    "%d deletes the registration (redirects are never followed)",
    async (status) => {
      await reset(BASE);
      const { d, b } = await pushed(
        status,
        status < 400 ? { location: "https://elsewhere.push.test/x" } : {},
      );
      expect(callsTo(d)).toHaveLength(1);
      expect(callsTo(d)[0].init.redirect).toBe("manual");
      expect(await record(d)).toBeNull();
      expect(await holders(b)).toEqual([]);
      fake.now! += PUSH_WINDOW * 1000;
      expect(await reaches(d, [b])).toBe(false);
    },
  );

  it("a gone answer leaves a registration made with other keys meanwhile", async () => {
    await reset(BASE);
    const d = dev();
    const b = P.random(16);
    await sub(d, [b]);
    fake.respond = async () => {
      // The device registered new keys while the push was in flight.
      const sk = p256.utils.randomSecretKey();
      Object.assign(d, { sk, p256dh: p256.getPublicKey(sk, false), auth: P.random(16) });
      await sub(d, [b]);
      return new Response(null, { status: 410 });
    };
    await ringApi([b]);
    expect(callsTo(d)).toHaveLength(1);
    expect(await record(d)).not.toBeNull();
    expect(await holders(b)).toEqual([P.hex(d.ep)]);
  });

  it("an endpoint whose host left PUSH_HOSTS is deleted without a request", async () => {
    await reset(BASE);
    const d = dev();
    const b = P.random(16);
    await sub(d, [b]);
    _resetPushConfigForTests();
    await ringApi([b], undefined, { PUSH_HOSTS: "other.push.test" });
    expect(fake.calls).toEqual([]);
    expect(await record(d)).toBeNull();
    _resetPushConfigForTests();
    expect(await reaches(d, [b])).toBe(false);
  });
});

// ───────────── 9. expiry and what is stored ─────────────

describe("expiry and what is stored (§9.8)", () => {
  it("the daily expiry deletes endpoints not refreshed for more than 30 days, with or without the key", async () => {
    await reset(BASE);
    const a = dev();
    const b = dev();
    const ba = P.random(16);
    await sub(a, [ba]);
    fake.now = BASE + 2 * DAY;
    await sub(b, bells(1));
    expect(await pushCleanup(env, BASE + 30 * DAY + 1000)).toEqual({ scanned: 2, expired: 0 });
    expect(await record(a)).not.toBeNull();
    _resetPushConfigForTests();
    expect(await pushCleanup(envOf({ PUSH_KEY: undefined }), BASE + 31 * DAY + 1000)).toEqual({
      scanned: 2,
      expired: 1,
    });
    _resetPushConfigForTests();
    expect(await record(a)).toBeNull();
    expect(await holders(ba)).toEqual([]);
    expect(await record(b)).not.toBeNull();
    expect(await pushCleanup(env, BASE + 33 * DAY)).toEqual({ scanned: 1, expired: 1 });
    expect(await record(b)).toBeNull();
    expect(PUSH_EXPIRY).toBe(30);
  });

  it("stores records and bells only: keyed hashes, sealed boxes, no bell in the clear, nothing per ring, nothing in the objects, and logs nothing identifying", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await reset(BASE);
      const d = dev();
      const bs = bells(3);
      const q = P.random(16);
      await sub(d, bs, q);
      fake.respond = () => new Response(null, { status: 500 });
      await ringApi(bs);
      fake.now! += 10_000;
      await drainQueue();
      const keys: string[] = [];
      const values: Bytes[] = [];
      let cursor: string | undefined;
      do {
        const page = await env.PUSH_KV.list({ cursor });
        for (const k of page.keys) {
          keys.push(k.name);
          values.push(new Uint8Array((await env.PUSH_KV.get(k.name, "arrayBuffer"))!));
        }
        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor);
      expect(keys.sort()).toEqual([...bs.map((b) => keyBell(tk(b))), keyEp(d.ep)].sort());
      const rec = (await record(d))!;
      expect(rec.tks.map(P.hex).sort()).toEqual(bs.map((b) => P.hex(tk(b))).sort());
      expect(P.hex(rec.qh!)).toBe(P.hex(qk(q)));
      for (const b of bs) {
        const [e] = decodeEntries(
          new Uint8Array((await env.PUSH_KV.get(keyBell(tk(b)), "arrayBuffer"))!),
        )!;
        expect(P.hex(e.ep)).toBe(P.hex(d.ep));
        const [ep, k, a] = P.dec(
          P.aeadOpen(PUSH_KEY, e.box, P.enc("segv.sh/v2/push/sub", d.ep)),
          3,
        );
        expect(new TextDecoder().decode(ep)).toBe(d.endpoint);
        expect(P.hex(k)).toBe(P.hex(d.p256dh));
        expect(P.hex(a)).toBe(P.hex(d.auth));
        expect(() => P.aeadOpen(P.random(32), e.box, P.enc("segv.sh/v2/push/sub", d.ep))).toThrow();
      }
      const all = keys.join("|") + P.hex(P.concat(...values));
      for (const x of [...bs, q]) {
        expect(all).not.toContain(P.hex(x));
        expect(all).not.toContain(P.b64u(x));
      }
      // The objects store nothing: no table, no key, no alarm.
      for (let i = 0; i < SHARDS; i++) {
        for (const stub of [quiet(i), bell(i)]) {
          const stored = await runInDurableObject(
            stub as DurableObjectStub<QuietDO>,
            async (_inst, state) => ({
              tables: state.storage.sql
                .exec<{ name: string }>(
                  "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite_%'",
                )
                .toArray()
                .map((r) => r.name),
              kv: (await state.storage.list()).size,
              alarm: await state.storage.getAlarm(),
            }),
          );
          expect(stored).toEqual({ tables: [], kv: 0, alarm: null });
        }
      }
      const lines = log.mock.calls.map((c) => c.map(String).join(" ")).join("\n");
      expect(lines).toContain("push results");
      for (const s of [
        d.endpoint,
        P.b64u(d.p256dh),
        P.b64u(d.auth),
        ...bs.map(P.b64u),
        ...bs.map(P.hex),
        P.hex(d.ep),
        P.hex(q),
      ])
        expect(lines).not.toContain(s);
    } finally {
      log.mockRestore();
    }
  });

  it("a restart loses the pushes due, not the registrations", async () => {
    await reset(BASE);
    const d = dev();
    const b = P.random(16);
    await sub(d, [b]);
    await ringState([b]);
    expect(await dueOf(d)).not.toBeNull();
    await restart();
    expect(await dueOf(d)).toBeNull();
    fake.now = BASE + HOLD + DELTA * 1000;
    await drainQueue([kOf(d)]);
    expect(fake.calls).toEqual([]);
    expect(await reaches(d, [b])).toBe(true);
  });
});

// ───────────── 10. seen ─────────────

describe("POST /api/v2/seen (§10.10)", () => {
  beforeEach(async () => {
    _resetPushConfigForTests();
    await reset(null);
  });
  const post = (b: Bytes, ip?: string) =>
    direct("/api/v2/seen", { method: "POST", body: b, ip }, OVER);

  it("answers 204 with no body whatever it marks; only the secret whose hash is the registered tag marks", async () => {
    const qS = P.random(16);
    const d = dev();
    await sub(d, [P.random(16)], P.quietTag(qS));
    const label = P.random(16);
    const at = (l: Bytes, E = 1): RowRef => ({ E, label: l });
    const cases: [Bytes, number][] = [
      [seenBody(P.quietTag(qS), [at(label)]), 0], // the tag, which push/sub sent, is not the secret
      [seenBody(P.random(16), [at(label)]), 0], // another account's secret
      [seenBody(qS, [at(label), at(label)]), 1], // a repeated row counts once
      [seenBody(qS, [at(label, 2)]), 2], // the same label in another era is another row
    ];
    const answers: string[] = [];
    for (const [b, n] of cases) {
      const r = await post(b);
      answers.push(`${r.status}|${await r.text()}|${r.headers.get("content-type")}`);
      expect(await marked(P.quietTag(qS))).toBe(n);
    }
    expect(new Set(answers)).toEqual(new Set(["204||null"]));
  });

  it("400 for ver 2, n 0, n 17 or a length mismatch; 413 above 306 bytes; 429 from RL_SEEN, not RL_RING; no proof of work", async () => {
    const qS = P.random(16);
    const rows = (n: number): RowRef[] =>
      Array.from({ length: n }, () => ({ E: 1, label: P.random(16) }));
    expect(MAX_SEEN_BODY).toBe(18 + 18 * 16);
    expect((await post(seenBody(qS, rows(1), 2))).status).toBe(400);
    expect((await post(seenBody(qS, []))).status).toBe(400);
    const n17 = seenBody(qS, rows(16));
    n17[17] = 17;
    expect((await post(n17)).status).toBe(400);
    expect((await post(seenBody(qS, rows(2)).subarray(0, 36))).status).toBe(400);
    expect((await post(P.concat(seenBody(qS, rows(2)), P.random(1)))).status).toBe(400);
    expect((await post(P.concat(seenBody(qS, rows(16)), P.random(1)))).status).toBe(413);
    const { ip, statuses, over } = await inOneRateWindow(async () => {
      const ip = freshIp();
      const statuses: number[] = [];
      for (let i = 0; i < 60; i++)
        statuses.push((await post(seenBody(P.random(16), rows(1)), ip)).status);
      return { ip, statuses, over: (await post(seenBody(P.random(16), rows(1)), ip)).status };
    });
    expect(statuses.every((s) => s === 204)).toBe(true);
    expect(over).toBe(429);
    const ring = P.concat(Uint8Array.of(1), P.u16(1), P.random(16), Uint8Array.of(1), P.random(16));
    expect((await direct("/api/v2/ring", { method: "POST", body: ring, ip }, OVER)).status).toBe(
      204,
    );
  });
});

describe("the QuietDO holds pushes for marks of rows seen (§9.8 `seen`)", () => {
  const seen = (Q: Bytes, rows: RowRef[]) => quiet(quietShard(qk(Q), SHARDS)).seen(qk(Q), rows);

  it("a mark before the ring keeps every endpoint of the account from the push, and nobody else's", async () => {
    await reset(BASE);
    const [phone, laptop, member, plain] = [dev(), dev(), dev(), dev()];
    const b = P.random(16); // bob's bell, which every member of the conversation computes
    const [qBob, qMember] = [P.random(16), P.random(16)];
    await sub(phone, [b], qBob);
    await sub(laptop, [b], qBob);
    await sub(member, [b], qMember); // a member who registered its own endpoint under bob's bell
    await sub(plain, [b]); // a tab of an earlier release: no quiet tag
    const row = { E: 1, label: P.random(16) };
    await seen(qBob, [row]);
    await ringState([b], row);
    expect(await dueOf(phone)).toBeNull();
    expect(await dueOf(laptop)).toBeNull();
    expect(await dueOf(member)).not.toBeNull();
    expect(await dueOf(plain)).not.toBeNull();
    fake.now = BASE + HOLD + DELTA * 1000;
    await drainQueue([kOf(member), kOf(plain)]);
    expect(callsTo(phone)).toHaveLength(0);
    expect(callsTo(laptop)).toHaveLength(0);
    expect(callsTo(member)).toHaveLength(1);
    expect(callsTo(plain)).toHaveLength(1);
  });

  it("a mark after the ring cancels the waiting push once every row that rang it is marked; `last` stays", async () => {
    await reset(BASE);
    const d = dev();
    const b = P.random(16);
    const q = P.random(16);
    await sub(d, [b], q);
    const [l1, l2] = [
      { E: 1, label: P.random(16) },
      { E: 1, label: P.random(16) },
    ];
    await ringState([b], l1);
    await ringState([b], l2);
    expect((await stateOf(d))!.rows?.size).toBe(2);
    await seen(q, [l1]);
    expect(await dueOf(d)).not.toBeNull();
    fake.now = BASE + 1000;
    await seen(q, [l2]);
    expect(await stateOf(d)).toMatchObject({ due: null, last: null, tries: 0, rang: [] });
    fake.now = BASE + HOLD + DELTA * 1000;
    await drainQueue([kOf(d)]);
    expect(callsTo(d)).toHaveLength(0);
    await ringApi([b]);
    expect(callsTo(d)).toHaveLength(1);
    const { last } = (await stateOf(d))!;
    expect(last).not.toBeNull();
    const l3 = { E: 1, label: P.random(16) };
    await ringState([b], l3);
    expect(await dueOf(d)).toBeGreaterThanOrEqual(last! + PUSH_WINDOW * 1000);
    await seen(q, [l3]);
    expect(await stateOf(d)).toMatchObject({ due: null, last });
  });

  it("a mark comes too late for a push in flight: it stops only its retry", async () => {
    await reset(BASE);
    const d = dev();
    const b = P.random(16);
    const q = P.random(16);
    await sub(d, [b], q);
    const row = { E: 1, label: P.random(16) };
    await ringState([b], row);
    fake.now = BASE + HOLD + DELTA * 1000;
    const k = kOf(d);
    const due = await quiet(k).due(); // in flight now
    expect(due).toHaveLength(1);
    await seen(q, [row]);
    expect(await dueOf(d)).not.toBeNull(); // not cancelled
    const wait = await quiet(k).sent([
      { ep: d.ep, kh: due[0].kh, outcome: "retry", retryAfterS: null },
    ]);
    expect(wait).toBeNull(); // cancelled instead of retried
    expect(await stateOf(d)).toMatchObject({ due: null, tries: 0 });
  });

  it("past PUSH_PENDING rows a push can no longer be cancelled", async () => {
    await reset(BASE);
    const d = dev();
    const b = P.random(16);
    const q = P.random(16);
    await sub(d, [b], q);
    const rows = Array.from({ length: PUSH_PENDING + 1 }, () => ({ E: 1, label: P.random(16) }));
    for (const r of rows) await ringState([b], r);
    expect((await stateOf(d))!.rows).toBeNull();
    await seen(q, rows.slice(0, 16));
    await seen(q, rows.slice(16));
    expect(await dueOf(d)).not.toBeNull();
  });

  it("the quiet tag is stored as a keyed hash under its own label: a bell never reaches it, nor it a bell", async () => {
    await reset(BASE);
    const d = dev();
    const b = P.random(16);
    const q = P.random(16);
    await sub(d, [b], q);
    const rec = (await record(d))!;
    expect(rec.tks.map(P.hex)).toEqual([P.hex(tk(b))]);
    expect(P.hex(rec.qh!)).toBe(P.hex(qk(q)));
    expect(P.hex(qk(q))).not.toBe(P.hex(tk(q)));
    expect(await reaches(d, [q])).toBe(false); // the tag rung as a bell
    const row = { E: 1, label: P.random(16) };
    await seen(b, [row]); // a bell given as the tag marks under another hash than the bell's
    expect(await reaches(d, [b], row)).toBe(true);
  });

  it("marks last SEEN_TTL, at most PUSH_SEEN per account (the first to expire goes), and a restart forgets them", async () => {
    await reset(BASE);
    const d = dev();
    const [b, b2] = bells(2);
    const q = P.random(16);
    await sub(d, [b, b2], q);
    const t0 = BASE + 1000;
    fake.now = t0;
    const row = { E: 1, label: P.random(16) };
    await seen(q, [row]);
    fake.now = t0 + SEEN_TTL * 1000 - 1;
    expect(await reaches(d, [b], row)).toBe(false);
    fake.now = t0 + SEEN_TTL * 1000;
    expect(await reaches(d, [b2], row)).toBe(true);
    expect(await marked(q)).toBe(0); // expired marks are dropped

    const rows = Array.from({ length: PUSH_SEEN + 1 }, () => ({ E: 1, label: P.random(16) }));
    for (const r of rows) await seen(q, [r]);
    expect(await marked(q)).toBe(PUSH_SEEN);
    expect(await reaches(d, [b], rows[0])).toBe(true); // the first mark went
    expect(await reaches(d, [b], rows[1])).toBe(false);

    const l = { E: 1, label: P.random(16) };
    await seen(q, [l]);
    await restart();
    expect(await marked(q)).toBe(0);
    expect(await reaches(d, [b], l)).toBe(true);
  });
});

afterEach(() => {
  _setRingSleepForTests(null);
  _setPushFetchForTests(null);
});
