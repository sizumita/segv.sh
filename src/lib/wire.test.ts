// Test suite for src/lib/wire.ts: the binary layouts of the v2 API (docs/PROTOCOL.md §10.3–§10.5, §10.8, §10.9).
//
//   1. layouts — every codec against bytes built by hand from the spec's layout (independent of the encoders).
//   2. round trips — every request, response, result kind, status and frame.
//   3. limits — the exact body caps (PUT_MAX_BYTES, INBOX_MAX_BYTES), counts, the 8 KiB client frame, u64 ≤ 2^53 − 1.
//   4. strictness — every truncation and every one-byte extension of every valid encoding is rejected with WireError;
//      bad enums, classes, counts, flags; encoders refuse what decoders would refuse.
//   5. fuzz — a seeded loop: decoders either return a value that re-encodes to the same bytes, or throw WireError.
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { describe, expect, it } from "vite-plus/test";
import * as W from "./wire";
import { BODY_LENS, INBOX_BODY_LEN } from "./proto";

type B = Uint8Array;

// ───────────────────────── helpers ─────────────────────────

const cat = (...xs: B[]): B => {
  const out = new Uint8Array(xs.reduce((a, x) => a + x.length, 0));
  let o = 0;
  for (const x of xs) {
    out.set(x, o);
    o += x.length;
  }
  return out;
};
const u8 = (n: number): B => Uint8Array.of(n);
const u16 = (n: number): B => Uint8Array.of(n >>> 8, n & 0xff);
const u32 = (n: number): B => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
};
const u64n = (n: bigint): B => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n);
  return b;
};
const u64 = (n: number): B => u64n(BigInt(n));
const toHex = (b: B): string => Buffer.from(b).toString("hex");
const fill = (n: number, v: number): B => new Uint8Array(n).fill(v);

/** Deterministic PRNG (mulberry32) so failures are reproducible. */
function prng(seed: number) {
  let s = seed >>> 0;
  const next = (): number => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (t ^ (t >>> 14)) >>> 0;
  };
  return {
    int: (n: number): number => next() % n,
    u32: (): number => next(),
    bytes: (n: number): B => {
      const b = new Uint8Array(n);
      for (let i = 0; i < n; i++) b[i] = next() & 0xff;
      return b;
    },
  };
}

const R = prng(0x5e9);
const label = (): B => R.bytes(16);
const body = (cls: number): B => R.bytes(BODY_LENS[cls]);
const ibody = (): B => R.bytes(INBOX_BODY_LEN);

/** Throws, and the error is a WireError (never a RangeError, TypeError or a plain Error). */
function wireErr(fn: () => unknown, what = ""): string {
  try {
    fn();
  } catch (e) {
    expect(e, what).toBeInstanceOf(W.WireError);
    return (e as Error).message;
  }
  return expect.unreachable(`expected a WireError: ${what}`);
}

// ───────────────────────── a corpus of valid encodings ─────────────────────────

interface Case {
  name: string;
  bytes: B;
  decode: (b: B) => unknown;
  encode: (v: never) => B;
}

function putReq(rows: W.PutRow[]): Case {
  return { name: `put request ×${rows.length}`, bytes: W.encodePutRequest(rows), decode: W.decodePutRequest, encode: W.encodePutRequest as (v: never) => B };
}
function putRes(results: W.PutResult[], name: string): Case {
  return { name: `put response ${name}`, bytes: W.encodePutResponse(results), decode: W.decodePutResponse, encode: W.encodePutResponse as (v: never) => B };
}
function getReq(keys: W.GetKey[]): Case {
  return { name: `get request ×${keys.length}`, bytes: W.encodeGetRequest(keys), decode: W.decodeGetRequest, encode: W.encodeGetRequest as (v: never) => B };
}
function getRes(st: W.GetStatus[], modes: number[], name: string): Case {
  return {
    name: `get response ${name}`,
    bytes: W.encodeGetResponse(st, modes),
    decode: (b) => W.decodeGetResponse(b, modes),
    encode: ((v: W.GetStatus[]) => W.encodeGetResponse(v, modes)) as (v: never) => B,
  };
}
function inboxPost(p: W.InboxPost): Case {
  return { name: `inbox post ×${p.rows.length}`, bytes: W.encodeInboxPost(p), decode: W.decodeInboxPost, encode: W.encodeInboxPost as (v: never) => B };
}
function inboxRead(x: W.InboxRead): Case {
  return { name: `inbox read ×${x.rows.length}`, bytes: W.encodeInboxRead(x), decode: W.decodeInboxRead, encode: W.encodeInboxRead as (v: never) => B };
}
function feed(p: W.FeedPage, name: string): Case {
  return { name: `feed ${name}`, bytes: W.encodeFeed(p), decode: W.decodeFeed, encode: W.encodeFeed as (v: never) => B };
}
function client(x: W.ClientFrame, name: string): Case {
  return { name: `client ${name}`, bytes: W.encodeClientFrame(x), decode: W.decodeClientFrame, encode: W.encodeClientFrame as (v: never) => B };
}
function server(x: W.ServerFrame, name: string): Case {
  return { name: `server ${name}`, bytes: W.encodeServerFrame(x), decode: W.decodeServerFrame, encode: W.encodeServerFrame as (v: never) => B };
}

const rtRow = (cls: number, seq: number): W.RtRow => ({ seq, topic: label(), E: 41, label: label(), t: 1234 + seq, cls, body: body(cls) });

const CORPUS: Case[] = [
  putReq([{ E: 41, label: label(), cls: 0, topic: new Uint8Array(16), body: body(0) }]),
  putReq([0, 1, 2, 3].map((cls) => ({ E: 0xfffe, label: label(), cls, topic: label(), body: body(cls) }))),
  putRes([{ s: "ok", t: 0xffffffff, receipt: R.bytes(64) }], "ok"),
  putRes(
    [
      { s: "ok", t: 7, receipt: R.bytes(64) },
      { s: "conflict", t: 8, cls: 0, body: body(0) },
      { s: "wrong_era", era: 42 },
      { s: "full" },
      { s: "bad" },
    ],
    "every kind",
  ),
  putRes([{ s: "conflict", t: 9, cls: 3, body: body(3) }], "conflict class 3"),
  getReq([{ E: 41, label: label(), mode: 0 }]),
  getReq([
    { E: 0, label: label(), mode: 1 },
    { E: 41, label: label(), mode: 0 },
    { E: 0xffff, label: label(), mode: 1 },
  ]),
  getRes(
    [
      { s: "hit", t: 5, cls: 0, body: body(0) },
      { s: "miss", sealed: false },
      { s: "miss", sealed: true },
      { s: "skipped" },
      { s: "no_era" },
    ],
    [0, 0, 0, 0, 0],
    "body mode, every status",
  ),
  getRes(
    [
      { s: "hit", t: 6, cls: 2 },
      { s: "hit", t: 7, cls: 1, body: body(1) },
      { s: "miss", sealed: true },
      { s: "no_era" },
    ],
    [1, 0, 1, 1],
    "exists mode",
  ),
  inboxPost({ E: 41, bucket: 0, rows: [{ eid: label(), body: ibody() }] }),
  inboxPost({ E: 41, bucket: 7, rows: [{ eid: label(), body: ibody() }, { eid: label(), body: ibody() }] }),
  inboxRead({ closed: 0, more: false, rows: [] }),
  inboxRead({
    closed: 99,
    more: true,
    rows: [
      { rel: 5, eid: label(), body: ibody() },
      { rel: 5, eid: label(), body: ibody() },
      { rel: 7, eid: label(), body: ibody() },
    ],
  }),
  feed({ more: false, batches: [] }, "empty"),
  feed(
    {
      more: true,
      batches: [
        { t: 10, n: 1, root: R.bytes(32), head: R.bytes(32), rows: [{ label: label(), cls: 0, body: body(0) }] },
        {
          t: 20,
          n: 2,
          root: R.bytes(32),
          head: R.bytes(32),
          rows: [
            { label: label(), cls: 1, body: body(1) },
            { label: label(), cls: 0, body: body(0) },
          ],
        },
      ],
    },
    "two batches",
  ),
  client({ f: "sub", topics: [label()] }, "SUB ×1"),
  client({ f: "unsub", topics: [label(), label(), label()] }, "UNSUB ×3"),
  client({ f: "resume", boot: R.bytes(8), since: 0, topics: [] }, "RESUME ×0"),
  client({ f: "resume", boot: R.bytes(8), since: 2 ** 53 - 1, topics: [label(), label()] }, "RESUME ×2"),
  server({ f: "hello", boot: R.bytes(8), now: 1_780_000_000_000, seq: 0 }, "HELLO"),
  server({ f: "rows", rows: [rtRow(0, 1)] }, "ROWS ×1"),
  server({ f: "rows", rows: [rtRow(0, 2), rtRow(1, 3)] }, "ROWS ×2"),
  server({ f: "gap", since: 12345 }, "GAP"),
  server({ f: "resumed" }, "RESUMED"),
];

// ═════════════════════════ 1. layouts ═════════════════════════

describe("layouts against the spec, byte for byte", () => {
  it("put request (§10.3): u8 count | (u16 E | label[16] | u8 cls | topic[16] | body) × count", () => {
    const rows: W.PutRow[] = [
      { E: 0x0102, label: fill(16, 0xaa), cls: 0, topic: fill(16, 0), body: fill(296, 1) },
      { E: 0xfffe, label: fill(16, 0xbb), cls: 2, topic: fill(16, 0xcc), body: fill(4136, 2) },
    ];
    const want = cat(u8(2), ...rows.flatMap((r) => [u16(r.E), r.label, u8(r.cls), r.topic, r.body]));
    expect(toHex(W.encodePutRequest(rows))).toBe(toHex(want));
    expect(W.decodePutRequest(want)).toEqual(rows);
    expect(want.length).toBe(1 + 2 * 35 + 296 + 4136);
  });

  it("put response (§10.3): OK | CONFLICT | WRONG_ERA | FULL | BAD (4 is reserved)", () => {
    const receipt = fill(64, 0x77);
    const b0 = fill(296, 3);
    const res: W.PutResult[] = [
      { s: "ok", t: 0x01020304, receipt },
      { s: "conflict", t: 5, cls: 0, body: b0 },
      { s: "wrong_era", era: 0x0a0b },
      { s: "full" },
      { s: "bad" },
    ];
    const want = cat(u8(5), u8(0), u32(0x01020304), receipt, u8(1), u32(5), u8(0), b0, u8(2), u16(0x0a0b), u8(3), u8(5));
    expect(toHex(W.encodePutResponse(res))).toBe(toHex(want));
    expect(W.decodePutResponse(want)).toEqual(res);
    expect([W.PUT_OK, W.PUT_CONFLICT, W.PUT_WRONG_ERA, W.PUT_FULL, W.PUT_BAD]).toEqual([0, 1, 2, 3, 5]);
    wireErr(() => W.decodePutResponse(cat(u8(1), u8(4))), "MOVED (4) is reserved for stage 2");
  });

  it("get request and response (§10.4)", () => {
    const keys: W.GetKey[] = [
      { E: 41, label: fill(16, 1), mode: 0 },
      { E: 42, label: fill(16, 2), mode: 1 },
    ];
    const req = cat(u16(2), u16(41), fill(16, 1), u8(0), u16(42), fill(16, 2), u8(1));
    expect(toHex(W.encodeGetRequest(keys))).toBe(toHex(req));
    expect(W.decodeGetRequest(req)).toEqual(keys);
    expect([W.MODE_BODY, W.MODE_EXISTS]).toEqual([0, 1]);
    const b1 = fill(1064, 9);
    const st: W.GetStatus[] = [
      { s: "hit", t: 300, cls: 1, body: b1 },
      { s: "hit", t: 301, cls: 3 },
      { s: "miss", sealed: false },
      { s: "miss", sealed: true },
      { s: "skipped" },
      { s: "no_era" },
    ];
    const modes = [0, 1, 0, 1, 0, 0];
    const res = cat(u16(6), u8(0), u32(300), u8(1), b1, u8(0), u32(301), u8(3), u8(1), u8(0), u8(1), u8(1), u8(2), u8(3));
    expect(toHex(W.encodeGetResponse(st, modes))).toBe(toHex(res));
    expect(W.decodeGetResponse(res, modes)).toEqual(st);
    expect([W.GET_HIT, W.GET_MISS, W.GET_SKIPPED, W.GET_NO_ERA]).toEqual([0, 1, 2, 3]);
  });

  it("inbox post and read (§10.5)", () => {
    const rows = [
      { eid: fill(16, 1), body: fill(1416, 2) },
      { eid: fill(16, 3), body: fill(1416, 4) },
    ];
    const post = cat(u16(41), u32(0), u8(2), ...rows.flatMap((r) => [r.eid, r.body]));
    expect(post.length).toBe(7 + 1432 * 2);
    expect(toHex(W.encodeInboxPost({ E: 41, bucket: 0, rows }))).toBe(toHex(post));
    expect(W.decodeInboxPost(post)).toEqual({ E: 41, bucket: 0, rows });
    const read = cat(u32(77), u8(1), u32(2), u32(70), rows[0].eid, rows[0].body, u32(71), rows[1].eid, rows[1].body);
    const x: W.InboxRead = { closed: 77, more: true, rows: [{ rel: 70, ...rows[0] }, { rel: 71, ...rows[1] }] };
    expect(toHex(W.encodeInboxRead(x))).toBe(toHex(read));
    expect(W.decodeInboxRead(read)).toEqual(x);
    expect([W.INBOX_ROW_LEN, W.INBOX_MAX_ROWS, W.INBOX_READ_MAX_LIMIT]).toEqual([1432, 32, 1024]);
  });

  it("feed (§10.9): u8 more | u32 nb | (u32 t | u32 n | root | head | (label | u8 cls | body) × n) × nb", () => {
    const b0 = fill(296, 5);
    const page: W.FeedPage = {
      more: false,
      batches: [{ t: 10, n: 1, root: fill(32, 1), head: fill(32, 2), rows: [{ label: fill(16, 3), cls: 0, body: b0 }] }],
    };
    const want = cat(u8(0), u32(1), u32(10), u32(1), fill(32, 1), fill(32, 2), fill(16, 3), u8(0), b0);
    expect(toHex(W.encodeFeed(page))).toBe(toHex(want));
    expect(W.decodeFeed(want)).toEqual(page);
  });

  it("realtime frames (§10.8)", () => {
    const t1 = fill(16, 1);
    const t2 = fill(16, 2);
    const boot = fill(8, 0xbb);
    expect([W.RT_SUB, W.RT_UNSUB, W.RT_RESUME, W.RT_HELLO, W.RT_ROWS, W.RT_GAP, W.RT_RESUMED]).toEqual([1, 2, 3, 0x80, 0x81, 0x82, 0x83]);
    const frames: [W.ClientFrame, B][] = [
      [{ f: "sub", topics: [t1, t2] }, cat(u8(1), u16(2), t1, t2)],
      [{ f: "unsub", topics: [t1] }, cat(u8(2), u16(1), t1)],
      [{ f: "resume", boot, since: 0x0102030405, topics: [t2] }, cat(u8(3), boot, u64(0x0102030405), u16(1), t2)],
      [{ f: "resume", boot, since: 0, topics: [] }, cat(u8(3), boot, u64(0), u16(0))],
    ];
    for (const [f, want] of frames) {
      expect(toHex(W.encodeClientFrame(f)), f.f).toBe(toHex(want));
      expect(W.decodeClientFrame(want)).toEqual(f);
    }
    const b1 = fill(1064, 7);
    const row: W.RtRow = { seq: 9, topic: t1, E: 41, label: t2, t: 1234, cls: 1, body: b1 };
    const sframes: [W.ServerFrame, B][] = [
      [{ f: "hello", boot, now: 1_780_000_000_000, seq: 5 }, cat(u8(0x80), boot, u64(1_780_000_000_000), u64(5))],
      [{ f: "rows", rows: [row] }, cat(u8(0x81), u16(1), u64(9), t1, u16(41), t2, u32(1234), u8(1), b1)],
      [{ f: "gap", since: 77 }, cat(u8(0x82), u64(77))],
      [{ f: "resumed" }, u8(0x83)],
    ];
    for (const [f, want] of sframes) {
      expect(toHex(W.encodeServerFrame(f)), f.f).toBe(toHex(want));
      expect(W.decodeServerFrame(want)).toEqual(f);
    }
  });
});

// ═════════════════════════ 2. round trips ═════════════════════════

describe("round trips", () => {
  it("every corpus entry decodes, re-encodes to the same bytes, and decode ∘ encode is the identity", () => {
    for (const c of CORPUS) {
      const v = c.decode(c.bytes);
      expect(toHex(c.encode(v as never)), c.name).toBe(toHex(c.bytes));
      expect(c.decode(c.encode(v as never)), c.name).toEqual(v);
    }
  });

  it("decoders accept a view with a non-zero byteOffset and copy what they return", () => {
    for (const c of CORPUS) {
      const outer = cat(fill(3, 0xee), c.bytes, fill(5, 0xdd));
      const view = outer.subarray(3, 3 + c.bytes.length);
      expect(c.decode(view), c.name).toEqual(c.decode(c.bytes));
    }
    const req = CORPUS[0].bytes.slice();
    const rows = W.decodePutRequest(req);
    req.fill(0);
    expect(rows[0].body.some((x) => x !== 0)).toBe(true);
  });

  it("put rows of every class and E at both ends; get keys of both modes up to 256", () => {
    for (const cls of [0, 1, 2, 3])
      for (const E of [0, 0xffff]) {
        const rows: W.PutRow[] = [{ E, label: label(), cls, topic: label(), body: body(cls) }];
        expect(W.decodePutRequest(W.encodePutRequest(rows))).toEqual(rows);
      }
    const keys: W.GetKey[] = Array.from({ length: 256 }, (_, i) => ({ E: i, label: label(), mode: (i % 2) as 0 | 1 }));
    const req = W.encodeGetRequest(keys);
    expect(req.length).toBe(2 + 256 * 19);
    expect(req.length).toBeLessThanOrEqual(W.GET_MAX_BYTES); // the 8 KiB cap admits the largest valid request
    expect(W.decodeGetRequest(req)).toEqual(keys);
    const st: W.GetStatus[] = keys.map((k, i) => (k.mode === 0 ? { s: "hit", t: i, cls: i % 4, body: body(i % 4) } : { s: "hit", t: i, cls: i % 4 }));
    const modes = keys.map((k) => k.mode);
    expect(W.decodeGetResponse(W.encodeGetResponse(st, modes), modes)).toEqual(st);
  });

  it("a HIT in exists mode carries no body (the encoder drops one if given)", () => {
    const enc = W.encodeGetResponse([{ s: "hit", t: 1, cls: 3, body: body(3) }], [1]);
    expect(enc.length).toBe(2 + 1 + 4 + 1);
    expect(W.decodeGetResponse(enc, [1])).toEqual([{ s: "hit", t: 1, cls: 3 }]);
  });

  it("ROWS frames with every class; SUB / UNSUB / RESUME with 256 topics", () => {
    const rows = [0, 1, 2, 3].map((cls) => rtRow(cls, cls + 100));
    expect(W.decodeServerFrame(W.encodeServerFrame({ f: "rows", rows }))).toEqual({ f: "rows", rows });
    const topics = Array.from({ length: 256 }, () => label());
    for (const f of ["sub", "unsub"] as const) {
      const fr = W.encodeClientFrame({ f, topics });
      expect(fr.length).toBe(3 + 256 * 16);
      expect(W.decodeClientFrame(fr)).toEqual({ f, topics });
    }
    const res: W.ClientFrame = { f: "resume", boot: R.bytes(8), since: 2 ** 53 - 1, topics };
    const fr = W.encodeClientFrame(res);
    expect(fr.length).toBe(1 + 8 + 8 + 2 + 256 * 16);
    expect(fr.length).toBeLessThanOrEqual(W.RT_MAX_CLIENT_FRAME);
    expect(W.decodeClientFrame(fr)).toEqual(res);
  });

  it("inbox read: equal rel values are allowed, the order is ascending", () => {
    const x: W.InboxRead = {
      closed: 10,
      more: false,
      rows: [3, 3, 3, 4, 10].map((rel) => ({ rel, eid: label(), body: ibody() })),
    };
    expect(W.decodeInboxRead(W.encodeInboxRead(x))).toEqual(x);
    const desc = W.encodeInboxRead({ ...x, rows: [x.rows[3], x.rows[0]] });
    expect(wireErr(() => W.decodeInboxRead(desc))).toMatch(/order/);
  });

  it("parseInboxPostResults: {rel} | {error: conflict | full}, one per row in order", () => {
    const ok = { results: [{ rel: 0 }, { error: "conflict" }, { error: "full" }, { rel: 0xffffffff }] };
    expect(W.parseInboxPostResults(ok, 4)).toEqual(ok.results);
    expect(W.parseInboxPostResults(JSON.parse(JSON.stringify(ok)), 4)).toEqual(ok.results);
    const bad: [string, unknown, number][] = [
      ["count mismatch", ok, 3],
      ["not an object", null, 1],
      ["no results", {}, 1],
      ["results not an array", { results: { rel: 1 } }, 1],
      ["rel negative", { results: [{ rel: -1 }] }, 1],
      ["rel float", { results: [{ rel: 1.5 }] }, 1],
      ["rel above u32", { results: [{ rel: 2 ** 32 }] }, 1],
      ["rel string", { results: [{ rel: "1" }] }, 1],
      ["other error", { results: [{ error: "wrong era" }] }, 1],
      ["extra key", { results: [{ rel: 1, error: "full" }] }, 1],
      ["empty object", { results: [{}] }, 1],
      ["null row", { results: [null] }, 1],
      ["array row", { results: [[1]] }, 1],
    ];
    for (const [name, json, n] of bad) wireErr(() => W.parseInboxPostResults(json, n), name);
  });
});

// ═════════════════════════ 3. limits ═════════════════════════

describe("limits", () => {
  it("PUT_MAX_BYTES = 263 345 is a valid 16 × class-3 request; one more byte fails", () => {
    expect(W.PUT_MAX_ROWS).toBe(16);
    expect(W.PUT_MAX_BYTES).toBe(263_345);
    expect(W.PUT_MAX_BYTES).toBe(1 + 16 * (2 + 16 + 1 + 16 + 16_424));
    const rows: W.PutRow[] = Array.from({ length: 16 }, (_, i) => ({ E: i, label: label(), cls: 3, topic: label(), body: body(3) }));
    const max = W.encodePutRequest(rows);
    expect(max.length).toBe(W.PUT_MAX_BYTES);
    expect(W.decodePutRequest(max)).toEqual(rows);
    wireErr(() => W.decodePutRequest(cat(max, u8(0))), "one more byte");
    wireErr(() => W.decodePutRequest(max.subarray(0, max.length - 1)), "one byte less");
    // 17 rows: the encoder refuses and the decoder rejects the count before reading any row
    wireErr(() => W.encodePutRequest([...rows, rows[0]]));
    const r17 = cat(u8(17), max.subarray(1), max.subarray(1, 1 + 35 + 16424));
    expect(wireErr(() => W.decodePutRequest(r17))).toMatch(/count/);
  });

  it("INBOX_MAX_BYTES = 45 831 is a valid 32-invite post; one more byte fails", () => {
    expect(W.INBOX_MAX_BYTES).toBe(45_831);
    expect(W.INBOX_MAX_BYTES).toBe(7 + 1432 * 32);
    const rows = Array.from({ length: 32 }, () => ({ eid: label(), body: ibody() }));
    const max = W.encodeInboxPost({ E: 41, bucket: 0, rows });
    expect(max.length).toBe(W.INBOX_MAX_BYTES);
    expect(W.decodeInboxPost(max).rows).toEqual(rows);
    wireErr(() => W.decodeInboxPost(cat(max, u8(0))), "one more byte");
    wireErr(() => W.encodeInboxPost({ E: 41, bucket: 0, rows: [...rows, rows[0]] }));
    const p33 = cat(max.subarray(0, 6), u8(33), max.subarray(7), max.subarray(7, 7 + 1432));
    expect(wireErr(() => W.decodeInboxPost(p33))).toMatch(/count/);
  });

  it("counts: put 1..16, get 1..256, inbox 1..32, SUB / UNSUB 1..256, RESUME 0..256, ROWS ≥ 1", () => {
    for (const n of [0, 17, 255]) expect(wireErr(() => W.decodePutRequest(u8(n)), `put ${n}`)).toMatch(/count/);
    for (const n of [0, 17, 255]) expect(wireErr(() => W.decodePutResponse(u8(n)), `put response ${n}`)).toMatch(/count/);
    for (const n of [0, 257, 0xffff]) expect(wireErr(() => W.decodeGetRequest(u16(n)), `get ${n}`)).toMatch(/count/);
    for (const n of [0, 33, 255]) expect(wireErr(() => W.decodeInboxPost(cat(u16(1), u32(0), u8(n))), `inbox ${n}`)).toMatch(/count/);
    for (const op of [1, 2])
      for (const n of [0, 257, 0xffff]) {
        const fr = cat(u8(op), u16(n), new Uint8Array(16 * Math.min(n, 257)));
        expect(wireErr(() => W.decodeClientFrame(fr), `op ${op} n ${n}`)).toMatch(/topic count/);
      }
    const boot = fill(8, 1);
    expect(W.decodeClientFrame(cat(u8(3), boot, u64(0), u16(0)))).toEqual({ f: "resume", boot, since: 0, topics: [] });
    expect(wireErr(() => W.decodeClientFrame(cat(u8(3), boot, u64(0), u16(257), new Uint8Array(257 * 16))))).toMatch(/topic count/);
    expect(wireErr(() => W.decodeServerFrame(cat(u8(0x81), u16(0))))).toMatch(/empty/);
    expect(wireErr(() => W.decodeFeed(cat(u8(0), u32(1), u32(10), u32(0), new Uint8Array(64))))).toMatch(/empty/);
    // encoders refuse the same counts
    wireErr(() => W.encodePutRequest([]));
    wireErr(() => W.encodePutResponse([]));
    wireErr(() => W.encodePutResponse(Array.from({ length: 17 }, () => ({ s: "full" as const }))));
    wireErr(() => W.encodeGetRequest([]));
    wireErr(() => W.encodeGetRequest(Array.from({ length: 257 }, () => ({ E: 0, label: label(), mode: 0 as const }))));
    wireErr(() => W.encodeGetResponse([], []));
    wireErr(() => W.encodeInboxPost({ E: 0, bucket: 0, rows: [] }));
    wireErr(() => W.encodeClientFrame({ f: "sub", topics: [] }));
    wireErr(() => W.encodeClientFrame({ f: "unsub", topics: [] }));
    wireErr(() => W.encodeClientFrame({ f: "sub", topics: Array.from({ length: 257 }, () => label()) }));
    wireErr(() => W.encodeClientFrame({ f: "resume", boot, since: 0, topics: Array.from({ length: 257 }, () => label()) }));
    wireErr(() => W.encodeServerFrame({ f: "rows", rows: [] }));
    wireErr(() => W.encodeFeed({ more: false, batches: [{ t: 1, n: 0, root: fill(32, 0), head: fill(32, 0), rows: [] }] }));
  });

  it("client frames above 8 KiB are rejected before parsing", () => {
    expect(W.RT_MAX_CLIENT_FRAME).toBe(8192);
    const sub = W.encodeClientFrame({ f: "sub", topics: [label()] });
    for (const len of [8193, 9000, 65536]) {
      const big = cat(sub, new Uint8Array(len - sub.length));
      expect(wireErr(() => W.decodeClientFrame(big), String(len))).toMatch(/too large/);
    }
    // exactly 8 KiB is not "too large" (it is rejected for its trailing bytes)
    expect(wireErr(() => W.decodeClientFrame(cat(sub, new Uint8Array(8192 - sub.length))))).toMatch(/trailing/);
  });

  it("u64 fields above 2^53 − 1 are rejected (RESUME since, HELLO now / seq, ROWS seq, GAP since)", () => {
    const boot = fill(8, 2);
    const limits: [bigint, boolean][] = [
      [2n ** 53n - 1n, true],
      [2n ** 53n, false],
      [2n ** 53n + 1n, false],
      [2n ** 63n, false],
      [2n ** 64n - 1n, false],
    ];
    const b0 = fill(296, 1);
    for (const [x, ok] of limits) {
      const frames: [string, () => unknown][] = [
        ["RESUME since", () => W.decodeClientFrame(cat(u8(3), boot, u64n(x), u16(0)))],
        ["HELLO now", () => W.decodeServerFrame(cat(u8(0x80), boot, u64n(x), u64(0)))],
        ["HELLO seq", () => W.decodeServerFrame(cat(u8(0x80), boot, u64(0), u64n(x)))],
        ["ROWS seq", () => W.decodeServerFrame(cat(u8(0x81), u16(1), u64n(x), fill(16, 1), u16(1), fill(16, 2), u32(1), u8(0), b0))],
        ["GAP since", () => W.decodeServerFrame(cat(u8(0x82), u64n(x)))],
      ];
      for (const [name, f] of frames) {
        if (ok) expect(f, `${name} = ${x}`).not.toThrow();
        else expect(wireErr(f, `${name} = ${x}`)).toMatch(/u64/);
      }
    }
    for (const x of [2 ** 53, -1, 1.5, NaN]) {
      wireErr(() => W.encodeClientFrame({ f: "resume", boot, since: x, topics: [] }), `since ${x}`);
      wireErr(() => W.encodeServerFrame({ f: "gap", since: x }), `gap ${x}`);
      wireErr(() => W.encodeServerFrame({ f: "hello", boot, now: x, seq: 0 }), `now ${x}`);
    }
  });
});

// ═════════════════════════ 4. strictness ═════════════════════════

describe("strictness", () => {
  it("every truncation and every one-byte extension of every valid encoding is rejected with WireError", () => {
    for (const c of CORPUS) {
      const n = c.bytes.length;
      const cuts = new Set<number>();
      if (n <= 8192) for (let i = 0; i < n; i++) cuts.add(i);
      else {
        for (let i = 0; i < 400; i++) cuts.add(i);
        for (let i = 0; i < n; i += 97) cuts.add(i);
        for (let i = n - 400; i < n; i++) cuts.add(i);
      }
      for (const i of cuts) wireErr(() => c.decode(c.bytes.subarray(0, i)), `${c.name}: truncated to ${i}`);
      const tails = n <= 8192 ? Array.from({ length: 256 }, (_, v) => v) : [0, 1, 0x80, 0xff];
      for (const v of tails) wireErr(() => c.decode(cat(c.bytes, u8(v))), `${c.name}: + ${v}`);
      // and a two-byte extension, for good measure
      wireErr(() => c.decode(cat(c.bytes, u16(0))), `${c.name}: + 2 bytes`);
    }
  }, 60_000);

  it("bad class bytes: every value other than the encoded class is rejected wherever a class appears", () => {
    // [case, offset of the class byte]
    const putReq1 = W.encodePutRequest([{ E: 1, label: label(), cls: 0, topic: label(), body: body(0) }]);
    const conflict = W.encodePutResponse([{ s: "conflict", t: 1, cls: 0, body: body(0) }]);
    const hit = W.encodeGetResponse([{ s: "hit", t: 1, cls: 0, body: body(0) }], [0]);
    const hitExists = W.encodeGetResponse([{ s: "hit", t: 1, cls: 0 }], [1]);
    const fd = W.encodeFeed({
      more: false,
      batches: [{ t: 1, n: 1, root: fill(32, 0), head: fill(32, 0), rows: [{ label: label(), cls: 0, body: body(0) }] }],
    });
    const rows = W.encodeServerFrame({ f: "rows", rows: [rtRow(0, 1)] });
    // [name, bytes, offset of the class byte, decoder, classes that stay valid]
    const sites: [string, B, number, (b: B) => unknown, number[]][] = [
      ["put request", putReq1, 1 + 2 + 16, W.decodePutRequest, [0]],
      ["put CONFLICT", conflict, 1 + 1 + 4, W.decodePutResponse, [0]],
      ["get HIT (body)", hit, 2 + 1 + 4, (b) => W.decodeGetResponse(b, [0]), [0]],
      // without a body every class is well-formed
      ["get HIT (exists)", hitExists, 2 + 1 + 4, (b) => W.decodeGetResponse(b, [1]), [0, 1, 2, 3]],
      ["feed row", fd, 1 + 4 + 4 + 4 + 32 + 32 + 16, W.decodeFeed, [0]],
      ["ROWS row", rows, 1 + 2 + 8 + 16 + 2 + 16 + 4, W.decodeServerFrame, [0]],
    ];
    for (const [name, bytes, off, decode, valid] of sites) {
      expect(bytes[off], name).toBe(0);
      for (let v = 0; v < 256; v++) {
        const m = bytes.slice();
        m[off] = v;
        if (valid.includes(v)) {
          expect(() => decode(m), `${name}: class ${v}`).not.toThrow();
          continue;
        }
        const msg = wireErr(() => decode(m), `${name}: class ${v}`);
        // an out-of-range class is named as such, never read as a length
        if (v > 3) expect(msg, `${name}: class ${v}`).toMatch(/class/);
      }
    }
  });

  it("bad enums and flags: put status, get mode, get status, sealed flag, more flags, frame types", () => {
    const enums: [string, (v: number) => B, (b: B) => unknown, number[]][] = [
      ["put status", (v) => cat(u8(1), u8(v)), W.decodePutResponse, [3, 5]],
      ["get mode", (v) => cat(u16(1), u16(0), fill(16, 0), u8(v)), W.decodeGetRequest, [0, 1]],
      ["get status", (v) => cat(u16(1), u8(v)), (b) => W.decodeGetResponse(b, [0]), [2, 3]],
      ["sealed flag", (v) => cat(u16(1), u8(1), u8(v)), (b) => W.decodeGetResponse(b, [0]), [0, 1]],
      ["inbox read more", (v) => cat(u32(0), u8(v), u32(0)), W.decodeInboxRead, [0, 1]],
      ["feed more", (v) => cat(u8(v), u32(0)), W.decodeFeed, [0, 1]],
      // as RESUME the same 19 bytes read as boot[8] | since 0 | n = 0
      ["client frame type", (v) => cat(u8(v), u16(1), fill(16, 0)), W.decodeClientFrame, [1, 2, 3]],
      ["server frame type", (v) => cat(u8(v), u64(1)), W.decodeServerFrame, [0x82]],
    ];
    for (const [name, build, decode, valid] of enums) {
      for (let v = 0; v < 256; v++) {
        if (valid.includes(v)) expect(() => decode(build(v)), `${name} ${v}`).not.toThrow();
        else wireErr(() => decode(build(v)), `${name} ${v}`);
      }
    }
    expect(wireErr(() => W.decodeGetRequest(cat(u16(1), u16(0), fill(16, 0), u8(2))))).toMatch(/mode/);
    expect(wireErr(() => W.decodeGetResponse(cat(u16(1), u8(1), u8(2)), [0]))).toMatch(/sealed/);
    expect(wireErr(() => W.decodeClientFrame(u8(0x80)))).toMatch(/frame type/);
    expect(wireErr(() => W.decodeServerFrame(u8(0x01)))).toMatch(/frame type/);
    wireErr(() => W.decodeClientFrame(new Uint8Array(0)), "empty client frame");
    wireErr(() => W.decodeServerFrame(new Uint8Array(0)), "empty server frame");
  });

  it("the get response must answer exactly the request's keys", () => {
    const res = W.encodeGetResponse([{ s: "skipped" }, { s: "no_era" }], [0, 0]);
    expect(W.decodeGetResponse(res, [0, 1])).toEqual([{ s: "skipped" }, { s: "no_era" }]);
    for (const modes of [[0], [0, 0, 0], []]) expect(wireErr(() => W.decodeGetResponse(res, modes), String(modes))).toMatch(/count/);
    // a HIT decoded with the wrong mode: body mode expects the body, exists mode rejects it as trailing bytes
    const hit = W.encodeGetResponse([{ s: "hit", t: 1, cls: 0, body: body(0) }], [0]);
    wireErr(() => W.decodeGetResponse(hit, [1]));
    wireErr(() => W.decodeGetResponse(W.encodeGetResponse([{ s: "hit", t: 1, cls: 0 }], [1]), [0]));
  });

  it("inbox post and read lengths are exact", () => {
    const one = W.encodeInboxPost({ E: 1, bucket: 0, rows: [{ eid: label(), body: ibody() }] });
    expect(wireErr(() => W.decodeInboxPost(cat(one.subarray(0, 6), u8(2), one.subarray(7))))).toMatch(/length/);
    const read = W.encodeInboxRead({ closed: 1, more: false, rows: [{ rel: 1, eid: label(), body: ibody() }] });
    expect(wireErr(() => W.decodeInboxRead(cat(read.subarray(0, 5), u32(2), read.subarray(9))))).toMatch(/length/);
    expect(wireErr(() => W.decodeInboxRead(cat(read.subarray(0, 5), u32(0xffffffff), read.subarray(9))))).toMatch(/length/);
    expect(wireErr(() => W.decodeInboxRead(cat(read.subarray(0, 5), u32(0), read.subarray(9))))).toMatch(/length/);
  });

  it("encoders refuse every field a decoder would refuse", () => {
    const L = label();
    const ok: W.PutRow = { E: 1, label: L, cls: 0, topic: L, body: body(0) };
    const badRows: [string, Partial<W.PutRow>][] = [
      ["label 15", { label: L.subarray(1) }],
      ["label 17", { label: cat(L, u8(0)) }],
      ["topic 15", { topic: L.subarray(1) }],
      ["body of class 1", { body: body(1) }],
      ["body short", { body: body(0).subarray(1) }],
      ["cls 4", { cls: 4 }],
      ["cls -1", { cls: -1 }],
      ["cls 1.5", { cls: 1.5 }],
      ["E 65536", { E: 0x10000 }],
      ["E -1", { E: -1 }],
    ];
    for (const [name, over] of badRows) wireErr(() => W.encodePutRequest([{ ...ok, ...over }]), name);
    const badResults: [string, W.PutResult][] = [
      ["receipt 63", { s: "ok", t: 1, receipt: new Uint8Array(63) }],
      ["t 2^32", { s: "ok", t: 2 ** 32, receipt: new Uint8Array(64) }],
      ["t -1", { s: "conflict", t: -1, cls: 0, body: body(0) }],
      ["conflict body", { s: "conflict", t: 1, cls: 1, body: body(0) }],
      ["conflict cls 4", { s: "conflict", t: 1, cls: 4, body: body(0) }],
      ["era 65536", { s: "wrong_era", era: 0x10000 }],
      ["unknown kind", { s: "moved" } as unknown as W.PutResult],
    ];
    for (const [name, x] of badResults) wireErr(() => W.encodePutResponse([x]), name);
    wireErr(() => W.encodeGetRequest([{ E: 1, label: L, mode: 2 as 0 }]), "mode 2");
    wireErr(() => W.encodeGetRequest([{ E: 1, label: L.subarray(1), mode: 0 }]), "label 15");
    wireErr(() => W.encodeGetResponse([{ s: "hit", t: 1, cls: 0 }], [0]), "hit without body");
    wireErr(() => W.encodeGetResponse([{ s: "hit", t: 1, cls: 4 }], [1]), "exists hit cls 4");
    wireErr(() => W.encodeGetResponse([{ s: "hit", t: 1, cls: 1, body: body(0) }], [0]), "hit body length");
    wireErr(() => W.encodeGetResponse([{ s: "skipped" }], [0, 0]), "modes length");
    wireErr(() => W.encodeGetResponse([{ s: "x" } as unknown as W.GetStatus], [0]), "unknown status");
    wireErr(() => W.encodeInboxPost({ E: 1, bucket: 0, rows: [{ eid: L.subarray(1), body: ibody() }] }), "eid 15");
    wireErr(() => W.encodeInboxPost({ E: 1, bucket: 0, rows: [{ eid: L, body: ibody().subarray(1) }] }), "body 1415");
    wireErr(() => W.encodeInboxPost({ E: 1, bucket: 2 ** 32, rows: [{ eid: L, body: ibody() }] }), "bucket 2^32");
    wireErr(() => W.encodeInboxRead({ closed: 2 ** 32, more: false, rows: [] }), "closed 2^32");
    wireErr(() => W.encodeInboxRead({ closed: 0, more: false, rows: [{ rel: 1, eid: L, body: ibody().subarray(1) }] }), "read body");
    const batch = { t: 1, n: 1, root: fill(32, 0), head: fill(32, 0), rows: [{ label: L, cls: 0, body: body(0) }] };
    wireErr(() => W.encodeFeed({ more: false, batches: [{ ...batch, n: 2 }] }), "n ≠ rows");
    wireErr(() => W.encodeFeed({ more: false, batches: [{ ...batch, root: fill(31, 0) }] }), "root 31");
    wireErr(() => W.encodeFeed({ more: false, batches: [{ ...batch, rows: [{ label: L, cls: 0, body: body(1) }] }] }), "row body");
    wireErr(() => W.encodeClientFrame({ f: "sub", topics: [L.subarray(1)] }), "topic 15");
    wireErr(() => W.encodeClientFrame({ f: "resume", boot: fill(7, 0), since: 0, topics: [] }), "boot 7");
    wireErr(() => W.encodeServerFrame({ f: "hello", boot: fill(9, 0), now: 0, seq: 0 }), "boot 9");
    wireErr(() => W.encodeServerFrame({ f: "rows", rows: [{ ...rtRow(0, 1), cls: 4 }] }), "rows cls 4");
    wireErr(() => W.encodeServerFrame({ f: "rows", rows: [{ ...rtRow(0, 1), t: 2 ** 32 }] }), "rows t");
    wireErr(() => W.encodeServerFrame({ f: "x" } as unknown as W.ServerFrame), "unknown frame");
  });
});

// ═════════════════════════ 5. fuzz ═════════════════════════

describe("fuzz", () => {
  it("decoders either return a value that re-encodes to the same bytes or throw WireError", () => {
    const r = prng(0xf0221);
    const decoders: Case[] = [
      ...CORPUS,
      // pure-noise targets for every decoder (the bytes are replaced below)
      { name: "noise put request", bytes: u8(1), decode: W.decodePutRequest, encode: W.encodePutRequest as (v: never) => B },
      { name: "noise put response", bytes: u8(1), decode: W.decodePutResponse, encode: W.encodePutResponse as (v: never) => B },
      { name: "noise get request", bytes: u8(1), decode: W.decodeGetRequest, encode: W.encodeGetRequest as (v: never) => B },
      { name: "noise inbox read", bytes: u8(1), decode: W.decodeInboxRead, encode: W.encodeInboxRead as (v: never) => B },
      { name: "noise feed", bytes: u8(1), decode: W.decodeFeed, encode: W.encodeFeed as (v: never) => B },
      { name: "noise client", bytes: u8(1), decode: W.decodeClientFrame, encode: W.encodeClientFrame as (v: never) => B },
      { name: "noise server", bytes: u8(1), decode: W.decodeServerFrame, encode: W.encodeServerFrame as (v: never) => B },
    ];
    let accepted = 0;
    let rejected = 0;
    for (let t = 0; t < 6000; t++) {
      const c = decoders[r.int(decoders.length)];
      let b: B;
      const op = r.int(6);
      if (c.name.startsWith("noise") || op === 0) {
        b = r.bytes(r.int(64));
        if (r.int(2)) b[0] = [0, 1, 2, 3, 0x80, 0x81, 0x82, 0x83][r.int(8)];
      } else {
        b = c.bytes.slice();
        if (op === 1) b[r.int(b.length)] ^= 1 << r.int(8);
        else if (op === 2) b[r.int(Math.min(b.length, 12))] = r.int(256); // headers: counts, enums, flags
        else if (op === 3) b = b.subarray(0, r.int(b.length + 1));
        else if (op === 4) b = cat(b, r.bytes(1 + r.int(4)));
        else {
          const i = r.int(b.length + 1);
          b = cat(b.subarray(0, i), r.bytes(1 + r.int(3)), b.subarray(i));
        }
      }
      let v: unknown;
      try {
        v = c.decode(b);
      } catch (e) {
        expect(e, `${c.name} #${t}`).toBeInstanceOf(W.WireError);
        rejected++;
        continue;
      }
      accepted++;
      expect(toHex(c.encode(v as never)), `${c.name} #${t}`).toBe(toHex(b));
    }
    expect(accepted).toBeGreaterThan(100);
    expect(rejected).toBeGreaterThan(1000);
  }, 60_000);
});

// ───────────────────────── 6. Node type stripping ─────────────────────────

describe("type stripping (test/e2e/run.mjs imports proto.ts and wire.ts with Node)", () => {
  it.each(["proto.ts", "wire.ts"])("%s strips without a transform (no parameter properties, enums or namespaces)", (f) => {
    const src = readFileSync(new URL(`./${f}`, import.meta.url), "utf8");
    expect(() => stripTypeScriptTypes(src)).not.toThrow();
  });

  it("wire.ts imports proto.ts by its file name, as Node resolves it", () => {
    const src = readFileSync(new URL("./wire.ts", import.meta.url), "utf8");
    expect(src).toMatch(/from "\.\/proto\.ts";/);
    expect(src).not.toMatch(/from "\.\/proto";/);
  });
});
