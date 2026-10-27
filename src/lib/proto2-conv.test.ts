// Test suite for the conversation codecs of src/lib/proto2.ts (below the "conversation codecs" banner):
// envelope M (§3.3), descriptors, joins, invites, hellos and SGB2 bundles (§5), claims and the old-epoch walk
// (§6.2, §6.4, §6.6–§6.8), and the self lane and snapshots (§7). The core above the banner is tested in
// proto2.test.ts.
//
// Layout (as in proto.test.ts):
//   1. reference helpers — an independent re-implementation of the layouts on top of node:crypto (noble only for
//                          XChaCha20 and X-Wing, which node:crypto lacks), used to cross-check byte for byte.
//   2. per-codec round trips, strictness, tamper tests and the plan's M1 test items.
//   3. fuzz — truncations, extensions and random bytes are rejected, and parsers only ever throw Error.
//   4. known answers — pinned outputs, with deterministic randomness through _setRandomForTests.
import { afterEach, describe, expect, it } from "vite-plus/test";
import { createHash, createHmac, createPublicKey, hkdfSync, verify as nodeVerify } from "node:crypto";
import { ml_kem768_x25519 as xwing } from "@noble/post-quantum/hybrid.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import * as P from "./proto2";

type B = Uint8Array;

// ───────────────────────── 1. reference helpers (independent of proto2.ts) ─────────────────────────

const te = new TextEncoder();
const s2b = (x: B | string): B => (typeof x === "string" ? te.encode(x) : x);
const cat = (...xs: B[]): B => {
  const out = new Uint8Array(xs.reduce((a, x) => a + x.length, 0));
  let o = 0;
  for (const x of xs) {
    out.set(x, o);
    o += x.length;
  }
  return out;
};
const be8 = (n: number): B => Uint8Array.of(n);
const be16 = (n: number): B => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return new Uint8Array(b);
};
const be32 = (n: number): B => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return new Uint8Array(b);
};
const be64 = (n: number | bigint): B => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return new Uint8Array(b);
};
/** §1.2: enc(a, b, …) = lp(a) ‖ lp(b) ‖ …, strings UTF-8 first. */
const refEnc = (...xs: (B | string)[]): B => cat(...xs.flatMap((x) => [be32(s2b(x).length), s2b(x)]));
const sha = (b: B): B => new Uint8Array(createHash("sha256").update(b).digest());
const hmacN = (k: B, m: B): B => new Uint8Array(createHmac("sha256", k).update(m).digest());
const hkdfN = (ikm: B, salt: B | string, info: B | string, len = 32): B =>
  new Uint8Array(hkdfSync("sha256", ikm, s2b(salt), s2b(info), len));
const toHex = (b: B): string => Buffer.from(b).toString("hex");
const fromHex = (h: string): B => new Uint8Array(Buffer.from(h, "hex"));
const fill = (n: number, v: number): B => new Uint8Array(n).fill(v);
const seqBytes = (n: number, start = 0): B => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);
const flip = (b: B, i: number, bit = 0): B => {
  const c = b.slice();
  c[i] ^= 1 << bit;
  return c;
};
/** §1.3 pad / unpad. */
const refPad = (x: B, classes: readonly number[]): B => {
  const t = classes.find((c) => c >= x.length + 1);
  if (t === undefined) throw new Error("too large");
  const o = new Uint8Array(t);
  o.set(x);
  o[x.length] = 0x80;
  return o;
};
const refUnpad = (x: B): B => {
  let i = x.length - 1;
  while (i >= 0 && x[i] === 0) i--;
  if (x[i] !== 0x80) throw new Error("bad pad");
  return x.slice(0, i);
};
const CLASSES = [256, 1024, 4096, 16384];
const xSeal = (k: B, nonce: B, aad: B, pt: B): B => cat(nonce, xchacha20poly1305(k, nonce, aad).encrypt(pt));
const xOpen = (k: B, box: B, aad: B): B => xchacha20poly1305(k, box.subarray(0, 24), aad).decrypt(box.subarray(24));

const ED_SPKI = fromHex("302a300506032b6570032100");
const nodeEdVerify = (sig: B, msg: B, pk: B): boolean =>
  nodeVerify(null, msg, createPublicKey({ key: Buffer.from(cat(ED_SPKI, pk)), format: "der", type: "spki" }), sig);

/** §4.2 with node:crypto. */
const refEpochKeys = (EK: B, conv: B, e: number) => {
  const k = (w: string): B => hkdfN(EK, conv, refEnc(`segv.sh/v2/ep/${w}`, be32(e)));
  return { rk: k("route"), mk: k("msg"), kc: k("commit"), nk: k("notify"), dk: k("desc") };
};
const refLmsg = (rk: B, l: number, E: number, n: number): B =>
  hmacN(rk, refEnc("segv.sh/v2/lab/msg", be16(l), be16(E), be32(n))).slice(0, 16);
const refLctl = (rk: B, E: number, k: number): B =>
  hmacN(rk, refEnc("segv.sh/v2/lab/ctl", be16(E), be32(k))).slice(0, 16);
const refEkc = (conv: B, e: number, EK: B): B => sha(refEnc("segv.sh/v2/ekc", conv, be32(e), EK));

/** §3.3 M with explicit fields (any value, so malformed variants can be built). */
interface RefM {
  ver: number;
  type: number;
  from: number;
  lane: number;
  n: number;
  Eprev: number;
  nprev: number;
  prevh: B;
  ts: number | bigint;
  ckq: number;
  ck16: B;
  content: B;
  len?: number;
}
const refM = (o: RefM): B =>
  cat(
    be8(o.ver),
    be8(o.type),
    be16(o.from),
    be16(o.lane),
    be32(o.n),
    be16(o.Eprev),
    be32(o.nprev),
    o.prevh,
    be64(o.ts),
    be32(o.ckq),
    o.ck16,
    be16(o.len ?? o.content.length),
    o.content,
  );
const NONE_REF = { Eprev: 0xffff, nprev: 0xffffffff, prevh: fill(16, 0) };
const TS = 1767700000000;
const baseRefM = (o: Partial<RefM>): B =>
  refM({
    ver: 2,
    type: 1,
    from: 1,
    lane: 1,
    n: 5,
    ...NONE_REF,
    ts: TS,
    ckq: 0,
    ck16: fill(16, 0),
    content: s2b("hi"),
    ...o,
  });

/** §5.1 D with explicit fields. */
interface RefD {
  ver?: number;
  conv: B;
  e: number;
  prev: B;
  by: B;
  ts: number | bigint;
  m?: number;
  members: { uid: B; sigPk: B }[];
  name: B;
  nlen?: number;
}
const refD = (x: RefD): B =>
  cat(
    be8(x.ver ?? 2),
    x.conv,
    be32(x.e),
    x.prev,
    x.by,
    be64(x.ts),
    be8(x.m ?? x.members.length),
    ...x.members.flatMap((m) => [m.uid, m.sigPk]),
    be16(x.nlen ?? x.name.length),
    x.name,
  );
/** §5.2 J. */
const refJ = (conv: B, e: number, EK: B, bundleId: B, bundleSize: number, ver = 2, type = 1): B =>
  cat(be8(ver), be8(type), conv, be32(e), EK, bundleId, be32(bundleSize));
/** §6.2 claim content. */
const refClaim = (c: {
  prevD: B;
  hD: B;
  ekc: B;
  bundleId: B;
  bundleSize: number;
  rm: number;
  cuts: [number, number][];
  m?: number;
}): B =>
  cat(
    c.prevD,
    c.hD,
    c.ekc,
    c.bundleId,
    be32(c.bundleSize),
    be32(c.rm),
    be8(c.m ?? c.cuts.length),
    ...c.cuts.map(([E, cnt]) => cat(be16(E), be32(cnt))),
  );
/** §7.1 record and S. */
const refRecord = (rtype: number, content: B): B => cat(be8(rtype), be16(content.length), content);
const refS = (Eprev: number, nprev: number, prevh: B, ts: number, records: B[], count = records.length, ver = 2): B =>
  cat(be8(ver), be16(Eprev), be32(nprev), prevh, be64(ts), be8(count), ...records);
/** §7.4 S2. */
const refS2 = (Eh: number, nh: number, ts: number, records: B[], count = records.length): B =>
  cat(s2b("SGS2"), be8(1), be16(Eh), be32(nh), be64(ts), be32(count), ...records);

/** Deterministic PRNG (mulberry32) so fuzz failures are reproducible. */
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
    bytes: (n: number): B => Uint8Array.from({ length: n }, () => next() & 0xff),
  };
}

/** A randomness source for _setRandomForTests: SHA-256(seed ‖ counter) blocks. */
const detRng = (seed: string) => {
  let ctr = 0;
  return (n: number): B => {
    const out = new Uint8Array(n);
    for (let o = 0; o < n; o += 32) out.set(sha(cat(s2b(seed), be32(ctr++))).subarray(0, Math.min(32, n - o)), o);
    return out;
  };
};
/** Hands out the given chunks in order and checks every requested length. */
const queueRng =
  (chunks: B[]) =>
  (n: number): B => {
    const c = chunks.shift();
    if (!c || c.length !== n) throw new Error(`queueRng: wanted ${n}, next chunk is ${c?.length}`);
    return c;
  };
function withRng<T>(fn: (n: number) => B, body: () => T): T {
  P._setRandomForTests(fn);
  try {
    return body();
  } finally {
    P._setRandomForTests(null);
  }
}
afterEach(() => P._setRandomForTests(null));

/** Every parser failure must be a plain Error (CodecError or a primitive's Error), never anything else. */
const throwsError = (f: () => unknown): boolean => {
  try {
    f();
    return false;
  } catch (err) {
    if (!(err instanceof Error)) throw new Error(`threw a non-Error: ${String(err)}`);
    return true;
  }
};

// ───────────────────────── fixtures ─────────────────────────

interface Person {
  uid: B;
  id: P.Identity;
}
const person = (k: number): Person => ({ uid: fill(16, 0xa0 + k), id: P.deriveIdentity(fill(32, k + 1)) });
const [alice, bob, carol, dave, erin] = [0, 1, 2, 3, 4].map(person);
const mem = (p: Person): P.Member => ({ uid: p.uid, sigPk: p.id.sigPk });
/** A cheap signing-only member (no KEM keygen) for large descriptors. */
const sigMember = (k: number): P.Member => ({ uid: fill(16, k), sigPk: P.sigPub(fill(32, 0x80 + k)) });

const conv = seqBytes(16, 0x60);
const EK0 = fill(32, 0x11);
const EK1 = fill(32, 0x22);
const keys0 = P.epochKeys(EK0, conv, 0);
const keys1 = P.epochKeys(EK1, conv, 1);

const D0f: P.DescriptorFields = {
  conv,
  e: 0,
  prev: P.ZERO32,
  by: alice.uid,
  ts: TS,
  members: [alice, bob, carol].map(mem),
  name: "kat",
};
const D0 = P.parseD(P.encodeD(D0f));
const dsig0 = P.signD(D0.bytes, keys0.kc, alice.id.sigSk);
/** e = 1: bob removed, dave added, renamed to null. */
const D1f: P.DescriptorFields = {
  conv,
  e: 1,
  prev: D0.hash,
  by: alice.uid,
  ts: TS + 1000,
  members: [alice, carol, dave].map(mem),
  name: null,
};
const D1 = P.parseD(P.encodeD(D1f));
const dsig1 = P.signD(D1.bytes, keys1.kc, alice.id.sigSk);

const hdr = (o: Partial<P.MHeader> = {}): P.MHeader => ({
  from: 1,
  lane: 1,
  n: 5,
  prev: P.NONE,
  prevh: P.ZERO16,
  ts: TS,
  ckq: 0,
  ck16: P.ZERO16,
  ...o,
});
const image: P.ImageRef = { id: fill(32, 0x31), k: fill(32, 0x32), mime: 1, w: 640, h: 480 };
const join1: P.Join = { conv, e: 1, EK: EK1, bundleId: fill(32, 0x33), bundleSize: 11640 };
const claim3: P.Claim = {
  prevD: D0.hash,
  hD: D1.hash,
  ekc: P.ekc(conv, 1, EK1),
  bundleId: fill(32, 0x34),
  bundleSize: 11640,
  rm: 2,
  cuts: [
    { E: 3, cnt: 4 },
    { E: 3, cnt: 0 },
    { E: 2, cnt: 9 },
  ],
};
const claimMsg = (c: P.Claim = claim3, k = 0, from = 0): P.Msg => ({
  ...hdr({ from, lane: P.CTL_LANE, n: k }),
  type: P.MT.CLAIM,
  claim: c,
});
const ctx0 = (sigSk: B = bob.id.sigSk) => ({ keys: keys0, conv, e: 0, sigSk });
const rowCtx0: P.RowContext = { keys: keys0, conv, e: 0, members: D0.members };
const E = 3;

// ───────────────────────── 2. envelope M (§3.3) ─────────────────────────

describe("envelope M: layout", () => {
  const J = refJ(conv, 1, EK1, fill(32, 0x33), 11640);
  const cases: [string, P.Msg, Partial<RefM>][] = [
    ["TEXT", { ...hdr(), type: P.MT.TEXT, text: "hello" }, { type: 1, content: s2b("hello") }],
    [
      "IMAGE",
      { ...hdr(), type: P.MT.IMAGE, image },
      { type: 2, content: cat(fill(32, 0x31), fill(32, 0x32), be8(1), be16(640), be16(480)) },
    ],
    ["WELCOME", { ...hdr(), type: P.MT.WELCOME, join: join1 }, { type: 8, content: J }],
    [
      "CLAIM",
      claimMsg(claim3, 7, 2),
      {
        type: 16,
        from: 2,
        lane: 0xffff,
        n: 7,
        content: refClaim({
          ...claim3,
          cuts: [
            [3, 4],
            [3, 0],
            [2, 9],
          ],
        }),
      },
    ],
    ["LEAVE", { ...hdr(), type: P.MT.LEAVE }, { type: 17, content: new Uint8Array(0) }],
    ["NEED_KEY", { ...hdr(), type: P.MT.NEED_KEY, ef: 3 }, { type: 18, content: be32(3) }],
    ["KEY_OK", { ...hdr(), type: P.MT.KEY_OK }, { type: 19, content: new Uint8Array(0) }],
    [
      "TEXT with prev and checkpoint",
      {
        ...hdr({ prev: { E: 3, n: 7 }, prevh: fill(16, 0x77), ckq: 9, ck16: fill(16, 0x99) }),
        type: P.MT.TEXT,
        text: "x",
      },
      { type: 1, Eprev: 3, nprev: 7, prevh: fill(16, 0x77), ckq: 9, ck16: fill(16, 0x99), content: s2b("x") },
    ],
  ];

  it.each(cases)("%s matches the reference layout and round-trips", (_, msg, ref) => {
    const M = P.encodeM(msg);
    expect(toHex(M)).toBe(toHex(baseRefM(ref)));
    expect(M.length).toBe(62 + (ref.content?.length ?? 0));
    expect(P.parseM(M)).toEqual(msg);
    expect(toHex(P.encodeM(P.parseM(M)))).toBe(toHex(M));
  });

  it("the image content is exactly 69 bytes with mime codes 1 and 2", () => {
    expect(P.encodeImage(image).length).toBe(69);
    expect(P.parseImage(P.encodeImage({ ...image, mime: 2, w: 8192, h: 1 }))).toEqual({
      ...image,
      mime: 2,
      w: 8192,
      h: 1,
    });
    expect(P.MIME).toEqual({ 1: "image/webp", 2: "image/jpeg" });
  });

  it("keeps a leading U+FEFF and any valid UTF-8 in text", () => {
    for (const text of ["﻿bom", "\u0000nul", "日本語", "😀".repeat(3000)]) {
      const M = P.encodeM({ ...hdr(), type: P.MT.TEXT, text });
      expect(P.parseM(M)).toMatchObject({ text });
    }
  });
});

describe("envelope M: strict parsing", () => {
  const rejects: [string, Partial<RefM>][] = [
    ["ver 1", { ver: 1 }],
    ["ver 3", { ver: 3 }],
    ...[0, 3, 4, 7, 9, 15, 20, 255].map((t): [string, Partial<RefM>] => [
      `type ${t}`,
      { type: t, content: new Uint8Array(0) },
    ]),
    ["lane ≠ from", { from: 1, lane: 2 }],
    ["lane row on lane 0xFFFF", { from: 1, lane: 0xffff }],
    ["from 32", { from: 32, lane: 32 }],
    ["claim not on lane 0xFFFF", { type: 16, from: 1, lane: 1, content: refClaim({ ...claim3, cuts: [[3, 4]] }) }],
    [
      "claim with a prev",
      { type: 16, lane: 0xffff, Eprev: 3, nprev: 0, content: refClaim({ ...claim3, cuts: [[3, 4]] }) },
    ],
    ["NONE prev with a non-zero prevh", { prevh: fill(16, 1) }],
    ["era 0xFFFF outside NONE", { Eprev: 0xffff, nprev: 0 }],
    ["ckq 0 with a non-zero ck16", { ck16: fill(16, 1) }],
    ["ts above 2^53 − 1", { ts: 2n ** 53n }],
    ["len too large", { len: 3 }],
    ["len too small", { len: 1 }],
    ["empty text", { content: new Uint8Array(0) }],
    ["text of 12001 bytes", { content: fill(12001, 0x61) }],
    ["text with 0xFF", { content: Uint8Array.of(0x61, 0xff) }],
    ["text with an overlong NUL", { content: Uint8Array.of(0xc0, 0x80) }],
    ["text with a surrogate", { content: Uint8Array.of(0xed, 0xa0, 0x80) }],
    ["image of 68 bytes", { type: 2, content: fill(68, 1) }],
    ["image of 70 bytes", { type: 2, content: cat(P.encodeImage(image), be8(0)) }],
    ["image mime 0", { type: 2, content: cat(fill(64, 1), be8(0), be16(1), be16(1)) }],
    ["image mime 3", { type: 2, content: cat(fill(64, 1), be8(3), be16(1), be16(1)) }],
    ["image w 0", { type: 2, content: cat(fill(64, 1), be8(1), be16(0), be16(1)) }],
    ["image h 8193", { type: 2, content: cat(fill(64, 1), be8(1), be16(1), be16(8193)) }],
    ["welcome J of 89 bytes", { type: 8, content: refJ(conv, 1, EK1, fill(32, 3), 11640).slice(0, 89) }],
    ["welcome J of 91 bytes", { type: 8, content: cat(refJ(conv, 1, EK1, fill(32, 3), 11640), be8(0)) }],
    ["welcome J ver 1", { type: 8, content: refJ(conv, 1, EK1, fill(32, 3), 11640, 1) }],
    ["welcome J type 2", { type: 8, content: refJ(conv, 1, EK1, fill(32, 3), 11640, 2, 2) }],
    ["claim m = 0", { type: 16, lane: 0xffff, content: refClaim({ ...claim3, cuts: [] }) }],
    ["claim m = 33", { type: 16, lane: 0xffff, content: refClaim({ ...claim3, cuts: Array(33).fill([3, 0]) }) }],
    ["claim m above its cuts", { type: 16, lane: 0xffff, content: refClaim({ ...claim3, cuts: [[3, 4]], m: 2 }) }],
    ["leave with content", { type: 17, content: be8(0) }],
    ["key-ok with content", { type: 19, content: be8(0) }],
    ["need-key of 3 bytes", { type: 18, content: fill(3, 0) }],
    ["need-key of 5 bytes", { type: 18, content: fill(5, 0) }],
  ];

  it.each(rejects)("rejects %s", (_, o) => {
    const M = baseRefM(o);
    expect(() => P.parseM(M)).toThrow(P.CodecError);
  });

  it("rejects truncated and extended headers", () => {
    const M = baseRefM({});
    for (let i = 0; i < M.length; i++) expect(throwsError(() => P.parseM(M.slice(0, i)))).toBe(true);
    expect(() => P.parseM(cat(M, be8(0)))).toThrow(P.CodecError);
  });

  it("encodeM refuses what parseM rejects", () => {
    const bads: P.Msg[] = [
      { ...hdr(), type: P.MT.TEXT, text: "" },
      { ...hdr(), type: P.MT.TEXT, text: "a".repeat(12001) },
      { ...hdr(), type: P.MT.TEXT, text: "\ud800" },
      { ...hdr({ lane: 2 }), type: P.MT.LEAVE },
      { ...hdr({ prevh: fill(16, 1) }), type: P.MT.LEAVE },
      { ...hdr({ ck16: fill(16, 1) }), type: P.MT.LEAVE },
      { ...hdr({ prev: { E: 0xffff, n: 0 } }), type: P.MT.LEAVE },
      { ...hdr({ from: 32, lane: 32 }), type: P.MT.LEAVE },
      { ...hdr({ ts: 2 ** 53 }), type: P.MT.LEAVE },
      { ...hdr(), type: P.MT.IMAGE, image: { ...image, w: 0 } },
      { ...hdr(), type: P.MT.IMAGE, image: { ...image, mime: 3 as P.MimeCode } },
      { ...hdr(), type: P.MT.NEED_KEY, ef: -1 },
      { ...hdr({ prev: { E: 3, n: 1 } }), type: P.MT.CLAIM, lane: P.CTL_LANE, claim: claim3 },
      { ...hdr({ lane: P.CTL_LANE }), type: P.MT.CLAIM, claim: { ...claim3, cuts: [] } },
      { ...hdr(), type: 5 as typeof P.MT.LEAVE },
    ];
    for (const m of bads) expect(throwsError(() => P.encodeM(m))).toBe(true);
  });
});

describe("conversation rows: seal, sign, open (§3.3)", () => {
  const msg: P.Msg = { ...hdr({ n: 6 }), type: P.MT.TEXT, text: "hi bob" };
  const label = P.Lmsg(keys0.rk, 1, E, 6);

  it("labels, signature and AEAD match the reference", () => {
    expect(toHex(label)).toBe(toHex(refLmsg(refEpochKeys(EK0, conv, 0).rk, 1, E, 6)));
    expect(toHex(P.expectedLabel(keys0, msg, E))).toBe(toHex(label));
    expect(toHex(P.expectedLabel(keys0, claimMsg(claim3, 4), E))).toBe(toHex(refLctl(keys0.rk, E, 4)));
    const M = P.encodeM(msg);
    const sig = P.signRow(bob.id.sigSk, conv, 0, E, label, M);
    expect(nodeEdVerify(sig, refEnc("segv.sh/v2/msg-sig", conv, be32(0), be16(E), label, M), bob.id.sigPk)).toBe(true);
    const nonce = seqBytes(24, 0xd0);
    const sealed = withRng(queueRng([nonce]), () => P.sealRow(keys0.mk, E, label, M, sig));
    const ref = xSeal(
      refEpochKeys(EK0, conv, 0).mk,
      nonce,
      refEnc("segv.sh/v2/msg", be16(E), label),
      refPad(cat(M, sig), CLASSES),
    );
    expect(sealed.cls).toBe(0);
    expect(toHex(sealed.body)).toBe(toHex(ref));
    const opened = P.openRow(keys0.mk, E, label, ref);
    expect(toHex(opened.M)).toBe(toHex(M));
    expect(toHex(opened.sig)).toBe(toHex(sig));
    expect(opened.msg).toEqual(msg);
    expect(P.verifyRow(bob.id.sigPk, opened.sig, conv, 0, E, label, opened.M)).toBe(true);
  });

  it("buildRow + acceptRow round-trip every type", () => {
    const msgs: P.Msg[] = [
      msg,
      { ...hdr(), type: P.MT.IMAGE, image },
      { ...hdr(), type: P.MT.WELCOME, join: join1 },
      { ...hdr(), type: P.MT.LEAVE },
      { ...hdr(), type: P.MT.NEED_KEY, ef: 0 },
      { ...hdr(), type: P.MT.KEY_OK },
      claimMsg(claim3, 2, 1),
    ];
    for (const m of msgs) {
      const r = P.buildRow(ctx0(), E, m);
      expect(r.body.length).toBe(P.BODY_LENS[r.cls]);
      const v = P.acceptRow(rowCtx0, E, r.label, r.body);
      expect(v.ok).toBe(true);
      if (v.ok) expect(v.msg).toEqual(m);
    }
  });

  it("selects classes by size (plan M1 test 6)", () => {
    const table: [number, number][] = [
      [1, 0],
      [129, 0],
      [130, 1],
      [897, 1],
      [898, 2],
      [3969, 2],
      [3970, 3],
      [12000, 3],
    ];
    for (const [len, cls] of table) {
      const r = P.buildRow(ctx0(), E, { ...hdr(), type: P.MT.TEXT, text: "a".repeat(len) });
      expect([len, r.cls]).toEqual([len, cls]);
      expect(r.body.length).toBe(CLASSES[cls] + 40);
    }
    expect(() => P.buildRow(ctx0(), E, { ...hdr(), type: P.MT.TEXT, text: "a".repeat(12001) })).toThrow();
    // claims: 62 + 137 + 6m + 64 + 1 = 270 (m = 1) … 456 (m = 32) → class 1
    for (const m of [1, 32]) {
      const c: P.Claim = { ...claim3, rm: 0, cuts: Array.from({ length: m }, () => ({ E: 3, cnt: 0 })) };
      const M = P.encodeM(claimMsg(c, 0, 0));
      expect(M.length + 64 + 1).toBe(m === 1 ? 270 : 456);
      expect(P.sealRow(keys0.mk, E, fill(16, 0), M, fill(64, 0)).cls).toBe(1);
    }
    // the short rows of §3.2 are class 0
    for (const m of [
      { ...hdr(), type: P.MT.IMAGE, image },
      { ...hdr(), type: P.MT.WELCOME, join: join1 },
      { ...hdr(), type: P.MT.LEAVE },
      { ...hdr(), type: P.MT.NEED_KEY, ef: 1 },
      { ...hdr(), type: P.MT.KEY_OK },
    ] as P.Msg[])
      expect(P.buildRow(ctx0(), E, m).cls).toBe(0);
  });

  it("flipping any byte of a body, or changing the label or E, makes the row fail to open (test 3)", () => {
    const r = P.buildRow(ctx0(), E, msg);
    expect(r.body.length).toBe(296);
    for (let i = 0; i < r.body.length; i++) {
      expect(() => P.openRow(keys0.mk, E, r.label, flip(r.body, i, i % 8))).toThrow();
      expect(P.acceptRow(rowCtx0, E, r.label, flip(r.body, i, i % 8))).toEqual({ ok: false, why: "decrypt" });
    }
    expect(() => P.openRow(keys0.mk, E, flip(r.label, 15), r.body)).toThrow();
    expect(() => P.openRow(keys0.mk, E + 1, r.label, r.body)).toThrow();
    expect(() => P.openRow(keys1.mk, E, r.label, r.body)).toThrow();
    expect(() => P.openRow(keys0.mk, E, r.label, r.body.slice(0, 295))).toThrow();
  });

  it("changing conv or e makes the signature fail (test 3)", () => {
    const r = P.buildRow(ctx0(), E, msg);
    expect(P.verifyRow(bob.id.sigPk, r.sig, conv, 0, E, r.label, r.M)).toBe(true);
    expect(P.verifyRow(bob.id.sigPk, r.sig, flip(conv, 0), 0, E, r.label, r.M)).toBe(false);
    expect(P.verifyRow(bob.id.sigPk, r.sig, conv, 1, E, r.label, r.M)).toBe(false);
    expect(P.verifyRow(bob.id.sigPk, r.sig, conv, 0, E + 1, r.label, r.M)).toBe(false);
    expect(P.verifyRow(bob.id.sigPk, r.sig, conv, 0, E, flip(r.label, 0), r.M)).toBe(false);
    expect(P.verifyRow(carol.id.sigPk, r.sig, conv, 0, E, r.label, r.M)).toBe(false);
    for (let i = 0; i < r.M.length; i++)
      expect(P.verifyRow(bob.id.sigPk, r.sig, conv, 0, E, r.label, flip(r.M, i))).toBe(false);
    expect(P.acceptRow({ ...rowCtx0, conv: flip(conv, 0) }, E, r.label, r.body)).toEqual({ ok: false, why: "sig" });
    expect(P.acceptRow({ ...rowCtx0, e: 1 }, E, r.label, r.body)).toEqual({ ok: false, why: "sig" });
  });

  it("acceptRow reports each receiver check (§3.3)", () => {
    const ok = P.buildRow(ctx0(), E, msg);
    expect(P.acceptRow(rowCtx0, E, ok.label, ok.body)).toMatchObject({ ok: true, msg });
    // decrypt
    expect(P.acceptRow({ ...rowCtx0, keys: keys1 }, E, ok.label, ok.body)).toEqual({ ok: false, why: "decrypt" });
    // malformed: decrypts, but holds junk / a bad M / bad padding
    const junk = (pt: B) => P.aeadSeal(keys0.mk, pt, P.rowAad(E, ok.label));
    expect(P.acceptRow(rowCtx0, E, ok.label, junk(refPad(fill(200, 7), CLASSES)))).toEqual({
      ok: false,
      why: "malformed",
    });
    expect(P.acceptRow(rowCtx0, E, ok.label, junk(fill(256, 0)))).toEqual({ ok: false, why: "malformed" });
    expect(P.acceptRow(rowCtx0, E, ok.label, junk(refPad(fill(125, 7), CLASSES)))).toEqual({
      ok: false,
      why: "malformed",
    });
    // from ≥ |D_e|
    expect(P.acceptRow({ ...rowCtx0, members: D0.members.slice(0, 1) }, E, ok.label, ok.body)).toEqual({
      ok: false,
      why: "from",
    });
    // label: M says n = 6 but the row sits (validly sealed and signed) at the label of n = 7
    const M = P.encodeM(msg);
    const label7 = P.Lmsg(keys0.rk, 1, E, 7);
    const wrongSlot = P.sealRow(keys0.mk, E, label7, M, P.signRow(bob.id.sigSk, conv, 0, E, label7, M));
    expect(P.acceptRow(rowCtx0, E, label7, wrongSlot.body)).toEqual({ ok: false, why: "label" });
    // content: NEED_KEY with e_f < e, a claim with m ≠ |D_e|
    const ctx5: P.RowContext = { ...rowCtx0, e: 5 };
    const nk = (ef: number) => P.buildRow({ ...ctx0(), e: 5 }, E, { ...hdr(), type: P.MT.NEED_KEY, ef });
    const nk4 = nk(4);
    expect(P.acceptRow(ctx5, E, nk4.label, nk4.body)).toEqual({ ok: false, why: "content" });
    const nk5 = nk(5);
    expect(P.acceptRow(ctx5, E, nk5.label, nk5.body).ok).toBe(true);
    const c2 = P.buildRow(ctx0(), E, claimMsg({ ...claim3, cuts: claim3.cuts.slice(0, 2) }, 0, 1));
    expect(P.acceptRow(rowCtx0, E, c2.label, c2.body)).toEqual({ ok: false, why: "content" });
    // sig: signed by carol, claims to be from bob
    const forged = P.buildRow(ctx0(carol.id.sigSk), E, msg);
    expect(P.acceptRow(rowCtx0, E, forged.label, forged.body)).toEqual({ ok: false, why: "sig" });
    // an M re-sealed with a modified field (an attacker holding mk) keeps the old signature
    const resealed = P.sealRow(keys0.mk, E, ok.label, P.encodeM({ ...msg, ts: TS + 1 }), ok.sig);
    expect(P.acceptRow(rowCtx0, E, ok.label, resealed.body)).toEqual({ ok: false, why: "sig" });
  });
});

// ───────────────────────── descriptor D (§5.1) ─────────────────────────

describe("descriptor D: layout and rules", () => {
  it("matches the reference layout", () => {
    const ref0 = refD({ ...D0f, members: [...D0f.members], name: s2b("kat") });
    expect(toHex(D0.bytes)).toBe(toHex(ref0));
    expect(D0.bytes.length).toBe(78 + 48 * 3 + 2 + 3);
    expect(toHex(D0.hash)).toBe(toHex(sha(ref0)));
    expect(toHex(P.hashD(D0.bytes))).toBe(toHex(sha(ref0)));
    expect(toHex(D1.bytes)).toBe(toHex(refD({ ...D1f, members: [...D1f.members], name: new Uint8Array(0) })));
    expect(D1.name).toBeNull();
    const { bytes: _b, hash: _h, ...fields } = D0;
    expect(fields).toEqual({ ...D0f, members: [...D0f.members] });
  });

  it("a maximal D (32 members, 64 four-byte code points) is 1872 B and D ‖ dsig fits [2048]", () => {
    const name = "😀".repeat(64);
    expect([...name].length).toBe(64);
    expect(s2b(name).length).toBe(256);
    const members = Array.from({ length: 32 }, (_, k) => sigMember(k + 1));
    const D = P.encodeD({ conv, e: 7, prev: fill(32, 9), by: members[31].uid, ts: 2 ** 53 - 1, members, name });
    expect(D.length).toBe(1872);
    expect(P.D_MAX_LEN).toBe(1872);
    const dsig = P.signD(D, keys0.kc, fill(32, 0x80 + 32));
    expect(P.verifyD(D, keys0.kc, dsig)).toBe(true);
    expect(cat(D, dsig).length).toBe(1936);
    expect(P.pad(cat(D, dsig), P.DESC_CLASSES).length).toBe(2048);
    expect(() => P.parseD(cat(D, be8(0)))).toThrow(P.CodecError);
  });

  it("parseD enforces every rule (test 10)", () => {
    const ms = [alice, bob].map(mem);
    const base: RefD = { conv, e: 1, prev: fill(32, 9), by: alice.uid, ts: TS, members: ms, name: s2b("n") };
    expect(P.parseD(refD(base)).name).toBe("n");
    const identity = cat(be8(1), fill(31, 0)); // the neutral element: small order
    const order8 = fromHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"); // a small-order point
    const notPoint = fill(32, 0xff);
    for (const pk of [identity, order8, notPoint, fill(32, 0)]) expect(P.isBadSigPk(pk)).toBe(true);
    const bads: [string, B][] = [
      ["ver 1", refD({ ...base, ver: 1 })],
      ["m = 0", refD({ ...base, members: [], by: fill(16, 0) })],
      ["m = 33", refD({ ...base, members: Array.from({ length: 33 }, (_, k) => sigMember(k + 1)), by: fill(16, 1) })],
      ["m above the listed members", refD({ ...base, m: 3 })],
      ["duplicate uids", refD({ ...base, members: [ms[0], { uid: alice.uid, sigPk: bob.id.sigPk }] })],
      ["the identity as sigPk", refD({ ...base, members: [ms[0], { uid: bob.uid, sigPk: identity }] })],
      ["an order-8 sigPk", refD({ ...base, members: [ms[0], { uid: bob.uid, sigPk: order8 }] })],
      ["a sigPk that is not a point", refD({ ...base, members: [ms[0], { uid: bob.uid, sigPk: notPoint }] })],
      ["by not a member", refD({ ...base, by: carol.uid })],
      ["e = 2^32 − 1", refD({ ...base, e: 0xffffffff })],
      ["e = 0 with a prev", refD({ ...base, e: 0 })],
      ["e > 0 without a prev", refD({ ...base, prev: fill(32, 0) })],
      ["ts above 2^53 − 1", refD({ ...base, ts: 2n ** 53n })],
      ["a name with 0xFF", refD({ ...base, name: Uint8Array.of(0x61, 0xff) })],
      ["a control character", refD({ ...base, name: s2b("a\u0007") })],
      ["a leading BOM", refD({ ...base, name: s2b("﻿a") })],
      ["a name starting with @", refD({ ...base, name: s2b("@alice") })],
      ["a fullwidth @", refD({ ...base, name: s2b(" ＠alice") })],
      ["only whitespace", refD({ ...base, name: s2b("   ") })],
      ["65 code points", refD({ ...base, name: s2b("a".repeat(65)) })],
      ["nlen past the end", refD({ ...base, nlen: 2 })],
      ["a trailing byte", cat(refD(base), be8(0))],
      ["a missing byte", refD(base).slice(0, -1)],
    ];
    for (const [what, b] of bads) expect([what, throwsError(() => P.parseD(b))]).toEqual([what, true]);
    expect(() => P.encodeD({ ...D0f, name: "﻿a" })).toThrow(P.CodecError);
    expect(() => P.encodeD({ ...D0f, name: "" })).toThrow(P.CodecError);
  });

  it("signD / verifyD: under D's own key for `by`, bound to kc_e", () => {
    expect(
      nodeEdVerify(dsig0, refEnc("segv.sh/v2/epoch", D0.bytes, refEpochKeys(EK0, conv, 0).kc), alice.id.sigPk),
    ).toBe(true);
    expect(P.verifyD(D0.bytes, keys0.kc, dsig0)).toBe(true);
    expect(P.verifyD(D0, keys0.kc, dsig0)).toBe(true);
    expect(P.verifyD(D0.bytes, keys1.kc, dsig0)).toBe(false);
    expect(P.verifyD(D0.bytes, keys0.kc, flip(dsig0, 0))).toBe(false);
    expect(P.verifyD(P.signD(D0.bytes, keys0.kc, bob.id.sigSk), keys0.kc, dsig0)).toBe(false);
    expect(P.verifyD(D0.bytes, keys0.kc, P.signD(D0.bytes, keys0.kc, bob.id.sigSk))).toBe(false); // bob is not `by`
    expect(P.verifyD(flip(D0.bytes, 100), keys0.kc, dsig0)).toBe(false);
    expect(P.verifyD(fill(10, 0), keys0.kc, dsig0)).toBe(false);
  });

  it("descriptor keys: verifyRow / verifyD use the key listed in D, never a directory key (test 12)", () => {
    // verifyRow(sigPk, sig, conv, e, E, label, M) and verifyD(D, kc, dsig): no directory argument exists
    expect(P.verifyRow.length).toBe(7);
    expect(P.verifyD.length).toBe(3);
    // D lists bob's uid with erin's key (not the key of bob's directory bundle)
    const Dx = P.parseD(
      P.encodeD({ ...D0f, by: bob.uid, members: [mem(alice), { uid: bob.uid, sigPk: erin.id.sigPk }] }),
    );
    expect(P.verifyD(Dx, keys0.kc, P.signD(Dx.bytes, keys0.kc, erin.id.sigSk))).toBe(true);
    expect(P.verifyD(Dx, keys0.kc, P.signD(Dx.bytes, keys0.kc, bob.id.sigSk))).toBe(false);
    const ctx: P.RowContext = { keys: keys0, conv, e: 0, members: Dx.members };
    const byListedKey = P.buildRow(ctx0(erin.id.sigSk), E, { ...hdr(), type: P.MT.TEXT, text: "x" });
    expect(P.acceptRow(ctx, E, byListedKey.label, byListedKey.body).ok).toBe(true);
    const byBundleKey = P.buildRow(ctx0(bob.id.sigSk), E, { ...hdr(), type: P.MT.TEXT, text: "x" });
    expect(P.acceptRow(ctx, E, byBundleKey.label, byBundleKey.body)).toEqual({ ok: false, why: "sig" });
  });

  it("splitDesc bounds D ‖ dsig to [192, 1936]", () => {
    const desc = cat(D0.bytes, dsig0);
    expect(P.splitDesc(desc)).toEqual({ D: D0.bytes, dsig: dsig0 });
    expect(() => P.splitDesc(fill(191, 0))).toThrow(P.CodecError);
    expect(() => P.splitDesc(fill(1937, 0))).toThrow(P.CodecError);
  });
});

describe("rm bits and the D′ checks (§6.2, §6.6 step 4, test 10)", () => {
  const claim = { from: 0, hD: D1.hash, rm: 2 };
  const next = { D: D1.bytes, dsig: dsig1, kc: keys1.kc };
  /** a variant D′ (signed by alice with kc_1) and a claim that commits to it */
  const variant = (f: Partial<P.DescriptorFields>, signer = alice) => {
    const D = P.encodeD({ ...D1f, ...f });
    return [
      { D, dsig: P.signD(D, keys1.kc, signer.id.sigSk), kc: keys1.kc },
      { ...claim, hD: sha(D) },
    ] as const;
  };

  it("rmBits round-trips through the claim", () => {
    expect(toHex(claim3.ekc)).toBe(toHex(refEkc(conv, 1, EK1)));
    expect(toHex(claim3.prevD)).toBe(toHex(sha(D0.bytes)));
    expect(P.rmBits(D0, D1)).toBe(2);
    expect(P.rmBits(D0, D0)).toBe(0);
    expect(P.rmBits(D1, D0)).toBe(4); // dave (index 2) is not in D0
    const big = Array.from({ length: 32 }, (_, k) => sigMember(k + 1));
    const rm = P.rmBits({ members: big }, { members: big.slice(0, 1) });
    expect(rm).toBe(2 ** 32 - 2);
    expect(P.rmHas(rm, 31) && P.rmHas(rm, 1) && !P.rmHas(rm, 0)).toBe(true);
    const c = P.parseClaim(P.encodeClaim({ ...claim3, rm, cuts: big.map(() => ({ E: 1, cnt: 0 })) }));
    expect(c.rm).toBe(rm);
  });

  it("accepts the honest D′", () => {
    expect(P.dPrimeChecks(next, D0, claim)).toEqual({ ok: true, D: D1 });
  });

  it("rejects each failure separately", () => {
    type Case = [P.DPrimeCheck, { D: B; dsig: B; kc: B }, { from: number; hD: B; rm: number }];
    const fails: Case[] = [
      ["desc", { ...next, dsig: dsig1.slice(0, 63) }, claim],
      ["desc", { ...next, D: fill(200, 1) }, { ...claim, hD: sha(fill(200, 1)) }],
      ["hD", next, { ...claim, hD: fill(32, 1) }],
      ["conv", ...variant({ conv: fill(16, 0x61) })],
      ["e", ...variant({ e: 2 })],
      ["prev", ...variant({ prev: fill(32, 9) })],
      ["by", ...variant({ by: carol.uid })],
      ["by", next, { ...claim, from: 3 }], // no member at `from`
      ["dsig", ...variant({}, carol)],
      ["dsig", { ...next, kc: keys0.kc }, claim],
      ["members", ...variant({ members: [alice, bob, carol, dave].map(mem) })], // bob kept although rm drops him
      ["members", ...variant({ members: [alice, dave].map(mem) })], // carol dropped although rm keeps her
      ["members", next, { ...claim, rm: 0 }], // rm keeps bob, D′ drops him
      ["sigPk", ...variant({ members: [mem(alice), { uid: carol.uid, sigPk: erin.id.sigPk }, mem(dave)] })],
    ];
    for (const [want, n, c] of fails)
      expect([want, P.dPrimeChecks(n, D0, c)]).toEqual([want, { ok: false, failed: want }]);
  });
});

// ───────────────────────── join J, invites, hellos (§5.2, §5.3, §5.5) ─────────────────────────

describe("join payload J (§5.2)", () => {
  it("matches the reference, is 90 B and parses strictly", () => {
    const J = P.encodeJ(join1);
    expect(toHex(J)).toBe(toHex(refJ(conv, 1, EK1, fill(32, 0x33), 11640)));
    expect(J.length).toBe(90);
    expect(P.parseJ(J)).toEqual(join1);
    for (const bad of [
      refJ(conv, 1, EK1, fill(32, 0x33), 11640, 1),
      refJ(conv, 1, EK1, fill(32, 0x33), 11640, 3),
      refJ(conv, 1, EK1, fill(32, 0x33), 11640, 2, 0),
      refJ(conv, 1, EK1, fill(32, 0x33), 11640, 2, 2),
      J.slice(0, 89),
      cat(J, be8(0)),
    ])
      expect(() => P.parseJ(bad)).toThrow(P.CodecError);
    expect(() => P.encodeJ({ ...join1, EK: fill(31, 0) })).toThrow(P.CodecError);
  });
});

describe("inbox invites (§5.3, test 8)", () => {
  const J = P.encodeJ(join1);

  it("matches the reference construction and is 1416 B", () => {
    const eid = seqBytes(16, 0xe0);
    const rnd = seqBytes(64, 0x40);
    const nonce = seqBytes(24, 0x90);
    const inv = withRng(queueRng([eid, rnd, nonce]), () => P.makeInvite(bob.id.kemPk, E, 0, join1));
    const { cipherText: kct, sharedSecret: ss } = xwing.encapsulate(bob.id.kemPk, rnd);
    const ctx = refEnc("segv.sh/v2/inv", be16(E), be32(0), eid);
    const ref = cat(kct, xSeal(hkdfN(ss, sha(kct), ctx), nonce, ctx, refPad(J, [256])));
    expect(toHex(inv.eid)).toBe(toHex(eid));
    expect(toHex(inv.body)).toBe(toHex(ref));
    expect(inv.body.length).toBe(1416);
    expect(P.INBOX_BODY_LEN).toBe(1416);
  });

  it("opens for the recipient only; every other case is a silent null", () => {
    const inv = P.makeInvite(bob.id.kemPk, E, 0, J);
    expect(P.tryOpenInvite(bob.id.kemSk, E, 0, inv.eid, inv.body)).toEqual({ kind: "join", join: join1 });
    for (const sk of [alice.id.kemSk, carol.id.kemSk, P.kemKeygen(fill(32, 0xee)).sk])
      expect(P.tryOpenInvite(sk, E, 0, inv.eid, inv.body)).toBeNull();
    expect(P.tryOpenInvite(bob.id.kemSk, E + 1, 0, inv.eid, inv.body)).toBeNull();
    expect(P.tryOpenInvite(bob.id.kemSk, E, 1, inv.eid, inv.body)).toBeNull();
    expect(P.tryOpenInvite(bob.id.kemSk, E, 0, flip(inv.eid, 0), inv.body)).toBeNull();
    expect(P.tryOpenInvite(bob.id.kemSk, E, 0, inv.eid, inv.body.slice(0, 1415))).toBeNull();
    expect(P.tryOpenInvite(bob.id.kemSk, E, 0, inv.eid.slice(0, 15), inv.body)).toBeNull();
    for (const i of [0, 1087, 1100, 1119, 1120, 1143, 1144, 1300, 1415])
      expect(P.tryOpenInvite(bob.id.kemSk, E, 0, inv.eid, flip(inv.body, i))).toBeNull();
  });

  it("distinguishes a decrypted but malformed J (noise warning)", () => {
    for (const bad of [
      J.slice(0, 89),
      cat(J, be8(0)),
      refJ(conv, 1, EK1, fill(32, 0x33), 11640, 1),
      new Uint8Array(0),
    ]) {
      const inv = P.makeInvite(bob.id.kemPk, E, 0, bad);
      expect(P.tryOpenInvite(bob.id.kemSk, E, 0, inv.eid, inv.body)).toEqual({ kind: "malformed" });
      expect(P.tryOpenInvite(alice.id.kemSk, E, 0, inv.eid, inv.body)).toBeNull();
    }
    // a padding error after a correct decryption is also "malformed"
    const eid = fill(16, 1);
    const { kct, ss } = P.kemEncap(bob.id.kemPk);
    const ctx = refEnc("segv.sh/v2/inv", be16(E), be32(0), eid);
    const body = cat(kct, P.aeadSeal(hkdfN(ss, sha(kct), ctx), fill(256, 0), ctx));
    expect(P.tryOpenInvite(bob.id.kemSk, E, 0, eid, body)).toEqual({ kind: "malformed" });
  });
});

describe("link hellos (§5.5)", () => {
  const s = seqBytes(16, 0x50);
  const label = P.Lhello(P.linkKeys(s).kL, E, 0);

  it("matches the reference construction: inner 1250 B, body class 2 (4136 B)", () => {
    const rnd = seqBytes(64, 0x41);
    const n1 = seqBytes(24, 0x91);
    const n2 = seqBytes(24, 0xa1);
    const h = withRng(queueRng([rnd, n1, n2]), () => P.makeHello(bob.id.kemPk, s, E, label, join1));
    const { cipherText: kct, sharedSecret: ss } = xwing.encapsulate(bob.id.kemPk, rnd);
    const ctx = refEnc(sha(s));
    const k = hkdfN(ss, sha(kct), refEnc("segv.sh/v2/seal", "segv.sh/v2/hello", ctx));
    const inner = cat(kct, xSeal(k, n1, refEnc("segv.sh/v2/hello", ctx), P.encodeJ(join1)));
    expect(inner.length).toBe(1250);
    expect(P.HELLO_INNER_LEN).toBe(1250);
    const mL = hkdfN(s, "", "segv.sh/v2/link/aead");
    const ref = xSeal(mL, n2, refEnc("segv.sh/v2/hello", be16(E), label), refPad(inner, CLASSES));
    expect(h.cls).toBe(2);
    expect(h.body.length).toBe(4136);
    expect(toHex(h.body)).toBe(toHex(ref));
  });

  it("opens with the link secret and the owner's key only", () => {
    const h = P.makeHello(bob.id.kemPk, s, E, label, join1);
    expect(P.openHello(bob.id.kemSk, s, E, label, h.body)).toEqual({ kind: "join", join: join1 });
    expect(P.openHello(alice.id.kemSk, s, E, label, h.body)).toBeNull(); // a link holder who is not Bob
    expect(P.openHello(bob.id.kemSk, flip(s, 0), E, label, h.body)).toBeNull();
    expect(P.openHello(bob.id.kemSk, s, E + 1, label, h.body)).toBeNull();
    expect(P.openHello(bob.id.kemSk, s, E, flip(label, 0), h.body)).toBeNull();
    expect(P.openHello(bob.id.kemSk, s, E, label, flip(h.body, 2000))).toBeNull();
    expect(P.openHello(bob.id.kemSk, s, E, label, h.body.slice(0, 4135))).toBeNull();
    const bad = P.makeHello(bob.id.kemPk, s, E, label, P.encodeJ(join1).slice(0, 89));
    expect(P.openHello(bob.id.kemSk, s, E, label, bad.body)).toEqual({ kind: "malformed" });
    // an inner seal made with another H(s) does not open
    const mL = P.linkKeys(s).mL;
    const otherInner = P.seal(bob.id.kemPk, P.HELLO_LABEL, P.enc(P.H(fill(16, 9))), P.encodeJ(join1));
    const body = P.aeadSeal(mL, P.pad(otherInner, CLASSES), P.helloAad(E, label));
    expect(P.openHello(bob.id.kemSk, s, E, label, body)).toBeNull();
  });
});

// ───────────────────────── SGB2 bundles (§5.4, test 7) ─────────────────────────

describe("SGB2 key bundles (§5.4)", () => {
  const prevKem = [alice, bob, carol].map((p) => p.id.kemPk);
  const spec: P.BundleSpec = {
    conv,
    e: 1,
    D: D1.bytes,
    dsig: dsig1,
    EK: EK1,
    prevMembers: prevKem,
    keep: [true, false, true],
  };
  const built = P.buildBundle(spec);
  const everyone = [alice, bob, carol, dave, erin].map((p) => p.id.kemSk);
  const stranger = P.kemKeygen(fill(32, 0xee)).sk;

  it("has the §3.2 sizes and header", () => {
    expect(built.B).toBe(8);
    expect(built.size).toBe(11640);
    expect(built.blob.length).toBe(11640);
    expect(P.SGB2_SIZES).toEqual([11640, 40248]);
    expect(toHex(built.blob.subarray(0, 16))).toBe(toHex(cat(s2b("SGB2"), be8(1), be8(8), fill(10, 0))));
    expect(toHex(built.id)).toBe(toHex(sha(built.blob)));
    const nine = Array.from({ length: 9 }, (_, k) => sigMember(k + 1));
    const D9 = P.encodeD({ conv, e: 0, prev: P.ZERO32, by: nine[0].uid, ts: TS, members: nine, name: null });
    const b32 = P.buildBundle({ conv, e: 0, D: D9, dsig: fill(64, 0), EK: EK0, prevMembers: [], keep: [] });
    expect([b32.B, b32.size, b32.blob[5]]).toEqual([32, 40248, 32]);
    expect(P.buildBundle({ ...spec, B: 32 }).size).toBe(40248);
    expect(() =>
      P.buildBundle({ conv, e: 0, D: D9, dsig: fill(64, 0), EK: EK0, prevMembers: [], keep: [], B: 8 }),
    ).toThrow();
    expect(() => P.buildBundle({ ...spec, keep: [true] })).toThrow();
    expect(() => P.buildBundle({ ...spec, e: 0 })).toThrow(); // epoch 0 has no previous members
    expect(P.sgb2B(8, 8)).toBe(8);
    expect(P.sgb2B(9, 2)).toBe(32);
    expect(P.sgb2B(2, 9)).toBe(32);
    expect(P.sgb2B(0, 8)).toBe(8);
  });

  it("matches the reference: descCt under dk_e, a real entry for EK and for REMOVED", () => {
    const rk = refEpochKeys(EK1, conv, 1);
    const descCt = built.blob.subarray(16, 16 + 2088);
    const desc = refUnpad(xOpen(rk.dk, descCt, refEnc("segv.sh/v2/desc", conv, be32(1))));
    expect(toHex(desc)).toBe(toHex(cat(D1.bytes, dsig1)));
    const entry = (i: number) => built.blob.subarray(16 + 2088 + 1192 * i, 16 + 2088 + 1192 * (i + 1));
    const refOpen = (sk: B, i: number): B => {
      const box = entry(i);
      const kct = box.subarray(0, 1120);
      const ctx = refEnc(conv, be32(1), be16(i));
      const k = hkdfN(xwing.decapsulate(kct, sk), sha(kct), refEnc("segv.sh/v2/seal", "segv.sh/v2/rekey", ctx));
      return xOpen(k, box.subarray(1120), refEnc("segv.sh/v2/rekey", ctx));
    };
    expect(toHex(refOpen(alice.id.kemSk, 0))).toBe(toHex(EK1));
    expect(toHex(refOpen(bob.id.kemSk, 1))).toBe(toHex(fill(32, 0)));
    expect(toHex(refOpen(carol.id.kemSk, 2))).toBe(toHex(EK1));
    for (let i = 0; i < 8; i++) expect(entry(i).length).toBe(1192);
  });

  it("opens EK for kept members, 'removed' for dropped ones, nothing for padding or strangers", () => {
    expect(P.openEntry(alice.id.kemSk, conv, 1, 0, built.blob)).toEqual(EK1);
    expect(P.openEntry(bob.id.kemSk, conv, 1, 1, built.blob)).toBe("removed");
    expect(P.openEntry(carol.id.kemSk, conv, 1, 2, built.blob)).toEqual(EK1);
    const parsed = P.parseBundleBlob(built.blob);
    for (let i = 0; i < 8; i++)
      for (const [k, sk] of everyone.entries()) {
        if (k === i && i < 3) continue;
        expect(P.openEntry(sk, conv, 1, i, parsed)).toBeNull();
      }
    for (let i = 0; i < 8; i++) expect(P.openEntry(stranger, conv, 1, i, built.blob)).toBeNull();
    expect(P.openEntry(alice.id.kemSk, conv, 2, 0, built.blob)).toBeNull(); // wrong e
    expect(P.openEntry(alice.id.kemSk, flip(conv, 0), 1, 0, built.blob)).toBeNull(); // wrong conv
    expect(P.openEntry(alice.id.kemSk, conv, 1, 8, built.blob)).toBeNull(); // i ≥ B
    expect(P.openEntry(alice.id.kemSk, conv, 1, 0, built.blob.slice(1))).toBeNull(); // malformed blob
  });

  it("an unknown member (null kemPk) gets a dummy entry that opens for nobody", () => {
    const b = P.buildBundle({ ...spec, prevMembers: [prevKem[0], null, prevKem[2]] });
    for (const sk of [...everyone, stranger]) expect(P.openEntry(sk, conv, 1, 1, b.blob)).toBeNull();
    expect(P.openEntry(alice.id.kemSk, conv, 1, 0, b.blob)).toEqual(EK1);
  });

  it("epoch 0: every entry is a dummy", () => {
    const b = P.buildBundle({ conv, e: 0, D: D0.bytes, dsig: dsig0, EK: EK0, prevMembers: [], keep: [] });
    expect(b.size).toBe(11640);
    for (let i = 0; i < 8; i++) for (const sk of everyone) expect(P.openEntry(sk, conv, 0, i, b.blob)).toBeNull();
    expect(P.openDesc(keys0.dk, conv, 0, b.blob)).toEqual({ D: D0.bytes, dsig: dsig0 });
  });

  it("openDesc returns D ‖ dsig and throws under another key", () => {
    expect(P.openDesc(keys1.dk, conv, 1, built.blob)).toEqual({ D: D1.bytes, dsig: dsig1 });
    expect(() => P.openDesc(keys0.dk, conv, 1, built.blob)).toThrow();
    expect(() => P.openDesc(keys1.dk, conv, 2, built.blob)).toThrow();
  });

  it("parseBundleBlob is strict", () => {
    const set = (i: number, v: number) => {
      const c = built.blob.slice();
      c[i] = v;
      return c;
    };
    expect(P.parseBundleBlob(built.blob).entries.length).toBe(8);
    for (const bad of [
      built.blob.slice(0, 11639),
      cat(built.blob, be8(0)),
      set(0, 0x54),
      set(3, 0x33),
      set(4, 2),
      set(5, 32),
      set(5, 7),
      set(6, 1),
      set(15, 1),
    ])
      expect(() => P.parseBundleBlob(bad)).toThrow(P.CodecError);
  });

  it("bundleShapeValid reports each failure of §6.4 (h) separately: size, length, hash", () => {
    expect(P.bundleShapeValid(built.blob, 11640, built.id, 3)).toBeNull();
    expect(P.bundleShapeValid(built.blob, 11640, built.id, 8)).toBeNull();
    expect(P.bundleShapeValid(built.blob, 11641, built.id, 3)).toBe("size");
    expect(P.bundleShapeValid(built.blob, 2104, built.id, 3)).toBe("size");
    expect(P.bundleShapeValid(built.blob, 40248, built.id, 3)).toBe("length");
    expect(P.bundleShapeValid(built.blob, 11640, flip(built.id, 0), 3)).toBe("hash");
  });

  it("bundleShapeValid: magic, version, B, the zero bytes and B < m", () => {
    const check = (i: number, v: number) => {
      const c = built.blob.slice();
      c[i] = v;
      return P.bundleShapeValid(c, 11640, sha(c), 3);
    };
    expect(check(0, 0x58)).toBe("magic");
    expect(check(4, 0)).toBe("ver");
    expect(check(5, 32)).toBe("B");
    expect(check(5, 16)).toBe("B");
    expect(check(9, 1)).toBe("header");
    expect(P.bundleShapeValid(built.blob, 11640, built.id, 9)).toBe("m");
    expect(P.bundleShapeValid(built.blob, 11640, built.id, 32)).toBe("m");
  });
});

describe("processing a winning claim and accepting a join (§6.6 steps 2–4, §6.7 steps 1–2)", () => {
  const prevKem = [alice, bob, carol].map((p) => p.id.kemPk);
  const spec: P.BundleSpec = {
    conv,
    e: 1,
    D: D1.bytes,
    dsig: dsig1,
    EK: EK1,
    prevMembers: prevKem,
    keep: [true, false, true],
  };
  const built = P.buildBundle(spec);
  const claim: P.Claim = { ...claim3, bundleId: built.id };
  const run = (i: number, sk: B, c = claim, blob: B = built.blob) =>
    P.processClaim({ kemSk: sk, De: D0, i, from: 0, claim: c, blob });

  it("accept / removed / excluded / withheld / invalid", () => {
    expect(run(0, alice.id.kemSk)).toMatchObject({ kind: "accept", EK: EK1, D: D1, dsig: dsig1 });
    expect(run(2, carol.id.kemSk)).toMatchObject({ kind: "accept", EK: EK1 });
    expect(run(1, bob.id.kemSk)).toEqual({ kind: "removed" });
    expect(run(1, stranger())).toEqual({ kind: "removed" }); // whatever V is
    // REMOVED sealed while rm keeps carol
    const excl = P.buildBundle({ ...spec, keep: [true, false, false] });
    expect(run(2, carol.id.kemSk, { ...claim, bundleId: excl.id }, excl.blob)).toEqual({ kind: "excluded" });
    // a dummy entry, or an EK that does not match ekc
    const dummy = P.buildBundle({ ...spec, prevMembers: [prevKem[0], prevKem[1], null] });
    expect(run(2, carol.id.kemSk, claim, dummy.blob)).toEqual({ kind: "withheld" });
    expect(run(2, carol.id.kemSk, { ...claim, ekc: fill(32, 1) })).toEqual({ kind: "withheld" });
    expect(run(2, alice.id.kemSk)).toEqual({ kind: "withheld" }); // not her entry
    // D′-invalid: a wrong prev, or a descCt that holds junk
    const Dbad = P.encodeD({ ...D1f, prev: fill(32, 9) });
    const badB = P.buildBundle({ ...spec, D: Dbad, dsig: P.signD(Dbad, keys1.kc, alice.id.sigSk) });
    expect(run(0, alice.id.kemSk, { ...claim, hD: sha(Dbad) }, badB.blob)).toEqual({ kind: "invalid", failed: "prev" });
    const junk = P.buildBundle({ ...spec, D: fill(200, 1) });
    expect(run(0, alice.id.kemSk, claim, junk.blob)).toEqual({ kind: "invalid", failed: "hD" });
    expect(run(0, alice.id.kemSk, { ...claim, hD: sha(fill(200, 1)) }, junk.blob)).toEqual({
      kind: "invalid",
      failed: "desc",
    });
  });

  const stranger = () => P.kemKeygen(fill(32, 0xee)).sk;

  it("checkJoinBundle (§6.7 steps 1–2)", () => {
    const J: P.Join = { conv, e: 1, EK: EK1, bundleId: built.id, bundleSize: built.size };
    expect(P.checkJoinBundle(J, built.blob, mem(dave))).toMatchObject({ ok: true, D: D1, dsig: dsig1 });
    expect(P.checkJoinBundle({ ...J, bundleId: fill(32, 0) }, built.blob, mem(dave))).toEqual({
      ok: false,
      failed: "hash",
    });
    expect(P.checkJoinBundle({ ...J, bundleSize: 40248 }, built.blob, mem(dave))).toEqual({
      ok: false,
      failed: "size",
    });
    const hb = built.blob.slice();
    hb[10] = 1;
    expect(P.checkJoinBundle({ ...J, bundleId: sha(hb) }, hb, mem(dave))).toEqual({ ok: false, failed: "header" });
    expect(P.checkJoinBundle({ ...J, EK: EK0 }, built.blob, mem(dave))).toEqual({ ok: false, failed: "desc" });
    expect(P.checkJoinBundle(J, built.blob, mem(bob))).toEqual({ ok: false, failed: "self" });
    expect(P.checkJoinBundle(J, built.blob, { uid: dave.uid, sigPk: erin.id.sigPk })).toEqual({
      ok: false,
      failed: "self",
    });
    const variant = (f: Partial<P.DescriptorFields>, signer = alice): [P.Join, B] => {
      const D = P.encodeD({ ...D1f, ...f });
      const b = P.buildBundle({ ...spec, D, dsig: P.signD(D, keys1.kc, signer.id.sigSk) });
      return [{ ...J, bundleId: b.id, bundleSize: b.size }, b.blob];
    };
    expect(P.checkJoinBundle(...variant({ conv: fill(16, 1) }), mem(dave))).toEqual({ ok: false, failed: "conv" });
    expect(P.checkJoinBundle(...variant({ e: 2 }), mem(dave))).toEqual({ ok: false, failed: "e" });
    expect(P.checkJoinBundle(...variant({}, carol), mem(dave))).toEqual({ ok: false, failed: "dsig" });
  });
});

// ───────────────────────── claims (§6.2, §6.4, §6.8, test 10) ─────────────────────────

describe("claims: content layout and shape rules", () => {
  it("matches the reference (137 + 6m) and round-trips", () => {
    for (const m of [1, 3, 32]) {
      const cuts = Array.from({ length: m }, (_, k): [number, number] => [k + 1, 1000 * k]);
      const c: P.Claim = { ...claim3, cuts: cuts.map(([Ec, cnt]) => ({ E: Ec, cnt })) };
      const b = P.encodeClaim(c);
      expect(toHex(b)).toBe(toHex(refClaim({ ...claim3, cuts })));
      expect(b.length).toBe(137 + 6 * m);
      expect(P.claimLen(m)).toBe(137 + 6 * m);
      expect(P.parseClaim(b)).toEqual(c);
    }
    const one = refClaim({ ...claim3, cuts: [[1, 1]] });
    for (const bad of [
      refClaim({ ...claim3, cuts: [] }),
      refClaim({ ...claim3, cuts: Array(33).fill([1, 1]) }),
      refClaim({ ...claim3, cuts: [[1, 1]], m: 2 }),
      cat(one, be8(0)),
      one.slice(0, -1),
    ])
      expect(() => P.parseClaim(bad)).toThrow(P.CodecError);
  });

  it("claimShapeValid rejects each failure of (a), (b), (e), (f) and the size set of (g)", () => {
    const ok = claim3; // m = 3, from 0, rm = bit 1, cuts in [2, 3]
    expect(P.claimShapeValid(ok, 3, 0, 2, 3)).toBeNull();
    expect(P.claimShapeValid(ok, 4, 0, 2, 3)).toBe("m");
    expect(P.claimShapeValid(ok, 3, 3, 2, 3)).toBe("from");
    expect(P.claimShapeValid({ ...ok, rm: 2 + 8 }, 3, 0, 2, 3)).toBe("rm-high");
    expect(P.claimShapeValid({ ...ok, rm: 2 ** 31 }, 3, 0, 2, 3)).toBe("rm-high");
    expect(P.claimShapeValid(ok, 3, 1, 2, 3)).toBe("rm-self");
    expect(P.claimShapeValid(ok, 3, 0, 3, 3)).toBe("cut"); // E_ℓ = 2 < E_start = 3
    expect(P.claimShapeValid(ok, 3, 0, 2, 2)).toBe("cut"); // E_ℓ = 3 > E = 2
    expect(P.claimShapeValid({ ...ok, bundleSize: 11641 }, 3, 0, 2, 3)).toBe("bundleSize");
    expect(P.claimShapeValid({ ...ok, bundleSize: 40248 }, 3, 0, 2, 3)).toBeNull();
    // m = 32: bit 31 is a member's bit, not "at or above m"
    const c32: P.Claim = { ...ok, rm: 2 ** 31, cuts: Array.from({ length: 32 }, () => ({ E: 2, cnt: 0 })) };
    expect(P.claimShapeValid(c32, 32, 0, 2, 3)).toBeNull();
    expect(P.claimShapeValid(c32, 32, 31, 2, 3)).toBe("rm-self");
  });

  it("cutBefore is exclusive in the cut's era", () => {
    const cut = { E: 5, cnt: 3 };
    expect(P.cutBefore(cut, 4, 1000)).toBe(true);
    expect(P.cutBefore(cut, 5, 2)).toBe(true);
    expect(P.cutBefore(cut, 5, 3)).toBe(false);
    expect(P.cutBefore(cut, 6, 0)).toBe(false);
    expect(P.cutBefore({ E: 5, cnt: 0 }, 5, 0)).toBe(false); // empty lane
  });
});

describe("acceptOldRow: the §6.8 walk (test 10)", () => {
  const [A, Bu, C, Du] = [alice, bob, carol, dave].map((p) => p.uid);
  // epoch e: [A, B, C]; C_e at t = 100 removes B; cuts B: (5, 3)
  const Ce = {
    t: 100,
    rm: 2,
    cuts: [
      { E: 5, cnt: 10 },
      { E: 5, cnt: 3 },
      { E: 5, cnt: 7 },
    ],
  };
  // epoch e+1: [A, C, D] (C moved to index 1); C_{e+1} at t = 200 removes C (index 1)
  const Ce1 = { t: 200, rm: 2, cuts: [0, 1, 2].map(() => ({ E: 6, cnt: 0 })) };
  const e0: P.WalkEpoch = { members: [A, Bu, C], claim: Ce };
  const e1: P.WalkEpoch = { members: [P.b64u(A), P.b64u(C), P.b64u(Du)], claim: Ce1 };
  const e2: P.WalkEpoch = { members: [A, Du], claim: null };
  const row = (i: number, t: number, Ep = 5, n = 0): P.WalkRow => ({ i, E: Ep, n, t });

  const table: [string, P.WalkRow, P.WalkEpoch[], boolean][] = [
    ["no claim yet", row(1, 1000), [{ ...e0, claim: null }], true],
    ["removed member, before the claim (a low cut cannot erase it)", row(1, 99, 5, 50), [e0, e1], true],
    ["removed member, after the claim (a high cut cannot keep it)", row(1, 101, 5, 0), [e0, e1], false],
    [
      "high cut: after the claim even though before the cut",
      row(1, 150, 5, 2),
      [{ ...e0, claim: { ...Ce, cuts: Ce.cuts.map(() => ({ E: 9, cnt: 99 })) } }],
      false,
    ],
    ["t_R = t(C) and before the cut", row(1, 100, 5, 2), [e0, e1], true],
    ["t_R = t(C) and at the cut", row(1, 100, 5, 3), [e0, e1], false],
    ["t_R = t(C) in an earlier era than the cut", row(1, 100, 4, 99), [e0, e1], true],
    [
      "low cut: t_R = t(C) with cut (5, 0)",
      row(1, 100, 5, 0),
      [{ ...e0, claim: { ...Ce, cuts: Ce.cuts.map(() => ({ E: 5, cnt: 0 })) } }],
      false,
    ],
    ["kept member, no later claim", row(2, 5000), [e0, e2], true],
    ["kept member, a later claim removes it: before", row(2, 199), [e0, e1, e2], true],
    ["kept member, a later claim removes it: equal t is after", row(2, 200, 0, 0), [e0, e1, e2], false],
    ["kept member, a later claim removes it: after", row(2, 250), [e0, e1, e2], false],
    [
      "the index is remapped: C_{e+1} removes D (index 2), not C",
      row(2, 250),
      [e0, { ...e1, claim: { ...Ce1, rm: 4 } }, e2],
      true,
    ],
    ["frozen reader (holds C_e, not D_{e+1}): kept member", row(2, 5000), [e0], true],
    ["frozen reader: removed member after the claim", row(1, 5000), [e0], false],
    ["frozen reader: removed member before the claim", row(1, 50), [e0], true],
    ["a member listed until the end", row(0, 9999), [e0, e1, e2], true],
  ];

  it.each(table)("%s", (_, r, epochs, want) => {
    expect(P.acceptOldRow(r, epochs)).toBe(want);
  });
});

// ───────────────────────── self lane (§7.1–§7.3) ─────────────────────────

const root = fill(32, 0x52);
const copy = { conv, root };
const mat = { e: 2, EK: EK1, bundleId: fill(32, 0x34), bundleSize: 40248 };
const refCopy = cat(conv, root);
const refMat = cat(be32(2), EK1, fill(32, 0x34), be32(40248));
const headsEntry: P.HeadsEntry = {
  ...copy,
  e: 4,
  lastTs: TS,
  ctl: { E: 7, cnt: 2 },
  lanes: [
    { E: 7, cnt: 10 },
    { E: 6, cnt: 0 },
    { E: 7, cnt: 1 },
  ],
  followed: [
    { ef: 2, lane: 1, E: 5, cnt: 3 },
    { ef: 3, lane: 0, E: 6, cnt: 9 },
  ],
};
const refHeadsEntry = cat(
  refCopy,
  be32(4),
  be64(TS),
  be16(7),
  be32(2),
  be8(3),
  be16(7),
  be32(10),
  be16(6),
  be32(0),
  be16(7),
  be32(1),
  be8(2),
  be32(2),
  be16(1),
  be16(5),
  be32(3),
  be32(3),
  be16(0),
  be16(6),
  be32(9),
);
const desc0 = cat(D0.bytes, dsig0);
const uidsAB = [alice.uid, bob.uid];

/** [record, reference content, spec length] for every rtype. */
const records: [string, P.SelfRecord, B, number][] = [
  ["CONV_JOIN", { rtype: 1, ...copy, ...mat, rootBy: alice.uid, via: 2 }, cat(refCopy, refMat, alice.uid, be8(2)), 137],
  [
    "EPOCH",
    { rtype: 2, ...copy, ...mat, claim: { E: 7, n: 3 }, flags: 1 },
    cat(refCopy, refMat, be16(7), be32(3), be8(1)),
    127,
  ],
  [
    "EPOCH (skip, NONE)",
    { rtype: 2, ...copy, ...mat, claim: P.NONE, flags: 2 },
    cat(refCopy, refMat, be16(0xffff), be32(0xffffffff), be8(2)),
    127,
  ],
  [
    "EPOCH_PENDING a = 0",
    { rtype: 3, ...copy, ...mat, tReg: 123456, uids: [] },
    cat(refCopy, refMat, be32(123456), be8(0)),
    125,
  ],
  [
    "EPOCH_PENDING a = 2",
    { rtype: 3, ...copy, ...mat, tReg: 1, uids: uidsAB },
    cat(refCopy, refMat, be32(1), be8(2), ...uidsAB),
    125 + 32,
  ],
  ["LEAVE", { rtype: 4, ...copy, e: 9 }, cat(refCopy, be32(9)), 52],
  ["CONTACT", { rtype: 5, uid: bob.uid, pin: fill(32, 0x70) }, cat(bob.uid, fill(32, 0x70)), 48],
  [
    "LINK",
    { rtype: 6, s: fill(16, 0x71), Ecreated: 3, Eexpires: 7, flags: 3 },
    cat(fill(16, 0x71), be16(3), be16(7), be8(3)),
    21,
  ],
  ["PREFS", { rtype: 7, key: 9, value: s2b("v") }, cat(be8(9), s2b("v")), 2],
  ["PREFS (empty value)", { rtype: 7, key: 0, value: new Uint8Array(0) }, be8(0), 1],
  ["HEADS c = 0 (cursor only)", { rtype: 8, Ein: 7, relIn: 99, entries: [] }, cat(be16(7), be32(99), be16(0)), 8],
  [
    "HEADS with an entry",
    { rtype: 8, Ein: 7, relIn: 99, entries: [headsEntry] },
    cat(be16(7), be32(99), be16(1), refHeadsEntry),
    8 + 68 + 6 * 3 + 12 * 2,
  ],
  ["CONFIRMED", { rtype: 9, ...copy }, refCopy, 48],
  [
    "DELIVERED a = 0",
    { rtype: 10, ...copy, e: 2, bundleId: fill(32, 0x34), uids: [] },
    cat(refCopy, be32(2), fill(32, 0x34), be8(0)),
    85,
  ],
  [
    "DELIVERED a = 2",
    { rtype: 10, ...copy, e: 2, bundleId: fill(32, 0x34), uids: uidsAB },
    cat(refCopy, be32(2), fill(32, 0x34), be8(2), ...uidsAB),
    85 + 32,
  ],
  [
    "REQUEST",
    { rtype: 11, ...copy, ...mat, tReg: 5, rootBy: alice.uid, via: 3, desc: desc0 },
    cat(refCopy, refMat, be32(5), alice.uid, be8(3), be16(desc0.length), desc0),
    143 + desc0.length,
  ],
  [
    "DESC",
    { rtype: 12, ...copy, e: 0, desc: desc0 },
    cat(refCopy, be32(0), be16(desc0.length), desc0),
    54 + desc0.length,
  ],
  [
    "MEMBER",
    { rtype: 13, uid: bob.uid, sigPk: bob.id.sigPk, pin: fill(32, 0x72), handle: "bob_1" },
    cat(bob.uid, bob.id.sigPk, fill(32, 0x72), be8(5), s2b("bob_1")),
    81 + 5,
  ],
  [
    "SNAP",
    { rtype: 0x20, blobId: fill(32, 0x73), key: fill(32, 0x74), size: 4096, pos: { E: 7, n: 12 } },
    cat(fill(32, 0x73), fill(32, 0x74), be32(4096), be16(7), be32(12)),
    74,
  ],
];

describe("self records (§7.2)", () => {
  it.each(records)("%s matches the reference with the spec's length", (_, rec, content, len) => {
    expect(content.length).toBe(len);
    const b = P.encodeRecord(rec);
    expect(toHex(b)).toBe(toHex(refRecord(rec.rtype, content)));
    expect(P.parseRecord(rec.rtype, content)).toEqual(rec);
  });

  it("HEADS entries are 68 + 6m + 12f bytes (the field list; the spec's summary says 71)", () => {
    expect(refHeadsEntry.length).toBe(68 + 6 * 3 + 12 * 2);
  });

  it.each(records)("%s: a missing or extra byte is rejected", (_, rec, content) => {
    if (rec.rtype === P.RT.PREFS) return; // PREFS has a free-length value
    expect(() => P.parseRecord(rec.rtype, content.slice(0, -1))).toThrow(P.CodecError);
    expect(() => P.parseRecord(rec.rtype, cat(content, be8(0)))).toThrow(P.CodecError);
  });

  it("rejects out-of-range enums and counts", () => {
    const set = (b: B, i: number, v: number): B => {
      const c = b.slice();
      c[i] = v;
      return c;
    };
    const content = (k: string) => records.find(([n]) => n === k)![2];
    const bads: [string, number, B][] = [
      ["CONV_JOIN via 0", 1, set(content("CONV_JOIN"), 136, 0)],
      ["CONV_JOIN via 6", 1, set(content("CONV_JOIN"), 136, 6)],
      ["EPOCH e = 0", 2, cat(refCopy, be32(0), EK1, fill(32, 0x34), be32(40248), be16(7), be32(3), be8(1))],
      ["EPOCH flags 4", 2, set(content("EPOCH"), 126, 4)],
      ["EPOCH claim era 0xFFFF outside NONE", 2, cat(refCopy, refMat, be16(0xffff), be32(0), be8(2))],
      ["EPOCH_PENDING a = 33", 3, cat(refCopy, refMat, be32(1), be8(33), ...Array(33).fill(fill(16, 1)))],
      ["LINK flags 4", 6, set(content("LINK"), 20, 4)],
      ["PREFS empty", 7, new Uint8Array(0)],
      [
        "HEADS lane count 0",
        8,
        cat(be16(7), be32(99), be16(1), refCopy, be32(4), be64(TS), be16(7), be32(2), be8(0), be8(0)),
      ],
      [
        "HEADS lane count 33",
        8,
        cat(
          be16(7),
          be32(99),
          be16(1),
          refCopy,
          be32(4),
          be64(TS),
          be16(7),
          be32(2),
          be8(33),
          ...Array(33).fill(fill(6, 0)),
          be8(0),
        ),
      ],
      [
        "HEADS 33 followed lanes",
        8,
        cat(
          be16(7),
          be32(99),
          be16(1),
          refCopy,
          be32(4),
          be64(TS),
          be16(7),
          be32(2),
          be8(1),
          fill(6, 0),
          be8(33),
          ...Array(33).fill(fill(12, 0)),
        ),
      ],
      ["HEADS c above its entries", 8, cat(be16(7), be32(99), be16(2), refHeadsEntry)],
      [
        "HEADS lastTs above 2^53 − 1",
        8,
        cat(
          be16(7),
          be32(99),
          be16(1),
          refCopy,
          be32(4),
          be64(2n ** 53n),
          be16(7),
          be32(2),
          be8(1),
          fill(6, 0),
          be8(0),
        ),
      ],
      ["DELIVERED a = 33", 10, cat(refCopy, be32(2), fill(32, 0x34), be8(33), ...Array(33).fill(fill(16, 1)))],
      ["REQUEST via 0", 11, cat(refCopy, refMat, be32(5), alice.uid, be8(0), be16(desc0.length), desc0)],
      ["REQUEST desc of 191 bytes", 11, cat(refCopy, refMat, be32(5), alice.uid, be8(3), be16(191), fill(191, 0))],
      ["DESC of 1937 bytes", 12, cat(refCopy, be32(0), be16(1937), fill(1937, 0))],
      ["MEMBER hlen 2", 13, cat(bob.uid, bob.id.sigPk, fill(32, 0x72), be8(2), s2b("bo"))],
      ["MEMBER hlen 21", 13, cat(bob.uid, bob.id.sigPk, fill(32, 0x72), be8(21), s2b("b".repeat(21)))],
      ["MEMBER upper case", 13, cat(bob.uid, bob.id.sigPk, fill(32, 0x72), be8(3), s2b("Bob"))],
      ["MEMBER non-ASCII", 13, cat(bob.uid, bob.id.sigPk, fill(32, 0x72), be8(4), s2b("bö"))],
      ["SNAP era 0xFFFF outside NONE", 0x20, cat(fill(32, 0x73), fill(32, 0x74), be32(4096), be16(0xffff), be32(1))],
    ];
    for (const [what, rtype, c] of bads)
      expect([what, throwsError(() => P.parseRecord(rtype, c))]).toEqual([what, true]);
    expect(() => P.encodeRecord({ rtype: 1, ...copy, ...mat, rootBy: alice.uid, via: 9 as P.Via })).toThrow(
      P.CodecError,
    );
    expect(() =>
      P.encodeRecord({ rtype: 13, uid: bob.uid, sigPk: bob.id.sigPk, pin: fill(32, 0), handle: "Bob" }),
    ).toThrow();
  });

  it("returns null (skip) for unknown rtypes", () => {
    for (const rtype of [0x00, 0x0e, 0x0f, 0x1f, 0x21, 0x80, 0xff])
      expect(P.parseRecord(rtype, fill(5, 0xff))).toBeNull();
  });
});

describe("self rows S (§7.1)", () => {
  const contact = records.find(([n]) => n === "CONTACT")!;
  const pending = records.find(([n]) => n === "EPOCH_PENDING a = 0")!;
  const snap = records.find(([n]) => n === "SNAP")!;
  const row: P.SelfRow = { prev: { E: 6, n: 4 }, prevh: fill(16, 0x75), ts: TS, records: [contact[1], records[0][1]] };
  const refRow = refS(6, 4, fill(16, 0x75), TS, [refRecord(5, contact[2]), refRecord(1, records[0][2])]);

  it("matches the reference (32-byte header) and round-trips", () => {
    const S = P.encodeS(row);
    expect(toHex(S)).toBe(toHex(refRow));
    expect(P.S_HEADER_LEN).toBe(32);
    expect(S.length).toBe(32 + 3 + 48 + 3 + 137);
    expect(P.parseS(S)).toEqual({ ...row, skipped: 0 });
    const first: P.SelfRow = { prev: P.NONE, prevh: P.ZERO16, ts: TS, records: [contact[1]] };
    expect(P.parseS(P.encodeS(first))).toEqual({ ...first, skipped: 0 });
  });

  it("skips unknown rtypes but keeps parsing", () => {
    const S = refS(6, 4, fill(16, 0x75), TS, [
      refRecord(0x0e, fill(3, 1)),
      refRecord(5, contact[2]),
      refRecord(0xff, new Uint8Array(0)),
    ]);
    expect(P.parseS(S)).toEqual({
      prev: { E: 6, n: 4 },
      prevh: fill(16, 0x75),
      ts: TS,
      records: [contact[1]],
      skipped: 2,
    });
    const onlyUnknown = refS(6, 4, fill(16, 0x75), TS, [refRecord(0x30, fill(3, 1))]);
    expect(P.parseS(onlyUnknown).records).toEqual([]);
  });

  it("rejects malformed rows", () => {
    const one = [refRecord(5, contact[2])];
    const bads: [string, B][] = [
      ["ver 1", refS(6, 4, fill(16, 1), TS, one, 1, 1)],
      ["count 0", refS(6, 4, fill(16, 1), TS, [], 0)],
      ["count above the records", refS(6, 4, fill(16, 1), TS, one, 2)],
      ["count below the records", refS(6, 4, fill(16, 1), TS, [...one, ...one], 1)],
      ["NONE with a prevh", refS(0xffff, 0xffffffff, fill(16, 1), TS, one)],
      ["era 0xFFFF outside NONE", refS(0xffff, 0, fill(16, 0), TS, one)],
      ["a malformed known record", refS(6, 4, fill(16, 1), TS, [refRecord(5, contact[2].slice(1))])],
      ["a SNAP in a self row", refS(6, 4, fill(16, 1), TS, [refRecord(0x20, snap[2])])],
      ["a trailing byte", cat(refS(6, 4, fill(16, 1), TS, one), be8(0))],
    ];
    for (const [what, b] of bads) expect([what, throwsError(() => P.parseS(b))]).toEqual([what, true]);
    expect(() => P.encodeS({ ...row, records: [] })).toThrow(P.CodecError);
    expect(() => P.encodeS({ ...row, records: Array(256).fill(contact[1]) })).toThrow(P.CodecError);
    expect(P.parseS(P.encodeS({ ...row, records: Array(255).fill(contact[1]) })).records.length).toBe(255);
    expect(() => P.encodeS({ ...row, records: [snap[1], contact[1]] })).toThrow(P.CodecError);
  });

  it("snapshot pointer rows (Lsnap) hold exactly one SNAP", () => {
    const ptr: P.SelfRow = { ...row, records: [snap[1]] };
    const S = P.encodeS(ptr);
    expect(P.parseS(S, "snap")).toEqual({ ...ptr, skipped: 0 });
    expect(() => P.parseS(S)).toThrow(P.CodecError);
    expect(() => P.parseS(refRow, "snap")).toThrow(P.CodecError);
    const two = refS(6, 4, fill(16, 0x75), TS, [refRecord(0x20, snap[2]), refRecord(0x20, snap[2])]);
    expect(() => P.parseS(two, "snap")).toThrow(P.CodecError);
    const withUnknown = refS(6, 4, fill(16, 0x75), TS, [refRecord(0x20, snap[2]), refRecord(0x40, fill(2, 0))]);
    expect(P.parseS(withUnknown, "snap").skipped).toBe(1);
  });

  it("sealSelf / openSelf: AAD, reference construction, and the EPOCH_PENDING class rule (test 6)", () => {
    const id = alice.id;
    const label = P.Lself(id.rS, E, 0);
    const nonce = seqBytes(24, 0x30);
    const plain: P.SelfRow = { prev: P.NONE, prevh: P.ZERO16, ts: TS, records: [contact[1]] };
    const sealed = withRng(queueRng([nonce]), () => P.sealSelf(id.kS, E, label, plain));
    const kS = hkdfN(fill(32, 1), "", "segv.sh/v2/self/aead");
    const aad = refEnc("segv.sh/v2/self", be16(E), label);
    expect(toHex(sealed.body)).toBe(toHex(xSeal(kS, nonce, aad, refPad(P.encodeS(plain), CLASSES))));
    expect(sealed.cls).toBe(0);
    expect(P.openSelf(id.kS, E, label, sealed.body)).toEqual({ ...plain, skipped: 0 });
    // EPOCH_PENDING with a = 0 fits class 0 (32 + 3 + 125 = 160 B) but is padded to class 1
    const withPending: P.SelfRow = { ...plain, records: [pending[1]] };
    expect(P.encodeS(withPending).length).toBe(160);
    const sp = withRng(queueRng([nonce]), () => P.sealSelf(id.kS, E, label, withPending));
    expect(sp.cls).toBe(1);
    expect(sp.body.length).toBe(1064);
    expect(toHex(sp.body)).toBe(toHex(xSeal(kS, nonce, aad, refPad(P.encodeS(withPending), [1024, 4096, 16384]))));
    expect(P.openSelf(id.kS, E, label, sp.body).records).toEqual([pending[1]]);
    // a snapshot pointer row opens only as a pointer
    const ptr = P.sealSelf(id.kS, E, P.Lsnap(id.rS, E, 0), { ...plain, records: [snap[1]] });
    expect(P.openSelf(id.kS, E, P.Lsnap(id.rS, E, 0), ptr.body, "snap").records).toEqual([snap[1]]);
    expect(() => P.openSelf(id.kS, E, P.Lsnap(id.rS, E, 0), ptr.body)).toThrow();
    // tampering
    expect(() => P.openSelf(id.kS, E + 1, label, sealed.body)).toThrow();
    expect(() => P.openSelf(id.kS, E, flip(label, 0), sealed.body)).toThrow();
    expect(() => P.openSelf(bob.id.kS, E, label, sealed.body)).toThrow();
    for (let i = 0; i < sealed.body.length; i += 7)
      expect(() => P.openSelf(id.kS, E, label, flip(sealed.body, i))).toThrow();
    expect(() => P.openSelf(id.kS, E, label, sealed.body.slice(1))).toThrow();
  });
});

describe("snapshots S2 (§7.4)", () => {
  const recs = records.filter(([, r]) => r.rtype !== P.RT.SNAP);
  const snapshot: P.Snapshot = { pos: { E: 7, n: 30 }, ts: TS, records: recs.map(([, r]) => r) };
  const ref = refS2(
    7,
    30,
    TS,
    recs.map(([, r, c]) => refRecord(r.rtype, c)),
  );

  it("matches the reference and round-trips", () => {
    const S2 = P.encodeSnapshot(snapshot);
    expect(toHex(S2)).toBe(toHex(ref));
    expect(P.parseSnapshot(S2)).toEqual({ ...snapshot, skipped: 0 });
    const empty: P.Snapshot = { pos: P.NONE, ts: 0, records: [] };
    expect(P.encodeSnapshot(empty).length).toBe(23);
    expect(P.parseSnapshot(P.encodeSnapshot(empty))).toEqual({ ...empty, skipped: 0 });
  });

  it("is strict, skips unknown rtypes, and refuses SNAP", () => {
    const one = [refRecord(5, records[6][2])];
    expect(P.parseSnapshot(refS2(7, 30, TS, [...one, refRecord(0x55, fill(9, 9))])).skipped).toBe(1);
    for (const bad of [
      cat(s2b("SGS3"), ref.subarray(4)),
      cat(s2b("SGS2"), be8(2), ref.subarray(5)),
      refS2(0xffff, 0, TS, one),
      refS2(7, 30, TS, one, 2),
      refS2(7, 30, TS, one, 0xffffffff),
      refS2(7, 30, TS, [refRecord(0x20, records[records.length - 1][2])]),
      cat(refS2(7, 30, TS, one), be8(0)),
      refS2(7, 30, TS, one).slice(0, -1),
    ])
      expect(() => P.parseSnapshot(bad)).toThrow(P.CodecError);
    expect(() => P.encodeSnapshot({ ...snapshot, records: [records[records.length - 1][1]] })).toThrow(P.CodecError);
  });

  it("encrypts with the snapshot AAD and padmé", () => {
    const { blob, id, key } = P.encryptSnapshot(snapshot);
    expect(id).toBe(Buffer.from(sha(blob)).toString("base64url"));
    expect(blob.length).toBe(24 + P.padmeLength(ref.length + 1) + 16);
    expect(P.decryptSnapshot(blob, id, key)).toEqual({ ...snapshot, skipped: 0 });
    expect(toHex(refUnpad(xOpen(key, blob, s2b("segv.sh/v2/snapshot"))))).toBe(toHex(ref));
    expect(() => P.decryptBlob(blob, id, key)).toThrow(); // the image-blob AAD does not open it
    const asImage = P.encryptBlob(ref);
    expect(() => P.decryptSnapshot(asImage.blob, asImage.id, asImage.key)).toThrow();
    expect(() => P.decryptSnapshot(blob, P.b64u(fill(32, 0)), key)).toThrow();
  });
});

// ───────────────────────── throwing decapsulation (§1.1, test 9) ─────────────────────────

describe("a low-order X25519 component makes every trial-open return 'does not open' (test 9)", () => {
  // X-Wing ct = ML-KEM ct (1088 B) ‖ X25519 ephemeral (32 B); u = 0 and u = 1 are low-order points
  const lowOrder = [fill(32, 0), cat(be8(1), fill(31, 0))].map((u) => cat(fill(1088, 5), u));
  const keys = [alice, bob, carol, dave].map((p) => p.id.kemSk);

  it("decapsulation throws (precondition)", () => {
    for (const kct of lowOrder) for (const sk of keys) expect(() => xwing.decapsulate(kct, sk)).toThrow();
  });

  it("tryOpenInvite returns null", () => {
    for (const kct of lowOrder) {
      const body = cat(kct, fill(296, 7));
      for (const sk of keys) expect(P.tryOpenInvite(sk, E, 0, fill(16, 1), body)).toBeNull();
    }
  });

  it("openEntry returns null and processClaim reports a withheld key", () => {
    const b = P.buildBundle({
      conv,
      e: 1,
      D: D1.bytes,
      dsig: dsig1,
      EK: EK1,
      prevMembers: [alice, bob, carol].map((p) => p.id.kemPk),
      keep: [true, false, true],
    });
    for (const kct of lowOrder) {
      const blob = b.blob.slice();
      for (let i = 0; i < 8; i++) blob.set(kct, 16 + 2088 + 1192 * i);
      for (const sk of keys) for (let i = 0; i < 8; i++) expect(P.openEntry(sk, conv, 1, i, blob)).toBeNull();
      const claim = { ...claim3, bundleId: sha(blob) };
      expect(P.processClaim({ kemSk: alice.id.kemSk, De: D0, i: 0, from: 0, claim, blob })).toEqual({
        kind: "withheld",
      });
    }
  });

  it("openHello returns null", () => {
    const s = fill(16, 3);
    const label = fill(16, 4);
    for (const kct of lowOrder) {
      const inner = cat(kct, fill(130, 7));
      const body = P.aeadSeal(P.linkKeys(s).mL, P.pad(inner, CLASSES), P.helloAad(E, label));
      for (const sk of keys) expect(P.openHello(sk, s, E, label, body)).toBeNull();
    }
  });

  it("openWrap throws an ordinary Error ('does not open')", () => {
    const key = P.recoveryKem(fill(20, 9));
    for (const kct of lowOrder) {
      const w = { uid: P.b64u(alice.uid), id: key.id, wrap: cat(kct, fill(72, 7)) };
      expect(throwsError(() => P.openWrap(w, key))).toBe(true);
    }
  });
});

// ───────────────────────── 3. fuzz ─────────────────────────

describe("fuzz: truncations, extensions and random bytes are rejected (test 4)", () => {
  const r = prng(0x5e9f);
  const samples: [string, (b: B) => unknown, B[]][] = [
    [
      "parseM",
      P.parseM,
      [
        P.encodeM({ ...hdr(), type: P.MT.TEXT, text: "fuzz me" }),
        P.encodeM({ ...hdr(), type: P.MT.IMAGE, image }),
        P.encodeM({ ...hdr(), type: P.MT.WELCOME, join: join1 }),
        P.encodeM(claimMsg()),
        P.encodeM({ ...hdr(), type: P.MT.NEED_KEY, ef: 1 }),
        P.encodeM({ ...hdr(), type: P.MT.KEY_OK }),
      ],
    ],
    ["parseD", P.parseD, [D0.bytes, D1.bytes]],
    ["parseJ", P.parseJ, [P.encodeJ(join1)]],
    ["parseClaim", P.parseClaim, [P.encodeClaim(claim3)]],
    ["parseImage", P.parseImage, [P.encodeImage(image)]],
    [
      "parseS",
      (b) => P.parseS(b),
      [
        P.encodeS({
          prev: { E: 6, n: 4 },
          prevh: fill(16, 1),
          ts: TS,
          records: records.filter(([, x]) => x.rtype !== 0x20).map(([, x]) => x),
        }),
      ],
    ],
    [
      "parseSnapshot",
      P.parseSnapshot,
      [P.encodeSnapshot({ pos: P.NONE, ts: TS, records: [records[0][1], records[11][1]] })],
    ],
    ...records
      .filter(([, x]) => x.rtype !== P.RT.PREFS)
      .map(([n, x, c]): [string, (b: B) => unknown, B[]] => [`record ${n}`, (b) => P.parseRecord(x.rtype, b), [c]]),
  ];

  it.each(samples)("%s", (_, parse, valid) => {
    for (const v of valid) {
      expect(() => parse(v)).not.toThrow();
      // every truncation (a sample of them for long inputs) and every extension
      const cuts =
        v.length <= 400
          ? Array.from({ length: v.length }, (_, i) => i)
          : Array.from({ length: 300 }, () => r.int(v.length));
      for (const i of cuts) expect(throwsError(() => parse(v.slice(0, i)))).toBe(true);
      for (let k = 1; k <= 8; k++) expect(throwsError(() => parse(cat(v, r.bytes(k))))).toBe(true);
      // bit flips either parse or throw an Error
      for (let k = 0; k < 200; k++) throwsError(() => parse(flip(v, r.int(v.length), r.int(8))));
    }
    // random bytes of random lengths: never a non-Error throw
    for (let k = 0; k < 300; k++) throwsError(() => parse(r.bytes(r.int(600))));
  });

  it("parseBundleBlob rejects every other length and random headers", () => {
    for (const n of [0, 16, 2104, 11639, 11641, 40247, 40249])
      expect(throwsError(() => P.parseBundleBlob(new Uint8Array(n)))).toBe(true);
    for (let k = 0; k < 50; k++) {
      const b = cat(r.bytes(16), new Uint8Array(11640 - 16));
      const ok =
        toHex(b.subarray(0, 6)) === toHex(cat(s2b("SGB2"), be8(1), be8(8))) && b.subarray(6, 16).every((x) => x === 0);
      expect(throwsError(() => P.parseBundleBlob(b))).toBe(!ok);
    }
  });
});

// ───────────────────────── 4. known-answer vectors ─────────────────────────
// Generated once from the implementation after the tests above passed (which cross-check every layout against
// the independent reference). If one of these fails, the wire format changed: do not "fix" the vector.

function computeKat() {
  const rng = detRng("segv.sh/v2/kat/conv");
  return withRng(rng, () => {
    const M = P.encodeM({
      ...hdr({ prev: { E: 3, n: 1 }, prevh: fill(16, 0x77), ckq: 9, ck16: fill(16, 0x99) }),
      type: P.MT.TEXT,
      text: "kat",
    });
    const label = P.Lmsg(keys0.rk, 1, E, 5);
    const sig = P.signRow(bob.id.sigSk, conv, 0, E, label, M);
    const row = P.sealRow(keys0.mk, E, label, M, sig);
    const claimRow = P.buildRow(ctx0(alice.id.sigSk), E, claimMsg(claim3, 0, 0));
    const inv = P.makeInvite(bob.id.kemPk, E, 0, join1);
    const hello = P.makeHello(bob.id.kemPk, fill(16, 0x50), E, fill(16, 0x51), join1);
    const bundle = P.buildBundle({
      conv,
      e: 1,
      D: D1.bytes,
      dsig: dsig1,
      EK: EK1,
      prevMembers: [alice, bob, carol].map((p) => p.id.kemPk),
      keep: [true, false, true],
    });
    const selfRow = P.sealSelf(alice.id.kS, E, P.Lself(alice.id.rS, E, 0), {
      prev: P.NONE,
      prevh: P.ZERO16,
      ts: TS,
      records: [records[3][1], records[0][1]],
    });
    const snap = P.encryptSnapshot({
      pos: { E: 7, n: 30 },
      ts: TS,
      records: records.filter(([, r]) => r.rtype !== 0x20).map(([, r]) => r),
    });
    return {
      D0: toHex(D0.bytes),
      hD1: toHex(D1.hash),
      dsig0: toHex(dsig0),
      J: toHex(P.encodeJ(join1)),
      claim: toHex(P.encodeClaim(claim3)),
      M: toHex(M),
      sig: toHex(sig),
      rowBodySha: toHex(sha(row.body)),
      claimRowSha: toHex(sha(claimRow.body)),
      invite: toHex(inv.eid) + ":" + toHex(sha(inv.body)),
      helloSha: toHex(sha(hello.body)),
      bundleId: toHex(bundle.id),
      selfRowSha: toHex(sha(selfRow.body)),
      snapshot: snap.id + ":" + toHex(snap.key),
    };
  });
}

const KAT = {
  // D_0 = alice (by), bob, carol; e = 0; name "kat" (cross-checked against refD above)
  D0:
    "02606162636465666768696a6b6c6d6e6f000000000000000000000000000000000000000000000000000000000000000000000000" +
    "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00000019b93216d0003" +
    "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a012dfde9fa01f1210b0744167dc73d4be8b07e2ce787e01aa8277453025f922e8" +
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a108d49f307d2069ae7103b5b61f6a8b2bb256dd9445960bab6413c565c0cb0e09" +
    "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2b2596b23571457937535034115fdeb96061e978fce56c1fcb0c93c518ae7ff6b" +
    "00036b6174",
  hD1: "f6b927933650e5802664a4d530c3de298f906901b0ed4c020f53a48067f507cc",
  dsig0:
    "ce664a8441022812520449561f2cda406f81c0475c53635f1de55d09c78e4e9c566a6325bbebee27e59797299036cedf77ad0260cd76849e3997ab39758dd10a",
  J: "0201606162636465666768696a6b6c6d6e6f000000012222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333300002d78",
  claim:
    "c87ea58357addb0100c8e17567bab6a262382703d6f56f51d49e1827cc8e43b8f6b927933650e5802664a4d530c3de298f906901b0ed4c020f53a48067f507cc" +
    "422e538f484476258feb88c91b1f2417ea32e3269632e1ae449aef62b745fe483434343434343434343434343434343434343434343434343434343434343434" +
    "00002d780000000203000300000004000300000000000200000009",
  M: "02010001000100000005000300000001777777777777777777777777777777770000019b93216d00000000099999999999999999999999999999999900036b6174",
  // Ed25519 is deterministic; every AEAD nonce, KEM randomness and dummy key below comes from detRng
  sig: "49e59d056278036d99b4fdc21b682372db8fe4d164cebf1f17bff119e678e7011f23954e9f705470433668775cd5e5d4fa51ff3b86ff0649b508b676b01c960a",
  rowBodySha: "3f782ad26eedbbfa24f7dea68487e6415187c14c5f0fa904cc2dc15b0d59eee0",
  claimRowSha: "7117cd2e30027154b5c49bdfa936787828d986053212e0fc4fa3198d77404f24",
  invite: "8792236681c1a310f4bb29598ebe7ab2:5627d0e7f167c816c7701c3246a4e5c1306aa7a1cb3e5f6bd1dfc4928b455af2",
  helloSha: "b165ef4d5c8abff45168d243114c856d007e395626b91334495874958bc29ec0",
  bundleId: "e5719061e6330c6a4b860284b4ae11199a79f6fcbe21fb01b7dc66a6b79b0e1d",
  selfRowSha: "926ddd200fb162bdc4286437ab751e77127850e536d4fdeae329ff67df3e84af",
  snapshot:
    "AJcGZ_p-jBMLmH3zTOcnA-rEq-g6kcT69--vmHPIz3g:80f5bdcfeacc5fb3903aa1b23492f0988b0e7796df52ae768950a024d44af82f",
};

describe("known-answer vectors", () => {
  it("are stable", () => {
    expect(computeKat()).toEqual(KAT);
  });
});
