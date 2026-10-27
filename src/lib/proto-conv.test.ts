// Test suite for the conversation codecs of src/lib/proto.ts (below the "conversation codecs" banner):
// envelope M (§3.3), descriptors, joins, invites, hellos and SGB2 bundles (§5), claims and the old-epoch walk
// (§6.2, §6.4, §6.6–§6.8), and the self lane and snapshots (§7). The core above the banner is tested in
// proto.test.ts.
//
// Layout (as in proto.test.ts):
//   1. reference helpers — an independent re-implementation of the layouts on top of node:crypto (noble only for
//                          XChaCha20 and X-Wing, which node:crypto lacks), used to cross-check byte for byte.
//                          (noble's ed25519 Point is used only to build a mixed-order test key.)
//   2. per-codec round trips, strictness, tamper tests and fuzzing.
//   3. fuzz — truncations, extensions and random bytes are rejected, and parsers only ever throw Error.
//   4. known answers — pinned outputs, with deterministic randomness through _setRandomForTests.
import { afterEach, describe, expect, it } from "vite-plus/test";
import { createHash, createHmac, createPrivateKey, createPublicKey, hkdfSync, verify as nodeVerify } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_kem768_x25519 as xwing } from "@noble/post-quantum/hybrid.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import * as P from "./proto";

type B = Uint8Array;

// ───────────────────────── 1. reference helpers (independent of proto.ts) ─────────────────────────

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

/** §5.1 kh = H(enc("segv.sh/v2/kh", kemPk)). */
const refKh = (kemPk: B): B => sha(refEnc("segv.sh/v2/kh", kemPk));
/** §5.1 D with explicit fields. */
interface RefD {
  ver?: number;
  conv: B;
  e: number;
  prev: B;
  by: B;
  ts: number | bigint;
  m?: number;
  members: { uid: B; sigPk: B; kh: B }[];
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
    ...x.members.flatMap((m) => [m.uid, m.sigPk, m.kh]),
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
/** §1.4 seal with explicit randomness: X-Wing encapsulation (noble) to `pk`, node:crypto HKDF, XChaCha20 (noble). */
const refSealWith = (pk: B, label: string, ctx: B, pt: B, kemRand: B, nonce: B): B => {
  const { cipherText: kct, sharedSecret: ss } = xwing.encapsulate(pk, kemRand);
  return cat(kct, xSeal(hkdfN(ss, sha(kct), refEnc("segv.sh/v2/seal", label, ctx)), nonce, refEnc(label, ctx), pt));
};
/** §5.4 rr_e, the entry context, and sealDet: ρ from node:crypto HKDF; noble only for X-Wing and XChaCha20. */
const refRr = (EK: B, conv: B, e: number): B => hkdfN(EK, conv, refEnc("segv.sh/v2/ep/rekey", be32(e)));
const refRekeyCtx = (conv: B, e: number, i: number): B => refEnc(conv, be32(e), be16(i));
const refRho = (EK: B, conv: B, e: number, i: number): B =>
  hkdfN(refRr(EK, conv, e), "", refEnc("segv.sh/v2/rekey-rnd", be16(i)), 88);
const refSealDet = (pk: B, conv: B, e: number, i: number, EK: B): B => {
  const rho = refRho(EK, conv, e, i);
  return refSealWith(pk, "segv.sh/v2/rekey", refRekeyCtx(conv, e, i), EK, rho.slice(0, 64), rho.slice(64, 88));
};
/** X25519 public key of a 32-byte secret, with node:crypto (RFC 8410 PKCS#8). */
const X25519_PKCS8 = fromHex("302e020100300506032b656e04220420");
const x25519Pub = (sk: B): B => {
  const priv = createPrivateKey({ key: Buffer.from(cat(X25519_PKCS8, sk)), format: "der", type: "pkcs8" });
  return new Uint8Array(Buffer.from(createPublicKey(priv).export({ format: "jwk" }).x!, "base64url"));
};
/** §5.4 pks: the kemPks in D order, zero-filled to B·1216 bytes. */
const refPks = (kemPks: B[], B: number): B => cat(...kemPks, new Uint8Array((B - kemPks.length) * 1216));
/** §5.4 SGB2 blob assembled from its parts (any parts, so malformed bundles can be built). */
const refBlob = (
  x: { B: number; conv: B; e: number; EK: B; desc: B; pks: B; entries: B[] },
  nonces: [B, B] = [seqBytes(24, 0x24), seqBytes(24, 0x42)],
): B => {
  const { dk } = refEpochKeys(x.EK, x.conv, x.e);
  return cat(
    s2b("SGB2"),
    be8(1),
    be8(x.B),
    fill(10, 0),
    xSeal(dk, nonces[0], refEnc("segv.sh/v2/desc", x.conv, be32(x.e)), refPad(x.desc, [4096])),
    xSeal(dk, nonces[1], refEnc("segv.sh/v2/pks", x.conv, be32(x.e)), x.pks),
    ...x.entries,
  );
};
/** Byte offsets of an SGB2 blob (§5.4): descCt at 16 (4136 B), pkCt at 4152 (B·1216 + 40 B), then the entries. */
const PKCT_AT = 16 + 4136;
const entryAt = (B: number, i: number): number => PKCT_AT + B * 1216 + 40 + 1192 * i;
/** A copy of `blob` with `part` written at `at`. */
const patch = (blob: B, at: number, part: B): B => {
  const c = blob.slice();
  c.set(part, at);
  return c;
};

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
/** Records every chunk an RNG hands out. */
const recording =
  (fn: (n: number) => B, calls: B[]) =>
  (n: number): B => {
    const b = fn(n);
    calls.push(b);
    return b;
  };
/** An RNG that must not be called (a construction that uses no randomness). */
const noRng = (): B => {
  throw new Error("random() must not be called");
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
const mem = (p: Person): P.Member => ({ uid: p.uid, sigPk: p.id.sigPk, kh: refKh(p.id.kemPk) });
/** A cheap signing-only member (no KEM keygen) for large descriptors; its kh is any 32 bytes (§5.1). */
const sigMember = (k: number): P.Member => ({
  uid: fill(16, k),
  sigPk: P.sigPub(fill(32, 0x80 + k)),
  kh: fill(32, 0x40 + k),
});

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
/** kemPks in D order: pks_0 (alice, bob, carol) and pks_1 (alice, carol, dave); pks1 zero-fills them to B = 8. */
const kem0 = [alice, bob, carol].map((p) => p.id.kemPk);
const kem1 = [alice, carol, dave].map((p) => p.id.kemPk);
const pks1 = refPks(kem1, 8);
/** The honest bundle of e = 1: bob (index 1) removed (rm = 2), dave added; alice and carol keep sealDet entries. */
const spec1: P.BundleSpec = {
  conv,
  e: 1,
  D: D1.bytes,
  dsig: dsig1,
  EK: EK1,
  pks: kem1,
  prevMembers: D0.members.map((x) => x.uid),
  rm: 2,
};
const built1 = P.buildBundle(spec1);

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
    ...[0, 3, 4, 7, 9, 15, 18, 19, 20, 255].map((t): [string, Partial<RefM>] => [
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
    // types 18 and 19 (stage 1 drafts' NEED_KEY and KEY_OK) are gone (§3.3), whatever their content
    ["type 18 with a u32 e_f", { type: 18, content: be32(3) }],
    ["type 19 with no content", { type: 19, content: new Uint8Array(0) }],
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
      { ...hdr(), type: 18 as typeof P.MT.LEAVE },
      { ...hdr(), type: 19 as typeof P.MT.LEAVE },
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

  it("selects classes by size", () => {
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
    ] as P.Msg[])
      expect(P.buildRow(ctx0(), E, m).cls).toBe(0);
  });

  it("types 18 and 19 make a row malformed, even sealed and signed by a member", () => {
    for (const [type, content] of [
      [18, be32(0)],
      [19, new Uint8Array(0)],
    ] as const) {
      const M = baseRefM({ type, content });
      expect(() => P.parseM(M)).toThrow(P.CodecError);
      const label = P.Lmsg(keys0.rk, 1, E, 5);
      const body = P.sealRow(keys0.mk, E, label, M, P.signRow(bob.id.sigSk, conv, 0, E, label, M)).body;
      expect(P.acceptRow(rowCtx0, E, label, body)).toEqual({ ok: false, why: "malformed" });
    }
    expect(Object.values(P.MT)).toEqual([1, 2, 8, 16, 17]);
  });

  it("flipping any byte of a body, or changing the label or E, makes the row fail to open", () => {
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

  it("changing conv or e makes the signature fail", () => {
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
    // content: a claim with m ≠ |D_e|
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
  it("matches the reference layout: members (uid, sigPk, kh) of 80 B, kh = kemHash(kemPk)", () => {
    const ref0 = refD({ ...D0f, members: [...D0f.members], name: s2b("kat") });
    expect(toHex(D0.bytes)).toBe(toHex(ref0));
    expect(D0.bytes.length).toBe(78 + 80 * 3 + 2 + 3);
    expect(toHex(D0.hash)).toBe(toHex(sha(ref0)));
    expect(toHex(P.hashD(D0.bytes))).toBe(toHex(sha(ref0)));
    expect(toHex(D1.bytes)).toBe(toHex(refD({ ...D1f, members: [...D1f.members], name: new Uint8Array(0) })));
    expect(D1.name).toBeNull();
    const { bytes: _b, hash: _h, ...fields } = D0;
    expect(fields).toEqual({ ...D0f, members: [...D0f.members] });
    for (const p of [alice, bob, carol, dave]) expect(toHex(P.kemHash(p.id.kemPk))).toBe(toHex(refKh(p.id.kemPk)));
    expect(toHex(D0.members[1].kh)).toBe(toHex(sha(refEnc("segv.sh/v2/kh", bob.id.kemPk))));
    // parseD puts no rule on kh: any 32 bytes
    for (const kh of [fill(32, 0), fill(32, 0xff), refKh(fill(1216, 0xff))]) {
      const D = P.parseD(refD({ ...D0f, members: [{ ...mem(alice), kh }], name: new Uint8Array(0) }));
      expect(toHex(D.members[0].kh)).toBe(toHex(kh));
    }
    const lens = [P.D_MEMBER_LEN, P.D_MIN_LEN, P.D_MAX_LEN, P.DESC_MIN_LEN, P.DESC_MAX_LEN];
    expect(lens).toEqual([80, 160, 2896, 224, 2960]);
  });

  it("a maximal D (32 members, 64 four-byte code points) is 2896 B and D ‖ dsig fits [4096]", () => {
    const name = "😀".repeat(64);
    expect([...name].length).toBe(64);
    expect(s2b(name).length).toBe(256);
    const members = Array.from({ length: 32 }, (_, k) => sigMember(k + 1));
    const D = P.encodeD({ conv, e: 7, prev: fill(32, 9), by: members[31].uid, ts: 2 ** 53 - 1, members, name });
    expect(D.length).toBe(2896);
    expect(P.D_MAX_LEN).toBe(2896);
    const dsig = P.signD(D, keys0.kc, fill(32, 0x80 + 32));
    expect(P.verifyD(D, keys0.kc, dsig)).toBe(true);
    expect(cat(D, dsig).length).toBe(2960);
    expect([...P.DESC_CLASSES]).toEqual([4096]);
    expect(P.pad(cat(D, dsig), P.DESC_CLASSES).length).toBe(4096);
    expect(() => P.parseD(cat(D, be8(0)))).toThrow(P.CodecError);
  });

  it("parseD enforces every rule and nothing else", () => {
    const ms = [alice, bob].map(mem);
    const base: RefD = { conv, e: 1, prev: fill(32, 9), by: alice.uid, ts: TS, members: ms, name: s2b("n") };
    expect(P.parseD(refD(base)).name).toBe("n");
    const identity = cat(be8(1), fill(31, 0)); // the neutral element: small order
    const order8 = fromHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"); // a small-order point
    const notPoint = fill(32, 0xff);
    // bob's key plus that order-8 point: a mixed-order key (not of small order, not in the prime-order subgroup)
    const mixed = ed25519.Point.fromBytes(bob.id.sigPk).add(ed25519.Point.fromBytes(order8)).toBytes();
    for (const pk of [identity, order8, notPoint, fill(32, 0), mixed]) expect(P.isBadSigPk(pk)).toBe(true);
    const withKey = (sigPk: B) => refD({ ...base, members: [ms[0], { ...ms[1], sigPk }] });
    const bads: [string, B][] = [
      ["ver 1", refD({ ...base, ver: 1 })],
      ["m = 0", refD({ ...base, members: [], by: fill(16, 0) })],
      ["m = 33", refD({ ...base, members: Array.from({ length: 33 }, (_, k) => sigMember(k + 1)), by: fill(16, 1) })],
      ["m above the listed members", refD({ ...base, m: 3 })],
      ["duplicate uids", refD({ ...base, members: [ms[0], { ...ms[1], uid: alice.uid }] })],
      ["the identity as sigPk", withKey(identity)],
      ["an order-8 sigPk", withKey(order8)],
      ["a sigPk that is not a point", withKey(notPoint)],
      ["a mixed-order sigPk", withKey(mixed)],
      ["by not a member", refD({ ...base, by: carol.uid })],
      ["e = 2^32 − 1", refD({ ...base, e: 0xffffffff })],
      ["e = 0 with a prev", refD({ ...base, e: 0 })],
      ["e > 0 without a prev", refD({ ...base, prev: fill(32, 0) })],
      ["ts above 2^53 − 1", refD({ ...base, ts: 2n ** 53n })],
      ["a name with 0xFF", refD({ ...base, name: Uint8Array.of(0x61, 0xff) })],
      ["a name with an overlong NUL", refD({ ...base, name: Uint8Array.of(0xc0, 0x80) })],
      ["a name with a surrogate", refD({ ...base, name: Uint8Array.of(0xed, 0xa0, 0x80) })],
      ["a truncated code point", refD({ ...base, name: Uint8Array.of(0x61, 0xe2, 0x82) })],
      ["65 code points", refD({ ...base, name: s2b("a".repeat(65)) })],
      ["65 four-byte code points (260 bytes)", refD({ ...base, name: s2b("😀".repeat(65)) })],
      ["257 bytes", refD({ ...base, name: s2b("😀".repeat(64) + "a") })],
      ["a leading U+FEFF then 64 code points", refD({ ...base, name: s2b("﻿" + "a".repeat(64)) })],
      ["nlen past the end", refD({ ...base, nlen: 2 })],
      ["a trailing byte", cat(refD(base), be8(0))],
      ["a missing byte", refD(base).slice(0, -1)],
    ];
    for (const [what, b] of bads) expect([what, throwsError(() => P.parseD(b))]).toEqual([what, true]);
    // names: only valid UTF-8 of 1–64 code points, whatever validName says (no Unicode tables involved)
    const names: [string, string, boolean][] = [
      ["a control character", "a\u0007", false],
      ["U+202E inside", "ok‮evil", false],
      ["a leading @", "@alice", false],
      ["a fullwidth @ after a space", " ＠alice", false],
      ["only whitespace", "   ", false],
      ["U+0000", "\u0000", false],
      ["U+1FAE9 (unassigned in older Unicode tables)", "\u{1fae9}", true],
      ["a lone U+FEFF (one code point)", "﻿", true],
      ["a leading U+FEFF then 63 code points", "﻿" + "b".repeat(63), true],
      ["64 four-byte code points (256 bytes)", "😀".repeat(64), true],
    ];
    for (const [what, name, displayable] of names) {
      const D = P.parseD(refD({ ...base, name: s2b(name) }));
      expect([what, D.name]).toEqual([what, name]);
      expect(toHex(P.encodeD(D))).toBe(toHex(D.bytes));
      if (!displayable) expect([what, P.validName(name)]).toEqual([what, false]);
    }
    expect([..."﻿"].length).toBe(1);
    // encodeD applies the same rules (no validName); it refuses "" (no name is null), lone surrogates, 65 code points
    expect(P.parseD(P.encodeD({ ...D0f, name: "﻿a" })).name).toBe("﻿a");
    expect(P.parseD(P.encodeD({ ...D0f, name: "@bob" })).name).toBe("@bob");
    for (const name of ["", "\ud800", "a".repeat(65), "﻿" + "a".repeat(64)])
      expect(() => P.encodeD({ ...D0f, name })).toThrow(P.CodecError);
    expect(() => P.encodeD({ ...D0f, members: [mem(alice), { ...mem(bob), kh: fill(31, 0) }] })).toThrow(P.CodecError);
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

  it("descriptor keys: rows, dsig and bundles use keys from D or passed in, never a directory", () => {
    // verifyRow(sigPk, sig, conv, e, E, label, M), verifyD(D, kc, dsig), buildBundle(spec): no directory argument
    expect(P.verifyRow.length).toBe(7);
    expect(P.verifyD.length).toBe(3);
    expect(P.buildBundle.length).toBe(1);
    // D lists bob's uid with erin's key (not the key of bob's directory bundle)
    const Dx = P.parseD(
      P.encodeD({ ...D0f, by: bob.uid, members: [mem(alice), { ...mem(erin), uid: bob.uid }] }),
    );
    expect(P.verifyD(Dx, keys0.kc, P.signD(Dx.bytes, keys0.kc, erin.id.sigSk))).toBe(true);
    expect(P.verifyD(Dx, keys0.kc, P.signD(Dx.bytes, keys0.kc, bob.id.sigSk))).toBe(false);
    const ctx: P.RowContext = { keys: keys0, conv, e: 0, members: Dx.members };
    const byListedKey = P.buildRow(ctx0(erin.id.sigSk), E, { ...hdr(), type: P.MT.TEXT, text: "x" });
    expect(P.acceptRow(ctx, E, byListedKey.label, byListedKey.body).ok).toBe(true);
    const byBundleKey = P.buildRow(ctx0(bob.id.sigSk), E, { ...hdr(), type: P.MT.TEXT, text: "x" });
    expect(P.acceptRow(ctx, E, byBundleKey.label, byBundleKey.body)).toEqual({ ok: false, why: "sig" });
    // a commit copies continuing members' kemPk from pks of the previous bundle: e = 0 → e = 1 without any lookup
    const b0 = P.buildBundle({ conv, e: 0, D: D0.bytes, dsig: dsig0, EK: EK0, pks: kem0, prevMembers: [], rm: 0 });
    const pks0 = P.openPks(keys0.dk, conv, 0, b0.blob);
    const fromPks = [P.pksAt(pks0, 0), P.pksAt(pks0, 2), dave.id.kemPk]; // alice and carol continue, dave is added
    const b1 = P.buildBundle({ ...spec1, pks: fromPks });
    expect(toHex(P.openEntry(alice.id.kemSk, conv, 1, 0, b1.blob)!)).toBe(toHex(EK1));
    expect(toHex(P.openEntry(carol.id.kemSk, conv, 1, 2, b1.blob)!)).toBe(toHex(EK1));
    expect(toHex(P.openPks(keys1.dk, conv, 1, b1.blob))).toBe(toHex(pks1));
  });

  it("splitDesc bounds D ‖ dsig to [224, 2960]", () => {
    const desc = cat(D0.bytes, dsig0);
    expect(P.splitDesc(desc)).toEqual({ D: D0.bytes, dsig: dsig0 });
    expect(P.splitDesc(fill(224, 0)).D.length).toBe(160);
    expect(P.splitDesc(fill(2960, 0)).D.length).toBe(2896);
    expect(() => P.splitDesc(fill(223, 0))).toThrow(P.CodecError);
    expect(() => P.splitDesc(fill(2961, 0))).toThrow(P.CodecError);
  });
});

describe("rm bits and the D′ checks (§6.2, §6.6 step 4)", () => {
  const claim = { from: 0, hD: D1.hash, rm: 2 };
  const next = { D: D1.bytes, dsig: dsig1, kc: keys1.kc, pks: pks1, EK: EK1 };
  const bundle = P.parseBundleBlob(built1.blob);
  /** a variant D′ (signed by alice with kc_1) and a claim that commits to it */
  const variant = (f: Partial<P.DescriptorFields>, signer = alice) => {
    const D = P.encodeD({ ...D1f, ...f });
    return [{ ...next, D, dsig: P.signD(D, keys1.kc, signer.id.sigSk) }, { ...claim, hD: sha(D) }] as const;
  };
  /** the bundle with entry i replaced */
  const withEntry = (i: number, entry: B): P.BundleBlob => ({
    ...bundle,
    entries: bundle.entries.map((x, k) => (k === i ? entry : x)),
  });
  /** an X-Wing key with an ML-KEM coefficient ≥ q: no encapsulation succeeds */
  const badKem = patch(kem1[2], 0, fill(2, 0xff));

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
    expect(P.dPrimeChecks(next, D0, claim, bundle)).toEqual({ ok: true, D: D1 });
    // the D′ checks never consult validName: a D′ named with characters it rejects is accepted
    const [n, c] = variant({ name: "\u202eevil" });
    expect(P.validName("\u202eevil")).toBe(false);
    expect(P.dPrimeChecks(n, D0, c, bundle)).toMatchObject({ ok: true, D: { name: "\u202eevil" } });
  });

  it("rejects each failure separately", () => {
    type Next = { D: B; dsig: B; kc: B; pks: B; EK: B };
    type Case = [P.DPrimeCheck, Next, { from: number; hD: B; rm: number }, P.BundleBlob?];
    const nine = [alice, carol].map(mem).concat(Array.from({ length: 7 }, (_, k) => sigMember(k + 1)));
    const [mNext, mClaim] = variant({ members: [mem(alice), mem(carol), { ...mem(dave), kh: refKh(badKem) }] });
    const ctx2 = refRekeyCtx(conv, 1, 2);
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
      ["sigPk", ...variant({ members: [mem(alice), { ...mem(carol), sigPk: erin.id.sigPk }, mem(dave)] })],
      ["kh", ...variant({ members: [mem(alice), { ...mem(carol), kh: refKh(erin.id.kemPk) }, mem(dave)] })],
      ["size", ...variant({ members: nine })], // |D′| = 9 > B = 8
      ["pks", { ...next, pks: pks1.subarray(0, 7 * 1216) }, claim], // not B·1216 bytes
      ["pks", { ...next, pks: cat(pks1, new Uint8Array(1216)) }, claim],
      ["pks", { ...next, pks: patch(pks1, 3 * 1216 + 5, be8(1)) }, claim], // non-zero after slot |D′| − 1
      ["pks", { ...next, pks: patch(pks1, 8 * 1216 - 1, be8(1)) }, claim],
      ["pks", { ...next, pks: refPks([kem1[0], kem1[1], erin.id.kemPk], 8) }, claim], // dave's slot ≠ his kh
      ["pks", { ...next, pks: refPks([kem1[0], erin.id.kemPk, kem1[2]], 8) }, claim], // carol's slot ≠ her kh
      ["pks", { ...next, pks: refPks([kem1[0], kem1[2], kem1[1]], 8) }, claim], // slots swapped
      ["pks", { ...mNext, pks: refPks([kem1[0], kem1[1], badKem], 8) }, mClaim], // kh binds a malformed key
      ["entry", next, claim, withEntry(2, P.dummySeal(P.REKEY_LABEL, ctx2, 32))], // a dummy for kept carol
      ["entry", next, claim, withEntry(2, P.seal(carol.id.kemPk, P.REKEY_LABEL, ctx2, EK1))], // fresh randomness
      ["entry", next, claim, withEntry(2, P.sealDet(erin.id.kemPk, conv, 1, 2, EK1))], // sealDet to another key
      ["entry", next, claim, withEntry(2, P.sealDet(carol.id.kemPk, conv, 1, 0, EK1))], // another index's derivation
      ["entry", next, claim, withEntry(0, bundle.entries[2])], // the checker's own entry is checked too
      ["entry", { ...next, EK: EK0 }, claim], // the entries do not derive from this EK′
    ];
    for (const [want, n, c, b] of fails)
      expect([want, P.dPrimeChecks(n, D0, c, b ?? bundle)]).toEqual([want, { ok: false, failed: want }]);
    // a fresh-randomness seal to carol opens for her to EK′, and still fails the check
    expect(toHex(P.open(carol.id.kemSk, P.REKEY_LABEL, ctx2, P.seal(carol.id.kemPk, P.REKEY_LABEL, ctx2, EK1)))).toBe(
      toHex(EK1),
    );
  });

  it("a kept member's malformed key fails its sealDet recomputation as 'pks' (the encapsulation it performs)", () => {
    const badKh = refKh(badKem);
    const De = P.parseD(P.encodeD({ ...D0f, members: [mem(alice), mem(bob), { ...mem(carol), kh: badKh }] }));
    const D = P.encodeD({ ...D1f, prev: De.hash, members: [mem(alice), { ...mem(carol), kh: badKh }, mem(dave)] });
    const n = { ...next, D, dsig: P.signD(D, keys1.kc, alice.id.sigSk), pks: refPks([kem1[0], badKem, kem1[2]], 8) };
    expect(P.dPrimeChecks(n, De, { ...claim, hD: sha(D) }, bundle)).toEqual({ ok: false, failed: "pks" });
    expect(P.checkPks(P.parseD(D), n.pks, 8)).toBe("pks"); // without the skip, checkPks finds it itself
    expect(P.checkPks(P.parseD(D), n.pks, 8, (j) => j === 1)).toBeNull();
  });

  it("checkPks: |D| ≤ B, B·1216 bytes, a zero tail, every slot hashing to its kh and usable (§6.6, §6.7)", () => {
    expect(P.checkPks(D1, pks1, 8)).toBeNull();
    expect(P.checkPks(D1, refPks(kem1, 32), 32)).toBeNull();
    expect(P.checkPks({ members: Array.from({ length: 9 }, (_, k) => sigMember(k + 1)) }, refPks([], 8), 8)).toBe(
      "size",
    );
    expect(P.checkPks(D1, refPks(kem1, 32), 8)).toBe("pks");
    expect(P.checkPks(D1, pks1, 32)).toBe("pks");
    expect(P.checkPks(D1, patch(pks1, 3 * 1216, be8(1)), 8)).toBe("pks");
    expect(P.checkPks(D1, refPks([kem1[0], kem1[1], erin.id.kemPk], 8), 8)).toBe("pks");
    const Dm = { members: [...D1.members.slice(0, 2), { ...D1.members[2], kh: refKh(badKem) }] };
    expect(P.checkPks(Dm, refPks([kem1[0], kem1[1], badKem], 8), 8)).toBe("pks");
    expect(P.checkPks(Dm, refPks([kem1[0], kem1[1], badKem], 8), 8, (j) => j === 2)).toBeNull();
    expect([0, 1, 2].map((j) => toHex(P.pksAt(pks1, j)))).toEqual(kem1.map(toHex));
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

describe("inbox invites (§5.3)", () => {
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

// ───────────────────────── SGB2 bundles (§5.4) ─────────────────────────

describe("SGB2 key bundles (§5.4)", () => {
  const everyone = [alice, bob, carol, dave, erin].map((p) => p.id.kemSk);
  const stranger = P.kemKeygen(fill(32, 0xee)).sk;
  /** an X-Wing key with an ML-KEM coefficient ≥ q: no encapsulation succeeds */
  const badKem = patch(kem1[2], 0, fill(2, 0xff));
  const nine = Array.from({ length: 9 }, (_, k) => sigMember(k + 1));
  const D9 = P.encodeD({ conv, e: 0, prev: P.ZERO32, by: nine[0].uid, ts: TS, members: nine, name: null });
  const kem9 = Array.from({ length: 9 }, (_, k) => fill(1216, k + 1)); // e = 0: no sealDet, so any 1216 bytes
  const spec9: P.BundleSpec = { conv, e: 0, D: D9, dsig: fill(64, 0), EK: EK0, pks: kem9, prevMembers: [], rm: 0 };

  it("has the §3.2 sizes and offsets: descCt 4136 B at 16, pkCt B·1216 + 40 B at 4152, entries after", () => {
    expect(built1.B).toBe(8);
    expect(built1.size).toBe(23456);
    expect(built1.blob.length).toBe(23456);
    expect([...P.SGB2_SIZES]).toEqual([23456, 81248]);
    expect(toHex(built1.blob.subarray(0, 16))).toBe(toHex(cat(s2b("SGB2"), be8(1), be8(8), fill(10, 0))));
    expect(toHex(built1.id)).toBe(toHex(sha(built1.blob)));
    const b = P.parseBundleBlob(built1.blob);
    expect([b.B, b.descCt.length, b.pkCt.length, b.entries.length]).toEqual([8, 4136, 9768, 8]);
    expect(toHex(b.descCt)).toBe(toHex(built1.blob.subarray(16, 4152)));
    expect(toHex(b.pkCt)).toBe(toHex(built1.blob.subarray(4152, 13920)));
    expect(entryAt(8, 0)).toBe(13920);
    b.entries.forEach((x, i) => expect(toHex(x)).toBe(toHex(built1.blob.subarray(entryAt(8, i), entryAt(8, i + 1)))));
    const b32 = P.buildBundle(spec9);
    expect([b32.B, b32.size, b32.blob.length, b32.blob[5]]).toEqual([32, 81248, 81248, 32]);
    const p32 = P.parseBundleBlob(b32.blob);
    expect([p32.descCt.length, p32.pkCt.length, p32.entries.length]).toEqual([4136, 38952, 32]);
    expect([entryAt(32, 0), entryAt(32, 32)]).toEqual([43104, 81248]);
    expect(P.buildBundle({ ...spec1, B: 32 }).size).toBe(81248);
    expect(P.sgb2B(8, 8)).toBe(8);
    expect(P.sgb2B(9, 2)).toBe(32);
    expect(P.sgb2B(2, 9)).toBe(32);
    expect(P.sgb2B(0, 8)).toBe(8);
  });

  it("buildBundle refuses inconsistent input", () => {
    const bads: [string, () => unknown][] = [
      ["B < |D_e|", () => P.buildBundle({ ...spec9, B: 8 })],
      ["a kemPk missing", () => P.buildBundle({ ...spec1, pks: kem1.slice(0, 2) })],
      ["a kemPk of 1215 bytes", () => P.buildBundle({ ...spec1, pks: [kem1[0], kem1[1], kem1[2].subarray(1)] })],
      ["e = 0 with previous members", () => P.buildBundle({ ...spec1, e: 0 })],
      ["e = 0 with an rm bit", () => P.buildBundle({ ...spec9, rm: 1 })],
      ["an rm bit at or above |D_{e−1}|", () => P.buildBundle({ ...spec1, rm: 2 + 8 })],
      ["a kept member that D_e does not list", () => P.buildBundle({ ...spec1, rm: 0 })],
      ["a short dsig", () => P.buildBundle({ ...spec1, dsig: dsig1.subarray(1) })],
      ["a short EK", () => P.buildBundle({ ...spec1, EK: EK1.subarray(1) })],
      ["a truncated descriptor", () => P.buildBundle({ ...spec1, D: D1.bytes.subarray(0, 300) })],
      ["a kept member's unusable kemPk", () => P.buildBundle({ ...spec1, pks: [badKem, kem1[1], kem1[2]] })],
    ];
    for (const [what, f] of bads) expect([what, throwsError(f)]).toEqual([what, true]);
  });

  it("matches the reference construction byte for byte: descCt, pkCt, sealDet entries and dummies", () => {
    for (const B of [8, 32] as const) {
      const calls: B[] = [];
      const b = withRng(recording(detRng(`segv.sh/v2/test/sgb2/${B}`), calls), () => P.buildBundle({ ...spec1, B }));
      const dummies = Array.from({ length: B }, (_, i) => i).filter((i) => i !== 0 && i !== 2);
      // the descCt nonce, the pkCt nonce, then per dummy entry (index order): the discarded key's seed, the sealed
      // 32-byte value, the encapsulation randomness and the nonce; the two kept entries draw nothing
      expect(calls.map((c) => c.length)).toEqual([24, 24, ...dummies.flatMap(() => [32, 32, 64, 24])]);
      let k = 2;
      const entries = Array.from({ length: B }, (_, i) => {
        if (i === 0) return refSealDet(alice.id.kemPk, conv, 1, 0, EK1);
        if (i === 2) return refSealDet(carol.id.kemPk, conv, 1, 2, EK1);
        const [seed, value, kemRand, nonce] = calls.slice(k, k + 4);
        k += 4;
        const pk = xwing.keygen(seed).publicKey;
        return refSealWith(pk, "segv.sh/v2/rekey", refRekeyCtx(conv, 1, i), value, kemRand, nonce);
      });
      const desc = cat(D1.bytes, dsig1);
      const ref = refBlob({ B, conv, e: 1, EK: EK1, desc, pks: refPks(kem1, B), entries }, [calls[0], calls[1]]);
      expect(b.size).toBe(ref.length);
      expect(Buffer.from(b.blob).equals(Buffer.from(ref))).toBe(true);
      expect(toHex(b.id)).toBe(toHex(sha(ref)));
    }
  });

  it("sealDet: a node:crypto + noble re-implementation gives the same 1192 bytes, and open() opens it", () => {
    const cases: [Person, number][] = [
      [alice, 0],
      [carol, 2],
      [dave, 31],
      [bob, 0xffff],
    ];
    for (const [p, i] of cases) {
      const entry = withRng(noRng, () => P.sealDet(p.id.kemPk, conv, 1, i, EK1)); // no RNG involved
      expect(entry.length).toBe(1192);
      expect(toHex(entry)).toBe(toHex(refSealDet(p.id.kemPk, conv, 1, i, EK1)));
      expect(toHex(P.open(p.id.kemSk, P.REKEY_LABEL, P.rekeyCtx(conv, 1, i), entry))).toBe(toHex(EK1));
      expect(P.tryOpen(stranger, P.REKEY_LABEL, P.rekeyCtx(conv, 1, i), entry)).toBeNull();
      // ρ[32..64] is the X25519 ephemeral secret (its public key, by node:crypto, ends kct), ρ[64..88] the nonce,
      // and ρ[0..32] the ML-KEM coins (the ML-KEM part of kct does not depend on the X25519 bytes)
      const rho = refRho(EK1, conv, 1, i);
      expect(toHex(entry.subarray(1088, 1120))).toBe(toHex(x25519Pub(rho.slice(32, 64))));
      expect(toHex(entry.subarray(1120, 1144))).toBe(toHex(rho.slice(64, 88)));
      const mlkem = xwing.encapsulate(p.id.kemPk, cat(rho.slice(0, 32), fill(32, 7))).cipherText.subarray(0, 1088);
      expect(toHex(entry.subarray(0, 1088))).toBe(toHex(mlkem));
    }
    expect(toHex(P.rekeyRoot(EK1, conv, 1))).toBe(toHex(refRr(EK1, conv, 1)));
    // every input changes the entry
    const base = toHex(P.sealDet(alice.id.kemPk, conv, 1, 0, EK1));
    for (const other of [
      P.sealDet(bob.id.kemPk, conv, 1, 0, EK1),
      P.sealDet(alice.id.kemPk, flip(conv, 0), 1, 0, EK1),
      P.sealDet(alice.id.kemPk, conv, 2, 0, EK1),
      P.sealDet(alice.id.kemPk, conv, 1, 1, EK1),
      P.sealDet(alice.id.kemPk, conv, 1, 0, EK0),
    ])
      expect(toHex(other)).not.toBe(base);
    // refusals: a key that cannot be encapsulated to, bad lengths, i outside u16
    for (const f of [
      () => P.sealDet(badKem, conv, 1, 0, EK1),
      () => P.sealDet(alice.id.kemPk.subarray(1), conv, 1, 0, EK1),
      () => P.sealDet(alice.id.kemPk, conv.subarray(1), 1, 0, EK1),
      () => P.sealDet(alice.id.kemPk, conv, 1, 0x10000, EK1),
      () => P.sealDet(alice.id.kemPk, conv, 1, 0, EK1.subarray(1)),
    ])
      expect(throwsError(f)).toBe(true);
  });

  it("kept entries open EK′ for their owner and equal others' recomputation; the rest open for nobody", () => {
    expect(toHex(P.openEntry(alice.id.kemSk, conv, 1, 0, built1.blob)!)).toBe(toHex(EK1));
    expect(toHex(P.openEntry(carol.id.kemSk, conv, 1, 2, built1.blob)!)).toBe(toHex(EK1));
    const b = P.parseBundleBlob(built1.blob);
    // carol, holding EK′ and pks′, recomputes alice's entry and her own byte for byte
    const pks = P.openPks(keys1.dk, conv, 1, b);
    expect(toHex(P.sealDet(P.pksAt(pks, 0), conv, 1, 0, EK1))).toBe(toHex(b.entries[0]));
    expect(toHex(P.sealDet(P.pksAt(pks, 1), conv, 1, 2, EK1))).toBe(toHex(b.entries[2]));
    // bob's entry (rm bit 1) and the padding entries 3..7 open for nobody, bob included
    for (let i = 0; i < 8; i++)
      for (const [k, sk] of everyone.entries()) {
        if ((i === 0 && k === 0) || (i === 2 && k === 2)) continue;
        expect([i, k, P.openEntry(sk, conv, 1, i, b)]).toEqual([i, k, null]);
      }
    for (let i = 0; i < 8; i++) expect(P.openEntry(stranger, conv, 1, i, built1.blob)).toBeNull();
    expect(P.openEntry(alice.id.kemSk, conv, 2, 0, built1.blob)).toBeNull(); // wrong e
    expect(P.openEntry(alice.id.kemSk, flip(conv, 0), 1, 0, built1.blob)).toBeNull(); // wrong conv
    expect(P.openEntry(alice.id.kemSk, conv, 1, 8, built1.blob)).toBeNull(); // i ≥ B
    expect(P.openEntry(alice.id.kemSk, conv, 1, -1, built1.blob)).toBeNull();
    expect(P.openEntry(alice.id.kemSk, conv, 1, 0, built1.blob.slice(1))).toBeNull(); // malformed blob
    // a rebuild has fresh dummies but the same derived entries
    const again = P.parseBundleBlob(P.buildBundle(spec1).blob);
    expect(toHex(again.entries[0])).toBe(toHex(b.entries[0]));
    expect(toHex(again.entries[2])).toBe(toHex(b.entries[2]));
    for (const i of [1, 3, 7]) expect(toHex(again.entries[i])).not.toBe(toHex(b.entries[i]));
  });

  it("epoch 0: every entry is a dummy; descCt and pkCt carry D_0 and pks_0", () => {
    const b = P.buildBundle({ conv, e: 0, D: D0.bytes, dsig: dsig0, EK: EK0, pks: kem0, prevMembers: [], rm: 0 });
    expect(b.size).toBe(23456);
    for (let i = 0; i < 8; i++) for (const sk of everyone) expect(P.openEntry(sk, conv, 0, i, b.blob)).toBeNull();
    expect(P.openDesc(keys0.dk, conv, 0, b.blob)).toEqual({ D: D0.bytes, dsig: dsig0 });
    expect(toHex(P.openPks(keys0.dk, conv, 0, b.blob))).toBe(toHex(refPks(kem0, 8)));
  });

  it("openDesc / openPks return D ‖ dsig and pks, and throw when corrupted or under a wrong EK′", () => {
    expect(P.openDesc(keys1.dk, conv, 1, built1.blob)).toEqual({ D: D1.bytes, dsig: dsig1 });
    expect(toHex(P.openPks(keys1.dk, conv, 1, built1.blob))).toBe(toHex(pks1));
    const rk = refEpochKeys(EK1, conv, 1);
    const descAad = refEnc("segv.sh/v2/desc", conv, be32(1));
    const pksAad = refEnc("segv.sh/v2/pks", conv, be32(1));
    const descPt = xOpen(rk.dk, built1.blob.subarray(16, 4152), descAad);
    expect(descPt.length).toBe(4096);
    expect(toHex(refUnpad(descPt))).toBe(toHex(cat(D1.bytes, dsig1)));
    expect(toHex(xOpen(rk.dk, built1.blob.subarray(4152, 13920), pksAad))).toBe(toHex(pks1));
    // a wrong EK′ (another dk), or another e or conv in the AAD
    for (const f of [
      () => P.openDesc(keys0.dk, conv, 1, built1.blob),
      () => P.openDesc(keys1.dk, conv, 2, built1.blob),
      () => P.openDesc(keys1.dk, flip(conv, 0), 1, built1.blob),
      () => P.openPks(keys0.dk, conv, 1, built1.blob),
      () => P.openPks(keys1.dk, conv, 2, built1.blob),
      () => P.openPks(keys1.dk, flip(conv, 0), 1, built1.blob),
    ])
      expect(throwsError(f)).toBe(true);
    // a flipped byte in descCt (nonce, ciphertext, tag) or pkCt
    for (const at of [16, 39, 40, 2000, 4151])
      expect(() => P.openDesc(keys1.dk, conv, 1, flip(built1.blob, at))).toThrow();
    for (const at of [4152, 4176, 9000, 13919])
      expect(() => P.openPks(keys1.dk, conv, 1, flip(built1.blob, at))).toThrow();
    // descCt and pkCt do not open under each other's AAD
    expect(() => xOpen(rk.dk, built1.blob.subarray(16, 4152), pksAad)).toThrow();
    // a descCt that decrypts to something other than D ‖ dsig padded: no marker, or a length outside [224, 2960]
    const reDesc = (pt: B) => patch(built1.blob, 16, xSeal(rk.dk, seqBytes(24, 1), descAad, pt));
    expect(() => P.openDesc(keys1.dk, conv, 1, reDesc(fill(4096, 0)))).toThrow();
    expect(() => P.openDesc(keys1.dk, conv, 1, reDesc(refPad(fill(223, 1), [4096])))).toThrow();
    expect(() => P.openDesc(keys1.dk, conv, 1, reDesc(refPad(fill(2961, 1), [4096])))).toThrow();
    expect(P.openDesc(keys1.dk, conv, 1, reDesc(refPad(fill(224, 1), [4096]))).D.length).toBe(160);
  });

  it("parseBundleBlob is strict", () => {
    const set = (i: number, v: number) => patch(built1.blob, i, be8(v));
    expect(P.parseBundleBlob(built1.blob).entries.length).toBe(8);
    for (const bad of [
      built1.blob.slice(0, 23455),
      cat(built1.blob, be8(0)),
      set(0, 0x54),
      set(3, 0x33),
      set(4, 2),
      set(5, 32),
      set(5, 7),
      set(6, 1),
      set(15, 1),
      new Uint8Array(11640), // the sizes before pkCt
      new Uint8Array(40248),
    ])
      expect(() => P.parseBundleBlob(bad)).toThrow(P.CodecError);
  });

  it("bundleShapeValid reports each failure of §6.4 (h) separately: size, length, hash", () => {
    expect(P.bundleShapeValid(built1.blob, 23456, built1.id, 3)).toBeNull();
    expect(P.bundleShapeValid(built1.blob, 23456, built1.id, 8)).toBeNull();
    expect(P.bundleShapeValid(built1.blob, 23457, built1.id, 3)).toBe("size");
    expect(P.bundleShapeValid(built1.blob, 11640, built1.id, 3)).toBe("size"); // the size before pkCt
    expect(P.bundleShapeValid(built1.blob, 81248, built1.id, 3)).toBe("length");
    expect(P.bundleShapeValid(built1.blob, 23456, flip(built1.id, 0), 3)).toBe("hash");
  });

  it("bundleShapeValid: magic, version, B, the zero bytes and B < m", () => {
    const check = (i: number, v: number) => {
      const c = patch(built1.blob, i, be8(v));
      return P.bundleShapeValid(c, 23456, sha(c), 3);
    };
    expect(check(0, 0x58)).toBe("magic");
    expect(check(4, 0)).toBe("ver");
    expect(check(5, 32)).toBe("B");
    expect(check(5, 16)).toBe("B");
    expect(check(9, 1)).toBe("header");
    expect(P.bundleShapeValid(built1.blob, 23456, built1.id, 9)).toBe("m");
    expect(P.bundleShapeValid(built1.blob, 23456, built1.id, 32)).toBe("m");
  });
});

describe("processing a winning claim and accepting a join (§6.6 steps 2–4, §6.7 steps 1–2)", () => {
  const claim: P.Claim = { ...claim3, bundleId: built1.id, bundleSize: built1.size };
  const run = (i: number, sk: B, c = claim, blob: B = built1.blob) =>
    P.processClaim({ kemSk: sk, De: D0, i, from: 0, claim: c, blob });
  const stranger = () => P.kemKeygen(fill(32, 0xee)).sk;
  const rk1 = refEpochKeys(EK1, conv, 1);
  /** built1 with descCt or pkCt re-sealed under dk_1 around another plaintext */
  const reDesc = (pt: B) =>
    patch(built1.blob, 16, xSeal(rk1.dk, seqBytes(24, 1), refEnc("segv.sh/v2/desc", conv, be32(1)), pt));
  const rePks = (pt: B, e = 1) =>
    patch(built1.blob, PKCT_AT, xSeal(rk1.dk, seqBytes(24, 2), refEnc("segv.sh/v2/pks", conv, be32(e)), pt));
  const ctx2 = refRekeyCtx(conv, 1, 2);
  const badKem = patch(kem1[2], 0, fill(2, 0xff));

  it("accept: EK′, D′, dsig′, the keys of e+1 and pks′", () => {
    const a = run(0, alice.id.kemSk);
    expect(a).toMatchObject({ kind: "accept", EK: EK1, D: D1, dsig: dsig1, pks: pks1 });
    if (a.kind === "accept") expect(a.keys).toEqual(keys1);
    expect(run(2, carol.id.kemSk)).toMatchObject({ kind: "accept", EK: EK1, D: D1, pks: pks1 });
    const parsed = P.parseBundleBlob(built1.blob);
    expect(P.processClaim({ kemSk: alice.id.kemSk, De: D0, i: 0, from: 0, claim, blob: parsed })).toMatchObject({
      kind: "accept",
    });
  });

  it("removed: an rm bit, whatever the entry holds", () => {
    expect(run(1, bob.id.kemSk)).toEqual({ kind: "removed" });
    expect(run(1, stranger())).toEqual({ kind: "removed" });
    expect(run(1, bob.id.kemSk, claim, built1.blob.slice(1))).toEqual({ kind: "removed" });
  });

  it("nokey: the own entry does not open, or its EK does not match ekc (frozen)", () => {
    const dummy = patch(built1.blob, entryAt(8, 2), P.dummySeal(P.REKEY_LABEL, ctx2, 32));
    expect(run(2, carol.id.kemSk, claim, dummy)).toEqual({ kind: "nokey" });
    expect(run(2, carol.id.kemSk, { ...claim, ekc: fill(32, 1) })).toEqual({ kind: "nokey" });
    expect(run(2, alice.id.kemSk)).toEqual({ kind: "nokey" }); // not her entry
    const otherEK = patch(built1.blob, entryAt(8, 2), P.seal(carol.id.kemPk, P.REKEY_LABEL, ctx2, EK0));
    expect(run(2, carol.id.kemSk, claim, otherEK)).toEqual({ kind: "nokey" });
    expect(run(0, alice.id.kemSk, claim, built1.blob.slice(1))).toEqual({ kind: "nokey" }); // not a bundle
  });

  it("invalid: a corrupted descCt or pkCt never throws, and each failing D′ check freezes", () => {
    const no = (failed: P.DPrimeCheck) => ({ kind: "invalid", failed });
    expect(run(0, alice.id.kemSk, claim, flip(built1.blob, 2000))).toEqual(no("desc"));
    expect(run(0, alice.id.kemSk, claim, flip(built1.blob, 9000))).toEqual(no("pks"));
    expect(run(0, alice.id.kemSk, claim, reDesc(fill(4096, 0)))).toEqual(no("desc")); // no padding marker
    expect(run(0, alice.id.kemSk, claim, reDesc(refPad(fill(100, 1), [4096])))).toEqual(no("desc")); // < 224 bytes
    expect(run(0, alice.id.kemSk, claim, rePks(pks1, 2))).toEqual(no("pks")); // pkCt under another epoch's AAD
    const junk = fill(300, 1);
    expect(run(0, alice.id.kemSk, claim, reDesc(refPad(junk, [4096])))).toEqual(no("hD"));
    expect(run(0, alice.id.kemSk, { ...claim, hD: sha(junk.subarray(0, 236)) }, reDesc(refPad(junk, [4096])))).toEqual(
      no("desc"),
    );
    const Dbad = P.encodeD({ ...D1f, prev: fill(32, 9) });
    const badB = P.buildBundle({ ...spec1, D: Dbad, dsig: P.signD(Dbad, keys1.kc, alice.id.sigSk) });
    expect(run(0, alice.id.kemSk, { ...claim, hD: sha(Dbad) }, badB.blob)).toEqual(no("prev"));
    expect(run(0, alice.id.kemSk, claim, rePks(patch(pks1, 5000, be8(1))))).toEqual(no("pks")); // non-zero tail
    expect(run(0, alice.id.kemSk, claim, rePks(refPks([kem1[0], kem1[1], erin.id.kemPk], 8)))).toEqual(no("pks"));
  });

  it("a wrong kept entry freezes every member who obtains EK′, the checker's own included (§5.4)", () => {
    const entryFails: P.ClaimOutcome = { kind: "invalid", failed: "entry" };
    const wrong: [string, B, P.ClaimOutcome][] = [
      ["a dummy", P.dummySeal(P.REKEY_LABEL, ctx2, 32), { kind: "nokey" }],
      ["a fresh-randomness seal", P.seal(carol.id.kemPk, P.REKEY_LABEL, ctx2, EK1), entryFails],
      ["a sealDet to another key", P.sealDet(erin.id.kemPk, conv, 1, 2, EK1), { kind: "nokey" }],
    ];
    for (const [what, entry, owner] of wrong) {
      const blob = patch(built1.blob, entryAt(8, 2), entry);
      expect([what, run(0, alice.id.kemSk, claim, blob)]).toEqual([what, entryFails]);
      expect([what, run(2, carol.id.kemSk, claim, blob)]).toEqual([what, owner]);
    }
  });

  const J: P.Join = { conv, e: 1, EK: EK1, bundleId: built1.id, bundleSize: built1.size };

  it("checkJoinBundle (§6.7 steps 1–2) accepts and returns D, dsig, the keys and pks", () => {
    const r = P.checkJoinBundle(J, built1.blob, mem(dave));
    expect(r).toMatchObject({ ok: true, D: D1, dsig: dsig1, pks: pks1 });
    if (r.ok) expect(r.keys).toEqual(keys1);
    expect(P.checkJoinBundle(J, built1.blob, mem(alice)).ok).toBe(true);
  });

  it("checkJoinBundle rejects each failure", () => {
    const forBlob = (blob: B): [P.Join, B] => [{ ...J, bundleId: sha(blob), bundleSize: blob.length }, blob];
    const variant = (f: Partial<P.DescriptorFields>, signer = alice, pks = kem1): [P.Join, B] => {
      const D = P.encodeD({ ...D1f, ...f });
      return forBlob(P.buildBundle({ ...spec1, D, dsig: P.signD(D, keys1.kc, signer.id.sigSk), pks }).blob);
    };
    // |D| = 9 > B = 8, assembled by hand (buildBundle refuses it), with dave listed
    const six = Array.from({ length: 6 }, (_, k) => sigMember(k + 1));
    const D9 = P.encodeD({ ...D1f, members: [...D1f.members, ...six] });
    const desc9 = cat(D9, P.signD(D9, keys1.kc, alice.id.sigSk));
    const entries = P.parseBundleBlob(built1.blob).entries;
    const big = refBlob({ B: 8, conv, e: 1, EK: EK1, desc: desc9, pks: pks1, entries });
    const malformed = variant({ members: [mem(alice), mem(carol), { ...mem(dave), kh: refKh(badKem) }] }, alice, [
      kem1[0],
      kem1[1],
      badKem,
    ]);
    const cases: [P.JoinCheckFailure, P.Join, B, P.Member?][] = [
      ["hash", { ...J, bundleId: fill(32, 0) }, built1.blob],
      ["size", { ...J, bundleSize: 81248 }, built1.blob],
      ["size", ...forBlob(built1.blob.slice(1))],
      ["header", ...forBlob(patch(built1.blob, 10, be8(1)))], // a non-zero reserved byte
      ["header", ...forBlob(patch(built1.blob, 0, be8(0x58)))],
      ["e", { ...J, e: 0xffffffff }, built1.blob],
      ["desc", { ...J, EK: EK0 }, built1.blob], // descCt does not open under dk_e(EK)
      ["desc", ...forBlob(flip(built1.blob, 2000))],
      ["desc", ...forBlob(reDesc(refPad(fill(300, 1), [4096])))], // D does not parse
      ["pks", ...forBlob(flip(built1.blob, 9000))], // a corrupted pkCt
      ["pks", ...forBlob(rePks(pks1, 2))],
      ["pks", ...forBlob(rePks(patch(pks1, 5000, be8(1))))], // a non-zero tail
      ["pks", ...forBlob(rePks(refPks([kem1[0], kem1[1], erin.id.kemPk], 8)))], // dave's slot is not his kh
      ["pks", ...forBlob(big)], // |D| > B
      ["pks", ...malformed], // kh binds a key that cannot be encapsulated to
      ["conv", ...variant({ conv: fill(16, 1) })],
      ["e", ...variant({ e: 2 })],
      ["dsig", ...variant({}, carol)],
      ["self", J, built1.blob, mem(bob)], // not listed
      ["self", J, built1.blob, { ...mem(dave), sigPk: erin.id.sigPk }], // listed with a foreign sigPk
      ["self", J, built1.blob, { ...mem(dave), kh: refKh(erin.id.kemPk) }], // own sigPk, a foreign kh
    ];
    for (const [want, j, blob, self] of cases)
      expect([want, P.checkJoinBundle(j, blob, self ?? mem(dave))]).toEqual([want, { ok: false, failed: want }]);
  });
});

// ───────────────────────── claims (§6.2, §6.4, §6.8) ─────────────────────────

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

  it("claimShapeValid rejects each failure of (a), (b), (e), (f), the size set of (g) and B ≥ m of (h)", () => {
    const ok = { ...claim3, bundleSize: 23456 }; // m = 3, from 0, rm = bit 1, cuts in [2, 3]
    expect(P.claimShapeValid(ok, 3, 0, 2, 3)).toBeNull();
    expect(P.claimShapeValid(ok, 4, 0, 2, 3)).toBe("m");
    expect(P.claimShapeValid(ok, 3, 3, 2, 3)).toBe("from");
    expect(P.claimShapeValid({ ...ok, rm: 2 + 8 }, 3, 0, 2, 3)).toBe("rm-high");
    expect(P.claimShapeValid({ ...ok, rm: 2 ** 31 }, 3, 0, 2, 3)).toBe("rm-high");
    expect(P.claimShapeValid(ok, 3, 1, 2, 3)).toBe("rm-self");
    expect(P.claimShapeValid(ok, 3, 0, 3, 3)).toBe("cut"); // E_ℓ = 2 < E_start = 3
    expect(P.claimShapeValid(ok, 3, 0, 2, 2)).toBe("cut"); // E_ℓ = 3 > E = 2
    expect(P.claimShapeValid({ ...ok, bundleSize: 23457 }, 3, 0, 2, 3)).toBe("bundleSize");
    expect(P.claimShapeValid({ ...ok, bundleSize: 11640 }, 3, 0, 2, 3)).toBe("bundleSize"); // the size before pkCt
    expect(P.claimShapeValid({ ...ok, bundleSize: 81248 }, 3, 0, 2, 3)).toBeNull();
    // m = 32 (with 81248: B = 32): bit 31 is a member's bit, not "at or above m"
    const c32: P.Claim = {
      ...ok,
      bundleSize: 81248,
      rm: 2 ** 31,
      cuts: Array.from({ length: 32 }, () => ({ E: 2, cnt: 0 })),
    };
    expect(P.claimShapeValid(c32, 32, 0, 2, 3)).toBeNull();
    expect(P.claimShapeValid(c32, 32, 31, 2, 3)).toBe("rm-self");
    // (h)'s local half: B = (bundleSize − 4192) / 2408 must hold the m members (§6.4 "Order of requests")
    const cuts = (m: number) => Array.from({ length: m }, () => ({ E: 2, cnt: 0 }));
    const c9: P.Claim = { ...ok, cuts: cuts(9) };
    expect(P.claimShapeValid(c9, 9, 0, 2, 3)).toBe("bundleSize"); // 23456: B = 8 < 9
    expect(P.claimShapeValid({ ...c9, bundleSize: 81248 }, 9, 0, 2, 3)).toBeNull(); // B = 32
    expect(P.claimShapeValid({ ...ok, cuts: cuts(8) }, 8, 0, 2, 3)).toBeNull(); // 23456: B = 8 = m
    expect(P.claimShapeValid({ ...c32, bundleSize: 23456 }, 32, 0, 2, 3)).toBe("bundleSize");
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

describe("acceptOldRow: the §6.8 walk", () => {
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
    // a carried LEFT record: NONE is never before a cut, so t_R = t(C) drops it
    ["carried LEFT record: NONE with t_R = t(C)", row(1, 100, 0xffff, 0xffffffff), [e0, e1], false],
    ["carried LEFT record: NONE with t_R < t(C)", row(1, 99, 0xffff, 0xffffffff), [e0, e1], true],
    // the bit without C_e: D_{e+1} lists C, so C's bit is 0 and the walk goes on to C_{e+1}
    ["no C_e, D_{e+1} held: C removed by C_{e+1}, after", row(2, 250), [{ ...e0, claim: null }, e1], false],
    ["no C_e, D_{e+1} held: C removed by C_{e+1}, equal t", row(2, 200), [{ ...e0, claim: null }, e1], false],
    ["no C_e, D_{e+1} held: C removed by C_{e+1}, before", row(2, 199), [{ ...e0, claim: null }, e1], true],
    ["no C_e, D_{e+1} held: A kept to the end", row(0, 9999), [{ ...e0, claim: null }, e1, e2], true],
  ];

  it.each(table)("%s", (_, r, epochs, want) => {
    expect(P.acceptOldRow(r, epochs)).toBe(want);
  });

  // a receiver removed by the last listed claim ends that epoch at the claim for every sender
  const removedTable: [string, P.WalkRow, P.WalkEpoch[], boolean][] = [
    ["removed receiver: a kept member's row before the claim", row(2, 99), [e0], true],
    ["removed receiver: a kept member's row after the claim", row(2, 101), [e0], false],
    ["removed receiver: equal t, before the kept member's cut", row(2, 100, 5, 6), [e0], true],
    ["removed receiver: equal t, at the kept member's cut", row(2, 100, 5, 7), [e0], false],
    ["removed receiver: a removed member's row keeps its rule", row(1, 101), [e0], false],
    ["removed receiver: a later claim ends a later epoch", row(2, 150), [e0, { ...e1, claim: { ...Ce1, rm: 1 } }], true],
    ["removed receiver: after the later claim", row(2, 250), [e0, { ...e1, claim: { ...Ce1, rm: 1 } }], false],
    ["removed receiver: a carried NONE source at equal t", row(2, 100, 0xffff, 0xffffffff), [e0], false],
    ["no claim on the last epoch: accept", row(2, 5000), [{ ...e0, claim: null }], true],
  ];

  it.each(removedTable)("%s", (_, r, epochs, want) => {
    expect(P.acceptOldRow(r, epochs, true)).toBe(want);
  });

  it("throws when the claim that ended an epoch is needed but not passed (§6.8 \"The bit without C_j\")", () => {
    // B (index 1 of e) is not listed in D_{e+1}: its bit in C_e is 1, and C_e is needed for t(C_e) and the cut
    for (const t of [50, 100, 5000]) {
      const err = throwsError(() => P.acceptOldRow(row(1, t), [{ ...e0, claim: null }, e1]));
      expect(err).toBe(true);
    }
    expect(() => P.acceptOldRow(row(1, 50), [{ ...e0, claim: null }, e1])).toThrow(P.MissingClaimError);
    // also one epoch further: C (index 1 of e+1) is not listed in D_{e+2} = [A, D]
    const e1open = { ...e1, claim: null };
    expect(() => P.acceptOldRow(row(2, 250), [e0, e1open, e2])).toThrow(P.MissingClaimError);
    try {
      P.acceptOldRow(row(2, 250), [e0, e1open, e2]);
    } catch (e) {
      expect((e as P.MissingClaimError).j).toBe(1);
    }
    // the last listed epoch without a claim still accepts
    expect(P.acceptOldRow(row(1, 5000), [{ ...e0, claim: null }])).toBe(true);
    expect(P.acceptOldRow(row(2, 5000), [e0, e1open])).toBe(true);
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
    { rtype: 2, ...copy, ...mat, claim: { E: 7, n: 3 }, flags: 0 },
    cat(refCopy, refMat, be16(7), be32(3), be8(0)),
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
    { rtype: 13, uid: bob.uid, sigPk: bob.id.sigPk, kh: refKh(bob.id.kemPk), pin: fill(32, 0x72), handle: "bob_1" },
    cat(bob.uid, bob.id.sigPk, refKh(bob.id.kemPk), fill(32, 0x72), be8(5), s2b("bob_1")),
    113 + 5,
  ],
  [
    "LEFT",
    { rtype: 0x0e, ...copy, e: 4, uid: bob.uid, t: 1_780_000_123, row: { E: 7, n: 12 } },
    cat(refCopy, be32(4), bob.uid, be32(1_780_000_123), be16(7), be32(12)),
    78,
  ],
  [
    "LEFT (carried, NONE)",
    { rtype: 0x0e, ...copy, e: 5, uid: bob.uid, t: 1_780_000_123, row: P.NONE },
    cat(refCopy, be32(5), bob.uid, be32(1_780_000_123), be16(0xffff), be32(0xffffffff)),
    78,
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

  it("HEADS entries are 68 + 6m + 12f bytes (§7.2)", () => {
    expect(refHeadsEntry.length).toBe(68 + 6 * 3 + 12 * 2);
    const one: P.HeadsEntry = { ...headsEntry, lanes: [{ E: 1, cnt: 2 }], followed: [] };
    expect(P.encodeRecord({ rtype: 8, Ein: 0, relIn: 0, entries: [one] }).length).toBe(3 + 8 + 68 + 6);
  });

  it("MEMBER is uid | sigPk | kh | pin | hlen | handle, 113 + hlen bytes with 3 ≤ hlen ≤ 20 (§7.2)", () => {
    for (const handle of ["bob", "b".repeat(20)]) {
      const keys = { uid: bob.uid, sigPk: bob.id.sigPk, kh: fill(32, 0x71), pin: fill(32, 0x72) };
      const rec: P.MemberRec = { rtype: 13, ...keys, handle };
      const b = P.encodeRecord(rec);
      expect(b.length).toBe(3 + 113 + handle.length);
      expect(toHex(b.subarray(3 + 48, 3 + 80))).toBe(toHex(fill(32, 0x71)));
      expect(P.parseRecord(13, b.subarray(3))).toEqual(rec);
    }
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
      ["EPOCH flags 1 (bit0 is not defined)", 2, set(content("EPOCH"), 126, 1)],
      ["EPOCH flags 3", 2, set(content("EPOCH"), 126, 3)],
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
      ["REQUEST desc of 223 bytes", 11, cat(refCopy, refMat, be32(5), alice.uid, be8(3), be16(223), fill(223, 0))],
      ["REQUEST desc of 2961 bytes", 11, cat(refCopy, refMat, be32(5), alice.uid, be8(3), be16(2961), fill(2961, 0))],
      ["DESC of 223 bytes", 12, cat(refCopy, be32(0), be16(223), fill(223, 0))],
      ["DESC of 2961 bytes", 12, cat(refCopy, be32(0), be16(2961), fill(2961, 0))],
      ["MEMBER hlen 2", 13, cat(bob.uid, bob.id.sigPk, fill(32, 0x71), fill(32, 0x72), be8(2), s2b("bo"))],
      ["MEMBER hlen 21", 13, cat(bob.uid, bob.id.sigPk, fill(32, 0x71), fill(32, 0x72), be8(21), s2b("b".repeat(21)))],
      ["MEMBER upper case", 13, cat(bob.uid, bob.id.sigPk, fill(32, 0x71), fill(32, 0x72), be8(3), s2b("Bob"))],
      ["MEMBER non-ASCII", 13, cat(bob.uid, bob.id.sigPk, fill(32, 0x71), fill(32, 0x72), be8(4), s2b("bö"))],
      ["MEMBER without kh (81 + hlen)", 13, cat(bob.uid, bob.id.sigPk, fill(32, 0x72), be8(5), s2b("bob_1"))],
      ["SNAP era 0xFFFF outside NONE", 0x20, cat(fill(32, 0x73), fill(32, 0x74), be32(4096), be16(0xffff), be32(1))],
      ["LEFT (E, n) = (0xFFFF, 0)", 0x0e, cat(refCopy, be32(4), bob.uid, be32(1), be16(0xffff), be32(0))],
      ["LEFT (E, n) = (0xFFFF, 0xFFFFFFFE)", 0x0e, cat(refCopy, be32(4), bob.uid, be32(1), be16(0xffff), be32(0xfffffffe))],
    ];
    for (const [what, rtype, c] of bads)
      expect([what, throwsError(() => P.parseRecord(rtype, c))]).toEqual([what, true]);
    expect(() => P.encodeRecord({ rtype: 1, ...copy, ...mat, rootBy: alice.uid, via: 9 as P.Via })).toThrow(
      P.CodecError,
    );
    const keys = { uid: bob.uid, sigPk: bob.id.sigPk, kh: fill(32, 0), pin: fill(32, 0) };
    expect(() => P.encodeRecord({ rtype: 13, ...keys, handle: "Bob" })).toThrow();
    expect(() =>
      P.encodeRecord({ rtype: 2, ...copy, ...mat, claim: { E: 7, n: 3 }, flags: 1 }),
    ).toThrow(P.CodecError);
    expect(() =>
      P.encodeRecord({ rtype: 0x0e, ...copy, e: 4, uid: bob.uid, t: 1, row: { E: 0xffff, n: 0 } }),
    ).toThrow(P.CodecError);
    // DESC / REQUEST desc: only 224 ≤ dlen ≤ 2960 at parse time (the consumer parses D, §7.2)
    for (const n of [224, 2960]) {
      const desc = cat(refCopy, be32(0), be16(n), fill(n, 0));
      expect(P.parseRecord(12, desc)).toMatchObject({ rtype: 12, desc: fill(n, 0) });
      const req = cat(refCopy, refMat, be32(5), alice.uid, be8(3), be16(n), fill(n, 0));
      expect(P.parseRecord(11, req)).toMatchObject({ rtype: 11, desc: fill(n, 0) });
    }
  });

  it("returns null (skip) for unknown rtypes", () => {
    for (const rtype of [0x00, 0x0f, 0x10, 0x1f, 0x21, 0x30, 0x80, 0xff])
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
      refRecord(0x10, fill(3, 1)),
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

  it("a LEFT of 77 or 79 B, or with (E, n) = (0xFFFF, n ≠ 0xFFFFFFFF), makes its row or S2 malformed", () => {
    const left = records.find(([n]) => n === "LEFT")!;
    const ok = refRecord(0x0e, left[2]);
    expect(P.parseS(refS(6, 4, fill(16, 1), TS, [ok])).records).toEqual([left[1]]);
    expect(P.parseSnapshot(refS2(7, 30, TS, [ok])).records).toEqual([left[1]]);
    expect(() => P.parseS(refS(6, 4, fill(16, 1), TS, [ok]), "snap")).toThrow(P.CodecError); // never at Lsnap
    for (const c of [left[2].slice(0, 77), cat(left[2], be8(0)), cat(left[2].slice(0, 72), be16(0xffff), be32(0))]) {
      expect(() => P.parseS(refS(6, 4, fill(16, 1), TS, [ok, refRecord(0x0e, c)]))).toThrow(P.CodecError);
      expect(() => P.parseSnapshot(refS2(7, 30, TS, [refRecord(0x0e, c), ok]))).toThrow(P.CodecError);
    }
  });

  it("snapshot pointer rows (Lsnap) hold exactly one SNAP, with prev fields NONE / ZERO16", () => {
    const ptr: P.SelfRow = { prev: P.NONE, prevh: P.ZERO16, ts: TS, records: [snap[1]] };
    const S = P.encodeS(ptr);
    expect(toHex(S)).toBe(toHex(refS(0xffff, 0xffffffff, fill(16, 0), TS, [refRecord(0x20, snap[2])])));
    expect(P.parseS(S, "snap")).toEqual({ ...ptr, skipped: 0 });
    expect(() => P.parseS(S)).toThrow(P.CodecError);
    // encodeS refuses a pointer row in the Lself prev chain (§7.1); readers ignore a pointer row's prev fields
    expect(() => P.encodeS({ ...row, records: [snap[1]] })).toThrow(P.CodecError);
    const chained = refS(6, 4, fill(16, 0x75), TS, [refRecord(0x20, snap[2])]);
    expect(P.parseS(chained, "snap").records).toEqual([snap[1]]);
    expect(() => P.parseS(refRow, "snap")).toThrow(P.CodecError);
    const two = refS(6, 4, fill(16, 0x75), TS, [refRecord(0x20, snap[2]), refRecord(0x20, snap[2])]);
    expect(() => P.parseS(two, "snap")).toThrow(P.CodecError);
    const withUnknown = refS(6, 4, fill(16, 0x75), TS, [refRecord(0x20, snap[2]), refRecord(0x40, fill(2, 0))]);
    expect(P.parseS(withUnknown, "snap").skipped).toBe(1);
  });

  it("sealSelf / openSelf: AAD, reference construction, and the EPOCH_PENDING / DELIVERED class rule", () => {
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
    // a row with only a DELIVERED is padded the same way, for a = 0, 8 and 31 (§7.1, §6.12 step 3)
    for (const a of [0, 8, 31]) {
      const uids = Array.from({ length: a }, (_, k) => fill(16, k));
      const delivered: P.SelfRecord = { rtype: 10, ...copy, e: 2, bundleId: fill(32, 0x34), uids };
      const r: P.SelfRow = { ...plain, records: [delivered] };
      const S = P.encodeS(r);
      expect(S.length).toBe(32 + 3 + 85 + 16 * a);
      const sd = withRng(queueRng([nonce]), () => P.sealSelf(id.kS, E, label, r));
      expect([a, sd.cls, sd.body.length]).toEqual([a, 1, 1064]);
      expect(toHex(sd.body)).toBe(toHex(xSeal(kS, nonce, aad, refPad(S, [1024, 4096, 16384]))));
      expect(P.openSelf(id.kS, E, label, sd.body).records).toEqual([delivered]);
    }
    // the same records without the padding rule would be class 0
    expect(P.clsFor(32 + 3 + 85 + 16 * 8)).toBe(0);
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

// ───────────────────────── throwing decapsulation (§1.1) ─────────────────────────

describe("a low-order X25519 component makes every trial-open return 'does not open'", () => {
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

  it("openEntry returns null and processClaim reports nokey (frozen)", () => {
    for (const kct of lowOrder) {
      const blob = built1.blob.slice();
      for (let i = 0; i < 8; i++) blob.set(kct, entryAt(8, i));
      for (const sk of keys) for (let i = 0; i < 8; i++) expect(P.openEntry(sk, conv, 1, i, blob)).toBeNull();
      const claim = { ...claim3, bundleId: sha(blob), bundleSize: 23456 };
      for (const [i, sk] of [alice.id.kemSk, bob.id.kemSk, carol.id.kemSk].entries())
        expect(P.processClaim({ kemSk: sk, De: D0, i, from: 0, claim, blob })).toEqual(
          i === 1 ? { kind: "removed" } : { kind: "nokey" },
        );
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

describe("fuzz: truncations, extensions and random bytes are rejected", () => {
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
        P.encodeM({ ...hdr(), type: P.MT.LEAVE }),
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
    for (const n of [0, 16, 4152, 11640, 13920, 23455, 23457, 40248, 81247, 81249])
      expect(throwsError(() => P.parseBundleBlob(new Uint8Array(n)))).toBe(true);
    for (let k = 0; k < 50; k++) {
      const b = cat(r.bytes(16), new Uint8Array(23456 - 16));
      const ok =
        toHex(b.subarray(0, 6)) === toHex(cat(s2b("SGB2"), be8(1), be8(8))) && b.subarray(6, 16).every((x) => x === 0);
      expect(throwsError(() => P.parseBundleBlob(b))).toBe(!ok);
    }
  });
});

// ───────────────────────── 4. known-answer vectors ─────────────────────────
// Generated once from the implementation after the tests above passed (which cross-check every layout against
// the independent reference). If one of these fails, the wire format changed: do not "fix" the vector.

/**
 * The claim of the claim and claim-row vectors: claim3 with the prevD and hD it had when the vectors were pinned (the
 * hashes of the descriptors before members carried kh). The claim codec did not change, so neither do its vectors.
 */
const claimKat: P.Claim = {
  ...claim3,
  prevD: fromHex("c87ea58357addb0100c8e17567bab6a262382703d6f56f51d49e1827cc8e43b8"),
  hD: fromHex("f6b927933650e5802664a4d530c3de298f906901b0ed4c020f53a48067f507cc"),
};

function computeKat() {
  const rng = detRng("segv.sh/v2/kat/conv");
  const main = withRng(rng, () => {
    const M = P.encodeM({
      ...hdr({ prev: { E: 3, n: 1 }, prevh: fill(16, 0x77), ckq: 9, ck16: fill(16, 0x99) }),
      type: P.MT.TEXT,
      text: "kat",
    });
    const label = P.Lmsg(keys0.rk, 1, E, 5);
    const sig = P.signRow(bob.id.sigSk, conv, 0, E, label, M);
    const row = P.sealRow(keys0.mk, E, label, M, sig);
    const claimRow = P.buildRow(ctx0(alice.id.sigSk), E, claimMsg(claimKat, 0, 0));
    const inv = P.makeInvite(bob.id.kemPk, E, 0, join1);
    const hello = P.makeHello(bob.id.kemPk, fill(16, 0x50), E, fill(16, 0x51), join1);
    // The SGB2 bundle draws from a stream of its own (below). Before pkCt it drew 35 blocks of this stream here;
    // skipping them keeps the self row and the snapshot at the stream positions their vectors were pinned with.
    rng(35 * 32);
    const selfRow = P.sealSelf(alice.id.kS, E, P.Lself(alice.id.rS, E, 0), {
      prev: P.NONE,
      prevh: P.ZERO16,
      ts: TS,
      records: [records[3][1], records[0][1]],
    });
    // LEFT (0x0E) came after this vector was pinned: it has a vector of its own (left, below)
    const snap = P.encryptSnapshot({
      pos: { E: 7, n: 30 },
      ts: TS,
      records: records.filter(([, r]) => r.rtype !== 0x20 && r.rtype !== 0x0e).map(([, r]) => r),
    });
    return {
      D0: toHex(D0.bytes),
      hD1: toHex(D1.hash),
      dsig0: toHex(dsig0),
      J: toHex(P.encodeJ(join1)),
      claim: toHex(P.encodeClaim(claimKat)),
      M: toHex(M),
      sig: toHex(sig),
      rowBodySha: toHex(sha(row.body)),
      claimRowSha: toHex(sha(claimRow.body)),
      invite: toHex(inv.eid) + ":" + toHex(sha(inv.body)),
      helloSha: toHex(sha(hello.body)),
      selfRowSha: toHex(sha(selfRow.body)),
      snapshot: snap.id + ":" + toHex(snap.key),
    };
  });
  const bundle = withRng(detRng("segv.sh/v2/kat/sgb2"), () => P.buildBundle(spec1));
  const record = (name: string): P.SelfRecord => records.find(([n]) => n === name)![1];
  return {
    ...main,
    bundleId: toHex(bundle.id),
    kh: toHex(P.kemHash(bob.id.kemPk)),
    rr: toHex(P.rekeyRoot(EK1, conv, 1)),
    sealDetSha: toHex(sha(withRng(noRng, () => P.sealDet(carol.id.kemPk, conv, 1, 2, EK1)))),
    heads: toHex(P.encodeRecord(record("HEADS with an entry"))),
    member: toHex(P.encodeRecord(record("MEMBER"))),
    left: toHex(P.encodeRecord(record("LEFT"))),
  };
}

const KAT = {
  // D_0 = alice (by), bob, carol; e = 0; name "kat"; members (uid, sigPk, kh) (cross-checked against refD above)
  D0:
    "02606162636465666768696a6b6c6d6e6f000000000000000000000000000000000000000000000000000000000000000000000000" +
    "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00000019b93216d0003" +
    "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a012dfde9fa01f1210b0744167dc73d4be8b07e2ce787e01aa8277453025f922e8" +
    "ccb66f7f0110f2f0f423bebd30e5eb2cc88d89f390a81854eb3b7ced926d74a4" +
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a108d49f307d2069ae7103b5b61f6a8b2bb256dd9445960bab6413c565c0cb0e09" +
    "5350b0d409bc0335181d38f4f25ae3c82486104f11f0d04833bcfb216e55c768" +
    "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2b2596b23571457937535034115fdeb96061e978fce56c1fcb0c93c518ae7ff6b" +
    "342ff078642d1caac5f1f966ec65fe27138084df759b551d509a07be3118a518" +
    "00036b6174",
  hD1: "651d0d71be8a316e453d8996d2bc295e09052f1627c874b4c383b93693fe4429",
  dsig0:
    "ec409af88f97dd99b5e23999ebced8ccc86cae3e465488c84c27050a8d6f3f19c09f603c7c5c32c0aea3896d1878002a0c2af772ba3116beba9afcdfb7f33004",
  J: "0201606162636465666768696a6b6c6d6e6f000000012222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333300002d78",
  // claimKat: the claim codec and the claim row are unchanged since they were first pinned
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
  selfRowSha: "926ddd200fb162bdc4286437ab751e77127850e536d4fdeae329ff67df3e84af",
  snapshot:
    "dlqa0JELwW4WWIikSgJaw0EFuQx2sqwWH7qspCnfhgw:80f5bdcfeacc5fb3903aa1b23492f0988b0e7796df52ae768950a024d44af82f",
  // the SGB2 bundle of e = 1 (spec1: sealDet entries for alice and carol, dummies elsewhere; its own detRng stream)
  bundleId: "4ba9d498e317de7616d740bec02a64904b984209068adebf54c96ade05ed91a4",
  // kh of bob's kemPk; rr_e for (EK1, conv, e = 1); one sealDet entry (carol's kemPk, e = 1, i = 2, EK1; no RNG)
  kh: "5350b0d409bc0335181d38f4f25ae3c82486104f11f0d04833bcfb216e55c768",
  rr: "79ed6b1bda843d3bfbca70e86ff36baa7c1cb8c5bbfff29d0897b7a62d653680",
  sealDetSha: "2f8452901c7088cb4f616bdf6d7fffa9ca42f9dea2d136990c446bd987633b87",
  // a HEADS record with one entry (68 + 6·3 + 12·2 bytes) and a MEMBER record (113 + 5 bytes, with kh)
  heads:
    "0800760007000000630001606162636465666768696a6b6c6d6e6f52525252525252525252525252525252525252525252525252525252525252520000000400" +
    "00019b93216d000007000000020300070000000a00060000000000070000000102000000020001000500000003000000030000000600000009",
  member:
    "0d0076a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a108d49f307d2069ae7103b5b61f6a8b2bb256dd9445960bab6413c565c0cb0e095350b0d409bc0335181d38f4f2" +
    "5ae3c82486104f11f0d04833bcfb216e55c768727272727272727272727272727272727272727272727272727272727272727205626f625f31",
  // a LEFT record (78 bytes): conv | root | e = 4 | bob | t | (E, n) = (7, 12)
  left: "0e004e606162636465666768696a6b6c6d6e6f525252525252525252525252525252525252525252525252525252525252525200000004a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a16a18a57b00070000000c",
};

describe("known-answer vectors", () => {
  it("are stable", () => {
    expect(computeKat()).toEqual(KAT);
  });
});
