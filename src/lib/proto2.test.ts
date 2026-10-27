// Test suite for the core of src/lib/proto2.ts (protocol v2, stage 1, docs/PROTOCOL-v2.md): everything above the
// "conversation codecs" banner. The codecs below the banner are tested in proto2-conv.test.ts.
//
// Layout (as in proto.test.ts):
//   1. reference helpers — an independent re-implementation of the spec's encoding / KDF / hash / commitment rules on
//                          top of node:crypto (plus BigInt arithmetic), used to cross-check proto2.ts byte for byte.
//   2. cross-checks and round trips — time, classes, sealing, accounts, derivations, routing, commitments, PoW,
//                          directory prefixes, blobs.
//   3. tamper / misuse — bit flips, wrong contexts, attacker-filed wraps, throwing decapsulation (§1.1).
//   4. fuzz — parsers only ever throw Error.
//   5. known answers — pinned outputs, with deterministic randomness through _setRandomForTests.
import { describe, expect, it } from "vite-plus/test";
import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";
import { ml_kem768_x25519 as xwing } from "@noble/post-quantum/hybrid.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import * as P from "./proto2";
import * as P1 from "./proto";

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
const be64n = (n: bigint): B => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(n);
  return new Uint8Array(b);
};
const be64 = (n: number): B => be64n(BigInt(n));
const beToBig = (b: B): bigint => b.reduce((acc, x) => (acc << 8n) | BigInt(x), 0n);
/** §1.2: enc(a, b, …) = lp(a) ‖ lp(b) ‖ … with lp(b) = u32(len(b)) ‖ b; strings are UTF-8 first. */
const refEnc = (...xs: (B | string)[]): B => cat(...xs.flatMap((x) => [be32(s2b(x).length), s2b(x)]));
const sha = (b: B): B => new Uint8Array(createHash("sha256").update(b).digest());
const hmacN = (k: B, m: B | string): B => new Uint8Array(createHmac("sha256", k).update(s2b(m)).digest());
const hkdfN = (ikm: B, salt: B | string, info: B | string, len = 32): B =>
  new Uint8Array(hkdfSync("sha256", ikm, s2b(salt), s2b(info), len));
const tr16 = (b: B): B => b.slice(0, 16);
const toHex = (b: B): string => Buffer.from(b).toString("hex");
const fromHex = (h: string): B => new Uint8Array(Buffer.from(h, "hex"));
const b64uN = (b: B): string => Buffer.from(b).toString("base64url");
const fill = (n: number, v: number): B => new Uint8Array(n).fill(v);
const seqBytes = (n: number, start = 0): B => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);
const flip = (b: B, i: number, bit = 0): B => {
  const c = b.slice();
  c[i] ^= 1 << bit;
  return c;
};
const bitLength = (n: number): number => (n <= 0 ? 0 : BigInt(n).toString(2).length);

// node:crypto Ed25519 from raw keys (PKCS#8 / SPKI DER prefixes, RFC 8410).
const ED_PKCS8 = fromHex("302e020100300506032b657004220420");
const ED_SPKI = fromHex("302a300506032b6570032100");
const edPriv = (sk: B) => createPrivateKey({ key: Buffer.from(cat(ED_PKCS8, sk)), format: "der", type: "pkcs8" });
const edPubRaw = (sk: B): B =>
  new Uint8Array(Buffer.from(createPublicKey(edPriv(sk)).export({ format: "jwk" }).x!, "base64url"));
const edSign = (msg: B, sk: B): B => new Uint8Array(nodeSign(null, msg, edPriv(sk)));
const edVerify = (sig: B, msg: B, pk: B): boolean =>
  nodeVerify(null, msg, createPublicKey({ key: Buffer.from(cat(ED_SPKI, pk)), format: "der", type: "spki" }), sig);

// Twisted Edwards arithmetic over BigInt (RFC 8032 §5.1), only to classify test keys independently of noble.
const Pq = 2n ** 255n - 19n;
const md = (a: bigint): bigint => ((a % Pq) + Pq) % Pq;
const pw = (b: bigint, e: bigint): bigint => {
  let r = 1n;
  let x = md(b);
  for (let k = e; k > 0n; k >>= 1n) {
    if (k & 1n) r = (r * x) % Pq;
    x = (x * x) % Pq;
  }
  return r;
};
const inv = (a: bigint): bigint => pw(a, Pq - 2n);
const Dq = md(-121665n * inv(121666n));
const SQRTM1 = pw(2n, (Pq - 1n) / 4n);
type Pt = [bigint, bigint];
const le32 = (n: bigint): B => Uint8Array.from({ length: 32 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));
/** RFC 8032 §5.1.3 point decoding; null when the encoding is not a canonical point. */
function edDecode(b: B): Pt | null {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(b[i]);
  const sign = y >> 255n;
  y &= (1n << 255n) - 1n;
  if (y >= Pq) return null;
  const u = md(y * y - 1n);
  const v = md(Dq * y * y + 1n);
  let x = md(u * pw(v, 3n) * pw(u * pw(v, 7n), (Pq - 5n) / 8n));
  const vx2 = md(v * x * x);
  if (vx2 === md(-u)) x = md(x * SQRTM1);
  else if (vx2 !== u) return null;
  if (x === 0n && sign === 1n) return null;
  if ((x & 1n) !== sign) x = md(-x);
  return [x, y];
}
const edEncode = ([x, y]: Pt): B => {
  const b = le32(y);
  if (x & 1n) b[31] |= 0x80;
  return b;
};
const edAdd = ([x1, y1]: Pt, [x2, y2]: Pt): Pt => {
  const t = md(Dq * x1 * x2 * y1 * y2);
  return [md((x1 * y2 + y1 * x2) * inv(1n + t)), md((y1 * y2 + x1 * x2) * inv(md(1n - t)))];
};
/** [8]P = identity. */
const edSmallOrder = (p: Pt): boolean => {
  let q = p;
  for (let i = 0; i < 3; i++) q = edAdd(q, q);
  return q[0] === 0n && q[1] === 1n;
};

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
    u32: (): number => next(),
    bytes: (n: number): B => {
      const b = new Uint8Array(n);
      for (let i = 0; i < n; i++) b[i] = next() & 0xff;
      return b;
    },
  };
}

/** Deterministic byte stream for _setRandomForTests: SHA-256(seed ‖ u32 counter) blocks, one fresh block per call. */
function detRandom(seed: string): (n: number) => B {
  let ctr = 0;
  return (n) => {
    const out = new Uint8Array(n);
    for (let o = 0; o < n; o += 32) out.set(sha(cat(s2b(seed), be32(ctr++))).subarray(0, Math.min(32, n - o)), o);
    return out;
  };
}
/** Runs f with the injected RNG and always restores the CSPRNG. */
function withRandom<T>(rnd: (n: number) => B, f: () => T): T {
  P._setRandomForTests(rnd);
  try {
    return f();
  } finally {
    P._setRandomForTests(null);
  }
}
/** An injected RNG that records every call. */
const recording = (rnd: (n: number) => B, calls: B[]) => (n: number) => {
  const b = rnd(n);
  calls.push(b);
  return b;
};

/** §1.4 sealing, independently: k = HKDF(ss, H(kct), enc("segv.sh/v2/seal", label, ctx)), aad = enc(label, ctx). */
const refSealKey = (ss: B, kct: B, label: string, ctx: B): B => hkdfN(ss, sha(kct), refEnc("segv.sh/v2/seal", label, ctx));
function refSeal(pk: B, label: string, ctx: B, pt: B, encapRand: B, nonce: B): B {
  const { cipherText: kct, sharedSecret: ss } = xwing.encapsulate(pk, encapRand);
  return cat(kct, nonce, xchacha20poly1305(refSealKey(ss, kct, label, ctx), nonce, refEnc(label, ctx)).encrypt(pt));
}
function refOpen(sk: B, label: string, ctx: B, box: B): B {
  const kct = box.subarray(0, 1120);
  const ss = xwing.decapsulate(kct, sk);
  return xchacha20poly1305(refSealKey(ss, kct, label, ctx), box.subarray(1120, 1144), refEnc(label, ctx)).decrypt(
    box.subarray(1144),
  );
}

/** RFC 6962 MTH, computed bottom-up (pair neighbours, promote an odd last node): equivalent to the recursive split. */
const refLeaf = (d: B): B => sha(cat(Uint8Array.of(0), d));
const refNode = (l: B, r: B): B => sha(cat(Uint8Array.of(1), l, r));
function refMth(leafHashes: B[]): B {
  let level = leafHashes;
  while (level.length > 1) {
    const next: B[] = [];
    for (let i = 0; i + 1 < level.length; i += 2) next.push(refNode(level[i], level[i + 1]));
    if (level.length % 2) next.push(level[level.length - 1]);
    level = next;
  }
  return level[0];
}

/** §10.2 difficulty with integers only: base + the smallest k with unit·2^k ≥ bytes, above the unit. */
const POW_UNIT_REF: Record<P.PowScope, bigint> = { register: 0n, wrap: 0n, put: 4096n, inbox: 4096n, blob: 1n << 20n };
const refPowDifficulty = (scope: P.PowScope, base: number, bytes: number): number => {
  const unit = POW_UNIT_REF[scope];
  if (unit === 0n || BigInt(bytes) <= unit) return base;
  let k = 0;
  while (unit << BigInt(k) < BigInt(bytes)) k++;
  return base + k;
};

/** Flips one bit at sampled positions of every region; returns the positions where `open` did NOT throw. */
function survivors(
  body: B,
  regions: { name: string; start: number; end: number; every?: boolean }[],
  open: (b: B) => unknown,
  seed = 1,
): string[] {
  const r = prng(seed);
  const out: string[] = [];
  for (const reg of regions) {
    const len = reg.end - reg.start;
    expect(len, `region ${reg.name}`).toBeGreaterThan(0);
    const pos = new Set<number>();
    if (reg.every) for (let i = 0; i < len; i++) pos.add(i);
    else {
      pos.add(0);
      pos.add(len - 1);
      pos.add(len >> 1);
      for (let i = 0; i < 5; i++) pos.add(r.int(len));
    }
    for (const p of pos) {
      const bit = (p * 3 + seed) % 8;
      let threw = false;
      try {
        open(flip(body, reg.start + p, bit));
      } catch (e) {
        threw = e instanceof Error;
      }
      if (!threw) out.push(`${reg.name}[${p}] bit ${bit}`);
    }
  }
  return out;
}

const throwsError = (fn: () => unknown): boolean => {
  try {
    fn();
    return false;
  } catch (e) {
    return e instanceof Error;
  }
};

const nonCanonical = (s: string): string => {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  return s.slice(0, -1) + A[A.indexOf(s[s.length - 1]) ^ 1];
};

// ───────────────────────── fixtures ─────────────────────────

const TS = 1_780_000_000_000;
const T0 = 1767639600000;
const ERA = 604_800_000;

interface TUser {
  AK: B;
  id: P.Identity;
  uid: B;
  uidS: string;
  handle: string;
  bundle: string;
  sig: string;
  user: P.User;
}

function mkUser(seed: number, handle: string): TUser {
  const AK = fill(32, seed);
  const uid = fill(16, seed ^ 0x55);
  const id = P.deriveIdentity(AK);
  const { bundle, sig } = P.makeBundle(uid, handle, id, TS + seed);
  return { AK, id, uid, uidS: P.b64u(uid), handle, bundle, sig, user: P.verifyBundle(bundle, sig) };
}

const alice = mkUser(0xa1, "alice");
const bob = mkUser(0xb2, "bob");
const carol = mkUser(0xc3, "carol");

const CONV = seqBytes(16, 0x60);
const EK = fill(32, 0xe0);
const LBL = "segv.sh/v2/test";

/** A real X-Wing ciphertext whose X25519 component (the last 32 bytes) is replaced by `u` (little-endian). */
const realKct = xwing.encapsulate(bob.id.kemPk, seqBytes(64, 0x10)).cipherText;
const withX25519 = (u: bigint): B => {
  const c = realKct.slice();
  c.set(le32(u), 1088);
  return c;
};
/** Curve25519 u-coordinates of small order (and non-canonical encodings of them), RFC 7748 §7. */
const LOW_ORDER_U: [string, bigint][] = [
  ["0 (order 4)", 0n],
  ["1 (order 1)", 1n],
  ["p-1 (order 2)", Pq - 1n],
  ["order 8 (a)", 325606250916557431795983626356110631294008115727848805560023387167927233504n],
  ["order 8 (b)", 39382357235489614581723060781553021112529911719440698176882885853963445705823n],
  ["p (= 0, non-canonical)", Pq],
  ["p+1 (= 1, non-canonical)", Pq + 1n],
  ["0 with bit 255 set", 1n << 255n],
];

// ═════════════════════════ 2. cross-checks and round trips ═════════════════════════

describe("encoding (§1.2) and the shared primitives", () => {
  it("enc matches the spec example and the reference encoder", () => {
    expect(toHex(P.enc("L", P.u16(5)))).toBe("000000014c000000020005");
    const r = prng(7);
    for (let t = 0; t < 200; t++) {
      const parts = Array.from({ length: r.int(5) }, () => r.bytes(r.int(300)));
      expect(toHex(P.enc(...parts))).toBe(toHex(refEnc(...parts)));
    }
    expect(toHex(P.enc("é", ""))).toBe(toHex(refEnc("é", "")));
  });

  it("t16 / t8 copy the first 16 / 8 bytes; ZERO16 / ZERO32", () => {
    const x = seqBytes(32);
    expect(toHex(P.t16(x))).toBe(toHex(seqBytes(16)));
    expect(toHex(P.t8(x))).toBe(toHex(seqBytes(8)));
    P.t16(x)[0] = 0xff;
    P.t8(x)[0] = 0xff;
    expect(x[0]).toBe(0);
    expect(toHex(P.ZERO16)).toBe("00".repeat(16));
    expect(toHex(P.ZERO32)).toBe("00".repeat(32));
  });

  it("re-exports the v1 primitives unchanged (§1.1)", () => {
    for (const k of ["H", "HKDF", "HMAC", "enc", "dec", "b64u", "fromB64u", "sign", "sigPub", "verify", "kemKeygen"] as const) {
      expect(P[k], k).toBe(P1[k]);
    }
    expect(toHex(P.H(s2b("abc")))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect([P.KEM_PK_LEN, P.KEM_CT_LEN, P.NONCE_LEN, P.TAG_LEN, P.WRAP_LEN]).toEqual([1216, 1120, 24, 16, 1192]);
  });

  it("_setRandomForTests drives random(), aeadSeal nonces, KEM encapsulation and recovery codes; null restores", () => {
    const k = fill(32, 1);
    const kp = P.kemKeygen(fill(32, 2));
    withRandom(
      (n) => fill(n, 0x42),
      () => {
        expect(toHex(P.random(3))).toBe("424242");
        expect(toHex(P.newRecoveryCode())).toBe("42".repeat(20));
        const box = P.aeadSeal(k, s2b("x"), new Uint8Array(0));
        expect(toHex(box.subarray(0, 24))).toBe("42".repeat(24));
        expect(toHex(P.aeadOpen(k, box, new Uint8Array(0)))).toBe("78");
        const { kct, ss } = P.kemEncap(kp.pk);
        const ref = xwing.encapsulate(kp.pk, fill(64, 0x42));
        expect(toHex(kct)).toBe(toHex(ref.cipherText));
        expect(toHex(ss)).toBe(toHex(ref.sharedSecret));
        expect(toHex(P.kemDecap(kct, kp.sk))).toBe(toHex(ss));
      },
    );
    expect(toHex(P.random(16))).not.toBe(toHex(P.random(16)));
    expect(P.newRecoveryCode().length).toBe(20);
  });
});

describe("time and eras (§3.1)", () => {
  it("T0 is Monday 2026-01-05 19:00 UTC (Tuesday 04:00 JST); ERA_MS is one week; NONE is (0xFFFF, 0xFFFFFFFF)", () => {
    expect(P.T0_MS).toBe(Date.UTC(2026, 0, 5, 19, 0, 0));
    expect(P.T0_MS).toBe(T0);
    expect(new Date(P.T0_MS).getUTCDay()).toBe(1);
    const jst = new Date(P.T0_MS + 9 * 3600_000);
    expect([jst.getUTCDay(), jst.getUTCHours(), jst.getUTCMinutes()]).toEqual([2, 4, 0]);
    expect(P.ERA_MS).toBe(7 * 24 * 3600 * 1000);
    expect([P.ERA_NONE, P.N_NONE]).toEqual([0xffff, 0xffffffff]);
    expect({ ...P.NONE }).toEqual({ E: 0xffff, n: 0xffffffff });
    expect(Object.isFrozen(P.NONE)).toBe(true);
    expect(P.isNone(P.NONE)).toBe(true);
    expect(P.isNone({ E: 0xffff, n: 0 })).toBe(false);
    expect(P.isNone({ E: 0, n: 0xffffffff })).toBe(false);
  });

  it("era boundaries at T0, T0 + ERA_MS − 1 and T0 + ERA_MS; the reserved era and times before T0 throw", () => {
    expect(P.era(T0)).toBe(0);
    expect(P.era(T0 + ERA - 1)).toBe(0);
    expect(P.era(T0 + ERA)).toBe(1);
    expect(P.era(T0 + 2 * ERA - 1)).toBe(1);
    expect(P.era(T0 + 2 * ERA)).toBe(2);
    expect(P.era(T0 + 0xfffe * ERA)).toBe(0xfffe);
    expect(P.era(T0 + 0xffff * ERA - 1)).toBe(0xfffe);
    for (const ms of [T0 - 1, T0 - ERA, 0, T0 + 0xffff * ERA, T0 + 0x10000 * ERA, NaN, Infinity, -Infinity]) {
      expect(() => P.era(ms), String(ms)).toThrow(/era/);
    }
    // start(E) = T0 + E·ERA_MS, end(E) = start(E + 1)
    for (const E of [0, 1, 2, 41, 0xfffe]) {
      expect(P.eraStart(E)).toBe(T0 + E * ERA);
      expect(P.eraEnd(E)).toBe(P.eraStart(E + 1));
      expect(P.era(P.eraStart(E))).toBe(E);
      expect(P.era(P.eraEnd(E) - 1)).toBe(E);
    }
    // against a BigInt reference
    const r = prng(31);
    for (let i = 0; i < 500; i++) {
      const ms = T0 + r.u32() * 1000 + r.int(1000);
      expect(P.era(ms)).toBe(Number((BigInt(ms) - BigInt(T0)) / BigInt(ERA)));
    }
  });

  it("sec is ⌊(ms − T0) / 1000⌋ as a u32", () => {
    expect(P.secOf(T0)).toBe(0);
    expect(P.secOf(T0 + 999)).toBe(0);
    expect(P.secOf(T0 + 1000)).toBe(1);
    expect(P.secOf(T0 + ERA)).toBe(604800);
    expect(P.secOf(T0 + 0xffffffff * 1000 + 999)).toBe(0xffffffff);
    for (const ms of [T0 - 1, T0 + 2 ** 32 * 1000, NaN]) expect(() => P.secOf(ms), String(ms)).toThrow(/sec/);
    for (const s of [0, 1, 604800, 0xffffffff]) expect(P.secOf(P.msOfSec(s))).toBe(s);
    expect(P.msOfSec(10)).toBe(T0 + 10_000);
  });

  it("tpub = ⌊sec / Δ⌋ · Δ for Δ ∈ {1, 10}", () => {
    const cases: [number, number, number][] = [
      [T0, 1, 0],
      [T0, 10, 0],
      [T0 + 999, 1, 0],
      [T0 + 1000, 1, 1],
      [T0 + 9999, 10, 0],
      [T0 + 10_000, 10, 10],
      [T0 + 19_999, 10, 10],
      [T0 + 20_000, 10, 20],
      [T0 + 12_345, 1, 12],
      [T0 + 12_345, 10, 10],
      [T0 + ERA - 1, 1, 604799],
      [T0 + ERA - 1, 10, 604790],
      [T0 + ERA, 1, 604800],
      [T0 + ERA, 10, 604800],
    ];
    for (const [ms, d, want] of cases) expect(P.tpub(ms, d), `tpub(T0 + ${ms - T0}, ${d})`).toBe(want);
    const r = prng(32);
    for (let i = 0; i < 500; i++) {
      const ms = T0 + r.int(2 ** 31) * 1000 + r.int(1000);
      for (const d of [1, 10]) {
        const want = ((BigInt(ms) - BigInt(T0)) / 1000n / BigInt(d)) * BigInt(d);
        expect(P.tpub(ms, d)).toBe(Number(want));
      }
    }
    for (const d of [0, -1, 1.5, 0x10000, NaN]) expect(() => P.tpub(T0, d), String(d)).toThrow(/delta/);
    expect(P.floorDelta(19, 10)).toBe(10);
    expect(P.floorDelta(19, 0xffff)).toBe(0);
    expect(P.floorDelta(0x1ffff, 0xffff)).toBe(0x1fffe);
  });

  it("posCmp orders (E, n) lexicographically, with NONE before every real position", () => {
    const N = P.NONE;
    const real: P.Pos[] = [
      { E: 0, n: 0 },
      { E: 0, n: 5 },
      { E: 0, n: 0xffffffff },
      { E: 1, n: 0 },
      { E: 1, n: 0xffffffff },
      { E: 0xfffe, n: 0xffffffff },
    ];
    expect(P.posCmp(N, N)).toBe(0);
    expect(P.posCmp(N, { E: 0xffff, n: 0xffffffff })).toBe(0);
    for (const p of real) {
      expect(P.posCmp(N, p)).toBeLessThan(0);
      expect(P.posCmp(p, N)).toBeGreaterThan(0);
      expect(P.posCmp(p, { ...p })).toBe(0);
    }
    for (let i = 0; i < real.length; i++)
      for (let j = 0; j < real.length; j++) expect(Math.sign(P.posCmp(real[i], real[j])), `${i} vs ${j}`).toBe(Math.sign(i - j));
    const shuffled = [real[3], N, real[5], real[0], real[2], real[1], real[4]];
    expect(shuffled.sort(P.posCmp)).toEqual([N, ...real]);
    // against a BigInt reference key
    const key = (p: P.Pos): bigint => (P.isNone(p) ? -1n : (BigInt(p.E) << 32n) | BigInt(p.n));
    const r = prng(33);
    const rnd = (): P.Pos => (r.int(10) === 0 ? N : { E: r.int(4), n: r.int(3) === 0 ? 0xffffffff : r.int(4) });
    for (let i = 0; i < 500; i++) {
      const a = rnd();
      const b = rnd();
      const k = key(a) - key(b);
      expect(Math.sign(P.posCmp(a, b))).toBe(k === 0n ? 0 : k < 0n ? -1 : 1);
    }
  });
});

describe("size classes (§3.2)", () => {
  it("CLASSES, BODY_LENS = 296 / 1064 / 4136 / 16424 and the fixed object lengths", () => {
    expect([...P.CLASSES]).toEqual([256, 1024, 4096, 16384]);
    expect([...P.BODY_LENS]).toEqual([296, 1064, 4136, 16424]);
    expect(P.ROW_OVERHEAD).toBe(40);
    expect(P.MAX_CLS).toBe(3);
    expect(P.SEAL_OVERHEAD).toBe(1120 + 24 + 16);
    expect(P.INBOX_BODY_LEN).toBe(1416);
    expect(P.INBOX_BODY_LEN).toBe(1120 + 24 + 256 + 16);
    expect([P.SGB2_HEADER_LEN, P.SGB2_DESC_LEN, P.SGB2_ENTRY_LEN]).toEqual([16, 2088, 1192]);
    expect([...P.SGB2_SIZES]).toEqual([11640, 40248]);
    expect([P.sgb2Size(8), P.sgb2Size(32)]).toEqual([16 + 2088 + 8 * 1192, 16 + 2088 + 32 * 1192]);
    // a key wrap and an SGB2 entry are a seal of 32 bytes
    expect(P.SGB2_ENTRY_LEN).toBe(P.WRAP_LEN);
    expect(P.SEAL_OVERHEAD + 32).toBe(1192);
  });

  it("clsOfBodyLen maps exactly the four body lengths", () => {
    expect([296, 1064, 4136, 16424].map(P.clsOfBodyLen)).toEqual([0, 1, 2, 3]);
    for (const n of [0, 40, 256, 295, 297, 1024, 1063, 1065, 1416, 4096, 16384, 16423, 16425, 11640]) {
      expect(P.clsOfBodyLen(n), String(n)).toBe(-1);
    }
  });

  it("clsFor picks the smallest class c with c ≥ len + 1 (exact boundaries, minCls)", () => {
    const cases: [number, number][] = [
      [0, 0],
      [255, 0],
      [256, 1],
      [1023, 1],
      [1024, 2],
      [4095, 2],
      [4096, 3],
      [16383, 3],
    ];
    for (const [len, cls] of cases) {
      expect(P.clsFor(len), `len ${len}`).toBe(cls);
      expect(P.pad(new Uint8Array(len), P.CLASSES).length).toBe(P.CLASSES[cls]);
    }
    expect(() => P.clsFor(16384)).toThrow(/too large/);
    expect(P.clsFor(0, 1)).toBe(1);
    expect(P.clsFor(0, 3)).toBe(3);
    expect(P.clsFor(1024, 1)).toBe(2);
    expect(P.clsFor(16383, 3)).toBe(3);
    for (let len = 0; len < 16384; len += 37) {
      const ref = [256, 1024, 4096, 16384].findIndex((c) => c >= len + 1);
      expect(P.clsFor(len)).toBe(ref);
    }
  });

  it("the text sizes of the §3.2 table land in their class (62-byte M header + 64-byte signature)", () => {
    const m = (text: number): number => 62 + text + 64;
    expect(P.clsFor(m(129))).toBe(0);
    expect(P.clsFor(m(130))).toBe(1);
    expect(P.clsFor(m(897))).toBe(1);
    expect(P.clsFor(m(898))).toBe(2);
    expect(P.clsFor(m(3969))).toBe(2);
    expect(P.clsFor(m(3970))).toBe(3);
    expect(P.clsFor(m(12000))).toBe(3);
  });
});

describe("sealing (KEM-DEM, §1.4)", () => {
  const kp = P.kemKeygen(fill(32, 0x5e));
  const other = P.kemKeygen(fill(32, 0x5f));
  const ctx = Uint8Array.of(1, 2, 3);

  it("matches the independent construction byte for byte (fixed randomness)", () => {
    for (const n of [0, 1, 32, 256, 1000]) {
      const pt = seqBytes(n, n);
      const calls: B[] = [];
      const box = withRandom(recording(detRandom(`seal ${n}`), calls), () => P.seal(kp.pk, LBL, ctx, pt));
      expect(calls.map((c) => c.length)).toEqual([64, 24]); // X-Wing encapsulation randomness, then the AEAD nonce
      expect(box.length).toBe(1120 + 24 + n + 16);
      expect(toHex(box)).toBe(toHex(refSeal(kp.pk, LBL, ctx, pt, calls[0], calls[1])));
      expect(toHex(refOpen(kp.sk, LBL, ctx, box))).toBe(toHex(pt));
      expect(toHex(P.open(kp.sk, LBL, ctx, box))).toBe(toHex(pt));
      expect(toHex(P.tryOpen(kp.sk, LBL, ctx, box)!)).toBe(toHex(pt));
    }
    // fresh randomness: two seals of the same plaintext differ
    expect(toHex(P.seal(kp.pk, LBL, ctx, s2b("x")))).not.toBe(toHex(P.seal(kp.pk, LBL, ctx, s2b("x"))));
  });

  it("the v2 seal info differs from v1 (segv.sh/v2/seal)", () => {
    const box = P.seal(kp.pk, LBL, ctx, s2b("secret"));
    expect(() => P1.open(kp.sk, LBL, ctx, box)).toThrow();
    expect(() => P.open(kp.sk, LBL, ctx, P1.seal(kp.pk, LBL, ctx, s2b("secret")))).toThrow();
  });

  it("wrong key / label / ctx / truncation throw in open and return null in tryOpen", () => {
    const box = P.seal(kp.pk, LBL, ctx, s2b("secret"));
    const bad: [string, () => unknown, () => unknown][] = [
      ["other key", () => P.open(other.sk, LBL, ctx, box), () => P.tryOpen(other.sk, LBL, ctx, box)],
      ["other label", () => P.open(kp.sk, LBL + "x", ctx, box), () => P.tryOpen(kp.sk, LBL + "x", ctx, box)],
      ["short ctx", () => P.open(kp.sk, LBL, ctx.subarray(0, 2), box), () => P.tryOpen(kp.sk, LBL, ctx.subarray(0, 2), box)],
      // the label / ctx boundary is unambiguous
      [
        "shifted boundary",
        () => P.open(kp.sk, LBL + "\u0001", ctx.subarray(1), box),
        () => P.tryOpen(kp.sk, LBL + "\u0001", ctx.subarray(1), box),
      ],
      ["truncated", () => P.open(kp.sk, LBL, ctx, box.subarray(0, box.length - 1)), () => P.tryOpen(kp.sk, LBL, ctx, box.subarray(1))],
      ["extended", () => P.open(kp.sk, LBL, ctx, cat(box, Uint8Array.of(0))), () => P.tryOpen(kp.sk, LBL, ctx, cat(box, Uint8Array.of(0)))],
      ["short", () => P.open(kp.sk, LBL, ctx, box.subarray(0, 1159)), () => P.tryOpen(kp.sk, LBL, ctx, box.subarray(0, 1159))],
      ["empty", () => P.open(kp.sk, LBL, ctx, new Uint8Array(0)), () => P.tryOpen(kp.sk, LBL, ctx, new Uint8Array(0))],
    ];
    for (const [name, open, tryOpen] of bad) {
      expect(throwsError(open), name).toBe(true);
      expect(tryOpen(), name).toBeNull();
    }
    expect(() => P.open(kp.sk, LBL, ctx, box.subarray(0, 1159))).toThrow(/short/);
    expect(() => P.seal(fill(1216, 0xff), LBL, ctx, s2b("x"))).toThrow(); // not a KEM public key
  });

  it("a bit flip anywhere (kct / nonce / ciphertext / tag) is rejected", () => {
    const box = P.seal(kp.pk, LBL, ctx, seqBytes(40));
    const s = survivors(
      box,
      [
        { name: "kct", start: 0, end: 1120 },
        { name: "kct x25519", start: 1088, end: 1120, every: true },
        { name: "nonce", start: 1120, end: 1144, every: true },
        { name: "ct", start: 1144, end: 1184, every: true },
        { name: "tag", start: 1184, end: 1200, every: true },
      ],
      (b) => P.open(kp.sk, LBL, ctx, b),
    );
    expect(s).toEqual([]);
  });

  it("dummySeal(label, ctx, n) is a real seal of random(n) to a fresh, discarded KEM key", () => {
    const calls: B[] = [];
    const box = withRandom(recording(detRandom("dummy"), calls), () => P.dummySeal(LBL, ctx, 100));
    expect(box.length).toBe(1160 + 100);
    const seed = calls.find((c) => c.length === 32)!;
    const pt = calls.find((c) => c.length === 100)!;
    expect(seed).toBeDefined();
    expect(pt).toBeDefined();
    // it opens with KEM.keygen(seed) (and nothing else): a genuine seal, indistinguishable by construction
    expect(toHex(refOpen(xwing.keygen(seed).secretKey, LBL, ctx, box))).toBe(toHex(pt));
    expect(P.tryOpen(kp.sk, LBL, ctx, box)).toBeNull();
    for (const n of [0, 1, 32, 256, 1416 - 1160]) {
      expect(P.dummySeal(LBL, ctx, n).length).toBe(P.seal(kp.pk, LBL, ctx, new Uint8Array(n)).length);
    }
    expect(toHex(P.dummySeal(LBL, ctx, 32))).not.toBe(toHex(P.dummySeal(LBL, ctx, 32)));
  });
});

describe("throwing decapsulation (§1.1; plan M1 test 9)", () => {
  const prf = fill(32, 0x11);
  const credId = seqBytes(20, 0x80);
  const cred = P.credKem(prf, credId);
  const rec = P.recoveryKem(seqBytes(20, 0x30));
  const r = prng(0x10e);
  const keys: [string, B][] = [
    ["alice identity", alice.id.kemSk],
    ["bob identity (the encapsulation target)", bob.id.kemSk],
    ["carol identity", carol.id.kemSk],
    ["passkey unlock key", cred.sk],
    ["recovery unlock key", rec.sk],
    ...Array.from({ length: 6 }, (_, i): [string, B] => [`random #${i}`, P.kemKeygen(r.bytes(32)).sk]),
  ];

  it("the reference: every low-order X25519 component makes X-Wing decapsulation throw, whatever the key", () => {
    for (const [name, u] of LOW_ORDER_U) {
      const kct = withX25519(u);
      for (const [kname, sk] of keys) expect(() => xwing.decapsulate(kct, sk), `${name} / ${kname}`).toThrow();
    }
    // a normal X25519 component does not throw (implicit rejection for the wrong key)
    for (const [kname, sk] of keys) expect(xwing.decapsulate(withX25519(9n), sk).length, kname).toBe(32);
  });

  it("tryDecap returns null, kemDecap throws, tryOpen returns null and open throws, for every recipient key", () => {
    for (const [name, u] of LOW_ORDER_U) {
      const kct = withX25519(u);
      const box = cat(kct, P.seal(bob.id.kemPk, LBL, CONV, seqBytes(32)).subarray(1120));
      for (const [kname, sk] of keys) {
        const what = `${name} / ${kname}`;
        expect(P.tryDecap(kct, sk), what).toBeNull();
        expect(() => P.kemDecap(kct, sk), what).toThrow();
        expect(P.tryOpen(sk, LBL, CONV, box), what).toBeNull();
        expect(throwsError(() => P.open(sk, LBL, CONV, box)), what).toBe(true);
      }
    }
    // the untouched ciphertext still decapsulates for its recipient
    expect(toHex(P.tryDecap(realKct, bob.id.kemSk)!)).toBe(toHex(xwing.decapsulate(realKct, bob.id.kemSk)));
  });

  it("openWrap and unwrapAK throw on a wrap whose kct has a low-order X25519 component; a trial unlock skips it", () => {
    const genuine = P.makeWrap(alice.uid, "passkey", credId, cred, alice.AK, alice.id, TS);
    const g = P.verifyWrap(genuine.record, genuine.sig, alice.id.sigPk);
    /** The client's unwrapFrom loop (§2.4): skip records that fail, including a decapsulation throw. */
    const trialUnlock = (recs: P.WrapRecord[], key: { sk: B; auth: B }): B | null => {
      for (const w of recs) {
        try {
          return P.unwrapAK(w, key, alice.id.sigPk);
        } catch {
          /* does not open */
        }
      }
      return null;
    };
    for (const [name, u] of LOW_ORDER_U) {
      const bad = { ...g, wrap: cat(withX25519(u), g.wrap.subarray(1120)) };
      for (const key of [cred, rec, { sk: alice.id.kemSk, auth: cred.auth }]) {
        expect(() => P.openWrap(bad, key), name).toThrow();
        expect(() => P.unwrapAK(bad, key, alice.id.sigPk), name).toThrow();
      }
      expect(trialUnlock([bad], cred), name).toBeNull();
      expect(toHex(trialUnlock([bad, g], cred)!), name).toBe(toHex(alice.AK));
    }
  });
});

// ───────────────────────── accounts ─────────────────────────

describe("accounts: identity derivation (§2.1)", () => {
  it("follows §2.1 with the v2 labels, including kS / rS / nS, and has no scan key", () => {
    const AK = seqBytes(32);
    const a = P.deriveIdentity(AK);
    expect(toHex(a.sigSk)).toBe(toHex(hkdfN(AK, "", "segv.sh/v2/id/ed25519")));
    expect(toHex(a.sigPk)).toBe(toHex(edPubRaw(a.sigSk)));
    const kem = xwing.keygen(hkdfN(AK, "", "segv.sh/v2/id/xwing"));
    expect(toHex(a.kemPk)).toBe(toHex(kem.publicKey));
    expect(toHex(a.kemSk)).toBe(toHex(kem.secretKey));
    expect(toHex(a.kS)).toBe(toHex(hkdfN(AK, "", "segv.sh/v2/self/aead")));
    expect(toHex(a.rS)).toBe(toHex(hkdfN(AK, "", "segv.sh/v2/self/route")));
    expect(toHex(a.nS)).toBe(toHex(hkdfN(AK, "", "segv.sh/v2/self/notify")));
    expect(Object.keys(a).sort()).toEqual(["kS", "kemPk", "kemSk", "nS", "rS", "sigPk", "sigSk"]);
    expect([a.sigSk, a.sigPk, a.kemSk, a.kemPk, a.kS, a.rS, a.nS].map((x) => x.length)).toEqual([32, 32, 32, 1216, 32, 32, 32]);
    expect(new Set([a.sigSk, a.kemSk, a.kS, a.rS, a.nS].map(toHex)).size).toBe(5);
    // deterministic, and unrelated to the v1 identity of the same AK
    expect(toHex(P.deriveIdentity(AK.slice()).kemPk)).toBe(toHex(a.kemPk));
    const v1 = P1.deriveIdentity(AK);
    expect(toHex(v1.sigPk)).not.toBe(toHex(a.sigPk));
    expect(toHex(v1.kemPk)).not.toBe(toHex(a.kemPk));
  });

  it("different AKs give unrelated keys; AK must be 32 bytes", () => {
    const a = P.deriveIdentity(fill(32, 1));
    const b = P.deriveIdentity(flip(fill(32, 1), 31, 7));
    for (const k of ["sigPk", "kemPk", "kS", "rS", "nS"] as const) expect(toHex(a[k]), k).not.toBe(toHex(b[k]));
    for (const n of [0, 16, 31, 33, 64]) expect(() => P.deriveIdentity(new Uint8Array(n))).toThrow(/32 bytes/);
  });
});

describe("accounts: bundles (§2.2)", () => {
  it("make → verify → parse with the exact v2 JSON (key order, no scan key)", () => {
    const u = alice.user;
    expect(u.uid).toBe(alice.uidS);
    expect(u.handle).toBe("alice");
    expect(toHex(u.sigPk)).toBe(toHex(alice.id.sigPk));
    expect(toHex(u.kemPk)).toBe(toHex(alice.id.kemPk));
    expect(u.bundle).toBe(alice.bundle);
    expect(u.bundleSig).toBe(alice.sig);
    expect(u.ts).toBe(TS + 0xa1);
    const want = `{"v":2,"uid":"${b64uN(alice.uid)}","handle":"alice","sig":"${b64uN(alice.id.sigPk)}","kem":"${b64uN(alice.id.kemPk)}","ts":${TS + 0xa1}}`;
    expect(alice.bundle).toBe(want);
    expect(Object.keys(JSON.parse(alice.bundle) as object)).toEqual([...P.BUNDLE_KEYS]);
    expect([...P.BUNDLE_KEYS]).toEqual(["v", "uid", "handle", "sig", "kem", "ts"]);
    expect(alice.bundle).not.toContain("scan");
    // canonical form: JSON.stringify(JSON.parse(text)) = text
    expect(JSON.stringify(JSON.parse(alice.bundle))).toBe(alice.bundle);
    // bundleSig = Sign(enc("segv.sh/v2/bundle", bundleBytes)), deterministic Ed25519, checked with node
    const msg = refEnc("segv.sh/v2/bundle", alice.bundle);
    expect(toHex(P.bundleSigMsg(alice.bundle))).toBe(toHex(msg));
    expect(edVerify(P.fromB64u(alice.sig), msg, alice.id.sigPk)).toBe(true);
    expect(b64uN(edSign(msg, alice.id.sigSk))).toBe(alice.sig);
  });

  it("makeBundle validates its inputs", () => {
    for (const h of ["al", "Alice", "a".repeat(21), "al-ice", "al ice", "ålice", "alice\n", "", "@alice"]) {
      expect(() => P.makeBundle(alice.uid, h, alice.id, TS), JSON.stringify(h)).toThrow(/handle/);
    }
    for (const h of ["abc", "a".repeat(20), "a_b_9", "___", "012"]) expect(() => P.makeBundle(alice.uid, h, alice.id, TS)).not.toThrow();
    for (const n of [15, 17]) expect(() => P.makeBundle(new Uint8Array(n), "alice", alice.id, TS)).toThrow(/uid/);
    for (const ts of [-1, 1.5, 2 ** 53, NaN]) expect(() => P.makeBundle(alice.uid, "alice", alice.id, ts)).toThrow(/ts/);
  });

  it("parseBundle rejects every malformed field, a v1 bundle, extra keys and a different key order", () => {
    const base = JSON.parse(alice.bundle) as Record<string, unknown>;
    const mut = (over: Record<string, unknown>) => JSON.stringify({ ...base, ...over });
    const { v, uid, handle, sig, kem, ts } = base;
    const bad: [string, string, string?][] = [
      ["not JSON", "{"],
      ["array", "[]"],
      ["null", "null"],
      ["string", '"x"'],
      ["v=1", mut({ v: 1 })],
      ['v="2"', mut({ v: "2" })],
      ["v missing", mut({ v: undefined })],
      ["scan key (v1 shape)", mut({ scan: P.b64u(new Uint8Array(32)) })],
      ["extra key", mut({ x: 1 })],
      ["reordered keys", JSON.stringify({ v, handle, uid, sig, kem, ts })],
      ["ts first", JSON.stringify({ ts, v, uid, handle, sig, kem })],
      ["uid 15 bytes", mut({ uid: P.b64u(new Uint8Array(15)) })],
      ["uid 17 bytes", mut({ uid: P.b64u(new Uint8Array(17)) })],
      ["uid non-canonical", mut({ uid: nonCanonical(alice.uidS) })],
      ["uid padded", mut({ uid: alice.uidS + "==" })],
      ["uid missing", mut({ uid: undefined })],
      ["handle uppercase", mut({ handle: "Alice" })],
      ["handle short", mut({ handle: "ab" })],
      ["handle number", mut({ handle: 123 })],
      ["sig 31 bytes", mut({ sig: P.b64u(new Uint8Array(31)) })],
      ["sig number", mut({ sig: 1 })],
      ["kem 1215 bytes", mut({ kem: P.b64u(new Uint8Array(1215)) })],
      ["kem 1217 bytes", mut({ kem: P.b64u(new Uint8Array(1217)) })],
      ["ts negative", mut({ ts: -1 })],
      ["ts float", mut({ ts: 1.5 })],
      ["ts string", mut({ ts: "1" })],
      ["ts unsafe", mut({ ts: 2 ** 53 })],
      ["signature 63 bytes", alice.bundle, P.b64u(new Uint8Array(63))],
      ["signature 65 bytes", alice.bundle, P.b64u(new Uint8Array(65))],
      ["signature not b64u", alice.bundle, "!!"],
    ];
    for (const [name, text, s] of bad) expect(() => P.parseBundle(text, s ?? alice.sig), name).toThrow(Error);
    // a genuine v1 bundle of the same account is not a v2 bundle
    const v1 = P1.makeBundle(alice.uid, "alice", P1.deriveIdentity(alice.AK), TS);
    expect(() => P.parseBundle(v1.bundle, v1.sig)).toThrow(/version/);
  });

  it("verifyBundle: the signature binds the exact bytes and the v2 label", () => {
    const tampered = alice.bundle.replace('"handle":"alice"', '"handle":"alicf"');
    expect(() => P.parseBundle(tampered, alice.sig)).not.toThrow();
    expect(() => P.verifyBundle(tampered, alice.sig)).toThrow(/signature/);
    const spaced = JSON.stringify(JSON.parse(alice.bundle), null, 1);
    expect(() => P.verifyBundle(spaced, alice.sig)).toThrow(Error);
    expect(() => P.verifyBundle(alice.bundle, bob.sig)).toThrow(/signature/);
    const forged = P.b64u(P.sign(P.bundleSigMsg(alice.bundle), bob.id.sigSk));
    expect(() => P.verifyBundle(alice.bundle, forged)).toThrow(/signature/);
    const noLabel = P.b64u(P.sign(s2b(alice.bundle), alice.id.sigSk));
    expect(() => P.verifyBundle(alice.bundle, noLabel)).toThrow(/signature/);
    const v1Label = P.b64u(P.sign(P1.bundleSigMsg(alice.bundle), alice.id.sigSk));
    expect(() => P.verifyBundle(alice.bundle, v1Label)).toThrow(/signature/);
    const wrapLabel = P.b64u(P.sign(P.wrapSigMsg(alice.bundle), alice.id.sigSk));
    expect(() => P.verifyBundle(alice.bundle, wrapLabel)).toThrow(/signature/);
  });

  it("fingerprint: H(enc('segv.sh/v2/fp', uid, sigPk, kemPk)) as 6 groups of 5 digits", () => {
    const fp = P.fingerprint(alice.uid, alice.id.sigPk, alice.id.kemPk);
    expect(fp).toMatch(/^\d{5}( \d{5}){5}$/);
    const h = sha(refEnc("segv.sh/v2/fp", alice.uid, alice.id.sigPk, alice.id.kemPk));
    const groups = Array.from({ length: 6 }, (_, k) => String(beToBig(h.subarray(5 * k, 5 * k + 5)) % 100000n).padStart(5, "0"));
    expect(fp).toBe(groups.join(" "));
    expect(P.fingerprint(bob.uid, alice.id.sigPk, alice.id.kemPk)).not.toBe(fp);
    expect(P.fingerprint(alice.uid, bob.id.sigPk, alice.id.kemPk)).not.toBe(fp);
    expect(P.fingerprint(alice.uid, alice.id.sigPk, bob.id.kemPk)).not.toBe(fp);
    // zero padding of a group: a digest whose groups are small is hard to hit, so check the formatter on all users
    for (const u of [alice, bob, carol]) {
      const g = P.fingerprint(u.uid, u.id.sigPk, u.id.kemPk).split(" ");
      const hh = sha(refEnc("segv.sh/v2/fp", u.uid, u.id.sigPk, u.id.kemPk));
      g.forEach((x, k) => expect(Number(x)).toBe(Number(beToBig(hh.subarray(5 * k, 5 * k + 5)) % 100000n)));
    }
  });

  it("pin = H(enc('segv.sh/v2/pin', bundleBytes, bundleSig))", () => {
    const sigRaw = P.fromB64u(alice.sig);
    expect(toHex(P.pin(alice.bundle, sigRaw))).toBe(toHex(sha(refEnc("segv.sh/v2/pin", alice.bundle, sigRaw))));
    expect(toHex(P.pin(alice.bundle, sigRaw))).not.toBe(toHex(P.pin(bob.bundle, sigRaw)));
    expect(toHex(P.pin(alice.bundle, sigRaw))).not.toBe(toHex(P.pin(alice.bundle, flip(sigRaw, 63))));
  });
});

describe("checkUserKeys / isBadSigPk (§2.1)", () => {
  // Every Ed25519 small-order encoding (the 8 torsion points, with both sign bits where a point exists) and some
  // non-canonical / non-point encodings. The classification is checked with the BigInt reference.
  const smallOrder: [string, string][] = [
    ["order 4 (y = 0)", "00".repeat(32)],
    ["order 4 (y = 0, other x)", "00".repeat(31) + "80"],
    ["identity (order 1)", "01" + "00".repeat(31)],
    ["order 2 (y = −1)", "ec" + "ff".repeat(30) + "7f"],
    ["order 8 (a)", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"],
    ["order 8 (a, other x)", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"],
    ["order 8 (b)", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"],
    ["order 8 (b, other x)", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"],
  ];
  const notPoints: [string, string][] = [
    ["identity with the sign bit (x = 0, sign 1)", "01" + "00".repeat(30) + "80"],
    ["y = −1 with the sign bit", "ec" + "ff".repeat(31)],
    ["y = p (non-canonical 0)", "ed" + "ff".repeat(30) + "7f"],
    ["y = p + 1 (non-canonical 1)", "ee" + "ff".repeat(30) + "7f"],
    ["all ones", "ff".repeat(32)],
  ];

  it("the reference agrees with the classification", () => {
    for (const [name, h] of smallOrder) {
      const p = edDecode(fromHex(h));
      expect(p, name).not.toBeNull();
      expect(edSmallOrder(p!), name).toBe(true);
    }
    for (const [name, h] of notPoints) expect(edDecode(fromHex(h)), name).toBeNull();
    for (const u of [alice, bob, carol]) expect(edSmallOrder(edDecode(u.id.sigPk)!)).toBe(false);
  });

  it("accepts real keys and rejects small-order, non-canonical and non-point signing keys", () => {
    for (const u of [alice, bob, carol]) {
      expect(P.isBadSigPk(u.id.sigPk)).toBe(false);
      expect(() => P.checkUserKeys(u.id.sigPk, u.id.kemPk)).not.toThrow();
    }
    for (const [name, h] of [...smallOrder, ...notPoints]) {
      expect(P.isBadSigPk(fromHex(h)), name).toBe(true);
      expect(() => P.checkUserKeys(fromHex(h), alice.id.kemPk), name).toThrow(/signing key/);
    }
    // y values with no x on the curve
    let found = 0;
    for (let y = 2n; found < 5; y++) {
      const b = le32(y);
      if (edDecode(b) !== null) continue;
      found++;
      expect(P.isBadSigPk(b), `y = ${y}`).toBe(true);
    }
    for (const n of [0, 31, 33, 64]) expect(P.isBadSigPk(new Uint8Array(n)), `${n} bytes`).toBe(true);
    // a mixed-order key (real key + an order-8 point) is not of small order: §2.1 accepts it
    const mixed = edEncode(edAdd(edDecode(alice.id.sigPk)!, edDecode(fromHex(smallOrder[4][1]))!));
    expect(edSmallOrder(edDecode(mixed)!)).toBe(false);
    expect(P.isBadSigPk(mixed)).toBe(false);
  });

  it("rejects KEM keys that cannot be encapsulated to", () => {
    const pk = alice.id.kemPk;
    const lowX = pk.slice();
    lowX.set(new Uint8Array(32), 1184); // the X25519 component is u = 0 (low order)
    const lowX1 = pk.slice();
    lowX1.set(le32(1n), 1184);
    const badMl = pk.slice();
    badMl.fill(0xff, 0, 2); // an ML-KEM coefficient ≥ q
    const bad: [string, B][] = [
      ["all 0xff", fill(1216, 0xff)],
      ["1215 bytes", pk.subarray(0, 1215)],
      ["1217 bytes", cat(pk, Uint8Array.of(0))],
      ["empty", new Uint8Array(0)],
      ["low-order X25519 u = 0", lowX],
      ["low-order X25519 u = 1", lowX1],
      ["ML-KEM coefficient out of range", badMl],
    ];
    for (const [name, k] of bad) expect(() => P.checkUserKeys(alice.id.sigPk, k), name).toThrow(/KEM key/);
  });
});

describe("signature strictness (§1.1: RFC 8032, zip215 false)", () => {
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const fromLe = (b: B): bigint => b.reduceRight((acc, x) => (acc << 8n) | BigInt(x), 0n);

  it("rejects the universal forgery under a small-order key and malleated signatures (S + L)", () => {
    const A = fromHex("01" + "00".repeat(31)); // identity
    const sig = cat(A, new Uint8Array(32)); // R = identity, S = 0
    for (const m of ["bundle", "", "other"]) expect(P.verify(sig, s2b(m), A), m).toBe(false);
    expect(() => P.verifyBundle(JSON.stringify({ ...(JSON.parse(alice.bundle) as object), sig: P.b64u(A) }), P.b64u(sig))).toThrow(
      /signature/,
    );
    const msg = P.bundleSigMsg(alice.bundle);
    const good = P.fromB64u(alice.sig);
    expect(P.verify(good, msg, alice.id.sigPk)).toBe(true);
    const mall = cat(good.subarray(0, 32), le32(fromLe(good.subarray(32)) + L));
    expect(P.verify(mall, msg, alice.id.sigPk)).toBe(false);
    expect(edVerify(good, msg, alice.id.sigPk)).toBe(true);
  });
});

// ───────────────────────── unlock secrets and wraps ─────────────────────────

describe("unlock secrets and wrap records (§2.3, §2.4)", () => {
  const prf = fill(32, 0x11);
  const credId = seqBytes(20, 0x80);
  const cred = P.credKem(prf, credId);
  const code = seqBytes(20, 0x30);
  const rec = P.recoveryKem(code);
  const pkWrap = P.makeWrap(alice.uid, "passkey", credId, cred, alice.AK, alice.id, TS);
  const recWrap = P.makeWrap(alice.uid, "recovery", rec.id, rec, alice.AK, alice.id, TS + 1);
  const AKW = "segv.sh/v2/ak-wrap";
  /** Signs an arbitrary record as `signer` (what anyone can POST to /api/v2/wraps for their own uid). */
  const signRecord = (raw: Record<string, unknown>, signer: TUser) => {
    const record = JSON.stringify(raw);
    return { record, sig: P.b64u(P.sign(P.wrapSigMsg(record), signer.id.sigSk)) };
  };

  it("PRF input, credKem and recoveryKem follow the v2 KDFs", () => {
    expect(P.PRF_INPUT).toBe("segv.sh/v2/prf");
    const credSeed = hkdfN(prf, credId, "segv.sh/v2/cred/xwing");
    expect(toHex(cred.pk)).toBe(toHex(xwing.keygen(credSeed).publicKey));
    expect(toHex(cred.sk)).toBe(toHex(xwing.keygen(credSeed).secretKey));
    expect(toHex(cred.auth)).toBe(toHex(hkdfN(prf, credId, "segv.sh/v2/cred/auth")));
    for (const o of [P.credKem(prf, seqBytes(20, 0x81)), P.credKem(fill(32, 0x12), credId)]) {
      expect(toHex(o.pk)).not.toBe(toHex(cred.pk));
      expect(toHex(o.auth)).not.toBe(toHex(cred.auth));
    }
    for (const n of [0, 31, 33]) expect(() => P.credKem(new Uint8Array(n), credId)).toThrow(/32 bytes/);
    const recSeed = hkdfN(code, "", "segv.sh/v2/recovery/xwing");
    expect(toHex(rec.pk)).toBe(toHex(xwing.keygen(recSeed).publicKey));
    expect(toHex(rec.sk)).toBe(toHex(xwing.keygen(recSeed).secretKey));
    expect(toHex(rec.auth)).toBe(toHex(hkdfN(code, "", "segv.sh/v2/recovery/auth")));
    expect(toHex(rec.id)).toBe(toHex(hkdfN(code, "", "segv.sh/v2/recovery/id", 16)));
    expect(new Set([rec.auth, rec.sk, rec.id].map(toHex)).size).toBe(3);
    for (const n of [0, 19, 21, 32]) expect(() => P.recoveryKem(new Uint8Array(n))).toThrow(/20 bytes/);
    // the v1 derivations of the same secrets differ
    expect(toHex(P1.credKem(prf, credId).auth)).not.toBe(toHex(cred.auth));
    expect(toHex(P1.recoveryKem(code).id)).not.toBe(toHex(rec.id));
  });

  it("makeWrap → verifyWrap → openWrap / unwrapAK, with the exact record and the segv.sh/v2/ak-wrap seal", () => {
    expect(P.AK_WRAP_LABEL).toBe(AKW);
    for (const [w, key, kind, id, ts] of [
      [pkWrap, cred, "passkey", credId, TS],
      [recWrap, rec, "recovery", rec.id, TS + 1],
    ] as const) {
      const r = P.verifyWrap(w.record, w.sig, alice.id.sigPk);
      expect(r.kind).toBe(kind);
      expect(r.uid).toBe(alice.uidS);
      expect(toHex(r.id)).toBe(toHex(id));
      expect(toHex(r.kemPk)).toBe(toHex(key.pk));
      expect(r.wrap.length).toBe(1192);
      expect(r.ts).toBe(ts);
      expect(w.record).toBe(
        `{"v":2,"uid":"${alice.uidS}","kind":"${kind}","id":"${b64uN(id)}","kem":"${b64uN(key.pk)}","wrap":"${b64uN(r.wrap)}","ts":${ts}}`,
      );
      expect(Object.keys(JSON.parse(w.record) as object)).toEqual([...P.WRAP_KEYS]);
      expect(toHex(P.openWrap(r, key))).toBe(toHex(alice.AK));
      expect(toHex(P.unwrapAK(r, key, alice.id.sigPk))).toBe(toHex(alice.AK));
      // independent open with ctx = enc(uid, id, auth) ...
      expect(toHex(refOpen(key.sk, AKW, refEnc(alice.uid, id, key.auth), r.wrap))).toBe(toHex(alice.AK));
      // ... and without auth, or with the v1 label, it does not open
      expect(() => refOpen(key.sk, AKW, refEnc(alice.uid, id), r.wrap)).toThrow();
      expect(() => refOpen(key.sk, "ak-wrap", refEnc(alice.uid, id, key.auth), r.wrap)).toThrow();
      // the record signature is Sign(enc("segv.sh/v2/wrap", recordBytes)), deterministic
      const msg = refEnc("segv.sh/v2/wrap", w.record);
      expect(toHex(P.wrapSigMsg(w.record))).toBe(toHex(msg));
      expect(edVerify(P.fromB64u(w.sig), msg, alice.id.sigPk)).toBe(true);
      expect(b64uN(edSign(msg, alice.id.sigSk))).toBe(w.sig);
      expect(w.record).not.toContain(P.b64u(key.auth));
    }
    expect([...P.WRAP_KEYS]).toEqual(["v", "uid", "kind", "id", "kem", "wrap", "ts"]);
    // a wrap built independently (fixed randomness) opens with proto2
    const box = refSeal(cred.pk, AKW, refEnc(alice.uid, credId, cred.auth), alice.AK, seqBytes(64, 1), seqBytes(24, 2));
    expect(toHex(P.openWrap({ uid: alice.uidS, id: credId, wrap: box }, cred))).toBe(toHex(alice.AK));
  });

  it("makeWrap validates its inputs", () => {
    expect(() => P.makeWrap(new Uint8Array(15), "passkey", credId, cred, alice.AK, alice.id, TS)).toThrow(/uid/);
    expect(() => P.makeWrap(alice.uid, "passkey", new Uint8Array(0), cred, alice.AK, alice.id, TS)).toThrow(/id/);
    expect(() => P.makeWrap(alice.uid, "passkey", new Uint8Array(1024), cred, alice.AK, alice.id, TS)).toThrow(/id/);
    expect(() => P.makeWrap(alice.uid, "recovery", new Uint8Array(15), rec, alice.AK, alice.id, TS)).toThrow(/id/);
    expect(() => P.makeWrap(alice.uid, "recovery", new Uint8Array(20), rec, alice.AK, alice.id, TS)).toThrow(/id/);
    expect(() => P.makeWrap(alice.uid, "passkey", credId, cred, new Uint8Array(31), alice.id, TS)).toThrow(/AK/);
    expect(P.parseWrap(P.makeWrap(alice.uid, "passkey", new Uint8Array(1023), cred, alice.AK, alice.id, TS).record, pkWrap.sig).id.length).toBe(1023);
    expect(P.parseWrap(P.makeWrap(alice.uid, "passkey", new Uint8Array(1), cred, alice.AK, alice.id, TS).record, pkWrap.sig).id.length).toBe(1);
  });

  it("parseWrap rejects every malformed field, a v1 record, extra keys and a different key order", () => {
    const base = JSON.parse(pkWrap.record) as Record<string, unknown>;
    const mut = (over: Record<string, unknown>) => JSON.stringify({ ...base, ...over });
    const { v, uid, kind, id, kem, wrap, ts } = base;
    const bad: [string, string][] = [
      ["not JSON", "x"],
      ["array", "[1]"],
      ["v=1", mut({ v: 1 })],
      ["v missing", mut({ v: undefined })],
      ["extra key", mut({ x: 1 })],
      ["reordered", JSON.stringify({ v, kind, uid, id, kem, wrap, ts })],
      ["kind other", mut({ kind: "password" })],
      ["kind missing", mut({ kind: undefined })],
      ["uid 15", mut({ uid: P.b64u(new Uint8Array(15)) })],
      ["uid missing", mut({ uid: undefined })],
      ["id empty", mut({ id: "" })],
      ["id 1024 bytes", mut({ id: P.b64u(new Uint8Array(1024)) })],
      ["id number", mut({ id: 5 })],
      ["id non-canonical", mut({ id: nonCanonical(base.id as string) })],
      ["recovery id 15 bytes", mut({ kind: "recovery", id: P.b64u(new Uint8Array(15)) })],
      ["recovery id 20 bytes", mut({ kind: "recovery" })],
      ["kem short", mut({ kem: P.b64u(new Uint8Array(1215)) })],
      ["wrap short", mut({ wrap: P.b64u(new Uint8Array(1191)) })],
      ["wrap long", mut({ wrap: P.b64u(new Uint8Array(1193)) })],
      ["ts float", mut({ ts: 0.5 })],
      ["ts negative", mut({ ts: -1 })],
      ["ts missing", mut({ ts: undefined })],
    ];
    for (const [name, text] of bad) expect(() => P.parseWrap(text, pkWrap.sig), name).toThrow(Error);
    expect(() => P.parseWrap(pkWrap.record, P.b64u(new Uint8Array(65)))).toThrow();
    expect(P.parseWrap(mut({ kind: "recovery", id: P.b64u(new Uint8Array(16)) }), pkWrap.sig).kind).toBe("recovery");
    const v1 = P1.makeWrap(alice.uid, "passkey", credId, P1.credKem(prf, credId), alice.AK, P1.deriveIdentity(alice.AK), TS);
    expect(() => P.parseWrap(v1.record, v1.sig)).toThrow(/version/);
  });

  it("verifyWrap rejects the wrong owner, a tampered record and other signature labels", () => {
    expect(() => P.verifyWrap(pkWrap.record, pkWrap.sig, bob.id.sigPk)).toThrow(/signature/);
    expect(() => P.verifyWrap(pkWrap.record, recWrap.sig, alice.id.sigPk)).toThrow(/signature/);
    const tampered = pkWrap.record.replace(`"ts":${TS}`, `"ts":${TS + 1}`);
    expect(tampered).not.toBe(pkWrap.record);
    expect(() => P.verifyWrap(tampered, pkWrap.sig, alice.id.sigPk)).toThrow(/signature/);
    for (const msg of [s2b(pkWrap.record), P.bundleSigMsg(pkWrap.record), P1.wrapSigMsg(pkWrap.record)]) {
      expect(() => P.verifyWrap(pkWrap.record, P.b64u(P.sign(msg, alice.id.sigSk)), alice.id.sigPk)).toThrow(/signature/);
    }
  });

  it("auth binding: a wrap opens only with the matching auth and KEM key", () => {
    const pw = P.parseWrap(pkWrap.record, pkWrap.sig);
    const rw = P.parseWrap(recWrap.record, recWrap.sig);
    const wrongAuths: [string, B][] = [
      ["zero", new Uint8Array(32)],
      ["empty", new Uint8Array(0)],
      ["truncated", cred.auth.subarray(0, 31)],
      ["extended", cat(cred.auth, Uint8Array.of(0))],
      ["recovery auth", rec.auth],
      ["other PRF", P.credKem(fill(32, 0x12), credId).auth],
      ["other credId", P.credKem(prf, seqBytes(20, 0x81)).auth],
      ["v1 auth", P1.credKem(prf, credId).auth],
    ];
    for (const [name, auth] of wrongAuths) expect(() => P.openWrap(pw, { sk: cred.sk, auth }), name).toThrow();
    for (let i = 0; i < 32; i++) expect(() => P.openWrap(pw, { sk: cred.sk, auth: flip(cred.auth, i, i % 8) }), `auth[${i}]`).toThrow();
    expect(() => P.openWrap(rw, { sk: rec.sk, auth: cred.auth })).toThrow();
    expect(() => P.openWrap(pw, { sk: rec.sk, auth: cred.auth })).toThrow();
    expect(() => P.openWrap(rw, { sk: cred.sk, auth: rec.auth })).toThrow();
    expect(() => P.unwrapAK(pw, rec, alice.id.sigPk)).toThrow();
    expect(() => P.unwrapAK(rw, cred, alice.id.sigPk)).toThrow();
  });

  it("unwrapAK adds the key check (§2.4 step 3) and the record signature check", () => {
    const otherAK = fill(32, 0x99);
    const ow = P.makeWrap(alice.uid, "passkey", credId, cred, otherAK, alice.id, TS);
    const w = P.verifyWrap(ow.record, ow.sig, alice.id.sigPk);
    expect(toHex(P.openWrap(w, cred))).toBe(toHex(otherAK));
    expect(() => P.unwrapAK(w, cred, alice.id.sigPk)).toThrow(/key check/);
    expect(() => P.unwrapAK(P.parseWrap(pkWrap.record, pkWrap.sig), cred, bob.id.sigPk)).toThrow(/key check/);
    // a record whose signature does not verify (parseWrap does not check it)
    const unsigned = P.parseWrap(pkWrap.record, P.b64u(new Uint8Array(64)));
    expect(toHex(P.openWrap(unsigned, cred))).toBe(toHex(alice.AK));
    expect(() => P.unwrapAK(unsigned, cred, alice.id.sigPk)).toThrow(/signature/);
    // the AK inside an authentic box must be exactly 32 bytes
    for (const n of [0, 31, 33]) {
      const box = P.seal(cred.pk, AKW, P.enc(alice.uid, credId, cred.auth), new Uint8Array(n));
      expect(() => P.openWrap({ uid: alice.uidS, id: credId, wrap: box }, cred), `AK of ${n} bytes`).toThrow(/AK length/);
    }
  });

  it("a wrap re-labelled with another uid or id (or uid and id swapped) does not open", () => {
    const r = P.parseWrap(pkWrap.record, pkWrap.sig);
    expect(() => P.openWrap({ ...r, uid: bob.uidS }, cred)).toThrow();
    expect(() => P.openWrap({ ...r, id: seqBytes(20, 0x81) }, cred)).toThrow();
    expect(() => P.openWrap({ ...r, id: credId.subarray(0, 19) }, cred)).toThrow();
    const rr = P.parseWrap(recWrap.record, recWrap.sig);
    expect(() => P.openWrap({ uid: P.b64u(rr.id), id: P.fromB64u(rr.uid), wrap: rr.wrap }, rec)).toThrow();
    expect(() => refOpen(rec.sk, AKW, refEnc(alice.uid, rec.auth, rec.id), rr.wrap)).toThrow();
    const raw = JSON.parse(pkWrap.record) as Record<string, unknown>;
    const moved = signRecord({ ...raw, id: P.b64u(seqBytes(20, 0x90)) }, alice);
    expect(() => P.unwrapAK(P.verifyWrap(moved.record, moved.sig, alice.id.sigPk), cred, alice.id.sigPk)).toThrow();
  });

  describe("an attacker files a wrap of their own AK under the victim's public id", () => {
    const vRec = P.parseWrap(recWrap.record, recWrap.sig);
    const vPk = P.parseWrap(pkWrap.record, pkWrap.sig);
    /** Every "auth" the attacker can compute from public data (plus their own secrets). */
    const guesses = (w: P.WrapRecord): [string, B][] => [
      ["zero", new Uint8Array(32)],
      ["empty", new Uint8Array(0)],
      ["id", w.id],
      ["victim uid", P.fromB64u(w.uid)],
      ["H(kem pk)", sha(w.kemPk)],
      ["H(victim box)", sha(w.wrap)],
      ["H(record)", sha(s2b(w.record))],
      ["recovery KDF on the id", hkdfN(w.id, "", "segv.sh/v2/recovery/auth")],
      ["cred KDF on the kem pk", hkdfN(w.kemPk, w.id, "segv.sh/v2/cred/auth")],
      ["attacker's own recovery auth", P.recoveryKem(seqBytes(20, 0x70)).auth],
      ["attacker's PRF with the victim's credId", P.credKem(fill(32, 0x77), w.id).auth],
      ...Array.from({ length: 4 }, (_, i): [string, B] => [`random #${i}`, prng(0xa77ac + i).bytes(32)]),
    ];

    it("the forged records are well-formed and attacker-signed, but cannot be filed under the victim's uid", () => {
      const f = P.makeWrap(carol.uid, "recovery", vRec.id, { pk: vRec.kemPk, auth: new Uint8Array(32) }, carol.AK, carol.id, TS + 9);
      const r = P.verifyWrap(f.record, f.sig, carol.id.sigPk);
      expect(toHex(r.id)).toBe(toHex(rec.id));
      const asVictim = signRecord({ ...(JSON.parse(f.record) as Record<string, unknown>), uid: alice.uidS }, carol);
      expect(() => P.verifyWrap(asVictim.record, asVictim.sig, alice.id.sigPk)).toThrow(/signature/);
    });

    it("no attacker wrap opens with the victim's recovery or passkey secret", () => {
      for (const [kind, v, key] of [
        ["recovery", vRec, rec],
        ["passkey", vPk, cred],
      ] as const) {
        for (const [name, auth] of guesses(v)) {
          const f = P.makeWrap(carol.uid, kind, v.id, { pk: v.kemPk, auth }, carol.AK, carol.id, TS + 9);
          const r = P.verifyWrap(f.record, f.sig, carol.id.sigPk);
          expect(() => P.openWrap(r, key), `${kind}: ${name}`).toThrow();
          expect(() => P.unwrapAK(r, key, carol.id.sigPk), `${kind}: ${name}`).toThrow();
        }
        // the construction without auth (ctx = enc(uid, id)) does not open either
        const box = P.seal(v.kemPk, AKW, P.enc(carol.uid, v.id), carol.AK);
        const f = signRecord({ v: 2, uid: carol.uidS, kind, id: P.b64u(v.id), kem: P.b64u(v.kemPk), wrap: P.b64u(box), ts: TS + 9 }, carol);
        expect(() => P.openWrap(P.verifyWrap(f.record, f.sig, carol.id.sigPk), key), kind).toThrow();
        // copying the victim's box into the attacker's record does not open (bound to the victim's uid)
        const c = signRecord({ v: 2, uid: carol.uidS, kind, id: P.b64u(v.id), kem: P.b64u(v.kemPk), wrap: P.b64u(v.wrap), ts: TS + 9 }, carol);
        expect(() => P.openWrap(P.verifyWrap(c.record, c.sig, carol.id.sigPk), key), kind).toThrow();
      }
    });

    it("a recovery login over every record filed under recId still finds only the victim", () => {
      const owners = new Map([alice, bob, carol].map((u) => [u.uidS, u.user]));
      const login = (c: B, log: { record: string; sig: string }[]) => {
        const k = P.recoveryKem(c);
        const opened: { uid: string; AK: B }[] = [];
        for (const w of log) {
          try {
            const r = P.parseWrap(w.record, w.sig);
            const owner = owners.get(r.uid);
            if (!owner || !P.equalBytes(r.id, k.id) || r.kind !== "recovery") continue;
            opened.push({ uid: r.uid, AK: P.unwrapAK(P.verifyWrap(w.record, w.sig, owner.sigPk), k, owner.sigPk) });
          } catch {
            /* not ours */
          }
        }
        return new Set(opened.map((o) => o.uid)).size === 1 ? opened[0] : null; // §2.4 step 4
      };
      const forged = guesses(vRec).map(([, auth]) =>
        P.makeWrap(carol.uid, "recovery", vRec.id, { pk: vRec.kemPk, auth }, carol.AK, carol.id, TS + 9),
      );
      const got = login(code, [...forged, recWrap]);
      expect(got?.uid).toBe(alice.uidS);
      expect(toHex(got!.AK)).toBe(toHex(alice.AK));
      expect(login(code, forged)).toBeNull();
    });
  });

  it("a bit flip in any region of the wrap is rejected", () => {
    const r = P.parseWrap(pkWrap.record, pkWrap.sig);
    const s = survivors(
      r.wrap,
      [
        { name: "kct", start: 0, end: 1120 },
        { name: "nonce", start: 1120, end: 1144, every: true },
        { name: "ct", start: 1144, end: 1176, every: true },
        { name: "tag", start: 1176, end: 1192, every: true },
      ],
      (b) => P.unwrapAK({ ...r, wrap: b }, cred, alice.id.sigPk),
      2,
    );
    expect(s).toEqual([]);
  }, 30_000);
});

describe("directory prefixes hpre / upre (§2.5)", () => {
  const u32ref = (b: B): number => Number(beToBig(b.subarray(0, 4)));

  it("are u32 of the first 4 bytes of the labelled hash, without sign bugs", () => {
    let high = 0;
    for (let i = 0; i < 300; i++) {
      const handle = `user_${i}`;
      const h = P.hpre(handle);
      expect(h).toBe(u32ref(sha(refEnc("segv.sh/v2/dir/handle", handle))));
      expect(Number.isInteger(h) && h >= 0 && h <= 0xffffffff).toBe(true);
      const uid = seqBytes(16, i);
      const u = P.upre(uid);
      expect(u).toBe(u32ref(sha(refEnc("segv.sh/v2/dir/uid", uid))));
      expect(Number.isInteger(u) && u >= 0 && u <= 0xffffffff).toBe(true);
      if (h >= 2 ** 31) high++;
    }
    expect(high).toBeGreaterThan(50); // values with the top bit set stay positive
    expect(P.hpre("alice")).not.toBe(P.upre(s2b("alice")));
  });
});

// ───────────────────────── derivations (§4) ─────────────────────────

describe("self lane labels (§4.1)", () => {
  const { rS, nS } = alice.id;

  it("Lself / Lsnap / Tself follow the spec", () => {
    for (const [E, n] of [
      [0, 0],
      [3, 7],
      [0xfffe, 0xffffffff],
    ]) {
      expect(toHex(P.Lself(rS, E, n))).toBe(toHex(tr16(hmacN(rS, refEnc("segv.sh/v2/lab/self", be16(E), be32(n))))));
      expect(toHex(P.Lsnap(rS, E, n))).toBe(toHex(tr16(hmacN(rS, refEnc("segv.sh/v2/lab/snap", be16(E), be32(n))))));
      expect(P.Lself(rS, E, n).length).toBe(16);
    }
    expect(toHex(P.topicSelf(nS))).toBe(toHex(tr16(hmacN(nS, "segv.sh/v2/topic/self"))));
    expect(P.topicSelf(nS).length).toBe(16);
  });

  it("rejects E and n outside u16 / u32 instead of aliasing", () => {
    for (const f of [P.Lself, P.Lsnap]) {
      expect(() => f(rS, 0x10000, 0)).toThrow();
      expect(() => f(rS, -1, 0)).toThrow();
      expect(() => f(rS, 0, 2 ** 32)).toThrow();
      expect(() => f(rS, 0, 0.5)).toThrow();
    }
  });
});

describe("conversation epochs (§4.2)", () => {
  it("epochKeys rk / mk / kc / nk / dk follow the spec and are distinct", () => {
    const k = P.epochKeys(EK, CONV, 5);
    for (const [name, what] of [
      ["rk", "route"],
      ["mk", "msg"],
      ["kc", "commit"],
      ["nk", "notify"],
      ["dk", "desc"],
    ] as const) {
      expect(toHex(k[name]), name).toBe(toHex(hkdfN(EK, CONV, refEnc(`segv.sh/v2/ep/${what}`, be32(5)))));
    }
    expect(Object.keys(k).sort()).toEqual(["dk", "kc", "mk", "nk", "rk"]);
    expect(new Set(Object.values(k).map(toHex)).size).toBe(5);
    expect(toHex(P.epochKeys(EK.slice(), CONV.slice(), 5).mk)).toBe(toHex(k.mk));
    expect(toHex(P1.epochKeys(EK, CONV, 5).mk)).not.toBe(toHex(k.mk));
  });

  it("every key changes with EK, conv and e; bad inputs throw", () => {
    const all = new Set<string>();
    let count = 0;
    for (const ek of [EK, fill(32, 0xe1)])
      for (const conv of [CONV, seqBytes(16, 0x61)])
        for (const e of [0, 1, 2, P.E_MAX]) {
          for (const x of Object.values(P.epochKeys(ek, conv, e))) {
            all.add(toHex(x));
            count++;
          }
        }
    expect(all.size).toBe(count);
    expect(P.E_MAX).toBe(0xffffffff);
    expect(() => P.epochKeys(new Uint8Array(31), CONV, 0)).toThrow();
    expect(() => P.epochKeys(EK, new Uint8Array(15), 0)).toThrow();
    expect(() => P.epochKeys(EK, CONV, -1)).toThrow();
    expect(() => P.epochKeys(EK, CONV, 2 ** 32)).toThrow();
    expect(() => P.epochKeys(EK, CONV, 0.5)).toThrow();
  });

  it("ekc = H(enc('segv.sh/v2/ekc', conv, u32 e, EK))", () => {
    expect(toHex(P.ekc(CONV, 7, EK))).toBe(toHex(sha(refEnc("segv.sh/v2/ekc", CONV, be32(7), EK))));
    expect(toHex(P.ekc(CONV, 7, EK))).not.toBe(toHex(P.ekc(CONV, 8, EK)));
    expect(() => P.ekc(CONV, 2 ** 32, EK)).toThrow();
  });

  it("Lmsg / Lctl / T_e follow the spec", () => {
    const { rk, nk } = P.epochKeys(EK, CONV, 3);
    for (const [l, E, n] of [
      [0, 0, 0],
      [3, 7, 9],
      [31, 0xfffe, 0xffffffff],
      [0xffff, 1, 1],
    ]) {
      expect(toHex(P.Lmsg(rk, l, E, n))).toBe(toHex(tr16(hmacN(rk, refEnc("segv.sh/v2/lab/msg", be16(l), be16(E), be32(n))))));
    }
    for (const [E, k] of [
      [0, 0],
      [7, 9],
      [0xfffe, 0xffffffff],
    ]) {
      expect(toHex(P.Lctl(rk, E, k))).toBe(toHex(tr16(hmacN(rk, refEnc("segv.sh/v2/lab/ctl", be16(E), be32(k))))));
    }
    expect(toHex(P.topicConv(nk))).toBe(toHex(tr16(hmacN(nk, "segv.sh/v2/topic/conv"))));
  });

  it("labels are distinct across lane, era, slot, epoch and label kind", () => {
    const seen = new Set<string>();
    let count = 0;
    const add = (b: B) => {
      expect(b.length).toBe(16);
      seen.add(toHex(b));
      count++;
    };
    for (const e of [0, 1]) {
      const { rk } = P.epochKeys(EK, CONV, e);
      for (const E of [0, 1])
        for (let n = 0; n < 16; n++) {
          add(P.Lctl(rk, E, n));
          for (let l = 0; l < 8; l++) add(P.Lmsg(rk, l, E, n));
          // the same key and (E, n) under the other label kinds
          add(P.Lself(rk, E, n));
          add(P.Lsnap(rk, E, n));
          add(P.Lhello(rk, E, n));
        }
      add(P.topicConv(rk));
      add(P.topicSelf(rk));
      add(P.topicLink(rk));
    }
    expect(seen.size).toBe(count);
  });

  it("rejects lane, E and n outside u16 / u16 / u32", () => {
    const { rk } = P.epochKeys(EK, CONV, 0);
    expect(() => P.Lmsg(rk, 0x10000, 0, 0)).toThrow();
    expect(() => P.Lmsg(rk, 0, 0x10000, 0)).toThrow();
    expect(() => P.Lmsg(rk, 0, 0, 2 ** 32)).toThrow();
    expect(() => P.Lmsg(rk, -1, 0, 0)).toThrow();
    expect(() => P.Lctl(rk, 0x10000, 0)).toThrow();
    expect(() => P.Lctl(rk, 0, -1)).toThrow();
  });
});

describe("links (§4.3)", () => {
  const s = seqBytes(16, 0x90);

  it("linkKeys, Lhello and Tlink follow the spec", () => {
    const k = P.linkKeys(s);
    expect(toHex(k.kL)).toBe(toHex(hkdfN(s, "", "segv.sh/v2/link/route")));
    expect(toHex(k.mL)).toBe(toHex(hkdfN(s, "", "segv.sh/v2/link/aead")));
    expect(toHex(k.nL)).toBe(toHex(hkdfN(s, "", "segv.sh/v2/link/notify")));
    expect(new Set([k.kL, k.mL, k.nL].map(toHex)).size).toBe(3);
    for (const [E, j] of [
      [0, 0],
      [5, 3],
      [0xfffe, 0xffffffff],
    ]) {
      expect(toHex(P.Lhello(k.kL, E, j))).toBe(toHex(tr16(hmacN(k.kL, refEnc("segv.sh/v2/lab/hello", be16(E), be32(j))))));
    }
    expect(toHex(P.topicLink(k.nL))).toBe(toHex(tr16(hmacN(k.nL, "segv.sh/v2/topic/link"))));
    for (const n of [0, 15, 17, 32]) expect(() => P.linkKeys(new Uint8Array(n))).toThrow(/16 bytes/);
  });

  it("encodeLink / parseLink: https://<host>/i# + b64u(u8 2 ‖ s ‖ uid)", () => {
    const url = P.encodeLink("segv.sh", s, alice.uid);
    expect(url).toBe(`https://segv.sh/i#${b64uN(cat(Uint8Array.of(2), s, alice.uid))}`);
    const p = P.parseLink(url);
    expect(p.host).toBe("segv.sh");
    expect(toHex(p.s)).toBe(toHex(s));
    expect(toHex(p.uid)).toBe(toHex(alice.uid));
    expect(toHex(P.parseLink(`  ${url}\n`).s)).toBe(toHex(s));
    const frag = (b: B) => `https://segv.sh/i#${b64uN(b)}`;
    const bad = [
      frag(cat(Uint8Array.of(1), s, alice.uid)), // version 1
      frag(cat(Uint8Array.of(3), s, alice.uid)),
      frag(cat(Uint8Array.of(2), s, alice.uid.subarray(1))), // 32 bytes
      frag(cat(Uint8Array.of(2), s, alice.uid, Uint8Array.of(0))), // 34 bytes
      url.replace("https://", "http://"),
      url.replace("/i#", "/j#"),
      url.replace("/i#", "/i?x#"),
      url + "=",
      url.replace("#", "#+").slice(0, -1),
      "",
    ];
    for (const u of bad) expect(() => P.parseLink(u), u).toThrow(/link/);
    expect(() => P.encodeLink("segv.sh", s.subarray(1), alice.uid)).toThrow();
    expect(() => P.encodeLink("segv.sh", s, alice.uid.subarray(1))).toThrow();
  });
});

describe("server routing (§4.4)", () => {
  const ROUTE_KEY = seqBytes(32, 0xa0);

  it("kroute / kcommit follow the spec", () => {
    for (const E of [0, 1, 41, 0xfffe]) {
      const k = P.kroute(ROUTE_KEY, E);
      expect(toHex(k)).toBe(toHex(hmacN(ROUTE_KEY, refEnc("segv.sh/v2/route", be16(E)))));
      expect(toHex(P.kcommit(k))).toBe(toHex(sha(refEnc("segv.sh/v2/kroute", k))));
    }
    expect(toHex(P.kroute(ROUTE_KEY, 1))).not.toBe(toHex(P.kroute(ROUTE_KEY, 2)));
    for (const n of [0, 31, 33]) expect(() => P.kroute(new Uint8Array(n), 0)).toThrow(/ROUTE_KEY/);
    expect(() => P.kroute(ROUTE_KEY, 0x10000)).toThrow();
  });

  it("routeV = u64(HMAC(kroute_E, label)[0..8]) >> 1 as 8 big-endian bytes", () => {
    const k = P.kroute(ROUTE_KEY, 3);
    const r = prng(0x7007e);
    for (let i = 0; i < 300; i++) {
      const label = r.bytes(16);
      const v = P.routeV(k, label);
      const want = beToBig(hmacN(k, label).subarray(0, 8)) >> 1n;
      expect(v.length).toBe(8);
      expect(toHex(v)).toBe(toHex(be64n(want)));
      expect(v[0] & 0x80).toBe(0); // a 63-bit value
    }
    for (const n of [0, 15, 17, 32]) expect(() => P.routeV(k, new Uint8Array(n))).toThrow(/16 bytes/);
  });

  it("shardOf = v >> (63 − s_E), and 0 for s_E = 0 (stage 1)", () => {
    const k = P.kroute(ROUTE_KEY, 3);
    const r = prng(0x54a);
    const vs = [new Uint8Array(8), fromHex("7fffffffffffffff"), fromHex("4000000000000000"), fromHex("0000800000000000")];
    for (let i = 0; i < 100; i++) vs.push(P.routeV(k, r.bytes(16)));
    for (const v of vs) {
      expect(P.shardOf(v, 0)).toBe(0);
      for (const s of [1, 2, 8, 16]) expect(P.shardOf(v, s), `${toHex(v)} s=${s}`).toBe(Number(beToBig(v) >> BigInt(63 - s)));
    }
    expect(P.shardOf(fromHex("7fffffffffffffff"), 1)).toBe(1);
    expect(P.shardOf(fromHex("7fffffffffffffff"), 16)).toBe(0xffff);
    expect(P.shardOf(fromHex("0000800000000000"), 16)).toBe(1);
    // a view with a non-zero byteOffset
    const buf = cat(Uint8Array.of(0xff, 0xff), fromHex("4000000000000000"));
    expect(P.shardOf(buf.subarray(2), 1)).toBe(1);
    for (const s of [-1, 17, 1.5]) expect(() => P.shardOf(vs[1], s)).toThrow(/shard/);
  });
});

// ───────────────────────── commitments (§9, §12) ─────────────────────────

describe("commitments: leaves and RFC 6962 MTH (§9)", () => {
  const L = (i: number): B => refLeaf(Uint8Array.of(i));

  it("leaf = H(0x00 ‖ data); node = H(0x01 ‖ l ‖ r)", () => {
    for (const d of [new Uint8Array(0), Uint8Array.of(0), seqBytes(100)]) expect(toHex(P.leaf(d))).toBe(toHex(refLeaf(d)));
    expect(toHex(P.mth([L(0), L(1)]))).toBe(toHex(refNode(L(0), L(1))));
  });

  it("MTH for 1, 2, 3, 5 and 7 leaves has the RFC 6962 shape", () => {
    const l = Array.from({ length: 7 }, (_, i) => L(i));
    const n = refNode;
    expect(toHex(P.mth(l.slice(0, 1)))).toBe(toHex(l[0]));
    expect(toHex(P.mth(l.slice(0, 2)))).toBe(toHex(n(l[0], l[1])));
    expect(toHex(P.mth(l.slice(0, 3)))).toBe(toHex(n(n(l[0], l[1]), l[2])));
    expect(toHex(P.mth(l.slice(0, 5)))).toBe(toHex(n(n(n(l[0], l[1]), n(l[2], l[3])), l[4])));
    expect(toHex(P.mth(l.slice(0, 7)))).toBe(toHex(n(n(n(l[0], l[1]), n(l[2], l[3])), n(n(l[4], l[5]), l[6]))));
  });

  it("MTH matches the certificate-transparency reference vectors", () => {
    // RFC 6962 reference implementation test data (leaf inputs and roots of the first n leaves).
    const inputs = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"];
    const roots = [
      "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
      "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
      "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
      "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
      "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
      "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
      "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
      "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];
    const leaves = inputs.map((h) => P.leaf(fromHex(h)));
    for (let n = 1; n <= 8; n++) {
      expect(toHex(P.mth(leaves.slice(0, n))), `n = ${n}`).toBe(roots[n - 1]);
      expect(toHex(refMth(leaves.slice(0, n))), `ref n = ${n}`).toBe(roots[n - 1]);
    }
  });

  it("MTH matches the bottom-up reference for 1..70 leaves, does not mutate its input, rejects empty batches", () => {
    const r = prng(0x6962);
    for (let n = 1; n <= 70; n++) {
      const leaves = Array.from({ length: n }, () => refLeaf(r.bytes(r.int(40))));
      const copy = leaves.map(toHex);
      expect(toHex(P.mth(leaves)), `n = ${n}`).toBe(toHex(refMth(leaves)));
      expect(leaves.map(toHex)).toEqual(copy);
    }
    expect(() => P.mth([])).toThrow(/empty/);
  });

  it("leafShard / leafInbox / leafBlob follow the spec", () => {
    const label = seqBytes(16, 0x30);
    const body = seqBytes(296, 1);
    expect(toHex(P.leafShard(7, label, 1234, 0, body))).toBe(
      toHex(refLeaf(refEnc("segv.sh/v2/leaf", be16(7), label, be32(1234), be8(0), sha(body)))),
    );
    const eid = seqBytes(16, 0x50);
    const ib = seqBytes(1416, 2);
    expect(toHex(P.leafInbox(7, 0, 99, eid, ib))).toBe(
      toHex(refLeaf(refEnc("segv.sh/v2/leaf/inbox", be16(7), be32(0), be32(99), eid, sha(ib)))),
    );
    const id = seqBytes(32, 0x70);
    expect(toHex(P.leafBlob(id, 11640, 600))).toBe(toHex(refLeaf(refEnc("segv.sh/v2/leaf/blob", sha(id), be32(11640), be32(600)))));
    // every field is bound
    const base = toHex(P.leafShard(7, label, 1234, 0, body));
    for (const other of [
      P.leafShard(8, label, 1234, 0, body),
      P.leafShard(7, flip(label, 0), 1234, 0, body),
      P.leafShard(7, label, 1235, 0, body),
      P.leafShard(7, label, 1234, 1, body),
      P.leafShard(7, label, 1234, 0, flip(body, 295)),
    ])
      expect(toHex(other)).not.toBe(base);
    expect(() => P.leafShard(7, label, 2 ** 32, 0, body)).toThrow();
    expect(() => P.leafShard(7, label, 0, 256, body)).toThrow();
  });

  it("byteCmp orders bytes lexicographically (shorter prefix first)", () => {
    expect(P.byteCmp(Uint8Array.of(1), Uint8Array.of(2))).toBeLessThan(0);
    expect(P.byteCmp(Uint8Array.of(2), Uint8Array.of(1, 9))).toBeGreaterThan(0);
    expect(P.byteCmp(Uint8Array.of(1), Uint8Array.of(1, 0))).toBeLessThan(0);
    expect(P.byteCmp(seqBytes(16), seqBytes(16))).toBe(0);
    expect(P.byteCmp(Uint8Array.of(0x7f), Uint8Array.of(0x80))).toBeLessThan(0);
    const r = prng(0xb7c);
    for (let i = 0; i < 300; i++) {
      const a = r.bytes(r.int(4));
      const b = r.bytes(r.int(4));
      expect(Math.sign(P.byteCmp(a, b))).toBe(Buffer.compare(Buffer.from(a), Buffer.from(b)));
    }
  });
});

describe("commitments: batch heads, checkpoints, receipts, prev (§9, §9.5, §10.3, §3.3)", () => {
  it("cids are decimal without padding", () => {
    expect(P.shardCid(0, 0)).toBe("shard/0/0");
    expect(P.shardCid(41, 0)).toBe("shard/41/0");
    expect(P.inboxCid(7, 0)).toBe("inbox/7/0");
    expect(P.inboxCid(65534, 12)).toBe("inbox/65534/12");
    expect([P.BLOBREG_CID, P.DIRLOG_CID]).toEqual(["blobreg", "dirlog"]);
  });

  it("nextHead = H(enc('segv.sh/v2/head', cid, head, u32 t, u32 n, root)); a shard's batch chain from ZERO32", () => {
    const E = 41;
    const cid = P.shardCid(E, 0);
    const r = prng(0x4ead);
    let head: B = P.ZERO32;
    let ref: B = new Uint8Array(32);
    for (const [t, count] of [
      [100, 1],
      [110, 3],
      [130, 5],
    ]) {
      const rows = Array.from({ length: count }, () => ({ label: r.bytes(16), cls: r.int(4), body: r.bytes(40 + r.int(50)) }));
      // the DO sorts by label; build the leaves both ways
      const sorted = [...rows].sort((a, b) => P.byteCmp(a.label, b.label));
      const root = P.mth(sorted.map((x) => P.leafShard(E, x.label, t, x.cls, x.body)));
      const refRows = [...rows].sort((a, b) => Buffer.compare(Buffer.from(a.label), Buffer.from(b.label)));
      const refRoot = refMth(refRows.map((x) => refLeaf(refEnc("segv.sh/v2/leaf", be16(E), x.label, be32(t), be8(x.cls), sha(x.body)))));
      expect(toHex(root)).toBe(toHex(refRoot));
      head = P.nextHead(cid, head, t, count, root);
      ref = sha(refEnc("segv.sh/v2/head", cid, ref, be32(t), be32(count), refRoot));
      expect(toHex(head)).toBe(toHex(ref));
    }
    expect(toHex(P.nextHead(cid, P.ZERO32, 1, 1, P.ZERO32))).not.toBe(toHex(P.nextHead(P.inboxCid(E, 0), P.ZERO32, 1, 1, P.ZERO32)));
  });

  it("ckptHd hashes the heads sorted by cid in byte order (input order does not matter)", () => {
    const heads = [
      { cid: "shard/9/0", head: fill(32, 1) },
      { cid: "shard/10/0", head: fill(32, 2) },
      { cid: "inbox/10/0", head: fill(32, 3) },
      { cid: "inbox/9/0", head: fill(32, 4) },
      { cid: "dirlog", head: fill(32, 5) },
      { cid: "blobreg", head: fill(32, 6) },
    ];
    const order = ["blobreg", "dirlog", "inbox/10/0", "inbox/9/0", "shard/10/0", "shard/9/0"]; // "1" < "9"
    const sorted = [...heads].sort((a, b) => Buffer.compare(Buffer.from(a.cid), Buffer.from(b.cid)));
    expect(sorted.map((h) => h.cid)).toEqual(order);
    const want = sha(refEnc("segv.sh/v2/ckpt/heads", ...sorted.flatMap((h) => [h.cid, h.head])));
    expect(toHex(P.ckptHd(heads))).toBe(toHex(want));
    const r = prng(0xc4);
    for (let i = 0; i < 20; i++) {
      const shuffled = [...heads].sort(() => r.int(3) - 1);
      expect(toHex(P.ckptHd(shuffled))).toBe(toHex(want));
    }
    expect(heads[0].cid).toBe("shard/9/0"); // not sorted in place
    expect(toHex(P.ckptHd([]))).toBe(toHex(sha(refEnc("segv.sh/v2/ckpt/heads"))));
    expect(toHex(P.ckptHd(heads.slice(1)))).not.toBe(toHex(want));
    expect(toHex(P.ckptHd([{ ...heads[0], head: flip(heads[0].head, 0) }, ...heads.slice(1)]))).not.toBe(toHex(want));
  });

  it("the checkpoint chain C_q = H(enc('segv.sh/v2/ckpt', C_{q−1}, u32 q, u32 sec, hd)) from C_0 = ZERO32", () => {
    const r = prng(0xc0c);
    const entries = Array.from({ length: 6 }, (_, i) => ({ q: i + 1, sec: 60 * (i + 1) + r.int(10), hd: r.bytes(32) }));
    let C: B = P.ZERO32;
    let ref: B = new Uint8Array(32);
    const Cs: B[] = [];
    for (const e of entries) {
      C = P.ckptC(C, e.q, e.sec, e.hd);
      ref = sha(refEnc("segv.sh/v2/ckpt", ref, be32(e.q), be32(e.sec), e.hd));
      expect(toHex(C)).toBe(toHex(ref));
      Cs.push(C);
    }
    // the client's range check: recompute forward from from.C = C_2 over entries 3..6 and land on latest.C
    let x = Cs[1];
    for (const e of entries.slice(2)) x = P.ckptC(x, e.q, e.sec, e.hd);
    expect(toHex(x)).toBe(toHex(Cs[5]));
    // any change to an entry changes every later C
    let y = Cs[1];
    for (const e of entries.slice(2)) y = P.ckptC(y, e.q, e.q === 4 ? e.sec + 1 : e.sec, e.hd);
    expect(toHex(y)).not.toBe(toHex(Cs[5]));
    // the signature message and an SRV_SK signature checked with node
    const srvSk = seqBytes(32, 0x5a);
    const msg = P.ckptSigMsg(6, Cs[5]);
    expect(toHex(msg)).toBe(toHex(refEnc("segv.sh/v2/ckpt-sig", be32(6), Cs[5])));
    expect(edVerify(P.sign(msg, srvSk), refEnc("segv.sh/v2/ckpt-sig", be32(6), Cs[5]), edPubRaw(srvSk))).toBe(true);
    expect(() => P.ckptC(P.ZERO32, 2 ** 32, 0, P.ZERO32)).toThrow();
  });

  it("receiptMsg = enc('segv.sh/v2/receipt', u16 E, label, H(body), u32 t), signed by SRV_SK (§12.5)", () => {
    const label = seqBytes(16, 0x31);
    const body = seqBytes(1064, 3);
    const msg = P.receiptMsg(41, label, body, 4242);
    expect(toHex(msg)).toBe(toHex(refEnc("segv.sh/v2/receipt", be16(41), label, sha(body), be32(4242))));
    const srvSk = seqBytes(32, 0x5a);
    const sig = edSign(msg, srvSk);
    expect(P.verify(sig, msg, edPubRaw(srvSk))).toBe(true);
    // a receipt for another E, label, body or t does not verify
    for (const m of [
      P.receiptMsg(42, label, body, 4242),
      P.receiptMsg(41, flip(label, 15), body, 4242),
      P.receiptMsg(41, label, flip(body, 0), 4242),
      P.receiptMsg(41, label, body, 4243),
    ])
      expect(P.verify(sig, m, edPubRaw(srvSk))).toBe(false);
  });

  it("prevh = t16(H(enc('segv.sh/v2/prev', label_prev, body_prev)))", () => {
    const label = seqBytes(16, 0x32);
    const body = seqBytes(296, 4);
    expect(toHex(P.prevh(label, body))).toBe(toHex(tr16(sha(refEnc("segv.sh/v2/prev", label, body)))));
    expect(P.prevh(label, body).length).toBe(16);
    expect(toHex(P.prevh(label, flip(body, 100)))).not.toBe(toHex(P.prevh(label, body)));
  });
});

describe("directory log chain (§9.6)", () => {
  it("ref_user / ref_wrap and h_seq = H(enc('segv.sh/v2/dirlog', h_{seq−1}, u64 seq, u8 kind, ref)) from ZERO32", () => {
    expect([P.DIRLOG_USER, P.DIRLOG_WRAP]).toEqual([1, 2]);
    const prf = fill(32, 0x11);
    const credId = seqBytes(20, 0x80);
    const w1 = P.makeWrap(alice.uid, "passkey", credId, P.credKem(prf, credId), alice.AK, alice.id, TS);
    const rk = P.recoveryKem(seqBytes(20, 0x30));
    const w2 = P.makeWrap(alice.uid, "recovery", rk.id, rk, alice.AK, alice.id, TS);
    const refUser = (b: string, s: B) => sha(refEnc("segv.sh/v2/dir/user", b, s));
    const refWrap = (r: string, s: B) => sha(refEnc("segv.sh/v2/dir/wrap", r, s));
    const entries: [number, B, B][] = [
      [1, P.dirlogRefUser(alice.bundle, P.fromB64u(alice.sig)), refUser(alice.bundle, P.fromB64u(alice.sig))],
      [2, P.dirlogRefWrap(w1.record, P.fromB64u(w1.sig)), refWrap(w1.record, P.fromB64u(w1.sig))],
      [2, P.dirlogRefWrap(w2.record, P.fromB64u(w2.sig)), refWrap(w2.record, P.fromB64u(w2.sig))],
      [1, P.dirlogRefUser(bob.bundle, P.fromB64u(bob.sig)), refUser(bob.bundle, P.fromB64u(bob.sig))],
    ];
    let h: B = P.ZERO32;
    let ref: B = new Uint8Array(32);
    entries.forEach(([kind, got, want], i) => {
      expect(toHex(got)).toBe(toHex(want));
      const seq = i + 1;
      h = P.dirlogH(h, seq, kind, got);
      ref = sha(refEnc("segv.sh/v2/dirlog", ref, be64(seq), be8(kind), want));
      expect(toHex(h)).toBe(toHex(ref));
    });
    // the user and wrap refs are domain-separated
    expect(toHex(P.dirlogRefUser(w1.record, P.fromB64u(w1.sig)))).not.toBe(toHex(entries[1][1]));
    // u64 sequence numbers above 2^32
    const big = 2 ** 40 + 3;
    expect(toHex(P.dirlogH(h, big, 1, entries[0][1]))).toBe(toHex(sha(refEnc("segv.sh/v2/dirlog", h, be64(big), be8(1), entries[0][1]))));
    expect(() => P.dirlogH(h, 2 ** 53, 1, entries[0][1])).toThrow();
    expect(() => P.dirlogH(h, 1, 256, entries[0][1])).toThrow();
  });
});

// ───────────────────────── proof of work (§10.2) ─────────────────────────

describe("proof of work (§10.2)", () => {
  it("constants", () => {
    expect([...P.POW_SCOPES]).toEqual(["register", "wrap", "put", "inbox", "blob"]);
    expect(P.POW_WINDOW_MS).toBe(600_000);
    expect(P.POW_MAX_BASE).toBe(26);
  });

  it("powPre = H(enc('segv.sh/v2/pow', scope, u32 window, digest)), distinct per scope and window", () => {
    const body = s2b("body");
    for (const scope of P.POW_SCOPES) {
      expect(toHex(P.powPre(scope, 2833333, sha(body)))).toBe(toHex(sha(refEnc("segv.sh/v2/pow", scope, be32(2833333), sha(body)))));
    }
    expect(new Set(P.POW_SCOPES.map((s) => toHex(P.powPre(s, 1, sha(body))))).size).toBe(5);
    expect(toHex(P.powPre("put", 2, sha(body)))).not.toBe(toHex(P.powPre("put", 1, sha(body))));
    expect(toHex(P.powPre("put", 1, sha(body)))).not.toBe(toHex(P1.powPre("append", 1, sha(body))));
    expect(() => P.powPre("put", -1, sha(body))).toThrow();
    expect(() => P.powPre("put", 2 ** 32, sha(body))).toThrow();
  });

  it("powDifficulty table for every scope (put / inbox unit 4096, blob 1 MiB, register / wrap always base)", () => {
    const MiB = 1 << 20;
    const table: [P.PowScope, number, number, number][] = [
      ["put", 16, 0, 16],
      ["put", 16, 1, 16],
      ["put", 16, 4096, 16],
      ["put", 16, 4097, 17],
      ["put", 16, 8192, 17],
      ["put", 16, 8193, 18],
      ["put", 16, 1 + 296 + 35, 16], // one class-0 row
      ["put", 16, 1 + 16424 + 35, 19], // one class-3 row
      ["put", 16, 263345, 23], // PUT_MAX_BYTES: 64.3 units
      ["put", 0, 4097, 1],
      ["inbox", 18, 0, 18],
      ["inbox", 18, 7 + 1432, 18], // one invite
      ["inbox", 18, 7 + 2 * 1432, 18],
      ["inbox", 18, 7 + 3 * 1432, 19],
      ["inbox", 18, 4096, 18],
      ["inbox", 18, 4097, 19],
      ["inbox", 18, 45831, 22], // INBOX_MAX_BYTES: 11.2 units
      ["blob", 18, 0, 18],
      ["blob", 18, 41, 18],
      ["blob", 18, 4097, 18],
      ["blob", 18, MiB, 18],
      ["blob", 18, MiB + 1, 19],
      ["blob", 18, 2 * MiB, 19],
      ["blob", 18, 2 * MiB + 1, 20],
      ["blob", 18, 8 * MiB, 21],
      ["blob", 18, 8 * MiB + 1, 22],
      ["blob", 18, 12 * MiB, 22],
      ["register", 20, 0, 20],
      ["register", 20, 4097, 20],
      ["register", 20, 64 * 1024, 20],
      ["register", 20, 100 * MiB, 20],
      ["wrap", 18, 0, 18],
      ["wrap", 18, 16 * 1024, 18],
      ["wrap", 18, 100 * MiB, 18],
    ];
    for (const [scope, base, bytes, want] of table) {
      expect(P.powDifficulty(scope, base, bytes), `${scope} base ${base}, ${bytes} B`).toBe(want);
      expect(refPowDifficulty(scope, base, bytes), `ref ${scope} ${bytes}`).toBe(want);
    }
  });

  it("powDifficulty matches the integer formula around every power of two, monotone in size", () => {
    for (const scope of P.POW_SCOPES) {
      let prev = 0;
      for (let k = 0; k <= 40; k++) {
        for (const d of [-1, 0, 1]) {
          const bytes = 2 ** k + d;
          if (bytes < 0) continue;
          const got = P.powDifficulty(scope, 10, bytes);
          expect(got, `${scope} 2^${k}${d < 0 ? "" : "+"}${d}`).toBe(refPowDifficulty(scope, 10, bytes));
          expect(got).toBeGreaterThanOrEqual(prev);
          prev = got;
        }
      }
    }
    for (const bad of [-1, 1.5, NaN, 2 ** 53]) expect(() => P.powDifficulty("put", 16, bad), String(bad)).toThrow(/size/);
    expect(() => P.powDifficulty("append" as P.PowScope, 16, 1)).toThrow(/scope/);
  });

  it("powSolve / powCheck work on a v2 challenge", async () => {
    const pre = P.powPre("put", 1, sha(s2b("x")));
    const nonce = await P.powSolve(pre, 8);
    expect(P.powCheck(pre, nonce, 8)).toBe(true);
    expect(P.leadingZeroBits(sha(cat(pre, be64(nonce))))).toBeGreaterThanOrEqual(8);
  });
});

// ───────────────────────── directory prefixes (§9.6, §10.6) ─────────────────────────

describe("directory prefix ranges and p (§9.6, §10.6)", () => {
  const refRange = (p: number, x: number) => {
    const span = 1n << BigInt(32 - p);
    const lo = BigInt(x) * span;
    return { lo: Number(lo), hi: Number(lo + span - 1n) };
  };

  it("prefixRange for p = 0, 1, 31, 32 with x at both ends (no 32-bit shift bugs)", () => {
    const cases: [number, number, number, number][] = [
      [0, 0, 0, 0xffffffff],
      [1, 0, 0, 0x7fffffff],
      [1, 1, 0x80000000, 0xffffffff],
      [31, 0, 0, 1],
      [31, 0x7fffffff, 0xfffffffe, 0xffffffff],
      [32, 0, 0, 0],
      [32, 0xffffffff, 0xffffffff, 0xffffffff],
      [16, 0x1234, 0x12340000, 0x1234ffff],
    ];
    for (const [p, x, lo, hi] of cases) {
      expect(P.prefixRange(p, x), `p=${p} x=${x}`).toEqual({ lo, hi });
      expect(refRange(p, x)).toEqual({ lo, hi });
    }
    for (let p = 0; p <= 32; p++) {
      const top = 2 ** p - 1;
      for (const x of [0, top, Math.floor(top / 3)]) expect(P.prefixRange(p, x), `p=${p} x=${x}`).toEqual(refRange(p, x));
    }
    for (const p of [-1, 33, 1.5, NaN]) expect(() => P.prefixRange(p, 0), `p=${p}`).toThrow(/prefix bits/);
    for (const [p, x] of [
      [0, 1],
      [1, 2],
      [31, 2 ** 31],
      [32, 2 ** 32],
      [8, -1],
      [8, 1.5],
    ])
      expect(() => P.prefixRange(p, x), `p=${p} x=${x}`).toThrow(/prefix value/);
  });

  it("topBits(pre, p) selects the range that contains pre", () => {
    const r = prng(0x70b);
    for (let i = 0; i < 200; i++) {
      const pre = i === 0 ? 0xffffffff : i === 1 ? 0 : r.u32();
      for (let p = 0; p <= 32; p++) {
        const x = P.topBits(pre, p);
        expect(x).toBe(p === 0 ? 0 : Number(BigInt(pre) >> BigInt(32 - p)));
        const { lo, hi } = P.prefixRange(p, x);
        expect(lo <= pre && pre <= hi, `pre=${pre} p=${p}`).toBe(true);
      }
    }
    expect(P.topBits(P.hpre("alice"), 32)).toBe(P.hpre("alice"));
  });

  it("serverP = max(0, ⌊log2(users / 32)⌋)", () => {
    const ref = (users: number): number => (users < 32 ? 0 : bitLength(users) - 1 - 5);
    const table: [number, number][] = [
      [0, 0],
      [1, 0],
      [31, 0],
      [32, 0],
      [63, 0],
      [64, 1],
      [127, 1],
      [128, 2],
      [1000, 4],
      [2 ** 20, 15],
      [2 ** 40 - 1, 34],
    ];
    for (const [users, want] of table) {
      expect(P.serverP(users), `users=${users}`).toBe(want);
      expect(ref(users)).toBe(want);
    }
    for (let k = 0; k <= 45; k++) for (const d of [-1, 0, 1]) if (2 ** k + d >= 0) expect(P.serverP(2 ** k + d)).toBe(ref(2 ** k + d));
  });

  it("clientP = max(0, min(P − 1, ⌊log2(dirSeq / 64)⌋, 16)): bounded by dirSeq, at most 16", () => {
    const ref = (Pv: number, dirSeq: number): number =>
      Math.max(0, Math.min(Pv - 1, dirSeq < 64 ? -1 : bitLength(dirSeq) - 1 - 6, 16));
    const table: [number, number, number][] = [
      [0, 0, 0],
      [0, 2 ** 30, 0],
      [1, 2 ** 30, 0],
      [5, 0, 0],
      [5, 63, 0],
      [5, 64, 0],
      [5, 128, 1],
      [5, 1000, 3],
      [5, 2 ** 20, 4], // P − 1
      [20, 1000, 3], // an inflated P does not help without an inflated dirlog
      [30, 2 ** 30, 16], // capped at 16
      [40, 2 ** 50, 16],
      [10, 2 ** 40, 9],
    ];
    for (const [Pv, dirSeq, want] of table) {
      expect(P.clientP(Pv, dirSeq), `P=${Pv} dirSeq=${dirSeq}`).toBe(want);
      expect(ref(Pv, dirSeq)).toBe(want);
    }
    const r = prng(0xc11);
    for (let i = 0; i < 500; i++) {
      const Pv = r.int(40);
      const dirSeq = r.int(2) ? r.int(5000) : r.u32() * 64;
      const got = P.clientP(Pv, dirSeq);
      expect(got).toBe(ref(Pv, dirSeq));
      expect(got).toBeLessThanOrEqual(16);
      expect(got).toBeLessThanOrEqual(Math.max(0, Pv - 1));
      // the server accepts p ∈ [0, min(32, P + 1)]
      expect(got).toBeLessThanOrEqual(Math.min(32, Pv + 1));
    }
  });
});

// ───────────────────────── blobs (§8.1) ─────────────────────────

describe("blobs (§8.1)", () => {
  it("encryptBlob: aeadSeal(key, padme(bytes), utf8('segv.sh/v2/blob')), id = b64u(H(blob))", () => {
    expect(P.BLOB_AAD).toBe("segv.sh/v2/blob");
    expect(P.BLOB_MIN).toBe(41);
    for (const n of [0, 1, 100, 5000]) {
      const data = seqBytes(n, 7);
      const { blob, id, key } = P.encryptBlob(data);
      expect(blob.length).toBe(24 + P.padmeLength(n + 1) + 16);
      expect(blob.length).toBeGreaterThanOrEqual(P.BLOB_MIN);
      expect(id).toBe(b64uN(sha(blob)));
      const pt = xchacha20poly1305(key, blob.subarray(0, 24), s2b("segv.sh/v2/blob")).decrypt(blob.subarray(24));
      expect(toHex(P.unpad(pt))).toBe(toHex(data));
      expect(toHex(P.decryptBlob(blob, id, key))).toBe(toHex(data));
      expect(() => P.decryptBlob(blob, b64uN(sha(flip(blob, 0))), key)).toThrow(/hash mismatch/);
      expect(() => P.decryptBlob(blob, id, flip(key, 0))).toThrow();
      expect(() => P.decryptBlob(blob, id, key, "segv.sh/v2/snapshot")).toThrow();
    }
    const snap = P.encryptBlob(s2b("state"), "segv.sh/v2/snapshot");
    expect(P.fromUtf8(P.decryptBlob(snap.blob, snap.id, snap.key, "segv.sh/v2/snapshot"))).toBe("state");
    expect(() => P.decryptBlob(snap.blob, snap.id, snap.key)).toThrow();
  });
});

// ═════════════════════════ 4. fuzz ═════════════════════════

describe("fuzz", () => {
  it("parseBundle / parseWrap / parseLink on random and mutated input throw Error, never anything else", () => {
    const r = prng(0xf022);
    const chars = '{}[]":,0123456789-.eAZaz_ \\nulvs';
    const bases = [
      alice.bundle,
      P.makeWrap(alice.uid, "recovery", seqBytes(16), P.recoveryKem(seqBytes(20)), alice.AK, alice.id, TS).record,
      P.encodeLink("segv.sh", seqBytes(16), alice.uid),
    ];
    let accepted = 0;
    for (let t = 0; t < 1500; t++) {
      const a = bases[t % 3].split("");
      for (let m = 0; m <= r.int(3); m++) {
        const i = r.int(a.length);
        const op = r.int(3);
        if (op === 0) a.splice(i, 1);
        else if (op === 1) a.splice(i, 0, chars[r.int(chars.length)]);
        else a[i] = chars[r.int(chars.length)];
      }
      const text = a.join("");
      for (const f of [() => P.parseBundle(text, alice.sig), () => P.parseWrap(text, alice.sig), () => P.parseLink(text)]) {
        try {
          f();
          accepted++;
        } catch (e) {
          expect(e).toBeInstanceOf(Error);
        }
      }
    }
    expect(accepted).toBeGreaterThan(0);
  }, 30_000);

  it("open / tryOpen / openWrap on random boxes: Error or null, never anything else", () => {
    const r = prng(0x0be2);
    const kp = P.kemKeygen(fill(32, 3));
    for (let t = 0; t < 60; t++) {
      const box = r.bytes(t % 2 ? 1160 + r.int(64) : r.int(1300));
      expect(P.tryOpen(kp.sk, LBL, CONV, box)).toBeNull();
      expect(throwsError(() => P.open(kp.sk, LBL, CONV, box))).toBe(true);
      expect(throwsError(() => P.openWrap({ uid: alice.uidS, id: CONV, wrap: box }, { sk: kp.sk, auth: EK }))).toBe(true);
    }
  });
});

// ═════════════════════════ 5. known-answer vectors ═════════════════════════
// Generated once from the implementation after the independent cross-checks above passed. If one of these fails, the
// v2 wire format changed: that breaks every account, row and conversation. Do not "fix" the vector — fix the code.

const KAT_AK = seqBytes(32); // 00 01 .. 1f
const KAT_UID = seqBytes(16, 0x40);
const KAT_TS = 1_780_000_000_000;

/** Every pinned value, computed from proto2 (deterministic randomness where a construction is randomised). */
function katValues() {
  const id = P.deriveIdentity(KAT_AK);
  const { bundle, sig } = P.makeBundle(KAT_UID, "kat_user", id, KAT_TS);
  const sigRaw = P.fromB64u(sig);
  const credId = seqBytes(20, 0x80);
  const cred = P.credKem(fill(32, 0x11), credId);
  const rec = P.recoveryKem(seqBytes(20));
  const wrapCalls: Record<string, B[]> = { passkey: [], recovery: [] };
  const pw = withRandom(recording(detRandom("kat wrap passkey"), wrapCalls.passkey), () =>
    P.makeWrap(KAT_UID, "passkey", credId, cred, KAT_AK, id, KAT_TS),
  );
  const rw = withRandom(recording(detRandom("kat wrap recovery"), wrapCalls.recovery), () =>
    P.makeWrap(KAT_UID, "recovery", rec.id, rec, KAT_AK, id, KAT_TS + 1),
  );
  const sealBox = withRandom(detRandom("kat seal"), () => P.seal(id.kemPk, LBL, seqBytes(5), seqBytes(40)));
  const dummy = withRandom(detRandom("kat dummy"), () => P.dummySeal(LBL, seqBytes(5), 40));
  const ep = P.epochKeys(seqBytes(32, 0x20), seqBytes(16, 0x60), 7);
  const lk = P.linkKeys(seqBytes(16, 0x90));
  const kr = P.kroute(seqBytes(32, 0xa0), 41);
  const label = seqBytes(16, 0x30);
  const body = seqBytes(1064, 3);
  const eid = seqBytes(16, 0x50);
  const ibody = seqBytes(1416, 2);
  const blobId = seqBytes(32, 0x70);
  const leaves = [P.leafShard(41, label, 1234, 1, body), P.leafInbox(41, 0, 99, eid, ibody), P.leafBlob(blobId, 11640, 600)];
  const root = P.mth(leaves);
  const head1 = P.nextHead(P.shardCid(41, 0), P.ZERO32, 1234, 3, root);
  const heads = [
    { cid: P.shardCid(41, 0), head: head1 },
    { cid: P.inboxCid(41, 0), head: fill(32, 0x11) },
    { cid: P.BLOBREG_CID, head: fill(32, 0x22) },
    { cid: P.DIRLOG_CID, head: fill(32, 0x33) },
  ];
  const hd = P.ckptHd(heads);
  const C1 = P.ckptC(P.ZERO32, 1, 60, hd);
  const C2 = P.ckptC(C1, 2, 120, P.ckptHd(heads.slice(1)));
  const srvSk = seqBytes(32, 0x5a);
  const receipt = P.receiptMsg(41, label, body, 1234);
  const refUser = P.dirlogRefUser(bundle, sigRaw);
  const refWrap = P.dirlogRefWrap(pw.record, P.fromB64u(pw.sig));
  const h1 = P.dirlogH(P.ZERO32, 1, P.DIRLOG_USER, refUser);
  const h2 = P.dirlogH(h1, 2, P.DIRLOG_WRAP, refWrap);
  return {
    identity: {
      sigSk: toHex(id.sigSk),
      sigPk: toHex(id.sigPk),
      kemSk: toHex(id.kemSk),
      kemPkSha256: toHex(sha(id.kemPk)),
      kS: toHex(id.kS),
      rS: toHex(id.rS),
      nS: toHex(id.nS),
    },
    bundle: { sha256: toHex(sha(s2b(bundle))), sig, fingerprint: P.fingerprint(KAT_UID, id.sigPk, id.kemPk), pin: toHex(P.pin(bundle, sigRaw)) },
    dir: { hpre: P.hpre("kat_user"), upre: P.upre(KAT_UID) },
    credKem: { pkSha256: toHex(sha(cred.pk)), sk: toHex(cred.sk), auth: toHex(cred.auth) },
    recoveryKem: { pkSha256: toHex(sha(rec.pk)), sk: toHex(rec.sk), id: toHex(rec.id), auth: toHex(rec.auth) },
    wrap: {
      passkey: { recordSha256: toHex(sha(s2b(pw.record))), sig: pw.sig, wrapSha256: toHex(sha(P.parseWrap(pw.record, pw.sig).wrap)) },
      recovery: { recordSha256: toHex(sha(s2b(rw.record))), sig: rw.sig, wrapSha256: toHex(sha(P.parseWrap(rw.record, rw.sig).wrap)) },
    },
    seal: { sha256: toHex(sha(sealBox)), dummySha256: toHex(sha(dummy)) },
    epoch: {
      rk: toHex(ep.rk),
      mk: toHex(ep.mk),
      kc: toHex(ep.kc),
      nk: toHex(ep.nk),
      dk: toHex(ep.dk),
      ekc: toHex(P.ekc(seqBytes(16, 0x60), 7, seqBytes(32, 0x20))),
    },
    labels: {
      Lmsg_3_41_5: toHex(P.Lmsg(ep.rk, 3, 41, 5)),
      Lmsg_0_0_0: toHex(P.Lmsg(ep.rk, 0, 0, 0)),
      Lctl_41_2: toHex(P.Lctl(ep.rk, 41, 2)),
      topicConv: toHex(P.topicConv(ep.nk)),
      Lself_41_9: toHex(P.Lself(id.rS, 41, 9)),
      Lsnap_41_1: toHex(P.Lsnap(id.rS, 41, 1)),
      topicSelf: toHex(P.topicSelf(id.nS)),
      kL: toHex(lk.kL),
      mL: toHex(lk.mL),
      nL: toHex(lk.nL),
      Lhello_41_0: toHex(P.Lhello(lk.kL, 41, 0)),
      topicLink: toHex(P.topicLink(lk.nL)),
      link: P.encodeLink("segv.sh", seqBytes(16, 0x90), KAT_UID),
    },
    routing: { kroute: toHex(kr), kcommit: toHex(P.kcommit(kr)), v: toHex(P.routeV(kr, label)) },
    commitments: {
      leafShard: toHex(leaves[0]),
      leafInbox: toHex(leaves[1]),
      leafBlob: toHex(leaves[2]),
      mth: toHex(root),
      head: toHex(head1),
      hd: toHex(hd),
      C1: toHex(C1),
      C2: toHex(C2),
      ckptSig: toHex(P.sign(P.ckptSigMsg(2, C2), srvSk)),
      receiptMsg: toHex(receipt),
      receiptSig: toHex(P.sign(receipt, srvSk)),
      prevh: toHex(P.prevh(label, body)),
      dirlogRefUser: toHex(refUser),
      dirlogRefWrap: toHex(refWrap),
      dirlogH1: toHex(h1),
      dirlogH2: toHex(h2),
    },
    powPre: toHex(P.powPre("put", 2833333, P.H(body))),
    _calls: wrapCalls,
    _boxes: { pw, rw, cred, rec, credId, id },
  };
}

// Generated from katValues() once the cross-checks above passed.
const KAT = {
  identity: {
    sigSk: "1bed77794e28cd19fc4ac82eaef9b350c0f9b3e59cd5404121484abf06679abb",
    sigPk: "50c9efc73d5fcb1da0836f651a4750046d5d486e0907def9fc51115a01bc7675",
    kemSk: "c93efe194e4d35b7c7d5f23098a7b6e5eef43134b97f599698ba9bf4e247064e",
    kemPkSha256: "f611b9c73cceb676e7be65bf2c9dc7465dbf913bb6b8ec947b74e630bea245e9",
    kS: "10a81df1fee104128932dd1e41874a52b062e96bba0ede4a69cbb8f7fc33be73",
    rS: "d00dc6049a2c40f9d9b8b8fa680818f7b605d2d76bb2d0141f931ca60c8d662b",
    nS: "8e954248c5634e2a4e2a6cafb43b08fb067107df8008e3d520f91d17e20845cf",
  },
  bundle: {
    sha256: "fc493f9b8dc4ecd7dde206316e7a09c591d5c5f424705d8a1807d9a8313d3127",
    sig: "XkMNPn5lpiPaYFtdkoBahE5kHlH3-qkQ4qF9LusW2__cNuhRMPKxfNLlNai6dFQKuQuMpldQ2ENocLsj9YLWBw",
    fingerprint: "70863 35163 00494 48310 14909 91457",
    pin: "9601b447843b82f53a0a340c06f2fd9657f88c825442154f5c4792e9b2cf39af",
  },
  dir: { hpre: 1518820017, upre: 509507751 },
  credKem: {
    pkSha256: "c4c832e8f21089a6580f7bc59927c266c167221ae7a53338afe88d85e7bdbf89",
    sk: "20f3bb8221099db1c8705135e89b585ef7815a6226c77110de58313383631a95",
    auth: "22c9865ae198beed41a6d95144597aa0146d4d18f10782c3d0bb676bdaca60d1",
  },
  recoveryKem: {
    pkSha256: "6e76c8638779ad31988633c1f55b0da266c2b62dccb92390bf0b67feaf88cb9a",
    sk: "031c23810cdd738fa6524c364f59491e8701e753404e55bf7b9a2704bb05305c",
    id: "975ff740785ed14f6ee9e6766cdbf473",
    auth: "bb97f8551ddd27623aefd55d922348cc0ed06c7366502d7226e268e47b91b3e9",
  },
  wrap: {
    passkey: {
      recordSha256: "8b13d9cb2e06084307c32c915b5467e53d570839c72aae98307fd2e2bf041c82",
      sig: "hdri0fyue50kTEn7JvPXsJH_4jBNxJzkCUJPk-OA56eVIsM-RlX2cOWpvJCYV1biXAwkDfCWYyXDCN079NxcDA",
      wrapSha256: "9403eb5016b94f7333d61ff761ecc20be4f84662b1039c3b88094b3d95494ce8",
    },
    recovery: {
      recordSha256: "938dade6133bac613734e45b6a65b91ad554b4de6f7e731c2b81315db4b861ce",
      sig: "tVjgP43c2HJF7GFuxQkTb_3hCvZXapDK4wZQVF1KKuDNf6EbAZlXssvJZBgQCQjtmo5IU-lN85dWhZ2Y7i8WBQ",
      wrapSha256: "acd87cbc081776bce6a5af91ab03255f6c8af7027116b9c5c6f784b26e6987c4",
    },
  },
  seal: {
    sha256: "954d244ad48d0523f7dd5f542b125b90dc8b65f8237180d7ba48ae7b1877fe87",
    dummySha256: "c7e3ca6b829585372a680eabff0faa0d2fc511203cb7c8613a06c42939249eb7",
  },
  epoch: {
    rk: "cce9c0a8668adb80b8d86c7c7af77a43f31202e23c75e49d358255d4ecbff5b9",
    mk: "5903167ad3ca32a5b415e5661cc5ece4c3f3ae4e0af83ba921765e6baee3c035",
    kc: "e0a7fe7d5fca837c3f3923277c27a0125f26da3efbc4c8bd4b88571d21ea559c",
    nk: "c100d8f1f22f383a42c44e4582bc217918167c8c0e6cc2413a3716310834597b",
    dk: "fab405f9f3d19ad2a2713aeb615a47331c082ea5503b0d6701f13050bb9dcbbd",
    ekc: "f580ab441f45fa99d6c10f3b4bdaa4e98f40c995ac0b1cf13117039fb1b66414",
  },
  labels: {
    Lmsg_3_41_5: "d78a1b710277204a5a17132028da99b7",
    Lmsg_0_0_0: "2462839006269ee01cd1a5658a7050c4",
    Lctl_41_2: "73dba5791ca3f86898291ac281bedbb2",
    topicConv: "928ae44345ec3808cac855805b094605",
    Lself_41_9: "b07192105cc332cbe7b2367a60e0ec72",
    Lsnap_41_1: "bb0874d1089f25ef58fdeb3a082c0d98",
    topicSelf: "af47a5aeffd264e8bd140d6450c528fc",
    kL: "0d778f29bdfb5cad22b87306f3ac5af1de922f2d636a3bf0d5ecf3fef21952e3",
    mL: "777bf865cfc09e68ec63437e25b8ba51b6d66f1026502df7c76d8971728b6b0e",
    nL: "a0258951ea20bcddc7256454976b202499a871dd1add62b123d1afcca003f4cc",
    Lhello_41_0: "85ef899c12b5daca23fdc05aedb61462",
    topicLink: "cf193f95fe8d944c9a5c773c7f691e3f",
    link: "https://segv.sh/i#ApCRkpOUlZaXmJmam5ydnp9AQUJDREVGR0hJSktMTU5P",
  },
  routing: {
    kroute: "95657ac9402060984afda72b8ff195e36959eea5778452fc2827fc216bd29bdc",
    kcommit: "6f90cee6b5f540f864579fd43f4307fdc468f4d8271046b747ead3325d6e9588",
    v: "7330dc8201a8a97d",
  },
  commitments: {
    leafShard: "e268911fc61d2fca15e1b642ee0061e8e72fb15eaaaa8d2ce7bf47dbbd81f557",
    leafInbox: "dacbc6b9949ac45d59196cb3323805b323c1109e5b273be8ed23a3ad6ee44326",
    leafBlob: "de1459bfc63f6d6dd8293cecf286e57c27e63e2ddc7d068ab0ee036101bcc101",
    mth: "75d163c357df66064fa7f2e61157279a505dd2ace3073228cba96d63e6f17567",
    head: "11b0ba1d0078c5823f230ee129b9069c391e37b4035d24d76b33b394699f91ab",
    hd: "83cfaf396f32982b1b8dd77d97ab6867fdad5847c6d3f0d648f735b93fc9bdbc",
    C1: "4df19b0dd9e4eb893b1a02a8ee6dc03fa3cc409261dc6432187a48aa62e13378",
    C2: "3e8f06f31a5058461dbe8b849cccca3b29a8142cccedb5870c430255224782fa",
    ckptSig:
      "e1303b9801495c9941b546171cc0dd9603bbc90c90db0228a85da968347c4c885041be6e8ae90cf7b75294b704e559088a1bbcf428f68b780e5bff974ac41c0a",
    // hand check: lp("segv.sh/v2/receipt") ‖ lp(u16 41) ‖ lp(label 30..3f) ‖ lp(H(body)) ‖ lp(u32 1234)
    receiptMsg:
      "00000012" +
      "736567762e73682f76322f72656365697074" +
      "00000002" +
      "0029" +
      "00000010" +
      "303132333435363738393a3b3c3d3e3f" +
      "00000020" +
      "9a02bff68a7fd32edc8544e8311a4fcf7504f288f90ccfc9efa338db79d7c988" +
      "00000004" +
      "000004d2",
    receiptSig:
      "fe66f9f7041b0b8d7ea42210f77878adfd9ca762c910754959e5cd3461b1d639856aa2a0d6190fd2a30fb92f8d1f2b3a495b3928f8b5bf40ebceab4c4ef41704",
    prevh: "5d0530b64da7e981b71970dee78cfc6e",
    dirlogRefUser: "062e89ff65baca10e3b083f8942333a117dc044f1a33b01e46028c02d40538fa",
    dirlogRefWrap: "b078c88973046ce09db3b347536a16f33ace964b01988c99b0e265b1b5b9db38",
    dirlogH1: "4c864621c5eba2089cf133a0321b1f9a3e50fce1796f5861c7e8bf66899c2458",
    dirlogH2: "6012a887d792e6c49a2a0955aa339f6c891f6788718bd696a6c88430a12b6f1c",
  },
  powPre: "1fa2a1a5fdfadb477b348438bb9fe6337cd5f9f4688e02f44afb9ca5b1d6cc99",
};

describe("known-answer vectors", () => {
  const V = katValues();

  it("deriveIdentity from AK = 00..1f", () => {
    expect(V.identity).toEqual(KAT.identity);
  });

  it("bundle, bundle signature, fingerprint, pin, hpre / upre", () => {
    expect(V.bundle).toEqual(KAT.bundle);
    expect(V.dir).toEqual(KAT.dir);
    const { bundle } = P.makeBundle(KAT_UID, "kat_user", V._boxes.id, KAT_TS);
    expect(bundle.startsWith('{"v":2,"uid":"QEFCQ0RFRkdISUpLTE1OTw","handle":"kat_user","sig":"UMnvxz1fyx2gg29lGkdQBG1dSG4JB975_FERWgG8dnU","kem":"')).toBe(true);
    expect(bundle.endsWith(`","ts":${KAT_TS}}`)).toBe(true);
    expect(P.b64u(fromHex(KAT.identity.sigPk))).toBe("UMnvxz1fyx2gg29lGkdQBG1dSG4JB975_FERWgG8dnU");
  });

  it("credential / recovery KEM keys and auth values", () => {
    expect(V.credKem).toEqual(KAT.credKem);
    expect(V.recoveryKem).toEqual(KAT.recoveryKem);
  });

  it("ak-wraps with fixed randomness, rebuilt independently from the recorded randomness", () => {
    expect(V.wrap).toEqual(KAT.wrap);
    const { pw, rw, cred, rec, credId } = V._boxes;
    for (const [kind, w, key, wid] of [
      ["passkey", pw, cred, credId],
      ["recovery", rw, rec, rec.id],
    ] as const) {
      const calls = V._calls[kind];
      expect(calls.map((c) => c.length), kind).toEqual([64, 24]);
      const box = refSeal(key.pk, "segv.sh/v2/ak-wrap", refEnc(KAT_UID, wid, key.auth), KAT_AK, calls[0], calls[1]);
      expect(toHex(sha(box)), kind).toBe(KAT.wrap[kind].wrapSha256);
      expect(toHex(P.parseWrap(w.record, w.sig).wrap)).toBe(toHex(box));
    }
  });

  it("seal and dummySeal with fixed randomness", () => {
    expect(V.seal).toEqual(KAT.seal);
    const calls: B[] = [];
    const box = withRandom(recording(detRandom("kat seal"), calls), () => P.seal(V._boxes.id.kemPk, LBL, seqBytes(5), seqBytes(40)));
    expect(toHex(sha(refSeal(V._boxes.id.kemPk, LBL, seqBytes(5), seqBytes(40), calls[0], calls[1])))).toBe(KAT.seal.sha256);
    expect(toHex(sha(box))).toBe(KAT.seal.sha256);
  });

  it("epoch keys, ekc, every label and topic, link keys and the link", () => {
    expect(V.epoch).toEqual(KAT.epoch);
    expect(V.labels).toEqual(KAT.labels);
  });

  it("routing", () => {
    expect(V.routing).toEqual(KAT.routing);
  });

  it("commitments: leaves, MTH, head, checkpoints, receipts, prevh, dirlog chain", () => {
    expect(V.commitments).toEqual(KAT.commitments);
    expect(edVerify(fromHex(KAT.commitments.receiptSig), fromHex(KAT.commitments.receiptMsg), edPubRaw(seqBytes(32, 0x5a)))).toBe(true);
    expect(edVerify(fromHex(KAT.commitments.ckptSig), refEnc("segv.sh/v2/ckpt-sig", be32(2), fromHex(KAT.commitments.C2)), edPubRaw(seqBytes(32, 0x5a)))).toBe(true);
  });

  it("PoW prefix", () => {
    expect(V.powPre).toBe(KAT.powPre);
  });
});
