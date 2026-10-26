// Test suite for src/lib/proto.ts (protocol v1, docs/PROTOCOL.md).
//
// Layout:
//   1. reference helpers   — an independent re-implementation of the spec's encoding/KDF/hash rules on
//                            top of node:crypto, used to cross-check proto.ts byte-for-byte.
//   2. round trips         — every primitive and record type.
//   3. tamper / misuse     — bit flips in every region of every ciphertext, wrong AAD contexts,
//                            cross-protocol confusion, signature binding.
//   4. fuzz                — decoders never hang and only ever throw `Error`s.
//   5. known answers       — pinned outputs of every deterministic function, so any accidental
//                            change to the wire format fails the build.
import { describe, expect, it } from 'vite-plus/test';
import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  randomBytes,
  verify as nodeVerify,
} from 'node:crypto';
import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import * as P from './proto';

type B = Uint8Array;

// ───────────────────────── 1. reference helpers (independent of proto.ts) ─────────────────────────

const te = new TextEncoder();
const s2b = (x: B | string): B => (typeof x === 'string' ? te.encode(x) : x);
const cat = (...xs: B[]): B => {
  const out = new Uint8Array(xs.reduce((a, x) => a + x.length, 0));
  let o = 0;
  for (const x of xs) {
    out.set(x, o);
    o += x.length;
  }
  return out;
};
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
const be64 = (n: number): B => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return new Uint8Array(b);
};
/** Spec §1: enc(a, b, ...) = lp(a) || lp(b) || ... with lp(b) = u32(len(b)) || b. */
const refEnc = (...xs: (B | string)[]): B => cat(...xs.flatMap((x) => [be32(s2b(x).length), s2b(x)]));
const sha = (b: B): B => new Uint8Array(createHash('sha256').update(b).digest());
const hmacN = (k: B, m: B | string): B => new Uint8Array(createHmac('sha256', k).update(s2b(m)).digest());
const hkdfN = (ikm: B, salt: B | string, info: B | string, len = 32): B =>
  new Uint8Array(hkdfSync('sha256', ikm, s2b(salt), s2b(info), len));
/** Spec §3.7 pad. */
const refPad = (x: B, classes: readonly number[]): B => {
  const t = classes.find((c) => c >= x.length + 1);
  if (t === undefined) throw new Error('too large');
  const o = new Uint8Array(t);
  o.set(x);
  o[x.length] = 0x80;
  return o;
};
/** Spec §3.7 Padmé, computed with exact integer arithmetic (no floating-point log2). */
const refPadmeLength = (L: number): number => {
  if (L < 2) return L;
  const E = BigInt(L).toString(2).length - 1; // floor(log2 L)
  const S = E.toString(2).length; // floor(log2 E) + 1
  const z = BigInt(E - S);
  const mask = (1n << z) - 1n;
  return Number((BigInt(L) + mask) & ~mask);
};
/**
 * PoW difficulty (§4.3), integer-only: append = base + ceil(log2(bytes / 4 KiB)) above 4 KiB,
 * blob = base + ceil(log2(bytes / 1 MiB)) above 1 MiB, register / wrap = base. "ceil(log2(x))" is the
 * smallest k with unit * 2^k >= bytes.
 */
const refPowDifficulty = (scope: string, base: number, bytes: number): number => {
  const unit = scope === 'append' ? 4096n : scope === 'blob' ? 1n << 20n : 0n;
  if (unit === 0n || BigInt(bytes) <= unit) return base;
  let k = 0;
  while (unit << BigInt(k) < BigInt(bytes)) k++;
  return base + k;
};
const toHex = (b: B): string => Buffer.from(b).toString('hex');
const fromHex = (h: string): B => new Uint8Array(Buffer.from(h, 'hex'));
const fill = (n: number, v: number): B => new Uint8Array(n).fill(v);
const seqBytes = (n: number, start = 0): B => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);
const flip = (b: B, i: number, bit = 0): B => {
  const c = b.slice();
  c[i] ^= 1 << bit;
  return c;
};

// node:crypto Ed25519 / X25519 from raw keys (PKCS#8 / SPKI DER prefixes, RFC 8410).
const ED_PKCS8 = fromHex('302e020100300506032b657004220420');
const ED_SPKI = fromHex('302a300506032b6570032100');
const X_PKCS8 = fromHex('302e020100300506032b656e04220420');
const X_SPKI = fromHex('302a300506032b656e032100');
const nodePrivKey = (prefix: B, sk: B) => createPrivateKey({ key: Buffer.from(cat(prefix, sk)), format: 'der', type: 'pkcs8' });
const nodePubKey = (prefix: B, pk: B) => createPublicKey({ key: Buffer.from(cat(prefix, pk)), format: 'der', type: 'spki' });
const nodeRawPub = (prefix: B, sk: B): B =>
  new Uint8Array(Buffer.from(createPublicKey(nodePrivKey(prefix, sk)).export({ format: 'jwk' }).x!, 'base64url'));
const nodeEdVerify = (sig: B, msg: B, pk: B): boolean => nodeVerify(null, msg, nodePubKey(ED_SPKI, pk), sig);
/** X25519 via OpenSSL — stands in for a WebCrypto-backed `dh` callback. */
const nodeX25519 = (sk: B, pk: B): B =>
  new Uint8Array(diffieHellman({ privateKey: nodePrivKey(X_PKCS8, sk), publicKey: nodePubKey(X_SPKI, pk) }));

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
    bytes: (n: number): B => {
      const b = new Uint8Array(n);
      for (let i = 0; i < n; i++) b[i] = next() & 0xff;
      return b;
    },
  };
}

/** Flips the lowest set-able bit of the last base64url character so the leftover bits become non-zero. */
const nonCanonical = (s: string): string => {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const v = A.indexOf(s[s.length - 1]);
  return s.slice(0, -1) + A[v ^ 1];
};

/**
 * Flips one bit at sampled positions of every region and returns the positions where `open` did NOT
 * throw (must be empty). `every` regions are flipped at every byte.
 */
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
      const mutated = flip(body, reg.start + p, bit);
      let threw = false;
      try {
        open(mutated);
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

// ───────────────────────── fixtures ─────────────────────────

const TS = 1_700_000_000_000;

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

const alice = mkUser(0xa1, 'alice');
const bob = mkUser(0xb2, 'bob');
const carol = mkUser(0xc3, 'carol');

const CONV_A = fill(16, 0x0a);
const CONV_B = fill(16, 0x0b);
const EK0 = fill(32, 0xe0);
const EK1 = fill(32, 0xe1);
const H32 = P.b64u(fill(32, 0x33));

function dObj(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { v: 1, conv: P.b64u(CONV_A), e: 0, members: [alice.uidS, bob.uidS], prev: null, by: alice.uidS, ts: TS, ...over };
}
const dText = (over: Record<string, unknown> = {}): string => JSON.stringify(dObj(over));

const payload = (over: Partial<P.Payload> = {}): P.Payload => ({
  v: 1,
  t: 'text',
  conv: P.b64u(CONV_A),
  e: 0,
  from: alice.uidS,
  n: 0,
  ts: TS + 123,
  text: 'hello',
  head: { seq: 1, h: H32 },
  ...over,
});

const uidN = (i: number): string => P.b64u(Uint8Array.from({ length: 16 }, (_, j) => (j === 0 ? i : 0x77)));

// ═════════════════════════ 2. round trips ═════════════════════════

describe('encoding: integers', () => {
  it('u8/u16/u32/u64 are big-endian and fixed width', () => {
    expect(toHex(P.u8(0))).toBe('00');
    expect(toHex(P.u8(255))).toBe('ff');
    expect(toHex(P.u16(0x0102))).toBe('0102');
    expect(toHex(P.u16(0xffff))).toBe('ffff');
    expect(toHex(P.u32(0xdeadbeef))).toBe('deadbeef');
    expect(toHex(P.u32(0))).toBe('00000000');
    expect(toHex(P.u64(0))).toBe('0000000000000000');
    expect(toHex(P.u64(2 ** 32 + 5))).toBe('0000000100000005');
    expect(toHex(P.u64(Number.MAX_SAFE_INTEGER))).toBe('001fffffffffffff');
  });

  it('rejects out-of-range / non-integer values instead of silently truncating', () => {
    for (const x of [-1, 256, 1.5, NaN, Infinity]) expect(() => P.u8(x), `u8(${x})`).toThrow(Error);
    for (const x of [-1, 65536, 1.5, NaN]) expect(() => P.u16(x), `u16(${x})`).toThrow(Error);
    for (const x of [-1, 2 ** 32, 1.5, NaN]) expect(() => P.u32(x), `u32(${x})`).toThrow(Error);
    for (const x of [-1, 2 ** 53, 1.5, NaN]) expect(() => P.u64(x), `u64(${x})`).toThrow(Error);
  });
});

describe('encoding: enc / dec', () => {
  it('matches hand-computed bytes', () => {
    expect(toHex(P.enc())).toBe('');
    expect(toHex(P.enc(''))).toBe('00000000');
    expect(toHex(P.enc('segv'))).toBe('0000000473656776');
    expect(toHex(P.enc('a', Uint8Array.of(1, 2)))).toBe('0000000161000000020102');
    expect(toHex(P.enc('é'))).toBe('00000002c3a9'); // strings are UTF-8 encoded
    expect(toHex(P.lp(Uint8Array.of(0xff)))).toBe('00000001ff');
    expect(toHex(P.enc(new Uint8Array(0), new Uint8Array(0)))).toBe('0000000000000000');
  });

  it('matches the reference encoder', () => {
    const r = prng(7);
    for (let t = 0; t < 200; t++) {
      const parts = Array.from({ length: r.int(5) }, () => r.bytes(r.int(300)));
      expect(toHex(P.enc(...parts))).toBe(toHex(refEnc(...parts)));
    }
  });

  it('dec inverts enc for any field count', () => {
    const r = prng(8);
    for (let t = 0; t < 200; t++) {
      const parts = Array.from({ length: r.int(6) }, () => r.bytes(r.int(100)));
      const got = P.dec(P.enc(...parts), parts.length);
      expect(got.map(toHex)).toEqual(parts.map(toHex));
    }
  });

  it('dec works on a subarray with a non-zero byteOffset', () => {
    const inner = P.enc('abc', Uint8Array.of(9));
    const outer = cat(Uint8Array.of(0xaa, 0xbb, 0xcc), inner, Uint8Array.of(0xdd));
    const view = outer.subarray(3, 3 + inner.length);
    expect(P.dec(view, 2).map(toHex)).toEqual(['616263', '09']);
  });

  it('dec rejects malformed input', () => {
    const good = P.enc('ab', 'c');
    expect(() => P.dec(good, 1)).toThrow(/trailing/); // too few fields requested
    expect(() => P.dec(good, 3)).toThrow(/truncated/); // too many fields requested
    expect(() => P.dec(good.subarray(0, good.length - 1), 2)).toThrow(/truncated/);
    expect(() => P.dec(cat(good, Uint8Array.of(0)), 2)).toThrow(/trailing/);
    expect(() => P.dec(Uint8Array.of(0, 0, 0), 1)).toThrow(/truncated/); // short length prefix
    expect(() => P.dec(Uint8Array.of(0xff, 0xff, 0xff, 0xff, 1), 1)).toThrow(/truncated/); // 4 GiB length
    expect(() => P.dec(Uint8Array.of(0, 0, 0, 5, 1, 2), 1)).toThrow(/truncated/);
    expect(P.dec(new Uint8Array(0), 0)).toEqual([]);
    expect(() => P.dec(Uint8Array.of(0), 0)).toThrow(/trailing/);
  });
});

describe('encoding: b64u', () => {
  it('RFC 4648 §10 vectors (url alphabet, no padding)', () => {
    const v: [string, string][] = [
      ['', ''],
      ['f', 'Zg'],
      ['fo', 'Zm8'],
      ['foo', 'Zm9v'],
      ['foob', 'Zm9vYg'],
      ['fooba', 'Zm9vYmE'],
      ['foobar', 'Zm9vYmFy'],
    ];
    for (const [plain, enc] of v) {
      expect(P.b64u(s2b(plain))).toBe(enc);
      expect(P.fromUtf8(P.fromB64u(enc))).toBe(plain);
    }
    // url-safe characters: 0xfb 0xef 0xbe -> 111110 111110 111110 111110 -> "----"
    expect(P.b64u(Uint8Array.of(0xfb, 0xef, 0xbe))).toBe('----');
    expect(P.b64u(Uint8Array.of(0xff, 0xff, 0xff))).toBe('____');
    expect(P.b64u(Uint8Array.of(0xfb, 0xff))).toBe('-_8');
  });

  it('round-trips every length 0..64 and agrees with Node base64url', () => {
    const r = prng(9);
    for (let n = 0; n <= 64; n++) {
      for (let t = 0; t < 4; t++) {
        const b = t === 0 ? fill(n, 0xff) : t === 1 ? new Uint8Array(n) : r.bytes(n);
        const s = P.b64u(b);
        expect(s).toBe(Buffer.from(b).toString('base64url'));
        expect(s).toMatch(/^[A-Za-z0-9_-]*$/);
        expect(toHex(P.fromB64u(s))).toBe(toHex(b));
      }
    }
  });

  it('rejects non-canonical encodings, padding and bad characters', () => {
    expect(() => P.fromB64u('Zh')).toThrow(); // 'f' is "Zg": leftover bits must be zero
    expect(() => P.fromB64u('Zm9')).toThrow(); // "fo" is "Zm8"
    expect(() => P.fromB64u('Zg==')).toThrow(); // padding
    expect(() => P.fromB64u('Zg=')).toThrow();
    expect(() => P.fromB64u('Z')).toThrow(); // length % 4 == 1
    expect(() => P.fromB64u('Zm9vY')).toThrow();
    for (const bad of ['Zm+v', 'Zm/v', 'Zm v', 'Zm\nv', 'Zm.v', 'Zm9v\0', 'Zmé9', 'Z\u{1F600}', 'Ｚｇ']) {
      expect(() => P.fromB64u(bad), JSON.stringify(bad)).toThrow();
    }
    for (const notString of [null, undefined, 5, {}, []]) expect(() => P.fromB64u(notString as unknown as string)).toThrow();
    for (let n = 1; n <= 40; n++) {
      if (n % 3 === 0) continue; // no leftover bits
      const s = P.b64u(seqBytes(n, 0x10));
      expect(() => P.fromB64u(nonCanonical(s)), `len ${n}`).toThrow();
    }
  });
});

describe('encoding: misc helpers', () => {
  it('hex, equalBytes, concat, trunc16', () => {
    expect(P.hex(Uint8Array.of(0, 15, 255))).toBe('000fff');
    expect(P.equalBytes(Uint8Array.of(1, 2), Uint8Array.of(1, 2))).toBe(true);
    expect(P.equalBytes(Uint8Array.of(1, 2), Uint8Array.of(1, 3))).toBe(false);
    expect(P.equalBytes(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 0))).toBe(false);
    expect(P.equalBytes(new Uint8Array(0), new Uint8Array(0))).toBe(true);
    expect(toHex(P.concat(Uint8Array.of(1), new Uint8Array(0), Uint8Array.of(2, 3)))).toBe('010203');
    const t = P.trunc16(seqBytes(32));
    expect(toHex(t)).toBe(toHex(seqBytes(16)));
    const src = seqBytes(32);
    P.trunc16(src)[0] = 0xff; // trunc16 copies
    expect(src[0]).toBe(0);
  });

  it('utf8 / fromUtf8 round trip and reject invalid UTF-8', () => {
    for (const s of ['', 'abc', 'é', '日本語', '\u{1F600}', 'a\u0000b']) expect(P.fromUtf8(P.utf8(s))).toBe(s);
    expect(() => P.fromUtf8(Uint8Array.of(0xff))).toThrow(Error);
    expect(() => P.fromUtf8(Uint8Array.of(0xc3))).toThrow(Error); // truncated sequence
    expect(() => P.fromUtf8(Uint8Array.of(0xed, 0xa0, 0x80))).toThrow(Error); // lone surrogate
    expect(() => P.fromUtf8(Uint8Array.of(0xc0, 0xaf))).toThrow(Error); // overlong '/'
  });
});

describe('primitives match standards / node:crypto', () => {
  it('H = SHA-256 (FIPS 180 "abc")', () => {
    expect(toHex(P.H(s2b('abc')))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('HMAC = HMAC-SHA-256 (RFC 4231 case 2)', () => {
    expect(toHex(P.HMAC(s2b('Jefe'), s2b('what do ya want for nothing?')))).toBe(
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    );
  });

  it('HKDF = HKDF-SHA-256 (RFC 5869 case 1) and matches node for empty salt', () => {
    const okm = P.HKDF(fill(22, 0x0b), seqBytes(13), seqBytes(10, 0xf0), 42);
    expect(toHex(okm)).toBe('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
    expect(toHex(okm)).toBe(toHex(hkdfN(fill(22, 0x0b), seqBytes(13), seqBytes(10, 0xf0), 42)));
    expect(toHex(P.HKDF(seqBytes(32), '', 'segv.sh/v1/id/ed25519'))).toBe(toHex(hkdfN(seqBytes(32), '', 'segv.sh/v1/id/ed25519')));
    expect(P.HKDF(seqBytes(32), '', 'x').length).toBe(32);
  });

  it('Ed25519 sign/verify = RFC 8032 test 1 and agrees with node', () => {
    const sk = fromHex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
    const pk = P.sigPub(sk);
    expect(toHex(pk)).toBe('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    const sig = P.sign(new Uint8Array(0), sk);
    expect(toHex(sig)).toBe(
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
    );
    expect(P.verify(sig, new Uint8Array(0), pk)).toBe(true);
    expect(nodeEdVerify(sig, new Uint8Array(0), pk)).toBe(true);
  });

  it('verify() fails closed on malformed inputs', () => {
    const msg = s2b('m');
    const sig = P.sign(msg, alice.id.sigSk);
    expect(P.verify(sig.subarray(0, 63), msg, alice.id.sigPk)).toBe(false);
    expect(P.verify(cat(sig, Uint8Array.of(0)), msg, alice.id.sigPk)).toBe(false);
    expect(P.verify(sig, msg, alice.id.sigPk.subarray(0, 31))).toBe(false);
    expect(P.verify(sig, msg, fill(32, 0xff))).toBe(false); // not a point
    expect(P.verify(new Uint8Array(64), msg, alice.id.sigPk)).toBe(false);
  });

  it('X25519 = RFC 7748 §6.1', () => {
    const a = fromHex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    const b = fromHex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
    expect(toHex(x25519.getPublicKey(a))).toBe('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
    const s = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';
    expect(toHex(x25519.getSharedSecret(a, x25519.getPublicKey(b)))).toBe(s);
    expect(toHex(nodeX25519(b, x25519.getPublicKey(a)))).toBe(s);
  });

  it('AEAD is XChaCha20-Poly1305 with layout nonce || ct || tag (draft-irtf-cfrg-xchacha A.3.1)', () => {
    const key = seqBytes(32, 0x80);
    const nonce = seqBytes(24, 0x40);
    const aad = fromHex('50515253c0c1c2c3c4c5c6c7');
    const pt =
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const ct =
      'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e';
    const tag = 'c0875924c1c7987947deafd8780acf49';
    expect(P.fromUtf8(P.aeadOpen(key, cat(nonce, fromHex(ct + tag)), aad))).toBe(pt);
  });

  it('aeadSeal uses a fresh random 24-byte nonce', () => {
    const k = fill(32, 1);
    const a = P.aeadSeal(k, s2b('x'), new Uint8Array(0));
    const b = P.aeadSeal(k, s2b('x'), new Uint8Array(0));
    expect(a.length).toBe(24 + 1 + 16);
    expect(toHex(a.subarray(0, 24))).not.toBe(toHex(b.subarray(0, 24)));
    expect(toHex(P.aeadOpen(k, a, new Uint8Array(0)))).toBe('78');
    expect(() => P.aeadOpen(k, a.subarray(0, 39), new Uint8Array(0))).toThrow(/short/);
    expect(() => P.aeadOpen(k, a, Uint8Array.of(0))).toThrow();
  });

  it('kemKeygen is deterministic X-Wing with the documented sizes', () => {
    const a = P.kemKeygen(fill(32, 1));
    const b = P.kemKeygen(fill(32, 1));
    const c = P.kemKeygen(fill(32, 2));
    expect(a.pk.length).toBe(P.KEM_PK_LEN);
    expect(a.sk.length).toBe(32);
    expect(toHex(a.pk)).toBe(toHex(b.pk));
    expect(toHex(a.pk)).not.toBe(toHex(c.pk));
    const { cipherText, sharedSecret } = xwing.encapsulate(a.pk);
    expect(cipherText.length).toBe(P.KEM_CT_LEN);
    expect(toHex(xwing.decapsulate(cipherText, a.sk))).toBe(toHex(sharedSecret));
  });
});

describe('padding', () => {
  it('pad picks the smallest class >= len+1 (exact boundaries)', () => {
    const cases: [number, number][] = [
      [0, 1024],
      [255, 1024],
      [256, 1024],
      [1023, 1024],
      [1024, 4096],
      [4095, 4096],
      [4096, 16384],
      [16383, 16384],
    ];
    for (const [n, cls] of cases) {
      const x = fill(n, 0xab);
      const p = P.pad(x, P.MSG_CLASSES);
      expect(p.length, `len ${n}`).toBe(cls);
      expect(p[n]).toBe(0x80);
      expect(p.subarray(n + 1).every((v) => v === 0)).toBe(true);
      expect(toHex(p)).toBe(toHex(refPad(x, P.MSG_CLASSES)));
      expect(toHex(P.unpad(p))).toBe(toHex(x));
    }
    expect(() => P.pad(new Uint8Array(16384), P.MSG_CLASSES)).toThrow(/too large/);
    // Invites have a single class: anything that needs more than 2048 bytes cannot be sent at all.
    expect(P.pad(new Uint8Array(0), P.INV_CLASSES).length).toBe(2048);
    expect(P.pad(new Uint8Array(2047), P.INV_CLASSES).length).toBe(2048);
    expect(() => P.pad(new Uint8Array(2048), P.INV_CLASSES)).toThrow(/too large/);
    expect(() => P.pad(new Uint8Array(16383), P.INV_CLASSES)).toThrow(/too large/);
  });

  it('size classes are exactly kind 4: 1024 | 4096 | 16384 (no 256), kind 3: 2048 (no 16384)', () => {
    expect([...P.MSG_CLASSES]).toEqual([1024, 4096, 16384]);
    expect([...P.INV_CLASSES]).toEqual([2048]);
    expect(P.MSG_BODY_LENS).toEqual([24 + 1024 + 16, 24 + 4096 + 16, 24 + 16384 + 16]);
    expect(P.INV_BODY_LENS).toEqual([32 + 1120 + 24 + 2048 + 16]);
    // the retired classes are gone
    expect(P.MSG_BODY_LENS).not.toContain(24 + 256 + 16);
    expect(P.INV_BODY_LENS).not.toContain(32 + 1120 + 24 + 16384 + 16);
    // the empty payload lands in the smallest class
    expect(P.pad(new Uint8Array(0), P.MSG_CLASSES).length).toBe(1024);
  });

  it('unpad round-trips data that itself ends in 0x00 or 0x80', () => {
    for (const x of [Uint8Array.of(0), Uint8Array.of(0x80), Uint8Array.of(1, 0x80, 0), Uint8Array.of(0x80, 0x80), new Uint8Array(0)]) {
      expect(toHex(P.unpad(P.pad(x, P.MSG_CLASSES)))).toBe(toHex(x));
      expect(toHex(P.unpad(P.padme(x)))).toBe(toHex(x));
    }
  });

  it('unpad rejects missing / wrong markers', () => {
    expect(() => P.unpad(new Uint8Array(0))).toThrow(/bad padding/);
    expect(() => P.unpad(new Uint8Array(256))).toThrow(/bad padding/);
    expect(() => P.unpad(Uint8Array.of(1, 2, 3))).toThrow(/bad padding/);
    expect(() => P.unpad(Uint8Array.of(0x80, 0x01))).toThrow(/bad padding/);
    expect(() => P.unpad(Uint8Array.of(0x80, 0x01, 0))).toThrow(/bad padding/);
    expect(() => P.unpad(Uint8Array.of(0x81, 0))).toThrow(/bad padding/);
    expect(toHex(P.unpad(Uint8Array.of(0x80)))).toBe('');
  });

  it('padmeLength matches the exact integer formula for every L in 0..70000', () => {
    for (let L = 0; L <= 70000; L++) {
      const got = P.padmeLength(L);
      if (got !== refPadmeLength(L)) expect(got, `L=${L}`).toBe(refPadmeLength(L));
    }
  });

  it('padmeLength is exact at power-of-two boundaries up to 2^40', () => {
    for (let k = 1; k <= 40; k++) {
      for (const d of [-2, -1, 0, 1, 2]) {
        const L = 2 ** k + d;
        if (L < 0) continue;
        expect(P.padmeLength(L), `L=2^${k}${d >= 0 ? '+' : ''}${d}`).toBe(refPadmeLength(L));
      }
    }
    // Hand-computed: L=9: E=3,S=2,z=1 -> 10; L=100: E=6,S=3,z=3 -> 104; L=1000: E=9,S=4,z=5 -> 1024.
    expect([0, 1, 2, 3, 9, 100, 1000, 8 * 1024 * 1024 + 1].map(P.padmeLength)).toEqual([0, 1, 2, 3, 10, 104, 1024, 8650752]);
  });

  it('padmeLength is monotone, idempotent and leaks at most ~12%', () => {
    let prev = 0;
    for (let L = 2; L <= 20000; L++) {
      const p = P.padmeLength(L);
      expect(p >= L && p >= prev).toBe(true);
      expect(P.padmeLength(p)).toBe(p);
      expect((p - L) / L).toBeLessThanOrEqual(0.12);
      prev = p;
    }
  });

  it('padme output length = Padmé(len+1) with a 0x80 marker', () => {
    for (const n of [0, 1, 2, 7, 8, 9, 63, 64, 1000, 4096, 100000]) {
      const x = fill(n, 0x5a);
      const p = P.padme(x);
      expect(p.length).toBe(refPadmeLength(n + 1));
      expect(p[n]).toBe(0x80);
      expect(toHex(P.unpad(p))).toBe(toHex(x));
    }
  });
});

describe('accounts: identity derivation', () => {
  it('is deterministic and follows §2.1 exactly', () => {
    const AK = seqBytes(32);
    const a = P.deriveIdentity(AK);
    const b = P.deriveIdentity(AK.slice());
    for (const k of ['sigSk', 'sigPk', 'kemSk', 'kemPk', 'scanSk', 'scanPk'] as const) expect(toHex(a[k])).toBe(toHex(b[k]));
    expect(toHex(a.sigSk)).toBe(toHex(hkdfN(AK, '', 'segv.sh/v1/id/ed25519')));
    expect(toHex(a.scanSk)).toBe(toHex(hkdfN(AK, '', 'segv.sh/v1/id/scan')));
    expect(toHex(a.kemPk)).toBe(toHex(xwing.keygen(hkdfN(AK, '', 'segv.sh/v1/id/xwing')).publicKey));
    expect(toHex(a.sigPk)).toBe(toHex(nodeRawPub(ED_PKCS8, a.sigSk)));
    expect(toHex(a.scanPk)).toBe(toHex(nodeRawPub(X_PKCS8, a.scanSk)));
    expect([a.sigSk.length, a.sigPk.length, a.kemSk.length, a.kemPk.length, a.scanSk.length, a.scanPk.length]).toEqual([
      32, 32, 32, 1216, 32, 32,
    ]);
  });

  it('different AKs give unrelated keys; the three secrets are distinct', () => {
    const a = P.deriveIdentity(fill(32, 1));
    const b = P.deriveIdentity(flip(fill(32, 1), 31, 7));
    expect(toHex(a.sigPk)).not.toBe(toHex(b.sigPk));
    expect(toHex(a.kemPk)).not.toBe(toHex(b.kemPk));
    expect(toHex(a.scanPk)).not.toBe(toHex(b.scanPk));
    expect(new Set([toHex(a.sigSk), toHex(a.scanSk), toHex(a.kemSk)]).size).toBe(3);
  });

  it('rejects AKs that are not 32 bytes', () => {
    for (const n of [0, 16, 31, 33, 64]) expect(() => P.deriveIdentity(new Uint8Array(n))).toThrow(/32 bytes/);
  });
});

describe('accounts: bundles', () => {
  it('make -> verify -> parse round trip with the exact §2.2 JSON', () => {
    const u = alice.user;
    expect(u.uid).toBe(alice.uidS);
    expect(u.handle).toBe('alice');
    expect(toHex(u.sigPk)).toBe(toHex(alice.id.sigPk));
    expect(toHex(u.kemPk)).toBe(toHex(alice.id.kemPk));
    expect(toHex(u.scanPk)).toBe(toHex(alice.id.scanPk));
    expect(u.bundle).toBe(alice.bundle);
    expect(u.bundleSig).toBe(alice.sig);
    expect(u.ts).toBe(TS + 0xa1);
    expect(alice.bundle).toBe(
      JSON.stringify({
        v: 1,
        uid: alice.uidS,
        handle: 'alice',
        sig: P.b64u(alice.id.sigPk),
        kem: P.b64u(alice.id.kemPk),
        scan: P.b64u(alice.id.scanPk),
        ts: TS + 0xa1,
      }),
    );
    // Signature is over enc("segv.sh/v1/bundle", bundleBytes), checked with an independent verifier.
    expect(nodeEdVerify(P.fromB64u(alice.sig), refEnc('segv.sh/v1/bundle', alice.bundle), alice.id.sigPk)).toBe(true);
    expect(P.parseBundle(alice.bundle, alice.sig).uid).toBe(alice.uidS);
  });

  it('makeBundle validates its inputs', () => {
    const id = alice.id;
    for (const h of ['al', 'Alice', 'a'.repeat(21), 'al-ice', 'al ice', 'ålice', 'alice\n', '', 'al.ice']) {
      expect(() => P.makeBundle(alice.uid, h, id, TS), JSON.stringify(h)).toThrow(/handle/);
    }
    for (const h of ['abc', 'a'.repeat(20), 'a_b_9', '___', '012']) expect(() => P.makeBundle(alice.uid, h, id, TS)).not.toThrow();
    expect(() => P.makeBundle(new Uint8Array(15), 'alice', id, TS)).toThrow(/uid/);
    expect(() => P.makeBundle(new Uint8Array(17), 'alice', id, TS)).toThrow(/uid/);
  });

  it('parseBundle rejects every malformed field', () => {
    const base = JSON.parse(alice.bundle) as Record<string, unknown>;
    const mut = (over: Record<string, unknown>) => JSON.stringify({ ...base, ...over });
    const bad: [string, string, string?][] = [
      ['not JSON', '{'],
      ['array', '[]'],
      ['null', 'null'],
      ['v=2', mut({ v: 2 })],
      ['v missing', mut({ v: undefined })],
      ['uid 15 bytes', mut({ uid: P.b64u(new Uint8Array(15)) })],
      ['uid non-canonical', mut({ uid: nonCanonical(alice.uidS) })],
      ['uid missing', mut({ uid: undefined })],
      ['handle uppercase', mut({ handle: 'Alice' })],
      ['handle short', mut({ handle: 'ab' })],
      ['handle number', mut({ handle: 123 })],
      ['sig 31 bytes', mut({ sig: P.b64u(new Uint8Array(31)) })],
      ['kem 1215 bytes', mut({ kem: P.b64u(new Uint8Array(1215)) })],
      ['scan 33 bytes', mut({ scan: P.b64u(new Uint8Array(33)) })],
      ['scan missing', mut({ scan: undefined })],
      ['ts negative', mut({ ts: -1 })],
      ['ts float', mut({ ts: 1.5 })],
      ['ts string', mut({ ts: '1' })],
      ['ts unsafe', mut({ ts: 2 ** 53 })],
      ['signature 63 bytes', alice.bundle, P.b64u(new Uint8Array(63))],
      ['signature not b64u', alice.bundle, '!!'],
    ];
    for (const [name, text, sig] of bad) expect(() => P.parseBundle(text, sig ?? alice.sig), name).toThrow(Error);
  });

  it('verifyBundle: signature binds the exact bytes', () => {
    // modified handle, re-serialised
    const tampered = alice.bundle.replace('"handle":"alice"', '"handle":"alicf"');
    expect(tampered).not.toBe(alice.bundle);
    expect(() => P.parseBundle(tampered, alice.sig)).not.toThrow();
    expect(() => P.verifyBundle(tampered, alice.sig)).toThrow(/signature/);
    // same JSON value, different bytes (whitespace) -> must fail: nobody re-serialises signed JSON
    const spaced = JSON.stringify(JSON.parse(alice.bundle), null, 1);
    expect(() => P.verifyBundle(spaced, alice.sig)).toThrow(/signature/);
    // another user's valid signature
    expect(() => P.verifyBundle(alice.bundle, bob.sig)).toThrow(/signature/);
    // bundle claiming alice's keys but signed by bob
    const forged = P.b64u(P.sign(P.bundleSigMsg(alice.bundle), bob.id.sigSk));
    expect(() => P.verifyBundle(alice.bundle, forged)).toThrow(/signature/);
    // signature over the bundle without the domain label
    const noLabel = P.b64u(P.sign(P.utf8(alice.bundle), alice.id.sigSk));
    expect(() => P.verifyBundle(alice.bundle, noLabel)).toThrow(/signature/);
  });

  it('fingerprint: format and binding to every key', () => {
    const fp = P.fingerprint(alice.user);
    expect(fp).toMatch(/^\d{5}( \d{5}){5}$/);
    expect(P.fingerprint(alice.user)).toBe(fp);
    expect(P.fingerprint(bob.user)).not.toBe(fp);
    expect(P.fingerprint({ ...alice.user, uid: bob.uidS })).not.toBe(fp);
    expect(P.fingerprint({ ...alice.user, sigPk: bob.user.sigPk })).not.toBe(fp);
    expect(P.fingerprint({ ...alice.user, kemPk: bob.user.kemPk })).not.toBe(fp);
    expect(P.fingerprint({ ...alice.user, scanPk: bob.user.scanPk })).not.toBe(fp);
    // independent computation: group k = u40(fp[5k..5k+5]) mod 100000
    const h = sha(refEnc('segv.sh/v1/fp', alice.uid, alice.id.sigPk, alice.id.kemPk, alice.id.scanPk));
    const groups = Array.from({ length: 6 }, (_, k) =>
      String(BigInt('0x' + toHex(h.subarray(5 * k, 5 * k + 5))) % 100000n).padStart(5, '0'),
    );
    expect(fp).toBe(groups.join(' '));
  });
});

describe('sealing (KEM-DEM, §2.3)', () => {
  const kp = P.kemKeygen(fill(32, 0x5e));
  const other = P.kemKeygen(fill(32, 0x5f));
  const ctx = Uint8Array.of(1, 2, 3);

  it('round trip and spec layout kct || nonce || AEAD', () => {
    const pt = s2b('secret');
    const box = P.seal(kp.pk, 'lbl', ctx, pt);
    expect(box.length).toBe(1120 + 24 + pt.length + 16);
    expect(P.fromUtf8(P.open(kp.sk, 'lbl', ctx, box))).toBe('secret');
    // independent decryption per §2.3
    const kct = box.subarray(0, 1120);
    const ss = xwing.decapsulate(kct, kp.sk);
    const k = hkdfN(ss, sha(kct), refEnc('segv.sh/v1/seal', 'lbl', ctx));
    const pt2 = xchacha20poly1305(k, box.subarray(1120, 1144), refEnc('lbl', ctx)).decrypt(box.subarray(1144));
    expect(P.fromUtf8(pt2)).toBe('secret');
    // two seals of the same plaintext differ
    expect(toHex(P.seal(kp.pk, 'lbl', ctx, pt))).not.toBe(toHex(box));
    expect(P.open(kp.sk, 'lbl', ctx, P.seal(kp.pk, 'lbl', ctx, new Uint8Array(0))).length).toBe(0);
  });

  it('wrong key / label / ctx / short box all throw', () => {
    const box = P.seal(kp.pk, 'lbl', ctx, s2b('secret'));
    expect(() => P.open(other.sk, 'lbl', ctx, box)).toThrow();
    expect(() => P.open(kp.sk, 'lbl2', ctx, box)).toThrow();
    expect(() => P.open(kp.sk, 'lbl', Uint8Array.of(1, 2), box)).toThrow();
    expect(() => P.open(kp.sk, 'lbl', Uint8Array.of(1, 2, 3, 0), box)).toThrow();
    // label/ctx boundary must not be ambiguous: ("lbl", 0x01..) vs ("lbl\x01", ..)
    expect(() => P.open(kp.sk, 'lbl\u0001', Uint8Array.of(2, 3), box)).toThrow();
    expect(() => P.open(kp.sk, 'lbl', ctx, box.subarray(0, 1120 + 24 + 15))).toThrow(/short/);
    expect(() => P.open(kp.sk, 'lbl', ctx, box.subarray(0, box.length - 1))).toThrow();
    expect(() => P.open(kp.sk, 'lbl', ctx, cat(box, Uint8Array.of(0)))).toThrow();
    expect(() => P.seal(fill(1216, 0xff), 'lbl', ctx, s2b('x'))).toThrow(); // invalid KEM pk
  });

  it('a bit flip anywhere (kct / nonce / ciphertext / tag) is rejected', () => {
    const box = P.seal(kp.pk, 'lbl', ctx, seqBytes(40));
    const s = survivors(
      box,
      [
        { name: 'kct', start: 0, end: 1120 },
        { name: 'nonce', start: 1120, end: 1144, every: true },
        { name: 'ct', start: 1144, end: 1184, every: true },
        { name: 'tag', start: 1184, end: 1200, every: true },
      ],
      (b) => P.open(kp.sk, 'lbl', ctx, b),
    );
    expect(s).toEqual([]);
  });
});

// ───────────────────────── wraps ─────────────────────────

describe('passkey & recovery wraps (§2.4)', () => {
  const prf = fill(32, 0x11);
  const credId = seqBytes(20, 0x80);
  const cred = P.credKem(prf, credId);
  const code = seqBytes(20, 0x30);
  const rec = P.recoveryKem(code);
  const pkWrap = P.makeWrap(alice.uid, 'passkey', credId, cred, alice.AK, alice.id, TS);
  const recWrap = P.makeWrap(alice.uid, 'recovery', rec.id, rec, alice.AK, alice.id, TS + 1);

  /** Independent open per §2.3 / §2.4: seal(kemPk, "ak-wrap", ctx = enc(uid, id, auth), AK). */
  const refOpenWrap = (box: B, sk: B, ctx: B): B => {
    const kct = box.subarray(0, 1120);
    const k = hkdfN(xwing.decapsulate(kct, sk), sha(kct), refEnc('segv.sh/v1/seal', 'ak-wrap', ctx));
    return xchacha20poly1305(k, box.subarray(1120, 1144), refEnc('ak-wrap', ctx)).decrypt(box.subarray(1144));
  };
  /** Signs an arbitrary record as `signer` (what anyone can POST to /api/wraps for their own uid). */
  const signRecord = (raw: Record<string, unknown>, signer: TUser) => {
    const record = JSON.stringify(raw);
    return { record, sig: P.b64u(P.sign(P.wrapSigMsg(record), signer.id.sigSk)) };
  };

  it('credKem / recoveryKem are deterministic and follow the spec KDFs', () => {
    const credSeed = hkdfN(prf, credId, 'segv.sh/v1/cred/xwing');
    expect(toHex(P.credKem(prf, credId).pk)).toBe(toHex(cred.pk));
    expect(toHex(cred.pk)).toBe(toHex(xwing.keygen(credSeed).publicKey));
    expect(toHex(cred.sk)).toBe(toHex(xwing.keygen(credSeed).secretKey));
    expect(toHex(cred.auth)).toBe(toHex(hkdfN(prf, credId, 'segv.sh/v1/cred/auth')));
    expect(toHex(P.credKem(prf, credId).auth)).toBe(toHex(cred.auth));
    expect(cred.auth.length).toBe(32);
    expect(toHex(cred.auth)).not.toBe(toHex(cred.sk));
    // credId is the salt of both outputs; the PRF output is the only secret
    for (const other of [P.credKem(prf, seqBytes(20, 0x81)), P.credKem(fill(32, 0x12), credId)]) {
      expect(toHex(other.pk)).not.toBe(toHex(cred.pk));
      expect(toHex(other.auth)).not.toBe(toHex(cred.auth));
    }
    for (const n of [0, 31, 33]) expect(() => P.credKem(new Uint8Array(n), credId)).toThrow(/32 bytes/);

    const recSeed = hkdfN(code, '', 'segv.sh/v1/recovery/xwing');
    expect(rec.id.length).toBe(16);
    expect(toHex(rec.id)).toBe(toHex(hkdfN(code, '', 'segv.sh/v1/recovery/id', 16)));
    expect(toHex(rec.pk)).toBe(toHex(xwing.keygen(recSeed).publicKey));
    expect(toHex(rec.sk)).toBe(toHex(xwing.keygen(recSeed).secretKey));
    expect(toHex(rec.auth)).toBe(toHex(hkdfN(code, '', 'segv.sh/v1/recovery/auth')));
    expect(rec.auth.length).toBe(32);
    const again = P.recoveryKem(code);
    expect([again.sk, again.auth, again.id].map(toHex)).toEqual([rec.sk, rec.auth, rec.id].map(toHex));
    // the published id, the KEM seed and the secret auth are unrelated HKDF outputs
    expect(new Set([toHex(rec.auth), toHex(rec.sk), toHex(rec.id)]).size).toBe(3);
    expect(toHex(rec.auth).startsWith(toHex(rec.id))).toBe(false);
    expect(toHex(P.recoveryKem(seqBytes(20, 0x31)).auth)).not.toBe(toHex(rec.auth));
    expect(P.PRF_INPUT).toBe('segv.sh/v1/prf');
  });

  it('makeWrap -> verifyWrap -> openWrap / unwrapAK (passkey and recovery)', () => {
    for (const [w, key, kind, id] of [
      [pkWrap, cred, 'passkey', credId],
      [recWrap, rec, 'recovery', rec.id],
    ] as const) {
      const r = P.verifyWrap(w.record, w.sig, alice.id.sigPk);
      expect(r.kind).toBe(kind);
      expect(r.uid).toBe(alice.uidS);
      expect(toHex(r.id)).toBe(toHex(id));
      expect(toHex(r.kemPk)).toBe(toHex(key.pk));
      expect(r.wrap.length).toBe(P.WRAP_LEN);
      expect(toHex(P.openWrap(r, key))).toBe(toHex(alice.AK));
      expect(toHex(P.unwrapAK(r, key, alice.id.sigPk))).toBe(toHex(alice.AK));
      // independent open with the spec context enc(uid, id, auth) ...
      expect(toHex(refOpenWrap(r.wrap, key.sk, refEnc(alice.uid, id, key.auth)))).toBe(toHex(alice.AK));
      // ... and the pre-fix context enc(uid, id) no longer opens it
      expect(() => refOpenWrap(r.wrap, key.sk, refEnc(alice.uid, id))).toThrow();
      // auth is never published
      expect(w.record).not.toContain(P.b64u(key.auth));
    }
    expect(P.WRAP_LEN).toBe(1192);
    const raw = JSON.parse(pkWrap.record) as Record<string, unknown>;
    expect(Object.keys(raw)).toEqual(['v', 'uid', 'kind', 'id', 'kem', 'wrap', 'ts']);
    expect(nodeEdVerify(P.fromB64u(pkWrap.sig), refEnc('segv.sh/v1/wrap', pkWrap.record), alice.id.sigPk)).toBe(true);
    // the minimal key shapes are enough: makeWrap needs {pk, auth}, openWrap / unwrapAK need {sk, auth}
    const minimal = P.makeWrap(alice.uid, 'passkey', credId, { pk: cred.pk, auth: cred.auth }, alice.AK, alice.id, TS);
    const m = P.verifyWrap(minimal.record, minimal.sig, alice.id.sigPk);
    expect(toHex(P.unwrapAK(m, { sk: cred.sk, auth: cred.auth }, alice.id.sigPk))).toBe(toHex(alice.AK));
    expect(toHex(P.openWrap({ uid: m.uid, id: m.id, wrap: m.wrap }, { sk: cred.sk, auth: cred.auth }))).toBe(toHex(alice.AK));
  });

  it('openWrap only authenticates the box; unwrapAK adds the key check', () => {
    const otherAK = fill(32, 0x99);
    // Owner-signed record that (mistakenly or maliciously) wraps a different AK: the box is authentic ...
    const w = P.makeWrap(alice.uid, 'passkey', credId, cred, otherAK, alice.id, TS);
    const r = P.verifyWrap(w.record, w.sig, alice.id.sigPk);
    expect(toHex(P.openWrap(r, cred))).toBe(toHex(otherAK));
    // ... but the AK does not belong to the owner: no new keys on a failed unlock
    expect(() => P.unwrapAK(r, cred, alice.id.sigPk)).toThrow(/key check/);
    // Correct AK but checked against the wrong owner.
    expect(() => P.unwrapAK(P.parseWrap(pkWrap.record, pkWrap.sig), cred, bob.id.sigPk)).toThrow(/key check/);
    // The AK inside an authentic box must be exactly 32 bytes.
    for (const n of [0, 31, 33]) {
      const box = P.seal(cred.pk, 'ak-wrap', P.enc(alice.uid, credId, cred.auth), new Uint8Array(n));
      expect(() => P.openWrap({ uid: alice.uidS, id: credId, wrap: box }, cred), `AK of ${n} bytes`).toThrow(/AK length/);
    }
  });

  it('verifyWrap rejects wrong owner / tampered record / unlabeled signature', () => {
    expect(() => P.verifyWrap(pkWrap.record, pkWrap.sig, bob.id.sigPk)).toThrow(/signature/);
    expect(() => P.verifyWrap(pkWrap.record, recWrap.sig, alice.id.sigPk)).toThrow(/signature/);
    const tampered = pkWrap.record.replace(`"ts":${TS}`, `"ts":${TS + 1}`);
    expect(tampered).not.toBe(pkWrap.record);
    expect(() => P.verifyWrap(tampered, pkWrap.sig, alice.id.sigPk)).toThrow(/signature/);
    const kindSwap = pkWrap.record.replace('"kind":"passkey"', '"kind":"recovery"');
    expect(() => P.verifyWrap(kindSwap, pkWrap.sig, alice.id.sigPk)).toThrow(/signature/);
    const noLabel = P.b64u(P.sign(P.utf8(pkWrap.record), alice.id.sigSk));
    expect(() => P.verifyWrap(pkWrap.record, noLabel, alice.id.sigPk)).toThrow(/signature/);
    // A bundle signature must not double as a wrap signature (distinct labels).
    expect(() => P.verifyWrap(pkWrap.record, P.b64u(P.sign(P.bundleSigMsg(pkWrap.record), alice.id.sigSk)), alice.id.sigPk)).toThrow(
      /signature/,
    );
  });

  it('parseWrap rejects every malformed field', () => {
    const base = JSON.parse(pkWrap.record) as Record<string, unknown>;
    const mut = (over: Record<string, unknown>) => JSON.stringify({ ...base, ...over });
    const bad: [string, string][] = [
      ['not JSON', 'x'],
      ['array', '[1]'],
      ['v=2', mut({ v: 2 })],
      ['kind other', mut({ kind: 'password' })],
      ['kind missing', mut({ kind: undefined })],
      ['uid 15', mut({ uid: P.b64u(new Uint8Array(15)) })],
      ['uid missing', mut({ uid: undefined })],
      ['id empty', mut({ id: '' })],
      ['id 1024 bytes', mut({ id: P.b64u(new Uint8Array(1024)) })],
      ['id number', mut({ id: 5 })],
      ['id non-canonical', mut({ id: nonCanonical(base.id as string) })],
      ['kem short', mut({ kem: P.b64u(new Uint8Array(1215)) })],
      ['wrap short', mut({ wrap: P.b64u(new Uint8Array(1191)) })],
      ['wrap long', mut({ wrap: P.b64u(new Uint8Array(1193)) })],
      ['ts float', mut({ ts: 0.5 })],
      ['ts missing', mut({ ts: undefined })],
    ];
    for (const [name, text] of bad) expect(() => P.parseWrap(text, pkWrap.sig), name).toThrow(Error);
    expect(() => P.parseWrap(pkWrap.record, P.b64u(new Uint8Array(65)))).toThrow();
    expect(P.parseWrap(mut({ id: P.b64u(new Uint8Array(1023)) }), pkWrap.sig).id.length).toBe(1023);
    expect(P.parseWrap(mut({ id: P.b64u(new Uint8Array(1)) }), pkWrap.sig).id.length).toBe(1);
  });

  it('a wrap opens only with the matching auth', () => {
    const pw = P.parseWrap(pkWrap.record, pkWrap.sig);
    const rw = P.parseWrap(recWrap.record, recWrap.sig);
    expect(toHex(P.openWrap(pw, cred))).toBe(toHex(alice.AK));
    expect(toHex(P.openWrap(rw, rec))).toBe(toHex(alice.AK));
    // right KEM secret key, wrong auth
    const wrongAuths: [string, B][] = [
      ['zero', new Uint8Array(32)],
      ['ones', fill(32, 0xff)],
      ['empty', new Uint8Array(0)],
      ['truncated', cred.auth.subarray(0, 31)],
      ['extended', cat(cred.auth, Uint8Array.of(0))],
      ['recovery auth', rec.auth],
      ['other PRF', P.credKem(fill(32, 0x12), credId).auth],
      ['other credId', P.credKem(prf, seqBytes(20, 0x81)).auth],
      ['KEM seed as auth', cred.sk],
    ];
    for (const [name, auth] of wrongAuths) expect(() => P.openWrap(pw, { sk: cred.sk, auth }), name).toThrow();
    for (let i = 0; i < 32; i++) expect(() => P.openWrap(pw, { sk: cred.sk, auth: flip(cred.auth, i, i % 8) }), `auth[${i}]`).toThrow();
    for (const [name, auth] of [
      ['passkey auth', cred.auth],
      ['other code', P.recoveryKem(seqBytes(20, 0x31)).auth],
      ['zero', new Uint8Array(32)],
      ['recovery id', rec.id],
    ] as const) {
      expect(() => P.openWrap(rw, { sk: rec.sk, auth }), name).toThrow();
    }
    // right auth, wrong KEM secret key
    expect(() => P.openWrap(pw, { sk: rec.sk, auth: cred.auth })).toThrow();
    expect(() => P.openWrap(pw, { sk: P.credKem(fill(32, 0x12), credId).sk, auth: cred.auth })).toThrow();
    expect(() => P.openWrap(rw, { sk: cred.sk, auth: rec.auth })).toThrow();
    // unwrapAK goes through the same check
    expect(() => P.unwrapAK(pw, { sk: cred.sk, auth: new Uint8Array(32) }, alice.id.sigPk)).toThrow();
    expect(() => P.unwrapAK(rw, { sk: rec.sk, auth: cred.auth }, alice.id.sigPk)).toThrow();
  });

  describe('wrap substitution under a public id (an attacker files a wrap of their own AK)', () => {
    // Everything the attacker (carol) can see: the victim's (alice's) public wrap records.
    const vRec = P.parseWrap(recWrap.record, recWrap.sig);
    const vPk = P.parseWrap(pkWrap.record, pkWrap.sig);
    const attackerCode = seqBytes(20, 0x70);
    const attackerPrf = fill(32, 0x77);
    /** Every "auth" the attacker can compute from public data (plus their own secrets). */
    const guesses = (w: P.WrapRecord): [string, B][] => [
      ['zero', new Uint8Array(32)],
      ['empty', new Uint8Array(0)],
      ['ones', fill(32, 0xff)],
      ['id', w.id],
      ['victim uid', P.fromB64u(w.uid)],
      ['H(kem pk)', sha(w.kemPk)],
      ['H(victim box)', sha(w.wrap)],
      ['H(record)', sha(s2b(w.record))],
      ['victim record signature', P.fromB64u(w.sig).subarray(0, 32)],
      ['recovery KDF on the id', hkdfN(w.id, '', 'segv.sh/v1/recovery/auth')],
      ['recovery KDF on the kem pk', hkdfN(w.kemPk, '', 'segv.sh/v1/recovery/auth')],
      ['cred KDF on the kem pk', hkdfN(w.kemPk, w.id, 'segv.sh/v1/cred/auth')],
      ["attacker's own recovery auth", P.recoveryKem(attackerCode).auth],
      ["attacker's PRF with the victim's credId", P.credKem(attackerPrf, w.id).auth],
      ...Array.from({ length: 8 }, (_, i): [string, B] => [`random #${i}`, prng(0xa77ac + i).bytes(32)]),
    ];

    it('the server would accept the forged records (they are well-formed and attacker-signed)', () => {
      const f = P.makeWrap(carol.uid, 'recovery', vRec.id, { pk: vRec.kemPk, auth: new Uint8Array(32) }, carol.AK, carol.id, TS + 9);
      const r = P.verifyWrap(f.record, f.sig, carol.id.sigPk);
      expect(toHex(r.id)).toBe(toHex(rec.id));
      expect(toHex(r.kemPk)).toBe(toHex(rec.pk));
      // ... and the attacker cannot file it under the victim's uid
      const asVictim = signRecord({ ...(JSON.parse(f.record) as Record<string, unknown>), uid: alice.uidS }, carol);
      expect(() => P.verifyWrap(asVictim.record, asVictim.sig, alice.id.sigPk)).toThrow(/signature/);
    });

    it("recovery: no attacker wrap opens with the victim's recoveryKem(code)", () => {
      for (const [name, auth] of guesses(vRec)) {
        const f = P.makeWrap(carol.uid, 'recovery', vRec.id, { pk: vRec.kemPk, auth }, carol.AK, carol.id, TS + 9);
        const r = P.verifyWrap(f.record, f.sig, carol.id.sigPk);
        expect(() => P.openWrap(r, rec), name).toThrow();
        expect(() => P.unwrapAK(r, rec, carol.id.sigPk), name).toThrow();
        expect(() => P.unwrapAK(r, rec, alice.id.sigPk), name).toThrow();
      }
    });

    it("passkey: no attacker wrap opens with the victim's credKem(prf, credId)", () => {
      for (const [name, auth] of guesses(vPk)) {
        const f = P.makeWrap(carol.uid, 'passkey', vPk.id, { pk: vPk.kemPk, auth }, carol.AK, carol.id, TS + 9);
        const r = P.verifyWrap(f.record, f.sig, carol.id.sigPk);
        expect(() => P.openWrap(r, cred), name).toThrow();
        expect(() => P.unwrapAK(r, cred, carol.id.sigPk), name).toThrow();
      }
    });

    it('the pre-fix construction (ctx = enc(uid, id), no auth) no longer opens', () => {
      for (const [kind, v, key] of [
        ['recovery', vRec, rec],
        ['passkey', vPk, cred],
      ] as const) {
        const box = P.seal(v.kemPk, 'ak-wrap', P.enc(carol.uid, v.id), carol.AK);
        const f = signRecord({ v: 1, uid: carol.uidS, kind, id: P.b64u(v.id), kem: P.b64u(v.kemPk), wrap: P.b64u(box), ts: TS + 9 }, carol);
        const r = P.verifyWrap(f.record, f.sig, carol.id.sigPk);
        expect(() => P.openWrap(r, key), kind).toThrow();
        expect(() => P.unwrapAK(r, key, carol.id.sigPk), kind).toThrow();
      }
    });

    it("copying the victim's box into the attacker's record does not open (the box is bound to the victim's uid)", () => {
      for (const [kind, v, key] of [
        ['recovery', vRec, rec],
        ['passkey', vPk, cred],
      ] as const) {
        const f = signRecord({ v: 1, uid: carol.uidS, kind, id: P.b64u(v.id), kem: P.b64u(v.kemPk), wrap: P.b64u(v.wrap), ts: TS + 9 }, carol);
        const r = P.verifyWrap(f.record, f.sig, carol.id.sigPk);
        expect(() => P.openWrap(r, key), kind).toThrow();
        expect(() => P.unwrapAK(r, key, carol.id.sigPk), kind).toThrow();
      }
    });

    it('a recovery login (all wraps under recId, newest first, no uid filter) still finds the victim', () => {
      const bundles = new Map([alice, bob, carol].map((u) => [u.uidS, u.user]));
      /** Mirrors the client: try every record filed under the code's id, newest first. */
      const recoveryLogin = (c: B, log: { record: string; sig: string }[]) => {
        const k = P.recoveryKem(c);
        for (const w of [...log].reverse()) {
          try {
            const r = P.parseWrap(w.record, w.sig);
            const owner = bundles.get(r.uid);
            if (!owner || !P.equalBytes(r.id, k.id)) continue;
            return { uid: P.verifyWrap(w.record, w.sig, owner.sigPk).uid, AK: P.unwrapAK(r, k, owner.sigPk) };
          } catch {
            /* not ours */
          }
        }
        return null;
      };
      const forged = [
        ...guesses(vRec).map(([, auth]) => P.makeWrap(carol.uid, 'recovery', vRec.id, { pk: vRec.kemPk, auth }, carol.AK, carol.id, TS + 9)),
        signRecord({ v: 1, uid: carol.uidS, kind: 'recovery', id: P.b64u(vRec.id), kem: P.b64u(vRec.kemPk), wrap: P.b64u(vRec.wrap), ts: TS + 9 }, carol),
      ];
      const got = recoveryLogin(code, [recWrap, ...forged]);
      expect(got?.uid).toBe(alice.uidS);
      expect(toHex(got!.AK)).toBe(toHex(alice.AK));
      // without the genuine record nothing unlocks (in particular not the attacker's account)
      expect(recoveryLogin(code, forged)).toBeNull();
      // and the attacker's own code still opens only the attacker's own wrap
      const ak = P.recoveryKem(attackerCode);
      const own = P.makeWrap(carol.uid, 'recovery', ak.id, ak, carol.AK, carol.id, TS + 10);
      expect(recoveryLogin(attackerCode, [recWrap, ...forged, own])?.uid).toBe(carol.uidS);
    });
  });

  it('a wrap re-labelled with another uid or id (or with uid and id swapped) does not open', () => {
    const r = P.parseWrap(pkWrap.record, pkWrap.sig);
    expect(() => P.unwrapAK({ ...r, uid: bob.uidS }, cred, alice.id.sigPk)).toThrow();
    expect(() => P.openWrap({ ...r, uid: bob.uidS }, cred)).toThrow();
    expect(() => P.unwrapAK({ ...r, id: seqBytes(20, 0x81) }, cred, alice.id.sigPk)).toThrow();
    expect(() => P.unwrapAK({ ...r, id: credId.subarray(0, 19) }, cred, alice.id.sigPk)).toThrow();
    // uid and id swapped: both are 16 bytes for a recovery wrap, so only the field order tells them apart
    const rr = P.parseWrap(recWrap.record, recWrap.sig);
    expect(() => P.openWrap({ uid: P.b64u(rr.id), id: P.fromB64u(rr.uid), wrap: rr.wrap }, rec)).toThrow();
    expect(() => refOpenWrap(rr.wrap, rec.sk, refEnc(rec.id, alice.uid, rec.auth))).toThrow();
    // auth moved into another position of the context
    expect(() => refOpenWrap(rr.wrap, rec.sk, refEnc(alice.uid, rec.auth, rec.id))).toThrow();
    // Re-signed by the owner with a different id but the same wrap bytes: still bound to the old id.
    const raw = JSON.parse(pkWrap.record) as Record<string, unknown>;
    const moved = signRecord({ ...raw, id: P.b64u(seqBytes(20, 0x90)) }, alice);
    expect(() => P.unwrapAK(P.verifyWrap(moved.record, moved.sig, alice.id.sigPk), cred, alice.id.sigPk)).toThrow();
    // The owner moving their own box to another uid they control (bob re-signs) does not open either.
    const toBob = signRecord({ ...raw, uid: bob.uidS }, bob);
    expect(() => P.openWrap(P.verifyWrap(toBob.record, toBob.sig, bob.id.sigPk), cred)).toThrow();
  });

  it('recovery wrap does not open with a passkey key and vice versa', () => {
    const rw = P.parseWrap(recWrap.record, recWrap.sig);
    const pw = P.parseWrap(pkWrap.record, pkWrap.sig);
    expect(() => P.unwrapAK(rw, cred, alice.id.sigPk)).toThrow();
    expect(() => P.unwrapAK(pw, rec, alice.id.sigPk)).toThrow();
    expect(() => P.unwrapAK(pw, P.credKem(fill(32, 0x12), credId), alice.id.sigPk)).toThrow(); // other PRF
    expect(() => P.unwrapAK(rw, P.recoveryKem(seqBytes(20, 0x31)), alice.id.sigPk)).toThrow(); // other code
  });

  it('a bit flip in any region of the wrap is rejected', () => {
    const r = P.parseWrap(pkWrap.record, pkWrap.sig);
    const s = survivors(
      r.wrap,
      [
        { name: 'kct', start: 0, end: 1120 },
        { name: 'nonce', start: 1120, end: 1144, every: true },
        { name: 'ct', start: 1144, end: 1176, every: true },
        { name: 'tag', start: 1176, end: 1192, every: true },
      ],
      (b) => P.unwrapAK({ ...r, wrap: b }, cred, alice.id.sigPk),
      2,
    );
    expect(s).toEqual([]);
  }, 30_000);
});

describe('recovery codes', () => {
  /** Independent Crockford base32 (BigInt). */
  const refCrockford = (b: B): string => {
    const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    let v = BigInt('0x' + toHex(b));
    let s = '';
    for (let i = 0; i < 32; i++) {
      s = A[Number(v & 31n)] + s;
      v >>= 5n;
    }
    return s.match(/.{4}/g)!.join('-');
  };

  it('format: 8 groups of 4 Crockford characters', () => {
    expect(P.formatRecoveryCode(new Uint8Array(20))).toBe('0000-0000-0000-0000-0000-0000-0000-0000');
    expect(P.formatRecoveryCode(fill(20, 0xff))).toBe('ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ');
    const r = prng(11);
    for (let t = 0; t < 200; t++) {
      const c = t === 0 ? P.newRecoveryCode() : r.bytes(20);
      const s = P.formatRecoveryCode(c);
      expect(s).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){7}$/);
      expect(s).toBe(refCrockford(c));
      expect(toHex(P.parseRecoveryCode(s))).toBe(toHex(c));
    }
    expect(P.newRecoveryCode().length).toBe(20);
    expect(toHex(P.newRecoveryCode())).not.toBe(toHex(P.newRecoveryCode()));
    for (const n of [0, 19, 21, 32]) expect(() => P.formatRecoveryCode(new Uint8Array(n))).toThrow(/20 bytes/);
  });

  it('parse is lenient about case, separators and look-alikes', () => {
    // A code containing both 0 and 1 so the O->0 and I/L->1 rules matter.
    const c = fromHex('0000108420c4000000000000000000000000ffff');
    const s = P.formatRecoveryCode(c);
    expect(s).toMatch(/0/);
    expect(s).toMatch(/1/);
    const variants = [
      s,
      s.toLowerCase(),
      s.replace(/-/g, ''),
      s.replace(/-/g, ' '),
      ` ${s.replace(/-/g, '  ')}\n`,
      s.replace(/-/g, '\t'),
      s.replace(/0/g, 'O'),
      s.replace(/0/g, 'o'),
      s.replace(/1/g, 'I'),
      s.replace(/1/g, 'i'),
      s.replace(/1/g, 'L'),
      s.replace(/1/g, 'l'),
      s.replace(/-/g, '-').replace(/(.{4})/g, '$1-'), // extra dashes
    ];
    for (const v of variants) expect(toHex(P.parseRecoveryCode(v)), JSON.stringify(v)).toBe(toHex(c));
  });

  it('parse rejects wrong length and invalid characters', () => {
    const s = P.formatRecoveryCode(seqBytes(20)).replace(/-/g, '');
    expect(() => P.parseRecoveryCode(s.slice(1))).toThrow(/32 characters/);
    expect(() => P.parseRecoveryCode(s + 'A')).toThrow(/32 characters/);
    expect(() => P.parseRecoveryCode('')).toThrow(/32 characters/);
    for (const ch of ['U', 'u', '!', '_', '.', '=', 'é', '\u0000']) {
      expect(() => P.parseRecoveryCode(ch + s.slice(1)), JSON.stringify(ch)).toThrow(Error);
    }
  });
});

// ───────────────────────── epochs ─────────────────────────

describe('epoch keys and tags (§3.1)', () => {
  it('epochKeys follow the spec and rk/mk/kc are distinct', () => {
    const k = P.epochKeys(EK0, CONV_A, 5);
    expect(toHex(k.rk)).toBe(toHex(hkdfN(EK0, CONV_A, refEnc('segv.sh/v1/ep/route', be32(5)))));
    expect(toHex(k.mk)).toBe(toHex(hkdfN(EK0, CONV_A, refEnc('segv.sh/v1/ep/msg', be32(5)))));
    expect(toHex(k.kc)).toBe(toHex(hkdfN(EK0, CONV_A, refEnc('segv.sh/v1/ep/commit', be32(5)))));
    expect(new Set([toHex(k.rk), toHex(k.mk), toHex(k.kc)]).size).toBe(3);
    const k2 = P.epochKeys(EK0.slice(), CONV_A.slice(), 5);
    expect(toHex(k2.mk)).toBe(toHex(k.mk));
  });

  it('every key changes with EK, conv and e', () => {
    const all = new Set<string>();
    let count = 0;
    for (const EK of [EK0, EK1])
      for (const conv of [CONV_A, CONV_B])
        for (const e of [0, 1, 2, 0xffffffff]) {
          const k = P.epochKeys(EK, conv, e);
          for (const x of [k.rk, k.mk, k.kc]) {
            all.add(toHex(x));
            count++;
          }
        }
    expect(all.size).toBe(count);
  });

  it('epochKeys rejects bad inputs', () => {
    expect(() => P.epochKeys(new Uint8Array(31), CONV_A, 0)).toThrow();
    expect(() => P.epochKeys(EK0, new Uint8Array(15), 0)).toThrow();
    expect(() => P.epochKeys(EK0, CONV_A, -1)).toThrow();
    expect(() => P.epochKeys(EK0, CONV_A, 2 ** 32)).toThrow();
    expect(() => P.epochKeys(EK0, CONV_A, 0.5)).toThrow();
  });

  it('msgTag / claimTag are distinct across i, n, e and conv', () => {
    const seen = new Set<string>();
    let count = 0;
    for (const conv of [CONV_A, CONV_B])
      for (const e of [0, 1]) {
        const { rk } = P.epochKeys(EK0, conv, e);
        const c = P.claimTag(rk);
        expect(c.length).toBe(16);
        expect(toHex(c)).toBe(toHex(hmacN(rk, 'c').subarray(0, 16)));
        seen.add(toHex(c));
        count++;
        for (let i = 0; i < 32; i++)
          for (let n = 0; n < 48; n++) {
            const t = P.msgTag(rk, i, n);
            expect(t.length).toBe(16);
            seen.add(toHex(t));
            count++;
          }
        expect(toHex(P.msgTag(rk, 3, 70000))).toBe(toHex(hmacN(rk, cat(s2b('m'), be16(3), be32(70000))).subarray(0, 16)));
      }
    expect(seen.size).toBe(count);
  });

  it('msgTag rejects indices / counters outside u16 / u32 instead of aliasing', () => {
    const { rk } = P.epochKeys(EK0, CONV_A, 0);
    expect(() => P.msgTag(rk, 65536, 0)).toThrow(); // would alias msgTag(rk, 0, 0) if truncated
    expect(() => P.msgTag(rk, -1, 0)).toThrow();
    expect(() => P.msgTag(rk, 0, -1)).toThrow();
    expect(() => P.msgTag(rk, 0, 2 ** 32)).toThrow();
  });
});

describe('checkUserKeys', () => {
  it('accepts real identities and rejects unusable keys', () => {
    const id = P.deriveIdentity(new Uint8Array(32).fill(7));
    expect(() => P.checkUserKeys(id)).not.toThrow();
    const identity = new Uint8Array(32);
    identity[0] = 1; // Ed25519 identity point (small order)
    expect(() => P.checkUserKeys({ ...id, sigPk: identity })).toThrow(/signing key/);
    expect(() => P.checkUserKeys({ ...id, sigPk: new Uint8Array(32).fill(0xff) })).toThrow(/signing key/);
    expect(() => P.checkUserKeys({ ...id, scanPk: new Uint8Array(32) })).toThrow(/scan key/); // order-1 point u=0
    const one = new Uint8Array(32);
    one[0] = 1;
    expect(() => P.checkUserKeys({ ...id, scanPk: one })).toThrow(/scan key/); // u=1, order 4
    expect(() => P.checkUserKeys({ ...id, kemPk: new Uint8Array(1216).fill(0xff) })).toThrow(/KEM key/);
  });
});

describe('descriptors (§3.1)', () => {
  it('makeDescriptor emits the §3.1 key order and parse round-trips', () => {
    const d = P.makeDescriptor({ conv: P.b64u(CONV_A), e: 0, members: [alice.uidS, bob.uidS], prev: null, by: alice.uidS, ts: TS });
    expect(d).toBe(dText());
    expect(P.parseDescriptor(d)).toEqual(dObj());
    const named = P.makeDescriptor({
      conv: P.b64u(CONV_A),
      e: 1,
      members: [alice.uidS],
      prev: H32,
      by: alice.uidS,
      ts: TS,
      name: 'Team',
    });
    expect(Object.keys(JSON.parse(named) as object)).toEqual(['v', 'conv', 'e', 'members', 'prev', 'by', 'ts', 'name']);
    expect(P.parseDescriptor(named).name).toBe('Team');
    // name: undefined must be omitted, not serialised
    const unnamed = P.makeDescriptor({ conv: P.b64u(CONV_A), e: 0, members: [alice.uidS], prev: null, by: alice.uidS, ts: TS, name: undefined });
    expect(unnamed).not.toMatch(/name/);
  });

  it('accepts the documented edge cases', () => {
    const members32 = Array.from({ length: 32 }, (_, i) => uidN(i));
    const ok = [
      dText({ members: members32, by: members32[31] }),
      dText({ members: [alice.uidS], by: alice.uidS }),
      dText({ e: 1, prev: H32 }),
      dText({ e: 0xffffffff, prev: H32 }),
      dText({ ts: 0 }),
      dText({ name: 'x'.repeat(64) }),
      dText({ name: 'チーム 🙂' }),
      dText({ name: '\u{1F600}'.repeat(64) }), // 64 code points (128 UTF-16 units)
    ];
    for (const t of ok) expect(() => P.parseDescriptor(t), t.slice(0, 120)).not.toThrow();
  });

  it('rejects every §3.1 / §3.3 shape violation', () => {
    const members33 = Array.from({ length: 33 }, (_, i) => uidN(i));
    const bad: [string, string][] = [
      ['not JSON', '{'],
      ['array', '[]'],
      ['null', 'null'],
      ['string', '"x"'],
      ['v missing', dText({ v: undefined })],
      ['v = 2', dText({ v: 2 })],
      ['v = "1"', dText({ v: '1' })],
      ['conv missing', dText({ conv: undefined })],
      ['conv 15 bytes', dText({ conv: P.b64u(new Uint8Array(15)) })],
      ['conv 17 bytes', dText({ conv: P.b64u(new Uint8Array(17)) })],
      ['conv non-canonical', dText({ conv: nonCanonical(P.b64u(CONV_A)) })],
      ['conv padded', dText({ conv: P.b64u(CONV_A) + '==' })],
      ['conv number', dText({ conv: 1 })],
      ['e missing', dText({ e: undefined })],
      ['e null', dText({ e: null })],
      ['e negative', dText({ e: -1 })],
      ['e fractional', dText({ e: 0.5, prev: H32 })],
      ['e string', dText({ e: '0' })],
      ['e = 2^32', dText({ e: 2 ** 32, prev: H32 })],
      ['members missing', dText({ members: undefined })],
      ['members string', dText({ members: alice.uidS })],
      ['members object', dText({ members: { 0: alice.uidS } })],
      ['members empty', dText({ members: [] })],
      ['members 33', dText({ members: members33, by: members33[0] })],
      ['member 15 bytes', dText({ members: [alice.uidS, P.b64u(new Uint8Array(15))] })],
      ['member number', dText({ members: [alice.uidS, 5] })],
      ['member null', dText({ members: [alice.uidS, null] })],
      ['member non-canonical', dText({ members: [alice.uidS, nonCanonical(bob.uidS)] })],
      ['duplicate member', dText({ members: [alice.uidS, bob.uidS, alice.uidS] })],
      ['prev missing', dText({ prev: undefined })],
      ['e=0 with prev', dText({ prev: H32 })],
      ['e=1 with prev null', dText({ e: 1, prev: null })],
      ['prev 31 bytes', dText({ e: 1, prev: P.b64u(new Uint8Array(31)) })],
      ['prev 33 bytes', dText({ e: 1, prev: P.b64u(new Uint8Array(33)) })],
      ['prev number', dText({ e: 1, prev: 0 })],
      ['prev empty string', dText({ e: 1, prev: '' })],
      ['by missing', dText({ by: undefined })],
      ['by not a member', dText({ by: carol.uidS })],
      ['by 15 bytes', dText({ by: P.b64u(new Uint8Array(15)) })],
      ['ts missing', dText({ ts: undefined })],
      ['ts negative', dText({ ts: -1 })],
      ['ts fractional', dText({ ts: 1.5 })],
      ['ts string', dText({ ts: String(TS) })],
      ['ts unsafe', dText({ ts: 2 ** 53 + 2 })],
      ['name 65 chars', dText({ name: 'x'.repeat(65) })],
      ['name 65 code points', dText({ name: '\u{1F600}'.repeat(65) })],
      ['name number', dText({ name: 5 })],
      ['name null', dText({ name: null })],
      ['name array', dText({ name: ['x'] })],
      ['name empty', dText({ name: '' })],
      ['name whitespace', dText({ name: '   ' })],
      ['name newline', dText({ name: 'a\nb' })],
      ['name NUL', dText({ name: 'a\u0000b' })],
      ['name RLO', dText({ name: 'abc\u202Etxt.exe' })],
      ['name LRI', dText({ name: '\u2066x' })],
      ['name RLM', dText({ name: 'x\u200F' })],
    ];
    for (const [name, text] of bad) expect(() => P.parseDescriptor(text), name).toThrow(Error);
  });

  it('validName: no leading "@" (it would pose as a 1:1 with that handle) and nothing invisible', () => {
    const rejected = [
      '@bob',
      ' @bob',
      '\t@bob',
      ' @bob', // NBSP
      ' @bob', // em space
      '　@bob', // ideographic space
      '﻿@bob', // BOM (trimmed as whitespace)
      '​@bob', // zero-width space (format character)
      '⁠@bob', // word joiner
      '@',
      '@@',
      '@ bob',
      '@bob, @carol',
      // invisible / blank-looking names
      'ㅤ', // Hangul filler
      'ᅟ',
      'ᅠ',
      'ﾠ',
      '⠀', // braille blank
      '​',
      'a​b',
      'x­', // soft hyphen
      'x\u{E0041}', // tag character
      '́', // a lone combining mark has nothing visible
    ];
    const accepted = ['a@b', 'bob@', 'team @bob', 'x', 'Team', 'チーム 🙂', 'a'.repeat(64), '#general', '1:1'];
    for (const n of rejected) expect(P.validName(n), JSON.stringify(n)).toBe(false);
    for (const n of accepted) expect(P.validName(n), JSON.stringify(n)).toBe(true);
    for (const n of [null, undefined, 5, ['x'], {}]) expect(P.validName(n), JSON.stringify(n)).toBe(false);
    // enforced on both ends: peers reject it and our own makeDescriptor refuses to emit it
    expect(() => P.parseDescriptor(dText({ name: '@bob' }))).toThrow(/name/);
    expect(() => P.parseDescriptor(dText({ name: ' @bob' }))).toThrow(/name/);
    expect(P.parseDescriptor(dText({ name: 'a@b' })).name).toBe('a@b');
    const base = { conv: P.b64u(CONV_A), e: 0, members: [alice.uidS], prev: null, by: alice.uidS, ts: TS };
    expect(() => P.makeDescriptor({ ...base, name: '@bob' })).toThrow(/name/);
    expect(() => P.makeDescriptor({ ...base, name: 'ㅤ' })).toThrow(/name/);
  });

  it('descriptor signature is bound to the exact text, kc (EK), conv, epoch and signer', () => {
    const d = dText();
    const k0 = P.epochKeys(EK0, CONV_A, 0);
    const dsig = P.signDescriptor(d, k0.kc, alice.id.sigSk);
    expect(dsig.length).toBe(64);
    expect(P.verifyDescriptorSig(d, k0.kc, dsig, alice.id.sigPk)).toBe(true);
    expect(nodeEdVerify(dsig, refEnc('segv.sh/v1/epoch', d, k0.kc), alice.id.sigPk)).toBe(true);
    // same descriptor, different EK -> different kc -> must fail
    expect(P.verifyDescriptorSig(d, P.epochKeys(EK1, CONV_A, 0).kc, dsig, alice.id.sigPk)).toBe(false);
    expect(P.verifyDescriptorSig(d, P.epochKeys(EK0, CONV_B, 0).kc, dsig, alice.id.sigPk)).toBe(false);
    expect(P.verifyDescriptorSig(d, P.epochKeys(EK0, CONV_A, 1).kc, dsig, alice.id.sigPk)).toBe(false);
    expect(P.verifyDescriptorSig(d, k0.mk, dsig, alice.id.sigPk)).toBe(false);
    expect(P.verifyDescriptorSig(d, k0.rk, dsig, alice.id.sigPk)).toBe(false);
    // different text
    expect(P.verifyDescriptorSig(dText({ ts: TS + 1 }), k0.kc, dsig, alice.id.sigPk)).toBe(false);
    expect(P.verifyDescriptorSig(JSON.stringify(dObj(), null, 1), k0.kc, dsig, alice.id.sigPk)).toBe(false);
    // different signer
    expect(P.verifyDescriptorSig(d, k0.kc, dsig, bob.id.sigPk)).toBe(false);
    expect(P.verifyDescriptorSig(d, k0.kc, P.signDescriptor(d, k0.kc, bob.id.sigSk), alice.id.sigPk)).toBe(false);
    // flipped signature bytes
    for (let i = 0; i < 64; i += 7) expect(P.verifyDescriptorSig(d, k0.kc, flip(dsig, i), alice.id.sigPk)).toBe(false);
  });
});

// ───────────────────────── invites ─────────────────────────

describe('invites (§3.2)', () => {
  const d = dText();
  const keys = P.epochKeys(EK0, CONV_A, 0);
  const dsig = P.signDescriptor(d, keys.kc, alice.id.sigSk);
  const inv = P.makeInvite(bob.user, d, EK0, dsig);
  const vkBob = P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, inv);
  const L = inv.body.length;

  it('round trip for the recipient', () => {
    expect(inv.kind).toBe(3);
    expect(inv.tag.length).toBe(16);
    expect(P.INV_BODY_LENS).toEqual([32 + 1120 + 24 + 2048 + 16]);
    expect(L).toBe(P.INV_BODY_LENS[0]);
    expect(vkBob).not.toBeNull();
    const o = P.openInvite(bob.id.kemSk, vkBob!, inv);
    expect(o.dText).toBe(d);
    expect(toHex(o.EK)).toBe(toHex(EK0));
    expect(toHex(o.dsig)).toBe(toHex(dsig));
    expect(P.verifyDescriptorSig(o.dText, P.epochKeys(o.EK, CONV_A, 0).kc, o.dsig, alice.id.sigPk)).toBe(true);
  });

  it('matches an independent decryption per §3.2', () => {
    const eph = inv.body.subarray(0, 32);
    const s = nodeX25519(bob.id.scanSk, eph);
    const vk = hkdfN(s, cat(eph, bob.id.scanPk), 'segv.sh/v1/inv/view');
    expect(toHex(vk)).toBe(toHex(vkBob!));
    const check = hmacN(vk, 'check').subarray(0, 16);
    expect(toHex(check)).toBe(toHex(inv.tag));
    const kct = inv.body.subarray(32, 1152);
    const k = hkdfN(cat(xwing.decapsulate(kct, bob.id.kemSk), vk), sha(kct), 'segv.sh/v1/inv/key');
    const padded = xchacha20poly1305(k, inv.body.subarray(1152, 1176), refEnc('segv.sh/v1/inv', eph, check)).decrypt(
      inv.body.subarray(1176),
    );
    expect(padded.length).toBe(2048);
    expect(toHex(padded)).toBe(toHex(refPad(refEnc(d, EK0, dsig), [2048])));
  });

  it('opens an invite built independently from the spec text', () => {
    const ephSk = new Uint8Array(randomBytes(32));
    const eph = x25519.getPublicKey(ephSk);
    const vk = hkdfN(nodeX25519(ephSk, carol.id.scanPk), cat(eph, carol.id.scanPk), 'segv.sh/v1/inv/view');
    const check = hmacN(vk, 'check').subarray(0, 16);
    const { cipherText: kct, sharedSecret: ss } = xwing.encapsulate(carol.id.kemPk);
    const k = hkdfN(cat(ss, vk), sha(kct), 'segv.sh/v1/inv/key');
    const nonce = new Uint8Array(randomBytes(24));
    const ct = xchacha20poly1305(k, nonce, refEnc('segv.sh/v1/inv', eph, check)).encrypt(refPad(refEnc(d, EK1, dsig), [2048]));
    const row = { tag: check, body: cat(eph, kct, nonce, ct) };
    const vk2 = P.inviteViewKey(carol.id.scanSk, carol.id.scanPk, row);
    expect(vk2).not.toBeNull();
    const o = P.openInvite(carol.id.kemSk, vk2!, row);
    expect(o.dText).toBe(d);
    expect(toHex(o.EK)).toBe(toHex(EK1));
  });

  it('non-recipients never match', () => {
    const invs = [inv, P.makeInvite(bob.user, d, EK0, dsig), P.makeInvite(carol.user, d, EK0, dsig)];
    const r = prng(12);
    const others = [alice, ...Array.from({ length: 24 }, () => P.deriveIdentity(r.bytes(32)))].map((x) => ('id' in x ? x.id : x));
    for (const row of invs.slice(0, 2)) {
      for (const o of [...others, carol.id]) expect(P.inviteViewKey(o.scanSk, o.scanPk, row)).toBeNull();
      // right secret, wrong public key (the vk salt binds scanPk)
      expect(P.inviteViewKey(bob.id.scanSk, carol.id.scanPk, row)).toBeNull();
    }
    for (const o of [...others, bob.id]) expect(P.inviteViewKey(o.scanSk, o.scanPk, invs[2])).toBeNull();
    // each invite is fresh (new eph), so tags never repeat
    expect(new Set(invs.map((x) => toHex(x.tag))).size).toBe(3);
  });

  it('works with a custom dh callback (node:crypto X25519, like WebCrypto)', () => {
    let calls = 0;
    const dh = (sk: B, pk: B): B => {
      calls++;
      return nodeX25519(sk, pk);
    };
    const vk = P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, inv, dh);
    expect(calls).toBe(1);
    expect(toHex(vk!)).toBe(toHex(vkBob!));
    expect(P.inviteViewKey(carol.id.scanSk, carol.id.scanPk, inv, dh)).toBeNull();
    expect(P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, inv, () => fill(32, 7))).toBeNull(); // wrong secret
    expect(
      P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, inv, () => {
        throw new Error('webcrypto failure');
      }),
    ).toBeNull();
    expect(P.openInvite(bob.id.kemSk, vk!, inv).dText).toBe(d);
  });

  it('inviteViewKey ignores malformed rows (never throws)', () => {
    expect(P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, { tag: inv.tag, body: inv.body.subarray(0, 31) })).toBeNull();
    expect(P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, { tag: inv.tag.subarray(0, 15), body: inv.body })).toBeNull();
    expect(P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, { tag: cat(inv.tag, Uint8Array.of(0)), body: inv.body })).toBeNull();
    // low-order eph points (all-zero shared secret) are rejected by the DH, not matched
    for (const bad of [new Uint8Array(32), cat(Uint8Array.of(1), new Uint8Array(31))]) {
      expect(P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, { tag: inv.tag, body: cat(bad, inv.body.subarray(32)) })).toBeNull();
    }
    const r = prng(13);
    for (let t = 0; t < 50; t++) {
      expect(P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, { tag: r.bytes(16), body: r.bytes(r.int(L + 10)) })).toBeNull();
    }
  });

  it('openInvite rejects wrong keys, wrong lengths and a different check tag', () => {
    expect(() => P.openInvite(carol.id.kemSk, vkBob!, inv)).toThrow(); // wrong KEM sk
    expect(() => P.openInvite(bob.id.kemSk, fill(32, 1), inv)).toThrow(); // wrong vk
    const vkCarol = P.inviteViewKey(carol.id.scanSk, carol.id.scanPk, P.makeInvite(carol.user, d, EK0, dsig))!;
    expect(() => P.openInvite(bob.id.kemSk, vkCarol, inv)).toThrow();
    // body under a different check tag (AAD = enc(label, eph, check))
    expect(() => P.openInvite(bob.id.kemSk, vkBob!, { tag: flip(inv.tag, 0), body: inv.body })).toThrow();
    expect(() => P.openInvite(bob.id.kemSk, vkBob!, { tag: P.makeInvite(bob.user, d, EK0, dsig).tag, body: inv.body })).toThrow();
    const retired = 32 + 1120 + 24 + 16384 + 16; // the former 16384 class
    for (const len of [0, 32, L - 1, L + 1, retired - 1, retired]) {
      const body = len <= L ? inv.body.subarray(0, len) : cat(inv.body, new Uint8Array(len - L));
      expect(() => P.openInvite(bob.id.kemSk, vkBob!, { tag: inv.tag, body }), `len ${len}`).toThrow(/bad length/);
    }
  });

  it('splicing parts of two invites to the same recipient fails', () => {
    const inv2 = P.makeInvite(bob.user, d, EK1, dsig);
    const vk2 = P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, inv2)!;
    // eph/tag of inv, kct+box of inv2
    const spliced1 = { tag: inv.tag, body: cat(inv.body.subarray(0, 32), inv2.body.subarray(32)) };
    expect(() => P.openInvite(bob.id.kemSk, vkBob!, spliced1)).toThrow();
    // kct of inv2, rest of inv
    const spliced2 = { tag: inv.tag, body: cat(inv.body.subarray(0, 32), inv2.body.subarray(32, 1152), inv.body.subarray(1152)) };
    expect(() => P.openInvite(bob.id.kemSk, vkBob!, spliced2)).toThrow();
    expect(() => P.openInvite(bob.id.kemSk, vk2, spliced2)).toThrow();
  });

  it('a bit flip in eph / kct / nonce / ciphertext / tag is rejected', () => {
    const regions = [
      { name: 'eph', start: 0, end: 32, every: true },
      { name: 'kct', start: 32, end: 1152 },
      { name: 'nonce', start: 1152, end: 1176 },
      { name: 'ct', start: 1176, end: L - 16 },
      { name: 'tag', start: L - 16, end: L, every: true },
    ];
    // Full receive path: detection + open must not yield a payload.
    const full = (b: B) => {
      const row = { tag: inv.tag, body: b };
      const vk = P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, row);
      if (vk === null) throw new Error('not for me');
      return P.openInvite(bob.id.kemSk, vk, row);
    };
    expect(survivors(inv.body, regions, full, 3)).toEqual([]);
    // Open with the original vk (as if detection were skipped): AEAD must still catch it.
    expect(survivors(inv.body, regions, (b) => P.openInvite(bob.id.kemSk, vkBob!, { tag: inv.tag, body: b }), 4)).toEqual([]);
  }, 60_000);

  it('the X25519-ignored top bit of eph is still authenticated', () => {
    const b = flip(inv.body, 31, 7); // X25519 masks this bit, so s is unchanged
    expect(toHex(nodeX25519(bob.id.scanSk, b.subarray(0, 32)))).toBe(toHex(nodeX25519(bob.id.scanSk, inv.body.subarray(0, 32))));
    expect(P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, { tag: inv.tag, body: b })).toBeNull();
    expect(() => P.openInvite(bob.id.kemSk, vkBob!, { tag: inv.tag, body: b })).toThrow();
  });

  it('one size class: the largest descriptor fits, anything bigger is refused', () => {
    // P = enc(D, EK, dsig) = (4 + |D|) + (4 + 32) + (4 + 64) = |D| + 108, and pad needs |P| + 1 <= 2048.
    const fits = 'x'.repeat(2048 - 1 - 108);
    const r = P.makeInvite(bob.user, fits, EK0, dsig);
    expect(r.body.length).toBe(P.INV_BODY_LENS[0]);
    const vk = P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, r)!;
    expect(P.openInvite(bob.id.kemSk, vk, r).dText).toBe(fits);
    expect(() => P.makeInvite(bob.user, fits + 'x', EK0, dsig)).toThrow(/too large/);
    expect(() => P.makeInvite(bob.user, 'x'.repeat(3000), EK0, dsig)).toThrow(/too large/); // formerly the 16384 class
    // The largest valid descriptors (32 members, extreme e / ts, the 64 code points with the longest JSON
    // encoding) fit with room to spare, so real invites never need a second class.
    const members32 = Array.from({ length: 32 }, (_, i) => uidN(i));
    const maxOver = { e: 0xffffffff, prev: H32, members: members32, by: members32[0], ts: Number.MAX_SAFE_INTEGER };
    for (const name of ['\u{1F600}'.repeat(64), '"'.repeat(64), '\\'.repeat(64)]) {
      const maxD = dText({ ...maxOver, name });
      P.parseDescriptor(maxD);
      expect(s2b(maxD).length, JSON.stringify(name[0])).toBeLessThan(1500);
      expect(P.makeInvite(bob.user, maxD, EK0, dsig).body.length).toBe(P.INV_BODY_LENS[0]);
    }
    // Upper bound for any accepted name: JSON spends at most 6 bytes per code point ("\uXXXX").
    expect(s2b(dText(maxOver)).length + ',"name":""'.length + 6 * 64).toBeLessThanOrEqual(fits.length);
    // An authentic invite in the retired 16384 class is refused by length before any decryption.
    const ephSk = new Uint8Array(randomBytes(32));
    const eph = x25519.getPublicKey(ephSk);
    const vkOld = hkdfN(nodeX25519(ephSk, bob.id.scanPk), cat(eph, bob.id.scanPk), 'segv.sh/v1/inv/view');
    const check = hmacN(vkOld, 'check').subarray(0, 16);
    const { cipherText: kct, sharedSecret: ss } = xwing.encapsulate(bob.id.kemPk);
    const nonce = new Uint8Array(randomBytes(24));
    const k = hkdfN(cat(ss, vkOld), sha(kct), 'segv.sh/v1/inv/key');
    const old = { tag: check, body: cat(eph, kct, nonce, xchacha20poly1305(k, nonce, refEnc('segv.sh/v1/inv', eph, check)).encrypt(refPad(refEnc(d, EK0, dsig), [16384]))) };
    expect(old.body.length).toBe(32 + 1120 + 24 + 16384 + 16);
    expect(toHex(P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, old)!)).toBe(toHex(vkOld));
    expect(() => P.openInvite(bob.id.kemSk, vkOld, old)).toThrow(/bad length/);
    // invalid recipient keys fail closed
    expect(() => P.makeInvite({ kemPk: bob.user.kemPk, scanPk: new Uint8Array(32) }, d, EK0, dsig)).toThrow();
    expect(() => P.makeInvite({ kemPk: fill(1216, 0xff), scanPk: bob.user.scanPk }, d, EK0, dsig)).toThrow();
  });

  it('openInvite rejects authenticated payloads with bad inner shapes', () => {
    // Build invites by hand whose AEAD is valid but whose plaintext is malformed.
    const craft = (Pt: B) => {
      const ephSk = new Uint8Array(randomBytes(32));
      const eph = x25519.getPublicKey(ephSk);
      const vk = hkdfN(nodeX25519(ephSk, bob.id.scanPk), cat(eph, bob.id.scanPk), 'segv.sh/v1/inv/view');
      const check = hmacN(vk, 'check').subarray(0, 16);
      const { cipherText: kct, sharedSecret: ss } = xwing.encapsulate(bob.id.kemPk);
      const k = hkdfN(cat(ss, vk), sha(kct), 'segv.sh/v1/inv/key');
      const nonce = new Uint8Array(randomBytes(24));
      const ct = xchacha20poly1305(k, nonce, refEnc('segv.sh/v1/inv', eph, check)).encrypt(Pt);
      return { vk, row: { tag: check, body: cat(eph, kct, nonce, ct) } };
    };
    const cases: [string, B][] = [
      ['EK 31 bytes', refPad(refEnc(d, new Uint8Array(31), dsig), [2048])],
      ['dsig 63 bytes', refPad(refEnc(d, EK0, new Uint8Array(63)), [2048])],
      ['two fields', refPad(refEnc(d, EK0), [2048])],
      ['four fields', refPad(refEnc(d, EK0, dsig, s2b('x')), [2048])],
      ['invalid UTF-8', refPad(refEnc(Uint8Array.of(0xff), EK0, dsig), [2048])],
      ['no padding marker', new Uint8Array(2048)],
    ];
    for (const [name, Pt] of cases) {
      const { vk, row } = craft(Pt);
      expect(toHex(P.inviteViewKey(bob.id.scanSk, bob.id.scanPk, row)!), name).toBe(toHex(vk));
      expect(() => P.openInvite(bob.id.kemSk, vk, row), name).toThrow(Error);
    }
  });
});

// ───────────────────────── claims & messages ─────────────────────────

describe('claims (§3.4)', () => {
  const k0 = P.epochKeys(EK0, CONV_A, 0);
  const d1 = dText({ e: 1, prev: P.b64u(P.H(P.utf8(dText()))) });
  const k1 = P.epochKeys(EK1, CONV_A, 1);
  const dsig1 = P.signDescriptor(d1, k1.kc, alice.id.sigSk);
  const claim = P.makeClaim(k0.mk, k0.rk, d1, dsig1, alice.id.sigSk);

  it('round trip, tag = claimTag(rk_e), body in the message size classes', () => {
    expect(claim.kind).toBe(4);
    expect(toHex(claim.tag)).toBe(toHex(P.claimTag(k0.rk)));
    expect(P.MSG_BODY_LENS).toEqual([24 + 1024 + 16, 24 + 4096 + 16, 24 + 16384 + 16]);
    expect(claim.body.length).toBe(P.MSG_BODY_LENS[0]);
    const o = P.openClaim(k0.mk, claim);
    expect(o.dText).toBe(d1);
    expect(toHex(o.dsig)).toBe(toHex(dsig1));
    expect(o.csig.length).toBe(64);
    expect(P.verifyClaimSig(claim.tag, o.dText, o.dsig, o.csig, alice.id.sigPk)).toBe(true);
    // csig = Ed25519 over enc("segv.sh/v1/claim-sig", tag, DBytes, dsig), checked with an independent verifier
    expect(nodeEdVerify(o.csig, refEnc('segv.sh/v1/claim-sig', claim.tag, d1, dsig1), alice.id.sigPk)).toBe(true);
    // independent decryption: C = enc(DBytes, dsig, csig), padded to the message classes
    const pt = xchacha20poly1305(k0.mk, claim.body.subarray(0, 24), refEnc('segv.sh/v1/claim', claim.tag)).decrypt(claim.body.subarray(24));
    expect(toHex(pt)).toBe(toHex(refPad(refEnc(d1, dsig1, o.csig), P.MSG_CLASSES)));
  });

  it('csig binds the claim slot, the descriptor text, dsig and the signer', () => {
    const { csig } = P.openClaim(k0.mk, claim);
    const ok = (tag: B, d: string, ds: B, cs: B, pk: B) => P.verifyClaimSig(tag, d, ds, cs, pk);
    expect(ok(claim.tag, d1, dsig1, csig, alice.id.sigPk)).toBe(true);
    // another slot (another epoch / conversation), another descriptor text, another dsig
    expect(ok(P.claimTag(k1.rk), d1, dsig1, csig, alice.id.sigPk)).toBe(false);
    expect(ok(P.claimTag(P.epochKeys(EK0, CONV_B, 0).rk), d1, dsig1, csig, alice.id.sigPk)).toBe(false);
    expect(ok(claim.tag, dText({ e: 1, prev: H32 }), dsig1, csig, alice.id.sigPk)).toBe(false);
    expect(ok(claim.tag, JSON.stringify(JSON.parse(d1), null, 1), dsig1, csig, alice.id.sigPk)).toBe(false);
    expect(ok(claim.tag, d1, flip(dsig1, 0), csig, alice.id.sigPk)).toBe(false);
    // another signer: an insider cannot pin a change on someone else
    expect(ok(claim.tag, d1, dsig1, csig, bob.id.sigPk)).toBe(false);
    const byBob = P.openClaim(k0.mk, P.makeClaim(k0.mk, k0.rk, d1, dsig1, bob.id.sigSk));
    expect(ok(claim.tag, d1, dsig1, byBob.csig, alice.id.sigPk)).toBe(false);
    expect(ok(claim.tag, d1, dsig1, byBob.csig, bob.id.sigPk)).toBe(true);
    // neither the descriptor signature nor a message signature over the same bytes passes as a csig
    expect(ok(claim.tag, d1, dsig1, dsig1, alice.id.sigPk)).toBe(false);
    expect(ok(claim.tag, d1, dsig1, P.sign(P.enc('segv.sh/v1/msg-sig', claim.tag, P.utf8(d1)), alice.id.sigSk), alice.id.sigPk)).toBe(false);
    for (let i = 0; i < 64; i += 5) expect(ok(claim.tag, d1, dsig1, flip(csig, i, i % 8), alice.id.sigPk)).toBe(false);
  });

  it('wrong mk / wrong tag / other epoch fail', () => {
    expect(() => P.openClaim(k1.mk, claim)).toThrow();
    expect(() => P.openClaim(P.epochKeys(EK0, CONV_B, 0).mk, claim)).toThrow();
    expect(() => P.openClaim(k0.mk, { tag: P.claimTag(k1.rk), body: claim.body })).toThrow();
    expect(() => P.openClaim(k0.mk, { tag: P.msgTag(k0.rk, 0, 0), body: claim.body })).toThrow();
    expect(() => P.openClaim(k0.mk, { tag: claim.tag, body: claim.body.subarray(0, 39) })).toThrow();
  });

  it('a bit flip anywhere in the body is rejected (every byte)', () => {
    const L = claim.body.length;
    const s = survivors(
      claim.body,
      [
        { name: 'nonce', start: 0, end: 24, every: true },
        { name: 'ct', start: 24, end: L - 16, every: true },
        { name: 'tag', start: L - 16, end: L, every: true },
      ],
      (b) => P.openClaim(k0.mk, { tag: claim.tag, body: b }),
      5,
    );
    expect(s).toEqual([]);
  });

  it('rejects authenticated claims with bad inner shapes', () => {
    const seal = (pt: B) => ({ tag: claim.tag, body: P.aeadSeal(k0.mk, pt, refEnc('segv.sh/v1/claim', claim.tag)) });
    const { csig } = P.openClaim(k0.mk, claim);
    const pad = (x: B) => refPad(x, P.MSG_CLASSES);
    expect(() => P.openClaim(k0.mk, seal(pad(refEnc(d1, new Uint8Array(63), csig))))).toThrow(/signature length/);
    expect(() => P.openClaim(k0.mk, seal(pad(refEnc(d1, dsig1, new Uint8Array(63)))))).toThrow(/signature length/);
    expect(() => P.openClaim(k0.mk, seal(pad(refEnc(d1, dsig1, cat(csig, Uint8Array.of(0))))))).toThrow(/signature length/);
    expect(() => P.openClaim(k0.mk, seal(pad(refEnc(d1, dsig1))))).toThrow(); // pre-csig layout
    expect(() => P.openClaim(k0.mk, seal(pad(refEnc(d1))))).toThrow();
    expect(() => P.openClaim(k0.mk, seal(pad(refEnc(d1, dsig1, csig, csig))))).toThrow();
    expect(() => P.openClaim(k0.mk, seal(pad(refEnc(Uint8Array.of(0xff), dsig1, csig))))).toThrow();
    expect(() => P.openClaim(k0.mk, seal(new Uint8Array(256)))).toThrow(/padding/);
    // sanity: the same helper with a well-formed plaintext opens
    expect(P.openClaim(k0.mk, seal(pad(refEnc(d1, dsig1, csig)))).dText).toBe(d1);
  });
});

describe('kind-4 size classes (claims and messages share them)', () => {
  const k = P.epochKeys(EK0, CONV_A, 0);
  const tag = P.msgTag(k.rk, 0, 0);
  const sig = new Uint8Array(64);

  it('claims: C = enc(D, dsig, csig) is |D| + 140 bytes; each class boundary is exact', () => {
    for (const cls of P.MSG_CLASSES) {
      const max = cls - 1 - 140;
      const c = P.makeClaim(k.mk, k.rk, 'd'.repeat(max), sig, alice.id.sigSk);
      expect(c.body.length, `|D| = ${max}`).toBe(24 + cls + 16);
      expect(P.openClaim(k.mk, c).dText.length).toBe(max);
      const next = () => P.makeClaim(k.mk, k.rk, 'd'.repeat(max + 1), sig, alice.id.sigSk).body.length;
      if (cls < 16384) expect(next(), `|D| = ${max + 1}`).toBeGreaterThan(24 + cls + 16);
      else expect(next).toThrow(/too large/);
    }
  });

  it('messages: M = enc(payload, psig) is |payload| + 72 bytes; each class boundary is exact', () => {
    const base = s2b(JSON.stringify(payload({ text: '' }))).length;
    for (const cls of P.MSG_CLASSES) {
      const n = cls - 1 - 72 - base;
      const row = P.makeMessage(k.mk, tag, payload({ text: 'y'.repeat(n) }), alice.id.sigSk);
      expect(row.body.length, `text ${n}`).toBe(24 + cls + 16);
      expect(P.openMessage(k.mk, row).payload.text!.length).toBe(n);
      if (cls < 16384) {
        expect(P.makeMessage(k.mk, tag, payload({ text: 'y'.repeat(n + 1) }), alice.id.sigSk).body.length).toBeGreaterThan(24 + cls + 16);
      } else {
        expect(() => P.makeMessage(k.mk, tag, payload({ text: 'y'.repeat(n + 1) }), alice.id.sigSk)).toThrow(/too large/);
      }
    }
  });

  it('real claims and messages only ever produce the three documented body lengths', () => {
    const seen = new Set<number>();
    const members32 = Array.from({ length: 32 }, (_, i) => uidN(i));
    const descriptors = [
      dText({ e: 1, prev: H32, members: [alice.uidS], by: alice.uidS }),
      dText({ e: 1, prev: H32 }),
      dText({ e: 0xffffffff, prev: H32, members: members32, by: members32[0], ts: Number.MAX_SAFE_INTEGER, name: '\u{1F600}'.repeat(64) }),
    ];
    for (const d of descriptors) seen.add(P.makeClaim(k.mk, k.rk, d, sig, alice.id.sigSk).body.length);
    const payloads = [
      payload({ t: 'leave', text: undefined, ts: 0, n: 0, head: { seq: 0, h: H32 } }),
      payload({ text: 'y' }),
      payload({ t: 'image', text: undefined, img: { id: P.b64u(fill(32, 1)), k: P.b64u(fill(32, 2)), mime: 'image/jpeg', w: 1, h: 1 } }),
      payload({ text: 'y'.repeat(2000) }),
      payload({ text: '日本語'.repeat(1000) }),
      payload({ text: '\u{1F600}'.repeat(2000) }),
    ];
    for (const p of payloads) seen.add(P.makeMessage(k.mk, tag, p, alice.id.sigSk).body.length);
    expect([...seen].sort((a, b) => a - b)).toEqual(P.MSG_BODY_LENS);
    // the smallest real rows (a 1-member claim, a leave) share the smallest class with ordinary texts
    expect(P.makeClaim(k.mk, k.rk, descriptors[0], sig, alice.id.sigSk).body.length).toBe(P.MSG_BODY_LENS[0]);
    expect(P.makeMessage(k.mk, tag, payloads[0], alice.id.sigSk).body.length).toBe(P.MSG_BODY_LENS[0]);
  });
});

describe('messages (§3.5)', () => {
  const kA = P.epochKeys(EK0, CONV_A, 0);
  const kB = P.epochKeys(EK0, CONV_B, 0);
  const tag = P.msgTag(kA.rk, 0, 0);
  const p = payload();
  const row = P.makeMessage(kA.mk, tag, p, alice.id.sigSk);

  it('round trip with the exact signed payload bytes', () => {
    expect(row.kind).toBe(4);
    expect(toHex(row.tag)).toBe(toHex(tag));
    expect(row.body.length).toBe(P.MSG_BODY_LENS[0]); // smallest class is 1024
    const o = P.openMessage(kA.mk, row);
    expect(o.text).toBe(JSON.stringify(p));
    expect(o.payload).toEqual(p);
    expect(P.validPayload(o.payload)).toBe(true);
    expect(P.verifyMessageSig(tag, o.text, o.psig, alice.id.sigPk)).toBe(true);
    expect(nodeEdVerify(o.psig, refEnc('segv.sh/v1/msg-sig', tag, o.text), alice.id.sigPk)).toBe(true);
    // independent decryption: M = enc(payloadBytes, psig), padded to message classes
    const pt = xchacha20poly1305(kA.mk, row.body.subarray(0, 24), refEnc('segv.sh/v1/msg', tag)).decrypt(row.body.subarray(24));
    expect(toHex(pt)).toBe(toHex(refPad(refEnc(o.text, o.psig), P.MSG_CLASSES)));
  });

  it('size classes 1024 / 4096 / 16384 and too-large payloads', () => {
    // A "leave" and a short text land in the same (smallest) class, so they are indistinguishable.
    const leave = payload({ t: 'leave', text: undefined, ts: 0, head: { seq: 1, h: H32 } });
    const sizes = [1, 3000, 12000].map((n) => P.makeMessage(kA.mk, tag, payload({ text: 'y'.repeat(n) }), alice.id.sigSk).body.length);
    expect(sizes).toEqual(P.MSG_BODY_LENS);
    expect(P.makeMessage(kA.mk, tag, leave, alice.id.sigSk).body.length).toBe(P.MSG_BODY_LENS[0]);
    const minText = payload({ text: 'y', ts: TS, n: 0, e: 0, head: { seq: 1, h: H32 } }); // realistic 13-digit ts
    expect(P.makeMessage(kA.mk, tag, minText, alice.id.sigSk).body.length).toBe(P.MSG_BODY_LENS[0]);
    expect(() => P.makeMessage(kA.mk, tag, payload({ text: 'y'.repeat(16384) }), alice.id.sigSk)).toThrow(/too large/);
    const unicode = payload({ text: '日本語\u{1F600}\u0000"\\' });
    const o = P.openMessage(kA.mk, P.makeMessage(kA.mk, tag, unicode, alice.id.sigSk));
    expect(o.payload.text).toBe(unicode.text);
  });

  it('a message body moved to a different tag fails', () => {
    for (const t of [P.msgTag(kA.rk, 0, 1), P.msgTag(kA.rk, 1, 0), P.claimTag(kA.rk), flip(tag, 15), tag.subarray(0, 15)]) {
      expect(() => P.openMessage(kA.mk, { tag: t, body: row.body })).toThrow();
    }
  });

  it("a message from conv A is not openable with conv B's (or another epoch's) mk", () => {
    expect(() => P.openMessage(kB.mk, row)).toThrow();
    expect(() => P.openMessage(P.epochKeys(EK0, CONV_A, 1).mk, row)).toThrow();
    expect(() => P.openMessage(P.epochKeys(EK1, CONV_A, 0).mk, row)).toThrow();
    expect(() => P.openMessage(kA.rk, row)).toThrow();
    expect(() => P.openMessage(kA.kc, row)).toThrow();
  });

  it('claims and messages are not interchangeable (domain-separated AAD)', () => {
    const d1 = dText({ e: 1, prev: H32 });
    const claim = P.makeClaim(kA.mk, kA.rk, d1, new Uint8Array(64), alice.id.sigSk);
    expect(() => P.openMessage(kA.mk, claim)).toThrow();
    const msgAtClaimSlot = P.makeMessage(kA.mk, P.claimTag(kA.rk), p, alice.id.sigSk);
    expect(() => P.openClaim(kA.mk, msgAtClaimSlot)).toThrow();
  });

  it('signature over payload A does not verify payload B, another tag or another key', () => {
    const o = P.openMessage(kA.mk, row);
    const other = JSON.stringify(payload({ text: 'hellp' }));
    expect(P.verifyMessageSig(tag, other, o.psig, alice.id.sigPk)).toBe(false);
    expect(P.verifyMessageSig(tag, JSON.stringify(p, null, 1), o.psig, alice.id.sigPk)).toBe(false);
    expect(P.verifyMessageSig(P.msgTag(kA.rk, 0, 1), o.text, o.psig, alice.id.sigPk)).toBe(false);
    expect(P.verifyMessageSig(P.msgTag(kB.rk, 0, 0), o.text, o.psig, alice.id.sigPk)).toBe(false);
    expect(P.verifyMessageSig(tag, o.text, o.psig, bob.id.sigPk)).toBe(false);
    expect(P.verifyMessageSig(tag, o.text, new Uint8Array(64), alice.id.sigPk)).toBe(false);
    for (let i = 0; i < 64; i++) expect(P.verifyMessageSig(tag, o.text, flip(o.psig, i, i % 8), alice.id.sigPk)).toBe(false);
    // A descriptor/bundle signature over the same bytes must not pass as a message signature.
    expect(P.verifyMessageSig(tag, o.text, P.sign(P.utf8(o.text), alice.id.sigSk), alice.id.sigPk)).toBe(false);
  });

  it('a bit flip anywhere in the body is rejected (every byte)', () => {
    const L = row.body.length;
    const s = survivors(
      row.body,
      [
        { name: 'nonce', start: 0, end: 24, every: true },
        { name: 'ct', start: 24, end: L - 16, every: true },
        { name: 'tag', start: L - 16, end: L, every: true },
      ],
      (b) => P.openMessage(kA.mk, { tag, body: b }),
      6,
    );
    expect(s).toEqual([]);
    expect(() => P.openMessage(kA.mk, { tag, body: row.body.subarray(0, L - 1) })).toThrow();
    expect(() => P.openMessage(kA.mk, { tag, body: cat(row.body, Uint8Array.of(0)) })).toThrow();
  });

  it('openMessage rejects authenticated bodies with bad inner shapes', () => {
    const seal = (pt: B) => ({ tag, body: P.aeadSeal(kA.mk, pt, refEnc('segv.sh/v1/msg', tag)) });
    const sig = new Uint8Array(64);
    const cases: [string, B][] = [
      ['v=2', refPad(refEnc('{"v":2}', sig), P.MSG_CLASSES)],
      ['null', refPad(refEnc('null', sig), P.MSG_CLASSES)],
      ['array', refPad(refEnc('[1]', sig), P.MSG_CLASSES)],
      ['not JSON', refPad(refEnc('{', sig), P.MSG_CLASSES)],
      ['invalid UTF-8', refPad(refEnc(Uint8Array.of(0xff), sig), P.MSG_CLASSES)],
      ['one field', refPad(refEnc('{"v":1}'), P.MSG_CLASSES)],
      ['three fields', refPad(refEnc('{"v":1}', sig, sig), P.MSG_CLASSES)],
      ['no marker', new Uint8Array(256)],
    ];
    for (const [name, pt] of cases) expect(() => P.openMessage(kA.mk, seal(pt)), name).toThrow(Error);
  });

  describe('validPayload', () => {
    const img = (over: Partial<P.ImageRef> = {}): P.ImageRef => ({
      id: P.b64u(fill(32, 0x42)),
      k: P.b64u(fill(32, 0x43)),
      mime: 'image/webp',
      w: 640,
      h: 480,
      ...over,
    });

    it('accepts well-formed text / image / leave payloads', () => {
      expect(P.validPayload(payload())).toBe(true);
      expect(P.validPayload(payload({ t: 'leave', text: undefined }))).toBe(true);
      expect(P.validPayload(payload({ t: 'image', text: undefined, img: img() }))).toBe(true);
      expect(P.validPayload(payload({ t: 'image', text: undefined, img: img({ mime: 'image/jpeg', w: 8192, h: 1 }) }))).toBe(true);
      expect(P.validPayload(payload({ e: 0xffffffff, n: 0xffffffff, ts: 0, head: { seq: 0, h: P.b64u(P.ZERO32) } }))).toBe(true);
    });

    it('rejects malformed payloads', () => {
      const bad: [string, unknown][] = [
        ['null', null],
        ['array', []],
        ['string', 'x'],
        ['t other', payload({ t: 'file' as P.Payload['t'] })],
        ['conv missing', payload({ conv: undefined as unknown as string })],
        ['conv not b64u', payload({ conv: 'not base64!' })],
        ['conv 15 bytes', payload({ conv: P.b64u(new Uint8Array(15)) })],
        ['from 17 bytes', payload({ from: P.b64u(new Uint8Array(17)) })],
        ['from number', payload({ from: 1 as unknown as string })],
        ['e negative', payload({ e: -1 })],
        ['e fractional', payload({ e: 0.5 })],
        ['e > u32', payload({ e: 2 ** 32 })],
        ['n negative', payload({ n: -1 })],
        ['n > u32', payload({ n: 2 ** 32 })],
        ['n string', payload({ n: '0' as unknown as number })],
        ['ts negative', payload({ ts: -1 })],
        ['ts fractional', payload({ ts: 1.5 })],
        ['head missing', payload({ head: undefined as unknown as P.Payload['head'] })],
        ['head.seq negative', payload({ head: { seq: -1, h: H32 } })],
        ['head.seq fractional', payload({ head: { seq: 1.5, h: H32 } })],
        ['head.h number', payload({ head: { seq: 1, h: 5 as unknown as string } })],
        ['head.h 16 bytes', payload({ head: { seq: 1, h: P.b64u(new Uint8Array(16)) } })],
        ['head.h hex', payload({ head: { seq: 1, h: '00'.repeat(32) } })],
        ['text empty', payload({ text: '' })],
        ['text missing', payload({ text: undefined })],
        ['text number', payload({ text: 5 as unknown as string })],
        ['image without img', payload({ t: 'image', text: undefined })],
        ['img.id path traversal', payload({ t: 'image', img: img({ id: '../../api/users/alice' }) })],
        ['img.id 31 bytes', payload({ t: 'image', img: img({ id: P.b64u(new Uint8Array(31)) }) })],
        ['img.id with query', payload({ t: 'image', img: img({ id: P.b64u(fill(32, 1)) + '?x=1' }) })],
        ['img.k 16 bytes', payload({ t: 'image', img: img({ k: P.b64u(new Uint8Array(16)) }) })],
        ['img.k empty', payload({ t: 'image', img: img({ k: '' }) })],
        ['img.mime svg', payload({ t: 'image', img: img({ mime: 'image/svg+xml' }) })],
        ['img.mime html', payload({ t: 'image', img: img({ mime: 'text/html' }) })],
        ['img.mime params', payload({ t: 'image', img: img({ mime: 'image/webp; charset=x' }) })],
        ['img.mime upper', payload({ t: 'image', img: img({ mime: 'IMAGE/WEBP' }) })],
        ['img.w 0', payload({ t: 'image', img: img({ w: 0 }) })],
        ['img.w 8193', payload({ t: 'image', img: img({ w: 8193 }) })],
        ['img.h negative', payload({ t: 'image', img: img({ h: -1 }) })],
        ['img.h fractional', payload({ t: 'image', img: img({ h: 1.5 }) })],
        ['img.w string', payload({ t: 'image', img: img({ w: '1' as unknown as number }) })],
      ];
      for (const [name, x] of bad) expect(P.validPayload(x as P.Payload), name).toBe(false);
    });
  });
});

// ───────────────────────── blobs ─────────────────────────

describe('blobs (§3.6)', () => {
  it('round trip for several sizes; id = b64u(H(blob)); length = 24 + Padmé(n+1) + 16', () => {
    for (const n of [0, 1, 2, 100, 5000, 65537, 300_000]) {
      const data = new Uint8Array(randomBytes(n));
      const { blob, id, key } = P.encryptBlob(data);
      expect(key.length).toBe(32);
      expect(id).toBe(P.b64u(sha(blob)));
      expect(id).toBe(Buffer.from(sha(blob)).toString('base64url'));
      expect(blob.length).toBe(24 + refPadmeLength(n + 1) + 16);
      expect(toHex(P.decryptBlob(blob, id, key))).toBe(toHex(data));
      // independent decryption
      const pt = xchacha20poly1305(key, blob.subarray(0, 24), s2b('segv.sh/v1/blob')).decrypt(blob.subarray(24));
      expect(toHex(P.unpad(pt))).toBe(toHex(data));
    }
  });

  it('fresh key per blob; wrong id / key / AAD fail', () => {
    const data = s2b('image bytes');
    const a = P.encryptBlob(data);
    const b = P.encryptBlob(data);
    expect(toHex(a.key)).not.toBe(toHex(b.key));
    expect(a.id).not.toBe(b.id);
    expect(() => P.decryptBlob(a.blob, b.id, a.key)).toThrow(/hash mismatch/);
    expect(() => P.decryptBlob(a.blob, a.id, b.key)).toThrow();
    expect(() => P.decryptBlob(a.blob, a.id, new Uint8Array(31))).toThrow();
    expect(() => P.decryptBlob(a.blob.subarray(0, 39), P.b64u(sha(a.blob.subarray(0, 39))), a.key)).toThrow();
    // a blob encrypted under a different AAD with the same key
    const foreign = P.aeadSeal(a.key, P.padme(data), s2b('segv.sh/v1/other'));
    expect(() => P.decryptBlob(foreign, P.b64u(sha(foreign)), a.key)).toThrow();
  });

  it('a bit flip in nonce / ciphertext / tag is rejected even if the id is recomputed', () => {
    const { blob, id, key } = P.encryptBlob(seqBytes(200));
    const L = blob.length;
    const regions = [
      { name: 'nonce', start: 0, end: 24, every: true },
      { name: 'ct', start: 24, end: L - 16 },
      { name: 'tag', start: L - 16, end: L, every: true },
    ];
    expect(survivors(blob, regions, (b) => P.decryptBlob(b, id, key), 7)).toEqual([]);
    expect(survivors(blob, regions, (b) => P.decryptBlob(b, P.b64u(sha(b)), key), 8)).toEqual([]);
  });
});

// ───────────────────────── log & PoW ─────────────────────────

describe('log rows (§4.1)', () => {
  const tag = seqBytes(16, 0x10);
  const body = seqBytes(40, 0x20);

  it('rowHash matches a hand-built hash-chain entry', () => {
    const h1 = P.rowHash(P.ZERO32, 1, 4, tag, body, TS);
    const manual = sha(
      cat(
        fromHex('0000000e'),
        s2b('segv.sh/v1/log'),
        fromHex('00000020'),
        new Uint8Array(32),
        fromHex('00000008' + '0000000000000001'),
        fromHex('00000001' + '04'),
        fromHex('00000010'),
        tag,
        fromHex('00000028'),
        body,
        fromHex('00000008'),
        be64(TS),
      ),
    );
    expect(toHex(h1)).toBe(toHex(manual));
    expect(toHex(P.rowHash(P.ZERO32, 1, 4, tag, body, TS))).toBe(toHex(h1));
    expect(P.ZERO32.length).toBe(32);
    expect(P.ZERO32.every((x) => x === 0)).toBe(true);
  });

  it('every field changes the hash; the chain links', () => {
    const base = toHex(P.rowHash(P.ZERO32, 1, 4, tag, body, TS));
    const variants = [
      P.rowHash(fill(32, 1), 1, 4, tag, body, TS),
      P.rowHash(P.ZERO32, 2, 4, tag, body, TS),
      P.rowHash(P.ZERO32, 1, 3, tag, body, TS),
      P.rowHash(P.ZERO32, 1, 4, flip(tag, 0), body, TS),
      P.rowHash(P.ZERO32, 1, 4, tag, flip(body, 39), TS),
      P.rowHash(P.ZERO32, 1, 4, tag, body, TS + 1000),
      // moving a byte from tag to body must change the hash (length-prefixed fields)
      P.rowHash(P.ZERO32, 1, 4, tag.subarray(0, 15), cat(tag.subarray(15), body), TS),
    ];
    const all = new Set([base, ...variants.map(toHex)]);
    expect(all.size).toBe(variants.length + 1);
    // chain of 5 rows recomputed independently
    let h: B = P.ZERO32;
    let ref: B = new Uint8Array(32);
    for (let seq = 1; seq <= 5; seq++) {
      h = P.rowHash(h, seq, 3, tag, body, TS + seq * 1000);
      ref = sha(refEnc('segv.sh/v1/log', ref, be64(seq), Uint8Array.of(3), tag, body, be64(TS + seq * 1000)));
      expect(toHex(h)).toBe(toHex(ref));
    }
    expect(() => P.rowHash(P.ZERO32, 1, 256, tag, body, TS)).toThrow(); // kind must fit u8, not wrap to 0
    expect(() => P.rowHash(P.ZERO32, -1, 4, tag, body, TS)).toThrow();
  });

  it('userTag / wrapTag follow §4.1', () => {
    expect(toHex(P.userTag(alice.uid))).toBe(toHex(sha(refEnc('segv.sh/v1/tag/user', alice.uid)).subarray(0, 16)));
    expect(toHex(P.wrapTag('{"a":1}'))).toBe(toHex(sha(refEnc('segv.sh/v1/tag/wrap', '{"a":1}')).subarray(0, 16)));
    expect(toHex(P.userTag(alice.uid))).not.toBe(toHex(P.userTag(bob.uid)));
    expect(toHex(P.wrapTag('{"a":1}'))).not.toBe(toHex(P.wrapTag('{"a":2}')));
  });
});

describe('proof of work (§4.3)', () => {
  it('leadingZeroBits table', () => {
    const table: [number[], number][] = [
      [[], 0],
      [[0x80], 0],
      [[0xff], 0],
      [[0x7f], 1],
      [[0x40], 1],
      [[0x3f], 2],
      [[0x20], 2],
      [[0x10], 3],
      [[0x08], 4],
      [[0x04], 5],
      [[0x02], 6],
      [[0x01], 7],
      [[0x00], 8],
      [[0x00, 0xff], 8],
      [[0x00, 0x01], 15],
      [[0x00, 0x00, 0x80], 16],
      [[0, 0, 0, 1], 31],
      [[0, 0, 0, 0], 32],
      [[1, 0, 0, 0], 7],
    ];
    for (const [bytes, n] of table) expect(P.leadingZeroBits(Uint8Array.from(bytes)), JSON.stringify(bytes)).toBe(n);
    expect(P.leadingZeroBits(new Uint8Array(32))).toBe(256);
  });

  it('powPre follows §4.3', () => {
    const body = s2b('{"rows":[]}');
    const pre = P.powPre('append', 2833333, P.H(body));
    expect(toHex(pre)).toBe(toHex(sha(refEnc('segv.sh/v1/pow', 'append', be32(2833333), sha(body)))));
    const scopes: P.PowScope[] = ['register', 'wrap', 'append', 'blob'];
    expect(new Set(scopes.map((s) => toHex(P.powPre(s, 1, P.H(body))))).size).toBe(4);
    expect(toHex(P.powPre('append', 2, P.H(body)))).not.toBe(toHex(P.powPre('append', 1, P.H(body))));
    expect(() => P.powPre('append', -1, P.H(body))).toThrow();
    expect(P.POW_WINDOW_MS).toBe(600_000);
  });

  it('powDifficulty table: +1 bit per doubling above 4 KiB (append) / 1 MiB (blob); register & wrap flat', () => {
    const KiB = 1024;
    const MiB = 1024 * 1024;
    // default bases from §4.3: register 20, wrap 18, append 16, blob 18
    const table: [P.PowScope, number, number, number][] = [
      ['append', 16, 0, 16],
      ['append', 16, 1, 16],
      ['append', 16, 4096, 16],
      ['append', 16, 4097, 17],
      ['append', 16, 8192, 17],
      ['append', 16, 8193, 18],
      ['append', 16, 16384, 18],
      ['append', 16, 16385, 19],
      ['append', 16, 40 * 3240, 21], // 40 invites (the batch maximum)
      ['append', 16, 40 * 16424, 24], // 40 messages of the 16384 class
      ['append', 16, MiB, 24],
      ['append', 16, MiB + 1, 25],
      ['append', 0, 4097, 1],
      ['blob', 18, 0, 18],
      ['blob', 18, 4097, 18],
      ['blob', 18, 512 * KiB, 18],
      ['blob', 18, MiB, 18],
      ['blob', 18, MiB + 1, 19],
      ['blob', 18, 2 * MiB, 19],
      ['blob', 18, 2 * MiB + 1, 20],
      ['blob', 18, 4 * MiB, 20],
      ['blob', 18, 4 * MiB + 1, 21],
      ['blob', 18, 8 * MiB, 21],
      ['blob', 18, 8 * MiB + 1, 22],
      ['blob', 18, P.BLOB_MAX, 22], // 12 MiB
      ['register', 20, 0, 20],
      ['register', 20, 4097, 20],
      ['register', 20, MiB + 1, 20],
      ['register', 20, 100 * MiB, 20],
      ['wrap', 18, 0, 18],
      ['wrap', 18, 8193, 18],
      ['wrap', 18, MiB + 1, 18],
      ['wrap', 18, 100 * MiB, 18],
    ];
    for (const [scope, base, bytes, want] of table) {
      expect(P.powDifficulty(scope, base, bytes), `${scope} base ${base}, ${bytes} B`).toBe(want);
      expect(refPowDifficulty(scope, base, bytes), `ref ${scope} ${bytes}`).toBe(want);
    }
  });

  it('powDifficulty matches the integer formula around every power of two and prices bytes linearly', () => {
    for (const scope of ['append', 'blob', 'register', 'wrap'] as const) {
      const unit = scope === 'append' ? 4096 : 1024 * 1024;
      let prev = 0;
      for (let k = 0; k <= 34; k++) {
        for (const d of [-1, 0, 1]) {
          const bytes = 2 ** k + d;
          if (bytes < 0) continue;
          const got = P.powDifficulty(scope, 10, bytes);
          expect(got, `${scope} 2^${k}${d < 0 ? '' : '+'}${d}`).toBe(refPowDifficulty(scope, 10, bytes));
          expect(got).toBeGreaterThanOrEqual(prev); // monotone in size
          prev = got;
          if ((scope === 'append' || scope === 'blob') && bytes > unit) {
            // work 2^(d - base) is at least bytes / unit and less than twice that
            const work = 2 ** (got - 10);
            expect(work).toBeGreaterThanOrEqual(bytes / unit);
            expect(work).toBeLessThan((2 * bytes) / unit);
          }
        }
      }
    }
  });

  it('powSolve finds the first valid nonce; powCheck verifies it', async () => {
    const pre = P.powPre('append', 1, P.H(s2b('x')));
    const nonce = await P.powSolve(pre, 12);
    expect(P.powCheck(pre, nonce, 12)).toBe(true);
    expect(P.leadingZeroBits(sha(cat(pre, be64(nonce))))).toBeGreaterThanOrEqual(12);
    for (let k = 0; k < nonce; k++) expect(P.powCheck(pre, k, 12)).toBe(false); // solver returns the first
    expect(P.powCheck(pre, nonce, 256)).toBe(false);
    expect(P.powCheck(P.powPre('append', 2, P.H(s2b('x'))), nonce, 12) && P.powCheck(pre, nonce + 1, 12)).toBe(false);
    expect(await P.powSolve(pre, 0)).toBe(0);
    expect(P.powCheck(pre, 0, 0)).toBe(true);
    const n1 = await P.powSolve(pre, 6, 1); // chunk = 1 yields after every hash
    expect(P.powCheck(pre, n1, 6)).toBe(true);
    expect(() => P.powCheck(pre, -1, 0)).toThrow();
  });
});

// ═════════════════════════ 4. fuzz ═════════════════════════

describe('fuzz', () => {
  it('dec: 2000 random byte strings either decode exactly or throw Error', () => {
    const r = prng(0xdec);
    for (let t = 0; t < 2000; t++) {
      // half pure noise, half valid encodings with a random mutation
      let b: B;
      if (t % 2 === 0) b = r.bytes(r.int(80));
      else {
        b = P.enc(...Array.from({ length: r.int(4) }, () => r.bytes(r.int(20))));
        if (b.length > 0) b = flip(b, r.int(b.length), r.int(8));
        if (r.int(4) === 0) b = b.subarray(0, r.int(b.length + 1));
      }
      const count = r.int(5);
      try {
        const parts = P.dec(b, count);
        expect(parts.length).toBe(count);
        expect(toHex(P.enc(...parts))).toBe(toHex(b));
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
      }
    }
  });

  it('fromB64u: 2000 random strings either round-trip canonically or throw Error', () => {
    const r = prng(0xb64);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/= .é';
    for (let t = 0; t < 2000; t++) {
      const n = r.int(30);
      let s = '';
      const pool = t % 3 === 0 ? alphabet.length : 64;
      for (let i = 0; i < n; i++) s += alphabet[r.int(pool)];
      try {
        expect(P.b64u(P.fromB64u(s))).toBe(s);
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
      }
    }
  });

  it('unpad: random input either throws or strips exactly one marker', () => {
    const r = prng(0x9ad);
    for (let t = 0; t < 2000; t++) {
      const b = r.bytes(r.int(16));
      if (r.int(2)) b.fill(0, r.int(b.length + 1));
      try {
        const x = P.unpad(b);
        expect(b[x.length]).toBe(0x80);
        expect(b.subarray(x.length + 1).every((v) => v === 0)).toBe(true);
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
      }
    }
  });

  it('parseDescriptor: mutated descriptors either throw Error or satisfy every invariant', () => {
    const r = prng(0xd35c);
    const base = dText({ e: 3, prev: H32, members: [alice.uidS, bob.uidS, carol.uidS], by: bob.uidS, name: 'grp' });
    const chars = '{}[]":,0123456789-.eAZaz_ \\nul';
    let accepted = 0;
    for (let t = 0; t < 1500; t++) {
      const a = base.split('');
      for (let m = 0; m <= r.int(3); m++) {
        const i = r.int(a.length);
        const op = r.int(3);
        if (op === 0) a.splice(i, 1);
        else if (op === 1) a.splice(i, 0, chars[r.int(chars.length)]);
        else a[i] = chars[r.int(chars.length)];
      }
      const text = a.join('');
      let d: P.Descriptor;
      try {
        d = P.parseDescriptor(text);
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
        continue;
      }
      accepted++;
      expect(d.v).toBe(1);
      expect(P.fromB64u(d.conv).length).toBe(16);
      expect(Number.isInteger(d.e) && d.e >= 0 && d.e <= 0xffffffff).toBe(true);
      expect(d.members.length >= 1 && d.members.length <= 32).toBe(true);
      for (const m of d.members) expect(P.fromB64u(m).length).toBe(16);
      expect(new Set(d.members).size).toBe(d.members.length);
      expect(d.members).toContain(d.by);
      expect(d.e === 0 ? d.prev === null : typeof d.prev === 'string' && P.fromB64u(d.prev).length === 32).toBe(true);
      expect(Number.isSafeInteger(d.ts) && d.ts >= 0).toBe(true);
      if (d.name !== undefined) expect(typeof d.name === 'string' && [...d.name].length <= 64).toBe(true);
    }
    expect(accepted).toBeGreaterThan(0);
  });

  it('openMessage / openClaim / openInvite / parsers on random input throw Error, never anything else', () => {
    const r = prng(0x0be);
    const { mk } = P.epochKeys(EK0, CONV_A, 0);
    for (let t = 0; t < 300; t++) {
      const body = r.bytes(t % 2 ? P.MSG_BODY_LENS[r.int(2)] : r.int(400));
      const tag = r.bytes(16);
      expect(throwsError(() => P.openMessage(mk, { tag, body }))).toBe(true);
      expect(throwsError(() => P.openClaim(mk, { tag, body }))).toBe(true);
      const s = P.fromUtf8(Uint8Array.from(r.bytes(r.int(60)), (x) => 0x20 + (x % 0x5f)));
      expect(throwsError(() => P.parseBundle(s, alice.sig))).toBe(true);
      expect(throwsError(() => P.parseWrap(s, alice.sig))).toBe(true);
      expect(throwsError(() => P.parseRecoveryCode(s))).toBe(true);
    }
    for (let t = 0; t < 10; t++) {
      const row = { tag: r.bytes(16), body: r.bytes(P.INV_BODY_LENS[0]) };
      expect(throwsError(() => P.openInvite(bob.id.kemSk, r.bytes(32), row))).toBe(true);
    }
  });
});

// ═════════════════════════ 3b. signature strictness ═════════════════════════

describe('signature strictness', () => {
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const le = (n: bigint): B => Uint8Array.from({ length: 32 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));
  const fromLe = (b: B): bigint => b.reduceRight((acc, x) => (acc << 8n) | BigInt(x), 0n);

  it('rejects the universal forgery under a small-order public key', () => {
    // A = identity point, R = identity, S = 0: passes the cofactored ZIP-215 equation for EVERY message.
    const A = cat(Uint8Array.of(1), new Uint8Array(31));
    const sig = cat(cat(Uint8Array.of(1), new Uint8Array(31)), new Uint8Array(32));
    for (const m of ['bundle', 'other message', '']) expect(P.verify(sig, s2b(m), A), m).toBe(false);
    // Consequences if accepted: a member with this "sigPk" could have one dsig/psig verify for any
    // descriptor/EK/payload, and anyone holding mk could forge their messages.
    expect(P.verifyDescriptorSig(dText(), P.epochKeys(EK0, CONV_A, 0).kc, sig, A)).toBe(false);
    expect(P.verifyMessageSig(fill(16, 1), '{"v":1}', sig, A)).toBe(false);
    // Other small-order encodings (order 2: y = -1).
    const minusOne = le(2n ** 255n - 19n - 1n);
    expect(P.verify(cat(minusOne, new Uint8Array(32)), s2b('x'), minusOne)).toBe(false);
  });

  it('rejects malleated signatures (S + L)', () => {
    const msg = s2b('payload');
    const sig = P.sign(msg, alice.id.sigSk);
    const S = fromLe(sig.subarray(32));
    const mall = cat(sig.subarray(0, 32), le(S + L));
    expect(P.verify(sig, msg, alice.id.sigPk)).toBe(true);
    expect(P.verify(mall, msg, alice.id.sigPk)).toBe(false);
  });

  it('a bundle with a small-order signing key cannot be registered', () => {
    const A = P.b64u(cat(Uint8Array.of(1), new Uint8Array(31)));
    const raw = { ...(JSON.parse(alice.bundle) as Record<string, unknown>), sig: A };
    const text = JSON.stringify(raw);
    const sig = P.b64u(cat(cat(Uint8Array.of(1), new Uint8Array(31)), new Uint8Array(32)));
    expect(() => P.parseBundle(text, sig)).not.toThrow();
    expect(() => P.verifyBundle(text, sig)).toThrow(/signature/);
  });
});

// ═════════════════════════ 5. known-answer vectors ═════════════════════════
// Generated once from the implementation after the tests above passed. enc / b64u / rowHash /
// powPre / tags / fingerprint / recovery codes are additionally cross-checked above by independent
// computation. If one of these fails, the wire format changed: that breaks every existing account,
// log row and conversation. Do not "fix" the vector — fix the code (or bump the protocol version).

const KAT = {
  AK: seqBytes(32), // 00 01 .. 1f
  UID: seqBytes(16, 0x40),
  identity: {
    sigSk: 'b13f5ad2995838464ac6ba731e22484268883bd2e350a978c10324911923d3b8',
    sigPk: '9e59ea48b6f064125961b179f2429aa774b325957276a6103c2417f895140887',
    kemSk: '805f57afd15ff17b2ae916161c5765286b57134172542fc0d2f7fe0e08e261b9',
    kemPkSha256: '42d50997338787800f0173db0527d5710c9c5bfe87c5c6c0e8b6c598543579da',
    scanSk: 'a0436518afc97e60bea9c0d80375d498ea932374e39162c0e0fbeee8b4cee74d',
    scanPk: '128e90cd4fcec9c80887843a99f63dbb8b50a6155db848ea079b4ab0289e8504',
  },
  bundlePrefix: '{"v":1,"uid":"QEFCQ0RFRkdISUpLTE1OTw","handle":"kat_user","sig":"nlnqSLbwZBJZYbF58kKap3SzJZVydqYQPCQX-JUUCIc","kem":"bUMty7WMFqxhh-iTPya0',
  bundleSuffix: '","scan":"Eo6QzU_OycgIh4Q6mfY9u4tQphVduEjqB5tKsCiehQQ","ts":1700000000000}',
  bundleSha256: 'dfb041c8134c078a0bd60889844738f43d98cc33267e106c12130839d330fb95',
  bundleSig: 'WV9F-t4eZ00yPukMGPhO_o5hzizFMSFTWno1YmiKGlScJueyfHeWjskq_rsdecHBBzhBO9y5LT7npNIB0jnMCQ',
  fingerprint: '34615 42488 34039 22546 24887 17801',
  credKem: {
    pkSha256: 'db45c744a520bf010e42c7c24d55ccedfee4be247d28418e1fc9f00655bc4fb1',
    sk: 'f60f4aeaa5afedd908b998e4b2b74fc7218a60ad2357d59fa3f473adf4c72cbb',
    // HKDF(prf = 11*32, salt = credId 80..93, "segv.sh/v1/cred/auth"); cross-checked with Python hmac/hashlib
    auth: '0c81fb308fd1be864e101d404d2c79168afa0ef6b247f001f47f1d401e52f1b7',
  },
  recoveryKem: {
    pkSha256: 'd13d8d60ffc00853e5eab27893b54a863eb3e0f62c23b84eda56a686402925f0',
    sk: 'a4810e9f844f2d70d3223ace1379a954f35d1228c1153358a944314e2eb1f74b',
    id: '7deeaa931ddf1a1f948ca8a27bac2d87',
    // HKDF(code = 00..13, "", "segv.sh/v1/recovery/auth"); cross-checked with Python hmac/hashlib
    auth: 'd65bcb69d941fece84a91a4c5822d6edef1793f27fdd3eda1914da9c452a9132',
  },
  // ak-wraps of AK = 00..1f for UID = 40..4f with fixed X-Wing randomness and nonce:
  // ctx = enc(uid, id, auth), key = HKDF(ss, H(kct), enc("segv.sh/v1/seal", "ak-wrap", ctx)).
  // ctx and key were recomputed with Python hmac/hashlib from ss and H(kct).
  wrap: {
    passkey: {
      ctxSha256: 'fc2cec7c8929f4f29370c9011b32a86e222fc0a332c650c3fb592400db4e469f',
      ss: 'fc0b871bddc13f086a2fe1cccc5eeebdd197748e2aba13ec628e0283d0b49282',
      key: '778d82e4d488d40c6c47f366f50800942cd5032f566cca5aea258d6ddb35d0a3',
      boxSha256: 'a92bbf47a4307759a893f338a9760c6c74ab6b4a07993fbf79e3f5a69bec5494',
    },
    recovery: {
      ctxSha256: '87283e99b60491cdf81da9b7b579173c26af77c2e0d8dcd4a24dbb03e4846d88',
      ss: '2a3aace9ed6bf3bacffdef08ff9b838d8fc95987fec63fd69edb7d25a8706f49',
      key: '3d52aa6345c5ab8cb12f59c2b84acd626045aa776239ba67a5461d5ea6e38639',
      boxSha256: '183d85d1c142c1170da31ee5f3c3bb078fa706fa5408b12714f073c5f1519d2d',
    },
  },
  // hand check of the first group: 00 01 02 03 04 -> 00000 00000 00000 10000 00100 00000 11000 00100 -> "000G40R4"
  recoveryCode: '000G-40R4-0M30-E209-185G-R38E-1W81-24GK',
  epoch: {
    rk: '547cee08d23fa9fbc7542f0928ff2353dcae3d057a83d38443aec735d674bfe0',
    mk: '3dd9f23197f347f5b76c95926ee03eb4987be216aa65f1f07b314dbb9b50a300',
    kc: 'adff7843caf10456305c8ce00d83006c6ebf9dded86b6f09308fb7d8dd2556cb',
    msgTag_3_5: '0fdd065cf745c99cd3452d84959d093a',
    msgTag_0_0: '64d3b2625af473c6ef11c5f08afcf33f',
    claimTag: 'e3bcec83fcaf577f99f3c64f006ea721',
  },
  descriptor:
    '{"v":1,"conv":"YGFiY2RlZmdoaWprbG1ubw","e":7,"members":["QEFCQ0RFRkdISUpLTE1OTw"],"prev":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo","by":"QEFCQ0RFRkdISUpLTE1OTw","ts":1700000000000,"name":"kat"}',
  dsig: 'cfce1c194a62fd7f2ea851e0ea23a53651505ac0886d657a882bc9529b5c6272502f2f0cb50d349c87266a69a183f2339b2e7f85ef4e4dac5e9573d51c889f0f',
  psig: '84953d8ffb7f286154c01b440862bcf96de4b8587c3f7e3d6719c5e70ebfc2757885b3b83e9351a72425427a81fd3ea7c30b4bc28be7700ff23a5ce715a60008',
  csig: '6fc71279301ea6f4fd492f0870757400e21d245984c3daade712a421ad42dd63616c423459744cbcbeb5df2b00cddcb0697547c3375115e3776d11c6eddd2608',
  // 32 + 1120 + 24 + 2048 + 16 (one invite class); 24 + {1024, 4096, 16384} + 16
  invBodyLens: [3240],
  msgBodyLens: [1064, 4136, 16424],
  rowHash: '0f4121678809b76207bafb3e974106b8ee846892a987628325e60ffe8c6c397c',
  rowHash2: '18cf78bb7536553506db9e876dd677e9e5dd4016579a32b31e1e529bea6b890a',
  userTag: 'd1e08b1104bf46f7c894554b89e65eda',
  wrapTag: 'abdb566cf3f608261ac664d449fcae65',
  powPre: 'b84354d84df8db5df0d20329747726ce97e2007fd8511c15cc8306f0557a2e86',
  powNonce16: 12109,
  // hand check: lp("segv.sh/v1/kat") || lp(00..04) || lp("") || lp(ff)
  enc: '0000000e' + '736567762e73682f76312f6b6174' + '00000005' + '0001020304' + '00000000' + '00000001' + 'ff',
  b64u: 'wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w',
};

describe('known-answer vectors', () => {
  const id = P.deriveIdentity(KAT.AK);

  it('enc / b64u', () => {
    expect(toHex(P.enc('segv.sh/v1/kat', seqBytes(5), '', Uint8Array.of(0xff)))).toBe(KAT.enc);
    expect(P.b64u(seqBytes(64, 0xc0))).toBe(KAT.b64u);
    expect(Buffer.from(seqBytes(64, 0xc0)).toString('base64url')).toBe(KAT.b64u); // independent
  });

  it('deriveIdentity from AK = 00..1f', () => {
    expect(toHex(id.sigSk)).toBe(KAT.identity.sigSk);
    expect(toHex(id.sigPk)).toBe(KAT.identity.sigPk);
    expect(toHex(id.kemSk)).toBe(KAT.identity.kemSk);
    expect(toHex(sha(id.kemPk))).toBe(KAT.identity.kemPkSha256);
    expect(toHex(id.scanSk)).toBe(KAT.identity.scanSk);
    expect(toHex(id.scanPk)).toBe(KAT.identity.scanPk);
  });

  it('bundle, bundle signature and fingerprint', () => {
    const { bundle, sig } = P.makeBundle(KAT.UID, 'kat_user', id, TS);
    expect(bundle.startsWith(KAT.bundlePrefix)).toBe(true);
    expect(bundle.endsWith(KAT.bundleSuffix)).toBe(true);
    expect(toHex(sha(s2b(bundle)))).toBe(KAT.bundleSha256);
    expect(sig).toBe(KAT.bundleSig); // Ed25519 is deterministic
    expect(P.fingerprint(P.verifyBundle(bundle, sig))).toBe(KAT.fingerprint);
  });

  it('credential / recovery KEM keys, auth values and recovery code', () => {
    const c = P.credKem(fill(32, 0x11), seqBytes(20, 0x80));
    expect(toHex(sha(c.pk))).toBe(KAT.credKem.pkSha256);
    expect(toHex(c.sk)).toBe(KAT.credKem.sk);
    expect(toHex(c.auth)).toBe(KAT.credKem.auth);
    const r = P.recoveryKem(seqBytes(20));
    expect(toHex(sha(r.pk))).toBe(KAT.recoveryKem.pkSha256);
    expect(toHex(r.sk)).toBe(KAT.recoveryKem.sk);
    expect(toHex(r.id)).toBe(KAT.recoveryKem.id);
    expect(toHex(r.auth)).toBe(KAT.recoveryKem.auth);
    expect(P.formatRecoveryCode(seqBytes(20))).toBe(KAT.recoveryCode);
  });

  it('ak-wraps with fixed randomness (ctx = enc(uid, id, auth))', () => {
    const c = P.credKem(fill(32, 0x11), seqBytes(20, 0x80));
    const r = P.recoveryKem(seqBytes(20));
    const cases = [
      ['passkey', c, seqBytes(20, 0x80), seqBytes(64, 0x90), seqBytes(24, 0xd0)],
      ['recovery', r, r.id, seqBytes(64, 0xa0), seqBytes(24, 0xe0)],
    ] as const;
    for (const [kind, key, wid, rnd, nonce] of cases) {
      const want = KAT.wrap[kind];
      const ctx = refEnc(KAT.UID, wid, key.auth);
      expect(toHex(sha(ctx)), kind).toBe(want.ctxSha256);
      const { cipherText: kct, sharedSecret: ss } = xwing.encapsulate(key.pk, rnd);
      expect(toHex(ss), kind).toBe(want.ss);
      const k = hkdfN(ss, sha(kct), refEnc('segv.sh/v1/seal', 'ak-wrap', ctx));
      expect(toHex(k), kind).toBe(want.key);
      const box = cat(kct, nonce, xchacha20poly1305(k, nonce, refEnc('ak-wrap', ctx)).encrypt(KAT.AK));
      expect(box.length).toBe(P.WRAP_LEN);
      expect(toHex(sha(box)), kind).toBe(want.boxSha256);
      // proto.ts opens the independently built box, and the owner-signed record passes the key check
      expect(toHex(P.openWrap({ uid: P.b64u(KAT.UID), id: wid, wrap: box }, key))).toBe(toHex(KAT.AK));
      const record = JSON.stringify({ v: 1, uid: P.b64u(KAT.UID), kind, id: P.b64u(wid), kem: P.b64u(key.pk), wrap: P.b64u(box), ts: TS });
      const sig = P.b64u(P.sign(P.wrapSigMsg(record), id.sigSk));
      expect(toHex(P.unwrapAK(P.verifyWrap(record, sig, id.sigPk), key, id.sigPk))).toBe(toHex(KAT.AK));
    }
  });

  it('size classes', () => {
    expect(P.INV_BODY_LENS).toEqual(KAT.invBodyLens);
    expect(P.MSG_BODY_LENS).toEqual(KAT.msgBodyLens);
  });

  it('epoch keys, tags, descriptor and signatures', () => {
    const k = P.epochKeys(seqBytes(32, 0x20), seqBytes(16, 0x60), 7);
    expect(toHex(k.rk)).toBe(KAT.epoch.rk);
    expect(toHex(k.mk)).toBe(KAT.epoch.mk);
    expect(toHex(k.kc)).toBe(KAT.epoch.kc);
    expect(toHex(P.msgTag(k.rk, 3, 5))).toBe(KAT.epoch.msgTag_3_5);
    expect(toHex(P.msgTag(k.rk, 0, 0))).toBe(KAT.epoch.msgTag_0_0);
    expect(toHex(P.claimTag(k.rk))).toBe(KAT.epoch.claimTag);
    const uid = P.b64u(KAT.UID);
    const d = P.makeDescriptor({ conv: P.b64u(seqBytes(16, 0x60)), e: 7, members: [uid], prev: P.b64u(fill(32, 0xaa)), by: uid, ts: TS, name: 'kat' });
    expect(d).toBe(KAT.descriptor);
    expect(toHex(P.signDescriptor(d, k.kc, id.sigSk))).toBe(KAT.dsig);
    const p: P.Payload = { v: 1, t: 'text', conv: P.b64u(seqBytes(16, 0x60)), e: 7, from: uid, n: 5, ts: TS, text: 'kat', head: { seq: 9, h: P.b64u(fill(32, 0xbb)) } };
    const row = P.makeMessage(k.mk, P.msgTag(k.rk, 0, 5), p, id.sigSk);
    expect(toHex(P.openMessage(k.mk, row).psig)).toBe(KAT.psig);
    const claim = P.openClaim(k.mk, P.makeClaim(k.mk, k.rk, d, fromHex(KAT.dsig), id.sigSk));
    expect(toHex(claim.csig)).toBe(KAT.csig);
    expect(nodeEdVerify(claim.csig, refEnc('segv.sh/v1/claim-sig', P.claimTag(k.rk), d, fromHex(KAT.dsig)), id.sigPk)).toBe(true);
  });

  it('log hashes, tags and PoW', () => {
    const h1 = P.rowHash(P.ZERO32, 1, 4, seqBytes(16, 0x10), seqBytes(40, 0x20), TS);
    expect(toHex(h1)).toBe(KAT.rowHash);
    expect(toHex(P.rowHash(h1, 2, 1, seqBytes(16), new Uint8Array(0), TS + 1000))).toBe(KAT.rowHash2);
    expect(toHex(P.userTag(KAT.UID))).toBe(KAT.userTag);
    expect(toHex(P.wrapTag('{"v":1}'))).toBe(KAT.wrapTag);
    const pre = P.powPre('register', 2833333, P.H(s2b('{"bundle":"x"}')));
    expect(toHex(pre)).toBe(KAT.powPre);
  });

  it('PoW nonce for a fixed challenge', async () => {
    const pre = P.powPre('register', 2833333, P.H(s2b('{"bundle":"x"}')));
    expect(await P.powSolve(pre, 16)).toBe(KAT.powNonce16);
  });
});
