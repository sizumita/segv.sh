// segv.sh protocol v2 (stage 1) — shared by the browser client, the Worker, the Durable Objects and the
// tests. Byte-exact implementation of docs/PROTOCOL-v2.md. Keep this file free of DOM / Workers APIs.
//
// Section map (spec §):
//   encoding .............. §1.2    primitives ......... §1.1    padding ........... §1.3
//   rng ................... §1      time ............... §3.1    classes ........... §3.2
//   accounts .............. §2      sealing ............ §1.4    epoch labels ...... §4.1–§4.2
//   links ................. §4.3    routing ............ §4.4    commitments ....... §9, §12
//   proof of work ......... §10.2   directory .......... §9.6, §10.6
//   blobs ................. §8.1
// The conversation codecs (§3.3 envelope M, §5 descriptors / joins / bundles, §6.2 claims, §7 self lane)
// follow the "conversation codecs" banner further down.
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_kem768_x25519 as xwing } from "@noble/post-quantum/hybrid.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { randomBytes } from "@noble/hashes/utils.js";

export type Bytes = Uint8Array;

// ───────────────────────── encoding ─────────────────────────

const te = new TextEncoder();
// §1.2: invalid UTF-8 is rejected, and a leading U+FEFF is kept (the default decoder would strip it).
const td = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export const utf8 = (s: string): Bytes => te.encode(s);
/** Strict UTF-8 decoding (§1.2): throws on invalid UTF-8 and keeps a leading U+FEFF. */
export const fromUtf8 = (b: Bytes): string => td.decode(b);

export function concat(...parts: Bytes[]): Bytes {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// Fixed-width encoders reject out-of-range values instead of silently truncating (u16(65536) would
// otherwise alias u16(0), e.g. msgTag(rk, 65536, n) === msgTag(rk, 0, n)).
export function u8(x: number): Bytes {
  if (!Number.isInteger(x) || x < 0 || x > 0xff) throw new Error('u8 out of range');
  return Uint8Array.of(x);
}
export function u16(x: number): Bytes {
  if (!Number.isInteger(x) || x < 0 || x > 0xffff) throw new Error('u16 out of range');
  return Uint8Array.of(x >>> 8, x & 0xff);
}
export function u32(x: number): Bytes {
  if (!Number.isInteger(x) || x < 0 || x > 0xffffffff) throw new Error('u32 out of range');
  return Uint8Array.of(x >>> 24, (x >>> 16) & 0xff, (x >>> 8) & 0xff, x & 0xff);
}
export function u64(x: number): Bytes {
  if (!Number.isSafeInteger(x) || x < 0) throw new Error('u64 out of range');
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(x));
  return out;
}

const asBytes = (x: Bytes | string): Bytes => (typeof x === 'string' ? utf8(x) : x);
export const lp = (b: Bytes): Bytes => concat(u32(b.length), b);
export const enc = (...xs: (Bytes | string)[]): Bytes => concat(...xs.map((x) => lp(asBytes(x))));

/** Inverse of enc() for a fixed number of fields; throws on any trailing / missing bytes. */
export function dec(b: Bytes, count: number): Bytes[] {
  const out: Bytes[] = [];
  let o = 0;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  for (let i = 0; i < count; i++) {
    if (o + 4 > b.length) throw new Error('dec: truncated');
    const n = dv.getUint32(o);
    o += 4;
    if (o + n > b.length) throw new Error('dec: truncated');
    out.push(b.subarray(o, o + n));
    o += n;
  }
  if (o !== b.length) throw new Error('dec: trailing bytes');
  return out;
}

const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64U_REV = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64U.length; i++) t[B64U.charCodeAt(i)] = i;
  return t;
})();

export function b64u(b: Bytes): string {
  let s = '';
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const v = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
    s += B64U[v >>> 18] + B64U[(v >>> 12) & 63] + B64U[(v >>> 6) & 63] + B64U[v & 63];
  }
  if (b.length - i === 1) {
    const v = b[i] << 16;
    s += B64U[v >>> 18] + B64U[(v >>> 12) & 63];
  } else if (b.length - i === 2) {
    const v = (b[i] << 16) | (b[i + 1] << 8);
    s += B64U[v >>> 18] + B64U[(v >>> 12) & 63] + B64U[(v >>> 6) & 63];
  }
  return s;
}

export function fromB64u(s: string): Bytes {
  if (typeof s !== 'string' || s.length % 4 === 1) throw new Error('bad base64url');
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? B64U_REV[c] : -1;
    if (v < 0) throw new Error('bad base64url');
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >>> bits) & 0xff;
    }
  }
  // Reject non-canonical encodings (non-zero leftover bits).
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) throw new Error('bad base64url');
  return out.subarray(0, o);
}

export const hex = (b: Bytes): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

export function equalBytes(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export const trunc16 = (b: Bytes): Bytes => b.slice(0, 16);

// ───────────────────────── primitives ─────────────────────────

export const H = (x: Bytes): Bytes => sha256(x);
export const HKDF = (ikm: Bytes, salt: Bytes | string, info: Bytes | string, len = 32): Bytes =>
  hkdf(sha256, ikm, asBytes(salt), asBytes(info), len);
export const HMAC = (k: Bytes, m: Bytes): Bytes => hmac(sha256, k, m);

export const NONCE_LEN = 24;
export const TAG_LEN = 16;

export function aeadOpen(key: Bytes, box: Bytes, aad: Bytes): Bytes {
  if (box.length < NONCE_LEN + TAG_LEN) throw new Error('aead: short');
  const nonce = box.subarray(0, NONCE_LEN);
  return xchacha20poly1305(key, nonce, aad).decrypt(box.subarray(NONCE_LEN));
}

export const KEM_PK_LEN = 1216;
export const KEM_CT_LEN = 1120;

export function kemKeygen(seed: Bytes): { pk: Bytes; sk: Bytes } {
  const kp = xwing.keygen(seed);
  return { pk: kp.publicKey, sk: kp.secretKey };
}

export function sigPub(sk: Bytes): Bytes {
  return ed25519.getPublicKey(sk);
}
export function sign(msg: Bytes, sk: Bytes): Bytes {
  return ed25519.sign(msg, sk);
}
/**
 * SIG.verify (§1.1), the one pinned rule for every v2 signature: validSigPk(pk), then noble's strict RFC 8032
 * verification (canonical R, S < L, the cofactored equation [8]([S]B − R − [k]A) = O). noble's ed25519 defaults
 * to ZIP-215, which accepts small-order public keys: with A = R = identity and S = 0 one "signature" verifies for
 * EVERY message. A mixed-order key is refused by validSigPk: the cofactored equation ignores its torsion part.
 */
export function verify(sig: Bytes, msg: Bytes, pk: Bytes): boolean {
  try {
    return sig.length === 64 && pk.length === 32 && !isBadSigPk(pk) && ed25519.verify(sig, msg, pk, { zip215: false });
  } catch {
    return false;
  }
}

// ───────────────────────── padding ─────────────────────────

export function pad(x: Bytes, classes: readonly number[]): Bytes {
  const target = classes.find((c) => c >= x.length + 1);
  if (target === undefined) throw new Error('payload too large');
  const out = new Uint8Array(target);
  out.set(x);
  out[x.length] = 0x80;
  return out;
}

export function unpad(x: Bytes): Bytes {
  let i = x.length - 1;
  while (i >= 0 && x[i] === 0) i--;
  if (i < 0 || x[i] !== 0x80) throw new Error('bad padding');
  return x.subarray(0, i);
}

export function padmeLength(L: number): number {
  if (L < 2) return L;
  const E = Math.floor(Math.log2(L));
  const S = Math.floor(Math.log2(E)) + 1;
  const z = E - S;
  const mask = 2 ** z - 1;
  // Use arithmetic (not bitwise) so lengths above 2^31 stay correct.
  return Math.ceil(L / (mask + 1)) * (mask + 1);
}

export function padme(x: Bytes): Bytes {
  const out = new Uint8Array(padmeLength(x.length + 1));
  out.set(x);
  out[x.length] = 0x80;
  return out;
}

// ───────────────────────── shared constants and helpers ─────────────────────────

export const HANDLE_RE = /^[a-z0-9_]{3,20}$/;

/** Bytes of a key wrap (§2.4): KEM ciphertext + nonce + AK + tag. */
export const WRAP_LEN = KEM_CT_LEN + NONCE_LEN + 32 + TAG_LEN; // 1192
/** WebAuthn credential ids are at most 1023 bytes. */
export const MAX_ID_LEN = 1023;

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function formatRecoveryCode(code: Bytes): string {
  if (code.length !== 20) throw new Error('recovery code must be 20 bytes');
  let bits = 0;
  let acc = 0;
  let s = '';
  for (const byte of code) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      s += CROCKFORD[(acc >>> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  return s.match(/.{4}/g)!.join('-');
}

export function parseRecoveryCode(text: string): Bytes {
  const norm = text
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
  if (norm.length !== 32) throw new Error('recovery code must have 32 characters');
  const out = new Uint8Array(20);
  let bits = 0;
  let acc = 0;
  let o = 0;
  for (const ch of norm) {
    const v = CROCKFORD.indexOf(ch);
    if (v < 0) throw new Error('invalid character in recovery code');
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >>> bits) & 0xff;
    }
    acc &= (1 << bits) - 1;
  }
  return out;
}

export const MAX_MEMBERS = 32;
export const MAX_NAME = 64;

// Control characters and bidi overrides/isolates would let a name spoof the UI.
// Also format characters (zero-width, tags, bidi) and the blank-looking Hangul / braille fillers.
const BAD_NAME_CHARS = /[\p{Cc}\p{Cf}\p{Cs}\u061c\u2028\u2029\u115f\u1160\u3164\uffa0\u2800]/u;
const VISIBLE = /[\p{L}\p{N}\p{P}\p{S}]/u;

/**
 * Group names: 1..MAX_NAME code points, no control / bidi characters, not only whitespace. A rule for building a new
 * name and for displaying one (§5.1), never for parsing: its character classes follow the engine's Unicode version.
 */
export function validName(name: unknown): name is string {
  return (
    typeof name === 'string' &&
    name.trim() !== '' &&
    VISIBLE.test(name) &&
    // would look like a 1:1 with that handle (NFKC folds look-alikes such as U+FF20 / U+FE6B into "@")
    !name.normalize('NFKC').trimStart().startsWith('@') &&
    [...name].length <= MAX_NAME &&
    !BAD_NAME_CHARS.test(name)
  );
}

export const BLOB_MAX = 12 * 1024 * 1024;

export function leadingZeroBits(b: Bytes): number {
  let n = 0;
  for (const x of b) {
    if (x === 0) {
      n += 8;
      continue;
    }
    return n + Math.clz32(x) - 24;
  }
  return n;
}

export function powCheck(pre: Bytes, nonce: number, difficulty: number): boolean {
  return leadingZeroBits(H(concat(pre, u64(nonce)))) >= difficulty;
}

export interface PowSolveOptions {
  /** the first nonce tried (default 0) */
  start?: number;
  /** hashes between two yields to the event loop (default 4096) */
  chunk?: number;
  /** checked before the search and at every yield: once aborted, the search ends without a nonce */
  signal?: AbortSignal;
}

/**
 * Finds a nonce in [start, 2^53 − 1], writing both halves of the big-endian u64 (§10.2). It yields to the event loop
 * every `chunk` hashes so the UI stays responsive. A search stopped through `signal` resolves to null, so the caller
 * can restart it with the next window when the one it searches in stops being current (§10.2).
 */
export function powSolve(pre: Bytes, difficulty: number, opts?: Omit<PowSolveOptions, "signal">): Promise<number>;
export function powSolve(pre: Bytes, difficulty: number, opts: PowSolveOptions): Promise<number | null>;
export async function powSolve(pre: Bytes, difficulty: number, opts: PowSolveOptions = {}): Promise<number | null> {
  const { start = 0, chunk = 4096, signal } = opts;
  if (!Number.isSafeInteger(start) || start < 0) throw new RangeError("pow: bad start nonce");
  if (!Number.isSafeInteger(chunk) || chunk < 1) throw new RangeError("pow: bad chunk");
  if (signal?.aborted) return null;
  const buf = new Uint8Array(pre.length + 8);
  buf.set(pre);
  const dv = new DataView(buf.buffer);
  let hi = Math.floor(start / 2 ** 32);
  let lo = start - hi * 2 ** 32;
  dv.setUint32(pre.length, hi);
  for (let nonce = start, k = 1; nonce <= Number.MAX_SAFE_INTEGER; nonce++, k++) {
    dv.setUint32(pre.length + 4, lo);
    if (leadingZeroBits(sha256(buf)) >= difficulty) return nonce;
    if (++lo === 2 ** 32) {
      lo = 0;
      dv.setUint32(pre.length, ++hi);
    }
    if (k % chunk === 0) {
      await new Promise((r) => setTimeout(r, 0));
      if (signal?.aborted) return null;
    }
  }
  throw new Error("pow: nonce space exhausted");
}


// ───────────────────────── randomness (injectable for known-answer tests) ─────────────────────────

let rng: (n: number) => Bytes = randomBytes;

/**
 * Test-only: replaces the CSPRNG behind random(), aeadSeal() nonces, KEM encapsulation randomness and
 * recovery codes, so known-answer tests are deterministic. Pass null to restore the CSPRNG.
 */
export function _setRandomForTests(fn: ((n: number) => Bytes) | null): void {
  rng = fn ?? randomBytes;
}

export const random = (n: number): Bytes => rng(n);

/** XChaCha20-Poly1305 with a random 24-byte nonce: nonce ‖ ct ‖ tag (§1.1). */
export function aeadSeal(key: Bytes, pt: Bytes, aad: Bytes): Bytes {
  const nonce = random(NONCE_LEN);
  return concat(nonce, xchacha20poly1305(key, nonce, aad).encrypt(pt));
}

/** X-Wing encapsulation with randomness from random() (deterministic under _setRandomForTests). */
export function kemEncap(pk: Bytes): { kct: Bytes; ss: Bytes } {
  const r = xwing.encapsulate(pk, random(xwing.lengths.msgRand ?? 64));
  return { kct: r.cipherText, ss: r.sharedSecret };
}

/**
 * X-Wing decapsulation. MAY throw on a malformed ciphertext (e.g. a low-order X25519 component, §1.1);
 * callers that scan or trial-open MUST use tryDecap (or catch) and treat a throw as "does not open".
 */
export const kemDecap = (kct: Bytes, sk: Bytes): Bytes => xwing.decapsulate(kct, sk);

export function tryDecap(kct: Bytes, sk: Bytes): Bytes | null {
  try {
    return xwing.decapsulate(kct, sk);
  } catch {
    return null;
  }
}

export const newRecoveryCode = (): Bytes => random(20);

/** t16(x) = first 16 bytes; t8(x) = first 8 bytes (§1.2). */
export const t16 = (b: Bytes): Bytes => b.slice(0, 16);
export const t8 = (b: Bytes): Bytes => b.slice(0, 8);

export const ZERO16 = new Uint8Array(16);
export const ZERO32 = new Uint8Array(32);

// ───────────────────────── time and eras (§3.1) ─────────────────────────

/** 2026-01-05T19:00:00Z (Monday 19:00 UTC = Tuesday 04:00 JST). */
export const T0_MS = 1767639600000;
/** One week. */
export const ERA_MS = 604_800_000;
/** Era 0xFFFF is reserved ("none"). */
export const ERA_NONE = 0xffff;
export const N_NONE = 0xffffffff;

/** era(ms) = ⌊(ms − T0) / ERA_MS⌋ as a u16. Throws before T0 or at/after the reserved era. */
export function era(ms: number): number {
  if (!Number.isFinite(ms)) throw new Error("era: bad time");
  const e = Math.floor((ms - T0_MS) / ERA_MS);
  if (e < 0 || e >= ERA_NONE) throw new Error("era: out of range");
  return e;
}

export const eraStart = (E: number): number => T0_MS + E * ERA_MS;
export const eraEnd = (E: number): number => T0_MS + (E + 1) * ERA_MS;

/** sec(ms) = ⌊(ms − T0) / 1000⌋, a u32. */
export function secOf(ms: number): number {
  const s = Math.floor((ms - T0_MS) / 1000);
  if (!Number.isSafeInteger(s) || s < 0 || s > 0xffffffff) throw new Error("sec: out of range");
  return s;
}

/** Rounds seconds-since-T0 down to a multiple of Δ. */
export function floorDelta(sec: number, delta: number): number {
  if (!Number.isInteger(delta) || delta < 1 || delta > 0xffff) throw new Error("bad delta");
  return Math.floor(sec / delta) * delta;
}

/** tpub(ms) = ⌊sec(ms) / Δ⌋ · Δ — the only time ever stored with a row. */
export const tpub = (ms: number, delta: number): number => floorDelta(secOf(ms), delta);

/** ms (Unix) of the start of second `sec` since T0. */
export const msOfSec = (sec: number): number => T0_MS + sec * 1000;

/** A lane position (E, n). NONE = (0xFFFF, 0xFFFFFFFF) sorts before every real position. */
export interface Pos {
  E: number;
  n: number;
}
export const NONE: Readonly<Pos> = Object.freeze({ E: ERA_NONE, n: N_NONE });
export const isNone = (p: Pos): boolean => p.E === ERA_NONE && p.n === N_NONE;

export function posCmp(a: Pos, b: Pos): number {
  const an = isNone(a);
  const bn = isNone(b);
  if (an || bn) return an === bn ? 0 : an ? -1 : 1;
  return a.E !== b.E ? a.E - b.E : a.n - b.n;
}

// ───────────────────────── size classes (§3.2) ─────────────────────────

export const CLASSES = [256, 1024, 4096, 16384] as const;
/** AEAD overhead of a row body: 24-byte nonce + 16-byte tag. */
export const ROW_OVERHEAD = NONCE_LEN + TAG_LEN;
/** Row body length per class: CLASSES[cls] + 40 = 296, 1064, 4136, 16424. */
export const BODY_LENS = CLASSES.map((c) => c + ROW_OVERHEAD) as readonly number[];
export const MAX_CLS = CLASSES.length - 1;

/** Class index whose body length is `len`, or -1. */
export const clsOfBodyLen = (len: number): number => BODY_LENS.indexOf(len);

/** Smallest class that pads a plaintext of `len` bytes (pad adds one 0x80 byte). Throws if none fits. */
export function clsFor(len: number, minCls = 0): number {
  for (let i = minCls; i < CLASSES.length; i++) if (CLASSES[i] >= len + 1) return i;
  throw new Error("payload too large");
}

/** Bytes of one sealed box (§1.4): KEM ciphertext + nonce + tag around the plaintext. */
export const SEAL_OVERHEAD = KEM_CT_LEN + NONCE_LEN + TAG_LEN; // 1160
/** Inbox invite body (§5.3): 1120 + 24 + 256 + 16. */
export const INBOX_BODY_LEN = KEM_CT_LEN + NONCE_LEN + 256 + TAG_LEN; // 1416
/** SGB2 bundle sizes (§3.2): 16 + 4136 + (B·1216 + 40) + B·1192 = 4192 + 2408·B for B ∈ {8, 32}. */
export const SGB2_HEADER_LEN = 16;
/** descCt: D ‖ dsig padded to [4096] (§5.4). */
export const SGB2_DESC_LEN = NONCE_LEN + 4096 + TAG_LEN; // 4136
/** pkCt: the B·1216-byte pks (§5.4), sealed under dk_e. */
export const sgb2PkCtLen = (B: number): number => B * KEM_PK_LEN + NONCE_LEN + TAG_LEN; // 9768, 38952
export const SGB2_ENTRY_LEN = SEAL_OVERHEAD + 32; // 1192
/** Byte offset of pkCt (after the header and descCt). */
export const SGB2_PKCT_AT = SGB2_HEADER_LEN + SGB2_DESC_LEN; // 4152
/** Byte offset of entry_0: 4192 + 1216·B (13920 or 43104). */
export const sgb2EntriesAt = (B: number): number => SGB2_PKCT_AT + sgb2PkCtLen(B);
export const sgb2Size = (B: number): number => sgb2EntriesAt(B) + B * SGB2_ENTRY_LEN;
export const SGB2_SIZES = [sgb2Size(8), sgb2Size(32)] as const; // 23456, 81248

// ───────────────────────── sealing (KEM-DEM, §1.4) ─────────────────────────

const sealKey = (ss: Bytes, kct: Bytes, label: string, ctx: Bytes): Bytes =>
  HKDF(ss, H(kct), enc("segv.sh/v2/seal", label, ctx));

export function seal(pk: Bytes, label: string, ctx: Bytes, pt: Bytes): Bytes {
  const { kct, ss } = kemEncap(pk);
  return concat(kct, aeadSeal(sealKey(ss, kct, label, ctx), pt, enc(label, ctx)));
}

/** Inverse of seal(). Throws on any failure, including a decapsulation throw (§1.1). */
export function open(sk: Bytes, label: string, ctx: Bytes, box: Bytes): Bytes {
  if (box.length < SEAL_OVERHEAD) throw new Error("seal: short");
  const kct = box.subarray(0, KEM_CT_LEN);
  const ss = kemDecap(kct, sk);
  return aeadOpen(sealKey(ss, kct, label, ctx), box.subarray(KEM_CT_LEN), enc(label, ctx));
}

/** open() that returns null instead of throwing ("does not open"). */
export function tryOpen(sk: Bytes, label: string, ctx: Bytes, box: Bytes): Bytes | null {
  try {
    return open(sk, label, ctx, box);
  } catch {
    return null;
  }
}

/** A seal of n random bytes to a fresh, discarded key: indistinguishable from a real seal (§1.4). */
export function dummySeal(label: string, ctx: Bytes, n: number): Bytes {
  return seal(kemKeygen(random(32)).pk, label, ctx, random(n));
}

// ───────────────────────── accounts (§2) ─────────────────────────

export interface Identity {
  sigSk: Bytes;
  sigPk: Bytes;
  kemSk: Bytes;
  kemPk: Bytes;
  /** self-lane AEAD key (§4.1) */
  kS: Bytes;
  /** self-lane routing key */
  rS: Bytes;
  /** self-lane notify (topic) key */
  nS: Bytes;
}

export function deriveIdentity(AK: Bytes): Identity {
  if (AK.length !== 32) throw new Error("AK must be 32 bytes");
  const sigSk = HKDF(AK, "", "segv.sh/v2/id/ed25519");
  const kem = kemKeygen(HKDF(AK, "", "segv.sh/v2/id/xwing"));
  return {
    sigSk,
    sigPk: sigPub(sigSk),
    kemSk: kem.sk,
    kemPk: kem.pk,
    kS: HKDF(AK, "", "segv.sh/v2/self/aead"),
    rS: HKDF(AK, "", "segv.sh/v2/self/route"),
    nS: HKDF(AK, "", "segv.sh/v2/self/notify"),
  };
}

export interface BundleJson {
  v: 2;
  uid: string;
  handle: string;
  sig: string;
  kem: string;
  ts: number;
}

/** Parsed bundle with decoded keys. */
export interface User {
  uid: string; // b64u(16 B)
  handle: string;
  sigPk: Bytes;
  kemPk: Bytes;
  /** exact signed text */
  bundle: string;
  /** b64u(64 B) */
  bundleSig: string;
  ts: number;
}

const isObj = (x: unknown): x is Record<string, unknown> =>
  typeof x === "object" && x !== null && !Array.isArray(x);
const isTs = (x: unknown): x is number => Number.isSafeInteger(x) && (x as number) >= 0;

function b64uLen(s: unknown, len: number): Bytes {
  if (typeof s !== "string") throw new Error("expected base64url");
  const b = fromB64u(s);
  if (b.length !== len) throw new Error(`expected ${len} bytes`);
  return b;
}

/** Exact key order and key set of a JSON object (signed JSON is never re-serialised, §1.2). */
function exactShape(raw: Record<string, unknown>, keys: readonly string[], what: string): void {
  const got = Object.keys(raw);
  if (got.length !== keys.length || got.some((k, i) => k !== keys[i])) throw new Error(`${what}: bad fields`);
}

export const BUNDLE_KEYS = ["v", "uid", "handle", "sig", "kem", "ts"] as const;
export const WRAP_KEYS = ["v", "uid", "kind", "id", "kem", "wrap", "ts"] as const;

export const bundleSigMsg = (bundle: string): Bytes => enc("segv.sh/v2/bundle", utf8(bundle));

export function makeBundle(uid: Bytes, handle: string, id: Identity, ts: number): { bundle: string; sig: string } {
  if (uid.length !== 16) throw new Error("uid must be 16 bytes");
  if (!HANDLE_RE.test(handle)) throw new Error("invalid handle");
  if (!isTs(ts)) throw new Error("bad ts");
  const b: BundleJson = { v: 2, uid: b64u(uid), handle, sig: b64u(id.sigPk), kem: b64u(id.kemPk), ts };
  const bundle = JSON.stringify(b);
  return { bundle, sig: b64u(sign(bundleSigMsg(bundle), id.sigSk)) };
}

/** Parses a bundle and checks every field's shape and the exact key order. Does NOT check the signature. */
export function parseBundle(bundle: string, sigB64: string): User {
  const raw = JSON.parse(bundle) as unknown;
  if (!isObj(raw) || raw.v !== 2) throw new Error("bundle: bad version");
  exactShape(raw, BUNDLE_KEYS, "bundle");
  const uid = b64uLen(raw.uid, 16);
  const sigPk = b64uLen(raw.sig, 32);
  const kemPk = b64uLen(raw.kem, KEM_PK_LEN);
  if (typeof raw.handle !== "string" || !HANDLE_RE.test(raw.handle)) throw new Error("bundle: bad handle");
  if (!isTs(raw.ts)) throw new Error("bundle: bad ts");
  b64uLen(sigB64, 64);
  return { uid: b64u(uid), handle: raw.handle, sigPk, kemPk, bundle, bundleSig: sigB64, ts: raw.ts };
}

/** Parses and verifies a bundle (shapes + signature). Throws on any problem. */
export function verifyBundle(bundle: string, sigB64: string): User {
  const u = parseBundle(bundle, sigB64);
  if (!verify(fromB64u(sigB64), bundleSigMsg(bundle), u.sigPk)) throw new Error("bundle: bad signature");
  return u;
}

/** validSigPk results by hex(pk); cleared when it reaches SIG_PK_CACHE_MAX entries (§1.1 allows a cache). */
const sigPkCache = new Map<string, boolean>();
const SIG_PK_CACHE_MAX = 4096;

/**
 * validSigPk (§1.1): `pk` is 32 bytes, decodes canonically (y < p; x = 0 only with sign bit 0), is not of small
 * order ([8]A ≠ O), and lies in the prime-order subgroup ([L]A = O): a mixed-order key (a real key plus a torsion
 * point) is refused. Memoised per key.
 */
export function validSigPk(pk: Bytes): boolean {
  if (pk.length !== 32) return false;
  const key = hex(pk);
  const known = sigPkCache.get(key);
  if (known !== undefined) return known;
  let ok: boolean;
  try {
    const A = ed25519.Point.fromBytes(pk); // strict decoding (zip215 = false)
    ok = !A.isSmallOrder() && A.isTorsionFree();
  } catch {
    ok = false;
  }
  if (sigPkCache.size >= SIG_PK_CACHE_MAX) sigPkCache.clear();
  sigPkCache.set(key, ok);
  return ok;
}

/** True when `pk` is not a usable Ed25519 key (§1.1, §5.1): !validSigPk(pk). */
export function isBadSigPk(pk: Bytes): boolean {
  return !validSigPk(pk);
}

/**
 * The kemPk half of checkUserKeys (§2.1): 1216 bytes and KEM.encap succeeds. Whether an X-Wing encapsulation
 * succeeds depends only on the key, so the randomness (noble's own CSPRNG, never random()) does not matter.
 */
export function validKemPk(kemPk: Bytes): boolean {
  try {
    return kemPk.length === KEM_PK_LEN && xwing.encapsulate(kemPk).cipherText.length === KEM_CT_LEN;
  } catch {
    return false;
  }
}

/** §2.1: validSigPk(sigPk), and KEM.encap(kemPk) succeeds. Throws otherwise. */
export function checkUserKeys(sigPk: Bytes, kemPk: Bytes): void {
  if (!validSigPk(sigPk)) throw new Error("bundle: unusable signing key");
  if (!validKemPk(kemPk)) throw new Error("bundle: unusable KEM key");
}

/** fp = H(enc("segv.sh/v2/fp", uid, sigPk, kemPk)), shown as 6 groups of 5 digits (§2.2). */
export function fingerprint(uid: Bytes, sigPk: Bytes, kemPk: Bytes): string {
  const fp = H(enc("segv.sh/v2/fp", uid, sigPk, kemPk));
  const groups: string[] = [];
  for (let k = 0; k < 6; k++) {
    let v = 0;
    for (let j = 0; j < 5; j++) v = v * 256 + fp[5 * k + j];
    groups.push(String(v % 100000).padStart(5, "0"));
  }
  return groups.join(" ");
}

/** TOFU pin of a bundle (§2.2): H(enc("segv.sh/v2/pin", bundleBytes, bundleSig)). */
export const pin = (bundle: string, bundleSig: Bytes): Bytes => H(enc("segv.sh/v2/pin", utf8(bundle), bundleSig));

// ── unlock secrets (§2.3) ──

export const PRF_INPUT = "segv.sh/v2/prf";

/** The unlock secret's key material; `auth` binds every wrap to the secret (§2.4). */
export interface UnlockKey {
  pk: Bytes;
  sk: Bytes;
  auth: Bytes;
}

export function credKem(prf: Bytes, credId: Bytes): UnlockKey {
  if (prf.length !== 32) throw new Error("PRF output must be 32 bytes");
  return {
    ...kemKeygen(HKDF(prf, credId, "segv.sh/v2/cred/xwing")),
    auth: HKDF(prf, credId, "segv.sh/v2/cred/auth"),
  };
}

export function recoveryKem(code: Bytes): UnlockKey & { id: Bytes } {
  if (code.length !== 20) throw new Error("recovery code must be 20 bytes");
  return {
    ...kemKeygen(HKDF(code, "", "segv.sh/v2/recovery/xwing")),
    auth: HKDF(code, "", "segv.sh/v2/recovery/auth"),
    id: HKDF(code, "", "segv.sh/v2/recovery/id", 16),
  };
}

// ── wrap records (§2.4) ──

export const AK_WRAP_LABEL = "segv.sh/v2/ak-wrap";
export type WrapKind = "passkey" | "recovery";

export interface WrapRecord {
  uid: string;
  kind: WrapKind;
  id: Bytes;
  kemPk: Bytes;
  wrap: Bytes;
  record: string;
  sig: string;
  ts: number;
}

export const wrapSigMsg = (record: string): Bytes => enc("segv.sh/v2/wrap", utf8(record));

export function makeWrap(
  uid: Bytes,
  kind: WrapKind,
  id: Bytes,
  key: { pk: Bytes; auth: Bytes },
  AK: Bytes,
  ident: Identity,
  ts: number,
): { record: string; sig: string } {
  if (uid.length !== 16) throw new Error("uid must be 16 bytes");
  if (id.length < 1 || id.length > MAX_ID_LEN || (kind === "recovery" && id.length !== 16)) throw new Error("bad wrap id");
  if (AK.length !== 32) throw new Error("AK must be 32 bytes");
  if (!isTs(ts)) throw new Error("bad ts");
  const wrap = seal(key.pk, AK_WRAP_LABEL, enc(uid, id, key.auth), AK);
  const record = JSON.stringify({ v: 2, uid: b64u(uid), kind, id: b64u(id), kem: b64u(key.pk), wrap: b64u(wrap), ts });
  return { record, sig: b64u(sign(wrapSigMsg(record), ident.sigSk)) };
}

/** Parses a wrap record and checks every field's shape and the key order. Does NOT check the signature. */
export function parseWrap(record: string, sigB64: string): WrapRecord {
  const raw = JSON.parse(record) as unknown;
  if (!isObj(raw) || raw.v !== 2) throw new Error("wrap: bad version");
  exactShape(raw, WRAP_KEYS, "wrap");
  if (raw.kind !== "passkey" && raw.kind !== "recovery") throw new Error("wrap: bad kind");
  b64uLen(raw.uid, 16);
  if (typeof raw.id !== "string") throw new Error("wrap: bad id");
  const id = fromB64u(raw.id);
  if (id.length < 1 || id.length > MAX_ID_LEN) throw new Error("wrap: bad id length");
  if (raw.kind === "recovery" && id.length !== 16) throw new Error("wrap: bad recovery id length");
  const kemPk = b64uLen(raw.kem, KEM_PK_LEN);
  const wrap = b64uLen(raw.wrap, WRAP_LEN);
  if (!isTs(raw.ts)) throw new Error("wrap: bad ts");
  b64uLen(sigB64, 64);
  return { uid: raw.uid as string, kind: raw.kind, id, kemPk, wrap, record, sig: sigB64, ts: raw.ts };
}

export function verifyWrap(record: string, sigB64: string, ownerSigPk: Bytes): WrapRecord {
  const w = parseWrap(record, sigB64);
  if (!verify(fromB64u(sigB64), wrapSigMsg(record), ownerSigPk)) throw new Error("wrap: bad signature");
  return w;
}

/** Opens a wrap with the unlock key. Throws unless it was sealed for this secret (decap throws included). */
export function openWrap(w: { uid: string; id: Bytes; wrap: Bytes }, key: { sk: Bytes; auth: Bytes }): Bytes {
  const AK = open(key.sk, AK_WRAP_LABEL, enc(fromB64u(w.uid), w.id, key.auth), w.wrap);
  if (AK.length !== 32) throw new Error("unwrap: bad AK length");
  return AK;
}

/** openWrap + the §2.4 step 3 check: the AK re-derives the record signer's key. */
export function unwrapAK(w: WrapRecord, key: { sk: Bytes; auth: Bytes }, ownerSigPk: Bytes): Bytes {
  const AK = openWrap(w, key);
  if (!equalBytes(deriveIdentity(AK).sigPk, ownerSigPk)) throw new Error("unwrap: key check failed");
  if (!verify(fromB64u(w.sig), wrapSigMsg(w.record), ownerSigPk)) throw new Error("unwrap: bad record signature");
  return AK;
}

// ── directory prefixes (§2.5) ──

const u32Of = (b: Bytes): number => ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];

/** hpre(handle) = u32(H(enc("segv.sh/v2/dir/handle", handle))[0..4]). */
export const hpre = (handle: string): number => u32Of(H(enc("segv.sh/v2/dir/handle", handle)));
/** upre(uid) = u32(H(enc("segv.sh/v2/dir/uid", uid))[0..4]). */
export const upre = (uid: Bytes): number => u32Of(H(enc("segv.sh/v2/dir/uid", uid)));

// ───────────────────────── self lane and epoch labels (§4.1, §4.2) ─────────────────────────

export const Lself = (rS: Bytes, E: number, n: number): Bytes =>
  t16(HMAC(rS, enc("segv.sh/v2/lab/self", u16(E), u32(n))));
export const Lsnap = (rS: Bytes, E: number, j: number): Bytes =>
  t16(HMAC(rS, enc("segv.sh/v2/lab/snap", u16(E), u32(j))));
export const topicSelf = (nS: Bytes): Bytes => t16(HMAC(nS, utf8("segv.sh/v2/topic/self")));

export interface EpochKeys {
  rk: Bytes;
  mk: Bytes;
  kc: Bytes;
  nk: Bytes;
  dk: Bytes;
}

export const E_MAX = 0xffffffff;

export function epochKeys(EK: Bytes, conv: Bytes, e: number): EpochKeys {
  if (EK.length !== 32 || conv.length !== 16) throw new Error("bad epoch key material");
  const k = (what: string): Bytes => HKDF(EK, conv, enc(`segv.sh/v2/ep/${what}`, u32(e)));
  return { rk: k("route"), mk: k("msg"), kc: k("commit"), nk: k("notify"), dk: k("desc") };
}

/** ekc_e = H(enc("segv.sh/v2/ekc", conv, u32 e, EK_e)): commits a claim to the new epoch key (§6.2). */
export const ekc = (conv: Bytes, e: number, EK: Bytes): Bytes => H(enc("segv.sh/v2/ekc", conv, u32(e), EK));

/** Lmsg_e(ℓ, E, n): member lane ℓ (index in D_e), slot n of era E. */
export const Lmsg = (rk: Bytes, lane: number, E: number, n: number): Bytes =>
  t16(HMAC(rk, enc("segv.sh/v2/lab/msg", u16(lane), u16(E), u32(n))));
/** Lctl_e(E, k): control lane (claims). */
export const Lctl = (rk: Bytes, E: number, k: number): Bytes => t16(HMAC(rk, enc("segv.sh/v2/lab/ctl", u16(E), u32(k))));
/** T_e: realtime topic of epoch e. */
export const topicConv = (nk: Bytes): Bytes => t16(HMAC(nk, utf8("segv.sh/v2/topic/conv")));

// ───────────────────────── links (§4.3) ─────────────────────────

export interface LinkKeys {
  kL: Bytes;
  mL: Bytes;
  nL: Bytes;
}

export function linkKeys(s: Bytes): LinkKeys {
  if (s.length !== 16) throw new Error("link secret must be 16 bytes");
  return {
    kL: HKDF(s, "", "segv.sh/v2/link/route"),
    mL: HKDF(s, "", "segv.sh/v2/link/aead"),
    nL: HKDF(s, "", "segv.sh/v2/link/notify"),
  };
}

export const Lhello = (kL: Bytes, E: number, j: number): Bytes =>
  t16(HMAC(kL, enc("segv.sh/v2/lab/hello", u16(E), u32(j))));
export const topicLink = (nL: Bytes): Bytes => t16(HMAC(nL, utf8("segv.sh/v2/topic/link")));

/** "https://<host>/i#" + b64u(u8 2 ‖ s[16] ‖ uid_inviter[16]); the fragment never reaches the server. */
export function encodeLink(host: string, s: Bytes, uid: Bytes): string {
  if (s.length !== 16 || uid.length !== 16) throw new Error("bad link material");
  return `https://${host}/i#${b64u(concat(u8(2), s, uid))}`;
}

export function parseLink(url: string): { host: string; s: Bytes; uid: Bytes } {
  const m = /^https:\/\/([^/#?]+)\/i#([A-Za-z0-9_-]{44})$/.exec(url.trim());
  if (!m) throw new Error("link: bad format");
  const b = fromB64u(m[2]);
  if (b.length !== 33 || b[0] !== 2) throw new Error("link: bad version");
  return { host: m[1], s: b.slice(1, 17), uid: b.slice(17, 33) };
}

// ───────────────────────── server routing (§4.4) ─────────────────────────

/** kroute_E = HMAC(ROUTE_KEY, enc("segv.sh/v2/route", u16 E)). Server only. */
export function kroute(routeKey: Bytes, E: number): Bytes {
  if (routeKey.length !== 32) throw new Error("ROUTE_KEY must be 32 bytes");
  return HMAC(routeKey, enc("segv.sh/v2/route", u16(E)));
}
/** kcommit_E = H(enc("segv.sh/v2/kroute", kroute_E)), published in params / era info. */
export const kcommit = (krouteE: Bytes): Bytes => H(enc("segv.sh/v2/kroute", krouteE));

/** v(E, label) = u64(HMAC(kroute_E, label)[0..8]) >> 1, as an 8-byte big-endian value. */
export function routeV(krouteE: Bytes, label: Bytes): Bytes {
  if (label.length !== 16) throw new Error("label must be 16 bytes");
  const h = HMAC(krouteE, label);
  const out = new Uint8Array(8);
  let carry = 0;
  for (let i = 0; i < 8; i++) {
    out[i] = (carry << 7) | (h[i] >>> 1);
    carry = h[i] & 1;
  }
  return out;
}

/** shard(E, label) = v >> (63 − s_E). Stage 1: s_E = 0 ⇒ 0. */
export function shardOf(v: Bytes, sE: number): number {
  if (sE === 0) return 0;
  if (!Number.isInteger(sE) || sE < 0 || sE > 16) throw new Error("bad shard bits");
  const x = new DataView(v.buffer, v.byteOffset, 8).getBigUint64(0);
  return Number(x >> BigInt(63 - sE));
}

// ───────────────────────── commitments (§9, §9.5, §9.6, §10.3, §3.3) ─────────────────────────

/** leaf(data) = H(0x00 ‖ data). */
export const leaf = (data: Bytes): Bytes => H(concat(Uint8Array.of(0), data));
const node = (l: Bytes, r: Bytes): Bytes => H(concat(Uint8Array.of(1), l, r));

/** RFC 6962 Merkle tree hash over leaf hashes (already leaf()-hashed). Batches are never empty. */
export function mth(leafHashes: readonly Bytes[]): Bytes {
  const n = leafHashes.length;
  if (n === 0) throw new Error("mth: empty");
  if (n === 1) return leafHashes[0];
  let k = 1;
  while (k * 2 < n) k *= 2;
  return node(mth(leafHashes.slice(0, k)), mth(leafHashes.slice(k)));
}

export const leafShard = (E: number, label: Bytes, t: number, cls: number, body: Bytes): Bytes =>
  leaf(enc("segv.sh/v2/leaf", u16(E), label, u32(t), u8(cls), H(body)));
export const leafInbox = (E: number, bucket: number, rel: number, eid: Bytes, body: Bytes): Bytes =>
  leaf(enc("segv.sh/v2/leaf/inbox", u16(E), u32(bucket), u32(rel), eid, H(body)));
export const leafBlob = (id: Bytes, size: number, t: number): Bytes =>
  leaf(enc("segv.sh/v2/leaf/blob", H(id), u32(size), u32(t)));

/** Ordering of leaves inside a batch: shard rows by label, inbox rows by eid, blobs by H(id). */
export function byteCmp(a: Bytes, b: Bytes): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

/** head' = H(enc("segv.sh/v2/head", cid, head, u32 t, u32 n, root)); the first batch chains from ZERO32. */
export const nextHead = (cid: string, head: Bytes, t: number, n: number, root: Bytes): Bytes =>
  H(enc("segv.sh/v2/head", cid, head, u32(t), u32(n), root));

export const shardCid = (E: number, i: number): string => `shard/${E}/${i}`;
export const inboxCid = (E: number, g: number): string => `inbox/${E}/${g}`;
export const BLOBREG_CID = "blobreg";
export const DIRLOG_CID = "dirlog";

/** hd = H(enc("segv.sh/v2/ckpt/heads", [cid_1, head_1, …])) over heads sorted by cid (byte order). */
export function ckptHd(heads: readonly { cid: string; head: Bytes }[]): Bytes {
  const sorted = [...heads].sort((a, b) => byteCmp(utf8(a.cid), utf8(b.cid)));
  return H(enc("segv.sh/v2/ckpt/heads", ...sorted.flatMap((h) => [utf8(h.cid), h.head])));
}

/** C_q = H(enc("segv.sh/v2/ckpt", C_{q−1}, u32 q, u32 sec, hd)); C_0 = ZERO32, q starts at 1. */
export const ckptC = (prevC: Bytes, q: number, sec: number, hd: Bytes): Bytes =>
  H(enc("segv.sh/v2/ckpt", prevC, u32(q), u32(sec), hd));
export const ckptSigMsg = (q: number, C: Bytes): Bytes => enc("segv.sh/v2/ckpt-sig", u32(q), C);

/** receipt = Sign(SRV_SK, enc("segv.sh/v2/receipt", u16 E, label, H(body), u32 t)) (§10.3). */
export const receiptMsg = (E: number, label: Bytes, body: Bytes, t: number): Bytes =>
  enc("segv.sh/v2/receipt", u16(E), label, H(body), u32(t));

/** Directory log (§9.6). Signatures are the raw 64-byte values. */
export const dirlogRefUser = (bundle: string, bundleSig: Bytes): Bytes =>
  H(enc("segv.sh/v2/dir/user", utf8(bundle), bundleSig));
export const dirlogRefWrap = (record: string, recordSig: Bytes): Bytes =>
  H(enc("segv.sh/v2/dir/wrap", utf8(record), recordSig));
export const DIRLOG_USER = 1;
export const DIRLOG_WRAP = 2;
/** h_seq = H(enc("segv.sh/v2/dirlog", h_{seq−1}, u64 seq, u8 kind, ref)), h_0 = ZERO32. */
export const dirlogH = (prev: Bytes, seq: number, kind: number, ref: Bytes): Bytes =>
  H(enc("segv.sh/v2/dirlog", prev, u64(seq), u8(kind), ref));

/** prevh = t16(H(enc("segv.sh/v2/prev", label_prev, body_prev))) (§3.3, §7.1). */
export const prevh = (label: Bytes, body: Bytes): Bytes => t16(H(enc("segv.sh/v2/prev", label, body)));

// ───────────────────────── proof of work (§10.2) ─────────────────────────

export type PowScope = "register" | "wrap" | "put" | "inbox" | "blob";
export const POW_SCOPES: readonly PowScope[] = ["register", "wrap", "put", "inbox", "blob"];
export const POW_WINDOW_MS = 600_000;
export const POW_MAX_BASE = 26;

const POW_UNIT: Readonly<Record<PowScope, number>> = { register: 0, wrap: 0, put: 4096, inbox: 4096, blob: 1 << 20 };

/** base + ⌈log2(bytes / unit)⌉ above the unit, else base. */
export function powDifficulty(scope: PowScope, base: number, bytes: number): number {
  if (!Number.isSafeInteger(bytes) || bytes < 0) throw new Error("powDifficulty: bad size");
  const unit = POW_UNIT[scope];
  if (unit === undefined) throw new Error("powDifficulty: bad scope");
  if (!unit || bytes <= unit) return base;
  let k = 0;
  while (unit * 2 ** k < bytes) k++;
  return base + k;
}

/** pre = H(enc("segv.sh/v2/pow", scope, u32 window, digest)). */
export const powPre = (scope: PowScope, window: number, digest: Bytes): Bytes =>
  H(enc("segv.sh/v2/pow", scope, u32(window), digest));

// ───────────────────────── directory prefixes (§9.6, §10.6) ─────────────────────────

/** lo = x · 2^(32−p), hi = lo + 2^(32−p) − 1, with arithmetic only (1 << 32 is 1 in JavaScript). */
export function prefixRange(p: number, x: number): { lo: number; hi: number } {
  if (!Number.isInteger(p) || p < 0 || p > 32) throw new Error("bad prefix bits");
  const span = 2 ** (32 - p);
  if (!Number.isInteger(x) || x < 0 || x >= 2 ** p) throw new Error("bad prefix value");
  const lo = x * span;
  return { lo, hi: lo + span - 1 };
}

/** Top p bits of a u32 prefix value. */
export const topBits = (pre: number, p: number): number => Math.floor(pre / 2 ** (32 - p));

/** Largest k ≥ 0 with b·2^k ≤ a, or −1 when a < b. Integer-exact. */
function floorLog2Div(a: number, b: number): number {
  if (a < b) return -1;
  let k = 0;
  while (b * 2 ** (k + 1) <= a) k++;
  return k;
}

/** Server: P = max(0, ⌊log2(users / 32)⌋). */
export const serverP = (users: number): number => Math.max(0, floorLog2Div(users, 32));

/** Client: p = max(0, min(P − 1, ⌊log2(dirSeq / 64)⌋, 16)). */
export const clientP = (P: number, dirSeq: number): number => Math.max(0, Math.min(P - 1, floorLog2Div(dirSeq, 64), 16));

// ───────────────────────── blobs (§8.1) ─────────────────────────

export const BLOB_AAD = "segv.sh/v2/blob";
/** Smallest possible encrypted blob: nonce + tag + one padded byte. */
export const BLOB_MIN = NONCE_LEN + TAG_LEN + 1;

export function encryptBlob(data: Bytes, aad = BLOB_AAD): { blob: Bytes; id: string; key: Bytes } {
  const key = random(32);
  const blob = aeadSeal(key, padme(data), utf8(aad));
  return { blob, id: b64u(H(blob)), key };
}

export function decryptBlob(blob: Bytes, id: string, key: Bytes, aad = BLOB_AAD): Bytes {
  if (b64u(H(blob)) !== id) throw new Error("blob: hash mismatch");
  return unpad(aeadOpen(key, blob, utf8(aad)));
}

// ═════════════════════════ conversation codecs (§3.3, §5, §6.2, §7) ═════════════════════════
// (added by the conversation-codec milestone; §5–§7 may still change)

// Every codec below is self-contained (encoder, strict parser, exported types), so a later change to one layout
// of §5–§7 touches one block. Encoders re-parse their output: nothing is emitted that a receiver would reject.

/** Thrown by the conversation-codec parsers and encoders on malformed input (§1.2). */
export class CodecError extends Error {}

// A declaration (not an arrow) so that control-flow analysis treats calls as never returning.
function bad(what: string): never {
  throw new CodecError(what);
}

// The default TextDecoder strips a leading U+FEFF, which would make decode ∘ encode lossy for message text.
const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function decodeUtf8(b: Bytes, what: string): string {
  try {
    return strictUtf8.decode(b);
  } catch {
    return bad(`${what}: invalid UTF-8`);
  }
}

/** utf8() of a string that must survive the round trip (rejects lone surrogates). */
function encodeUtf8(s: string, what: string): Bytes {
  const b = utf8(s);
  if (decodeUtf8(b, what) !== s) bad(`${what}: not well-formed UTF-16`);
  return b;
}

const fixed = (b: Bytes, n: number, what: string): Bytes =>
  b instanceof Uint8Array && b.length === n ? b : bad(`${what}: expected ${n} bytes`);

/** Strict big-endian reader: short input throws, `end()` rejects trailing bytes (§1.2). */
class Rd {
  private o = 0;
  private readonly dv: DataView;
  constructor(
    private readonly b: Bytes,
    private readonly what: string,
  ) {
    this.dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  }
  private take(n: number): number {
    if (this.o + n > this.b.length) bad(`${this.what}: truncated`);
    const o = this.o;
    this.o += n;
    return o;
  }
  u8(): number {
    return this.b[this.take(1)];
  }
  u16(): number {
    return this.dv.getUint16(this.take(2));
  }
  u32(): number {
    return this.dv.getUint32(this.take(4));
  }
  /** u64 limited to 2^53 − 1 (times in ms). */
  u64(): number {
    const v = this.dv.getBigUint64(this.take(8));
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) bad(`${this.what}: u64 above 2^53 − 1`);
    return Number(v);
  }
  bytes(n: number): Bytes {
    const o = this.take(n);
    return this.b.slice(o, o + n);
  }
  end(): void {
    if (this.o !== this.b.length) bad(`${this.what}: trailing bytes`);
  }
}

/** A position `u16 E | u32 n`; era 0xFFFF is reserved, so it is valid only as NONE (§3.1). */
function rdPos(r: Rd, what: string): Pos {
  const E = r.u16();
  const n = r.u32();
  if (E === ERA_NONE && n !== N_NONE) bad(`${what}: era 0xFFFF outside NONE`);
  return { E, n };
}

function wrPos(p: Pos, what: string): Bytes {
  if (p.E === ERA_NONE && p.n !== N_NONE) bad(`${what}: era 0xFFFF outside NONE`);
  return concat(u16(p.E), u32(p.n));
}

/** Pads to the smallest fitting class and reports its index in CLASSES. */
function padClass(x: Bytes, classes: readonly number[]): { cls: number; pt: Bytes } {
  const pt = pad(x, classes);
  return { cls: (CLASSES as readonly number[]).indexOf(pt.length), pt };
}

/** A sealed row ready for `put`: its class and fixed-length body (§3.2). */
export interface SealedRow {
  cls: number;
  body: Bytes;
}

export const SIG_LEN = 64;

/** Index of `uid` in a member list, or −1. */
export const memberIndex = (d: { members: readonly { uid: Bytes }[] }, uid: Bytes): number =>
  d.members.findIndex((x) => equalBytes(x.uid, uid));

// ───────────────────────── descriptor D (§5.1) ─────────────────────────

export const D_VER = 2;
/** ver | conv | e | prev | by | ts | m: the offset of the member list. */
export const D_FIXED_LEN = 78;
/** uid[16] | sigPk[32] | kh[32]. */
export const D_MEMBER_LEN = 80;
/** nlen ≤ 256 (§5.1). */
export const MAX_NAME_BYTES = 256;
/** m = 1, no name. */
export const D_MIN_LEN = D_FIXED_LEN + D_MEMBER_LEN + 2; // 160
/** 78 + 80·32 + 2 + 256. */
export const D_MAX_LEN = D_FIXED_LEN + D_MEMBER_LEN * MAX_MEMBERS + 2 + MAX_NAME_BYTES; // 2896
/** D ‖ dsig, the plaintext of descCt and of DESC / REQUEST records. */
export const DESC_MIN_LEN = D_MIN_LEN + SIG_LEN; // 224
export const DESC_MAX_LEN = D_MAX_LEN + SIG_LEN; // 2960

export interface Member {
  uid: Bytes;
  sigPk: Bytes;
  /** kh = kemHash(kemPk) of the member's X-Wing key (§5.1); parseD puts no rule on it. */
  kh: Bytes;
}

/** kh = H(enc("segv.sh/v2/kh", kemPk)): a member's X-Wing key by hash (§5.1). */
export const kemHash = (kemPk: Bytes): Bytes => H(enc("segv.sh/v2/kh", kemPk));

export interface DescriptorFields {
  conv: Bytes;
  e: number;
  /** H(D_{e−1}), or ZERO32 for e = 0. */
  prev: Bytes;
  by: Bytes;
  ts: number;
  /** members[i] is member index i and lane i. */
  members: readonly Member[];
  /** null when nlen = 0. */
  name: string | null;
}

/** A parsed descriptor with its exact bytes and H(D). */
export interface Descriptor extends DescriptorFields {
  members: Member[];
  bytes: Bytes;
  hash: Bytes;
}

/**
 * Encodes D (§5.1). The name is checked only by the parse rules (≤ 256 bytes, 1–64 code points of well-formed
 * text), never by validName: the engine applies validName to a new name before building (§6.1, §6.3), and a name
 * carried over is copied unchanged.
 */
export function encodeD(d: DescriptorFields): Bytes {
  const m = d.members.length;
  if (m < 1 || m > MAX_MEMBERS) bad("D: bad member count");
  // "" would encode as nlen = 0 and come back as null: no name is null
  if (d.name === "") bad("D: an empty name is written as null");
  const name = d.name === null ? new Uint8Array(0) : encodeUtf8(d.name, "D name");
  const out = concat(
    u8(D_VER),
    fixed(d.conv, 16, "D conv"),
    u32(d.e),
    fixed(d.prev, 32, "D prev"),
    fixed(d.by, 16, "D by"),
    u64(d.ts),
    u8(m),
    ...d.members.flatMap((x) => [fixed(x.uid, 16, "D uid"), fixed(x.sigPk, 32, "D sigPk"), fixed(x.kh, 32, "D kh")]),
    u16(name.length),
    name,
  );
  parseD(out);
  return out;
}

/**
 * Parses D and enforces every §5.1 rule. The name rules are only `nlen ≤ 256` and, for nlen > 0, valid UTF-8
 * (§1.2: a leading U+FEFF is kept and counts) of 1–64 code points: nothing here depends on the Unicode tables of
 * the JavaScript engine (no \p{…}, trim or normalize), since a D′ that fails to parse freezes the conversation.
 */
export function parseD(b: Bytes): Descriptor {
  if (b.length > D_MAX_LEN) bad("D: too long");
  const r = new Rd(b, "D");
  if (r.u8() !== D_VER) bad("D: bad version");
  const conv = r.bytes(16);
  const e = r.u32();
  const prev = r.bytes(32);
  const by = r.bytes(16);
  const ts = r.u64();
  const m = r.u8();
  if (m < 1 || m > MAX_MEMBERS) bad("D: bad member count");
  const members: Member[] = [];
  for (let i = 0; i < m; i++) members.push({ uid: r.bytes(16), sigPk: r.bytes(32), kh: r.bytes(32) });
  const nlen = r.u16();
  if (nlen > MAX_NAME_BYTES) bad("D: name over 256 bytes");
  const nameBytes = r.bytes(nlen);
  r.end();
  if (e >= E_MAX) bad("D: e must be below 2^32 − 1");
  if ((e === 0) !== equalBytes(prev, ZERO32)) bad("D: e = 0 ⇔ prev = ZERO32");
  if (new Set(members.map((x) => b64u(x.uid))).size !== m) bad("D: duplicate uid");
  if (memberIndex({ members }, by) < 0) bad("D: by is not a member");
  let name: string | null = null;
  if (nlen > 0) {
    name = decodeUtf8(nameBytes, "D name");
    const cps = [...name].length;
    if (cps < 1 || cps > MAX_NAME) bad("D: the name must be 1–64 code points");
  }
  if (members.some((x) => !validSigPk(x.sigPk))) bad("D: unusable sigPk");
  return { conv, e, prev, by, ts, members, name, bytes: b.slice(), hash: H(b) };
}

export const hashD = (D: Bytes): Bytes => H(D);
export const dSigMsg = (D: Bytes, kc: Bytes): Bytes => enc("segv.sh/v2/epoch", D, kc);
/** dsig = SIG.sign(enc("segv.sh/v2/epoch", D, kc_e), sk_by). */
export const signD = (D: Bytes, kc: Bytes, sigSk: Bytes): Bytes => sign(dSigMsg(D, kc), sigSk);

/** Verifies dsig under D's own sigPk for `by` (never a directory key, §5.1). False for an unparsable D. */
export function verifyD(D: Bytes | Descriptor, kc: Bytes, dsig: Bytes): boolean {
  let d: Descriptor;
  if (D instanceof Uint8Array) {
    try {
      d = parseD(D);
    } catch {
      return false;
    }
  } else d = D;
  const i = memberIndex(d, d.by);
  return i >= 0 && verify(dsig, dSigMsg(d.bytes, kc), d.members[i].sigPk);
}

/** desc = D ‖ dsig: D is self-delimiting and dsig is the last 64 bytes (§6.6 step 4). */
export function splitDesc(desc: Bytes): { D: Bytes; dsig: Bytes } {
  if (desc.length < DESC_MIN_LEN || desc.length > DESC_MAX_LEN) bad("desc: bad length");
  return { D: desc.slice(0, desc.length - SIG_LEN), dsig: desc.slice(desc.length - SIG_LEN) };
}

/** kemPk of D.members[j]: slot j of pks (§5.4). */
export const pksAt = (pks: Bytes, j: number): Bytes => pks.subarray(j * KEM_PK_LEN, (j + 1) * KEM_PK_LEN);

/** Why `pks` does not fit D (checkPks): `|D| > B`, or any other pks rule. */
export type PksFailure = "size" | "pks";

/**
 * The pks rules of §6.6 step 4 and §6.7 step 2: `|D| ≤ B` ("size"); pks is B·1216 bytes and zero after slot
 * |D| − 1, and every pks[j] hashes to D.members[j].kh and passes the kemPk half of checkUserKeys ("pks").
 * `skipKem(j)` skips that encapsulation for a slot that another check encapsulates to anyway (a kept member's
 * sealDet recomputation, §6.6 step 4); whether it succeeds does not depend on the randomness (§2.1).
 */
export function checkPks(
  D: { members: readonly { kh: Bytes }[] },
  pks: Bytes,
  B: number,
  skipKem: (j: number) => boolean = () => false,
): PksFailure | null {
  const m = D.members.length;
  if (m > B) return "size";
  if (pks.length !== B * KEM_PK_LEN) return "pks";
  if (pks.subarray(m * KEM_PK_LEN).some((x) => x !== 0)) return "pks";
  for (let j = 0; j < m; j++) if (!equalBytes(kemHash(pksAt(pks, j)), D.members[j].kh)) return "pks";
  for (let j = 0; j < m; j++) if (!skipKem(j) && !validKemPk(pksAt(pks, j))) return "pks";
  return null;
}

/** The D′ checks of §6.6 step 4, in spec order. */
export type DPrimeCheck =
  /** D′ ‖ dsig′ is malformed (descCt does not open, or D′ does not parse) */
  | "desc"
  | "hD"
  | "conv"
  | "e"
  | "prev"
  | "by"
  | "dsig"
  /** D′ ∩ D_e ≠ the members whose rm bit is 0 */
  | "members"
  /** a continuing member's sigPk changed */
  | "sigPk"
  /** a continuing member's kh changed */
  | "kh"
  /** |D′| > B */
  | "size"
  /** pkCt does not open, or pks′ breaks a checkPks rule (length, tail, a kh, a kemPk) */
  | "pks"
  /** a kept entry is not sealDet(pks′[j], …) under EK′ byte for byte */
  | "entry";

export type DPrimeResult = { ok: true; D: Descriptor } | { ok: false; failed: DPrimeCheck };

/**
 * The D′ checks of §6.6 step 4 after the decryption: D_{e+1} (bytes `next.D` and `next.dsig` from openDesc,
 * `next.pks` = pks′ from openPks, `next.kc` = kc_{e+1}, `next.EK` = EK′) against D_e, the claim (`from` = the
 * committer's index in D_e, `hD`, `rm`) and the bundle of e+1. Returns the first failing check. The caller maps a
 * throw of openDesc / openPks to "desc" / "pks" (processClaim).
 */
export function dPrimeChecks(
  next: { D: Bytes; dsig: Bytes; kc: Bytes; pks: Bytes; EK: Bytes },
  De: Descriptor,
  claim: { from: number; hD: Bytes; rm: number },
  bundle: BundleBlob,
): DPrimeResult {
  const no = (failed: DPrimeCheck): DPrimeResult => ({ ok: false, failed });
  fixed(next.EK, 32, "D′ checks EK′");
  if (next.dsig.length !== SIG_LEN) return no("desc");
  if (!equalBytes(H(next.D), claim.hD)) return no("hD");
  let D: Descriptor;
  try {
    D = parseD(next.D);
  } catch {
    return no("desc");
  }
  if (!equalBytes(D.conv, De.conv)) return no("conv");
  if (D.e !== De.e + 1) return no("e");
  if (!equalBytes(D.prev, De.hash)) return no("prev");
  const committer = De.members[claim.from];
  if (!committer || !equalBytes(D.by, committer.uid)) return no("by");
  if (!verify(next.dsig, dSigMsg(next.D, next.kc), committer.sigPk)) return no("dsig");
  const kept = De.members.map((_, i) => !rmHas(claim.rm, i));
  const at = De.members.map((x) => memberIndex(D, x.uid));
  if (kept.some((k, i) => k !== (at[i] >= 0))) return no("members");
  if (kept.some((k, i) => k && !equalBytes(D.members[at[i]].sigPk, De.members[i].sigPk))) return no("sigPk");
  if (kept.some((k, i) => k && !equalBytes(D.members[at[i]].kh, De.members[i].kh))) return no("kh");
  // a kept member's encapsulation is performed by its sealDet recomputation below
  const continuing = new Set(at.filter((_, i) => kept[i]));
  const pf = checkPks(D, next.pks, bundle.B, (j) => continuing.has(j));
  if (pf) return no(pf);
  for (let i = 0; i < De.members.length; i++) {
    if (!kept[i]) continue;
    let want: Bytes;
    try {
      want = sealDet(pksAt(next.pks, at[i]), De.conv, D.e, i, next.EK);
    } catch {
      return no("pks"); // the kemPk half of checkUserKeys fails
    }
    const entry = bundle.entries[i];
    if (!entry || !equalBytes(entry, want)) return no("entry");
  }
  return { ok: true, D };
}

// ───────────────────────── join payload J (§5.2) ─────────────────────────

export const J_VER = 2;
export const J_TYPE = 1;
export const J_LEN = 90;

export interface Join {
  conv: Bytes;
  e: number;
  EK: Bytes;
  bundleId: Bytes;
  bundleSize: number;
}

export function encodeJ(j: Join): Bytes {
  return concat(
    u8(J_VER),
    u8(J_TYPE),
    fixed(j.conv, 16, "J conv"),
    u32(j.e),
    fixed(j.EK, 32, "J EK"),
    fixed(j.bundleId, 32, "J bundleId"),
    u32(j.bundleSize),
  );
}

export function parseJ(b: Bytes): Join {
  const r = new Rd(b, "J");
  if (r.u8() !== J_VER) bad("J: bad version");
  if (r.u8() !== J_TYPE) bad("J: bad type");
  const j: Join = { conv: r.bytes(16), e: r.u32(), EK: r.bytes(32), bundleId: r.bytes(32), bundleSize: r.u32() };
  r.end();
  return j;
}

/** A join that decrypted: well-formed, or malformed (the spec's noise warning, §5.3 step 3). */
export type JoinOpen = { kind: "join"; join: Join } | { kind: "malformed" };

function joinOf(Jbytes: Bytes): JoinOpen {
  try {
    return { kind: "join", join: parseJ(Jbytes) };
  } catch {
    return { kind: "malformed" };
  }
}

const joinBytes = (J: Join | Bytes): Bytes => (J instanceof Uint8Array ? J : encodeJ(J));

// ───────────────────────── inbox invite (§5.3) ─────────────────────────

export const INVITE_CLASSES = [256] as const;

/** enc("segv.sh/v2/inv", u16 E, u32 bucket, eid): both the HKDF info and the AAD. */
export const inviteCtx = (E: number, bucket: number, eid: Bytes): Bytes =>
  enc("segv.sh/v2/inv", u16(E), u32(bucket), fixed(eid, 16, "invite eid"));

/** Builds a 1416-byte invite of J (a Join, or raw bytes ≤ 255 B for tests) for `kemPk`. */
export function makeInvite(kemPk: Bytes, E: number, bucket: number, J: Join | Bytes): { eid: Bytes; body: Bytes } {
  const eid = random(16);
  const { kct, ss } = kemEncap(kemPk);
  const ctx = inviteCtx(E, bucket, eid);
  return { eid, body: concat(kct, aeadSeal(HKDF(ss, H(kct), ctx), pad(joinBytes(J), INVITE_CLASSES), ctx)) };
}

/**
 * Trial decryption (§5.3): null when the invite is not for this key (a decapsulation throw or an AEAD failure,
 * silently), else the join or "malformed" (decrypted, but J does not parse: a noise warning).
 */
export function tryOpenInvite(kemSk: Bytes, E: number, bucket: number, eid: Bytes, body: Bytes): JoinOpen | null {
  if (body.length !== INBOX_BODY_LEN || eid.length !== 16) return null;
  const kct = body.subarray(0, KEM_CT_LEN);
  const ss = tryDecap(kct, kemSk);
  if (!ss) return null;
  const ctx = inviteCtx(E, bucket, eid);
  let padded: Bytes;
  try {
    padded = aeadOpen(HKDF(ss, H(kct), ctx), body.subarray(KEM_CT_LEN), ctx);
  } catch {
    return null;
  }
  try {
    return joinOf(unpad(padded));
  } catch {
    return { kind: "malformed" };
  }
}

// ───────────────────────── link hello (§5.5) ─────────────────────────

export const HELLO_LABEL = "segv.sh/v2/hello";
/** seal of a 90-byte J: 1120 + 24 + 90 + 16. */
export const HELLO_INNER_LEN = SEAL_OVERHEAD + J_LEN; // 1250

export const helloAad = (E: number, label: Bytes): Bytes => enc(HELLO_LABEL, u16(E), fixed(label, 16, "hello label"));

/** inner = seal(kemPk, "segv.sh/v2/hello", enc(H(s)), J); body = aeadSeal(mL, pad(inner, CLASSES), aad). Class 2. */
export function makeHello(kemPk: Bytes, s: Bytes, E: number, label: Bytes, J: Join | Bytes): SealedRow {
  const inner = seal(kemPk, HELLO_LABEL, enc(H(s)), joinBytes(J));
  const { cls, pt } = padClass(inner, CLASSES);
  return { cls, body: aeadSeal(linkKeys(s).mL, pt, helloAad(E, label)) };
}

/** Opens both layers of a hello. null when either layer does not open (decapsulation throws included). */
export function openHello(kemSk: Bytes, s: Bytes, E: number, label: Bytes, body: Bytes): JoinOpen | null {
  if (clsOfBodyLen(body.length) < 0) return null;
  let inner: Bytes;
  try {
    inner = unpad(aeadOpen(linkKeys(s).mL, body, helloAad(E, label)));
  } catch {
    return null;
  }
  const J = tryOpen(kemSk, HELLO_LABEL, enc(H(s)), inner);
  return J ? joinOf(J) : null;
}

// ───────────────────────── SGB2 key bundle (§5.4) ─────────────────────────

export const SGB2_MAGIC = "SGB2";
export const SGB2_VER = 1;
export const DESC_CLASSES = [4096] as const;
export const REKEY_LABEL = "segv.sh/v2/rekey";

export const rekeyCtx = (conv: Bytes, e: number, i: number): Bytes => enc(conv, u32(e), u16(i));
export const descAad = (conv: Bytes, e: number): Bytes => enc("segv.sh/v2/desc", conv, u32(e));
export const pksAad = (conv: Bytes, e: number): Bytes => enc("segv.sh/v2/pks", conv, u32(e));

/** B = 8 if max(|D_prev|, |D_e|) ≤ 8, otherwise 32 (e = 0: prevM = 0). */
export const sgb2B = (prevM: number, curM: number): 8 | 32 => (Math.max(prevM, curM) <= 8 ? 8 : 32);

/** B implied by a bundle size, or null. */
export const sgb2BOfSize = (size: number): 8 | 32 | null =>
  size === SGB2_SIZES[0] ? 8 : size === SGB2_SIZES[1] ? 32 : null;

/** rr_e = HKDF(EK_e, conv, enc("segv.sh/v2/ep/rekey", u32 e), 32): the root of the derived entries (§5.4). */
export function rekeyRoot(EK: Bytes, conv: Bytes, e: number): Bytes {
  fixed(EK, 32, "rr EK");
  fixed(conv, 16, "rr conv");
  return HKDF(EK, conv, enc("segv.sh/v2/ep/rekey", u32(e)));
}

/**
 * sealDet (§5.4): the entry of a member X_i kept by e (`pk` = its kemPk in pks_e), a seal of EK_e whose randomness
 * is derived from EK_e, so every member of e recomputes it byte for byte:
 *   ρ = HKDF(rr_e, "", enc("segv.sh/v2/rekey-rnd", u16 i), 88)
 *   (kct, ss) = X-Wing EncapsulateDerand(pk, ρ[0..64])     ρ[0..32] ML-KEM coins, ρ[32..64] the X25519 ephemeral key
 *   entry = kct ‖ ρ[64..88] ‖ XChaCha20-Poly1305(k, nonce ρ[64..88], EK_e, aad = enc("segv.sh/v2/rekey", ctx))
 * with k and ctx = enc(conv, u32 e, u16 i) as in seal(pk, "segv.sh/v2/rekey", ctx, EK_e) (§1.4), whose layout it
 * has, so open() opens it. 1192 B. Uses no RNG. Throws when `pk` cannot be encapsulated to.
 */
export function sealDet(pk: Bytes, conv: Bytes, e: number, i: number, EK: Bytes): Bytes {
  const ctx = rekeyCtx(conv, e, i);
  const rho = HKDF(rekeyRoot(EK, conv, e), "", enc("segv.sh/v2/rekey-rnd", u16(i)), 88);
  const r = xwing.encapsulate(fixed(pk, KEM_PK_LEN, "sealDet pk"), rho.slice(0, 64));
  const nonce = rho.slice(64, 88);
  const k = sealKey(r.sharedSecret, r.cipherText, REKEY_LABEL, ctx);
  return concat(r.cipherText, nonce, xchacha20poly1305(k, nonce, enc(REKEY_LABEL, ctx)).encrypt(EK));
}

export interface BundleSpec {
  conv: Bytes;
  /** The epoch the bundle defines. */
  e: number;
  /** D_e bytes (not validated here, so tests can build bundles with bad descriptors; its uids are read by layout). */
  D: Bytes;
  dsig: Bytes;
  EK: Bytes;
  /**
   * pks_e: the kemPk of D_e.members[j], in D order (§5.4). A continuing member's comes from pks_{e−1} (the bundle of
   * e−1), a new member's from its verified directory bundle, self's from its identity. Nothing is looked up here.
   */
  pks: readonly Bytes[];
  /** The uids of D_{e−1}.members in index order; empty for e = 0. */
  prevMembers: readonly Bytes[];
  /** The claim's rm (§6.2): bit i set iff D_{e−1}.members[i] is not in D_e. 0 for e = 0. */
  rm: number;
  /** Defaults to sgb2B(|D_{e−1}|, |D_e|). */
  B?: 8 | 32;
}

export interface BuiltBundle {
  blob: Bytes;
  /** bundleId = H(blob), raw 32 bytes (the blob id is its b64u). */
  id: Bytes;
  size: number;
  B: 8 | 32;
}

/** The member uids of D bytes, read by layout only (D is not validated). */
function layoutUids(D: Bytes): Bytes[] {
  const m = D.length < D_MIN_LEN ? 0 : D[D_FIXED_LEN - 1];
  if (m < 1 || D.length < D_FIXED_LEN + D_MEMBER_LEN * m + 2) bad("SGB2: short descriptor");
  const at = (j: number): number => D_FIXED_LEN + D_MEMBER_LEN * j;
  return Array.from({ length: m }, (_, j) => D.subarray(at(j), at(j) + 16));
}

/**
 * Builds the SGB2 blob of epoch e (§5.4): header, descCt (D ‖ dsig padded to [4096]), pkCt (pks zero-filled to
 * B·1216 bytes), and per i < B: sealDet(pks[j], …) for a member X_i = D_{e−1}.members[i] whose rm bit is 0 (j = its
 * index in D_e), a dummy seal otherwise (rm bit 1, i ≥ |D_{e−1}|, and every entry for e = 0). random() is drawn for
 * the descCt nonce, the pkCt nonce, then each dummy entry in index order.
 */
export function buildBundle(x: BundleSpec): BuiltBundle {
  const { conv, e, D, dsig, EK, pks, prevMembers, rm } = x;
  fixed(conv, 16, "SGB2 conv");
  fixed(EK, 32, "SGB2 EK");
  fixed(dsig, SIG_LEN, "SGB2 dsig");
  if (e === 0 && (prevMembers.length > 0 || rm !== 0)) bad("SGB2: epoch 0 has no previous members");
  const uids = layoutUids(D);
  if (pks.length !== uids.length) bad("SGB2: one kemPk per member of D");
  const B = x.B ?? sgb2B(prevMembers.length, uids.length);
  if (B !== 8 && B !== 32) bad("SGB2: B must be 8 or 32");
  if (B < prevMembers.length || B < uids.length) bad("SGB2: B too small");
  if (!Number.isInteger(rm) || rm < 0 || rm >= 2 ** prevMembers.length) bad("SGB2: rm must fit D_{e−1}");
  const { dk } = epochKeys(EK, conv, e);
  const descCt = aeadSeal(dk, pad(concat(D, dsig), DESC_CLASSES), descAad(conv, e));
  const pksPt = new Uint8Array(B * KEM_PK_LEN);
  pks.forEach((pk, j) => pksPt.set(fixed(pk, KEM_PK_LEN, "SGB2 kemPk"), j * KEM_PK_LEN));
  const pkCt = aeadSeal(dk, pksPt, pksAad(conv, e));
  const entries: Bytes[] = [];
  for (let i = 0; i < B; i++) {
    if (i < prevMembers.length && !rmHas(rm, i)) {
      const j = uids.findIndex((u) => equalBytes(u, prevMembers[i]));
      if (j < 0) bad("SGB2: a kept member is not in D_e");
      entries.push(sealDet(pks[j], conv, e, i, EK));
    } else entries.push(dummySeal(REKEY_LABEL, rekeyCtx(conv, e, i), 32));
  }
  const blob = concat(utf8(SGB2_MAGIC), u8(SGB2_VER), u8(B), new Uint8Array(10), descCt, pkCt, ...entries);
  return { blob, id: H(blob), size: blob.length, B };
}

export interface BundleBlob {
  B: 8 | 32;
  descCt: Bytes;
  pkCt: Bytes;
  entries: Bytes[];
}

export type Sgb2HeaderFailure = "magic" | "ver" | "B" | "header";

function sgb2Header(blob: Bytes, B: 8 | 32): Sgb2HeaderFailure | null {
  if (!equalBytes(blob.subarray(0, 4), utf8(SGB2_MAGIC))) return "magic";
  if (blob[4] !== SGB2_VER) return "ver";
  if (blob[5] !== B) return "B";
  if (blob.subarray(6, SGB2_HEADER_LEN).some((x) => x !== 0)) return "header";
  return null;
}

/**
 * Strict: the size is 23456 or 81248, magic "SGB2", ver 1, B matching the size, 10 zero bytes. Splits descCt
 * (at 16), pkCt (at 4152) and the B entries (from 4192 + 1216·B).
 */
export function parseBundleBlob(blob: Bytes): BundleBlob {
  const B = sgb2BOfSize(blob.length) ?? bad("SGB2: bad size");
  const f = sgb2Header(blob, B);
  if (f) bad(`SGB2: bad ${f}`);
  const at = sgb2EntriesAt(B);
  const entries: Bytes[] = [];
  for (let i = 0; i < B; i++) entries.push(blob.slice(at + i * SGB2_ENTRY_LEN, at + (i + 1) * SGB2_ENTRY_LEN));
  return { B, descCt: blob.slice(SGB2_HEADER_LEN, SGB2_PKCT_AT), pkCt: blob.slice(SGB2_PKCT_AT, at), entries };
}

const bundleOf = (blob: Bytes | BundleBlob): BundleBlob => (blob instanceof Uint8Array ? parseBundleBlob(blob) : blob);

/**
 * Opens entry i for epoch e (§6.6 step 2): EK, or null when it does not open (a decapsulation throw, an AEAD
 * failure, a length ≠ 32, a malformed blob or i ≥ B).
 */
export function openEntry(kemSk: Bytes, conv: Bytes, e: number, i: number, blob: Bytes | BundleBlob): Bytes | null {
  let b: BundleBlob;
  try {
    b = bundleOf(blob);
  } catch {
    return null;
  }
  if (!Number.isInteger(i) || i < 0 || i >= b.B) return null;
  const V = tryOpen(kemSk, REKEY_LABEL, rekeyCtx(conv, e, i), b.entries[i]);
  return V && V.length === 32 ? V : null;
}

/**
 * Decrypts descCt with dk_e, unpads and splits D ‖ dsig. Throws on any failure (a wrong key, a corrupted descCt,
 * a length outside [224, 2960]); never returns garbage. Does not parse D.
 */
export function openDesc(dk: Bytes, conv: Bytes, e: number, blob: Bytes | BundleBlob): { D: Bytes; dsig: Bytes } {
  return splitDesc(unpad(aeadOpen(dk, bundleOf(blob).descCt, descAad(conv, e))));
}

/** Decrypts pkCt with dk_e: pks_e, B·1216 bytes (§5.4). Throws on any failure (a wrong key, a corrupted pkCt). */
export function openPks(dk: Bytes, conv: Bytes, e: number, blob: Bytes | BundleBlob): Bytes {
  return aeadOpen(dk, bundleOf(blob).pkCt, pksAad(conv, e));
}

/** §6.4 (h), each failure separately: bundleSize ∉ {23456, 81248}, length, hash, magic, ver, B, the zero bytes, B < m. */
export type BundleShapeFailure = "size" | "length" | "hash" | Sgb2HeaderFailure | "m";

export function bundleShapeValid(blob: Bytes, size: number, id: Bytes, m: number): BundleShapeFailure | null {
  const B = sgb2BOfSize(size);
  if (!B) return "size";
  if (blob.length !== size) return "length";
  if (!equalBytes(H(blob), id)) return "hash";
  const f = sgb2Header(blob, B);
  if (f) return f;
  return B < m ? "m" : null;
}

// ───────────────────────── claims (§6.2, §6.4, §6.8) ─────────────────────────

/** prevD | hD | ekc | bundleId | u32 bundleSize | u32 rm | u8 m. */
export const CLAIM_FIXED_LEN = 137;
export const claimLen = (m: number): number => CLAIM_FIXED_LEN + 6 * m;

/** `u16 E | u32 cnt`: a cut (§6.2) or a processed position (HEADS, §7.2). */
export interface EraCount {
  E: number;
  cnt: number;
}
export type Cut = EraCount;

export interface Claim {
  /** H(D_e) */
  prevD: Bytes;
  /** H(D_{e+1}) */
  hD: Bytes;
  /** ekc_{e+1} */
  ekc: Bytes;
  bundleId: Bytes;
  bundleSize: number;
  /** bit i = D_e.members[i] is not in D_{e+1} */
  rm: number;
  /** one cut per lane of D_e (m = cuts.length) */
  cuts: Cut[];
}

const wrEraCount = (x: EraCount): Bytes => concat(u16(x.E), u32(x.cnt));

export function encodeClaim(c: Claim): Bytes {
  const m = c.cuts.length;
  if (m < 1 || m > MAX_MEMBERS) bad("claim: bad m");
  return concat(
    fixed(c.prevD, 32, "claim prevD"),
    fixed(c.hD, 32, "claim hD"),
    fixed(c.ekc, 32, "claim ekc"),
    fixed(c.bundleId, 32, "claim bundleId"),
    u32(c.bundleSize),
    u32(c.rm),
    u8(m),
    ...c.cuts.map(wrEraCount),
  );
}

/** Structural parse (exactly 137 + 6m bytes, 1 ≤ m ≤ 32). The e-validity rules are claimShapeValid / §6.4. */
export function parseClaim(b: Bytes): Claim {
  const r = new Rd(b, "claim");
  const prevD = r.bytes(32);
  const hD = r.bytes(32);
  const ekc_ = r.bytes(32);
  const bundleId = r.bytes(32);
  const bundleSize = r.u32();
  const rm = r.u32();
  const m = r.u8();
  if (m < 1 || m > MAX_MEMBERS) bad("claim: bad m");
  const cuts: Cut[] = [];
  for (let i = 0; i < m; i++) cuts.push({ E: r.u16(), cnt: r.u32() });
  r.end();
  return { prevD, hD, ekc: ekc_, bundleId, bundleSize, rm, cuts };
}

/** Bit i of rm (value 2^i). */
export const rmHas = (rm: number, i: number): boolean =>
  Number.isInteger(i) && i >= 0 && i < 32 && ((rm >>> i) & 1) === 1;

/** rm for a change D_e → D_{e+1}: bit i set iff D_e.members[i] is not in D_{e+1}. */
export function rmBits(
  De: { members: readonly { uid: Bytes }[] },
  Dnext: { members: readonly { uid: Bytes }[] },
): number {
  let rm = 0;
  De.members.forEach((x, i) => {
    if (memberIndex(Dnext, x.uid) < 0) rm += 2 ** i;
  });
  return rm;
}

/**
 * The local e-validity rules (a) m = |D_e|, (b) from, (e), (f), and the local halves of (g) and (h): the size set and
 * B ≥ m with B from `bundleSize` (§6.4 "Order of requests": all of them pass before any `blob/meta` request).
 */
export type ClaimShapeFailure = "m" | "from" | "rm-high" | "rm-self" | "cut" | "bundleSize";

export function claimShapeValid(
  c: Claim,
  m: number,
  from: number,
  Estart: number,
  E: number,
): ClaimShapeFailure | null {
  if (c.cuts.length !== m) return "m";
  if (!Number.isInteger(from) || from < 0 || from >= m) return "from";
  if (m < 32 && c.rm >= 2 ** m) return "rm-high";
  if (rmHas(c.rm, from)) return "rm-self";
  if (c.cuts.some((x) => x.E < Estart || x.E > E)) return "cut";
  const B = sgb2BOfSize(c.bundleSize);
  if (B === null || B < m) return "bundleSize";
  return null;
}

/** A lane row (E, n) is before the cut (E_ℓ, cnt_ℓ) iff E < E_ℓ, or E = E_ℓ and n < cnt_ℓ (§6.2). */
export const cutBefore = (cut: Cut, E: number, n: number): boolean => E < cut.E || (E === cut.E && n < cut.cnt);

/** One epoch of the §6.8 walk, as the receiver holds it. */
export interface WalkEpoch {
  /** uids of D_j in index order (raw or b64u), to follow the sender across epochs. */
  members: readonly (Bytes | string)[];
  /**
   * The claim that ended epoch j (its stored t, rm and cuts): the final winning claim C_j, or, for the last epoch
   * before a skip re-add, the claim that removed self; null when the epoch has no final winning claim yet.
   */
  claim: { t: number; rm: number; cuts: readonly Cut[] } | null;
}

/** A valid lane row of epoch e from member index i at (E, n), stored at time t. */
export interface WalkRow {
  i: number;
  E: number;
  n: number;
  t: number;
}

const uidKey = (u: Bytes | string): string => (typeof u === "string" ? u : b64u(u));

/** `acceptOldRow` needs the claim that ended `epochs[j]`, which the caller holds but did not pass (§6.8). */
export class MissingClaimError extends Error {
  readonly j: number;
  constructor(j: number) {
    super(`acceptOldRow: the claim that ended epoch +${j} is needed`);
    this.name = "MissingClaimError";
    this.j = j;
  }
}

/**
 * §6.8 old-epoch acceptance. `epochs` are consecutive held epochs: `epochs[0]` is D_e (the row's epoch) and
 * `epochs[k]` is D_{e+k}, so the list stops before an epoch reached by a skip re-add, and a frozen receiver's at its
 * frozen epoch. The caller passes the claim that ended each listed epoch whenever one exists, read at the position
 * of the next held epoch's EPOCH record when it did not process it (for the epoch before a skip: the claim that
 * removed self). A null claim on the last listed epoch means it has no final winning claim yet: accept. A null claim
 * with a next epoch continues by membership, since the sender's bit is 0 iff D_{j+1} lists it ("The bit without
 * C_j"); when D_{j+1} does not list the sender, the bit is 1 and the claim is needed, so the call throws
 * `MissingClaimError`. A row is never accepted for lack of a claim.
 */
export function acceptOldRow(row: WalkRow, epochs: readonly WalkEpoch[]): boolean {
  let idx = row.i;
  for (let j = 0; j < epochs.length; j++) {
    const { members, claim } = epochs[j];
    if (idx < 0 || idx >= members.length) return true;
    if (!claim || !rmHas(claim.rm, idx)) {
      const next = epochs[j + 1];
      if (!next) return true;
      const key = uidKey(members[idx]);
      idx = next.members.findIndex((u) => uidKey(u) === key);
      if (!claim && idx < 0) throw new MissingClaimError(j);
      continue;
    }
    if (row.t < claim.t) return true;
    if (j > 0 || row.t !== claim.t) return false;
    const cut = claim.cuts[row.i];
    return cut !== undefined && cutBefore(cut, row.E, row.n);
  }
  return true;
}

// ───────────────────────── envelope M (§3.3) ─────────────────────────

export const M_VER = 2;
export const M_HEADER_LEN = 62;
/** The types of M (§3.3): every other value is invalid. */
export const MT = { TEXT: 1, IMAGE: 2, WELCOME: 8, CLAIM: 16, LEAVE: 17 } as const;
export type MsgType = (typeof MT)[keyof typeof MT];
const MSG_TYPES: readonly number[] = Object.values(MT);
/** lane of a CLAIM. */
export const CTL_LANE = 0xffff;
export const MAX_TEXT = 12000;

export const IMAGE_LEN = 69;
export const MAX_IMAGE_DIM = 8192;
export const MIME = { 1: "image/webp", 2: "image/jpeg" } as const;
export type MimeCode = keyof typeof MIME;

/** IMAGE content: id[32] | k[32] | u8 mime | u16 w | u16 h. */
export interface ImageRef {
  /** raw blob id (H(blob)) */
  id: Bytes;
  k: Bytes;
  mime: MimeCode;
  w: number;
  h: number;
}

export function parseImage(b: Bytes): ImageRef {
  const r = new Rd(b, "image");
  const id = r.bytes(32);
  const k = r.bytes(32);
  const mime = r.u8();
  const w = r.u16();
  const h = r.u16();
  r.end();
  if (mime !== 1 && mime !== 2) bad("image: bad mime");
  if (w < 1 || w > MAX_IMAGE_DIM || h < 1 || h > MAX_IMAGE_DIM) bad("image: bad dimensions");
  return { id, k, mime, w, h };
}

export function encodeImage(x: ImageRef): Bytes {
  const out = concat(fixed(x.id, 32, "image id"), fixed(x.k, 32, "image key"), u8(x.mime), u16(x.w), u16(x.h));
  parseImage(out);
  return out;
}

/** The header fields of M other than ver, type and len. */
export interface MHeader {
  /** The sender's index in D_e. */
  from: number;
  /** = from for lane rows, CTL_LANE for a CLAIM. */
  lane: number;
  /** The slot in era E: the lane counter, or k for a CLAIM. */
  n: number;
  /** The sender's previous valid row on this lane in this epoch, or NONE (first row, every CLAIM). */
  prev: Pos;
  /** t16(H(enc("segv.sh/v2/prev", label_prev, body_prev))), or ZERO16 with NONE. */
  prevh: Bytes;
  /** The sender's clock in ms (display only). */
  ts: number;
  /** The sender's latest verified checkpoint q and t16(C_q), or (0, ZERO16). */
  ckq: number;
  ck16: Bytes;
}

/** The type and typed content of M. */
export type MBody =
  | { type: typeof MT.TEXT; text: string }
  | { type: typeof MT.IMAGE; image: ImageRef }
  | { type: typeof MT.WELCOME; join: Join }
  | { type: typeof MT.CLAIM; claim: Claim }
  | { type: typeof MT.LEAVE };

export type Msg = MHeader & MBody;

function encodeContent(m: MBody): Bytes {
  switch (m.type) {
    case MT.TEXT: {
      const t = encodeUtf8(m.text, "text");
      return t.length >= 1 && t.length <= MAX_TEXT ? t : bad("text: bad length");
    }
    case MT.IMAGE:
      return encodeImage(m.image);
    case MT.WELCOME:
      return encodeJ(m.join);
    case MT.CLAIM:
      return encodeClaim(m.claim);
    case MT.LEAVE:
      return new Uint8Array(0);
    default:
      return bad("M: bad type");
  }
}

function parseContent(type: number, c: Bytes): MBody {
  switch (type) {
    case MT.TEXT:
      if (c.length < 1 || c.length > MAX_TEXT) bad("text: bad length");
      return { type: MT.TEXT, text: decodeUtf8(c, "text") };
    case MT.IMAGE:
      return { type: MT.IMAGE, image: parseImage(c) };
    case MT.WELCOME:
      return { type: MT.WELCOME, join: parseJ(c) };
    case MT.CLAIM:
      return { type: MT.CLAIM, claim: parseClaim(c) };
    case MT.LEAVE:
      if (c.length !== 0) bad("M: content must be empty");
      return { type };
    default:
      return bad("M: bad type");
  }
}

/**
 * Parses M and checks every parse rule of §3.3 (none needs epoch context): ver, type ∈ {1, 2, 8, 16, 17}, content,
 * `lane = from` for lane rows and `lane = 0xFFFF` with NONE / ZERO16 prev fields for a CLAIM, `from < 32`, the
 * position rule, prevh = ZERO16 with NONE, ts ≤ 2^53 − 1, ck16 = ZERO16 with ckq = 0, len. `from < |D_e|`, the
 * label, a CLAIM's m = |D_e| and the signature are contextual (acceptRow).
 */
export function parseM(M: Bytes): Msg {
  const r = new Rd(M, "M");
  if (r.u8() !== M_VER) bad("M: bad version");
  const type = r.u8();
  if (!MSG_TYPES.includes(type)) bad("M: bad type");
  const from = r.u16();
  const lane = r.u16();
  const n = r.u32();
  const prev = rdPos(r, "M prev");
  const prevh = r.bytes(16);
  const ts = r.u64();
  const ckq = r.u32();
  const ck16 = r.bytes(16);
  const content = r.bytes(r.u16());
  r.end();
  if (from >= MAX_MEMBERS) bad("M: bad from");
  if (type === MT.CLAIM) {
    if (lane !== CTL_LANE) bad("M: a claim is on lane 0xFFFF");
    if (!isNone(prev)) bad("M: a claim has no prev");
  } else if (lane !== from) bad("M: lane must equal from");
  if (isNone(prev) && !equalBytes(prevh, ZERO16)) bad("M: prevh without prev");
  if (ckq === 0 && !equalBytes(ck16, ZERO16)) bad("M: ck16 without ckq");
  return { from, lane, n, prev, prevh, ts, ckq, ck16, ...parseContent(type, content) };
}

export function encodeM(m: Msg): Bytes {
  const content = encodeContent(m);
  const out = concat(
    u8(M_VER),
    u8(m.type),
    u16(m.from),
    u16(m.lane),
    u32(m.n),
    wrPos(m.prev, "M prev"),
    fixed(m.prevh, 16, "M prevh"),
    u64(m.ts),
    u32(m.ckq),
    fixed(m.ck16, 16, "M ck16"),
    u16(content.length),
    content,
  );
  parseM(out);
  return out;
}

export const rowAad = (E: number, label: Bytes): Bytes => enc("segv.sh/v2/msg", u16(E), label);
export const rowSigMsg = (conv: Bytes, e: number, E: number, label: Bytes, M: Bytes): Bytes =>
  enc("segv.sh/v2/msg-sig", conv, u32(e), u16(E), label, M);

/** sig = SIG.sign(enc("segv.sh/v2/msg-sig", conv, u32 e, u16 E, label, M), sk_from). */
export const signRow = (sigSk: Bytes, conv: Bytes, e: number, E: number, label: Bytes, M: Bytes): Bytes =>
  sign(rowSigMsg(conv, e, E, label, M), sigSk);

/** Verifies under `sigPk`, which MUST be D_e.members[from].sigPk (§5.1); there is no directory argument. */
export const verifyRow = (
  sigPk: Bytes,
  sig: Bytes,
  conv: Bytes,
  e: number,
  E: number,
  label: Bytes,
  M: Bytes,
): boolean => verify(sig, rowSigMsg(conv, e, E, label, M), sigPk);

/** body = aeadSeal(mk_e, pad(M ‖ sig, CLASSES), aad = enc("segv.sh/v2/msg", u16 E, label)). */
export function sealRow(mk: Bytes, E: number, label: Bytes, M: Bytes, sig: Bytes): SealedRow {
  fixed(label, 16, "row label");
  fixed(sig, SIG_LEN, "row sig");
  const { cls, pt } = padClass(concat(M, sig), CLASSES);
  return { cls, body: aeadSeal(mk, pt, rowAad(E, label)) };
}

export interface OpenedRow {
  /** the exact M bytes (signed) */
  M: Bytes;
  sig: Bytes;
  msg: Msg;
}

/** The padded plaintext of a row body, or null when it does not decrypt. */
function decryptRow(mk: Bytes, E: number, label: Bytes, body: Bytes): Bytes | null {
  if (clsOfBodyLen(body.length) < 0) return null;
  try {
    return aeadOpen(mk, body, rowAad(E, label));
  } catch {
    return null;
  }
}

function splitRow(padded: Bytes): OpenedRow {
  let x: Bytes;
  try {
    x = unpad(padded);
  } catch {
    return bad("row: bad padding");
  }
  if (x.length < M_HEADER_LEN + SIG_LEN) bad("row: short");
  const M = x.slice(0, x.length - SIG_LEN);
  return { M, sig: x.slice(x.length - SIG_LEN), msg: parseM(M) };
}

/** Decrypts, unpads, splits M ‖ sig and parses M. Throws on any failure. Does not verify the signature. */
export function openRow(mk: Bytes, E: number, label: Bytes, body: Bytes): OpenedRow {
  const padded = decryptRow(mk, E, label, body);
  return splitRow(padded ?? bad("row: does not decrypt"));
}

/** The label a row must sit at: Lmsg_e(lane, E, n) for lane rows, Lctl_e(E, n) for a CLAIM (§3.3). */
export const expectedLabel = (keys: { rk: Bytes }, m: { type: number; lane: number; n: number }, E: number): Bytes =>
  m.type === MT.CLAIM ? Lctl(keys.rk, E, m.n) : Lmsg(keys.rk, m.lane, E, m.n);

export interface RowContext {
  keys: { rk: Bytes; mk: Bytes };
  conv: Bytes;
  e: number;
  /** D_e.members: signatures verify under these keys only (§5.1). */
  members: readonly { sigPk: Bytes }[];
}

/** Why a conversation row is not accepted (§3.3), in check order. "decrypt" is the "undecryptable" warning. */
export type RowReject = "decrypt" | "malformed" | "from" | "label" | "content" | "sig";
export type RowVerdict = ({ ok: true } & OpenedRow) | { ok: false; why: RowReject };

/** Every receiver check of §3.3 for a row stored at (E, label) of epoch ctx.e. */
export function acceptRow(ctx: RowContext, E: number, label: Bytes, body: Bytes): RowVerdict {
  const no = (why: RowReject): RowVerdict => ({ ok: false, why });
  const padded = decryptRow(ctx.keys.mk, E, label, body);
  if (!padded) return no("decrypt");
  let row: OpenedRow;
  try {
    row = splitRow(padded);
  } catch {
    return no("malformed");
  }
  const m = row.msg;
  if (m.from >= ctx.members.length) return no("from");
  if (!equalBytes(expectedLabel(ctx.keys, m, E), label)) return no("label");
  if (m.type === MT.CLAIM && m.claim.cuts.length !== ctx.members.length) return no("content");
  if (!verifyRow(ctx.members[m.from].sigPk, row.sig, ctx.conv, ctx.e, E, label, row.M)) return no("sig");
  return { ok: true, ...row };
}

/** Encodes, labels, signs and seals one row of epoch ctx.e in era E. */
export function buildRow(
  ctx: { keys: { rk: Bytes; mk: Bytes }; conv: Bytes; e: number; sigSk: Bytes },
  E: number,
  msg: Msg,
): SealedRow & { label: Bytes; M: Bytes; sig: Bytes } {
  const M = encodeM(msg);
  const label = expectedLabel(ctx.keys, msg, E);
  const sig = signRow(ctx.sigSk, ctx.conv, ctx.e, E, label, M);
  return { label, M, sig, ...sealRow(ctx.keys.mk, E, label, M, sig) };
}

// ───────────────────────── processing a winning claim (§6.6 steps 2–4) ─────────────────────────

/**
 * What member i of D_e does with the final winning claim (§6.6 steps 3–4): removed (rm bit 1); frozen "nokey" (its
 * entry does not open, or its ekc mismatches); frozen "invalid" with the first failing D′ check; or accept.
 */
export type ClaimOutcome =
  | { kind: "removed" }
  | { kind: "nokey" }
  | { kind: "invalid"; failed: DPrimeCheck }
  | { kind: "accept"; EK: Bytes; keys: EpochKeys; D: Descriptor; dsig: Bytes; pks: Bytes };

/** §6.6 steps 2–4 for one member. Whatever the bundle holds, every failure is an outcome, never a throw. */
export function processClaim(p: {
  kemSk: Bytes;
  De: Descriptor;
  /** self's index in D_e */
  i: number;
  /** the claim's `from` */
  from: number;
  claim: Claim;
  blob: Bytes | BundleBlob;
}): ClaimOutcome {
  const { De, claim } = p;
  const e1 = De.e + 1;
  if (rmHas(claim.rm, p.i)) return { kind: "removed" };
  let b: BundleBlob;
  try {
    b = bundleOf(p.blob);
  } catch {
    return { kind: "nokey" }; // no entry opens (rule (h) has already refused such a blob)
  }
  const V = openEntry(p.kemSk, De.conv, e1, p.i, b);
  if (!V || !equalBytes(ekc(De.conv, e1, V), claim.ekc)) return { kind: "nokey" };
  const keys = epochKeys(V, De.conv, e1);
  // The first D′ check: descCt and pkCt open under dk_{e+1}(EK′); D′ ‖ dsig′ unpads (and parses, in dPrimeChecks).
  let opened: "desc" | "pks" = "desc";
  let pair: { D: Bytes; dsig: Bytes };
  let pks: Bytes;
  try {
    pair = openDesc(keys.dk, De.conv, e1, b);
    opened = "pks";
    pks = openPks(keys.dk, De.conv, e1, b);
  } catch {
    return { kind: "invalid", failed: opened };
  }
  const r = dPrimeChecks({ ...pair, kc: keys.kc, pks, EK: V }, De, { from: p.from, hD: claim.hD, rm: claim.rm }, b);
  if (!r.ok) return { kind: "invalid", failed: r.failed };
  return { kind: "accept", EK: V, keys, D: r.D, dsig: pair.dsig, pks };
}

// ───────────────────────── accepting a join (§6.7 steps 1–2) ─────────────────────────

/** "pks": pkCt does not open, or checkPks fails; "self": self is missing, or listed with a foreign sigPk or kh. */
export type JoinCheckFailure = "hash" | "size" | "header" | "desc" | "pks" | "conv" | "e" | "dsig" | "self";
export type JoinCheck =
  | { ok: true; D: Descriptor; dsig: Bytes; keys: EpochKeys; pks: Bytes }
  | { ok: false; failed: JoinCheckFailure };

/**
 * §6.7 steps 1–2 on a fetched blob: it matches J (hash, size = bundleSize ∈ {23456, 81248}, header with 10 zero
 * bytes), descCt and pkCt open with dk_e(EK), D parses with D.conv = J.conv and D.e = J.e < 2^32 − 1, dsig verifies
 * under D's own key for D.by, pks fits D (checkPks), and self is listed with its own sigPk and kh. Returns pks too
 * (later commits copy continuing members' kemPk from it). Steps 3–6 (duplicates, fit, D.by's directory key) are
 * the engine's.
 */
export function checkJoinBundle(J: Join, blob: Bytes, self: Member): JoinCheck {
  const no = (failed: JoinCheckFailure): JoinCheck => ({ ok: false, failed });
  if (!equalBytes(H(blob), J.bundleId)) return no("hash");
  if (blob.length !== J.bundleSize || sgb2BOfSize(blob.length) === null) return no("size");
  let b: BundleBlob;
  try {
    b = parseBundleBlob(blob);
  } catch {
    return no("header");
  }
  if (J.e >= E_MAX) return no("e");
  const keys = epochKeys(J.EK, J.conv, J.e);
  let opened: "desc" | "pks" = "desc";
  let pair: { D: Bytes; dsig: Bytes };
  let D: Descriptor;
  let pks: Bytes;
  try {
    pair = openDesc(keys.dk, J.conv, J.e, b);
    D = parseD(pair.D);
    opened = "pks";
    pks = openPks(keys.dk, J.conv, J.e, b);
  } catch {
    return no(opened);
  }
  if (!equalBytes(D.conv, J.conv)) return no("conv");
  if (D.e !== J.e) return no("e");
  if (!verifyD(D, keys.kc, pair.dsig)) return no("dsig");
  if (checkPks(D, pks, b.B)) return no("pks");
  const i = memberIndex(D, self.uid);
  const listed = i >= 0 ? D.members[i] : null;
  if (!listed || !equalBytes(listed.sigPk, self.sigPk) || !equalBytes(listed.kh, self.kh)) return no("self");
  return { ok: true, D, dsig: pair.dsig, keys, pks };
}

// ───────────────────────── self lane (§7.1–§7.3) ─────────────────────────

export const S_VER = 2;
export const S_HEADER_LEN = 32;
export const MAX_SELF_RECORDS = 255;
/** A self row carrying EPOCH_PENDING or DELIVERED is padded with these classes, so it is class ≥ 1 (§7.1). */
export const SELF_PENDING_CLASSES = [1024, 4096, 16384] as const;

export const RT = {
  CONV_JOIN: 0x01,
  EPOCH: 0x02,
  EPOCH_PENDING: 0x03,
  LEAVE: 0x04,
  CONTACT: 0x05,
  LINK: 0x06,
  PREFS: 0x07,
  HEADS: 0x08,
  CONFIRMED: 0x09,
  DELIVERED: 0x0a,
  REQUEST: 0x0b,
  DESC: 0x0c,
  MEMBER: 0x0d,
  LEFT: 0x0e,
  SNAP: 0x20,
} as const;
export type RType = (typeof RT)[keyof typeof RT];

/** CONV_JOIN / REQUEST `via`. */
export const VIA = { CREATED: 1, INBOX: 2, WELCOME: 3, HELLO: 4, REQUEST_ACCEPTED: 5 } as const;
export type Via = (typeof VIA)[keyof typeof VIA];
const isVia = (v: number): v is Via => v >= 1 && v <= 5;

/** EPOCH flags: bit1 = accepted by a skip join; every other bit, bit0 included, is 0 (§7.2). */
export const EPOCH_SKIP = 2;
/** LINK flags. */
export const LINK_ONE_SHOT = 1;
export const LINK_REVOKED = 2;

/** A conversation copy: (conv, root = H(D) of the first epoch the account accepted). */
export interface CopyRef {
  conv: Bytes;
  root: Bytes;
}
/** u32 e | EK[32] | bundleId[32] | u32 bundleSize. */
export interface EpochMaterial {
  e: number;
  EK: Bytes;
  bundleId: Bytes;
  bundleSize: number;
}

export interface ConvJoinRec extends CopyRef, EpochMaterial {
  rtype: typeof RT.CONV_JOIN;
  rootBy: Bytes;
  via: Via;
}
export interface EpochRec extends CopyRef, EpochMaterial {
  rtype: typeof RT.EPOCH;
  /**
   * the winning claim that ended the previous held epoch: on Lctl_{e−1}, or, for a skip re-add (flag bit1), the claim
   * that removed self, on Lctl_k of the epoch k it removed self from (§7.2)
   */
  claim: Pos;
  flags: number;
}
export interface EpochPendingRec extends CopyRef, EpochMaterial {
  rtype: typeof RT.EPOCH_PENDING;
  tReg: number;
  /** the uids that need J */
  uids: Bytes[];
}
export interface LeaveRec extends CopyRef {
  rtype: typeof RT.LEAVE;
  e: number;
}
export interface ContactRec {
  rtype: typeof RT.CONTACT;
  uid: Bytes;
  pin: Bytes;
}
export interface LinkRec {
  rtype: typeof RT.LINK;
  s: Bytes;
  Ecreated: number;
  Eexpires: number;
  flags: number;
}
export interface PrefsRec {
  rtype: typeof RT.PREFS;
  key: number;
  value: Bytes;
}
/** A followed lane of an older epoch (§11.2) with its processed position. */
export interface FollowedLane {
  ef: number;
  lane: number;
  E: number;
  cnt: number;
}
export interface HeadsEntry extends CopyRef {
  e: number;
  lastTs: number;
  /** (ctlE, ctlCnt) */
  ctl: EraCount;
  /** one processed position per member of D_e (m = lanes.length) */
  lanes: EraCount[];
  followed: FollowedLane[];
}
export interface HeadsRec {
  rtype: typeof RT.HEADS;
  /** the inbox cursor (Ein, relIn) */
  Ein: number;
  relIn: number;
  /** empty: the record carries only the inbox cursor */
  entries: HeadsEntry[];
}
export interface ConfirmedRec extends CopyRef {
  rtype: typeof RT.CONFIRMED;
}
export interface DeliveredRec extends CopyRef {
  rtype: typeof RT.DELIVERED;
  e: number;
  bundleId: Bytes;
  uids: Bytes[];
}
export interface RequestRec extends CopyRef, EpochMaterial {
  rtype: typeof RT.REQUEST;
  tReg: number;
  rootBy: Bytes;
  via: Via;
  /** D ‖ dsig of epoch e (length-checked; parse it with splitDesc + parseD) */
  desc: Bytes;
}
export interface DescRec extends CopyRef {
  rtype: typeof RT.DESC;
  e: number;
  /** D ‖ dsig of epoch e (length-checked; parse it with splitDesc + parseD) */
  desc: Bytes;
}
export interface MemberRec {
  rtype: typeof RT.MEMBER;
  uid: Bytes;
  sigPk: Bytes;
  /** kemHash of the member's directory kemPk (§5.1) */
  kh: Bytes;
  pin: Bytes;
  handle: string;
}
/**
 * Another member's leave as self recorded it (§7.2): `uid` is recorded as left in epoch e of the copy. It stands for
 * the LEAVE row R of the leave's kept source (§6.9), so a restore decides the leave as R would be decided (§6.8).
 */
export interface LeftRec extends CopyRef {
  rtype: typeof RT.LEFT;
  e: number;
  uid: Bytes;
  /** the stored time of R */
  t: number;
  /** R's position when e is R's own epoch, or NONE when the leave was carried into e from an earlier epoch */
  row: Pos;
}
export interface SnapRec {
  rtype: typeof RT.SNAP;
  blobId: Bytes;
  key: Bytes;
  size: number;
  /** (Eh, nh) */
  pos: Pos;
}

export type SelfRecord =
  | ConvJoinRec
  | EpochRec
  | EpochPendingRec
  | LeaveRec
  | ContactRec
  | LinkRec
  | PrefsRec
  | HeadsRec
  | ConfirmedRec
  | DeliveredRec
  | RequestRec
  | DescRec
  | MemberRec
  | LeftRec
  | SnapRec;

const wrCopy = (x: CopyRef): Bytes => concat(fixed(x.conv, 16, "record conv"), fixed(x.root, 32, "record root"));
const wrMaterial = (x: EpochMaterial): Bytes =>
  concat(u32(x.e), fixed(x.EK, 32, "record EK"), fixed(x.bundleId, 32, "record bundleId"), u32(x.bundleSize));
const wrUids = (uids: readonly Bytes[]): Bytes =>
  concat(u8(uids.length), ...uids.map((x) => fixed(x, 16, "record uid")));
const wrDesc = (d: Bytes): Bytes => concat(u16(d.length), d);

function wrHeadsEntry(x: HeadsEntry): Bytes {
  return concat(
    wrCopy(x),
    u32(x.e),
    u64(x.lastTs),
    wrEraCount(x.ctl),
    u8(x.lanes.length),
    ...x.lanes.map(wrEraCount),
    u8(x.followed.length),
    ...x.followed.map((f) => concat(u32(f.ef), u16(f.lane), u16(f.E), u32(f.cnt))),
  );
}

function recordContent(x: SelfRecord): Bytes {
  switch (x.rtype) {
    case RT.CONV_JOIN:
      return concat(wrCopy(x), wrMaterial(x), fixed(x.rootBy, 16, "record rootBy"), u8(x.via));
    case RT.EPOCH:
      return concat(wrCopy(x), wrMaterial(x), wrPos(x.claim, "EPOCH claim"), u8(x.flags));
    case RT.EPOCH_PENDING:
      return concat(wrCopy(x), wrMaterial(x), u32(x.tReg), wrUids(x.uids));
    case RT.LEAVE:
      return concat(wrCopy(x), u32(x.e));
    case RT.CONTACT:
      return concat(fixed(x.uid, 16, "CONTACT uid"), fixed(x.pin, 32, "CONTACT pin"));
    case RT.LINK:
      return concat(fixed(x.s, 16, "LINK s"), u16(x.Ecreated), u16(x.Eexpires), u8(x.flags));
    case RT.PREFS:
      return concat(u8(x.key), x.value);
    case RT.HEADS:
      return concat(u16(x.Ein), u32(x.relIn), u16(x.entries.length), ...x.entries.map(wrHeadsEntry));
    case RT.CONFIRMED:
      return wrCopy(x);
    case RT.DELIVERED:
      return concat(wrCopy(x), u32(x.e), fixed(x.bundleId, 32, "record bundleId"), wrUids(x.uids));
    case RT.REQUEST:
      return concat(
        wrCopy(x),
        wrMaterial(x),
        u32(x.tReg),
        fixed(x.rootBy, 16, "record rootBy"),
        u8(x.via),
        wrDesc(x.desc),
      );
    case RT.DESC:
      return concat(wrCopy(x), u32(x.e), wrDesc(x.desc));
    case RT.MEMBER: {
      const h = utf8(x.handle);
      return concat(
        fixed(x.uid, 16, "MEMBER uid"),
        fixed(x.sigPk, 32, "MEMBER sigPk"),
        fixed(x.kh, 32, "MEMBER kh"),
        fixed(x.pin, 32, "MEMBER pin"),
        u8(h.length),
        h,
      );
    }
    case RT.LEFT:
      return concat(wrCopy(x), u32(x.e), fixed(x.uid, 16, "LEFT uid"), u32(x.t), wrPos(x.row, "LEFT"));
    case RT.SNAP:
      return concat(
        fixed(x.blobId, 32, "SNAP blobId"),
        fixed(x.key, 32, "SNAP key"),
        u32(x.size),
        wrPos(x.pos, "SNAP"),
      );
    default:
      return bad("record: unknown rtype");
  }
}

const rdCopy = (r: Rd): CopyRef => ({ conv: r.bytes(16), root: r.bytes(32) });
const rdMaterial = (r: Rd): EpochMaterial => ({
  e: r.u32(),
  EK: r.bytes(32),
  bundleId: r.bytes(32),
  bundleSize: r.u32(),
});
const rdEraCount = (r: Rd): EraCount => ({ E: r.u16(), cnt: r.u32() });

function rdUids(r: Rd, what: string): Bytes[] {
  const a = r.u8();
  if (a > MAX_MEMBERS) bad(`${what}: too many uids`);
  const uids: Bytes[] = [];
  for (let i = 0; i < a; i++) uids.push(r.bytes(16));
  return uids;
}

function rdVia(r: Rd, what: string): Via {
  const v = r.u8();
  return isVia(v) ? v : bad(`${what}: bad via`);
}

function rdDesc(r: Rd, what: string): Bytes {
  const d = r.bytes(r.u16());
  if (d.length < DESC_MIN_LEN || d.length > DESC_MAX_LEN) bad(`${what}: bad desc length`);
  return d;
}

function rdHeadsEntry(r: Rd): HeadsEntry {
  const copy = rdCopy(r);
  const e = r.u32();
  const lastTs = r.u64();
  const ctl = rdEraCount(r);
  const m = r.u8();
  if (m < 1 || m > MAX_MEMBERS) bad("HEADS: bad lane count");
  const lanes: EraCount[] = [];
  for (let i = 0; i < m; i++) lanes.push(rdEraCount(r));
  const f = r.u8();
  if (f > MAX_MEMBERS) bad("HEADS: too many followed lanes");
  const followed: FollowedLane[] = [];
  for (let i = 0; i < f; i++) followed.push({ ef: r.u32(), lane: r.u16(), E: r.u16(), cnt: r.u32() });
  return { ...copy, e, lastTs, ctl, lanes, followed };
}

/** Parses the content of a record; null for an unknown rtype (skipped, §7.1). Known records are parsed strictly. */
export function parseRecord(rtype: number, c: Bytes): SelfRecord | null {
  const what = `record 0x${rtype.toString(16).padStart(2, "0")}`;
  const r = new Rd(c, what);
  let x: SelfRecord;
  switch (rtype) {
    case RT.CONV_JOIN:
      x = { rtype, ...rdCopy(r), ...rdMaterial(r), rootBy: r.bytes(16), via: rdVia(r, what) };
      break;
    case RT.EPOCH: {
      x = { rtype, ...rdCopy(r), ...rdMaterial(r), claim: rdPos(r, what), flags: r.u8() };
      if (x.e === 0) bad(`${what}: EPOCH is for e ≥ 1`);
      if (x.flags & ~EPOCH_SKIP) bad(`${what}: bad flags`);
      break;
    }
    case RT.EPOCH_PENDING:
      x = { rtype, ...rdCopy(r), ...rdMaterial(r), tReg: r.u32(), uids: rdUids(r, what) };
      break;
    case RT.LEAVE:
      x = { rtype, ...rdCopy(r), e: r.u32() };
      break;
    case RT.CONTACT:
      x = { rtype, uid: r.bytes(16), pin: r.bytes(32) };
      break;
    case RT.LINK:
      x = { rtype, s: r.bytes(16), Ecreated: r.u16(), Eexpires: r.u16(), flags: r.u8() };
      if (x.flags & ~(LINK_ONE_SHOT | LINK_REVOKED)) bad(`${what}: bad flags`);
      break;
    case RT.PREFS:
      x = { rtype, key: r.u8(), value: r.bytes(c.length - 1) };
      break;
    case RT.HEADS: {
      const Ein = r.u16();
      const relIn = r.u32();
      const n = r.u16();
      const entries: HeadsEntry[] = [];
      for (let i = 0; i < n; i++) entries.push(rdHeadsEntry(r));
      x = { rtype, Ein, relIn, entries };
      break;
    }
    case RT.CONFIRMED:
      x = { rtype, ...rdCopy(r) };
      break;
    case RT.DELIVERED:
      x = { rtype, ...rdCopy(r), e: r.u32(), bundleId: r.bytes(32), uids: rdUids(r, what) };
      break;
    case RT.REQUEST:
      x = {
        rtype,
        ...rdCopy(r),
        ...rdMaterial(r),
        tReg: r.u32(),
        rootBy: r.bytes(16),
        via: rdVia(r, what),
        desc: rdDesc(r, what),
      };
      break;
    case RT.DESC:
      x = { rtype, ...rdCopy(r), e: r.u32(), desc: rdDesc(r, what) };
      break;
    case RT.MEMBER: {
      const uid = r.bytes(16);
      const sigPk = r.bytes(32);
      const kh = r.bytes(32);
      const pin_ = r.bytes(32);
      const hlen = r.u8();
      if (hlen < 3 || hlen > 20) bad(`${what}: bad handle length`);
      const handle = decodeUtf8(r.bytes(hlen), what);
      if (!HANDLE_RE.test(handle)) bad(`${what}: bad handle`);
      x = { rtype, uid, sigPk, kh, pin: pin_, handle };
      break;
    }
    case RT.LEFT:
      x = { rtype, ...rdCopy(r), e: r.u32(), uid: r.bytes(16), t: r.u32(), row: rdPos(r, what) };
      break;
    case RT.SNAP:
      x = { rtype, blobId: r.bytes(32), key: r.bytes(32), size: r.u32(), pos: rdPos(r, what) };
      break;
    default:
      return null;
  }
  r.end();
  return x;
}

/** rtype | u16 len | content. */
export function encodeRecord(x: SelfRecord): Bytes {
  const c = recordContent(x);
  parseRecord(x.rtype, c);
  return concat(u8(x.rtype), u16(c.length), c);
}

/** Where a record list sits: a self row at Lself, a pointer row at Lsnap, or a snapshot S2. */
export type RecordsAt = "self" | "snap" | "snapshot";

function rdRecords(r: Rd, count: number, at: RecordsAt): { records: SelfRecord[]; skipped: number } {
  const records: SelfRecord[] = [];
  let skipped = 0;
  for (let i = 0; i < count; i++) {
    const rtype = r.u8();
    const rec = parseRecord(rtype, r.bytes(r.u16()));
    if (!rec) skipped++;
    else if ((rec.rtype === RT.SNAP) !== (at === "snap"))
      bad(`records: rtype 0x${rtype.toString(16)} not allowed here`);
    else records.push(rec);
  }
  if (at === "snap" && records.length !== 1) bad("S: a pointer row holds exactly one SNAP");
  return { records, skipped };
}

function checkRecordsAt(records: readonly SelfRecord[], at: RecordsAt): void {
  const snaps = records.filter((x) => x.rtype === RT.SNAP).length;
  if (at === "snap" ? snaps !== 1 || records.length !== 1 : snaps !== 0) bad("records: SNAP only, and alone, at Lsnap");
}

/** S = u8 ver | u16 Eprev | u32 nprev | prevh[16] | u64 ts | u8 count | record × count. */
export interface SelfRow {
  /** the previous self row (any device), or NONE for the account's first */
  prev: Pos;
  prevh: Bytes;
  ts: number;
  records: SelfRecord[];
}
export interface ParsedSelfRow extends SelfRow {
  /** records with an unknown rtype, ignored */
  skipped: number;
}

/**
 * Encodes S; a row whose records are one SNAP is a snapshot pointer (Lsnap) with prev fields NONE / ZERO16 (it is not
 * part of the Lself prev chain, §7.1), any other may not hold SNAP.
 */
export function encodeS(row: SelfRow): Bytes {
  const count = row.records.length;
  if (count < 1 || count > MAX_SELF_RECORDS) bad("S: 1 ≤ count ≤ 255");
  const pointer = row.records.some((x) => x.rtype === RT.SNAP);
  checkRecordsAt(row.records, pointer ? "snap" : "self");
  if (isNone(row.prev) && !equalBytes(row.prevh, ZERO16)) bad("S: prevh without prev");
  if (pointer && !isNone(row.prev)) bad("S: a pointer row has prev fields NONE / ZERO16");
  return concat(
    u8(S_VER),
    wrPos(row.prev, "S prev"),
    fixed(row.prevh, 16, "S prevh"),
    u64(row.ts),
    u8(count),
    ...row.records.map(encodeRecord),
  );
}

export function parseS(S: Bytes, at: "self" | "snap" = "self"): ParsedSelfRow {
  const r = new Rd(S, "S");
  if (r.u8() !== S_VER) bad("S: bad version");
  const prev = rdPos(r, "S prev");
  const prevh = r.bytes(16);
  const ts = r.u64();
  const count = r.u8();
  if (count < 1) bad("S: no records");
  if (isNone(prev) && !equalBytes(prevh, ZERO16)) bad("S: prevh without prev");
  const { records, skipped } = rdRecords(r, count, at);
  r.end();
  return { prev, prevh, ts, records, skipped };
}

export const selfAad = (E: number, label: Bytes): Bytes =>
  enc("segv.sh/v2/self", u16(E), fixed(label, 16, "self label"));

/**
 * body = aeadSeal(kS, pad(S, CLASSES), aad); a row with EPOCH_PENDING or DELIVERED uses pad(S, [1024, 4096, 16384]),
 * so it is class ≥ 1 (§7.1).
 */
export function sealSelf(kS: Bytes, E: number, label: Bytes, row: SelfRow): SealedRow {
  const S = encodeS(row);
  const pending = row.records.some((x) => x.rtype === RT.EPOCH_PENDING || x.rtype === RT.DELIVERED);
  const { cls, pt } = padClass(S, pending ? SELF_PENDING_CLASSES : CLASSES);
  return { cls, body: aeadSeal(kS, pt, selfAad(E, label)) };
}

/** Opens a self row (`at = "snap"` for a pointer row at Lsnap). Throws on any failure. */
export function openSelf(kS: Bytes, E: number, label: Bytes, body: Bytes, at: "self" | "snap" = "self"): ParsedSelfRow {
  if (clsOfBodyLen(body.length) < 0) bad("S: bad body length");
  return parseS(unpad(aeadOpen(kS, body, selfAad(E, label))), at);
}

// ───────────────────────── snapshots (§7.4) ─────────────────────────

export const S2_MAGIC = "SGS2";
export const S2_VER = 1;
export const S2_HEADER_LEN = 23;
export const SNAPSHOT_AAD = "segv.sh/v2/snapshot";

/** S2 = "SGS2" | u8 ver | u16 Eh | u32 nh | u64 ts | u32 count | record × count. */
export interface Snapshot {
  /** (Eh, nh): the last self-lane position whose effects are included, or NONE */
  pos: Pos;
  ts: number;
  records: SelfRecord[];
}
export interface ParsedSnapshot extends Snapshot {
  skipped: number;
}

export function encodeSnapshot(s: Snapshot): Bytes {
  checkRecordsAt(s.records, "snapshot");
  return concat(
    utf8(S2_MAGIC),
    u8(S2_VER),
    wrPos(s.pos, "S2"),
    u64(s.ts),
    u32(s.records.length),
    ...s.records.map(encodeRecord),
  );
}

export function parseSnapshot(b: Bytes): ParsedSnapshot {
  const r = new Rd(b, "S2");
  if (!equalBytes(r.bytes(4), utf8(S2_MAGIC))) bad("S2: bad magic");
  if (r.u8() !== S2_VER) bad("S2: bad version");
  const pos = rdPos(r, "S2");
  const ts = r.u64();
  const count = r.u32();
  // every record takes ≥ 3 bytes: reject absurd counts before looping
  if (count * 3 > b.length) bad("S2: truncated");
  const { records, skipped } = rdRecords(r, count, "snapshot");
  r.end();
  return { pos, ts, records, skipped };
}

/** blob = aeadSeal(skey, padme(S2), aad = utf8("segv.sh/v2/snapshot")); id = b64u(H(blob)). */
export const encryptSnapshot = (s: Snapshot): { blob: Bytes; id: string; key: Bytes } =>
  encryptBlob(encodeSnapshot(s), SNAPSHOT_AAD);

/** Checks H(blob) = id, decrypts and parses S2. Throws on any failure. */
export const decryptSnapshot = (blob: Bytes, id: string, key: Bytes): ParsedSnapshot =>
  parseSnapshot(decryptBlob(blob, id, key, SNAPSHOT_AAD));
