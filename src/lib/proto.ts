// segv.sh protocol v1 — shared by the browser client and the Worker.
// Byte-exact implementation of docs/PROTOCOL.md. Keep this file free of DOM / Workers APIs.
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { randomBytes } from '@noble/hashes/utils.js';

export type Bytes = Uint8Array;

// ───────────────────────── encoding ─────────────────────────

const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });

export const utf8 = (s: string): Bytes => te.encode(s);
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
export const random = (n: number): Bytes => randomBytes(n);

export const NONCE_LEN = 24;
export const TAG_LEN = 16;

export function aeadSeal(key: Bytes, pt: Bytes, aad: Bytes): Bytes {
  const nonce = random(NONCE_LEN);
  return concat(nonce, xchacha20poly1305(key, nonce, aad).encrypt(pt));
}

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
export function verify(sig: Bytes, msg: Bytes, pk: Bytes): boolean {
  try {
    // Strict RFC 8032 verification. noble's ed25519 defaults to ZIP-215, which accepts small-order
    // public keys: with A = R = identity and S = 0 one "signature" verifies for EVERY message.
    return sig.length === 64 && pk.length === 32 && ed25519.verify(sig, msg, pk, { zip215: false });
  } catch {
    return false;
  }
}

// ───────────────────────── padding ─────────────────────────

// No real message fits in 256 bytes (a text payload is >= ~265 B), so the smallest class is 1024:
// otherwise the rare rows that did fit (e.g. `leave`) would stand out by size.
export const MSG_CLASSES = [1024, 4096, 16384] as const;
// One class: a descriptor for the maximum group (32 members, 64-code-point name) is < 1.5 KB.
export const INV_CLASSES = [2048] as const;

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

// ───────────────────────── accounts ─────────────────────────

export interface Identity {
  sigSk: Bytes;
  sigPk: Bytes;
  kemSk: Bytes;
  kemPk: Bytes;
  scanSk: Bytes;
  scanPk: Bytes;
}

export function deriveIdentity(AK: Bytes): Identity {
  if (AK.length !== 32) throw new Error('AK must be 32 bytes');
  const sigSk = HKDF(AK, '', 'segv.sh/v1/id/ed25519');
  const kem = kemKeygen(HKDF(AK, '', 'segv.sh/v1/id/xwing'));
  const scanSk = HKDF(AK, '', 'segv.sh/v1/id/scan');
  return {
    sigSk,
    sigPk: sigPub(sigSk),
    kemSk: kem.sk,
    kemPk: kem.pk,
    scanSk,
    scanPk: x25519.getPublicKey(scanSk),
  };
}

export const HANDLE_RE = /^[a-z0-9_]{3,20}$/;

export interface Bundle {
  v: 1;
  uid: string;
  handle: string;
  sig: string;
  kem: string;
  scan: string;
  ts: number;
}

/** Parsed + verified bundle with decoded keys. */
export interface User {
  uid: string; // b64u
  handle: string;
  sigPk: Bytes;
  kemPk: Bytes;
  scanPk: Bytes;
  bundle: string; // exact signed text
  bundleSig: string; // b64u
  ts: number;
}

export function makeBundle(uid: Bytes, handle: string, id: Identity, ts: number): { bundle: string; sig: string } {
  if (uid.length !== 16) throw new Error('uid must be 16 bytes');
  if (!HANDLE_RE.test(handle)) throw new Error('invalid handle');
  const b: Bundle = { v: 1, uid: b64u(uid), handle, sig: b64u(id.sigPk), kem: b64u(id.kemPk), scan: b64u(id.scanPk), ts };
  const bundle = JSON.stringify(b);
  const sig = sign(bundleSigMsg(bundle), id.sigSk);
  return { bundle, sig: b64u(sig) };
}

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
const isTs = (x: unknown): x is number => Number.isSafeInteger(x) && (x as number) >= 0;

function b64uLen(s: unknown, len: number): Bytes {
  if (typeof s !== 'string') throw new Error('expected base64url');
  const b = fromB64u(s);
  if (b.length !== len) throw new Error(`expected ${len} bytes`);
  return b;
}

export const bundleSigMsg = (bundle: string): Bytes => enc('segv.sh/v1/bundle', utf8(bundle));

/** Parses a bundle and checks every field's shape. Does NOT check the signature. */
export function parseBundle(bundle: string, sigB64: string): User {
  const raw = JSON.parse(bundle) as unknown;
  if (!isObj(raw) || raw.v !== 1) throw new Error('bundle: bad version');
  const uid = b64uLen(raw.uid, 16);
  const sigPk = b64uLen(raw.sig, 32);
  const kemPk = b64uLen(raw.kem, KEM_PK_LEN);
  const scanPk = b64uLen(raw.scan, 32);
  if (typeof raw.handle !== 'string' || !HANDLE_RE.test(raw.handle)) throw new Error('bundle: bad handle');
  if (!isTs(raw.ts)) throw new Error('bundle: bad ts');
  b64uLen(sigB64, 64);
  return { uid: b64u(uid), handle: raw.handle, sigPk, kemPk, scanPk, bundle, bundleSig: sigB64, ts: raw.ts };
}

/** Parses and verifies a bundle (shapes + signature). Throws on any problem. */
export function verifyBundle(bundle: string, sigB64: string): User {
  const u = parseBundle(bundle, sigB64);
  if (!verify(fromB64u(sigB64), bundleSigMsg(bundle), u.sigPk)) throw new Error('bundle: bad signature');
  return u;
}

/**
 * Checks that a bundle's public keys are usable: the signing key is not a small-order point, the
 * scan key is not a low-order X25519 point and the X-Wing key encapsulates (ML-KEM modulus check).
 * Costs ~2 ms; the server runs it at registration so nobody can register keys that break invites.
 */
export function checkUserKeys(u: { sigPk: Bytes; kemPk: Bytes; scanPk: Bytes }): void {
  let smallOrder = true;
  try {
    smallOrder = ed25519.Point.fromBytes(u.sigPk).isSmallOrder();
  } catch {
    /* not a point */
  }
  if (smallOrder) throw new Error('bundle: unusable signing key');
  let shared: Bytes | null = null;
  try {
    shared = x25519.getSharedSecret(HKDF(utf8('segv.sh/v1/keycheck'), '', 'x25519'), u.scanPk);
  } catch {
    /* low-order point */
  }
  if (!shared || shared.every((b) => b === 0)) throw new Error('bundle: unusable scan key');
  try {
    xwing.encapsulate(u.kemPk);
  } catch {
    throw new Error('bundle: unusable KEM key');
  }
}

export function fingerprint(u: { uid: string; sigPk: Bytes; kemPk: Bytes; scanPk: Bytes }): string {
  const fp = H(enc('segv.sh/v1/fp', fromB64u(u.uid), u.sigPk, u.kemPk, u.scanPk));
  const groups: string[] = [];
  for (let k = 0; k < 6; k++) {
    let v = 0;
    for (let j = 0; j < 5; j++) v = v * 256 + fp[5 * k + j];
    groups.push(String(v % 100000).padStart(5, '0'));
  }
  return groups.join(' ');
}

// ───────────────────────── sealing (KEM-DEM) ─────────────────────────

export function seal(pk: Bytes, label: string, ctx: Bytes, pt: Bytes): Bytes {
  const { cipherText: kct, sharedSecret: ss } = xwing.encapsulate(pk);
  const k = HKDF(ss, H(kct), enc('segv.sh/v1/seal', label, ctx));
  return concat(kct, aeadSeal(k, pt, enc(label, ctx)));
}

export function open(sk: Bytes, label: string, ctx: Bytes, box: Bytes): Bytes {
  if (box.length < KEM_CT_LEN + NONCE_LEN + TAG_LEN) throw new Error('seal: short');
  const kct = box.subarray(0, KEM_CT_LEN);
  const ss = xwing.decapsulate(kct, sk);
  const k = HKDF(ss, H(kct), enc('segv.sh/v1/seal', label, ctx));
  return aeadOpen(k, box.subarray(KEM_CT_LEN), enc(label, ctx));
}

// ───────────────────────── key wraps (passkey PRF / recovery code) ─────────────────────────

export const PRF_INPUT = 'segv.sh/v1/prf';
export const WRAP_LEN = KEM_CT_LEN + NONCE_LEN + 32 + TAG_LEN; // 1192
/** WebAuthn credential ids are at most 1023 bytes. */
export const MAX_ID_LEN = 1023;

/** The unlock secret's key material. `auth` binds every wrap to the secret: the KEM public key and the
 *  wrap id are public, so without it anyone could file a wrap of *their* AK that opens for your secret. */
export interface UnlockKey {
  pk: Bytes;
  sk: Bytes;
  auth: Bytes;
}

export function credKem(prf: Bytes, credId: Bytes): UnlockKey {
  if (prf.length !== 32) throw new Error('PRF output must be 32 bytes');
  return { ...kemKeygen(HKDF(prf, credId, 'segv.sh/v1/cred/xwing')), auth: HKDF(prf, credId, 'segv.sh/v1/cred/auth') };
}

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function newRecoveryCode(): Bytes {
  return random(20);
}

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

export function recoveryKem(code: Bytes): UnlockKey & { id: Bytes } {
  return {
    ...kemKeygen(HKDF(code, '', 'segv.sh/v1/recovery/xwing')),
    auth: HKDF(code, '', 'segv.sh/v1/recovery/auth'),
    id: HKDF(code, '', 'segv.sh/v1/recovery/id', 16),
  };
}

export type WrapKind = 'passkey' | 'recovery';

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

export function makeWrap(
  uid: Bytes,
  kind: WrapKind,
  id: Bytes,
  key: { pk: Bytes; auth: Bytes },
  AK: Bytes,
  ident: Identity,
  ts: number,
): { record: string; sig: string } {
  const kemPk = key.pk;
  const wrap = seal(kemPk, 'ak-wrap', enc(uid, id, key.auth), AK);
  const record = JSON.stringify({ v: 1, uid: b64u(uid), kind, id: b64u(id), kem: b64u(kemPk), wrap: b64u(wrap), ts });
  const sig = sign(wrapSigMsg(record), ident.sigSk);
  return { record, sig: b64u(sig) };
}

export const wrapSigMsg = (record: string): Bytes => enc('segv.sh/v1/wrap', utf8(record));

/** Parses a wrap record and checks every field's shape. Does NOT check the signature. */
export function parseWrap(record: string, sigB64: string): WrapRecord {
  const raw = JSON.parse(record) as unknown;
  if (!isObj(raw) || raw.v !== 1) throw new Error('wrap: bad version');
  if (raw.kind !== 'passkey' && raw.kind !== 'recovery') throw new Error('wrap: bad kind');
  b64uLen(raw.uid, 16);
  if (typeof raw.id !== 'string') throw new Error('wrap: bad id');
  const id = fromB64u(raw.id);
  if (id.length < 1 || id.length > MAX_ID_LEN) throw new Error('wrap: bad id length');
  const kemPk = b64uLen(raw.kem, KEM_PK_LEN);
  const wrap = b64uLen(raw.wrap, WRAP_LEN);
  if (!isTs(raw.ts)) throw new Error('wrap: bad ts');
  b64uLen(sigB64, 64);
  return { uid: raw.uid as string, kind: raw.kind, id, kemPk, wrap, record, sig: sigB64, ts: raw.ts };
}

/** Parses a wrap record and checks its signature against the owner's sigPk. */
export function verifyWrap(record: string, sigB64: string, ownerSigPk: Bytes): WrapRecord {
  const w = parseWrap(record, sigB64);
  if (!verify(fromB64u(sigB64), wrapSigMsg(record), ownerSigPk)) throw new Error('wrap: bad signature');
  return w;
}

/** Opens a wrap with the record's KEM secret key and checks the result against the owner's bundle. */
/** Opens a wrap with the unlock key (sk + auth). Throws unless the box was sealed by someone holding the secret. */
export function openWrap(w: { uid: string; id: Bytes; wrap: Bytes }, key: { sk: Bytes; auth: Bytes }): Bytes {
  const AK = open(key.sk, 'ak-wrap', enc(fromB64u(w.uid), w.id, key.auth), w.wrap);
  if (AK.length !== 32) throw new Error('unwrap: bad AK length');
  return AK;
}

export function unwrapAK(w: WrapRecord, key: { sk: Bytes; auth: Bytes }, ownerSigPk: Bytes): Bytes {
  const AK = openWrap(w, key);
  if (AK.length !== 32) throw new Error('unwrap: bad AK length');
  if (!equalBytes(deriveIdentity(AK).sigPk, ownerSigPk)) throw new Error('unwrap: key check failed');
  return AK;
}

// ───────────────────────── epochs ─────────────────────────

export const MAX_MEMBERS = 32;
export const MAX_NAME = 64;

// Control characters and bidi overrides/isolates would let a name spoof the UI.
// Also format characters (zero-width, tags, bidi) and the blank-looking Hangul / braille fillers.
const BAD_NAME_CHARS = /[\p{Cc}\p{Cf}\p{Cs}\u061c\u2028\u2029\u115f\u1160\u3164\uffa0\u2800]/u;
const VISIBLE = /[\p{L}\p{N}\p{P}\p{S}]/u;

/** Group names: 1..MAX_NAME code points, no control / bidi characters, not only whitespace. */
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

export interface Descriptor {
  v: 1;
  conv: string;
  e: number;
  members: string[];
  prev: string | null;
  by: string;
  ts: number;
  name?: string;
}

export interface EpochKeys {
  rk: Bytes;
  mk: Bytes;
  kc: Bytes;
}

export function epochKeys(EK: Bytes, conv: Bytes, e: number): EpochKeys {
  if (EK.length !== 32 || conv.length !== 16) throw new Error('bad epoch key material');
  return {
    rk: HKDF(EK, conv, enc('segv.sh/v1/ep/route', u32(e))),
    mk: HKDF(EK, conv, enc('segv.sh/v1/ep/msg', u32(e))),
    kc: HKDF(EK, conv, enc('segv.sh/v1/ep/commit', u32(e))),
  };
}

export const msgTag = (rk: Bytes, i: number, n: number): Bytes => trunc16(HMAC(rk, concat(utf8('m'), u16(i), u32(n))));
export const claimTag = (rk: Bytes): Bytes => trunc16(HMAC(rk, utf8('c')));

export function makeDescriptor(d: Omit<Descriptor, 'v'>): string {
  const out: Descriptor = { v: 1, conv: d.conv, e: d.e, members: d.members, prev: d.prev, by: d.by, ts: d.ts };
  if (d.name !== undefined) out.name = d.name;
  const text = JSON.stringify(out);
  parseDescriptor(text); // never emit something peers would reject
  return text;
}

export function parseDescriptor(text: string): Descriptor {
  const raw = JSON.parse(text) as unknown;
  if (!isObj(raw) || raw.v !== 1) throw new Error('descriptor: bad version');
  b64uLen(raw.conv, 16);
  if (!Number.isInteger(raw.e) || (raw.e as number) < 0 || (raw.e as number) > 0xffffffff) throw new Error('descriptor: bad e');
  if (!Array.isArray(raw.members) || raw.members.length < 1 || raw.members.length > MAX_MEMBERS)
    throw new Error('descriptor: bad members');
  for (const m of raw.members) b64uLen(m, 16);
  if (new Set(raw.members).size !== raw.members.length) throw new Error('descriptor: duplicate member');
  if (raw.prev !== null) b64uLen(raw.prev, 32);
  if (raw.e === 0 && raw.prev !== null) throw new Error('descriptor: e=0 must have prev=null');
  if ((raw.e as number) > 0 && raw.prev === null) throw new Error('descriptor: missing prev');
  b64uLen(raw.by, 16);
  if (!raw.members.includes(raw.by)) throw new Error('descriptor: committer not a member');
  if (!isTs(raw.ts)) throw new Error('descriptor: bad ts');
  if (raw.name !== undefined && !validName(raw.name)) throw new Error('descriptor: bad name');
  return raw as unknown as Descriptor;
}

export const signDescriptor = (dText: string, kc: Bytes, sigSk: Bytes): Bytes =>
  sign(enc('segv.sh/v1/epoch', utf8(dText), kc), sigSk);
export const verifyDescriptorSig = (dText: string, kc: Bytes, dsig: Bytes, sigPk: Bytes): boolean =>
  verify(dsig, enc('segv.sh/v1/epoch', utf8(dText), kc), sigPk);

// ───────────────────────── invites (kind 3) ─────────────────────────

export const INV_BODY_LENS = INV_CLASSES.map((c) => 32 + KEM_CT_LEN + NONCE_LEN + c + TAG_LEN);

export interface Row {
  kind: number;
  tag: Bytes;
  body: Bytes;
}

export interface Recipient {
  kemPk: Bytes;
  scanPk: Bytes;
}

export function makeInvite(to: Recipient, dText: string, EK: Bytes, dsig: Bytes): Row {
  const P = enc(utf8(dText), EK, dsig);
  const ephSk = x25519.utils.randomSecretKey();
  const eph = x25519.getPublicKey(ephSk);
  const s = x25519.getSharedSecret(ephSk, to.scanPk);
  const vk = HKDF(s, concat(eph, to.scanPk), 'segv.sh/v1/inv/view');
  const check = trunc16(HMAC(vk, utf8('check')));
  const { cipherText: kct, sharedSecret: ss } = xwing.encapsulate(to.kemPk);
  const k = HKDF(concat(ss, vk), H(kct), 'segv.sh/v1/inv/key');
  const box = aeadSeal(k, pad(P, INV_CLASSES), enc('segv.sh/v1/inv', eph, check));
  return { kind: 3, tag: check, body: concat(eph, kct, box) };
}

/**
 * Cheap detection step: one X25519. Returns the view key when the row is addressed to us.
 * `dh` lets callers plug in a faster (WebCrypto) X25519; it must return the raw shared secret.
 */
export function inviteViewKey(
  scanSk: Bytes,
  scanPk: Bytes,
  row: { tag: Bytes; body: Bytes },
  dh: (sk: Bytes, pk: Bytes) => Bytes = x25519.getSharedSecret,
): Bytes | null {
  if (row.body.length < 32 || row.tag.length !== 16) return null;
  const eph = row.body.subarray(0, 32);
  let s: Bytes;
  try {
    s = dh(scanSk, eph);
  } catch {
    return null;
  }
  const vk = HKDF(s, concat(eph, scanPk), 'segv.sh/v1/inv/view');
  return equalBytes(trunc16(HMAC(vk, utf8('check'))), row.tag) ? vk : null;
}

export function openInvite(kemSk: Bytes, vk: Bytes, row: { tag: Bytes; body: Bytes }): { dText: string; EK: Bytes; dsig: Bytes } {
  if (!INV_BODY_LENS.includes(row.body.length)) throw new Error('invite: bad length');
  const eph = row.body.subarray(0, 32);
  const kct = row.body.subarray(32, 32 + KEM_CT_LEN);
  const ss = xwing.decapsulate(kct, kemSk);
  const k = HKDF(concat(ss, vk), H(kct), 'segv.sh/v1/inv/key');
  const P = unpad(aeadOpen(k, row.body.subarray(32 + KEM_CT_LEN), enc('segv.sh/v1/inv', eph, row.tag)));
  const [d, EK, dsig] = dec(P, 3);
  if (EK.length !== 32 || dsig.length !== 64) throw new Error('invite: bad payload');
  return { dText: fromUtf8(d), EK: EK.slice(), dsig: dsig.slice() };
}

// ───────────────────────── claims & messages (kind 4) ─────────────────────────

export const MSG_BODY_LENS = MSG_CLASSES.map((c) => NONCE_LEN + c + TAG_LEN);

const claimSigMsg = (tag: Bytes, dText: string, dsig: Bytes): Bytes => enc('segv.sh/v1/claim-sig', tag, utf8(dText), dsig);

/**
 * The claim for epoch e+1, readable by every member of epoch e. `dsig` binds the descriptor to the new
 * EK (only members of e+1 can check it); `csig` lets every member of e check who made the change.
 */
export function makeClaim(mkPrev: Bytes, rkPrev: Bytes, nextDText: string, nextDsig: Bytes, sigSk: Bytes): Row {
  const tag = claimTag(rkPrev);
  const csig = sign(claimSigMsg(tag, nextDText, nextDsig), sigSk);
  const C = enc(utf8(nextDText), nextDsig, csig);
  return { kind: 4, tag, body: aeadSeal(mkPrev, pad(C, MSG_CLASSES), enc('segv.sh/v1/claim', tag)) };
}

export function openClaim(mkPrev: Bytes, row: { tag: Bytes; body: Bytes }): { dText: string; dsig: Bytes; csig: Bytes } {
  const [d, dsig, csig] = dec(unpad(aeadOpen(mkPrev, row.body, enc('segv.sh/v1/claim', row.tag))), 3);
  if (dsig.length !== 64 || csig.length !== 64) throw new Error('claim: bad signature length');
  return { dText: fromUtf8(d), dsig: dsig.slice(), csig: csig.slice() };
}

export const verifyClaimSig = (tag: Bytes, dText: string, dsig: Bytes, csig: Bytes, sigPk: Bytes): boolean =>
  verify(csig, claimSigMsg(tag, dText, dsig), sigPk);

export interface ImageRef {
  id: string;
  k: string;
  mime: string;
  w: number;
  h: number;
}

export interface Payload {
  v: 1;
  t: 'text' | 'image' | 'leave';
  conv: string;
  e: number;
  from: string;
  n: number;
  ts: number;
  text?: string;
  img?: ImageRef;
  head: { seq: number; h: string };
}

export function makeMessage(mk: Bytes, tag: Bytes, payload: Payload, sigSk: Bytes): Row {
  const pBytes = utf8(JSON.stringify(payload));
  const psig = sign(enc('segv.sh/v1/msg-sig', tag, pBytes), sigSk);
  return { kind: 4, tag, body: aeadSeal(mk, pad(enc(pBytes, psig), MSG_CLASSES), enc('segv.sh/v1/msg', tag)) };
}

/** Decrypts a message row; the caller verifies the signature once it knows the sender. */
export function openMessage(mk: Bytes, row: { tag: Bytes; body: Bytes }): { text: string; payload: Payload; psig: Bytes } {
  const [p, psig] = dec(unpad(aeadOpen(mk, row.body, enc('segv.sh/v1/msg', row.tag))), 2);
  const text = fromUtf8(p);
  const payload = JSON.parse(text) as Payload;
  if (!isObj(payload) || payload.v !== 1) throw new Error('message: bad version');
  return { text, payload, psig: psig.slice() };
}

export const verifyMessageSig = (tag: Bytes, payloadText: string, psig: Bytes, sigPk: Bytes): boolean =>
  verify(psig, enc('segv.sh/v1/msg-sig', tag, utf8(payloadText)), sigPk);

const isU32 = (x: unknown): x is number => Number.isInteger(x) && (x as number) >= 0 && (x as number) <= 0xffffffff;
function isB64uLen(s: unknown, len: number): boolean {
  try {
    b64uLen(s, len);
    return true;
  } catch {
    return false;
  }
}

export function validPayload(p: Payload): boolean {
  if (!isObj(p)) return false;
  if (p.t !== 'text' && p.t !== 'image' && p.t !== 'leave') return false;
  if (!isB64uLen(p.conv, 16) || !isB64uLen(p.from, 16)) return false;
  if (!isU32(p.e) || !isU32(p.n) || !isTs(p.ts)) return false;
  if (!isObj(p.head) || !isTs(p.head.seq) || !isB64uLen(p.head.h, 32)) return false;
  if (p.t === 'text' && (typeof p.text !== 'string' || p.text.length === 0)) return false;
  if (p.t === 'image') {
    const i = p.img;
    if (!isObj(i) || typeof i.mime !== 'string') return false;
    // img.id ends up in a fetch URL (/api/blob/:id) and img.k is an AEAD key: exact shapes only.
    if (!isB64uLen(i.id, 32) || !isB64uLen(i.k, 32)) return false;
    if (i.mime !== 'image/webp' && i.mime !== 'image/jpeg') return false;
    if (!Number.isInteger(i.w) || !Number.isInteger(i.h) || i.w <= 0 || i.h <= 0 || i.w > 8192 || i.h > 8192) return false;
  }
  return true;
}

// ───────────────────────── blobs ─────────────────────────

export const BLOB_MAX = 12 * 1024 * 1024;

export function encryptBlob(data: Bytes): { blob: Bytes; id: string; key: Bytes } {
  const key = random(32);
  const blob = aeadSeal(key, padme(data), utf8('segv.sh/v1/blob'));
  return { blob, id: b64u(H(blob)), key };
}

export function decryptBlob(blob: Bytes, id: string, key: Bytes): Bytes {
  if (b64u(H(blob)) !== id) throw new Error('blob: hash mismatch');
  return unpad(aeadOpen(key, blob, utf8('segv.sh/v1/blob')));
}

// ───────────────────────── log ─────────────────────────

export const ZERO32 = new Uint8Array(32);

export function rowHash(prev: Bytes, seq: number, kind: number, tag: Bytes, body: Bytes, ts: number): Bytes {
  return H(enc('segv.sh/v1/log', prev, u64(seq), u8(kind), tag, body, u64(ts)));
}

export const userTag = (uid: Bytes): Bytes => trunc16(H(enc('segv.sh/v1/tag/user', uid)));
export const wrapTag = (record: string): Bytes => trunc16(H(enc('segv.sh/v1/tag/wrap', utf8(record))));

// ───────────────────────── proof of work ─────────────────────────

export type PowScope = 'register' | 'wrap' | 'append' | 'blob';
export const POW_WINDOW_MS = 600_000;

/**
 * Required difficulty for a request of `bytes` bytes: work grows linearly with what the request makes
 * everyone store (append: every client downloads every row) — one extra bit per doubling above 4 KiB
 * for appends and above 1 MiB for blobs.
 */
export function powDifficulty(scope: PowScope, base: number, bytes: number): number {
  if (!Number.isSafeInteger(bytes) || bytes < 0) throw new Error('powDifficulty: bad size');
  const unit = scope === 'append' ? 4096 : scope === 'blob' ? 1 << 20 : 0;
  if (!unit || bytes <= unit) return base;
  return base + Math.ceil(Math.log2(bytes / unit));
}

/** `bodyDigest` = H(request body bytes). For blob uploads it is the blob id (raw 32 bytes). */
export const powPre = (scope: PowScope, window: number, bodyDigest: Bytes): Bytes =>
  H(enc('segv.sh/v1/pow', scope, u32(window), bodyDigest));

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

/** Finds a nonce. Yields to the event loop every `chunk` hashes so the UI stays responsive. */
export async function powSolve(pre: Bytes, difficulty: number, chunk = 4096): Promise<number> {
  const buf = new Uint8Array(pre.length + 8);
  buf.set(pre);
  const dv = new DataView(buf.buffer);
  for (let nonce = 0; nonce <= 0xffffffff; nonce++) {
    dv.setUint32(pre.length + 4, nonce); // high 32 bits stay zero (u64 big-endian)
    if (leadingZeroBits(sha256(buf)) >= difficulty) return nonce;
    if (nonce % chunk === chunk - 1) await new Promise((r) => setTimeout(r, 0));
  }
  throw new Error('pow: nonce space exhausted');
}
