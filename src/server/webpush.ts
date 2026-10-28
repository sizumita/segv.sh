/**
 * Web Push sending primitives for PushDO (docs/PROTOCOL.md §9.8 "Sending a push"): the VAPID key and its JWT
 * (RFC 8292, ES256), the message encryption to a subscription (RFC 8291, aes128gcm), and the payload.
 *
 * The elliptic-curve parts use noble (P-256), so the encryption is deterministic under a fixed salt and key pair,
 * which the tests check against RFC 8291 Appendix A. Payloads are tiny (one record), so the pure-JS AES-GCM and
 * HMAC cost nothing next to the push request itself.
 */
import { gcm } from "@noble/ciphers/aes.js";
import { p256 } from "@noble/curves/nist.js";
import { HMAC, b64u, concat, fromB64u, random, utf8, type Bytes } from "../lib/proto";

/** The order n of P-256. */
const N = p256.Point.Fn.ORDER;

const bigOf = (b: Bytes): bigint => {
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  return x;
};

/** A VAPID_SK value: 32-byte big-endian P-256 scalar d (b64u, surrounding whitespace allowed) with 1 ≤ d < n, else null. */
export function parseVapidKey(s: string): Uint8Array | null {
  if (typeof s !== "string") return null;
  let d: Bytes;
  try {
    d = fromB64u(s.trim());
  } catch {
    return null;
  }
  if (d.length !== 32) return null;
  const x = bigOf(d);
  return x >= 1n && x < N ? Uint8Array.from(d) : null;
}

/** [d]G, 65 bytes uncompressed (0x04 ‖ x ‖ y). */
export function vapidPublicKey(d: Uint8Array): Uint8Array {
  return p256.getPublicKey(d, false);
}

/** True iff b is a 65-byte uncompressed P-256 point on the curve (not the point at infinity). */
export function isP256Point(b: Uint8Array): boolean {
  if (!(b instanceof Uint8Array) || b.length !== 65 || b[0] !== 0x04) return false;
  try {
    p256.Point.fromBytes(b).assertValidity();
    return true;
  } catch {
    return false;
  }
}

/** A JWT is made for 12 hours (§9.8: `exp` at most 12 hours ahead) and reused until one hour before its `exp`. */
const JWT_LIFETIME_S = 12 * 3600;
const JWT_REUSE_MARGIN_S = 3600;
/** The push hosts' origins are few; the cache is only bounded against a long-lived isolate with many `*.d` hosts. */
const JWT_CACHE_MAX = 64;

const JWT_HEADER = b64u(utf8(JSON.stringify({ typ: "JWT", alg: "ES256" })));

/** RFC 8292 Authorization header values, cached per aud: reuse a JWT for the same aud until one hour before its exp. */
export class VapidSigner {
  readonly publicKey: Uint8Array;
  private readonly k: string;
  private readonly cache = new Map<string, { value: string; exp: number }>();

  constructor(
    private readonly d: Uint8Array,
    private readonly sub: string,
  ) {
    this.publicKey = vapidPublicKey(d);
    this.k = b64u(this.publicKey);
  }

  /** "vapid t=<JWT>, k=<b64u public key>", with `aud` the origin of the endpoint (§9.8). */
  async authorization(aud: string, nowMs: number): Promise<string> {
    const nowS = Math.floor(nowMs / 1000);
    const hit = this.cache.get(aud);
    if (hit && nowS < hit.exp - JWT_REUSE_MARGIN_S) return hit.value;
    const exp = nowS + JWT_LIFETIME_S;
    const signing = `${JWT_HEADER}.${b64u(utf8(JSON.stringify({ aud, exp, sub: this.sub })))}`;
    // ES256: ECDSA P-256 over SHA-256 of the signing input, the raw 64-byte r ‖ s (RFC 7518 §3.4).
    const sig = p256.sign(utf8(signing), this.d, { prehash: true });
    const value = `vapid t=${signing}.${b64u(sig)}, k=${this.k}`;
    if (this.cache.size >= JWT_CACHE_MAX) this.cache.clear();
    this.cache.set(aud, { value, exp });
    return value;
  }
}

/** The most bells one push names (§9.8 `PUSH_BELLS`). */
export const PUSH_BELLS = 4;

/**
 * The payload of §9.8 for the given host (UTF-8): `bells` are the endpoint's `rang` (16 bytes each, newest first), of
 * which the first PUSH_BELLS go in, zero-padded to 64 bytes. Every push therefore has the same length.
 */
export function pushPayload(host: string, bells: readonly Bytes[] = []): Uint8Array {
  const b = new Uint8Array(16 * PUSH_BELLS);
  bells.slice(0, PUSH_BELLS).forEach((x, i) => {
    if (x.length !== 16) throw new RangeError("a bell is 16 bytes");
    b.set(x, 16 * i);
  });
  return utf8(
    `{"web_push":8030,"mutable":true,"notification":{"title":"segv.sh","body":"new messages","navigate":"https://${host}/","tag":"segv","data":{"bells":"${b64u(b)}"}}}`,
  );
}

/** RFC 8291 record size: one record holds the whole payload. */
const RS = 4096;
const TAG = 16;
const ONE = Uint8Array.of(1);

/** HKDF-Expand for a single block (L ≤ 32): HMAC(prk, info ‖ 0x01) truncated (RFC 5869). */
const expand1 = (prk: Bytes, info: Bytes, len: number): Bytes => HMAC(prk, concat(info, ONE)).slice(0, len);

/**
 * RFC 8291 aes128gcm body (header salt ‖ rs = 4096 ‖ idlen = 65 ‖ as_public, then one record), to the subscription's
 * p256dh and auth. `fixed` is for tests only (the RFC 8291 Appendix A salt and application-server private key); a
 * real push uses a fresh key pair and salt every time (§9.8).
 */
export async function encryptPayload(
  plaintext: Uint8Array,
  p256dh: Uint8Array,
  auth: Uint8Array,
  fixed?: { salt: Uint8Array; asPrivate: Uint8Array },
): Promise<Uint8Array> {
  if (!isP256Point(p256dh)) throw new RangeError("p256dh is not a P-256 point");
  if (auth.length !== 16) throw new RangeError("auth is not 16 bytes");
  // One record: plaintext, the last-record delimiter 0x02, and the tag.
  if (plaintext.length + 1 + TAG > RS) throw new RangeError("payload does not fit one record");
  const asPrivate = fixed?.asPrivate ?? p256.utils.randomSecretKey();
  const salt = fixed?.salt ?? random(16);
  if (salt.length !== 16) throw new RangeError("salt is not 16 bytes");
  const asPublic = p256.getPublicKey(asPrivate, false);
  // ecdh_secret is the x-coordinate of the shared point.
  const ecdh = p256.getSharedSecret(asPrivate, p256dh, true).subarray(1);
  const prkKey = HMAC(auth, ecdh);
  const keyInfo = concat(utf8("WebPush: info\0"), p256dh, asPublic);
  const ikm = expand1(prkKey, keyInfo, 32);
  const prk = HMAC(salt, ikm);
  const cek = expand1(prk, utf8("Content-Encoding: aes128gcm\0"), 16);
  const nonce = expand1(prk, utf8("Content-Encoding: nonce\0"), 12);
  const record = gcm(cek, nonce).encrypt(concat(plaintext, Uint8Array.of(2)));
  const header = new Uint8Array(16 + 4 + 1 + 65);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, RS);
  header[20] = 65;
  header.set(asPublic, 21);
  return concat(header, record);
}
