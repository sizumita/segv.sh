/**
 * Server-side shape checks of the signed directory JSON (docs/PROTOCOL-v2.md §1.2, §2.2, §2.4, §10.6).
 * Signatures are checked separately with WebCrypto.
 */
import {
  BUNDLE_KEYS,
  WRAP_KEYS,
  bundleSigMsg,
  fromB64u,
  parseBundle,
  parseWrap,
  wrapSigMsg,
  type User,
  type WrapRecord,
} from "../lib/proto";
import { HttpError, ed25519Verify } from "./http";

/**
 * Signed texts are small: a bundle is ~1.9 KB and a record at most ~4.7 KB (a 1023-byte credential id).
 * Anything larger is not ours.
 */
export const MAX_SIGNED_TEXT = 8 * 1024;

/** Never echoes JSON parser messages (they quote input). */
const detail = (e: unknown): string => (e instanceof Error && !(e instanceof SyntaxError) ? e.message : "malformed JSON");

/**
 * §1.2 canonical form: the keys appear in the spec's order, there are no extra (or duplicate) keys, and
 * `JSON.stringify(JSON.parse(text)) === text` (no whitespace, no alternative number or string spellings).
 */
export function canonical(text: string, keys: readonly string[]): boolean {
  const o = JSON.parse(text) as Record<string, unknown>;
  if (typeof o !== "object" || o === null || Array.isArray(o)) return false;
  const got = Object.keys(o);
  if (got.length !== keys.length || got.some((k, i) => k !== keys[i])) return false;
  return JSON.stringify(o) === text;
}

/**
 * Shape-checks a v2 bundle + signature (not the signature itself, not checkUserKeys): string types, size,
 * canonical JSON in the order {v, uid, handle, sig, kem, ts}, v = 2, uid 16 B, sig 32 B, kem 1216 B, handle
 * `^[a-z0-9_]{3,20}$`, ts a safe non-negative integer, signature 64 B; every b64u value canonical.
 */
export function checkBundleShape(bundle: unknown, sig: unknown): User {
  if (typeof bundle !== "string" || typeof sig !== "string") throw new HttpError(400, "bundle: expected strings");
  if (bundle.length > MAX_SIGNED_TEXT) throw new HttpError(400, "bundle: too large");
  let u: User;
  try {
    u = parseBundle(bundle, sig);
  } catch (e) {
    throw new HttpError(400, `invalid bundle (${detail(e)})`);
  }
  if (!canonical(bundle, BUNDLE_KEYS)) throw new HttpError(400, "invalid bundle (not canonical JSON)");
  return u;
}

/**
 * Shape-checks a v2 wrap record + signature (not the signature itself): string types, size, canonical JSON
 * in the order {v, uid, kind, id, kem, wrap, ts}, v = 2, kind passkey | recovery, uid 16 B, id 1..1023 B
 * (recovery: 16 B), kem 1216 B, wrap 1192 B, ts, signature 64 B; every b64u value canonical.
 */
export function checkRecordShape(record: unknown, sig: unknown): WrapRecord {
  if (typeof record !== "string" || typeof sig !== "string") throw new HttpError(400, "wrap: expected strings");
  if (record.length > MAX_SIGNED_TEXT) throw new HttpError(400, "wrap: too large");
  let w: WrapRecord;
  try {
    w = parseWrap(record, sig);
  } catch (e) {
    throw new HttpError(400, `invalid wrap record (${detail(e)})`);
  }
  if (!canonical(record, WRAP_KEYS)) throw new HttpError(400, "invalid wrap record (not canonical JSON)");
  return w;
}

/** bundleSig over enc("segv.sh/v2/bundle", bundleBytes), via WebCrypto. */
export async function verifyBundleSig(u: User): Promise<boolean> {
  return ed25519Verify(u.sigPk, fromB64u(u.bundleSig), bundleSigMsg(u.bundle));
}

/** recordSig over enc("segv.sh/v2/wrap", recordBytes) under the owner's bundle key, via WebCrypto. */
export async function verifyRecordSig(w: WrapRecord, ownerSigPk: Uint8Array): Promise<boolean> {
  return ed25519Verify(ownerSigPk, fromB64u(w.sig), wrapSigMsg(w.record));
}
