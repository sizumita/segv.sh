/** Server-side validation of log rows (docs/PROTOCOL.md §4.2). */
import {
  INV_BODY_LENS,
  MSG_BODY_LENS,
  bundleSigMsg,
  checkUserKeys,
  fromB64u,
  parseBundle,
  parseWrap,
  utf8,
  wrapSigMsg,
  type User,
  type WrapRecord,
} from "../lib/proto";
import { b64Len, dec64 } from "./b64";
import { HttpError, ed25519Verify, exactKeys } from "./http";
import { BATCH_MAX, BATCH_MAX_KIND4, type AppendRow } from "./types";

/** Signed texts are tiny (a bundle is ~1.9 KB, a record ~3.3 KB); anything larger is not ours. */
const MAX_SIGNED_TEXT = 8 * 1024;

const detail = (e: unknown): string => (e instanceof Error && !(e instanceof SyntaxError) ? e.message : "malformed JSON");

/**
 * The signed JSON must be exactly what JSON.stringify produces for the spec's key order: no unknown or
 * duplicate keys, no whitespace. Everyone (server, D1, every client) therefore reads the same values.
 */
function canonical(text: string, keys: readonly string[]): boolean {
  const o = JSON.parse(text) as Record<string, unknown>;
  const c: Record<string, unknown> = {};
  for (const k of keys) c[k] = o[k];
  return JSON.stringify(c) === text;
}

const BUNDLE_KEYS = ["v", "uid", "handle", "sig", "kem", "scan", "ts"] as const;
const RECORD_KEYS = ["v", "uid", "kind", "id", "kem", "wrap", "ts"] as const;

/** Shape-checks a bundle + signature (not the signature itself). */
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
  // Reject keys that clients would refuse (small-order signing key: WebCrypto's Ed25519 accepts a
  // universal forgery for it; low-order scan key / invalid ML-KEM key: nobody could invite this user).
  try {
    checkUserKeys(u);
  } catch (e) {
    throw new HttpError(400, `invalid bundle (${detail(e)})`);
  }
  return u;
}

/** Shape-checks a wrap record + signature (not the signature itself). */
export function checkRecordShape(record: unknown, sig: unknown): WrapRecord {
  if (typeof record !== "string" || typeof sig !== "string") throw new HttpError(400, "wrap: expected strings");
  if (record.length > MAX_SIGNED_TEXT) throw new HttpError(400, "wrap: too large");
  let w: WrapRecord;
  try {
    w = parseWrap(record, sig);
  } catch (e) {
    throw new HttpError(400, `invalid wrap record (${detail(e)})`);
  }
  if (!canonical(record, RECORD_KEYS)) throw new HttpError(400, "invalid wrap record (not canonical JSON)");
  return w;
}

export async function verifyBundleSig(u: User): Promise<boolean> {
  return ed25519Verify(u.sigPk, fromB64u(u.bundleSig), bundleSigMsg(u.bundle));
}

export async function verifyRecordSig(w: WrapRecord, ownerSigPk: Uint8Array): Promise<boolean> {
  return ed25519Verify(ownerSigPk, fromB64u(w.sig), wrapSigMsg(w.record));
}

/** Server-built row bodies for kinds 1 and 2. */
export const userBody = (u: User): Uint8Array => utf8(JSON.stringify({ bundle: u.bundle, sig: u.bundleSig }));
export const wrapBody = (w: WrapRecord): Uint8Array => utf8(JSON.stringify({ record: w.record, sig: w.sig }));

// ───────────── /api/append rows (kinds 3 and 4) ─────────────

const BODY_LENS: Readonly<Record<number, readonly number[]>> = { 3: INV_BODY_LENS, 4: MSG_BODY_LENS };
const BODY_B64_LENS: Readonly<Record<number, readonly number[]>> = {
  3: INV_BODY_LENS.map(b64Len),
  4: MSG_BODY_LENS.map(b64Len),
};
const TAG_B64_LEN = b64Len(16);

/**
 * Validates `{rows:[{kind, tag, body}]}`: kinds 3|4, 16-byte tags, exact body lengths, ≤ 40 rows, distinct
 * tags, and at most one kind-4 row (a batch is one message, or one claim + its invites, or invites only).
 */
export function checkAppendRows(rows: unknown): AppendRow[] {
  if (!Array.isArray(rows)) throw new HttpError(400, "rows: expected an array");
  if (rows.length < 1 || rows.length > BATCH_MAX) throw new HttpError(400, `rows: expected 1..${BATCH_MAX} rows`);
  const kind4 = rows.filter((r: unknown) => typeof r === "object" && r !== null && (r as { kind?: unknown }).kind === 4).length;
  if (kind4 > BATCH_MAX_KIND4) throw new HttpError(400, `rows: at most ${BATCH_MAX_KIND4} kind-4 row (message or claim) per batch`);
  const tags = new Set<string>();
  return rows.map((r: unknown, i): AppendRow => {
    const o = exactKeys(r, ["kind", "tag", "body"], `rows[${i}]`);
    const { kind, tag, body } = o;
    if (kind !== 3 && kind !== 4) throw new HttpError(400, `rows[${i}]: kind must be 3 or 4`);
    if (typeof tag !== "string" || tag.length !== TAG_B64_LEN) throw new HttpError(400, `rows[${i}]: tag must be 16 bytes`);
    // Cheap length check before decoding up to 23 KB of base64.
    if (typeof body !== "string" || !BODY_B64_LENS[kind].includes(body.length)) {
      throw new HttpError(400, `rows[${i}]: bad body length for kind ${kind}`);
    }
    let t: Uint8Array;
    let b: Uint8Array;
    try {
      t = dec64(tag);
      b = dec64(body);
    } catch {
      throw new HttpError(400, `rows[${i}]: invalid base64url`);
    }
    if (t.length !== 16) throw new HttpError(400, `rows[${i}]: tag must be 16 bytes`);
    if (!BODY_LENS[kind].includes(b.length)) throw new HttpError(400, `rows[${i}]: bad body length for kind ${kind}`);
    if (tags.has(tag)) throw new HttpError(400, `rows[${i}]: duplicate tag in batch`);
    tags.add(tag);
    return { kind, tag: t, body: b };
  });
}
