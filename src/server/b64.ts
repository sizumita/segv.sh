/**
 * base64url (no padding) for the Worker / Durable Object.
 *
 * Byte-for-byte identical to proto.b64u / proto.fromB64u, but uses the native
 * Uint8Array.prototype.toBase64 / Uint8Array.fromBase64 when the runtime has them (workerd does):
 * feed pages and realtime frames carry megabytes of row bodies, and the JS fallback is
 * far too slow for the Workers CPU budget.
 */
import { b64u as jsEncode, fromB64u as jsDecode } from "../lib/proto";

type ToB64 = (opts: { alphabet: "base64url"; omitPadding: boolean }) => string;
type FromB64 = (s: string, opts: { alphabet: "base64url"; lastChunkHandling: "loose" }) => Uint8Array;

const nativeTo = (Uint8Array.prototype as unknown as { toBase64?: ToB64 }).toBase64;
const nativeFrom = (Uint8Array as unknown as { fromBase64?: FromB64 }).fromBase64;
const HAS_NATIVE = typeof nativeTo === "function" && typeof nativeFrom === "function";

const B64U_RE = /^[A-Za-z0-9_-]*$/;

export function enc64(b: Uint8Array): string {
  return HAS_NATIVE ? nativeTo!.call(b, { alphabet: "base64url", omitPadding: true }) : jsEncode(b);
}

/**
 * Strict decode: base64url alphabet only, no padding, no whitespace, canonical trailing bits.
 * Throws on anything proto.fromB64u would reject. The result never shares a larger buffer.
 */
export function dec64(s: unknown): Uint8Array {
  if (typeof s !== "string" || s.length % 4 === 1 || !B64U_RE.test(s)) throw new Error("bad base64url");
  if (!HAS_NATIVE) return jsDecode(s).slice();
  const out = nativeFrom!.call(Uint8Array, s, { alphabet: "base64url", lastChunkHandling: "loose" });
  // "loose" ignores non-zero leftover bits; re-encoding exposes non-canonical input.
  if (nativeTo!.call(out, { alphabet: "base64url", omitPadding: true }) !== s) throw new Error("bad base64url");
  return out;
}

/** Number of base64url characters (no padding) for `n` bytes. */
export const b64Len = (n: number): number => Math.ceil((n * 4) / 3);
