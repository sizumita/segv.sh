/** Response / request helpers for the /api surface. */

/** Thrown by handlers; turned into `{error}` JSON with this status by handleApi(). */
export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly headers?: Record<string, string>,
  ) {
    super(message);
  }
}

/** Headers on every /api response. */
export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

/** HSTS (2 years, subdomains). Only ever sent on https responses (browsers ignore it over http anyway). */
export const HSTS = "max-age=63072000; includeSubDomains";

/** Adds the per-request headers every /api response carries (HSTS when the request came over https). */
export function finalize(res: Response, url: URL): Response {
  // 101 = WebSocket upgrade from the Durable Object: immutable headers, and HSTS is meaningless there.
  if (url.protocol !== "https:" || res.status === 101) return res;
  try {
    res.headers.set("strict-transport-security", HSTS);
    return res;
  } catch {
    const copy = new Response(res.body, res);
    copy.headers.set("strict-transport-security", HSTS);
    return copy;
  }
}

export function json(data: unknown, status = 200, extra?: Record<string, string>): Response {
  const headers = new Headers({
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...SECURITY_HEADERS,
  });
  if (extra) for (const [k, v] of Object.entries(extra)) headers.set(k, v);
  return new Response(JSON.stringify(data), { status, headers });
}

export const errorResponse = (status: number, error: string, extra?: Record<string, string>): Response =>
  json({ error }, status, extra);

/** Parses a Content-Length header. null when absent; HttpError(400) when malformed. */
export function contentLength(request: Request): number | null {
  const cl = request.headers.get("content-length");
  if (cl === null) return null;
  if (!/^\d{1,15}$/.test(cl)) throw new HttpError(400, "invalid content-length");
  return Number(cl);
}

/**
 * Reads the whole request body, enforcing `max` both from Content-Length (before reading) and from the
 * bytes actually received (while reading).
 */
export async function readBody(request: Request, max: number): Promise<Uint8Array> {
  const declared = contentLength(request);
  if (declared !== null && declared > max) throw new HttpError(413, "request body too large");
  if (request.body === null) return new Uint8Array(0);
  const reader = (request.body as ReadableStream<Uint8Array>).getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.byteLength;
    if (n > max) {
      await reader.cancel().catch(() => {});
      throw new HttpError(413, "request body too large");
    }
    chunks.push(value);
  }
  if (declared !== null && n !== declared) throw new HttpError(400, "body length does not match content-length");
  if (chunks.length === 1) return chunks[0];
  const out = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.byteLength;
  }
  return out;
}

const td = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

/** UTF-8 + JSON.parse; requires a plain object. Never echoes parser messages (they quote input). */
export function parseJsonObject(bytes: Uint8Array): Record<string, unknown> {
  let v: unknown;
  try {
    v = JSON.parse(td.decode(bytes));
  } catch {
    throw new HttpError(400, "invalid JSON");
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new HttpError(400, "expected a JSON object");
  return v as Record<string, unknown>;
}

/** Requires `o` to have exactly these keys (fail closed on unknown fields). */
export function exactKeys(o: unknown, keys: readonly string[], what: string): Record<string, unknown> {
  if (typeof o !== "object" || o === null || Array.isArray(o)) throw new HttpError(400, `${what}: expected an object`);
  const got = Object.keys(o);
  if (got.length !== keys.length || !keys.every((k) => Object.prototype.hasOwnProperty.call(o, k))) {
    throw new HttpError(400, `${what}: expected exactly {${keys.join(", ")}}`);
  }
  return o as Record<string, unknown>;
}

/** Integer query parameter in [min, max]; `dflt` when absent. */
export function intParam(v: string | null, dflt: number, min: number, max: number, name: string): number {
  if (v === null) return dflt;
  if (!/^\d{1,16}$/.test(v)) throw new HttpError(400, `invalid ${name}`);
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < min || n > max) throw new HttpError(400, `invalid ${name}`);
  return n;
}

/** WebCrypto's BufferSource typing rejects Uint8Array<ArrayBufferLike>; our arrays never use SharedArrayBuffer. */
const bs = (b: Uint8Array): Uint8Array<ArrayBuffer> => b as Uint8Array<ArrayBuffer>;

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bs(data)));
}

/** Ed25519 verification via WebCrypto (native; noble is too slow for the Workers CPU budget). */
export async function ed25519Verify(pk: Uint8Array, sig: Uint8Array, msg: Uint8Array): Promise<boolean> {
  if (pk.length !== 32 || sig.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("raw", bs(pk), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, bs(sig), bs(msg));
  } catch {
    return false;
  }
}

export const errMsg = (e: unknown): string => (e instanceof Error ? `${e.name}: ${e.message}` : String(e));

/**
 * An error message that is safe to log: base64url / hex runs (ids, uids, blob hashes, credential ids) and
 * IP addresses are redacted, and the length is capped. Never log request bodies, URLs or client addresses.
 */
export function logErr(e: unknown): string {
  return errMsg(e)
    // ids are long base64url / hex runs: they contain digits or mix cases (unlike SQLITE_CONSTRAINT_... names)
    .replace(/[A-Za-z0-9_+/=-]{16,}/g, (t) => (/\d/.test(t) || (/[a-z]/.test(t) && /[A-Z]/.test(t)) ? "<redacted>" : t))
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, "<ip>")
    .replace(/\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b/gi, "<ip>")
    .slice(0, 300);
}

/** Concatenates byte chunks and streams into one stream (pull-based: nothing is buffered). */
export function joinStreams(parts: (Uint8Array | ReadableStream<Uint8Array>)[]): ReadableStream<Uint8Array> {
  let i = 0;
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  return new ReadableStream<Uint8Array>({
    async pull(ctrl) {
      for (;;) {
        if (reader) {
          const { done, value } = await reader.read();
          if (!done) {
            ctrl.enqueue(value);
            return;
          }
          reader = null;
          i++;
          continue;
        }
        if (i >= parts.length) {
          ctrl.close();
          return;
        }
        const p = parts[i];
        if (p instanceof Uint8Array) {
          i++;
          ctrl.enqueue(p);
          return;
        }
        reader = p.getReader();
      }
    },
    async cancel(reason) {
      await reader?.cancel(reason);
      for (const p of parts.slice(i + 1)) if (!(p instanceof Uint8Array)) await p.cancel(reason).catch(() => {});
    },
  });
}
