/** Abuse control: proof of work (docs/PROTOCOL.md §4.3) and per-IP rate limiting. Nothing here is persisted. */
import { HMAC, POW_WINDOW_MS, hex, powCheck, powDifficulty, powPre, utf8, type PowScope } from "../lib/proto";
import { HttpError, logErr } from "./http";

const POW_DEFAULTS: Readonly<Record<PowScope, number>> = { register: 20, wrap: 18, append: 16, blob: 18 };
const POW_VARS: Readonly<Record<PowScope, string>> = {
  register: "POW_REGISTER",
  wrap: "POW_WRAP",
  append: "POW_APPEND",
  blob: "POW_BLOB",
};

/**
 * Base difficulty (leading zero bits) for `scope` from env vars; invalid / missing values fall back to the
 * defaults. This is what GET /api/params reports; the required difficulty grows with the request size
 * (proto.powDifficulty).
 */
export function powBase(env: Env, scope: PowScope): number {
  const raw = (env as unknown as Record<string, unknown>)[POW_VARS[scope]];
  const s = typeof raw === "number" ? String(raw) : raw;
  if (typeof s === "string" && /^\d{1,2}$/.test(s)) {
    const n = Number(s);
    if (n <= 64) return n;
  }
  return POW_DEFAULTS[scope];
}

export const powParams = (env: Env): Record<PowScope, number> => ({
  register: powBase(env, "register"),
  wrap: powBase(env, "wrap"),
  append: powBase(env, "append"),
  blob: powBase(env, "blob"),
});

export const powWindow = (now = Date.now()): number => Math.floor(now / POW_WINDOW_MS);

/**
 * Checks `x-segv-pow: <window>.<nonce>` against `digest` (SHA-256 of the raw request body, or the raw
 * 32-byte blob id). `bytes` is the size of what the request stores (the raw request body; for blobs the
 * declared Content-Length): the required difficulty is proto.powDifficulty(scope, base, bytes).
 * Accepts the current and the previous window. Throws HttpError(403).
 */
export function checkPow(request: Request, env: Env, scope: PowScope, digest: Uint8Array, bytes: number): void {
  const header = request.headers.get("x-segv-pow");
  if (header === null) throw new HttpError(403, "missing proof of work");
  const m = /^(\d{1,12})\.(\d{1,16})$/.exec(header);
  if (!m) throw new HttpError(403, "malformed proof of work");
  const window = Number(m[1]);
  const nonce = Number(m[2]);
  if (!Number.isSafeInteger(nonce)) throw new HttpError(403, "malformed proof of work");
  const current = powWindow();
  if (window !== current && window !== current - 1) throw new HttpError(403, "stale proof of work");
  const need = powDifficulty(scope, powBase(env, scope), bytes);
  if (!powCheck(powPre(scope, window, digest), nonce, need)) {
    throw new HttpError(403, `insufficient proof of work (${need} bits required)`);
  }
}

// ───────────── rate limiting ─────────────

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** Expands an IPv6 address into 8 numeric groups; null if invalid. Handles "::" and an IPv4 tail. */
function ipv6Groups(ip: string): number[] | null {
  let s = ip.toLowerCase();
  const pct = s.indexOf("%");
  if (pct >= 0) s = s.slice(0, pct);
  let v4: number[] = [];
  if (s.includes(".")) {
    // Embedded IPv4 tail ("::ffff:1.2.3.4", "64:ff9b::1.2.3.4"): becomes the last two groups.
    const i = s.lastIndexOf(":");
    const tail = s.slice(i + 1);
    if (i < 0 || !IPV4_RE.test(tail)) return null;
    const o = tail.split(".").map(Number);
    v4 = [(o[0] << 8) | o[1], (o[2] << 8) | o[3]];
    s = s.slice(0, i + 1); // keep a trailing "::", drop a single trailing ":"
    if (!s.endsWith("::")) s = s.slice(0, -1);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const part = (x: string): string[] => (x === "" ? [] : x.split(":"));
  const a = part(halves[0]);
  const b = halves.length === 2 ? part(halves[1]) : [];
  const want = 8 - v4.length;
  const fill = halves.length === 2 ? want - a.length - b.length : 0;
  if (fill < 0 || (halves.length === 2 && fill < 1) || (halves.length === 1 && a.length !== want)) return null;
  const groups = [...a, ...Array<string>(fill).fill("0"), ...b];
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
  return [...groups.map((g) => parseInt(g, 16)), ...v4];
}

/** Rate-limit key for the client: IPv4 address, or the IPv6 /64 prefix. Never stored. */
export function clientKey(request: Request): string {
  const ip = (request.headers.get("cf-connecting-ip") ?? "").trim();
  if (IPV4_RE.test(ip)) return `4:${ip}`;
  if (ip.includes(":")) {
    const g = ipv6Groups(ip);
    if (!g) return "x:invalid";
    // IPv4-mapped (::ffff:a.b.c.d): key on the IPv4 address, not on the shared ::ffff:0:0/96 prefix.
    if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
      return `4:${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
    }
    return `6:${g
      .slice(0, 4)
      .map((x) => x.toString(16))
      .join(":")}::/64`;
  }
  return "x:unknown";
}

/**
 * Applies a Workers rate-limit binding keyed by client IP (/64 for IPv6). Skipped when the binding is
 * absent. Fails closed (503) if the limiter itself errors.
 */
export async function rateLimit(binding: RateLimit | undefined, scope: string, request: Request): Promise<void> {
  if (!binding) return;
  let ok: boolean;
  try {
    ok = (await binding.limit({ key: `${scope}|${clientKey(request)}` })).success;
  } catch (e) {
    console.error(JSON.stringify({ msg: "rate limiter error", scope, error: logErr(e) }));
    throw new HttpError(503, "rate limiter unavailable", { "retry-after": "10" });
  }
  if (!ok) throw new HttpError(429, "rate limited", { "retry-after": "60" });
}

/**
 * Opaque per-client tag (hex, 128 bits) for counting a client's WebSockets: HMAC(key, clientKey). The key is
 * a random secret held by the LogDO, so the tag cannot be reversed to an address by enumeration without it.
 * Tags only live on open sockets (acceptWebSocket tags); they are never written to storage.
 */
export const clientTag = (key: Uint8Array, request: Request): string =>
  hex(HMAC(key, utf8(`ws|${clientKey(request)}`)).subarray(0, 16));
