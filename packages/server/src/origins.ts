/**
 * App origins (wrangler var APP_ORIGINS; docs/PROTOCOL.md §9.7, §10.1 "Cross-origin requests", §10.8, §11.14).
 *
 * APP_ORIGINS lists the origins of the deployment's native apps, comma-separated, and is empty by default. Each entry
 * is the serialization of an origin whose scheme is https, capacitor or tauri: `<scheme>://<host>`, the host lowercase,
 * with no port, path, userinfo, query or fragment. It is checked by hand: `new URL("tauri://localhost").origin` is
 * "null" for schemes that are not special.
 *
 * A request whose Origin header equals an app origin gets the CORS headers below on every /api answer except the 101
 * upgrade (stampResponse, after any caches.default lookup; cachePut never stores them), a preflight from one is
 * answered 204 at the method check, and its realtime socket is accepted. Answers to any other origin carry none of
 * these headers. A value that is not such a list counts as empty: the native apps are refused and nothing else
 * changes, and the setting is logged once per isolate by name, never by value.
 */
import { listVar, logSettingOnce } from "./env";
import { SECURITY_HEADERS } from "./http";

const HOST_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const APP_ORIGIN_RE = new RegExp(`^(?:https|capacitor|tauri)://(${HOST_LABEL}(?:\\.${HOST_LABEL})*)$`);

/** The app origins of an APP_ORIGINS value: [] when it is unset or empty, null when it is not a list of them. */
export function parseAppOrigins(raw: unknown): string[] | null {
  // A host name has at most 253 characters (RFC 1035).
  return listVar(raw, (o) => (APP_ORIGIN_RE.exec(o)?.[1].length ?? 254) <= 253);
}

let cache: { raw: unknown; origins: readonly string[]; bad: boolean } | null = null;

/** The deployment's app origins; none when APP_ORIGINS is unset, empty or invalid (§9.7). */
export function appOrigins(env: Env): readonly string[] {
  const raw = (env as unknown as Record<string, unknown>).APP_ORIGINS;
  if (cache === null || cache.raw !== raw) {
    const origins = parseAppOrigins(raw);
    cache = { raw, origins: origins ?? [], bad: origins === null };
  }
  if (cache.bad) logSettingOnce("native apps are refused: invalid setting", "APP_ORIGINS");
  return cache.origins;
}

/** The request's Origin header when it equals an app origin, else null. */
export function appOriginOf(env: Env, request: Request): string | null {
  const origin = request.headers.get("origin");
  return origin !== null && appOrigins(env).includes(origin) ? origin : null;
}

/** A CORS preflight: OPTIONS with `access-control-request-method`. */
export const isPreflight = (request: Request): boolean =>
  request.method === "OPTIONS" && request.headers.has("access-control-request-method");

/** The headers of every answer to an app origin (§10.1); never stored in caches.default. */
export const CORS_HEADERS = ["access-control-allow-origin", "access-control-expose-headers", "vary"] as const;

export function setCorsHeaders(headers: Headers, origin: string): void {
  headers.set("access-control-allow-origin", origin);
  headers.set("access-control-expose-headers", "x-segv-now, retry-after");
  headers.set("vary", "origin");
}

/**
 * The 204 to a preflight from an app origin (§10.1). The methods and request headers that the clients use; no
 * `access-control-allow-credentials`, since the API has no credentials. stampResponse adds the allow-origin, `vary`
 * and `x-segv-now`.
 */
export function preflightResponse(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "access-control-allow-methods": "GET, POST, PUT",
      "access-control-allow-headers": "content-type, x-segv-pow",
      "access-control-max-age": "600",
      "cache-control": "no-store",
      ...SECURITY_HEADERS,
    },
  });
}
