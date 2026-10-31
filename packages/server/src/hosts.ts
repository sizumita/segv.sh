/**
 * Host pinning (wrangler var APP_HOSTS, comma-separated hostnames, first = canonical).
 *
 * The passkey RP ID is the page hostname and every PRF output is bound to it (docs/DESIGN.md §1.6), so the
 * app must only ever run on its canonical host(s): a registration on any other hostname that reaches the
 * production log would create passkeys that stop working once that hostname goes away.
 * Unknown hosts get a 308 to https://<canonical><path> (pages) or 421 Misdirected Request (/api/*).
 * An empty / missing APP_HOSTS disables the check.
 */
import { errorResponse } from "./http";

export function appHosts(env: Env): string[] {
  const raw = (env as unknown as Record<string, unknown>).APP_HOSTS;
  if (typeof raw !== "string") return [];
  return raw
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h !== "");
}

/** null when `url` is on an allowed host; otherwise the response to send instead. */
export function pinHost(env: Env, url: URL): Response | null {
  const hosts = appHosts(env);
  if (hosts.length === 0 || hosts.includes(url.hostname.toLowerCase())) return null;
  if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
    return errorResponse(421, `misdirected request: this service only answers on ${hosts[0]}`);
  }
  return new Response(null, {
    status: 308,
    headers: { location: `https://${hosts[0]}${url.pathname}${url.search}`, "cache-control": "no-store" },
  });
}
