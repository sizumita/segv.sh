import type { RequestHandler } from "@qwik.dev/router";

/**
 * Security headers for every response rendered by Qwik Router (HTML + q-data). `/api/*` is
 * handled before Qwik in src/entry.cloudflare-workers.ts, and static files under /build and
 * /assets come straight from the assets binding (see public/_headers).
 *
 * The per-request nonce goes into sharedMap "@nonce": Qwik Router copies it to
 * serverData.nonce, and the SSR renderer stamps it on every <script>/<link rel=modulepreload>
 * it emits (qwikloader, state, preloader). No other inline script is allowed.
 */
const NONCE = "@nonce"; // RequestEvSharedNonce in @qwik.dev/router

function makeNonce(): string {
  const b = crypto.getRandomValues(new Uint8Array(18));
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s); // 24 chars of [A-Za-z0-9+/], no padding for 18 bytes
}

export const onRequest: RequestHandler = ({ headers, sharedMap, url }) => {
  const nonce = makeNonce();
  sharedMap.set(NONCE, nonce);

  const ws = `${url.protocol === "https:" ? "wss:" : "ws:"}//${url.host}`;
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    // The only stylesheet is /global.css (no inline <style>, no style="" attributes).
    "style-src 'self'",
    "img-src 'self' blob: data:",
    "font-src 'self'",
    // blob: lets the image viewer read back the decrypted image it shows, to hand it to the share sheet.
    `connect-src 'self' ${ws} blob:`,
    "worker-src 'self'",
    "manifest-src 'self'",
    "media-src 'self' blob:",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    // DOM XSS sinks (innerHTML, script.src, eval-like) are disabled outright: the UI renders
    // user content only as text and needs no Trusted Types policy.
    "require-trusted-types-for 'script'",
    // Two policies, each accepting one URL: the inbox Web Worker's (packages/engine/src/inbox-worker-url.ts;
    // §11.5 step 2) and the push Service Worker's (packages/engine/src/sw-url.ts; §11.13).
    "trusted-types segv-worker segv-sw",
  ].join("; ");

  headers.set("Content-Security-Policy", csp);
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Cross-Origin-Opener-Policy", "same-origin");
  headers.set("Cross-Origin-Resource-Policy", "same-origin");
  headers.set(
    "Permissions-Policy",
    [
      "publickey-credentials-get=(self)",
      "publickey-credentials-create=(self)",
      "clipboard-write=(self)",
      "camera=()",
      "microphone=()",
      "geolocation=()",
      "payment=()",
      "usb=()",
      "serial=()",
      "hid=()",
      "bluetooth=()",
      "display-capture=()",
    ].join(", "),
  );
  // HTTPS only from now on (an SSL-stripped page could phish the recovery code). Browsers ignore HSTS
  // over plain http, and local dev (http://localhost) must not be pinned to https.
  if (url.protocol === "https:")
    headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  // The HTML carries a fresh nonce on every request: it must never be served from a cache.
  headers.set("Cache-Control", "no-store");
};
