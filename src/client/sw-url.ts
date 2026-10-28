// Registers the push Service Worker (public/sw.js; docs/PROTOCOL.md §11.13). The CSP requires Trusted Types for
// scripts, and `navigator.serviceWorker.register(url)` is a TrustedScriptURL sink: the one policy for it, `segv-sw`,
// accepts only this URL.
export const SW_URL = "/sw.js";

interface TrustedTypesLike {
  createPolicy(
    name: string,
    rules: { createScriptURL(u: string): string },
  ): { createScriptURL(u: string): unknown };
}

let policy: { createScriptURL(u: string): unknown } | null = null;

/** When `refreshServiceWorker` last asked the browser to check the script (ms). */
let checkedAt = -Infinity;
const CHECK_EVERY_MS = 60_000;

/**
 * Asks the browser to check the registered push Service Worker for a new /sw.js. Browsers check it by themselves only
 * now and then (iOS rarely), so a Service Worker deployed with a new version of the app could go on running the old
 * code for days. The app calls this at every launch and whenever it comes back to the screen, at most once a minute.
 * It registers nothing: a browser without a registration stays without one.
 */
export function refreshServiceWorker(now = Date.now()): void {
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;
  if (now - checkedAt < CHECK_EVERY_MS) return;
  checkedAt = now;
  navigator.serviceWorker
    .getRegistration("/")
    .then((r) => r?.update())
    .catch(() => {});
}

/** The push Service Worker's registration (scope "/"), registering it first if needed. */
export async function pushServiceWorker(): Promise<ServiceWorkerRegistration> {
  const existing = await navigator.serviceWorker.getRegistration("/");
  if (
    existing &&
    (existing.active ?? existing.waiting ?? existing.installing)?.scriptURL.endsWith(SW_URL)
  ) {
    void existing.update().catch(() => {});
    return existing;
  }
  const tt = (globalThis as { trustedTypes?: TrustedTypesLike }).trustedTypes;
  if (tt && !policy) {
    policy = tt.createPolicy("segv-sw", {
      createScriptURL: (u) => {
        if (u !== SW_URL) throw new TypeError("unexpected service worker URL");
        return u;
      },
    });
  }
  const url = policy ? policy.createScriptURL(SW_URL) : SW_URL;
  // updateViaCache "none": the browser checks the script itself on every update, never from its HTTP cache.
  await navigator.serviceWorker.register(url as string | URL, {
    scope: "/",
    updateViaCache: "none",
  });
  return navigator.serviceWorker.ready;
}
