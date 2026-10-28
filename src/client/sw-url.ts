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

/** The push Service Worker's registration (scope "/"), registering it first if needed. */
export async function pushServiceWorker(): Promise<ServiceWorkerRegistration> {
  const existing = await navigator.serviceWorker.getRegistration("/");
  if (
    existing &&
    (existing.active ?? existing.waiting ?? existing.installing)?.scriptURL.endsWith(SW_URL)
  )
    return existing;
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
