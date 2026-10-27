/// <reference types="vite/client" />
// Creates the inbox trial-decryption Web Worker (docs/PROTOCOL-v2.md §11.5 step 2; docs/STAGE1-PLAN.md §0.4). The CSP
// requires Trusted Types for scripts and allows one policy, `segv-worker`, which accepts only this worker's URL:
// `new Worker(url)` is a TrustedScriptURL sink. The engine imports this module dynamically (EngineOptions.inboxWorker),
// so the engine's tests, which load no `vite/client` types, never reach the `?worker&url` import.
import workerUrl from "./inbox-worker.ts?worker&url";

interface TrustedTypesLike {
  createPolicy(
    name: string,
    rules: { createScriptURL(u: string): string },
  ): { createScriptURL(u: string): unknown };
}

let policy: { createScriptURL(u: string): unknown } | null = null;

/** A new inbox worker, or null when workers are unavailable. */
export async function createInboxWorker(): Promise<Worker | null> {
  if (typeof Worker === "undefined") return null;
  const tt = (globalThis as { trustedTypes?: TrustedTypesLike }).trustedTypes;
  if (tt && !policy) {
    policy = tt.createPolicy("segv-worker", {
      createScriptURL: (u) => {
        if (u !== workerUrl) throw new TypeError("unexpected worker URL");
        return u;
      },
    });
  }
  const url = policy ? policy.createScriptURL(workerUrl) : workerUrl;
  return new Worker(url as string | URL, { type: "module" });
}
