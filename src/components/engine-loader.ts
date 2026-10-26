// Browser-only access to the Engine singleton. Never call this during SSR.
//
// The real engine lives in '~/client/engine' (imported only dynamically, so it never reaches the
// server bundle and only loads after the page is interactive). In DEV, `?mock` in the URL swaps in
// the in-memory mock (src/client/mock-engine.ts); `import.meta.env.DEV` is statically false in
// production builds, so that branch and the mock module are dropped from the bundle.
import type { Engine } from "~/client/types";

let pending: Promise<Engine> | undefined;

async function pick(): Promise<Engine> {
  // Statically true in the SSR bundle: the engine (and its crypto deps) never enter it.
  if (import.meta.env.SSR || typeof window === "undefined") {
    throw new Error("engine is browser-only");
  }
  if (import.meta.env.DEV && new URLSearchParams(location.search).has("mock")) {
    const { getMockEngine } = await import("~/client/mock-engine");
    return getMockEngine();
  }
  const { getEngine } = await import("./real-engine");
  return getEngine();
}

export function loadEngine(): Promise<Engine> {
  pending ??= pick().catch((e: unknown) => {
    pending = undefined; // allow a retry (e.g. a chunk failed to download)
    throw e;
  });
  return pending;
}
