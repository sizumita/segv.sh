/*
 * Cloudflare Worker entry (production). Built by Vite (Qwik SSR build) -> server/entry.cloudflare-workers.js,
 * which wrangler.jsonc "main" points to.
 *
 * Order: host pinning (APP_HOSTS), then API routes (plain fetch, incl. WebSocket upgrade -> Durable Object),
 * then Qwik Router SSR. Everything under /api/ is answered by handleApi (src/server/api.ts) and never
 * reaches Qwik.
 */
import {
  createQwikRouter,
  type PlatformCloudflarePages,
} from "@qwik.dev/router/middleware/cloudflare-pages";
import render from "./entry.ssr";
import { handleApi } from "./server/api";
import { pinHost } from "./server/hosts";

// Durable Object classes must be exported from the Worker's main module.
// LogDO = the single sequencer of the public hash-chained log (env.LOG.getByName("global")).
export { LogDO } from "./server/log-do";

export interface PlatformCloudflareWorkers extends PlatformCloudflarePages {
  env: Env;
  ctx: ExecutionContext;
}

declare global {
  // Types `requestEvent.platform` in routeLoader$/routeAction$/server$/onRequest
  type QwikRouterPlatform = PlatformCloudflareWorkers;
}

const qwikRouter = createQwikRouter({ render });
// Qwik types ASSETS.fetch as sync; workerd's Fetcher returns a Promise (runtime is fine).
type QwikEnv = Parameters<typeof qwikRouter>[1];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    // The passkey RP ID is the hostname: never serve the app (or the log) on a non-canonical host.
    const pinned = pinHost(env, url);
    if (pinned) return pinned;
    if (url.pathname.startsWith("/api/")) {
      return handleApi(request, env, ctx, url);
    }
    return qwikRouter(request, env as unknown as QwikEnv, ctx);
  },
} satisfies ExportedHandler<Env>;
