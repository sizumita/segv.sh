/*
 * Cloudflare Worker entry (production). Built by Vite (Qwik SSR build) -> server/entry.cloudflare-workers.js,
 * which wrangler.jsonc "main" points to. The API and the Durable Objects come from @segv/server (packages/server).
 *
 * Order: host pinning (APP_HOSTS), then the native apps' association files under /.well-known/, then API routes
 * (plain fetch, incl. WebSocket upgrade -> Durable Object), then Qwik Router SSR. Everything under /api/ is answered
 * by handleApi (packages/server/src/api.ts) and never reaches Qwik.
 */
import {
  createQwikRouter,
  type PlatformCloudflarePages,
} from "@qwik.dev/router/middleware/cloudflare-pages";
import { handleApi, pinHost, pushCleanup, pushQueue, stampResponse, wellKnown } from "@segv/server";
import render from "./entry.ssr";

// Durable Object classes must be exported from the Worker's main module (docs/PROTOCOL.md §9): per-era
// shards and inboxes, the blob registry, realtime WebSockets, checkpoints and the push object.
export {
  ShardDO,
  BlobRegDO,
  DirSeqDO,
  KeyDO,
  InboxDO,
  ConnDO,
  FeedDO,
  CheckpointDO,
  QuietDO,
} from "@segv/server";

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
    const isApi = url.pathname.startsWith("/api/");
    // §10.1: the 421 on /api/* carries x-segv-now (and HSTS, and the CORS headers for an app
    // origin) like every other API response.
    if (pinned) return isApi ? stampResponse(pinned, request, env, url) : pinned;
    // §11.14: the native apps' association files, at the canonical host and without a redirect.
    const wellKnownFile = wellKnown(request, env, url);
    if (wellKnownFile) return wellKnownFile;
    // Every endpoint is under /api/v2/; any other /api/* path is a 404 from the same router (§10.1).
    if (isApi) return handleApi(request, env, ctx, url);
    return qwikRouter(request, env as unknown as QwikEnv, ctx);
  },
  // Pushes due later than a Worker can wait (docs/PROTOCOL.md §9.8 "The Worker's part").
  async queue(batch, env) {
    await pushQueue(batch, env);
  },
  // The daily expiry of push registrations (§9.8 "Expiry").
  async scheduled(_controller, env, ctx) {
    ctx.waitUntil(pushCleanup(env));
  },
} satisfies ExportedHandler<Env>;
