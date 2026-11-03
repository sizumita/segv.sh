/**
 * Test Worker entry: the production host pinning + association files + API + Durable Objects without Qwik SSR
 * (other paths -> 404).
 */
import { handleApi, stampResponse } from "../src/api";
import { pushCleanup, pushQueue } from "../src/push";
import { pinHost } from "../src/hosts";
import { wellKnown } from "../src/well-known";

export { ShardDO } from "../src/shard-do";
export { BlobRegDO } from "../src/blobreg-do";
export { DirSeqDO } from "../src/dirseq-do";
export { InboxDO } from "../src/inbox-do";
export { ConnDO } from "../src/conn-do";
export { FeedDO } from "../src/feed-do";
export { CheckpointDO } from "../src/ckpt-do";
export { BellDO } from "../src/bell-do";
export { QuietDO } from "../src/quiet-do";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pinned = pinHost(env, url);
    const isApi = url.pathname.startsWith("/api/");
    if (pinned) return isApi ? stampResponse(pinned, request, env, url) : pinned;
    const wellKnownFile = wellKnown(request, env, url);
    if (wellKnownFile) return wellKnownFile;
    if (isApi) return handleApi(request, env, ctx, url);
    return new Response("not found", { status: 404 });
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
