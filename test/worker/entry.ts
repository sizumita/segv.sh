/** Test Worker entry: the production host pinning + API + Durable Objects without Qwik SSR (non-/api paths -> 404). */
import { handleApi, stampResponse } from "../../src/server/api";
import { pinHost } from "../../src/server/hosts";

export { ShardDO } from "../../src/server/shard-do";
export { BlobRegDO } from "../../src/server/blobreg-do";
export { InboxDO } from "../../src/server/inbox-do";
export { RealtimeDO } from "../../src/server/realtime-do";
export { CheckpointDO } from "../../src/server/ckpt-do";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pinned = pinHost(env, url);
    if (pinned) return url.pathname.startsWith("/api/") ? stampResponse(pinned, url) : pinned;
    if (url.pathname.startsWith("/api/")) return handleApi(request, env, ctx, url);
    return new Response("not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
