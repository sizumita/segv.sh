/** Test Worker entry: the production host pinning + API + Durable Objects without Qwik SSR (non-/api paths -> 404). */
import { handleApi, stampResponse } from "../src/api";
import { pinHost } from "../src/hosts";

export { ShardDO } from "../src/shard-do";
export { BlobRegDO } from "../src/blobreg-do";
export { InboxDO } from "../src/inbox-do";
export { RealtimeDO } from "../src/realtime-do";
export { CheckpointDO } from "../src/ckpt-do";
export { PushDO } from "../src/push-do";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pinned = pinHost(env, url);
    if (pinned) return url.pathname.startsWith("/api/") ? stampResponse(pinned, url) : pinned;
    if (url.pathname.startsWith("/api/")) return handleApi(request, env, ctx, url);
    return new Response("not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
