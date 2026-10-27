/** Test Worker entry: the production host pinning + API + LogDO without Qwik SSR (non-/api paths -> 404). */
import { handleApi } from "../../src/server/api";
import { pinHost } from "../../src/server/hosts";
import { handleApiV2, stampV2 } from "../../src/server/v2/api";

export { LogDO } from "../../src/server/log-do";
export { ShardDO } from "../../src/server/v2/shard-do";
export { BlobRegDO } from "../../src/server/v2/blobreg-do";
export { InboxDO } from "../../src/server/v2/inbox-do";
export { RealtimeDO } from "../../src/server/v2/realtime-do";
export { CheckpointDO } from "../../src/server/v2/ckpt-do";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pinned = pinHost(env, url);
    if (pinned) return url.pathname.startsWith("/api/v2/") ? stampV2(pinned, url) : pinned;
    if (url.pathname.startsWith("/api/v2/")) return handleApiV2(request, env, ctx, url);
    if (url.pathname.startsWith("/api/")) return handleApi(request, env, ctx, url);
    return new Response("not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
