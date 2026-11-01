/**
 * Test Worker entry: the production host pinning + association files + API + Durable Objects without Qwik SSR
 * (other paths -> 404).
 */
import { handleApi, stampResponse } from "../src/api";
import { pinHost } from "../src/hosts";
import { wellKnown } from "../src/well-known";

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
    const isApi = url.pathname.startsWith("/api/");
    if (pinned) return isApi ? stampResponse(pinned, request, env, url) : pinned;
    const wellKnownFile = wellKnown(request, env, url);
    if (wellKnownFile) return wellKnownFile;
    if (isApi) return handleApi(request, env, ctx, url);
    return new Response("not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
