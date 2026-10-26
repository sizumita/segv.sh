/** Test Worker entry: the production host pinning + API + LogDO without Qwik SSR (non-/api paths -> 404). */
import { handleApi } from "../../src/server/api";
import { pinHost } from "../../src/server/hosts";

export { LogDO } from "../../src/server/log-do";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pinned = pinHost(env, url);
    if (pinned) return pinned;
    if (url.pathname.startsWith("/api/")) return handleApi(request, env, ctx, url);
    return new Response("not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
