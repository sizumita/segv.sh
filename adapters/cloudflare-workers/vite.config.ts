import { cloudflarePagesAdapter } from "@qwik.dev/router/adapters/cloudflare-pages/vite";
import { extendConfig } from "@qwik.dev/router/vite";
import baseConfig from "../../vite.config";

// Qwik ships no Workers-specific adapter: the "cloudflare-workers" starter reuses the
// cloudflare-pages adapter (webworker conditions, noExternal SSR bundle into ./server).
export default extendConfig(baseConfig, () => {
  return {
    build: {
      ssr: true,
      rolldownOptions: {
        input: ["src/entry.cloudflare-workers.ts"],
        // workerd built-ins must stay as bare imports (wrangler resolves them)
        external: [/^cloudflare:/],
      },
    },
    plugins: [
      cloudflarePagesAdapter({ functionRoutes: false }),
      {
        // workerd treats every export of the main module as a handler or Durable Object class, and
        // Qwik's optimizer forces preserveEntrySignatures "allow-extension" on SSR builds, which can
        // re-export shared chunks' symbols from the entry ("Incorrect type for map entry ..."). Keep
        // the entry's exports exactly what the source declares: `default` and `LogDO`.
        name: "segv:strict-worker-entry",
        enforce: "post",
        options(opts: Record<string, unknown>) {
          return { ...opts, preserveEntrySignatures: "strict" };
        },
      },
    ],
  };
});
