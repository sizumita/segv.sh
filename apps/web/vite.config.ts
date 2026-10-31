/**
 * Vite+ config of the web app (lint, format and the test projects live in the workspace's vite.config.ts).
 *  - `vp dev`  : Qwik SSR + /api + Durable Objects run inside workerd via @cloudflare/vite-plugin
 *                (Qwik's Node dev-SSR middleware is disabled so requests fall through to the Worker).
 *  - `vp build`: plain Qwik client build; adapters/cloudflare-workers/vite.config.ts extends this
 *                for the server bundle that wrangler deploys.
 */
import { createRequire } from "node:module";
import { cloudflare } from "@cloudflare/vite-plugin";
import { qwikVite } from "@qwik.dev/core/optimizer";
import { qwikRouter } from "@qwik.dev/router/vite";
import type { Plugin } from "vite";
import { defineConfig, lazyPlugins } from "vite-plus";

/** The push Service Worker's entry, in @segv/engine (packages/engine/src/sw-main.ts). */
const SW_ENTRY = createRequire(import.meta.url).resolve("@segv/engine/sw-main");
/** The push Service Worker's own CSP: it loads nothing, and reads rows from this origin's API only (§11.13). */
const SW_CSP = "default-src 'none'; connect-src 'self'";

/** Bundles @segv/engine/sw-main into one classic script (a Service Worker at a fixed URL, /sw.js). */
async function bundleSw(minify: boolean): Promise<string> {
  const { build } = await import("vite");
  const out = await build({
    configFile: false,
    logLevel: "warn",
    build: {
      write: false,
      minify,
      target: "es2022",
      lib: { entry: SW_ENTRY, formats: ["iife"], name: "segvSw", fileName: () => "sw.js" },
    },
  });
  const outputs = (Array.isArray(out) ? out : [out]) as { output: { type: string; code?: string }[] }[];
  const code = outputs.flatMap((o) => o.output).find((o) => o.type === "chunk")?.code;
  if (!code) throw new Error("sw.js: the bundle has no chunk");
  return code;
}

/** Serves /sw.js in dev and emits it at the root of the client build. */
function swPlugin(): Plugin {
  return {
    name: "segv:sw",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url?.split("?")[0] !== "/sw.js") return next();
        bundleSw(false).then(
          (code) => {
            res.setHeader("Content-Type", "application/javascript");
            res.setHeader("Cache-Control", "no-store");
            res.setHeader("Content-Security-Policy", SW_CSP);
            res.end(code);
          },
          (e: unknown) => next(e),
        );
      });
    },
    async generateBundle() {
      if (this.environment?.config.consumer !== "client") return;
      this.emitFile({ type: "asset", fileName: "sw.js", source: await bundleSw(true) });
    },
  };
}

// In workerd dev, Qwik libs must be transformed by the Qwik optimizer instead of being
// pre-bundled by Vite's dep optimizer, otherwise their QRL segments 404 in the browser.
const QWIK_LIBS = [
  "@qwik.dev/core",
  "@qwik.dev/core/internal",
  "@qwik.dev/core/build",
  "@qwik.dev/core/server",
  "@qwik.dev/core/jsx-runtime",
  "@qwik.dev/core/jsx-dev-runtime",
  "@qwik.dev/router",
  "@qwik.dev/router/middleware/cloudflare-pages",
  "@qwik.dev/router/middleware/request-handler",
];

export default defineConfig(({ command, mode }) => {
  const dev = command === "serve" && mode !== "test";
  return {
    environments: dev ? { ssr: { optimizeDeps: { exclude: QWIK_LIBS } } } : undefined,
    // lazyPlugins: factories are skipped by `vp lint` / `vp fmt` / `vp check`.
    plugins: lazyPlugins(() => mode === "test" ? [] : [
      swPlugin(),
      qwikRouter(dev ? { devSsrServer: false } : {}),
      qwikVite(),
      ...(dev
        ? [
            cloudflare({
              viteEnvironment: { name: "ssr" },
              // wrangler.jsonc "main" is the built bundle; in dev run the TS source instead.
              config: { main: "./src/entry.cloudflare-workers.ts" },
            }),
          ]
        : []),
    ]),
    server: { headers: { "Cache-Control": "public, max-age=0" } },
    preview: { headers: { "Cache-Control": "public, max-age=600" } },
  };
});
