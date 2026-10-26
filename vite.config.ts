/**
 * Vite+ config.
 *  - `vp dev`  : Qwik SSR + /api + Durable Objects run inside workerd via @cloudflare/vite-plugin
 *                (Qwik's Node dev-SSR middleware is disabled so requests fall through to the Worker).
 *  - `vp build`: plain Qwik client build; adapters/cloudflare-workers/vite.config.ts extends this
 *                for the server bundle that wrangler deploys.
 */
import { cloudflare } from "@cloudflare/vite-plugin";
import { qwikVite } from "@qwik.dev/core/optimizer";
import { qwikRouter } from "@qwik.dev/router/vite";
import { defineConfig, lazyPlugins } from "vite-plus";

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
    resolve: { tsconfigPaths: true }, // "~/*" alias from tsconfig (replaces vite-tsconfig-paths)
    environments: dev ? { ssr: { optimizeDeps: { exclude: QWIK_LIBS } } } : undefined,
    // `vp lint` (oxlint). eslint-plugin-qwik runs as an oxlint JS plugin; its
    // qwik/valid-lexical-scope rule needs TS type info that JS plugins don't get -> off.
    lint: {
      plugins: ["oxc", "typescript", "unicorn"],
      jsPlugins: ["eslint-plugin-qwik"],
      categories: { correctness: "warn" },
      rules: {
        "qwik/valid-lexical-scope": "off",
        "qwik/use-method-usage": "error",
        "qwik/no-react-props": "error",
        "qwik/loader-location": "warn",
        "qwik/jsx-key": "warn",
        "qwik/unused-server": "error",
        "qwik/jsx-img": "warn",
        "qwik/jsx-a": "warn",
        "qwik/serializer-signal-usage": "error",
        "qwik/scope-use-task": "error",
      },
    },
    fmt: { ignorePatterns: ["worker-configuration.d.ts", "dist/**", "server/**"] },
    // lazyPlugins: factories are skipped by `vp lint` / `vp fmt` / `vp check`.
    // `vp test`: unit tests (pure TS, Node) + Workers-runtime tests (test/worker/vitest.config.ts).
    test: {
      projects: [
        { test: { name: "unit", include: ["src/**/*.test.ts"], environment: "node" } },
        "test/worker/vitest.config.ts",
        // The real client engine (src/client/engine.ts) against an in-memory fake Worker (test/engine/harness.ts).
        {
          resolve: { alias: { "~": `${import.meta.dirname}/src` } },
          test: { name: "engine", include: ["test/engine/**/*.spec.ts"], environment: "node", testTimeout: 120_000, hookTimeout: 60_000 },
        },
      ],
    },
    plugins: lazyPlugins(() => mode === "test" ? [] : [
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
