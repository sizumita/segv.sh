/**
 * Workers-runtime tests (project "workers"): `npx vp test run --project workers`.
 * Runs src/server/** inside workerd via @cloudflare/vitest-plugin with test/worker/entry.ts as the Worker
 * (no Qwik SSR) and test/worker/wrangler.test.jsonc bindings. D1 migrations are applied in ./setup.ts.
 */
import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vite-plus";

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(import.meta.dirname, "../../migrations"));
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: path.join(import.meta.dirname, "wrangler.test.jsonc") },
        miniflare: { bindings: { TEST_MIGRATIONS: migrations } },
      }),
    ],
    test: {
      name: "workers",
      root: import.meta.dirname,
      include: ["**/*.spec.ts"],
      setupFiles: ["./setup.ts"],
      testTimeout: 30_000,
    },
  };
});
