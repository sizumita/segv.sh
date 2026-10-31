/**
 * `vp test` project "server": the API, the Durable Objects and the D1 directory inside workerd, through
 * @cloudflare/vitest-plugin, with test/entry.ts as the Worker (no Qwik SSR) and the bindings of
 * test/wrangler.test.jsonc. D1 migrations are applied in test/setup.ts.
 */
import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vite-plus";

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"));
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: path.join(import.meta.dirname, "test/wrangler.test.jsonc") },
        miniflare: { bindings: { TEST_MIGRATIONS: migrations } },
      }),
    ],
    test: {
      name: "server",
      root: path.join(import.meta.dirname, "test"),
      include: ["**/*.spec.ts"],
      setupFiles: ["./setup.ts"],
      testTimeout: 30_000,
    },
  };
});
