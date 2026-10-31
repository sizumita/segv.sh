/**
 * `vp test` project "engine", in Node: the engine's modules (src/*.test.ts), and the real engine against FakeWorld, an
 * in-memory implementation of the server (test/harness.ts, test/*.spec.ts).
 */
import { defineConfig } from "vite-plus";

export default defineConfig({
  test: {
    name: "engine",
    include: ["src/**/*.test.ts", "test/**/*.spec.ts"],
    environment: "node",
    testTimeout: 120_000,
    hookTimeout: 60_000,
  },
});
