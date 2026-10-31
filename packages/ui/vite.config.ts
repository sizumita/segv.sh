/** `vp test` project "ui": the UI's plain helpers (routing, formatting), in Node. */
import { defineConfig } from "vite-plus";

export default defineConfig({
  test: { name: "ui", include: ["src/**/*.test.ts"], environment: "node" },
});
