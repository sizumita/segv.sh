/** `vp test` project "protocol": the cryptographic core and the wire formats, in Node. */
import { defineConfig } from "vite-plus";

export default defineConfig({
  test: { name: "protocol", include: ["src/**/*.test.ts"], environment: "node" },
});
