/**
 * Vite+ config of the desktop app's pages: @segv/ui rendered in the client only (Qwik's CSR mode), so that the page is
 * one static index.html with no inline script, which the app's Content Security Policy (src-tauri/tauri.conf.json)
 * can forbid outright.
 *  - `vp build`: the pages that `tauri build` puts into the app (dist/).
 *  - `vp dev`: the pages for `tauri dev`, at http://localhost:1420. The page then calls the API at its own origin, and
 *    this server passes /api/* (the realtime socket included) on to SEGV_DEV_API (default: the local `pnpm run dev`).
 *
 * SEGV_ORIGIN, at build time, is the deployment that a built app calls (default https://segv.sh; docs/PROTOCOL.md
 * §11.14 "API"); its passkeys' RP ID is that origin's host.
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { qwikVite } from "@qwik.dev/core/optimizer";
import type { Plugin } from "vite";
import { defineConfig, lazyPlugins } from "vite-plus";

/** Qwik's loader, which dispatches the UI's events: a classic script of its own, as on the web app's pages. */
const QWIKLOADER = createRequire(import.meta.url).resolve("@qwik.dev/core/qwikloader.js");

/** Serves /qwikloader.js in dev and emits it at the root of the build (index.html loads it before the app). */
function qwikloaderPlugin(): Plugin {
  return {
    name: "segv:qwikloader",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url?.split("?")[0] !== "/qwikloader.js") return next();
        readFile(QWIKLOADER, "utf8").then(
          (code) => {
            res.setHeader("Content-Type", "application/javascript");
            res.end(code);
          },
          (e: unknown) => next(e),
        );
      });
    },
    async generateBundle() {
      this.emitFile({
        type: "asset",
        fileName: "qwikloader.js",
        source: await readFile(QWIKLOADER, "utf8"),
      });
    },
  };
}

const ORIGIN = process.env.SEGV_ORIGIN ?? "https://segv.sh";
const DEV_API = process.env.SEGV_DEV_API ?? "http://localhost:5173";

export default defineConfig(({ command, mode }) => ({
  plugins: lazyPlugins(() =>
    mode === "test" ? [] : [qwikloaderPlugin(), qwikVite({ csr: true })],
  ),
  define: {
    // A dev page calls its own origin (the proxy below); a built app the deployment's canonical origin.
    "import.meta.env.SEGV_ORIGIN": JSON.stringify(command === "serve" ? "" : ORIGIN),
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    proxy: { "/api": { target: DEV_API, changeOrigin: true, ws: true } },
  },
  build: {
    // WKWebView of macOS 15, the oldest system the app supports (src-tauri/tauri.conf.json). WebView2 on Windows is an
    // evergreen Chromium, which reads whatever this one does.
    target: "safari18",
    outDir: "dist",
    emptyOutDir: true,
    // Every asset stays a file of its own: the CSP allows no data: script or style.
    assetsInlineLimit: 0,
  },
}));
