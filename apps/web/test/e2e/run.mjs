// End-to-end tests (docs/DEVELOPMENT.md, "End-to-end tests"): the production build under `wrangler dev`
// (lib/server.mjs), driven by Playwright, with a screenshot of each screen.
//
//   pnpm run test:e2e                     # build, then test the web app in headless Chromium (web.mjs)
//   pnpm run test:e2e --no-build          # reuse the last build
//   pnpm run test:e2e --windows-app <exe> # test the installed Windows app instead (windows.mjs)
//   HEADED=1 pnpm run test:e2e            # watch the browsers
//
// Environment: E2E_PORT (8817), the port of `wrangler dev`, which a Windows app must be built for; E2E_CDP_PORT
// (9222), the Windows app's DevTools port; E2E_SHOTS, the directory of the screenshots (.wrangler/e2e/shots);
// E2E_VERBOSE=1 prints wrangler's output after a failure.
import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { chromium } from "playwright";
import { report, shots } from "./lib/harness.mjs";
import { startServer } from "./lib/server.mjs";
import { web } from "./web.mjs";
import { windows } from "./windows.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const STATE = join(ROOT, ".wrangler/e2e");
const PORT = Number(process.env.E2E_PORT ?? 8817);
const BASE = `http://localhost:${PORT}`;
const SHOTS = process.env.E2E_SHOTS ?? join(STATE, "shots");

const { values: opts } = parseArgs({
  args: process.argv.slice(2).filter((a) => a !== "--"),
  options: { "no-build": { type: "boolean" }, "windows-app": { type: "string" } },
});

// Plain Node imports the protocol's TypeScript sources (type stripping): the workspace links @segv/protocol, so its
// files resolve outside node_modules.
const P = await import("@segv/protocol/proto");
const Wire = await import("@segv/protocol/wire");

if (!opts["no-build"]) {
  console.log("building…");
  // pnpm is a .cmd shim on Windows, which only a shell runs.
  execFileSync("pnpm", ["run", "build"], {
    cwd: ROOT,
    stdio: "inherit",
    shell: process.platform === "win32",
  });
}
console.log("starting wrangler dev…");
const server = await startServer({ root: ROOT, state: STATE, port: PORT, P });
const browser = await chromium.launch({ headless: !process.env.HEADED });
let error = null;
try {
  if (opts["windows-app"])
    await windows({
      base: BASE,
      browser,
      // Mica's base colors, approximately: the app's page is transparent over it on Windows 11.
      shots: shots(SHOTS, "windows", ["light", "dark"], {
        backdrop: { light: { r: 243, g: 243, b: 243, a: 1 }, dark: { r: 32, g: 32, b: 32, a: 1 } },
      }),
      exe: opts["windows-app"],
      cdpPort: Number(process.env.E2E_CDP_PORT ?? 9222),
    });
  else
    await web({
      base: BASE,
      browser,
      shots: shots(SHOTS, "web", ["light", "dark", "narrow"]),
      P,
      Wire,
    });
} catch (e) {
  error = e;
} finally {
  await browser.close();
  server.stop();
}

const ok = report(error);
console.log(`screenshots in ${SHOTS}`);
if (!ok && process.env.E2E_VERBOSE) console.log(server.log());
process.exit(ok ? 0 : 1);
