// The local deployment that the end-to-end runs drive: the production build of the Worker under `wrangler dev`, with a
// generated configuration (low proof of work, Δ = 1 s, fresh secrets, relaxed rate limits) and its own state
// directory, so that it never touches the data of `pnpm run dev`.
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

// Wrangler's CLI through this Node: on Windows, node_modules/.bin holds .cmd shims that only a shell runs.
const WRANGLER = join(
  dirname(createRequire(import.meta.url).resolve("wrangler/package.json")),
  "bin/wrangler.js",
);

function stripJsonc(text) {
  let out = "";
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      out += c;
      if (c === "\\") out += text[++i];
      else if (c === '"') inStr = false;
    } else if (c === '"') {
      inStr = true;
      out += c;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (c === "/" && text[i + 1] === "*") {
      i = text.indexOf("*/", i + 2) + 1;
    } else out += c;
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}

/** wrangler.jsonc with the test's settings, written to the state directory. */
function config(root, state, P) {
  const cfg = JSON.parse(stripJsonc(readFileSync(join(root, "wrangler.jsonc"), "utf8")));
  delete cfg.$schema;
  delete cfg.routes;
  cfg.main = join(root, cfg.main);
  cfg.assets.directory = join(root, cfg.assets.directory);
  for (const db of cfg.d1_databases)
    db.migrations_dir = join(root, db.migrations_dir ?? "migrations");
  // Low proof of work, Δ = 1 s, SKEW = 0, Δin = 1 s, this era as E_FIRST, and fresh secrets (`wrangler dev` reads no
  // .dev.vars for a config here; without ROUTE_KEY / SRV_KEY every /api/v2/* call answers 503).
  cfg.vars = {
    ...cfg.vars,
    POW_REGISTER: "10",
    POW_WRAP: "10",
    POW_PUT: "8",
    POW_INBOX: "8",
    POW_BLOB: "8",
    DELTA_S: "1",
    SKEW_S: "0",
    INBOX_SLOT_S: "1",
    E_FIRST: String(P.era(Date.now())),
    ROUTE_KEY: P.b64u(P.random(32)),
    SRV_KEY: P.b64u(P.random(32)),
  };
  for (const rl of cfg.ratelimits ?? []) rl.simple = { ...rl.simple, limit: 100000 };
  const path = join(state, "wrangler.json");
  writeFileSync(path, JSON.stringify(cfg, null, 2));
  return path;
}

/**
 * Starts `wrangler dev` on `port` with a fresh state directory, once the directory's migrations are applied, and
 * resolves when the API answers. `stop()` ends it; `log()` is what it printed.
 */
export async function startServer({ root, state, port, P }) {
  rmSync(state, { recursive: true, force: true });
  mkdirSync(state, { recursive: true });
  const path = config(root, state, P);
  const persist = join(state, "state");
  const env = { ...process.env, CI: "1", NO_COLOR: "1" };
  const wrangler = (args, opts) => [
    process.execPath,
    [WRANGLER, ...args],
    { cwd: root, env, ...opts },
  ];
  execFileSync(
    ...wrangler(
      ["d1", "migrations", "apply", "DB", "--local", "-c", path, "--persist-to", persist],
      {
        stdio: "pipe",
      },
    ),
  );
  const proc = spawn(
    ...wrangler(
      ["dev", "-c", path, "--port", String(port), "--persist-to", persist, "--log-level", "warn"],
      { stdio: ["ignore", "pipe", "pipe"] },
    ),
  );
  let log = "";
  proc.stdout.on("data", (d) => (log += d));
  proc.stderr.on("data", (d) => (log += d));
  const t0 = Date.now();
  for (;;) {
    try {
      const r = await fetch(`http://localhost:${port}/api/v2/params`);
      if (r.ok) break;
    } catch {
      /* not up yet */
    }
    if (proc.exitCode !== null || Date.now() - t0 > 90_000)
      throw new Error(`wrangler dev did not start:\n${log}`);
    await new Promise((r) => setTimeout(r, 300));
  }
  return { stop: () => kill(proc), log: () => log };
}

/** Ends a process and the processes it started (wrangler's workerd, a web view's browser processes). */
export function kill(proc) {
  if (proc.exitCode !== null) return;
  if (process.platform === "win32")
    spawnSync("taskkill", ["/pid", String(proc.pid), "/t", "/f"], { stdio: "ignore" });
  else proc.kill("SIGTERM");
}
