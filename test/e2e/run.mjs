// End-to-end test: production build + `wrangler dev` + headless Chromium with virtual passkeys (PRF).
//
//   npm run test:e2e              # build, then test
//   npm run test:e2e -- --no-build
//   HEADED=1 npm run test:e2e     # watch it
//
// Uses a throwaway local state dir and a generated wrangler config with low proof-of-work and
// relaxed rate limits, so it never touches your dev database.
import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const STATE = join(ROOT, ".wrangler/e2e");
const PORT = Number(process.env.E2E_PORT ?? 8817);
const BASE = `http://localhost:${PORT}`;
const SHOTS = process.env.E2E_SHOTS ?? join(STATE, "shots");
const T = 60_000;

const P = await import(join(ROOT, "src/lib/proto.ts"));

// ───────────── tiny test harness ─────────────

const results = [];
const devices = [];
let failed = 0;
async function step(name, fn) {
  const t0 = Date.now();
  try {
    await fn();
    results.push(`  ok   ${name} (${Date.now() - t0} ms)`);
    console.log(results.at(-1));
  } catch (e) {
    failed++;
    results.push(`  FAIL ${name}: ${e?.message?.split("\n").slice(0, 6).join(" | ")}`);
    console.log(results.at(-1));
    for (const d of devices) {
      try {
        await d.page.screenshot({ path: join(SHOTS, `fail-${d.name}.png`) });
        console.log(
          `  [${d.name}] ${(await d.page.locator("body").innerText()).replace(/\s+/g, " ").slice(0, 600)}`,
        );
      } catch {
        /* closed */
      }
    }
    throw e;
  }
}
function check(cond, msg) {
  if (!cond) throw new Error(msg);
}

// ───────────── server ─────────────

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

function e2eConfig() {
  const cfg = JSON.parse(stripJsonc(readFileSync(join(ROOT, "wrangler.jsonc"), "utf8")));
  delete cfg.$schema;
  delete cfg.routes;
  cfg.main = join(ROOT, cfg.main);
  cfg.assets.directory = join(ROOT, cfg.assets.directory);
  for (const db of cfg.d1_databases)
    db.migrations_dir = join(ROOT, db.migrations_dir ?? "migrations");
  cfg.vars = { ...cfg.vars, POW_REGISTER: "10", POW_WRAP: "10", POW_APPEND: "8", POW_BLOB: "8" };
  for (const rl of cfg.ratelimits ?? []) rl.simple = { ...rl.simple, limit: 100000 };
  const path = join(STATE, "wrangler.json");
  writeFileSync(path, JSON.stringify(cfg, null, 2));
  return path;
}

async function startServer() {
  rmSync(STATE, { recursive: true, force: true });
  mkdirSync(SHOTS, { recursive: true });
  const config = e2eConfig();
  const env = { ...process.env, CI: "1", NO_COLOR: "1" };
  const wrangler = join(ROOT, "node_modules/.bin/wrangler");
  execFileSync(
    wrangler,
    [
      "d1",
      "migrations",
      "apply",
      "DB",
      "--local",
      "-c",
      config,
      "--persist-to",
      join(STATE, "state"),
    ],
    {
      cwd: ROOT,
      env,
      stdio: "pipe",
    },
  );
  const proc = spawn(
    wrangler,
    [
      "dev",
      "-c",
      config,
      "--port",
      String(PORT),
      "--persist-to",
      join(STATE, "state"),
      "--log-level",
      "warn",
    ],
    {
      cwd: ROOT,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let log = "";
  proc.stdout.on("data", (d) => (log += d));
  proc.stderr.on("data", (d) => (log += d));
  const t0 = Date.now();
  for (;;) {
    try {
      const r = await fetch(`${BASE}/api/params`);
      if (r.ok) break;
    } catch {
      /* not up yet */
    }
    if (proc.exitCode !== null || Date.now() - t0 > 90_000)
      throw new Error(`wrangler dev did not start:\n${log}`);
    await new Promise((r) => setTimeout(r, 300));
  }
  return { proc, log: () => log };
}

// ───────────── browser helpers ─────────────

const problems = [];

async function device(browser, name) {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  await ctx.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) =>
      console.error(`CSP violation: ${e.violatedDirective} blocked=${e.blockedURI}`),
    );
  });
  const page = await ctx.newPage();
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    const t = m.text();
    // Expected: the handle-availability probe 404s during registration.
    if (/Failed to load resource.*404/.test(t)) return;
    problems.push(`[${name}] console.error: ${t}`);
  });
  page.on("pageerror", (e) => problems.push(`[${name}] pageerror: ${e.message}`));
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
    },
  });
  await page.goto(`${BASE}/`, { waitUntil: "load" });
  const d = { name, ctx, page, cdp, authenticatorId };
  devices.push(d);
  return d;
}

async function signedOut(d) {
  await d.page.getByRole("button", { name: "create account" }).waitFor({ timeout: T });
}

async function register(d, handle, { remember = false } = {}) {
  await signedOut(d);
  if (remember) await d.page.getByLabel("remember this device").check();
  await d.page.getByLabel("handle", { exact: true }).fill(handle);
  await d.page.getByRole("button", { name: "create account" }).click();
  await d.page.getByText("save your recovery code").waitFor({ timeout: T });
  const code = (await d.page.locator(".code").innerText()).replace(/\s+/g, "-");
  check(/^([0-9A-Z]{4}-){7}[0-9A-Z]{4}$/.test(code), `unexpected recovery code format: ${code}`);
  await d.page.getByLabel("i saved it").check();
  await d.page.getByRole("button", { name: "continue" }).click();
  await ready(d);
  return code;
}

async function ready(d) {
  await d.page.locator("aside.left").waitFor({ timeout: T });
}

async function newConversation(d, handles, name) {
  const btn = d.page.getByRole("button", { name: "new conversation" });
  if (await btn.isVisible()) await btn.click();
  await d.page.getByLabel("handles").fill(handles);
  if (name) await d.page.getByLabel("group name (optional)").fill(name);
  await d.page.getByRole("button", { name: "start" }).click();
  const title =
    name ??
    handles
      .split(/[\s,]+/)
      .filter(Boolean)
      .map((h) => `@${h}`)
      .join(", ");
  await d.page.locator(".convhead .title", { hasText: title }).waitFor({ timeout: T });
  await d.page.getByLabel("message").waitFor({ timeout: T });
}

async function open(d, convName) {
  const item = d.page
    .locator(".conv", { has: d.page.locator(".name", { hasText: convName }) })
    .first();
  await item.waitFor({ timeout: T });
  await item.click();
  await d.page.locator(".convhead .title", { hasText: convName }).waitFor({ timeout: T });
}

async function send(d, text) {
  await d.page.getByLabel("message").fill(text);
  await d.page.getByLabel("message").press("Enter");
  await seen(d, text);
  await d.page.waitForFunction(() => !document.body.innerText.includes("sending…"), null, {
    timeout: T,
  });
}

async function seen(d, text, timeout = T) {
  await d.page.locator(".thread").getByText(text, { exact: false }).first().waitFor({ timeout });
}

async function notSeen(d, text, waitMs = 4000) {
  await d.page.waitForTimeout(waitMs);
  const n = await d.page.locator(".thread").getByText(text, { exact: false }).count();
  check(n === 0, `${d.name} should not see "${text}"`);
}

async function openMembers(d) {
  const panel = d.page.locator("aside.members");
  if (!(await panel.isVisible()))
    await d.page.locator(".convhead").getByRole("button", { name: "members" }).click();
  await panel.waitFor({ timeout: T });
  return panel;
}

async function shot(d, name) {
  await d.page.screenshot({ path: join(SHOTS, `${name}.png`) });
}

async function pngBytes(page, label) {
  return page.evaluate(async (label) => {
    const c = document.createElement("canvas");
    c.width = 1600;
    c.height = 900;
    const g = c.getContext("2d");
    g.fillStyle = "#123";
    g.fillRect(0, 0, 1600, 900);
    g.fillStyle = "#fc3";
    g.font = "120px monospace";
    g.fillText(label, 80, 480);
    const b = await new Promise((r) => c.toBlob(r, "image/png"));
    return Array.from(new Uint8Array(await b.arrayBuffer()));
  }, label);
}

// ───────────── the scenario ─────────────

if (!process.argv.includes("--no-build")) {
  console.log("building…");
  execFileSync("npm", ["run", "build"], { cwd: ROOT, stdio: "inherit" });
}
console.log("starting wrangler dev…");
const server = await startServer();
const browser = await chromium.launch({ headless: !process.env.HEADED });
const sfx = Date.now().toString(36).slice(-4);
const H = { alice: `alice_${sfx}`, bob: `bob_${sfx}`, carol: `carol_${sfx}`, dave: `dave_${sfx}` };
const secrets = []; // every plaintext we send; none may appear in the public log
let codeAlice = "";

try {
  const A = await device(browser, "alice");
  const B = await device(browser, "bob");
  const C = await device(browser, "carol");

  await step("CSP and security headers on the HTML", async () => {
    const r = await fetch(`${BASE}/`);
    const csp = r.headers.get("content-security-policy") ?? "";
    check(/script-src[^;]*'nonce-/.test(csp), `no nonce CSP: ${csp}`);
    check(
      csp.includes("object-src 'none'") && csp.includes("frame-ancestors 'none'"),
      `weak CSP: ${csp}`,
    );
    check(r.headers.get("referrer-policy") === "no-referrer", "referrer-policy");
  });

  await step("register three accounts with passkeys (PRF)", async () => {
    codeAlice = await register(A, H.alice);
    await register(B, H.bob);
    await register(C, H.carol);
    await shot(A, "01-alice-ready");
  });

  await step("1:1 conversation, text both ways (Japanese + emoji)", async () => {
    await newConversation(A, H.bob);
    const t1 = `こんにちは bob — secret-1 ${sfx} 🙂`;
    secrets.push(t1);
    await send(A, t1);
    await open(B, `@${H.alice}`);
    await seen(B, t1);
    const t2 = `返信です secret-2 ${sfx}`;
    secrets.push(t2);
    await send(B, t2);
    await seen(A, t2);
    await shot(B, "02-bob-1to1");
  });

  await step("encrypted image arrives and decrypts", async () => {
    const bytes = await pngBytes(A.page, `img ${sfx}`);
    await A.page
      .locator("input[type=file]")
      .setInputFiles({ name: "pic.png", mimeType: "image/png", buffer: Buffer.from(bytes) });
    await A.page.getByRole("button", { name: "send", exact: true }).click();
    await A.page.locator('.thread img[src^="blob:"]').first().waitFor({ timeout: T });
    const img = B.page.locator('.thread img[src^="blob:"]').first();
    await img.waitFor({ timeout: T });
    await B.page.waitForFunction(
      () => {
        const i = document.querySelector('.thread img[src^="blob:"]');
        return i && i.complete && i.naturalWidth > 0;
      },
      null,
      { timeout: T },
    );
    const w = await img.evaluate((i) => i.naturalWidth);
    check(w === 1600, `decoded image width ${w}`);
    await shot(B, "03-bob-image");
  });

  await step("group conversation with three members", async () => {
    await newConversation(A, `${H.bob}, ${H.carol}`, `team ${sfx}`);
    const t = `group hello secret-3 ${sfx}`;
    secrets.push(t);
    await send(A, t);
    await open(B, `team ${sfx}`);
    await open(C, `team ${sfx}`);
    await seen(B, t);
    await seen(C, t);
    const tc = `carol here secret-4 ${sfx}`;
    secrets.push(tc);
    await send(C, tc);
    await seen(A, tc);
    await seen(B, tc);
  });

  await step("removing a member cuts them off from new messages", async () => {
    const panel = await openMembers(A);
    const row = panel.locator("li", { hasText: H.carol });
    await row.getByRole("button", { name: "remove" }).click();
    await row.locator(".confirm").getByRole("button", { name: "remove" }).click();
    await seen(A, `removed @${H.carol}`);
    await seen(C, "removed you");
    await C.page.getByText("you are no longer a member").waitFor({ timeout: T });
    const t = `after removal secret-5 ${sfx}`;
    secrets.push(t);
    await send(A, t);
    await seen(B, t);
    await notSeen(C, t);
    await shot(C, "04-carol-removed");
  });

  await step("leaving rotates keys on the next send", async () => {
    const panel = await openMembers(B);
    await panel.getByRole("button", { name: "leave conversation" }).click();
    await panel.locator(".confirm").getByRole("button", { name: "leave" }).click();
    await B.page.getByText("you are no longer a member").waitFor({ timeout: T });
    await seen(A, `@${H.bob} left`);
    const t = `after bob left secret-6 ${sfx}`;
    secrets.push(t);
    await send(A, t);
    await notSeen(B, t);
  });

  await step(
    'reload without "remember": signed out, passkey sign-in restores history',
    async () => {
      await A.page.reload({ waitUntil: "load" });
      await signedOut(A);
      await A.page.getByRole("button", { name: "sign in with passkey" }).click();
      await ready(A);
      await open(A, `@${H.bob}`);
      await seen(A, secrets[0]);
      await seen(A, secrets[1]);
      await A.page.locator('.thread img[src^="blob:"]').first().waitFor({ timeout: T });
    },
  );

  await step(
    "new device: recovery code unlocks full history, then enrol a passkey there",
    async () => {
      const A2 = await device(browser, "alice-2");
      await signedOut(A2);
      await A2.page.getByRole("button", { name: "use recovery code" }).click();
      await A2.page.getByLabel("recovery code").fill(codeAlice.toLowerCase());
      await A2.page.getByRole("button", { name: "unlock" }).click();
      await ready(A2);
      await open(A2, `team ${sfx}`);
      await seen(A2, secrets[2]);
      await seen(A2, secrets[5]);
      await A2.page.getByRole("button", { name: "add passkey" }).click();
      await A2.page.getByText("passkey added.").waitFor({ timeout: T });
      await A2.page.getByRole("button", { name: "sign out" }).click();
      await signedOut(A2);
      await A2.page.getByRole("button", { name: "sign in with passkey" }).click();
      await ready(A2);
      await open(A2, `@${H.bob}`);
      await seen(A2, secrets[1]);
      // A message from device 2 shows up on device 1.
      const t = `from alice's second device secret-7 ${sfx}`;
      secrets.push(t);
      await send(A2, t);
      await seen(A, t);
      await shot(A2, "05-alice-device2");
      await A2.ctx.close();
    },
  );

  await step('"remember this device" survives a reload', async () => {
    const D = await device(browser, "dave");
    await register(D, H.dave, { remember: true });
    await D.page.reload({ waitUntil: "load" });
    await ready(D);
    await D.page.getByText(`@${H.dave}`).first().waitFor({ timeout: T });
    await D.page.getByRole("button", { name: "sign out" }).click();
    await signedOut(D);
    await D.page.reload({ waitUntil: "load" });
    await signedOut(D);
    await D.ctx.close();
  });

  await step("the public log verifies and leaks no plaintext or metadata", async () => {
    const rows = [];
    for (let after = 0; ;) {
      const r = await (await fetch(`${BASE}/api/log?after=${after}&limit=1000`)).json();
      if (r.rows.length === 0) break;
      rows.push(...r.rows);
      after = r.rows.at(-1).seq;
    }
    let h = P.ZERO32;
    for (const [i, w] of rows.entries()) {
      check(w.seq === i + 1, `gap at ${w.seq}`);
      h = P.rowHash(h, w.seq, w.kind, P.fromB64u(w.tag), P.fromB64u(w.body), w.ts);
      check(P.b64u(h) === w.h, `hash chain broken at ${w.seq}`);
    }
    const kinds = rows.reduce((m, w) => ((m[w.kind] = (m[w.kind] ?? 0) + 1), m), {});
    check(kinds[1] === 4, `expected 4 user rows, got ${kinds[1]}`);
    const needles = [...secrets, `team ${sfx}`, ...Object.values(H)].map((s) =>
      Buffer.from(s, "utf8"),
    );
    for (const w of rows) {
      const body = Buffer.from(P.fromB64u(w.body));
      if (w.kind === 3) check(P.INV_BODY_LENS.includes(body.length), `invite size ${body.length}`);
      if (w.kind === 4) check(P.MSG_BODY_LENS.includes(body.length), `message size ${body.length}`);
      if (w.kind === 1) continue; // the directory (handles + public keys) is public by design
      for (const n of needles)
        if (w.kind === 3 || w.kind === 4)
          check(!body.includes(n), `plaintext "${n}" visible in row #${w.seq}`);
    }
    results.push(`       log: ${rows.length} rows ${JSON.stringify(kinds)}`);
    console.log(results.at(-1));
  });

  await step("no page errors or CSP violations", async () => {
    check(problems.length === 0, problems.join("\n"));
  });
} catch {
  /* reported by step() */
} finally {
  await browser.close();
  server.proc.kill("SIGTERM");
}

console.log(`\n${failed ? "FAILED" : "PASSED"} — screenshots in ${SHOTS}`);
if (failed && process.env.E2E_VERBOSE) console.log(server.log());
process.exit(failed ? 1 : 0);
