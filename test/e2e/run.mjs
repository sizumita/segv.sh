// End-to-end test: production build + `wrangler dev` + headless Chromium with virtual passkeys (PRF), on protocol v2
// (docs/PROTOCOL-v2.md; docs/STAGE1-PLAN.md §5). The steps are those of milestone M6b; M6c adds images and
// scrollback, M7 removing and leaving.
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
const Wire = await import(join(ROOT, "src/lib/wire.ts"));

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
      const r = await fetch(`${BASE}/api/v2/params`);
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

async function shot(d, name) {
  await d.page.screenshot({ path: join(SHOTS, `${name}.png`) });
}

// ───────────── the public data (the audit) ─────────────

async function getJson(path) {
  const r = await fetch(`${BASE}${path}`);
  check(r.ok, `${path}: ${r.status}`);
  return r.json();
}

async function getBytes(path) {
  const r = await fetch(`${BASE}${path}`);
  check(r.ok, `${path}: ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

/** Every closed batch of shard (E, 0), with each batch's root and the head chain verified (§9.1, §10.9). */
async function feedOf(E) {
  const batches = [];
  let head = P.ZERO32;
  for (let after = 0; ;) {
    const page = Wire.decodeFeed(await getBytes(`/api/v2/feed/${E}/0?after=${after}`));
    for (const b of page.batches) {
      const leaves = [...b.rows]
        .sort((x, y) => Buffer.compare(Buffer.from(x.label), Buffer.from(y.label)))
        .map((r) => P.leafShard(E, r.label, b.t, r.cls, r.body));
      check(b.rows.length === b.n, `feed ${E}: batch ${b.t} has ${b.rows.length} rows, n = ${b.n}`);
      check(
        P.equalBytes(P.mth(leaves), b.root),
        `feed ${E}: the root of batch ${b.t} does not verify`,
      );
      head = P.nextHead(P.shardCid(E, 0), head, b.t, b.n, b.root);
      check(P.equalBytes(head, b.head), `feed ${E}: the head chain breaks at batch ${b.t}`);
      batches.push(b);
      after = b.t;
    }
    if (!page.more) break;
  }
  return batches;
}

/** Every inbox row of era E (§10.5). */
async function inboxOf(E) {
  const rows = [];
  for (let after = 0; ;) {
    const page = Wire.decodeInboxRead(await getBytes(`/api/v2/inbox/${E}/0?after=${after}`));
    rows.push(...page.rows);
    if (!page.more) break;
    after = page.rows.at(-1).rel;
  }
  return rows;
}

// ───────────── the scenario ─────────────

if (!process.argv.includes("--no-build")) {
  console.log("building…");
  execFileSync("npm", ["run", "build"], { cwd: ROOT, stdio: "inherit" });
}
console.log("starting wrangler dev…");
const server = await startServer();
const startEra = P.era(Date.now());
const browser = await chromium.launch({ headless: !process.env.HEADED });
const sfx = Date.now().toString(36).slice(-4);
const H = { alice: `alice_${sfx}`, bob: `bob_${sfx}`, carol: `carol_${sfx}`, dave: `dave_${sfx}` };
const team = `team ${sfx}`;
// Every plaintext sent: none may appear in the public data.
const t1 = `こんにちは bob — secret-1 ${sfx} 🙂`;
const t2 = `返信です secret-2 ${sfx}`;
const t3 = `group hello secret-3 ${sfx}`;
const t4 = `carol here secret-4 ${sfx}`;
const t7 = `from alice's second device secret-7 ${sfx}`;
const t5 = `after removal secret-5 ${sfx}`;
const t6 = `after bob left secret-6 ${sfx}`;
const bulk = (i) => `bulk ${i} secret-8 ${sfx}`;
const secrets = [t1, t2, t3, t4, t5, t6, t7, bulk(0), bulk(99)];
let codeAlice = "";

try {
  const A = await device(browser, "alice");
  const B = await device(browser, "bob");
  const C = await device(browser, "carol");

  await step("CSP and security headers on the HTML and the API", async () => {
    const r = await fetch(`${BASE}/`);
    const csp = r.headers.get("content-security-policy") ?? "";
    check(/script-src[^;]*'nonce-/.test(csp), `no nonce CSP: ${csp}`);
    check(
      csp.includes("object-src 'none'") && csp.includes("frame-ancestors 'none'"),
      `weak CSP: ${csp}`,
    );
    check(r.headers.get("referrer-policy") === "no-referrer", "referrer-policy");
    const api = await fetch(`${BASE}/api/v2/params`);
    check(/^\d+$/.test(api.headers.get("x-segv-now") ?? ""), "x-segv-now on the API");
    check(api.headers.get("x-content-type-options") === "nosniff", "nosniff on the API");
  });

  await step("register three accounts with passkeys (PRF)", async () => {
    codeAlice = await register(A, H.alice);
    await register(B, H.bob);
    await register(C, H.carol);
    await shot(A, "01-alice-ready");
  });

  await step(
    "1:1 conversation, text both ways (bob opens alice's request, which accepts it)",
    async () => {
      await newConversation(A, H.bob);
      await send(A, t1);
      await open(B, `@${H.alice}`);
      await seen(B, t1);
      await send(B, t2);
      await seen(A, t2);
      await shot(B, "02-bob-1to1");
    },
  );

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
    await shot(B, "02b-bob-image");
  });

  await step("group conversation with three members, named at creation", async () => {
    await newConversation(A, `${H.bob}, ${H.carol}`, team);
    await send(A, t3);
    await open(B, team);
    await open(C, team);
    await seen(B, t3);
    await seen(C, t3);
    await send(C, t4);
    await seen(A, t4);
    await seen(B, t4);
  });

  await step("removing a member cuts them off from new messages", async () => {
    await open(A, team);
    await open(B, team);
    await open(C, team);
    const panel = await openMembers(A);
    const row = panel.locator("li", { hasText: H.carol });
    await row.getByRole("button", { name: "remove" }).click();
    await row.locator(".confirm").getByRole("button", { name: "remove" }).click();
    await seen(A, `removed @${H.carol}`);
    await seen(C, "removed you");
    await C.page.getByText("you are no longer a member").waitFor({ timeout: T });
    await send(A, t5);
    await seen(B, t5);
    await notSeen(C, t5);
    await shot(C, "04-carol-removed");
  });

  await step("leaving rotates keys on the next send", async () => {
    const panel = await openMembers(B);
    await panel.getByRole("button", { name: "leave conversation" }).click();
    await panel.locator(".confirm").getByRole("button", { name: "leave" }).click();
    await B.page.getByText("you are no longer a member").waitFor({ timeout: T });
    await seen(A, `@${H.bob} left`);
    await send(A, t6);
    await seen(A, `keys rotated after @${H.bob} left`);
    await notSeen(B, t6);
    await shot(A, "05-alice-after-leave");
  });

  await step(
    'reload without "remember": signed out, passkey sign-in restores the texts',
    async () => {
      await A.page.reload({ waitUntil: "load" });
      await signedOut(A);
      await A.page.getByRole("button", { name: "sign in with passkey" }).click();
      await ready(A);
      await open(A, `@${H.bob}`);
      await seen(A, t1);
      await seen(A, t2);
      await A.page.locator('.thread img[src^="blob:"]').first().waitFor({ timeout: T });
    },
  );

  await step(
    "new device: the recovery code restores the history, then a passkey is enrolled there",
    async () => {
      const A2 = await device(browser, "alice-2");
      await signedOut(A2);
      await A2.page.getByRole("button", { name: "use recovery code" }).click();
      await A2.page.getByLabel("recovery code").fill(codeAlice.toLowerCase());
      await A2.page.getByRole("button", { name: "unlock" }).click();
      await ready(A2);
      await open(A2, team);
      await seen(A2, t3);
      await seen(A2, t4);
      await A2.page.getByRole("button", { name: "add passkey" }).click();
      await A2.page.getByText("passkey added.").waitFor({ timeout: T });
      await A2.page.getByRole("button", { name: "sign out" }).click();
      await signedOut(A2);
      await A2.page.getByRole("button", { name: "sign in with passkey" }).click();
      await ready(A2);
      await open(A2, `@${H.bob}`);
      await seen(A2, t2);
      // A message from device 2 reaches device 1 (and bob).
      await send(A2, t7);
      await seen(A, t7);
      await open(B, `@${H.alice}`);
      await seen(B, t7);
      await shot(A2, "03-alice-device2");
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

  await step(
    "scrollback: after a reload, opening a 1:1 with 100 messages shows the oldest",
    async () => {
      await newConversation(C, H.alice);
      for (let i = 0; i < 100; i++) await send(C, bulk(i));
      const count = (d) =>
        d.page.evaluate(
          (needle) => document.querySelector(".thread").innerText.split(needle).length - 1,
          `secret-8 ${sfx}`,
        );
      check((await count(C)) === 100, `carol shows ${await count(C)} of 100 messages`);
      await A.page.reload({ waitUntil: "load" });
      await signedOut(A);
      await A.page.getByRole("button", { name: "sign in with passkey" }).click();
      await ready(A);
      await open(A, `@${H.carol}`);
      await seen(A, bulk(99));
      await seen(A, bulk(0)); // older than the last 30 of carol's lane: loaded by scrollback when the pane opened
      check(
        (await count(A)) > 60,
        `alice shows ${await count(A)} of 100 messages after scrollback`,
      );
    },
  );

  await step("the public data verifies and leaks no plaintext", async () => {
    const Enow = P.era(Date.now());
    const needles = [...secrets, team, ...Object.values(H)].map((s) => Buffer.from(s, "utf8"));
    const clean = (what, bytes) => {
      const b = Buffer.from(bytes);
      for (const n of needles) check(!b.includes(n), `plaintext "${n}" visible in ${what}`);
    };
    // Shard feeds: roots, head chains, row sizes, no plaintext.
    let rows = 0;
    const heads = new Map();
    for (let E = startEra; E <= Enow; E++) {
      const batches = await feedOf(E);
      heads.set(E, new Set(batches.map((b) => P.b64u(b.head))));
      for (const b of batches)
        for (const r of b.rows) {
          rows++;
          check(P.BODY_LENS.includes(r.body.length), `row size ${r.body.length}`);
          clean(`a row of batch ${b.t}`, r.body);
        }
    }
    check(rows > 0, "the feed holds no rows");
    // The latest checkpoint's head of this era's shard occurs in the feed's head chain (§9.5).
    const cid = P.shardCid(Enow, 0);
    const t0 = Date.now();
    for (;;) {
      const r = await fetch(`${BASE}/api/v2/ckpt/latest`);
      const ck = r.ok ? await r.json() : null;
      const h = ck?.heads?.find((x) => x.cid === cid)?.head;
      if (h) {
        const known = (await feedOf(Enow)).map((b) => P.b64u(b.head));
        check(
          known.includes(h),
          `checkpoint ${ck.q}: the head of ${cid} is not in the feed's head chain`,
        );
        break;
      }
      check(Date.now() - t0 < 150_000, "no checkpoint covered the shard within 150 s");
      await new Promise((res) => setTimeout(res, 2000));
    }
    // Inbox rows: the one size, no plaintext.
    let invites = 0;
    for (let E = startEra; E <= Enow; E++)
      for (const r of await inboxOf(E)) {
        invites++;
        check(r.body.length === P.INBOX_BODY_LEN, `invite size ${r.body.length}`);
        clean(`an invite of era ${E}`, r.body);
      }
    // bob's 1:1 invite, carol's group invite and alice's invite to carol's 1:1; bob's group J is a WELCOME in his
    // 1:1 with alice (§6.12 step 1)
    check(invites === 3, `expected 3 invites, got ${invites}`);
    // The directory's public log: four registrations.
    const log = await getJson(`/api/v2/dirlog?after=0&limit=1000`);
    const users = log.entries.filter((x) => x.kind === 1).length;
    check(users === 4, `expected 4 user entries in the dirlog, got ${users}`);
    results.push(
      `       data: ${rows} rows, ${invites} invites, ${log.entries.length} dirlog entries`,
    );
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
