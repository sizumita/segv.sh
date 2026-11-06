// The page's memory and script time while messages arrive (docs/DEVELOPMENT.md, "End-to-end tests"; not part of
// `pnpm run test:e2e`): the production build under `wrangler dev`, as the end-to-end tests run it, with two devices in
// headless Chromium. Bob sends messages and images to alice in several conversations, first while alice's page is
// hidden (a closed desktop window), then while it shows them; each phase prints alice's live JS heap after a full GC,
// the highest heap seen while the phase ran, and the script time the phase cost her page. Each conversation is a
// named group with carol too, whose device only registers: the "new conversation" dialog names only groups.
//
//   node test/e2e/memory.mjs [--no-build] [--convs N] [--messages N] [--images N] [--snapshot FILE]
//
// --snapshot saves alice's heap snapshot at the end, which Chromium's DevTools open (Memory, Load profile).
import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { chromium } from "playwright";
import { T } from "./lib/harness.mjs";
import { startServer } from "./lib/server.mjs";
import {
  accept,
  device,
  newConversation,
  open,
  openRequest,
  register,
  send,
  sendImage,
  seen,
  seenImage,
} from "./lib/ui.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const STATE = join(ROOT, ".wrangler/memory");
const PORT = Number(process.env.E2E_PORT ?? 8818);
const BASE = `http://localhost:${PORT}`;

const { values: opts } = parseArgs({
  args: process.argv.slice(2).filter((a) => a !== "--"),
  options: {
    "no-build": { type: "boolean" },
    convs: { type: "string", default: "4" },
    messages: { type: "string", default: "100" },
    images: { type: "string", default: "2" },
    snapshot: { type: "string" },
  },
});
const CONVS = Number(opts.convs);
const MESSAGES = Number(opts.messages);
const IMAGES = Number(opts.images);

const P = await import("@segv/protocol/proto");
if (!opts["no-build"]) execFileSync("pnpm", ["run", "build"], { cwd: ROOT, stdio: "inherit" });

const server = await startServer({ root: ROOT, state: STATE, port: PORT, P });
const browser = await chromium.launch({ headless: true });
const MB = (n) => `${(n / 1048576).toFixed(1)} MB`;

/** Alice's page as CDP sees it: the live heap after a full GC, and the cumulative script and task time. */
async function probe(cdp) {
  await cdp.send("HeapProfiler.collectGarbage");
  const heap = await cdp.send("Runtime.getHeapUsage");
  const { metrics } = await cdp.send("Performance.getMetrics");
  const m = Object.fromEntries(metrics.map((x) => [x.name, x.value]));
  return { live: heap.usedSize, script: m.ScriptDuration, task: m.TaskDuration, nodes: m.Nodes };
}

/**
 * Hides or shows alice's page as the app sees it: headless Chromium keeps every page visible, so the page's
 * visibilityState, hidden and hasFocus() are replaced, and a visibilitychange is sent.
 */
async function setHidden(page, hidden) {
  await page.evaluate((hidden) => {
    if (!window.__hide) {
      let h = false;
      Object.defineProperty(document, "visibilityState", { get: () => (h ? "hidden" : "visible") });
      Object.defineProperty(document, "hidden", { get: () => h });
      document.hasFocus = () => !h;
      window.__hide = (v) => {
        h = v;
        document.dispatchEvent(new Event("visibilitychange"));
      };
    }
    window.__hide(hidden);
  }, hidden);
}

/** Runs `fn` while sampling alice's heap (without GC) every 100 ms, and reports the phase. */
async function phase(name, cdp, fn) {
  const before = await probe(cdp);
  let peak = 0;
  let sampling = true;
  const sampler = (async () => {
    while (sampling) {
      const h = await cdp.send("Runtime.getHeapUsage").catch(() => null);
      if (h) peak = Math.max(peak, h.usedSize);
      await new Promise((r) => setTimeout(r, 100));
    }
  })();
  const t0 = Date.now();
  await fn();
  sampling = false;
  await sampler;
  const after = await probe(cdp);
  const row = {
    phase: name,
    seconds: ((Date.now() - t0) / 1000).toFixed(0),
    liveAfter: MB(after.live),
    peak: MB(peak),
    scriptS: (after.script - before.script).toFixed(2),
    taskS: (after.task - before.task).toFixed(2),
    nodes: after.nodes,
  };
  console.log(JSON.stringify(row));
  return row;
}

try {
  const sfx = Date.now().toString(36).slice(-4);
  const A = await device(browser, BASE, "alice");
  const B = await device(browser, BASE, "bob");
  const cdp = await A.ctx.newCDPSession(A.page);
  await cdp.send("Performance.enable");
  const alice = `alice_${sfx}`;
  const bob = `bob_${sfx}`;
  const carol = `carol_${sfx}`;
  await register(A, alice);
  await register(B, bob);
  // carol's account makes each room a group, which keeps its name; her device is not needed after that
  const C = await device(browser, BASE, "carol");
  await register(C, carol);
  await C.ctx.close();
  const rooms = Array.from({ length: CONVS }, (_, i) => `room ${i} ${sfx}`);
  // The first conversation is a request for bob; once he accepts it, alice is his contact.
  for (const [i, room] of rooms.entries()) {
    await newConversation(A, `${bob}, ${carol}`, room);
    await send(A, `hello ${room}`);
    if (i === 0) {
      await openRequest(B, room, `hello ${room}`);
      await accept(B);
    }
  }
  const setup = await probe(cdp);
  console.log(JSON.stringify({ phase: "setup", liveAfter: MB(setup.live), nodes: setup.nodes }));

  /** Bob sends `n` messages and `images` images to every room; alice has seen the last one when it returns. */
  const burst = async (tag, n, images) => {
    for (const room of rooms) {
      await open(B, room);
      for (let k = 0; k < n; k++) {
        const text = `${tag} ${k} ${room} ` + "lorem ipsum dolor sit amet ".repeat(1 + (k % 5));
        const box = B.page.getByLabel("message", { exact: true });
        await box.fill(text);
        await box.press("Enter");
        // The composer takes the text once its handler ran: the next fill would replace it before.
        await B.page.waitForFunction(
          () => document.querySelector("textarea[aria-label=message]")?.value === "",
          null,
          { timeout: T },
        );
      }
      for (let k = 0; k < images; k++) await sendImage(B, `${tag} ${k}`);
      await B.page.waitForFunction(() => !document.body.innerText.includes("sending…"), null, {
        timeout: 5 * T,
      });
    }
  };

  // A closed desktop window.
  await setHidden(A.page, true);
  await phase("hidden: messages arrive", cdp, async () => {
    await burst("h", MESSAGES, IMAGES);
    // Alice has them all once her list shows the last room's last message time; wait for her engine to settle.
    await A.page.waitForTimeout(8000);
  });
  await phase("hidden: idle 60 s", cdp, () => A.page.waitForTimeout(60_000));

  await setHidden(A.page, false);
  await phase("shown: open every room, see the images", cdp, async () => {
    for (const room of rooms) {
      await open(A, room);
      await seen(A, `h ${MESSAGES - 1} ${room}`);
      if (IMAGES) await seenImage(A);
    }
  });
  await phase("shown: messages arrive in the open room", cdp, async () => {
    await burst("s", Math.ceil(MESSAGES / 2), 0);
    await seen(A, `s ${Math.ceil(MESSAGES / 2) - 1} ${rooms.at(-1)}`, 5 * T);
  });
  await phase("shown: idle 60 s", cdp, () => A.page.waitForTimeout(60_000));
  if (opts.snapshot) {
    const { createWriteStream } = await import("node:fs");
    const out = createWriteStream(opts.snapshot);
    cdp.on("HeapProfiler.addHeapSnapshotChunk", (e) => out.write(e.chunk));
    await cdp.send("HeapProfiler.takeHeapSnapshot", { reportProgress: false });
    await new Promise((r) => out.end(r));
    console.log(`heap snapshot: ${opts.snapshot}`);
  }
} finally {
  await browser.close();
  server.stop();
}
