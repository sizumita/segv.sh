// The desktop app on Windows, as it was built and installed: its web view (WebView2) opens a DevTools port when it is
// started with WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS, and Playwright drives its page over that port as it drives
// Chromium. WebView2 ignores that variable in an elevated app (CI's, whose runner is elevated, gets the flag from a
// machine-wide policy instead: .github/workflows/ci.yml). The app must be built for the local deployment (SEGV_ORIGIN=http://localhost:<port>,
// apps/desktop/scripts/bundle.mjs): it calls the API of `wrangler dev` from https://tauri.localhost, an app origin of
// wrangler.jsonc.
//
// The app's passkeys are the system's (webauthn.dll), which a test cannot answer: the accounts are made on the web,
// and the app unlocks with a recovery code, as on a new device. macOS has no such port in WKWebView, so the macOS app
// is not driven here.
import { spawn, spawnSync } from "node:child_process";
import { chromium } from "playwright";
import { kill } from "./lib/server.mjs";
import { check, problems, step, unwatch, watch } from "./lib/harness.mjs";
import {
  accept,
  closeImage,
  closeMembers,
  closeSettings,
  device,
  newConversation,
  openImage,
  openMembers,
  openRequest,
  register,
  seen,
  seenImage,
  send,
  sendImage,
  settings,
  signedOut,
  unlockWithCode,
} from "./lib/ui.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Starts the app with its web view's DevTools on `port`, and resolves with its page once the page has loaded. */
async function launch(exe, port) {
  const proc = spawn(exe, [], {
    env: {
      ...process.env,
      WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port}`,
    },
    stdio: "ignore",
  });
  let failed = null;
  proc.on("error", (e) => (failed = e));
  const t0 = Date.now();
  const until = (what) => {
    if (failed) throw new Error(`the app did not start: ${failed.message}`);
    if (proc.exitCode !== null) throw new Error(`the app exited (${proc.exitCode}) before ${what}`);
    if (Date.now() - t0 > 60_000) {
      // Whether the web view started at all, or started without the flag.
      const views = spawnSync(
        "tasklist",
        ["/fo", "csv", "/nh", "/fi", "IMAGENAME eq msedgewebview2.exe"],
        {
          encoding: "utf8",
        },
      ).stdout?.match(/msedgewebview2/gi)?.length;
      throw new Error(`no ${what} within 60 s (web view processes: ${views ?? 0})`);
    }
    return sleep(300);
  };
  try {
    for (;;) {
      try {
        if ((await fetch(`http://127.0.0.1:${port}/json/version`)).ok) break;
      } catch {
        /* not up yet */
      }
      await until("DevTools port");
    }
    const browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
    for (;;) {
      const page = browser
        .contexts()
        .flatMap((c) => c.pages())
        .find((p) => p.url().startsWith("https://tauri.localhost/"));
      if (page) {
        await page.waitForLoadState("load");
        return { page, stop: () => kill(proc) };
      }
      await until("page");
    }
  } catch (e) {
    kill(proc);
    throw e;
  }
}

export async function windows({ base, browser, shots, exe, cdpPort }) {
  const sfx = Date.now().toString(36).slice(-4);
  const H = { alice: `alice_${sfx}`, bob: `bob_${sfx}` };
  const t1 = `from the web secret-1 ${sfx}`;
  const t2 = `from the app secret-2 ${sfx}`;
  const t3 = `while the app runs secret-3 ${sfx}`;
  const screen = (d, title) => shots.screen(d.page, title);
  let code = "";
  let B;
  let W;
  let app;

  try {
    await step("alice and bob register on the web; bob writes to alice", async () => {
      const A = await device(browser, base, "alice (web)");
      code = await register(A, H.alice);
      unwatch(A.page);
      await A.ctx.close();
      B = await device(browser, base, "bob");
      await register(B, H.bob);
      await newConversation(B, H.alice);
      await send(B, t1);
      await sendImage(B, `img ${sfx}`);
    });

    await step("the installed app starts and shows its page", async () => {
      app = await launch(exe, cdpPort);
      W = { name: "app", page: app.page };
      watch("app", W.page);
      const origin = await W.page.evaluate(() => location.origin);
      check(origin === "https://tauri.localhost", `the app's page is at ${origin}`);
    });

    await step("the app unlocks with alice's recovery code", async () => {
      await signedOut(W);
      await screen(W, "signed out");
      await unlockWithCode(W, code, { atForm: () => screen(W, "unlock with the recovery code") });
    });

    await step("in the app, alice reads bob's request, accepts it and replies", async () => {
      await openRequest(W, `@${H.bob}`, t1);
      await screen(W, "request");
      await accept(W);
      await seenImage(W);
      await send(W, t2);
      await seen(B, t2);
    });

    await step("a message from the web reaches the running app", async () => {
      await send(B, t3);
      await seen(W, t3);
      await screen(W, "conversation");
      await openImage(W);
      await screen(W, "image");
      await closeImage(W);
      await openMembers(W);
      await screen(W, "members");
      await closeMembers(W);
      await settings(W);
      await screen(W, "settings");
      await closeSettings(W);
    });

    await step("no page errors or CSP violations", async () => {
      check(problems.length === 0, problems.join("\n"));
    });
  } finally {
    app?.stop();
  }
}
