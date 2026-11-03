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
//
// What the system does is read through Windows PowerShell (5.1, which reaches WinRT): the browser that a link of a
// message starts, and the notifications that the app shows with its window closed (its toast history).
import { spawn, spawnSync } from "node:child_process";
import { chromium } from "playwright";
import { kill } from "./lib/server.mjs";
import { T, check, note, problems, step, unwatch, watch } from "./lib/harness.mjs";
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

/** The app's AppUserModelID, under which its toasts are kept (the installer's shortcut, src-tauri/src/lib.rs). */
const AUMID = "sh.segv.desktop";
/**
 * How long the window stays closed before a message comes: longer than the 5 minutes after which Chromium throttles a
 * hidden page's timers hardest, which the app must not depend on (docs/PROTOCOL.md §11.14 "Desktop").
 */
const HIDDEN_MS = Number(process.env.E2E_HIDDEN_MS ?? 6 * 60_000);

/** Runs a Windows PowerShell script and returns what it printed. */
function powershell(script) {
  const r = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    encoding: "utf8",
  });
  if (r.status !== 0) throw new Error(`PowerShell failed: ${(r.stderr || r.stdout).trim()}`);
  return r.stdout.trim();
}

/** Windows PowerShell's JSON of a list, which it prints as a lone object for one item. */
const list = (json) => (json ? [JSON.parse(json)].flat() : []);

const TOASTS =
  "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; " +
  "$h = [Windows.UI.Notifications.ToastNotificationManager]::History;";

/** The app's toasts in the notification center: their tags and XML. */
const toasts = () =>
  list(
    powershell(
      `${TOASTS} ConvertTo-Json -Compress -InputObject @($h.GetHistory('${AUMID}') | ForEach-Object { @{ tag = $_.Tag; xml = $_.Content.GetXml() } })`,
    ),
  );

const clearToasts = () => powershell(`${TOASTS} $h.Clear('${AUMID}')`);

/** The processes, other than this script's, whose command line holds `text`: a browser started for a URL. */
const processesWith = (text) =>
  list(
    powershell(
      `ConvertTo-Json -Compress -InputObject @(Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like '*${text}*' } | ForEach-Object { @{ id = $_.ProcessId; name = $_.Name } })`,
    ),
  );

/** Polls `fn` every 500 ms until it returns a truthy value, for at most `ms`; returns that value, or null. */
async function until(fn, ms) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) return null;
    await sleep(500);
  }
}

/** The page's visibility, read without waiting for a frame (a hidden page draws none). */
const visibility = (d) => d.page.evaluate(() => document.visibilityState);

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
        return { page, pid: proc.pid, alive: () => proc.exitCode === null, stop: () => kill(proc) };
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
  const t4 = `while the window is closed secret-4 ${sfx}`;
  const url = `https://example.com/segv-e2e-${sfx}`;
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

    await step("a link of a message opens in the browser, not in the app", async () => {
      await send(B, `see ${url}`);
      await seen(W, url);
      await W.page.locator(`.thread a[href="${url}"]`).first().click();
      const started = await until(() => processesWith(url), 30_000);
      check(started, `no browser started for the link`);
      note(`started ${started.map((p) => p.name).join(", ")}`);
      check(
        W.page.url().startsWith("https://tauri.localhost/"),
        `the app's window left its page: ${W.page.url()}`,
      );
      for (const p of started) spawnSync("taskkill", ["/pid", String(p.id), "/t", "/f"]);
    });

    await step("notifications turn on in the app, with the message shown", async () => {
      const dialog = await settings(W);
      await dialog.getByRole("button", { name: "turn on", exact: true }).click();
      await dialog
        .getByRole("button", { name: "turn off", exact: true })
        .waitFor({ timeout: T })
        .catch(() => {
          throw new Error("notifications did not turn on: the system refused them");
        });
      await dialog.getByRole("radio", { name: /the name and the newest message/ }).check();
      await screen(W, "settings, notifications on");
      await closeSettings(W);
    });

    let toast;
    await step(
      `with its window closed for ${Math.round(HIDDEN_MS / 60_000)} min, the app gets a message and notifies of it`,
      async () => {
        clearToasts();
        powershell(
          `if (-not (Get-Process -Id ${app.pid}).CloseMainWindow()) { throw 'no window to close' }`,
        );
        check(
          await until(async () => (await visibility(W)) === "hidden", 10_000),
          "the page did not go hidden",
        );
        await sleep(HIDDEN_MS);
        check((await visibility(W)) === "hidden", "the page did not stay hidden");
        check(app.alive(), "the app quit when its window closed");
        await send(B, t4);
        const sent = Date.now();
        toast = await until(() => toasts().find((n) => n.xml.includes(t4)), 30_000);
        // The page draws nothing while hidden, but keeps its title, which counts the unread messages.
        const title = await W.page.title();
        check(
          toast,
          `no notification of the message (title "${title}"); the app's notifications: ${JSON.stringify(toasts())}`,
        );
        note(`notified ${Date.now() - sent} ms after the send (title "${title}")`);
      },
    );

    await step("the notification's link opens the app at the conversation", async () => {
      const launch = /launch="([^"]+)"/.exec(toast.xml)?.[1]?.replaceAll("&amp;", "&") ?? "";
      check(
        /^segv:\/\/open#c\/[A-Za-z0-9_-]{12}$/.test(launch),
        `the notification opens ${launch}`,
      );
      // As a click on the toast does: the system opens its link, and the app's second instance hands it over.
      powershell(`Start-Process '${launch}'`);
      check(
        await until(async () => (await visibility(W)) === "visible", T),
        "the window did not open",
      );
      await seen(W, t4);
      const hash = await W.page.evaluate(() => location.hash);
      check(launch.endsWith(hash), `the app shows ${hash}, not the conversation of ${launch}`);
      await screen(W, "opened from a notification");
    });

    await step("no page errors or CSP violations", async () => {
      check(problems.length === 0, problems.join("\n"));
    });
  } finally {
    app?.stop();
  }
}
