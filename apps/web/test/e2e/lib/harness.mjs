// The end-to-end runs' harness: steps that stop at the first failure (each one builds on the state of the ones before
// it), the problems that pages report, and screenshots of each screen.
//
// Screenshots go to <dir>/<group>/<NN>-<screen>.<variant>.png: NN orders the screens, <screen> is the title in
// lowercase words joined by "-", and <variant> is one of
//   light    the page in the light color scheme
//   dark     the page in the dark color scheme
//   narrow   the page in a phone's viewport (390 × 844), which shows one pane at a time (pages with a viewport only)
// A failed step adds 99-failed-<device>.light.png for each device, as its page was.
// .github/scripts/screenshots.mjs reads these names, and nothing else, to lay the screenshots out in a pull request.
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";

/** The timeout of each wait for the UI. */
export const T = 60_000;

export function check(cond, msg) {
  if (!cond) throw new Error(msg);
}

let failed = false;
/** Every page that a run drives, for the screenshots and texts of a failure. */
const pages = [];
/** Console errors, page errors and CSP violations. */
export const problems = [];
/** Where a failure's screenshots go: the group of the latest shots(). */
let failures = null;

/** Console errors that a fresh deployment causes by design, as "<text> @ <url>". */
const EXPECTED = [
  // No checkpoint yet (§9.5): /api/v2/ckpt/latest answers 404 until the deployment makes its first one.
  /^Failed to load resource: .* 404 .* @ https?:\/\/[^/]+\/api\/v2\/ckpt\/latest$/,
];

/**
 * Watches a page: its console errors (except the EXPECTED ones) and uncaught errors become problems, and a failure
 * takes its screenshot.
 */
export function watch(name, page) {
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    const error = `${m.text()} @ ${m.location().url}`;
    if (!EXPECTED.some((re) => re.test(error))) problems.push(`[${name}] console.error: ${error}`);
  });
  page.on("pageerror", (e) => problems.push(`[${name}] pageerror: ${e.message}`));
  pages.push({ name, page });
}

export function unwatch(page) {
  const i = pages.findIndex((p) => p.page === page);
  if (i >= 0) pages.splice(i, 1);
}

/** Runs a step. A failing step records every watched page and ends the run (step throws). */
export async function step(name, fn) {
  const t0 = Date.now();
  try {
    await fn();
    console.log(`  ok   ${name} (${Date.now() - t0} ms)`);
  } catch (e) {
    failed = true;
    console.log(`  FAIL ${name}: ${e?.message?.split("\n").slice(0, 6).join(" | ")}`);
    for (const { name: who, page } of pages) {
      try {
        await failures?.(page, who);
        const text = (await page.locator("body").innerText()).replace(/\s+/g, " ").slice(0, 600);
        console.log(`  [${who}] ${text}`);
      } catch {
        /* closed */
      }
    }
    throw e;
  }
}

export function note(line) {
  console.log(`       ${line}`);
}

const slug = (title) =>
  title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");

/** Waits until the page has its fonts and images decoded, and has painted twice since. */
async function settle(page) {
  await page.evaluate(async () => {
    await document.fonts.ready;
    await Promise.all([...document.images].map((i) => i.decode().catch(() => {})));
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  });
}

/**
 * The screenshots of one group (one app): each screen in each of `variants`. `backdrop` gives, for each color scheme,
 * the color behind a transparent page: what the window shows there (Mica on Windows), which a capture of the page
 * leaves white.
 */
export function shots(dir, group, variants, { backdrop } = {}) {
  const at = join(dir, group);
  rmSync(at, { recursive: true, force: true });
  mkdirSync(at, { recursive: true });
  let n = 0;
  const take = async (page, name, variant) => {
    const color = backdrop?.[variant];
    const cdp = color ? await page.context().newCDPSession(page) : null;
    await cdp?.send("Emulation.setDefaultBackgroundColorOverride", { color });
    await settle(page);
    await page.screenshot({
      path: join(at, `${name}.${variant}.png`),
      animations: "disabled",
      caret: "hide",
    });
    await cdp?.send("Emulation.setDefaultBackgroundColorOverride", {});
    await cdp?.detach();
  };
  failures = (page, who) => page.screenshot({ path: join(at, `99-failed-${slug(who)}.light.png`) });
  return {
    /** Takes the screen that `page` shows, titled `title`, in every variant; leaves the page as it was. */
    async screen(page, title) {
      const name = `${String(++n).padStart(2, "0")}-${slug(title)}`;
      for (const variant of variants) {
        if (variant === "narrow") {
          const size = page.viewportSize();
          await page.setViewportSize({ width: 390, height: 844 });
          await take(page, name, variant);
          await page.setViewportSize(size);
        } else {
          await page.emulateMedia({ colorScheme: variant });
          await take(page, name, variant);
          await page.emulateMedia({ colorScheme: null });
        }
      }
    },
  };
}

/** Prints the verdict; true when every step passed and nothing else threw (`error`). */
export function report(error) {
  if (error && !failed) {
    failed = true;
    console.log(`  FAIL outside a step: ${error?.stack ?? error}`);
  }
  console.log(`\n${failed ? "FAILED" : "PASSED"}`);
  return !failed;
}
