// The push Service Worker (public/sw.js; docs/PROTOCOL.md §11.13), run against a minimal worker-like `self`.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vite-plus/test";

const SOURCE = readFileSync(new URL("../../public/sw.js", import.meta.url), "utf8");
const ORIGIN = "https://segv.test";

interface Shown {
  title: string;
  opts: { body: string; tag: string; data: { navigate: string } };
}

function load(windows: { url: string; focused?: boolean }[] = []) {
  const listeners = new Map<string, (ev: unknown) => void>();
  const shown: Shown[] = [];
  const opened: string[] = [];
  const focused: string[] = [];
  const self = {
    location: new URL(`${ORIGIN}/sw.js`),
    addEventListener: (type: string, f: (ev: unknown) => void) => listeners.set(type, f),
    skipWaiting: () => Promise.resolve(),
    registration: {
      showNotification: (title: string, opts: Shown["opts"]) => {
        shown.push({ title, opts });
        return Promise.resolve();
      },
    },
    clients: {
      claim: () => Promise.resolve(),
      matchAll: () =>
        Promise.resolve(
          windows.map((w) => ({
            url: w.url,
            focus: () => {
              focused.push(w.url);
              return Promise.resolve();
            },
          })),
        ),
      openWindow: (u: string) => {
        opened.push(u);
        return Promise.resolve(null);
      },
    },
  };
  new Function("self", SOURCE)(self);
  /** Dispatches an event and waits for what it passed to waitUntil. */
  async function dispatch(type: string, ev: Record<string, unknown>): Promise<void> {
    let pending: Promise<unknown> = Promise.resolve();
    listeners.get(type)?.({ ...ev, waitUntil: (p: Promise<unknown>) => (pending = p) });
    await pending;
  }
  const push = (data: unknown) =>
    dispatch("push", {
      data:
        data === null
          ? null
          : {
              json: () => {
                if (typeof data === "string") return JSON.parse(data);
                return data;
              },
            },
    });
  const click = (navigate: unknown) =>
    dispatch("notificationclick", { notification: { data: { navigate }, close: () => {} } });
  return { listeners, shown, opened, focused, push, click };
}

const PAYLOAD =
  '{"web_push":8030,"notification":{"title":"segv.sh","body":"new messages","navigate":"https://segv.test/","tag":"segv"}}';

describe("public/sw.js", () => {
  it("has no fetch handler", () => {
    const sw = load();
    expect([...sw.listeners.keys()].sort()).toEqual([
      "activate",
      "install",
      "notificationclick",
      "push",
    ]);
  });

  it("shows the payload's title, body and tag", async () => {
    const sw = load();
    await sw.push(PAYLOAD);
    expect(sw.shown).toEqual([
      {
        title: "segv.sh",
        opts: { body: "new messages", tag: "segv", data: { navigate: `${ORIGIN}/` } },
      },
    ]);
  });

  it("shows the fixed notification for any other data, and never a cross-origin navigate", async () => {
    const sw = load();
    await sw.push(null);
    await sw.push("not json {");
    await sw.push({ web_push: 1, notification: { title: "x" } });
    await sw.push({
      web_push: 8030,
      notification: { title: "", body: 5, tag: "t", navigate: "https://evil.example/" },
    });
    for (const s of sw.shown) expect(s.title).toBe("segv.sh");
    expect(sw.shown.map((s) => s.opts.body)).toEqual([
      "new messages",
      "new messages",
      "new messages",
      "new messages",
    ]);
    expect(sw.shown[3].opts.tag).toBe("t");
    expect(sw.shown.every((s) => s.opts.data.navigate === "/")).toBe(true);
  });

  it("a click focuses an open window of the app, or opens navigate", async () => {
    const open = load([{ url: "https://other.example/" }, { url: `${ORIGIN}/` }]);
    await open.click(`${ORIGIN}/`);
    expect(open.focused).toEqual([`${ORIGIN}/`]);
    expect(open.opened).toEqual([]);
    const none = load();
    await none.click(`${ORIGIN}/`);
    expect(none.opened).toEqual([`${ORIGIN}/`]);
  });
});
