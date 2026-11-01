// Notifications of an app without push (local-notify.ts; docs/PROTOCOL.md §11.13 "Apps without push"): what each one
// says with each preview, at most one per conversation per PUSH_WINDOW, none while the device is in use, closing when
// the conversation is shown, the badge, and the setting, against a fake notifier and a manual clock.
import { describe, expect, it } from "vite-plus/test";
import type { Preview } from "./notify-cache";
import type { EngineClock, EngineTimer } from "./options";
import {
  DEFAULT_WINDOW_MS,
  LocalNotify,
  noteFor,
  type Arrival,
  type LocalNotification,
  type LocalNotifier,
  type LocalPermission,
} from "./local-notify";

class ManualClock implements EngineClock {
  t = 0;
  private timers: { at: number; fn: () => void; dead: boolean }[] = [];
  mono = () => this.t;
  wall = () => this.t;
  setTimer(fn: () => void, ms: number): EngineTimer {
    const x = { at: this.t + Math.max(0, ms), fn, dead: false };
    this.timers.push(x);
    return { cancel: () => (x.dead = true) };
  }
  advance(ms: number): void {
    const end = this.t + ms;
    for (;;) {
      const next = this.timers.filter((x) => !x.dead && x.at <= end).sort((a, b) => a.at - b.at)[0];
      if (!next) break;
      this.t = next.at;
      next.dead = true;
      next.fn();
    }
    this.t = end;
  }
}

class FakeNotifier implements LocalNotifier {
  perm: LocalPermission = "default";
  answer: LocalPermission = "granted";
  shown: LocalNotification[] = [];
  closed: string[] = [];
  closedAll = 0;
  badges: number[] = [];
  permission = async () => this.perm;
  requestPermission = async () => (this.perm = this.answer);
  show = (n: LocalNotification) => void this.shown.push(n);
  close = (tag: string) => void this.closed.push(tag);
  closeAll = () => void this.closedAll++;
  badge = (count: number) => void this.badges.push(count);
}

const REF = "AbCdEfGhIjKl";
const arrival = (o: Partial<Arrival> = {}): Arrival => ({
  ref: REF,
  name: "@bob",
  handle: "bob",
  text: "hello",
  unread: 1,
  ...o,
});

function setup(o: { preview?: Preview; on?: boolean; window?: number } = {}) {
  const clock = new ManualClock();
  const notifier = new FakeNotifier();
  let stored = o.on ?? true;
  const st = { inUse: false, preview: o.preview ?? ("message" as Preview) };
  const n = new LocalNotify({
    notifier,
    store: { load: () => stored, save: (v) => void (stored = v) },
    clock,
    preview: () => st.preview,
    windowMs: () => o.window ?? DEFAULT_WINDOW_MS,
    inUse: () => st.inUse,
  });
  return { n, clock, notifier, st, stored: () => stored };
}

describe("noteFor (§11.13 steps 1–3)", () => {
  it("shows the fixed text, grouped under segv and opening the start page, with the preview none", () => {
    expect(noteFor(arrival(), "none")).toEqual({
      tag: "segv",
      title: "segv.sh",
      body: "new messages",
      open: "",
    });
  });

  it("shows the conversation's name with the preview name, and opens it", () => {
    expect(noteFor(arrival(), "name")).toEqual({
      tag: REF,
      title: "@bob",
      body: "new messages",
      open: `#c/${REF}`,
    });
  });

  it("shows the newest message as plain text, cut to 200 characters, with how many more are unread", () => {
    // A spoiler never reaches the lock screen.
    expect(noteFor(arrival({ text: "**hi** ||secret||", unread: 3 }), "message").body).toBe(
      "@bob: hi (spoiler) (+2)",
    );
    expect(noteFor(arrival({ text: null }), "message").body).toBe("@bob sent an image");
    const long = noteFor(arrival({ text: "x".repeat(300) }), "message").body;
    expect(Array.from(long)).toHaveLength(200);
    expect(long.endsWith("…")).toBe(true);
  });
});

describe("LocalNotify", () => {
  it("notifies at once, then at most once per conversation per PUSH_WINDOW, with the newest row", () => {
    const { n, clock, notifier } = setup();
    n.arrived(arrival({ text: "one" }));
    expect(notifier.shown.map((x) => x.body)).toEqual(["@bob: one"]);
    clock.advance(10_000);
    n.arrived(arrival({ text: "two", unread: 2 }));
    n.arrived(arrival({ text: "three", unread: 3 }));
    expect(notifier.shown).toHaveLength(1);
    clock.advance(DEFAULT_WINDOW_MS - 10_000);
    expect(notifier.shown.map((x) => x.body)).toEqual(["@bob: one", "@bob: three (+2)"]);
    // another conversation has its own window
    n.arrived(arrival({ ref: "ZZZZZZZZZZZZ", name: "@carol", handle: "carol" }));
    expect(notifier.shown).toHaveLength(3);
  });

  it("makes a waiting notification with the preview in effect when it is shown", () => {
    const { n, clock, notifier, st } = setup();
    n.arrived(arrival({ text: "one" }));
    n.arrived(arrival({ text: "a secret", unread: 2 }));
    st.preview = "name";
    clock.advance(DEFAULT_WINDOW_MS);
    expect(notifier.shown.map((x) => x.body)).toEqual(["@bob: one", "new messages"]);
    expect(notifier.shown.some((x) => x.body.includes("secret"))).toBe(false);
  });

  it("notifies nothing while the device is in use, or while notifications are off", () => {
    const a = setup();
    a.st.inUse = true;
    a.n.arrived(arrival());
    expect(a.notifier.shown).toHaveLength(0);
    const b = setup({ on: false });
    b.n.arrived(arrival());
    expect(b.notifier.shown).toHaveLength(0);
  });

  it("closes a conversation's notifications, and drops the one waiting, when the conversation is shown", () => {
    const { n, clock, notifier } = setup();
    n.arrived(arrival());
    n.arrived(arrival({ text: "later" }));
    n.shown(REF);
    expect(notifier.closed).toEqual([REF]);
    clock.advance(DEFAULT_WINDOW_MS);
    expect(notifier.shown).toHaveLength(1);
  });

  it("drops a waiting row when its conversation is shown, also with the fixed text", () => {
    const { n, clock, notifier } = setup({ preview: "none" });
    n.arrived(arrival({ text: "one" }));
    n.arrived(arrival({ text: "two", unread: 2 }));
    n.shown(REF);
    clock.advance(DEFAULT_WINDOW_MS);
    expect(notifier.shown).toHaveLength(1);
    expect(notifier.closed).toEqual([REF, "segv"]);
  });

  it("closes the fixed notification once every conversation it tells of is shown", () => {
    const { n, notifier } = setup({ preview: "none" });
    const OTHER = "ZZZZZZZZZZZZ";
    n.arrived(arrival());
    n.arrived(arrival({ ref: OTHER, name: "@carol", handle: "carol" }));
    expect(notifier.shown.map((x) => x.tag)).toEqual(["segv", "segv"]);
    n.shown(REF);
    expect(notifier.closed).toEqual([REF]);
    n.shown(OTHER);
    expect(notifier.closed).toEqual([REF, OTHER, "segv"]);
  });

  it("sets the badge only when the count changes", () => {
    const { n, notifier } = setup();
    n.badge(0);
    n.badge(2);
    n.badge(2);
    n.badge(1);
    expect(notifier.badges).toEqual([0, 2, 1]);
  });

  it("turns on only with the system's permission, and off with nothing left on screen", async () => {
    const a = setup({ on: false });
    a.notifier.answer = "denied";
    expect(await a.n.enable()).toBe(false);
    expect(a.stored()).toBe(false);
    a.notifier.answer = "granted";
    expect(await a.n.enable()).toBe(true);
    expect(a.stored()).toBe(true);
    a.n.arrived(arrival());
    a.n.arrived(arrival({ text: "waiting" }));
    a.n.disable();
    expect(a.stored()).toBe(false);
    expect(a.notifier.closedAll).toBe(1);
    a.clock.advance(DEFAULT_WINDOW_MS);
    expect(a.notifier.shown).toHaveLength(1);
  });

  it("turns itself off at start when the system no longer allows notifications", async () => {
    const { n, notifier, stored } = setup();
    notifier.perm = "denied";
    await n.check();
    expect(n.on).toBe(false);
    expect(stored()).toBe(false);
  });
});
