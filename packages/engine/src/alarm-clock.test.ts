// The clock of a page that the system may throttle (alarm-clock.ts): with a base clock whose timers run only when the
// test lets them (a throttled page), timers still run when the native alarm comes, once each, and alarms are asked for
// only while the page is hidden and only when an earlier one is needed.
import { beforeEach, describe, expect, it } from "vite-plus/test";
import { alarmClock, type AlarmClock } from "./alarm-clock";
import type { EngineClock, EngineTimer } from "./options";

class PageClock implements EngineClock {
  t = 0;
  timers: { at: number; fn: () => void; live: boolean }[] = [];
  mono = (): number => this.t;
  wall = (): number => this.t;
  setTimer(fn: () => void, ms: number): EngineTimer {
    const timer = { at: this.t + Math.max(0, ms), fn, live: true };
    this.timers.push(timer);
    return { cancel: () => void (timer.live = false) };
  }
  /** Time passes; the page's own timers run only when `runs` (false: a throttled page). */
  advance(ms: number, runs: boolean): void {
    const end = this.t + ms;
    if (runs) {
      for (;;) {
        const next = this.timers
          .filter((x) => x.live && x.at <= end)
          .sort((a, b) => a.at - b.at)[0];
        if (!next) break;
        next.live = false;
        this.t = next.at;
        next.fn();
      }
    }
    this.t = end;
  }
}

describe("alarm clock", () => {
  let page: PageClock;
  let hidden: boolean;
  let arms: (number | null)[];
  let c: AlarmClock;

  beforeEach(() => {
    page = new PageClock();
    hidden = true;
    arms = [];
    c = alarmClock({ base: page, hidden: () => hidden, arm: (ms) => arms.push(ms) });
  });

  it("runs a hidden page's timers when the alarm comes, though the page's own timers do not run", () => {
    const ran: string[] = [];
    c.clock.setTimer(() => ran.push("ping"), 30_000);
    c.clock.setTimer(() => ran.push("catch-up"), 300_000);
    expect(arms).toEqual([30_250]); // one alarm, for the earliest
    page.advance(30_250, false);
    c.alarm();
    expect(ran).toEqual(["ping"]);
    expect(arms).toEqual([30_250, 270_000]); // then the next one
    page.advance(270_000, false);
    c.alarm();
    expect(ran).toEqual(["ping", "catch-up"]);
    // The page's own timers, when they finally run, run nothing twice.
    page.advance(1_000_000, true);
    expect(ran).toEqual(["ping", "catch-up"]);
  });

  it("runs every due timer in their order, including those set by the timers it runs", () => {
    const ran: number[] = [];
    c.clock.setTimer(() => ran.push(2), 2_000);
    c.clock.setTimer(() => {
      ran.push(1);
      c.clock.setTimer(() => ran.push(3), 0);
    }, 1_000);
    page.advance(10_000, false);
    c.alarm();
    expect(ran).toEqual([1, 2]);
    expect(arms.at(-1)).toBe(250); // the new timer asks for an alarm of its own
    page.advance(250, false);
    c.alarm();
    expect(ran).toEqual([1, 2, 3]);
  });

  it("asks for an alarm only when an earlier one is needed", () => {
    c.clock.setTimer(() => {}, 10_000);
    c.clock.setTimer(() => {}, 20_000); // later: the pending alarm comes first and asks again
    c.clock.setTimer(() => {}, 5_000); // earlier: a new alarm
    expect(arms).toEqual([10_250, 5_250]);
  });

  it("needs no alarm while the page runs its own timers on time", () => {
    const ran: string[] = [];
    c.clock.setTimer(() => ran.push("a"), 1_000);
    page.advance(1_000, true);
    expect(ran).toEqual(["a"]);
    c.alarm(); // the alarm still comes, and finds nothing to run
    expect(ran).toEqual(["a"]);
  });

  it("does not run a timer before its time, or one that was cancelled", () => {
    const ran: string[] = [];
    const t = c.clock.setTimer(() => ran.push("cancelled"), 1_000);
    c.clock.setTimer(() => ran.push("later"), 60_000);
    t.cancel();
    page.advance(5_000, false);
    c.alarm();
    expect(ran).toEqual([]);
    expect(arms.at(-1)).toBe(55_250);
  });

  it("keeps running the other timers when one throws", async () => {
    const ran: string[] = [];
    const errors: unknown[] = [];
    const onError = (e: unknown) => errors.push(e);
    process.on("uncaughtException", onError);
    try {
      c.clock.setTimer(() => {
        throw new Error("boom");
      }, 1_000);
      c.clock.setTimer(() => ran.push("after"), 2_000);
      page.advance(2_000, false);
      c.alarm();
      expect(ran).toEqual(["after"]);
      await new Promise((r) => setTimeout(r, 0));
      expect(errors).toHaveLength(1);
    } finally {
      process.off("uncaughtException", onError);
    }
  });

  it("asks for alarms only while the page is hidden", () => {
    hidden = false;
    c.clock.setTimer(() => {}, 1_000);
    expect(arms).toEqual([]);
    hidden = true;
    c.visibility();
    expect(arms).toEqual([1_250]);
    hidden = false;
    c.visibility();
    expect(arms).toEqual([1_250, null]); // shown: the alarm is cancelled
    c.visibility();
    expect(arms).toEqual([1_250, null]);
  });

  it("asks for alarms in whole milliseconds, rounded up, from a clock with fractions", () => {
    page.t = 1234.5678; // performance.now() in Chromium
    const ran: string[] = [];
    c.clock.setTimer(() => ran.push("ping"), 30_000);
    expect(arms).toEqual([30_250]);
    page.advance(0.4, false);
    c.clock.setTimer(() => ran.push("probe"), 10_000);
    expect(arms).toEqual([30_250, 10_250]);
    expect(arms.every((ms) => ms === null || Number.isInteger(ms))).toBe(true);
    page.advance(10_250, false); // the alarm of 10 250 ms, which the page asked for rounded up
    c.alarm();
    expect(ran).toEqual(["probe"]);
    expect(arms.every((ms) => ms === null || Number.isInteger(ms))).toBe(true);
  });

  it("asks again when the pending alarm never came", () => {
    c.clock.setTimer(() => {}, 1_000);
    page.advance(10_000, false); // the alarm at 1 250 was lost
    c.clock.setTimer(() => {}, 30_000);
    expect(arms).toEqual([1_250, 0]);
  });
});
