// A clock whose timers keep their schedule in a page that the system may throttle (docs/PROTOCOL.md §11.14 "Desktop"):
// a desktop app's page runs on while its window is closed, but a hidden web view may run its timers late or rarely,
// and with them the realtime socket's pings and reconnects (§10.8), the catch-up (§11.6) and the notifications
// (§11.13). Each timer is still the page's own; while the page is hidden, the app's native code also keeps one alarm at
// the earliest timer's time, a little after it, and the alarm, an event, runs every timer that is due by then. A timer
// that runs on time needs no alarm: the next one is asked for only when it is earlier than the one pending.
import { systemClock, type EngineClock, type EngineTimer } from "./options";

export interface AlarmClockOptions {
  /** asks the native code for one alarm `ms` (whole milliseconds) from now, replacing the pending one; null cancels it */
  arm(ms: number | null): void;
  /** whether the page is hidden, and so may be throttled: alarms are asked for only then */
  hidden(): boolean;
  /** the page's own clock and timers (default: systemClock) */
  base?: EngineClock;
  /** how long after a timer's time its alarm comes, so that a timer that runs on time beats it (default 250 ms) */
  slackMs?: number;
}

export interface AlarmClock {
  readonly clock: EngineClock;
  /** The alarm came: runs every timer that is due, then asks for the next alarm. */
  alarm(): void;
  /** The page was shown or hidden. */
  visibility(): void;
}

/** A pending alarm older than this was lost (an event that never came): the next timer asks for a new one. */
const LOST_MS = 5_000;

interface Entry {
  at: number;
  fn: () => void;
  done: boolean;
  inner: EngineTimer | null;
}

export function alarmClock(o: AlarmClockOptions): AlarmClock {
  const base = o.base ?? systemClock;
  const slack = o.slackMs ?? 250;
  const pending = new Set<Entry>();
  /** the time of the alarm asked for, on the base clock, or null */
  let armedAt: number | null = null;

  const drop = (e: Entry) => {
    e.done = true;
    pending.delete(e);
    e.inner?.cancel();
  };

  const rearm = () => {
    if (!o.hidden()) {
      if (armedAt !== null) {
        armedAt = null;
        o.arm(null);
      }
      return;
    }
    let next = Infinity;
    for (const e of pending) if (e.at < next) next = e.at;
    // With no timer left, a pending alarm finds nothing to run, which costs nothing.
    if (next === Infinity) return;
    const at = next + slack;
    const now = base.mono();
    if (armedAt !== null && armedAt <= at && armedAt > now - LOST_MS) return;
    armedAt = at;
    // In whole milliseconds, rounded up: the native command takes no fraction, and a timer is never run early.
    o.arm(Math.max(0, Math.ceil(at - now)));
  };

  const clock: EngineClock = {
    mono: () => base.mono(),
    wall: () => base.wall(),
    setTimer(fn, ms) {
      const e: Entry = { at: base.mono() + Math.max(0, ms), fn, done: false, inner: null };
      pending.add(e);
      e.inner = base.setTimer(() => {
        if (e.done) return;
        drop(e);
        e.fn();
        rearm();
      }, ms);
      rearm();
      return { cancel: () => drop(e) };
    },
  };

  return {
    clock,
    alarm() {
      armedAt = null;
      const now = base.mono();
      const due = [...pending].filter((e) => e.at <= now).sort((a, b) => a.at - b.at);
      for (const e of due) {
        if (e.done) continue; // cancelled by an earlier one
        drop(e);
        try {
          e.fn();
        } catch (err) {
          // Reported as a timer's error would be, without keeping the other timers from running.
          queueMicrotask(() => {
            throw err;
          });
        }
      }
      rearm();
    },
    visibility: rearm,
  };
}
