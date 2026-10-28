// "Quiet my other devices while I use this one" (docs/PROTOCOL.md §11.13 "Seen elsewhere"): while this device is in use,
// it marks seen the rows of other members that it shows as they arrive, and the server sends no push for them to any
// device of the account. A web push must show a notification (a browser revokes a subscription whose pushes show
// nothing), so a phone cannot drop the notification itself: the server holds every push back for a few seconds
// (PUSH_HOLD, §9.8) and cancels it when the account's mark comes first.
//
// The device sends nothing else: no mark while no row comes, and none while it is not in use, so the server learns that
// the account is in use only at the moments at which rows reach it (§13.4).
import * as P from "~/lib/proto";
import type { EngineClock, EngineTimer } from "./options";

/** A device is in use while its last input is at most this old (and its page is visible and focused). */
export const IN_USE_MS = 60_000;
/** A row is marked only when it was stored recently enough to have rung (§10.10 RING_FRESH). */
export const RING_FRESH_S = 60;
/** The most rows one `seen` marks (§10.10). */
export const SEEN_ROWS = 16;
/** Marks go out at most once per this, gathered; a retry waits as long. */
export const SEEN_EVERY_MS = 1_000;

/** The quiet setting: per device, on by default, never synced. */
export interface QuietStore {
  load(): boolean;
  save(on: boolean): void;
}

/** The setting in localStorage (storage that throws or is missing reads as on, the default). */
export function localQuietStore(key = "segv.quiet"): QuietStore {
  return {
    load() {
      try {
        return globalThis.localStorage?.getItem(key) !== "off";
      } catch {
        return true;
      }
    },
    save(on) {
      try {
        if (on) globalThis.localStorage?.removeItem(key);
        else globalThis.localStorage?.setItem(key, "off");
      } catch {
        // private mode or blocked storage: the setting lasts for this page only
      }
    },
  };
}

/** The parts of a page this needs. */
export interface PageLike {
  readonly visibilityState: DocumentVisibilityState;
  hasFocus(): boolean;
  addEventListener(type: string, f: () => void, o: AddEventListenerOptions): void;
}

/** Input that shows someone is at the device. Focus alone is not: a window keeps it after its user has left. */
const INPUT = ["keydown", "pointerdown", "pointermove", "touchstart", "wheel", "scroll"];

/**
 * Whether this page is in use now: visible, focused, and the user's last input on it at most IN_USE_MS old. Without a
 * page (a worker, the tests) it never is.
 */
export function pageInUse(
  page: PageLike | null = typeof document === "undefined" ? null : document,
  now: () => number = () => performance.now(),
): () => boolean {
  if (!page) return () => false;
  let last = -Infinity;
  const touch = () => {
    last = now();
  };
  for (const t of INPUT) page.addEventListener(t, touch, { capture: true, passive: true });
  return () => page.visibilityState === "visible" && page.hasFocus() && now() - last <= IN_USE_MS;
}

/** `POST /api/v2/seen`. Errors carry `status` (0: no answer). */
export interface SeenTransport {
  seen(qS: Uint8Array, rows: { E: number; label: Uint8Array }[]): Promise<void>;
}

export interface QuietClientOptions {
  transport: SeenTransport;
  store: QuietStore;
  clock: EngineClock;
  /** whether this device is in use now */
  inUse: () => boolean;
  /** whether the server offers push (params carry `push`) */
  offered: () => boolean;
  /** the account's quiet secret qS, or null without a session */
  secret: () => Uint8Array | null;
  /** Δ in seconds */
  delta: () => number;
  /** the estimated server time, Unix ms */
  serverNow: () => number;
}

const statusOf = (e: unknown): number => {
  const s = (e as { status?: unknown } | null)?.status;
  return typeof s === "number" ? s : 0;
};

export class QuietClient {
  private queue: { E: number; label: Uint8Array; key: string }[] = [];
  private queued = new Set<string>();
  private timer: EngineTimer | null = null;
  /** when the last request went out (monotonic) */
  private lastAt = -Infinity;

  constructor(private readonly o: QuietClientOptions) {}

  /** Whether the setting can be offered: the server offers push. This device's own notifications do not matter. */
  get available(): boolean {
    return this.o.offered();
  }

  get on(): boolean {
    return this.o.store.load();
  }

  set(on: boolean): void {
    this.o.store.save(on);
    if (!on) this.stop();
  }

  /**
   * A TEXT or IMAGE row of another member, stored at `t` (seconds since T0), was just shown and counted unread
   * (§11.13): marked seen while this device is in use and the row is fresh enough to have rung.
   */
  shown(E: number, label: Uint8Array, t: number): void {
    if (!this.available || !this.on || !this.o.inUse()) return;
    if (t + this.o.delta() < P.secOf(this.o.serverNow()) - RING_FRESH_S) return;
    const key = `${E}:${P.b64u(label)}`;
    if (this.queued.has(key)) return;
    this.queued.add(key);
    this.queue.push({ E, label, key });
    this.schedule();
  }

  /** Drops what is queued (at logout, or when the setting turns off). */
  stop(): void {
    this.timer?.cancel();
    this.timer = null;
    this.queue = [];
    this.queued.clear();
  }

  /** The first rows go out at once (after the rows applied with them), later ones at most once per SEEN_EVERY_MS. */
  private schedule(): void {
    if (this.timer || this.queue.length === 0) return;
    const wait = Math.max(0, this.lastAt + SEEN_EVERY_MS - this.o.clock.mono());
    this.timer = this.o.clock.setTimer(() => {
      this.timer = null;
      this.flush();
    }, wait);
  }

  private flush(): void {
    const qS = this.o.secret();
    if (!qS || !this.available || !this.on) return this.stop();
    const rows = this.queue.splice(0, SEEN_ROWS);
    for (const r of rows) this.queued.delete(r.key);
    this.lastAt = this.o.clock.mono();
    const body = rows.map(({ E, label }) => ({ E, label }));
    const attempt = (last: boolean): void => {
      this.o.transport.seen(qS, body).catch((e: unknown) => {
        const s = statusOf(e);
        if (last || (s !== 0 && s < 500)) return;
        this.o.clock.setTimer(() => attempt(true), SEEN_EVERY_MS);
      });
    };
    attempt(false);
    this.schedule();
  }
}
