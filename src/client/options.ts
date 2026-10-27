// Engine options (docs/PROTOCOL.md §11): the transport, the clocks, and every protocol delay, so tests can inject
// them (docs/STAGE1-PLAN.md §2.2). The app constructs the engine without options.

/** A scheduled callback; `cancel()` is idempotent. */
export interface EngineTimer {
  cancel(): void;
}

/**
 * The engine's clocks (§10.1, §11.3). Timers run on the monotonic clock. The server-time estimate is anchored on the
 * monotonic clock and never reads the wall clock; only the elapsed-time checks of §11.3 steps 6 and 8 read `wall()`.
 */
export interface EngineClock {
  /** monotonic milliseconds (performance.now(); a browser may stop it while the system sleeps) */
  mono(): number;
  /** wall-clock milliseconds (Date.now(); the user or the system may set it) */
  wall(): number;
  /** runs `fn` once `ms` of monotonic time have passed */
  setTimer(fn: () => void, ms: number): EngineTimer;
}

export const systemClock: EngineClock = {
  mono: () => performance.now(),
  wall: () => Date.now(),
  setTimer(fn, ms) {
    const t = setTimeout(fn, Math.max(0, ms));
    return { cancel: () => clearTimeout(t) };
  },
};

/** Protocol delays (ms). Tests shorten them; production uses the defaults. */
export interface EngineDelays {
  /** first back-off after a transient failure of background work (doubles up to `retryMax`) */
  retryBase: number;
  retryMax: number;
  /** the processing wait of §11.3 step 2 (a send waits this long for a pending claim before it is refused) */
  processingWait: number;
  /** the rotation rank delay of §6.9 */
  rotationRank: number;
  /** RESUME_AFTER (§6.11) */
  resumeAfter: number;
  /** a HEADS self row is written at most this often (§7.3) */
  headsInterval: number;
  /** and after a random delay of up to this much */
  headsJitter: number;
  /** inbox poll interval (§11.5: max(inboxSlot, 2) s by default; 0 = derived from params) */
  pollInterval: number;
  /** catch-up interval while the realtime socket is down */
  catchUpInterval: number;
}

export const DEFAULT_DELAYS: EngineDelays = {
  retryBase: 500,
  retryMax: 30_000,
  processingWait: 30_000,
  rotationRank: 10_000,
  resumeAfter: 10 * 60_000,
  headsInterval: 30 * 60_000,
  headsJitter: 5 * 60_000,
  pollInterval: 0,
  catchUpInterval: 10_000,
};

/** A WebSocket constructor (the browser's, or a test fake with the same surface). */
export type WebSocketCtor = new (url: string | URL, protocols?: string | string[]) => WebSocket;

export interface EngineOptions {
  /** HTTP transport (default: the global fetch) */
  fetch?: typeof fetch;
  /** realtime transport (default: the global WebSocket) */
  WebSocket?: WebSocketCtor;
  /** clocks and timers (default: performance.now / Date.now / setTimeout) */
  clock?: EngineClock;
  delays?: Partial<EngineDelays>;
  /** test hook awaited after the proof of work of a put and before the fresh-probe check (§11.3 step 6) */
  beforePutAttempt?: () => void | Promise<void>;
  /**
   * Creates the trial-decryption Web Worker (§11.5 step 2). Absent: the default factory; `null`, or a factory that
   * resolves to null: no worker, trial decryption runs on the same thread (the engine tests set it to null).
   */
  inboxWorker?: (() => Promise<Worker | null>) | null;
}
