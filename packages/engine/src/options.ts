// Engine options (docs/PROTOCOL.md §11): the transport, the clocks, and every protocol delay, so tests can inject
// them. The app constructs the engine without options.
import type { LocalNotifier, LocalStore } from "./local-notify";
import type { CacheStore, PreviewStore } from "./notify-cache";
import type { PushPlatform, PushStore } from "./push";
import type { QuietStore } from "./quiet";
import type { SessionStore } from "./session";
import type { PasskeyPlatform } from "./webauthn";

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
  /** a BELL row is posted after a random delay of up to this much (BELL_DELAY, §11.13) */
  bellDelay: number;
  /** an alias repeats a LEAVE after a random delay of up to this much (§2.6, §6.9) */
  aliasLeaveDelay: number;
  /** catch-up interval while the realtime socket is down (the inbox is read at each catch-up, and on notices, §11.5) */
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
  bellDelay: 60_000,
  aliasLeaveDelay: 12 * 3600_000,
  catchUpInterval: 10_000,
};

/** A WebSocket constructor (the browser's, or a test fake with the same surface). */
export type WebSocketCtor = new (url: string | URL, protocols?: string | string[]) => WebSocket;

export interface EngineOptions {
  /**
   * The canonical origin of the deployment, for a native app (§11.14): every API call and the realtime socket go there
   * (`https://segv.sh/api/v2/…`, `wss://segv.sh/api/v2/rt`), and the passkeys' RP ID is its host (§2.5). Absent: the
   * page's own origin, as in a browser.
   */
  origin?: string;
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
  /**
   * Web Push on this device (§11.13). Absent: the browser's (Push API, Service Worker) and localStorage; `platform`
   * null: no Web Push (the engine tests inject fakes).
   */
  push?: { platform: PushPlatform | null; store?: PushStore };
  /** The notification cache and the preview setting (§11.13); defaults: IndexedDB and localStorage. */
  notify?: { store: CacheStore | null; preview: PreviewStore };
  /**
   * "Quiet my other devices while I use this one" (§11.13): the setting (default localStorage) and whether the device is
   * in use (default: the page's visibility, focus and input; never without a page).
   */
  quiet?: { store?: QuietStore; inUse?: () => boolean };
  /**
   * Passkeys through the platform's own API (AuthenticationServices on macOS, §2.3, §11.14) instead of the web view's
   * WebAuthn, which cannot use the canonical host as RP ID from an app origin. Default: the browser's WebAuthn.
   */
  passkeys?: PasskeyPlatform;
  /**
   * Where the remembered session is kept (§11.11). Default: IndexedDB, under a non-extractable WebCrypto key. A native
   * app keeps it in its own files, under a key of the system's key store (§11.14 "Storage").
   */
  session?: SessionStore;
  /**
   * Notifications of an app without push (§11.13 "Apps without push"): shown by the app itself while it runs, from the
   * rows that reach it while it is not in use. With it, `push.platform` should be null.
   */
  local?: { notifier: LocalNotifier; store?: LocalStore };
  /**
   * Registers a listener for the system waking from sleep (§11.14 "Desktop"): the engine then replaces its realtime
   * sockets at once and catches up, instead of waiting for a probe to time out.
   */
  onWake?: (listener: () => void) => void;
}
