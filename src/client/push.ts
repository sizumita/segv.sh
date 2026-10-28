// Notifications on this device (docs/PROTOCOL.md §11.13): the per-device setting, the browser's push subscription,
// its registration with the server, and the ring a sender makes after a text or an image. The engine passes in what it
// owns (the registration set, the API, the clock), so this module keeps no protocol state of its own.
import * as P from "~/lib/proto";
import type { EngineClock, EngineTimer } from "./options";

/** params.push (§10.9), decoded. */
export interface PushParams {
  vapid: Uint8Array;
  window: number;
  maxTokens: number;
}

export interface PushSubBody {
  endpoint: string;
  p256dh: string;
  auth: string;
  tokens: string[];
  /** the account's quiet tag Qself (§4.1), so that its marks reach this endpoint; absent when deleting */
  quiet?: string;
}

/** The two endpoints of §10.10. Errors carry `status` (0: no answer) and `retryAfter` (seconds or null). */
export interface PushTransport {
  pushSub(body: PushSubBody): Promise<void>;
  ring(E: number, label: Uint8Array, tokens: Uint8Array[]): Promise<void>;
}

export interface PushSubscriptionLike {
  readonly endpoint: string;
  readonly options: { readonly applicationServerKey: ArrayBuffer | null };
  getKey(name: "p256dh" | "auth"): ArrayBuffer | null;
  unsubscribe(): Promise<boolean>;
}

export interface PushManagerLike {
  getSubscription(): Promise<PushSubscriptionLike | null>;
  subscribe(options: {
    userVisibleOnly: true;
    applicationServerKey: BufferSource;
  }): Promise<PushSubscriptionLike>;
}

/** The browser's side of Web Push. */
export interface PushPlatform {
  permission(): NotificationPermission;
  requestPermission(): Promise<NotificationPermission>;
  /** The push manager of the Service Worker, registering it first. */
  manager(): Promise<PushManagerLike>;
  /** The push manager of an already registered Service Worker, or null (never registers one). */
  existing(): Promise<PushManagerLike | null>;
}

/** What the device remembers, never synced: whether notifications are on, and the endpoint it last registered. */
export interface PushSetting {
  on: boolean;
  endpoint: string | null;
}

export interface PushStore {
  load(): PushSetting;
  save(s: PushSetting): void;
}

const OFF: PushSetting = { on: false, endpoint: null };

/** The setting in localStorage (per browser profile; storage that throws or is missing reads as off). */
export function localPushStore(key = "segv.push"): PushStore {
  return {
    load() {
      try {
        const v = JSON.parse(
          globalThis.localStorage?.getItem(key) ?? "null",
        ) as Partial<PushSetting> | null;
        return v && typeof v.on === "boolean"
          ? { on: v.on, endpoint: typeof v.endpoint === "string" ? v.endpoint : null }
          : OFF;
      } catch {
        return OFF;
      }
    },
    save(s) {
      try {
        globalThis.localStorage?.setItem(key, JSON.stringify(s));
      } catch {
        // private mode or blocked storage: the setting lasts for this page only
      }
    },
  };
}

/**
 * The browser's Web Push, or null where it is missing. Safari on iOS and iPadOS exposes it only to a web app added to
 * the Home Screen, so feature detection is enough.
 */
export function browserPushPlatform(): PushPlatform | null {
  if (typeof window === "undefined" || typeof navigator === "undefined") return null;
  if (
    !("serviceWorker" in navigator) ||
    !("PushManager" in window) ||
    typeof Notification === "undefined"
  )
    return null;
  const asManager = (r: ServiceWorkerRegistration): PushManagerLike =>
    r.pushManager as unknown as PushManagerLike;
  return {
    permission: () => Notification.permission,
    requestPermission: () => Notification.requestPermission(),
    manager: async () => asManager(await (await import("./sw-url")).pushServiceWorker()),
    existing: async () => {
      const r = await navigator.serviceWorker.getRegistration("/");
      return r ? asManager(r) : null;
    },
  };
}

export interface PushClientOptions {
  transport: PushTransport;
  platform: PushPlatform | null;
  store: PushStore;
  clock: EngineClock;
  /** params.push, or null when the server offers no push */
  params: () => PushParams | null;
  /** Δ in ms: re-sends are batched over it, and a ring's retry falls within it */
  deltaMs: () => number;
  /** the registration set (§11.13), newest `lastTs` first */
  bells: () => Uint8Array[];
  /** the account's quiet tag Qself (§4.1), registered with the set; null without a session */
  quiet?: () => Uint8Array | null;
  /** told when the setting turns off by itself (push gone from the server, or a subscription that needs a click) */
  onOff?: () => void;
  random?: () => number;
}

const DAY_MS = 86_400_000;
const RETRY_MIN = 1_000;
const RETRY_MAX = 600_000;

const statusOf = (e: unknown): number => {
  const s = (e as { status?: unknown } | null)?.status;
  return typeof s === "number" ? s : 0;
};

function sameKey(s: PushSubscriptionLike, vapid: Uint8Array): boolean {
  const k = s.options.applicationServerKey;
  // A browser that does not report the key cannot tell: keep the subscription.
  return k === null || P.equalBytes(new Uint8Array(k), vapid);
}

function bodyOf(s: PushSubscriptionLike, tokens: string[]): PushSubBody {
  const p = s.getKey("p256dh");
  const a = s.getKey("auth");
  if (!p || !a) throw new Error("push subscription without keys");
  return {
    endpoint: s.endpoint,
    p256dh: P.b64u(new Uint8Array(p)),
    auth: P.b64u(new Uint8Array(a)),
    tokens,
  };
}

export class PushClient {
  private timer: EngineTimer | null = null;
  private dueAt = Infinity;
  private retry = RETRY_MIN;
  private notBefore = 0;
  private syncing: Promise<void> | null = null;
  private again = false;
  private stopped = false;
  /** the endpoint and set last registered, and when (monotonic): an unchanged set is sent again only daily */
  private lastKey: string | null = null;
  private lastAt = -Infinity;
  /** the next sync sends even an unchanged set (at start, after a restore, after turning on) */
  private force = false;

  constructor(private readonly o: PushClientOptions) {}

  /** Whether the setting can be offered: the browser has Web Push and the server offers it. */
  get available(): boolean {
    return this.o.platform !== null && this.o.params() !== null;
  }

  get on(): boolean {
    return this.o.store.load().on;
  }

  /** Turns notifications on. Call it from the user's click: it may ask for permission. */
  async enable(): Promise<void> {
    const pl = this.o.platform;
    const params = this.o.params();
    if (!pl || !params) throw new Error("notifications are not available in this browser");
    // Both start inside the click: the permission prompt needs the user's gesture, and registering the Service Worker
    // meanwhile keeps the subscription below from waiting for it after the gesture has passed.
    const asked =
      pl.permission() === "granted" ? Promise.resolve("granted" as const) : pl.requestPermission();
    const mgrP = pl.manager();
    mgrP.catch(() => {});
    if ((await asked) !== "granted") throw new Error("notifications are not allowed for this site");
    const mgr = await mgrP;
    let s = await mgr.getSubscription();
    if (s && !sameKey(s, params.vapid)) {
      await s.unsubscribe().catch(() => false);
      s = null;
    }
    if (!s)
      await mgr.subscribe({
        userVisibleOnly: true,
        applicationServerKey: params.vapid as BufferSource,
      });
    this.o.store.save({ ...this.o.store.load(), on: true });
    this.stopped = false;
    this.force = true;
    await this.syncNow();
  }

  /** Turns notifications off: the subscription ends first, then its registration is deleted (§11.13). */
  disable(): Promise<void> {
    return this.off();
  }

  /** At logout, the same as turning notifications off: the next account on this browser starts with them off. */
  logout(): Promise<void> {
    return this.off();
  }

  /**
   * The registration set may have changed (epoch switch, join, acceptance, new contact, leave, end): within Δ the set
   * is computed again, and sent if it differs from the one last registered.
   */
  changed(): void {
    this.schedule(this.o.deltaMs());
  }

  /** At start and after each restore: the set is sent even if unchanged. */
  restored(): void {
    this.force = true;
    this.schedule(0);
  }

  /**
   * After a successful TEXT or IMAGE put (§11.3 step 6): ask the server to ring the other lanes' bells. Never waits;
   * one retry within Δ after a network error, a timeout or a 5xx, none after a 4xx.
   */
  ring(E: number, label: Uint8Array, bells: Uint8Array[]): void {
    if (bells.length === 0 || this.o.params() === null) return;
    const tokens = bells.slice(0, 64);
    const attempt = (last: boolean): void => {
      this.o.transport.ring(E, label, tokens).catch((e: unknown) => {
        const s = statusOf(e);
        if (last || (s !== 0 && s < 500)) return;
        this.o.clock.setTimer(
          () => attempt(true),
          Math.floor((this.o.random ?? Math.random)() * this.o.deltaMs()),
        );
      });
    };
    attempt(false);
  }

  stop(): void {
    this.stopped = true;
    this.timer?.cancel();
    this.timer = null;
    this.dueAt = Infinity;
  }

  /**
   * Resolves once the subscription has ended; deleting its registration (a request with a proof of work) goes on in
   * the background.
   */
  private async off(): Promise<void> {
    this.stop();
    this.o.store.save(OFF);
    this.lastKey = null;
    const pl = this.o.platform;
    const offered = this.o.params() !== null;
    if (!pl) return;
    let s: PushSubscriptionLike | null = null;
    try {
      s = (await (await pl.existing())?.getSubscription()) ?? null;
    } catch {
      s = null;
    }
    if (!s) return;
    // Read the endpoint and keys, end the subscription, then delete the registration: in the other order a tab closed
    // in between would leave a live subscription registered for whoever uses this browser next.
    let body: PushSubBody | null = null;
    try {
      body = bodyOf(s, []);
    } catch {
      body = null;
    }
    await s.unsubscribe().catch(() => false);
    if (body && offered) void this.o.transport.pushSub(body).catch(() => {});
  }

  private turnOff(): void {
    this.stop();
    this.o.store.save(OFF);
    this.o.onOff?.();
  }

  private schedule(ms: number): void {
    if (this.stopped || !this.on || !this.available) return;
    const now = this.o.clock.mono();
    const at = Math.max(now + ms, this.notBefore);
    if (at >= this.dueAt) return;
    this.timer?.cancel();
    this.dueAt = at;
    this.timer = this.o.clock.setTimer(() => {
      this.timer = null;
      this.dueAt = Infinity;
      void this.syncNow();
    }, at - now);
  }

  private syncNow(): Promise<void> {
    if (this.syncing) {
      this.again = true;
      return this.syncing;
    }
    this.syncing = this.sync().finally(() => {
      this.syncing = null;
      if (this.again) {
        this.again = false;
        this.schedule(0);
      }
    });
    return this.syncing;
  }

  /** Registers the current set for the current subscription, handling a new endpoint, a new key or a lost one. */
  private async sync(): Promise<void> {
    const pl = this.o.platform;
    const params = this.o.params();
    const st = this.o.store.load();
    if (!st.on || !pl || !params || this.stopped) return;
    const force = this.force || this.o.clock.mono() >= this.lastAt + DAY_MS;
    this.force = false;
    try {
      const mgr = await pl.manager();
      let s = await mgr.getSubscription();
      let deleted: string | null = null;
      if (s && !sameKey(s, params.vapid)) {
        // The server's VAPID key changed: end this subscription, delete its registration, subscribe again.
        const old = bodyOf(s, []);
        await s.unsubscribe().catch(() => false);
        await this.o.transport.pushSub(old).catch(() => {});
        deleted = old.endpoint;
        s = null;
      }
      if (!s) {
        try {
          s = await mgr.subscribe({
            userVisibleOnly: true,
            applicationServerKey: params.vapid as BufferSource,
          });
        } catch {
          // Subscribing again needs a click here: show the setting off.
          this.turnOff();
          return;
        }
      }
      // A new endpoint: delete the old one's registration first (its keys are gone; any valid keys serve).
      if (st.endpoint !== null && st.endpoint !== s.endpoint && st.endpoint !== deleted)
        await this.o.transport.pushSub({ ...bodyOf(s, []), endpoint: st.endpoint });
      const seen = new Set<string>();
      const tokens: string[] = [];
      for (const b of this.o.bells()) {
        const t = P.b64u(b);
        if (seen.has(t)) continue;
        seen.add(t);
        tokens.push(t);
        if (tokens.length >= params.maxTokens) break;
      }
      const q = this.o.quiet?.() ?? null;
      const quiet = q ? P.b64u(q) : null;
      // Each registration costs a proof of work: an unchanged set for the same endpoint waits for the daily refresh.
      const key = `${s.endpoint} ${quiet ?? ""} ${tokens.join(",")}`;
      if (force || key !== this.lastKey || st.endpoint !== s.endpoint) {
        await this.o.transport.pushSub({ ...bodyOf(s, tokens), ...(quiet ? { quiet } : {}) });
        this.o.store.save({ on: true, endpoint: s.endpoint });
        this.lastKey = key;
        this.lastAt = this.o.clock.mono();
      }
      this.retry = RETRY_MIN;
      this.notBefore = 0;
      // At least once a day while running (§11.13).
      this.schedule(Math.max(0, this.lastAt + DAY_MS - this.o.clock.mono()));
    } catch (e) {
      this.force ||= force;
      if (statusOf(e) === 404) {
        // The server no longer offers push.
        try {
          await (await pl.existing())?.getSubscription().then((x) => x?.unsubscribe());
        } catch {
          // gone already
        }
        this.turnOff();
        return;
      }
      const ra = (e as { retryAfter?: unknown } | null)?.retryAfter;
      if (typeof ra === "number" && ra >= 0) this.notBefore = this.o.clock.mono() + ra * 1000;
      const wait = this.retry;
      this.retry = Math.min(this.retry * 2, RETRY_MAX);
      this.schedule(wait);
    }
  }
}
