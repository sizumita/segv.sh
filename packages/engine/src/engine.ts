// The segv.sh client engine (docs/PROTOCOL.md §11): unlocks the account key with a passkey (PRF) or the recovery
// code, checks the account against the directory, restores the account's state from its self lane, and turns it into
// the view the UI renders. Browser only: the UI imports it dynamically (packages/ui/src/engine-loader.ts).
//
// The session's conversations live in Messaging (messaging.ts); this class owns accounts, the session lifecycle,
// the generation guards, state emission and warnings. It runs the owner's aliases (temporary handles, §2.6) as
// accounts of their own, each with its own self lane and Messaging, and routes view ids to the account of the copy.
import * as P from "@segv/protocol/proto";
import {
  ALIAS_CREATE_FAILED,
  addPasskeyTo,
  aliasKeys,
  isAliasEntry,
  loginWithCode,
  loginWithPasskey,
  registerAccount,
  registerAlias,
  type AliasKeys,
  type AliasRegistration,
  type Passkeys,
  type Unlocked,
} from "./accounts";
import { Api, isTransient, pushParams, type Progress } from "./api";
import { SessionEnded, UserError, message } from "./errors";
import {
  DEFAULT_DELAYS,
  systemClock,
  type EngineClock,
  type EngineDelays,
  type EngineOptions,
  type EngineTimer,
  type WebSocketCtor,
} from "./options";
import { refKeyOf } from "./conv";
import { cursorAt, type InboxCursor } from "./inbox";
import { RealtimeHub } from "./hub";
import { DEFAULT_WINDOW_MS, LocalNotify, localSettingStore } from "./local-notify";
import { Messaging, type MessagingHost } from "./messaging";
import {
  cacheGen,
  deleteCache,
  idbCacheStore,
  localPreviewStore,
  writeCache,
  type CacheStore,
  type Preview,
  type PreviewStore,
} from "./notify-cache";
import { PushClient, browserPushPlatform, localPushStore } from "./push";
import { QuietClient, localQuietStore, pageInUse } from "./quiet";
import { SelfLane } from "./selflane";
import { readSnapshot } from "./snapshot";
import { idbSessionStore, type SessionStore } from "./session";
import type { ImageCache } from "./image-cache";
import type {
  ConversationView,
  EditVersion,
  Engine,
  EngineState,
  FileRef,
  IdentityView,
  ImageRef,
  PersonView,
} from "./types";
import { browserPasskeys } from "./webauthn";

export { alarmClock, type AlarmClock, type AlarmClockOptions } from "./alarm-clock";
export type { EngineClock, EngineOptions, EngineTimer } from "./options";
export type { LocalNotification, LocalNotifier, LocalPermission, LocalStore } from "./local-notify";
export type { SessionStore } from "./session";
export type { PasskeyPlatform } from "./webauthn";

/** Messages per conversation handed to the UI (§11). */
export const VIEW_MESSAGES = 500;
/** Noise warnings kept (deduplicated, with a count). */
const MAX_NOISE = 5;

export const ACCOUNT_MISSING = "your account was not found in the directory of this server";
export const ACCOUNT_KEYS_MISMATCH =
  "the public keys registered for your account do not match your passkey's keys";
/** §2.6 "Running aliases": an alias whose directory entry does not check is not run. */
export const ALIAS_NOT_LISTED =
  "the directory does not list one of your temporary handles as created; it is not used on this device";
/** §11.19 "Rules". */
export const NICK_INVALID = "a nickname: 1–64 characters, not starting with @";
export const NICK_OWN = "you cannot give your own handles a nickname";
/** §2.6 "Creating" step 1: creating or bringing one back beyond MAX_LIVE_ALIASES. */
export const TOO_MANY_ALIASES = `at most ${P.MAX_LIVE_ALIASES} temporary handles can be active; retire one first`;
/** A device that sees more live aliases than it runs (§2.6): it runs the newest. */
export const ALIASES_NOT_RUN = `more than ${P.MAX_LIVE_ALIASES} temporary handles are active; only ${P.MAX_LIVE_ALIASES} run on this device`;
const STILL_RESTORING = "still restoring; try again in a moment";

/** Two alias tables are the same (§2.6). */
const sameTable = (a: readonly P.AliasEntry[], b: readonly P.AliasEntry[]): boolean =>
  P.equalBytes(P.encodeAliasTable(a), P.encodeAliasTable(b));

/** The change of an alias table that sets fields of entry i (its `rest` bits kept, §7.1); none when it has none. */
const setEntry =
  (i: number, x: Partial<P.AliasEntry>) =>
  (t: P.AliasEntry[]): P.AliasEntry[] =>
    i < t.length ? t.map((y, k) => (k === i ? { ...y, ...x } : y)) : t;

/** A promise and its resolver. */
function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
}

/** The view id prefix of an alias's copies (§11.11 "Accounts in the view"): copy keys never start with "@". */
const aliasPrefix = (i: number): string => `@${i}/`;

interface Account {
  uid: Uint8Array;
  uidB: string;
  AK: Uint8Array;
  /** the quiet secret qS and its tag Qself (§2.1, §4.1), derived once per session */
  quiet?: { qS: Uint8Array; Q: Uint8Array };
  id: P.Identity;
  handle: string;
  /** era of registration, from the directory (§11.1); null until the account check */
  regEra: number | null;
  /** the account's inbox buckets (§10.6 `inbox`), from the same directory entry */
  inbox: { E: number; g: number }[];
}

/** What the registering device knows of its registration: its server time, when the response arrived (§11.1). */
interface Registration {
  now: number | null;
}

/** An alias that this device runs as an account of its own (§2.6 "Running aliases"). */
interface AliasRun {
  i: number;
  keys: AliasKeys;
  acc: Account;
  self: SelfLane;
  msg: Messaging | null;
  status: "starting" | "ready" | "failed";
  /** its own work queue, so that its work never waits for the owner's (or another alias's) */
  queue: Promise<unknown>;
  /** retired, or the session ended: its pending work ends with SessionEnded */
  stopped: boolean;
  /**
   * registered on this device, its own register request answered by a 200: the cursor of its first self row comes
   * from that response (§2.6 "Creating" step 5, §11.1)
   */
  registered: Registration | null;
  /** resolves once it runs; rejects when it fails or stops first */
  running: Promise<void>;
  settle: { ok(): void; fail(e: Error): void };
}

const emptyState = (): EngineState => ({
  phase: "boot",
  progress: "",
  error: "",
  me: null,
  identities: [],
  people: [],
  conversations: [],
  head: { seq: 0, h: "" },
  connected: false,
  syncing: false,
  warnings: [],
  prfSupported: null,
  notifications: "unavailable",
  localNotify: false,
  preview: "unavailable",
  quiet: "unavailable",
});

/** The notification cache is written at least this often while the session runs (§11.13). */
const CACHE_EVERY_MS = 5 * 60_000;
/** Bursts of changes are written together. */
const CACHE_DEBOUNCE_MS = 2_000;

export class SegvEngine implements Engine {
  private state: EngineState = emptyState();
  private readonly listeners = new Set<(s: EngineState) => void>();
  /** UI emission throttle: a real timer, never the engine clock (state reaches the UI even while a test holds it) */
  private emitTimer: ReturnType<typeof setTimeout> | null = null;

  readonly clock: EngineClock;
  private readonly delays: EngineDelays;
  private readonly fetchFn: typeof fetch;
  private readonly opts: EngineOptions;
  private api: Api;
  /** notifications on this device (§11.13); outlives sessions, like the device's setting */
  private readonly push: PushClient;
  /** marks of the rows this device shows while in use (§11.13 "Seen elsewhere") */
  private readonly quiet: QuietClient;
  /** the notification cache (null: no storage) and the preview setting (§11.13) */
  private readonly cacheStore: CacheStore | null;
  private readonly previewStore: PreviewStore;
  private cacheTimer: EngineTimer | null = null;
  private cacheDue = Infinity;
  /** cache writes and deletions, one at a time and in order, so a deletion is never undone by a write before it */
  private cacheOps: Promise<void> = Promise.resolve();
  /** the session is kept on this device (loaded at boot, or saved at sign-in) */
  private remembered = false;
  /** where the remembered session is kept (§11.11, §11.14) */
  private readonly sessionStore: SessionStore;
  /** the passkey API and the RP ID (§2.5, §11.14) */
  private readonly passkeys: Passkeys;
  /** the notifications of an app without push (§11.13), or null where pushes notify */
  private readonly local: LocalNotify | null;

  private account: Account | null = null;
  private self: SelfLane | null = null;
  /** the session's conversations, once restored */
  private msg: Messaging | null = null;
  /** the owner's work queue */
  private ownerQueue: Promise<unknown> = Promise.resolve();
  /** the aliases this device runs, live or failed, by index (§2.6) */
  private readonly aliases = new Map<number, AliasRun>();
  /**
   * the owner's restore has applied its self delta (§11.4 step 4), so the fold holds the alias table, and the device's
   * checkpoints were verified: from then on the live aliases run (§2.6 "Running aliases")
   */
  private tableKnown = false;
  /** resolved then, or once the session ended */
  private selfApplied = deferred();
  private ownerDone = false;
  /** the alias restores, one after the other, alongside the owner's §11.4 steps 5–11 (§2.6, §11.1 step 5) */
  private aliasChain: Promise<void> = Promise.resolve();
  /** this device's creations, by the index whose table entry they wrote: resolved once its registration ends (§2.6) */
  private readonly creating = new Map<number, Promise<void>>();
  /** the alias keys derived this session, by index */
  private readonly aliasKeyCache = new Map<number, AliasKeys>();
  /** alias uids by index (cheap, without the keys) */
  private readonly aliasUids = new Map<number, string>();
  /**
   * aliases whose creation here got the 200 to its own register request, until their run takes it, by index (§2.6
   * "Creating" step 5: the cursor of the registration HEADS)
   */
  private readonly justRegistered = new Map<number, Registration>();
  /** the owner fold's NICK and alias-table versions last acted on */
  private nickSeen = 0;
  private aliasSeen = 0;
  /**
   * the uids of the owner (-1) and of every alias of its table (its index), retired ones included, at a version of
   * the table
   */
  private ownUidMap: { v: number; map: Map<string, number> } | null = null;
  /** each own account's sigPk and kh as D lists them (§2.6 "The owner's accounts"), by index (-1: the owner) */
  private readonly ownMemberKeys = new Map<number, { sigPk: Uint8Array; kh: Uint8Array }>();
  /** an alias's handle and fingerprint, by `${i}:${c}` */
  private readonly aliasShown = new Map<string, { handle: string; fingerprint: string }>();
  /** the device is in use (§11.13 "Seen elsewhere") */
  private readonly inUse: () => boolean;
  /** `createAlias` calls, one at a time (each takes the next index of the table, §2.6) */
  private aliasCreation: Promise<unknown> = Promise.resolve();
  /** the device's realtime sockets, for every account the session runs (§10.8) */
  private hub: RealtimeHub | null = null;
  /** the periodic catch-up of every account, in turn (§11.6) */
  private periodicTimer: EngineTimer | null = null;
  readonly pending = new Map<string, string>();
  fatal = false;
  /** bumped on logout, so stale async work stops */
  generation = 0;
  /** bumped on every applied row or record (the test harness's settle stamp) */
  version = 0;
  /** in-flight actions and tracked background work (sign-in flows, user actions, deliveries) */
  private inflight = 0;
  /** of those, the ones now waiting on a protocol timer */
  private waiting = 0;
  /** tracked background work per session generation (work of an ended session no longer counts) */
  private readonly tracked = new Map<number, number>();
  /** scheduled protocol timers (retries) with their monotonic due time; periodic timers are not here */
  private readonly protocolTimers = new Map<
    EngineTimer,
    { due: number; release: () => void; run: AliasRun | null }
  >();
  private live = false;
  private critical: string[] = [];
  private readonly noise = new Map<string, number>();

  constructor(opts: EngineOptions = {}) {
    this.opts = opts;
    this.clock = opts.clock ?? systemClock;
    this.delays = { ...DEFAULT_DELAYS, ...opts.delays };
    this.fetchFn = opts.fetch ?? ((input, init) => fetch(input, init));
    this.sessionStore = opts.session ?? idbSessionStore;
    this.passkeys = {
      platform: opts.passkeys ?? browserPasskeys,
      // The canonical host, never the host of a native app's own origin (§2.5, §11.14).
      rpId: opts.origin
        ? new URL(opts.origin).hostname
        : typeof location === "undefined"
          ? "localhost"
          : location.hostname,
    };
    this.api = this.newApi();
    const inUse = opts.quiet?.inUse ?? pageInUse();
    this.inUse = inUse;
    this.push = new PushClient({
      transport: {
        pushSub: (b) => this.api.pushSub(b),
        ring: (E, label, tokens) => this.api.ring(E, label, tokens),
      },
      platform: opts.push ? opts.push.platform : browserPushPlatform(),
      store: opts.push?.store ?? localPushStore(),
      clock: this.clock,
      params: () => {
        const p = this.api.cachedParams;
        return p ? pushParams(p) : null;
      },
      deltaMs: () => (this.api.cachedParams?.delta ?? 10) * 1000,
      secrets: () => this.pushSecrets(),
      // never a set of only some accounts' copies: sent once every running account has restored (§2.6, §11.13)
      ready: () => this.live && !this.syncingNow(),
      quiet: () => this.quietKeys()?.Q ?? null,
      onOff: () => {
        void this.dropCache();
        this.patch(this.notificationPatch());
      },
    });
    this.quiet = new QuietClient({
      transport: { seen: (qS, rows) => this.api.seen(qS, rows) },
      store: opts.quiet?.store ?? localQuietStore(),
      clock: this.clock,
      inUse,
      offered: () => {
        const p = this.api.cachedParams;
        return !!p && pushParams(p) !== null;
      },
      secret: () => this.quietKeys()?.qS ?? null,
      delta: () => this.api.cachedParams?.delta ?? 10,
      serverNow: () => this.api.serverNow(),
    });
    // An app without push keeps no notification cache: only a push's handler reads one (§11.13).
    this.cacheStore = opts.local ? null : opts.notify ? opts.notify.store : idbCacheStore();
    this.previewStore = opts.notify?.preview ?? localPreviewStore();
    this.local = opts.local
      ? new LocalNotify({
          notifier: opts.local.notifier,
          store: opts.local.store ?? localSettingStore(),
          clock: this.clock,
          preview: () => this.preview(),
          windowMs: () => {
            const p = this.api.cachedParams;
            const push = p ? pushParams(p) : null;
            return push ? push.window * 1000 : DEFAULT_WINDOW_MS;
          },
          inUse,
        })
      : null;
    opts.onWake?.(() => {
      if (!this.live) return;
      this.hub?.wake();
      this.msg?.wake();
      for (const m of this.aliasMsgs()) m.wake();
    });
    if (typeof document !== "undefined")
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "hidden") this.scheduleCache(0);
      });
  }

  private notificationState(): EngineState["notifications"] {
    if (this.local) return this.local.on ? "on" : "off";
    if (!this.push.available) return "unavailable";
    return this.push.on ? "on" : "off";
  }

  /** Whether this device's notifications are on, through push or as an app without push. */
  private notifying(): boolean {
    return this.local ? this.local.on : this.push.on;
  }

  private previewState(): EngineState["preview"] {
    // An app without push shows its notifications from what it holds while it runs: it needs no cache (§11.13).
    if (this.local) return this.previewStore.load();
    if (!this.push.available || !this.remembered || this.cacheStore === null) return "unavailable";
    return this.previewStore.load();
  }

  private notificationPatch(): Pick<
    EngineState,
    "notifications" | "localNotify" | "preview" | "quiet"
  > {
    return {
      notifications: this.notificationState(),
      localNotify: this.local !== null,
      preview: this.previewState(),
      quiet: this.quiet.available ? (this.quiet.on ? "on" : "off") : "unavailable",
    };
  }

  /** The account's quiet secret and tag (§2.1, §4.1), or null without a session. */
  private quietKeys(): { qS: Uint8Array; Q: Uint8Array } | null {
    const acc = this.account;
    if (!acc) return null;
    if (!acc.quiet) {
      const qS = P.quietSecret(acc.AK);
      acc.quiet = { qS, Q: P.quietTag(qS) };
    }
    return acc.quiet;
  }

  /** The preview in effect: `none` unless notifications are on and the session is kept (§11.13). */
  private preview(): Preview {
    const p = this.previewState();
    return p === "unavailable" || !this.notifying() ? "none" : p;
  }

  /**
   * Writes the notification cache within `ms` (§11.13): after a restore, when the registration set or a name may have
   * changed, when the page is hidden, and every 5 minutes while the session runs.
   */
  private scheduleCache(ms: number): void {
    // Only a push's notification handler reads the cache; an app without push keeps none.
    if (this.local || !this.live || this.syncingNow() || this.preview() === "none") return;
    const now = this.clock.mono();
    if (now + ms >= this.cacheDue) return;
    this.cacheTimer?.cancel();
    this.cacheDue = now + ms;
    const gen = this.generation;
    this.cacheTimer = this.clock.setTimer(() => {
      this.cacheTimer = null;
      this.cacheDue = Infinity;
      if (gen !== this.generation) return;
      void this.writeCacheNow().finally(() => this.scheduleCache(CACHE_EVERY_MS));
    }, ms);
  }

  private cacheOp(fn: () => Promise<void>): Promise<void> {
    const run = this.cacheOps.then(fn);
    this.cacheOps = run.catch(() => {});
    return run;
  }

  private writeCacheNow(): Promise<void> {
    return this.cacheOp(async () => {
      const store = this.cacheStore;
      if (!store) return;
      try {
        // The generation first, then the decision (the settings are shared by every tab): a deletion or a change of
        // the preview made anywhere after this read voids the write.
        const gen = await cacheGen(store);
        const p = this.preview();
        if (p === "none" || !this.msg || !this.live || this.syncingNow()) return;
        // every account's copies: the owner's and those of every running alias (§11.13)
        const copies = [this.msg, ...this.aliasMsgs()].flatMap((m) =>
          m.notifyCopies(p === "message"),
        );
        await writeCache(
          store,
          { v: 1, preview: p, deltaS: this.api.cachedParams?.delta ?? 10, copies },
          gen,
        );
      } catch (e) {
        console.error("could not write the notification cache", e);
      }
    });
  }

  private dropCache(): Promise<void> {
    this.cacheTimer?.cancel();
    this.cacheTimer = null;
    this.cacheDue = Infinity;
    const store = this.cacheStore;
    return this.cacheOp(async () => {
      if (store) await deleteCache(store).catch(() => {});
    });
  }

  private newApi(): Api {
    return new Api({
      fetch: this.fetchFn,
      origin: this.opts.origin,
      clock: this.clock,
      warn: (t) => this.warn(t),
      critical: (t) => this.warn(t, true),
    });
  }

  // ───────────── public API ─────────────

  getState(): EngineState {
    return this.state;
  }

  subscribe(fn: (s: EngineState) => void): () => void {
    this.listeners.add(fn);
    fn(this.state);
    return () => this.listeners.delete(fn);
  }

  /** Loads a remembered session, if any (the app calls this once). */
  async boot(): Promise<void> {
    this.patch({
      prfSupported: await this.passkeys.platform.capability().catch(() => null),
    });
    await this.local?.check();
    this.patch(this.notificationPatch());
    const s = await this.sessionStore.load().catch(() => null);
    if (!s) return this.patch({ phase: "signed-out" });
    this.remembered = true;
    try {
      await this.unlock(s.AK, P.fromB64u(s.uid), "");
    } catch (e) {
      await this.sessionStore.clear().catch(() => {});
      this.remembered = false;
      this.patch({ phase: "signed-out", error: `could not restore session: ${message(e)}` });
    }
  }

  register(handleIn: string, remember = false): Promise<{ recoveryCode: string }> {
    return this.authFlow(async () => {
      const r = await registerAccount(this.api, this.passkeys, handleIn, (m) => this.progress(m));
      await this.unlock(r.AK, r.uid, r.handle, { now: r.regNow });
      if (remember) await this.remember(r);
      return { recoveryCode: r.recoveryCode };
    });
  }

  login(remember: boolean): Promise<void> {
    return this.authFlow(async () => {
      const found = await loginWithPasskey(this.api, this.passkeys, (m) => this.progress(m));
      await this.unlock(found.AK, found.uid, "");
      if (remember) await this.remember(found);
    });
  }

  loginWithRecovery(code: string, remember: boolean): Promise<void> {
    return this.authFlow(async () => {
      const found = await loginWithCode(this.api, code, (m) => this.progress(m));
      await this.unlock(found.AK, found.uid, "");
      if (remember) await this.remember(found);
    });
  }

  async addPasskey(): Promise<void> {
    const acc = this.requireAccount();
    const gen = this.generation;
    await this.action(() =>
      addPasskeyTo(
        this.api,
        this.passkeys,
        acc,
        (m) => this.progress(m),
        () => this.assertSession(acc, gen),
      ),
    );
  }

  async logout(): Promise<void> {
    this.generation++;
    this.stopTimers();
    // The next account on this browser starts with notifications off, and gets none of this one's (§11.13).
    await this.push.logout().catch(() => {});
    // An app without push turns its notifications off too, and leaves none on screen (§11.13).
    this.local?.disable();
    this.local?.stop();
    this.quiet.stop();
    await this.dropCache();
    this.previewStore.save("none");
    this.remembered = false;
    await this.sessionStore.clear().catch(() => {});
    this.msg?.images.clear();
    for (const p of this.fileCache.values())
      p.then((f) => URL.revokeObjectURL(f.url)).catch(() => {});
    this.resetData();
    this.account = null;
    this.self = null;
    this.fatal = false;
    this.api = this.newApi();
    this.state = { ...emptyState(), phase: "signed-out", prfSupported: this.state.prfSupported };
    this.emitNow();
  }

  async setNotifications(on: boolean): Promise<void> {
    if (this.local) {
      try {
        if (!on) this.local.disable();
        else if (!(await this.local.enable()))
          this.patch({
            error: "notifications are not allowed for segv.sh: allow them in the system's settings",
          });
      } catch (e) {
        this.patch({ error: message(e) });
      } finally {
        this.patch(this.notificationPatch());
      }
      return;
    }
    try {
      if (on) await this.push.enable();
      else {
        await this.push.disable();
        await this.dropCache();
      }
    } catch (e) {
      this.patch({ error: message(e) });
    } finally {
      this.patch(this.notificationPatch());
      if (on) this.scheduleCache(0);
    }
  }

  async setQuiet(on: boolean): Promise<void> {
    this.quiet.set(on);
    this.patch(this.notificationPatch());
  }

  async setPreview(p: Preview): Promise<void> {
    if (this.previewState() === "unavailable") return;
    // Saved before the cache changes, so that a write decided after it, in any tab, sees it. The old cache goes before
    // the change is reported, whatever the new preview: a `message` cache's names and keys never outlive a downgrade,
    // even when the page closes before the new cache is written.
    this.previewStore.save(p);
    await this.dropCache();
    this.patch(this.notificationPatch());
    this.scheduleCache(0);
  }

  /** §6.1 as the account `as` (the owner when absent, §11.11); the id is that account's view id of the copy. */
  async createConversation(handles: string[], name?: string, as?: string): Promise<string> {
    this.requireAccount();
    return this.action(async () => {
      const t = this.accountFor(as);
      return t.prefix + (await t.msg.create(handles, name));
    });
  }

  async sendText(convId: string, text: string, replyTo?: string): Promise<void> {
    this.requireAccount();
    try {
      const t = this.route(convId);
      await t.msg.sendText(t.key, text, replyTo);
    } catch (e) {
      this.patch({ error: message(e) });
    }
  }

  async sendImage(convId: string, file: File, replyTo?: string): Promise<void> {
    this.requireAccount();
    try {
      const t = this.route(convId);
      await t.msg.sendImage(t.key, file, replyTo);
    } catch (e) {
      this.patch({ error: message(e) });
    }
  }

  async sendFile(convId: string, file: File, replyTo?: string): Promise<void> {
    this.requireAccount();
    try {
      const t = this.route(convId);
      await t.msg.sendFile(t.key, file, replyTo);
    } catch (e) {
      this.patch({ error: message(e) });
    }
  }

  /** §11.12: one emoji reaction to a TEXT, IMAGE, FILE or REPLY message, without an echo; rejects with §11.3's errors. */
  async react(convId: string, messageKey: string, emoji: string, on: boolean): Promise<void> {
    this.requireAccount();
    await this.action(() => {
      const t = this.route(convId);
      return t.msg.react(t.key, messageKey, emoji, on);
    });
  }

  /** §11.18: one EDIT row with a new text for self's text message, without an echo; rejects with §11.3's errors. */
  async editText(convId: string, messageKey: string, text: string): Promise<void> {
    this.requireAccount();
    await this.action(() => {
      const t = this.route(convId);
      return t.msg.editText(t.key, messageKey, text);
    });
  }

  /** §11.18 "Display": the versions of an edited message, its own text first. */
  editHistory(convId: string, messageKey: string): EditVersion[] {
    const t = this.tryRoute(convId);
    return t ? t.msg.editHistory(t.key, messageKey) : [];
  }

  /** The accept control (§11.5, §11.11): the user's acceptance of a copy whose inviter is not a contact yet. */
  async accept(convId: string): Promise<void> {
    this.requireAccount();
    await this.action(() => {
      const t = this.route(convId);
      return t.msg.accept(t.key);
    });
  }

  async addMembers(convId: string, handles: string[]): Promise<void> {
    this.requireAccount();
    await this.action(() => {
      const t = this.route(convId);
      return t.msg.addMembers(t.key, handles);
    });
  }

  async removeMember(convId: string, uid: string): Promise<void> {
    this.requireAccount();
    await this.action(() => {
      const t = this.route(convId);
      return t.msg.removeMember(t.key, uid);
    });
  }

  async leave(convId: string): Promise<void> {
    this.requireAccount();
    await this.action(() => {
      const t = this.route(convId);
      return t.msg.leave(t.key);
    });
  }

  /**
   * §2.6 "Creating": once the owner's restore has applied its self delta, the next index of the table is written into
   * the table, then registered without wraps (a proof of work), then run; resolves with its uid once it runs. One
   * creation at a time.
   */
  createAlias(): Promise<string> {
    const acc = this.requireAccount();
    const gen = this.generation;
    const run = () =>
      this.action(async () => {
        try {
          return await this.createAliasNow(acc, gen);
        } catch (e) {
          if (e instanceof SessionEnded || e instanceof UserError) throw e;
          console.error("segv:", e);
          throw new UserError(ALIAS_CREATE_FAILED);
        }
      });
    const p = this.aliasCreation.then(run, run);
    this.aliasCreation = p.catch(() => {});
    return p;
  }

  private async createAliasNow(acc: Account, gen: number): Promise<string> {
    this.progress("making a temporary handle…");
    await this.selfApplied.promise;
    this.assertSession(acc, gen);
    // step 1: the owner's self lane caught up, so that the fold holds the table as written so far
    await this.messaging().catchUpSelf();
    this.assertSession(acc, gen);
    if (this.table().filter((x) => !x.retired).length >= P.MAX_LIVE_ALIASES)
      throw new UserError(TOO_MANY_ALIASES);
    // step 2: the table names the alias before any request, so every device of the owner knows it whether or not this
    // creation finishes. A sibling's row that takes the slot first (a CONFLICT) moves it to the next index. This
    // device's run of it waits for the registration (`creating`).
    let ended!: () => void;
    const made = new Promise<void>((r) => (ended = r));
    let i = -1;
    let written = false;
    try {
      await this.writeTable(acc, gen, (cur) => {
        if (this.creating.get(i) === made) this.creating.delete(i);
        i = cur.length;
        this.creating.set(i, made);
        return [...cur, { c: 0, retired: false }];
      });
      written = true;
      // steps 3–4: registered with the table's c, a 409 settled by an exact lookup
      const r = await this.registerAliasAt(
        acc,
        gen,
        i,
        () => this.assertSession(acc, gen),
        (ms) => this.wait(ms),
        (m) => this.progress(m),
      );
      if (!r.exists) this.justRegistered.set(i, { now: r.regNow });
    } catch (e) {
      // no device runs an alias that may not be registered; bringing it back runs it, which registers it
      if (written && !(e instanceof SessionEnded))
        await this.writeTable(acc, gen, setEntry(i, { retired: true })).catch(() => {});
      throw e;
    } finally {
      if (this.creating.get(i) === made) this.creating.delete(i);
      ended();
    }
    // step 5: it runs; its first self row is the registration HEADS when this device's register request got the 200
    this.progress("making a temporary handle…");
    this.syncAliases(gen);
    const a = this.aliases.get(i);
    if (!a) throw new UserError(ALIAS_CREATE_FAILED);
    await a.running;
    return a.acc.uidB;
  }

  /**
   * §2.6 "Creating" steps 3–4 for alias i, whose table entry exists: registered with the table's c, and on a 409 an
   * exact lookup; a c that changes (the next one, or a sibling's) is written into the table.
   */
  private registerAliasAt(
    acc: Account,
    gen: number,
    i: number,
    check: () => void,
    wait: (ms: number) => Promise<void>,
    progress: Progress,
  ): Promise<AliasRegistration> {
    return registerAlias(this.api, this.aliasKeysOf(i), this.table()[i]?.c ?? 0, progress, {
      wait,
      check,
      retryBase: this.delays.retryBase,
      setC: (c) => this.writeTable(acc, gen, setEntry(i, { c })),
    });
  }

  /** §2.6 "Retiring": the table written with the alias's retired bit set, or clear; the device stops or starts it. */
  async setAliasRetired(uid: string, retired: boolean): Promise<void> {
    const acc = this.requireAccount();
    const gen = this.generation;
    await this.action(async () => {
      await this.selfApplied.promise;
      this.assertSession(acc, gen);
      const t = this.table();
      const i = t.findIndex((_, k) => this.aliasUidOf(k) === uid);
      if (i < 0) throw new UserError("unknown temporary handle");
      if (t[i].retired === retired) return;
      if (!retired && t.filter((x) => !x.retired).length >= P.MAX_LIVE_ALIASES)
        throw new UserError(TOO_MANY_ALIASES);
      await this.writeTable(acc, gen, setEntry(i, { retired }));
      this.syncAliases(gen);
    });
  }

  /** §11.19: a NICK record of the owner's self lane, written at once ("" removes the nickname). */
  async setNickname(uid: string, nickname: string): Promise<void> {
    const acc = this.requireAccount();
    const gen = this.generation;
    await this.action(async () => {
      let uidBytes: Uint8Array;
      try {
        uidBytes = P.fromB64u(uid);
      } catch {
        throw new UserError("unknown user");
      }
      if (uidBytes.length !== 16) throw new UserError("unknown user");
      if (this.ownUids().has(uid)) throw new UserError(NICK_OWN);
      const name = nickname === "" ? "" : nickname.trim();
      if (nickname !== "" && !P.validNickname(name)) throw new UserError(NICK_INVALID);
      await this.selfApplied.promise;
      this.assertSession(acc, gen);
      const self = this.self!;
      if ((self.fold.nicks.get(uid) ?? "") === name) return;
      await this.enqueue(async () => {
        this.assertSession(acc, gen);
        await self.write([{ rtype: P.RT.NICK, uid: uidBytes, name }]);
      });
      this.assertSession(acc, gen);
      this.ownerFoldChanged();
    });
  }

  /**
   * Links (§4.3, §5.5, §11.11): internal in stage 1 (no link UI and no Engine method yet); the tests reach them
   * through I(e). `createLink` resolves with the link to share, `openLink` with the new conversation's id.
   */
  async createLink(opts: { oneShot?: boolean } = {}): Promise<string> {
    this.requireAccount();
    return this.action(() => this.messaging().createLink(opts));
  }

  async openLink(url: string): Promise<string> {
    this.requireAccount();
    return this.action(() => this.messaging().openLink(url));
  }

  // images and files: every account's Messaging shares the owner's caches, so the owner's loads them all

  loadImage(img: ImageRef): Promise<string> {
    if (!this.msg) return Promise.reject(new UserError("not signed in"));
    return this.msg.loadImage(img);
  }

  releaseImage(img: ImageRef): void {
    this.msg?.releaseImage(img);
  }

  loadFile(file: FileRef): Promise<string> {
    if (!this.msg) return Promise.reject(new UserError("not signed in"));
    return this.msg.loadFile(file);
  }

  markRead(convId: string, opened = true): void {
    const t = this.tryRoute(convId);
    if (!t) return;
    t.msg.markRead(t.key, opened);
    // Shown: its notifications close (§11.13 "Closing and the badge").
    if (this.local && t.msg.copies.has(t.key)) this.local.shown(t.msg.refOfKey(t.key));
  }

  clearError(): void {
    this.patch({ error: "" });
  }

  private messaging(): Messaging {
    if (!this.msg) throw new UserError(STILL_RESTORING);
    return this.msg;
  }

  /** The Messaging of a view id and the copy key in it: an alias's ids carry its prefix (§11.11). */
  private route(convId: string): { msg: Messaging; key: string } {
    const m = /^@(\d+)\/(.+)$/.exec(convId);
    if (!m) return { msg: this.messaging(), key: convId };
    const run = this.aliases.get(Number(m[1]));
    if (!run || run.stopped || !run.msg) throw new UserError("unknown conversation");
    return { msg: run.msg, key: m[2] };
  }

  private tryRoute(convId: string): { msg: Messaging; key: string } | null {
    try {
      return this.route(convId);
    } catch {
      return null;
    }
  }

  /** The Messaging of the account `as` (a b64u uid; the owner when absent) and its view id prefix. */
  private accountFor(as: string | undefined): { msg: Messaging; prefix: string } {
    const acc = this.requireAccount();
    if (as === undefined || as === "" || as === acc.uidB)
      return { msg: this.messaging(), prefix: "" };
    for (const run of this.aliases.values())
      if (run.acc.uidB === as && !run.stopped) {
        if (run.status === "failed")
          throw new UserError("this temporary handle is not used on this device");
        if (run.status !== "ready" || !run.msg) throw new UserError(STILL_RESTORING);
        return { msg: run.msg, prefix: aliasPrefix(run.i) };
      }
    if (this.table().some((x, i) => x.retired && this.aliasUidOf(i) === as))
      throw new UserError("this temporary handle is retired");
    throw new UserError("unknown account");
  }

  /** The Messaging of every alias that runs (its restore done), in index order. */
  private aliasMsgs(): Messaging[] {
    return [...this.aliases.values()]
      .filter((r) => !r.stopped && r.status === "ready" && r.msg)
      .sort((a, b) => a.i - b.i)
      .map((r) => r.msg!);
  }

  // ───────────── white-box hooks (the test harness's I(e)) ─────────────

  /** conversation copies by view key */
  get convs(): Map<string, unknown> {
    return this.msg?.copies ?? new Map();
  }

  /** the checkpoint chain the session verified (§12.3) */
  get ckpt(): Messaging["ckpt"] | null {
    return this.msg?.ckpt ?? null;
  }

  /** decrypted images of the session, by `id.k` */
  get images(): ImageCache | null {
    return this.msg?.images ?? null;
  }

  /** decrypted files of the session, by `id.k` */
  get fileCache(): Map<string, Promise<{ url: string; size: number }>> {
    return this.msg?.fileCache ?? new Map();
  }

  /** the per-conversation send chains of every account, by view id */
  get sendChains(): Map<string, Promise<unknown>> {
    const out = new Map(this.msg?.chains ?? []);
    for (const run of this.aliases.values())
      for (const [k, p] of run.msg?.chains ?? []) out.set(aliasPrefix(run.i) + k, p);
    return out;
  }

  /** every account's work queue: the owner's and each alias's */
  get queue(): Promise<unknown> {
    return Promise.all([this.ownerQueue, ...[...this.aliases.values()].map((r) => r.queue)]);
  }

  /** an alias run by index (white-box: tests) */
  aliasRun(i: number): AliasRun | undefined {
    return this.aliases.get(i);
  }

  /** Busy work: in-flight actions plus scheduled protocol timers (the harness's settle waits for 0). */
  get busy(): number {
    return this.inflight + (this.tracked.get(this.generation) ?? 0) + this.protocolTimers.size;
  }

  /** In-flight work that is not just waiting on a protocol timer (settle ticks the clocks when this is 0). */
  get busyActions(): number {
    return Math.max(0, this.inflight + (this.tracked.get(this.generation) ?? 0) - this.waiting);
  }

  /** The monotonic due time of the earliest protocol timer, or null. */
  nextProtocolDue(): number | null {
    let due: number | null = null;
    for (const { due: d } of this.protocolTimers.values()) if (due === null || d < due) due = d;
    return due;
  }

  /** The clock sample the server-time estimate uses (§10.1). */
  get timeSample(): { s: number; mid: number; rtt: number } | null {
    return this.api.time.sample;
  }

  /** One catch-up round (§11.6) of every account: the self lane, every copy's lanes, the inbox, HEADS. */
  async catchUp(): Promise<void> {
    if (!this.msg || !this.live || this.fatal) return;
    await this.msg.catchUp();
    for (const m of this.aliasMsgs()) await m.catchUp().catch(() => {});
  }

  /** Every account's views, most recent first; an alias's ids carry its prefix (§11.11 "Accounts in the view"). */
  views(): ConversationView[] {
    const out = this.msg?.views() ?? [];
    let more = false;
    for (const run of [...this.aliases.values()].sort((a, b) => a.i - b.i)) {
      if (run.stopped || !run.msg) continue;
      const prefix = aliasPrefix(run.i);
      for (const v of run.msg.views()) out.push({ ...v, id: prefix + v.id });
      more = true;
    }
    return more ? out.sort((a, b) => b.lastTs - a.lastTs) : out;
  }

  /** §11.11 "Accounts in the view": the owner, then its aliases by index, with handles computed from the table. */
  identities(): IdentityView[] {
    const acc = this.account;
    if (!acc) return [];
    const out: IdentityView[] = [
      {
        uid: acc.uidB,
        handle: acc.handle,
        fingerprint: this.state.me?.fingerprint ?? "",
        alias: false,
        index: -1,
        retired: false,
        status: this.ownerDone ? "ready" : "starting",
      },
    ];
    const t = this.table();
    const runs = this.runnable(t);
    t.forEach((x, i) => {
      const run = this.aliases.get(i);
      out.push({
        uid: this.aliasUidOf(i),
        ...this.aliasShownOf(i, x.c),
        alias: true,
        index: i,
        retired: x.retired,
        // a live alias beyond the ones this device runs is idle here (§2.6 "Running aliases")
        status: x.retired
          ? "retired"
          : run && !run.stopped
            ? run.status
            : runs.has(i)
              ? "starting"
              : "idle",
      });
    });
    return out;
  }

  /**
   * The users that the running accounts know by a MEMBER record, with the owner's nicknames and the accounts they are
   * contacts of (§11.19); never one of the user's own accounts.
   */
  people(): PersonView[] {
    const acc = this.account;
    if (!acc || !this.self) return [];
    const accounts = [
      { uidB: acc.uidB, fold: this.self.fold },
      ...[...this.aliases.values()]
        .filter((r) => !r.stopped && r.status !== "failed")
        .sort((a, b) => a.i - b.i)
        .map((r) => ({ uidB: r.acc.uidB, fold: r.self.fold })),
    ];
    const own = this.ownUids();
    const by = new Map<string, PersonView>();
    for (const { fold } of accounts)
      for (const [u, m] of fold.members)
        if (!own.has(u) && !by.has(u))
          by.set(u, { uid: u, handle: m.handle, nickname: this.nickOf(u), contactOf: [] });
    for (const { uidB, fold } of accounts)
      for (const u of fold.contacts.keys()) by.get(u)?.contactOf.push(uidB);
    return [...by.values()].sort((a, b) =>
      a.handle < b.handle ? -1 : a.handle > b.handle ? 1 : 0,
    );
  }

  // ───────────── unlock, account check and restore (§11.1, §11.4) ─────────────

  /**
   * Starts a session for an unlocked account: the UI is ready at once, and the account check (§11.1) and the restore
   * (§11.4) run in the background (`syncing`). `registered`: the account was just created here, so its first self
   * row, a HEADS record with the inbox cursor at the registration's slot, is written right after the restore (§7.3,
   * §11.1).
   */
  async unlock(
    AK: Uint8Array,
    uid: Uint8Array,
    handle: string,
    registered: Registration | null = null,
  ): Promise<void> {
    const id = P.deriveIdentity(AK);
    const uidB = P.b64u(uid);
    this.resetData();
    this.account = { uid, uidB, AK, id, handle, regEra: null, inbox: [] };
    const WS =
      this.opts.WebSocket ??
      (typeof WebSocket === "undefined" ? null : (WebSocket as unknown as WebSocketCtor));
    this.hub = new RealtimeHub(WS, {
      clock: this.clock,
      origin: this.api.origin,
      onHello: (s, sent, recv) => this.api.time.add(s, sent, recv),
      onState: (on) => this.patch({ connected: on }),
    });
    this.self = new SelfLane(this.api, id, {
      warn: (t, critical) => this.warn(t, critical),
      applied: () => {
        this.version++;
        this.scheduleEmit();
        this.ownerFoldChanged(); // a NICK record or the alias table, of this device or a sibling (§7.3, §11.7)
      },
    });
    this.patch({
      phase: "ready",
      me: { uid: uidB, handle, fingerprint: P.fingerprint(uid, id.sigPk, id.kemPk) },
      warnings: [],
      syncing: true,
    });
    void this.startSync(this.generation, registered);
  }

  private async startSync(gen: number, registered: Registration | null): Promise<void> {
    const acc = this.account!;
    const self = this.self!;
    // The registration's cursor is computed once, so a retried write keeps it (a later time could pass invites).
    let cursor: InboxCursor | null = null;
    const ok = await this.retrying(gen, async () => {
      const p = await this.api.params();
      if (acc.regEra === null) await this.checkAccount(acc, gen);
      if (this.fatal) return;
      self.floorEra = acc.regEra!;
      // §11.4 steps 2–4: the latest snapshot, then the self delta from its position (or the lane from regEra).
      await this.enqueue(() => this.readSelf(self, acc));
      this.assertSession(acc, gen);
      if (registered && !self.fold.cursor) {
        cursor ??= cursorAt(
          registered.now ?? P.eraStart(acc.regEra!),
          p,
          P.era(this.api.serverNow()),
        );
        const c = cursor;
        await this.enqueue(() =>
          self.write([{ rtype: P.RT.HEADS, Ein: c.E, relIn: c.rel, entries: [] }]),
        );
      }
      const msg = (this.msg ??= new Messaging(this.host(acc, gen)));
      // §11.1 step 3 for every account of the device, before any restore: the aliases share the checkpoints (§2.6); a
      // failure is retried at catch-up
      await msg.ckpt.verify().catch(() => {});
      this.assertSession(acc, gen);
      if (!this.tableKnown) {
        // The self delta is applied (§11.4 step 4), so the fold holds the alias table: the live aliases restore from
        // now on, one after another, alongside the owner's steps 5–11 (§2.6 "Running aliases", §11.1 step 5).
        this.tableKnown = true;
        this.selfApplied.resolve();
        this.syncAliases(gen);
      }
      await this.enqueue(() => msg.restore()); // serialised with the work it starts (new copies, member lookups)
    });
    if (!ok || gen !== this.generation || this.fatal) return;
    if (this.state.error.startsWith("sync failed:")) this.patch({ error: "" });
    this.live = true;
    this.ownerDone = true;
    this.msg!.start();
    this.refreshHub();
    this.startPeriodic(gen);
    this.patch(this.notificationPatch());
    this.updateSyncing();
  }

  /** `syncing` (§11.11): until the owner and every live alias that runs here have restored or failed. */
  /**
   * `syncing` follows the restores; once the owner and every alias that runs have restored (or failed), the
   * registration set is sent and the notification cache written, with every account's copies (§2.6, §11.13).
   */
  private updateSyncing(): void {
    const syncing = this.syncingNow();
    if (syncing === this.state.syncing) return;
    this.patch({ syncing });
    if (syncing || !this.live) return;
    this.push.restored();
    this.scheduleCache(0);
  }

  private syncingNow(): boolean {
    if (!this.ownerDone) return true;
    for (const r of this.aliases.values()) if (!r.stopped && r.status === "starting") return true;
    return false;
  }

  /** The device's sockets serve the accounts that run: the owner, then its aliases by index (§10.8). */
  private refreshHub(): void {
    if (!this.hub || !this.msg || !this.live) return;
    this.hub.setAccounts([this.msg, ...this.aliasMsgs()]);
  }

  /**
   * The periodic catch-up (§11.6): one timer at the short interval for the device, which gives every account that runs
   * its tick in turn (each catches up every 300 s while realtime is connected, else at each tick).
   */
  private startPeriodic(gen: number): void {
    const tick = () => {
      this.periodicTimer = null;
      if (gen !== this.generation || this.fatal) return;
      void (async () => {
        for (const m of [this.msg, ...this.aliasMsgs()])
          if (m && gen === this.generation) await m.periodic().catch(() => {});
      })().finally(() => {
        if (gen === this.generation && !this.fatal && !this.periodicTimer)
          this.periodicTimer = this.clock.setTimer(tick, this.delays.catchUpInterval);
      });
    };
    this.periodicTimer?.cancel();
    this.periodicTimer = this.clock.setTimer(tick, this.delays.catchUpInterval);
  }

  /**
   * §11.4 steps 2–4 for one account's self lane: the latest snapshot, then the self delta from its position (or the
   * lane from regEra). Runs in the account's queue.
   */
  private async readSelf(self: SelfLane, acc: Account): Promise<void> {
    if (!self.snapshotRead) {
      const snap = await readSnapshot(this.api, acc.id, acc.regEra!);
      self.snapshotRead = true;
      if (snap) {
        self.fold.applySnapshot(snap.records, snap.ts);
        self.snapshot = { E: snap.E, applied: self.fold.applied, pos: snap.pos };
      }
    }
    const pos = self.snapshot?.pos;
    await self.catchUp(pos && !P.isNone(pos) ? { E: pos.E, n: pos.n } : { E: acc.regEra!, n: 0 });
  }

  /** What the Messaging of an account calls back into: the owner's (`run` null) or an alias's. */
  private host(acc: Account, gen: number, run: AliasRun | null = null): MessagingHost {
    const owner = this.msg;
    const base = this.clock;
    return {
      api: this.api,
      // An alias's rows and descriptors carry the server time as their ts, never this device's clock (§2.6, §3.3).
      clock: run
        ? {
            mono: () => base.mono(),
            wall: () => this.api.serverNow(),
            setTimer: (fn, ms) => base.setTimer(fn, ms),
          }
        : base,
      delays: this.delays,
      opts: this.opts,
      acc: {
        uid: acc.uid,
        uidB: acc.uidB,
        id: acc.id,
        get handle() {
          return acc.handle;
        },
        regEra: acc.regEra!,
        inbox: acc.inbox,
        refKey: refKeyOf(acc.AK),
        bellKey: P.bellKey(acc.AK),
      },
      self: run ? run.self : this.self!,
      check: () => (run ? this.assertAlias(run, gen) : this.assertSession(acc, gen)),
      warn: (t, c) => this.warn(t, c),
      changed: () => {
        this.version++;
        this.scheduleEmit();
        // The registration set may have changed: computed again within Δ, sent only if it differs (§11.13).
        if (this.live && gen === this.generation) {
          this.push.changed();
          this.scheduleCache(CACHE_DEBOUNCE_MS);
        }
      },
      emitNow: () => this.emitNow(),
      progress: (t) => this.progress(t),
      error: (t) => this.patch({ error: t }),
      wait: (ms) => this.wait(ms, run),
      enqueue: (fn) => (run ? this.enqueueRun(run, fn) : this.enqueue(fn)),
      track: (p) => this.track(p),
      // `head` follows the checkpoints, the owner's (shared with its aliases)
      setHead: (q, C) => {
        if (!run) this.patch({ head: { seq: q, h: P.b64u(C) } });
      },
      ring: (E, label, bells) => {
        if (gen === this.generation) this.push.ring(E, label, bells);
      },
      shown: (E, label, t) => {
        if (this.live && gen === this.generation) this.quiet.shown(E, label, t);
      },
      arrived: this.local
        ? (a) => {
            if (this.live && gen === this.generation) this.local?.arrived(a);
          }
        : undefined,
      nick: (uidB) => this.nickOf(uidB),
      ownAccounts: () => this.ownAccounts(),
      shared: run && owner ? owner : undefined,
      alias: run !== null,
      isOwn: (m) => this.isOwnMember(m),
      subscribe: () => this.hub?.subscribe(),
      connected: () => this.hub?.connected ?? false,
      inUse: () => this.inUse(),
    };
  }

  /** Counts background work as in flight until it settles (the harness's settle waits for it). */
  private track<T>(p: Promise<T>): Promise<T> {
    const gen = this.generation;
    this.tracked.set(gen, (this.tracked.get(gen) ?? 0) + 1);
    return p.finally(() => this.tracked.set(gen, (this.tracked.get(gen) ?? 1) - 1));
  }

  /** §11.1 step 2: the account must be registered with exactly the keys the unlocked AK derives. */
  private async checkAccount(acc: Account, gen: number): Promise<void> {
    const u = await this.api.userByUid(acc.uid);
    this.assertSession(acc, gen);
    if (!u) return this.die(ACCOUNT_MISSING);
    try {
      const b = P.verifyBundle(u.bundle, u.sig);
      if (
        u.uid !== acc.uidB ||
        b.uid !== acc.uidB ||
        b.handle !== u.handle ||
        !P.equalBytes(b.sigPk, acc.id.sigPk) ||
        !P.equalBytes(b.kemPk, acc.id.kemPk)
      )
        throw new Error("mismatch");
    } catch {
      return this.die(ACCOUNT_KEYS_MISMATCH);
    }
    acc.handle = u.handle;
    acc.regEra = u.regEra;
    acc.inbox = u.inbox;
    if (this.state.me) this.patch({ me: { ...this.state.me, handle: u.handle } });
  }

  /**
   * Runs `fn` until it succeeds, retrying failures with back-off on protocol timers (so the session's `busy` count
   * covers the wait). Resolves false when the session ended or went fatal, or the alias `run` stopped.
   */
  private async retrying(
    gen: number,
    fn: () => Promise<void>,
    run: AliasRun | null = null,
  ): Promise<boolean> {
    const over = () => gen !== this.generation || this.fatal || !!run?.stopped;
    for (let attempt = 0; ; attempt++) {
      if (over()) return false;
      try {
        await fn();
        return !over();
      } catch (e) {
        if (e instanceof SessionEnded || over()) return false;
        if (!isTransient(e)) console.error("segv:", e);
        this.patch({ error: `sync failed: ${message(e)} (retrying)` });
        await this.wait(Math.min(this.delays.retryMax, this.delays.retryBase * 2 ** attempt), run);
      }
    }
  }

  /**
   * Waits `ms` on a protocol timer (counted in `busy`). It resolves early when the session ends or goes fatal, or the
   * alias `run` stops (`stopTimers`); the caller then sees the new generation, `fatal` or the stop, and stops.
   */
  private wait(ms: number, run: AliasRun | null = null): Promise<void> {
    if (run?.stopped) return Promise.resolve();
    this.waiting++;
    return new Promise<void>((resolve) => {
      const t = this.clock.setTimer(() => {
        this.protocolTimers.delete(t);
        resolve();
      }, ms);
      this.protocolTimers.set(t, { due: this.clock.mono() + ms, release: resolve, run });
    }).finally(() => this.waiting--);
  }

  /** Releases the protocol timers: every one, or those of one alias. */
  private stopTimers(run?: AliasRun): void {
    const timers = [...this.protocolTimers].filter(([, x]) => run === undefined || x.run === run);
    for (const [t, { release }] of timers) {
      this.protocolTimers.delete(t);
      t.cancel();
      release();
    }
  }

  // ───────────── aliases (§2.6) ─────────────

  /** The owner's alias table (PREFS key 1): one entry per index 0..n−1 (§2.6, §7.2). */
  private table(): P.AliasEntry[] {
    return this.self?.fold.aliasTable() ?? [];
  }

  /** The indices this device runs: the live ones, at most the newest MAX_LIVE_ALIASES (§2.6). */
  private runnable(t: readonly P.AliasEntry[] = this.table()): Set<number> {
    const live = t.flatMap((x, i) => (x.retired ? [] : [i]));
    return new Set(live.slice(-P.MAX_LIVE_ALIASES));
  }

  /** The uid of alias i (b64u), from AK. */
  private aliasUidOf(i: number): string {
    let u = this.aliasUids.get(i);
    if (u === undefined) {
      u = this.aliasKeyCache.get(i)?.uidB ?? P.b64u(P.aliasUid(P.aliasKey(this.account!.AK, i)));
      this.aliasUids.set(i, u);
    }
    return u;
  }

  /** Every key of alias i (§2.6 "Keys"). */
  private aliasKeysOf(i: number): AliasKeys {
    let k = this.aliasKeyCache.get(i);
    if (!k) this.aliasKeyCache.set(i, (k = aliasKeys(this.account!.AK, i)));
    return k;
  }

  /**
   * The uids of the user's own accounts: the owner (-1) and every alias of the table (its index), retired ones
   * included (§2.6).
   */
  private ownUids(): Map<string, number> {
    const acc = this.account;
    if (!acc) return new Map();
    const v = this.self?.fold.aliasVersion ?? 0;
    if (this.ownUidMap?.v !== v) {
      const map = new Map<string, number>([[acc.uidB, -1]]);
      this.table().forEach((_, i) => map.set(this.aliasUidOf(i), i));
      this.ownUidMap = { v, map };
    }
    return this.ownUidMap.map;
  }

  /**
   * A member of a descriptor is one of the user's own accounts: D lists that account's uid with its own derived sigPk
   * and kh (§2.6 "The owner's accounts"). Any other slot with such a uid is an unknown member, rung, counted and
   * notified like any other, so a committer learns nothing from a forged slot.
   */
  private isOwnMember(m: P.Member): boolean {
    const i = this.ownUids().get(P.b64u(m.uid));
    if (i === undefined) return false;
    let k = this.ownMemberKeys.get(i);
    if (!k) {
      const id = i < 0 ? this.account!.id : this.aliasKeysOf(i).id;
      this.ownMemberKeys.set(i, (k = { sigPk: id.sigPk, kh: P.kemHash(id.kemPk) }));
    }
    return P.equalBytes(m.sigPk, k.sigPk) && P.equalBytes(m.kh, k.kh);
  }

  /** The handle and fingerprint of alias i with handle counter c (§2.6), computed once. */
  private aliasShownOf(i: number, c: number): { handle: string; fingerprint: string } {
    let x = this.aliasShown.get(`${i}:${c}`);
    if (!x) {
      const k = this.aliasKeysOf(i);
      x = {
        handle: P.aliasHandle(k.uid, k.id.sigPk, k.id.kemPk, c),
        fingerprint: P.fingerprint(k.uid, k.id.sigPk, k.id.kemPk),
      };
      this.aliasShown.set(`${i}:${c}`, x);
    }
    return x;
  }

  /**
   * The user's accounts that a conversation of another never gets (§2.6): the owner and every alias of the table,
   * retired ones included, each with its handle (an alias's computed from the table).
   */
  private ownAccounts(): { uidB: string; handle: string }[] {
    const acc = this.account;
    if (!acc) return [];
    return [
      { uidB: acc.uidB, handle: acc.handle },
      ...this.table().map((x, i) => ({
        uidB: this.aliasUidOf(i),
        handle: this.aliasShownOf(i, x.c).handle,
      })),
    ];
  }

  /** The owner's nickname for a user (§11.19): shown only while it is a valid name, never for an own account. */
  private nickOf(uidB: string): string {
    const name = this.self?.fold.nicks.get(uidB);
    return name && P.validNickname(name) && !this.ownUids().has(uidB) ? name : "";
  }

  /**
   * The owner's fold changed: new nicknames are shown everywhere at once (§11.19), and the device starts or stops the
   * aliases whose table entries changed (§2.6 "Running aliases").
   */
  private ownerFoldChanged(): void {
    const f = this.self?.fold;
    if (!f) return;
    if (f.aliasVersion !== this.aliasSeen) {
      this.aliasSeen = f.aliasVersion;
      const gen = this.generation;
      if (this.tableKnown) queueMicrotask(() => this.syncAliases(gen));
      this.scheduleEmit(true);
    }
    if (f.nickVersion !== this.nickSeen) {
      this.nickSeen = f.nickVersion;
      this.msg?.nicknamesChanged();
      for (const run of this.aliases.values()) if (!run.stopped) run.msg?.nicknamesChanged();
      this.scheduleCache(0);
      this.scheduleEmit(true);
    }
  }

  /** Runs every live alias of the table (the newest MAX_LIVE_ALIASES) and stops every other one (§2.6). */
  private syncAliases(gen: number): void {
    if (!this.tableKnown || gen !== this.generation || this.fatal || !this.self) return;
    const t = this.table();
    const runs = this.runnable(t);
    if (t.filter((x) => !x.retired).length > runs.size) this.warn(ALIASES_NOT_RUN);
    for (const run of this.aliases.values()) if (!runs.has(run.i)) this.stopAlias(run);
    for (const i of runs) if (!this.aliases.has(i)) this.startAlias(i, gen);
  }

  private startAlias(i: number, gen: number): void {
    const keys = this.aliasKeysOf(i);
    const acc: Account = {
      uid: keys.uid,
      uidB: keys.uidB,
      AK: keys.AK,
      id: keys.id,
      handle: "",
      regEra: null,
      inbox: [],
    };
    let settle!: AliasRun["settle"];
    const running = new Promise<void>((ok, fail) => (settle = { ok, fail }));
    running.catch(() => {});
    const self = new SelfLane(
      this.api,
      keys.id,
      {
        warn: (t, critical) => this.warn(t, critical),
        applied: () => {
          this.version++;
          this.scheduleEmit();
        },
      },
      false,
    );
    const run: AliasRun = {
      i,
      keys,
      acc,
      self,
      msg: null,
      status: "starting",
      queue: Promise.resolve(),
      stopped: false,
      registered: null,
      running,
      settle,
    };
    this.aliases.set(i, run);
    // one alias at a time, alongside the owner's §11.4 steps 5–11 (§2.6 "Running aliases", §11.1 step 5)
    const next = this.aliasChain.then(() => this.runAlias(run, gen));
    this.aliasChain = next.catch(() => {});
    void this.track(next).catch(() => {});
    this.updateSyncing();
  }

  /**
   * §11.1 step 5 for one alias: its account check (`checkAlias`; a failure is not fatal, §2.6), its restore from its
   * own self lane (with the registration HEADS when its register request got the 200 here), then its realtime and
   * catch-up.
   */
  private async runAlias(run: AliasRun, gen: number): Promise<void> {
    const { acc, self } = run;
    // This device's creation of it registers it first (§2.6 "Creating"); a failed one retires it, which stops it.
    const making = this.creating.get(run.i);
    if (making) {
      await making;
      this.syncAliases(gen);
    }
    let cursor: InboxCursor | null = null;
    const ok = await this.retrying(
      gen,
      async () => {
        this.assertAlias(run, gen);
        const mine = this.justRegistered.get(run.i);
        if (mine) {
          run.registered ??= mine;
          this.justRegistered.delete(run.i);
        }
        const p = await this.api.params();
        if (acc.regEra === null && !(await this.checkAlias(run, gen))) return;
        self.floorEra = acc.regEra!;
        await this.enqueueRun(run, () => this.readSelf(self, acc));
        this.assertAlias(run, gen);
        if (run.registered && !self.fold.cursor) {
          cursor ??= cursorAt(
            run.registered.now ?? P.eraStart(acc.regEra!),
            p,
            P.era(this.api.serverNow()),
          );
          const c = cursor;
          await this.enqueueRun(run, () =>
            self.write([{ rtype: P.RT.HEADS, Ein: c.E, relIn: c.rel, entries: [] }]),
          );
        }
        const msg = (run.msg ??= new Messaging(this.host(acc, gen, run)));
        await this.enqueueRun(run, () => msg.restore());
      },
      run,
    );
    if (run.status === "failed") {
      run.settle.fail(new UserError(ALIAS_CREATE_FAILED));
      this.updateSyncing();
      return;
    }
    if (!ok || run.stopped || !run.msg) {
      run.settle.fail(new SessionEnded());
      return;
    }
    if (this.state.error.startsWith("sync failed:")) this.patch({ error: "" });
    run.status = "ready";
    run.msg.start();
    this.refreshHub();
    run.settle.ok();
    if (this.live) {
      this.push.changed();
      this.scheduleCache(CACHE_DEBOUNCE_MS);
    }
    this.updateSyncing();
  }

  /**
   * §11.1 step 2 for an alias (§2.6 "Running aliases"): an exact lookup of its uid. A 404 means that a creation stopped
   * after writing the table, so this device registers it ("Creating" steps 3–4). A bundle with its derived keys and the
   * handle of another c′ ≤ 3 than the table's gets c′ written into the table. Any other entry, or a registration that
   * fails, and the device does not run it: status "failed" with the critical warning, and false. Transient failures
   * throw (the restore retries them).
   */
  private async checkAlias(run: AliasRun, gen: number): Promise<boolean> {
    const { acc, keys } = run;
    const owner = this.account!;
    const check = () => this.assertAlias(run, gen);
    let u = await this.api.userByUid(acc.uid);
    check();
    if (!u) {
      let r: AliasRegistration;
      try {
        r = await this.registerAliasAt(
          owner,
          gen,
          run.i,
          check,
          (ms) => this.wait(ms, run),
          () => {},
        );
      } catch (e) {
        if (e instanceof UserError) return this.aliasFailed(run);
        throw e;
      }
      // its first self row is the registration HEADS only when this device's own register request got the 200
      if (!r.exists) run.registered ??= { now: r.regNow };
      u = r.user ?? (await this.api.userByUid(acc.uid));
      check();
    }
    const x = this.table()[run.i];
    const c =
      x && u && isAliasEntry(u, keys)
        ? P.aliasHandleTry(u.handle, keys.uid, keys.id.sigPk, keys.id.kemPk)
        : -1;
    if (!x || !u || c < 0) return this.aliasFailed(run);
    // a creation that stopped between registering with c′ and writing it
    if (c !== x.c) await this.writeTable(owner, gen, setEntry(run.i, { c }));
    check();
    acc.handle = u.handle;
    acc.regEra = u.regEra;
    acc.inbox = u.inbox;
    return true;
  }

  /** §2.6: an alias whose directory entry does not check, or that cannot be registered, is not run here. */
  private aliasFailed(run: AliasRun): false {
    run.status = "failed";
    this.warn(ALIAS_NOT_LISTED, true);
    return false;
  }

  /**
   * Stops an alias (retired, beyond the ones that run, or the session ends) as a sign-out stops an account: nothing of
   * it runs, its pending deliveries wait, its views go; the registration set and the cache are sent again (§2.6).
   */
  private stopAlias(run: AliasRun): void {
    if (run.stopped) return;
    run.stopped = true;
    run.msg?.stop();
    if (this.aliases.get(run.i) === run) this.aliases.delete(run.i);
    if (run.msg) this.dropBlobs(run.msg);
    this.stopTimers(run);
    run.settle.fail(new SessionEnded());
    this.refreshHub();
    if (this.live) {
      this.push.changed();
      this.scheduleCache(CACHE_DEBOUNCE_MS);
    }
    this.updateSyncing();
  }

  /** Throws once the alias run stopped or the session changed. */
  private assertAlias(run: AliasRun, gen: number): void {
    if (this.generation !== gen || run.stopped || this.aliases.get(run.i) !== run)
      throw new SessionEnded();
  }

  /** Serialises an alias's state-changing work in its own queue. */
  private enqueueRun<T>(run: AliasRun, fn: () => Promise<T>): Promise<T> {
    const p = run.queue.then(fn);
    run.queue = p.catch(() => {});
    return p;
  }

  /**
   * §2.6 "Retiring": the device revokes the image and file URLs of a stopped alias. The caches are the device's, shared
   * by its accounts, so a blob that the copies of the owner or of another running alias also show stays.
   */
  private dropBlobs(gone: Messaging): void {
    const keys = gone.blobKeys();
    if (keys.size === 0) return;
    const others = [
      this.msg,
      ...[...this.aliases.values()].filter((r) => !r.stopped).map((r) => r.msg),
    ];
    for (const m of others) if (m && m !== gone) for (const k of m.blobKeys()) keys.delete(k);
    for (const k of keys) {
      gone.images.drop(k);
      const f = gone.fileCache.get(k);
      if (!f) continue;
      gone.fileCache.delete(k);
      f.then((x) => URL.revokeObjectURL(x.url)).catch(() => {});
    }
  }

  /**
   * Writes the alias table that `change` makes of the fold's (§2.6, §7.3): at once, in the owner's queue. On a CONFLICT
   * the table is built again from the fold, with the occupant applied, and changed again, so a sibling's concurrent
   * change is kept. Nothing is written when the change changes nothing.
   */
  private async writeTable(
    acc: Account,
    gen: number,
    change: (t: P.AliasEntry[]) => P.AliasEntry[],
  ): Promise<void> {
    const self = this.self!;
    const records = (): P.SelfRecord[] => {
      const cur = self.fold.aliasTable();
      const next = change(cur);
      return sameTable(cur, next)
        ? []
        : [{ rtype: P.RT.PREFS, key: P.PREFS_ALIASES, value: P.encodeAliasTable(next) }];
    };
    await this.enqueue(async () => {
      this.assertSession(acc, gen);
      const first = records();
      if (first.length) await self.write(first, async () => records());
    });
    this.assertSession(acc, gen);
    this.ownerFoldChanged();
  }

  /** The registration set's secrets of every running account, ranked together by `lastTs` (§11.13). */
  private pushSecrets(): Uint8Array[] {
    const all = this.msg?.pushEntries() ?? [];
    for (const m of this.aliasMsgs()) all.push(...m.pushEntries());
    return all.sort((a, b) => b.lastTs - a.lastTs).map((x) => x.secret);
  }

  /** The badge (§11.13): the copies of every running account that count as unread. */
  private unreadCount(): number {
    if (!this.msg) return 0;
    return [this.msg, ...this.aliasMsgs()].reduce((n, m) => n + m.unreadCount(), 0);
  }

  /** "Remember this device" is a convenience: failing to store the session must not fail the sign-in. */
  private async remember(u: Unlocked): Promise<void> {
    try {
      await this.sessionStore.save(P.b64u(u.uid), u.AK);
      this.remembered = true;
      this.patch(this.notificationPatch());
    } catch (e) {
      this.patch({
        error: `this browser could not remember the session (${message(e)}); you will need to sign in again next time`,
      });
    }
  }

  private resetData(): void {
    for (const run of this.aliases.values()) {
      run.stopped = true;
      run.msg?.stop();
      run.settle.fail(new SessionEnded());
    }
    this.aliases.clear();
    this.tableKnown = false;
    // waiters see the session end (their check throws)
    this.selfApplied.resolve();
    this.selfApplied = deferred();
    this.ownerDone = false;
    this.aliasChain = Promise.resolve();
    this.creating.clear();
    this.hub?.stop();
    this.hub = null;
    this.periodicTimer?.cancel();
    this.periodicTimer = null;
    this.aliasKeyCache.clear();
    this.aliasUids.clear();
    this.justRegistered.clear();
    this.nickSeen = 0;
    this.aliasSeen = 0;
    this.ownUidMap = null;
    this.ownMemberKeys.clear();
    this.aliasShown.clear();
    this.aliasCreation = Promise.resolve();
    this.msg?.stop();
    this.msg = null;
    this.pending.clear();
    this.critical = [];
    this.noise.clear();
    this.live = false;
    this.ownerQueue = Promise.resolve();
  }

  /** Throws if the user signed out (or another account signed in) since `acc` was captured. */
  private assertSession(acc: Account, gen = this.generation): void {
    if (this.account !== acc || this.generation !== gen) throw new SessionEnded();
  }

  private requireAccount(): Account {
    if (!this.account) throw new UserError("not signed in");
    return this.account;
  }

  /** Serialises the owner's state-changing work. */
  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.ownerQueue.then(fn);
    this.ownerQueue = p.catch(() => {});
    return p;
  }

  // ───────────── state, errors and warnings ─────────────

  private async authFlow<T>(fn: () => Promise<T>): Promise<T> {
    if (this.account) throw new UserError("already signed in");
    this.patch({ phase: "working", error: "", progress: "" });
    this.inflight++;
    try {
      return await fn();
    } catch (e) {
      if (!this.account) this.patch({ phase: "signed-out" });
      this.patch({ error: message(e) });
      throw e;
    } finally {
      this.inflight--;
      this.progress("");
    }
  }

  private async action<T>(fn: () => Promise<T>): Promise<T> {
    this.inflight++;
    try {
      return await fn();
    } catch (e) {
      if (!(e instanceof UserError) && !(e instanceof SessionEnded)) console.error("segv:", e);
      if (!(e instanceof SessionEnded)) this.patch({ error: message(e) });
      throw e;
    } finally {
      this.inflight--;
      this.progress("");
    }
  }

  /**
   * Security warnings (`critical`) stay until sign-out and are never evicted. Everything else is noise an outsider
   * can trigger (junk invites, short directory pages), so it is deduplicated and only the latest few are kept.
   */
  private warn(text: string, critical = false): void {
    if (critical) {
      if (this.critical.includes(text)) return;
      this.critical.push(text);
    } else {
      const n = (this.noise.get(text) ?? 0) + 1;
      this.noise.delete(text);
      this.noise.set(text, n);
      while (this.noise.size > MAX_NOISE) this.noise.delete(this.noise.keys().next().value!);
    }
    const noise = [...this.noise].map(([t, n]) => (n > 1 ? `${t} (×${n})` : t));
    this.state = { ...this.state, warnings: [...this.critical, ...noise] };
    this.scheduleEmit();
  }

  /** Ends the session's work: the account check failed (§11.1, §12.7). */
  private die(text: string): void {
    this.fatal = true;
    for (const run of this.aliases.values()) this.stopAlias(run);
    this.selfApplied.resolve();
    this.periodicTimer?.cancel();
    this.periodicTimer = null;
    this.stopTimers();
    this.patch({ phase: "fatal", error: text, syncing: false, connected: false });
  }

  private progress(text: string): void {
    if (this.state.progress !== text) this.patch({ progress: text });
  }

  private patch(p: Partial<EngineState>): void {
    this.state = { ...this.state, ...p };
    this.scheduleEmit(true);
  }

  private scheduleEmit(soon = false): void {
    if (this.emitTimer) {
      if (!soon) return;
      clearTimeout(this.emitTimer);
    }
    this.emitTimer = setTimeout(() => this.emitNow(), soon ? 0 : this.live ? 30 : 200);
  }

  private emitNow(): void {
    if (this.emitTimer) clearTimeout(this.emitTimer);
    this.emitTimer = null;
    if (this.account)
      this.state = {
        ...this.state,
        conversations: this.views(),
        identities: this.identities(),
        people: this.people(),
      };
    if (this.local) this.local.badge(this.account ? this.unreadCount() : 0);
    for (const fn of this.listeners) {
      try {
        fn(this.state);
      } catch (e) {
        console.error(e);
      }
    }
  }
}

let instance: SegvEngine | undefined;

let configured: EngineOptions | undefined;

/**
 * The platform of a native app (§11.14), given once before the UI first asks for the engine: its canonical origin, its
 * passkeys, storage and notifications. A browser never calls it.
 */
export function configureEngine(opts: EngineOptions): void {
  if (instance) throw new Error("the engine has already started");
  configured = opts;
}

/** The browser-wide engine singleton (booted on first use). */
export function getEngine(): Engine {
  if (!instance) {
    instance = new SegvEngine(configured);
    void instance.boot();
  }
  return instance;
}
