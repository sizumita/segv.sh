// The segv.sh client engine (docs/PROTOCOL.md §11): unlocks the account key with a passkey (PRF) or the recovery
// code, checks the account against the directory, restores the account's state from its self lane, and turns it into
// the view the UI renders. Browser only: the UI imports it dynamically (src/components/engine-loader.ts).
//
// The session's conversations live in Messaging (messaging.ts); this class owns accounts, the session lifecycle,
// the generation guards, state emission and warnings.
import * as P from "~/lib/proto";
import {
  addPasskeyTo,
  loginWithCode,
  loginWithPasskey,
  registerAccount,
  type Unlocked,
} from "./accounts";
import { Api, isTransient, pushParams } from "./api";
import { SessionEnded, UserError, message } from "./errors";
import {
  DEFAULT_DELAYS,
  systemClock,
  type EngineClock,
  type EngineDelays,
  type EngineOptions,
  type EngineTimer,
} from "./options";
import { refKeyOf } from "./conv";
import { cursorAt, type InboxCursor } from "./inbox";
import { Messaging, type MessagingHost } from "./messaging";
import { PushClient, browserPushPlatform, localPushStore } from "./push";
import { SelfLane } from "./selflane";
import { readSnapshot } from "./snapshot";
import { clearSession, loadSession, saveSession } from "./session";
import type { ConversationView, Engine, EngineState, ImageRef } from "./types";
import { prfCapability } from "./webauthn";

export type { EngineOptions } from "./options";

/** Messages per conversation handed to the UI (§11). */
export const VIEW_MESSAGES = 500;
/** Noise warnings kept (deduplicated, with a count). */
const MAX_NOISE = 5;

export const ACCOUNT_MISSING = "your account was not found in the directory of this server";
export const ACCOUNT_KEYS_MISMATCH =
  "the public keys registered for your account do not match your passkey's keys";

interface Account {
  uid: Uint8Array;
  uidB: string;
  AK: Uint8Array;
  id: P.Identity;
  handle: string;
  /** era of registration, from the directory (§11.1); null until the account check */
  regEra: number | null;
}

/** What the registering device knows of its registration: its server time, when the response arrived (§11.1). */
interface Registration {
  now: number | null;
}

const emptyState = (): EngineState => ({
  phase: "boot",
  progress: "",
  error: "",
  me: null,
  conversations: [],
  head: { seq: 0, h: "" },
  connected: false,
  syncing: false,
  warnings: [],
  prfSupported: null,
  notifications: "unavailable",
});

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

  private account: Account | null = null;
  private self: SelfLane | null = null;
  /** the session's conversations, once restored */
  private msg: Messaging | null = null;
  queue: Promise<unknown> = Promise.resolve();
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
  private readonly protocolTimers = new Map<EngineTimer, { due: number; release: () => void }>();
  private live = false;
  private critical: string[] = [];
  private readonly noise = new Map<string, number>();

  constructor(opts: EngineOptions = {}) {
    this.opts = opts;
    this.clock = opts.clock ?? systemClock;
    this.delays = { ...DEFAULT_DELAYS, ...opts.delays };
    this.fetchFn = opts.fetch ?? ((input, init) => fetch(input, init));
    this.api = this.newApi();
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
      bells: () => this.msg?.pushBells() ?? [],
      onOff: () => this.patch({ notifications: this.notificationState() }),
    });
  }

  private notificationState(): EngineState["notifications"] {
    if (!this.push.available) return "unavailable";
    return this.push.on ? "on" : "off";
  }

  private newApi(): Api {
    return new Api({
      fetch: this.fetchFn,
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
    this.patch({ prfSupported: await prfCapability() });
    const s = await loadSession();
    if (!s) return this.patch({ phase: "signed-out" });
    try {
      await this.unlock(s.AK, P.fromB64u(s.uid), "");
    } catch (e) {
      await clearSession();
      this.patch({ phase: "signed-out", error: `could not restore session: ${message(e)}` });
    }
  }

  register(handleIn: string, remember = false): Promise<{ recoveryCode: string }> {
    return this.authFlow(async () => {
      const r = await registerAccount(this.api, handleIn, (m) => this.progress(m));
      await this.unlock(r.AK, r.uid, r.handle, { now: r.regNow });
      if (remember) await this.remember(r);
      return { recoveryCode: r.recoveryCode };
    });
  }

  login(remember: boolean): Promise<void> {
    return this.authFlow(async () => {
      const found = await loginWithPasskey(this.api, (m) => this.progress(m));
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
    await clearSession();
    for (const p of this.imageCache.values()) p.then((u) => URL.revokeObjectURL(u)).catch(() => {});
    this.resetData();
    this.account = null;
    this.self = null;
    this.fatal = false;
    this.api = this.newApi();
    this.state = { ...emptyState(), phase: "signed-out", prfSupported: this.state.prfSupported };
    this.emitNow();
  }

  async setNotifications(on: boolean): Promise<void> {
    try {
      if (on) await this.push.enable();
      else await this.push.disable();
    } catch (e) {
      this.patch({ error: message(e) });
    } finally {
      this.patch({ notifications: this.notificationState() });
    }
  }

  async createConversation(handles: string[], name?: string): Promise<string> {
    this.requireAccount();
    return this.action(() => this.messaging().create(handles, name));
  }

  async sendText(convId: string, text: string): Promise<void> {
    this.requireAccount();
    try {
      await this.messaging().sendText(convId, text);
    } catch (e) {
      this.patch({ error: message(e) });
    }
  }

  async sendImage(convId: string, file: File): Promise<void> {
    this.requireAccount();
    try {
      await this.messaging().sendImage(convId, file);
    } catch (e) {
      this.patch({ error: message(e) });
    }
  }

  /** §11.12: one emoji reaction to a TEXT or IMAGE message, without an echo; rejects with §11.3's errors. */
  async react(convId: string, messageKey: string, emoji: string, on: boolean): Promise<void> {
    this.requireAccount();
    await this.action(() => this.messaging().react(convId, messageKey, emoji, on));
  }

  /** The accept control (§11.5, §11.11): the user's acceptance of a copy whose inviter is not a contact yet. */
  async accept(convId: string): Promise<void> {
    this.requireAccount();
    await this.action(() => this.messaging().accept(convId));
  }

  async addMembers(convId: string, handles: string[]): Promise<void> {
    this.requireAccount();
    await this.action(() => this.messaging().addMembers(convId, handles));
  }

  async removeMember(convId: string, uid: string): Promise<void> {
    this.requireAccount();
    await this.action(() => this.messaging().removeMember(convId, uid));
  }

  async leave(convId: string): Promise<void> {
    this.requireAccount();
    await this.action(() => this.messaging().leave(convId));
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

  loadImage(img: ImageRef): Promise<string> {
    if (!this.msg) return Promise.reject(new UserError("not signed in"));
    return this.msg.loadImage(img);
  }

  markRead(convId: string): void {
    this.msg?.markRead(convId);
  }

  clearError(): void {
    this.patch({ error: "" });
  }

  private messaging(): Messaging {
    if (!this.msg) throw new UserError("still restoring; try again in a moment");
    return this.msg;
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
  get imageCache(): Map<string, Promise<string>> {
    return this.msg?.imageCache ?? new Map();
  }

  /** the per-conversation send chains */
  get sendChains(): Map<string, Promise<unknown>> {
    return this.msg?.chains ?? new Map();
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

  /** One catch-up round (§11.6): the self lane, every copy's lanes, the inbox, HEADS. */
  async catchUp(): Promise<void> {
    if (!this.msg || !this.live || this.fatal) return;
    await this.msg.catchUp();
  }

  views(): ConversationView[] {
    return this.msg?.views() ?? [];
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
    this.account = { uid, uidB, AK, id, handle, regEra: null };
    this.self = new SelfLane(this.api, id, {
      warn: (t, critical) => this.warn(t, critical),
      applied: () => {
        this.version++;
        this.scheduleEmit();
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
      await this.enqueue(async () => {
        if (!self.snapshotRead) {
          const snap = await readSnapshot(this.api, acc.id, acc.regEra!);
          self.snapshotRead = true;
          if (snap) {
            self.fold.applySnapshot(snap.records, snap.ts);
            self.snapshot = { E: snap.E, applied: self.fold.applied, pos: snap.pos };
          }
        }
        const pos = self.snapshot?.pos;
        await self.catchUp(
          pos && !P.isNone(pos) ? { E: pos.E, n: pos.n } : { E: acc.regEra!, n: 0 },
        );
      });
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
      await this.enqueue(() => msg.restore()); // serialised with the work it starts (new copies, member lookups)
    });
    if (!ok || gen !== this.generation || this.fatal) return;
    if (this.state.error.startsWith("sync failed:")) this.patch({ error: "" });
    this.live = true;
    this.msg!.start();
    this.push.restored();
    this.patch({ syncing: false, notifications: this.notificationState() });
  }

  /** What the session's Messaging calls back into. */
  private host(acc: Account, gen: number): MessagingHost {
    return {
      api: this.api,
      clock: this.clock,
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
        refKey: refKeyOf(acc.AK),
      },
      self: this.self!,
      check: () => this.assertSession(acc, gen),
      warn: (t, c) => this.warn(t, c),
      changed: () => {
        this.version++;
        this.scheduleEmit();
        // The registration set may have changed: computed again within Δ, sent only if it differs (§11.13).
        if (this.live && gen === this.generation) this.push.changed();
      },
      emitNow: () => this.emitNow(),
      progress: (t) => this.progress(t),
      error: (t) => this.patch({ error: t }),
      wait: (ms) => this.wait(ms),
      enqueue: (fn) => this.enqueue(fn),
      track: (p) => this.track(p),
      setConnected: (on) => this.patch({ connected: on }),
      setHead: (q, C) => this.patch({ head: { seq: q, h: P.b64u(C) } }),
      ring: (E, label, bells) => {
        if (gen === this.generation) this.push.ring(E, label, bells);
      },
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
    if (this.state.me) this.patch({ me: { ...this.state.me, handle: u.handle } });
  }

  /**
   * Runs `fn` until it succeeds, retrying failures with back-off on protocol timers (so the session's `busy` count
   * covers the wait). Resolves false when the session ended or went fatal.
   */
  private async retrying(gen: number, fn: () => Promise<void>): Promise<boolean> {
    for (let attempt = 0; ; attempt++) {
      if (gen !== this.generation || this.fatal) return false;
      try {
        await fn();
        return gen === this.generation && !this.fatal;
      } catch (e) {
        if (e instanceof SessionEnded || gen !== this.generation || this.fatal) return false;
        if (!isTransient(e)) console.error("segv:", e);
        this.patch({ error: `sync failed: ${message(e)} (retrying)` });
        await this.wait(Math.min(this.delays.retryMax, this.delays.retryBase * 2 ** attempt));
      }
    }
  }

  /**
   * Waits `ms` on a protocol timer (counted in `busy`). It resolves early when the session ends or goes fatal
   * (`stopTimers`); the caller then sees the new generation or `fatal` and stops.
   */
  private wait(ms: number): Promise<void> {
    this.waiting++;
    return new Promise<void>((resolve) => {
      const t = this.clock.setTimer(() => {
        this.protocolTimers.delete(t);
        resolve();
      }, ms);
      this.protocolTimers.set(t, { due: this.clock.mono() + ms, release: resolve });
    }).finally(() => this.waiting--);
  }

  private stopTimers(): void {
    const timers = [...this.protocolTimers];
    this.protocolTimers.clear();
    for (const [t, { release }] of timers) {
      t.cancel();
      release();
    }
  }

  /** "Remember this device" is a convenience: failing to store the session must not fail the sign-in. */
  private async remember(u: Unlocked): Promise<void> {
    try {
      await saveSession(P.b64u(u.uid), u.AK);
    } catch (e) {
      this.patch({
        error: `this browser could not remember the session (${message(e)}); you will need to sign in again next time`,
      });
    }
  }

  private resetData(): void {
    this.msg?.stop();
    this.msg = null;
    this.pending.clear();
    this.critical = [];
    this.noise.clear();
    this.live = false;
    this.queue = Promise.resolve();
  }

  /** Throws if the user signed out (or another account signed in) since `acc` was captured. */
  private assertSession(acc: Account, gen = this.generation): void {
    if (this.account !== acc || this.generation !== gen) throw new SessionEnded();
  }

  private requireAccount(): Account {
    if (!this.account) throw new UserError("not signed in");
    return this.account;
  }

  /** Serialises state-changing work. */
  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.queue.then(fn);
    this.queue = p.catch(() => {});
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
    if (this.account) this.state = { ...this.state, conversations: this.views() };
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

/** The browser-wide engine singleton (booted on first use). */
export function getEngine(): Engine {
  if (!instance) {
    instance = new SegvEngine();
    void instance.boot();
  }
  return instance;
}
