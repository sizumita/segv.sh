/**
 * Engine-v2 test harness (docs/STAGE1-PLAN.md §2): runs the client engine (src/client/engine.ts, milestone M6) in
 * Node against `FakeWorld`, an in-memory fake of the v2 Worker and its Durable Objects (test/engine/fake/).
 *
 * - `server()` is the current FakeWorld; `freshWorldPerTest()` gives every test its own world and an empty
 *   localStorage, and runs the registered cleanups (engine logouts) afterwards.
 * - Browser globals the engine touches are replaced by fakes bound to the current world: `fetch`, `WebSocket`
 *   (FakeWebSocket), `location` (http://segv.test/), `localStorage` (`localStore`), and an always-failing
 *   `indexedDB` (as in a private window). `installBrowserGlobals()` runs on import; `uninstallBrowserGlobals()`
 *   restores Node's originals.
 * - Requests through the global fetch / WebSocket are anonymous (`who = null`). Per-engine attribution (needed by
 *   `world.shard.hide()`, per-user rate limits and per-user request counts) uses `world.transport(who)`; see
 *   test/engine/fake/world.ts.
 */
import { afterEach, beforeEach } from "vite-plus/test";
import * as P from "../../src/lib/proto";
import * as W from "../../src/lib/wire";
import type { ConversationView, Engine } from "../../src/client/types";
import { SegvEngine, type EngineOptions } from "../../src/client/engine";
import type {
  EngineClock,
  EngineDelays,
  EngineTimer,
  WebSocketCtor,
} from "../../src/client/options";
import type { SelfLane } from "../../src/client/selflane";
import type { Copy, Epoch } from "../../src/client/conv";
import { FakeWebSocket } from "./fake/rt";
import { FakeWorld, type FakeWorldOptions } from "./fake/world";

export { P, W, FakeWorld, FakeWebSocket, SegvEngine };
export * from "./fake/world";
export type { FakeParams, PublishRow } from "./fake/common";
export type { ShardRow, ShardBatch } from "./fake/shard";
export type { BlobRegEntry } from "./fake/blobs";
export type { InboxStoredRow, InboxRowResult, InboxJitterFn } from "./fake/inbox";
export type { RtLimits } from "./fake/rt";
export type { DirUserRow, DirWrapRow, DirlogRow, DirPrefixQuery } from "./fake/dir";
export type { CkptEntry, CkptHead } from "./fake/ckpt";
export { CKPT_PERIOD_MS } from "./fake/ckpt";
export { RT_LIMITS } from "./fake/rt";

// ───────────────────────── the current world ─────────────────────────

let current = new FakeWorld();

/** The FakeWorld every global (fetch, WebSocket) is currently bound to. */
export const server = (): FakeWorld => current;

/** Makes `w` the current world (freshWorldPerTest does this before every test). */
export function useWorld(w: FakeWorld): FakeWorld {
  current = w;
  return w;
}

// ───────────────────────── browser globals ─────────────────────────

const storage = new Map<string, string>();
/** The fake localStorage's backing map. */
export const localStore = storage;

const fakeLocalStorage = {
  getItem: (k: string) => (storage.has(k) ? storage.get(k)! : null),
  setItem: (k: string, v: string) => void storage.set(k, String(v)),
  removeItem: (k: string) => void storage.delete(k),
  clear: () => storage.clear(),
  key: (i: number) => [...storage.keys()][i] ?? null,
  get length() {
    return storage.size;
  },
};

const fakeLocation = {
  href: "http://segv.test/",
  origin: "http://segv.test",
  protocol: "http:",
  hostname: "segv.test",
  host: "segv.test",
  port: "",
  pathname: "/",
  search: "",
  hash: "",
};

// No IndexedDB: "remember this device" fails and clearing a remembered session is a no-op, as in a private window.
const fakeIndexedDB = {
  open() {
    const req: { error?: Error; onerror?: () => void } = {};
    setTimeout(() => {
      req.error = new Error("indexedDB unavailable");
      req.onerror?.();
    }, 0);
    return req;
  },
};

const GLOBALS: Record<string, unknown> = {
  localStorage: fakeLocalStorage,
  location: fakeLocation,
  WebSocket: FakeWebSocket,
  fetch: (input: RequestInfo | URL, init?: RequestInit) => current.fetch(input, init),
  indexedDB: fakeIndexedDB,
};

const saved = new Map<string, PropertyDescriptor | undefined>();
let installed = false;

/** Installs the fake browser globals (idempotent; runs when this module is imported). */
export function installBrowserGlobals(): void {
  if (installed) return;
  installed = true;
  FakeWebSocket.resolveHost = () => current;
  for (const [name, value] of Object.entries(GLOBALS)) {
    saved.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    Object.defineProperty(globalThis, name, {
      value,
      writable: true,
      configurable: true,
      enumerable: true,
    });
  }
}

/** Restores the globals that installBrowserGlobals() replaced. */
export function uninstallBrowserGlobals(): void {
  if (!installed) return;
  installed = false;
  FakeWebSocket.resolveHost = null;
  for (const [name, d] of saved) {
    if (d) Object.defineProperty(globalThis, name, d);
    else delete (globalThis as Record<string, unknown>)[name];
  }
  saved.clear();
}

installBrowserGlobals();

// ───────────────────────── lifecycle ─────────────────────────

const cleanups: (() => unknown)[] = [];

/** Runs `fn` after the current test (engine logouts register here). */
export function onCleanup(fn: () => unknown): void {
  cleanups.push(fn);
}

/**
 * A fresh FakeWorld (built from `opts`) and an empty localStorage for every test. Afterwards every registered
 * cleanup runs (signing engines out stops their sockets and timers) and the world's sockets are closed.
 */
export function freshWorldPerTest(opts: FakeWorldOptions = {}): void {
  beforeEach(() => {
    current = new FakeWorld(opts);
    storage.clear();
  });
  afterEach(async () => {
    for (const fn of cleanups.splice(0)) {
      try {
        await fn();
      } catch {
        /* ignore */
      }
    }
    current.close();
  });
}

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export async function waitFor(cond: () => boolean, what = "condition", ms = 20_000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(5);
  }
}

// ───────────────────────── users ─────────────────────────

export interface TestUser {
  handle: string;
  AK: Uint8Array;
  uid: Uint8Array;
  uidB: string;
  id: P.Identity;
  /** recovery code (20 bytes) */
  code: Uint8Array;
  /** recovery unlock key + recovery id */
  rk: P.UnlockKey & { id: Uint8Array };
}

/** A user's keys, not registered anywhere (register later with `server().dir.register(registrationOf(u))`). */
export function newTestUser(handle: string): TestUser {
  const AK = P.random(32);
  const uid = P.random(16);
  const id = P.deriveIdentity(AK);
  const code = P.newRecoveryCode();
  return { handle, AK, uid, uidB: P.b64u(uid), id, code, rk: P.recoveryKem(code) };
}

/** The `POST /api/v2/register` body of `u`: its bundle and its recovery wrap. */
export function registrationOf(u: TestUser): {
  bundle: string;
  sig: string;
  wraps: { record: string; sig: string }[];
} {
  const { bundle, sig } = P.makeBundle(u.uid, u.handle, u.id, Date.now());
  const wrap = P.makeWrap(u.uid, "recovery", u.rk.id, u.rk, u.AK, u.id, Date.now());
  return { bundle, sig, wraps: [wrap] };
}

/** Registers a user directly in the current world's directory (bundle + recovery wrap), like POST /api/v2/register. */
export function makeUser(handle: string, opts: { register?: boolean } = {}): TestUser {
  const u = newTestUser(handle);
  if (opts.register === false) return u;
  const r = current.dir.register(registrationOf(u));
  if (r.status !== 200) throw new Error(`register ${handle} failed: ${JSON.stringify(r.json)}`);
  return u;
}

// ───────────────────────── raw rows ─────────────────────────

/** A random row body of class `cls` (what an outsider or a squatter can write). */
export const junkBody = (cls = 0): Uint8Array => P.random(P.BODY_LENS[cls]);

/** Writes a junk row at (E, label) as an attacker; returns the stored row (null when the label was taken). */
export const junkRow = (E: number, label: Uint8Array = P.random(16), cls = 0) =>
  current.shard.commit(E, label, cls, junkBody(cls));

// ───────────────────────── views (through the Engine interface) ─────────────────────────

/**
 * The engine's conversation views, computed now (`I(e).views()`): the emitted `getState().conversations` is
 * throttled, so a test reading it right after `settle` could see an older state.
 */
export const viewsOf = (e: Engine): ConversationView[] => I(e).views();

export const view = (e: Engine, convId: string): ConversationView | undefined =>
  viewsOf(e).find((c) => c.id === convId);

export function mustView(e: Engine, convId: string): ConversationView {
  const v = view(e, convId);
  if (!v) throw new Error("conversation not found in view");
  return v;
}

/** Non-system messages as "handle: text" (status appended unless 'sent'). */
export const chat = (e: Engine, convId: string): string[] =>
  (view(e, convId)?.messages ?? [])
    .filter((m) => m.kind !== "system")
    .map(
      (m) =>
        `${m.fromHandle}: ${m.kind === "image" ? "[image]" : m.text}${m.status === "sent" ? "" : ` (${m.status})`}`,
    );

export const systemLines = (e: Engine, convId: string): string[] =>
  (view(e, convId)?.messages ?? []).filter((m) => m.kind === "system").map((m) => m.text ?? "");

// ═════════════════════════ engines (M6a; docs/STAGE1-PLAN.md §2.2) ═════════════════════════

type Timer = { due: number; fn: () => void; real: ReturnType<typeof setTimeout> | null };

/**
 * An engine's clocks in tests: real time plus offsets (plan §2.2). `world.tick(ms)` moves every registered engine
 * clock with the world; `advance(ms, {mono?, wall?})` moves one engine's clocks (both by default); `pauseMono()` holds
 * the monotonic clock still while the wall clock and the world run on. Timers run on the monotonic clock: they fire
 * when it reaches their due time, by real time or at once when an advance passes it.
 */
export class TestClock implements EngineClock {
  private monoOff = 0;
  private wallOff: number;
  private pausedAt: number | null = null;
  private seq = 0;
  private readonly timers = new Map<number, Timer>();

  /** `wallOffset`: the world's offset, so a new engine's wall clock agrees with the server's time. */
  constructor(wallOffset = 0) {
    this.wallOff = wallOffset;
  }

  mono(): number {
    return (this.pausedAt ?? performance.now()) + this.monoOff;
  }

  wall(): number {
    return Date.now() + this.wallOff;
  }

  setTimer(fn: () => void, ms: number): EngineTimer {
    const id = ++this.seq;
    this.timers.set(id, { due: this.mono() + Math.max(0, ms), fn, real: null });
    this.arm(id);
    return {
      cancel: () => {
        const t = this.timers.get(id);
        if (t?.real) clearTimeout(t.real);
        this.timers.delete(id);
      },
    };
  }

  /** Moves the monotonic and/or the wall clock by `ms` (both by default) and fires the timers that fall due. */
  advance(ms: number, opts: { mono?: boolean; wall?: boolean } = {}): void {
    if (opts.mono ?? true) this.monoOff += ms;
    if (opts.wall ?? true) this.wallOff += ms;
    this.fireDue();
  }

  /** Holds the monotonic clock still (a frozen tab, or a system asleep); timers wait with it. */
  pauseMono(): void {
    if (this.pausedAt === null) this.pausedAt = performance.now();
  }

  resumeMono(): void {
    if (this.pausedAt === null) return;
    this.monoOff += this.pausedAt - performance.now();
    this.pausedAt = null;
    for (const id of this.timers.keys()) this.arm(id);
  }

  /** The due time (monotonic ms) of the earliest timer, or null. */
  nextDue(): number | null {
    let due: number | null = null;
    for (const t of this.timers.values()) if (due === null || t.due < due) due = t.due;
    return due;
  }

  /** Cancels every timer (end of the test). */
  dispose(): void {
    for (const t of this.timers.values()) if (t.real) clearTimeout(t.real);
    this.timers.clear();
  }

  private arm(id: number): void {
    const t = this.timers.get(id);
    if (!t) return;
    if (t.real) clearTimeout(t.real);
    t.real =
      this.pausedAt === null
        ? setTimeout(() => this.fire(id), Math.max(0, t.due - this.mono()))
        : null;
  }

  private fire(id: number): void {
    const t = this.timers.get(id);
    if (!t) return;
    if (this.mono() < t.due) return this.arm(id);
    this.timers.delete(id);
    t.fn();
  }

  private fireDue(): void {
    const due = [...this.timers.entries()]
      .filter(([, t]) => t.due <= this.mono())
      .sort((a, b) => a[1].due - b[1].due);
    for (const [id] of due) this.fire(id);
    for (const id of this.timers.keys()) this.arm(id);
  }
}

/** Protocol delays for tests: retries in milliseconds; the processing wait keeps its 30 s (tests that measure it). */
export const TEST_DELAYS: Partial<EngineDelays> = {
  retryBase: 20,
  retryMax: 500,
  rotationRank: 0,
  resumeAfter: 0,
  headsInterval: 0,
  headsJitter: 0,
  catchUpInterval: 1000,
};

/** White-box view of an engine (plan §2.3). */
export interface EngineI {
  account: {
    uid: Uint8Array;
    uidB: string;
    AK: Uint8Array;
    id: P.Identity;
    handle: string;
    regEra: number | null;
  } | null;
  /** the account's self lane: its head and fold (null while signed out) */
  self: SelfLane | null;
  convs: Map<string, unknown>;
  queue: Promise<unknown>;
  sendChains: Map<string, Promise<unknown>>;
  imageCache: Map<string, Promise<string>>;
  pending: Map<string, string>;
  fatal: boolean;
  generation: number;
  /** bumped on every applied row or record (settle's stamp) */
  version: number;
  /** in-flight actions plus scheduled protocol timers (settle waits for 0) */
  busy: number;
  busyActions: number;
  /** the engine's clocks (a TestClock for engines made by newEngine) */
  clock: TestClock;
  /** the clock sample `{s, mid, rtt}` the server-time estimate uses */
  timeSample: { s: number; mid: number; rtt: number } | null;
  nextProtocolDue(): number | null;
  catchUp(): Promise<void>;
  unlock(
    AK: Uint8Array,
    uid: Uint8Array,
    handle: string,
    registered?: { now: number | null } | null,
  ): Promise<void>;
  views(): ConversationView[];
}

/** White-box access to an engine's private state. */
export const I = (e: Engine): EngineI => e as unknown as EngineI;

/** A copy of the engine by its view key (white-box; plan §2.2). */
export function conv(e: Engine, convId: string): Copy {
  const c = I(e).convs.get(convId) as Copy | undefined;
  if (!c) throw new Error(`no copy ${convId}`);
  return c;
}

/** The current epoch of a copy (white-box; plan §2.2). */
export function epoch(e: Engine, convId: string): Epoch {
  const c = conv(e, convId);
  return c.epochs.get(c.current)!;
}

/**
 * A new signed-out engine attributed to `who` (its requests carry it, plan §2.1), on its own TestClock registered
 * with the world, with TEST_DELAYS and no inbox Web Worker. It is signed out after the test.
 */
export function newEngine(who: string | null = null, opts: EngineOptions = {}): SegvEngine {
  const w = current;
  const clock = new TestClock(w.offsetMs);
  w.clocks.add(clock);
  const t = w.transport(who);
  const e = new SegvEngine({
    fetch: t.fetch,
    WebSocket: t.WebSocket as unknown as WebSocketCtor,
    clock,
    inboxWorker: null,
    ...opts,
    delays: { ...TEST_DELAYS, ...opts.delays },
  });
  onCleanup(async () => {
    await e.logout();
    clock.dispose();
    w.clocks.delete(clock);
  });
  return e;
}

/** Unlocks `u` on a new engine, waits for the restore (`!syncing`), then settles (plan §2.2). */
export async function engineFor(u: TestUser, opts: EngineOptions = {}): Promise<SegvEngine> {
  const e = newEngine(u.handle, opts);
  await I(e).unlock(u.AK, u.uid, u.handle);
  await waitFor(
    () => !e.getState().syncing || e.getState().phase === "fatal",
    `${u.handle} restore`,
  );
  await settle(e);
  return e;
}

/**
 * Runs rounds of {await every engine's queue and sendChains; world.ckpt.tick(); await I(e).catchUp()} until
 * `world.writeCount + Σ I(e).version` is unchanged for 2 rounds, every `I(e).busy` is 0 and the fake inbox holds no
 * row with rel > closed (plan §2.2). When the engines are busy only with protocol timers, it moves the world and the
 * engines' clocks to the earliest one with `world.tick` instead of sleeping.
 *
 * Checkpoints: `ckpt.tick()` mints a new q only once CKPT_PERIOD_MS (60 s) of world clock have passed since the last
 * checkpoint, as the CheckpointDO's alarm does (q grows at most once per 60 s; the client's §12.3 step 4 check relies
 * on it). A test that needs a fresh checkpoint first calls `server().tick(CKPT_PERIOD_MS)`, which moves the world and
 * every engine's clocks together; the server-only `advance` would leave the engines' clocks behind. Never use
 * `tick({ force: true })` here: it models a server minting faster than the spec allows.
 */
export async function settle(...es: Engine[]): Promise<void> {
  const w = current;
  const end = Date.now() + 60_000;
  let last = -1;
  let same = 0;
  for (let round = 0; ; round++) {
    if (Date.now() > end) throw new Error("settle: timed out");
    for (const e of es) {
      const x = I(e);
      await x.queue.catch(() => {});
      for (const p of x.sendChains.values()) await p.catch(() => {});
    }
    w.ckpt.tick();
    for (const e of es) {
      const x = I(e);
      if (x.account && !x.fatal) await x.catchUp().catch(() => {});
    }
    const stamp = w.writeCount + es.reduce((n, e) => n + I(e).version, 0);
    same = stamp === last ? same + 1 : 0;
    last = stamp;
    const busy = es.filter((e) => I(e).busy > 0);
    if (same >= 2 && busy.length === 0 && w.inbox.pendingTotal() === 0) return;
    if (busy.length > 0 && busy.every((e) => I(e).busyActions === 0)) {
      const wait = Math.min(
        ...busy.map((e) => (I(e).nextProtocolDue() ?? Infinity) - I(e).clock.mono()),
      );
      if (Number.isFinite(wait)) w.tick(Math.max(0, Math.ceil(wait)));
    } else if (busy.length === 0 && w.inbox.pendingTotal() > 0) {
      w.tick(w.params.inboxSlot * 1000);
    }
    await sleep(round < 2 ? 2 : 10);
  }
}

// ═════════════════════════ builders (plan §2.3; M6c) ═════════════════════════

/** A row as stored: era, label, class and body. */
export interface BuiltRow {
  E: number;
  label: Uint8Array;
  cls: number;
  body: Uint8Array;
}

/**
 * A signed lane row of `from` in epoch `ep` at `(E, n)` (plan §2.3 `buildMessage`): TEXT, IMAGE, WELCOME or LEAVE,
 * with optional header overrides (a forged `ck`, another `ts`). `prev` is the sender's previous row on the lane, if
 * any (its stored label and body, for prevh).
 */
export function buildMessage(
  from: TestUser,
  ep: Epoch,
  slot: { E: number; n: number; prev?: BuiltRow & { n: number } },
  partial: P.MBody & Partial<P.MHeader>,
): BuiltRow {
  const i = P.memberIndex(ep.D, from.uid);
  if (i < 0) throw new Error(`${from.handle} is not a member of this epoch`);
  const prev = slot.prev;
  const msg = {
    from: i,
    lane: i,
    n: slot.n,
    prev: prev ? { E: prev.E, n: prev.n } : P.NONE,
    prevh: prev ? P.prevh(prev.label, prev.body) : P.ZERO16,
    ts: Date.now(),
    ckq: 0,
    ck16: P.ZERO16,
    ...partial,
  } as P.Msg;
  const row = P.buildRow(
    { keys: ep.keys, conv: ep.D.conv, e: ep.e, sigSk: from.id.sigSk },
    slot.E,
    msg,
  );
  return { E: slot.E, label: row.label, cls: row.cls, body: row.body };
}

/** Stores a built row without validation, published on the epoch's topic (an attacker's or another client's put). */
export function postRow(ep: Epoch, row: BuiltRow): void {
  const r = current.shard.commit(row.E, row.label, row.cls, row.body, { topic: ep.topic });
  if (!r) throw new Error("slot taken");
}
