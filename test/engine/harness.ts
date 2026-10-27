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
import { FakeWebSocket } from "./fake/rt";
import { FakeWorld, type FakeWorldOptions } from "./fake/world";

export { P, W, FakeWorld, FakeWebSocket };
export * from "./fake/world";
export type { FakeParams, PublishRow } from "./fake/common";
export type { ShardRow, ShardBatch } from "./fake/shard";
export type { BlobRegEntry } from "./fake/blobs";
export type { InboxStoredRow, InboxRowResult } from "./fake/inbox";
export type { RtLimits } from "./fake/rt";
export type { DirUserRow, DirWrapRow, DirlogRow } from "./fake/dir";
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
 * The engine's conversation views. Uses the public `getState()`; M6 should switch this to the synchronous
 * `I(e).views()` if state emission is throttled.
 */
export const viewsOf = (e: Engine): ConversationView[] => e.getState().conversations;

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

// ═════════════════════════ M6: engine-dependent helpers (placeholders) ═════════════════════════
// These need SegvEngine (src/client/engine.ts, milestone M6), which does not exist yet. Signatures follow
// docs/STAGE1-PLAN.md §2.2–§2.3; M6 replaces the bodies (and fills in EngineI).

const needsM6 = (what: string): never => {
  throw new Error(`${what}: needs the v2 engine (milestone M6)`);
};

/** White-box view of an engine (plan §2.3). M6 types it against SegvEngine's internals. */
export interface EngineI {
  account: { uid: Uint8Array; uidB: string; AK: Uint8Array; id: P.Identity; handle: string } | null;
  convs: Map<string, unknown>;
  queue: Promise<unknown>;
  sendChains: Map<string, Promise<unknown>>;
  fatal: boolean;
  generation: number;
  /** bumped on every applied row or record (settle's stamp) */
  version: number;
  /** in-flight actions plus scheduled protocol timers (settle waits for 0) */
  busy: number;
  catchUp(): Promise<void>;
  unlock(AK: Uint8Array, uid: Uint8Array, handle: string): Promise<void>;
  views(): ConversationView[];
}

/** M6: `new SegvEngine({...server().transport(who), ...opts})`, signed out by onCleanup after the test. */
export function newEngine(_who?: string, _opts?: Record<string, unknown>): Engine {
  return needsM6("newEngine");
}

/** M6: unlock `u` on a new engine, wait for `!syncing`, then settle. */
export async function engineFor(_u: TestUser, _opts?: Record<string, unknown>): Promise<Engine> {
  return needsM6("engineFor");
}

/**
 * M6 (plan §2.2): rounds of {await queue + sendChains; server().ckpt.tick(); await I(e).catchUp()} until
 * `server().writeCount + Σ I(e).version` is unchanged for 2 rounds, every `I(e).busy === 0`, and
 * `server().inbox.pending(E) === 0`; advances the fake clock to a pending protocol timer instead of sleeping.
 *
 * Checkpoints: `ckpt.tick()` mints a new q only once CKPT_PERIOD_MS (60 s) of world clock have passed since the last
 * checkpoint, as the CheckpointDO's alarm does (q grows at most once per 60 s; the client's §12.3 step 4 check
 * relies on it). When a round needs a fresh checkpoint, settle must first advance the world clock by at least 60 s
 * with `server().advance(CKPT_PERIOD_MS, { keepSockets: true })` (keepSockets, so the engines' sockets stay open),
 * then tick. Never use `tick({ force: true })` here: it models a server minting faster than the spec allows.
 */
export async function settle(..._es: Engine[]): Promise<void> {
  return needsM6("settle");
}

/** M6: white-box access to an engine's private state. */
export const I = (_e: Engine): EngineI => needsM6("I");
