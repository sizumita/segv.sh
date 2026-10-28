// The push Service Worker (docs/PROTOCOL.md §11.13), built to /sw.js from src/client/sw-main.ts. For every push it
// shows at least one notification within 8 s: the payload's fixed text, or, with the device's preview, the name of each
// conversation whose bell rang (from the notification cache), and with `message` its newest message, read with one
// `get` and decrypted and verified here. The text never comes from the payload, which the operator composes. It has no
// fetch handler and caches nothing, so it never serves the app's pages or scripts.
import * as P from "~/lib/proto";
import * as W from "~/lib/wire";
import {
  advanceCache,
  idbCacheStore,
  readCache,
  type CacheCopy,
  type CacheEpoch,
  type CacheStore,
  type Move,
  type NotifyCache,
} from "./notify-cache";

/** What a push asks to show: the payload's notification (§9.8) and the bells it names. */
export interface Proposed {
  title: string;
  body: string;
  tag: string;
  navigate: string;
  bells: string[];
}

/** A notification to show. */
export interface Note {
  title: string;
  body: string;
  tag: string;
  navigate: string;
}

export const FIXED = { title: "segv.sh", body: "new messages", tag: "segv" } as const;
/** Every push shows its notifications within this time (§11.13). */
export const DEADLINE_MS = 8_000;
/** Lane lookahead (§11 constants `W`) and the most keys of one `get` (§10.4). */
const W_SLOTS = 8;
const MAX_KEYS = 256;
/** §11.8: shown times stay within 5 minutes of the stored time. */
const TS_SLACK_MS = 300_000;
const MAX_BODY = 200;

const str = (v: unknown, d: string): string =>
  typeof v === "string" && v.length > 0 && v.length <= 256 ? v : d;

/**
 * Reads a push: the proposed notification of a declarative push message (a browser that supports those hands it to the
 * Service Worker since the payload is `mutable`), or the payload's JSON (any other browser). Anything else gives the
 * fixed notification.
 */
export function proposedOf(proposed: unknown, json: unknown, origin: string): Proposed {
  let n: Record<string, unknown> | null = null;
  if (proposed && typeof proposed === "object") n = proposed as Record<string, unknown>;
  else if (json && typeof json === "object") {
    const m = json as Record<string, unknown>;
    if (m.web_push === 8030 && m.notification && typeof m.notification === "object")
      n = m.notification as Record<string, unknown>;
  }
  let navigate = `${origin}/`;
  if (n && typeof n.navigate === "string") {
    try {
      const u = new URL(n.navigate, origin);
      if (u.origin === origin) navigate = u.href;
    } catch {
      // keep the app's root
    }
  }
  const data = n?.data as { bells?: unknown } | undefined;
  return {
    title: str(n?.title, FIXED.title),
    body: str(n?.body, FIXED.body),
    tag: str(n?.tag, FIXED.tag),
    navigate,
    bells: bellsOf(data?.bells),
  };
}

/** The bells of a payload's `bells` field: 16-byte groups other than the zero padding, in order. */
export function bellsOf(v: unknown): string[] {
  if (typeof v !== "string" || v.length > 200) return [];
  let raw: Uint8Array;
  try {
    raw = P.fromB64u(v);
  } catch {
    return [];
  }
  const out: string[] = [];
  for (let i = 0; i + 16 <= raw.length; i += 16) {
    const b = raw.subarray(i, i + 16);
    if (b.some((x) => x !== 0)) out.push(P.b64u(b));
  }
  return out;
}

export const fixedNote = (p: Proposed): Note => ({
  title: p.title,
  body: p.body,
  tag: p.tag,
  navigate: p.navigate,
});

export interface SwDeps {
  origin: string;
  readCache(): Promise<NotifyCache | null>;
  advance(moves: Move[]): Promise<void>;
  get(keys: W.GetKey[]): Promise<W.GetStatus[]>;
  /** wall clock, ms */
  now(): number;
  /** resolves after `ms` */
  sleep(ms: number): Promise<void>;
}

const urlOf = (origin: string, ref: string): string => `${origin}/#c/${ref}`;

/** The slots read for one lane (§11.13 step 3): from its next slot, `k` in all, the last one slot 0 of E_now when the next slot's era is below. */
function slotsOf(next: P.Pos, k: number, Enow: number): { E: number; n: number }[] {
  const out: { E: number; n: number }[] = [];
  const room = next.E < Enow ? k - 1 : k;
  for (let i = 0; i < room; i++) out.push({ E: next.E, n: next.n + i });
  if (next.E < Enow) out.push({ E: Enow, n: 0 });
  return out;
}

interface Found {
  ts: number;
  text: string;
}

/** The newest verified TEXT or IMAGE of each copy, and how far each lane's dense prefix reaches. */
async function readNewest(
  copies: { copy: CacheCopy; ep: CacheEpoch }[],
  d: SwDeps,
  deltaS: number,
): Promise<{ found: Map<string, Found[]>; moves: Move[] }> {
  const Enow = P.era(d.now());
  const lanes: { copy: CacheCopy; ep: CacheEpoch; j: number }[] = [];
  for (const x of copies)
    x.ep.next.forEach((_, j) => {
      if (j !== x.ep.self) lanes.push({ ...x, j });
    });
  const found = new Map<string, Found[]>();
  if (lanes.length === 0) return { found, moves: [] };
  const per = Math.max(1, Math.min(W_SLOTS, Math.floor(MAX_KEYS / lanes.length)));
  const keys: W.GetKey[] = [];
  const at: { lane: number; E: number; n: number }[] = [];
  const keysOf = new Map<
    CacheCopy,
    { rk: Uint8Array; mk: Uint8Array; conv: Uint8Array; members: { sigPk: Uint8Array }[] }
  >();
  lanes.forEach((l, li) => {
    if (keys.length >= MAX_KEYS) return;
    let k = keysOf.get(l.copy);
    if (!k) {
      k = {
        rk: P.fromB64u(l.ep.rk),
        mk: P.fromB64u(l.ep.mk),
        conv: P.fromB64u(l.ep.conv),
        members: l.ep.members.map((m) => ({ sigPk: P.fromB64u(m.sigPk) })),
      };
      keysOf.set(l.copy, k);
    }
    for (const s of slotsOf(l.ep.next[l.j], per, Enow)) {
      if (keys.length >= MAX_KEYS) break;
      keys.push({ E: s.E, label: P.Lmsg(k.rk, l.j, s.E, s.n), mode: 0 });
      at.push({ lane: li, ...s });
    }
  });
  const st = await d.get(keys);
  const reach = lanes.map((l) => ({ ...l.ep.next[l.j] }));
  const walking = lanes.map(() => true);
  st.forEach((r, i) => {
    const a = at[i];
    const l = lanes[a.lane];
    const k = keysOf.get(l.copy)!;
    const next = reach[a.lane];
    if (r.s === "hit") {
      // Any row occupies its slot: the dense prefix reaches past it (§4.2).
      if (a.E === next.E && a.n === next.n && walking[a.lane])
        reach[a.lane] = { E: a.E, n: a.n + 1 };
      else if (a.E > l.ep.next[l.j].E && a.n === 0) reach[a.lane] = { E: a.E, n: 1 };
      if (!r.body) return;
      const v = P.acceptRow(
        { keys: { rk: k.rk, mk: k.mk }, conv: k.conv, e: l.ep.e, members: k.members },
        a.E,
        keys[i].label,
        r.body,
      );
      if (!v.ok || v.msg.from !== l.j) return;
      const who = `@${l.ep.members[l.j]?.handle ?? "?"}`;
      let text: string;
      if (v.msg.type === P.MT.TEXT) text = `${who}: ${v.msg.text}`;
      else if (v.msg.type === P.MT.IMAGE) text = `${who} sent an image`;
      else return;
      const lo = P.T0_MS + r.t * 1000 - TS_SLACK_MS;
      const hi = P.T0_MS + (r.t + deltaS) * 1000 + TS_SLACK_MS;
      const ts = Math.min(Math.max(v.msg.ts, lo), hi);
      const list = found.get(l.copy.bell) ?? [];
      list.push({ ts, text });
      found.set(l.copy.bell, list);
    } else if (a.E === next.E) walking[a.lane] = false;
  });
  const moves = new Map<string, Move>();
  lanes.forEach((l, li) => {
    const m = moves.get(l.copy.bell) ?? {
      bell: l.copy.bell,
      e: l.ep.e,
      next: l.ep.next.map((s) => ({ ...s })),
    };
    m.next[l.j] = reach[li];
    moves.set(l.copy.bell, m);
  });
  return { found, moves: [...moves.values()] };
}

/** A message body: the newest row, cut to 200 characters, and how many more were found. */
export function bodyOf(found: readonly Found[]): string {
  const newest = found.reduce((a, b) => (b.ts > a.ts ? b : a));
  const chars = Array.from(newest.text);
  const text = chars.length > MAX_BODY ? `${chars.slice(0, MAX_BODY - 1).join("")}…` : newest.text;
  return found.length > 1 ? `${text} (+${found.length - 1})` : text;
}

/** The notifications of one push (§11.13 steps 1–3). Never throws; the caller falls back to the fixed one anyway. */
export async function notesFor(p: Proposed, d: SwDeps, deadline: number): Promise<Note[]> {
  const fixed = [fixedNote(p)];
  let cache: NotifyCache | null = null;
  try {
    cache = await d.readCache();
  } catch {
    cache = null;
  }
  if (!cache || p.bells.length === 0) return fixed;
  const byBell = new Map(cache.copies.map((c) => [c.bell, c]));
  const picked: CacheCopy[] = [];
  for (const b of p.bells) {
    const c = byBell.get(b);
    if (c && !picked.includes(c)) picked.push(c);
  }
  if (picked.length === 0) return fixed;
  const named = picked.map((c): Note => ({
    title: c.name,
    body: p.body,
    tag: c.ref,
    navigate: urlOf(d.origin, c.ref),
  }));
  if (cache.preview !== "message") return named;
  const withEpoch = picked.flatMap((c) => (c.epoch ? [{ copy: c, ep: c.epoch }] : []));
  if (withEpoch.length === 0) return named;
  const left = deadline - d.now();
  const timeout = d.sleep(Math.max(0, left)).then(() => null);
  let read: Awaited<ReturnType<typeof readNewest>> | null;
  try {
    read = await Promise.race([readNewest(withEpoch, d, cache.deltaS), timeout]);
  } catch {
    read = null;
  }
  if (!read) return named;
  try {
    await Promise.race([d.advance(read.moves), timeout]);
  } catch {
    // a lost move only repeats a preview
  }
  return picked.map((c, i) => {
    const f = read!.found.get(c.bell);
    return f && f.length > 0 ? { ...named[i], body: bodyOf(f) } : named[i];
  });
}

// ───────────────────────── the worker ─────────────────────────

interface NotificationLike {
  readonly data: unknown;
  close(): void;
}

interface WindowClientLike {
  readonly url: string;
  focus?(): Promise<unknown>;
  postMessage(m: unknown): void;
}

/** The parts of ServiceWorkerGlobalScope this worker uses. */
export interface SwScope {
  location: { origin: string };
  addEventListener(type: string, f: (ev: never) => void): void;
  skipWaiting(): Promise<void>;
  registration: {
    showNotification(
      title: string,
      opts: { body: string; tag: string; data: { navigate: string } },
    ): Promise<void>;
  };
  clients: {
    claim(): Promise<void>;
    matchAll(o: {
      type: "window";
      includeUncontrolled: boolean;
    }): Promise<readonly WindowClientLike[]>;
    openWindow(url: string): Promise<unknown>;
  };
}

interface ExtendableEventLike {
  waitUntil(p: Promise<unknown>): void;
}

interface PushEventLike extends ExtendableEventLike {
  readonly data: { json(): unknown } | null;
  /** the proposed notification of a declarative push message */
  readonly notification?: unknown;
}

interface NotificationEventLike extends ExtendableEventLike {
  readonly notification: NotificationLike;
}

/** The browser's dependencies of `notesFor` (the engine's tests pass their own fetch and cache store). */
export function browserDeps(
  origin: string,
  o: { fetch?: typeof fetch; store?: CacheStore | null } = {},
): SwDeps {
  const store = o.store === undefined ? idbCacheStore() : o.store;
  const fetchFn = o.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));
  return {
    origin,
    readCache: () => (store ? readCache(store) : Promise.resolve(null)),
    advance: (moves) => (store ? advanceCache(store, moves) : Promise.resolve()),
    async get(keys) {
      const res = await fetchFn(`${origin}/api/v2/get`, {
        method: "POST",
        headers: { "content-type": "application/octet-stream" },
        body: W.encodeGetRequest(keys) as BodyInit,
      });
      if (!res.ok) throw new Error(`get: ${res.status}`);
      return W.decodeGetResponse(
        new Uint8Array(await res.arrayBuffer()),
        keys.map((k) => k.mode),
      );
    },
    now: () => Date.now(),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  };
}

/** Message the worker posts to a window of the app to show a conversation. */
export interface OpenMessage {
  type: "segv.open";
  url: string;
}

export function install(self: SwScope, deps: SwDeps = browserDeps(self.location.origin)): void {
  const origin = self.location.origin;

  self.addEventListener("install", () => {
    void self.skipWaiting();
  });
  self.addEventListener("activate", (event: ExtendableEventLike) => {
    event.waitUntil(self.clients.claim());
  });

  // Every push shows a notification (userVisibleOnly: a browser may revoke a subscription whose pushes show none).
  self.addEventListener("push", (event: PushEventLike) => {
    const started = deps.now();
    let json: unknown = null;
    try {
      json = event.data ? event.data.json() : null;
    } catch {
      json = null;
    }
    const p = proposedOf(event.notification ?? null, json, origin);
    event.waitUntil(
      (async () => {
        let notes: Note[];
        try {
          notes = await notesFor(p, deps, started + DEADLINE_MS - 500);
        } catch {
          notes = [];
        }
        if (notes.length === 0) notes = [fixedNote(p)];
        await Promise.all(
          notes.map((n) =>
            self.registration.showNotification(n.title, {
              body: n.body,
              tag: n.tag,
              data: { navigate: n.navigate },
            }),
          ),
        );
      })(),
    );
  });

  self.addEventListener("notificationclick", (event: NotificationEventLike) => {
    event.notification.close();
    const data = event.notification.data as { navigate?: unknown } | null;
    let target = `${origin}/`;
    if (data && typeof data.navigate === "string") {
      try {
        const u = new URL(data.navigate, origin);
        if (u.origin === origin) target = u.href;
      } catch {
        // keep the app's root
      }
    }
    event.waitUntil(
      (async () => {
        const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
        for (const w of windows) {
          if (new URL(w.url).origin !== origin) continue;
          await w.focus?.();
          const m: OpenMessage = { type: "segv.open", url: target };
          w.postMessage(m);
          return;
        }
        await self.clients.openWindow(target);
      })(),
    );
  });
}
