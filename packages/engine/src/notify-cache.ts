// The notification cache (docs/PROTOCOL.md §11.13): what the push Service Worker needs to name a conversation and,
// with the `message` preview, to read and verify its newest rows. It is sealed with AES-GCM under a device key that the
// browser cannot export, kept beside it in IndexedDB. The app writes it; the Service Worker reads it and moves its lane
// positions forward. Shared by both, so it uses no DOM API beyond IndexedDB and WebCrypto.

/** What a notification shows on this device (§11.13). */
export type Preview = "none" | "name" | "message";

export interface CacheSlot {
  E: number;
  n: number;
}

export interface CacheMember {
  /** b64u */
  sigPk: string;
  /** the handle the client shows for the member */
  handle: string;
}

/** The current epoch of a copy, for the `message` preview. Byte strings are b64u. */
export interface CacheEpoch {
  e: number;
  conv: string;
  mk: string;
  rk: string;
  /** self's lane index */
  self: number;
  members: CacheMember[];
  /** per lane: the slot after its head as the client last knew it */
  next: CacheSlot[];
}

export interface CacheCopy {
  /** b64u of the bell registered for the copy */
  bell: string;
  ref: string;
  name: string;
  epoch?: CacheEpoch;
}

export interface NotifyCache {
  v: 1;
  preview: "name" | "message";
  /** Δ in seconds (params), for the clamped `ts` of §11.8 */
  deltaS: number;
  copies: CacheCopy[];
}

export interface SealedBox {
  iv: Uint8Array;
  ct: ArrayBuffer;
}

/** What the store holds: the device key, the sealed cache, and the generation. */
export interface Stored {
  key: CryptoKey | null;
  box: SealedBox | null;
  /**
   * Moves on at every deletion, in any tab (a change of the preview deletes the cache too), and survives it: a write
   * decided under an earlier generation is stale, and is never stored.
   */
  gen: number;
}

/**
 * Where the device key, the sealed cache and its generation live, shared by every tab of the app and by the Service
 * Worker. Writes compare and store in one transaction, so stale work never undoes a deletion, a change of the preview
 * or a newer cache.
 */
export interface CacheStore {
  read(): Promise<Stored>;
  /**
   * Stores `box` (and `key`, when given) only if the generation is still `gen` and the stored box is still the one with
   * IV `iv` (null: no box), in one transaction; true if stored.
   */
  writeIf(
    gen: number,
    iv: Uint8Array | null,
    w: { box: SealedBox; key?: CryptoKey },
  ): Promise<boolean>;
  /** Deletes the key and the box and moves the generation on, in one transaction. */
  clear(): Promise<void>;
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);

/** Whether `stored` is the box with IV `expect` (null: no box). */
export const isBox = (stored: SealedBox | null | undefined, expect: Uint8Array | null): boolean =>
  expect === null ? !stored : !!stored && sameBytes(new Uint8Array(stored.iv), expect);

const AAD = new TextEncoder().encode("segv.sh/notify-cache/v1");

/** The later of two slots. */
export const later = (a: CacheSlot, b: CacheSlot): CacheSlot =>
  a.E > b.E || (a.E === b.E && a.n >= b.n) ? a : b;

const isSlot = (x: unknown): x is CacheSlot =>
  !!x &&
  typeof x === "object" &&
  Number.isSafeInteger((x as CacheSlot).E) &&
  Number.isSafeInteger((x as CacheSlot).n);

function validEpoch(x: unknown): x is CacheEpoch {
  const e = x as CacheEpoch;
  return (
    !!e &&
    Number.isSafeInteger(e.e) &&
    typeof e.conv === "string" &&
    typeof e.mk === "string" &&
    typeof e.rk === "string" &&
    Number.isSafeInteger(e.self) &&
    Array.isArray(e.members) &&
    e.members.every((m) => m && typeof m.sigPk === "string" && typeof m.handle === "string") &&
    Array.isArray(e.next) &&
    e.next.every(isSlot) &&
    e.next.length === e.members.length
  );
}

/** The cache, or null when the text is not one this version wrote. */
export function parseCache(text: string): NotifyCache | null {
  let c: NotifyCache;
  try {
    c = JSON.parse(text) as NotifyCache;
  } catch {
    return null;
  }
  if (!c || c.v !== 1 || (c.preview !== "name" && c.preview !== "message")) return null;
  if (typeof c.deltaS !== "number" || !Array.isArray(c.copies)) return null;
  for (const x of c.copies) {
    if (!x || typeof x.bell !== "string" || typeof x.ref !== "string" || typeof x.name !== "string")
      return null;
    if (x.epoch !== undefined && !validEpoch(x.epoch)) return null;
  }
  return c;
}

/** `fresh`, with each lane's next slot moved to the stored one where that is later (same bell, same epoch). */
export function mergeNext(fresh: NotifyCache, stored: NotifyCache | null): NotifyCache {
  if (!stored) return fresh;
  const old = new Map(stored.copies.map((c) => [c.bell, c]));
  return {
    ...fresh,
    copies: fresh.copies.map((c) => {
      const o = old.get(c.bell);
      if (!c.epoch || !o?.epoch || o.epoch.e !== c.epoch.e) return c;
      const prev = o.epoch.next;
      return {
        ...c,
        epoch: { ...c.epoch, next: c.epoch.next.map((s, j) => (prev[j] ? later(s, prev[j]) : s)) },
      };
    }),
  };
}

/** Lane positions found by the Service Worker for one copy's epoch. */
export interface Move {
  bell: string;
  e: number;
  next: CacheSlot[];
}

/** `stored` with the moves applied (each lane keeps the later slot). */
export function applyMoves(stored: NotifyCache, moves: readonly Move[]): NotifyCache {
  const by = new Map(moves.map((m) => [m.bell, m]));
  return {
    ...stored,
    copies: stored.copies.map((c) => {
      const m = by.get(c.bell);
      if (!m || !c.epoch || c.epoch.e !== m.e) return c;
      const ep = c.epoch;
      return {
        ...c,
        epoch: { ...ep, next: ep.next.map((s, j) => (m.next[j] ? later(s, m.next[j]) : s)) },
      };
    }),
  };
}

/** What is stored, with the cache it opens to (null where missing or unreadable). */
async function load(store: CacheStore): Promise<Stored & { cache: NotifyCache | null }> {
  const cur = await store.read();
  if (!cur.key || !cur.box) return { ...cur, cache: null };
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: cur.box.iv as BufferSource, additionalData: AAD },
      cur.key,
      cur.box.ct,
    );
    return { ...cur, cache: parseCache(new TextDecoder().decode(pt)) };
  } catch {
    return { ...cur, cache: null };
  }
}

export async function readCache(store: CacheStore): Promise<NotifyCache | null> {
  return (await load(store)).cache;
}

/** The generation now: read it before deciding to write, and pass it to `writeCache`. */
export async function cacheGen(store: CacheStore): Promise<number> {
  return (await store.read()).gen;
}

async function sealWith(key: CryptoKey, c: NotifyCache): Promise<SealedBox> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: AAD },
    key,
    new TextEncoder().encode(JSON.stringify(c)),
  );
  return { iv, ct };
}

/**
 * Writes the app's cache, decided under generation `gen` (read before the decision), keeping each lane's stored next
 * slot where it is later. Only the app creates the device key, and only together with the box. When the Service Worker
 * wrote in between, it reads and merges again (at most 3 times; a lost move only repeats a preview); once the
 * generation has moved on (a deletion, in any tab: a change of the preview deletes the cache) it stops. True if
 * stored.
 */
export async function writeCache(store: CacheStore, c: NotifyCache, gen: number): Promise<boolean> {
  for (let i = 0; i < 3; i++) {
    const cur = await load(store);
    if (cur.gen !== gen) return false;
    const key =
      cur.key ??
      (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
        "encrypt",
        "decrypt",
      ]));
    const box = await sealWith(key, mergeNext(c, cur.cache));
    const iv = cur.box ? new Uint8Array(cur.box.iv) : null;
    if (await store.writeIf(gen, iv, cur.key ? { box } : { box, key })) return true;
  }
  return false;
}

/**
 * The Service Worker's write: moves lane positions forward in the stored cache. It never creates a key, and stores
 * only over the box it read under the same generation, so stale work never brings back a cache that was deleted or
 * replaced meanwhile.
 */
export async function advanceCache(store: CacheStore, moves: readonly Move[]): Promise<void> {
  if (moves.length === 0) return;
  const cur = await load(store);
  if (!cur.key || !cur.box || !cur.cache) return;
  const box = await sealWith(cur.key, applyMoves(cur.cache, moves));
  await store.writeIf(cur.gen, new Uint8Array(cur.box.iv), { box });
}

export const deleteCache = (store: CacheStore): Promise<void> => store.clear();

const DB = "segv-notify";
const STORE = "kv";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** One transaction over the store; `fn` queues its requests and returns the result to resolve with. */
async function txn<T>(
  mode: IDBTransactionMode,
  fn: (s: IDBObjectStore, done: (v: T) => void) => void,
): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const t = db.transaction(STORE, mode);
      let out: T;
      fn(t.objectStore(STORE), (v) => (out = v));
      t.oncomplete = () => resolve(out);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  } finally {
    db.close();
  }
}

/** Reads key, box and generation in one transaction, then calls `then` (still inside it). */
function readIn(s: IDBObjectStore, then: (cur: Stored) => void): void {
  const k = s.get("key");
  const b = s.get("box");
  const g = s.get("gen");
  g.onsuccess = () =>
    then({
      key: (k.result as CryptoKey | undefined) ?? null,
      box: (b.result as SealedBox | undefined) ?? null,
      gen: typeof g.result === "number" ? g.result : 0,
    });
}

/** The cache in this origin's IndexedDB, or null where there is none (Node, blocked storage). */
export function idbCacheStore(): CacheStore | null {
  if (typeof indexedDB === "undefined") return null;
  return {
    read: () => txn<Stored>("readonly", (s, done) => readIn(s, done)),
    writeIf: (gen, iv, w) =>
      txn<boolean>("readwrite", (s, done) => {
        done(false);
        readIn(s, (cur) => {
          if (cur.gen !== gen || !isBox(cur.box, iv)) return;
          if (w.key) s.put(w.key, "key");
          s.put(w.box, "box");
          done(true);
        });
      }),
    clear: () =>
      txn<void>("readwrite", (s, done) => {
        done(undefined);
        readIn(s, (cur) => {
          s.delete("key");
          s.delete("box");
          s.put(cur.gen + 1, "gen");
        });
      }),
  };
}

/** The preview of this device (§11.13), in localStorage; anything unreadable is `none`. */
export interface PreviewStore {
  load(): Preview;
  save(p: Preview): void;
}

export function localPreviewStore(key = "segv.preview"): PreviewStore {
  return {
    load() {
      try {
        const v = globalThis.localStorage?.getItem(key);
        return v === "name" || v === "message" ? v : "none";
      } catch {
        return "none";
      }
    },
    save(p) {
      try {
        globalThis.localStorage?.setItem(key, p);
      } catch {
        // blocked storage: the choice lasts for this page only
      }
    },
  };
}
