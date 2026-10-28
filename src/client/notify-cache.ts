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

/** Where the device key and the sealed cache live. */
export interface CacheStore {
  getKey(): Promise<CryptoKey | null>;
  putKey(k: CryptoKey): Promise<void>;
  getBox(): Promise<SealedBox | null>;
  putBox(b: SealedBox): Promise<void>;
  clear(): Promise<void>;
}

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

export async function readCache(store: CacheStore): Promise<NotifyCache | null> {
  const [key, box] = await Promise.all([store.getKey(), store.getBox()]);
  if (!key || !box) return null;
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: box.iv as BufferSource, additionalData: AAD },
      key,
      box.ct,
    );
    return parseCache(new TextDecoder().decode(pt));
  } catch {
    return null;
  }
}

async function seal(store: CacheStore, c: NotifyCache): Promise<void> {
  let key = await store.getKey();
  if (!key) {
    key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
      "encrypt",
      "decrypt",
    ]);
    await store.putKey(key);
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: AAD },
    key,
    new TextEncoder().encode(JSON.stringify(c)),
  );
  await store.putBox({ iv, ct });
}

/** Writes the app's cache, keeping each lane's stored next slot where it is later. */
export async function writeCache(store: CacheStore, c: NotifyCache): Promise<void> {
  await seal(store, mergeNext(c, await readCache(store)));
}

/** The Service Worker's write: moves lane positions forward in the stored cache, if there is one. */
export async function advanceCache(store: CacheStore, moves: readonly Move[]): Promise<void> {
  if (moves.length === 0) return;
  const stored = await readCache(store);
  if (stored) await seal(store, applyMoves(stored, moves));
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

async function tx<T>(
  mode: IDBTransactionMode,
  fn: (s: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const t = db.transaction(STORE, mode);
      const req = fn(t.objectStore(STORE));
      t.oncomplete = () => resolve(req.result);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  } finally {
    db.close();
  }
}

/** The cache in this origin's IndexedDB, or null where there is none (Node, blocked storage). */
export function idbCacheStore(): CacheStore | null {
  if (typeof indexedDB === "undefined") return null;
  const get = async <T>(k: string): Promise<T | null> =>
    ((await tx("readonly", (s) => s.get(k))) as T | undefined) ?? null;
  return {
    getKey: () => get<CryptoKey>("key"),
    putKey: async (k) => void (await tx("readwrite", (s) => s.put(k, "key"))),
    getBox: () => get<SealedBox>("box"),
    putBox: async (b) => void (await tx("readwrite", (s) => s.put(b, "box"))),
    clear: async () => void (await tx("readwrite", (s) => s.clear())),
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
