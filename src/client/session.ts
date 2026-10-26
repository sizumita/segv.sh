// "Remember this device": keeps the account key (AK) in IndexedDB, encrypted under a
// non-extractable WebCrypto AES-GCM key that is stored next to it. Script running on this origin
// can still use the key (as it could use an unlocked session anyway), but the raw AK never sits in
// storage in the clear and cannot be copied out of the browser profile as bytes.
const DB = "segv";
const STORE = "session";
const KEY = "current";

interface Stored {
  v: 1;
  uid: string;
  key: CryptoKey;
  iv: Uint8Array;
  ct: ArrayBuffer;
}

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

export async function saveSession(uid: string, AK: Uint8Array): Promise<void> {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(`segv.sh/v1/session/${uid}`) },
    key,
    AK as BufferSource,
  );
  const value: Stored = { v: 1, uid, key, iv, ct };
  await tx("readwrite", (s) => s.put(value, KEY));
}

export async function loadSession(): Promise<{ uid: string; AK: Uint8Array } | null> {
  try {
    const v = (await tx("readonly", (s) => s.get(KEY))) as Stored | undefined;
    if (!v || v.v !== 1) return null;
    const pt = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: v.iv as BufferSource,
        additionalData: new TextEncoder().encode(`segv.sh/v1/session/${v.uid}`),
      },
      v.key,
      v.ct,
    );
    return { uid: v.uid, AK: new Uint8Array(pt) };
  } catch {
    return null;
  }
}

export async function clearSession(): Promise<void> {
  try {
    await tx("readwrite", (s) => s.delete(KEY));
  } catch {
    /* nothing stored */
  }
}
