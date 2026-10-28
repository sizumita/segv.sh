// The notification cache (docs/PROTOCOL.md §11.13): sealed under a key that cannot be exported, merged so that lane
// positions only move forward, and never brought back by stale work once deleted or superseded, by the Service Worker
// or by another tab of the app.
import { describe, expect, it } from "vite-plus/test";
import {
  advanceCache,
  applyMoves,
  bumpCache,
  cacheGen,
  deleteCache,
  isBox,
  mergeNext,
  parseCache,
  readCache,
  writeCache,
  type CacheStore,
  type NotifyCache,
  type SealedBox,
  type Stored,
} from "./notify-cache";

/**
 * One origin's store, shared by every tab and the worker, as IndexedDB is. Its next `read` or `writeIf` can be held
 * until a test lets it go on; `writeIf` compares and stores with no await in between, as one transaction does.
 */
function memoryStore() {
  const m = {
    key: null as CryptoKey | null,
    box: null as SealedBox | null,
    gen: 0,
    holdRead: null as Promise<void> | null,
    holdWrite: null as Promise<void> | null,
    /** called when a held writeIf starts waiting */
    onHeld: null as (() => void) | null,
    async read(): Promise<Stored> {
      const h = m.holdRead;
      m.holdRead = null;
      if (h) await h;
      return { key: m.key, box: m.box, gen: m.gen };
    },
    async writeIf(gen: number, iv: Uint8Array | null, w: { box: SealedBox; key?: CryptoKey }) {
      const h = m.holdWrite;
      m.holdWrite = null;
      if (h) {
        m.onHeld?.();
        await h;
      }
      if (m.gen !== gen || !isBox(m.box, iv)) return false;
      if (w.key) m.key = w.key;
      m.box = w.box;
      return true;
    },
    bump: async () => void m.gen++,
    clear: async () => {
      m.key = null;
      m.box = null;
      m.gen++;
    },
  };
  return m satisfies CacheStore;
}

function gate(): { wait: Promise<void>; open: () => void } {
  let open = () => {};
  const wait = new Promise<void>((r) => (open = r));
  return { wait, open };
}

/** Holds the store's next writeIf (after its caller has read and sealed); resolves once that write is waiting. */
function holdNextWrite(s: ReturnType<typeof memoryStore>): {
  reached: Promise<void>;
  open: () => void;
} {
  const g = gate();
  const reached = new Promise<void>((r) => (s.onHeld = r));
  s.holdWrite = g.wait;
  return { reached, open: g.open };
}

const cache = (next: { E: number; n: number }[], e = 2, bell = "bell-1"): NotifyCache => ({
  v: 1,
  preview: "message",
  deltaS: 10,
  copies: [
    {
      bell,
      ref: "AAAAAAAAAAAA",
      name: "bob",
      epoch: {
        e,
        conv: "Y29udg",
        mk: "bWs",
        rk: "cms",
        self: 0,
        members: next.map((_, j) => ({ sigPk: `pk${j}`, handle: `u${j}` })),
        next,
      },
    },
  ],
});

const named: NotifyCache = {
  v: 1,
  preview: "name",
  deltaS: 10,
  copies: [{ bell: "bell-1", ref: "AAAAAAAAAAAA", name: "bob" }],
};

/** The app's write, deciding now. */
const write = async (s: CacheStore, c: NotifyCache): Promise<boolean> =>
  writeCache(s, c, await cacheGen(s));

const moveTo9 = [{ bell: "bell-1", e: 2, next: [{ E: 50, n: 9 }] }];

describe("notification cache", () => {
  it("round-trips sealed under a key that cannot be exported", async () => {
    const s = memoryStore();
    expect(await readCache(s)).toBeNull();
    const c = cache([{ E: 50, n: 3 }]);
    expect(await write(s, c)).toBe(true);
    expect(s.key?.extractable).toBe(false);
    expect(new TextDecoder().decode(new Uint8Array(s.box!.ct))).not.toContain("bob");
    expect(await readCache(s)).toEqual(c);
  });

  it("reads a tampered or foreign box as no cache; deleting moves the generation on", async () => {
    const s = memoryStore();
    await write(s, cache([{ E: 50, n: 3 }]));
    const ct = new Uint8Array(s.box!.ct.slice(0));
    ct[0] ^= 1;
    s.box = { iv: s.box!.iv, ct: ct.buffer };
    expect(await readCache(s)).toBeNull();
    const before = await cacheGen(s);
    await deleteCache(s);
    expect([s.key, s.box]).toEqual([null, null]);
    expect(await cacheGen(s)).toBe(before + 1);
  });

  it("parses only what this version writes", () => {
    const ok = cache([{ E: 1, n: 0 }]);
    expect(parseCache(JSON.stringify(ok))).toEqual(ok);
    for (const bad of [
      "x",
      "null",
      JSON.stringify({ ...ok, v: 2 }),
      JSON.stringify({ ...ok, preview: "none" }),
      JSON.stringify({ ...ok, copies: [{ ...ok.copies[0], ref: 1 }] }),
      JSON.stringify({
        ...ok,
        copies: [{ ...ok.copies[0], epoch: { ...ok.copies[0].epoch, next: [] } }],
      }),
    ])
      expect(parseCache(bad)).toBeNull();
  });

  it("keeps each lane's later next slot: the app's write keeps the worker's moves, and moves never go back", async () => {
    const s = memoryStore();
    const lanes = (a: number, b: { E: number; n: number }) => [{ E: 50, n: a }, b];
    await write(s, cache(lanes(3, { E: 50, n: 0 })));
    await advanceCache(s, [{ bell: "bell-1", e: 2, next: lanes(5, { E: 49, n: 9 }) }]);
    expect((await readCache(s))!.copies[0].epoch!.next).toEqual(lanes(5, { E: 50, n: 0 }));
    // The app knew less than the worker moved: the stored slot stays.
    await write(s, cache(lanes(4, { E: 51, n: 0 })));
    expect((await readCache(s))!.copies[0].epoch!.next).toEqual(lanes(5, { E: 51, n: 0 }));
    // Another epoch starts from the app's slots.
    await write(
      s,
      cache(
        [
          { E: 51, n: 1 },
          { E: 51, n: 0 },
        ],
        3,
      ),
    );
    expect((await readCache(s))!.copies[0].epoch!.next).toEqual([
      { E: 51, n: 1 },
      { E: 51, n: 0 },
    ]);
  });

  it("applies moves only to the same bell and epoch, and writes nothing without a stored cache", async () => {
    const c = cache([{ E: 50, n: 3 }]);
    expect(applyMoves(c, [{ bell: "other", e: 2, next: [{ E: 60, n: 0 }] }])).toEqual(c);
    expect(applyMoves(c, [{ bell: "bell-1", e: 1, next: [{ E: 60, n: 0 }] }])).toEqual(c);
    expect(mergeNext(c, null)).toBe(c);
    const s = memoryStore();
    await advanceCache(s, moveTo9);
    expect([s.key, s.box]).toEqual([null, null]);
  });

  // ───────────── the Service Worker against the app ─────────────

  it("a worker's move in flight never brings back a cache deleted meanwhile, nor creates a key", async () => {
    // Paused while reading, as the review first reproduced it…
    const early = memoryStore();
    await write(early, cache([{ E: 50, n: 3 }]));
    const k = gate();
    early.holdRead = k.wait;
    const m1 = advanceCache(early, moveTo9);
    await deleteCache(early);
    k.open();
    await m1;
    expect([early.key, early.box]).toEqual([null, null]);
    // …and just before storing, after it read and sealed.
    const s = memoryStore();
    await write(s, cache([{ E: 50, n: 3 }]));
    const g = holdNextWrite(s);
    const moving = advanceCache(s, moveTo9);
    await g.reached;
    await deleteCache(s); // the preview set to "new messages", notifications off, or sign-out
    g.open();
    await moving;
    expect([s.key, s.box]).toEqual([null, null]);
  });

  it("nor overwrites the app's newer cache (a downgrade from `message` to `name`)", async () => {
    const s = memoryStore();
    await write(s, cache([{ E: 50, n: 3 }]));
    const g = holdNextWrite(s);
    const moving = advanceCache(s, moveTo9);
    await g.reached;
    await bumpCache(s);
    await write(s, named);
    g.open();
    await moving;
    expect(await readCache(s)).toEqual(named);
  });

  it("the app's write reads again when the worker moved a lane meanwhile, and keeps the move", async () => {
    const s = memoryStore();
    await write(s, cache([{ E: 50, n: 3 }]));
    const g = holdNextWrite(s);
    const writing = write(s, cache([{ E: 50, n: 4 }]));
    await g.reached;
    await advanceCache(s, moveTo9);
    g.open();
    expect(await writing).toBe(true);
    expect((await readCache(s))!.copies[0].epoch!.next).toEqual([{ E: 50, n: 9 }]);
  });

  // ───────────── two tabs of the app ─────────────

  it("a write in flight in one tab never brings back what another tab deleted", async () => {
    const s = memoryStore();
    await write(s, cache([{ E: 50, n: 3 }]));
    const g = holdNextWrite(s);
    const tabA = write(s, cache([{ E: 50, n: 4 }]));
    await g.reached; // read, sealed, about to store
    await deleteCache(s); // tab B: "new messages", notifications off, or sign-out
    g.open();
    expect(await tabA).toBe(false);
    expect([s.key, s.box]).toEqual([null, null]);
    expect(await readCache(s)).toBeNull();
  });

  it("nor a write decided before the deletion that reads the store only after it", async () => {
    const s = memoryStore();
    await write(s, cache([{ E: 50, n: 3 }]));
    const gen = await cacheGen(s); // tab A decides to write
    await deleteCache(s); // tab B deletes
    expect(await writeCache(s, cache([{ E: 50, n: 4 }]), gen)).toBe(false);
    expect([s.key, s.box]).toEqual([null, null]);
  });

  it("nor undoes another tab's downgrade, in either order", async () => {
    // tab A's stale `message` write lands after tab B's change of preview and its `name` cache
    const s = memoryStore();
    await write(s, cache([{ E: 50, n: 3 }]));
    const g = holdNextWrite(s);
    const tabA = write(s, cache([{ E: 50, n: 4 }]));
    await g.reached;
    await bumpCache(s);
    await write(s, named);
    g.open();
    expect(await tabA).toBe(false);
    expect(await readCache(s)).toEqual(named);
    // tab A's stale write would land first: the change of preview came before it, so it is refused
    const t = memoryStore();
    await write(t, cache([{ E: 50, n: 3 }]));
    const gen = await cacheGen(t);
    await bumpCache(t);
    expect(await writeCache(t, cache([{ E: 50, n: 4 }]), gen)).toBe(false);
    await write(t, named);
    expect(await readCache(t)).toEqual(named);
  });
});
