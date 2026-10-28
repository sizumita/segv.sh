// The notification cache (docs/PROTOCOL.md §11.13): sealed under a key that cannot be exported, merged so that lane
// positions only move forward.
import { describe, expect, it } from "vite-plus/test";
import {
  advanceCache,
  applyMoves,
  deleteCache,
  isBox,
  mergeNext,
  parseCache,
  readCache,
  writeCache,
  type CacheStore,
  type NotifyCache,
  type SealedBox,
} from "./notify-cache";

/** A store whose next `getKey` or `putBoxIf` can be held until a test lets it go on. */
function memoryStore() {
  const m = {
    key: null as CryptoKey | null,
    box: null as SealedBox | null,
    /** awaited once by the next getKey / putBoxIf, then cleared */
    holdGet: null as Promise<void> | null,
    holdPut: null as Promise<void> | null,
    /** called when a held putBoxIf starts waiting */
    onHeld: null as (() => void) | null,
    async getKey() {
      const h = m.holdGet;
      m.holdGet = null;
      if (h) await h;
      return m.key;
    },
    putKey: async (k: CryptoKey) => void (m.key = k),
    getBox: async () => m.box,
    async putBoxIf(expect: Uint8Array | null, b: SealedBox) {
      const h = m.holdPut;
      m.holdPut = null;
      if (h) {
        m.onHeld?.();
        await h;
      }
      // compare and write with no await in between, as one IndexedDB transaction does
      if (!isBox(m.box, expect)) return false;
      m.box = b;
      return true;
    },
    clear: async () => void ((m.key = null), (m.box = null)),
  };
  return m satisfies CacheStore;
}

function gate(): { wait: Promise<void>; open: () => void } {
  let open = () => {};
  const wait = new Promise<void>((r) => (open = r));
  return { wait, open };
}

/** Holds the store's next putBoxIf (after its caller has read and sealed); resolves once that write is waiting. */
function holdNextWrite(s: ReturnType<typeof memoryStore>): {
  reached: Promise<void>;
  open: () => void;
} {
  const g = gate();
  const reached = new Promise<void>((r) => (s.onHeld = r));
  s.holdPut = g.wait;
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

describe("notification cache", () => {
  it("round-trips sealed under a key that cannot be exported", async () => {
    const s = memoryStore();
    expect(await readCache(s)).toBeNull();
    const c = cache([{ E: 50, n: 3 }]);
    await writeCache(s, c);
    expect(s.key?.extractable).toBe(false);
    expect(new TextDecoder().decode(new Uint8Array(s.box!.ct))).not.toContain("bob");
    expect(await readCache(s)).toEqual(c);
  });

  it("reads a tampered or foreign box as no cache, and clears", async () => {
    const s = memoryStore();
    await writeCache(s, cache([{ E: 50, n: 3 }]));
    const ct = new Uint8Array(s.box!.ct.slice(0));
    ct[0] ^= 1;
    s.box = { iv: s.box!.iv, ct: ct.buffer };
    expect(await readCache(s)).toBeNull();
    await deleteCache(s);
    expect(s.key).toBeNull();
    expect(await readCache(s)).toBeNull();
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
    await writeCache(
      s,
      cache([
        { E: 50, n: 3 },
        { E: 50, n: 0 },
      ]),
    );
    await advanceCache(s, [
      {
        bell: "bell-1",
        e: 2,
        next: [
          { E: 50, n: 5 },
          { E: 49, n: 9 },
        ],
      },
    ]);
    expect((await readCache(s))!.copies[0].epoch!.next).toEqual([
      { E: 50, n: 5 },
      { E: 50, n: 0 },
    ]);
    // The app knew less than the worker moved: the stored slot stays.
    await writeCache(
      s,
      cache([
        { E: 50, n: 4 },
        { E: 51, n: 0 },
      ]),
    );
    expect((await readCache(s))!.copies[0].epoch!.next).toEqual([
      { E: 50, n: 5 },
      { E: 51, n: 0 },
    ]);
    // Another epoch starts from the app's slots.
    await writeCache(
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
    await advanceCache(s, [{ bell: "bell-1", e: 2, next: [{ E: 60, n: 0 }] }]);
    expect(s.box).toBeNull();
  });

  it("a worker's move in flight never brings back a cache deleted meanwhile, nor creates a key", async () => {
    const early = memoryStore();
    await writeCache(early, cache([{ E: 50, n: 3 }]));
    const k = gate();
    early.holdGet = k.wait; // paused while reading the key, as the review reproduced it
    const m1 = advanceCache(early, [{ bell: "bell-1", e: 2, next: [{ E: 50, n: 9 }] }]);
    await deleteCache(early);
    k.open();
    await m1;
    expect([early.key, early.box]).toEqual([null, null]);

    const s = memoryStore();
    await writeCache(s, cache([{ E: 50, n: 3 }]));
    const g = holdNextWrite(s);
    const moving = advanceCache(s, [{ bell: "bell-1", e: 2, next: [{ E: 50, n: 9 }] }]);
    await g.reached; // read and sealed, about to write
    await deleteCache(s); // the preview set to "new messages", notifications off, or sign-out
    g.open();
    await moving;
    expect(s.key).toBeNull();
    expect(s.box).toBeNull();
    expect(await readCache(s)).toBeNull();
  });

  it("nor overwrites the app's newer cache (a downgrade from `message` to `name`)", async () => {
    const s = memoryStore();
    await writeCache(s, cache([{ E: 50, n: 3 }]));
    const g = holdNextWrite(s);
    const moving = advanceCache(s, [{ bell: "bell-1", e: 2, next: [{ E: 50, n: 9 }] }]);
    await g.reached;
    const named: NotifyCache = {
      v: 1,
      preview: "name",
      deltaS: 10,
      copies: [{ bell: "bell-1", ref: "AAAAAAAAAAAA", name: "bob" }],
    };
    await writeCache(s, named);
    g.open();
    await moving;
    expect(await readCache(s)).toEqual(named);
  });

  it("the app's write reads again when the worker moved a lane meanwhile, and keeps the move", async () => {
    const s = memoryStore();
    await writeCache(s, cache([{ E: 50, n: 3 }]));
    const g = holdNextWrite(s);
    const writing = writeCache(s, cache([{ E: 50, n: 4 }]));
    await g.reached;
    const advanced = advanceCache(s, [{ bell: "bell-1", e: 2, next: [{ E: 50, n: 9 }] }]);
    await advanced;
    g.open();
    await writing;
    expect((await readCache(s))!.copies[0].epoch!.next).toEqual([{ E: 50, n: 9 }]);
  });
});
