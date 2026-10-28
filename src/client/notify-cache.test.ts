// The notification cache (docs/PROTOCOL.md §11.13): sealed under a key that cannot be exported, merged so that lane
// positions only move forward.
import { describe, expect, it } from "vite-plus/test";
import {
  advanceCache,
  applyMoves,
  deleteCache,
  mergeNext,
  parseCache,
  readCache,
  writeCache,
  type CacheStore,
  type NotifyCache,
  type SealedBox,
} from "./notify-cache";

function memoryStore(): CacheStore & { box: SealedBox | null; key: CryptoKey | null } {
  const m = {
    key: null as CryptoKey | null,
    box: null as SealedBox | null,
    getKey: async () => m.key,
    putKey: async (k: CryptoKey) => void (m.key = k),
    getBox: async () => m.box,
    putBox: async (b: SealedBox) => void (m.box = b),
    clear: async () => void ((m.key = null), (m.box = null)),
  };
  return m;
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
});
