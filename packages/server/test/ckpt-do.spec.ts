/**
 * CheckpointDO (docs/PROTOCOL.md §9.5, §10.9): the C_q chain and its signatures, no new q for
 * unchanged heads, the previous era's sealed shard (once more, then dropped), failing components (and ones that
 * never answered, which are left out), the sec clamp, the hourly blob registry head, alarm arming and ensure().
 *
 * The checkpoint object is one instance: each test moves its clock to a fresh era further in the future and drives
 * tick() by hand (the alarm it re-arms then never fires on its own). Components are reached through the real DOs;
 * the InboxDO may or may not answer yet, so assertions only look at the components a test controls.
 */
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import * as P from "@segv/protocol/proto";
import type { BlobRegDO } from "../src/blobreg-do";
import type { CheckpointDO } from "../src/ckpt-do";
import type { ShardDO } from "../src/shard-do";
import { blobRegStub, ckptStub, shardStub, type CkptRecord } from "../src/types";

const E_NOW = P.era(Date.now());
let nextEra = E_NOW + 20;
/** Two fresh consecutive eras (previous, current) nobody has touched, later than every earlier test's. */
const freshEras = (): [number, number] => {
  const E = nextEra + 1;
  nextEra += 3;
  return [E - 1, E];
};
const ck = () => ckptStub(env);
const SRV_PK = P.sigPub(P.fromB64u((env as unknown as { SRV_KEY: string }).SRV_KEY));

type CkInternals = { clock: () => number; env: Env; sizeWarnBytes: number };
async function ckClock(ms: number): Promise<void> {
  await runInDurableObject(ck(), (inst: CheckpointDO) => {
    (inst as unknown as CkInternals).clock = () => ms;
  });
}
async function tick(): Promise<CkptRecord> {
  await ck().tick();
  const r = await ck().latest();
  expect(r).not.toBeNull();
  return r!;
}
const headOf = (r: CkptRecord, cid: string): Uint8Array | undefined => r.heads.find((h) => h.cid === cid)?.head;

async function shardClock(E: number, ms: number): Promise<void> {
  await runInDurableObject(shardStub(env, E, 0), (inst: ShardDO) => {
    (inst as unknown as { clock: () => number }).clock = () => ms;
  });
}
const shardRow = () => ({ v: P.random(8), label: P.random(16), cls: 0, body: P.random(P.BODY_LENS[0]) });
/** Puts one row into shard E at `ms` and leaves the shard's clock 3 s later (the next head() closes the batch). */
async function shardWrite(E: number, ms: number): Promise<void> {
  await shardClock(E, ms);
  expect((await shardStub(env, E, 0).put(E, 0, [shardRow()]))[0].s).toBe("ok");
  await shardClock(E, ms + 3000);
}

/** Runs `fn` with some bindings of the checkpoint object replaced (the rest read through to the real env). */
async function withEnv(patch: Record<string, unknown>, fn: () => Promise<void>): Promise<void> {
  let real: Env | undefined;
  await runInDurableObject(ck(), (inst: CheckpointDO) => {
    const self = inst as unknown as CkInternals;
    real = self.env;
    self.env = new Proxy(real, { get: (t, k) => (typeof k === "string" && k in patch ? patch[k] : Reflect.get(t, k)) });
  });
  try {
    await fn();
  } finally {
    await runInDurableObject(ck(), (inst: CheckpointDO) => {
      (inst as unknown as CkInternals).env = real!;
    });
  }
}
/** A DO namespace whose every object fails head(). */
const deadNs = { getByName: () => ({ head: () => Promise.reject(new Error("component unavailable")) }) };

/** Checks one record: sorted cids, hd = H(heads), C chains from `prevC`, and the signature. */
function checkRecord(r: CkptRecord, prevC: Uint8Array): void {
  const cids = r.heads.map((h) => h.cid);
  expect([...cids].sort((a, b) => P.byteCmp(P.utf8(a), P.utf8(b)))).toEqual(cids);
  expect(new Set(cids).size).toBe(cids.length);
  expect(r.hd).toEqual(P.ckptHd(r.heads));
  expect(r.C).toEqual(P.ckptC(prevC, r.q, r.sec, r.hd));
  expect(P.verify(r.sig, P.ckptSigMsg(r.q, r.C), SRV_PK)).toBe(true);
}

describe("CheckpointDO", () => {
  it("chains C_q, makes no new q for unchanged heads, and signs under SRV_KEY", async () => {
    const [, F] = freshEras();
    const base = P.eraStart(F) + 10 * 60_000;
    await ckClock(base);
    const r1 = await tick();
    expect(r1.sec).toBe(P.secOf(base));
    expect(headOf(r1, P.shardCid(F, 0))).toEqual(P.ZERO32);
    expect(headOf(r1, P.DIRLOG_CID)).toBeDefined();
    expect(headOf(r1, P.BLOBREG_CID)).toBeDefined();
    expect((await tick()).q).toBe(r1.q); // nothing changed

    await shardWrite(F, base);
    const r2 = await tick();
    expect(r2.q).toBe(r1.q + 1);
    const sh = await shardStub(env, F, 0).head(F, 0);
    expect(sh.tLast).toBeGreaterThan(0);
    expect(headOf(r2, P.shardCid(F, 0))).toEqual(sh.head);
    expect((await tick()).q).toBe(r2.q);
    await ckClock(base + 60_000);
    expect((await tick()).q).toBe(r2.q); // a new second alone is no change

    // The whole chain recomputes from C_0 = ZERO32 to latest.C; every record verifies.
    const range = await ck().range(0, 1440);
    expect(range).not.toBeNull();
    expect(range!.from).toEqual({ q: 0, C: P.ZERO32 });
    expect(range!.entries.map((e) => e.q)).toEqual(Array.from({ length: r2.q }, (_, k) => k + 1));
    let C: Uint8Array = P.ZERO32;
    for (const e of range!.entries) {
      const rec = await ck().get(e.q);
      expect(rec).not.toBeNull();
      expect({ q: rec!.q, sec: rec!.sec, hd: rec!.hd }).toEqual(e);
      checkRecord(rec!, C);
      C = P.ckptC(C, e.q, e.sec, e.hd);
    }
    expect(range!.latest).toEqual({ q: r2.q, C: r2.C, sig: r2.sig });
    expect(C).toEqual(r2.C);
    expect(await ck().latest()).toEqual(r2);

    // Paging from a stored q, and the edges.
    const tail = await ck().range(r1.q, 10);
    expect(tail!.from).toEqual({ q: r1.q, C: r1.C });
    expect(tail!.entries.map((e) => e.q)).toEqual([r2.q]);
    expect(P.ckptC(tail!.from.C, tail!.entries[0].q, tail!.entries[0].sec, tail!.entries[0].hd)).toEqual(tail!.latest.C);
    expect((await ck().range(r2.q, 5))!.entries).toEqual([]);
    expect(await ck().range(r2.q + 1, 5)).toBeNull();
    expect(await ck().get(0)).toBeNull();
    expect(await ck().get(r2.q + 1)).toBeNull();
    await runInDurableObject(ck(), (inst: CheckpointDO) => {
      expect(() => inst.range(0, 0)).toThrow(RangeError);
      expect(() => inst.range(0, 1441)).toThrow(RangeError);
      expect(() => inst.range(-1, 1)).toThrow(RangeError);
    });
  });

  it("includes a sealed previous-era shard once more, then drops it", async () => {
    const [Pe, F] = freshEras();
    await ckClock(P.eraStart(F) + 5 * 60_000);
    await shardWrite(Pe, P.eraStart(Pe) + 5000);
    const r1 = await tick();
    const h1 = headOf(r1, P.shardCid(Pe, 0));
    expect(h1).toBeDefined();
    expect(h1).not.toEqual(P.ZERO32);
    expect(headOf(r1, P.shardCid(F, 0))).toBeDefined();

    // Another row is still open when the era ends; the checkpoint's head() call seals the shard (prepare()).
    await shardClock(Pe, P.eraStart(Pe) + 10_000);
    expect((await shardStub(env, Pe, 0).put(Pe, 0, [shardRow()]))[0].s).toBe("ok");
    await shardClock(Pe, P.eraEnd(Pe) + 1000);
    const r2 = await tick();
    expect(r2.q).toBe(r1.q + 1);
    const final = await shardStub(env, Pe, 0).head(Pe, 0);
    expect(final.sealed).toBe(true);
    expect(headOf(r2, P.shardCid(Pe, 0))).toEqual(final.head);
    expect(final.head).not.toEqual(h1);

    const r3 = await tick();
    expect(r3.q).toBe(r2.q + 1);
    expect(headOf(r3, P.shardCid(Pe, 0))).toBeUndefined();
    expect(headOf(r3, P.shardCid(F, 0))).toBeDefined();
    expect((await tick()).q).toBe(r3.q);
  });

  it("a component that fails keeps its previous head", async () => {
    const [, F] = freshEras();
    const base = P.eraStart(F) + 20 * 60_000;
    await ckClock(base);
    await shardWrite(F, base);
    const r1 = await tick();
    const h1 = headOf(r1, P.shardCid(F, 0))!;
    expect(h1).not.toEqual(P.ZERO32);
    await shardWrite(F, base + 10_000);
    const h2 = (await shardStub(env, F, 0).head(F, 0)).head;
    expect(h2).not.toEqual(h1);

    const X = P.random(32);
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const fakeDb = (first: () => Promise<unknown>) => ({ prepare: () => ({ first }) });

      // The shard fails: it keeps h1, so nothing changed and no new q is made.
      await withEnv({ SHARD: deadNs }, async () => {
        expect((await tick()).q).toBe(r1.q);
      });
      // The shard still fails while the dirlog moves: the new checkpoint carries the old shard head.
      await withEnv({ SHARD: deadNs, DB: fakeDb(async () => ({ seq: 9, h: P.b64u(X) })) }, async () => {
        const r = await tick();
        expect(r.q).toBe(r1.q + 1);
        expect(headOf(r, P.shardCid(F, 0))).toEqual(h1);
        expect(headOf(r, P.DIRLOG_CID)).toEqual(X);
      });
      // D1 fails: the dirlog keeps X.
      await withEnv({ DB: fakeDb(async () => Promise.reject(new Error("D1_ERROR: network connection lost"))) }, async () => {
        const r = await tick();
        expect(headOf(r, P.DIRLOG_CID)).toEqual(X);
        expect(headOf(r, P.shardCid(F, 0))).toEqual(h2);
      });
      // A missing dirlog table (before migration 0003) or an empty one is ZERO32.
      const noTable = fakeDb(async () => Promise.reject(new Error("D1_ERROR: no such table: dirlog: SQLITE_ERROR")));
      await withEnv({ DB: noTable }, async () => {
        expect(headOf(await tick(), P.DIRLOG_CID)).toEqual(P.ZERO32);
      });
      await withEnv({ DB: fakeDb(async () => null) }, async () => {
        expect(headOf(await tick(), P.DIRLOG_CID)).toEqual(P.ZERO32);
      });
      expect(errors.mock.calls.some((c) => String(c[0]).includes("did not answer"))).toBe(true);
    } finally {
      errors.mockRestore();
    }
    // Back to the real components.
    const r = await tick();
    expect(headOf(r, P.shardCid(F, 0))).toEqual(h2);
  });

  it("leaves out a component that has never answered (never ZERO32); sec never decreases", async () => {
    const [Pe, F] = freshEras();
    const base = P.eraStart(F) + 30 * 60_000;
    await ckClock(base);
    const prev = (await ck().latest()) ?? { q: 0, C: P.ZERO32 };
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    let r1: CkptRecord | undefined;
    try {
      // No shard or inbox of eras F and F − 1 has ever answered, and none answers now.
      await withEnv({ SHARD: deadNs, INBOX: deadNs }, async () => {
        r1 = await tick();
      });
      expect(errors.mock.calls.filter((c) => String(c[0]).includes("did not answer"))).toHaveLength(4);
    } finally {
      errors.mockRestore();
    }
    expect(r1!.q).toBe(prev.q + 1);
    checkRecord(r1!, prev.C);
    for (const cid of [P.shardCid(F, 0), P.shardCid(Pe, 0), P.inboxCid(F, 0), P.inboxCid(Pe, 0)]) {
      expect(headOf(r1!, cid), cid).toBeUndefined();
    }
    expect(r1!.heads.map((h) => h.cid)).toEqual([P.BLOBREG_CID, P.DIRLOG_CID]);
    expect(r1!.sec).toBe(P.secOf(base));

    // They answer again while the clock has stepped back 2 minutes: a new q (they are listed now), sec clamped.
    await ckClock(base - 120_000);
    const r2 = await tick();
    expect(r2.q).toBe(r1!.q + 1);
    checkRecord(r2, r1!.C);
    expect(headOf(r2, P.shardCid(F, 0))).toEqual(P.ZERO32); // the empty shard's real head
    expect(headOf(r2, P.inboxCid(F, 0))).toEqual(P.ZERO32);
    expect(r2.sec).toBe(r1!.sec); // sec(now) is 120 lower
    // Forward again: sec follows the clock.
    await ckClock(base + 60_000);
    await shardWrite(F, base + 50_000);
    const r3 = await tick();
    expect(r3.q).toBe(r2.q + 1);
    expect(r3.sec).toBe(P.secOf(base + 60_000));
  });

  it("takes the blob registry head at most once per UTC hour", async () => {
    const [, F] = freshEras();
    const h0 = P.eraStart(F); // eras start on a whole UTC hour
    expect(h0 % 3_600_000).toBe(0);
    const blobClock = (ms: number) =>
      runInDurableObject(blobRegStub(env), (inst: BlobRegDO) => {
        (inst as unknown as { clock: () => number }).clock = () => ms;
      });
    await blobClock(h0);
    await ckClock(h0 + 30_000);
    const first = await tick();
    const b0 = headOf(first, P.BLOBREG_CID)!;
    expect(b0).toEqual((await blobRegStub(env).head()).head);

    const seen = new Set<string>([P.b64u(b0)]);
    for (const m of [1, 2, 3, 4, 5, 30, 58, 59]) {
      await blobClock(h0 + m * 60_000);
      expect((await blobRegStub(env).register(P.random(32), 100)).created).toBe(true); // closes last minute's batch
      await ckClock(h0 + m * 60_000 + 30_000);
      const r = await tick();
      expect(headOf(r, P.BLOBREG_CID)).toEqual(b0);
      seen.add(P.b64u(headOf(r, P.BLOBREG_CID)!));
    }
    const moved = (await blobRegStub(env).head()).head;
    expect(moved).not.toEqual(b0); // the registry did change during the hour

    await ckClock(h0 + 3_600_000 + 30_000);
    const next = await tick();
    expect(headOf(next, P.BLOBREG_CID)).toEqual(moved);
    seen.add(P.b64u(headOf(next, P.BLOBREG_CID)!));
    expect(seen.size).toBe(2);
    await ckClock(h0 + 3_600_000 + 90_000);
    expect(headOf(await tick(), P.BLOBREG_CID)).toEqual(moved);
  });

  it("logs a shard above 4 GiB", async () => {
    const [, F] = freshEras();
    await ckClock(P.eraStart(F) + 60_000);
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runInDurableObject(ck(), (inst: CheckpointDO) => {
        (inst as unknown as CkInternals).sizeWarnBytes = 0;
      });
      await tick();
      expect(errors.mock.calls.some((c) => String(c[0]).includes("above 4 GiB"))).toBe(true);
    } finally {
      errors.mockRestore();
      await runInDurableObject(ck(), (inst: CheckpointDO) => {
        (inst as unknown as CkInternals).sizeWarnBytes = 4 * 2 ** 30;
      });
    }
  });

  it("arms its alarm from the constructor; ensure() writes nothing while one is set", async () => {
    await runInDurableObject(ck(), (_inst: CheckpointDO, state) => state.storage.deleteAlarm());
    await evictDurableObject(ck());
    const t0 = Date.now();
    const armed = await runInDurableObject(ck(), (_inst: CheckpointDO, state) => state.storage.getAlarm());
    expect(armed).not.toBeNull();
    expect(armed!).toBeGreaterThanOrEqual(t0 + 59_000);
    expect(armed!).toBeLessThanOrEqual(Date.now() + 60_000);

    const q0 = (await ck().latest())?.q ?? 0;
    await runInDurableObject(ck(), async (inst: CheckpointDO, state) => {
      const setAlarm = vi.spyOn(state.storage, "setAlarm");
      const exec = vi.spyOn(state.storage.sql, "exec");
      try {
        for (let k = 0; k < 5; k++) await inst.ensure();
        expect(setAlarm).not.toHaveBeenCalled();
        expect(exec).not.toHaveBeenCalled();
      } finally {
        setAlarm.mockRestore();
        exec.mockRestore();
      }
      expect(await state.storage.getAlarm()).toBe(armed);
    });
    for (let k = 0; k < 3; k++) await ck().ensure();
    expect(await runInDurableObject(ck(), (_inst: CheckpointDO, state) => state.storage.getAlarm())).toBe(armed);
    expect((await ck().latest())?.q ?? 0).toBe(q0);

    // ensure() is also the safety net when the alarm went missing.
    await runInDurableObject(ck(), async (inst: CheckpointDO, state) => {
      await state.storage.deleteAlarm();
      await inst.ensure();
      expect(await state.storage.getAlarm()).not.toBeNull();
      // Park it far away so no tick runs on its own while the rest of the file runs.
      await state.storage.setAlarm(P.eraStart(E_NOW + 1000));
    });
  });
});
