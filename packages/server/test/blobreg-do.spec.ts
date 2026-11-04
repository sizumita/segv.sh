/**
 * BlobRegDO (docs/PROTOCOL.md §8.2, §9.2): create-only registrations, the MISS high-water mark that
 * makes §6.4(g) final, closed_t, the head chain over H(id)-ordered leaves, and Δ pinned by the first write.
 *
 * The registry is one object, so every test moves its clock forward to a fresh hour far in the future (its
 * batch alarms then never fire on their own; tests run them by hand).
 */
import { evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import * as P from "@segv/protocol/proto";
import type { BlobRegDO } from "../src/blobreg-do";
import { blobRegLegacyStub, blobRegStub } from "../src/types";

type Internals = { clock: () => number; params: { delta: number }; blobBits: number };

/** The registry under test is shard 0 of the two of ../wrangler.test.jsonc (BLOBREG_SHARDS = 2). */
const reg = () => blobRegStub(env, 0);
const BITS = 1;
const BLOB_KEY = P.kblob(P.fromB64u((env as unknown as { ROUTE_KEY: string }).ROUTE_KEY));
/** A random blob id that routes to shard j (§4.4). */
function idFor(j: number): Uint8Array {
  for (;;) {
    const id = P.random(32);
    if (P.blobShardOf(BLOB_KEY, id, BITS) === j) return id;
  }
}
/** A random blob id of the shard under test. */
const blobId = (): Uint8Array => idFor(0);
const DELTA = 1; // packages/server/test/wrangler.test.jsonc DELTA_S
let cursor = P.eraStart(P.era(Date.now()) + 20);
/** A fresh time base, one hour after the previous one (aligned to a whole minute). */
const later = (): number => (cursor += 3_600_000);

const internals = (inst: BlobRegDO): Internals => inst as unknown as Internals;
/** Sets the registry's clock; with `delta`, runs it under that Δ (deployment value and the pinned one alike). */
async function setClock(ms: number, delta?: number): Promise<void> {
  await runInDurableObject(reg(), (inst: BlobRegDO, state) => {
    internals(inst).clock = () => ms;
    if (delta === undefined) return;
    internals(inst).params = { delta };
    state.storage.sql.exec("INSERT OR REPLACE INTO meta (k, v) VALUES ('delta', ?)", delta);
  });
}
const metaOf = (k: string): Promise<unknown> =>
  runInDurableObject(reg(), (_inst: BlobRegDO, state) => {
    const r = state.storage.sql
      .exec<{ v: SqlStorageValue }>("SELECT v FROM meta WHERE k = ?", k)
      .toArray()[0];
    return r?.v ?? null;
  });
const batchDue = (t: number): number => P.T0_MS + (t + DELTA) * 1000 + 1000;

/** Recomputes every batch of the registry from its tables (leaves by H(id), chain from ZERO32). */
async function recomputeHead(): Promise<{ head: Uint8Array; closedT: number }> {
  return runInDurableObject(reg(), (_inst: BlobRegDO, state) => {
    const sql = state.storage.sql;
    const batches = sql
      .exec<{ t: number; n: number; root: ArrayBuffer; head: ArrayBuffer }>(
        "SELECT t, n, root, head FROM batch ORDER BY t",
      )
      .toArray();
    let head: Uint8Array = P.ZERO32;
    for (const b of batches) {
      const blobs = sql
        .exec<{ id: ArrayBuffer; size: number }>("SELECT id, size FROM blob WHERE t = ?", b.t)
        .toArray()
        .map((r) => ({ id: new Uint8Array(r.id), size: r.size }))
        .sort((x, y) => P.byteCmp(P.H(x.id), P.H(y.id)));
      expect(blobs).toHaveLength(b.n);
      const root = P.mth(blobs.map((x) => P.leafBlob(x.id, x.size, b.t)));
      expect(new Uint8Array(b.root)).toEqual(root);
      head = P.nextHead(P.blobRegCid(0), head, b.t, b.n, root); // the shard's own cid (§9.2)
      expect(new Uint8Array(b.head)).toEqual(head);
    }
    // Every registration at or below closed_t is inside a batch.
    const last = batches[batches.length - 1]?.t ?? -1;
    const committed = sql
      .exec<{ n: number }>("SELECT count(*) AS n FROM blob WHERE t <= ?", last)
      .one().n;
    expect(committed).toBe(batches.reduce((n, b) => n + b.n, 0));
    return { head, closedT: last };
  });
}

describe("BlobRegDO", () => {
  it("is create-only: a second register returns the original t and size with created = false", async () => {
    const c = later();
    await setClock(c);
    const id = blobId();
    const t = P.secOf(c);
    expect(await reg().register(id, 11640)).toEqual({ t, size: 11640, created: true });
    expect(await reg().meta(id)).toEqual({ hit: true, t, size: 11640 });
    await setClock(c + 5000);
    expect(await reg().register(id, 40248)).toEqual({ t, size: 11640, created: false });
    expect(await reg().meta(id)).toEqual({ hit: true, t, size: 11640 });
  });

  it("a MISS reports now, and later registrations get t ≥ tpub(now) even with the clock set back", async () => {
    const x = later();
    await setClock(x);
    const missing = blobId();
    expect(await reg().meta(missing)).toEqual({ hit: false, now: P.secOf(x) });
    expect(await metaOf("hw")).toBe(P.secOf(x));

    await setClock(x - 5000);
    const r = await reg().register(blobId(), 100);
    expect(r.created).toBe(true);
    expect(r.t).toBeGreaterThanOrEqual(P.tpub(x, DELTA));
    expect(r.t).toBe(P.secOf(x)); // tpub(hw); last_t and closed_t of earlier tests lie an hour back

    // The id reported missing registers with t_reg ≥ the reported now, so the MISS was final (§6.4(g)).
    const late = await reg().register(missing, 100);
    expect(late.t).toBeGreaterThanOrEqual(P.secOf(x));
  });

  it("writes the high-water mark at most once per Δ", async () => {
    const x = later(); // a whole hour: aligned to Δ = 10
    const s = P.secOf(x);
    expect(s % 10).toBe(0);
    const missing = blobId();
    try {
      await setClock(x + 1000, 10);
      await reg().meta(missing);
      expect(await metaOf("hw")).toBe(s + 1);
      for (const ms of [x + 5000, x + 9999, x + 1000, x - 30_000]) {
        await setClock(ms, 10);
        expect(await reg().meta(missing)).toEqual({ hit: false, now: P.secOf(ms) });
        expect(await metaOf("hw")).toBe(s + 1); // same Δ window (or earlier): no write
      }
      await setClock(x + 10_000, 10);
      await reg().meta(missing);
      expect(await metaOf("hw")).toBe(s + 10);
      // A registration with the clock back in the first window still gets t ≥ tpub(hw).
      await setClock(x + 2000, 10);
      const r = await reg().register(blobId(), 1);
      expect(r.t).toBe(s + 10);
    } finally {
      await setClock(x + 20_000, DELTA);
    }
    // Close the Δ = 10 batch (t = s + 10) before the next test runs with Δ = 1.
    await setClock(x + 30_000);
    expect((await reg().head()).tLast).toBe(s + 10);
  });

  it("closed_t: after the alarm closed a batch, a registration with the clock stepped back gets t = closed_t + Δ", async () => {
    const c = later();
    await setClock(c);
    // An earlier test's batch alarm may still be scheduled (min(current, due) keeps it): let it run first.
    await runDurableObjectAlarm(reg());
    expect(
      await runInDurableObject(reg(), (_inst: BlobRegDO, state) => state.storage.getAlarm()),
    ).toBeNull();
    const a = await reg().register(blobId(), 7);
    expect(a.t).toBe(P.secOf(c));
    const alarm = await runInDurableObject(reg(), (_inst: BlobRegDO, state) =>
      state.storage.getAlarm(),
    );
    expect(alarm).toBe(batchDue(a.t));

    await setClock(batchDue(a.t));
    expect(await runDurableObjectAlarm(reg())).toBe(true);
    expect(await metaOf("closed_t")).toBe(a.t);
    expect(await metaOf("open_t")).toBeNull();
    expect((await reg().head()).tLast).toBe(a.t);

    await setClock(c); // stepped back
    const b = await reg().register(blobId(), 8);
    expect(b.t).toBe(a.t + DELTA);
    const b2 = await reg().register(blobId(), 9);
    expect(b2.t).toBe(b.t); // joins the open batch
    const before = await reg().head();
    expect(before.tLast).toBe(a.t); // tpub(now) ≤ open_t: still open

    await setClock(c + 5000);
    const h = await reg().head();
    expect(h.tLast).toBe(b.t);
    expect(await recomputeHead()).toEqual({ head: h.head, closedT: b.t });
  });

  it("orders leaves by H(id), keeps everything across a cold start, and re-arms a missing batch alarm", async () => {
    const c = later();
    await setClock(c);
    const ids = Array.from({ length: 6 }, () => blobId());
    for (const [k, id] of ids.entries())
      expect((await reg().register(id, 100 + k)).created).toBe(true);
    await runInDurableObject(reg(), (_inst: BlobRegDO, state) => state.storage.deleteAlarm());
    await evictDurableObject(reg());
    // The constructor re-arms the open batch's alarm.
    const t = P.secOf(c);
    expect(
      await runInDurableObject(reg(), (_inst: BlobRegDO, state) => state.storage.getAlarm()),
    ).toBe(batchDue(t));
    await setClock(batchDue(t));
    expect(await runDurableObjectAlarm(reg())).toBe(true);
    const h = await reg().head();
    expect(h.tLast).toBe(t);
    expect(await recomputeHead()).toEqual({ head: h.head, closedT: t });
    for (const [k, id] of ids.entries())
      expect(await reg().meta(id)).toEqual({ hit: true, t, size: 100 + k });
    // No batch left open: the alarm handler armed nothing.
    expect(
      await runInDurableObject(reg(), (_inst: BlobRegDO, state) => state.storage.getAlarm()),
    ).toBeNull();
  });

  it("rejects malformed RPC input", async () => {
    await runInDurableObject(reg(), (inst: BlobRegDO) => {
      expect(() => inst.register(P.random(31), 1)).toThrow(TypeError);
      expect(() => inst.register(blobId(), -1)).toThrow(TypeError);
      expect(() => inst.register(blobId(), 2 ** 32)).toThrow(TypeError);
      expect(() => inst.register(blobId(), 1.5)).toThrow(TypeError);
      expect(() => inst.meta(P.random(33))).toThrow(TypeError);
    });
  });

  it("pins Δ at its first write and keeps it when the deployment Δ changes, logging the mismatch once", async () => {
    // Separate, fresh registries: the two shards of the test deployment, emptied and started again here (the file
    // shares them), each with ids of its own.
    for (const j of [0, 1]) {
      await runInDurableObject(blobRegStub(env, j), (_inst: BlobRegDO, state) =>
        state.storage.deleteAll(),
      );
      await evictDurableObject(blobRegStub(env, j));
    }
    const pinnedOf = (r: DurableObjectStub<BlobRegDO>) =>
      runInDurableObject(r, (_inst: BlobRegDO, state) => {
        const row = state.storage.sql
          .exec<{ v: SqlStorageValue }>("SELECT v FROM meta WHERE k = 'delta'")
          .toArray()[0];
        return row?.v ?? null;
      });
    const run = (r: DurableObjectStub<BlobRegDO>, ms: number, delta: number) =>
      runInDurableObject(r, (inst: BlobRegDO) => {
        internals(inst).clock = () => ms;
        internals(inst).params = { delta };
      });
    const x = later(); // a whole hour: aligned to Δ = 10
    const s = P.secOf(x);

    // A MISS's high-water mark write pins Δ, and so does a first registration.
    const a = blobRegStub(env, 1);
    await run(a, x, DELTA);
    expect(await pinnedOf(a)).toBeNull();
    expect(await a.meta(idFor(1))).toEqual({ hit: false, now: s });
    expect(await pinnedOf(a)).toBe(DELTA);
    const b = reg();
    await run(b, x, 10);
    expect((await b.register(blobId(), 1)).t).toBe(s);
    expect(await pinnedOf(b)).toBe(10);

    // The deployment now says Δ = 1: the registry keeps Δ = 10 for t, the high-water mark and the batch alarm.
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await run(b, x + 13_500, DELTA);
      const late = await b.register(blobId(), 2);
      expect(late.t).toBe(s + 10); // tpub under the pinned Δ = 10 (Δ = 1 would give s + 13)
      expect(await b.meta(blobId())).toEqual({ hit: false, now: s + 13 });
      await run(b, x + 17_000, DELTA);
      await b.meta(blobId());
      const hw = await runInDurableObject(
        b,
        (_inst: BlobRegDO, state) =>
          state.storage.sql.exec<{ v: number }>("SELECT v FROM meta WHERE k = 'hw'").one().v,
      );
      expect(hw).toBe(s + 13); // same Δ = 10 window as s + 13: no second write
      expect(await pinnedOf(b)).toBe(10);
      const logged = () => errors.mock.calls.filter((c) => String(c[0]).includes("pinned delta"));
      expect(logged()).toHaveLength(1);
      expect(JSON.parse(String(logged()[0][0]))).toMatchObject({ pinned: 10, env: DELTA });

      // A new instance (deployment Δ = 1) re-arms the open batch's alarm under the pinned Δ, and logs once itself.
      await runInDurableObject(b, (_inst: BlobRegDO, state) => state.storage.deleteAlarm());
      await evictDurableObject(b);
      const alarm = await runInDurableObject(b, (_inst: BlobRegDO, state) =>
        state.storage.getAlarm(),
      );
      expect(alarm).toBe(P.T0_MS + (late.t + 10) * 1000 + 1000);
      expect(logged()).toHaveLength(2);
    } finally {
      errors.mockRestore();
    }
  });
});

describe("BlobRegDO shards (§9.2)", () => {
  it("answers only the ids that route to it, under the b it pinned at its first write", async () => {
    const one = blobRegStub(env, 1);
    const ms = later();
    await runInDurableObject(one, (inst: BlobRegDO) => {
      internals(inst).clock = () => ms;
    });
    expect((await one.register(idFor(1), 5)).created).toBe(true);
    await runInDurableObject(one, async (inst: BlobRegDO, state) => {
      expect(() => inst.register(idFor(0), 5)).toThrow(/another shard/);
      expect(() => inst.meta(idFor(0))).toThrow(/another shard/);
      expect(
        state.storage.sql.exec<{ v: number }>("SELECT v FROM meta WHERE k = 'bbits'").one().v,
      ).toBe(BITS);
      // The deployment changes B (an operator error): the pin wins, and the mismatch is logged once.
      const errors = vi.spyOn(console, "error").mockImplementation(() => {});
      try {
        internals(inst).blobBits = 0;
        expect(() => inst.meta(idFor(0))).toThrow(/another shard/);
        expect(inst.meta(idFor(1)).hit).toBe(false);
        expect(
          errors.mock.calls.filter((c) => String(c[0]).includes("BLOBREG_SHARDS")),
        ).toHaveLength(1);
      } finally {
        internals(inst).blobBits = BITS;
        errors.mockRestore();
      }
      // The legacy registry is read-only, and only it exports.
      expect(() => inst.exportShard(0, BITS, null, 10)).toThrow(/legacy/);
    });
    await runInDurableObject(blobRegLegacyStub(env), (inst: BlobRegDO) => {
      expect(() => inst.register(idFor(0), 1)).toThrow(/read-only/);
      expect(() => inst.meta(idFor(0))).toThrow(/read-only/);
      expect(() => inst.exportShard(2, BITS, null, 10)).toThrow(RangeError);
      expect(() => inst.exportShard(0, 13, null, 10)).toThrow(RangeError);
    });
  });

  it("imports its rows, hw and last_t from the first release's registry the first time it runs", async () => {
    // Rows of both shards in the legacy registry, written as the first release left them.
    const delta = 1;
    const base = later();
    const rows = Array.from({ length: 7 }, (_, k) => ({
      id: idFor(k % 2),
      size: 100 + k,
      t: P.secOf(base) + 10 * k,
    }));
    const hw = P.secOf(base) + 500;
    const lastT = P.secOf(base) + 60;
    await runInDurableObject(blobRegLegacyStub(env), (_inst: BlobRegDO, state) => {
      const sql = state.storage.sql;
      for (const r of rows)
        sql.exec("INSERT INTO blob (id, size, t) VALUES (?, ?, ?)", r.id.buffer, r.size, r.t);
      sql.exec("INSERT OR REPLACE INTO meta (k, v) VALUES ('hw', ?)", hw);
      sql.exec("INSERT OR REPLACE INTO meta (k, v) VALUES ('last_t', ?)", lastT);
    });
    // exportShard pages by id and keeps only the shard's rows.
    const exported: { id: Uint8Array; t: number }[] = [];
    for (let after: Uint8Array | null = null; ;) {
      const page = await blobRegLegacyStub(env).exportShard(1, BITS, after, 2);
      exported.push(...page.rows);
      expect(page.hw).toBe(hw);
      expect(page.lastT).toBe(lastT);
      if (page.next === null) break;
      after = page.next;
    }
    const ofShard = (j: number) => rows.filter((r) => P.blobShardOf(BLOB_KEY, r.id, BITS) === j);
    expect(exported.map((r) => P.b64u(r.id)).sort()).toEqual(
      ofShard(1)
        .map((r) => P.b64u(r.id))
        .sort(),
    );
    // Each shard imports on its first run (both objects exist from earlier tests: empty them and start them again).
    for (const j of [0, 1]) {
      await runInDurableObject(blobRegStub(env, j), (_inst: BlobRegDO, state) =>
        state.storage.deleteAll(),
      );
      await evictDurableObject(blobRegStub(env, j));
      const s = blobRegStub(env, j);
      const mine = ofShard(j);
      for (const r of mine) expect(await s.meta(r.id)).toEqual({ hit: true, t: r.t, size: r.size });
      for (const r of ofShard(1 - j)) {
        await runInDurableObject(s, (inst: BlobRegDO) =>
          expect(() => inst.meta(r.id)).toThrow(/another shard/),
        );
      }
      await runInDurableObject(s, (inst: BlobRegDO, state) => {
        const meta = (k: string) =>
          state.storage.sql
            .exec<{ v: SqlStorageValue }>("SELECT v FROM meta WHERE k = ?", k)
            .toArray()[0]?.v ?? null;
        expect(meta("imported")).toBe(1);
        expect(meta("bbits")).toBe(BITS);
        expect(meta("hw")).toBe(hw);
        expect(meta("last_t")).toBe(lastT);
        expect(
          state.storage.sql.exec<{ n: number }>("SELECT count(*) AS n FROM blob").one().n,
        ).toBe(mine.length);
        expect(
          state.storage.sql.exec<{ n: number }>("SELECT count(*) AS n FROM batch").one().n,
        ).toBe(0); // the legacy chain holds them
        internals(inst).clock = () => base; // before the legacy hw: a new registration still lands above it
      });
      expect((await s.head()).head).toEqual(P.ZERO32);
      const fresh = await s.register(idFor(j), 9);
      expect(fresh.created).toBe(true);
      expect(fresh.t).toBeGreaterThanOrEqual(P.floorDelta(hw, delta));
      expect(fresh.t).toBeGreaterThanOrEqual(lastT);
    }
  });
});
