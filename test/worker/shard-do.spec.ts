/**
 * ShardDO (docs/PROTOCOL.md §9.1, plan M2): CAS, BAD, WRONG_ERA, sealing, batches and the head chain, feed
 * paging (feedBatches / feedRows, which never close a due batch), monotonic t (IMP-7), early acceptance at the SKEW
 * boundary, identity and alarm discipline (an ended era arms nothing), the pinned Δ, and batches of thousands of
 * rows (closeBatch never reads a body; feed results stay within budget).
 *
 * Every test uses fresh eras far in the future, so every alarm a DO arms lies in the future and only fires when a
 * test runs it (runDurableObjectAlarm). Time inside a DO is set through its protected `clock` field.
 */
import { evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import * as P from "../../src/lib/proto";
import { leafShardFromHash } from "../../src/server/batch";
import type { ShardDO } from "../../src/server/shard-do";
import { shardStub, type ShardFeedRow, type ShardPutResult, type ShardPutRow } from "../../src/server/types";

type Internals = { clock: () => number; params: { delta: number; skew: number }; fullBytes: number };

const E_NOW = P.era(Date.now());
let nextEra = E_NOW + 20;
/** A fresh era whose DO nobody has touched yet (far in the future: its alarms never fire on their own). */
const freshEra = (): number => nextEra++;
const stub = (E: number) => shardStub(env, E, 0);
const DELTA = 1; // test/worker/wrangler.test.jsonc DELTA_S

const internals = (inst: ShardDO): Internals => inst as unknown as Internals;
/** Sets the DO's clock to a fixed ms value (and, optionally, overrides SKEW: tests run with SKEW = 0). */
async function setClock(E: number, ms: number, skew?: number): Promise<void> {
  await runInDurableObject(stub(E), (inst: ShardDO) => {
    internals(inst).clock = () => ms;
    if (skew !== undefined) internals(inst).params = { ...internals(inst).params, skew };
  });
}
const metaOf = (state: DurableObjectState, k: string): unknown =>
  state.storage.sql.exec<{ v: SqlStorageValue }>("SELECT v FROM meta WHERE k = ?", k).toArray()[0]?.v ?? null;
const alarmOf = (E: number): Promise<number | null> =>
  runInDurableObject(stub(E), (_inst: ShardDO, state) => state.storage.getAlarm());

const row = (cls = 0): ShardPutRow => ({ v: P.random(8), label: P.random(16), cls, body: P.random(P.BODY_LENS[cls]) });
const put = (E: number, rows: ShardPutRow[]): Promise<ShardPutResult[]> => stub(E).put(E, 0, rows);
async function putOk(E: number, rows: ShardPutRow[]): Promise<number> {
  const res = await put(E, rows);
  for (const r of res) expect(r.s).toBe("ok");
  return (res[0] as { t: number }).t;
}
/** Batch alarm due time for an open batch at t (§9.1). */
const batchDue = (t: number): number => P.T0_MS + (t + DELTA) * 1000 + 1000;
/** A ms value exactly at the start of second `s` past start(E). */
const at = (E: number, s: number): number => P.eraStart(E) + s * 1000;

/** A closed batch with all of its rows, as one §10.9 feed batch. */
interface Batch {
  t: number;
  n: number;
  root: Uint8Array;
  head: Uint8Array;
  rows: ShardFeedRow[];
}
/** §10.9 wire size of a batch: 72 + Σ (17 + len(body)). */
const wireSize = (b: { rows: ShardFeedRow[] }): number => 72 + b.rows.reduce((n, r) => n + 17 + r.body.length, 0);
const rowsBytes = (rows: ShardFeedRow[]): number => rows.reduce((n, r) => n + 17 + r.body.length, 0);

/** Every row of the closed batch t through feedRows, `budget` bytes per call, checking each call's contract. */
async function rowsVia(E: number, t: number, budget: number): Promise<ShardFeedRow[]> {
  const rows: ShardFeedRow[] = [];
  let after: Uint8Array | null = null;
  for (;;) {
    const r = await stub(E).feedRows(E, 0, t, after, budget);
    if (r.rows.length > 1) expect(rowsBytes(r.rows)).toBeLessThanOrEqual(budget);
    if (!r.done) expect(r.rows.length).toBeGreaterThan(0);
    rows.push(...r.rows);
    if (r.done) return rows;
    after = r.rows[r.rows.length - 1].label;
  }
}

/**
 * Every closed batch through feed pages of `budget` bytes (feedBatches, then feedRows for a batch sent without its
 * rows), checking the page contract: ≥ 1 batch while `more`, within budget unless it is one batch, rows inline
 * exactly when the page fits, `bytes` = the batch's wire size.
 */
async function feedAll(E: number, budget = 4 << 20): Promise<Batch[]> {
  const out: Batch[] = [];
  let after = 0;
  for (;;) {
    const f = await stub(E).feedBatches(E, 0, after, budget);
    const total = f.batches.reduce((n, b) => n + b.bytes, 0);
    if (f.batches.length > 1) expect(total).toBeLessThanOrEqual(budget);
    if (f.more) expect(f.batches.length).toBeGreaterThan(0);
    for (const { bytes, rows, ...b } of f.batches) {
      expect(rows !== undefined).toBe(total <= budget);
      const all = rows ?? (await rowsVia(E, b.t, budget));
      expect(bytes).toBe(wireSize({ rows: all }));
      out.push({ ...b, rows: all });
      after = b.t;
    }
    if (!f.more) return out;
  }
}

/** Recomputes roots and the head chain of `batches` (from ZERO32) and returns the final head. */
function verifyChain(E: number, batches: Batch[]): Uint8Array {
  let head: Uint8Array = P.ZERO32;
  let lastT = -1;
  for (const b of batches) {
    expect(b.t).toBeGreaterThan(lastT);
    expect(b.rows).toHaveLength(b.n);
    for (let k = 1; k < b.rows.length; k++) expect(P.byteCmp(b.rows[k - 1].label, b.rows[k].label)).toBeLessThan(0);
    expect(b.root).toEqual(P.mth(b.rows.map((r) => P.leafShard(E, r.label, b.t, r.cls, r.body))));
    head = P.nextHead(P.shardCid(E, 0), head, b.t, b.n, b.root);
    expect(b.head).toEqual(head);
    lastT = b.t;
  }
  return head;
}

describe("ShardDO.put", () => {
  it("first writer wins a CAS race; the loser gets CONFLICT with the winner's row", async () => {
    const E = freshEra();
    await setClock(E, at(E, 60));
    const a = row(1);
    const b: ShardPutRow = { ...a, cls: 0, body: P.random(P.BODY_LENS[0]) };
    const [ra, rb] = await Promise.all([put(E, [a]), put(E, [b])]);
    const results = [ra[0], rb[0]];
    const ok = results.filter((r) => r.s === "ok");
    expect(ok).toHaveLength(1);
    const winner = ra[0].s === "ok" ? a : b;
    const loser = results.find((r) => r.s === "conflict");
    expect(loser).toEqual({ s: "conflict", t: (ok[0] as { t: number }).t, cls: winner.cls, body: winner.body });
    const got = await stub(E).get(E, 0, [{ v: a.v, label: a.label, mode: 0 }]);
    expect(got).toEqual([{ s: "hit", t: P.secOf(at(E, 60)), cls: winner.cls, body: winner.body }]);
  });

  it("answers BAD for wrong lengths and CONFLICT(first copy) for a duplicate label; rows are independent", async () => {
    const E = freshEra();
    await setClock(E, at(E, 30));
    const good = row(2);
    const dup: ShardPutRow = { ...good, body: P.random(P.BODY_LENS[2]) };
    const rows = [
      good,
      { ...row(0), body: P.random(P.BODY_LENS[0] + 1) },
      { ...row(1), body: P.random(P.BODY_LENS[0]) }, // body of another class
      { ...row(0), label: P.random(15) },
      { ...row(0), v: P.random(7) },
      { ...row(0), cls: 4 }, // no such class
      { ...row(0), cls: -1 },
      { ...row(0), cls: 0.5 },
      dup,
      row(3),
    ];
    const t = P.secOf(at(E, 30));
    const res = await put(E, rows);
    expect(res).toEqual([
      { s: "ok", t },
      { s: "bad" },
      { s: "bad" },
      { s: "bad" },
      { s: "bad" },
      { s: "bad" },
      { s: "bad" },
      { s: "bad" },
      { s: "conflict", t, cls: 2, body: good.body },
      { s: "ok", t },
    ]);
  });

  it("refuses with WRONG_ERA(era(now)): a past era, a future era, and once the era has ended", async () => {
    // A past era with the real clock: prepare() seals it on the first call; it arms nothing.
    const past = E_NOW - 1;
    const resPast = await put(past, [row()]);
    expect(resPast).toEqual([{ s: "wrong_era", era: P.era(Date.now()) }]);
    expect(await stub(past).get(past, 0, [{ v: P.random(8), label: P.random(16), mode: 1 }])).toEqual([
      { s: "miss", sealed: true },
    ]);
    expect(await alarmOf(past)).toBeNull();

    // A future era with the real clock.
    const fut = freshEra();
    expect(await put(fut, [row(), row()])).toEqual([
      { s: "wrong_era", era: P.era(Date.now()) },
      { s: "wrong_era", era: P.era(Date.now()) },
    ]);
    expect(await stub(fut).get(fut, 0, [{ v: P.random(8), label: P.random(16), mode: 1 }])).toEqual([
      { s: "miss", sealed: false },
    ]);

    // The last millisecond of the era is accepted; end(E) is not (and with SKEW = 0 it also seals).
    const E = freshEra();
    await setClock(E, P.eraEnd(E) - 1);
    await putOk(E, [row()]);
    await setClock(E, P.eraEnd(E));
    expect(await put(E, [row()])).toEqual([{ s: "wrong_era", era: E + 1 }]);
    expect((await stub(E).head(E, 0)).sealed).toBe(true);
  });

  it("answers FULL above the size limit", async () => {
    const E = freshEra();
    await runInDurableObject(stub(E), (inst: ShardDO) => {
      internals(inst).clock = () => at(E, 5);
      internals(inst).fullBytes = 0;
    });
    const r = row();
    expect(await put(E, [r, row()])).toEqual([{ s: "full" }, { s: "full" }]);
    expect(await stub(E).get(E, 0, [{ v: r.v, label: r.label, mode: 0 }])).toEqual([{ s: "miss", sealed: false }]);
  });

  it("get mode 1 answers HIT without the body", async () => {
    const E = freshEra();
    await setClock(E, at(E, 7));
    const r = row(1);
    const t = await putOk(E, [r]);
    expect(await stub(E).get(E, 0, [{ v: r.v, label: r.label, mode: 1 }])).toEqual([{ s: "hit", t, cls: 1 }]);
    // Same label under another v is another key.
    expect(await stub(E).get(E, 0, [{ v: P.random(8), label: r.label, mode: 0 }])).toEqual([{ s: "miss", sealed: false }]);
  });
});

describe("ShardDO sealing", () => {
  it("MISS(sealed = 0) before the seal alarm, MISS(sealed = 1) after it; a put after the seal is WRONG_ERA", async () => {
    const E = freshEra();
    await setClock(E, at(E, 1));
    const r = row();
    const t = await putOk(E, [r]);
    expect(await alarmOf(E)).toBe(batchDue(t));

    // The batch alarm closes the batch and re-arms the seal alarm at end(E) + SKEW.
    await setClock(E, batchDue(t));
    expect(await runDurableObjectAlarm(stub(E))).toBe(true);
    expect(await alarmOf(E)).toBe(P.eraEnd(E));
    const missing = { v: P.random(8), label: P.random(16), mode: 0 as const };
    expect(await stub(E).get(E, 0, [missing])).toEqual([{ s: "miss", sealed: false }]);

    // A second row is still open when the seal alarm fires: sealing closes it.
    await setClock(E, P.eraEnd(E) - 1);
    await putOk(E, [row()]);
    await setClock(E, P.eraEnd(E));
    expect(await runDurableObjectAlarm(stub(E))).toBe(true);
    await runInDurableObject(stub(E), async (_inst: ShardDO, state) => {
      expect(metaOf(state, "state")).toBe("sealed"); // persisted by the alarm, before any RPC ran prepare()
      expect(metaOf(state, "open_t")).toBeNull();
      expect(await state.storage.getAlarm()).toBeNull(); // nothing left to arm
    });
    expect(await stub(E).get(E, 0, [missing, { ...r, mode: 1 }])).toEqual([
      { s: "miss", sealed: true },
      { s: "hit", t, cls: 0 },
    ]);
    expect(await put(E, [row()])).toEqual([{ s: "wrong_era", era: E + 1 }]);
    const h = await stub(E).head(E, 0);
    expect(h.sealed).toBe(true);
    const f = await stub(E).feedBatches(E, 0, 0, 1 << 30);
    expect(f.sealed).toBe(true);
    expect(f.batches).toHaveLength(2);
    expect(verifyChain(E, await feedAll(E))).toEqual(h.head);
  });

  it("prepare() seals synchronously once now ≥ end(E) + SKEW, even without the alarm", async () => {
    const E = freshEra();
    await setClock(E, at(E, 3));
    await putOk(E, [row(), row()]);
    await setClock(E, P.eraEnd(E) + 5000);
    expect(await stub(E).get(E, 0, [{ v: P.random(8), label: P.random(16), mode: 1 }])).toEqual([
      { s: "miss", sealed: true },
    ]);
    const h = await stub(E).head(E, 0);
    expect(h).toMatchObject({ sealed: true, tLast: P.secOf(at(E, 3)) });
    expect(verifyChain(E, await feedAll(E))).toEqual(h.head);
  });
});

describe("ShardDO batches", () => {
  it("the head chain recomputed from feed() matches head(), also after eviction", async () => {
    const E = freshEra();
    const c0 = at(E, 100);
    await setClock(E, c0);
    const first = [row(0), row(1), row(3)];
    const t0 = await putOk(E, first);
    expect(t0).toBe(P.secOf(c0));
    expect((await stub(E).head(E, 0)).tLast).toBe(0); // nothing closed yet (tpub(now) = open_t)

    await setClock(E, c0 + 1000);
    const t1 = await putOk(E, [row(2), row(0)]); // t > open_t: closes batch t0
    expect(t1).toBe(t0 + 1);
    await setClock(E, c0 + 5000);
    const res = await put(E, [first[1], row(1)]);
    expect(res[0]).toEqual({ s: "conflict", t: t0, cls: 1, body: first[1].body });
    expect(res[1]).toEqual({ s: "ok", t: t0 + 5 });

    await setClock(E, c0 + 7000);
    const h = await stub(E).head(E, 0); // closes the due batch
    expect(h.tLast).toBe(t0 + 5);
    expect(h.sealed).toBe(false);
    expect(h.size).toBeGreaterThan(0);
    const batches = await feedAll(E);
    expect(batches.map((b) => [b.t, b.n])).toEqual([
      [t0, 3],
      [t0 + 1, 2],
      [t0 + 5, 1],
    ]);
    expect(verifyChain(E, batches)).toEqual(h.head);

    // Nothing is lost across a cold start, and the chain continues seamlessly.
    await evictDurableObject(stub(E));
    expect(await stub(E).head(E, 0)).toMatchObject({ head: h.head, tLast: h.tLast, sealed: false });
    expect(await feedAll(E)).toEqual(batches);
    await setClock(E, c0 + 9000);
    const r = row(2);
    await putOk(E, [r, row(0)]);
    await setClock(E, c0 + 12_000);
    const h2 = await stub(E).head(E, 0);
    expect(h2.tLast).toBe(t0 + 9);
    const all = await feedAll(E);
    expect(all).toHaveLength(4);
    expect(all.slice(0, 3)).toEqual(batches);
    expect(verifyChain(E, all)).toEqual(h2.head);
    expect(await stub(E).get(E, 0, [{ v: first[0].v, label: first[0].label, mode: 0 }])).toEqual([
      { s: "hit", t: t0, cls: 0, body: first[0].body },
    ]);
  });

  it("feed pages never split a batch and always hold at least one", async () => {
    const E = freshEra();
    for (let k = 0; k < 5; k++) {
      await setClock(E, at(E, 10 + k));
      await putOk(
        E,
        Array.from({ length: k + 1 }, (_, j) => row((k + j) % 4)),
      );
    }
    await setClock(E, at(E, 20));
    await stub(E).head(E, 0);
    const all = await feedAll(E, 1 << 30);
    expect(all.map((b) => b.n)).toEqual([1, 2, 3, 4, 5]);
    verifyChain(E, all);
    const withBytes = (bs: Batch[]) => bs.map((b) => ({ ...b, bytes: wireSize(b) }));
    const header = ({ t, n, root, head, rows }: Batch) => ({ t, n, root, head, bytes: wireSize({ rows }) });

    // budget 1: one whole batch per page, sent without its rows (they come from feedRows).
    expect(await feedAll(E, 1)).toEqual(all);
    const lone = await stub(E).feedBatches(E, 0, all[2].t, 1);
    expect(lone.batches).toEqual([header(all[3])]);
    expect(lone.more).toBe(true);

    // A budget of exactly two batches holds two (rows inline); one byte less holds one.
    const two = wireSize(all[0]) + wireSize(all[1]);
    const f2 = await stub(E).feedBatches(E, 0, 0, two);
    expect(f2).toEqual({ batches: withBytes(all.slice(0, 2)), more: true, sealed: false });
    const f1 = await stub(E).feedBatches(E, 0, 0, two - 1);
    expect(f1.batches).toEqual(withBytes(all.slice(0, 1)));
    expect(f1.more).toBe(true);
    // A page in the middle, and the empty tail.
    const mid = await stub(E).feedBatches(E, 0, all[1].t, wireSize(all[2]) + wireSize(all[3]));
    expect(mid.batches).toEqual(withBytes(all.slice(2, 4)));
    expect(await stub(E).feedBatches(E, 0, all[4].t, 1 << 20)).toEqual({ batches: [], more: false, sealed: false });
    // The open batch is never in the feed, and its rows cannot be read with feedRows.
    await setClock(E, at(E, 30));
    const open = await putOk(E, [row()]);
    expect(await feedAll(E)).toEqual(all);
    await runInDurableObject(stub(E), (inst: ShardDO) => {
      expect(() => inst.feedRows(E, 0, open, null, 1 << 20)).toThrow(/no closed batch/);
      expect(() => inst.feedRows(E, 0, all[0].t + 1000, null, 1 << 20)).toThrow(/no closed batch/);
    });
  });

  it("feedRows: label order after the cursor, at least one row, never past the budget otherwise", async () => {
    const E = freshEra();
    await setClock(E, at(E, 10));
    const put = Array.from({ length: 12 }, (_, k) => row(k % 4));
    const t = await putOk(E, put);
    await setClock(E, at(E, 12));
    expect((await stub(E).head(E, 0)).tLast).toBe(t);
    const [b] = await feedAll(E, 1 << 30);
    expect(b.n).toBe(12);
    const byLabel = [...put]
      .sort((x, y) => P.byteCmp(x.label, y.label))
      .map((r) => ({ label: r.label, cls: r.cls, body: r.body }));
    expect(b.rows).toEqual(byLabel);

    // Whatever the budget, paging returns every row once, in label order.
    const all = rowsBytes(byLabel);
    for (const budget of [1, 17 + P.BODY_LENS[0], 20_000, 40_000, all - 1, all, 1 << 30]) {
      expect(await rowsVia(E, t, budget), `budget ${budget}`).toEqual(byLabel);
    }
    // Exact budget boundaries: a budget of the first three rows holds three; one byte less holds two.
    const three = rowsBytes(byLabel.slice(0, 3));
    expect(await stub(E).feedRows(E, 0, t, null, three)).toEqual({ rows: byLabel.slice(0, 3), done: false });
    expect(await stub(E).feedRows(E, 0, t, null, three - 1)).toEqual({ rows: byLabel.slice(0, 2), done: false });
    // budget 1 still makes progress: one row per call.
    expect(await stub(E).feedRows(E, 0, t, byLabel[4].label, 1)).toEqual({ rows: [byLabel[5]], done: false });
    // The last row is done; past it there is nothing left.
    expect(await stub(E).feedRows(E, 0, t, byLabel[10].label, 1)).toEqual({ rows: [byLabel[11]], done: true });
    expect(await stub(E).feedRows(E, 0, t, byLabel[11].label, 1 << 20)).toEqual({ rows: [], done: true });
    expect(await stub(E).feedRows(E, 0, t, new Uint8Array(16).fill(0xff), 1 << 20)).toEqual({ rows: [], done: true });
    // A cursor between two labels (label 6 minus one, as a 128-bit number) starts at the next one.
    const between = byLabel[6].label.slice();
    for (let k = 15; k >= 0 && between[k]-- === 0; k--);
    expect((await stub(E).feedRows(E, 0, t, between, 1)).rows).toEqual([byLabel[6]]);
  });

  it("t never decreases when the clock steps back", async () => {
    const E = freshEra();
    const c = at(E, 500);
    const ts: number[] = [];
    for (const ms of [c, c - 5000, c + 3000, c - 10_000, c + 3000, c + 4000, c - 60_000]) {
      await setClock(E, ms);
      ts.push(await putOk(E, [row()]));
    }
    const s = P.secOf(c);
    expect(ts).toEqual([s, s, s + 3, s + 3, s + 3, s + 4, s + 4]);
    await setClock(E, c + 10_000);
    const h = await stub(E).head(E, 0);
    const batches = await feedAll(E);
    expect(batches.map((b) => [b.t, b.n])).toEqual([
      [s, 2],
      [s + 3, 3],
      [s + 4, 2],
    ]);
    expect(verifyChain(E, batches)).toEqual(h.head);
  });

  it("IMP-7: after the alarm closed a batch, a put with the clock stepped back by SKEW gets t = closed_t + Δ", async () => {
    const E = freshEra();
    const c = at(E, 1000);
    await setClock(E, c, 2);
    const t1 = await putOk(E, [row()]);
    expect(await alarmOf(E)).toBe(batchDue(t1)); // T0 + (open_t + Δ)·1000 + 1000
    expect(batchDue(t1)).toBe(c + 2000);

    await setClock(E, c + 2000);
    expect(await runDurableObjectAlarm(stub(E))).toBe(true);
    await runInDurableObject(stub(E), (_inst: ShardDO, state) => {
      expect(metaOf(state, "closed_t")).toBe(t1);
      expect(metaOf(state, "open_t")).toBeNull();
    });

    await setClock(E, c + 2000 - 2000); // stepped back by SKEW
    const t2 = await putOk(E, [row(), row()]);
    expect(t2).toBe(t1 + DELTA);
    expect(await putOk(E, [row()])).toBe(t2); // joins the open batch
    await setClock(E, c + 5000);
    const h = await stub(E).head(E, 0);
    const batches = await feedAll(E);
    expect(batches.map((b) => [b.t, b.n])).toEqual([
      [t1, 1],
      [t2, 3],
    ]);
    expect(verifyChain(E, batches)).toEqual(h.head);
  });

  it("an alarm that fires before the batch is due only re-arms", async () => {
    const E = freshEra();
    const c = at(E, 40);
    await setClock(E, c);
    const t = await putOk(E, [row()]);
    expect(await runDurableObjectAlarm(stub(E))).toBe(true); // clock still at c: tpub(now) = open_t
    expect(await alarmOf(E)).toBe(batchDue(t));
    expect((await stub(E).head(E, 0)).tLast).toBe(0);
  });

  it("the feed never closes a due batch: feedBatches and feedRows leave it open until head() closes it", async () => {
    const E = freshEra();
    const c = at(E, 200);
    await setClock(E, c);
    const t = await putOk(E, [row(0), row(3), row(1)]);
    await setClock(E, c + 5000); // tpub(now) > open_t: the batch is due, and its alarm has not run
    for (let k = 0; k < 2; k++) {
      expect(await stub(E).feedBatches(E, 0, 0, 1 << 30)).toEqual({ batches: [], more: false, sealed: false });
      expect(await stub(E).feedBatches(E, 0, 0, 1)).toEqual({ batches: [], more: false, sealed: false });
      await runInDurableObject(stub(E), (inst: ShardDO, state) => {
        expect(() => inst.feedRows(E, 0, t, null, 1 << 20)).toThrow(/no closed batch/);
        expect(metaOf(state, "open_t")).toBe(t);
        expect(metaOf(state, "closed_t")).toBeNull();
        expect(state.storage.sql.exec("SELECT count(*) AS n FROM batch").one().n).toBe(0);
      });
    }
    // head() closes the due batch first, so every head it reports is in the feed's chain.
    const h = await stub(E).head(E, 0);
    expect(h.tLast).toBe(t);
    const batches = await feedAll(E);
    expect(batches.map((b) => [b.t, b.n])).toEqual([[t, 3]]);
    expect(verifyChain(E, batches)).toEqual(h.head);
    expect(await feedAll(E, 1)).toEqual(batches); // the same rows through feedRows chunks
  });
});

describe("ShardDO era window", () => {
  it("accepts from start(E) − SKEW with t = sec(start(E)), and refuses before", async () => {
    const SKEW = 2;
    const E = freshEra();
    await setClock(E, P.eraStart(E) - SKEW * 1000 + 1, SKEW);
    expect(await putOk(E, [row()])).toBe(P.secOf(P.eraStart(E)));

    const E2 = freshEra();
    await setClock(E2, P.eraStart(E2) - SKEW * 1000, SKEW);
    expect(await putOk(E2, [row()])).toBe(P.secOf(P.eraStart(E2)));

    const E3 = freshEra();
    await setClock(E3, P.eraStart(E3) - SKEW * 1000 - 1, SKEW);
    expect(await put(E3, [row()])).toEqual([{ s: "wrong_era", era: E3 - 1 }]);
  });

  it("two shards whose clocks differ by at most SKEW never both refuse a write at the boundary", async () => {
    const SKEW = 2;
    const offsets = [-3000, -2000, -1, 0, 1, 2000, 3000];
    const pairs: [number, number][] = [
      [-1000, 1000],
      [1000, -1000],
      [0, 0],
      [-2000, 0],
      [0, -2000],
    ];
    for (const x of offsets) {
      for (const [da, db] of pairs) {
        const A = nextEra;
        const B = A + 1;
        nextEra += 2;
        const boundary = P.eraStart(B) + x; // true time
        await setClock(A, boundary + da, SKEW);
        await setClock(B, boundary + db, SKEW);
        const ra = (await put(A, [row()]))[0];
        const rb = (await put(B, [row()]))[0];
        expect(ra.s === "ok" || rb.s === "ok", `x=${x} da=${da} db=${db}`).toBe(true);
        if (rb.s === "ok") expect(rb.t).toBeGreaterThanOrEqual(P.secOf(P.eraStart(B)));
      }
    }
  });
});

describe("ShardDO identity and alarms", () => {
  it("takes (E, i) from its name: a mismatched E or i is a programming error", async () => {
    const E = freshEra();
    await runInDurableObject(stub(E), async (inst: ShardDO) => {
      await expect(inst.put(E + 1, 0, [])).rejects.toThrow();
      await expect(inst.put(E, 1, [])).rejects.toThrow();
      expect(() => inst.get(E - 1, 0, [])).toThrow();
      expect(() => inst.head(E, 1)).toThrow();
      expect(() => inst.feedBatches(E + 1, 0, 0, 1)).toThrow();
      expect(() => inst.feedBatches(E, 0, -1, 1)).toThrow(RangeError);
      expect(() => inst.feedBatches(E, 0, 0, 0)).toThrow(RangeError);
      expect(() => inst.feedRows(E, 1, 0, null, 1)).toThrow();
      expect(() => inst.feedRows(E, 0, -1, null, 1)).toThrow(RangeError);
      expect(() => inst.feedRows(E, 0, 0, P.random(15), 1)).toThrow(RangeError);
      expect(() => inst.feedRows(E, 0, 0, null, 0)).toThrow(RangeError);
      expect(await inst.put(E, 0, [])).toEqual([]);
    });
  });

  it("the constructor arms min(getAlarm(), due) unless the era has ended", async () => {
    // A fresh object of a running (here: future) era arms its seal alarm.
    const E = freshEra();
    expect(await alarmOf(E)).toBe(P.eraEnd(E));

    // A write arms the earlier batch alarm in the same block as the commit.
    const c = at(E, 77);
    await setClock(E, c);
    const t = await putOk(E, [row()]);
    expect(await alarmOf(E)).toBe(batchDue(t));

    // A wake keeps an earlier alarm…
    const earlier = batchDue(t) - 500;
    await runInDurableObject(stub(E), (_inst: ShardDO, state) => state.storage.setAlarm(earlier));
    await evictDurableObject(stub(E));
    expect(await alarmOf(E)).toBe(earlier);

    // …and re-arms the pending batch alarm when none is set.
    await runInDurableObject(stub(E), (_inst: ShardDO, state) => state.storage.deleteAlarm());
    await evictDurableObject(stub(E));
    expect(await alarmOf(E)).toBe(batchDue(t));

    // An object of an ended era arms nothing.
    expect(await alarmOf(E_NOW - 3)).toBeNull();
  });

  it("a DO of an era that has already ended arms no alarm in its constructor and seals in prepare() (CMP-18)", async () => {
    // The constructor runs before a test can reach the object: spy on setAlarm of every storage in the isolate.
    const proto = await runInDurableObject(stub(freshEra()), (_inst: ShardDO, state) => Object.getPrototypeOf(state.storage));
    const setAlarm = vi.spyOn(proto as DurableObjectStorage, "setAlarm");
    const stateOf = (E: number) => runInDurableObject(stub(E), (_inst: ShardDO, state) => metaOf(state, "state"));
    try {
      // The spy sees the constructor of a running era arm its seal alarm …
      const live = freshEra();
      expect(await alarmOf(live)).toBe(P.eraEnd(live));
      expect(setAlarm.mock.calls.map((c) => c[0])).toEqual([P.eraEnd(live)]);
      setAlarm.mockClear();

      // … and nothing from an ended era: neither its constructor nor prepare(), which seals on the first RPC.
      const E = E_NOW - 5;
      expect(await alarmOf(E)).toBeNull();
      expect(await stateOf(E)).toBeNull(); // the constructor persisted nothing either
      expect(await stub(E).get(E, 0, [{ v: P.random(8), label: P.random(16), mode: 1 }])).toEqual([
        { s: "miss", sealed: true },
      ]);
      expect(await stateOf(E)).toBe("sealed");
      expect(await stub(E).head(E, 0)).toMatchObject({ head: P.ZERO32, tLast: 0, sealed: true });
      await evictDurableObject(stub(E));
      expect(await alarmOf(E)).toBeNull();
      expect(setAlarm).not.toHaveBeenCalled();
    } finally {
      setAlarm.mockRestore();
    }
  });

  it("keeps the pinned Δ when the deployment Δ changes, and logs the mismatch exactly once per instance", async () => {
    const E = freshEra();
    const c = at(E, 1000);
    const s = P.secOf(c);
    expect(s % 10).toBe(0); // sec(start(E)) is a multiple of every Δ that divides 604 800
    /** Runs the object with its clock at `ms` under a deployment Δ of `delta`. */
    const deploy = (ms: number, delta: number) =>
      runInDurableObject(stub(E), (inst: ShardDO) => {
        internals(inst).clock = () => ms;
        internals(inst).params = { ...internals(inst).params, delta };
      });
    const pinned = () => runInDurableObject(stub(E), (_inst: ShardDO, state) => metaOf(state, "delta"));

    // The first put pins the deployment Δ = 10.
    await deploy(c, 10);
    expect(await pinned()).toBeNull();
    expect(await putOk(E, [row()])).toBe(s);
    expect(await pinned()).toBe(10);

    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const logged = () => errors.mock.calls.filter((x) => String(x[0]).includes("pinned delta"));
    try {
      // The deployment now says Δ = 1: t, closing a batch and the batch alarm keep the pinned Δ = 10.
      await deploy(c + 13_500, DELTA);
      const t1 = await putOk(E, [row()]);
      expect(t1).toBe(s + 10); // tpub under Δ = 10 (Δ = 1 would give s + 13); it closed batch s
      await deploy(c + 19_999, DELTA);
      expect((await stub(E).head(E, 0)).tLast).toBe(s); // tpub(now) = s + 10 = open_t under Δ = 10: still open
      await deploy(c + 20_000, DELTA);
      expect((await stub(E).head(E, 0)).tLast).toBe(t1);
      expect(await pinned()).toBe(10);
      expect(logged()).toHaveLength(1); // once per instance, however many calls
      expect(JSON.parse(String(logged()[0][0]))).toEqual({ msg: expect.any(String), E, pinned: 10, env: DELTA });

      // A new instance (Δ = 1 from the env) keeps Δ = 10 for t and for the batch alarm it re-arms, and logs once.
      await evictDurableObject(stub(E));
      await setClock(E, c + 25_000);
      const t2 = await putOk(E, [row()]);
      expect(t2).toBe(s + 20); // closed_t + 10 (Δ = 1 would give s + 25)
      expect(logged()).toHaveLength(2);
      await runInDurableObject(stub(E), (_inst: ShardDO, state) => state.storage.deleteAlarm());
      await evictDurableObject(stub(E));
      expect(await alarmOf(E)).toBe(P.T0_MS + (t2 + 10) * 1000 + 1000);
      expect(logged()).toHaveLength(3);
      expect(await pinned()).toBe(10);
    } finally {
      errors.mockRestore();
    }
  });
});

describe("ShardDO batches of thousands of rows", () => {
  it("leafShardFromHash over H(body) is byte-identical to proto.leafShard", () => {
    for (const cls of [0, 1, 2, 3]) {
      for (const [E, t] of [
        [0, 0],
        [1, 1],
        [4242, 2_000_000],
        [0xfffe, 0xffffffff],
      ]) {
        const label = P.random(16);
        const body = P.random(P.BODY_LENS[cls]);
        expect(leafShardFromHash(E, label, t, cls, P.H(body))).toEqual(P.leafShard(E, label, t, cls, body));
      }
    }
  });

  it("head(), the alarm and sealing close them without reading a body; the chain recomputes from the feed", async () => {
    const E = freshEra();
    const N = 2000;
    const PER_PUT = 500;
    async function fill(ms: number): Promise<number> {
      await setClock(E, ms);
      let t = -1;
      for (let k = 0; k < N; k += PER_PUT) {
        t = await putOk(E, Array.from({ length: PER_PUT }, (_, j) => row((k + j) % 4)));
      }
      return t;
    }
    // Records every SQL statement of the object (its one SqlStorage, shared by meta and the batch chain).
    const log: string[] = [];
    await runInDurableObject(stub(E), (inst: ShardDO) => {
      const sql = (inst as unknown as { sql: SqlStorage }).sql;
      const exec = sql.exec.bind(sql);
      const spy = (q: string, ...b: SqlStorageValue[]) => (log.push(q), exec(q, ...b));
      Object.defineProperty(sql, "exec", { configurable: true, writable: true, value: spy });
    });
    async function closing(what: string, op: () => Promise<unknown>): Promise<void> {
      log.length = 0;
      await op();
      expect(log.filter((q) => /\bbody\b/.test(q)), `${what} read no body`).toEqual([]);
      expect(log.some((q) => /SELECT label, cls, bh FROM row/.test(q)), `${what} closed a batch`).toBe(true);
    }

    // A batch closed by head() …
    const c = at(E, 100);
    const t1 = await fill(c);
    await setClock(E, c + 2000);
    await closing("head()", async () => expect((await stub(E).head(E, 0)).tLast).toBe(t1));
    // … one closed by the batch alarm …
    const t2 = await fill(c + 10_000);
    await setClock(E, batchDue(t2));
    await closing("the alarm", async () => expect(await runDurableObjectAlarm(stub(E))).toBe(true));
    expect((await stub(E).head(E, 0)).tLast).toBe(t2);
    // … and one closed by sealing.
    const t3 = await fill(P.eraEnd(E) - 1000);
    await setClock(E, P.eraEnd(E));
    await closing("sealing", async () => expect(await stub(E).head(E, 0)).toMatchObject({ sealed: true, tLast: t3 }));

    const h = await stub(E).head(E, 0);
    const batches = await feedAll(E); // 4 MiB pages: every batch is larger, so its rows come through feedRows
    expect(batches.map((b) => [b.t, b.n])).toEqual([
      [t1, N],
      [t2, N],
      [t3, N],
    ]);
    expect(verifyChain(E, batches)).toEqual(h.head);
  }, 120_000);
});
