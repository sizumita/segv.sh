/** InboxDO (docs/PROTOCOL-v2.md §9.3): slot clock, Δin pin, closed_hw, era end, posts, paging, slot commitments. */
import { evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import * as P from "../../src/lib/proto";
import { INBOX_DAY_CAP } from "../../src/server/env";
import type { InboxDO } from "../../src/server/inbox-do";
import { inboxStub, type InboxHead, type InboxPostOut, type InboxReadOut } from "../../src/server/types";

/** Δin = INBOX_SLOT_S = 1 s and SKEW = 0 in ../wrangler.test.jsonc. */
const D = 1000;
const E_NOW = P.era(Date.now());
const DAY_MS = 86_400_000;

/** The RPC methods plus the protected / private fields the tests drive. */
type Inner = Pick<InboxDO, "post" | "read" | "head"> & {
  clock: () => number;
  jitter: (D: number) => number;
  skewMs: number;
  inboxSlot: number;
  dayCap: number;
};

/** Unix ms at the start of slot `s` (slot = ⌊(ms − T0)/D⌋) plus `off` ms. */
const atSlot = (s: number, off = 0): number => P.T0_MS + s * D + off;
const slotOf = (ms: number): number => Math.floor((ms - P.T0_MS) / D);

const invite = () => ({ eid: P.random(16), body: P.random(P.INBOX_BODY_LEN) });
const invites = (n: number) => Array.from({ length: n }, invite);

let gNext = 1 + Math.floor(Math.random() * 50_000);

/** A fresh InboxDO ("inbox/v2/{E}/{g}" with an unused g) and helpers that run calls at a chosen time. */
function box(E = E_NOW) {
  const g = gNext++;
  const stub = inboxStub(env, E, g);
  /** Runs `fn` inside the object with the clock at `now` (and the jitter fixed at `j` when given). */
  const at = <R>(now: number, fn: (inst: Inner, state: DurableObjectState) => R | Promise<R>, j?: number) =>
    runInDurableObject(stub, async (inst: InboxDO, state) => {
      const x = inst as unknown as Inner;
      x.clock = () => now;
      if (j !== undefined) x.jitter = () => j;
      return fn(x, state);
    });
  return {
    E,
    g,
    stub,
    at,
    post: (now: number, rows: { eid: Uint8Array; body: Uint8Array }[], j = 0, bucket = 0): Promise<InboxPostOut> =>
      at(now, (i) => i.post(E, g, bucket, rows), j),
    read: (now: number, after = 0, limit = 1024): Promise<InboxReadOut> => at(now, (i) => i.read(E, g, 0, after, limit)),
    head: (now: number): Promise<InboxHead> => at(now, (i) => i.head(E, g)),
    meta: (k: string) =>
      runInDurableObject(
        stub,
        (_i: InboxDO, state) => state.storage.sql.exec<{ v: number }>("SELECT v FROM meta WHERE k = ?", k).toArray()[0]?.v,
      ),
  };
}

const rels = (out: InboxPostOut): (number | string)[] => {
  if (out.s !== "ok") throw new Error(`expected ok, got ${JSON.stringify(out)}`);
  return out.results.map((r) => ("rel" in r ? r.rel : r.error));
};

/** A time well inside era E (one hour after its start), on an exact slot boundary. */
const inside = (E = E_NOW): number => P.eraStart(E) + 3_600_000;

describe("InboxDO slot clock", () => {
  it("rel and closed with fixed jitter: a row is invisible until its slot closes", async () => {
    const b = box();
    const S = slotOf(inside());
    const now = atSlot(S, 400);
    // rel = ⌊(ms + j)/D⌋ + 1
    expect(rels(await b.post(now, [invite()], 700))).toEqual([S + 2]);
    expect(rels(await b.post(now, [invite()], 599))).toEqual([S + 1]);

    let r = await b.read(now);
    expect(r.closed).toBe(S); // ⌊ms/D⌋
    expect(r.rows).toEqual([]);
    r = await b.read(atSlot(S + 1, 999));
    expect(r.closed).toBe(S + 1);
    expect(r.rows.map((x) => x.rel)).toEqual([S + 1]);
    r = await b.read(atSlot(S + 2));
    expect(r.closed).toBe(S + 2);
    expect(r.rows.map((x) => x.rel)).toEqual([S + 1, S + 2]);
    expect(r.more).toBe(false);
    expect(r.ended).toBe(false);
  });

  it("a post at an exact slot boundary with j = 0 gets rel = closed + 1", async () => {
    const b = box();
    const S = slotOf(inside());
    const now = atSlot(S);
    const r = await b.read(now);
    expect(r.closed).toBe(S);
    expect(rels(await b.post(now, [invite()], 0))).toEqual([r.closed + 1]);
    expect(rels(await b.post(now, [invite()], D - 1))).toEqual([r.closed + 1]);
    // With the clock one millisecond back, closed stays S (closed_hw) instead of S − 1.
    expect((await b.read(now - 1)).closed).toBe(S);
  });

  it("after a read reported closed = c, a restart with the clock stepped back still gives rel > c", async () => {
    const b = box();
    const S = slotOf(inside());
    const t = atSlot(S, 500);
    expect((await b.read(t)).closed).toBe(S);
    expect(await b.meta("closed_hw")).toBe(S);

    await evictDurableObject(b.stub);
    const back = t - 5_000;
    expect(rels(await b.post(back, [invite()], 0))).toEqual([S + 1]); // not ⌊ms/D⌋ + 1 = S − 4
    const r = await b.read(back);
    expect(r.closed).toBe(S); // still the high-water mark
    expect(r.rows).toEqual([]); // and the new row is not inside it
    expect((await b.read(atSlot(S + 1))).rows.map((x) => x.rel)).toEqual([S + 1]);
  });

  it("persists closed_hw at most once per slot", async () => {
    const b = box();
    const S = slotOf(inside());
    const writes = async (now: number) =>
      b.at(now, (inst) => {
        const storage = (inst as unknown as { ctx: DurableObjectState }).ctx.storage;
        const spy = vi.spyOn(storage, "transactionSync");
        try {
          inst.read(b.E, b.g, 0, 0, 10);
          inst.head(b.E, b.g);
          return spy.mock.calls.length;
        } finally {
          spy.mockRestore();
        }
      });
    expect(await writes(atSlot(S, 10))).toBe(1);
    expect(await writes(atSlot(S, 500))).toBe(0);
    expect(await writes(atSlot(S, 999))).toBe(0);
    expect(await writes(atSlot(S + 1, 0))).toBe(1);
    expect(await b.meta("closed_hw")).toBe(S + 1);
  });

  it("Δin is pinned by the era's first write; a later INBOX_SLOT_S is logged once and ignored for the era", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      /** Runs `fn` as a redeploy with INBOX_SLOT_S = `slot` would. */
      const deployed = <R>(bx: ReturnType<typeof box>, slot: number, now: number, fn: (inst: Inner) => R, j?: number) =>
        bx.at(
          now,
          (inst) => {
            inst.inboxSlot = slot;
            return fn(inst);
          },
          j,
        );
      const S = slotOf(inside());
      const t = atSlot(S, 500);

      // Pinned by the first persisted closed_hw.
      const b = box();
      expect((await b.read(t)).closed).toBe(S);
      expect(await b.meta("slot")).toBe(1);
      // A redeploy raises Δin to 3 s: closed_hw and rel stay in 1 s slots, so the new row closes a slot later.
      await evictDurableObject(b.stub);
      expect(rels(await deployed(b, 3, t + 1_000, (i) => i.post(b.E, b.g, 0, [invite()]), 0))).toEqual([S + 2]);
      let r = await deployed(b, 3, t + 2_000, (i) => i.read(b.E, b.g, 0, 0, 10));
      expect(r.closed).toBe(S + 2);
      expect(r.rows.map((x) => x.rel)).toEqual([S + 2]);
      expect(await b.meta("slot")).toBe(1);
      expect(errors).toHaveBeenCalledTimes(1); // once per instance, however many calls
      expect(JSON.parse(errors.mock.calls[0][0] as string)).toMatchObject({ E: b.E, pinned: 1, deployed: 3 });

      // Pinned by the first post (no read yet).
      const c = box();
      expect(rels(await c.post(t, [invite()], 0))).toEqual([S + 1]);
      expect(await c.meta("slot")).toBe(1);
      await evictDurableObject(c.stub);
      r = await deployed(c, 3, t + 1_000, (i) => i.read(c.E, c.g, 0, 0, 10));
      expect(r.closed).toBe(S + 1);
      expect(r.rows.map((x) => x.rel)).toEqual([S + 1]);

      // Before any write the deployment value applies, and the first write pins it.
      const d = box();
      r = await deployed(d, 3, t, (i) => i.read(d.E, d.g, 0, 0, 10));
      expect(r.closed).toBe(Math.floor((t - P.T0_MS) / 3_000));
      expect(await d.meta("slot")).toBe(3);
      await evictDurableObject(d.stub); // back to INBOX_SLOT_S = 1
      expect((await d.read(t + 3_000)).closed).toBe(Math.floor((t + 3_000 - P.T0_MS) / 3_000));
      expect(errors).toHaveBeenCalledTimes(3);
    } finally {
      errors.mockRestore();
    }
  });
});

describe("InboxDO posts", () => {
  it("a post of 32 invites returns 32 results; the day cap turns rows past it into full", async () => {
    const b = box();
    const now = inside();
    const out = rels(await b.post(now, invites(32), 0));
    expect(out).toHaveLength(32);
    expect(out.every((r) => r === slotOf(now) + 1)).toBe(true);
    const day = Math.floor(P.secOf(now) / 86_400);
    const count = (bb: ReturnType<typeof box>) =>
      runInDurableObject(
        bb.stub,
        (_i: InboxDO, s) => s.storage.sql.exec<{ n: number }>("SELECT n FROM cnt WHERE bucket = 0 AND day = ?", day).one().n,
      );
    expect(await count(b)).toBe(32);

    // Another inbox whose day count is 10 below the cap.
    const c = box();
    await c.post(now, invites(1), 0);
    await runInDurableObject(c.stub, (_i: InboxDO, s) => {
      s.storage.sql.exec("UPDATE cnt SET n = ? WHERE bucket = 0 AND day = ?", INBOX_DAY_CAP - 10, day);
    });
    const rows = invites(32);
    const res = rels(await c.post(now, rows, 0));
    expect(res.slice(0, 10).every((r) => typeof r === "number")).toBe(true);
    expect(res.slice(10)).toEqual(Array(22).fill("full"));
    expect(await count(c)).toBe(INBOX_DAY_CAP);
    // An idempotent retry of an accepted row still answers its rel; a refused row stays refused.
    expect(rels(await c.post(now + 2_000, [rows[0], rows[31]], 0))).toEqual([res[0], "full"]);
    // Rows refused as full are not stored.
    expect((await c.read(now + 10_000)).rows).toHaveLength(11);
    // The cap is per day (⌊sec/86400⌋ since T0).
    const nextDay = P.T0_MS + (day + 1) * DAY_MS;
    expect(rels(await c.post(nextDay, [rows[31]], 0))).toEqual([slotOf(nextDay) + 1]);
  });

  it("an eid-idempotent retry returns the original rel; a duplicate inside one post too", async () => {
    const b = box();
    const now = inside();
    const x = invite();
    const [r1] = rels(await b.post(now, [x], 300));
    expect(rels(await b.post(now + 5_000, [x], D - 1))).toEqual([r1]);
    const y = invite();
    expect(rels(await b.post(now, [y, y], 0))).toEqual([slotOf(now) + 1, slotOf(now) + 1]);
    const r = await b.read(now + 20_000);
    expect(r.rows).toHaveLength(2);
    const day = Math.floor(P.secOf(now) / 86_400);
    const n = await runInDurableObject(b.stub, (_i: InboxDO, s) =>
      s.storage.sql.exec<{ n: number }>("SELECT n FROM cnt WHERE bucket = 0 AND day = ?", day).one().n,
    );
    expect(n).toBe(2);
  });

  it("a reused eid with another body is a conflict; the stored row is unchanged", async () => {
    const b = box();
    const now = inside();
    const x = invite();
    const [r1] = rels(await b.post(now, [x], 0));
    const other = { eid: x.eid, body: P.random(P.INBOX_BODY_LEN) };
    const z = invite();
    expect(rels(await b.post(now, [other, z], 0))).toEqual(["conflict", r1]);
    const rows = (await b.read(now + 10_000)).rows;
    const got = rows.find((r) => P.equalBytes(r.eid, x.eid))!;
    expect(P.equalBytes(got.body, x.body)).toBe(true);
    expect(rows).toHaveLength(2);
  });

  it("WRONG_ERA for the whole call outside start(E) − SKEW ≤ now < end(E)", async () => {
    const b = box();
    const E = b.E;
    expect(await b.post(P.eraStart(E) - 1, invites(3))).toEqual({ s: "wrong_era", era: E - 1 });
    expect(rels(await b.post(P.eraStart(E), invites(1)))).toEqual([slotOf(P.eraStart(E)) + 1]);
    expect(rels(await b.post(P.eraEnd(E) - 1, invites(1)))).toHaveLength(1);
    expect(await b.post(P.eraEnd(E), invites(3))).toEqual({ s: "wrong_era", era: E + 1 });
    // Nothing refused was stored.
    expect((await b.read(P.eraEnd(E))).rows).toHaveLength(2);

    // With SKEW = 2 s the window opens 2 s early (and still closes at end(E)).
    const c = box();
    const early = async (now: number) =>
      c.at(
        now,
        (inst) => {
          inst.skewMs = 2_000;
          return inst.post(c.E, c.g, 0, invites(1));
        },
        0,
      );
    // IMP-9: start(E) − SKEW·1000 − 1 is refused; start(E) − SKEW·1000 and + 1 are accepted.
    expect(await early(P.eraStart(E) - 2_001)).toEqual({ s: "wrong_era", era: E - 1 });
    expect(rels(await early(P.eraStart(E) - 2_000))).toEqual([slotOf(P.eraStart(E) - 2_000) + 1]);
    expect(rels(await early(P.eraStart(E) - 1_999))).toEqual([slotOf(P.eraStart(E) - 1_999) + 1]);
    expect(await early(P.eraEnd(E) + 1_000)).toEqual({ s: "wrong_era", era: E + 1 });
  });

  it("posts in the SKEW window before start(E) count against the era's first day: at most 7 day caps per era", async () => {
    const b = box(E_NOW + 1); // a future era: only the object's clock matters
    const cap = 3;
    const start = P.eraStart(b.E);
    const accepted = async (now: number, n: number): Promise<number> => {
      const out = await b.at(
        now,
        (inst) => {
          inst.skewMs = 2_000;
          inst.dayCap = cap;
          return inst.post(b.E, b.g, 0, invites(n));
        },
        0,
      );
      return rels(out).filter((r) => typeof r === "number").length;
    };
    let total = await accepted(start - 1_000, cap + 1);
    expect(total).toBe(cap);
    const perDay: number[] = [];
    for (let d = 0; d < 7; d++) perDay.push(await accepted(start + d * DAY_MS + 1_000, cap + 1));
    expect(perDay).toEqual([0, cap, cap, cap, cap, cap, cap]); // the pre-start rows used up the first day
    total += perDay.reduce((x, y) => x + y, 0);
    expect(total).toBe(7 * cap);
    const firstDay = P.secOf(start) / 86_400;
    const cnt = await runInDurableObject(b.stub, (_i: InboxDO, s) =>
      s.storage.sql.exec<{ day: number; n: number }>("SELECT day, n FROM cnt WHERE bucket = 0 ORDER BY day").toArray(),
    );
    expect(cnt).toEqual(Array.from({ length: 7 }, (_, d) => ({ day: firstDay + d, n: cap })));
    expect((await b.read(P.eraEnd(b.E) - 1)).rows).toHaveLength(7 * cap);
  });

  it("rejects bad input and a mismatched (E, g)", async () => {
    const b = box();
    await b.at(inside(), (inst) => {
      expect(() => inst.post(b.E + 1, b.g, 0, invites(1))).toThrow(/does not match/);
      expect(() => inst.read(b.E, b.g + 1, 0, 0, 10)).toThrow(/does not match/);
      expect(() => inst.head(b.E + 1, b.g)).toThrow(/does not match/);
      expect(() => inst.post(b.E, b.g, 0, [])).toThrow(TypeError);
      expect(() => inst.post(b.E, b.g, 0, invites(33))).toThrow(TypeError);
      expect(() => inst.post(b.E, b.g, 0, [{ eid: P.random(15), body: P.random(P.INBOX_BODY_LEN) }])).toThrow(TypeError);
      expect(() => inst.post(b.E, b.g, 0, [{ eid: P.random(16), body: P.random(P.INBOX_BODY_LEN - 1) }])).toThrow(TypeError);
      expect(() => inst.post(b.E, b.g, -1, invites(1))).toThrow(TypeError);
      expect(() => inst.read(b.E, b.g, 0, -1, 10)).toThrow(RangeError);
      expect(() => inst.read(b.E, b.g, 0, 0, 0)).toThrow(RangeError);
      expect(() => inst.read(b.E, b.g, 0, 0, 1025)).toThrow(RangeError);
    });
  });

  it("works over RPC (structured clone of the rows)", async () => {
    const b = box(E_NOW + 1); // a future era: only the object's clock matters
    const now = inside(b.E);
    await b.at(now, () => undefined, 250);
    const rows = invites(2);
    const out = await b.stub.post(b.E, b.g, 0, rows);
    expect(rels(out)).toEqual([slotOf(now) + 1, slotOf(now) + 1]);
    await b.at(now + 3_000, () => undefined);
    const r = await b.stub.read(b.E, b.g, 0, 0, 10);
    expect(r.rows.map((x) => P.b64u(x.eid)).sort()).toEqual(rows.map((x) => P.b64u(x.eid)).sort());
    expect(r.rows.every((x) => x.body.length === P.INBOX_BODY_LEN)).toBe(true);
  });
});

describe("InboxDO reads", () => {
  it("returns whole rel groups; stops before the next group once limit rows are in", async () => {
    const b = box();
    const S = slotOf(inside());
    const A = invites(3);
    const B = invites(4);
    const C = invites(2);
    expect(rels(await b.post(atSlot(S), A, 0))).toEqual([S + 1, S + 1, S + 1]);
    expect(rels(await b.post(atSlot(S + 1), B, 0))).toEqual(Array(4).fill(S + 2));
    expect(rels(await b.post(atSlot(S + 2), C, 0))).toEqual(Array(2).fill(S + 3));
    const now = atSlot(S + 5);
    const page = async (after: number, limit: number) => {
      const r = await b.read(now, after, limit);
      expect(r.closed).toBe(S + 5);
      return { rels: r.rows.map((x) => x.rel), more: r.more, rows: r.rows };
    };
    expect(await page(0, 1)).toMatchObject({ rels: Array(3).fill(S + 1), more: true });
    expect(await page(0, 3)).toMatchObject({ rels: Array(3).fill(S + 1), more: true });
    expect(await page(0, 4)).toMatchObject({ rels: [...Array(3).fill(S + 1), ...Array(4).fill(S + 2)], more: true });
    expect(await page(S + 1, 5)).toMatchObject({ rels: [...Array(4).fill(S + 2), ...Array(2).fill(S + 3)], more: false });
    expect(await page(S + 3, 5)).toMatchObject({ rels: [], more: false });
    // Ordered by (rel, eid).
    const all = await page(0, 1024);
    expect(all.more).toBe(false);
    const sorted = [...all.rows].sort((x, y) => x.rel - y.rel || P.byteCmp(x.eid, y.eid));
    expect(all.rows.map((x) => P.b64u(x.eid))).toEqual(sorted.map((x) => P.b64u(x.eid)));
    // A group larger than limit is still returned whole.
    expect((await page(S + 1, 1)).rels).toEqual(Array(4).fill(S + 2));
  });
});

describe("InboxDO era end", () => {
  it("the constructor arms the seal alarm at end(E) + SKEW; an ended era arms nothing and seals in prepare()", async () => {
    const b = box();
    await b.read(Date.now());
    expect(await runInDurableObject(b.stub, (_i: InboxDO, s) => s.storage.getAlarm())).toBe(P.eraEnd(b.E));

    const old = box(E_NOW - 2);
    const alarm = await runInDurableObject(old.stub, (_i: InboxDO, s) => s.storage.getAlarm());
    expect(alarm).toBeNull();
    expect(await old.meta("ended")).toBeUndefined();
    const r = await runInDurableObject(old.stub, (inst: InboxDO) => inst.read(old.E, old.g, 0, 0, 10)); // real clock
    expect(r.ended).toBe(true);
    expect(r.closed).toBe(0); // no rows and nothing ever reported: closed_hw = 0
    expect(await old.meta("ended")).toBe(1);
  });

  it("ended is persisted at end(E) + SKEW; later posts get WRONG_ERA; the final closed is max(largest rel, closed_hw)", async () => {
    const b = box();
    const end = P.eraEnd(b.E);
    const Send = slotOf(end);
    // j = D − 1 one millisecond before the end lands two slots past the last closed one.
    expect(rels(await b.post(end - 1, [invite()], D - 1))).toEqual([Send + 1]);
    expect(rels(await b.post(end - 1_500, [invite()], 0))).toEqual([Send - 1]);
    let r = await b.read(end - 1);
    expect(r).toMatchObject({ closed: Send - 1, ended: false });
    expect(r.rows.map((x) => x.rel)).toEqual([Send - 1]);

    // The alarm (due at end(E) + SKEW = end(E) in tests) persists `ended`.
    await b.at(end, () => undefined);
    expect(await runDurableObjectAlarm(b.stub)).toBe(true);
    expect(await b.meta("ended")).toBe(1);
    expect(await runInDurableObject(b.stub, (_i: InboxDO, s) => s.storage.getAlarm())).toBeNull();

    // Posts are refused from now on, even with the clock stepped back into the era.
    expect(await b.post(end, [invite()])).toEqual({ s: "wrong_era", era: b.E + 1 });
    expect(await b.post(end - 10, [invite()])).toEqual({ s: "wrong_era", era: b.E });

    // closed = max(largest rel, closed_hw) (here the largest rel), whatever the clock says, also after a restart.
    r = await b.read(end, Send - 1);
    expect(r).toMatchObject({ closed: Send + 1, ended: true, more: false });
    expect(r.rows.map((x) => x.rel)).toEqual([Send + 1]);
    await evictDurableObject(b.stub);
    r = await b.read(end + 3 * DAY_MS, 0);
    expect(r).toMatchObject({ closed: Send + 1, ended: true, more: false });
    expect(r.rows.map((x) => x.rel)).toEqual([Send - 1, Send + 1]);
    expect(await b.head(end + 3 * DAY_MS)).toMatchObject({ tLast: Send + 1, ended: true });
  });

  it("closed never goes down: after ended it stays at closed_hw when every rel is below it", async () => {
    const b = box();
    const S = slotOf(inside());
    const x = invite();
    expect(rels(await b.post(atSlot(S), [x], 0))).toEqual([S + 1]);
    const end = P.eraEnd(b.E);
    const before = await b.read(end - 1, S + 1);
    expect(before).toMatchObject({ closed: slotOf(end - 1), ended: false, rows: [] });
    expect(before.closed).toBeGreaterThan(S + 1);

    let r = await b.read(end, before.closed);
    expect(r).toMatchObject({ closed: before.closed, ended: true, more: false, rows: [] });
    await evictDurableObject(b.stub);
    r = await b.read(end + DAY_MS, 0);
    expect(r).toMatchObject({ closed: before.closed, ended: true, more: false });
    expect(r.rows.map((y) => P.b64u(y.eid))).toEqual([P.b64u(x.eid)]);
    expect(await b.head(end + DAY_MS)).toMatchObject({ tLast: S + 1, ended: true });

    // An era without rows reports its closed_hw.
    const c = box();
    expect((await c.read(end - 1)).closed).toBe(slotOf(end - 1));
    expect(await c.read(end + 1)).toMatchObject({ closed: slotOf(end - 1), ended: true, rows: [] });

    // head() persists closed_hw as read does: an empty era whose only report came from head() ends there too.
    const d = box();
    expect(await d.head(end - 1)).toMatchObject({ tLast: 0, ended: false });
    expect(await d.meta("closed_hw")).toBe(slotOf(end - 1));
    expect(await d.read(end + DAY_MS)).toMatchObject({ closed: slotOf(end - 1), ended: true, more: false, rows: [] });
    // With nothing ever reported, an empty era ends at closed = 0.
    expect(await box().read(end)).toMatchObject({ closed: 0, ended: true, rows: [] });
  });

  it("a post at end(E) − D/2 with jitter D − 1 is above the closed of every read before end(E) + D; a read after ended returns it", async () => {
    const b = box();
    const end = P.eraEnd(b.E);
    const SKEW_MS = 2_000; // ≥ D: reads up to end(E) + D still run before `ended`
    const call = <R>(now: number, fn: (inst: Inner) => R) =>
      b.at(
        now,
        (inst) => {
          inst.skewMs = SKEW_MS;
          return fn(inst);
        },
        D - 1,
      );
    const x = invite();
    const [rel] = rels(await call(end - D / 2, (i) => i.post(b.E, b.g, 0, [x]))) as number[];
    expect(rel).toBe((end - P.T0_MS) / D + 1);
    for (const now of [end - D / 2, end - 1, end, end + D / 2, end + D - 1]) {
      const r = await call(now, (i) => i.read(b.E, b.g, 0, 0, 1024));
      expect(r.ended, String(now - end)).toBe(false);
      expect(r.closed, String(now - end)).toBeLessThan(rel);
      expect(r.rows).toEqual([]);
    }
    // Posts closed at end(E); once the era has ended, a read returns the row and closed covers it.
    expect(await call(end, (i) => i.post(b.E, b.g, 0, [invite()]))).toEqual({ s: "wrong_era", era: b.E + 1 });
    const r = await call(end + SKEW_MS, (i) => i.read(b.E, b.g, 0, 0, 1024));
    expect(r).toMatchObject({ closed: rel, ended: true, more: false });
    expect(r.rows.map((y) => [y.rel, P.b64u(y.eid)])).toEqual([[rel, P.b64u(x.eid)]]);

    // The same with SKEW = 0: every read before end(E) misses it, and the first read at end(E) (ended) returns it.
    const c = box();
    const [rel0] = rels(await c.post(end - D / 2, [x], D - 1));
    expect(rel0).toBe(rel);
    expect((await c.read(end - 1)).rows).toEqual([]);
    expect(await c.read(end)).toMatchObject({ closed: rel, ended: true, rows: [{ rel, eid: x.eid, body: x.body }] });
  });

  it("an alarm that fires before end(E) + SKEW sets no `ended` and re-arms at max(end(E) + SKEW, now + 1000)", async () => {
    const b = box();
    const end = P.eraEnd(b.E);
    const alarm = () => runInDurableObject(b.stub, (_i: InboxDO, s) => s.storage.getAlarm());
    const fire = async (now: number, skewMs = 0) => {
      await b.at(now, (inst) => void (inst.skewMs = skewMs));
      expect(await runDurableObjectAlarm(b.stub)).toBe(true);
    };
    expect(await alarm()).toBe(end); // armed by the constructor (SKEW = 0)

    // A few ms early (the alarm ran ahead of this object's clock): 1 s from now, never at once.
    await fire(end - 5);
    expect(await b.meta("ended")).toBeUndefined();
    expect(await alarm()).toBe(end - 5 + 1000);
    // Well before the end: at end(E) + SKEW.
    await fire(end - 60_000);
    expect(await b.meta("ended")).toBeUndefined();
    expect(await alarm()).toBe(end);
    await fire(end - 60_000, 2_000);
    expect(await alarm()).toBe(end + 2_000);
    // Inside the SKEW window after end(E): not ended yet, and again never sooner than now + 1000.
    await fire(end + 1_500, 2_000);
    expect(await b.meta("ended")).toBeUndefined();
    expect(await alarm()).toBe(end + 2_500);
    // On time: `ended` is persisted and nothing is re-armed.
    await fire(end + 2_000, 2_000);
    expect(await b.meta("ended")).toBe(1);
    expect(await alarm()).toBeNull();
  });

  it("prepare() seals without the alarm, and SKEW delays it", async () => {
    const b = box();
    const end = P.eraEnd(b.E);
    expect(await b.head(end)).toMatchObject({ ended: true, tLast: 0 });
    expect(await b.meta("ended")).toBe(1);

    const c = box();
    const at = (now: number) =>
      c.at(now, (inst) => {
        inst.skewMs = 2_000;
        return inst.head(c.E, c.g);
      });
    expect((await at(end + 1_999)).ended).toBe(false);
    expect(await c.post(end + 1_999, [invite()])).toEqual({ s: "wrong_era", era: c.E + 1 });
    expect((await at(end + 2_000)).ended).toBe(true);
  });
});

describe("InboxDO slot commitments", () => {
  it("one slot per closed rel with rows: leaves leafInbox ordered by eid, chained with t = rel", async () => {
    const b = box();
    const S = slotOf(inside());
    await b.post(atSlot(S), invites(3), 0); // rel S + 1
    await b.post(atSlot(S + 1), invites(1), 0); // rel S + 2
    await b.post(atSlot(S + 3), invites(2), 0); // rel S + 4 (S + 3 stays empty)
    await b.post(atSlot(S + 8), invites(2), 0); // rel S + 9: still open below

    const now = atSlot(S + 5);
    const h = await b.head(now);
    expect(h.tLast).toBe(S + 4);
    const rows = (await b.read(now)).rows;
    expect(rows).toHaveLength(6);

    const cid = P.inboxCid(b.E, b.g);
    const recompute = (all: typeof rows) => {
      let head: Uint8Array = P.ZERO32;
      const slots: { rel: number; n: number; root: string; head: string }[] = [];
      for (const rel of [...new Set(all.map((r) => r.rel))].sort((x, y) => x - y)) {
        const grp = all.filter((r) => r.rel === rel).sort((x, y) => P.byteCmp(x.eid, y.eid));
        const root = P.mth(grp.map((r) => P.leafInbox(b.E, 0, rel, r.eid, r.body)));
        head = P.nextHead(cid, head, rel, grp.length, root);
        slots.push({ rel, n: grp.length, root: P.b64u(root), head: P.b64u(head) });
      }
      return { head, slots };
    };
    const stored = () =>
      runInDurableObject(b.stub, (_i: InboxDO, s) =>
        s.storage.sql
          .exec<{ rel: number; n: number; root: ArrayBuffer; head: ArrayBuffer }>("SELECT rel, n, root, head FROM slot ORDER BY rel")
          .toArray()
          .map((r) => ({ rel: r.rel, n: r.n, root: P.b64u(new Uint8Array(r.root)), head: P.b64u(new Uint8Array(r.head)) })),
      );
    let want = recompute(rows);
    expect(P.b64u(h.head)).toBe(P.b64u(want.head));
    expect(want.slots.map((x) => x.rel)).toEqual([S + 1, S + 2, S + 4]);
    expect(await stored()).toEqual(want.slots);

    // Later slots extend the same chain; a restart changes nothing.
    const later = atSlot(S + 12);
    const all = (await b.read(later)).rows;
    expect(all).toHaveLength(8);
    want = recompute(all);
    await evictDurableObject(b.stub);
    const h2 = await b.head(later);
    expect(h2.tLast).toBe(S + 9);
    expect(P.b64u(h2.head)).toBe(P.b64u(want.head));
    expect(await stored()).toEqual(want.slots);
    // An inbox without rows keeps head = ZERO32.
    expect(await box().head(later)).toMatchObject({ head: P.ZERO32, tLast: 0, ended: false });
  });
});
