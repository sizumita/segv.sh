/** FeedDO (docs/PROTOCOL.md §9.4): the pull at start, interest / replace, expiry, fan-out with one retry, validation. */
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import * as P from "@segv/protocol/proto";
import * as W from "@segv/protocol/wire";
import type { ConnDO } from "../src/conn-do";
import type { ConnLink, FeedDO, FeedLimits } from "../src/feed-do";
import { connName, feedName, type RtPublishRow } from "../src/types";

type FeedInner = Pick<FeedDO, "publish" | "interest" | "replace" | "topicsOf"> & {
  clock: () => number;
  limits: FeedLimits;
  conns: (c: number) => ConnLink;
};

const KFEED = P.kfeed(P.fromB64u(env.ROUTE_KEY));
const FBITS = P.feedBits(Number(env.RT_FEEDS));
const C = Number(env.RT_CONNS);
const jOf = (T: Uint8Array): number => P.feedOf(P.feedHash(KFEED, T), FBITS);
const feedNs = env.FEED as unknown as DurableObjectNamespace<FeedDO>;
const connNs = env.CONN as unknown as DurableObjectNamespace<ConnDO>;
const feedOf = (T: Uint8Array) => feedNs.getByName(feedName(jOf(T)));
const connAt = (c: number) => connNs.getByName(connName(c));
const randomC = (): number => 2 ** 20 + Math.floor(Math.random() * 2 ** 30);
const topic = (): Uint8Array => P.random(16);
const row = (t: Uint8Array, cls = 0): RtPublishRow => ({
  topic: t,
  E: 42,
  label: P.random(16),
  t: 123_456,
  cls,
  body: P.random(P.BODY_LENS[cls]),
});
const feedInside = <R>(
  stub: DurableObjectStub<FeedDO>,
  fn: (i: FeedInner, state: DurableObjectState) => R | Promise<R>,
) => runInDurableObject(stub, (inst: FeedDO, state) => fn(inst as unknown as FeedInner, state));
/** A socket on ConnDO `stub` that records its ROWS frames. */
async function socket(stub: DurableObjectStub<ConnDO>, c = -1) {
  const res = await stub.fetch("https://rt.test/", {
    headers: { upgrade: "websocket", "x-segv-client": P.hex(P.random(16)) },
  });
  expect(res.status).toBe(101);
  const ws = res.webSocket!;
  const rows: W.RtRow[] = [];
  let hello = false;
  ws.addEventListener("message", (e) => {
    const f = W.decodeServerFrame(new Uint8Array(e.data as ArrayBuffer));
    if (f.f === "hello") hello = true;
    if (f.f === "rows") rows.push(...f.rows);
  });
  ws.binaryType = "arraybuffer";
  ws.accept();
  await eventually(
    () => hello,
    (x) => x,
    "HELLO",
  );
  return {
    c,
    ws,
    rows,
    sub: (topics: Uint8Array[]) => ws.send(W.encodeClientFrame({ f: "sub", topics })),
    rowsAre: (n: number) =>
      eventually(
        () => rows.length,
        (x) => x >= n,
        `${n} rows`,
      ),
    close: () => ws.close(1000),
  };
}

async function eventually<T>(
  fn: () => T | Promise<T>,
  pred: (x: T) => boolean,
  what: string,
): Promise<T> {
  let x = await fn();
  for (let i = 0; i < 250 && !pred(x); i++) {
    await new Promise((r) => setTimeout(r, 20));
    x = await fn();
  }
  if (!pred(x)) throw new Error(`timeout waiting for ${what}: ${JSON.stringify(x)}`);
  return x;
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("FeedDO", () => {
  it("pulls the interest of every ConnDO below C when it starts, so a restart loses no subscription", async () => {
    const T = topic();
    const conn = connAt(C - 1);
    const s = await socket(conn);
    s.sub([T]);
    await eventually(
      () => feedOf(T).topicsOf(C - 1),
      (x) => x.includes(P.hex(T)),
      "interest",
    );
    // A fresh construction: the index is gone until the pull brings it back.
    await evictDurableObject(feedOf(T));
    const x = row(T);
    await feedOf(T).publish([x]);
    await s.rowsAre(1);
    expect(P.equalBytes(s.rows[0].label, x.label)).toBe(true);
    // A ConnDO above C is not pulled: it reports itself (its resync or its next change).
    const far = randomC();
    const sf = await socket(connAt(far));
    sf.sub([T]);
    await eventually(
      () => feedOf(T).topicsOf(far),
      (x) => x.includes(P.hex(T)),
      "far interest",
    );
    await evictDurableObject(feedOf(T));
    expect(await feedOf(T).topicsOf(far)).toEqual([]);
    expect(await feedOf(T).topicsOf(C - 1)).toEqual([P.hex(T)]);
    s.close();
    sf.close();
  });

  it("delivers each row to the ConnDOs with interest in its topic only, the rows of one publish in one deliver", async () => {
    const [T1, T2] = [topic(), topic()];
    const [ca, cb, cboth] = [randomC(), randomC(), randomC()];
    const a = await socket(connAt(ca), ca);
    const b = await socket(connAt(cb), cb);
    const both = await socket(connAt(cboth), cboth);
    a.sub([T1]);
    b.sub([T2]);
    both.sub([T1, T2]);
    for (const [c, T] of [
      [a.c, T1],
      [b.c, T2],
      [both.c, T2],
    ] as const) {
      await eventually(
        () => feedOf(T).topicsOf(c),
        (x) => x.includes(P.hex(T)),
        "interest",
      );
    }
    const x1 = row(T1);
    const x2 = row(T2);
    if (jOf(T1) === jOf(T2)) await feedOf(T1).publish([x1, x2]);
    else {
      await feedOf(T1).publish([x1]);
      await feedOf(T2).publish([x2]);
    }
    await a.rowsAre(1);
    await b.rowsAre(1);
    await both.rowsAre(2);
    await sleep(50);
    expect(a.rows.map((r) => P.b64u(r.label))).toEqual([P.b64u(x1.label)]);
    expect(b.rows.map((r) => P.b64u(r.label))).toEqual([P.b64u(x2.label)]);
    expect(both.rows.map((r) => P.b64u(r.label)).sort()).toEqual(
      [P.b64u(x1.label), P.b64u(x2.label)].sort(),
    );
    for (const s of [a, b, both]) s.close();
  });

  it("a deliver that fails is made once more, then the rows are dropped for that ConnDO", async () => {
    const T = topic();
    const c = randomC();
    const s = await socket(connAt(c));
    s.sub([T]);
    await eventually(
      () => feedOf(T).topicsOf(c),
      (x) => x.includes(P.hex(T)),
      "interest",
    );
    const feed = feedOf(T);
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    let failures = 0;
    try {
      await feedInside(feed, (i) => {
        const real = i.conns;
        i.conns = (cc) => ({
          topicsFor: (j) => real(cc).topicsFor(j),
          deliver: async (rows) => {
            if (failures > 0) {
              failures--;
              throw new Error("conn down");
            }
            return real(cc).deliver(rows);
          },
        });
      });
      failures = 1;
      const x = row(T);
      await feed.publish([x]);
      await s.rowsAre(1);
      expect(P.equalBytes(s.rows[0].label, x.label)).toBe(true);
      failures = 2;
      await feed.publish([row(T)]);
      await sleep(100);
      expect(s.rows).toHaveLength(1);
      expect(errors).toHaveBeenCalledTimes(1);
    } finally {
      errors.mockRestore();
      await feedInside(feed, (i) => void (i.conns = (cc) => connAt(cc)));
      s.close();
    }
  });

  it("interest and replace keep a ConnDO's set; a ConnDO silent for RT_FORGET is forgotten at the next publish", async () => {
    const [T, U] = [topic(), topic()];
    const feed = feedOf(T);
    const c = randomC();
    await feed.interest(c, [T, U], []);
    expect((await feed.topicsOf(c)).sort()).toEqual([P.hex(T), P.hex(U)].sort());
    await feed.interest(c, [], [U]);
    expect(await feed.topicsOf(c)).toEqual([P.hex(T)]);
    await feed.replace(c, [U]);
    expect(await feed.topicsOf(c)).toEqual([P.hex(U)]);
    await feed.replace(c, []);
    expect(await feed.topicsOf(c)).toEqual([]);

    await feed.interest(c, [T], []);
    const t0 = Date.now();
    await feedInside(feed, (i) => void (i.clock = () => t0 + 900_001));
    try {
      await feed.publish([row(topic())]); // any publish expires the silent ConnDOs
      expect(await feed.topicsOf(c)).toEqual([]);
      // A call refreshes the time; a ConnDO heard from stays.
      await feed.interest(c, [T], []);
      await feedInside(feed, (i) => void (i.clock = () => t0 + 1_800_000));
      await feed.publish([row(topic())]);
      expect(await feed.topicsOf(c)).toEqual([P.hex(T)]);
    } finally {
      await feedInside(feed, (i) => void (i.clock = () => Date.now()));
      await feed.replace(c, []);
    }
  });

  it("rejects malformed rows, topics and indexes", async () => {
    await feedInside(feedNs.getByName(feedName(0)), async (i) => {
      const ok = row(topic());
      await expect(i.publish([{ ...ok, topic: P.random(15) }])).rejects.toThrow(TypeError);
      await expect(i.publish([{ ...ok, body: P.random(P.BODY_LENS[1]) }])).rejects.toThrow(
        TypeError,
      );
      await expect(i.publish([{ ...ok, cls: 4 }])).rejects.toThrow(TypeError);
      expect(() => i.interest(-1, [], [])).toThrow(TypeError);
      expect(() => i.interest(2 ** 31, [], [])).toThrow(TypeError);
      expect(() => i.interest(1, [P.random(15)], [])).toThrow(TypeError);
      expect(() => i.replace(1, [P.random(17)])).toThrow(TypeError);
      expect(() => i.topicsOf(1.5)).toThrow(TypeError);
    });
  });
});
