/**
 * FeedDO (docs/PROTOCOL.md §9.4): the pull at start (in the background, rows held for the ConnDOs not pulled yet),
 * interest / replace, expiry, fan-out with one retry, validation.
 */
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import * as P from "@segv/protocol/proto";
import * as W from "@segv/protocol/wire";
import type { ConnDO } from "../src/conn-do";
import type { ConnLink, FeedDO, FeedLimits } from "../src/feed-do";
import { connName, feedName, type RtPublishRow } from "../src/types";

type FeedInner = Pick<FeedDO, "publish" | "inbox" | "interest" | "replace" | "topicsOf"> & {
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
  const frames: W.ServerFrame[] = [];
  let hello = false;
  ws.addEventListener("message", (e) => {
    const f = W.decodeServerFrame(new Uint8Array(e.data as ArrayBuffer));
    frames.push(f);
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
    frames,
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
    // A fresh construction: the index is gone until the pull brings it back. A publish at once is held for the
    // ConnDOs not pulled yet and delivered when their pull answers.
    await evictDurableObject(feedOf(T));
    const x = row(T);
    await feedOf(T).publish([x]);
    await s.rowsAre(1);
    expect(P.equalBytes(s.rows[0].label, x.label)).toBe(true);
    await sleep(50);
    expect(s.rows).toHaveLength(1); // once
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
    await eventually(
      () => feedOf(T).topicsOf(C - 1),
      (x) => x.includes(P.hex(T)),
      "pulled again",
    );
    expect(await feedOf(T).topicsOf(far)).toEqual([]);
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
          deliverInbox: (E, g, rel) => real(cc).deliverInbox(E, g, rel),
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

  it("inbox(E, g, rel) reaches the ConnDOs with interest in Tinbox(E, g) only, as one INBOX frame per socket (§9.3)", async () => {
    const E = 42;
    const g = 1 + Math.floor(Math.random() * 1e6);
    const T = P.topicInbox(E, g);
    const conn = connAt(C - 1);
    const s = await socket(conn);
    const other = await socket(conn);
    s.sub([T]);
    other.sub([topic()]);
    await eventually(
      () => feedOf(T).topicsOf(C - 1),
      (x) => x.includes(P.hex(T)),
      "interest",
    );
    await feedOf(T).inbox(E, g, 7);
    const inboxFrames = (x: typeof s) => x.frames.filter((f) => f.f === "inbox");
    await eventually(
      () => inboxFrames(s).length,
      (n) => n >= 1,
      "INBOX",
    );
    expect(inboxFrames(s)).toEqual([{ f: "inbox", E, g, rel: 7 }]);
    await sleep(50);
    expect(inboxFrames(other)).toEqual([]);
    expect(s.rows).toEqual([]);
    await feedInside(feedOf(T), async (i) => {
      for (const [e, gg, r] of [
        [-1, 0, 0],
        [0xffff, 0, 0],
        [0, -1, 0],
        [0, 0, 2 ** 32],
        [1.5, 0, 0],
      ]) {
        await expect(i.inbox(e, gg, r)).rejects.toThrow(TypeError);
      }
    });
    s.close();
    other.close();
  });

  it("serves a publish while a ConnDO's pull is still outstanding, and gives that ConnDO the held rows when it answers", async () => {
    const [T, U] = [topic(), topic()];
    // A FeedDO of its own (j far above F): nothing else calls it, and its start pull goes to the fakes below.
    const feed = feedNs.getByName(feedName(2 ** 20 + Math.floor(Math.random() * 2 ** 30)));
    const got: string[] = [];
    let answer!: (topics: Uint8Array[]) => void;
    const slow = new Promise<Uint8Array[]>((r) => (answer = r));
    const pulls: number[] = [];
    await feedInside(feed, (i) => {
      i.limits.pullTimeoutMs = 60_000;
      i.limits.holdMs = 60_000;
      i.conns = (c) => ({
        topicsFor: async () => {
          pulls.push(c);
          return c === 0 ? [T] : slow; // ConnDO 1 does not answer yet
        },
        deliver: async (rows) => {
          got.push(`${c}:${rows.map((r) => (P.equalBytes(r.topic, T) ? "T" : "U")).join("")}`);
        },
        deliverInbox: async (E, g, rel) => {
          got.push(`${c}:inbox:${E}:${g}:${rel}`);
        },
      });
    });
    expect(C).toBe(2);
    // The first request starts the pull. A publish made while pulls are out returns once they have answered.
    const calls = [feed.publish([row(T), row(U)])];
    await eventually(
      () => got.slice(),
      (x) => x.includes("0:T"),
      "ConnDO 0 served",
    );
    expect(pulls.sort()).toEqual([0, 1]);
    // ConnDO 1 is still pending: the FeedDO answers calls and serves the other ConnDOs meanwhile.
    await feed.interest(5, [U], []);
    calls.push(feed.publish([row(U)]));
    await eventually(
      () => got.slice(),
      (x) => x.includes("5:U"),
      "ConnDO 5 served",
    );
    // A call from ConnDO 1 while its pull is out: the late answer only adds to it.
    await feed.interest(1, [U], []);
    answer([T]);
    await Promise.all(calls);
    expect((await feed.topicsOf(1)).sort()).toEqual([P.hex(T), P.hex(U)].sort());
    // ConnDO 1 gets, once, every held row of its topics that it had not had: published while it was pending.
    expect(got.filter((x) => x.startsWith("1:"))).toEqual(["1:TUU"]);
    expect(got.filter((x) => x.startsWith("0:"))).toEqual(["0:T"]);
    // Nothing is pending any more: a publish goes out at once and nothing is held.
    got.length = 0;
    await feed.publish([row(T)]);
    expect(got.sort()).toEqual(["0:T", "1:T"]);
  });

  it("a pull that fails leaves the ConnDO pending and is made again at a later request, at most once per repullMs", async () => {
    const T = topic();
    const feed = feedNs.getByName(feedName(2 ** 20 + Math.floor(Math.random() * 2 ** 30)));
    const pulls: number[] = [];
    const got: string[] = [];
    let down = true;
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await feedInside(feed, (i) => {
        i.conns = (c) => ({
          topicsFor: async () => {
            pulls.push(c);
            if (c === 1 && down) throw new Error("conn down");
            return [T];
          },
          deliver: async () => void got.push(`${c}`),
          deliverInbox: async () => {},
        });
      });
      await feed.publish([row(T)]);
      await eventually(
        () => pulls.length,
        (n) => n >= 2,
        "the first pulls",
      );
      expect(got).toEqual(["0"]);
      await feed.publish([row(T)]); // within repullMs: no new pull of 1
      expect(pulls.filter((c) => c === 1)).toHaveLength(1);
      down = false;
      await feedInside(feed, (i) => void (i.limits.repullMs = 0));
      await feed.publish([row(T)]); // pulls 1 again; the rows held since it failed reach it once it answers
      await eventually(
        () => got.filter((c) => c === "1").length,
        (n) => n >= 1,
        "ConnDO 1",
      );
      expect(await feed.topicsOf(1)).toEqual([P.hex(T)]);
    } finally {
      errors.mockRestore();
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
