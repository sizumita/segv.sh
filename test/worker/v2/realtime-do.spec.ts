/** RealtimeDO (docs/PROTOCOL-v2.md §9.4, §10.8): HELLO, SUB / UNSUB / RESUME, publish, limits, caps, max age, hibernation. */
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import * as P from "../../../src/lib/proto2";
import * as W from "../../../src/lib/wire";
import type { RealtimeDO, RtLimits } from "../../../src/server/v2/realtime-do";
import type { RtPublishRow } from "../../../src/server/v2/types";

/** The protected / private fields the tests drive or observe. */
type Inner = Pick<RealtimeDO, "publish"> & { clock: () => number; limits: RtLimits; pairs: number; seq: number };
type Stub = DurableObjectStub<RealtimeDO>;
type Frame = W.ServerFrame | { f: "text"; text: string };

const HOUR_MS = 3_600_000;

/** A fresh RealtimeDO instance per test (the class does not care about its name). */
const fresh = (): Stub => (env.RT as unknown as DurableObjectNamespace<RealtimeDO>).getByName(`rt-test/${crypto.randomUUID()}`);
const clientTag = (): string => P.hex(P.random(16));
const topic = (): Uint8Array => P.random(16);
const row = (t: Uint8Array, cls = 0): RtPublishRow => ({
  topic: t,
  E: 42,
  label: P.random(16),
  t: 123_456,
  cls,
  body: P.random(P.BODY_LENS[cls]),
});

const inside = <R>(stub: Stub, fn: (inst: Inner, state: DurableObjectState) => R | Promise<R>): Promise<R> =>
  runInDurableObject(stub, (inst: RealtimeDO, state) => fn(inst as unknown as Inner, state));
const setClock = (stub: Stub, ms: number) => inside(stub, (i) => void (i.clock = () => ms));
const setLimits = (stub: Stub, l: Partial<RtLimits>) => inside(stub, (i) => void Object.assign(i.limits, l));

async function eventually<T>(fn: () => Promise<T>, pred: (x: T) => boolean, what: string): Promise<T> {
  let x = await fn();
  for (let i = 0; i < 250 && !pred(x); i++) {
    await new Promise((r) => setTimeout(r, 20));
    x = await fn();
  }
  if (!pred(x)) throw new Error(`timeout waiting for ${what}: ${JSON.stringify(x)}`);
  return x;
}
/** Waits until the object has processed control frames: its (topic, socket) pair count equals `n`. */
const pairsAre = (stub: Stub, n: number) => eventually(() => inside(stub, (i) => i.pairs), (x) => x === n, `${n} pairs`);

function watch(ws: WebSocket) {
  const frames: Frame[] = [];
  let closeEv: { code: number; reason: string } | null = null;
  const waiters = new Set<() => void>();
  const notify = () => {
    for (const w of waiters) w(); // a waiter may delete itself: Set iteration allows that
  };
  ws.addEventListener("message", (e) => {
    frames.push(typeof e.data === "string" ? { f: "text", text: e.data } : W.decodeServerFrame(new Uint8Array(e.data as ArrayBuffer)));
    notify();
  });
  ws.addEventListener("close", (e) => {
    closeEv = { code: e.code, reason: e.reason };
    notify();
  });
  ws.binaryType = "arraybuffer"; // the default is "blob" at this compatibility date
  ws.accept();
  const until = (pred: () => boolean, what: string) =>
    new Promise<void>((resolve, reject) => {
      const check = () => {
        if (!pred()) return;
        clearTimeout(timer);
        waiters.delete(check);
        resolve();
      };
      const timer = setTimeout(() => {
        waiters.delete(check);
        reject(new Error(`timeout waiting for ${what}; frames=${frames.map((f) => f.f).join(",")}`));
      }, 5000);
      waiters.add(check);
      check();
    });
  const rows = () => frames.flatMap((f) => (f.f === "rows" ? f.rows : []));
  return {
    ws,
    frames,
    rows,
    until,
    closed: () => closeEv,
    send: (f: W.ClientFrame) => ws.send(W.encodeClientFrame(f)),
    hello: async () => {
      await until(() => frames.length > 0, "HELLO");
      const h = frames[0];
      if (h.f !== "hello") throw new Error(`first frame is ${h.f}`);
      return h;
    },
    closedWith: async (code: number) => {
      await until(() => closeEv !== null, `close ${code}`);
      expect(closeEv!.code).toBe(code);
    },
    rowsAre: (n: number) => until(() => rows().length >= n, `${n} rows`),
  };
}
type Sock = ReturnType<typeof watch>;

const upgrade = (stub: Stub, client: string | null = clientTag()) =>
  stub.fetch("https://rt.test/", {
    headers: client === null ? { upgrade: "websocket" } : { upgrade: "websocket", "x-segv-client": client },
  });

async function connect(stub: Stub, client: string | null = clientTag()): Promise<Sock> {
  const res = await upgrade(stub, client);
  expect(res.status).toBe(101);
  const s = watch(res.webSocket!);
  await s.hello();
  return s;
}

const sameRow = (got: W.RtRow, want: RtPublishRow) =>
  P.equalBytes(got.topic, want.topic) &&
  got.E === want.E &&
  P.equalBytes(got.label, want.label) &&
  got.t === want.t &&
  got.cls === want.cls &&
  P.equalBytes(got.body, want.body);

describe("RealtimeDO connect", () => {
  it("426 without an upgrade; HELLO {boot, now, seq} right after accept", async () => {
    const stub = fresh();
    const plain = await stub.fetch("https://rt.test/");
    expect(plain.status).toBe(426);
    await plain.text();
    const before = Date.now();
    const a = await connect(stub);
    const h = await a.hello();
    expect(h.boot).toHaveLength(8);
    expect(h.now).toBeGreaterThanOrEqual(before);
    expect(h.now).toBeLessThanOrEqual(Date.now());
    expect(h.seq).toBe(0);
    await stub.publish([row(topic()), row(topic())]);
    const b = await connect(stub);
    const h2 = await b.hello();
    expect(P.b64u(h2.boot)).toBe(P.b64u(h.boot)); // same boot, seq = last assigned
    expect(h2.seq).toBe(2);
    a.ws.close(1000);
    b.ws.close(1000);
  });

  it("ping is answered pong", async () => {
    const stub = fresh();
    const a = await connect(stub);
    a.ws.send("ping");
    await a.until(() => a.frames.some((f) => f.f === "text" && f.text === "pong"), "pong");
    expect(a.closed()).toBeNull();
    a.ws.close(1000);
  });

  it("wsTagKey is 32 random bytes kept in meta; nothing about topics or rows is persisted", async () => {
    const stub = fresh();
    const k = await stub.wsTagKey();
    expect(k).toHaveLength(32);
    const a = await connect(stub);
    const T = topic();
    a.send({ f: "sub", topics: [T] });
    await pairsAre(stub, 1);
    await stub.publish([row(T)]);
    await a.rowsAre(1);
    await evictDurableObject(stub);
    expect(P.b64u(await stub.wsTagKey())).toBe(P.b64u(k));
    const stored = await inside(stub, async (_i, state) => ({
      tables: state.storage.sql
        .exec<{ name: string }>(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\' " +
            "AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'",
        )
        .toArray()
        .map((r) => r.name),
      keys: state.storage.sql.exec<{ k: string }>("SELECT k FROM meta").toArray().map((r) => r.k),
      kv: [...(await state.storage.list()).keys()],
    }));
    expect(stored).toEqual({ tables: ["meta"], keys: ["ws-tag-key"], kv: [] });
    a.ws.close(1000);
  });
});

describe("RealtimeDO delivery", () => {
  it("SUB, then a publish to two topics: each socket receives only its topics, one ROWS frame per publish", async () => {
    const stub = fresh();
    const [T1, T2] = [topic(), topic()];
    const a = await connect(stub);
    const b = await connect(stub);
    a.send({ f: "sub", topics: [T1] });
    b.send({ f: "sub", topics: [T2] });
    await pairsAre(stub, 2);

    const r1 = row(T1);
    const r2 = row(T2, 1);
    await stub.publish([r1, r2]);
    const r3 = row(T2);
    await stub.publish([r3]);
    const r4 = row(T1, 3);
    const r5 = row(T1);
    await stub.publish([r4, r5]);

    await a.rowsAre(3);
    await b.rowsAre(2);
    const aFrames = a.frames.filter((f) => f.f === "rows");
    expect(aFrames.map((f) => (f.f === "rows" ? f.rows.length : 0))).toEqual([1, 2]);
    expect(a.rows().map((r) => r.seq)).toEqual([1, 4, 5]);
    expect(a.rows().every((r, i) => sameRow(r, [r1, r4, r5][i]))).toBe(true);
    expect(b.rows().map((r) => r.seq)).toEqual([2, 3]);
    expect(b.rows().every((r, i) => sameRow(r, [r2, r3][i]))).toBe(true);
    a.ws.close(1000);
    b.ws.close(1000);
  });

  it("UNSUB stops delivery of that topic only", async () => {
    const stub = fresh();
    const [T1, T2] = [topic(), topic()];
    const a = await connect(stub);
    a.send({ f: "sub", topics: [T1, T2, T1] });
    await pairsAre(stub, 2); // duplicates count once
    a.send({ f: "unsub", topics: [T1, topic()] }); // an unknown topic is ignored
    await pairsAre(stub, 1);
    const x = row(T1);
    const y = row(T2);
    await stub.publish([x]);
    await stub.publish([y]);
    await a.rowsAre(1);
    expect(a.rows()).toHaveLength(1);
    expect(sameRow(a.rows()[0], y)).toBe(true);
    a.ws.close(1000);
  });

  it("topics sharing an 8-byte prefix are told apart by the full 16 bytes", async () => {
    const stub = fresh();
    const T1 = topic();
    const T2 = T1.slice();
    T2[15] ^= 1;
    const a = await connect(stub);
    const b = await connect(stub);
    a.send({ f: "sub", topics: [T1, T2] });
    b.send({ f: "sub", topics: [T2] });
    await pairsAre(stub, 3);
    a.send({ f: "unsub", topics: [T1] }); // a keeps T2 under the same prefix
    await pairsAre(stub, 2);
    await stub.publish([row(T1)]);
    const y = row(T2);
    await stub.publish([y]);
    await a.rowsAre(1);
    await b.rowsAre(1);
    expect(sameRow(a.rows()[0], y)).toBe(true);
    expect(sameRow(b.rows()[0], y)).toBe(true);
    expect(a.rows()).toHaveLength(1);
    expect(b.rows()).toHaveLength(1);
    a.ws.close(1000);
    b.ws.close(1000);
  });

  it("an UNSUB reads each topic prefix a bounded number of times (no removed × remaining scan)", async () => {
    const stub = fresh();
    const a = await connect(stub);
    const ts = Array.from({ length: 256 }, topic);
    a.send({ f: "sub", topics: ts });
    await pairsAre(stub, 256);
    const prefixReads = vi.spyOn(DataView.prototype, "getBigUint64");
    try {
      a.send({ f: "unsub", topics: ts.slice(0, 128) });
      await pairsAre(stub, 128);
      // About one read per removed and per kept topic; a nested scan reads 128 × 128.
      expect(prefixReads.mock.calls.length).toBeGreaterThanOrEqual(128);
      expect(prefixReads.mock.calls.length).toBeLessThanOrEqual(2 * 256);
    } finally {
      prefixReads.mockRestore();
    }
    const gone = row(ts[0]);
    const kept = row(ts[200]);
    await stub.publish([gone, kept]);
    await a.rowsAre(1);
    expect(a.rows()).toHaveLength(1);
    expect(sameRow(a.rows()[0], kept)).toBe(true);
    a.ws.close(1000);
  });

  it("publish encodes each distinct row list once and sends the same bytes to every socket that gets it", async () => {
    const stub = fresh();
    const [T1, T2] = [topic(), topic()];
    const many = [await connect(stub), await connect(stub), await connect(stub)];
    for (const s of many) s.send({ f: "sub", topics: [T1] });
    const both = await connect(stub);
    both.send({ f: "sub", topics: [T1, T2] });
    await pairsAre(stub, 5);

    const x = row(T1);
    const y = row(T1);
    const z = row(T2);
    const sends = vi.spyOn(WebSocket.prototype, "send");
    // ROWS frames only (the test pool talks to its host over a WebSocket too).
    const rowsSent = () => sends.mock.calls.map((c) => c[0]).filter((m) => m instanceof Uint8Array && m[0] === W.RT_ROWS);
    let first: unknown[];
    let second: unknown[];
    try {
      await stub.publish([x]);
      first = rowsSent();
      sends.mockClear();
      await stub.publish([y, z]);
      second = rowsSent();
    } finally {
      sends.mockRestore();
    }
    expect(first).toHaveLength(4);
    expect(new Set(first).size).toBe(1); // one encoding for all four sockets
    expect(second).toHaveLength(4);
    expect(new Set(second).size).toBe(2); // [y] for three sockets, [y, z] for one

    for (const s of many) await s.rowsAre(2);
    await both.rowsAre(3);
    for (const s of many) {
      expect(s.rows().map((r) => r.seq)).toEqual([1, 2]);
      expect(sameRow(s.rows()[0], x) && sameRow(s.rows()[1], y)).toBe(true);
    }
    expect(both.rows().map((r) => r.seq)).toEqual([1, 2, 3]);
    expect(sameRow(both.rows()[2], z)).toBe(true);
    for (const s of [...many, both]) s.ws.close(1000);
  });
});

describe("RealtimeDO RESUME", () => {
  it("with the current boot: replays ring rows newer than since on its topics, then RESUMED; the topics are installed", async () => {
    const stub = fresh();
    const [T1, T2] = [topic(), topic()];
    const a = await connect(stub);
    const { boot } = await a.hello();
    const x1 = row(T1);
    const x2 = row(T2);
    const x3 = row(T1);
    await stub.publish([x1, x2]);
    await stub.publish([x3]);

    const b = await connect(stub);
    b.send({ f: "resume", boot, since: 1, topics: [T1] });
    await b.until(() => b.frames.some((f) => f.f === "resumed"), "RESUMED");
    expect(b.frames.map((f) => f.f)).toEqual(["hello", "rows", "resumed"]);
    expect(b.rows().map((r) => r.seq)).toEqual([3]);
    expect(sameRow(b.rows()[0], x3)).toBe(true);

    const c = await connect(stub);
    c.send({ f: "resume", boot, since: 0, topics: [T2, T1] });
    await c.until(() => c.frames.some((f) => f.f === "resumed"), "RESUMED");
    expect(c.rows().map((r) => r.seq)).toEqual([1, 2, 3]);

    const x4 = row(T1);
    await stub.publish([x4]);
    await b.rowsAre(2);
    expect(sameRow(b.rows()[1], x4)).toBe(true);
    expect(b.rows()[1].seq).toBe(4);
    for (const s of [a, b, c]) s.ws.close(1000);
  });

  it("two rows published in the same millisecond are both replayed, by seq", async () => {
    const stub = fresh();
    await setClock(stub, Date.now());
    const T = topic();
    const a = await connect(stub);
    const { boot, seq } = await a.hello();
    const x = row(T);
    const y = row(T);
    await stub.publish([x]);
    await stub.publish([y]);
    const b = await connect(stub);
    b.send({ f: "resume", boot, since: seq, topics: [T] });
    await b.until(() => b.frames.some((f) => f.f === "resumed"), "RESUMED");
    expect(b.rows().map((r) => r.seq)).toEqual([seq + 1, seq + 2]);
    expect(sameRow(b.rows()[0], x) && sameRow(b.rows()[1], y)).toBe(true);
    a.ws.close(1000);
    b.ws.close(1000);
  });

  it("a stale boot gets GAP(since), and the topics are still installed", async () => {
    const stub = fresh();
    const T = topic();
    await stub.publish([row(T)]);
    const a = await connect(stub);
    a.send({ f: "resume", boot: P.random(8), since: 7, topics: [T] });
    await a.until(() => a.frames.length >= 2, "GAP");
    expect(a.frames[1]).toEqual({ f: "gap", since: 7 });
    await pairsAre(stub, 1);
    const y = row(T);
    await stub.publish([y]);
    await a.rowsAre(1);
    expect(sameRow(a.rows()[0], y)).toBe(true);
    a.ws.close(1000);
  });

  it("a since older than the ring (rows, bytes or 10 minutes) gets GAP; a since inside it is replayed", async () => {
    const T = topic();
    // Row cap.
    let stub = fresh();
    await setLimits(stub, { ringRows: 2 });
    let a = await connect(stub);
    const { boot } = await a.hello();
    await stub.publish([row(T), row(T), row(T)]); // seq 1 is dropped
    const gap = await connect(stub);
    gap.send({ f: "resume", boot, since: 0, topics: [T] });
    await gap.until(() => gap.frames.length >= 2, "GAP");
    expect(gap.frames[1]).toEqual({ f: "gap", since: 0 });
    const ok = await connect(stub);
    ok.send({ f: "resume", boot, since: 1, topics: [T] });
    await ok.until(() => ok.frames.some((f) => f.f === "resumed"), "RESUMED");
    expect(ok.rows().map((r) => r.seq)).toEqual([2, 3]);
    // The GAP socket still gets new rows.
    await stub.publish([row(T)]);
    await gap.rowsAre(1);
    expect(gap.rows()[0].seq).toBe(4);
    for (const s of [a, gap, ok]) s.ws.close(1000);

    // Byte cap: room for two class-0 rows.
    stub = fresh();
    await setLimits(stub, { ringBytes: 2 * (47 + P.BODY_LENS[0]) });
    a = await connect(stub);
    const h2 = await a.hello();
    await stub.publish([row(T), row(T), row(T)]);
    let b = await connect(stub);
    b.send({ f: "resume", boot: h2.boot, since: 0, topics: [T] });
    await b.until(() => b.frames.length >= 2, "GAP");
    expect(b.frames[1]).toEqual({ f: "gap", since: 0 });
    a.ws.close(1000);
    b.ws.close(1000);

    // Age: rows older than 10 minutes are gone.
    stub = fresh();
    const t0 = Date.now();
    await setClock(stub, t0);
    a = await connect(stub);
    const h3 = await a.hello();
    await stub.publish([row(T)]);
    await setClock(stub, t0 + 10 * 60_000);
    await stub.publish([row(T)]);
    await setClock(stub, t0 + 10 * 60_000 + 1);
    b = await connect(stub);
    b.send({ f: "resume", boot: h3.boot, since: 0, topics: [T] });
    await b.until(() => b.frames.length >= 2, "GAP");
    expect(b.frames[1]).toEqual({ f: "gap", since: 0 });
    const c = await connect(stub);
    c.send({ f: "resume", boot: h3.boot, since: 1, topics: [T] });
    await c.until(() => c.frames.some((f) => f.f === "resumed"), "RESUMED");
    expect(c.rows().map((r) => r.seq)).toEqual([2]);
    for (const s of [a, b, c]) s.ws.close(1000);
  });

  it("a since above the last assigned seq (current boot) gets GAP; since = seq is RESUMED with nothing to replay", async () => {
    const stub = fresh();
    const T = topic();
    await stub.publish([row(T), row(T)]);
    const a = await connect(stub);
    const { boot, seq } = await a.hello();
    expect(seq).toBe(2);
    a.send({ f: "resume", boot, since: seq + 500, topics: [T] }); // e.g. a seq kept from another boot
    await a.until(() => a.frames.length >= 2, "GAP");
    expect(a.frames).toEqual([expect.objectContaining({ f: "hello" }), { f: "gap", since: seq + 500 }]);
    await pairsAre(stub, 1); // the topics are installed

    const b = await connect(stub);
    b.send({ f: "resume", boot, since: seq, topics: [T] });
    await b.until(() => b.frames.some((f) => f.f === "resumed"), "RESUMED");
    expect(b.frames.map((f) => f.f)).toEqual(["hello", "resumed"]);

    const y = row(T);
    await stub.publish([y]);
    await a.rowsAre(1);
    await b.rowsAre(1);
    expect(sameRow(a.rows()[0], y) && sameRow(b.rows()[0], y)).toBe(true);
    expect(a.rows()[0].seq).toBe(3);
    a.ws.close(1000);
    b.ws.close(1000);
  });

  it("a replay over the replay budget gets GAP(since), and the topics are still installed", async () => {
    const stub = fresh();
    const size = 47 + P.BODY_LENS[0];
    await setLimits(stub, { replayBytes: 2 * size });
    const [T, U] = [topic(), topic()];
    const a = await connect(stub);
    const { boot } = await a.hello();
    await stub.publish([row(T), row(U), row(U), row(T), row(T)]); // T at seq 1, 4, 5

    // since 0 on T: three rows (3 · size) are over the budget.
    const b = await connect(stub);
    b.send({ f: "resume", boot, since: 0, topics: [T] });
    await b.until(() => b.frames.length >= 2, "GAP");
    expect(b.frames.map((f) => f.f)).toEqual(["hello", "gap"]);
    expect(b.frames[1]).toEqual({ f: "gap", since: 0 });
    await pairsAre(stub, 1);

    // since 1 on T: two rows, exactly the budget (rows on other topics do not count).
    const c = await connect(stub);
    c.send({ f: "resume", boot, since: 1, topics: [T] });
    await c.until(() => c.frames.some((f) => f.f === "resumed"), "RESUMED");
    expect(c.frames.map((f) => f.f)).toEqual(["hello", "rows", "resumed"]);
    expect(c.rows().map((r) => r.seq)).toEqual([4, 5]);
    await pairsAre(stub, 2);

    const y = row(T);
    await stub.publish([y]);
    await b.rowsAre(1);
    await c.rowsAre(3);
    expect(sameRow(b.rows()[0], y)).toBe(true);
    expect(b.rows()[0].seq).toBe(6);
    for (const s of [a, b, c]) s.ws.close(1000);
  });
});

describe("RealtimeDO protocol violations", () => {
  const closes = async (setup: (s: Sock, stub: Stub) => Promise<void> | void, code = 1008) => {
    const stub = fresh();
    await setClock(stub, Math.floor(Date.now() / 60_000) * 60_000 + 1_000); // one fixed minute
    const s = await connect(stub);
    await setup(s, stub);
    await s.closedWith(code);
    return stub;
  };

  it("closes with 1008: a text other than ping", async () => {
    await closes((s) => s.ws.send("hello"));
  });

  it("closes with 1008: a malformed binary frame", async () => {
    await closes((s) => s.ws.send(Uint8Array.of(0x09, 0, 1)));
    await closes((s) => s.ws.send(Uint8Array.of(W.RT_SUB, 0, 0))); // n = 0
    await closes((s) => {
      const f = W.encodeClientFrame({ f: "sub", topics: [topic()] });
      const extra = new Uint8Array(f.length + 1);
      extra.set(f);
      s.ws.send(extra); // trailing byte
    });
  });

  it("closes with 1008: more than 256 topics on the socket", async () => {
    await closes(async (s, stub) => {
      s.send({ f: "sub", topics: Array.from({ length: 200 }, topic) });
      await pairsAre(stub, 200);
      s.send({ f: "sub", topics: Array.from({ length: 57 }, topic) });
    });
  });

  it("closes with 1008: a frame over 8 KiB", async () => {
    await closes((s) => {
      const f = new Uint8Array(8 * 1024 + 1);
      f[0] = W.RT_SUB;
      s.ws.send(f);
    });
  });

  it("closes with 1008: a second RESUME, or a RESUME after another binary frame", async () => {
    await closes(async (s) => {
      const { boot, seq } = await s.hello();
      s.send({ f: "resume", boot, since: seq, topics: [topic()] });
      await s.until(() => s.frames.some((f) => f.f === "resumed"), "RESUMED");
      s.send({ f: "resume", boot, since: seq, topics: [topic()] });
    });
    await closes(async (s, stub) => {
      const { boot, seq } = await s.hello();
      s.send({ f: "sub", topics: [topic()] });
      await pairsAre(stub, 1);
      s.send({ f: "resume", boot, since: seq, topics: [] });
    });
  });

  it("closes with 1008: more than 30 SUB/UNSUB frames in a minute (the next minute starts afresh)", async () => {
    await closes((s) => {
      const T = topic();
      for (let i = 0; i < 31; i++) s.send({ f: i % 2 === 0 ? "sub" : "unsub", topics: [T] });
    });
    const stub = fresh();
    const minute = Math.floor(Date.now() / 60_000) * 60_000;
    await setClock(stub, minute + 1_000);
    const s = await connect(stub);
    for (let i = 0; i < 30; i++) s.send({ f: "sub", topics: [topic()] });
    await pairsAre(stub, 30);
    await setClock(stub, minute + 61_000);
    for (let i = 0; i < 30; i++) s.send({ f: "sub", topics: [topic()] });
    await pairsAre(stub, 60);
    expect(s.closed()).toBeNull();
    s.send({ f: "sub", topics: [topic()] });
    await s.closedWith(1008);
  });

  it("closes with 1008: more than 2048 topic changes in a minute", async () => {
    await closes(async (s, stub) => {
      const ts = Array.from({ length: 256 }, topic);
      for (let i = 0; i < 4; i++) {
        s.send({ f: "sub", topics: ts });
        await pairsAre(stub, 256);
        s.send({ f: "unsub", topics: ts });
        await pairsAre(stub, 0);
      }
      expect(s.closed()).toBeNull(); // exactly 2048 changes
      s.send({ f: "sub", topics: [ts[0]] });
    });
  });

  it("closes with 1013 when a SUB would push the total above the pair budget", async () => {
    const stub = fresh();
    await setLimits(stub, { pairs: 5 });
    const a = await connect(stub);
    const b = await connect(stub);
    const c = await connect(stub);
    const TA = [topic(), topic(), topic()];
    a.send({ f: "sub", topics: TA });
    await pairsAre(stub, 3);
    b.send({ f: "sub", topics: [topic(), topic(), topic()] });
    await b.closedWith(1013);
    c.send({ f: "sub", topics: [topic(), topic()] });
    await pairsAre(stub, 5);
    // A RESUME beyond the budget is refused the same way.
    const d = await connect(stub);
    const { boot, seq } = await d.hello();
    d.send({ f: "resume", boot, since: seq, topics: [topic()] });
    await d.closedWith(1013);
    // The others are untouched.
    const x = row(TA[1]);
    await stub.publish([x]);
    await a.rowsAre(1);
    expect(sameRow(a.rows()[0], x)).toBe(true);
    expect(a.closed()).toBeNull();
    expect(c.closed()).toBeNull();
    a.ws.close(1000);
    c.ws.close(1000);
  });
});

describe("RealtimeDO caps and age", () => {
  it("429 per client and 503 in total, counted through tags without deserialising any attachment", async () => {
    const stub = fresh();
    const spy = vi.spyOn(WebSocket.prototype, "deserializeAttachment");
    const open: Sock[] = [];
    const A = clientTag();
    try {
      for (let i = 0; i < 8; i++) open.push(await connect(stub, A));
      const ninth = await upgrade(stub, A);
      expect(ninth.status).toBe(429);
      expect(ninth.headers.get("retry-after")).toBe("60");
      await ninth.text(); // an unread body keeps the request in flight (and blocks the eviction below)
      open.push(await connect(stub)); // another client
      open.push(await connect(stub, null)); // no tag: "none"
      open.push(await connect(stub, "not-a-tag")); // also "none"

      await setLimits(stub, { total: 11 });
      const full = await upgrade(stub);
      expect(full.status).toBe(503);
      expect(full.headers.get("retry-after")).toBe("60");
      await full.text();
      expect(spy).not.toHaveBeenCalled();

      // Positive control: after a wake, the topic index is rebuilt from the attachments (through the spy).
      await evictDurableObject(stub);
      open[0].send({ f: "sub", topics: [topic()] });
      await pairsAre(stub, 1);
      expect(spy.mock.calls.length).toBeGreaterThanOrEqual(open.length);
    } finally {
      spy.mockRestore();
    }
    // Closing frees the client's slots.
    for (const s of open.slice(0, 8)) s.ws.close(1000);
    const res = await eventually(
      async () => {
        const r = await upgrade(stub, A);
        if (r.status !== 101) await r.text();
        return r;
      },
      (r) => r.status === 101,
      "a free slot",
    );
    watch(res.webSocket!).ws.close(1000);
    for (const s of open.slice(8)) s.ws.close(1000);
  });

  it("503 when accepting fails", async () => {
    const stub = fresh();
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await inside(stub, (_i, state) => {
        Object.defineProperty(state, "acceptWebSocket", {
          configurable: true,
          value: () => {
            throw new Error("accept failed");
          },
        });
      });
      const res = await upgrade(stub);
      expect(res.status).toBe(503);
      expect(res.headers.get("retry-after")).toBe("60");
      await res.text();
    } finally {
      errors.mockRestore();
      await inside(stub, (_i, state) => void delete (state as unknown as Record<string, unknown>).acceptWebSocket);
    }
    const ok = await connect(stub);
    ok.ws.close(1000);
  });

  it("closes sockets older than an hour with 4000: exact age before sending, hour tags when counting", async () => {
    const stub = fresh();
    const h0 = Math.floor(Date.now() / HOUR_MS) * HOUR_MS;
    const T = topic();

    // Exact age: accepted at h0 + 1 s, sent to at h0 + 1 h + 61 s (the previous hour's tag is not swept).
    await setClock(stub, h0 + 1_000);
    const old = await connect(stub);
    old.send({ f: "sub", topics: [T] });
    await pairsAre(stub, 1);
    await setClock(stub, h0 + HOUR_MS + 2_000);
    const young = await connect(stub);
    young.send({ f: "sub", topics: [T] });
    await pairsAre(stub, 2);
    expect(old.closed()).toBeNull(); // counting at h0 + 1 h did not close the previous hour
    await setClock(stub, h0 + HOUR_MS + 61_000);
    await stub.publish([row(T)]);
    await old.closedWith(4000);
    await young.rowsAre(1);
    expect(old.rows()).toEqual([]);

    // Hour tags: at h0 + 2 h + 3 s, counting closes every socket accepted before h0 + 1 h.
    await setClock(stub, h0 + 1_500);
    const ancient = await connect(stub);
    await setClock(stub, h0 + 2 * HOUR_MS + 3_000);
    const fresh2 = await connect(stub);
    await ancient.closedWith(4000);
    expect(young.closed()).toBeNull();
    expect(fresh2.closed()).toBeNull();
    for (const s of [young, fresh2]) s.ws.close(1000);
  });

  it("hibernated sockets still receive after evictDurableObject (new boot, index rebuilt lazily)", async () => {
    const stub = fresh();
    const [T1, T2] = [topic(), topic()];
    const a = await connect(stub);
    const { boot } = await a.hello();
    a.send({ f: "sub", topics: [T1, T2] });
    await pairsAre(stub, 2);

    await evictDurableObject(stub);
    const x = row(T1);
    await stub.publish([x]);
    await a.rowsAre(1);
    expect(sameRow(a.rows()[0], x)).toBe(true);
    expect(a.rows()[0].seq).toBe(1); // seq restarts with the new boot

    // Control frames keep working on the rebuilt index.
    a.send({ f: "unsub", topics: [T1] });
    await pairsAre(stub, 1);
    const y = row(T2);
    await stub.publish([row(T1), y]);
    await a.rowsAre(2);
    expect(sameRow(a.rows()[1], y)).toBe(true);

    // The ring did not survive: RESUME with the old boot gets GAP.
    const b = await connect(stub);
    const h = await b.hello();
    expect(P.b64u(h.boot)).not.toBe(P.b64u(boot));
    b.send({ f: "resume", boot, since: 0, topics: [T2] });
    await b.until(() => b.frames.length >= 2, "GAP");
    expect(b.frames[1]).toEqual({ f: "gap", since: 0 });
    a.ws.close(1000);
    b.ws.close(1000);
  });

  it("publish rejects malformed rows", async () => {
    const stub = fresh();
    await inside(stub, (inst) => {
      const ok = row(topic());
      expect(() => inst.publish([{ ...ok, topic: P.random(15) }])).toThrow(TypeError);
      expect(() => inst.publish([{ ...ok, label: P.random(17) }])).toThrow(TypeError);
      expect(() => inst.publish([{ ...ok, cls: 4 }])).toThrow(TypeError);
      expect(() => inst.publish([{ ...ok, body: P.random(P.BODY_LENS[1]) }])).toThrow(TypeError);
      expect(() => inst.publish([{ ...ok, E: 0x10000 }])).toThrow(TypeError);
      expect(() => inst.publish([{ ...ok, t: -1 }])).toThrow(TypeError);
      expect(inst.seq).toBe(0);
    });
  });
});
