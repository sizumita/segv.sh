/** LogDO internals: atomicity under concurrency, cold start, hibernated sockets, D1 outbox retries. */
import { evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import * as P from "../../src/lib/proto";
import type { LogDO } from "../../src/server/log-do";
import type { AppendResult, AppendRow } from "../../src/server/types";
import { api, appendOk, downloadVerified, head, makeAccount, randomMsgRow, registerOk } from "./helpers";

const stub = () => (env.LOG as unknown as DurableObjectNamespace<LogDO>).getByName("global");
const msgRow = (tag = P.random(16)): AppendRow => ({ kind: 4, tag, body: P.random(P.MSG_BODY_LENS[0]) });
const invRow = (tag = P.random(16)): AppendRow => ({ kind: 3, tag, body: P.random(P.INV_BODY_LENS[0]) });
const outbox = (state: DurableObjectState) => state.storage.sql.exec<{ n: number }>("SELECT count(*) AS n FROM d1_outbox").one().n;

describe("LogDO.append", () => {
  it("first writer wins a tag race; the loser's whole batch is dropped", async () => {
    const tag = P.random(16);
    const loserOnly = P.random(16);
    const h0 = await head();
    const [r1, r2] = (await Promise.all([
      stub().append([msgRow(tag)]),
      stub().append([invRow(loserOnly), msgRow(tag)]),
    ])) as AppendResult[];
    const oks = [r1, r2].filter((r) => r.ok);
    expect(oks).toHaveLength(1);
    expect([r1, r2].find((r) => !r.ok)).toEqual({ ok: false, conflict: "tag" });
    const h1 = await head();
    expect(h1.seq - h0.seq).toBe(r1.ok ? 1 : 2);
  });

  it("enforces handle and uid uniqueness inside the transaction", async () => {
    const a = makeAccount();
    const user = (handle: string, uid: string): AppendRow => ({ kind: 1, tag: P.random(16), body: P.utf8("{}"), handle, uid });
    const uid2 = P.b64u(P.random(16));
    const [x, y] = (await Promise.all([stub().append([user(a.handle, a.uidB64)]), stub().append([user(a.handle, uid2)])])) as AppendResult[];
    expect([x.ok, y.ok].sort()).toEqual([false, true]);
    expect([x, y].find((r) => !r.ok)).toEqual({ ok: false, conflict: "handle" });
    const z = (await stub().append([user("someone_else", a.uidB64)])) as AppendResult;
    expect(z).toEqual({ ok: false, conflict: "uid" });
  });

  it("rejects malformed RPC input", async () => {
    const bad: unknown[][] = [
      [],
      Array.from({ length: 41 }, () => msgRow()),
      [{ kind: 9, tag: P.random(16), body: P.random(10) }],
      [{ kind: 4, tag: P.random(15), body: P.random(10) }],
      [{ kind: 4, tag: P.random(16), body: new Uint8Array(0) }],
      [{ kind: 4, tag: P.random(16), body: new Uint8Array(64 * 1024 + 1) }],
      [{ kind: 1, tag: P.random(16), body: P.random(10) }], // no handle / uid
      [{ kind: 4, tag: P.random(16), body: P.random(10), handle: "abc", uid: P.b64u(P.random(16)) }],
      [msgRow(), msgRow()], // at most one kind-4 row per batch
      [
        { kind: 1, tag: P.random(16), body: P.random(10), handle: "abc_1", uid: P.b64u(P.random(16)) },
        { kind: 1, tag: P.random(16), body: P.random(10), handle: "abc_2", uid: P.b64u(P.random(16)) },
      ],
    ];
    const h0 = await head();
    // Called on the instance: RPC rejections from a DO surface as unhandled rejections in vitest.
    await runInDurableObject(stub(), async (inst: LogDO) => {
      for (const rows of bad) await expect(inst.append(rows as AppendRow[])).rejects.toThrow(TypeError);
      expect(() => inst.since(-1, 10)).toThrow(RangeError);
      expect(() => inst.since(0, 1001)).toThrow(RangeError);
      expect(() => inst.since(0.5, 10)).toThrow(RangeError);
      expect(() => inst.userRow("not b64!")).toThrow();
    });
    expect(await head()).toEqual(h0);
  });
});

describe("LogDO lifecycle", () => {
  it("reloads the head after eviction; hibernated sockets still get broadcasts", async () => {
    await appendOk([randomMsgRow()]);
    const res = await api("/api/ws", { headers: { upgrade: "websocket" } });
    const ws = res.webSocket!;
    ws.accept();
    const frames: string[] = [];
    ws.addEventListener("message", (e) => {
      frames.push(String(e.data));
    });

    await evictDurableObject(stub());
    const row = randomMsgRow();
    await appendOk([row]);
    await downloadVerified(1000); // chain continues seamlessly across the cold start

    const tag = P.b64u(row.tag);
    for (let i = 0; i < 50 && !frames.some((f) => f.includes(tag)); i++) await new Promise((r) => setTimeout(r, 20));
    expect(frames.some((f) => f.includes(tag))).toBe(true);
    ws.close(1000);
  });

  it("a D1 outage never loses index rows: logged, retried by the alarm, idempotent", async () => {
    const a = makeAccount();
    await registerOk(a);
    const credId = P.random(16);
    const w = P.makeWrap(a.uid, "passkey", credId, P.credKem(P.random(32), credId), a.AK, a.ident, Date.now());
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runInDurableObject(stub(), async (inst: LogDO, state) => {
        const self = inst as unknown as { env: Env };
        const realEnv = self.env;
        const brokenDb = new Proxy(realEnv.DB, {
          get: (t, k) => (k === "batch" ? async () => Promise.reject(new Error("D1 is down")) : Reflect.get(t, k)),
        });
        self.env = new Proxy(realEnv, { get: (t, k) => (k === "DB" ? brokenDb : Reflect.get(t, k)) });
        try {
          const res = await inst.append([{ kind: 2, tag: P.wrapTag(w.record), body: P.utf8(JSON.stringify(w)) }]);
          expect(res.ok).toBe(true); // the append itself is never undone
          expect(state.storage.sql.exec<{ n: number }>("SELECT count(*) AS n FROM d1_outbox").one().n).toBe(1);
          expect(await state.storage.getAlarm()).not.toBeNull();
        } finally {
          self.env = realEnv;
        }
      });
      expect(errors.mock.calls.some((c) => String(c[0]).includes("d1 index failed"))).toBe(true);
    } finally {
      errors.mockRestore();
    }
    const lookup = async () => ((await (await api(`/api/wraps/${P.b64u(credId)}`)).json()) as { wraps: unknown[] }).wraps;
    expect(await lookup()).toEqual([]);

    expect(await runDurableObjectAlarm(stub())).toBe(true);
    expect(await lookup()).toHaveLength(1);

    // Re-indexing everything again is a no-op (INSERT OR IGNORE).
    const count = async () =>
      (await env.DB.prepare("SELECT (SELECT count(*) FROM users) + (SELECT count(*) FROM wraps) AS n").first<{ n: number }>())!.n;
    const before = await count();
    await runInDurableObject(stub(), async (inst: LogDO, state) => {
      state.storage.sql.exec("INSERT OR IGNORE INTO d1_outbox (seq) SELECT seq FROM log WHERE kind IN (1, 2)");
      await (inst as unknown as { flushIndex(): Promise<void> }).flushIndex();
      expect(outbox(state)).toBe(0);
    });
    expect(await count()).toBe(before);
  });

  it("arms the index alarm with the commit and clears it once D1 has the rows", async () => {
    const a = makeAccount();
    await registerOk(a);
    await runInDurableObject(stub(), async (_inst: LogDO, state) => {
      expect(outbox(state)).toBe(0);
      expect(await state.storage.getAlarm()).toBeNull();
    });
  });

  it("a hung D1 does not hold the append; after an eviction the committed alarm drains the outbox", async () => {
    const a = makeAccount();
    await registerOk(a);
    const credId = P.random(16);
    const w = P.makeWrap(a.uid, "passkey", credId, P.credKem(P.random(32), credId), a.AK, a.ident, Date.now());
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runInDurableObject(stub(), async (inst: LogDO, state) => {
        const self = inst as unknown as { env: Env; indexTimeouts: { waitMs: number; batchMs: number } };
        const realEnv = self.env;
        const hungDb = new Proxy(realEnv.DB, {
          get: (t, k) => (k === "batch" ? () => new Promise<never>(() => {}) : Reflect.get(t, k)),
        });
        self.env = new Proxy(realEnv, { get: (t, k) => (k === "DB" ? hungDb : Reflect.get(t, k)) });
        // Shorter than production (2 s / 30 s) so the test stays fast; the order is what matters.
        self.indexTimeouts = { waitMs: 100, batchMs: 1_000 };
        const t0 = Date.now();
        const res = await inst.append([{ kind: 2, tag: P.wrapTag(w.record), body: P.utf8(JSON.stringify(w)) }]);
        expect(res.ok).toBe(true);
        expect(Date.now() - t0).toBeLessThan(900); // answered after the index wait, while D1 still hangs
        expect(outbox(state)).toBe(1);
        expect(await state.storage.getAlarm()).not.toBeNull(); // committed with the rows, not by a failure
      });
      // The object goes away while the D1 call hangs (deploy, crash, CPU limit).
      await evictDurableObject(stub());
    } finally {
      errors.mockRestore();
    }
    const lookup = async () => ((await (await api(`/api/wraps/${P.b64u(credId)}`)).json()) as { wraps: unknown[] }).wraps;
    expect(await lookup()).toEqual([]);
    // Kind-3/4 traffic alone does not drain the outbox; the alarm does.
    await appendOk([randomMsgRow()]);
    await runInDurableObject(stub(), async (_inst: LogDO, state) => {
      expect(outbox(state)).toBe(1);
      expect(await state.storage.getAlarm()).not.toBeNull();
    });
    expect(await runDurableObjectAlarm(stub())).toBe(true);
    expect(await lookup()).toHaveLength(1);
    await runInDurableObject(stub(), async (_inst: LogDO, state) => {
      expect(outbox(state)).toBe(0);
      expect(await state.storage.getAlarm()).toBeNull();
    });
  });
});
