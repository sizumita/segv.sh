// Integrity (docs/STAGE1-PLAN.md M8 integrity.spec.ts; ports of 3de5f5e:test/engine/sync.spec.ts #40–#45; SPEC §12):
// row immutability, lane omission through prev / prevh, receipts, checkpoints (key, rollback, rewrite, the range and
// its skip), and the split-view check.
import { describe, expect, it } from "vite-plus/test";
import {
  BAD_RECEIPT,
  CHANGED_ENTRY,
  CKPT_KEY,
  KEY_CHANGED,
  hiding,
  rewritten,
  rolledBack,
  splitView,
} from "../../src/client/integrity";
import { UNDECRYPTABLE } from "../../src/client/sync";
import type { Engine } from "../../src/client/types";
import {
  CKPT_PERIOD_MS,
  I,
  P,
  buildMessage,
  chat,
  conv,
  engineFor,
  epoch,
  freshWorldPerTest,
  junkRow,
  localStore,
  makeUser,
  postRow,
  server,
  settle,
} from "./harness";

freshWorldPerTest();

async function pair() {
  const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
  const A = await engineFor(alice);
  const B = await engineFor(bob);
  const id = await A.createConversation(["bob"]);
  await settle(A, B);
  B.markRead(id);
  await settle(A, B);
  return { alice, bob, A, B, id };
}

const crit = (E: Engine) => E.getState().warnings;

/** Mints `n` checkpoints: a row changes the shard head, then a minute passes (world.tick moves every clock). */
function mint(n: number): void {
  for (let i = 0; i < n; i++) {
    junkRow(server().era);
    server().tick(CKPT_PERIOD_MS);
    server().ckpt.tick();
  }
}

describe("row immutability (§12.1, SEC-14)", () => {
  it("a changed body, t or class of a row this session saw is a critical warning", async () => {
    const { A, B, id } = await pair();
    await A.sendText(id, "original");
    await settle(A, B);
    const ep = epoch(B, id);
    const lane = ep.lanes[P.memberIndex(ep.D, epoch(A, id).D.members[epoch(A, id).myIndex].uid)];
    const at = lane.last!;
    expect(crit(B)).toEqual([]);
    server().shard.retime(at.E, at.label, server().shard.row(at.E, at.label)!.t + 5);
    await I(B).api.get([{ E: at.E, label: at.label, mode: 1 }]);
    expect(crit(B)).toEqual([CHANGED_ENTRY]);
  });

  it("a realtime frame with another body for a fetched row is a critical warning", async () => {
    const { A, B, id } = await pair();
    await A.sendText(id, "seen");
    await settle(A, B);
    const at = epoch(B, id).lanes.find((l) => l.last)!.last!;
    const row = server().shard.row(at.E, at.label)!;
    const body = P.random(row.body.length);
    server().publish([{ topic: epoch(B, id).topic, E: at.E, label: at.label, t: row.t, cls: row.cls, body }]);
    await settle(A, B);
    expect(crit(B)).toContain(CHANGED_ENTRY);
  });
});

describe("lane omission (§12.2, COR-10)", () => {
  it("an omitted middle row: later rows are still shown, with one 'hiding messages' warning", async () => {
    const { alice, A, B, id } = await pair();
    const ep = epoch(A, id);
    const ai = ep.myIndex;
    const E = server().era;
    server().shard.hide(E, P.Lmsg(ep.keys.rk, ai, E, 2), "bob");
    for (let i = 0; i < 6; i++) await A.sendText(id, `m${i}`);
    await settle(A, B);
    expect(chat(B, id)).toEqual(["alice: m0", "alice: m1", "alice: m3", "alice: m4", "alice: m5"]);
    expect(crit(B)).toEqual([hiding("@alice")]);
    expect(crit(A)).toEqual([]);
    void alice;
  });

  it("a row whose prev names another body is 'showing different messages'", async () => {
    const { alice, A, B, id } = await pair();
    await A.sendText(id, "first");
    await settle(A, B);
    const ep = epoch(A, id);
    const lane = ep.lanes[ep.myIndex];
    const last = lane.last!;
    // a validly signed row of alice whose prevh names a different body at her last slot
    const forged = buildMessage(
      alice,
      ep,
      { E: lane.next.E, n: lane.next.n, prev: { E: last.E, n: last.n, label: last.label, body: P.random(last.body.length), cls: 0 } },
      { type: P.MT.TEXT, text: "forked" },
    );
    postRow(ep, forged);
    await settle(A, B);
    expect(crit(B)).toContain(
      "the server is showing different messages from @alice to different members",
    );
  });
});

describe("receipts (§12.5)", () => {
  it("an invalid receipt on a put is a critical warning", async () => {
    const { A, id } = await pair();
    server().hooks.afterPut = (_rows, results, who) => {
      if (who !== "alice") return;
      for (const r of results) if (r.s === "ok") r.receipt = P.random(64);
    };
    await A.sendText(id, "receipted");
    server().hooks.afterPut = undefined;
    expect(crit(A)).toContain(BAD_RECEIPT);
  });
});

describe("checkpoints (§12.3)", () => {
  it("the first checkpoint is pinned and shown; a returning device whose checkpoint advanced reports nothing", async () => {
    mint(1);
    const alice = makeUser("alice");
    const A = await engineFor(alice);
    const q1 = server().ckpt.latest()!.q;
    expect(A.getState().head.seq).toBe(q1);
    expect(A.getState().head.h).toBe(P.b64u(server().ckpt.latest()!.C));
    const stored = JSON.parse(localStore.get(CKPT_KEY)!) as { q: number; k: string };
    expect(stored.q).toBe(q1);
    await A.logout();
    mint(5);
    const A2 = await engineFor(alice);
    expect(crit(A2)).toEqual([]);
    expect(A2.getState().head.seq).toBe(server().ckpt.latest()!.q);
    expect((JSON.parse(localStore.get(CKPT_KEY)!) as { q: number }).q).toBe(server().ckpt.latest()!.q);
  });

  it("a different server key is a critical warning and nothing is verified", async () => {
    mint(1);
    localStore.set(
      CKPT_KEY,
      JSON.stringify({ k: P.b64u(P.random(32)), q: 1, C: P.b64u(P.random(32)), at: server().now() }),
    );
    const A = await engineFor(makeUser("alice"));
    expect(crit(A)).toContain(KEY_CHANGED);
    expect(A.getState().head.seq).toBe(0);
  });

  it("a rolled-back log warns, and the stored value is kept (sticky across sessions)", async () => {
    mint(2);
    const latest = server().ckpt.latest()!;
    const k = (await (await fetch("/api/v2/params")).json()) as { srvKey: string };
    localStore.set(
      CKPT_KEY,
      JSON.stringify({ k: k.srvKey, q: latest.q + 10, C: P.b64u(P.random(32)), at: server().now() }),
    );
    const alice = makeUser("alice");
    const A = await engineFor(alice);
    expect(crit(A)).toContain(rolledBack(latest.q + 10, latest.q));
    await A.logout();
    const A2 = await engineFor(alice);
    expect(crit(A2)).toContain(rolledBack(latest.q + 10, latest.q));
  });

  it("equal q with a different C is 'history was rewritten', in every later session (CMP-16)", async () => {
    mint(2);
    const latest = server().ckpt.latest()!;
    const k = (await (await fetch("/api/v2/params")).json()) as { srvKey: string };
    localStore.set(
      CKPT_KEY,
      JSON.stringify({ k: k.srvKey, q: latest.q, C: P.b64u(P.random(32)), at: server().now() }),
    );
    const alice = makeUser("alice");
    const A = await engineFor(alice);
    expect(crit(A)).toContain(rewritten(latest.q));
    await A.logout();
    mint(2); // now latest.q > stored q: the range from the stored C does not match either
    const A2 = await engineFor(alice);
    expect(crit(A2)).toContain(rewritten(latest.q));
  });

  it("a forked chain below the stored checkpoint is 'history was rewritten'", async () => {
    mint(3);
    const alice = makeUser("alice");
    const A = await engineFor(alice);
    const stored = A.getState().head.seq;
    await A.logout();
    server().ckpt.forkAt(2);
    mint(2);
    const A2 = await engineFor(alice);
    expect(crit(A2)).toContain(rewritten(stored));
  });

  it("q jumping far ahead of the time since the stored checkpoint is 'rewritten'; after 30 days the range is skipped (SEC-8)", async () => {
    mint(1);
    const c1 = server().ckpt.latest()!;
    mint(62);
    const k = (await (await fetch("/api/v2/params")).json()) as { srvKey: string };
    localStore.set(CKPT_KEY, JSON.stringify({ k: k.srvKey, q: c1.q, C: P.b64u(c1.C), at: server().now() }));
    const alice = makeUser("alice");
    const A = await engineFor(alice);
    expect(crit(A)).toContain(rewritten(c1.q));
    await A.logout();
    localStore.set(
      CKPT_KEY,
      JSON.stringify({
        k: k.srvKey,
        q: c1.q,
        C: P.b64u(P.random(32)),
        at: server().now() - 31 * 86_400_000,
      }),
    );
    const A2 = await engineFor(alice);
    expect(crit(A2)).toEqual([]);
    expect(A2.getState().head.seq).toBe(server().ckpt.latest()!.q);
  });
});

describe("split view (§12.4)", () => {
  it("a reference that matches the first 8 bytes only is still detected (SEC-7); one line per sender", async () => {
    mint(1);
    const { bob, A, B, id } = await pair();
    const ck = I(A).ckpt!.latest!;
    const ep = epoch(B, id);
    const bi = ep.myIndex;
    let n = ep.lanes[bi].next.n;
    for (let i = 0; i < 30; i++) {
      const forged = P.concat(P.t16(ck.C).subarray(0, 8), P.random(8));
      postRow(
        ep,
        buildMessage(bob, ep, { E: server().era, n: n++ }, {
          type: P.MT.TEXT,
          text: `x${i}`,
          ckq: ck.q,
          ck16: forged,
        }),
      );
    }
    await settle(A);
    expect(crit(A).filter((w) => w.startsWith("split view"))).toEqual([splitView("@bob")]);
    // an honest reference to the same checkpoint passes
    expect(chat(A, id).length).toBe(30);
  });

  it("the critical warnings stay first under a noise flood; noise is deduplicated with a count", async () => {
    mint(1);
    const { mallory, A, id } = await (async () => {
      const [alice, mallory] = ["alice", "mallory"].map((h) => makeUser(h));
      const A = await engineFor(alice);
      const id = await A.createConversation(["mallory"]);
      await settle(A);
      return { mallory, A, id };
    })();
    const ck = I(A).ckpt!.latest!;
    const ep = epoch(A, id);
    const mi = P.memberIndex(ep.D, mallory.uid);
    postRow(
      ep,
      buildMessage(mallory, ep, { E: server().era, n: 0 }, {
        type: P.MT.TEXT,
        text: "forked view",
        ckq: ck.q,
        ck16: P.random(16),
      }),
    );
    for (let n = 1; n <= 120; n++) junkRow(server().era, P.Lmsg(ep.keys.rk, mi, server().era, n));
    postRow(
      ep,
      buildMessage(mallory, ep, { E: server().era, n: 121 }, { type: P.MT.TEXT, text: "after junk" }),
    );
    await settle(A);
    const w = crit(A);
    expect(w[0]).toBe(splitView("@mallory"));
    expect(w).toContain(`${UNDECRYPTABLE} (×120)`);
    expect(w.length).toBeLessThanOrEqual(6);
    void conv;
  });
});
