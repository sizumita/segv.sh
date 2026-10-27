// Claims: e-validity, winner and finality, processing, commits (docs/STAGE1-PLAN.md M7 claims.spec.ts tests 1–3,
// 5, 7–9, 11–15, 19, 27; SPEC §6.3–§6.6, §6.10, §11.3 step 2).
import { describe, expect, it } from "vite-plus/test";
import { CHANGING } from "../../src/client/conv";
import { INVALID_CHANGE, frozenInvalid, frozenNoKey } from "../../src/client/claims";
import { FROZEN_REMOVAL } from "../../src/client/send";
import { UNDECRYPTABLE } from "../../src/client/sync";
import type { Engine } from "../../src/client/types";
import {
  I,
  P,
  buildClaim,
  buildMessage,
  chat,
  commitChange,
  conv,
  dummyEntry,
  engineFor,
  entryOutcome,
  epoch,
  forgeJoin,
  freshWorldPerTest,
  garbleDesc,
  junkRow,
  makeUser,
  mustView,
  postRow,
  readableWith,
  replaceEntry,
  server,
  settle,
  sleep,
  systemLines,
  view,
  type TestUser,
} from "./harness";

freshWorldPerTest();

/** A group created by the first user, opened (accepted) by every other one. */
async function group(names: string[], name = "g") {
  const users = names.map((h) => makeUser(h));
  const engines: Engine[] = [];
  for (const u of users) engines.push(await engineFor(u));
  const id = await engines[0].createConversation(names.slice(1), name);
  await settle(...engines);
  for (const E of engines.slice(1)) E.markRead(id);
  await settle(...engines);
  return { users, engines, id };
}

const crit = (E: Engine) => E.getState().warnings;

describe("winner (tests 1–3)", () => {
  it("the first e-valid claim wins over a later one; junk before it is skipped with a noise warning", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const ep = epoch(A, id);
    const E = server().era;
    junkRow(E, P.Lctl(ep.keys.rk, E, 0), 1);
    const first = await commitChange(alice, ep, [alice, bob, carol], "first");
    await commitChange(bob, ep, [alice, bob, carol], "second");
    await settle(A, B, C);
    expect(first.claim.n).toBe(1);
    for (const X of [A, B, C]) {
      expect(mustView(X, id).name).toBe("# first");
      expect(mustView(X, id).epoch).toBe(1);
      expect(crit(X)).toContain(UNDECRYPTABLE);
    }
    expect(systemLines(B, id).at(-1)).toBe("@alice renamed the conversation to “first”");
  });

  it("a claim whose bundle is registered at or after the claim's time is e-invalid for every member", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const ep = epoch(A, id);
    await commitChange(alice, ep, [alice, bob, carol], "late", {
      afterRegister: (x) => server().blobreg.forceT(x.id, x.t + 3600),
    });
    await settle(A, B, C);
    for (const X of [A, B, C]) {
      expect(mustView(X, id).epoch).toBe(0);
      expect(mustView(X, id).name).toBe("# g");
      expect(crit(X)).toContain(INVALID_CHANGE);
    }
    await B.sendText(id, "still in e");
    await settle(A, B, C);
    expect(chat(C, id)).toEqual(["bob: still in e"]);
  });

  it("a MISS within SKEW of the claim's time is retried, not decided", async () => {
    const {
      users: [alice, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    const ep = epoch(A, id);
    const bundleId = P.random(32);
    const row = buildClaim(alice, ep, {
      hD: P.random(32),
      ekc: P.random(32),
      bundleId,
      bundleSize: P.SGB2_SIZES[0],
    });
    let early = 2;
    server().blobreg.missNow((idB, now) => (idB === P.b64u(bundleId) && early-- > 0 ? now - 5 : null));
    postRow(ep, row);
    await settle(A, B);
    const metas = server().requests.filter(
      (r) => r.path === `/api/v2/blob/${P.b64u(bundleId)}/meta` && r.who === "bob",
    );
    expect(metas.length).toBeGreaterThanOrEqual(2);
    for (const X of [A, B]) {
      expect(mustView(X, id).epoch).toBe(0);
      expect(crit(X)).toContain(INVALID_CHANGE);
    }
    void bob;
  });
});

describe("freezes (tests 5, 7–9)", () => {
  it("an e-valid claim with an invalid D′ freezes everyone; a later honest claim is not used; messaging goes on", async () => {
    const {
      users: [alice, bob, carol, mallory],
      engines: [A, B, C, M],
      id,
    } = await group(["alice", "bob", "carol", "mallory"]);
    const ep = epoch(A, id);
    const all = [alice, bob, carol, mallory];
    await commitChange(mallory, ep, all, "x", { patchBlob: garbleDesc });
    await commitChange(alice, ep, all, "honest");
    await settle(A, B, C, M);
    for (const X of [A, B, C]) {
      expect(mustView(X, id).epoch).toBe(0);
      expect(mustView(X, id).frozen).toBe(true);
      expect(mustView(X, id).canSend).toBe(true);
      expect(crit(X)).toContain(frozenInvalid("@mallory"));
    }
    await B.sendText(id, "hello in e");
    await settle(A, B, C, M);
    expect(chat(A, id)).toEqual(["bob: hello in e"]);
    await expect(A.addMembers(id, ["mallory"])).rejects.toThrow(/can no longer change/);
  });

  it("a J for a D′-invalid epoch is ignored by every member (the claimed rule)", async () => {
    const {
      users: [alice, bob, carol, mallory],
      engines: [A, B, C, M],
      id,
    } = await group(["alice", "bob", "carol", "mallory"]);
    const ep = epoch(A, id);
    const all = [alice, bob, carol, mallory];
    const r = await commitChange(mallory, ep, all, "y", {
      D: (f) => ({ ...f, prev: P.random(32) }),
    });
    await settle(A, B, C, M);
    const before = [A, B, C].map((X) => crit(X).slice());
    for (const u of [alice, bob, carol]) forgeJoin(u, r.J);
    await settle(A, B, C, M);
    [A, B, C].forEach((X, i) => {
      expect(mustView(X, id).epoch).toBe(0);
      expect(mustView(X, id).frozen).toBe(true);
      expect(crit(X)).toEqual(before[i]);
      expect(I(X).self!.fold.epochs.size).toBe(0);
    });
    expect(crit(A)).toContain(frozenInvalid("@mallory"));
  });

  it("partial withholding freezes everyone: the withheld member as never delivered, the others as invalid", async () => {
    const {
      users: [alice, bob, carol, mallory],
      engines: [A, B, C, M],
      id,
    } = await group(["alice", "bob", "carol", "mallory"]);
    const ep = epoch(A, id);
    const bi = P.memberIndex(ep.D, bob.uid);
    await commitChange(mallory, ep, [alice, bob, carol, mallory], undefined, {
      patchBlob: (blob) => replaceEntry(blob, bi, dummyEntry(ep.D.conv, 1, bi)),
    });
    await settle(A, B, C, M);
    expect(conv(B, id).frozen).toBe("nokey");
    expect(crit(B)).toContain(frozenNoKey("@mallory"));
    for (const X of [A, C]) {
      expect(conv(X, id).frozen).toBe("invalid");
      expect(crit(X)).toContain(frozenInvalid("@mallory"));
    }
    for (const X of [A, B, C, M]) expect(mustView(X, id).epoch).toBe(0);
    await B.sendText(id, "hello?");
    await A.sendText(id, "hi bob");
    await settle(A, B, C, M);
    expect(chat(C, id)).toEqual(["bob: hello?", "alice: hi bob"]);
    expect(chat(B, id)).toContain("alice: hi bob");
    // A reload re-derives the same freeze.
    const B2 = await engineFor(bob);
    expect(conv(B2, id).frozen).toBe("nokey");
  });

  it("an entry sealed to the right key with fresh randomness freezes everyone as invalid", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const ep = epoch(A, id);
    const bi = P.memberIndex(ep.D, bob.uid);
    await commitChange(carol, ep, [alice, bob, carol], undefined, {
      patchBlob: (blob, EK) =>
        replaceEntry(blob, bi, P.seal(bob.id.kemPk, P.REKEY_LABEL, P.rekeyCtx(ep.D.conv, 1, bi), EK)),
    });
    await settle(A, B, C);
    for (const X of [A, B, C]) {
      expect(conv(X, id).frozen).toBe("invalid");
      expect(mustView(X, id).epoch).toBe(0);
    }
  });

  it("a covert removal is impossible: D′ that omits a member rm keeps freezes everyone, and its J is ignored", async () => {
    const {
      users: [alice, bob, victor, mallory],
      engines: [A, B, V, M],
      id,
    } = await group(["alice", "bob", "victor", "mallory"]);
    const ep = epoch(A, id);
    const r = await commitChange(mallory, ep, [alice, bob, mallory], undefined, { rm: 0 });
    await settle(A, B, V, M);
    expect(conv(V, id).frozen).toBe("nokey");
    expect(crit(V)).toContain(frozenNoKey("@mallory"));
    for (const X of [A, B]) expect(crit(X)).toContain(frozenInvalid("@mallory"));
    for (const X of [A, B, V]) {
      expect(mustView(X, id).epoch).toBe(0);
      expect(systemLines(X, id).some((l) => l.includes("removed"))).toBe(false);
    }
    for (const u of [alice, bob, victor]) forgeJoin(u, r.J);
    await settle(A, B, V, M);
    for (const X of [A, B, V]) expect(mustView(X, id).epoch).toBe(0);
    expect(view(V, id)!.frozen).toBe(true);
  });

  it("removal lines agree; a D′-invalid claim that removes a member blocks texts but not leaving", async () => {
    const {
      users: [alice, , victor],
      engines: [A, B, V],
      id,
    } = await group(["alice", "bob", "victor"]);
    await B.removeMember(id, victor.uidB);
    await settle(A, B, V);
    expect(systemLines(A, id).at(-1)).toBe("@bob removed @victor");
    expect(systemLines(V, id).at(-1)).toBe("@bob removed you");

    const g2 = await group(["carol", "dave", "mallory", "vera"]);
    const [C, D, M, Vr] = g2.engines;
    const [carol, dave, mallory, vera] = g2.users;
    const ep = epoch(C, g2.id);
    await commitChange(mallory, ep, [carol, dave, mallory], undefined, { patchBlob: garbleDesc });
    await settle(C, D, M, Vr);
    for (const X of [C, D, M]) {
      expect(systemLines(X, g2.id).at(-1)).toBe(
        X === M ? "you removed @vera" : "@mallory removed @vera",
      );
      expect(mustView(X, g2.id).canSend).toBe(false);
      expect(mustView(X, g2.id).blocked).toBe("frozen");
      expect(mustView(X, g2.id).frozen).toBe(true);
    }
    expect(systemLines(Vr, g2.id).at(-1)).toBe("@mallory removed you");
    const readable = readableWith(ep.keys.mk).length;
    await C.sendText(g2.id, "can vera read this?");
    expect(C.getState().error).toBe(FROZEN_REMOVAL);
    expect(readableWith(ep.keys.mk).length).toBe(readable);
    await D.leave(g2.id);
    await settle(C, D, M);
    expect(systemLines(D, g2.id)).toContain("you left the conversation");
    expect(systemLines(C, g2.id)).toContain("@dave left");
    void [alice, carol, dave, vera];
  });
});

describe("cuts (test 11)", () => {
  it("a cut beyond the claim's era is e-invalid", async () => {
    const {
      users: [alice, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    const ep = epoch(A, id);
    await commitChange(alice, ep, [alice, bob], "far", {
      cuts: (cs) => cs.map((c, j) => (j === 1 ? { E: 0xfffe, cnt: 0 } : c)),
    });
    await settle(A, B);
    for (const X of [A, B]) {
      expect(mustView(X, id).epoch).toBe(0);
      expect(crit(X)).toContain(INVALID_CHANGE);
    }
  });

  it("low cuts never hide a removed member's earlier rows; rows after the claim are dropped and retracted", async () => {
    const {
      users: [alice, bob, rita],
      engines: [A, B, R],
      id,
    } = await group(["alice", "bob", "rita"]);
    await R.sendText(id, "before the claim");
    await settle(A, B, R);
    const ep = epoch(A, id);
    const ri = P.memberIndex(ep.D, rita.uid);
    const lane = conv(R, id).epochs.get(0)!.lanes[ri];
    const r = await commitChange(alice, ep, [alice, bob], undefined, {
      cuts: (cs) => cs.map(() => ({ E: ep.Estart!, cnt: 0 })),
      hideFrom: ["bob"],
    });
    // Rita's row stored after the claim: bob applies it before he sees the claim.
    const late = buildMessage(
      rita,
      ep,
      { E: server().era, n: lane.next.E === server().era ? lane.next.n : 0 },
      { type: P.MT.TEXT, text: "after the claim" },
    );
    server().tick(1001);
    postRow(ep, late);
    await I(B).catchUp();
    expect(chat(B, id)).toContain("rita: after the claim");
    server().shard.unhide(r.claim.E, r.claim.label);
    await settle(A, B, R);
    for (const X of [A, B]) {
      expect(chat(X, id)).toEqual(["rita: before the claim"]);
      expect(mustView(X, id).epoch).toBe(1);
    }
  });
});

describe("bundle shape and undecided claims (test 12)", () => {
  it("a claim naming a large blob, a bad header or too small a B is e-invalid without fetching it", async () => {
    const {
      users: [alice, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    const ep = epoch(A, id);
    const big = server().putBlob(new Uint8Array(4 * 1024 * 1024).fill(7));
    const bad = server().putBlob(new Uint8Array(P.SGB2_SIZES[1]).fill(9));
    server().tick(2001);
    for (const b of [big, bad])
      postRow(
        ep,
        buildClaim(alice, ep, {
          hD: P.random(32),
          ekc: P.random(32),
          bundleId: P.fromB64u(b.id),
          bundleSize: P.SGB2_SIZES[1],
        }),
      );
    await settle(A, B);
    const gets = (idB: string) =>
      server().requests.filter((r) => r.method === "GET" && r.path === `/api/v2/blob/${idB}`).length;
    expect(gets(big.id)).toBe(0);
    expect(gets(bad.id)).toBeGreaterThan(0);
    for (const X of [A, B]) expect(mustView(X, id).epoch).toBe(0);
    void bob;
  });

  it("a claim with B = 8 for a group of 20 is refused by the local rules, without a request", async () => {
    const names = Array.from({ length: 19 }, (_, i) => `member${i}`);
    for (const h of names) makeUser(h);
    const alice = makeUser("alice");
    const A = await engineFor(alice);
    const id = await A.createConversation(names, "big");
    await settle(A);
    const ep = epoch(A, id);
    const bundleId = P.random(32);
    postRow(
      ep,
      buildClaim(alice, ep, {
        hD: P.random(32),
        ekc: P.random(32),
        bundleId,
        bundleSize: P.SGB2_SIZES[0],
      }),
    );
    await settle(A);
    expect(server().requests.some((r) => r.path.includes(P.b64u(bundleId)))).toBe(false);
    expect(crit(A)).toContain(INVALID_CHANGE);
  });

  it("an undecided claim makes a send wait 30 s and fail; once decided, a send goes to e+1", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const ep = epoch(A, id);
    const r = await commitChange(alice, ep, [alice, bob, carol], "next", { noPost: true });
    server().blobs.failGet(P.b64u(r.bundleId), Infinity);
    postRow(ep, r.claim);
    await I(B).catchUp();
    expect(mustView(B, id).blocked).toBe("");
    const send = B.sendText(id, "while changing");
    await sleep(100);
    server().tick(31_000);
    await send;
    expect(B.getState().error).toBe(CHANGING);
    expect(mustView(B, id).blocked).toBe("pending");
    expect(mustView(B, id).canSend).toBe(false);
    server().blobs.failGet(P.b64u(r.bundleId), 0);
    await settle(A, B, C);
    expect(mustView(B, id).epoch).toBe(1);
    expect(mustView(B, id).blocked).toBe("");
    await B.sendText(id, "now in e+1");
    await settle(A, B, C);
    expect(chat(C, id)).toEqual(["bob: now in e+1"]);
    expect(readableWith(ep.keys.mk).filter((m) => m.type === P.MT.TEXT)).toEqual([]);
  });

  it("a failed control probe fails the send and writes nothing", async () => {
    const {
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    const rows = server().shard.rows().length;
    server().hooks.fail = (m, p, who) =>
      who === "bob" && m === "POST" && p === "/api/v2/get" ? "before" : undefined;
    await B.sendText(id, "lost");
    server().hooks.fail = undefined;
    expect(B.getState().error).toMatch(/not delivered/);
    expect(server().shard.rows().length).toBe(rows);
    void A;
  });
});

describe("commits (tests 13–15, 19, 27)", () => {
  it("an early CAS (shard clock behind BlobReg) is an ignored slot; the next claim wins", async () => {
    const {
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    const d = makeUser("dave");
    const D = await engineFor(d);
    server().shardLagMs = 1500;
    await A.addMembers(id, ["dave"]);
    server().shardLagMs = 0;
    await settle(A, B, D);
    const w = conv(B, id).epochs.get(0)!.ctl.winner!;
    expect(w.n).toBeGreaterThanOrEqual(1);
    expect(mustView(D, id).epoch).toBe(1);
    expect(mustView(B, id).epoch).toBe(1);
  });

  it("an undecided occupant makes the committer wait; a late registration loses to the next slot", async () => {
    const {
      users: [alice, bob, mallory],
      engines: [A, B, M],
      id,
    } = await group(["alice", "bob", "mallory"]);
    const ep = epoch(A, id);
    const r = await commitChange(mallory, ep, [alice, bob, mallory], "mal", { noRegister: true });
    server().blobreg.missNow((idB, now) => (idB === P.b64u(r.bundleId) ? now - 30 : null));
    const add = A.addMembers(id, ["carol"]).catch((e: unknown) => e);
    makeUser("carol");
    await sleep(1500);
    expect(epoch(A, id).ctl.queue.length).toBeGreaterThan(0);
    server().blobreg.missNow(null);
    server().putBlob(r.blob);
    await add;
    await settle(A, B, M);
    const wa = conv(A, id).epochs.get(0)!.ctl.winner!;
    const wb = conv(B, id).epochs.get(0)!.ctl.winner!;
    expect([wa.E, wa.n]).toEqual([wb.E, wb.n]);
    expect(wa.n).toBe(r.claim.n + 1);
    expect(mustView(B, id).members.map((m) => m.handle)).toContain("carol");
  });

  it("a lost CAS response is recovered from the slot: the commit completes and dave gets J at once", async () => {
    const {
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    const dave = makeUser("dave");
    const ep = epoch(A, id);
    let lost = 0;
    server().hooks.afterPut = (rows, _res, who) => {
      if (who !== "alice" || lost > 0) return;
      for (const r of rows)
        for (let k = 0; k < 4; k++)
          if (P.equalBytes(r.label, P.Lctl(ep.keys.rk, r.E, k))) {
            lost++;
            return "lose";
          }
    };
    await A.addMembers(id, ["dave"]);
    server().hooks.afterPut = undefined;
    expect(lost).toBe(1);
    expect(A.getState().error).toBe("");
    const D = await engineFor(dave);
    expect(mustView(D, id).epoch).toBe(1);
    await settle(A, B, D);
    expect(mustView(B, id).epoch).toBe(1);
  });

  it("a second device of a committer that crashed before delivering J delivers it", async () => {
    const {
      users: [alice],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    const dave = makeUser("dave");
    server().hooks.beforeRequest = (m, p, who) =>
      who === "alice" && m === "POST" && p === "/api/v2/inbox" ? new Promise<void>(() => {}) : undefined;
    void A.addMembers(id, ["dave"]).catch(() => {});
    for (let i = 0; i < 100 && epoch(A, id).e < 1; i++) await sleep(50);
    expect(epoch(A, id).e).toBe(1);
    await A.logout();
    server().hooks.beforeRequest = undefined;
    const A2 = await engineFor(alice);
    await settle(A2, B);
    const D = await engineFor(dave);
    expect(mustView(D, id).epoch).toBe(1);
    expect(mustView(D, id).name).toBe("# g");
  });

  it("an honest commit needs no directory lookup, and an unknown member gets a real entry", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    // An unregistered member U, added by bob's commit (its keys only in D and pks).
    const U: TestUser = makeUser("ursula", { register: false });
    await commitChange(bob, epoch(A, id), [alice, bob, carol, U], undefined, { noJoin: true });
    await settle(A, B, C);
    expect(mustView(A, id).epoch).toBe(1);
    const before = server().requests.length;
    server().dir.failDir(() => true, Infinity);
    await A.removeMember(id, carol.uidB);
    await settle(A, B, C);
    server().dir.failDir(null);
    const dirReqs = server()
      .requests.slice(before)
      .filter((r) => r.who === "alice" && r.path.startsWith("/api/v2/dir"));
    expect(dirReqs).toEqual([]);
    expect(mustView(A, id).epoch).toBe(2);
    expect(mustView(B, id).epoch).toBe(2);
    const ep2 = epoch(A, id);
    const blob = server().blobs.bytes(P.b64u(ep2.bundleId))!;
    expect(entryOutcome(blob, ep2.D.conv, 2, U)).toBe("EK");
    expect(entryOutcome(blob, ep2.D.conv, 2, carol)).toBe("none");
  });
});
