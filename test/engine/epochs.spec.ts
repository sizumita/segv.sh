// Epochs at restore, forged member slots, WELCOME channels, and races with a removal and a logout (docs/PROTOCOL.md
// §6.6, §6.12 step 1, §11.2, §11.3, §11.4 step 5; the races are ported from the v1 engine tests).
import { describe, expect, it } from "vite-plus/test";
import type { Engine } from "../../src/client/types";
import {
  I,
  P,
  chat,
  conv,
  engineFor,
  entryOutcome,
  epoch,
  forgeJoin,
  freshWorldPerTest,
  makeUser,
  mustView,
  newTestUser,
  readableWith,
  server,
  settle,
  sleep,
  view,
} from "./harness";

freshWorldPerTest();

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

describe("followed lanes at restore", () => {
  it("a member who posted in c is not followed after a reload, and its rows of c−1 are not fetched", async () => {
    const {
      users: [alice, bob],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    for (let i = 0; i < 40; i++) await B.sendText(id, `old ${i}`);
    await settle(A, B, C);
    const ep0 = epoch(A, id);
    const bj = P.memberIndex(ep0.D, bob.uid);
    await A.removeMember(id, P.b64u(ep0.D.members[2].uid)); // c = 1
    await settle(A, B, C);
    await B.sendText(id, "bob in c");
    await settle(A, B);
    await I(A).catchUp();
    const before = server().requests.length;
    const A2 = await engineFor(alice);
    const after = server().requests.slice(before);
    const gets = after.filter((r) => r.who === "alice" && r.getKeys);
    const old = new Set(Array.from({ length: 64 }, (_, n) => P.b64u(P.Lmsg(ep0.keys.rk, bj, server().era, n))));
    const fetched = gets.reduce(
      (k, r) => k + r.getKeys!.filter((x, i) => x.mode === 0 && old.has(P.b64u(x.label)) && r.getStatuses?.[i]?.s === "hit").length,
      0,
    );
    // Only the initial history of the previous epoch may read bob's old rows (the last HISTORY_INITIAL slots).
    expect(fetched).toBeLessThanOrEqual(32);
    const c0 = conv(A2, id).epochs.get(0)!;
    expect(c0.lanes[bj].swept).toBe(true);
    expect(chat(A2, id).at(-1)).toBe("bob: bob in c");
  });

  it("a member silent in c is followed from the position the HEADS entry lists", async () => {
    const {
      users: [alice, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    await B.sendText(id, "in e0");
    await settle(A, B);
    await A.addMembers(id, [makeUser("carol").handle]);
    await settle(A, B);
    await I(A).catchUp();
    const heads = I(A).self!.fold.heads;
    const entry = [...heads.values()].find((h) => h.e === 1)!;
    const bj = P.memberIndex(conv(A, id).epochs.get(0)!.D, bob.uid);
    expect(entry.followed.map((f) => [f.ef, f.lane])).toEqual([[0, bj]]);
    const A2 = await engineFor(alice);
    const c0 = conv(A2, id).epochs.get(0)!;
    expect(c0.lanes[bj].swept).toBe(false);
    expect(c0.lanes[bj].next.n).toBe(entry.followed[0].cnt);
    await B.sendText(id, "now in e1");
    await settle(A2, B);
    expect(chat(A2, id).at(-1)).toBe("bob: now in e1");
    expect(conv(A2, id).epochs.get(0)!.lanes[bj].swept).toBe(true);
  });
});

describe("WELCOME channels", () => {
  it("an expired request is not a WELCOME channel: the J goes by inbox", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const one = await A.createConversation(["bob"]);
    await settle(A);
    for (let i = 0; i < 5; i++) server().advanceEra();
    const B = await engineFor(bob);
    expect(view(B, one)).toBeUndefined(); // the request expired (§7.3)
    const C = await engineFor(carol);
    const g = await A.createConversation(["bob", "carol"], "G");
    await settle(A, B, C);
    expect(readableWith(epoch(A, one).keys.mk).some((m) => m.type === P.MT.WELCOME)).toBe(false);
    expect(mustView(B, g).name).toBe("# G");
  });
});

describe("forged member slots", () => {
  it("a slot with bob's sigPk but another kemPk is shown as unknown, and removing it leaves its key no entry", async () => {
    const [alice, bob, mallory] = ["alice", "bob", "mallory"].map((h) => makeUser(h));
    const X = newTestUser("xkey"); // a key mallory holds
    const A = await engineFor(alice);
    // mallory's group: alice, mallory, and "bob" with bob's real sigPk but kh of X's kemPk.
    const conv0 = P.random(16);
    const EK = P.random(32);
    const keys = P.epochKeys(EK, conv0, 0);
    const members = [
      { uid: mallory.uid, sigPk: mallory.id.sigPk, kh: P.kemHash(mallory.id.kemPk) },
      { uid: alice.uid, sigPk: alice.id.sigPk, kh: P.kemHash(alice.id.kemPk) },
      { uid: bob.uid, sigPk: bob.id.sigPk, kh: P.kemHash(X.id.kemPk) },
    ];
    const Dbytes = P.encodeD({
      conv: conv0,
      e: 0,
      prev: P.ZERO32,
      by: mallory.uid,
      ts: server().now(),
      members,
      name: "trap",
    });
    const dsig = P.signD(Dbytes, keys.kc, mallory.id.sigSk);
    const b = P.buildBundle({
      conv: conv0,
      e: 0,
      D: Dbytes,
      dsig,
      EK,
      pks: [mallory.id.kemPk, alice.id.kemPk, X.id.kemPk],
      prevMembers: [],
      rm: 0,
    });
    const reg = server().putBlob(b.blob);
    forgeJoin(alice, { conv: conv0, e: 0, EK, bundleId: P.fromB64u(reg.id), bundleSize: b.size });
    await settle(A);
    const id = P.b64u(conv0);
    A.markRead(id);
    await settle(A);
    const handles = mustView(A, id).members.map((m) => m.handle);
    expect(handles).toContain("mallory");
    expect(handles).not.toContain("bob");
    expect(handles.some((h) => h.startsWith("?"))).toBe(true);
    expect(A.getState().warnings).toContain("the public keys of @bob changed");
    // alice removes mallory, then the ? slot: no later bundle seals to X or to mallory.
    await A.removeMember(id, mallory.uidB);
    await A.removeMember(id, bob.uidB);
    await settle(A);
    for (const e of [1, 2]) {
      const ep = conv(A, id).epochs.get(e)!;
      const blob = server().blobs.bytes(P.b64u(ep.bundleId))!;
      expect(entryOutcome(blob, conv0, e, mallory)).toBe("none");
      if (e === 2) expect(entryOutcome(blob, conv0, e, X)).toBe("none");
    }
    const A2 = await engineFor(alice);
    expect(mustView(A2, id).members.map((m) => m.handle)).toEqual(["alice"]);
  });
});

describe("races with a removal and a logout", () => {
  it("a send racing a removal ends failed with an error, not stuck sending", async () => {
    const {
      users: [, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob", "carol"]);
    const removal = A.removeMember(id, bob.uidB);
    await sleep(30);
    await B.sendText(id, "racing");
    await removal;
    await settle(A, B);
    const mine = mustView(B, id).messages.filter((m) => m.mine && m.kind === "text");
    for (const m of mine) expect(m.status === "sent" || m.status === "failed").toBe(true);
    if (mine.some((m) => m.status === "failed")) expect(B.getState().error).not.toBe("");
    expect(chat(A, id).filter((t) => t === "bob: racing").length).toBeLessThanOrEqual(1);
  });

  it("an add in flight across a logout is not committed by the next account", async () => {
    const {
      users: [alice],
      engines: [A],
      id,
    } = await group(["alice", "bob"]);
    makeUser("dave");
    let release!: () => void;
    server().hooks.beforeRequest = (m, p, who) =>
      who === "alice" && m === "PUT" && p.startsWith("/api/v2/blob/")
        ? new Promise<void>((r) => (release = r))
        : undefined;
    const mk0 = epoch(A, id).keys.mk;
    const add = A.addMembers(id, ["dave"]).catch((e: unknown) => e);
    for (let i = 0; i < 100 && !release; i++) await sleep(20);
    await A.logout();
    server().hooks.beforeRequest = undefined;
    release();
    await add;
    await sleep(1500);
    expect(readableWith(mk0).filter((m) => m.type === P.MT.CLAIM)).toEqual([]);
    const A2 = await engineFor(alice);
    expect(mustView(A2, id).epoch).toBe(0);
  });
});
