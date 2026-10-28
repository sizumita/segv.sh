// Copies after a removal (docs/PROTOCOL.md §6.6 step 3, §6.7 steps 4–6, §7.2, §7.3, §11.4 step 5): a copy whose
// self was removed has ended, its ENDED record and a third member's claim's CONFIRMED ride in the next HEADS row, a
// restore holds it by that record, a re-add is a separate copy, forks of an ended copy are compared with it, ⚠ is
// pairwise, and an overtaken J's own copy is settled first.
import { describe, expect, it } from "vite-plus/test";
import type { Engine } from "../../src/client/types";
import { CONFIRMED_COPY_WARNING } from "../../src/client/selflane";
import { secondCopyWarning } from "../../src/client/join";
import {
  I,
  P,
  buildMessage,
  chat,
  commitChange,
  conv,
  engineFor,
  epoch,
  forgeJoin,
  freshWorldPerTest,
  makeUser,
  mustView,
  newEngine,
  postRow,
  selfRowsOf,
  server,
  settle,
  systemLines,
  view,
  waitFor,
  writeSelfRow,
  type TestUser,
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

/** A J for epoch e of `conv` whose D (by `by`, listing `members`) no claim names: a forged descriptor, registered. */
function forgedJ(by: TestUser, convId: Uint8Array, e: number, members: TestUser[]): P.Join {
  const EK = P.random(32);
  const keys = P.epochKeys(EK, convId, e);
  const Dbytes = P.encodeD({
    conv: convId,
    e,
    prev: P.random(32),
    by: by.uid,
    ts: server().now(),
    members: members.map((u) => ({ uid: u.uid, sigPk: u.id.sigPk, kh: P.kemHash(u.id.kemPk) })),
    name: "forged",
  });
  const dsig = P.signD(Dbytes, keys.kc, by.id.sigSk);
  const b = P.buildBundle({
    conv: convId,
    e,
    D: Dbytes,
    dsig,
    EK,
    pks: members.map((u) => u.id.kemPk),
    prevMembers: [],
    rm: 0,
  });
  const reg = server().putBlob(b.blob);
  return { conv: convId, e, EK, bundleId: P.fromB64u(reg.id), bundleSize: b.blob.length };
}

const warnings = (e: Engine) => e.getState().warnings;
const isWarned = (v: { name: string }) => v.name.startsWith("⚠");

/** bob's requests since request index `from`: blob GETs and meta requests for a bundle, and get keys of a lane. */
function asks(who: string, from: number) {
  const reqs = server().requests.slice(from).filter((r) => r.who === who);
  return {
    blob: (id: Uint8Array) => reqs.filter((r) => r.method === "GET" && r.path === `/api/v2/blob/${P.b64u(id)}`).length,
    meta: (id: Uint8Array) => reqs.filter((r) => r.path === `/api/v2/blob/${P.b64u(id)}/meta`).length,
    keys: (labels: Set<string>) =>
      reqs.flatMap((r) => r.getKeys ?? []).filter((k) => labels.has(P.hex(k.label))),
  };
}

/** The epochs of the Js of `convId` in `u`'s inbox, in inbox order. */
function inboxEpochs(u: TestUser, convId: Uint8Array): number[] {
  const out: number[] = [];
  for (const E of server().inbox.eraList().sort((a, b) => a - b))
    for (const r of server().inbox.rowsOf(E)) {
      const o = P.tryOpenInvite(u.id.kemSk, E, 0, r.eid, r.body);
      if (o?.kind === "join" && P.equalBytes(o.join.conv, convId)) out.push(o.join.e);
    }
  return out;
}

/** Every Lctl label of epoch `ep` in the eras from its start to now, slots 0..63. */
function ctlLabels(ep: { keys: P.EpochKeys; Estart: number | null }): Set<string> {
  const out = new Set<string>();
  for (let E = ep.Estart ?? server().era - 2; E <= server().era; E++)
    for (let n = 0; n < 64; n++) out.add(P.hex(P.Lctl(ep.keys.rk, E, n)));
  return out;
}

describe("ENDED records and confirmation by claims (§6.6 step 3, §6.7 step 6)", () => {
  it("(a, b) the end rides with the next HEADS row; a restore holds the copy by it and reads the claim for history", async () => {
    const {
      users: [, bob],
      engines: [A, B, C, D],
      id,
    } = await group(["alice", "bob", "carol", "dave"]);
    await A.sendText(id, "before");
    await settle(A, B, C, D);
    const before = selfRowsOf(bob).length;
    await C.removeMember(id, bob.uidB);
    await settle(A, B, C, D);
    expect(mustView(B, id).blocked).toBe("removed");
    expect(systemLines(B, id)).toContain("@carol removed you");
    const ep = conv(B, id).epochs.get(0)!;
    const w = ep.ctl.winner!;
    const rows = selfRowsOf(bob).slice(before);
    const row = rows.find((rs) => rs.some((r) => r.rtype === P.RT.ENDED))!;
    expect(row).toBeDefined();
    const ended = row.find((r) => r.rtype === P.RT.ENDED) as P.EndedRec;
    expect([ended.e, ended.claim]).toEqual([0, { E: w.E, n: w.n }]);
    // carol is neither rootBy (alice) nor bob: her claim confirms G, recorded beside it
    expect(row.some((r) => r.rtype === P.RT.CONFIRMED && P.equalBytes(r.root, conv(B, id).root))).toBe(true);
    expect(row.at(-1)!.rtype).toBe(P.RT.HEADS);
    expect(rows.filter((rs) => rs.some((r) => r.rtype === P.RT.ENDED)).length).toBe(1);
    expect(conv(B, id).confirmed).toBe(true);

    // (b) A reload: G has ended at once, no key of Lctl_0 but the claim's own position, no bundle or meta for C_0.
    const from = server().requests.length;
    const B2 = await engineFor(bob);
    expect(mustView(B2, id).blocked).toBe("removed");
    expect(conv(B2, id).confirmed).toBe(true);
    const a = asks("bob", from);
    expect(a.blob(w.claim.bundleId)).toBe(0);
    expect(a.meta(w.claim.bundleId)).toBe(0);
    const ctl = a.keys(ctlLabels(ep));
    expect(ctl.map((k) => [k.E, P.hex(k.label), k.mode])).toEqual([[w.E, P.hex(w.label), 0]]);
    // its initial history read the claim: the TEXT and the removal line, as live
    expect(chat(B2, id)).toEqual(["alice: before"]);
    expect(systemLines(B2, id)).toContain("@carol removed you");
    expect(warnings(B2)).toEqual([]);
  });

  it("(d) a copy ended without an ENDED record (an earlier version's) is processed once, then held by its record", async () => {
    const {
      users: [, bob],
      engines: [A, B, C, D],
      id,
    } = await group(["alice", "bob", "carol", "dave"]);
    await B.logout();
    await C.removeMember(id, bob.uidB);
    await settle(A, C, D);
    const bundleId = conv(A, id).epochs.get(0)!.ctl.winner!.claim.bundleId;
    let from = server().requests.length;
    const B2 = await engineFor(bob);
    expect(mustView(B2, id).blocked).toBe("removed");
    expect(systemLines(B2, id)).toContain("@carol removed you");
    expect(asks("bob", from).meta(bundleId)).toBe(1); // rule (g) of the claim it processed
    await settle(A, B2, C, D); // its HEADS row writes the ENDED and CONFIRMED records
    const recs = selfRowsOf(bob).flat();
    expect(recs.some((r) => r.rtype === P.RT.ENDED)).toBe(true);
    expect(recs.some((r) => r.rtype === P.RT.CONFIRMED)).toBe(true);
    await B2.logout();
    from = server().requests.length;
    const B3 = await engineFor(bob);
    expect(mustView(B3, id).blocked).toBe("removed");
    expect(asks("bob", from).meta(bundleId)).toBe(0);
    expect(asks("bob", from).blob(bundleId)).toBe(0);
    expect(systemLines(B3, id)).toContain("@carol removed you");
  });
});

describe("forks of an ended copy (§6.7 step 6)", () => {
  it("a J for the epoch after an ended copy's last is rejected when a third member's claim confirmed it", async () => {
    const {
      users: [alice, bob, , dave],
      engines: [A, B, C, D],
      id,
    } = await group(["alice", "bob", "carol", "dave"]);
    await C.removeMember(id, bob.uidB);
    await settle(A, B, C, D);
    expect(conv(B, id).confirmed).toBe(true); // by carol's claim
    forgeJoin(bob, forgedJ(dave, conv(B, id).conv, 1, [bob, dave]));
    await settle(A, B, C, D);
    expect(warnings(B)).toContain(CONFIRMED_COPY_WARNING);
    expect(I(B).views().map((v) => v.id)).toEqual([id]);
    // after a reload the copy is still confirmed (its CONFIRMED record), so another fork is rejected too
    const B2 = await engineFor(bob);
    expect(conv(B2, id).confirmed).toBe(true);
    forgeJoin(bob, forgedJ(dave, conv(B2, id).conv, 1, [bob, dave]));
    await settle(A, B2, C, D);
    expect(warnings(B2)).toContain(CONFIRMED_COPY_WARNING);
    expect(I(B2).views().map((v) => v.id)).toEqual([id]);
    void alice;
  });

  it("with the ended copy unconfirmed the fork is kept with the second-copy warning; ⚠ is pairwise", async () => {
    const {
      users: [alice, bob, carol, dave],
      engines: [A, B, C, D],
      id,
    } = await group(["alice", "bob", "carol", "dave"]);
    await A.removeMember(id, bob.uidB); // alice is rootBy: her claim confirms nothing
    await settle(A, B, C, D);
    expect(conv(B, id).confirmed).toBe(false);
    forgeJoin(bob, forgedJ(dave, conv(B, id).conv, 1, [bob, dave]));
    await settle(A, B, C, D);
    expect(warnings(B)).toContain(secondCopyWarning("dave"));
    const fork = `${id}~1`;
    expect(isWarned(mustView(B, id))).toBe(true);
    expect(isWarned(mustView(B, fork))).toBe(true);
    // the fork's own branch removes bob at 1, so it ends there
    await commitChange(dave, epoch(B, fork), [dave], null, { noJoin: true });
    await settle(A, B, C, D);
    expect(mustView(B, fork).blocked).toBe("removed");
    // alice moves on (1 → 3) and re-adds bob at 4: a first contact, contesting neither ended copy
    for (const name of ["x", "y"]) {
      await commitChange(alice, epoch(A, id), [alice, carol, dave], name);
      await settle(A, B, C, D);
    }
    await A.addMembers(id, ["bob"]);
    await settle(A, B, C, D);
    const readd = `${id}~2`;
    expect(mustView(B, readd).epoch).toBe(4);
    expect(isWarned(mustView(B, readd))).toBe(false);
    expect(isWarned(mustView(B, id))).toBe(true);
    expect(isWarned(mustView(B, fork))).toBe(true);
    expect(warnings(B).filter((w) => w === secondCopyWarning("alice"))).toEqual([]);
    void alice;
  });
});

describe("re-adds as separate copies (§6.7 steps 4–6, §11.5 step 2)", () => {
  it("two re-adds in one poll: the second waits for the next poll, then starts its own copy", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    await B.logout();
    await A.removeMember(id, bob.uidB); // C_0
    await settle(A, C);
    await A.addMembers(id, ["bob"]); // J1 at 2
    await settle(A, C);
    await C.removeMember(id, bob.uidB); // C_2
    await settle(A, C);
    await C.addMembers(id, ["bob"]); // J2 at 4
    await settle(A, C);
    const B2 = await engineFor(bob);
    await settle(A, B2, C);
    const views = I(B2).views();
    expect(views.map((v) => [v.id, v.epoch, v.blocked]).sort()).toEqual(
      [
        [id, 0, "removed"],
        [`${id}~1`, 2, "removed"],
        [`${id}~2`, 4, ""],
      ].sort(),
    );
    expect(warnings(B2)).toEqual([]);
    expect(views.some(isWarned)).toBe(false);
    void [alice, carol];
  });

  it("an overtaken J (its re-add's J landed after a later one) is settled first and kept as an ended copy", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    await B.logout();
    await A.removeMember(id, bob.uidB); // C_0
    await settle(A, C);
    let hold = true;
    server().hooks.fail = (m, p, who) =>
      hold && who === "alice" && m === "POST" && p === "/api/v2/inbox" ? "before" : undefined;
    await A.addMembers(id, ["bob"]); // J1 at 2, its invite held back (alice keeps retrying)
    await settle(C);
    await C.removeMember(id, bob.uidB); // C_2
    await settle(C);
    await C.addMembers(id, ["bob"]); // J2 at 4, delivered first
    await settle(C);
    hold = false;
    server().hooks.fail = undefined;
    await settle(A, C); // alice's retry delivers J1 after J2
    expect(inboxEpochs(bob, conv(A, id).conv)).toEqual([0, 4, 2]);
    const B2 = await engineFor(bob);
    await settle(A, B2, C);
    const views = I(B2).views();
    expect(views.map((v) => [v.epoch, v.blocked]).sort()).toEqual(
      [
        [0, "removed"],
        [2, "removed"],
        [4, ""],
      ].sort(),
    );
    expect(warnings(B2)).toEqual([]);
    expect(views.some(isWarned)).toBe(false);
    void [alice, carol, view];
  });
});

describe("the removal line follows the LEAVE records (§6.6 step 3)", () => {
  it("a LEAVE record that arrives after the claim takes '@by removed you' away, live and after a reload", async () => {
    const {
      users: [, bob],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    await A.removeMember(id, bob.uidB);
    await settle(A, B, C);
    expect(systemLines(B, id)).toContain("@alice removed you");
    // a sibling's LEAVE record of epoch 0 reaches this device on Tself after the claim
    const c = conv(B, id);
    writeSelfRow(bob, [{ rtype: P.RT.LEAVE, conv: c.conv, root: c.root, e: 0 }]);
    await settle(A, B, C);
    expect(systemLines(B, id)).not.toContain("@alice removed you");
    const B2 = await engineFor(bob);
    expect(systemLines(B2, id)).not.toContain("@alice removed you");
    expect(mustView(B2, id).blocked).toBe("removed");
  });
});

describe("requests and ended requests (§11.5)", () => {
  /** carol, a stranger to bob, creates G with bob and dave: bob holds it as a request R. */
  async function strangerGroup() {
    const [alice, bob, carol, dave] = ["alice", "bob", "carol", "dave"].map((h) => makeUser(h));
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const D = await engineFor(dave);
    const id = await C.createConversation(["bob", "dave"], "g");
    await settle(B, C, D);
    D.markRead(id);
    await settle(B, C, D);
    expect(mustView(B, id).request).toBe(true);
    return { users: { alice, bob, carol, dave }, B, C, D, id };
  }

  it("(a) a removed request's re-add is a new request; the ended one is inert", async () => {
    const { users, B, C, D, id } = await strangerGroup();
    await C.removeMember(id, users.bob.uidB);
    await settle(B, C, D);
    expect(mustView(B, id).blocked).toBe("removed");
    await C.addMembers(id, ["bob"]);
    await settle(B, C, D);
    const r1 = `${id}~1`;
    expect(mustView(B, r1).request).toBe(true);
    expect(mustView(B, r1).epoch).toBe(2);
    expect(warnings(B)).toEqual([]);
    expect(mustView(B, id).name.startsWith("⚠")).toBe(false);
    expect(mustView(B, r1).name.startsWith("⚠")).toBe(false);
    B.markRead(id); // the ended request: nothing accepts it
    await settle(B, C, D);
    expect(mustView(B, id).request).toBe(true);
    B.markRead(r1);
    await settle(B, C, D);
    expect(mustView(B, r1).request).toBe(false);
    expect(mustView(B, id).request).toBe(true);
    const recs = selfRowsOf(users.bob).flat();
    const joins = recs.filter((r) => r.rtype === P.RT.CONV_JOIN) as P.ConvJoinRec[];
    expect(joins.map((r) => P.equalBytes(r.root, conv(B, r1).root))).toEqual([true]);
    expect(warnings(B)).toEqual([]);
  });

  it("(b) offline: a member's row from before the claim that removed self neither accepts nor confirms the request", async () => {
    const { users, B, C, D, id } = await strangerGroup();
    await B.logout();
    await D.sendText(id, "hi from dave"); // dave is neither rootBy nor bob
    await settle(C, D);
    await D.removeMember(id, users.bob.uidB); // dave's claim: it confirms R, and ends it
    await settle(C, D);
    await C.addMembers(id, ["bob"]);
    await settle(C, D);
    const B2 = await engineFor(users.bob);
    await settle(B2, C, D);
    expect(mustView(B2, id).blocked).toBe("removed");
    expect(mustView(B2, id).request).toBe(true); // not accepted by dave's row
    expect(conv(B2, id).confirmed).toBe(true); // confirmed by dave's claim
    const r1 = `${id}~1`;
    expect(mustView(B2, r1).request).toBe(true);
    B2.markRead(r1);
    await settle(B2, C, D);
    expect(mustView(B2, r1).request).toBe(false);
    const recs = selfRowsOf(users.bob).flat();
    const rootOf = (k: string) => conv(B2, k).root;
    expect(
      recs.some(
        (r) => r.rtype === P.RT.CONV_JOIN && P.equalBytes(r.root, rootOf(id)),
      ),
    ).toBe(false);
    expect(
      recs.filter((r) => r.rtype === P.RT.CONFIRMED && P.equalBytes(r.root, rootOf(id))).length,
    ).toBe(1);
    const B3 = await engineFor(users.bob);
    expect(mustView(B3, r1).request).toBe(false);
    expect(warnings(B3)).toEqual([]);
  });

  it("(38 g) a claim's confirmation accepts nothing; a third member's later row still accepts the request", async () => {
    const { users, B, C, D, id } = await strangerGroup();
    const frank = makeUser("frank");
    const F = await engineFor(frank);
    await C.addMembers(id, ["frank"]); // C_0: carol's (rootBy) claim confirms nothing
    await settle(B, C, D, F);
    F.markRead(id);
    await commitChange(users.dave, epoch(D, id), [users.carol, users.bob, users.dave, frank], "r");
    await settle(B, C, D, F);
    expect(conv(B, id).confirmed).toBe(true); // by dave's rename
    expect(mustView(B, id).request).toBe(true);
    const before = selfRowsOf(users.bob).flat().length;
    await F.sendText(id, "hi from frank");
    await settle(B, C, D, F);
    expect(mustView(B, id).request).toBe(false);
    const recs = selfRowsOf(users.bob).flat().slice(before);
    const join = recs.find((r) => r.rtype === P.RT.CONV_JOIN) as P.ConvJoinRec;
    expect(join.via).toBe(P.VIA.REQUEST_ACCEPTED);
    expect(recs.filter((r) => r.rtype === P.RT.CONFIRMED).length).toBe(0);
    const B2 = await engineFor(users.bob);
    expect(mustView(B2, id).request).toBe(false);
  });
});

describe("siblings (§11.7)", () => {
  it("a sibling's ENDED record ends the copy on a device that never processed the claim", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const B2 = newEngine("bob2");
    await I(B2).unlock(bob.AK, bob.uid, bob.handle);
    await waitFor(() => !B2.getState().syncing, "bob2's restore");
    await settle(A, B, B2, C);
    const r = await commitChange(alice, epoch(A, id), [alice, carol], undefined, { hideFrom: ["bob2"] });
    await settle(A, B, B2, C);
    expect(mustView(B, id).blocked).toBe("removed");
    expect(selfRowsOf(bob).flat().some((x) => x.rtype === P.RT.ENDED)).toBe(true);
    // bob2 never saw C_0: B1's ENDED record ends its copy, without the claim's bundle or meta
    expect(mustView(B2, id).blocked).toBe("removed");
    const meta = server().requests.filter(
      (q) => q.who === "bob2" && q.path === `/api/v2/blob/${P.b64u(r.bundleId)}/meta`,
    );
    expect(meta).toEqual([]);
  });
});

describe("a CONFLICT with a sibling's CONFIRMED row (§7.3)", () => {
  it("runs §6.7 steps 3–6 again for the J: neither device holds the forged copy", async () => {
    const {
      users: [, bob, carol, mallory],
      engines: [A, B, C, M],
      id,
    } = await group(["alice", "bob", "carol", "mallory"]);
    const B2 = newEngine("bob2");
    await I(B2).unlock(bob.AK, bob.uid, bob.handle);
    await waitFor(() => !B2.getState().syncing, "bob2's restore");
    await settle(A, B, B2, C, M);
    // B1's next self rows, and carol's row that makes B1 confirm G, are hidden from bob2
    const E = server().era;
    let n0 = 0;
    while (server().shard.hasLabel(E, P.Lself(bob.id.rS, E, n0))) n0++;
    for (let n = n0; n < n0 + 64; n++) server().shard.hide(E, P.Lself(bob.id.rS, E, n), "bob2");
    const ep = epoch(C, id);
    const j = P.memberIndex(ep.D, carol.uid);
    const row = buildMessage(carol, ep, { E, n: ep.lanes[j].next.n }, { type: P.MT.TEXT, text: "hi" } as P.MBody);
    server().shard.hide(row.E, row.label, "bob2");
    postRow(ep, row);
    await settle(A, B, C, M);
    expect(conv(B, id).confirmed).toBe(true);
    expect(conv(B2, id).confirmed).toBe(false);
    const conflicts = () =>
      server().requests.filter(
        (r) => r.who === "bob2" && r.path === "/api/v2/put" && r.putResults?.some((x) => x.s === "conflict"),
      ).length;
    const before = conflicts();
    forgeJoin(bob, forgedJ(mallory, conv(B, id).conv, 3, [bob, mallory]));
    await settle(A, B, C, M);
    expect(warnings(B)).toContain(CONFIRMED_COPY_WARNING);
    await settle(B2); // bob2's poll (live, it may have run already) meets B1's rows by CONFLICT
    expect(conflicts()).toBeGreaterThan(before);
    expect(warnings(B2)).toContain(CONFIRMED_COPY_WARNING);
    expect(warnings(B2)).not.toContain(secondCopyWarning("mallory"));
    for (const X of [B, B2]) expect(I(X).views().map((v) => v.id)).toEqual([id]);
    const B3 = await engineFor(bob);
    expect(I(B3).views().map((v) => v.id)).toEqual([id]);
  });
});
