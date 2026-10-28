// Snapshots of the self lane (docs/PROTOCOL.md §7.4, §11.4 steps 2–5 and 10): a restore writes one when its era has
// none, the next restore reads it and the self delta after its position, starts each copy at the snapshot's top (or
// its HEADS epoch) without processing the claims below, reads older epochs for history, and keeps ended copies, legacy
// skip records and requests as the self lane had them.
import { describe, expect, it } from "vite-plus/test";
import type { Engine } from "../../src/client/types";
import {
  I,
  P,
  buildClaim,
  chat,
  commitChange,
  conv,
  engineFor,
  epoch,
  freshWorldPerTest,
  makeUser,
  mustView,
  postRow,
  server,
  settle,
  systemLines,
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

/** The snapshot pointers of `u` in the current era, opened. */
function pointers(u: TestUser, E = server().era): P.SnapRec[] {
  const out: P.SnapRec[] = [];
  for (let j = 0; ; j++) {
    const label = P.Lsnap(u.id.rS, E, j);
    const row = server().shard.row(E, label);
    if (!row) return out;
    out.push(P.openSelf(u.id.kS, E, label, row.body, "snap").records[0] as P.SnapRec);
  }
}

/** The records of `u`'s latest snapshot in the current era. */
function latestSnapshot(u: TestUser): P.SelfRecord[] {
  const ptr = pointers(u).at(-1)!;
  const blob = server().blobs.bytes(P.b64u(ptr.blobId))!;
  return P.decryptSnapshot(blob, P.b64u(ptr.blobId), ptr.key).records;
}

/** `who`'s requests since request index `from`. */
const since = (who: string, from: number) => server().requests.slice(from).filter((r) => r.who === who);
const metaOf = (who: string, from: number, id: Uint8Array) =>
  since(who, from).filter((r) => r.path === `/api/v2/blob/${P.b64u(id)}/meta`).length;
const blobOf = (who: string, from: number, id: Uint8Array) =>
  since(who, from).filter((r) => r.method === "GET" && r.path === `/api/v2/blob/${P.b64u(id)}`).length;

describe("snapshots (§7.4)", () => {
  it("a live device writes the new era's snapshot; the next restore reads it and the self delta after it", async () => {
    const {
      users: [alice, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    await A.sendText(id, "one");
    await B.sendText(id, "two");
    await settle(A, B);
    server().advanceEra(); // an era without a pointer: the live device writes one (§7.4)
    await settle(A, B);
    expect(pointers(alice)).toHaveLength(1);
    const recs = latestSnapshot(alice);
    expect(recs.some((r) => r.rtype === P.RT.CONV_JOIN)).toBe(true);
    expect(recs.some((r) => r.rtype === P.RT.HEADS)).toBe(true);
    const from = server().requests.length;
    const A3 = await engineFor(alice);
    expect(chat(A3, id)).toEqual(["alice: one", "bob: two"]);
    expect(mustView(A3, id).name).toBe("# g");
    // the snapshot's blob was read; one more snapshot is not written in the same era
    expect(since("alice", from).some((r) => r.method === "GET" && r.path.startsWith("/api/v2/blob/"))).toBe(true);
    const puts = since("alice", from).filter((r) => r.method === "PUT" && r.path.startsWith("/api/v2/blob/"));
    expect(puts).toEqual([]);
    void bob;
  });

  it("a restore starts at the snapshot's top: the claims below it are not processed, and history reads them", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    await A.sendText(id, "in e0");
    await settle(A, B, C);
    const bundles: Uint8Array[] = [];
    for (const name of ["x", "y"]) {
      const r = await commitChange(alice, epoch(A, id), [alice, bob, carol], name);
      bundles.push(r.bundleId);
      await settle(A, B, C);
    }
    await C.sendText(id, "in e2");
    await settle(A, B, C);
    expect(mustView(B, id).epoch).toBe(2);
    server().advanceEra(); // bob's device writes the new era's snapshot, at epoch 2
    await settle(A, B, C);
    const recs = latestSnapshot(bob);
    const epochs = recs.filter((r) => r.rtype === P.RT.EPOCH) as P.EpochRec[];
    expect(epochs.map((r) => [r.e, r.flags])).toEqual([
      [1, 0],
      [2, 0],
    ]);
    const from = server().requests.length;
    const B3 = await engineFor(bob);
    expect(mustView(B3, id).epoch).toBe(2);
    expect(mustView(B3, id).canSend).toBe(true);
    // neither claim below the top was evaluated, and epoch 2 came from its records (DESC, TREG): no meta request and
    // no bundle fetch for either bundle
    for (const b of bundles) {
      expect(metaOf("bob", from, b)).toBe(0);
      expect(blobOf("bob", from, b)).toBe(0);
    }
    expect(chat(B3, id)).toContain("carol: in e2");
    // scrollback reads the older epochs from the account's records
    B3.markRead(id);
    await settle(A, B3, C);
    expect(chat(B3, id)).toEqual(["alice: in e0", "carol: in e2"]);
    expect(systemLines(B3, id)).toContain('@alice renamed the conversation to “x”');
    await B3.sendText(id, "after the snapshot");
    await settle(A, B3, C);
    expect(chat(A, id).at(-1)).toBe("bob: after the snapshot");
  });

  it("an ended copy restores from the snapshot by its ENDED record, without its last claim", async () => {
    const {
      users: [, bob],
      engines: [A, B, C, D],
      id,
    } = await group(["alice", "bob", "carol", "dave"]);
    await A.sendText(id, "before");
    await settle(A, B, C, D);
    await C.removeMember(id, bob.uidB);
    await settle(A, B, C, D);
    const w = conv(B, id).epochs.get(0)!.ctl.winner!;
    server().advanceEra();
    await settle(A, B, C, D); // the new era's snapshot
    const recs = latestSnapshot(bob);
    expect(recs.some((r) => r.rtype === P.RT.ENDED)).toBe(true);
    expect(recs.some((r) => r.rtype === P.RT.CONFIRMED)).toBe(true);
    const from = server().requests.length;
    const B2 = await engineFor(bob);
    expect(mustView(B2, id).blocked).toBe("removed");
    expect(conv(B2, id).confirmed).toBe(true);
    expect(metaOf("bob", from, w.claim.bundleId)).toBe(0);
    expect(blobOf("bob", from, w.claim.bundleId)).toBe(0);
    expect(chat(B2, id)).toEqual(["alice: before"]);
    expect(systemLines(B2, id)).toContain("@carol removed you");
  });

  it("a legacy skip record's copy is written as its own CONV_JOIN with the bit1 record beside it", async () => {
    const {
      users: [, bob],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const G = { conv: conv(B, id).conv, root: conv(B, id).root };
    await B.logout();
    await A.removeMember(id, bob.uidB);
    await settle(A, C);
    await A.addMembers(id, ["bob"]);
    await settle(A, C);
    const w = conv(A, id).epochs.get(0)!.ctl.winner!;
    const e2 = conv(A, id).epochs.get(2)!;
    server().advanceEra(); // bob's next restore writes this era's snapshot
    writeSelfRow(bob, [
      {
        rtype: P.RT.EPOCH,
        ...G,
        e: 2,
        EK: e2.EK,
        bundleId: e2.bundleId,
        bundleSize: e2.bundleSize,
        claim: { E: w.E, n: w.n },
        flags: P.EPOCH_SKIP,
      },
    ]);
    const B2 = await engineFor(bob); // reads the record from the bundle, then writes the era's snapshot
    await settle(A, B2, C);
    const recs = latestSnapshot(bob);
    const joins = recs.filter((r) => r.rtype === P.RT.CONV_JOIN) as P.ConvJoinRec[];
    expect(joins.map((r) => r.e)).toEqual([0, 2]);
    const bit1 = recs.filter((r) => r.rtype === P.RT.EPOCH && r.flags === P.EPOCH_SKIP);
    expect(bit1).toHaveLength(1);
    expect(recs.indexOf(bit1[0])).toBeGreaterThan(recs.indexOf(joins[1]));
    const from = server().requests.length;
    const B3 = await engineFor(bob);
    expect(mustView(B3, `${id}~1`).epoch).toBe(2);
    expect(mustView(B3, id).blocked).toBe("removed");
    expect(blobOf("bob", from, e2.bundleId)).toBe(0); // matched to its CONV_JOIN: no fetch
    expect(metaOf("bob", from, e2.bundleId)).toBe(0); // its TREG is in the snapshot
    expect(B3.getState().warnings).toEqual([]);
  });

  it("an ended request is kept until it expires", async () => {
    const [bob, carol, dave] = ["bob", "carol", "dave"].map((h) => makeUser(h));
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const D = await engineFor(dave);
    const id = await C.createConversation(["bob", "dave"], "g");
    await settle(B, C, D);
    await C.removeMember(id, bob.uidB);
    await settle(B, C, D);
    expect(mustView(B, id).request).toBe(true);
    expect(mustView(B, id).blocked).toBe("removed");
    server().advanceEra();
    await settle(B, C, D);
    const B2 = await engineFor(bob);
    expect(mustView(B2, id).blocked).toBe("removed");
    for (let i = 0; i < 5; i++) {
      server().advanceEra();
      await settle(B2, C, D);
    }
    const B3 = await engineFor(bob);
    expect(I(B3).views().map((v) => v.id)).toEqual([]);
  });
});

describe("control positions at restore (§7.3, §11.4 step 5)", () => {
  it("(35 a) below the top the winners are read at their records; the top's control lane starts at its furthest HEADS position", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(["bob"]);
    await settle(A, B);
    B.markRead(id);
    await settle(A, B);
    const junk: Uint8Array[] = [];
    // three signed junk claims that pass the local rules (their bundles are not registered: rule (g) decides them)
    const postJunk = () => {
      for (let i = 0; i < 3; i++) {
        const ep = epoch(A, id);
        const bundleId = P.random(32);
        junk.push(bundleId);
        postRow(ep, buildClaim(alice, ep, { hD: P.random(32), ekc: P.random(32), bundleId, bundleSize: 23456 }));
      }
    };
    for (const name of ["a", "b", "c"]) {
      postJunk();
      await settle(A, B);
      await commitChange(alice, epoch(A, id), [alice, bob], name);
      await settle(A, B);
    }
    postJunk(); // and three in epoch 3
    await settle(A, B);
    expect(mustView(A, id).epoch).toBe(3);
    server().advanceEra(); // alice's device writes the era's snapshot at 3, its HEADS entry past the junk
    await settle(A, B);
    // a lagging sibling's HEADS entry for epoch 0, written after the snapshot: the restore starts there
    const c = conv(A, id);
    const e0 = c.epochs.get(0)!;
    writeSelfRow(alice, [
      {
        rtype: P.RT.HEADS,
        Ein: 0,
        relIn: 0,
        entries: [
          {
            conv: c.conv,
            root: c.root,
            e: 0,
            lastTs: 0,
            ctl: { E: e0.Estart!, cnt: 0 },
            lanes: e0.D.members.map(() => ({ E: e0.Estart!, cnt: 0 })),
            followed: [],
          },
        ],
      },
    ]);
    await A.logout();
    const from = server().requests.length;
    const A2 = await engineFor(alice);
    expect(mustView(A2, id).epoch).toBe(3);
    expect(mustView(A2, id).name).toBe("# c");
    for (const b of junk) expect(metaOf("alice", from, b)).toBe(0);
    await A2.sendText(id, "still here");
    await settle(A2, B);
    expect(chat(B, id).at(-1)).toBe("alice: still here");
  });
});
