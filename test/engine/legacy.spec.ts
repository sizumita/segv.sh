// Legacy skip records (docs/PROTOCOL.md §7.2 "Legacy skip records", §7.3, §11.4 step 5, §11.7): the EPOCH records
// with flag bit1 that the first release wrote when it took a re-add as a skip of a removed copy are read as the joins
// of separate copies, merged with a copy of the same key, and the legacy copy's later records are split among them.
import { describe, expect, it } from "vite-plus/test";
import type { Engine } from "../../src/client/types";
import {
  I,
  P,
  conv,
  engineFor,
  freshWorldPerTest,
  makeUser,
  mustView,
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

const warnings = (e: Engine) => e.getState().warnings;
const ids = (e: Engine) => I(e).views().map((v) => [v.id, v.epoch, v.blocked, v.request] as const);

/** The (era, rel) of the invite carrying J(e) of `convId` in `u`'s inbox. */
function inviteOf(u: TestUser, convId: Uint8Array, e: number): { E: number; rel: number } {
  for (const E of server().inbox.eraList())
    for (const r of server().inbox.rowsOf(E)) {
      const o = P.tryOpenInvite(u.id.kemSk, E, 0, r.eid, r.body);
      if (o?.kind === "join" && P.equalBytes(o.join.conv, convId) && o.join.e === e) return { E, rel: r.rel };
    }
  throw new Error(`no invite for e = ${e}`);
}

/**
 * The bit1 record that the first release wrote when it took the re-add J(e′) of the held copy `G` as a skip, naming
 * the claim that removed self (from the committer's copy), and the HEADS record that moved its cursor past J(e′).
 */
function legacySkip(
  bob: TestUser,
  G: { conv: Uint8Array; root: Uint8Array },
  ep: { e: number; EK: Uint8Array; bundleId: Uint8Array; bundleSize: number },
  removal: { E: number; n: number },
): P.SelfRecord[] {
  const at = inviteOf(bob, G.conv, ep.e);
  return [
    {
      rtype: P.RT.EPOCH,
      conv: G.conv,
      root: G.root,
      e: ep.e,
      EK: ep.EK,
      bundleId: ep.bundleId,
      bundleSize: ep.bundleSize,
      claim: removal,
      flags: P.EPOCH_SKIP,
    },
    { rtype: P.RT.HEADS, Ein: at.E, relIn: at.rel, entries: [] },
  ];
}

/** bob's blob GETs and meta requests for a bundle since request index `from`. */
function bundleAsks(who: string, from: number, id: Uint8Array): { blob: number; meta: number } {
  const reqs = server().requests.slice(from).filter((r) => r.who === who);
  return {
    blob: reqs.filter((r) => r.method === "GET" && r.path === `/api/v2/blob/${P.b64u(id)}`).length,
    meta: reqs.filter((r) => r.path === `/api/v2/blob/${P.b64u(id)}/meta`).length,
  };
}

describe("legacy skip records (§7.2)", () => {
  it("(a) a restore reads a bit1 record as the join of a separate copy, with its own records split by epoch", async () => {
    const {
      users: [, bob],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const G = { conv: conv(B, id).conv, root: conv(B, id).root };
    await B.logout(); // bob's tab on the first release takes the re-add as a skip
    await A.removeMember(id, bob.uidB); // C_0
    await settle(A, C);
    await A.addMembers(id, ["bob"]); // J(2)
    await settle(A, C);
    const w = conv(A, id).epochs.get(0)!.ctl.winner!;
    const e2 = conv(A, id).epochs.get(2)!;
    writeSelfRow(bob, legacySkip(bob, G, e2, { E: w.E, n: w.n }));
    writeSelfRow(bob, [{ rtype: P.RT.LEAVE, ...G, e: 2 }]); // the tab left the copy it continued
    const from = server().requests.length;
    const B2 = await engineFor(bob);
    await settle(A, B2, C);
    // G keeps `id`, ended at C_0 with "@alice removed you" (its own LEAVE records: none); the bit1 record's copy G′
    // is `id~1`, accepted (G's CONV_JOIN is in the fold), with its join line and the LEAVE record of epoch 2.
    expect(ids(B2).sort()).toEqual(
      [
        [id, 0, "removed", false],
        [`${id}~1`, 2, "left", false],
      ].sort(),
    );
    expect(systemLines(B2, id)).toContain("@alice removed you");
    expect(systemLines(B2, `${id}~1`)[0]).toBe("@alice added you");
    expect(conv(B2, id).left).toBe(false);
    expect(warnings(B2)).toEqual([]);
    // D_{e′} from its bundle (one fetch) and t_reg from one meta request (the record has no TREG)
    expect(bundleAsks("bob", from, e2.bundleId)).toEqual({ blob: 1, meta: 1 });
  });

  it("(c) a tab's bit1 record of a J this device took as a first contact merges with that copy", async () => {
    const {
      users: [, bob],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const G = { conv: conv(B, id).conv, root: conv(B, id).root };
    await A.removeMember(id, bob.uidB);
    await settle(A, B, C);
    await A.addMembers(id, ["bob"]);
    await settle(A, B, C);
    expect(ids(B).map((x) => x[0]).sort()).toEqual([id, `${id}~1`].sort());
    const w = conv(A, id).epochs.get(0)!.ctl.winner!;
    writeSelfRow(bob, legacySkip(bob, G, conv(A, id).epochs.get(2)!, { E: w.E, n: w.n }));
    await settle(A, B, C);
    expect(ids(B).map((x) => x[0]).sort()).toEqual([id, `${id}~1`].sort());
    expect(warnings(B)).toEqual([]);
    const B2 = await engineFor(bob);
    await settle(A, B2, C);
    expect(ids(B2).sort()).toEqual(
      [
        [id, 0, "removed", false],
        [`${id}~1`, 2, "", false],
      ].sort(),
    );
    expect(warnings(B2)).toEqual([]);
  });

  it("(c) with the bit1 record written first, the restore holds the copy from it and the J is a duplicate", async () => {
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
    const [skip] = legacySkip(bob, G, conv(A, id).epochs.get(2)!, { E: w.E, n: w.n });
    writeSelfRow(bob, [skip]); // without the cursor: the restore's poll finds J(2) again
    const B2 = await engineFor(bob);
    await settle(A, B2, C);
    expect(ids(B2).sort()).toEqual(
      [
        [id, 0, "removed", false],
        [`${id}~1`, 2, "", false],
      ].sort(),
    );
    expect(warnings(B2)).toEqual([]);
  });

  it("(c) request variant: a bit1 record never accepts a copy this device holds as a request", async () => {
    const {
      users: [, bob],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const G = { conv: conv(B, id).conv, root: conv(B, id).root };
    await C.removeMember(id, bob.uidB);
    await settle(A, B, C);
    await C.addMembers(id, ["bob"]); // carol is no contact of bob's: a request
    await settle(A, B, C);
    expect(mustView(B, `${id}~1`).request).toBe(true);
    const w = conv(C, id).epochs.get(0)!.ctl.winner!;
    writeSelfRow(bob, legacySkip(bob, G, conv(C, id).epochs.get(2)!, { E: w.E, n: w.n }));
    await settle(A, B, C);
    expect(mustView(B, `${id}~1`).request).toBe(true);
    const B2 = await engineFor(bob);
    await settle(A, B2, C);
    expect(mustView(B2, `${id}~1`).request).toBe(true);
    expect(ids(B2).length).toBe(2);
    expect(warnings(B2)).toEqual([]);
  });

  it("(d) two bit1 records of one copy start two copies, the first ended by its own removal", async () => {
    const {
      users: [, bob],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const G = { conv: conv(B, id).conv, root: conv(B, id).root };
    await B.logout();
    await A.removeMember(id, bob.uidB); // C_0
    await settle(A, C);
    await A.addMembers(id, ["bob"]); // J(2)
    await settle(A, C);
    await C.removeMember(id, bob.uidB); // C_2
    await settle(A, C);
    await C.addMembers(id, ["bob"]); // J(4)
    await settle(A, C);
    const w0 = conv(A, id).epochs.get(0)!.ctl.winner!;
    const w2 = conv(A, id).epochs.get(2)!.ctl.winner!;
    writeSelfRow(bob, legacySkip(bob, G, conv(A, id).epochs.get(2)!, { E: w0.E, n: w0.n }));
    writeSelfRow(bob, legacySkip(bob, G, conv(A, id).epochs.get(4)!, { E: w2.E, n: w2.n }));
    const B2 = await engineFor(bob);
    await settle(A, B2, C);
    expect(ids(B2).sort()).toEqual(
      [
        [id, 0, "removed", false],
        [`${id}~1`, 2, "removed", false],
        [`${id}~2`, 4, "", false],
      ].sort(),
    );
    expect(warnings(B2)).toEqual([]);
    expect(I(B2).views().some((v) => v.name.startsWith("⚠"))).toBe(false);
  });
});
