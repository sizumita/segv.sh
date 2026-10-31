// TREG (docs/PROTOCOL.md §7.2): a join's CONV_JOIN carries its bundle's t_reg in the same self row, so a restore takes
// E_start from the record instead of asking BlobReg; a copy joined before TREG existed falls back to one blob/meta.
import { describe, expect, it } from "vite-plus/test";
import {
  I,
  P,
  conv,
  engineFor,
  epoch,
  freshWorldPerTest,
  makeUser,
  mustView,
  server,
  settle,
  type TestUser,
} from "./harness";

freshWorldPerTest();

/** Every self row of `u` in the current and the previous era, opened, in lane order. */
function selfRows(u: TestUser): P.SelfRecord[][] {
  const out: P.SelfRecord[][] = [];
  for (let E = server().era - 1; E <= server().era; E++)
    for (let n = 0; ; n++) {
      const label = P.Lself(u.id.rS, E, n);
      const row = server().shard.row(E, label);
      if (!row) break;
      out.push(P.openSelf(u.id.kS, E, label, row.body).records);
    }
  return out;
}

/** blob/meta requests of one client for one bundle since request index `from`. */
const metaAsks = (who: string, bundleId: Uint8Array, from = 0): number =>
  server()
    .requests.slice(from)
    .filter((r) => r.who === who && r.path === `/api/v2/blob/${P.b64u(bundleId)}/meta`).length;

describe("TREG", () => {
  it("a join writes its CONV_JOIN and TREG in one row; a restore reads E_start from it without blob/meta", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    await engineFor(carol);
    await B.createConversation(["alice"]); // bob resolves alice by handle: she becomes his contact
    await settle(A, B);
    const g = await A.createConversation(["bob", "carol"], "g");
    await settle(A, B);
    expect(mustView(B, g).request).toBe(false); // from a contact: an accepted copy (CONV_JOIN)
    const ep = epoch(A, g);
    const row = selfRows(bob).find((rs) =>
      rs.some((r) => r.rtype === P.RT.CONV_JOIN && P.equalBytes(r.conv, ep.D.conv)),
    )!;
    const treg = row.find((r) => r.rtype === P.RT.TREG) as P.TregRec | undefined;
    expect(treg).toBeDefined();
    expect(P.equalBytes(treg!.bundleId, ep.bundleId)).toBe(true);
    expect(treg!.tReg).toBe(ep.tReg);
    const from = server().requests.length;
    const B2 = await engineFor(bob);
    expect(mustView(B2, g).name).toBe("# g");
    expect(metaAsks("bob", ep.bundleId, from)).toBe(0);
  });

  it("a copy joined before TREG existed (CONV_JOIN alone) restores with one blob/meta", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    // The invite never reaches the inbox: bob's copy comes only from the CONV_JOIN written below.
    server().hooks.fail = (m, p, who) =>
      who === "alice" && m === "POST" && p === "/api/v2/inbox" ? "before" : undefined;
    const id = await A.createConversation(["bob"]); // resolves once its CONV_JOIN and EPOCH_PENDING are written
    const ep = epoch(A, id);
    const c = conv(A, id);
    await I(B).self!.write([
      {
        rtype: P.RT.CONV_JOIN,
        conv: c.conv,
        root: c.root,
        e: 0,
        EK: ep.EK,
        bundleId: ep.bundleId,
        bundleSize: ep.bundleSize,
        rootBy: alice.uid,
        via: P.VIA.INBOX,
      },
    ]);
    await B.logout();
    const from = server().requests.length;
    const B2 = await engineFor(bob);
    expect(mustView(B2, id).name).toBe("@alice");
    expect(metaAsks("bob", ep.bundleId, from)).toBe(1);
    server().hooks.fail = undefined;
  });
});
