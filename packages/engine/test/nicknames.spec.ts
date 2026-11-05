// Nicknames (docs/PROTOCOL.md §11.19, §7.2 NICK, §7.4): private names for other users in NICK records of the owner's
// self lane, shown in place of their handles in names, system lines, members and senders, never for an unknown member
// and never in warnings, applied by sibling devices and kept by snapshots.
import { describe, expect, it } from "vite-plus/test";
import { aliasKeys } from "../src/accounts";
import { NICK_INVALID, NICK_OWN } from "../src/engine";
import { keysChangedWarning } from "../src/selflane";
import {
  I,
  P,
  engineFor,
  freshWorldPerTest,
  makeUser,
  mustView,
  selfRowsOf,
  server,
  settle,
  systemLines,
  viewsOf,
  waitFor,
  writeSelfRow,
  type TestUser,
} from "./harness";

freshWorldPerTest();

/** The NICK records of `u`'s self lane, each with the number of records of its row. */
const nickRows = (u: TestUser) =>
  selfRowsOf(u).flatMap((row) =>
    row.filter((r) => r.rtype === P.RT.NICK).map((r) => ({ r: r as P.NickRec, count: row.length })),
  );

/** The records of `u`'s latest snapshot in the current era. */
function latestSnapshot(u: TestUser): P.SelfRecord[] {
  const E = server().era;
  let last: P.SnapRec | null = null;
  for (let j = 0; ; j++) {
    const label = P.Lsnap(u.id.rS, E, j);
    const row = server().shard.row(E, label);
    if (!row) break;
    last = P.openSelf(u.id.kS, E, label, row.body, "snap").records[0] as P.SnapRec;
  }
  if (!last) return [];
  const blob = server().blobs.bytes(P.b64u(last.blobId))!;
  return P.decryptSnapshot(blob, P.b64u(last.blobId), last.key).records;
}

describe("nicknames (§11.19)", () => {
  it('a NICK row of its own; names, lines, members and senders show it, handles stay; "" removes it', async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const one = await A.createConversation(["bob"]);
    await settle(A, B, C);
    await B.accept(viewsOf(B)[0].id);
    await settle(A, B, C);
    // bob, now alice's contact, starts a group with alice and carol, and adds a line naming him
    const g = await B.createConversation(["alice"], "");
    await settle(A, B, C);
    await B.addMembers(g, ["carol"]);
    await B.sendText(g, "hi");
    await settle(A, B, C);
    const gA = viewsOf(A).find((v) => v.id !== one)!.id;
    expect(systemLines(A, gA)).toEqual(["@bob started the conversation", "@bob added @carol"]);

    await A.setNickname(bob.uidB, "Bobby");
    const rows = nickRows(alice);
    expect(rows.map((x) => [P.b64u(x.r.uid), x.r.name, x.count])).toEqual([[bob.uidB, "Bobby", 1]]);
    expect(mustView(A, one).name).toBe("Bobby");
    expect(mustView(A, gA).name).toBe("Bobby, @carol");
    expect(systemLines(A, gA)).toEqual(["Bobby started the conversation", "Bobby added @carol"]);
    const m = mustView(A, gA).members.find((x) => x.uid === bob.uidB)!;
    expect(m).toMatchObject({ handle: "bob", nickname: "Bobby", you: false, own: false });
    expect(mustView(A, gA).members.find((x) => x.uid === alice.uidB)).toMatchObject({
      nickname: "",
      you: true,
    });
    const hi = mustView(A, gA).messages.find((x) => x.text === "hi")!;
    expect(hi).toMatchObject({ fromHandle: "bob", fromNickname: "Bobby" });
    // a message that arrives later carries it too
    await B.sendText(one, "later");
    await settle(A, B, C);
    expect(mustView(A, one).messages.find((x) => x.text === "later")).toMatchObject({
      fromNickname: "Bobby",
    });
    // nobody else sees it
    expect(mustView(C, viewsOf(C)[0].id).members.every((x) => x.nickname === "")).toBe(true);
    expect(
      I(A)
        .people()
        .find((p) => p.uid === bob.uidB),
    ).toEqual({
      uid: bob.uidB,
      handle: "bob",
      nickname: "Bobby",
      contactOf: [alice.uidB],
    });
    expect(
      I(A)
        .people()
        .some((p) => p.uid === alice.uidB),
    ).toBe(false);

    await A.setNickname(bob.uidB, "");
    expect(nickRows(alice).map((x) => x.r.name)).toEqual(["Bobby", ""]);
    expect(mustView(A, one).name).toBe("@bob");
    expect(systemLines(A, gA)).toEqual(["@bob started the conversation", "@bob added @carol"]);
    expect(mustView(A, gA).messages.find((x) => x.text === "hi")!.fromNickname).toBe("");
  });

  it("an unknown member never shows a nickname, and warnings keep the @handle", async () => {
    const [alice, bob, dave, carol] = ["alice", "bob", "dave", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const D = await engineFor(dave);
    const one = await A.createConversation(["bob", "carol"]);
    await settle(A, B, D);
    await A.setNickname(carol.uidB, "Caz");
    await A.setNickname(bob.uidB, "Bobby");
    expect(mustView(A, one).members.find((m) => m.uid === carol.uidB)!.nickname).toBe("Caz");
    // dave is no contact of alice: his request shows its members other than him as unknown (§11.5)
    await D.createConversation(["alice", "carol"], "");
    await settle(A, B, D);
    const req = viewsOf(A).find((v) => v.request)!;
    const c = req.members.find((m) => m.uid === carol.uidB)!;
    expect(c.handle.startsWith("?")).toBe(true);
    expect(c.nickname).toBe("");
    expect(req.name).toContain(`@${c.handle}`);
    expect(req.name).not.toContain("Caz");
    // a MEMBER record that disagrees with bob's pin: the warning names @bob, never his nickname
    writeSelfRow(alice, [
      {
        rtype: P.RT.MEMBER,
        uid: bob.uid,
        sigPk: bob.id.sigPk,
        kh: P.kemHash(bob.id.kemPk),
        pin: P.random(32),
        handle: "bob",
      },
    ]);
    await settle(A, B, D);
    await waitFor(() => A.getState().warnings.includes(keysChangedWarning("bob")), "warning");
    expect(A.getState().warnings.some((w) => w.includes("Bobby"))).toBe(false);
  });

  it("a sibling device applies it, and a snapshot keeps it", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const A1 = await engineFor(alice);
    const A2 = await engineFor(alice);
    const B = await engineFor(bob);
    const one = await A1.createConversation(["bob"]);
    await settle(A1, A2, B);
    await A1.setNickname(bob.uidB, "Bobby");
    await settle(A1, A2, B);
    expect(mustView(A2, one).name).toBe("Bobby");
    server().advanceEra(); // a live device writes the new era's snapshot (§7.4)
    await settle(A1, A2, B);
    const nicks = latestSnapshot(alice).filter((r) => r.rtype === P.RT.NICK) as P.NickRec[];
    expect(nicks.map((r) => [P.b64u(r.uid), r.name])).toEqual([[bob.uidB, "Bobby"]]);
    const A3 = await engineFor(alice);
    await settle(A1, A2, A3, B);
    expect(mustView(A3, one).name).toBe("Bobby");
  });

  it("refuses names that are not valid and the user's own accounts", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const uid = await A.createAlias();
    for (const bad of ["@bob", " ", "‮", "x".repeat(65), "＠bob"])
      await expect(A.setNickname(bob.uidB, bad)).rejects.toThrow(NICK_INVALID);
    await expect(A.setNickname(alice.uidB, "me")).rejects.toThrow(NICK_OWN);
    await expect(A.setNickname(uid, "me too")).rejects.toThrow(NICK_OWN);
    expect(uid).toBe(aliasKeys(alice.AK, 0).uidB);
    expect(nickRows(alice)).toEqual([]);
    // surrounding white space is dropped; the same name again writes nothing
    await A.setNickname(bob.uidB, "  Bob B.  ");
    await A.setNickname(bob.uidB, "Bob B.");
    expect(nickRows(alice).map((x) => x.r.name)).toEqual(["Bob B."]);
  });
});
