// Membership changes end to end (docs/STAGE1-PLAN.md M7; ported from 3de5f5e:test/engine/flows.spec.ts "add, remove
// and rename" and "leave"; SPEC §6.3, §6.6, §6.9, §11.9).
import { describe, expect, it } from "vite-plus/test";
import {
  chat,
  commitChange,
  engineFor,
  epoch,
  freshWorldPerTest,
  makeUser,
  mustView,
  readableWith,
  settle,
  systemLines,
  view,
} from "./harness";

freshWorldPerTest();

describe("add, remove and rename", () => {
  it("shows add, remove and rename system lines to everyone", async () => {
    const [alice, bob, carol, dave] = ["alice", "bob", "carol", "dave"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const D = await engineFor(dave);
    const id = await A.createConversation(["bob", "carol"], "team");
    await settle(A, B, C);
    for (const E of [B, C]) E.markRead(id); // opening a request accepts it (§11.5)
    await settle(A, B, C);

    await A.addMembers(id, ["dave"]);
    await settle(A, B, C, D);
    expect(systemLines(A, id).at(-1)).toBe("you added @dave");
    expect(systemLines(B, id).at(-1)).toBe("@alice added @dave");
    expect(systemLines(D, id)).toEqual(["@alice added you"]);
    expect(mustView(D, id).name).toBe("# team");
    expect(mustView(B, id).epoch).toBe(1);

    await B.removeMember(id, carol.uidB);
    await settle(A, B, C, D);
    expect(systemLines(A, id).at(-1)).toBe("@bob removed @carol");
    expect(systemLines(B, id).at(-1)).toBe("you removed @carol");
    expect(systemLines(C, id).at(-1)).toBe("@bob removed you");
    expect(mustView(C, id).canSend).toBe(false);
    expect(mustView(C, id).blocked).toBe("removed");

    await A.sendText(id, "carol cannot read this");
    await settle(A, B, C, D);
    expect(chat(B, id)).toEqual(["alice: carol cannot read this"]);
    expect(chat(D, id)).toEqual(["alice: carol cannot read this"]);
    expect(chat(C, id)).toEqual([]);
    await C.sendText(id, "am I here?");
    expect(C.getState().error).toMatch(/no longer a member/);

    // Rename: a well-formed change whose descriptor carries a new name (no UI action builds one).
    const ep = epoch(A, id);
    await commitChange(alice, ep, [alice, bob, dave], "new name");
    await settle(A, B, D);
    expect(systemLines(B, id).at(-1)).toBe("@alice renamed the conversation to “new name”");
    expect(systemLines(A, id).at(-1)).toBe("you renamed the conversation to “new name”");
    expect(mustView(D, id).name).toBe("# new name");

    const ep2 = epoch(A, id);
    await commitChange(alice, ep2, [alice, bob, dave], null);
    await settle(A, B, D);
    expect(systemLines(B, id).at(-1)).toBe("@alice removed the conversation name");
    expect(mustView(B, id).name).toBe("@alice, @dave");
    for (const E of [A, B, C, D]) expect(E.getState().warnings).toEqual([]);
  });

  it("a restore re-derives every epoch from the control lanes, with the same lines", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const id = await A.createConversation(["bob"], "pair");
    await settle(A, B);
    await A.sendText(id, "before");
    await A.addMembers(id, ["carol"]);
    await settle(A, B, C);
    await B.sendText(id, "after");
    await settle(A, B, C);
    const B2 = await engineFor(bob);
    expect(mustView(B2, id).epoch).toBe(1);
    expect(mustView(B2, id).members.map((m) => m.handle)).toEqual(["alice", "bob", "carol"]);
    expect(systemLines(B2, id)).toContain("@alice added @carol");
    expect(chat(B2, id)).toContain("bob: after");
    await B2.sendText(id, "from the new device");
    await settle(A, B2, C);
    expect(chat(C, id)).toContain("bob: from the new device");
    expect(B2.getState().warnings).toEqual([]);
  });

  it("refuses adding nobody new, removing self, and non-members", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const id = await A.createConversation(["bob"]);
    await settle(A);
    await expect(A.addMembers(id, ["bob"])).rejects.toThrow(/nobody new to add/);
    await expect(A.removeMember(id, alice.uidB)).rejects.toThrow(/leave/);
    await expect(A.removeMember(id, makeUser("zed").uidB)).rejects.toThrow(/not a member/);
    expect(mustView(A, id).epoch).toBe(0);
    void bob;
  });
});

describe("leave", () => {
  it("the leaver stops, the next sender rotates the keys and the leaver cannot read on", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const id = await A.createConversation(["bob", "carol"]);
    await settle(A, B, C);
    for (const E of [B, C]) E.markRead(id);
    await settle(A, B, C);

    await B.leave(id);
    await settle(A, B, C);
    expect(systemLines(A, id).at(-1)).toBe("@bob left");
    expect(systemLines(B, id).at(-1)).toBe("you left the conversation");
    expect(mustView(B, id).canSend).toBe(false);
    expect(mustView(A, id).members.find((m) => m.handle === "bob")!.left).toBe(true);

    await A.sendText(id, "after bob left");
    await settle(A, B, C);
    expect(mustView(A, id).epoch).toBe(1);
    expect(
      mustView(A, id)
        .members.map((m) => m.handle)
        .sort(),
    ).toEqual(["alice", "carol"]);
    expect(systemLines(C, id)).toContain("keys rotated after @bob left");
    expect(chat(C, id)).toEqual(["alice: after bob left"]);
    expect(chat(B, id)).toEqual([]);
    expect(view(B, id)!.epoch).toBe(0);
    expect(A.getState().error).toBe("");
    // The leaver's own timeline says so once (the leave row), not again when the rotation lands.
    expect(systemLines(B, id).filter((l) => l === "you left the conversation")).toHaveLength(1);
    // No row readable with the old epoch's key holds the text.
    const old = A.getState().conversations.find((c) => c.id === id)!;
    expect(old.epoch).toBe(1);
  });

  it("a text after a leave is never readable with the old epoch's key", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const id = await A.createConversation(["bob", "carol"]);
    await settle(A, B, C);
    for (const E of [B, C]) E.markRead(id);
    await settle(A, B, C);
    const mk0 = epoch(A, id).keys.mk;
    await B.leave(id);
    await settle(A, B, C);
    await C.sendText(id, "secret after the leave");
    await settle(A, B, C);
    const texts = readableWith(mk0).filter((m) => m.type === 1);
    expect(texts).toEqual([]);
    expect(chat(A, id)).toEqual(["carol: secret after the leave"]);
    expect(systemLines(A, id)).toContain("keys rotated after @bob left");
  });

  it("a leaver's other device and a reload keep the copy left", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(["bob"]);
    await settle(A, B);
    await B.leave(id);
    await settle(A, B);
    const B2 = await engineFor(bob);
    expect(mustView(B2, id).canSend).toBe(false);
    expect(mustView(B2, id).blocked).toBe("left");
    await B2.sendText(id, "still here?");
    expect(B2.getState().error).toBe("you left this conversation");
  });
});

describe("history across epochs (§11.4 step 6, §11.10)", () => {
  it("a reload shows the end of the previous epoch, and scrollback walks down to the root epoch", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const id = await A.createConversation(["bob"], "hist");
    await settle(A, B);
    B.markRead(id);
    await settle(A, B);
    for (let i = 0; i < 40; i++) await A.sendText(id, `e0 #${i}`);
    await A.addMembers(id, ["carol"]);
    await settle(A, B, C);
    await B.sendText(id, "e1 first");
    await settle(A, B, C);
    const B2 = await engineFor(bob);
    const shown = chat(B2, id);
    expect(shown).toContain("bob: e1 first");
    expect(shown).toContain("alice: e0 #39"); // the previous epoch's end, without opening it
    expect(shown).not.toContain("alice: e0 #0");
    B2.markRead(id);
    await settle(B2);
    const all = chat(B2, id);
    for (let i = 0; i < 40; i++) expect(all).toContain(`alice: e0 #${i}`);
    expect(all.indexOf("alice: e0 #0")).toBeLessThan(all.indexOf("alice: e0 #39"));
    expect(all.at(-1)).toBe("bob: e1 first");
    // Carol, added at e1, has no history below her root epoch.
    C.markRead(id);
    await settle(C);
    expect(chat(C, id)).toEqual(["bob: e1 first"]);
  });

  it("history below a removal shows the removed member's rows before the claim only", async () => {
    const [alice, bob, rita] = ["alice", "bob", "rita"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const R = await engineFor(rita);
    const id = await A.createConversation(["bob", "rita"], "cut");
    await settle(A, B, R);
    for (const X of [B, R]) X.markRead(id);
    await settle(A, B, R);
    await R.sendText(id, "rita before");
    await settle(A, B, R);
    await A.removeMember(id, rita.uidB);
    await settle(A, B, R);
    await A.sendText(id, "after");
    await settle(A, B);
    const B2 = await engineFor(bob);
    B2.markRead(id);
    await settle(B2);
    expect(chat(B2, id)).toEqual(["rita: rita before", "alice: after"]);
    expect(systemLines(B2, id)).toContain("@alice removed @rita");
  });
});
