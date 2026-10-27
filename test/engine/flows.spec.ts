// Honest end-to-end flows of the engine against the FakeWorld (docs/STAGE1-PLAN.md M6b; ported from
// 3de5f5e:test/engine/flows.spec.ts): 1:1 both ways (the recipient's copy is a request until it posts or opens it),
// a later device, unknown handles, group "# " names and name sanitisation. Add, remove, rename and leave land with M7.
import { describe, expect, it } from "vite-plus/test";
import {
  I,
  P,
  chat,
  engineFor,
  epoch,
  freshWorldPerTest,
  makeUser,
  mustView,
  server,
  settle,
  systemLines,
} from "./harness";

freshWorldPerTest();

describe("1:1 conversations", () => {
  it("creates a conversation and delivers messages both ways", async () => {
    const alice = makeUser("alice");
    const bob = makeUser("bob");
    const A = await engineFor(alice);
    const B = await engineFor(bob);

    const id = await A.createConversation(["@bob"]);
    await settle(A, B);
    expect(systemLines(A, id)).toEqual(["you started the conversation"]);
    expect(systemLines(B, id)).toEqual(["@alice started the conversation"]);
    expect(mustView(A, id).name).toBe("@bob");
    expect(mustView(B, id).name).toBe("@alice");
    expect(mustView(B, id).request).toBe(true); // a first contact from a stranger (§11.5)
    expect(
      mustView(A, id)
        .members.map((m) => m.handle)
        .sort(),
    ).toEqual(["alice", "bob"]);

    await A.sendText(id, "hi bob");
    await settle(A, B);
    await B.sendText(id, "hi alice");
    await settle(A, B);
    expect(mustView(B, id).request).toBe(false); // posting accepted it
    expect(chat(A, id)).toEqual(["alice: hi bob", "bob: hi alice"]);
    expect(chat(B, id)).toEqual(["alice: hi bob", "bob: hi alice"]);
    expect(mustView(B, id).unread).toBeGreaterThanOrEqual(1);
    // The local echo was replaced by the stored row (exactly one copy, status "sent").
    expect(mustView(A, id).messages.filter((m) => m.mine)).toHaveLength(1);
    expect(mustView(A, id).messages.find((m) => m.mine)!.status).toBe("sent");
    expect(A.getState().error).toBe("");
    expect(A.getState().warnings).toEqual([]);
    expect(B.getState().warnings).toEqual([]);
  });

  it("a later device of the same account sees the history", async () => {
    const alice = makeUser("alice");
    const bob = makeUser("bob");
    const A = await engineFor(alice);
    const id = await A.createConversation(["bob"]);
    await A.sendText(id, "one");
    await A.sendText(id, "two");
    await settle(A);
    const A2 = await engineFor(alice);
    const B = await engineFor(bob);
    expect(chat(A2, id)).toEqual(["alice: one", "alice: two"]);
    expect(chat(B, id)).toEqual(["alice: one", "alice: two"]);
    // Own rows from another device advance this device's counter: no CONFLICT loop.
    await A2.sendText(id, "three");
    await settle(A, A2, B);
    expect(chat(B, id)).toEqual(["alice: one", "alice: two", "alice: three"]);
    expect(chat(A, id)).toEqual(["alice: one", "alice: two", "alice: three"]);
    expect(A2.getState().error).toBe("");
  });

  it("finds a user who registered after this session looked the handle up", async () => {
    const A = await engineFor(makeUser("alice"));
    await expect(A.createConversation(["bob"])).rejects.toThrow(/unknown: @bob/); // the answer is now cached
    const bob = makeUser("bob");
    const id = await A.createConversation(["bob"]);
    const B = await engineFor(bob);
    await settle(A, B);
    expect(mustView(B, id).name).toBe("@alice");
  });

  it("a join's line takes D.ts clamped to the bundle's t_reg ± 5 min, live and after a reload (R10-2)", async () => {
    const alice = makeUser("alice");
    const bob = makeUser("bob");
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    I(A).clock.advance(86_400_000, { mono: false, wall: true }); // alice's wall clock runs a day ahead
    const id = await A.createConversation(["bob"]);
    await settle(A, B);
    const tReg = epoch(B, id).tReg!;
    const hi = P.T0_MS + (tReg + server().params.delta) * 1000 + 300_000;
    const line = (E: Parameters<typeof mustView>[0]) => mustView(E, id).messages.find((m) => m.kind === "system")!;
    expect(line(B).ts).toBe(hi);
    expect(mustView(B, id).lastTs).toBe(hi);
    const B2 = await engineFor(bob); // the restore takes t_reg from the REQUEST record
    expect(line(B2).ts).toBe(hi);
    expect(mustView(B2, id).lastTs).toBe(hi);
  });

  it("rejects unknown handles and empty conversations", async () => {
    const alice = makeUser("alice");
    const A = await engineFor(alice);
    await expect(A.createConversation(["nobody"])).rejects.toThrow(/unknown: @nobody/);
    await expect(A.createConversation(["alice"])).rejects.toThrow(/at least one other/);
  });
});

describe("groups", () => {
  it('delivers group messages to every member and marks chosen names with "# "', async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const id = await A.createConversation(["bob, carol"], "team");
    await settle(A, B, C);
    for (const E of [A, B, C]) expect(mustView(E, id).name).toBe("# team");

    await A.sendText(id, "from alice");
    await settle(A, B, C);
    await B.sendText(id, "from bob");
    await settle(A, B, C);
    await C.sendText(id, "from carol");
    await settle(A, B, C);
    for (const E of [A, B, C])
      expect(chat(E, id)).toEqual(["alice: from alice", "bob: from bob", "carol: from carol"]);
    for (const E of [A, B, C]) expect(E.getState().warnings).toEqual([]);
  });

  it("a name can never pass for a 1:1 and unnamed groups list the other members", async () => {
    const [alice] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    await expect(A.createConversation(["bob"], "@bob")).rejects.toThrow(/cannot start with/);
    const id = await A.createConversation(["bob", "carol"]);
    const id2 = await A.createConversation(["bob"], "  ‮evil\u0007  name ");
    await settle(A);
    expect(mustView(A, id).name).toBe("@bob, @carol");
    expect(mustView(A, id2).name).toBe("# evil name"); // control / bidi characters stripped, whitespace collapsed
  });
});
