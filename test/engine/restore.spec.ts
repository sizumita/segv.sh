// Restore and creation (docs/PROTOCOL.md §6.1, §11.4): a reload rebuilds conversations
// from the self lane, and a creation resolves before its commit wait, holds own sends until the decoy is stored, and
// never turns a transient lookup failure into "unknown".
import { describe, expect, it } from "vite-plus/test";
import { I, P, chat, engineFor, freshWorldPerTest, makeUser, mustView, server, settle, systemLines, view, type W } from "./harness";

freshWorldPerTest();

describe("restore from the self lane", () => {
  it("a reload holds every conversation with its history, names and request state, and nothing unread", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const one = await A.createConversation(["bob"]);
    const team = await A.createConversation(["bob", "carol"], "team");
    await settle(A, B);
    await A.sendText(one, "hello bob");
    await A.sendText(team, "hello team");
    await settle(A, B);
    await B.sendText(one, "hi alice"); // accepts bob's 1:1; the group stays a request on bob's side
    await settle(A, B);

    const A2 = await engineFor(alice);
    const B2 = await engineFor(bob);
    expect(chat(A2, one)).toEqual(["alice: hello bob", "bob: hi alice"]);
    expect(chat(A2, team)).toEqual(["alice: hello team"]);
    expect(chat(B2, one)).toEqual(["alice: hello bob", "bob: hi alice"]);
    expect(chat(B2, team)).toEqual(["alice: hello team"]);
    expect(mustView(A2, team).name).toBe("# team");
    expect(mustView(B2, team).name).toBe("# team");
    expect(mustView(B2, one).request).toBe(false);
    expect(mustView(B2, team).request).toBe(true);
    expect(systemLines(A2, one)).toEqual(["you started the conversation"]);
    expect(systemLines(B2, team)).toEqual(["@alice started the conversation"]);
    for (const E of [A2, B2]) for (const v of I(E).views()) expect(v.unread).toBe(0);
    // the reloaded devices send on: their counters are past the rows they restored
    await A2.sendText(one, "back");
    await settle(A, A2, B, B2);
    expect(chat(B, one)).toEqual(["alice: hello bob", "bob: hi alice", "alice: back"]);
    expect(chat(B2, one)).toEqual(["alice: hello bob", "bob: hi alice", "alice: back"]);
    for (const E of [A, A2, B, B2]) expect([E.getState().error, E.getState().warnings]).toEqual(["", []]);
    void carol;
  });
});

describe("creation", () => {
  it("resolves with the copy in conversations before the commit wait ends; own sends wait for the decoy", async () => {
    makeUser("bob");
    const A = await engineFor(makeUser("alice"));
    // Hold the decoy (a cls-1 row without a topic) until released.
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let decoyLabel: Uint8Array | null = null;
    server().hooks.beforePut = async (rows: W.PutRow[]) => {
      const d = rows.find((r) => r.cls === 1 && P.equalBytes(r.topic, P.ZERO16));
      if (d) {
        decoyLabel = d.label;
        await held;
      }
    };
    const id = await A.createConversation(["bob"]);
    expect(A.getState().conversations.map((c) => c.id)).toContain(id); // emitted before resolving
    expect(decoyLabel).toBeNull(); // the commit wait (Δ + SKEW) has not ended
    const sent = A.sendText(id, "early");
    expect(view(A, id)!.messages.find((m) => m.mine)!.status).toBe("sending");
    await new Promise((r) => setTimeout(r, 1500)); // the wait ends and the decoy is put, then held
    expect(decoyLabel).not.toBeNull();
    expect(view(A, id)!.messages.find((m) => m.mine)!.status).toBe("sending");
    release();
    await sent;
    await settle(A);
    const mine = view(A, id)!.messages.find((m) => m.mine)!;
    expect(mine.status).toBe("sent");
    const byLabel = (hex: string) => server().shard.rows().find((r) => P.hex(r.label) === hex)!;
    const decoy = byLabel(P.hex(decoyLabel!));
    const text = byLabel(mine.key.split(":")[1]);
    expect(text.t).toBeGreaterThanOrEqual(decoy.t);
    server().hooks.beforePut = undefined;
  });

  it("a failed handle lookup fails the creation with the request error, never \"unknown\"", async () => {
    makeUser("bob");
    const A = await engineFor(makeUser("alice"));
    server().dir.failDir(() => true, 1);
    const err = (await A.createConversation(["bob"]).then(
      () => null,
      (e: unknown) => e,
    )) as Error;
    expect(err).toBeInstanceOf(Error);
    expect(err.message).not.toMatch(/unknown/);
    // a complete answer without the handle is "unknown"; with it, the creation succeeds
    await expect(A.createConversation(["nobody"])).rejects.toThrow(/unknown: @nobody/);
    const id = await A.createConversation(["bob"]);
    expect(I(A).views().map((v) => v.id)).toContain(id);
  });
});

describe("scrollback after a reload", () => {
  it("opening a 1:1 with 100 messages after a reload shows more than 60 of them", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(["bob"]);
    await settle(A, B);
    for (let i = 0; i < 100; i++) await A.sendText(id, `m ${i}`);
    await settle(A, B);
    expect(chat(B, id)).toHaveLength(100);
    const B2 = await engineFor(bob);
    const before = chat(B2, id).length;
    expect(before).toBeLessThanOrEqual(30); // the initial history: the last 30 slots of alice's lane
    B2.markRead(id);
    await settle(B2);
    const after = chat(B2, id);
    expect(after.length).toBeGreaterThan(60);
    expect(after.at(-1)).toBe("alice: m 99");
    expect(after[0]).toBe("alice: m 0"); // the whole history fits VIEW_MESSAGES
    expect(I(B2).views().find((v) => v.id === id)!.unread).toBe(0); // scrollback never counts as unread
  });
});
