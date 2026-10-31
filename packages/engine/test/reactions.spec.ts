// Reactions (docs/PROTOCOL.md §3.3, §11.12): a REACTION row on the sender's own lane, bound to its target row by a
// keyed `th`; per target, member and emoji the latest row in lane order decides, at most 8 on per member and target;
// sent like a text without an echo; a valid row everywhere a rule asks for one, but not a message.
import { describe, expect, it } from "vite-plus/test";
import type { Engine, MessageView } from "../src/types";
import { FROZEN_REMOVAL, YOU_LEFT_REFUSAL } from "../src/send";
import {
  I,
  P,
  buildMessage,
  chat,
  commitChange,
  conv,
  engineFor,
  epoch,
  freshWorldPerTest,
  makeUser,
  mustView,
  newEngine,
  postRow,
  selfRowsOf,
  server,
  settle,
  systemLines,
  waitFor,
  type TestUser,
} from "./harness";

freshWorldPerTest();

async function group(names: string[], name = "g") {
  const users = names.map((h) => makeUser(h));
  const engines: Engine[] = [];
  for (const u of users) engines.push(await engineFor(u));
  const id = await engines[0].createConversation(names.slice(1), name);
  await settle(...engines);
  for (const E of engines.slice(1)) await E.accept(id);
  await settle(...engines);
  return { users, engines, id };
}

/** A second device of `u`, signed in on its own transport (`who`). */
async function device(u: TestUser, who: string): Promise<Engine> {
  const e = newEngine(who);
  await I(e).unlock(u.AK, u.uid, u.handle);
  await waitFor(() => !e.getState().syncing, `${who} restore`);
  await settle(e);
  return e;
}

/** The message of `text` in the view of `e`. */
const msgOf = (e: Engine, id: string, text: string): MessageView =>
  mustView(e, id).messages.find((m) => m.text === text)!;
const reactionsOf = (e: Engine, id: string, text: string) =>
  msgOf(e, id, text).reactions.map((r) => [r.emoji, r.count, r.mine]);

/** A REACTION row of `from` on its lane of epoch `ep` at its next slot (an earlier client, or a forged target). */
function postReaction(from: TestUser, ep: ReturnType<typeof epoch>, reaction: P.Reaction): void {
  const j = P.memberIndex(ep.D, from.uid);
  const E = server().era;
  let n = 0;
  while (server().shard.hasLabel(E, P.Lmsg(ep.keys.rk, j, E, n))) n++;
  const prev = n > 0 ? P.Lmsg(ep.keys.rk, j, E, n - 1) : null;
  const body = prev ? server().shard.row(E, prev)!.body : null;
  const row = buildMessage(
    from,
    ep,
    { E, n, prev: prev && body ? { E, n: n - 1, label: prev, cls: 0, body } : undefined },
    { type: P.MT.REACTION, reaction } as P.MBody,
  );
  postRow(ep, row);
}

/** The target fields of the TEXT row `text` as `e` holds it (its epoch, lane, slot and keyed th). */
function targetOf(e: Engine, id: string, text: string): Omit<P.Reaction, "op" | "emoji"> {
  const key = msgOf(e, id, text).key;
  for (const ep of conv(e, id).epochs.values()) {
    const row = ep.rows.get(key);
    if (row) return { te: ep.e, tl: row.j, tE: row.E, tn: row.n, th: row.th };
  }
  throw new Error("no such row");
}

describe("reactions (§11.12)", () => {
  it("1. add and remove: counts, mine, siblings and reloads; no unread, no lastTs, no line", async () => {
    const {
      users: [alice, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    const B2 = await device(bob, "bob2");
    await A.sendText(id, "lunch?");
    await settle(A, B, B2);
    A.markRead(id);
    const lastA = mustView(A, id).lastTs;
    const lastB = mustView(B, id).lastTs;
    const lines = systemLines(A, id).length;
    const key = msgOf(B, id, "lunch?").key;
    await B.react(id, key, "👍", true);
    await settle(A, B, B2);
    expect(reactionsOf(B, id, "lunch?")).toEqual([["👍", 1, true]]);
    expect(reactionsOf(B2, id, "lunch?")).toEqual([["👍", 1, true]]);
    expect(reactionsOf(A, id, "lunch?")).toEqual([["👍", 1, false]]);
    expect(mustView(A, id).unread).toBe(0);
    expect([mustView(A, id).lastTs, mustView(B, id).lastTs]).toEqual([lastA, lastB]);
    expect(systemLines(A, id).length).toBe(lines);
    expect(chat(A, id)).toEqual(["alice: lunch?"]);
    const A2 = await engineFor(alice);
    expect(reactionsOf(A2, id, "lunch?")).toEqual([["👍", 1, false]]);
    await B2.react(id, key, "👍", false);
    await settle(A, A2, B, B2);
    for (const X of [A, A2, B, B2]) expect(reactionsOf(X, id, "lunch?")).toEqual([]);
  });

  it("2. siblings racing: every device shows the state of the later row in lane order", async () => {
    const {
      users: [alice, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    const B2 = await device(bob, "bob2");
    await A.sendText(id, "race");
    await settle(A, B, B2);
    const key = msgOf(B, id, "race").key;
    await Promise.all([B.react(id, key, "🎉", true), B2.react(id, key, "🎉", false)]);
    await B.react(id, key, "🎉", true);
    await settle(A, B, B2);
    const want = reactionsOf(B, id, "race");
    for (const X of [A, B2]) expect(reactionsOf(X, id, "race").map((x) => x.slice(0, 2))).toEqual(want.map((x) => x.slice(0, 2)));
    const B3 = await engineFor(bob);
    expect(reactionsOf(B3, id, "race")).toEqual(want);
    void alice;
  });

  it("3. at most 8 emoji per member and target; a remove frees a place", async () => {
    const {
      users: [, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    await A.sendText(id, "many");
    await settle(A, B);
    const key = msgOf(B, id, "many").key;
    const emoji = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣"];
    for (const e of emoji) await B.react(id, key, e, true);
    await settle(A, B);
    // the ninth: the engine sends nothing, and a row an earlier client sent anyway is ignored by everyone
    const rows = server().shard.rows().length;
    await B.react(id, key, "9️⃣", true);
    expect(server().shard.rows().length).toBe(rows);
    postReaction(bob, epoch(A, id), { ...targetOf(B, id, "many"), op: 1, emoji: "9️⃣" });
    await settle(A, B);
    for (const X of [A, B]) expect(reactionsOf(X, id, "many").length).toBe(8);
    await B.react(id, key, "1️⃣", false);
    postReaction(bob, epoch(A, id), { ...targetOf(B, id, "many"), op: 1, emoji: "9️⃣" });
    await settle(A, B);
    for (const X of [A, B]) {
      const on = reactionsOf(X, id, "many").map((x) => x[0]);
      expect(on).toContain("9️⃣");
      expect(on).not.toContain("1️⃣");
    }
  });

  it("4. a REACTION whose target does not check reacts to nothing, without a warning", async () => {
    const {
      users: [alice, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    await A.sendText(id, "target");
    await settle(A, B);
    const ep = epoch(A, id);
    const t = targetOf(A, id, "target");
    const label = P.Lmsg(ep.keys.rk, t.tl, t.tE, t.tn);
    const body = server().shard.row(t.tE, label)!.body;
    const unkeyed = P.prevh(label, body).slice(0, 16); // any other 16 bytes
    const bad: P.Reaction[] = [
      { ...t, th: P.random(16), op: 1, emoji: "a" },
      { ...t, th: unkeyed, op: 1, emoji: "b" },
      { ...t, tl: ep.D.members.length, op: 1, emoji: "c" },
      { ...t, te: t.te + 1, op: 1, emoji: "d" },
      { ...t, tn: t.tn + 5, op: 1, emoji: "e" },
    ];
    for (const r of bad) postReaction(bob, ep, r);
    await settle(A, B);
    for (const X of [A, B]) {
      expect(reactionsOf(X, id, "target")).toEqual([]);
      expect(X.getState().warnings).toEqual([]);
    }
    void alice;
  });

  it("6. a target in an epoch the copy does not hold never takes effect", async () => {
    const {
      users: [alice, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    await A.sendText(id, "before dave");
    await settle(A, B);
    const dave = makeUser("dave");
    const D = await engineFor(dave);
    await A.addMembers(id, ["dave"]);
    await settle(A, B, D);
    await D.accept(id);
    await settle(A, B, D);
    await A.react(id, msgOf(A, id, "before dave").key, "👀", true); // a REACTION of epoch 1 to a TEXT of epoch 0
    await settle(A, B, D);
    expect(reactionsOf(B, id, "before dave")).toEqual([["👀", 1, false]]);
    expect(mustView(D, id).messages.every((m) => m.reactions.length === 0)).toBe(true);
    void [alice, bob];
  });

  it("8. refused where a text is: frozen with a removal, after self's leave; a rotation first after a leave", async () => {
    const {
      users: [alice, , carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    await A.sendText(id, "hello");
    await settle(A, B, C);
    // after carol's LEAVE, bob's REACTION commits a rotation first
    await C.leave(id);
    await settle(A, B, C);
    const e0 = mustView(B, id).epoch;
    await B.react(id, msgOf(B, id, "hello").key, "👋", true);
    await settle(A, B, C);
    expect(mustView(B, id).epoch).toBe(e0 + 1);
    expect(reactionsOf(A, id, "hello")).toEqual([["👋", 1, false]]);
    // after self's leave: refused
    await B.leave(id);
    await settle(A, B, C);
    await expect(B.react(id, msgOf(B, id, "hello").key, "😀", true)).rejects.toThrow(YOU_LEFT_REFUSAL);
    void [alice, carol];
  });

  it("8. frozen with a removal: refused as a text is", async () => {
    const {
      users: [alice, bob, , mallory],
      engines: [A, B, C, M],
      id,
    } = await group(["alice", "bob", "carol", "mallory"]);
    await A.sendText(id, "hello");
    await settle(A, B, C, M);
    const ep = epoch(A, id);
    // mallory's claim removes carol and is D′-invalid: everyone is frozen with a removal
    await commitChange(mallory, ep, [alice, bob, mallory], undefined, {
      patchBlob: (blob) => {
        const out = blob.slice();
        out.set(P.random(64), P.SGB2_HEADER_LEN);
        return out;
      },
    });
    await settle(A, B, C, M);
    expect(mustView(B, id).blocked).toBe("frozen");
    await expect(B.react(id, msgOf(B, id, "hello").key, "😀", true)).rejects.toThrow(FROZEN_REMOVAL);
  });

  it("9. a valid row: it ends a followed lane, confirms, accepts a request, and makes a 1:1 a WELCOME channel", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    // carol, a stranger to bob, starts a group: bob holds a request, which alice's REACTION accepts and confirms
    const id = await C.createConversation(["alice", "bob"], "g");
    await settle(A, B, C);
    await A.accept(id);
    await C.sendText(id, "first");
    await settle(A, B, C);
    expect(mustView(B, id).request).toBe(true);
    await A.react(id, msgOf(A, id, "first").key, "👍", true);
    await settle(A, B, C);
    expect(mustView(B, id).request).toBe(false);
    expect(conv(B, id).confirmed).toBe(true);
    const recs = selfRowsOf(bob).flat();
    expect(recs.some((r) => r.rtype === P.RT.CONV_JOIN && r.via === P.VIA.REQUEST_ACCEPTED)).toBe(true);
    // CONFIRMED and the via-5 CONV_JOIN ride in a row with a HEADS record (§7.3)
    const acc = selfRowsOf(bob).find((rs) => rs.some((r) => r.rtype === P.RT.CONV_JOIN && r.via === P.VIA.REQUEST_ACCEPTED))!;
    expect(acc.map((r) => r.rtype)).toEqual([P.RT.CONFIRMED, P.RT.CONV_JOIN, P.RT.HEADS]);
    // a third member's row accepts it, but only the user's own act makes carol a contact (§11.5)
    expect(recs.some((r) => r.rtype === P.RT.CONTACT && P.equalBytes(r.uid, carol.uid))).toBe(false);
    expect(mustView(B, id).byContact).toBe(false);
    // bob's own REACTION is the user's acceptance: the CONTACT at once, in a row with a HEADS record, before its put
    await B.react(id, msgOf(B, id, "first").key, "🙂", true);
    const rows = selfRowsOf(bob);
    const row = rows.find((rs) => rs.some((r) => r.rtype === P.RT.CONTACT && P.equalBytes(r.uid, carol.uid)))!;
    expect(row.some((r) => r.rtype === P.RT.HEADS)).toBe(true);
    expect(mustView(B, id).byContact).toBe(true);
    await settle(A, B, C);
    expect(reactionsOf(C, id, "first")).toEqual([
      ["👍", 1, false],
      ["🙂", 1, false],
    ]);
  });

  it("10. the initial history counts REACTION rows: a current epoch of 20 TEXT and 15 REACTION rows loads nothing older", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    for (let i = 0; i < 5; i++) await A.sendText(id, `old ${i}`);
    await settle(A, B, C);
    await commitChange(alice, epoch(A, id), [alice, bob, carol], "e1");
    await settle(A, B, C);
    for (let i = 0; i < 20; i++) await A.sendText(id, `new ${i}`);
    await settle(A, B, C);
    // 20 rows: fewer than 30, so a reload also shows the end of the previous epoch
    const C1 = await engineFor(carol);
    expect(chat(C1, id).filter((t) => t.includes("old ")).length).toBeGreaterThan(0);
    await C1.logout();
    const keys = mustView(B, id).messages.filter((m) => m.text?.startsWith("new ")).map((m) => m.key);
    const emoji = ["a", "b", "c", "d", "e", "f", "g", "h"];
    for (let i = 0; i < 15; i++) await B.react(id, keys[i % keys.length], emoji[i % 8], true);
    await settle(A, B, C);
    const C2 = await engineFor(carol);
    expect(chat(C2, id).filter((t) => t.includes("old "))).toEqual([]);
  });
});

describe("accept and contacts (§11.5, §11.11)", () => {
  it("markRead accepts nothing; accept writes the request's acceptance and the CONTACT at once, with HEADS", async () => {
    const [bob, carol] = ["bob", "carol"].map((h) => makeUser(h));
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const id = await C.createConversation(["bob"]);
    await settle(B, C);
    expect(mustView(B, id).request).toBe(true);
    expect(mustView(B, id).byContact).toBe(false);
    const before = selfRowsOf(bob).length;
    B.markRead(id);
    await settle(B, C);
    expect(mustView(B, id).request).toBe(true);
    expect(selfRowsOf(bob).slice(before).flat().some((r) => r.rtype === P.RT.CONTACT)).toBe(false);
    await B.accept(id);
    const row = selfRowsOf(bob)
      .slice(before)
      .find((rs) => rs.some((r) => r.rtype === P.RT.CONTACT))!;
    expect(row.map((r) => r.rtype)).toEqual([P.RT.CONV_JOIN, P.RT.CONTACT, P.RT.HEADS]);
    expect(mustView(B, id).request).toBe(false);
    expect(mustView(B, id).byContact).toBe(true);
    await B.accept(id); // nothing more
    expect(selfRowsOf(bob).slice(before).flat().filter((r) => r.rtype === P.RT.CONTACT)).toHaveLength(1);
  });

  it("a post in a copy whose inviter has no MEMBER fails before its put when the lookup fails", async () => {
    const [bob, carol] = ["bob", "carol"].map((h) => makeUser(h));
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const id = await C.createConversation(["bob"]);
    await settle(B, C);
    // bob's MEMBER of carol is in the fold (a request's row carries it), so accepting needs no lookup
    expect(I(B).self!.fold.members.has(carol.uidB)).toBe(true);
    await B.sendText(id, "hi");
    await settle(B, C);
    expect(mustView(B, id).byContact).toBe(true);
    expect(chat(C, id)).toEqual(["bob: hi"]);
  });
});
