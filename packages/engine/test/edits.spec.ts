// Edits (docs/PROTOCOL.md §3.3, §11.18): an EDIT row on the sender's own lane carries a whole new text for one of the
// sender's own TEXT rows (or REPLY rows carrying a text), named as a REACTION names its target (`th`). The original row
// never changes; per target the latest counting EDIT in lane order decides the text shown (never `ts`). Sent like a
// text without an echo; a valid row everywhere a rule asks for one, but not a message.
import { describe, expect, it, vi } from "vite-plus/test";
import type { Epoch } from "../src/conv";
import {
  DEFAULT_WINDOW_MS,
  type LocalNotification,
  type LocalNotifier,
  type LocalPermission,
} from "../src/local-notify";
import { FROZEN_REMOVAL, YOU_LEFT_REFUSAL } from "../src/send";
import type { Engine, MessageView } from "../src/types";
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
  readableWith,
  server,
  settle,
  systemLines,
  waitFor,
  type BuiltRow,
  type TestUser,
} from "./harness";

// The canvas re-encoder needs a DOM: a pass-through, as in images.spec.ts.
vi.mock("../src/image", () => ({
  prepareImage: async (file: Blob) => ({
    bytes: new Uint8Array(await file.arrayBuffer()),
    mime: "image/webp" as const,
    w: 4,
    h: 3,
  }),
}));

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

/** The key of the message `text` in the view of `e` (only before it is edited: an edit changes the text). */
function keyOf(e: Engine, id: string, text: string): string {
  const m = mustView(e, id).messages.find((x) => x.text === text);
  if (!m) throw new Error(`no message ${text}`);
  return m.key;
}

/** The message `key` in the view of `e`. */
function msg(e: Engine, id: string, key: string): MessageView {
  const m = mustView(e, id).messages.find((x) => x.key === key);
  if (!m) throw new Error(`no message ${key}`);
  return m;
}

/** The text and the edits of the message `key` in the view of `e`. */
const shown = (e: Engine, id: string, key: string) => {
  const m = msg(e, id, key);
  return { text: m.text, edited: m.edited };
};

const texts = (e: Engine, id: string, key: string) => e.editHistory(id, key).map((v) => v.text);

/** The target fields of the message `key` as `e` holds it (its epoch, lane, slot and keyed th). */
function targetOf(e: Engine, id: string, key: string): P.ReplyTo {
  for (const ep of conv(e, id).epochs.values()) {
    const row = ep.rows.get(key);
    if (row) return { te: ep.e, tl: row.j, tE: row.E, tn: row.n, th: row.th };
  }
  throw new Error("no such row");
}

/** The target fields that name the stored row at (E, n) on lane j of `ep`, whatever its type (`th` keyed over it). */
function slotTarget(ep: Epoch, j: number, E: number, n: number): P.ReplyTo {
  const label = P.Lmsg(ep.keys.rk, j, E, n);
  const body = server().shard.row(E, label)!.body;
  return { te: ep.e, tl: j, tE: E, tn: n, th: P.reactTh(ep.keys.rk, label, body) };
}

/** A row of `from` on its lane of epoch `ep` at its next slot (an earlier client, or a forged row). */
function postAt(
  from: TestUser,
  ep: Epoch,
  content: P.MBody & Partial<P.MHeader>,
): BuiltRow & { n: number } {
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
    content,
  );
  postRow(ep, row);
  return { ...row, n };
}

/** The stored rows of lane j of `ep` in the current era, parsed, in slot order. */
function laneRows(ep: Epoch, j: number): P.Msg[] {
  const E = server().era;
  const out: P.Msg[] = [];
  for (let n = 0; ; n++) {
    const label = P.Lmsg(ep.keys.rk, j, E, n);
    const row = server().shard.row(E, label);
    if (!row) return out;
    const v = P.acceptRow(
      { keys: ep.keys, conv: ep.D.conv, e: ep.e, members: ep.D.members },
      E,
      label,
      row.body,
    );
    if (!v.ok) throw new Error(`junk at ${n}`);
    out.push(v.msg);
  }
}

/** The system's notifications of an app without push, permission granted (local-notify.test.ts). */
class FakeNotifier implements LocalNotifier {
  shown: LocalNotification[] = [];
  permission = async (): Promise<LocalPermission> => "granted";
  requestPermission = async (): Promise<LocalPermission> => "granted";
  show = (n: LocalNotification) => void this.shown.push(n);
  close = () => {};
  closeAll = () => {};
  badge = () => {};
}

/** The texts of the EDIT rows `e` holds, in lane order (by epoch, then (E, n)). */
const editsInLaneOrder = (e: Engine, id: string): string[] =>
  [...conv(e, id).edits.values()]
    .sort((a, b) => a.e - b.e || a.E - b.E || a.n - b.n)
    .map((r) => r.text);

describe("edits (§11.18)", () => {
  it("1. an edit shows on every device and after a reload; it is not a message and changes no row (§11.18 State, Display, Not a message)", async () => {
    const {
      users: [alice, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    const A2 = await device(alice, "alice2");
    await A.sendText(id, "lunch at noon?");
    await B.sendText(id, "sure");
    await settle(A, A2, B);
    B.markRead(id);
    A.markRead(id);
    await settle(A, A2, B);
    const key = keyOf(A, id, "lunch at noon?");
    const sentTs = msg(B, id, key).ts;
    const at = mustView(B, id).messages.findIndex((m) => m.key === key);
    const lastA = mustView(A, id).lastTs;
    const lastB = mustView(B, id).lastTs;
    const lines = systemLines(B, id).length;
    const rows = readableWith(epoch(A, id).keys.mk).length;

    const sending = A.editText(id, key, "lunch at one?");
    // the sender shows the new text at once, marked as being sent (§11.18 "Sending", informative)
    const now = msg(A, id, key);
    expect(now.text).toBe("lunch at one?");
    expect(now.edited).toMatchObject({ count: 0, sending: true });
    expect(typeof now.edited?.ts).toBe("number");
    await sending;
    expect(A.getState().error).toBe("");
    expect(msg(A, id, key).edited).toMatchObject({ count: 1, sending: false });
    await settle(A, A2, B);

    for (const X of [A, A2, B]) {
      const m = msg(X, id, key);
      expect(m.text).toBe("lunch at one?");
      expect(m.edited).toMatchObject({ count: 1, sending: false });
      expect(m.edited!.ts).toBeGreaterThanOrEqual(sentTs);
      expect(m.ts).toBe(sentTs);
      expect(X.editHistory(id, key)).toEqual([
        { text: "lunch at noon?", ts: sentTs },
        { text: "lunch at one?", ts: m.edited!.ts },
      ]);
    }
    expect(msg(A2, id, key).edited).toEqual(msg(B, id, key).edited);
    expect(msg(A, id, key).edited).toEqual(msg(B, id, key).edited);
    // not a message: no unread, no lastTs, no system line; the message keeps its key and place
    expect(mustView(B, id).unread).toBe(0);
    expect([mustView(A, id).lastTs, mustView(B, id).lastTs]).toEqual([lastA, lastB]);
    expect(systemLines(B, id).length).toBe(lines);
    expect(mustView(B, id).messages.findIndex((m) => m.key === key)).toBe(at);
    expect(chat(B, id)).toEqual(["alice: lunch at one?", "bob: sure"]);
    // one EDIT row was stored, naming the original row, which is unchanged (§12.1)
    const stored = readableWith(epoch(A, id).keys.mk);
    expect(stored.length).toBe(rows + 1);
    expect(stored.filter((m) => m.type === P.MT.EDIT)).toHaveLength(1);
    const edits = [...conv(B, id).edits.values()];
    expect(edits).toHaveLength(1);
    const ep = conv(B, id).epochs.get(edits[0].e)!;
    const label = P.Lmsg(ep.keys.rk, edits[0].j, edits[0].E, edits[0].n);
    const v = P.acceptRow(
      { keys: ep.keys, conv: ep.D.conv, e: ep.e, members: ep.D.members },
      edits[0].E,
      label,
      server().shard.row(edits[0].E, label)!.body,
    );
    expect(v.ok && v.msg.type).toBe(P.MT.EDIT);
    const t = targetOf(B, id, key);
    expect(v.ok && v.msg.type === P.MT.EDIT && v.msg.to).toEqual(t);
    expect(v.ok && v.msg.type === P.MT.EDIT && v.msg.text).toBe("lunch at one?");
    const orig = P.acceptRow(
      { keys: ep.keys, conv: ep.D.conv, e: ep.e, members: ep.D.members },
      t.tE,
      P.Lmsg(ep.keys.rk, t.tl, t.tE, t.tn),
      server().shard.row(t.tE, P.Lmsg(ep.keys.rk, t.tl, t.tE, t.tn))!.body,
    );
    expect(orig.ok && orig.msg.type === P.MT.TEXT && orig.msg.text).toBe("lunch at noon?");
    // a reload of each rebuilds the same state from the server
    const A3 = await engineFor(alice);
    const B3 = await engineFor(bob);
    for (const X of [A3, B3]) {
      expect(shown(X, id, key)).toEqual(shown(B, id, key));
      expect(texts(X, id, key)).toEqual(["lunch at noon?", "lunch at one?"]);
      expect(msg(X, id, key).key).toBe(key);
    }
    expect(mustView(B3, id).messages.filter((m) => m.kind !== "system")).toHaveLength(2);
    for (const X of [A, A2, B, A3, B3]) expect(X.getState().warnings).toEqual([]);
  });

  it("2. several edits: the latest in lane order decides, also when two devices race, and never by ts (§11.18 State, Agreement)", async () => {
    const {
      users: [alice, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    const A2 = await device(alice, "alice2");
    await A.sendText(id, "v1");
    await settle(A, A2, B);
    const key = keyOf(A, id, "v1");
    await A.editText(id, key, "v2");
    await A.editText(id, key, "v3");
    await settle(A, A2, B);
    for (const X of [A, A2, B]) {
      expect(shown(X, id, key)).toMatchObject({ text: "v3", edited: { count: 2, sending: false } });
      expect(texts(X, id, key)).toEqual(["v1", "v2", "v3"]);
    }
    // the second device edits from v3 too
    await A2.editText(id, key, "v4");
    await settle(A, A2, B);
    expect(shown(A, id, key)).toMatchObject({ text: "v4", edited: { count: 3 } });
    // two devices of alice racing: both rows are stored on the shared lane, the later one decides everywhere
    await Promise.all([A.editText(id, key, "from A"), A2.editText(id, key, "from A2")]);
    await settle(A, A2, B);
    const order = editsInLaneOrder(B, id);
    expect(order.slice(0, 3)).toEqual(["v2", "v3", "v4"]);
    expect(new Set(order.slice(3))).toEqual(new Set(["from A", "from A2"]));
    for (const X of [A, A2, B]) {
      expect(editsInLaneOrder(X, id)).toEqual(order);
      expect(shown(X, id, key)).toMatchObject({
        text: order.at(-1),
        edited: { count: 5, sending: false },
      });
      expect(texts(X, id, key)).toEqual(["v1", ...order]);
    }
    // a later row with an earlier ts still decides: lane order, never ts
    const ep = epoch(A, id);
    const before = msg(B, id, key).edited!.ts;
    postAt(alice, ep, {
      type: P.MT.EDIT,
      to: targetOf(A, id, key),
      text: "slow clock",
      ts: server().now() - 60_000,
    });
    await settle(A, A2, B);
    for (const X of [A, A2, B]) {
      const m = msg(X, id, key);
      expect(m.text).toBe("slow clock");
      expect(m.edited!.count).toBe(6);
      expect(m.edited!.ts).toBeLessThan(before);
      expect(X.editHistory(id, key).at(-1)).toEqual({ text: "slow clock", ts: m.edited!.ts });
    }
    const B2 = await engineFor(bob);
    expect(shown(B2, id, key)).toEqual(shown(B, id, key));
    expect(B2.editHistory(id, key)).toEqual(B.editHistory(id, key));
    for (const X of [A, A2, B, B2]) expect(X.getState().warnings).toEqual([]);
  });

  it("3. an edited reply keeps its target; replies and reactions name the original row and survive an edit (§11.18 Display, §11.17, §11.12)", async () => {
    const {
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    await A.sendText(id, "lunch?");
    await settle(A, B, C);
    const lunch = keyOf(A, id, "lunch?");
    await B.sendText(id, "ramen?", lunch);
    await B.react(id, lunch, "👍", true);
    await settle(A, B, C);
    const ramen = keyOf(B, id, "ramen?");
    // alice edits the message bob replied and reacted to
    await A.editText(id, lunch, "dinner?");
    await settle(A, B, C);
    // bob edits his reply, a REPLY carrying a text
    await B.editText(id, ramen, "sushi?");
    await settle(A, B, C);
    // carol replies to the edited message, after the edit
    await C.sendText(id, "yes!", lunch);
    await settle(A, B, C);
    const yes = keyOf(C, id, "yes!");
    for (const X of [A, B, C]) {
      expect(shown(X, id, lunch)).toMatchObject({ text: "dinner?", edited: { count: 1 } });
      expect(msg(X, id, lunch).reactions.map((r) => [r.emoji, r.count])).toEqual([["👍", 1]]);
      expect(shown(X, id, ramen)).toMatchObject({ text: "sushi?", edited: { count: 1 } });
      expect(msg(X, id, ramen).reply).toEqual({ key: lunch, state: "shown" });
      expect(msg(X, id, ramen).kind).toBe("text");
      expect(texts(X, id, ramen)).toEqual(["ramen?", "sushi?"]);
      // the reply sent after the edit names the original key; its quote shows the current text
      expect(msg(X, id, yes).reply).toEqual({ key: lunch, state: "shown" });
      expect(msg(X, id, msg(X, id, yes).reply!.key).text).toBe("dinner?");
      expect(msg(X, id, yes).edited).toBeUndefined();
    }
    // a reaction after the edit still reacts to the original row
    await C.react(id, lunch, "🍣", true);
    await settle(A, B, C);
    expect(
      msg(A, id, lunch)
        .reactions.map((r) => r.emoji)
        .sort(),
    ).toEqual(["👍", "🍣"].sort());
    expect(chat(A, id)).toEqual(["alice: dinner?", "bob: sushi?", "carol: yes!"]);
  });

  it("4. an EDIT that names no editable row of its sender edits nothing, without a warning (§11.18 Target)", async () => {
    const {
      users: [alice, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    await A.sendText(id, "target");
    await A.sendImage(
      id,
      new File([P.utf8("RIFF....WEBPVP8 bowl") as BlobPart], "p.webp", { type: "image/webp" }),
    );
    await A.sendFile(id, new File([P.utf8("menu") as BlobPart], "menu.txt"));
    await settle(A, B);
    const target = keyOf(A, id, "target");
    await A.sendFile(id, new File([P.utf8("map") as BlobPart], "map.txt"), target);
    await A.react(id, target, "👀", true);
    await A.editText(id, target, "edited once");
    await settle(A, B);
    const ep = epoch(A, id);
    const msgs = mustView(A, id).messages;
    const image = msgs.find((m) => m.kind === "image")!.key;
    const file = msgs.find((m) => m.file?.name === "menu.txt")!.key;
    const fileReply = msgs.find((m) => m.file?.name === "map.txt")!.key;
    const t = targetOf(A, id, target);
    expect(slotTarget(ep, t.tl, t.tE, t.tn)).toEqual(t); // the helper names rows as the engine does
    const label = P.Lmsg(ep.keys.rk, t.tl, t.tE, t.tn);
    const unkeyed = P.prevh(label, server().shard.row(t.tE, label)!.body).slice(0, 16);
    const reaction = [...conv(A, id).reactions.values()][0];
    const edit = [...conv(A, id).edits.values()][0];
    const cases: [P.ReplyTo, string][] = [
      [{ ...t, th: P.random(16) }, "bad th"],
      [{ ...t, th: unkeyed }, "unkeyed th"],
      [{ ...t, tl: ep.D.members.length }, "bad lane"],
      [{ ...t, te: t.te + 1 }, "later epoch"],
      [targetOf(A, id, image), "an image"],
      [targetOf(A, id, file), "a file"],
      [targetOf(A, id, fileReply), "a reply carrying a file"],
      [slotTarget(ep, reaction.j, reaction.E, reaction.n), "a reaction"],
      [slotTarget(ep, edit.j, edit.E, edit.n), "an edit"],
      [{ ...t, tn: t.tn + 100 }, "not loaded"],
    ];
    for (const [to, text] of cases) postAt(alice, ep, { type: P.MT.EDIT, to, text });
    // bob's EDIT of alice's message, with a th that checks: only the sender edits its own rows
    postAt(bob, ep, { type: P.MT.EDIT, to: t, text: "bob's edit" });
    await settle(A, B);
    for (const X of [A, B]) {
      // every forged row was read as a valid EDIT row, and none counts
      expect(conv(X, id).edits.size).toBe(cases.length + 2);
      expect(shown(X, id, target)).toMatchObject({
        text: "edited once",
        edited: { count: 1, sending: false },
      });
      expect(texts(X, id, target)).toEqual(["target", "edited once"]);
      for (const k of [image, file, fileReply]) {
        expect(msg(X, id, k).edited).toBeUndefined();
        expect(X.editHistory(id, k)).toEqual([]);
      }
      expect(msg(X, id, fileReply).reply).toEqual({ key: target, state: "shown" });
      expect(msg(X, id, target).reactions.map((r) => r.emoji)).toEqual(["👀"]);
      expect(X.getState().warnings).toEqual([]);
    }
    expect(chat(B, id)).toEqual([
      "alice: edited once",
      "alice: [image]",
      "alice: [file menu.txt]",
      "alice: [file map.txt]",
    ]);
  });

  it("5. a target in an epoch the copy does not hold never takes effect (§11.18 Target, §11.12)", async () => {
    const {
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    await A.sendText(id, "before dave");
    await settle(A, B);
    const key = keyOf(A, id, "before dave");
    const D = await engineFor(makeUser("dave"));
    await A.addMembers(id, ["dave"]);
    await settle(A, B, D);
    await D.accept(id);
    await settle(A, B, D);
    // an EDIT of epoch 1 naming a TEXT of epoch 0
    await A.editText(id, key, "edited after dave joined");
    await settle(A, B, D);
    expect(shown(B, id, key)).toMatchObject({
      text: "edited after dave joined",
      edited: { count: 1 },
    });
    expect(conv(D, id).edits.size).toBe(1);
    expect(mustView(D, id).messages.every((m) => !m.edited)).toBe(true);
    expect(chat(D, id)).toEqual([]);
    expect(D.editHistory(id, key)).toEqual([]);
    expect(D.getState().warnings).toEqual([]);
  });

  it("6. an EDIT whose target is older than the initial history waits, and takes effect once scrollback loads it (§11.18 Not a message, §11.4)", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(["bob"]);
    await settle(A, B);
    await A.sendText(id, "old one");
    for (let i = 0; i < 40; i++) await A.sendText(id, `m ${i}`);
    await settle(A, B);
    const key = keyOf(A, id, "old one");
    await A.editText(id, key, "old one, edited");
    await settle(A, B);
    expect(shown(B, id, key)).toMatchObject({ text: "old one, edited", edited: { count: 1 } });
    const B2 = await engineFor(bob);
    expect(mustView(B2, id).messages.some((m) => m.key === key)).toBe(false);
    expect(conv(B2, id).edits.size).toBe(1);
    expect(mustView(B2, id).messages.every((m) => !m.edited)).toBe(true);
    B2.markRead(id);
    await settle(B2);
    expect(shown(B2, id, key)).toMatchObject({
      text: "old one, edited",
      edited: { count: 1, sending: false },
    });
    expect(texts(B2, id, key)).toEqual(["old one", "old one, edited"]);
    expect(B2.getState().warnings).toEqual([]);
  });

  it("7. editText refuses what cannot be edited and sends nothing for an unchanged text (§11.18 Sending)", async () => {
    const {
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    await A.sendText(id, "hello");
    await A.sendImage(
      id,
      new File([P.utf8("RIFF....WEBPVP8 bowl") as BlobPart], "p.webp", { type: "image/webp" }),
    );
    await A.sendFile(id, new File([P.utf8("menu") as BlobPart], "menu.txt"));
    await settle(A, B);
    const key = keyOf(A, id, "hello");
    const msgs = mustView(A, id).messages;
    const image = msgs.find((m) => m.kind === "image")!.key;
    const file = msgs.find((m) => m.kind === "file")!.key;
    const rows = server().shard.rows().length;
    const refused: [Engine, string, string, string][] = [
      [A, "0:00", "x", "unknown message"],
      [B, key, "bob's words", "this message cannot be edited"],
      [A, image, "x", "this message cannot be edited"],
      [A, file, "x", "this message cannot be edited"],
      [A, key, "", "an edit cannot be empty"],
      [A, key, "  \n ", "an edit cannot be empty"],
      [A, key, "a".repeat(12_001), "message is too long"],
      [A, key, "é".repeat(6_001), "message is too long"],
    ];
    for (const [X, k, text, error] of refused) {
      await expect(X.editText(id, k, text)).rejects.toThrow(error);
      expect(X.getState().error).toBe(error);
    }
    expect(server().shard.rows().length).toBe(rows);
    expect(shown(A, id, key)).toEqual({ text: "hello", edited: undefined });
    // 12000 bytes is not too long
    await A.editText(id, key, "a".repeat(12_000));
    expect(server().shard.rows().length).toBe(rows + 1);
    await A.editText(id, key, "hello again");
    await settle(A, B);
    const stored = readableWith(epoch(A, id).keys.mk).length;
    // an unchanged text (trailing white space aside) resolves without a row
    await A.editText(id, key, "hello again");
    await A.editText(id, key, "hello again \n");
    expect(readableWith(epoch(A, id).keys.mk).length).toBe(stored);
    expect(shown(A, id, key)).toMatchObject({ text: "hello again", edited: { count: 2 } });
    // back to the original text is a change
    await A.editText(id, key, "hello");
    await settle(A, B);
    expect(readableWith(epoch(A, id).keys.mk).length).toBe(stored + 1);
    expect(shown(B, id, key)).toMatchObject({ text: "hello", edited: { count: 3 } });
    expect(texts(B, id, key)).toEqual(["hello", "a".repeat(12_000), "hello again", "hello"]);
    // an echo not sent yet cannot be edited
    const sending = A.sendText(id, "on its way");
    const echo = mustView(A, id).messages.find((m) => m.text === "on its way")!;
    expect(echo.key.startsWith("local:")).toBe(true);
    await expect(A.editText(id, echo.key, "changed")).rejects.toThrow(
      "this message cannot be edited",
    );
    await sending;
    await settle(A, B);
    expect(chat(B, id).at(-1)).toBe("alice: on its way");
  });

  it("8. refused where a text is: a rotation first after a member's leave, refused after self's leave (§11.18 Sending, §11.3 steps 2–3)", async () => {
    const {
      users: [, , carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    await A.sendText(id, "hello");
    await settle(A, B, C);
    const key = keyOf(A, id, "hello");
    // after carol's LEAVE, alice's EDIT commits a rotation first
    await C.leave(id);
    await settle(A, B, C);
    const e0 = mustView(A, id).epoch;
    await A.editText(id, key, "hello, two of us");
    await settle(A, B, C);
    expect(mustView(A, id).epoch).toBe(e0 + 1);
    expect(mustView(B, id).epoch).toBe(e0 + 1);
    expect(shown(B, id, key)).toMatchObject({ text: "hello, two of us", edited: { count: 1 } });
    const edit = [...conv(B, id).edits.values()][0];
    expect(edit.e).toBe(e0 + 1);
    expect(edit.to.te).toBe(e0);
    // after self's leave: refused, nothing stored, the text stays
    await A.leave(id);
    await settle(A, B, C);
    const rows = server().shard.rows().length;
    await expect(A.editText(id, key, "after leaving")).rejects.toThrow(YOU_LEFT_REFUSAL);
    expect(server().shard.rows().length).toBe(rows);
    await settle(A, B);
    expect(msg(A, id, key).text).toBe("hello, two of us");
    expect(msg(B, id, key).text).toBe("hello, two of us");
    void carol;
  });

  it("9. frozen with a removal: refused as a text is (§11.18 Sending, §6.6 step 6)", async () => {
    const {
      users: [alice, bob, , mallory],
      engines: [A, B, C, M],
      id,
    } = await group(["alice", "bob", "carol", "mallory"]);
    await A.sendText(id, "hello");
    await settle(A, B, C, M);
    const key = keyOf(A, id, "hello");
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
    expect(mustView(A, id).blocked).toBe("frozen");
    const rows = server().shard.rows().length;
    await expect(A.editText(id, key, "hello?")).rejects.toThrow(FROZEN_REMOVAL);
    expect(server().shard.rows().length).toBe(rows);
    expect(shown(A, id, key)).toEqual({ text: "hello", edited: undefined });
  });

  it("10. a send that fails shows the current text again (§11.18 Sending, §11.3 step 7)", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    await A.sendText(id, "one");
    await A.sendText(id, "two");
    await settle(A, B, C);
    const one = keyOf(A, id, "one");
    const two = keyOf(A, id, "two");
    await A.editText(id, one, "one, edited");
    await settle(A, B, C);
    const ep0 = epoch(A, id);
    // carol's claim removes alice; it lands while alice's next put is held (sendstatus.spec.ts)
    const r = await commitChange(carol, ep0, [bob, carol], undefined, { noPost: true });
    await settle(A, B, C);
    let armed = true;
    server().hooks.beforePut = async (rows, who) => {
      if (!armed || who !== "alice" || !rows.some((x) => P.equalBytes(x.topic, ep0.topic))) return;
      armed = false;
      postRow(ep0, r.claim);
      await waitFor(() => conv(A, id).removed, "alice removed");
    };
    const failTwo = A.editText(id, two, "two, edited");
    const failOne = A.editText(id, one, "one, edited again");
    // both show at once while their sends run
    expect(shown(A, id, two)).toMatchObject({
      text: "two, edited",
      edited: { count: 0, sending: true },
    });
    expect(shown(A, id, one)).toMatchObject({
      text: "one, edited again",
      edited: { count: 1, sending: true },
    });
    await expect(failTwo).rejects.toThrow(/not delivered/);
    // the next edit in the chain finds alice removed and is refused before its put (§11.3 step 2)
    await expect(failOne).rejects.toThrow(/no longer a member/);
    server().hooks.beforePut = undefined;
    // the current text again: the original where no edit counts, else the latest edit that counts
    expect(shown(A, id, two)).toEqual({ text: "two", edited: undefined });
    expect(shown(A, id, one)).toMatchObject({
      text: "one, edited",
      edited: { count: 1, sending: false },
    });
    expect(A.editHistory(id, two)).toEqual([]);
    await settle(A, B, C);
    for (const X of [A, B, C]) {
      expect(shown(X, id, two)).toEqual({ text: "two", edited: undefined });
      expect(shown(X, id, one)).toMatchObject({ text: "one, edited", edited: { count: 1 } });
      expect(texts(X, id, one)).toEqual(["one", "one, edited"]);
    }
    void alice;
  });

  it("11. an EDIT that a later final claim makes §6.8 drop counts for nothing: the text reverts (§11.18 State, §6.8)", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    await A.sendText(id, "kept");
    await settle(A, B, C);
    const key = keyOf(A, id, "kept");
    await A.editText(id, key, "kept, edited");
    await settle(A, B, C);
    const ep = epoch(A, id);
    // carol's claim removes alice; bob does not see it yet (claims.spec.ts "low cuts never hide …")
    const r = await commitChange(carol, ep, [bob, carol], undefined, { hideFrom: ["bob"] });
    // alice's EDIT stored after the claim: bob counts it before he sees the claim
    server().tick(1001);
    postAt(alice, ep, { type: P.MT.EDIT, to: targetOf(B, id, key), text: "after the claim" });
    await I(B).catchUp();
    expect(shown(B, id, key)).toMatchObject({
      text: "after the claim",
      edited: { count: 2, sending: false },
    });
    server().shard.unhide(r.claim.E, r.claim.label);
    await settle(A, B, C);
    for (const X of [B, C]) {
      expect(mustView(X, id).epoch).toBe(1);
      expect(shown(X, id, key)).toMatchObject({
        text: "kept, edited",
        edited: { count: 1, sending: false },
      });
      expect(texts(X, id, key)).toEqual(["kept", "kept, edited"]);
      expect(chat(X, id)).toEqual(["alice: kept, edited"]);
    }
    const B2 = await engineFor(bob);
    expect(shown(B2, id, key)).toMatchObject({ text: "kept, edited", edited: { count: 1 } });
    void alice;
  });

  it("12. a valid row of its member: the next text after an EDIT is accepted, its prev names the EDIT (§11.18 Not a message, §12.2)", async () => {
    const {
      users: [alice, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    const unread = mustView(B, id).unread;
    await A.sendText(id, "a");
    await settle(A, B);
    const key = keyOf(A, id, "a");
    await A.editText(id, key, "a, edited");
    await A.sendText(id, "b");
    await settle(A, B);
    expect(chat(B, id)).toEqual(["alice: a, edited", "alice: b"]);
    expect(mustView(B, id).unread).toBe(unread + 2);
    const ep = epoch(A, id);
    const rows = laneRows(ep, P.memberIndex(ep.D, alice.uid));
    const types = rows.map((m) => m.type);
    const at = types.lastIndexOf(P.MT.EDIT);
    expect(types.slice(at - 1)).toEqual([P.MT.TEXT, P.MT.EDIT, P.MT.TEXT]);
    expect(rows[at + 1].prev).toEqual({ E: server().era, n: at });
    const B2 = await engineFor(bob);
    expect(chat(B2, id)).toEqual(["alice: a, edited", "alice: b"]);
    for (const X of [A, B, B2]) expect(X.getState().warnings).toEqual([]);
  });

  it("13. the initial history counts EDIT rows: a current epoch of 20 TEXT and 15 EDIT rows loads nothing older (§11.18, §11.4 step 6)", async () => {
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
    const keys = mustView(A, id)
      .messages.filter((m) => m.text?.startsWith("new "))
      .map((m) => m.key);
    for (let i = 0; i < 15; i++) await A.editText(id, keys[i], `new ${i}, edited`);
    await settle(A, B, C);
    const C2 = await engineFor(carol);
    expect(chat(C2, id).filter((t) => t.includes("old "))).toEqual([]);
    expect(conv(C2, id).edits.size).toBe(15);
  });

  it("14. the target's sender is the EDIT's by uid, never by index: an edit from an epoch where the sender's index changed counts; one by the member now at a departed sender's index never does (§11.18 Target)", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    await A.sendText(id, "alice's words");
    await B.sendText(id, "bob's words");
    await settle(A, B, C);
    const hers = keyOf(B, id, "alice's words");
    const his = keyOf(B, id, "bob's words");
    const ep0 = epoch(B, id);
    // alice (index 0) leaves; bob's edit commits a rotation first, whose descriptor keeps bob and carol, in order
    await A.leave(id);
    await settle(A, B, C);
    await B.editText(id, his, "bob's words, edited");
    await settle(A, B, C);
    const ep1 = epoch(B, id);
    expect(ep1.e).toBe(ep0.e + 1);
    expect(epoch(C, id).e).toBe(ep1.e);
    expect(P.memberIndex(ep1.D, alice.uid)).toBe(-1);
    // bob's index differs: 1 in the epoch of his message, 0 in the epoch of his edit
    expect(P.memberIndex(ep0.D, bob.uid)).toBe(1);
    expect(P.memberIndex(ep1.D, bob.uid)).toBe(0);
    const [edit] = [...conv(C, id).edits.values()];
    expect([edit.e, edit.j, edit.to.te, edit.to.tl]).toEqual([ep1.e, 0, ep0.e, 1]);
    for (const X of [B, C]) {
      expect(shown(X, id, his)).toMatchObject({
        text: "bob's words, edited",
        edited: { count: 1, sending: false },
      });
      expect(texts(X, id, his)).toEqual(["bob's words", "bob's words, edited"]);
    }
    // bob now holds index 0, alice's in epoch 0; carol holds index 1, bob's in epoch 0. Each forges an EDIT of the
    // message of the member whose index it holds now, with a th that names that row: an index check would take each
    // for its sender's own.
    const herT = targetOf(C, id, hers);
    const hisT = targetOf(C, id, his);
    expect(slotTarget(ep0, herT.tl, herT.tE, herT.tn)).toEqual(herT);
    expect(slotTarget(ep0, hisT.tl, hisT.tE, hisT.tn)).toEqual(hisT);
    expect(herT.tl).toBe(P.memberIndex(ep1.D, bob.uid));
    expect(hisT.tl).toBe(P.memberIndex(ep1.D, carol.uid));
    postAt(bob, ep1, { type: P.MT.EDIT, to: herT, text: "forged by bob" });
    postAt(carol, ep1, { type: P.MT.EDIT, to: hisT, text: "forged by carol" });
    await settle(B, C);
    const C2 = await engineFor(carol);
    const forged = [...conv(C, id).edits.values()].filter((r) => r.text.startsWith("forged by"));
    expect(forged).toHaveLength(2);
    for (const r of forged) {
      // read on the lane whose index its target names; only the uids differ
      expect([r.e, r.j]).toEqual([ep1.e, r.to.tl]);
      expect(r.uid).not.toBe(P.b64u(ep0.D.members[r.to.tl].uid));
    }
    for (const X of [B, C, C2]) {
      // both were read as valid EDIT rows and are held; neither counts
      expect(conv(X, id).edits.size).toBe(3);
      expect(shown(X, id, hers)).toEqual({ text: "alice's words", edited: undefined });
      expect(X.editHistory(id, hers)).toEqual([]);
      expect(shown(X, id, his)).toMatchObject({
        text: "bob's words, edited",
        edited: { count: 1, sending: false },
      });
      expect(texts(X, id, his)).toEqual(["bob's words", "bob's words, edited"]);
      expect(X.getState().warnings).toEqual([]);
    }
  });

  it("15. an app without push notifies with the message's current text: an EDIT read with the message, or before its notification is shown, is in it; an EDIT notifies nothing (§11.18 Not a message, §11.13)", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const notifier = new FakeNotifier();
    const A = await engineFor(alice);
    const B = await engineFor(bob, {
      push: { platform: null },
      local: { notifier, store: { load: () => true, save: () => {} } },
      notify: { store: null, preview: { load: () => "message", save: () => {} } },
      quiet: { inUse: () => false },
    });
    const id = await A.createConversation(["bob"], "g");
    await settle(A, B);
    await B.accept(id);
    await settle(A, B);
    expect(B.getState()).toMatchObject({ notifications: "on", preview: "message" });
    B.markRead(id);
    await settle(A, B);
    expect(mustView(B, id).unread).toBe(0);
    const bodies = () => notifier.shown.map((n) => n.body);
    expect(bodies()).toEqual([]);
    // A TEXT and its EDIT reach bob in one read: their realtime frames are lost, and his catch-up finds both.
    const ep = epoch(A, id);
    server().rt.dropPublish((row) => P.equalBytes(row.topic, ep.topic));
    await A.sendText(id, "lunch at noon");
    const lunch = keyOf(A, id, "lunch at noon");
    await A.editText(id, lunch, "lunch at one");
    server().rt.dropPublish(null);
    expect(mustView(B, id).messages.some((m) => m.key === lunch)).toBe(false);
    await I(B).catchUp();
    await settle(A, B);
    expect(shown(B, id, lunch)).toMatchObject({ text: "lunch at one", edited: { count: 1 } });
    expect(bodies()).toEqual(["@alice: lunch at one"]);
    expect(notifier.shown[0].tag).toBe(mustView(B, id).ref);
    // The EDIT queued no notification of its own for the end of the window.
    server().tick(DEFAULT_WINDOW_MS);
    await settle(A, B);
    expect(bodies()).toEqual(["@alice: lunch at one"]);
    // The window over, the next TEXT notifies at once; the one after it waits for the end of the window, and an EDIT
    // that reaches bob meanwhile is in its notification.
    await A.sendText(id, "ping");
    await settle(A, B);
    expect(bodies()).toEqual(["@alice: lunch at one", "@alice: ping (+1)"]);
    await A.sendText(id, "helo");
    await settle(A, B);
    const helo = keyOf(B, id, "helo");
    expect(bodies()).toHaveLength(2);
    await A.editText(id, helo, "hello");
    await settle(A, B);
    expect(shown(B, id, helo)).toMatchObject({ text: "hello", edited: { count: 1 } });
    expect(bodies()).toHaveLength(2);
    server().tick(DEFAULT_WINDOW_MS);
    await settle(A, B);
    expect(bodies()).toEqual(["@alice: lunch at one", "@alice: ping (+1)", "@alice: hello (+2)"]);
    expect(bodies().some((b) => b.includes("helo") || b.includes("noon"))).toBe(false);
    // nothing else waits: the EDIT queued nothing
    server().tick(DEFAULT_WINDOW_MS);
    await settle(A, B);
    expect(bodies()).toHaveLength(3);
    expect(B.getState().warnings).toEqual([]);
  });
});
