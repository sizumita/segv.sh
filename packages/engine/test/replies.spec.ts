// Replies (docs/PROTOCOL.md §3.3, §11.17): a REPLY row carries a TEXT, IMAGE or FILE and names its target as a REACTION
// does; it is sent, counted and shown as the message it carries, and its view names the target's message key once the
// target is loaded and checks, `waiting` before that, and `none` when it names no message the copy can show.
import { describe, expect, it, vi } from "vite-plus/test";
import type { Engine, MessageView } from "../src/types";
import {
  I,
  P,
  buildMessage,
  chat,
  conv,
  engineFor,
  epoch,
  freshWorldPerTest,
  makeUser,
  mustView,
  newEngine,
  postRow,
  server,
  settle,
  waitFor,
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

/** The message of `text` in the view of `e`. */
const msgOf = (e: Engine, id: string, text: string): MessageView => {
  const m = mustView(e, id).messages.find((x) => x.text === text);
  if (!m) throw new Error(`no message ${text}`);
  return m;
};
/** What the message `text` replies to, as the text of its target ("" while waiting or none). */
const replyOf = (e: Engine, id: string, text: string): [string, string] | undefined => {
  const r = msgOf(e, id, text).reply;
  if (!r) return undefined;
  const t = mustView(e, id).messages.find((m) => m.key === r.key);
  return [r.state, t?.text ?? ""];
};

/** The target fields of the message `text` as `e` holds it (its epoch, lane, slot and keyed th). */
function targetOf(e: Engine, id: string, text: string): P.ReplyTo {
  const key = msgOf(e, id, text).key;
  for (const ep of conv(e, id).epochs.values()) {
    const row = ep.rows.get(key);
    if (row) return { te: ep.e, tl: row.j, tE: row.E, tn: row.n, th: row.th };
  }
  throw new Error("no such row");
}

/** A row of `from` on its lane of epoch `ep` at its next slot (an earlier client, or a forged target). */
function postAt(from: TestUser, ep: ReturnType<typeof epoch>, content: P.MBody): void {
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
}

describe("REPLY content (§3.3)", () => {
  const to: P.ReplyTo = { te: 3, tl: 1, tE: 7, tn: 42, th: P.random(16) };
  const hdr = {
    from: 0,
    lane: 0,
    n: 0,
    prev: P.NONE,
    prevh: P.ZERO16,
    ts: 1,
    ckq: 0,
    ck16: P.ZERO16,
  };

  it("carries a TEXT, IMAGE or FILE and its target, and parses back", () => {
    const bodies: P.ReplyBody[] = [
      { type: P.MT.TEXT, text: "ramen?" },
      { type: P.MT.IMAGE, image: { id: P.random(32), k: P.random(32), mime: 1, w: 3, h: 4 } },
      { type: P.MT.FILE, file: { id: P.random(32), k: P.random(32), size: 9, name: "a.txt" } },
    ];
    for (const body of bodies) {
      const M = P.encodeM({ ...hdr, type: P.MT.REPLY, to, body });
      expect(M[1]).toBe(6);
      const m = P.parseM(M);
      expect(m.type === P.MT.REPLY && m.to).toEqual(to);
      expect(m.type === P.MT.REPLY && m.body).toEqual(body);
    }
  });

  it("is 29 bytes longer than its message: a text of 100 B stays in class 0, 101 B does not", () => {
    const ctx = {
      keys: { rk: P.random(32), mk: P.random(32) },
      conv: P.random(32),
      e: 0,
      sigSk: makeUser("xavier").id.sigSk,
    };
    const cls = (len: number) =>
      P.buildRow(ctx, 0, {
        ...hdr,
        type: P.MT.REPLY,
        to,
        body: { type: P.MT.TEXT, text: "a".repeat(len) },
      }).cls;
    expect(cls(100)).toBe(0);
    expect(cls(101)).toBe(1);
    const M = P.encodeM({ ...hdr, type: P.MT.REPLY, to, body: { type: P.MT.TEXT, text: "abc" } });
    expect(M.length).toBe(P.M_HEADER_LEN + P.REPLY_FIXED + 3);
  });

  it("is malformed with another kind, a short content, or a body its kind refuses", () => {
    const M = P.encodeM({ ...hdr, type: P.MT.REPLY, to, body: { type: P.MT.TEXT, text: "abc" } });
    const kindAt = P.M_HEADER_LEN + 28;
    for (const kind of [0, 3, 5, 6, 8, 16, 17]) {
      const bad = M.slice();
      bad[kindAt] = kind;
      expect(() => P.parseM(bad)).toThrow();
    }
    // an empty text, and a content that ends before its kind
    const empty = P.concat(
      M.slice(0, P.M_HEADER_LEN - 2),
      P.u16(29),
      M.slice(P.M_HEADER_LEN, kindAt + 1),
    );
    expect(() => P.parseM(empty)).toThrow();
    const short = P.concat(
      M.slice(0, P.M_HEADER_LEN - 2),
      P.u16(28),
      M.slice(P.M_HEADER_LEN, kindAt),
    );
    expect(() => P.parseM(short)).toThrow();
    expect(() =>
      P.encodeM({
        ...hdr,
        type: P.MT.REPLY,
        to,
        body: { type: P.MT.TEXT, text: "a".repeat(12001) },
      }),
    ).toThrow();
  });
});

describe("replies (§11.17)", () => {
  it("1. a reply shows on every device with its target, counts as a message, and survives a reload", async () => {
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
    const target = msgOf(B, id, "lunch?").key;
    const sending = B.sendText(id, "ramen?", target);
    // the echo already names its target
    expect(msgOf(B, id, "ramen?").reply).toEqual({ key: target, state: "shown" });
    await sending;
    await settle(A, B, B2);
    expect(B.getState().error).toBe("");
    for (const X of [A, B, B2]) {
      expect(replyOf(X, id, "ramen?")).toEqual(["shown", "lunch?"]);
      expect(msgOf(X, id, "ramen?").kind).toBe("text");
      expect(msgOf(X, id, "lunch?").reply).toBeUndefined();
    }
    expect(chat(A, id)).toEqual(["alice: lunch?", "bob: ramen?"]);
    expect(mustView(A, id).unread).toBe(1);
    expect(mustView(A, id).lastTs).toBeGreaterThan(lastA);
    // the row on the server is a REPLY of epoch 0's lane of bob
    const ep = epoch(A, id);
    const at = targetOf(A, id, "ramen?");
    const label = P.Lmsg(ep.keys.rk, at.tl, at.tE, at.tn);
    const stored = server().shard.row(at.tE, label)!;
    const v = P.acceptRow(
      { keys: ep.keys, conv: ep.D.conv, e: ep.e, members: ep.D.members },
      at.tE,
      label,
      stored.body,
    );
    expect(v.ok && v.msg.type).toBe(P.MT.REPLY);
    const A2 = await engineFor(alice);
    expect(replyOf(A2, id, "ramen?")).toEqual(["shown", "lunch?"]);
  });

  it("2. replies to replies, images and files; a reaction to a reply", async () => {
    const {
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    await A.sendText(id, "lunch?");
    await settle(A, B, C);
    await B.sendText(id, "ramen?", msgOf(B, id, "lunch?").key);
    await settle(A, B, C);
    await C.sendText(id, "yes!", msgOf(C, id, "ramen?").key);
    await settle(A, B, C);
    await A.sendImage(
      id,
      new File([P.utf8("RIFF....WEBPVP8 bowl") as BlobPart], "p.webp", { type: "image/webp" }),
      msgOf(A, id, "yes!").key,
    );
    await A.sendFile(
      id,
      new File([P.utf8("menu") as BlobPart], "menu.txt"),
      msgOf(A, id, "lunch?").key,
    );
    await settle(A, B, C);
    for (const X of [A, B, C]) {
      expect(replyOf(X, id, "ramen?")).toEqual(["shown", "lunch?"]);
      expect(replyOf(X, id, "yes!")).toEqual(["shown", "ramen?"]);
      const msgs = mustView(X, id).messages;
      const img = msgs.find((m) => m.kind === "image")!;
      const file = msgs.find((m) => m.kind === "file")!;
      expect(img.reply).toEqual({ key: msgOf(X, id, "yes!").key, state: "shown" });
      expect(file.reply).toEqual({ key: msgOf(X, id, "lunch?").key, state: "shown" });
      expect(file.file?.name).toBe("menu.txt");
    }
    await C.react(id, msgOf(C, id, "ramen?").key, "🍜", true);
    await settle(A, B, C);
    expect(msgOf(B, id, "ramen?").reactions).toEqual([{ emoji: "🍜", count: 1, mine: false }]);
  });

  it("3. a target that does not check is none, one not loaded is waiting; the reply still shows, without a warning", async () => {
    const {
      users: [alice, bob],
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    await A.sendText(id, "target");
    await settle(A, B);
    await B.react(id, msgOf(B, id, "target").key, "👍", true);
    await settle(A, B);
    const ep = epoch(A, id);
    const t = targetOf(A, id, "target");
    // the slot of bob's REACTION: a valid row, but no message
    const r = [...conv(A, id).reactions.values()][0];
    const reactSlot = { te: r.e, tl: r.j, tE: r.E, tn: r.n, th: t.th };
    const cases: [P.ReplyTo, string][] = [
      [{ ...t, th: P.random(16) }, "bad th"],
      [{ ...t, tl: ep.D.members.length }, "bad lane"],
      [{ ...t, te: t.te + 1 }, "later epoch"],
      [reactSlot, "a reaction"],
      [{ ...t, tn: t.tn + 5 }, "not loaded"],
    ];
    for (const [to, text] of cases)
      postAt(bob, ep, { type: P.MT.REPLY, to, body: { type: P.MT.TEXT, text } });
    await settle(A, B);
    for (const X of [A, B]) {
      expect(replyOf(X, id, "bad th")).toEqual(["none", ""]);
      expect(replyOf(X, id, "bad lane")).toEqual(["none", ""]);
      expect(replyOf(X, id, "later epoch")).toEqual(["none", ""]);
      expect(replyOf(X, id, "a reaction")).toEqual(["none", ""]);
      expect(replyOf(X, id, "not loaded")).toEqual(["waiting", ""]);
      expect(X.getState().warnings).toEqual([]);
    }
    void alice;
  });

  it("4. a target older than the initial history waits, and shows once scrollback loads it", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(["bob"]);
    await settle(A, B);
    await A.sendText(id, "old one");
    for (let i = 0; i < 40; i++) await A.sendText(id, `m ${i}`);
    await settle(A, B);
    await B.sendText(id, "about that", msgOf(B, id, "old one").key);
    await settle(A, B);
    const B2 = await engineFor(bob);
    expect(chat(B2, id)).not.toContain("alice: old one");
    expect(replyOf(B2, id, "about that")).toEqual(["waiting", ""]);
    B2.markRead(id);
    await settle(B2);
    expect(replyOf(B2, id, "about that")).toEqual(["shown", "old one"]);
  });

  it("5. a target in an epoch the copy does not hold is none", async () => {
    const {
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    await A.sendText(id, "before dave");
    await settle(A, B);
    const D = await engineFor(makeUser("dave"));
    await A.addMembers(id, ["dave"]);
    await settle(A, B, D);
    await D.accept(id);
    await settle(A, B, D);
    await B.sendText(id, "re: before", msgOf(B, id, "before dave").key);
    await settle(A, B, D);
    expect(replyOf(A, id, "re: before")).toEqual(["shown", "before dave"]);
    expect(replyOf(D, id, "re: before")).toEqual(["none", ""]);
    expect(msgOf(D, id, "re: before").status).toBe("sent");
  });

  it("6. an unknown target key sends nothing and reports the error", async () => {
    const {
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    await settle(A, B);
    const rows = server().shard.rows().length;
    await A.sendText(id, "to nowhere", "0:00");
    await A.sendFile(id, new File([P.utf8("x") as BlobPart], "x.txt"), "local:1");
    expect(A.getState().error).toBe("unknown message");
    expect(server().shard.rows().length).toBe(rows);
    expect(chat(A, id)).toEqual([]);
  });
});
