// Leaves, re-adds as separate copies and rows that land late in an older epoch (docs/PROTOCOL.md §6.6 step 3,
// §6.7 steps 4–6, §6.8, §6.9, §11.2, §11.3 steps 1–3 and 8).
import { describe, expect, it } from "vite-plus/test";
import type { Engine } from "../../src/client/types";
import type { EngineOptions } from "../../src/client/options";
import {
  I,
  P,
  chat,
  commitChange,
  conv,
  engineFor,
  epoch,
  freshWorldPerTest,
  makeUser,
  mustView,
  postRow,
  readableWith,
  server,
  settle,
  systemLines,
  view,
  type TestUser,
} from "./harness";

freshWorldPerTest();

async function group(names: string[], name = "g", opts: Record<string, EngineOptions> = {}) {
  const users = names.map((h) => makeUser(h));
  const engines: Engine[] = [];
  for (const u of users) engines.push(await engineFor(u, opts[u.handle] ?? {}));
  const id = await engines[0].createConversation(names.slice(1), name);
  await settle(...engines);
  for (const E of engines.slice(1)) await E.accept(id);
  await settle(...engines);
  return { users, engines, id };
}

const LEAVE = P.MT.LEAVE as number;
const TEXT = P.MT.TEXT as number;

describe("re-adds", () => {
  it("a removed leaver re-added later gets a separate copy; the old one has ended (live and after a reload)", async () => {
    const {
      users: [alice, bob],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    await B.leave(id);
    await settle(A, B, C);
    expect(mustView(B, id).blocked).toBe("left");
    await A.addMembers(id, ["bob"]); // drops the leaver (e1), then adds bob back (e2)
    await settle(A, B, C);
    expect(mustView(A, id).epoch).toBe(2);
    // G has ended at e0's claim: "you left the conversation", no "@alice removed you" (bob had left).
    const G = mustView(B, id);
    expect(G.epoch).toBe(0);
    expect(G.blocked).toBe("removed");
    expect(systemLines(B, id)).toContain("you left the conversation");
    expect(systemLines(B, id)).not.toContain("@alice removed you");
    // The re-add is a separate copy G′, rooted at e2: "@alice added you", no warning, no ⚠.
    const id1 = `${id}~1`;
    const G1 = mustView(B, id1);
    expect(G1.epoch).toBe(2);
    expect(G1.canSend).toBe(true);
    expect(G1.name.startsWith("⚠")).toBe(false);
    expect(G.name.startsWith("⚠")).toBe(false);
    expect(systemLines(B, id1)).toEqual(["@alice added you"]);
    expect(conv(B, id1).left).toBe(false);
    expect(B.getState().warnings).toEqual([]);
    for (const X of [A, C]) {
      const m = mustView(X, id).members.find((x) => x.handle === "bob")!;
      expect(m.left).toBe(false);
    }
    await B.sendText(id1, "back again");
    await A.sendText(id, "welcome back");
    await settle(A, B, C);
    expect(mustView(A, id).epoch).toBe(2); // no rotation needed
    expect(chat(C, id)).toEqual(["bob: back again", "alice: welcome back"]);
    expect(chat(B, id1)).toEqual(["bob: back again", "alice: welcome back"]);
    // bob's device puts no LEAVE in the re-added epoch, live or after a reload.
    const leaves = () => readableWith(epoch(A, id).keys.mk).filter((m) => m.type === LEAVE).length;
    expect(leaves()).toBe(0);
    const B2 = await engineFor(bob);
    expect(mustView(B2, id).blocked).toBe("removed");
    expect(systemLines(B2, id)).not.toContain("@alice removed you");
    expect(mustView(B2, id1).epoch).toBe(2);
    expect(mustView(B2, id1).canSend).toBe(true);
    expect(systemLines(B2, id1)).toContain("@alice added you");
    expect(B2.getState().warnings).toEqual([]);
    await settle(A, B2, C);
    expect(leaves()).toBe(0);
    void alice;
  });

  it("a J for the re-added epoch that arrives before the dropping claim waits for it, then starts its own copy", async () => {
    const {
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    await B.leave(id);
    await settle(A, B, C);
    const ep0 = epoch(A, id);
    server().rt.dropPublish((row) => P.equalBytes(row.topic, ep0.topic));
    await A.addMembers(id, ["bob"]);
    server().rt.dropPublish(null);
    // bob's next inbox poll finds J(e2) before any frame of the dropping claim reached him: settling G processes the
    // claim first (G ends), and J(e2) starts G′.
    await I(B).catchUp();
    await settle(A, B, C);
    expect(mustView(B, id).blocked).toBe("removed");
    expect(systemLines(B, id)).toContain("you left the conversation");
    expect(systemLines(B, id)).not.toContain("@alice removed you");
    const G1 = mustView(B, `${id}~1`);
    expect(G1.epoch).toBe(2);
    expect(G1.canSend).toBe(true);
    expect(G1.name.startsWith("⚠")).toBe(false);
    expect(systemLines(B, `${id}~1`)).toEqual(["@alice added you"]);
    expect(B.getState().warnings).toEqual([]);
  });
});

describe("frozen and leaving", () => {
  it("a frozen member can still send a text after another member left (no rotation)", async () => {
    const {
      users: [alice, bob, carol, mallory],
      engines: [A, B, C, M],
      id,
    } = await group(["alice", "bob", "carol", "mallory"]);
    const ep = epoch(A, id);
    await commitChange(mallory, ep, [alice, bob, carol, mallory], undefined, {
      patchBlob: (blob) => {
        const out = blob.slice();
        out.set(P.random(64), P.SGB2_HEADER_LEN);
        return out;
      },
    });
    await settle(A, B, C, M);
    expect(mustView(A, id).frozen).toBe(true);
    await C.leave(id);
    await settle(A, B, C, M);
    expect(systemLines(A, id)).toContain("@carol left");
    await A.sendText(id, "frozen but talking");
    await settle(A, B, C, M);
    expect(A.getState().error).toBe("");
    expect(chat(B, id)).toContain("alice: frozen but talking");
    expect(mustView(A, id).epoch).toBe(0);
  });
});

describe("late rows in an older epoch", () => {
  it("(a) a LEAVE sent right after a claim whose frame was lost lands in the new epoch", async () => {
    const {
      users: [alice, bob, zed],
      engines: [A, B, Z],
      id,
    } = await group(["alice", "bob", "zed"]);
    const ep = epoch(A, id);
    const r = await commitChange(alice, ep, [alice, bob, zed], "renamed", { noPost: true });
    server().rt.dropPublish((row) => P.equalBytes(row.label, r.claim.label));
    postRow(ep, r.claim);
    await Z.leave(id);
    server().rt.dropPublish(null);
    expect(epoch(Z, id).e).toBe(1);
    expect(readableWith(epoch(Z, id).keys.mk).some((m) => m.type === LEAVE)).toBe(true);
    expect(readableWith(ep.keys.mk).some((m) => m.type === LEAVE)).toBe(false);
    await settle(A, B, Z);
    expect(systemLines(A, id)).toContain("@zed left");
  });

  async function lateSetup(kind: "leave" | "text") {
    let armed = false;
    let users: TestUser[] = [];
    let ep: ReturnType<typeof epoch> | null = null;
    const g = await group(["alice", "bob", "zed"], "g", {
      zed: {
        beforePutAttempt: async () => {
          if (!armed || !ep) return;
          armed = false;
          // C is stored after zed's step-1 probe was answered; zed's clocks do not move.
          await commitChange(users[0], ep, users, "renamed", { serverOnly: true });
        },
      },
    });
    users = g.users;
    const [A, B, Z] = g.engines;
    ep = epoch(A, g.id);
    armed = true;
    if (kind === "leave") await Z.leave(g.id);
    else await Z.sendText(g.id, "late text");
    return { ...g, A, B, Z, ep };
  }

  it("(b) a LEAVE that lands in e after the others switched is seen on the followed lane; they rotate", async () => {
    const { A, B, Z, id, ep } = await lateSetup("leave");
    expect(readableWith(ep.keys.mk).some((m) => m.type === LEAVE)).toBe(true);
    await settle(A, B, Z);
    expect(mustView(A, id).epoch).toBe(1);
    expect(systemLines(A, id)).toContain("@zed left");
    expect(mustView(A, id).members.find((m) => m.handle === "zed")!.left).toBe(true);
    await A.sendText(id, "after zed left");
    await settle(A, B, Z);
    expect(mustView(A, id).epoch).toBe(2);
    expect(systemLines(B, id)).toContain("keys rotated after @zed left");
    expect(chat(B, id)).toEqual(["alice: after zed left"]);
    expect(chat(Z, id)).toEqual([]);
  });

  it("(c) a TEXT that lands in e after the others switched is shown, and the followed lane ends", async () => {
    const { A, B, Z, id } = await lateSetup("text");
    await settle(A, B, Z);
    for (const X of [A, B]) expect(chat(X, id)).toContain("zed: late text");
    await Z.sendText(id, "now in e+1");
    await settle(A, B, Z);
    expect(chat(A, id).at(-1)).toBe("zed: now in e+1");
    const prev = conv(A, id).epochs.get(0)!;
    const zi = P.memberIndex(prev.D, epoch(Z, id).D.members[epoch(Z, id).myIndex].uid);
    expect(prev.lanes[zi].swept).toBe(true);
  });
});

describe("leave order and WELCOMEs", () => {
  it("a lost LEAVE answer is recovered from the slot before the LEAVE record is written", async () => {
    const {
      engines: [A, B],
      id,
    } = await group(["alice", "bob"]);
    let lost = 0;
    const ep = epoch(B, id);
    server().hooks.afterPut = (rows, _res, who) => {
      if (who !== "bob" || lost) return;
      if (rows.some((r) => P.equalBytes(r.topic, ep.topic))) {
        lost++;
        return "lose";
      }
    };
    await B.leave(id);
    server().hooks.afterPut = undefined;
    expect(lost).toBe(1);
    expect(B.getState().error).toBe("");
    expect(I(B).self!.fold.leaves.get(`${P.b64u(ep.D.conv)}.${P.b64u(conv(B, id).root)}`)).toHaveLength(1);
    await settle(A, B);
    expect(systemLines(A, id)).toContain("@bob left");
  });

  it("a WELCOME written before a leave reached the leaver is still processed", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const one = await A.createConversation(["bob"]);
    await settle(A, B);
    await B.accept(one);
    await B.sendText(one, "hi alice");
    await settle(A, B);
    const ep = epoch(A, one);
    server().rt.dropPublish((row) => P.equalBytes(row.topic, ep.topic));
    const g = await A.createConversation(["bob", "carol"], "g");
    await settle(A);
    await B.leave(one);
    server().rt.dropPublish(null);
    await settle(A, B, C);
    expect(mustView(B, g).name).toBe("# g");
    expect(readableWith(ep.keys.mk).some((m) => m.type === P.MT.WELCOME)).toBe(true);
  });

  it("(30 a) a WELCOME is never written into a later epoch of its carrier: the J goes by inbox", async () => {
    const [alice, bob, carol, dave] = ["alice", "bob", "carol", "dave"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const D = await engineFor(dave);
    const one = await A.createConversation(["bob"]);
    await settle(A, B);
    await B.accept(one);
    await B.sendText(one, "hi");
    await settle(A, B);
    const ep = epoch(A, one);
    server().rt.dropPublish((row) => P.equalBytes(row.topic, ep.topic));
    await B.addMembers(one, ["dave"]);
    const invites = server().inbox.pendingTotal();
    const g = await A.createConversation(["bob", "carol"], "G");
    await settle(A);
    server().rt.dropPublish(null);
    await settle(A, B, C, D);
    expect(mustView(B, g).name).toBe("# G");
    expect(view(D, g)).toBeUndefined();
    const next = conv(A, one).epochs.get(1)!;
    expect(readableWith(next.keys.mk).some((m) => m.type === P.MT.WELCOME)).toBe(false);
    expect(readableWith(ep.keys.mk).some((m) => m.type === P.MT.WELCOME)).toBe(false);
    void invites;
  });
});

describe("others' leaves at a reload", () => {
  it("a leave applied live is kept by a LEFT record: after a reload the next text still rotates first", async () => {
    const {
      users: [alice],
      engines: [A, B, L],
      id,
    } = await group(["alice", "bob", "lee"]);
    await L.leave(id);
    await settle(A, B, L);
    const mk0 = epoch(A, id).keys.mk;
    const A2 = await engineFor(alice);
    expect(mustView(A2, id).members.find((m) => m.handle === "lee")!.left).toBe(true);
    await A2.sendText(id, "after the reload");
    await settle(A2, B, L);
    expect(mustView(A2, id).epoch).toBe(1);
    expect(readableWith(mk0).filter((m) => m.type === TEXT)).toEqual([]);
    expect(chat(B, id)).toEqual(["alice: after the reload"]);
    expect(systemLines(B, id)).toContain("keys rotated after @lee left");
  });
});
