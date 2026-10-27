// Links (docs/STAGE1-PLAN.md M10 links.spec.ts; SPEC §4.3, §5.5, §7.2): hellos at the first empty slot, the owner's
// probing, one-shot and expired links, junk hellos, and the conversation a link starts.
import { describe, expect, it } from "vite-plus/test";
import { UNDECRYPTABLE } from "../../src/client/sync";
import {
  I,
  P,
  chat,
  engineFor,
  freshWorldPerTest,
  junkRow,
  makeUser,
  mustView,
  server,
  settle,
  view,
} from "./harness";

freshWorldPerTest();

const linkOf = (url: string) => P.parseLink(url);

describe("links", () => {
  it("racing hellos take slots 0 and 1; the owner finds both and the conversations work both ways", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const url = await I(B).createLink();
    const { s, uid } = linkOf(url);
    expect(P.equalBytes(uid, bob.uid)).toBe(true);
    const [ida, idc] = await Promise.all([I(A).openLink(url), I(C).openLink(url)]);
    await settle(A, B, C);
    const kL = P.linkKeys(s).kL;
    const E = server().era;
    expect(server().shard.hasLabel(E, P.Lhello(kL, E, 0))).toBe(true);
    expect(server().shard.hasLabel(E, P.Lhello(kL, E, 1))).toBe(true);
    expect(server().shard.hasLabel(E, P.Lhello(kL, E, 2))).toBe(false);
    expect(mustView(B, ida).request).toBe(true);
    expect(mustView(B, idc).request).toBe(true);
    expect(mustView(A, ida).name).toBe("@bob");
    B.markRead(ida);
    await B.sendText(ida, "hi alice, via my link");
    await A.sendText(ida, "hi bob");
    await settle(A, B, C);
    expect(chat(A, ida)).toEqual(["bob: hi alice, via my link", "alice: hi bob"]);
    expect(chat(B, ida)).toEqual(["bob: hi alice, via my link", "alice: hi bob"]);
    // the hellos are the only delivery: no inbox invite was posted for bob
    expect(server().inbox.pendingTotal()).toBe(0);
    for (const X of [A, B, C]) expect(X.getState().warnings).toEqual([]);
  });

  it("a one-shot link stops after its first valid hello", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const url = await I(B).createLink({ oneShot: true });
    const ida = await I(A).openLink(url);
    await settle(A, B);
    expect(view(B, ida)).toBeDefined();
    const rec = [...I(B).self!.fold.links.values()][0];
    expect(rec.flags & P.LINK_REVOKED).toBe(P.LINK_REVOKED);
    const idc = await I(C).openLink(url);
    await settle(B, C);
    expect(view(B, idc)).toBeUndefined();
    // a reload of the owner does not listen either
    const B2 = await engineFor(bob);
    await settle(B2, C);
    expect(view(B2, idc)).toBeUndefined();
    expect(view(B2, ida)).toBeDefined();
  });

  it("an expired link is not probed", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const B = await engineFor(bob);
    const url = await I(B).createLink();
    await B.logout();
    server().advanceEra(5);
    const A = await engineFor(alice);
    const id = await I(A).openLink(url);
    await settle(A);
    const B2 = await engineFor(bob);
    await settle(A, B2);
    expect(view(B2, id)).toBeUndefined();
    const kL = P.linkKeys(linkOf(url).s).kL;
    const asked = server()
      .requests.filter((r) => r.who === "bob" && r.getKeys)
      .some((r) => r.getKeys!.some((k) => P.equalBytes(k.label, P.Lhello(kL, server().era, 0))));
    expect(asked).toBe(false);
  });

  it("a junk hello gives a noise warning and no conversation", async () => {
    const bob = makeUser("bob");
    const B = await engineFor(bob);
    const url = await I(B).createLink();
    const kL = P.linkKeys(linkOf(url).s).kL;
    const E = server().era;
    junkRow(E, P.Lhello(kL, E, 0), 2);
    await I(B).catchUp();
    await settle(B);
    expect(B.getState().warnings).toContain(UNDECRYPTABLE);
    expect(I(B).views()).toEqual([]);
  });

  it("a link of one's own and a malformed link are refused", async () => {
    const bob = makeUser("bob");
    const B = await engineFor(bob);
    const url = await I(B).createLink();
    await expect(I(B).openLink(url)).rejects.toThrow(/your own link/);
    await expect(I(B).openLink("https://segv.test/i#nope")).rejects.toThrow(/not a segv.sh link/);
  });
});
