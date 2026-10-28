// Notifications (docs/PROTOCOL.md §11.13): the registration set, its re-sends, the rings after a TEXT or IMAGE, and
// the device's subscription at logout, against FakeWorld's push endpoints and a fake browser per device.
import { describe, expect, it } from "vite-plus/test";
import type { Engine } from "../../src/client/types";
import {
  FakePushDevice,
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
  waitFor,
  type TestUser,
} from "./harness";

freshWorldPerTest({ push: true });

/** `u`'s bell in the current epoch of `id`, as engine `e` computes it. */
function bellOf(e: Engine, id: string, u: TestUser): string {
  const ep = epoch(e, id);
  return P.b64u(P.bell(ep.keys.nk, P.memberIndex(ep.D, u.uid)));
}

/** The bells last registered for the device's endpoint. */
const registered = (d: FakePushDevice): string[] => [...(server().push.subs.get(d.endpoint) ?? [])].sort();

/** Waits until the device's registration equals `bells` (re-sends are batched over Δ). */
async function registeredAs(d: FakePushDevice, bells: string[]): Promise<void> {
  const want = [...bells].sort();
  await waitFor(() => JSON.stringify(registered(d)) === JSON.stringify(want), `${d.name} registers ${want.length} bells`, 10_000);
}

const ringCount = (): number => server().push.rings().length;

/** The rings sent after `fn` (rings never wait: give them a moment to arrive). */
async function ringsAfter(fn: () => Promise<void>, engines: Engine[]) {
  const before = ringCount();
  await fn();
  await settle(...engines);
  await new Promise((r) => setTimeout(r, 50));
  return server().push.rings().slice(before);
}

const msgKey = (e: Engine, id: string, text: string): string => mustView(e, id).messages.find((m) => m.text === text)!.key;

describe("the registration set (§11.13)", () => {
  it("holds the bell of self's lane in each accepted copy's current epoch, as the other members compute it", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const bobDev = new FakePushDevice("bob");
    const A = await engineFor(alice);
    const B = await engineFor(bob, bobDev.options);
    const C = await engineFor(carol);
    const one = await A.createConversation(["bob"]);
    const g = await A.createConversation(["bob", "carol"], "g");
    await settle(A, B, C);
    expect(B.getState().notifications).toBe("off");
    await B.setNotifications(true);
    expect(B.getState().notifications).toBe("on");
    expect(bobDev.log.slice(0, 2)).toEqual(["permission", `subscribe ${bobDev.endpoint}`]);
    // Both are still requests on bob's side: nothing to register.
    expect(server().push.subsOf(bobDev.endpoint).at(-1)!.tokens).toEqual([]);
    await B.accept(g);
    await C.accept(g);
    await settle(A, B, C);
    // Accepting g made alice a contact, so her 1:1 joins the set too (§11.13: a new contact changes the set).
    expect(mustView(B, one).request).toBe(false);
    await registeredAs(bobDev, [bellOf(A, g, bob), bellOf(A, one, bob)]);
    expect(bellOf(B, g, bob)).toBe(bellOf(C, g, bob));
    expect(bellOf(B, one, bob)).toBe(bellOf(A, one, bob));
    // A copy whose leave is current is left out.
    await B.leave(g);
    await settle(A, B, C);
    await registeredAs(bobDev, [bellOf(A, one, bob)]);
  });

  it("leaves out a copy that only a third member's row accepted until the user's own accept, which re-sends the set", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const bobDev = new FakePushDevice("bob");
    const A = await engineFor(alice);
    const B = await engineFor(bob, bobDev.options);
    const C = await engineFor(carol);
    await B.setNotifications(true);
    // carol, a stranger to bob, starts a group; alice's row accepts it on bob's device, writing no CONTACT
    const id = await C.createConversation(["alice", "bob"], "g");
    await settle(A, B, C);
    await A.accept(id);
    await C.sendText(id, "first");
    await settle(A, B, C);
    await A.react(id, msgKey(A, id, "first"), "👍", true);
    await settle(A, B, C);
    expect(mustView(B, id).request).toBe(false);
    expect(mustView(B, id).byContact).toBe(false);
    B.markRead(id); // opening the pane accepts nothing
    await settle(A, B, C);
    await new Promise((r) => setTimeout(r, 1200)); // a batch over Δ would have run
    expect(registered(bobDev)).toEqual([]);
    // carol's text rings bob's bell, but bob registered none: no push
    await C.sendText(id, "second");
    await settle(A, B, C);
    await new Promise((r) => setTimeout(r, 50));
    expect(server().push.pushes.filter((p) => p.endpoint === bobDev.endpoint)).toEqual([]);
    await B.accept(id);
    await settle(A, B, C);
    expect(mustView(B, id).byContact).toBe(true);
    await registeredAs(bobDev, [bellOf(A, id, bob)]);
  });
});

describe("re-sends and the subscription (§11.13)", () => {
  it("re-sends after an epoch change and after a restore; an unchanged set is not sent again", async () => {
    const [alice, bob, carol, dave] = ["alice", "bob", "carol", "dave"].map((h) => makeUser(h));
    const bobDev = new FakePushDevice("bob");
    const A = await engineFor(alice);
    const B = await engineFor(bob, bobDev.options);
    const id = await A.createConversation(["bob", "carol"], "g");
    await settle(A, B);
    await B.accept(id);
    await B.setNotifications(true);
    await registeredAs(bobDev, [bellOf(A, id, bob)]);
    const sends = () => server().push.subsOf(bobDev.endpoint).length;
    const n0 = sends();
    await A.sendText(id, "hi");
    await settle(A, B);
    await new Promise((r) => setTimeout(r, 1200));
    expect(sends()).toBe(n0); // a new message changes nothing in the set
    const old = bellOf(A, id, bob);
    await A.addMembers(id, ["dave"]);
    await settle(A, B);
    expect(bellOf(A, id, bob)).not.toBe(old);
    await registeredAs(bobDev, [bellOf(A, id, bob)]);
    void carol;
    void dave;
    // A restore on a new engine of the same browser sends the set again, unchanged.
    await B.logout().catch(() => {});
    const bobDev2 = bobDev; // the same browser profile
    bobDev2.store.save({ on: true, endpoint: null });
    bobDev2.sub = null;
    const B2 = await engineFor(bob, bobDev2.options);
    await registeredAs(bobDev2, [bellOf(A, id, bob)]);
    expect(B2.getState().notifications).toBe("on");
  });

  it("turning off and logout end the subscription first, then delete the registration; the next account starts off", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const dev = new FakePushDevice("shared");
    const A = await engineFor(alice);
    const B = await engineFor(bob, dev.options);
    const id = await A.createConversation(["bob"]);
    await settle(A, B);
    await B.accept(id);
    await B.setNotifications(true);
    await registeredAs(dev, [bellOf(A, id, bob)]);
    const ep = dev.endpoint;
    const order: string[] = [];
    dev.onUnsubscribe = () => order.push("unsubscribe");
    const before = server().push.calls.length;
    await B.logout();
    await waitFor(() => server().push.subsOf(ep).at(-1)?.tokens.length === 0, "the empty set", 10_000);
    order.push(...server().push.calls.slice(before).map((c) => c.kind));
    expect(order).toEqual(["unsubscribe", "sub"]);
    expect(server().push.subs.has(ep)).toBe(false);
    // alice signs in on the same browser: notifications are off, nothing is registered for her
    const A2 = await engineFor(alice, dev.options);
    expect(A2.getState().notifications).toBe("off");
    await A.sendText(id, "after logout");
    await settle(A, A2);
    expect(server().push.pushes.filter((p) => p.endpoint === ep)).toEqual([]);
  });

  it("a 404 (push no longer offered) ends the subscription and turns the setting off", async () => {
    const bob = makeUser("bob");
    const dev = new FakePushDevice("bob");
    const B = await engineFor(bob, dev.options);
    await B.setNotifications(true);
    expect(dev.sub!.ended).toBe(false);
    server().pushOn = false;
    I(B).push.restored();
    await waitFor(() => B.getState().notifications !== "on", "setting off", 10_000);
    expect(dev.sub!.ended).toBe(true);
    expect(dev.store.load().on).toBe(false);
  });
});

describe("rings (§11.3 step 6, §11.13)", () => {
  it("a TEXT rings once with the other lanes' bells; a REACTION and a LEAVE never ring", async () => {
    const [alice, bob, carol, dave] = ["alice", "bob", "carol", "dave"].map((h) => makeUser(h));
    const engines = [await engineFor(alice), await engineFor(bob), await engineFor(carol), await engineFor(dave)];
    const [A, B, C, D] = engines;
    const id = await A.createConversation(["bob", "carol", "dave"], "g");
    await settle(...engines);
    for (const e of [B, C, D]) await e.accept(id);
    await settle(...engines);
    const rings = await ringsAfter(() => A.sendText(id, "hello"), engines);
    expect(rings).toHaveLength(1);
    expect([...rings[0].tokens].sort()).toEqual([bellOf(A, id, bob), bellOf(A, id, carol), bellOf(A, id, dave)].sort());
    expect(rings[0].E).toBe(server().era);
    expect(await ringsAfter(() => B.react(id, msgKey(B, id, "hello"), "👍", true), engines)).toEqual([]);
    expect(await ringsAfter(() => D.leave(id), engines)).toEqual([]);
  });

  it("after an epoch change a TEXT also rings the old bells of the members silent in the new epoch", async () => {
    const [alice, bob, carol, dave] = ["alice", "bob", "carol", "dave"].map((h) => makeUser(h));
    const engines = [await engineFor(alice), await engineFor(bob), await engineFor(carol)];
    const [A, B, C] = engines;
    const id = await A.createConversation(["bob", "carol"], "g");
    await settle(...engines);
    for (const e of [B, C]) await e.accept(id);
    await settle(...engines);
    const oldBob = bellOf(A, id, bob);
    const oldCarol = bellOf(A, id, carol);
    await A.addMembers(id, ["dave"]);
    await settle(...engines);
    const now = [bellOf(A, id, bob), bellOf(A, id, carol), bellOf(A, id, dave)];
    let [r] = await ringsAfter(() => A.sendText(id, "one"), engines);
    expect([...r.tokens].sort()).toEqual([...now, oldBob, oldCarol].sort());
    // bob posts in the new epoch: his old bell is no longer rung
    await B.sendText(id, "bob here");
    await settle(...engines);
    [r] = await ringsAfter(() => A.sendText(id, "two"), engines);
    expect([...r.tokens].sort()).toEqual([...now, oldCarol].sort());
  });

  it("end to end: bob's device gets a push for alice's TEXT, none for a REACTION, and none while his copy is a request", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const bobDev = new FakePushDevice("bob");
    const A = await engineFor(alice);
    const B = await engineFor(bob, bobDev.options);
    await B.setNotifications(true);
    const id = await A.createConversation(["bob"]);
    await settle(A, B);
    const pushes = () => server().push.pushes.filter((p) => p.endpoint === bobDev.endpoint).length;
    await A.sendText(id, "while a request");
    await settle(A, B);
    await new Promise((r) => setTimeout(r, 50));
    expect(pushes()).toBe(0);
    await B.accept(id);
    await settle(A, B);
    await registeredAs(bobDev, [bellOf(A, id, bob)]);
    await A.sendText(id, "hello bob");
    await settle(A, B);
    await waitFor(() => pushes() === 1, "one push", 5_000);
    await A.react(id, msgKey(A, id, "hello bob"), "👍", true);
    await settle(A, B);
    await new Promise((r) => setTimeout(r, 50));
    expect(pushes()).toBe(1);
    expect(chat(B, id)).toContain("alice: hello bob");
  });
});
