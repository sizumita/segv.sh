// Notifications (docs/PROTOCOL.md §11.13): the bells (BELL rows and generations), the registration set, its re-sends,
// the rings after a TEXT, IMAGE or FILE, and the device's subscription at logout, against FakeWorld's push endpoints and
// a fake browser per device.
import { describe, expect, it } from "vite-plus/test";
import {
  isBox,
  readCache,
  type Preview,
  type PreviewStore,
  type SealedBox,
  type Stored,
} from "../src/notify-cache";
import { browserDeps, notesFor, type Proposed } from "../src/sw-core";
import type { Engine } from "../src/types";
import {
  FakePushDevice,
  I,
  P,
  chat,
  conv,
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

/** An in-memory notification cache and preview setting, as one device keeps them. */
function notifyOf() {
  const store = {
    key: null as CryptoKey | null,
    box: null as SealedBox | null,
    gen: 0,
    /** the next write waits for this (set by a test), after calling `onHeld` */
    holdWrite: null as Promise<void> | null,
    onHeld: null as (() => void) | null,
    read: async (): Promise<Stored> => ({ key: store.key, box: store.box, gen: store.gen }),
    async writeIf(gen: number, iv: Uint8Array | null, w: { box: SealedBox; key?: CryptoKey }) {
      const h = store.holdWrite;
      store.holdWrite = null;
      if (h) {
        store.onHeld?.();
        await h;
      }
      if (store.gen !== gen || !isBox(store.box, iv)) return false;
      if (w.key) store.key = w.key;
      store.box = w.box;
      return true;
    },
    clear: async () => {
      store.key = null;
      store.box = null;
      store.gen++;
    },
  };
  let p: Preview = "none";
  const preview: PreviewStore = { load: () => p, save: (x) => void (p = x) };
  return { store, preview };
}

/**
 * `u`'s bell in `id` as engine `e` learned it from u's BELL rows (§11.13): the latest row of u's lane in the current
 * epoch, else in the newest earlier held epoch; what `e` rings for u, and, for e's own user, what it registers.
 */
function bellOf(e: Engine, id: string, u: TestUser): string {
  const c = conv(e, id);
  for (let k = c.current; k >= c.rootE; k--) {
    const ep = c.epochs.get(k);
    const j = ep ? P.memberIndex(ep.D, u.uid) : -1;
    const b = j >= 0 ? ep!.lanes[j].bell : null;
    if (b) return P.b64u(b.bell);
  }
  throw new Error(`no bell of ${u.handle} known in ${id}`);
}

/** `u`'s own bell for generation `g` of the conversation, from its account key alone (§4.1). */
const ownBell = (u: TestUser, convBytes: Uint8Array, g: number): string =>
  P.b64u(P.bellOf(P.bellSecret(P.bellKey(u.AK), convBytes, g)));

/** The bells last registered for the device's endpoint. */
const registered = (d: FakePushDevice): string[] =>
  [...(server().push.subs.get(d.endpoint) ?? [])].sort();

/** Waits until the device's registration equals `bells` (re-sends are batched over Δ). */
async function registeredAs(d: FakePushDevice, bells: string[]): Promise<void> {
  const want = [...bells].sort();
  await waitFor(
    () => JSON.stringify(registered(d)) === JSON.stringify(want),
    `${d.name} registers ${want.length} bells`,
    10_000,
  );
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

const msgKey = (e: Engine, id: string, text: string): string =>
  mustView(e, id).messages.find((m) => m.text === text)!.key;

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
    // Generation 0 (the root epoch) of each: a function of bob's account key and the conversation alone (§4.1).
    expect(bellOf(A, g, bob)).toBe(ownBell(bob, conv(A, g).conv, 0));
    expect(bellOf(A, one, bob)).toBe(ownBell(bob, conv(A, one).conv, 0));
    expect(bellOf(A, g, bob)).not.toBe(bellOf(A, one, bob));
    // The server holds the hashes of the secrets, never a secret: what bob registered hashes to what alice rings.
    const sent = server().push.subsOf(bobDev.endpoint).at(-1)!.tokens;
    expect(sent.map((t) => P.b64u(P.bellOf(P.fromB64u(t)))).sort()).toEqual(registered(bobDev));
    expect(sent).not.toContain(bellOf(A, g, bob));
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
    await settle(A, B); // bob's BELL row reaches alice
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
    expect(bellOf(A, id, bob)).toBe(old); // an addition starts no generation: the bell stays (§4.1)
    await new Promise((r) => setTimeout(r, 1200));
    expect(sends()).toBe(n0);
    await A.removeMember(id, carol.uidB);
    await settle(A, B);
    expect(bellOf(A, id, bob)).not.toBe(old); // a removal starts one: bob posted and registered a new bell
    expect(bellOf(A, id, bob)).toBe(ownBell(bob, conv(A, id).conv, epoch(A, id).e));
    await registeredAs(bobDev, [bellOf(A, id, bob)]);
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
    await settle(A, B);
    await B.setNotifications(true);
    await registeredAs(dev, [bellOf(A, id, bob)]);
    const ep = dev.endpoint;
    const order: string[] = [];
    dev.onUnsubscribe = () => order.push("unsubscribe");
    const before = server().push.calls.length;
    await B.logout();
    await waitFor(
      () => server().push.subsOf(ep).at(-1)?.tokens.length === 0,
      "the empty set",
      10_000,
    );
    order.push(
      ...server()
        .push.calls.slice(before)
        .map((c) => c.kind),
    );
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
    const engines = [
      await engineFor(alice),
      await engineFor(bob),
      await engineFor(carol),
      await engineFor(dave),
    ];
    const [A, B, C, D] = engines;
    const id = await A.createConversation(["bob", "carol", "dave"], "g");
    await settle(...engines);
    for (const e of [B, C, D]) await e.accept(id);
    await settle(...engines);
    const rings = await ringsAfter(() => A.sendText(id, "hello"), engines);
    expect(rings).toHaveLength(1);
    expect([...rings[0].tokens].sort()).toEqual(
      [bellOf(A, id, bob), bellOf(A, id, carol), bellOf(A, id, dave)].sort(),
    );
    expect(rings[0].E).toBe(server().era);
    expect(
      await ringsAfter(() => B.react(id, msgKey(B, id, "hello"), "👍", true), engines),
    ).toEqual([]);
    expect(await ringsAfter(() => D.leave(id), engines)).toEqual([]);
  });

  it("a FILE rings once, as a TEXT does", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const engines = [await engineFor(alice), await engineFor(bob)];
    const [A, B] = engines;
    const id = await A.createConversation(["bob"]);
    await settle(...engines);
    await B.accept(id);
    await settle(...engines);
    const file = new File([P.utf8("notes") as BlobPart], "notes.txt", { type: "text/plain" });
    const rings = await ringsAfter(() => A.sendFile(id, file), engines);
    expect(rings).toHaveLength(1);
    expect([...rings[0].tokens]).toEqual([bellOf(A, id, bob)]);
  });

  it("a removal starts a generation: a TEXT rings the new bells of the members who posted them and the old bell of one whose devices are closed; an addition changes no bell", async () => {
    const [alice, bob, carol, dave, erin] = ["alice", "bob", "carol", "dave", "erin"].map((h) =>
      makeUser(h),
    );
    const [A, B, C, D] = [
      await engineFor(alice),
      await engineFor(bob),
      await engineFor(carol),
      await engineFor(dave),
    ];
    const id = await A.createConversation(["bob", "carol", "dave"], "g");
    await settle(A, B, C, D);
    for (const e of [B, C, D]) await e.accept(id);
    await settle(A, B, C, D);
    const oldBob = bellOf(A, id, bob);
    const oldCarol = bellOf(A, id, carol);
    await C.logout(); // carol's only device is closed from now on
    await A.removeMember(id, dave.uidB);
    await settle(A, B);
    const e1 = epoch(A, id).e;
    const newBob = bellOf(A, id, bob);
    expect(newBob).not.toBe(oldBob);
    expect(newBob).toBe(ownBell(bob, conv(A, id).conv, e1)); // generation = the epoch of the removal
    // carol's old bell, which the removed member knows, is rung while she has posted none in the new generation
    let [r] = await ringsAfter(() => A.sendText(id, "one"), [A, B]);
    expect([...r.tokens].sort()).toEqual([newBob, oldCarol].sort());
    // carol opens a device: it posts her new bell, and the old one is rung no more
    const C2 = await engineFor(carol);
    await settle(A, B, C2);
    const newCarol = bellOf(A, id, carol);
    expect(newCarol).not.toBe(oldCarol);
    expect(newCarol).toBe(bellOf(C2, id, carol));
    [r] = await ringsAfter(() => A.sendText(id, "two"), [A, B, C2]);
    expect([...r.tokens].sort()).toEqual([newBob, newCarol].sort());
    // an addition changes nobody's bell, and the new member's bell joins the ring once she posted it
    const E = await engineFor(erin);
    await A.addMembers(id, ["erin"]);
    await settle(A, B, C2, E);
    await E.accept(id);
    await settle(A, B, C2, E);
    expect(epoch(A, id).e).toBe(e1 + 1);
    expect(bellOf(A, id, bob)).toBe(newBob);
    expect(bellOf(A, id, carol)).toBe(newCarol);
    [r] = await ringsAfter(() => A.sendText(id, "three"), [A, B, C2, E]);
    expect([...r.tokens].sort()).toEqual([newBob, newCarol, bellOf(A, id, erin)].sort());
    expect(bellOf(A, id, erin)).toBe(ownBell(erin, conv(A, id).conv, e1 + 1)); // her generation: her root epoch
  });

  it("a restore keeps the bells it knew (BELLS beside HEADS, §7.3): the new device rings them without re-reading the rows", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const [A, B, C] = [await engineFor(alice), await engineFor(bob), await engineFor(carol)];
    const id = await A.createConversation(["bob", "carol"], "g");
    await settle(A, B, C);
    for (const e of [B, C]) await e.accept(id);
    await settle(A, B, C);
    const bells = [bellOf(A, id, bob), bellOf(A, id, carol)].sort();
    // Many rows after the BELL rows, so that a restore's history never reaches them.
    for (let i = 0; i < 40; i++) await B.sendText(id, `row ${i}`);
    await settle(A, B, C);
    await I(A).catchUp(); // a HEADS row with the BELLS record
    await settle(A, B, C);
    await A.logout();
    const A2 = await engineFor(alice);
    await settle(A2, B, C);
    expect(chat(A2, id)).not.toContain("row 0");
    expect([bellOf(A2, id, bob), bellOf(A2, id, carol)].sort()).toEqual(bells);
    const [r] = await ringsAfter(() => A2.sendText(id, "after the restore"), [A2, B, C]);
    expect([...r.tokens].sort()).toEqual(bells);
    // Its own bell too: the restored device holds the generation it had posted (seeded from the record, so it posts
    // no second row), and registers that bell.
    const ep2 = epoch(A2, id);
    expect(ep2.lanes[ep2.myIndex].bell).toMatchObject({ seeded: true });
    expect(bellOf(A2, id, alice)).toBe(bellOf(B, id, alice));
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

describe("previews (§11.13)", () => {
  const ORIGIN = "https://segv.test";
  const pushOf = (bells: string[]): Proposed => ({
    title: "segv.sh",
    body: "new messages",
    tag: "segv",
    navigate: `${ORIGIN}/`,
    bells,
  });

  it("the cache names each registered copy, and the worker reads, verifies and previews the newest message", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const bobDev = new FakePushDevice("bob");
    const n = notifyOf();
    const A = await engineFor(alice);
    const B = await engineFor(bob, { ...bobDev.options, notify: n });
    const one = await A.createConversation(["bob"]);
    await settle(A, B);
    await B.accept(one);
    await B.setNotifications(true);
    // Not kept on this device: no preview to choose.
    expect(B.getState().preview).toBe("unavailable");
    (B as unknown as { remembered: boolean }).remembered = true;
    await B.setPreview("message");
    expect(B.getState().preview).toBe("message");
    await settle(A, B);
    let cache = await readCache(n.store);
    await waitFor(
      () => (void readCache(n.store).then((c) => (cache = c)), cache !== null),
      "cache written",
    );
    const bell = bellOf(A, one, bob);
    const ref = mustView(B, one).ref;
    expect(cache!.preview).toBe("message");
    expect(cache!.copies.map((c) => [c.bell, c.ref, c.name])).toEqual([[bell, ref, "@alice"]]);
    const ep = cache!.copies[0].epoch!;
    expect(ep.members.map((m) => m.handle)).toEqual(mustView(B, one).members.map((m) => m.handle));

    // The device is closed now: its cache stays as it was while alice writes.
    const frozen = cache;
    await A.sendText(one, "hello bob");
    await settle(A, B);
    const deps = {
      ...browserDeps(ORIGIN, { fetch: server().fetchAs("bob-sw"), store: null }),
      readCache: async () => frozen,
    };
    const moves: unknown[] = [];
    deps.advance = async (m) => void moves.push(m);
    expect(await notesFor(pushOf([bell]), deps, Infinity)).toEqual([
      { title: "@alice", body: "@alice: hello bob", tag: ref, navigate: `${ORIGIN}/#c/${ref}` },
    ]);
    expect(moves).toHaveLength(1);
    // The device is open instead: it read the row and moved its cache past it before the push came. The worker still
    // previews the row, which was stored moments ago.
    let open: Awaited<ReturnType<typeof readCache>> = null;
    await waitFor(
      () => (
        void readCache(n.store).then((c) => (open = c)),
        open?.copies[0].epoch?.next.some((s, j) => j !== open!.copies[0].epoch!.self && s.n > 0) ??
          false
      ),
      "cache moved past alice's row",
    );
    const openDeps = {
      ...browserDeps(ORIGIN, { fetch: server().fetchAs("bob-sw"), store: null }),
      readCache: async () => open,
      advance: async () => {},
      now: () => server().now(),
    };
    expect(await notesFor(pushOf([bell]), openDeps, Infinity)).toEqual([
      { title: "@alice", body: "@alice: hello bob", tag: ref, navigate: `${ORIGIN}/#c/${ref}` },
    ]);
    // A bell this device never registered names nothing.
    expect(await notesFor(pushOf([bellOf(A, one, alice)]), deps, Infinity)).toEqual([
      { title: "segv.sh", body: "new messages", tag: "segv", navigate: `${ORIGIN}/` },
    ]);

    // `none` deletes the cache; so does turning notifications off.
    await B.setPreview("none");
    expect(await readCache(n.store)).toBeNull();
    await B.setPreview("name");
    await waitFor(() => n.store.box !== null, "cache written again");
    expect((await readCache(n.store))!.copies[0].epoch).toBeUndefined();
    await B.setNotifications(false);
    expect(await readCache(n.store)).toBeNull();
    expect(B.getState().preview).toBe("name");
    // Logout forgets the choice too, so the next account starts with `none`.
    await B.logout();
    expect(n.preview.load()).toBe("none");
  });

  it("a choice of `none` made while a cache write is in flight leaves no cache", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const bobDev = new FakePushDevice("bob");
    const n = notifyOf();
    const A = await engineFor(alice);
    const B = await engineFor(bob, { ...bobDev.options, notify: n });
    const one = await A.createConversation(["bob"]);
    await settle(A, B);
    await B.accept(one);
    await B.setNotifications(true);
    (B as unknown as { remembered: boolean }).remembered = true;
    await B.setPreview("message");
    await waitFor(() => n.store.box !== null, "cache written");
    // The next write (the switch to `name`) stops just before it stores its box.
    let open = () => {};
    n.store.holdWrite = new Promise<void>((r) => (open = r));
    const reached = new Promise<void>((r) => (n.store.onHeld = r));
    await B.setPreview("name");
    await reached;
    const none = B.setPreview("none");
    open();
    await none;
    await settle(A, B);
    expect([n.store.key, n.store.box]).toEqual([null, null]);
    expect(B.getState().preview).toBe("none");
  });

  it("a downgrade from `message` deletes the old cache before it is reported", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const bobDev = new FakePushDevice("bob");
    const n = notifyOf();
    const A = await engineFor(alice);
    const B = await engineFor(bob, { ...bobDev.options, notify: n });
    const one = await A.createConversation(["bob"]);
    await settle(A, B);
    await B.accept(one);
    await B.setNotifications(true);
    (B as unknown as { remembered: boolean }).remembered = true;
    await B.setPreview("message");
    await waitFor(() => n.store.box !== null, "cache written");
    expect((await readCache(n.store))!.copies[0].epoch).toBeDefined();
    await B.setPreview("name");
    // Once the change is reported no message data is stored, whether or not the `name` cache has been written yet: a
    // page that closes now leaves none behind.
    const after = await readCache(n.store);
    expect(after === null || after.copies.every((c) => c.epoch === undefined)).toBe(true);
    await waitFor(() => n.store.box !== null, "the name cache");
    expect((await readCache(n.store))!.copies.map((c) => c.epoch)).toEqual([undefined]);
  });
});

describe("seen elsewhere (§11.13)", () => {
  /** A device's quiet setting (in memory, on by default) and whether it is in use. */
  function quietOf(inUse: () => boolean) {
    let on = true;
    return { store: { load: () => on, save: (x: boolean) => void (on = x) }, inUse };
  }
  const tagOf = (u: TestUser): string => P.b64u(P.quietTag(P.quietSecret(u.AK)));

  /** alice and bob in an accepted 1:1; bob has a phone with notifications on and a desktop without. */
  async function setup() {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const phone = new FakePushDevice("bob-phone");
    const use = { desktop: true };
    const desk = quietOf(() => use.desktop);
    const A = await engineFor(alice);
    const Bp = await engineFor(bob, phone.options);
    const Bd = await engineFor(bob, { quiet: desk });
    await Bp.setNotifications(true);
    const id = await A.createConversation(["bob"]);
    await settle(A, Bp, Bd);
    await Bd.accept(id);
    await settle(A, Bp, Bd);
    await registeredAs(phone, [bellOf(A, id, bob)]);
    const pushes = () => server().push.pushes.filter((p) => p.endpoint === phone.endpoint).length;
    return { alice, bob, phone, use, desk, A, Bp, Bd, id, pushes };
  }

  it("every device registers the account's quiet tag; a device without notifications offers the setting, on by default", async () => {
    const x = await setup();
    const phone2 = new FakePushDevice("bob-tablet");
    const Bt = await engineFor(x.bob, phone2.options);
    await Bt.setNotifications(true);
    await settle(x.A, x.Bp, x.Bd, Bt);
    expect(server().push.subsOf(x.phone.endpoint).at(-1)!.quiet).toBe(tagOf(x.bob));
    expect(server().push.subsOf(phone2.endpoint).at(-1)!.quiet).toBe(tagOf(x.bob));
    expect(tagOf(x.bob)).not.toBe(tagOf(x.alice));
    expect(x.Bd.getState()).toMatchObject({ notifications: "unavailable", quiet: "on" });
  });

  it("a device in use marks the rows of others that it shows, and the account's phone gets no push for them", async () => {
    const x = await setup();
    server().push.holdMs = 2_000;
    await x.A.sendText(x.id, "are you there?");
    await settle(x.A, x.Bp, x.Bd);
    await waitFor(() => server().push.seens().length === 1, "one mark", 5_000);
    const [mark] = server().push.seens();
    expect(mark.quiet).toBe(tagOf(x.bob));
    const row = server().push.rings().at(-1)!;
    expect(mark.rows).toEqual([{ E: row.E, label: row.label }]);
    await new Promise((r) => setTimeout(r, 2_500)); // past the hold
    expect(x.pushes()).toBe(0);
    expect(chat(x.Bp, x.id)).toContain("alice: are you there?");
    // bob's own message is never marked (it rings nobody of his).
    await x.Bd.sendText(x.id, "yes");
    await settle(x.A, x.Bp, x.Bd);
    await new Promise((r) => setTimeout(r, 50));
    expect(server().push.seens()).toHaveLength(1);
  });

  it("a device not in use, or whose setting is off, marks nothing, and the phone is notified", async () => {
    const x = await setup();
    server().push.holdMs = 200;
    x.use.desktop = false;
    await x.A.sendText(x.id, "one");
    await settle(x.A, x.Bp, x.Bd);
    await waitFor(() => x.pushes() === 1, "a push", 5_000);
    x.use.desktop = true;
    await x.Bd.setQuiet(false);
    expect(x.Bd.getState().quiet).toBe("off");
    await x.A.sendText(x.id, "two");
    await settle(x.A, x.Bp, x.Bd);
    await waitFor(() => x.pushes() === 2, "a second push", 5_000);
    expect(server().push.seens()).toHaveLength(0);
    await x.Bd.setQuiet(true);
    expect(x.Bd.getState().quiet).toBe("on");
  });

  it("rows applied at a restore are never marked", async () => {
    const x = await setup();
    x.use.desktop = false;
    await x.A.sendText(x.id, "while you were away");
    await settle(x.A, x.Bp, x.Bd);
    const Bn = await engineFor(x.bob, { quiet: quietOf(() => true) });
    await settle(x.A, x.Bp, x.Bd, Bn);
    expect(chat(Bn, x.id)).toContain("alice: while you were away");
    await new Promise((r) => setTimeout(r, 50));
    expect(server().push.seens()).toHaveLength(0);
  });
});
