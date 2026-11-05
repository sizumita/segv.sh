// Aliases, the temporary handles (docs/PROTOCOL.md §2.6, §11.1 step 5, §11.11, §11.13): an alias is an account derived
// from the owner's AK, registered without wraps under a handle derived from its keys, listed in the owner's alias table
// (PREFS key 1 of the owner's self lane), and run by the owner's devices as an account of its own.
import { resolveObjectURL } from "node:buffer";
import { describe, expect, it, vi } from "vite-plus/test";
import {
  ALIAS_CREATE_FAILED,
  ALIAS_HANDLE_RESERVED,
  aliasKeys,
  registerAccount,
  type AliasKeys,
} from "../src/accounts";
import type { Api } from "../src/api";
import type { Epoch } from "../src/conv";
import {
  ALIASES_NOT_RUN,
  ALIAS_NOT_LISTED,
  TOO_MANY_ALIASES,
  type EngineOptions,
} from "../src/engine";
import { Messaging } from "../src/messaging";
import type { Engine } from "../src/types";
import {
  FakePushDevice,
  I,
  P,
  buildMessage,
  chat,
  commitChange,
  engineFor,
  epoch,
  freshWorldPerTest,
  makeUser,
  mustView,
  newEngine,
  postRow,
  readableWith,
  selfRowsOf,
  server,
  settle,
  sleep,
  viewsOf,
  waitFor,
  writeSelfRow,
  type TestUser,
} from "./harness";

// The canvas re-encoder (packages/engine/src/image.ts) needs a DOM: a pass-through, as in images.spec.ts.
vi.mock("../src/image", () => ({
  prepareImage: async (file: Blob) => ({
    bytes: new Uint8Array(await file.arrayBuffer()),
    mime: "image/webp" as const,
    w: 4,
    h: 3,
  }),
}));

freshWorldPerTest({ push: true });

const handleOf = (k: AliasKeys, c = 0): string => P.aliasHandle(k.uid, k.id.sigPk, k.id.kemPk, c);

/** Alias i of `u` as a test user (its derived keys), for the harness's readers. */
function aliasUser(u: TestUser, i: number, c = 0): TestUser {
  const k = aliasKeys(u.AK, i);
  const code = new Uint8Array(20);
  return {
    handle: handleOf(k, c),
    AK: k.AK,
    uid: k.uid,
    uidB: k.uidB,
    id: k.id,
    code,
    rk: P.recoveryKem(code),
  };
}

/** The PREFS records of key 1 (the alias table, §2.6) on `u`'s self lane, in lane order. */
const tableRows = (u: TestUser): P.SelfRecord[] =>
  selfRowsOf(u)
    .flat()
    .filter((r) => r.rtype === P.RT.PREFS && r.key === P.PREFS_ALIASES);

/** `u`'s alias table as its self lane holds it now. */
function tableOf(u: TestUser): P.AliasEntry[] {
  const last = tableRows(u).at(-1);
  const t = last && last.rtype === P.RT.PREFS ? P.parseAliasTable(last.value) : [];
  return t.map(({ c, retired }) => ({ c, retired }));
}

/**
 * Registers alias i of `u` directly in the directory with handle counter c, as a device whose creation stopped
 * before it wrote that c into the table would have.
 */
function registerDirect(u: TestUser, i: number, c = 0): void {
  const k = aliasKeys(u.AK, i);
  const { bundle, sig } = P.makeBundle(k.uid, handleOf(k, c), k.id, 4242 + i);
  const r = server().dir.register({ bundle, sig, wraps: [] });
  if (r.status !== 200) throw new Error(`register alias ${i}: ${JSON.stringify(r.json)}`);
}

/** Registers the uid of alias i of `u` with keys that are not its own: a directory entry that does not check (§2.6). */
function registerForeign(u: TestUser, i: number): void {
  const uid = P.aliasUid(P.aliasKey(u.AK, i));
  const id = P.deriveIdentity(P.random(32));
  const { bundle, sig } = P.makeBundle(uid, P.aliasHandle(uid, id.sigPk, id.kemPk, 0), id, 77 + i);
  const r = server().dir.register({ bundle, sig, wraps: [] });
  if (r.status !== 200) throw new Error(`register foreign ${i}: ${JSON.stringify(r.json)}`);
}

/** A self row of `u` that writes its alias table (§2.6), as another device of the owner would. */
const writeTable = (u: TestUser, t: P.AliasEntry[]) =>
  writeSelfRow(u, [{ rtype: P.RT.PREFS, key: P.PREFS_ALIASES, value: P.encodeAliasTable(t) }]);

const viewsAs = (e: Engine, uid: string) => viewsOf(e).filter((v) => v.as === uid);
const aliasesOf = (e: Engine) =>
  I(e)
    .identities()
    .filter((x) => x.alias);

/** The register requests of the engine that sends as `who`. */
const registers = (who: string) =>
  server().requests.filter((r) => r.who === who && r.path === "/api/v2/register").length;

/** The uids that the engine sending as `who` looked up exactly (`GET /api/v2/dir/uid/{uid}`), in order. */
const uidLookups = (who: string) =>
  server()
    .requests.filter((r) => r.who === who && r.path.startsWith("/api/v2/dir/uid/"))
    .map((r) => r.path.slice("/api/v2/dir/uid/".length));

/** Another device of `u` whose requests carry `who`, unlocked and restored. */
async function deviceOf(u: TestUser, who: string, opts: EngineOptions = {}): Promise<Engine> {
  const e = newEngine(who, opts);
  await I(e).unlock(u.AK, u.uid, u.handle);
  await waitFor(() => !e.getState().syncing, `${who} restore`);
  await settle(e);
  return e;
}

/** The b64u bell of `u`'s alias i in a conversation, for generation g (§4.1, §11.13). */
const aliasBell = (u: TestUser, i: number, conv: Uint8Array, g = 0): string =>
  P.b64u(P.bellOf(P.bellSecret(P.bellKey(P.aliasKey(u.AK, i)), conv, g)));

/** The current epoch of a copy of alias 0, by its view id (white-box). */
function aliasEpoch(e: Engine, id: string): Epoch {
  const c = I(e).aliasRun(0)!.msg!.copies.get(id.slice("@0/".length))!;
  return c.epochs.get(c.current)!;
}

/** The row types on member `uid`'s own lane in an epoch, as the shard holds them. */
function laneTypes(ep: Epoch, uid: Uint8Array): number[] {
  const j = P.memberIndex(ep.D, uid);
  return readableWith(ep.keys.mk)
    .filter((m) => m.from === j && m.lane === j)
    .map((m) => m.type);
}

/** A device's "quiet my other devices" setting in memory, and whether it is in use (§11.13). */
function quietOf(inUse: () => boolean): NonNullable<EngineOptions["quiet"]> {
  let on = true;
  return { store: { load: () => on, save: (x: boolean) => void (on = x) }, inUse };
}

/** alice and bob, each with an engine (alice's built with `aOpts`); alice's first alias created. */
async function withAlias(aOpts: EngineOptions = {}) {
  const alice = makeUser("alice");
  const bob = makeUser("bob");
  const A = await engineFor(alice, aOpts);
  const B = await engineFor(bob);
  const uid = await A.createAlias();
  await settle(A, B);
  const k = aliasKeys(alice.AK, 0);
  return { alice, bob, A, B, uid, k, h: handleOf(k) };
}

describe('creating an alias (§2.6 "Creating")', () => {
  it("registers index 0 without wraps under its derived handle, records it in the owner's table, and runs it", async () => {
    const alice = makeUser("alice");
    const A = await engineFor(alice);
    const uid = await A.createAlias();
    await settle(A);
    const k = aliasKeys(alice.AK, 0);
    expect(uid).toBe(k.uidB);
    const row = server().dir.byUid(k.uidB)!;
    expect(row.handle).toBe(handleOf(k));
    expect(row.handle).toMatch(P.ALIAS_HANDLE_RE);
    expect(server().dir.wraps.filter((w) => w.uid === k.uidB)).toHaveLength(0);
    // its bundle names nothing of the owner, and carries no clock of the device (a random ts, §2.6 "Bundle")
    expect(row.bundle).not.toContain(alice.uidB);
    expect(row.bundle).not.toContain("alice");
    expect(tableOf(alice)).toEqual([{ c: 0, retired: false }]);
    expect(
      I(A)
        .identities()
        .map((x) => [x.alias, x.index, x.handle, x.retired, x.status]),
    ).toEqual([
      [false, -1, "alice", false, "ready"],
      [true, 0, handleOf(k), false, "ready"],
    ]);
    expect(I(A).identities()[1].fingerprint).toBe(P.fingerprint(k.uid, k.id.sigPk, k.id.kemPk));
    // the alias's first self row is its registration HEADS (§11.1), under its own keys
    const first = selfRowsOf(aliasUser(alice, 0))[0];
    expect(first.map((r) => r.rtype)).toEqual([P.RT.HEADS]);
    await waitFor(() => !A.getState().syncing, "syncing done");
    // a second one takes index 1
    const uid1 = await A.createAlias();
    expect(uid1).toBe(aliasKeys(alice.AK, 1).uidB);
    expect(tableOf(alice)).toEqual([
      { c: 0, retired: false },
      { c: 0, retired: false },
    ]);
  });

  it("moves to the next c when the handle is taken, and fails after c = 3", async () => {
    const alice = makeUser("alice");
    const k = aliasKeys(alice.AK, 0);
    server().dir.squat(handleOf(k, 0));
    const A = await engineFor(alice);
    const uid = await A.createAlias();
    await settle(A);
    expect(uid).toBe(k.uidB);
    expect(server().dir.byUid(k.uidB)!.handle).toBe(handleOf(k, 1));
    expect(tableOf(alice)).toEqual([{ c: 1, retired: false }]);
    expect(aliasesOf(A).map((x) => [x.handle, x.status])).toEqual([[handleOf(k, 1), "ready"]]);

    // every c taken: the creation fails, and leaves its entry retired, so that no device runs it unregistered
    const carol = makeUser("carol");
    const kc = aliasKeys(carol.AK, 0);
    for (let c = 0; c < P.ALIAS_TRIES; c++) server().dir.squat(handleOf(kc, c));
    const C = await engineFor(carol);
    await expect(C.createAlias()).rejects.toThrow(ALIAS_CREATE_FAILED);
    await settle(C);
    expect(server().dir.byUid(kc.uidB)).toBeNull();
    expect(tableOf(carol)).toEqual([{ c: 3, retired: true }]);
    expect(aliasesOf(C).map((x) => [x.uid, x.retired, x.status])).toEqual([
      [kc.uidB, true, "retired"],
    ]);
    expect(I(C).aliasRun(0)).toBeUndefined();
    expect(registers("carol")).toBe(P.ALIAS_TRIES);
    // brought back, a device runs it, which registers it: no handle is free, so it is not run, with the warning
    await C.setAliasRetired(kc.uidB, false);
    await settle(C);
    expect(aliasesOf(C).map((x) => [x.retired, x.status])).toEqual([[false, "failed"]]);
    await waitFor(() => C.getState().warnings.includes(ALIAS_NOT_LISTED), "critical warning");
    expect(server().dir.byUid(kc.uidB)).toBeNull();
  });

  it("two devices creating at once end with two distinct aliases, each recorded once and run on both", async () => {
    const alice = makeUser("alice");
    const A1 = await engineFor(alice);
    const A2 = await engineFor(alice);
    const [u1, u2] = await Promise.all([A1.createAlias(), A2.createAlias()]);
    await settle(A1, A2);
    expect(u1).not.toBe(u2);
    const want = [0, 1].map((i) => aliasKeys(alice.AK, i).uidB);
    expect([u1, u2].sort()).toEqual([...want].sort());
    expect(tableOf(alice)).toEqual([
      { c: 0, retired: false },
      { c: 0, retired: false },
    ]);
    for (const e of [A1, A2])
      expect(aliasesOf(e).map((x) => [x.uid, x.status])).toEqual([
        [want[0], "ready"],
        [want[1], "ready"],
      ]);
  });

  it("refuses beyond 16 live aliases (§2.6), and a device that sees more runs the newest 16", async () => {
    const alice = makeUser("alice");
    // a table of 17 live aliases whose uids are registered with keys not their own: none checks, none is fatal
    for (let i = 0; i < 17; i++) registerForeign(alice, i);
    writeTable(
      alice,
      Array.from({ length: 17 }, () => ({ c: 0, retired: false })),
    );
    const A = await engineFor(alice);
    expect(A.getState().phase).toBe("ready");
    const ids = aliasesOf(A);
    expect(ids).toHaveLength(17);
    // the lowest index is idle (live, not run here); the 16 newest failed their directory check
    expect(ids.map((x) => x.status)).toEqual(["idle", ...Array<string>(16).fill("failed")]);
    expect(I(A).aliasRun(0)).toBeUndefined();
    expect(I(A).aliasRun(16)?.status).toBe("failed");
    await waitFor(() => A.getState().warnings.includes(ALIAS_NOT_LISTED), "critical warning");
    expect(A.getState().warnings.some((w) => w.startsWith(ALIASES_NOT_RUN))).toBe(true);
    await expect(A.createAlias()).rejects.toThrow(TOO_MANY_ALIASES);
    // a registered entry with other keys is never registered over (§2.6)
    expect(registers("alice")).toBe(0);
  });

  it("a chosen handle never starts with _ (§2.5 step 1)", async () => {
    const pk = {
      platform: { create: () => Promise.reject(new Error("never reached")) },
      rpId: "x",
    } as unknown as Parameters<typeof registerAccount>[1];
    await expect(registerAccount(null as unknown as Api, pk, "_abc", () => {})).rejects.toThrow(
      ALIAS_HANDLE_RESERVED,
    );
    await expect(
      registerAccount(null as unknown as Api, pk, "@_k7m2_q9x4", () => {}),
    ).rejects.toThrow(ALIAS_HANDLE_RESERVED);
  });
});

describe('running aliases (§2.6 "Running aliases")', () => {
  it("a creation that stopped after its table write is registered by the next device that runs it; no restore looks up an unused index", async () => {
    const alice = makeUser("alice");
    const k = aliasKeys(alice.AK, 0);
    const A1 = await deviceOf(alice, "alice1");
    // another device wrote the table, then stopped before its register request
    writeTable(alice, [{ c: 0, retired: false }]);
    await settle(A1);
    await waitFor(() => aliasesOf(A1)[0]?.status === "ready", "the alias runs");
    expect(server().dir.byUid(k.uidB)!.handle).toBe(handleOf(k));
    expect(server().dir.wraps.filter((w) => w.uid === k.uidB)).toHaveLength(0);
    expect(registers("alice1")).toBe(1);
    // its own register request got the 200: its first self row is the registration HEADS (§11.1)
    expect(selfRowsOf(aliasUser(alice, 0))[0].map((r) => r.rtype)).toEqual([P.RT.HEADS]);
    expect(tableRows(alice)).toHaveLength(1);
    // a reload, or the next device: the entry checks, nothing is registered, and nothing else is looked up
    const A2 = await deviceOf(alice, "alice2");
    await settle(A1, A2);
    expect(aliasesOf(A2).map((x) => [x.handle, x.status])).toEqual([[handleOf(k), "ready"]]);
    expect(registers("alice2")).toBe(0);
    expect(uidLookups("alice2")).toEqual([alice.uidB, k.uidB]);
    expect(new Set(uidLookups("alice1"))).toEqual(new Set([alice.uidB, k.uidB]));
    // without a table, a restore looks up its own uid only
    const bob = makeUser("bob");
    await deviceOf(bob, "bob1");
    expect(uidLookups("bob1")).toEqual([bob.uidB]);
  });

  it("each live alias restores alongside the owner's §11.4 steps 5–11, not after them (§11.1 step 5)", async () => {
    const { alice, A } = await withAlias();
    // the owner's steps 5–11 (Messaging.restore) wait on the next device until released
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const restore = Messaging.prototype.restore;
    const spy = vi.spyOn(Messaging.prototype, "restore").mockImplementation(async function (
      this: Messaging,
    ) {
      if (!(this as unknown as { h: { alias?: boolean } }).h.alias) await gate;
      return restore.call(this);
    });
    try {
      const A2 = newEngine("alice2");
      await I(A2).unlock(alice.AK, alice.uid, "alice");
      await waitFor(() => I(A2).identities()[1]?.status === "ready", "the alias runs");
      expect(I(A2).identities()[0].status).toBe("starting");
      expect(A2.getState().syncing).toBe(true);
      release();
      await waitFor(() => !A2.getState().syncing, "alice2's restore");
      await settle(A, A2);
      expect(
        I(A2)
          .identities()
          .map((x) => x.status),
      ).toEqual(["ready", "ready"]);
    } finally {
      release();
      spy.mockRestore();
    }
  });

  it("a handle registered with another c is written into the table, by a run and by a creation", async () => {
    const alice = makeUser("alice");
    const k0 = aliasKeys(alice.AK, 0);
    // a creation that registered alias 0 with c = 2, and stopped before it wrote that c
    registerDirect(alice, 0, 2);
    writeTable(alice, [{ c: 0, retired: false }]);
    const A = await engineFor(alice);
    await settle(A);
    expect(tableOf(alice)).toEqual([{ c: 2, retired: false }]);
    expect(aliasesOf(A).map((x) => [x.handle, x.status])).toEqual([[handleOf(k0, 2), "ready"]]);
    expect(registers("alice")).toBe(0);
    // a creation whose register request meets the registration of another device, with another c
    registerDirect(alice, 1, 1);
    const uid1 = await A.createAlias();
    await settle(A);
    expect(uid1).toBe(aliasKeys(alice.AK, 1).uidB);
    expect(tableOf(alice)).toEqual([
      { c: 2, retired: false },
      { c: 1, retired: false },
    ]);
    expect(aliasesOf(A).map((x) => [x.handle, x.status])).toEqual([
      [handleOf(k0, 2), "ready"],
      [handleOf(aliasKeys(alice.AK, 1), 1), "ready"],
    ]);
  });
});

describe("an alias's conversations (§2.6)", () => {
  it("bob sees only the alias: its handle, keys and lane, never the owner's; his reply reaches the alias's copy", async () => {
    const { alice, B, A, uid, h } = await withAlias();
    const id = await A.createConversation(["bob"], undefined, uid);
    expect(id.startsWith("@0/")).toBe(true);
    expect(mustView(A, id).as).toBe(uid);
    await settle(A, B);
    const [bv] = viewsOf(B);
    expect(bv.request).toBe(true); // the alias is nobody's contact
    await B.accept(bv.id);
    await A.sendText(id, "hello from the alias");
    await settle(A, B);
    await B.sendText(bv.id, "hi alias");
    await settle(A, B);
    expect(chat(A, id)).toEqual([`${h}: hello from the alias`, "bob: hi alias"]);
    expect(chat(B, bv.id)).toEqual([`${h}: hello from the alias`, "bob: hi alias"]);
    const v = mustView(B, bv.id);
    expect(v.members.map((m) => m.handle).sort()).toEqual(["bob", h].sort());
    expect(v.members.some((m) => m.uid === alice.uidB || m.handle === "alice")).toBe(false);
    const ep = epoch(B, bv.id);
    expect(P.b64u(ep.D.by)).toBe(uid);
    for (const m of ep.D.members) {
      expect(P.equalBytes(m.uid, alice.uid)).toBe(false);
      expect(P.equalBytes(m.sigPk, alice.id.sigPk)).toBe(false);
    }
    for (const msg of readableWith(ep.keys.mk))
      if (msg.from < ep.D.members.length)
        expect(P.equalBytes(ep.D.members[msg.from].uid, alice.uid)).toBe(false);
    // the owner's account holds no copy of it
    expect(viewsAs(A, alice.uidB)).toHaveLength(0);
  });

  it("bob invites the alias by handle: a request, though bob is the owner's contact; the owner's copies are unaffected", async () => {
    const { alice, A, B, uid, h } = await withAlias();
    const one = await A.createConversation(["bob"]);
    await settle(A, B);
    await B.accept(viewsOf(B)[0].id);
    await settle(A, B);
    const before = viewsAs(A, alice.uidB).map((v) => v.id);
    expect(before).toEqual([one]);
    const id2 = await B.createConversation([h]);
    await settle(A, B);
    const mine = viewsAs(A, uid);
    expect(mine).toHaveLength(1);
    expect(mine[0].request).toBe(true);
    expect(mine[0].byContact).toBe(false);
    expect(viewsAs(A, alice.uidB).map((v) => v.id)).toEqual(before);
    await A.accept(mine[0].id);
    await B.sendText(id2, "to the alias");
    await settle(A, B);
    expect(chat(A, mine[0].id)).toEqual(["bob: to the alias"]);
    expect(chat(A, one)).toEqual([]);
  });

  it("a conversation of both the owner and its alias: two views, separate members, each other's rows not unread", async () => {
    const { alice, A, B, uid, h } = await withAlias();
    const id = await B.createConversation(["alice", h], "both");
    await settle(A, B);
    const vs = viewsOf(A).filter((v) => v.name === "# both");
    expect(vs).toHaveLength(2);
    expect(new Set(vs.map((v) => v.id)).size).toBe(2);
    const ownerV = vs.find((v) => v.as === alice.uidB)!;
    const aliasV = vs.find((v) => v.as === uid)!;
    expect(ownerV).toBeDefined();
    expect(aliasV).toBeDefined();
    expect(ownerV.ref).not.toBe(aliasV.ref);
    for (const v of vs) {
      await A.accept(v.id);
      A.markRead(v.id);
    }
    await settle(A, B);
    expect(vs.map((v) => mustView(A, v.id).unread)).toEqual([0, 0]);
    const o = mustView(A, ownerV.id);
    const a = mustView(A, aliasV.id);
    expect(o.members.find((m) => m.uid === alice.uidB)).toMatchObject({ you: true, own: false });
    expect(o.members.find((m) => m.uid === uid)).toMatchObject({
      you: false,
      own: true,
      handle: h,
    });
    expect(a.members.find((m) => m.uid === uid)).toMatchObject({ you: true, own: false });
    expect(a.members.find((m) => m.uid === alice.uidB)).toMatchObject({
      you: false,
      own: true,
      handle: "alice",
    });
    await A.sendText(aliasV.id, "from the alias");
    await settle(A, B);
    const rings = server().push.rings().length;
    await A.sendText(ownerV.id, "from the owner");
    await settle(A, B);
    const m = mustView(A, aliasV.id).messages.find((x) => x.text === "from the owner")!;
    expect(m).toMatchObject({ mine: false, from: alice.uidB, fromHandle: "alice" });
    const n = mustView(A, ownerV.id).messages.find((x) => x.text === "from the alias")!;
    expect(n).toMatchObject({ mine: false, from: uid, fromHandle: h });
    // another of the user's accounts counts as self: no unread, and its bell is never rung (§2.6, §11.13)
    expect(mustView(A, aliasV.id).unread).toBe(0);
    expect(mustView(A, ownerV.id).unread).toBe(0);
    const aliasBell = P.b64u(
      P.bellOf(P.bellSecret(P.bellKey(aliasUser(alice, 0).AK), epoch(B, id).D.conv, 0)),
    );
    const after = server().push.rings().slice(rings);
    expect(after.length).toBeGreaterThan(0);
    for (const r of after) expect(r.tokens).not.toContain(aliasBell);
    expect(chat(B, id)).toEqual([`${h}: from the alias`, "alice: from the owner"]);
    // both posted their BELL rows on their own lanes
    const ep = epoch(B, id);
    const belled = new Set(
      readableWith(ep.keys.mk)
        .filter((x) => x.type === P.MT.BELL)
        .map((x) => P.b64u(ep.D.members[x.from].uid)),
    );
    expect(belled.has(alice.uidB)).toBe(true);
    expect(belled.has(uid)).toBe(true);
  });

  it("refuses the handles of the user's own accounts, before any request (§2.6)", async () => {
    const { A, B, uid, h } = await withAlias();
    const dir = () => server().requests.filter((r) => r.path.startsWith("/api/v2/dir/")).length;
    const n = dir();
    await expect(A.createConversation([h])).rejects.toThrow(`@${h} is one of your own handles`);
    await expect(A.createConversation(["alice"], undefined, uid)).rejects.toThrow(
      "@alice is one of your own handles",
    );
    await expect(A.createConversation(["bob", "alice"], undefined, uid)).rejects.toThrow(
      "@alice is one of your own handles",
    );
    expect(dir()).toBe(n);
    // the creating account's own handle is dropped as before
    const id = await A.createConversation([h, "bob"], undefined, uid);
    expect(mustView(A, id).members.map((m) => m.handle)).toEqual([h, "bob"]);
    const mine = await A.createConversation(["bob"]);
    await settle(A, B);
    await expect(A.addMembers(mine, [h])).rejects.toThrow(`@${h} is one of your own handles`);
    // a retired alias's handle too
    await A.setAliasRetired(uid, true);
    await expect(A.createConversation([h])).rejects.toThrow(`@${h} is one of your own handles`);
    await expect(A.createConversation(["bob"], undefined, uid)).rejects.toThrow("retired");
  });

  it("an alias posts its BELL row only with an act of the user's, and writes server time as ts (§2.6)", async () => {
    const { alice, A, B, uid, h } = await withAlias();
    // this device's clock runs 2 minutes ahead of the server's
    I(A).clock.advance(120_000, { mono: false });
    // bob's conversation: accepted, but no BELL row until the alias acts there
    const bid = await B.createConversation([h]);
    await settle(A, B);
    const [v] = viewsAs(A, uid);
    await A.accept(v.id);
    await settle(A, B);
    const bep = epoch(B, bid);
    const mine = P.memberIndex(bep.D, P.fromB64u(uid));
    const lane = () => readableWith(bep.keys.mk).filter((x) => x.from === mine && x.lane === mine);
    expect(lane()).toEqual([]);
    const now = server().now();
    await A.sendText(v.id, "first");
    await settle(A, B);
    expect(lane().map((x) => x.type)).toEqual([P.MT.BELL, P.MT.TEXT]);
    for (const x of lane()) expect(Math.abs(x.ts - now)).toBeLessThan(30_000);
    // its own creation is its first act there: the BELL row follows it, and D's ts is the server's time too
    const id = await A.createConversation(["bob"], undefined, uid);
    await settle(A, B);
    const run = I(A).aliasRun(0)!;
    const c = run.msg!.copies.get(id.slice("@0/".length))!;
    const ep = c.epochs.get(c.current)!;
    expect(ep.lanes[ep.myIndex].bell).not.toBeNull();
    expect(Math.abs(ep.D.ts - server().now())).toBeLessThan(30_000);
    // the owner keeps its own clock
    const own = await A.createConversation(["bob"]);
    await A.sendText(own, "owner");
    await settle(A, B);
    const oep = epoch(A, own);
    expect(oep.D.ts - server().now()).toBeGreaterThan(60_000);
    const t = readableWith(oep.keys.mk).find((x) => x.type === P.MT.TEXT)!;
    expect(t.ts - server().now()).toBeGreaterThan(60_000);
    void alice;
  });

  it("the push registration set holds the alias's bells under the owner's quiet tag (§11.13)", async () => {
    const alice = makeUser("alice");
    const bob = makeUser("bob");
    const dev = new FakePushDevice("alice");
    const A = await engineFor(alice, dev.options);
    const B = await engineFor(bob);
    const uid = await A.createAlias();
    const id = await A.createConversation(["bob"], undefined, uid);
    await settle(A, B);
    await B.accept(viewsOf(B)[0].id);
    await A.sendText(id, "hi");
    await settle(A, B);
    await A.setNotifications(true);
    await settle(A, B);
    const conv = epoch(B, viewsOf(B)[0].id).D.conv;
    const bell = P.b64u(P.bellOf(P.bellSecret(P.bellKey(aliasUser(alice, 0).AK), conv, 0)));
    await waitFor(
      () =>
        JSON.stringify([...(server().push.subs.get(dev.endpoint) ?? [])]) ===
        JSON.stringify([bell]),
      "the alias's bell registered",
      10_000,
    );
    expect(server().push.quiet.get(dev.endpoint)).toBe(P.b64u(P.quietTag(P.quietSecret(alice.AK))));
    // another device registers only once the owner and the alias have restored: never a set without the alias's
    // bells (§2.6, §11.13), even when notifications are turned on while the alias still restores
    let hold = true;
    server().hooks.fail = (_m, path, who) =>
      hold && who === "alice2" && path === `/api/v2/dir/uid/${uid}` ? "before" : undefined;
    const dev2 = new FakePushDevice("alice2");
    const A2 = newEngine("alice2", dev2.options);
    await I(A2).unlock(alice.AK, alice.uid, "alice");
    await waitFor(() => I(A2).identities()[0]?.status === "ready", "the owner's restore");
    expect(A2.getState().syncing).toBe(true);
    await A2.setNotifications(true);
    expect(
      server()
        .push.subsOf(dev2.endpoint)
        .filter((x) => x.tokens.length > 0),
    ).toEqual([]);
    hold = false;
    await settle(A, A2, B);
    const subs = server().push.subsOf(dev2.endpoint);
    expect(subs.length).toBeGreaterThan(0);
    for (const x of subs)
      expect(x.tokens.map((t) => P.b64u(P.bellOf(P.fromB64u(t))))).toContain(bell);
  });
});

describe("siblings, retiring and bringing back (§2.6)", () => {
  it("a sibling runs an alias that another device created, stops it when retired, and restores it when brought back", async () => {
    const alice = makeUser("alice");
    const bob = makeUser("bob");
    const A1 = await engineFor(alice);
    const A2 = await engineFor(alice);
    const B = await engineFor(bob);
    const uid = await A1.createAlias();
    await settle(A1, A2, B);
    expect(aliasesOf(A2).map((x) => [x.uid, x.status])).toEqual([[uid, "ready"]]);
    const id = await A1.createConversation(["bob"], undefined, uid);
    await settle(A1, A2, B);
    const bv = viewsOf(B)[0].id;
    await B.accept(bv);
    await A1.sendText(id, "one");
    await settle(A1, A2, B);
    expect(viewsAs(A2, uid).map((v) => chat(A2, v.id))).toEqual([
      [`${handleOf(aliasKeys(alice.AK, 0))}: one`],
    ]);

    await A1.setAliasRetired(uid, true);
    await settle(A1, A2, B);
    expect(tableOf(alice)).toEqual([{ c: 0, retired: true }]);
    for (const e of [A1, A2]) {
      expect(aliasesOf(e).map((x) => [x.retired, x.status])).toEqual([[true, "retired"]]);
      expect(viewsAs(e, uid)).toHaveLength(0);
      expect(I(e).aliasRun(0)).toBeUndefined();
    }
    await B.sendText(bv, "anyone?");
    await settle(A1, A2, B);

    await A2.setAliasRetired(uid, false);
    await settle(A1, A2, B);
    expect(tableOf(alice)).toEqual([{ c: 0, retired: false }]);
    for (const e of [A1, A2]) {
      expect(aliasesOf(e).map((x) => x.status)).toEqual(["ready"]);
      const [v] = viewsAs(e, uid);
      expect(chat(e, v.id)).toEqual([`${handleOf(aliasKeys(alice.AK, 0))}: one`, "bob: anyone?"]);
    }
  });
});

describe("an alias's BELL row on opening (§2.6, §11.13 \"An alias's BELL row\")", () => {
  /** bob's 1:1 with alice's alias, accepted without a row of the alias's; alice's device is in use while `use.v`. */
  async function opened(use: { v: boolean }) {
    const x = await withAlias({ quiet: quietOf(() => use.v) });
    const bid = await x.B.createConversation([x.h]);
    await settle(x.A, x.B);
    const [v] = viewsAs(x.A, x.uid);
    await x.A.accept(v.id);
    await settle(x.A, x.B);
    const lane = () => laneTypes(epoch(x.B, bid), P.fromB64u(x.uid));
    return { ...x, bid, id: v.id, lane };
  }

  it("is posted when the user opens the copy on a device in use, once per epoch, and then the members ring it", async () => {
    const use = { v: false };
    const { alice, A, B, bid, id, lane } = await opened(use);
    expect(lane()).toEqual([]);
    A.markRead(id); // not in use: no opening
    await settle(A, B);
    expect(lane()).toEqual([]);
    use.v = true;
    A.markRead(id);
    await settle(A, B);
    expect(lane()).toEqual([P.MT.BELL]);
    A.markRead(id); // its lane has one in this epoch
    await settle(A, B);
    expect(lane()).toEqual([P.MT.BELL]);
    const n = server().push.rings().length;
    await B.sendText(bid, "are you there?");
    await settle(A, B);
    const bell = aliasBell(alice, 0, epoch(B, bid).D.conv);
    expect(
      server()
        .push.rings()
        .slice(n)
        .some((r) => r.tokens.includes(bell)),
    ).toBe(true);
  });

  it("rows that arrive in a pane already open are no opening: a member's commit does not make the alias write", async () => {
    const use = { v: true };
    const { alice, bob, A, B, bid, id, lane } = await opened(use);
    A.markRead(id);
    await settle(A, B);
    expect(lane()).toEqual([P.MT.BELL]);
    // bob renames: a new epoch, which counts as unread in the open pane
    const ep = epoch(B, bid);
    const a = aliasUser(alice, 0);
    const members = ep.D.members.map((m) => (P.equalBytes(m.uid, bob.uid) ? bob : a));
    await commitChange(bob, ep, members, "renamed", { noJoin: true });
    await settle(A, B);
    expect(epoch(B, bid).e).toBe(ep.e + 1);
    expect(mustView(A, id).epoch).toBe(ep.e + 1);
    expect(mustView(A, id).unread).toBeGreaterThan(0);
    A.markRead(id, false); // the pane reports the arrival: unread clears, nothing is written
    await settle(A, B);
    expect(mustView(A, id).unread).toBe(0);
    expect(lane()).toEqual([]);
    A.markRead(id); // the user opens it again
    await settle(A, B);
    expect(lane()).toEqual([P.MT.BELL]);
  });

  it("an opening during the alias's restore posts the row once the alias runs", async () => {
    const use = { v: false };
    const { alice, A, B, uid, lane } = await opened(use);
    // alice's second device, in use; the alias's restore fails transiently while its copies are shown ("starting")
    let hold = true;
    const A2 = newEngine("alice2", { quiet: quietOf(() => true) });
    server().hooks.fail = (_m, path, who) =>
      hold && who === "alice2" && path === "/api/v2/get" && I(A2).aliasRun(0)?.msg
        ? "before"
        : undefined;
    await I(A2).unlock(alice.AK, alice.uid, "alice");
    await waitFor(() => viewsAs(A2, uid).length === 1, "the alias's copy shown");
    expect(I(A2).aliasRun(0)?.status).toBe("starting");
    A2.markRead(viewsAs(A2, uid)[0].id);
    await sleep(50);
    expect(lane()).toEqual([]);
    hold = false;
    await waitFor(() => !A2.getState().syncing, "alice2's restore");
    await settle(A, A2, B);
    expect(I(A2).aliasRun(0)?.status).toBe("ready");
    expect(lane()).toEqual([P.MT.BELL]);
  });
});

describe("the owner's accounts, by uid and keys (§2.6 \"The owner's accounts\")", () => {
  it("a slot that lists an alias's uid with other keys is an unknown member: rung, counted, never own", async () => {
    const { alice, bob, A, B, uid } = await withAlias();
    const id = await A.createConversation(["bob"]);
    await settle(A, B);
    await B.accept(viewsOf(B)[0].id);
    await settle(A, B);
    // bob, as a committer may, adds a slot with the alias's uid and keys of his own
    const fake: TestUser = { ...aliasUser(alice, 0), id: P.deriveIdentity(P.random(32)) };
    const ep = epoch(A, id);
    const members = ep.D.members.map((m) => (P.equalBytes(m.uid, alice.uid) ? alice : bob));
    await commitChange(bob, ep, [...members, fake], undefined, { noJoin: true });
    await settle(A, B);
    const ep1 = epoch(A, id);
    expect(ep1.e).toBe(ep.e + 1);
    const j = P.memberIndex(ep1.D, fake.uid);
    const m = mustView(A, id).members[j];
    expect(m).toMatchObject({ uid, own: false, you: false, nickname: "" });
    expect(m.handle.startsWith("?")).toBe(true);
    A.markRead(id);
    await settle(A, B);
    expect(mustView(A, id).unread).toBe(0);
    // the slot posts a BELL row with a bell of bob's, and a text
    const bell = P.bellOf(P.random(32));
    const E = server().era;
    const r0 = buildMessage(fake, ep1, { E, n: 0 }, { type: P.MT.BELL, bell: { g: 0, bell } });
    postRow(ep1, r0);
    postRow(
      ep1,
      buildMessage(fake, ep1, { E, n: 1, prev: { ...r0, n: 0 } }, { type: P.MT.TEXT, text: "hi" }),
    );
    await settle(A, B);
    // counted as unread, like any other member's row
    expect(mustView(A, id).unread).toBe(1);
    expect(chat(A, id).at(-1)).toBe(`${m.handle}: hi`);
    // the owner's send rings it, like any other member
    const n = server().push.rings().length;
    await A.sendText(id, "who is this?");
    await settle(A, B);
    expect(
      server()
        .push.rings()
        .slice(n)
        .some((r) => r.tokens.includes(P.b64u(bell))),
    ).toBe(true);
  });
});

describe('retiring an alias (§2.6 "Retiring")', () => {
  it("revokes the image and file URLs that only the alias's copies show, and keeps those the owner's show", async () => {
    const { A, B, uid, h } = await withAlias();
    const one = await B.createConversation([h]);
    const both = await B.createConversation(["alice", h], "both");
    await settle(A, B);
    for (const v of viewsOf(A)) await A.accept(v.id);
    await settle(A, B);
    await B.sendFile(one, new File([P.utf8("for the alias only") as BlobPart], "a.txt"));
    await B.sendImage(
      one,
      new File([P.utf8("RIFF....WEBPVP8 the alias's photo") as BlobPart], "p.webp", {
        type: "image/webp",
      }),
    );
    await B.sendFile(both, new File([P.utf8("for both") as BlobPart], "s.txt"));
    await settle(A, B);
    const mine = viewsAs(A, uid);
    const solo = mine.find((v) => v.name !== "# both")!;
    const group = mine.find((v) => v.name === "# both")!;
    const file = mustView(A, solo.id).messages.find((x) => x.kind === "file")!.file!;
    const img = mustView(A, solo.id).messages.find((x) => x.kind === "image")!.image!;
    const shared = mustView(A, group.id).messages.find((x) => x.kind === "file")!.file!;
    const fileUrl = await A.loadFile(file);
    const imgUrl = await A.loadImage(img);
    const sharedUrl = await A.loadFile(shared);
    for (const u of [fileUrl, imgUrl, sharedUrl]) expect(resolveObjectURL(u)).toBeDefined();
    const images = I(A).images!.size;

    await A.setAliasRetired(uid, true);
    await settle(A, B);
    expect(viewsAs(A, uid)).toHaveLength(0);
    expect(resolveObjectURL(fileUrl)).toBeUndefined();
    expect(resolveObjectURL(imgUrl)).toBeUndefined();
    expect(I(A).fileCache.has(`${file.id}.${file.k}`)).toBe(false);
    expect(I(A).images!.size).toBe(images - 1);
    // the owner's copy of the group shows that file too: it stays
    expect(resolveObjectURL(sharedUrl)).toBeDefined();
    expect(I(A).fileCache.has(`${shared.id}.${shared.k}`)).toBe(true);
    A.releaseImage(img); // the view's late release does nothing
  });
});

describe("an alias's LEAVE repeat (§2.6, §6.9)", () => {
  it("comes after its own random delay, exactly once, and not at all once it is no longer due", async () => {
    const H = 12 * 3600_000;
    const alice = makeUser("alice");
    const bob = makeUser("bob");
    const carol = makeUser("carol");
    const A = await engineFor(alice, { delays: { aliasLeaveDelay: H } });
    const uid = await A.createAlias();
    const a = aliasUser(alice, 0);
    // every draw is half its range: the repeat falls due 6 h after the device finds it due
    const random = vi.spyOn(Math, "random").mockReturnValue(0.5);
    try {
      // two groups of the alias with bob and carol, who run no device here; the alias leaves both
      const g1 = await A.createConversation(["bob", "carol"], "one", uid);
      const g2 = await A.createConversation(["bob", "carol"], "two", uid);
      await settle(A);
      await A.leave(g1);
      await A.leave(g2);
      await settle(A);
      const order = (ep: Epoch) =>
        ep.D.members.map((m) => [a, bob, carol].find((u) => P.equalBytes(u.uid, m.uid))!);
      // bob's commits, racing the leaves, list the alias again: the LEAVE is to be repeated there
      const e1 = aliasEpoch(A, g1);
      const e2 = aliasEpoch(A, g2);
      await commitChange(bob, e1, order(e1), "one again", { noJoin: true });
      await commitChange(bob, e2, order(e2), "two again", { noJoin: true });
      await settle(A);
      const n1 = aliasEpoch(A, g1);
      const n2 = aliasEpoch(A, g2);
      expect([n1.e, n2.e]).toEqual([e1.e + 1, e2.e + 1]);
      const leaves = (ep: Epoch) => laneTypes(ep, a.uid).filter((t) => t === P.MT.LEAVE).length;
      // the owner would repeat at once; the alias waits
      expect([leaves(n1), leaves(n2)]).toEqual([0, 0]);
      // bob removes the alias from the second group before the delay ends: no longer due there
      await commitChange(bob, n2, [bob, carol], undefined, { noJoin: true });
      await settle(A);
      expect(aliasEpoch(A, g2).e).toBe(n2.e);
      server().tick(H / 2 + 1);
      await settle(A);
      expect([leaves(n1), leaves(n2)]).toEqual([1, 0]);
      // and never a second one
      server().tick(H + 1);
      await settle(A);
      expect([leaves(n1), leaves(n2)]).toEqual([1, 0]);
    } finally {
      random.mockRestore();
    }
  });
});
