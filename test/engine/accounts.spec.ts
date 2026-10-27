// Accounts (docs/PROTOCOL-v2.md §2.4–§2.5, §11.1; docs/STAGE1-PLAN.md §3 rows 1–10): wraps filed under someone
// else's public id, the registration's lost response, passkeys without PRF, a second passkey, and "remember this
// device" without IndexedDB, ported from v1 (3de5f5e:test/engine/accounts.spec.ts); plus the v2 account check and
// the registration's first self row. WebAuthn is replaced by an in-memory authenticator (credential id → uid + PRF).
import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { ACCOUNT_KEYS_MISMATCH, ACCOUNT_MISSING } from "../../src/client/engine";
import {
  I,
  P,
  engineFor,
  freshWorldPerTest,
  makeUser,
  newEngine,
  newTestUser,
  server,
  settle,
  sleep,
  waitFor,
} from "./harness";

const wa = vi.hoisted(() => {
  const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));
  const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const creds = new Map<string, { credId: Uint8Array; uid: Uint8Array; prf: Uint8Array }>();
  return {
    rnd,
    hex,
    creds,
    forgotten: [] as Uint8Array[],
    /** The credential the next signInWithPasskey() picks (and whether it returns its user handle). */
    pick: null as null | { credId: Uint8Array; withUserHandle: boolean },
    /** Runs inside createPasskey(), i.e. after the handle check and before POST /api/v2/register. */
    onCreate: null as null | (() => void),
    prfAtCreate: true,
  };
});

vi.mock("../../src/client/webauthn", () => ({
  PasskeyError: class PasskeyError extends Error {},
  prfCapability: async () => true,
  createPasskey: async (uid: Uint8Array) => {
    wa.onCreate?.();
    const credId = wa.rnd(16);
    const prf = wa.rnd(32);
    wa.creds.set(wa.hex(credId), { credId, uid: uid.slice(), prf });
    return { credId, prf: wa.prfAtCreate ? prf : null };
  },
  prfForCredential: async (credId: Uint8Array) => wa.creds.get(wa.hex(credId))?.prf ?? null,
  signInWithPasskey: async () => {
    const p = wa.pick!;
    const c = wa.creds.get(wa.hex(p.credId))!;
    return { credId: c.credId, uid: p.withUserHandle ? c.uid : null, prf: c.prf };
  },
  forgetCredential: async (credId: Uint8Array) => {
    wa.forgotten.push(credId);
  },
}));

freshWorldPerTest();

beforeEach(() => {
  wa.creds.clear();
  wa.forgotten.length = 0;
  wa.pick = null;
  wa.onCreate = null;
  wa.prfAtCreate = true;
});

/** Successful writes of the directory and the shard (what a failed unlock must never cause). */
const writes = () =>
  server().requests.filter(
    (r) => ["/api/v2/register", "/api/v2/wraps", "/api/v2/put"].includes(r.path) && r.status === 200,
  ).length;

describe("protocol-3 / engine-3 / web-1: wraps filed under someone else's public id", () => {
  it("a recovery wrap of the attacker's AK under the victim's recovery id never unlocks the attacker's account", async () => {
    const victim = makeUser("alice");
    // Ids are public: anyone can file a record under the victim's recovery id with their own uid (one per uid).
    const attackers = ["a1ice", "al1ce", "a11ce", "a_ice"].map((h) => makeUser(h));
    const vRec = server().dir.wraps.find((w) => w.uid === victim.uidB)!;
    const rec = P.parseWrap(vRec.record, vRec.sig);
    // Without the code an attacker cannot know `auth`: guesses, including a zero key and the attacker's own.
    const guesses = [P.random(32), new Uint8Array(32), attackers[2].rk.auth];
    guesses.forEach((auth, k) => {
      const a = attackers[k];
      const evil = P.makeWrap(a.uid, "recovery", rec.id, { pk: rec.kemPk, auth }, a.AK, a.id, Date.now());
      expect(server().dir.postWrap(evil).status).toBe(200);
    });
    // Also re-file the victim's own sealed box under an attacker's uid (the AAD binds the uid).
    const a = attackers[3];
    const reboxed = JSON.stringify({ ...JSON.parse(rec.record), uid: a.uidB, ts: Date.now() });
    expect(server().dir.postWrap({ record: reboxed, sig: P.b64u(P.sign(P.wrapSigMsg(reboxed), a.id.sigSk)) }).status).toBe(200);
    expect(server().dir.wraps.filter((w) => w.id === P.b64u(rec.id))).toHaveLength(5);

    const V = newEngine();
    await V.loginWithRecovery(P.formatRecoveryCode(victim.code), false);
    await settle(V);
    expect(V.getState().me?.uid).toBe(victim.uidB);
    expect(V.getState().me?.handle).toBe("alice");
    expect(V.getState().phase).toBe("ready");
    expect(V.getState().error).toBe("");
  });

  it("a wrong recovery code is refused and creates nothing", async () => {
    makeUser("alice");
    const before = writes();
    const V = newEngine();
    await expect(V.loginWithRecovery(P.formatRecoveryCode(P.newRecoveryCode()), false)).rejects.toThrow(/not recognised/);
    expect(V.getState().phase).toBe("signed-out");
    expect(V.getState().me).toBeNull();
    expect(writes()).toBe(before);
    await expect(V.loginWithRecovery("not a code", false)).rejects.toThrow(/32 characters/);
    expect(writes()).toBe(before);
  });

  it("a passkey wrap of the attacker's AK under the victim's credential id does not open (even without a user handle)", async () => {
    const R = newEngine("victim");
    const { recoveryCode } = await R.register("victim");
    const victimUid = R.getState().me!.uid;
    await settle(R);
    await R.logout();
    expect(recoveryCode).toMatch(/^([0-9A-Z]{4}-){7}[0-9A-Z]{4}$/);
    const [cred] = [...wa.creds.values()];
    const attacker = makeUser("v1ctim");
    const vRec = server().dir.wraps.find((w) => w.uid === victimUid && P.parseWrap(w.record, w.sig).kind === "passkey")!;
    const rec = P.parseWrap(vRec.record, vRec.sig);
    expect(P.equalBytes(rec.id, cred.credId)).toBe(true);
    const evil = P.makeWrap(attacker.uid, "passkey", rec.id, { pk: rec.kemPk, auth: P.random(32) }, attacker.AK, attacker.id, Date.now());
    expect(server().dir.postWrap(evil).status).toBe(200);

    for (const withUserHandle of [true, false]) {
      wa.pick = { credId: cred.credId, withUserHandle };
      const L = newEngine();
      await L.login(false);
      await settle(L);
      expect(L.getState().me?.uid).toBe(victimUid);
      expect(L.getState().me?.handle).toBe("victim");
      await L.logout();
    }
  });
});

describe("engine-12: registration", () => {
  it("registers (handle checked by prefix), shows the recovery code once, and both factors unlock the account", async () => {
    const R = newEngine("newbie");
    const { recoveryCode } = await R.register("@Newbie");
    expect(R.getState().phase).toBe("ready");
    expect(R.getState().me?.handle).toBe("newbie");
    // The handle check is a prefix query, filtered locally (§2.5 step 2): no exact handle lookup exists.
    const dirReqs = server().requests.filter((r) => r.path.startsWith("/api/v2/dir/"));
    expect(dirReqs[0].path).toMatch(/^\/api\/v2\/dir\/h\/\d+\/\d+$/);
    const uid = R.getState().me!.uid;
    await settle(R);
    await R.logout();

    const viaCode = newEngine();
    await viaCode.loginWithRecovery(recoveryCode.toLowerCase(), false);
    expect(viaCode.getState().me?.uid).toBe(uid);
    await viaCode.logout();
    wa.pick = { credId: [...wa.creds.values()].at(-1)!.credId, withUserHandle: true };
    const viaPasskey = newEngine();
    await viaPasskey.login(false);
    expect(viaPasskey.getState().me?.uid).toBe(uid);
  });

  it("a register whose response is lost after the server committed still completes", async () => {
    server().hooks.fail = (m, p) => (m === "POST" && p === "/api/v2/register" ? "after" : null);
    const R = newEngine();
    const { recoveryCode } = await R.register("lucky");
    server().hooks.fail = undefined;
    expect(R.getState().phase).toBe("ready");
    expect(R.getState().me?.handle).toBe("lucky");
    expect(wa.forgotten).toHaveLength(0);
    // The lost-response check is a fresh handle-prefix query after the failed POST (§2.5 step 8).
    const paths = server().requests.map((r) => r.path);
    const post = paths.indexOf("/api/v2/register");
    expect(paths.slice(post + 1).some((p) => p.startsWith("/api/v2/dir/h/"))).toBe(true);
    await settle(R);
    expect(R.getState().phase).toBe("ready"); // the account check found it in the directory
    const uid = R.getState().me!.uid;
    await R.logout();
    const L = newEngine();
    await L.loginWithRecovery(recoveryCode, false);
    expect(L.getState().me?.uid).toBe(uid);
  });

  it("a register that never reached the server fails without pretending success", async () => {
    server().hooks.fail = (m, p) => (m === "POST" && p === "/api/v2/register" ? "before" : null);
    const R = newEngine();
    await expect(R.register("unlucky")).rejects.toThrow();
    expect(R.getState().phase).toBe("signed-out");
    expect(server().dir.byHandleName("unlucky")).toBeNull();
    expect(wa.forgotten).toHaveLength(0); // nobody else holds the handle: the passkey may still be used
  });

  it("a definitive rejection (handle taken in a race) forgets the new passkey", async () => {
    wa.onCreate = () => {
      wa.onCreate = null;
      makeUser("racer"); // someone else takes the handle between the check and the POST
    };
    const R = newEngine();
    await expect(R.register("racer")).rejects.toThrow(/taken/);
    expect(wa.forgotten).toHaveLength(1);
    expect(R.getState().phase).toBe("signed-out");
  });

  it("asks for the PRF in a second ceremony when the authenticator did not return it at creation", async () => {
    wa.prfAtCreate = false;
    const R = newEngine();
    await R.register("second");
    expect(R.getState().phase).toBe("ready");
  });

  it("a signed-in user can add a second passkey that unlocks the same account", async () => {
    const u = makeUser("multi");
    const E = await engineFor(u);
    await E.addPasskey();
    await settle(E);
    const added = [...wa.creds.values()].at(-1)!;
    wa.pick = { credId: added.credId, withUserHandle: true };
    await E.logout();
    const L = newEngine();
    await L.login(false);
    await settle(L);
    expect(L.getState().me?.uid).toBe(u.uidB);
    expect(L.getState().me?.handle).toBe("multi"); // filled in from dir/uid at unlock (§11.1)
    expect(I(L).account?.handle).toBe("multi");
  });

  it('"remember this device" failing (no IndexedDB, e.g. a private window) does not lose the new account', async () => {
    // The harness has no IndexedDB, so saveSession() rejects.
    const R = newEngine();
    const res = await R.register("private", true).catch((e: unknown) => e);
    expect(server().dir.byHandleName("private")).not.toBeNull();
    expect(res).toHaveProperty("recoveryCode");
    expect(R.getState().phase).toBe("ready");
  });
});

describe("v2: the registration's self row and the account check (§7.3, §11.1)", () => {
  it("the first self row is a HEADS record with the inbox cursor at the current slot, and a restore reads it", async () => {
    const R = newEngine("first");
    const { recoveryCode } = await R.register("first");
    await settle(R);
    // the first row, at Lself(E, 0) with prev NONE, holds only the HEADS record with the registration's cursor
    const id = P.deriveIdentity(I(R).account!.AK);
    const rows = server().shard.rows().filter((r) => P.equalBytes(r.label, P.Lself(id.rS, server().era, 0)));
    expect(rows).toHaveLength(1);
    const row = P.openSelf(id.kS, server().era, rows[0].label, rows[0].body);
    expect(row.prev).toEqual(P.NONE);
    expect(row.records).toHaveLength(1);
    const first = row.records[0] as P.HeadsRec;
    expect(first).toMatchObject({ rtype: P.RT.HEADS, entries: [] });
    const slot = Math.floor((server().now() - P.T0_MS) / (server().params.inboxSlot * 1000));
    expect(first.Ein).toBe(server().era);
    expect(first.relIn).toBeLessThanOrEqual(slot);
    expect(first.relIn).toBeGreaterThanOrEqual(slot - 5);
    // later HEADS rows only move the cursor forward (the inbox poll read past it)
    const self = I(R).self!;
    const cursor = self.fold.cursor!;
    expect(cursor.E > first.Ein || (cursor.E === first.Ein && cursor.rel >= first.relIn)).toBe(true);
    const head = { E: self.head!.E, n: self.head!.n };
    await R.logout();

    // A restore on another device probes the lane from (regEra, 0), applies the row and writes nothing.
    const before = writes();
    const L = newEngine();
    await L.loginWithRecovery(recoveryCode, false);
    await waitFor(() => !L.getState().syncing, "restore");
    await settle(L);
    expect(I(L).self!.fold.cursor).toEqual(cursor);
    expect(I(L).self!.head).toMatchObject(head);
    expect(writes()).toBe(before);
  });

  it("an account missing from the directory is fatal (§11.1 step 2)", async () => {
    const u = newTestUser("ghost"); // keys exist, but the account was never registered
    const E = newEngine();
    await I(E).unlock(u.AK, u.uid, u.handle);
    await waitFor(() => E.getState().phase === "fatal", "fatal");
    expect(E.getState().error).toBe(ACCOUNT_MISSING);
    expect(E.getState().syncing).toBe(false);
  });

  it("keys that differ from the registered bundle are fatal (§11.1 step 2)", async () => {
    const u = makeUser("keys");
    const E = newEngine();
    await I(E).unlock(P.random(32), u.uid, u.handle); // another AK: other derived keys for the same uid
    await waitFor(() => E.getState().phase === "fatal", "fatal");
    expect(E.getState().error).toBe(ACCOUNT_KEYS_MISMATCH);
  });

  it("a transient failure of the account check is retried, never fatal", async () => {
    const u = makeUser("flaky");
    let fails = 2;
    server().hooks.fail = (m, p) => (p.startsWith("/api/v2/dir/uid/") && fails-- > 0 ? "before" : null);
    const E = await engineFor(u);
    expect(E.getState().phase).toBe("ready");
    expect(E.getState().error).toBe("");
    expect(fails).toBeLessThan(0);
  });

  it("signing out during a retry back-off stops the restore at once", async () => {
    const u = makeUser("quits");
    server().hooks.fail = (_m, p) => (p.startsWith("/api/v2/dir/uid/") ? "before" : null);
    const E = newEngine("quits");
    await I(E).unlock(u.AK, u.uid, u.handle);
    await waitFor(() => /sync failed/.test(E.getState().error), "a retry");
    await E.logout();
    expect(I(E).busy).toBe(0);
    const n = server().requests.length;
    await sleep(200);
    expect(server().requests.length).toBe(n);
    expect(E.getState().phase).toBe("signed-out");
  });

  it("a lost POST /api/v2/wraps response is success only when the exact record is listed (§10.6)", async () => {
    const u = makeUser("wrapper");
    const E = await engineFor(u);
    server().hooks.fail = (m, p) => (m === "POST" && p === "/api/v2/wraps" ? "after" : null);
    await E.addPasskey(); // stored, response lost: found by dir/wraps/{id}?uid=
    expect(server().requests.at(-1)!.path).toMatch(/^\/api\/v2\/dir\/wraps\//);
    expect(server().requests.at(-1)!.query).toBe(`?uid=${u.uidB}`);
    server().hooks.fail = (m, p) => (m === "POST" && p === "/api/v2/wraps" ? "before" : null);
    await expect(E.addPasskey()).rejects.toThrow(); // never reached the server: not listed
    server().hooks.fail = undefined;
    expect(server().dir.wraps.filter((w) => w.uid === u.uidB && P.parseWrap(w.record, w.sig).kind === "passkey")).toHaveLength(1);
  });
});
