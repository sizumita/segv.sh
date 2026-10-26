// Accounts: regression tests for protocol-3 / engine-3 / web-1 (wrap substitution under a public id) and
// engine-12 (registration whose response is lost after the server committed). WebAuthn is replaced by an
// in-memory authenticator (credential id -> uid + PRF secret).
import { describe, expect, it, vi } from 'vite-plus/test';
import { engineFor, I, makeUser, newEngine, P, server, settle, freshWorldPerTest, view } from './harness';

const wa = vi.hoisted(() => {
  const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));
  const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const creds = new Map<string, { credId: Uint8Array; uid: Uint8Array; prf: Uint8Array }>();
  return {
    rnd,
    hex,
    creds,
    forgotten: [] as Uint8Array[],
    /** The credential the next signInWithPasskey() picks (and whether it returns its user handle). */
    pick: null as null | { credId: Uint8Array; withUserHandle: boolean },
    /** Runs inside createPasskey(), i.e. after the handle check and before POST /api/register. */
    onCreate: null as null | (() => void),
    prfAtCreate: true,
  };
});

vi.mock('../../src/client/webauthn', () => ({
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

describe('protocol-3 / engine-3 / web-1: wraps filed under someone else\'s public id', () => {
  it('a recovery wrap of the attacker\'s AK under the victim\'s recovery id never unlocks the attacker\'s account', async () => {
    const victim = makeUser('alice');
    const attacker = makeUser('a1ice');
    // The victim's recovery record is public (kind 2): id = recId, kem = recKemPk.
    const vRec = server().wraps.find((w) => w.uid === victim.uidB)!;
    const rec = P.parseWrap(vRec.record, vRec.sig);
    // Without the code the attacker cannot know `auth`; try a few guesses, including none-like values.
    for (const auth of [P.random(32), new Uint8Array(32), attacker.rk.auth]) {
      const evil = P.makeWrap(attacker.uid, 'recovery', rec.id, { pk: rec.kemPk, auth }, attacker.AK, attacker.id, Date.now());
      expect(server().postWrap(evil).status).toBe(200); // the server accepts it: ids are public
    }
    // Also re-file the victim's own sealed box under the attacker's uid (AAD binds the uid).
    const reboxed = JSON.stringify({ ...JSON.parse(rec.record), uid: attacker.uidB, ts: Date.now() });
    expect(server().postWrap({ record: reboxed, sig: P.b64u(P.sign(P.wrapSigMsg(reboxed), attacker.id.sigSk)) }).status).toBe(200);
    expect(server().wraps.filter((w) => w.id === P.b64u(rec.id))).toHaveLength(5);

    const V = newEngine();
    await V.loginWithRecovery(P.formatRecoveryCode(victim.code), false);
    await settle(V);
    expect(V.getState().me?.uid).toBe(victim.uidB);
    expect(V.getState().me?.handle).toBe('alice');
    expect(V.getState().phase).toBe('ready');
    expect(V.getState().error).toBe('');
  });

  it('a wrong recovery code is refused and creates nothing', async () => {
    makeUser('alice');
    const before = server().head.seq;
    const V = newEngine();
    await expect(V.loginWithRecovery(P.formatRecoveryCode(P.newRecoveryCode()), false)).rejects.toThrow(/not recognised/);
    expect(V.getState().phase).toBe('signed-out');
    expect(V.getState().me).toBeNull();
    expect(server().head.seq).toBe(before);
    await expect(V.loginWithRecovery('not a code', false)).rejects.toThrow(/32 characters/);
  });

  it('a passkey wrap of the attacker\'s AK under the victim\'s credential id does not open (even without a user handle)', async () => {
    const R = newEngine();
    const { recoveryCode } = await R.register('victim');
    const victimUid = R.getState().me!.uid;
    await R.logout();
    expect(recoveryCode).toMatch(/^([0-9A-Z]{4}-){7}[0-9A-Z]{4}$/);
    const [cred] = [...wa.creds.values()];
    const attacker = makeUser('v1ctim');
    const vRec = server().wraps.find((w) => w.uid === victimUid && P.parseWrap(w.record, w.sig).kind === 'passkey')!;
    const rec = P.parseWrap(vRec.record, vRec.sig);
    expect(P.equalBytes(rec.id, cred.credId)).toBe(true);
    const evil = P.makeWrap(attacker.uid, 'passkey', rec.id, { pk: rec.kemPk, auth: P.random(32) }, attacker.AK, attacker.id, Date.now());
    expect(server().postWrap(evil).status).toBe(200);

    for (const withUserHandle of [true, false]) {
      wa.pick = { credId: cred.credId, withUserHandle };
      const L = newEngine();
      await L.login(false);
      await settle(L);
      expect(L.getState().me?.uid).toBe(victimUid);
      expect(L.getState().me?.handle).toBe('victim');
      await L.logout();
    }
  });
});

describe('engine-12: registration', () => {
  it('registers, shows the recovery code once, and both factors unlock the account', async () => {
    const R = newEngine();
    const { recoveryCode } = await R.register('@Newbie');
    expect(R.getState().phase).toBe('ready');
    expect(R.getState().me?.handle).toBe('newbie');
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

  it('a register whose response is lost after the server committed still completes', async () => {
    wa.forgotten.length = 0;
    server().hooks.fail = (m, p) => (m === 'POST' && p === '/api/register' ? 'after' : null);
    const R = newEngine();
    const { recoveryCode } = await R.register('lucky');
    server().hooks.fail = undefined;
    expect(R.getState().phase).toBe('ready');
    expect(R.getState().me?.handle).toBe('lucky');
    expect(wa.forgotten).toHaveLength(0);
    await settle(R);
    expect(R.getState().phase).toBe('ready'); // its own kind-1 row is in the log
    const uid = R.getState().me!.uid;
    await R.logout();
    const L = newEngine();
    await L.loginWithRecovery(recoveryCode, false);
    expect(L.getState().me?.uid).toBe(uid);
  });

  it('a register that never reached the server fails without pretending success', async () => {
    server().hooks.fail = (m, p) => (m === 'POST' && p === '/api/register' ? 'before' : null);
    const R = newEngine();
    await expect(R.register('unlucky')).rejects.toThrow();
    expect(R.getState().phase).toBe('signed-out');
    expect(server().handles.has('unlucky')).toBe(false);
  });

  it('a definitive rejection (handle taken in a race) forgets the new passkey', async () => {
    wa.forgotten.length = 0;
    wa.onCreate = () => {
      wa.onCreate = null;
      makeUser('racer'); // someone else takes the handle between the check and the POST
    };
    const R = newEngine();
    await expect(R.register('racer')).rejects.toThrow(/taken/);
    expect(wa.forgotten).toHaveLength(1);
    expect(R.getState().phase).toBe('signed-out');
  });

  it('asks for the PRF in a second ceremony when the authenticator did not return it at creation', async () => {
    wa.prfAtCreate = false;
    try {
      const R = newEngine();
      await R.register('second');
      expect(R.getState().phase).toBe('ready');
    } finally {
      wa.prfAtCreate = true;
    }
  });

  it('a signed-in user can add a second passkey that unlocks the same account', async () => {
    const u = makeUser('multi');
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
    expect(L.getState().me?.handle).toBe('multi'); // filled in from the log
    expect(I(L).account?.handle).toBe('multi');
    void view;
  });

  it('"remember this device" failing (no IndexedDB, e.g. a private window) does not lose the new account', async () => {
    // The harness has no IndexedDB, so saveSession() rejects.
    const R = newEngine();
    const res = await R.register('private', true).catch((e: unknown) => e);
    // Expected: the account exists, so registration completes and shows the recovery code (remembering is best effort).
    expect(server().handles.has('private')).toBe(true);
    expect(res).toHaveProperty('recoveryCode');
    expect(R.getState().phase).toBe('ready');
  });
});
