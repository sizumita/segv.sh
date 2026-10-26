// Epoch chain, claims and membership: regression tests for review findings
// engine-1 / protocol-1 (unchained epochs), protocol-2 / engine-4 (posting into superseded epochs),
// protocol-4 / engine-7 (forged claims), engine-5 / privacy-1 (leave undone by add/remove),
// engine-10 (concurrent rotation after a leave).
import { describe, expect, it } from 'vite-plus/test';
import {
  buildChange,
  buildMessage,
  chat,
  conv,
  engineFor,
  epoch,
  I,
  invitesFor,
  junkInviteRow,
  junkMessageRow,
  makeUser,
  mustView,
  P,
  readableWith,
  server,
  settle,
  signEpoch,
  systemLines,
  freshWorldPerTest,
  view,
} from './harness';

freshWorldPerTest();

/** alice creates [alice, bob, mallory]; alice removes mallory -> e1 [alice, bob]. */
async function removedMallory() {
  const [alice, bob, mallory] = ['alice', 'bob', 'mallory'].map(makeUser);
  const A = await engineFor(alice);
  const B = await engineFor(bob);
  const M = await engineFor(mallory);
  const id = await A.createConversation(['bob', 'mallory']);
  await settle(A, B, M);
  await A.removeMember(id, mallory.uidB);
  await settle(A, B, M);
  expect(mustView(B, id).epoch).toBe(1);
  expect(mustView(M, id).canSend).toBe(false);
  return { alice, bob, mallory, A, B, M, id };
}

describe('engine-1 / protocol-1: unchained epochs from a removed member', () => {
  for (const [label, e] of [
    ['far ahead (e = 7)', 7],
    ['the next epoch number without a claim (e = 2)', 2],
    ['e = 2^32-2', 0xfffffffe],
    ['e = 0xffffffff', 0xffffffff],
  ] as const) {
    it(`members ignore an invite-only epoch ${label} and the attacker cannot read on`, async () => {
      const { alice, bob, mallory, A, B, M, id } = await removedMallory();
      // Mallory only knows the conversation id and her own keys: invites only, no claim.
      const members = [alice.uidB, bob.uidB, mallory.uidB];
      const forged = signEpoch({ conv: id, e, members, by: mallory, prev: P.b64u(P.random(32)) });
      server().mustAppend(invitesFor(members, forged.dText, forged.EK, forged.dsig));
      await settle(A, B, M);

      for (const E of [A, B]) {
        const v = mustView(E, id);
        expect(v.epoch).toBe(1);
        expect(v.canSend).toBe(true);
        expect(v.members.map((m) => m.handle).sort()).toEqual(['alice', 'bob']);
        expect(systemLines(E, id).join('\n')).not.toMatch(/mallory added/);
        expect(E.getState().warnings.length).toBeGreaterThan(0); // the attempt is reported
      }

      await B.sendText(id, 'secret plan: meet at 7');
      await settle(A, B, M);
      await A.sendText(id, 'ok, see you');
      await settle(A, B, M);
      expect(chat(A, id)).toEqual(['bob: secret plan: meet at 7', 'alice: ok, see you']);
      expect(chat(B, id)).toEqual(['bob: secret plan: meet at 7', 'alice: ok, see you']);
      // Neither message is readable with the forged epoch's key, nor shown by Mallory's client.
      expect(readableWith(forged.keys.mk)).toEqual([]);
      expect(chat(M, id)).toEqual([]);
      // Membership can still change (no u32 overflow, no stuck epoch).
      await A.addMembers(id, ['mallory']).catch(() => {});
      await settle(A, B, M);
      expect(mustView(B, id).epoch).toBe(2);
    });
  }

  it('a current member cannot fork the group by skipping the claim slot', async () => {
    const [alice, bob, carol] = ['alice', 'bob', 'carol'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const id = await A.createConversation(['bob', 'carol']);
    await settle(A, B, C);
    // Carol (a member) sends bob alone an epoch 1 that drops alice, chained correctly but with no claim.
    const ep = epoch(C, id);
    const f = signEpoch({ conv: id, e: 1, members: [bob.uidB, carol.uidB], by: carol, prev: P.b64u(P.H(P.utf8(ep.dText))) });
    server().mustAppend(invitesFor([bob.uidB], f.dText, f.EK, f.dsig));
    await settle(A, B, C);
    expect(mustView(B, id).epoch).toBe(0);
    await B.sendText(id, 'for everyone');
    await settle(A, B, C);
    expect(chat(A, id)).toEqual(['bob: for everyone']);
    expect(readableWith(f.keys.mk)).toEqual([]);
  });

  it('a legitimate re-add of a removed member at a later epoch is accepted by that member', async () => {
    const { mallory, A, B, M, id } = await removedMallory();
    await A.sendText(id, 'while mallory is out');
    await settle(A, B, M);
    await A.addMembers(id, ['mallory']);
    await settle(A, B, M);
    const vm = mustView(M, id);
    expect(vm.epoch).toBe(2);
    expect(vm.canSend).toBe(true);
    expect(systemLines(M, id).at(-1)).toBe('@alice added you');
    expect(chat(M, id)).toEqual([]); // nothing from the epoch she was not in
    await A.sendText(id, 'welcome back');
    await settle(A, B, M);
    await M.sendText(id, 'thanks');
    await settle(A, B, M);
    expect(chat(M, id)).toEqual(['alice: welcome back', 'mallory: thanks']);
    expect(chat(B, id)).toEqual(['alice: while mallory is out', 'alice: welcome back', 'mallory: thanks']);
    expect(M.getState().warnings).toEqual([]);
    void mallory;
  });

  it('a future member cannot be captured by a forged epoch planted before they are added', async () => {
    // Mallory was removed; she pre-sends dave (not yet a member) an invite for the same conversation id.
    const { alice, bob, mallory, A, B, id } = await removedMallory();
    const dave = makeUser('dave');
    const D = await engineFor(dave);
    const f = signEpoch({
      conv: id,
      e: 0xfffffffe,
      members: [alice.uidB, bob.uidB, dave.uidB, mallory.uidB],
      by: mallory,
      prev: P.b64u(P.random(32)),
    });
    server().mustAppend(invitesFor([dave.uidB], f.dText, f.EK, f.dsig));
    await settle(D);

    // Later alice really adds dave. Dave cannot tell which copy is genuine, so he gets both, marked ⚠,
    // plus a security warning — instead of the first one silently winning.
    await A.addMembers(id, ['dave']);
    await settle(A, B, D);
    const copies = I(D).views().filter((v) => v.id === id || v.id.startsWith(`${id}~`));
    expect(copies).toHaveLength(2);
    expect(copies.every((v) => v.name.startsWith('⚠ '))).toBe(true);
    expect(D.getState().warnings.some((w) => w.includes('second, different copy'))).toBe(true);
    const real = copies.find((v) => v.epoch === 2)!;
    expect(real.members.map((m) => m.handle).sort()).toEqual(['alice', 'bob', 'dave']);

    // Once alice or bob posts in the real copy it is corroborated and loses the mark; the fake keeps it.
    await B.sendText(id, 'welcome dave');
    await settle(A, B, D);
    expect(mustView(D, real.id).name.startsWith('⚠ ')).toBe(false);
    expect(I(D).views().find((v) => v.id !== real.id && v.id.startsWith(id.split('~')[0]))!.name.startsWith('⚠ ')).toBe(true);

    await D.sendText(real.id, 'hi, dave here');
    await settle(A, B, D);
    expect(chat(A, id)).toContain('dave: hi, dave here');
    expect(readableWith(f.keys.mk)).toEqual([]);

    // A further junk copy is now rejected outright (dave holds a corroborated copy).
    const g = signEpoch({ conv: id, e: 0xfffffffd, members: [alice.uidB, dave.uidB, mallory.uidB], by: mallory, prev: P.b64u(P.random(32)) });
    server().mustAppend(invitesFor([dave.uidB], g.dText, g.EK, g.dsig));
    await settle(D);
    expect(I(D).views().filter((v) => v.id.startsWith(id))).toHaveLength(2);
  });
});

describe('protocol-2 / engine-4: removed members posting into superseded epochs', () => {
  it('a member removed after two consecutive epochs cannot post into either old epoch', async () => {
    const [alice, bob, carol, mallory] = ['alice', 'bob', 'carol', 'mallory'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const M = await engineFor(mallory);
    const id = await A.createConversation(['bob', 'mallory']);
    await settle(A, B, M);
    await M.sendText(id, 'mallory in e0');
    await settle(A, B, M);
    await A.addMembers(id, ['carol']); // e1 [alice, bob, mallory, carol]
    await settle(A, B, C, M);
    await M.sendText(id, 'mallory in e1');
    await settle(A, B, C, M);
    await A.removeMember(id, mallory.uidB); // e2 [alice, bob, carol]
    await settle(A, B, C, M);
    expect(mustView(B, id).epoch).toBe(2);

    for (const e of [0, 1]) {
      const ep = epoch(M, id, e);
      const n = ep.maxN[ep.myIndex] + 1;
      server().mustAppend([buildMessage(mallory, id, ep, n, { text: `still here via e${e}` })]);
    }
    await settle(A, B, C, M);
    const expected = ['mallory: mallory in e0', 'mallory: mallory in e1'];
    expect(chat(B, id)).toEqual(expected);
    expect(chat(A, id)).toEqual(expected);
    expect(chat(C, id)).toEqual(['mallory: mallory in e1']);
  });

  it('messages that landed in an old epoch before its claim are still shown', async () => {
    const [alice, bob, carol] = ['alice', 'bob', 'carol'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(['bob']);
    await settle(A, B);
    await B.sendText(id, 'before the change');
    await settle(A, B);
    await A.addMembers(id, ['carol']);
    await settle(A, B);
    await B.sendText(id, 'after the change');
    await settle(A, B);
    expect(chat(A, id)).toEqual(['bob: before the change', 'bob: after the change']);
    void carol;
  });
});

describe('protocol-4 / engine-7: forged and invalid claims', () => {
  async function group4() {
    const [alice, bob, victor, mallory] = ['alice', 'bob', 'victor', 'mallory'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const V = await engineFor(victor);
    const M = await engineFor(mallory);
    const id = await A.createConversation(['bob', 'victor', 'mallory']);
    await settle(A, B, V, M);
    await B.sendText(id, 'hi all');
    await settle(A, B, V, M);
    return { alice, bob, victor, mallory, A, B, V, M, id };
  }

  it('a claim that names another member as committer (bad csig) removes nobody and freezes membership only', async () => {
    const { alice, bob, mallory, A, B, V, M, id } = await group4();
    const ep = epoch(M, id);
    const s = signEpoch({
      conv: id,
      e: 1,
      members: [alice.uidB, bob.uidB, mallory.uidB],
      by: alice, // forged committer: Mallory cannot sign as alice
      prev: P.b64u(P.H(P.utf8(ep.dText))),
    });
    // Mallory signs csig with her own key while the descriptor says by = alice.
    server().mustAppend([P.makeClaim(ep.keys.mk, ep.keys.rk, s.dText, P.random(64), mallory.id.sigSk)]);
    await settle(A, B, V, M);

    for (const E of [A, B, V, M]) {
      expect(systemLines(E, id).join('\n')).not.toMatch(/removed you/);
      expect(mustView(E, id).canSend).toBe(true);
      expect(mustView(E, id).epoch).toBe(0);
      expect(E.getState().warnings.join('\n')).toMatch(/members can no longer change/);
    }
    await V.sendText(id, 'am I still here?');
    await settle(A, B, V, M);
    await A.sendText(id, 'yes you are');
    await settle(A, B, V, M);
    for (const E of [A, B, V]) expect(chat(E, id)).toEqual(['bob: hi all', 'victor: am I still here?', 'alice: yes you are']);
    expect(V.getState().error).toBe('');

    await expect(A.addMembers(id, ['mallory'])).rejects.toThrow(/nobody new|can no longer change/);
    await expect(A.removeMember(id, mallory.uidB)).rejects.toThrow(/can no longer change/);
  });

  for (const [label, row] of [
    ['a junk kind-4 row', (tag: Uint8Array) => junkMessageRow(tag)],
    ['a kind-3 row', (tag: Uint8Array) => junkInviteRow(tag)],
  ] as const) {
    it(`${label} on the claim slot freezes membership but messaging continues`, async () => {
      const { mallory, A, B, V, M, id } = await group4();
      const ep = epoch(M, id);
      server().mustAppend([row(P.claimTag(ep.keys.rk))]);
      await settle(A, B, V, M);
      for (const E of [A, B, V]) {
        expect(mustView(E, id).canSend).toBe(true);
        expect(E.getState().warnings.join('\n')).toMatch(/members can no longer change/);
      }
      await V.sendText(id, 'still works');
      await settle(A, B, V);
      expect(chat(A, id)).toEqual(['bob: hi all', 'victor: still works']);
      await expect(A.removeMember(id, mallory.uidB)).rejects.toThrow(/can no longer change/);
    });
  }

  it('a valid claim whose invites never arrive does not stop messaging forever', async () => {
    // Mallory (a member) signs a real claim for e1 but never posts the invites: the slot is taken, nobody gets e1.
    const { alice, bob, victor, mallory, A, B, V, M, id } = await group4();
    const ep = epoch(M, id);
    const ch = buildChange(mallory, id, ep, [alice.uidB, bob.uidB, victor.uidB, mallory.uidB]);
    server().mustAppend([ch.claim]);
    await settle(A, B, V, M);
    await sleep(50);
    await V.sendText(id, 'can we still talk?');
    await settle(A, B, V, M);
    // Expected (PROTOCOL §3.4 "frozen" semantics): the conversation keeps working in epoch 0.
    expect(V.getState().error).toBe('');
    expect(chat(A, id)).toContain('victor: can we still talk?');
  });

  it('a valid claim by a member is honoured: the removed member is told who removed them', async () => {
    const { alice, _bob, victor, A, B, V, id } = await group4();
    await B.removeMember(id, victor.uidB);
    await settle(A, B, V);
    expect(systemLines(V, id).at(-1)).toBe('@bob removed you');
    expect(mustView(V, id).canSend).toBe(false);
    expect(systemLines(A, id).at(-1)).toBe('@bob removed @victor');
    void alice;
  });
});

describe('engine-5 / privacy-1: a leave survives the next add / remove', () => {
  it('bob leaves, alice adds dave: bob is not in the new epoch and cannot read on', async () => {
    const [alice, bob, carol, dave] = ['alice', 'bob', 'carol', 'dave'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const D = await engineFor(dave);
    const id = await A.createConversation(['bob', 'carol']);
    await settle(A, B, C);
    await B.leave(id);
    await settle(A, B, C);
    const before = server().head.seq;

    await A.addMembers(id, ['dave']);
    await settle(A, B, C, D);
    const va = mustView(A, id);
    expect(va.epoch).toBe(1);
    expect(va.members.map((m) => m.handle).sort()).toEqual(['alice', 'carol', 'dave']);
    expect(mustView(B, id).canSend).toBe(false);
    expect(conv(B, id).current).toBe(0); // bob got no invite for e1
    // No invite in the change batch is addressed to bob.
    const { inviteRecipients } = await import('./harness');
    const changeRows = server().rows.filter((r) => r.seq > before && r.kind === 3);
    expect(changeRows.flatMap((r) => inviteRecipients(r, [alice, bob, carol, dave])).sort()).toEqual(['alice', 'carol', 'dave']);

    await A.sendText(id, 'now that bob is gone...');
    await settle(A, B, C, D);
    expect(chat(C, id)).toEqual(['alice: now that bob is gone...']);
    expect(chat(D, id)).toEqual(['alice: now that bob is gone...']);
    expect(chat(B, id)).toEqual([]);
    expect(readableWith(epoch(A, id).keys.mk).map((x) => x.payload.text)).toEqual(['now that bob is gone...']);
  });

  it('bob leaves, alice removes carol: neither is in the new epoch', async () => {
    const [alice, bob, carol, dave] = ['alice', 'bob', 'carol', 'dave'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const id = await A.createConversation(['bob', 'carol', 'dave']);
    await settle(A, B, C);
    await B.leave(id);
    await settle(A, B, C);
    await A.removeMember(id, carol.uidB);
    await settle(A, B, C);
    expect(mustView(A, id).members.map((m) => m.handle).sort()).toEqual(['alice', 'dave']);
    expect(mustView(B, id).canSend).toBe(false);
    expect(mustView(C, id).canSend).toBe(false);
    void dave;
  });

  it('a leaver that is explicitly re-added comes back', async () => {
    const [alice, bob, carol] = ['alice', 'bob', 'carol'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(['bob', 'carol']);
    await settle(A, B);
    await B.leave(id);
    await settle(A, B);
    await A.sendText(id, 'rotate bob out');
    await settle(A, B);
    expect(mustView(A, id).members.map((m) => m.handle).sort()).toEqual(['alice', 'carol']);
    await A.addMembers(id, ['bob']);
    await settle(A, B);
    expect(mustView(B, id).canSend).toBe(true);
    await A.sendText(id, 'welcome back bob');
    await settle(A, B);
    expect(chat(B, id)).toEqual(['alice: welcome back bob']);
    void carol;
  });

  it('a leaver who was not rotated out yet can be re-added explicitly', async () => {
    const [alice, bob, carol] = ['alice', 'bob', 'carol'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(['bob', 'carol']);
    await settle(A, B);
    await B.leave(id);
    await settle(A, B);
    // engine.ts addMembers: "Re-adding someone who left is allowed explicitly".
    await A.addMembers(id, ['bob']);
    await settle(A, B);
    expect(A.getState().error).toBe('');
    expect(mustView(A, id).members.find((m) => m.handle === 'bob')?.left).toBe(false);
    void carol;
  });
});

describe('engine-10: concurrent rotation after a leave', () => {
  it('two members sending at the same time after a leave both get their message delivered', async () => {
    const [alice, bob, carol] = ['alice', 'bob', 'carol'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const id = await A.createConversation(['bob', 'carol']);
    await settle(A, B, C);
    await B.leave(id);
    await settle(A, B, C);

    // Hold both rotation batches (claim + invites) until both clients have built theirs: a real race.
    let held: (() => void)[] = [];
    server().hooks.beforeAppend = (rows) => {
      if (!rows.some((r) => r.kind === 3)) return;
      return new Promise<void>((resolve) => {
        held.push(resolve);
        if (held.length === 2) {
          const go = held;
          held = [];
          server().hooks.beforeAppend = undefined;
          for (const r of go) r();
        }
      });
    };
    await Promise.all([A.sendText(id, 'from alice'), C.sendText(id, 'from carol')]);
    await settle(A, B, C);
    // One rotation won, the other got 409 and retried on top of it.
    expect(server().requests.filter((r) => r.path === '/api/append' && r.status === 409)).toHaveLength(1);
    expect(server().batches.filter((b) => b.kinds[0] === 4 && b.kinds.length > 1).length).toBe(2); // creation + one rotation
    for (const E of [A, C]) {
      expect(E.getState().error).toBe('');
      expect(chat(E, id).sort()).toEqual(['alice: from alice', 'carol: from carol']);
      expect(mustView(E, id).epoch).toBe(1);
    }
    expect(chat(B, id)).toEqual([]);
    expect(view(B, id)!.canSend).toBe(false);
  });
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
