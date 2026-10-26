// Metadata: regression tests for privacy-4 (invite order inside a batch) and privacy-5 (creation batches look
// like membership changes).
import { describe, expect, it } from 'vite-plus/test';
import { engineFor, epoch, inviteRecipients, makeUser, P, server, settle, freshWorldPerTest } from './harness';

freshWorldPerTest();

const batchRows = (b: { seqs: number[] }) => b.seqs.map((s) => server().rows[s - 1]);

describe('privacy-5: batch shapes', () => {
  it('a creation batch has the same [4, 3×N] shape as a membership change, and a message is [4]', async () => {
    const [alice, bob, carol, dave] = ['alice', 'bob', 'carol', 'dave'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const n0 = server().batches.length;
    const id = await A.createConversation(['bob', 'carol']);
    await settle(A, B);
    const creation = server().batches[n0];
    expect(creation.kinds).toEqual([4, 3, 3, 3]);

    const n1 = server().batches.length;
    await A.addMembers(id, ['dave']);
    await settle(A, B);
    expect(server().batches[n1].kinds).toEqual([4, 3, 3, 3, 3]);

    const n2 = server().batches.length;
    await B.sendText(id, 'hi');
    await settle(A, B);
    expect(server().batches[n2].kinds).toEqual([4]);

    // The decoy and the claim use message size classes; the decoy is ignored by everyone.
    const [decoy] = batchRows(creation);
    expect(P.MSG_BODY_LENS).toContain(P.fromB64u(decoy.body).length);
    expect(A.getState().warnings).toEqual([]);
    expect(B.getState().warnings).toEqual([]);
    void carol;
    void dave;
  });

  it('the creation decoy has the size class a claim for the same group would have (large group with a long name)', async () => {
    const users = Array.from({ length: 32 }, (_, i) => makeUser(`member_${String(i).padStart(2, '0')}`));
    const A = await engineFor(users[0]);
    const n0 = server().batches.length;
    const name = 'Ω'.repeat(64);
    const id = await A.createConversation(users.slice(1, 30).map((u) => u.handle), name);
    await settle(A);
    const decoyLen = P.fromB64u(batchRows(server().batches[n0])[0].body).length;
    const n1 = server().batches.length;
    await A.addMembers(id, [users[30].handle]);
    await settle(A);
    const claimLen = P.fromB64u(batchRows(server().batches[n1])[0].body).length;
    expect(claimLen).toBeGreaterThan(P.MSG_BODY_LENS[0]); // a 30-member descriptor no longer fits 1 KiB
    // Expected: an observer cannot tell creation from change by the kind-4 row's size either.
    expect(decoyLen).toBe(claimLen);
    void epoch;
  });
});

describe('privacy-4: invite order', () => {
  it('the creator\'s invite is not always first and an added member\'s invite is not always last', async () => {
    const [alice, bob, carol, dave] = ['alice', 'bob', 'carol', 'dave'].map(makeUser);
    const A = await engineFor(alice);
    const creatorPos: number[] = [];
    const addedPos: number[] = [];
    for (let k = 0; k < 12; k++) {
      const n0 = server().batches.length;
      const id = await A.createConversation(['bob', 'carol']);
      await settle(A);
      const inv = batchRows(server().batches[n0]).filter((r) => r.kind === 3);
      creatorPos.push(inv.findIndex((r) => inviteRecipients(r, [alice, bob, carol]).includes('alice')));
      const n1 = server().batches.length;
      await A.addMembers(id, ['dave']);
      await settle(A);
      const inv2 = batchRows(server().batches[n1]).filter((r) => r.kind === 3);
      expect(inv2.flatMap((r) => inviteRecipients(r, [alice, bob, carol, dave])).sort()).toEqual(['alice', 'bob', 'carol', 'dave']);
      addedPos.push(inv2.findIndex((r) => inviteRecipients(r, [dave]).length === 1));
    }
    expect(creatorPos.every((p) => p >= 0)).toBe(true);
    // P(all 12 equal by chance) = 3 * (1/3)^12 ≈ 6e-6 and 4 * (1/4)^12 ≈ 2e-7.
    expect(new Set(creatorPos).size).toBeGreaterThan(1);
    expect(new Set(addedPos).size).toBeGreaterThan(1);
  });
});
