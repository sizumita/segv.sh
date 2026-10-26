// Sending: regression tests for engine-8 / protocol-6 (slot squatting), engine-9 (echo state after races and
// lost responses) and engine-11 (sends queued across a logout).
import { describe, expect, it } from 'vite-plus/test';
import {
  buildChange,
  chat,
  engineFor,
  epoch,
  I,
  junkInviteRow,
  junkMessageRow,
  makeUser,
  mustView,
  P,
  readableWith,
  server,
  settle,
  sleep,
  systemLines,
  freshWorldPerTest,
} from './harness';

freshWorldPerTest();

async function trio() {
  const [alice, bob, mallory] = ['alice', 'bob', 'mallory'].map(makeUser);
  const A = await engineFor(alice);
  const B = await engineFor(bob);
  const M = await engineFor(mallory);
  const id = await A.createConversation(['bob', 'mallory']);
  await settle(A, B, M);
  return { alice, bob, mallory, A, B, M, id };
}

describe('engine-8 / protocol-6: an insider squatting the next message slots', () => {
  it('kind-3 and kind-4 junk on the victim\'s next slots does not mute the victim', async () => {
    const { alice, A, B, M, id } = await trio();
    const ep = epoch(M, id);
    const ai = ep.members.indexOf(alice.uidB);
    // Slots 0..5 with kind-3 rows (one batch), 6 and 7 with junk kind-4 rows (one kind-4 row per batch).
    server().mustAppend(Array.from({ length: 6 }, (_, n) => junkInviteRow(P.msgTag(ep.keys.rk, ai, n))));
    server().mustAppend([junkMessageRow(P.msgTag(ep.keys.rk, ai, 6))]);
    server().mustAppend([junkMessageRow(P.msgTag(ep.keys.rk, ai, 7))]);
    await settle(A, B, M);
    for (let k = 0; k < 3; k++) {
      await A.sendText(id, `hello ${k}`);
      await settle(A, B);
      expect(A.getState().error).toBe('');
    }
    expect(chat(B, id)).toEqual(['alice: hello 0', 'alice: hello 1', 'alice: hello 2']);
    expect(chat(A, id)).toEqual(['alice: hello 0', 'alice: hello 1', 'alice: hello 2']);
    expect(epoch(B, id).maxN[ai]).toBe(10);
    expect(B.getState().warnings.join('\n')).toMatch(/squatting a message slot|undecryptable message/);
  });

  it('a squat just beyond the receivers\' window does not mute the victim later', async () => {
    const { alice, A, B, M, id } = await trio();
    const ep = epoch(M, id);
    const ai = ep.members.indexOf(alice.uidB);
    // Slot 8 is outside every client's window (n < 8) when it lands, so nobody marks it as used.
    server().mustAppend([junkInviteRow(P.msgTag(ep.keys.rk, ai, 8))]);
    await settle(A, B, M);
    const sent: string[] = [];
    for (let k = 0; k < 10; k++) {
      await A.sendText(id, `m${k}`);
      await settle(A, B);
      sent.push(`alice: m${k}`);
    }
    // Expected: the 9th send (n = 8 -> 409) skips the burned slot and everyone still receives it.
    expect(A.getState().error).toBe('');
    expect(chat(B, id)).toEqual(sent);
  });

  it('squatting a burst of slots beyond the window does not mute the victim', async () => {
    const { alice, A, B, M, id } = await trio();
    const ep = epoch(M, id);
    const ai = ep.members.indexOf(alice.uidB);
    server().mustAppend(Array.from({ length: 40 }, (_, k) => junkInviteRow(P.msgTag(ep.keys.rk, ai, 9 + k))));
    await settle(A, B, M);
    for (let k = 0; k < 12; k++) await A.sendText(id, `m${k}`);
    await settle(A, B);
    expect(A.getState().error).toBe('');
    expect(chat(B, id)).toHaveLength(12);
  });
});

describe('engine-9: echo state', () => {
  it('a send racing a removal ends "failed" with an error, not stuck "sending"', async () => {
    const [alice, bob, carol] = ['alice', 'bob', 'carol'].map(makeUser);
    const A = await engineFor(alice);
    const C = await engineFor(carol);
    const id = await A.createConversation(['bob', 'carol']);
    await settle(A, C);
    // Alice's removal of carol (exactly what changeMembers builds) lands just before carol's append.
    const removal = buildChange(alice, id, epoch(A, id), [alice.uidB, bob.uidB]);
    server().hooks.beforeAppend = () => {
      server().hooks.beforeAppend = undefined;
      server().mustAppend(removal.rows);
    };
    await C.sendText(id, 'hi all');
    await settle(A, C);
    const mine = mustView(C, id).messages.filter((m) => m.mine);
    expect(mine.map((m) => `${m.text}:${m.status}`)).toEqual(['hi all:failed']);
    expect(C.getState().error).toMatch(/not delivered/);
    expect(chat(A, id)).toEqual([]);
    expect(mustView(C, id).canSend).toBe(false);
    // The row did land (after the claim that removed carol): it is dropped by the acceptance rule, not lost.
    expect(readableWith(epoch(A, id, 0).keys.mk).map((r) => r.payload.text)).toEqual(['hi all']);
  });

  it('a lost append response (committed on the server) leaves exactly one sent message', async () => {
    const [alice, bob] = ['alice', 'bob'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(['bob']);
    await settle(A, B);
    let once = true;
    server().hooks.fail = (m, p) => (m === 'POST' && p === '/api/append' && once ? ((once = false), 'after') : null);
    await A.sendText(id, 'hello');
    await settle(A, B);
    expect(mustView(A, id).messages.filter((m) => m.mine).map((m) => `${m.text}:${m.status}`)).toEqual(['hello:sent']);
    expect(A.getState().error).toBe('');
    expect(chat(B, id)).toEqual(['alice: hello']);
  });

  it('an append that never reached the server is reported failed, and a retry works', async () => {
    const [alice, bob] = ['alice', 'bob'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(['bob']);
    await settle(A, B);
    let once = true;
    server().hooks.fail = (m, p) => (m === 'POST' && p === '/api/append' && once ? ((once = false), 'before') : null);
    await A.sendText(id, 'lost');
    await settle(A, B);
    expect(mustView(A, id).messages.filter((m) => m.mine).map((m) => `${m.text}:${m.status}`)).toEqual(['lost:failed']);
    expect(A.getState().error).toMatch(/not delivered/);
    await A.sendText(id, 'again');
    await settle(A, B);
    expect(chat(B, id)).toEqual(['alice: again']);
  });

  it('a 409 on a message slot (another device took it) retries with the next counter', async () => {
    const [alice, bob] = ['alice', 'bob'].map(makeUser);
    const A = await engineFor(alice);
    const A2 = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(['bob']);
    await settle(A, A2, B);
    // Both devices pick n = 0 at the same time.
    await Promise.all([A.sendText(id, 'from device 1'), A2.sendText(id, 'from device 2')]);
    await settle(A, A2, B);
    expect(chat(B, id).sort()).toEqual(['alice: from device 1', 'alice: from device 2']);
    expect(A.getState().error).toBe('');
    expect(A2.getState().error).toBe('');
  });
});

describe('engine-11: a send queued before logout', () => {
  it('does not run under the next account', async () => {
    const [alice, bob, dave] = ['alice', 'bob', 'dave'].map(makeUser);
    const E = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await E.createConversation(['bob']);
    await settle(E, B);
    const mk0 = epoch(B, id).keys.mk;

    let release!: () => void;
    server().hooks.beforeAppend = () => new Promise<void>((r) => (release = r)); // the first append hangs
    const p1 = E.sendText(id, 'first (slow)');
    const p2 = E.sendText(id, 'second (queued)');
    await sleep(50);
    expect(release).toBeTypeOf('function');
    await E.logout();
    await I(E).unlock(dave.AK, dave.uid, 'dave'); // same tab, another account
    await settle(E);
    server().hooks.beforeAppend = undefined;
    release();
    await p1;
    await p2;
    await settle(E, B);

    const rows = readableWith(mk0);
    expect(rows.some((r) => r.payload.from === dave.uidB)).toBe(false);
    expect(rows.some((r) => r.payload.text === 'second (queued)')).toBe(false);
    expect(E.getState().me?.handle).toBe('dave');
    expect(E.getState().error).toBe('');
    expect(I(E).convs.size).toBe(0);
    expect(B.getState().warnings).toEqual([]);
  });

  it('an add-member action in flight across a logout is not committed by the next account', async () => {
    const [alice, bob, dave] = ['alice', 'bob', 'dave'].map(makeUser);
    const E = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await E.createConversation(['bob', 'dave']); // the next account (dave) is a member too
    await settle(E, B);
    makeUser('carol'); // registered after alice's sync: addMembers has to sync to resolve @carol
    let release!: () => void;
    server().hooks.beforeRequest = (m, p) => {
      if (m === 'GET' && p === '/api/log') {
        server().hooks.beforeRequest = undefined;
        return new Promise<void>((r) => (release = r));
      }
    };
    const p = E.addMembers(id, ['carol']).catch(() => {});
    await sleep(50);
    expect(release).toBeTypeOf('function');
    await E.logout();
    await I(E).unlock(dave.AK, dave.uid, 'dave');
    await settle(E);
    release();
    await p;
    await settle(E, B);
    expect(systemLines(B, id).join('\n')).not.toMatch(/@dave added @carol/);
    expect(mustView(B, id).epoch).toBe(0);
  });
});
