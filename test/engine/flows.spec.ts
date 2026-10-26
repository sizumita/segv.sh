// Honest end-to-end flows of the real engine against the fake Worker: 1:1 and group messaging,
// add / remove / leave / rename system lines, and the "# " group-name prefix.
import { describe, expect, it } from 'vite-plus/test';
import {
  buildChange,
  chat,
  engineFor,
  epoch,
  makeUser,
  mustView,
  server,
  settle,
  systemLines,
  freshWorldPerTest,
  view,
} from './harness';

freshWorldPerTest();

describe('1:1 conversations', () => {
  it('creates a conversation and delivers messages both ways', async () => {
    const alice = makeUser('alice');
    const bob = makeUser('bob');
    const A = await engineFor(alice);
    const B = await engineFor(bob);

    const id = await A.createConversation(['@bob']);
    await settle(A, B);
    expect(systemLines(A, id)).toEqual(['you started the conversation']);
    expect(systemLines(B, id)).toEqual(['@alice started the conversation']);
    expect(mustView(A, id).name).toBe('@bob');
    expect(mustView(B, id).name).toBe('@alice');
    expect(mustView(A, id).members.map((m) => m.handle).sort()).toEqual(['alice', 'bob']);

    await A.sendText(id, 'hi bob');
    await settle(A, B);
    await B.sendText(id, 'hi alice');
    await settle(A, B);
    expect(chat(A, id)).toEqual(['alice: hi bob', 'bob: hi alice']);
    expect(chat(B, id)).toEqual(['alice: hi bob', 'bob: hi alice']);
    expect(mustView(B, id).unread).toBeGreaterThanOrEqual(1);
    // The local echo was replaced by the row from the log (exactly one copy, status 'sent').
    expect(mustView(A, id).messages.filter((m) => m.mine)).toHaveLength(1);
    expect(mustView(A, id).messages.find((m) => m.mine)!.status).toBe('sent');
    expect(A.getState().error).toBe('');
    expect(A.getState().warnings).toEqual([]);
    expect(B.getState().warnings).toEqual([]);
  });

  it('a later device of the same account sees the history', async () => {
    const alice = makeUser('alice');
    const bob = makeUser('bob');
    const A = await engineFor(alice);
    const id = await A.createConversation(['bob']);
    await A.sendText(id, 'one');
    await A.sendText(id, 'two');
    await settle(A);
    const A2 = await engineFor(alice);
    const B = await engineFor(bob);
    expect(chat(A2, id)).toEqual(['alice: one', 'alice: two']);
    expect(chat(B, id)).toEqual(['alice: one', 'alice: two']);
    // Own rows from another device advance this device's counter: no 409 loop.
    await A2.sendText(id, 'three');
    await settle(A, A2, B);
    expect(chat(B, id)).toEqual(['alice: one', 'alice: two', 'alice: three']);
    expect(A2.getState().error).toBe('');
  });

  it('rejects unknown handles and empty conversations', async () => {
    const alice = makeUser('alice');
    const A = await engineFor(alice);
    await expect(A.createConversation(['nobody'])).rejects.toThrow(/unknown: @nobody/);
    await expect(A.createConversation(['alice'])).rejects.toThrow(/at least one other/);
  });
});

describe('groups', () => {
  it('delivers group messages to every member and marks chosen names with "# "', async () => {
    const [alice, bob, carol] = ['alice', 'bob', 'carol'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const id = await A.createConversation(['bob, carol'], 'team');
    await settle(A, B, C);
    for (const E of [A, B, C]) expect(mustView(E, id).name).toBe('# team');

    await A.sendText(id, 'from alice');
    await settle(A, B, C);
    await B.sendText(id, 'from bob');
    await settle(A, B, C);
    await C.sendText(id, 'from carol');
    await settle(A, B, C);
    for (const E of [A, B, C]) expect(chat(E, id)).toEqual(['alice: from alice', 'bob: from bob', 'carol: from carol']);
  });

  it('a name can never pass for a 1:1 and unnamed groups list the other members', async () => {
    const [alice, _bob, carol] = ['alice', 'bob', 'carol'].map(makeUser);
    const A = await engineFor(alice);
    await expect(A.createConversation(['bob'], '@bob')).rejects.toThrow(/cannot start with/);
    const id = await A.createConversation(['bob', 'carol']);
    const id2 = await A.createConversation(['bob'], '  ‮evil\u0007  name ');
    await settle(A);
    expect(mustView(A, id).name).toBe('@bob, @carol');
    expect(mustView(A, id2).name).toBe('# evil name'); // control / bidi characters stripped, whitespace collapsed
    void carol;
  });

  it('shows add, remove and rename system lines to everyone', async () => {
    const [alice, bob, carol, dave] = ['alice', 'bob', 'carol', 'dave'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const D = await engineFor(dave);
    const id = await A.createConversation(['bob', 'carol'], 'team');
    await settle(A, B, C);

    await A.addMembers(id, ['dave']);
    await settle(A, B, C, D);
    expect(systemLines(A, id).at(-1)).toBe('you added @dave');
    expect(systemLines(B, id).at(-1)).toBe('@alice added @dave');
    expect(systemLines(D, id)).toEqual(['@alice added you']);
    expect(mustView(D, id).name).toBe('# team');
    expect(mustView(B, id).epoch).toBe(1);

    await B.removeMember(id, carol.uidB);
    await settle(A, B, C, D);
    expect(systemLines(A, id).at(-1)).toBe('@bob removed @carol');
    expect(systemLines(B, id).at(-1)).toBe('you removed @carol');
    expect(systemLines(C, id).at(-1)).toBe('@bob removed you');
    expect(mustView(C, id).canSend).toBe(false);

    await A.sendText(id, 'carol cannot read this');
    await settle(A, B, C, D);
    expect(chat(B, id)).toEqual(['alice: carol cannot read this']);
    expect(chat(D, id)).toEqual(['alice: carol cannot read this']);
    expect(chat(C, id)).toEqual([]);
    await C.sendText(id, 'am I here?');
    expect(C.getState().error).toMatch(/no longer a member/);

    // Rename: a well-formed change whose descriptor carries a new name (no UI action builds one yet).
    const ep = epoch(A, id);
    server().mustAppend(buildChange(alice, id, ep, ep.members, 'new name').rows);
    await settle(A, B, D);
    expect(systemLines(B, id).at(-1)).toBe('@alice renamed the conversation to “new name”');
    expect(systemLines(A, id).at(-1)).toBe('you renamed the conversation to “new name”');
    expect(mustView(D, id).name).toBe('# new name');

    const ep2 = epoch(A, id);
    server().mustAppend(buildChange(alice, id, ep2, ep2.members, null).rows);
    await settle(A, B, D);
    expect(systemLines(B, id).at(-1)).toBe('@alice removed the conversation name');
    expect(mustView(B, id).name).toBe('@alice, @dave');
    for (const E of [A, B, C, D]) expect(E.getState().warnings).toEqual([]);
  });

  it('leave: the leaver stops, the next sender rotates the keys and the leaver cannot read on', async () => {
    const [alice, bob, carol] = ['alice', 'bob', 'carol'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const id = await A.createConversation(['bob', 'carol']);
    await settle(A, B, C);

    await B.leave(id);
    await settle(A, B, C);
    expect(systemLines(A, id).at(-1)).toBe('@bob left');
    expect(systemLines(B, id).at(-1)).toBe('you left the conversation');
    expect(mustView(B, id).canSend).toBe(false);
    expect(mustView(A, id).members.find((m) => m.handle === 'bob')!.left).toBe(true);

    await A.sendText(id, 'after bob left');
    await settle(A, B, C);
    expect(mustView(A, id).epoch).toBe(1);
    expect(mustView(A, id).members.map((m) => m.handle).sort()).toEqual(['alice', 'carol']);
    expect(systemLines(C, id)).toContain('keys rotated after @bob left');
    expect(chat(C, id)).toEqual(['alice: after bob left']);
    expect(chat(B, id)).toEqual([]);
    expect(view(B, id)!.epoch).toBe(0);
    expect(A.getState().error).toBe('');
    // The leaver's own timeline says so once (the leave row), not again when the rotation lands.
    expect(systemLines(B, id).filter((l) => l === 'you left the conversation')).toHaveLength(1);
  });
});
