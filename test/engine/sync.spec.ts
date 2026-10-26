// Log sync, warnings and scan cost: regression tests for engine-2 / server-1 (short pages), web-2 (warning
// eviction) and engine-6 (per-invite tag amplification).
import { describe, expect, it } from 'vite-plus/test';
import {
  buildMessage,
  chat,
  engineFor,
  epoch,
  I,
  invitesFor,
  junkInvite,
  junkInviteRow,
  junkMessageRow,
  localStore,
  makeUser,
  mustView,
  newEngine,
  P,
  PAGE_BODY_BUDGET,
  server,
  settle,
  signEpoch,
  sleep,
  freshWorldPerTest,
  waitFor,
} from './harness';

freshWorldPerTest();

const CHECKPOINT_KEY = 'segv.checkpoint';

/** > 4 MiB of junk an anonymous client can append: one 16 KiB-class kind-4 row per batch (server rule). */
function junkRegion(rows = 260) {
  for (let i = 0; i < rows; i++) server().mustAppend([junkMessageRow(P.random(16), 2)]);
  const bytes = server().rows.reduce((n, r) => n + (r.kind === 4 ? P.fromB64u(r.body).length : 0), 0);
  expect(bytes).toBeGreaterThan(PAGE_BODY_BUDGET);
}

describe('engine-2 / server-1: pages cut by the 4 MiB body budget', () => {
  it('a user registered after > 4 MiB of junk syncs to the head and reaches ready', async () => {
    server().wsEnabled = false; // the initial backfill alone must reach the head
    const alice = makeUser('alice');
    const bob = makeUser('bob');
    junkRegion();
    // A second junk region of kind-3 rows (40 per batch is legal for invites).
    for (let b = 0; b < 33; b++) server().mustAppend(Array.from({ length: 40 }, () => junkInviteRow()));
    const victim = makeUser('victim');
    const A = await engineFor(alice);
    const id = await A.createConversation(['bob', 'victim']);
    await A.sendText(id, 'after the junk');
    await settle(A);

    const V = await engineFor(victim);
    expect(V.getState().phase).toBe('ready');
    expect(V.getState().error).toBe('');
    expect(I(V).head.seq).toBe(server().head.seq);
    expect(chat(V, id)).toEqual(['alice: after the junk']);
    const B = await engineFor(bob);
    expect(I(B).head.seq).toBe(server().head.seq);
    expect(chat(B, id)).toEqual(['alice: after the junk']);
    expect(V.getState().warnings).toEqual([]);
    // The fake really did return short pages.
    expect(server().since(0, 1000).rows.length).toBeLessThan(1000);
  });

  it('a returning device does not report a false rollback after a short page', async () => {
    server().wsEnabled = false;
    const alice = makeUser('alice');
    const bob = makeUser('bob');
    junkRegion();
    const A = await engineFor(alice);
    await A.createConversation(['bob']);
    await settle(A);
    const B1 = await engineFor(bob);
    expect(I(B1).head.seq).toBe(server().head.seq);
    await B1.logout();
    const B2 = await engineFor(bob);
    expect(I(B2).head.seq).toBe(server().head.seq);
    expect(B2.getState().warnings).toEqual([]);
    expect(I(B2).convs.size).toBe(1);
  });

  it('a transient log fetch failure during the first sync is not fatal', async () => {
    const alice = makeUser('alice');
    let failed = 0;
    server().hooks.fail = (method, path) => (method === 'GET' && path === '/api/log' && failed++ === 0 ? 'before' : null);
    const A = newEngine();
    await I(A).unlock(alice.AK, alice.uid, 'alice');
    await sleep(300);
    // Expected: the engine retries (or waits for the feed) instead of declaring the account missing.
    expect(A.getState().phase).not.toBe('fatal');
    await waitFor(() => I(A).head.seq === server().head.seq, 'catch-up after the failed page', 3000);
    expect(A.getState().phase).toBe('ready');
  });

  it('detects a rewritten history at the checkpoint and keeps warning in later sessions', async () => {
    const alice = makeUser('alice');
    localStore.set(CHECKPOINT_KEY, JSON.stringify({ seq: 1, h: P.b64u(P.random(32)) }));
    const A = await engineFor(alice);
    expect(A.getState().warnings.join('\n')).toMatch(/history was rewritten/);
    await A.logout();
    const A2 = await engineFor(alice);
    expect(A2.getState().warnings.join('\n')).toMatch(/history was rewritten/);
  });

  it('detects a rolled-back log', async () => {
    const alice = makeUser('alice');
    localStore.set(CHECKPOINT_KEY, JSON.stringify({ seq: server().head.seq + 10, h: P.b64u(P.random(32)) }));
    const A = await engineFor(alice);
    expect(A.getState().warnings.join('\n')).toMatch(/rolled back/);
  });
});

describe('web-2: warnings', () => {
  it('junk invites do not evict a checkpoint-rewrite warning and are deduplicated', async () => {
    const alice = makeUser('alice');
    localStore.set(CHECKPOINT_KEY, JSON.stringify({ seq: 1, h: P.b64u(P.random(32)) }));
    const target = server().user(alice.uidB);
    for (let b = 0; b < 3; b++) server().mustAppend(Array.from({ length: 40 }, () => junkInvite(target)));
    const A = await engineFor(alice);
    const w = A.getState().warnings;
    expect(w[0]).toMatch(/history was rewritten/);
    expect(w.filter((x) => /undecryptable invite/.test(x))).toHaveLength(1);
    expect(w.length).toBeLessThanOrEqual(1 + 5);
  });

  it('a deduplicated noise warning shows how often it happened', async () => {
    const alice = makeUser('alice');
    const target = server().user(alice.uidB);
    for (let b = 0; b < 3; b++) server().mustAppend(Array.from({ length: 40 }, () => junkInvite(target)));
    const A = await engineFor(alice);
    expect(A.getState().warnings).toEqual(['ignored an undecryptable invite addressed to you (×120)']);
  });

  it('a split-view warning survives a flood of every kind of noise', async () => {
    const [alice, bob, mallory] = ['alice', 'bob', 'mallory'].map(makeUser);
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const M = await engineFor(mallory);
    const id = await A.createConversation(['bob', 'mallory']);
    await settle(A, B, M);
    // Bob claims a different hash for log entry #1: split view.
    const ep = epoch(B, id);
    server().mustAppend([buildMessage(bob, id, ep, 0, { text: 'hi', head: { seq: 1, h: P.b64u(P.random(32)) } })]);
    await settle(A);
    expect(A.getState().warnings.join('\n')).toMatch(/split view: @bob/);

    // Many distinct noise warnings from an insider and an outsider.
    const mep = epoch(M, id);
    const ai = mep.members.indexOf(alice.uidB);
    const t = server().user(alice.uidB);
    server().mustAppend(Array.from({ length: 40 }, () => junkInvite(t))); // undecryptable invites
    server().mustAppend([junkInviteRow(P.msgTag(mep.keys.rk, ai, 0))]); // squatted slot
    server().mustAppend([junkMessageRow(P.msgTag(mep.keys.rk, ai, 1))]); // undecryptable message
    const bad = signEpoch({ conv: P.b64u(P.random(16)), e: 0, members: [alice.uidB, mallory.uidB], by: mallory, prev: null });
    server().mustAppend(invitesFor([alice.uidB], bad.dText, P.random(32), bad.dsig)); // invalid signature
    server().mustAppend([junkMessageRow(P.claimTag(mep.keys.rk))]); // burned claim slot
    for (let k = 0; k < 10; k++) server().mustAppend(Array.from({ length: 40 }, () => junkInvite(t)));
    await settle(A);
    const w = A.getState().warnings;
    expect(w[0]).toMatch(/split view: @bob/);
    const noise = w.filter((x) => !/split view|rewritten|rolled back/.test(x));
    expect(noise.length).toBeLessThanOrEqual(5);
    expect(new Set(w).size).toBe(w.length);
    expect(w.filter((x) => /undecryptable invite addressed to you/.test(x))).toHaveLength(1);
  });

  it('one insider cannot flood the never-evicted critical list with distinct split-view warnings', async () => {
    const [alice, mallory] = ['alice', 'mallory'].map(makeUser);
    const A = await engineFor(alice);
    const M = await engineFor(mallory);
    const id = await A.createConversation(['mallory']);
    for (let k = 0; k < 20; k++) await A.sendText(id, `filler ${k}`); // log entries to "disagree" about
    await settle(A, M);
    const ep = epoch(M, id);
    for (let n = 0; n < 30; n++) {
      // Each message claims a different log entry differs: one unique critical warning each.
      server().mustAppend([buildMessage(mallory, id, ep, n, { text: `x${n}`, head: { seq: 2 + n, h: P.b64u(P.random(32)) } })]);
      await settle(A);
    }
    const critical = A.getState().warnings.filter((x) => /split view/.test(x));
    // Expected: deduplicated per sender (one line, maybe with a count), not one line per forged entry.
    expect(critical.length).toBeLessThanOrEqual(1);
  });
});

describe('engine-6: invite spam amplification', () => {
  it('each spam invite registers at most members*8+1 tags', async () => {
    const victim = makeUser('victim');
    const others = Array.from({ length: 31 }, (_, i) => makeUser(`u${String(i).padStart(2, '0')}`));
    const attacker = others[0];
    const members = [attacker.uidB, victim.uidB, ...others.slice(1).map((u) => u.uidB)];
    const N = 120;
    let batch: P.Row[] = [];
    for (let k = 0; k < N; k++) {
      const s = signEpoch({ conv: P.b64u(P.random(16)), e: 0, members, by: attacker, prev: null });
      batch.push(...invitesFor([victim.uidB], s.dText, s.EK, s.dsig)); // only the victim's invite is needed
      if (batch.length === 40) {
        server().mustAppend(batch);
        batch = [];
      }
    }
    if (batch.length) server().mustAppend(batch);
    const V = await engineFor(victim);
    const x = I(V);
    expect(x.convs.size).toBe(N);
    const perEpoch = new Map<object, number>();
    for (const t of x.tags.values()) perEpoch.set(t.ep, (perEpoch.get(t.ep) ?? 0) + 1);
    expect(perEpoch.size).toBe(N);
    for (const [ep, n] of perEpoch) expect(n).toBeLessThanOrEqual((ep as { members: string[] }).members.length * 8 + 1);
    expect(x.tags.size).toBeLessThanOrEqual(N * (32 * 8 + 1));
  });

  it('the window slides as a member sends and stays bounded', async () => {
    const alice = makeUser('alice');
    const bob = makeUser('bob');
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(['bob']);
    await settle(A, B);
    for (let k = 0; k < 20; k++) await A.sendText(id, `m${k}`);
    await settle(A, B);
    expect(chat(B, id)).toHaveLength(20);
    const ep = epoch(B, id);
    const ai = ep.members.indexOf(alice.uidB);
    const watched = [...I(B).tags.values()].filter((t) => t.ep === ep && t.type === 'msg' && t.i === ai);
    expect(watched.length).toBe(8);
    expect(mustView(B, id).messages.length).toBeGreaterThan(0);
  });
});
