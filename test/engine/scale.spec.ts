// The O(history) acceptance tests: every scenario runs in a clean world and in a noise
// world (50 000 random rows over the last four eras, 2 000 registered users, 5 000 inbox rows in older eras and 300
// for others in the current era), and the client's cost must not depend on the noise. The restore-at-scale cases
// (a long history, many groups, spam requests) need self-lane snapshots and are not here yet.
import { describe, expect, it } from "vite-plus/test";
import {
  FakeWorld,
  I,
  P,
  engineFor,
  freshWorldPerTest,
  localStore,
  makeUser,
  newEngine,
  server,
  settle,
  useWorld as installWorld,
  waitFor,
  type FakeRequest,
  type TestUser,
} from "./harness";

freshWorldPerTest();

interface Noise {
  labels: Set<string>;
}

/** The noise of §4, added through the world's attacker APIs. */
function addNoise(w: FakeWorld): Noise {
  const E = w.era;
  const labels = new Set<string>();
  for (let i = 0; i < 50_000; i++) {
    const label = P.random(16);
    const Ex = E - (i % 4);
    w.shard.commit(Ex, label, 0, P.random(P.BODY_LENS[0]));
    labels.add(`${Ex}:${P.b64u(label)}`);
  }
  for (let i = 0; i < 2000; i++) makeUser(`noise${String(i).padStart(4, "0")}`);
  const body = () => P.random(P.INBOX_BODY_LEN);
  for (let i = 0; i < 5000; i++)
    w.inbox.post(E - 4 - (i % 2), [{ eid: P.random(16), body: body() }], { ignoreCap: true });
  for (let i = 0; i < 300; i++)
    w.inbox.post(E, [{ eid: P.random(16), body: body() }], { ignoreCap: true });
  return { labels };
}

function noiseHits(w: FakeWorld, n: Noise): number {
  let hits = 0;
  for (const r of w.shard.rows())
    if (r.hits > 0 && n.labels.has(`${r.E}:${P.b64u(r.label)}`)) hits += r.hits;
  return hits;
}

/**
 * Requests of one client since index `from`, without inbox and checkpoint requests, and, when `self` is given,
 * without the probes of that account's own self lane (its length depends on how many HEADS rows the account wrote
 * while settling, which timing decides, not the noise).
 */
function measured(w: FakeWorld, who: string, from: number, self?: TestUser, untilLive = false) {
  const selfLabels = new Set<string>();
  if (self)
    for (let E = w.era - 1; E <= w.era; E++)
      for (let n = 0; n < 512; n++) selfLabels.add(P.b64u(P.Lself(self.id.rS, E, n)));
  const all = w.requests.slice(from).filter((r) => r.who === who);
  // The restore ends where the session goes live: its realtime socket opens (§11.4 step 9).
  const live = untilLive ? all.findIndex((r) => r.path === "/api/v2/rt") : -1;
  const rs = (live >= 0 ? all.slice(0, live) : all)
    .filter(
      (r: FakeRequest) =>
        r.who === who &&
        !r.path.startsWith("/api/v2/inbox") &&
        !r.path.startsWith("/api/v2/ckpt") &&
        !(r.getKeys && r.getKeys.length > 0 && r.getKeys.every((k) => selfLabels.has(P.b64u(k.label)))),
    );
  return { count: rs.length, bytes: rs.reduce((n, r) => n + r.resBytes, 0), rs };
}

/** A fresh world for the second run of a scenario (the per-browser checkpoint pin is cleared too). */
function newWorld(): FakeWorld {
  localStore.clear();
  return installWorld(new FakeWorld());
}

/** Unlocks `u` on a new engine and waits until its restore finished (no settle: only the restore is measured). */
async function restoreOnly(u: TestUser) {
  const e = newEngine(u.handle);
  await I(e).unlock(u.AK, u.uid, u.handle);
  await waitFor(() => !e.getState().syncing, `${u.handle} restore`);
  return e;
}

describe("T1: the client never downloads the log", () => {
  it("a restore and 20 more messages cost the same with 50 000 unrelated rows and 2 000 users", async () => {
    const run = async (noisy: boolean) => {
      const w = noisy ? newWorld() : server();
      const noise = noisy ? addNoise(w) : null;
      const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
      const A = await engineFor(alice);
      const B = await engineFor(bob);
      const id = await A.createConversation(["bob"]);
      await settle(A, B);
      B.markRead(id);
      for (let i = 0; i < 25; i++) await A.sendText(id, `a${i}`);
      for (let i = 0; i < 25; i++) await B.sendText(id, `b${i}`);
      await settle(A, B);
      await A.logout();
      const from = w.requests.length;
      const A2 = await restoreOnly(alice);
      const restore = measured(w, "alice", from, alice, true);
      for (let i = 0; i < 20; i++) await A2.sendText(id, `more ${i}`);
      await settle(A2, B);
      return {
        restore,
        hits: noise ? noiseHits(w, noise) : 0,
        dir: restore.rs.filter((r) => r.path.startsWith("/api/v2/dir")).map((r) => r.path),
      };
    };
    const clean = await run(false);
    const noisy = await run(true);
    expect(noisy.hits).toBe(0);
    expect(noisy.restore.count).toBe(clean.restore.count);
    expect(Math.abs(noisy.restore.bytes - clean.restore.bytes)).toBeLessThanOrEqual(
      clean.restore.bytes * 0.02,
    );
    // bob's MEMBER record is in the self lane: no prefix lookup, no dirlog read, only the own uid lookup
    expect(noisy.dir.every((p) => p.startsWith("/api/v2/dir/uid/"))).toBe(true);
    expect(noisy.dir.length).toBe(clean.dir.length);
  }, 300_000);
});

describe("T2: no trial scan of every invite", () => {
  it("inbox reads never name an era below E_now − 3, and a second restore reads none of the 300 rows again", async () => {
    const run = async (noisy: boolean) => {
      const w = noisy ? newWorld() : server();
      if (noisy) addNoise(w);
      const alice = makeUser("alice");
      const A = await engineFor(alice);
      await settle(A);
      await A.logout();
      const from = w.requests.length;
      await restoreOnly(alice);
      const inbox = w.requests
        .slice(from)
        .filter((r) => r.who === "alice" && r.path.startsWith("/api/v2/inbox"));
      return { inbox, E: w.era };
    };
    const clean = await run(false);
    const noisy = await run(true);
    for (const x of [clean, noisy])
      for (const r of x.inbox) {
        const m = /\/api\/v2\/inbox\/(\d+)/.exec(r.path);
        if (m) expect(Number(m[1])).toBeGreaterThanOrEqual(x.E - 3);
      }
    const bytes = (x: typeof clean) => x.inbox.reduce((n, r) => n + r.resBytes, 0);
    expect(Math.abs(bytes(noisy) - bytes(clean))).toBeLessThanOrEqual(bytes(clean) * 0.02 + 64);
  }, 300_000);
});

describe("T3: no global feed of rows", () => {
  it("a connected client receives no row of a conversation it is not in", async () => {
    const [alice, carol, dave] = ["alice", "carol", "dave"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const C = await engineFor(carol);
    const D = await engineFor(dave);
    const id = await C.createConversation(["dave"]);
    await settle(A, C, D);
    D.markRead(id);
    await settle(A, C, D);
    const mine = () => [...server().rt.sockets].filter((s) => s.who === "alice");
    const rx = () => mine().reduce((n, s) => n + s.rx.rows, 0);
    const before = { rows: rx(), reqs: server().requests.length };
    for (let i = 0; i < 50; i++) {
      await C.sendText(id, `c${i}`);
      await D.sendText(id, `d${i}`);
    }
    await settle(A, C, D);
    expect(mine().length).toBeGreaterThan(0);
    // Only alice's own self-lane rows (her Tself) may reach her socket meanwhile, never carol's or dave's.
    const ownRows = server()
      .requests.slice(before.reqs)
      .filter((r) => r.who === "alice" && r.path === "/api/v2/put")
      .reduce((n, r) => n + (r.putResults?.filter((x) => x.s === "ok").length ?? 0), 0);
    expect(rx() - before.rows).toBeLessThanOrEqual(ownRows);
  }, 300_000);
});

describe("T5: catch-up after being offline", () => {
  it("costs the same with 10 000 unrelated rows written meanwhile", async () => {
    const run = async (noisy: boolean) => {
      const w = noisy ? newWorld() : server();
      const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
      const A = await engineFor(alice);
      const B = await engineFor(bob);
      const id = await A.createConversation(["bob"]);
      await settle(A, B);
      B.markRead(id);
      await settle(A, B);
      await A.logout();
      if (noisy)
        for (let i = 0; i < 10_000; i++) w.shard.commit(w.era, P.random(16), 0, P.random(P.BODY_LENS[0]));
      await B.sendText(id, "while you were away");
      const A2 = await engineFor(alice);
      const from = w.requests.length;
      await I(A2).catchUp();
      return measured(w, "alice", from);
    };
    const clean = await run(false);
    const noisy = await run(true);
    expect(noisy.count).toBe(clean.count);
    expect(Math.abs(noisy.bytes - clean.bytes)).toBeLessThanOrEqual(clean.bytes * 0.02 + 64);
  }, 300_000);
});
