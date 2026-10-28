// The O(history) acceptance tests: every scenario runs in a clean world and in a noise
// world (50 000 random rows over the last four eras, 2 000 registered users, 5 000 inbox rows in older eras and 300
// for others in the current era), and the client's cost must not depend on the noise. The restore-at-scale cases
// (a long history, many groups, spam requests) restore from a self-lane snapshot and HEADS (§7.4, §11.4).
import { describe, expect, it } from "vite-plus/test";
import { HISTORY_INITIAL } from "../../src/client/conv";
import {
  FakeWorld,
  I,
  P,
  buildMessage,
  engineFor,
  epoch,
  forgeJoin,
  freshWorldPerTest,
  localStore,
  makeUser,
  newEngine,
  postRow,
  server,
  settle,
  useWorld as installWorld,
  waitFor,
  writeSelfRow,
  type BuiltRow,
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
      await B.accept(id);
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
    await D.accept(id);
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
      await B.accept(id);
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

/** Posts `count` TEXT rows of `from` on its lane of epoch `ep` in the current era, chained as its device chains them. */
function postTexts(ep: Parameters<typeof buildMessage>[1], from: TestUser, count: number, first = 0): void {
  let prev: (BuiltRow & { n: number }) | undefined;
  const E = server().era;
  for (let i = 0; i < count; i++) {
    const n = first + i;
    const row = buildMessage(from, ep, { E, n, prev }, { type: P.MT.TEXT, text: `m${n}` } as P.MBody);
    postRow(ep, row);
    prev = { ...row, n };
  }
}

/** Get keys of `who` since request index `from` whose label is one of `labels`, with their statuses. */
function keysOn(w: FakeWorld, who: string, from: number, labels: Set<string>) {
  const out: { mode: number; hit: boolean }[] = [];
  for (const r of w.requests.slice(from))
    if (r.who === who && r.getKeys)
      r.getKeys.forEach((k, i) => {
        if (labels.has(P.b64u(k.label))) out.push({ mode: k.mode, hit: r.getStatuses?.[i]?.s === "hit" });
      });
  return out;
}

describe("T4: no replay of the whole history on a new device", () => {
  it("a restore costs the same with 2 000 or 4 000 messages and a compacted self state", async () => {
    const run = async (messages: number, headsRows: number, fresh: boolean) => {
      const w = fresh ? newWorld() : server();
      const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
      const A = await engineFor(alice);
      const B = await engineFor(bob);
      const id = await A.createConversation(["bob"]);
      await settle(A, B);
      await B.accept(id);
      await settle(A, B);
      const ep = epoch(A, id);
      postTexts(ep, bob, messages);
      await settle(A, B);
      // the self lane's HEADS history differs (300 overwrites against 3); the snapshot compacts it
      for (let i = 0; i < headsRows; i++)
        writeSelfRow(alice, [{ rtype: P.RT.HEADS, Ein: w.era, relIn: 0, entries: [] }]);
      w.advanceEra(); // a snapshot and HEADS written just before the measured restore
      await settle(A, B);
      await A.logout();
      const from = w.requests.length;
      await restoreOnly(alice);
      const restore = measured(w, "alice", from, alice, true);
      const j = P.memberIndex(ep.D, bob.uid);
      const lane = new Set<string>();
      for (let n = 0; n < messages; n++) lane.add(P.b64u(P.Lmsg(ep.keys.rk, j, w.era - 1, n)));
      const bodies = keysOn(w, "alice", from, lane).filter((k) => k.mode === 0 && k.hit).length;
      return { restore, bodies };
    };
    const short = await run(2000, 300, false);
    const long = await run(4000, 3, true);
    expect(Math.abs(long.restore.count - short.restore.count)).toBeLessThanOrEqual(1);
    expect(Math.abs(long.restore.bytes - short.restore.bytes)).toBeLessThanOrEqual(short.restore.bytes * 0.05);
    expect(short.bodies).toBe(HISTORY_INITIAL);
    expect(long.bodies).toBe(HISTORY_INITIAL);
  }, 600_000);

  it("with many self records and no snapshot of them, the restore writes one, and the next restore's self probes are few", async () => {
    const alice = makeUser("alice");
    const A = await engineFor(alice);
    await settle(A);
    await A.logout();
    for (let i = 0; i < 10; i++)
      writeSelfRow(
        alice,
        Array.from(
          { length: 200 },
          (): P.SelfRecord => ({ rtype: P.RT.CONTACT, uid: P.random(16), pin: P.random(32) }),
        ),
      );
    const A2 = await engineFor(alice); // applies 2 000 records: more than 200 since the snapshot it read
    await settle(A2);
    await A2.logout();
    const w = server();
    const from = w.requests.length;
    await restoreOnly(alice);
    const self = new Set<string>();
    for (let E = w.era - 1; E <= w.era; E++)
      for (let n = 0; n < 512; n++) self.add(P.b64u(P.Lself(alice.id.rS, E, n)));
    // the restore's requests: up to its session going live (its realtime socket, §11.4 step 9)
    const mine = w.requests.slice(from).filter((r) => r.who === "alice");
    const live = mine.findIndex((r) => r.path === "/api/v2/rt");
    const gets = (live >= 0 ? mine.slice(0, live) : mine).filter((r) =>
      r.getKeys?.some((k) => self.has(P.b64u(k.label))),
    );
    expect(gets.length).toBeLessThanOrEqual(2);
  }, 300_000);
});

describe("T7: spam requests", () => {
  it("100 spam joins before the snapshot cost a restore at most 64 × (2·32 + 3) probe keys, no bundle and no lookup", async () => {
    const run = async (spam: number, fresh: boolean) => {
      const w = fresh ? newWorld() : server();
      const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
      const A = await engineFor(alice);
      const B = await engineFor(bob);
      const id = await A.createConversation(["bob"]);
      await settle(A, B);
      await B.accept(id);
      postTexts(epoch(A, id), bob, 40);
      await settle(A, B);
      for (let i = 0; i < spam; i++) {
        const s = makeUser(`spam${String(i).padStart(4, "0")}`);
        const conv = P.random(16);
        const EK = P.random(32);
        const keys = P.epochKeys(EK, conv, 0);
        const members = [s, alice];
        const D = P.encodeD({
          conv,
          e: 0,
          prev: P.ZERO32,
          by: s.uid,
          ts: w.now(),
          members: members.map((u) => ({ uid: u.uid, sigPk: u.id.sigPk, kh: P.kemHash(u.id.kemPk) })),
          name: null,
        });
        const b = P.buildBundle({
          conv,
          e: 0,
          D,
          dsig: P.signD(D, keys.kc, s.id.sigSk),
          EK,
          pks: members.map((u) => u.id.kemPk),
          prevMembers: [],
          rm: 0,
        });
        const reg = w.putBlob(b.blob);
        forgeJoin(alice, { conv, e: 0, EK, bundleId: P.fromB64u(reg.id), bundleSize: b.blob.length });
      }
      await settle(A, B);
      w.advanceEra(); // the snapshot holds the live requests
      await settle(A, B);
      await A.logout();
      const from = w.requests.length;
      const A2 = await restoreOnly(alice);
      const restore = measured(w, "alice", from, alice, true);
      const keys = restore.rs.reduce((n, r) => n + (r.getKeys?.length ?? 0), 0);
      const blobs = restore.rs.filter((r) => r.method === "GET" && /^\/api\/v2\/blob\/[^/]+$/.test(r.path));
      const dir = restore.rs.filter((r) => r.path.startsWith("/api/v2/dir") && !r.path.startsWith("/api/v2/dir/uid/"));
      return { restore, keys, blobs: blobs.length, dir: dir.length, requests: I(A2).views().filter((v) => v.request).length };
    };
    const clean = await run(0, false);
    const spam = await run(100, true);
    expect(spam.requests).toBe(64);
    expect(spam.keys - clean.keys).toBeLessThanOrEqual(64 * (2 * 32 + 3));
    expect(spam.blobs - clean.blobs).toBe(0);
    expect(spam.dir).toBe(0);
  }, 600_000);
});

describe("T6: restore at scale", () => {
  it("50 groups of 32 members: under 600 requests, no bundle under DESC, history for 20 copies, one directory request", async () => {
    const w = server();
    const others = Array.from({ length: 1000 }, (_, i) => makeUser(`m${String(i).padStart(4, "0")}`));
    for (let i = 0; i < 1000; i++) makeUser(`x${String(i).padStart(4, "0")}`); // 2 000 users in the directory
    const alice = makeUser("alice");
    const A = await engineFor(alice);
    const ids: string[] = [];
    for (let g = 0; g < 50; g++) {
      const members = Array.from({ length: 31 }, (_, k) => others[(g * 20 + k) % others.length]);
      const id = await A.createConversation(
        members.map((u) => u.handle),
        `g${g}`,
      );
      ids.push(id);
      postTexts(epoch(A, id), members[0], 40);
    }
    await settle(A);
    w.advanceEra(); // HEADS and the snapshot are current
    await settle(A);
    await A.logout();
    const from = w.requests.length;
    const A2 = await restoreOnly(alice);
    const mine = w.requests.slice(from).filter((r) => r.who === "alice");
    const live = mine.findIndex((r) => r.path === "/api/v2/rt");
    const restore = live >= 0 ? mine.slice(0, live) : mine;
    expect(restore.length).toBeLessThan(600);
    const blobs = restore.filter((r) => r.method === "GET" && /^\/api\/v2\/blob\/[^/]+$/.test(r.path));
    expect(blobs.length).toBeLessThanOrEqual(1); // the snapshot's own blob only
    const dir = restore.filter((r) => r.path.startsWith("/api/v2/dir"));
    expect(dir.map((r) => r.path.split("/").slice(0, 5).join("/"))).toEqual(["/api/v2/dir/uid"]);
    const withHistory = ids.filter((id) => (I(A2).views().find((v) => v.id === id)?.messages.length ?? 0) > 1);
    expect(withHistory.length).toBe(20);
  }, 900_000);
});
