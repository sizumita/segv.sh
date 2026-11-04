// Deliveries, WELCOMEs, parked joins and stale times (docs/PROTOCOL.md §6.1, §6.7, §6.11, §6.12, §10.1).
import * as W from "@segv/protocol/wire";
import { describe, expect, it } from "vite-plus/test";
import { CHANGING } from "../src/conv";
import { notNotified } from "../src/deliver";
import {
  I,
  P,
  chat,
  engineFor,
  epoch,
  freshWorldPerTest,
  makeUser,
  mustView,
  newEngine,
  server,
  settle,
  sleep,
  view,
  waitFor,
  type TestUser,
} from "./harness";

freshWorldPerTest();

/** Invites per inbox post: the body is 7 + 1432·count bytes (§10.5). */
const postSizes = () =>
  server()
    .requests.filter((r) => r.method === "POST" && r.path === "/api/v2/inbox" && r.status === 200)
    .map((r) => (r.reqBytes - 3) / W.INBOX_POST_ROW_LEN);

describe("creation crash and resume", () => {
  it("a second device of the creator delivers J after RESUME_AFTER; the invitee holds the conversation", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const id = await A.createConversation(["bob"]);
    await A.logout(); // during the commit wait: no decoy, no invite
    expect(postSizes()).toEqual([]);
    const A2 = await engineFor(alice);
    await settle(A2);
    expect(postSizes()).toEqual([1]); // resumed (RESUME_AFTER is 0 in the tests); the resume skips the decoy
    const B = await engineFor(bob);
    expect(mustView(B, id).name).toBe("@alice");
    // the resumed delivery is recorded: a later device does not deliver again
    const A3 = await engineFor(alice);
    await settle(A2, A3);
    expect(postSizes()).toEqual([1]);
  });

  it("a creator stopped before the bundle upload leaves no copy", async () => {
    makeUser("bob");
    const alice = makeUser("alice");
    const A = await engineFor(alice);
    let release!: () => void;
    server().hooks.beforeRequest = (m, p) => {
      if (m === "PUT" && p.startsWith("/api/v2/blob/"))
        return new Promise<void>((r) => (release = r));
    };
    const pending = A.createConversation(["bob"]).catch(() => null);
    await sleep(50);
    await A.logout();
    server().hooks.beforeRequest = undefined;
    release();
    await pending;
    const A2 = await engineFor(alice);
    expect(I(A2).views()).toEqual([]);
  });
});

describe("a commit that gave up after its claim was stored (§6.3, §6.11)", () => {
  /** alice and bob in a group, carol registered; alice resumes another session's records only after 10 minutes. */
  async function setup() {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice, { delays: { resumeAfter: 600_000 } });
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    const id = await A.createConversation(["bob"], "g");
    await settle(A, B, C);
    await B.accept(id);
    await settle(A, B, C);
    return { A, B, C, id, carol };
  }

  /** carol was delivered J of epoch 1: she holds the conversation, and alice's DELIVERED records cover her. */
  function deliveredToCarol(A: ReturnType<typeof newEngine>, C: typeof A, id: string, uid: string) {
    expect(mustView(C, id).epoch).toBe(1);
    const covered = [...I(A).self!.fold.delivered.values()].some((s) => s.has(uid));
    expect(covered).toBe(true);
  }

  it("CHANGING after the finality wait: once the claim wins, this session delivers J", async () => {
    const { A, B, C, id, carol } = await setup();
    server().sealDelayMs = 3_600_000; // the era before the claim's stays open: the claim cannot be final
    server().advanceEra();
    const invites = postSizes().length;
    let done = false;
    let error: unknown = null;
    void A.addMembers(id, ["carol"])
      .catch((e: unknown) => (error = e))
      .finally(() => (done = true));
    for (let i = 0; i < 400 && !done; i++) {
      server().tick(1000);
      await sleep(5);
    }
    expect(done).toBe(true);
    expect((error as Error | null)?.message).toBe(CHANGING);
    server().sealPrevious();
    await settle(A, B, C);
    expect(mustView(A, id).epoch).toBe(1);
    expect(mustView(B, id).epoch).toBe(1);
    deliveredToCarol(A, C, id, carol.uidB);
    expect(postSizes().slice(invites)).toEqual([1]); // one job, one invite
  });

  it("a lost CAS answer whose probe fails: the commit's own claim wins at the next sync, and J is delivered", async () => {
    const { A, B, C, id, carol } = await setup();
    const topic = epoch(A, id).topic;
    let failUntil = 0;
    server().hooks.afterPut = (rows, _res, who) => {
      if (who !== "alice" || failUntil || !rows.some((r) => P.equalBytes(r.topic, topic))) return;
      failUntil = Date.now() + 2000;
      return "lose";
    };
    server().hooks.fail = (_m, p, who) =>
      who === "alice" && p === "/api/v2/get" && Date.now() < failUntil ? "before" : null;
    const invites = postSizes().length;
    await A.addMembers(id, ["carol"]);
    expect(failUntil).toBeGreaterThan(0);
    await settle(A, B, C);
    expect(mustView(A, id).epoch).toBe(1);
    deliveredToCarol(A, C, id, carol.uidB);
    expect(postSizes().slice(invites)).toEqual([1]);
  });
});

describe("delivery under limits", () => {
  it("rows past the day cap stay pending with one warning each, and are delivered after the day rolls over", async () => {
    const names = ["bob", "carol", "dave", "erin"];
    const users = names.map((h) => makeUser(h));
    const A = await engineFor(makeUser("alice"));
    server().inbox.dayCap = 2;
    const id = await A.createConversation(names, "capped");
    await settle(A);
    expect(postSizes()[0]).toBe(4); // one batched post
    const warnings = A.getState().warnings.filter((w) =>
      w.endsWith("has not been notified yet; retrying"),
    );
    expect(warnings).toHaveLength(2);
    server().inbox.rollDay();
    server().tick(10_000); // the first retry is due 10 s later
    await settle(A);
    for (const u of users) {
      const E = await engineFor(u);
      expect(mustView(E, id).name).toBe("# capped");
    }
    expect(warnings.every((w) => names.some((n) => w === notNotified(n)))).toBe(true);
  });
});

describe("WELCOME through a qualifying 1:1", () => {
  it("dave, offline, finds the J that came as a WELCOME in his 1:1 with alice, behind 40 texts", async () => {
    const [alice, carol, dave] = ["alice", "carol", "dave"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const D = await engineFor(dave);
    const one = await A.createConversation(["dave"]);
    await settle(A, D);
    await D.sendText(one, "hi alice"); // dave posted in the 1:1: it qualifies (§6.12 step 1)
    await settle(A, D);
    await D.logout();
    const before = postSizes().length;
    const g = await A.createConversation(["carol", "dave"], "g");
    await settle(A);
    expect(postSizes().slice(before)).toEqual([1]); // only carol by inbox
    for (let i = 0; i < 40; i++) await A.sendText(one, `text ${i}`);
    await settle(A);
    const D2 = await engineFor(dave);
    expect(mustView(D2, g).name).toBe("# g");
    expect(chat(D2, one)).toContain("alice: text 39");
    const C = await engineFor(carol);
    expect(mustView(C, g).name).toBe("# g");
  });

  it("without a row of dave in the 1:1, dave's J goes by inbox", async () => {
    const [alice, dave] = ["alice", "dave"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const D = await engineFor(dave);
    await A.createConversation(["dave"]);
    await settle(A, D);
    const before = postSizes().length;
    const g = await A.createConversation(["dave"], "g2");
    await settle(A, D);
    expect(postSizes().slice(before)).toEqual([1]);
    expect(mustView(D, g).name).toBe("# g2");
  });
});

describe("parked joins", () => {
  it("a join whose blob GET answers 503 twice is parked, holds the cursor, and is accepted once the fake recovers", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const id = await A.createConversation(["bob"]);
    await settle(A);
    const blobId = P.b64u(epoch(A, id).bundleId);
    server().blobs.failGet(blobId, Infinity); // 503 until cleared
    const B = newEngine("bob");
    await I(B).unlock(bob.AK, bob.uid, bob.handle);
    await waitFor(() => !B.getState().syncing, "bob's restore");
    await I(B).catchUp();
    expect(view(B, id)).toBeUndefined(); // parked, not dropped
    // The cursor B holds stays before the parked invite.
    const E = server().era;
    const rel = server().inbox.rowsOf(E)[0].rel;
    const c = I(B).self!.fold.cursor!;
    expect(c.E < E || (c.E === E && c.rel < rel)).toBe(true);
    server().blobs.failGet(blobId, 0);
    await settle(A, B);
    expect(mustView(B, id).name).toBe("@alice");
    expect(B.getState().warnings).toEqual([]);
  });
});

describe("a parked WELCOME (§6.7 step 4, §7.3)", () => {
  it("holds its lane's HEADS position before the row until the J is accepted, live and after a reload", async () => {
    const [alice, carol, dave] = ["alice", "carol", "dave"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const D = await engineFor(dave);
    const one = await A.createConversation(["dave"]);
    await settle(A, D);
    await D.sendText(one, "hi alice"); // the 1:1 qualifies as dave's WELCOME channel (§6.12 step 1)
    await settle(A, D);
    let failing = true;
    // the J's blob/meta fails transiently, so the WELCOME's J parks (§6.7 step 1)
    server().hooks.fail = (m, p, who) =>
      failing &&
      who === "dave" &&
      m === "GET" &&
      p.startsWith("/api/v2/blob/") &&
      p.endsWith("/meta")
        ? "before"
        : undefined;
    const g = await A.createConversation(["carol", "dave"], "g");
    await settle(A, D);
    expect(view(D, g)).toBeUndefined(); // parked, not dropped
    const ep = epoch(A, one);
    const j = P.memberIndex(ep.D, alice.uid);
    const row = ep.lanes[j].last!; // alice's WELCOME row in the 1:1
    const key = `${P.b64u(ep.D.conv)}.${P.b64u(epoch(D, one).D.hash)}`; // the 1:1 is at its root epoch
    const entry = I(D).self!.fold.headsOf(key)!;
    expect(entry.e).toBe(0);
    expect(entry.lanes[j]).toEqual({ E: row.E, cnt: row.n });
    // a reload starts from that entry, finds the WELCOME again, and parks it again
    await D.logout();
    const D2 = await engineFor(dave);
    expect(view(D2, g)).toBeUndefined();
    failing = false;
    server().hooks.fail = undefined;
    await settle(A, D2);
    expect(mustView(D2, g).name).toBe("# g");
    const after = I(D2).self!.fold.headsOf(key)!;
    expect(after.lanes[j].cnt).toBeGreaterThan(row.n);
    void carol;
  });
});

/**
 * Fails `u`'s self-lane puts that hold a CONV_JOIN with a 500 while `failing()` (nothing is stored), counting them.
 */
function failJoinPuts(u: TestUser, failing: () => boolean): { count: number } {
  const n = { count: 0 };
  server().hooks.beforePut = (rows, who) => {
    if (who !== u.handle || !failing()) return;
    for (const r of rows) {
      let recs: P.SelfRecord[];
      try {
        recs = P.openSelf(u.id.kS, r.E, r.label, r.body).records;
      } catch {
        continue;
      }
      if (recs.some((x) => x.rtype === P.RT.CONV_JOIN)) {
        n.count++;
        throw new Error("CONV_JOIN put fails");
      }
    }
  };
  return n;
}

/** Alice and dave with a 1:1 in which dave has posted, so it is dave's WELCOME channel (§6.12 step 1). */
async function welcomeChannel() {
  const [alice, carol, dave] = ["alice", "carol", "dave"].map((h) => makeUser(h));
  const A = await engineFor(alice);
  const D = await engineFor(dave);
  const one = await A.createConversation(["dave"]);
  await settle(A, D);
  await D.sendText(one, "hi alice");
  await settle(A, D);
  const key = `${P.b64u(epoch(A, one).D.conv)}.${P.b64u(epoch(D, one).D.hash)}`; // the 1:1 is at its root epoch
  const j = P.memberIndex(epoch(A, one).D, alice.uid);
  return { alice, carol, dave, A, D, one, key, j };
}

describe("a WELCOME whose CONV_JOIN write fails (§6.7 step 1, §7.3 Durability order)", () => {
  it("keeps the J and the lane's HEADS position before the row until the write is CAS OK", async () => {
    const { dave, A, D, one, key, j } = await welcomeChannel();
    let failing = true;
    const fails = failJoinPuts(dave, () => failing);
    const g = await A.createConversation(["carol", "dave"], "g");
    await settle(A, D);
    expect(fails.count).toBeGreaterThan(0);
    expect(view(D, g)).toBeUndefined();
    const row = epoch(A, one).lanes[j].last!; // alice's WELCOME row in the 1:1
    // the lane moves on past the WELCOME; HEADS keeps the lane before it
    await A.sendText(one, "after the welcome");
    await settle(A, D);
    expect(chat(D, one)).toContain("alice: after the welcome");
    expect(I(D).self!.fold.headsOf(key)!.lanes[j]).toEqual({ E: row.E, cnt: row.n });
    // the next catch-up writes it
    failing = false;
    await settle(A, D);
    expect(mustView(D, g).name).toBe("# g");
    expect(I(D).self!.fold.headsOf(key)!.lanes[j].cnt).toBeGreaterThan(row.n);
  });

  it("a parked J whose retry fails to write stays parked, with the other parked Js", async () => {
    const { dave, A, D, one, key, j } = await welcomeChannel();
    let metaFails = true;
    server().hooks.fail = (m, p, who) =>
      metaFails &&
      who === "dave" &&
      m === "GET" &&
      p.startsWith("/api/v2/blob/") &&
      p.endsWith("/meta")
        ? "before"
        : undefined;
    const g = await A.createConversation(["carol", "dave"], "g");
    await settle(A, D);
    const h = await A.createConversation(["carol", "dave"], "h");
    await settle(A, D);
    expect(view(D, g)).toBeUndefined(); // both parked
    expect(view(D, h)).toBeUndefined();
    const rowH = epoch(A, one).lanes[j].last!; // the WELCOME of h
    // meta recovers; the CONV_JOIN put of the retry fails once
    metaFails = false;
    server().hooks.fail = undefined;
    let once = true;
    const fails = failJoinPuts(dave, () => once);
    await I(D)
      .catchUp()
      .catch(() => {});
    expect(fails.count).toBe(1);
    once = false;
    await A.sendText(one, "after the welcomes");
    await settle(A, D);
    expect(mustView(D, g).name).toBe("# g");
    expect(mustView(D, h).name).toBe("# h");
    expect(I(D).self!.fold.headsOf(key)!.lanes[j].cnt).toBeGreaterThan(rowH.n);
  });
});

describe("a WELCOME before the processed position (§11.10)", () => {
  it("whose J no copy holds still goes through §6.7: a group whose J was never recorded is recovered", async () => {
    const { A, D, one, key, j, dave } = await welcomeChannel();
    // a device that drops the J without recording it (as one whose CONV_JOIN write failed once could)
    const m = (D as unknown as { msg: { processJoins: () => Promise<string[]> } }).msg;
    const real = m.processJoins;
    m.processJoins = async () => ["dropped"];
    const g = await A.createConversation(["carol", "dave"], "g");
    await settle(A, D);
    m.processJoins = real;
    const row = epoch(A, one).lanes[j].last!;
    await A.sendText(one, "after the welcome");
    await settle(A, D);
    expect(view(D, g)).toBeUndefined();
    expect(I(D).self!.fold.headsOf(key)!.lanes[j].cnt).toBeGreaterThan(row.n); // HEADS is past the WELCOME
    await D.logout();
    // the reload's initial history reads the row again
    const D2 = await engineFor(dave);
    await settle(A, D2);
    expect(mustView(D2, g).name).toBe("# g");
    expect(D2.getState().warnings).toEqual([]);
    // and the next reload holds it, and skips the WELCOME by its bundle: no `meta` request of §6.7 step 1
    const from = server().requests.length;
    await D2.logout();
    const D3 = await engineFor(dave);
    await settle(A, D3);
    expect(mustView(D3, g).name).toBe("# g");
    const meta = `/api/v2/blob/${P.b64u(epoch(A, g).bundleId)}/meta`;
    expect(
      server()
        .requests.slice(from)
        .filter((r) => r.who === "dave" && r.path === meta),
    ).toEqual([]);
  });
});

describe("stale server time", () => {
  it("cacheable responses with a weeks-old x-segv-now never move the estimate", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(["bob"]);
    await settle(A, B);
    server().staleNow = true;
    await I(B).catchUp(); // inbox reads are public (cacheable)
    const s = I(B).timeSample!;
    const est = s.s + (I(B).clock.mono() - s.mid);
    expect(Math.abs(est - server().now())).toBeLessThan(2000);
    await B.sendText(id, "still now");
    await settle(A, B);
    expect(chat(A, id)).toEqual(["bob: still now"]);
    expect(B.getState().error).toBe("");
  });
});
