// The inbox notice topic (docs/PROTOCOL.md §9.3, §10.8, §11.5): the engine watches Tinbox(E_now − 1 .. E_now + 1) on
// its first socket, reads the inbox when a notice comes instead of polling every slot, reads once more after Δin when
// the read did not reach the announced slot, ignores other buckets, and follows the era.
import { describe, expect, it } from "vite-plus/test";
import * as W from "@segv/protocol/wire";
import {
  P,
  engineFor,
  freshWorldPerTest,
  makeUser,
  mustView,
  server,
  settle,
  sleep,
  viewsOf,
  waitFor,
} from "./harness";

freshWorldPerTest();

const inboxReads = (who: string) =>
  server().requests.filter(
    (r) => r.who === who && r.method === "GET" && r.path.startsWith("/api/v2/inbox/"),
  );
const socketsOf = (who: string) => [...server().rt.sockets].filter((ws) => ws.who === who);
const topicsOf = (who: string) => socketsOf(who).flatMap((ws) => [...ws.topics.keys()]);
const tinbox = (E: number) => P.b64u(P.topicInbox(E, 0));
/** The eras whose notices a client watches now (§10.8). */
const watched = () => {
  const E = server().era;
  return [E - 1, E, E + 1].filter((x) => x >= Math.max(server().params.efirst, E - 3));
};

describe("inbox notices (§10.8, §11.5)", () => {
  it("watches Tinbox(E − 1 .. E + 1) of bucket 0 on the first socket, next to Tself", async () => {
    const bob = makeUser("bob");
    await engineFor(bob);
    const want = watched().map(tinbox);
    expect(want.length).toBeGreaterThanOrEqual(2);
    await waitFor(() => want.every((t) => topicsOf("bob").includes(t)), "inbox topics");
    expect(socketsOf("bob")).toHaveLength(1);
    expect(topicsOf("bob")).toHaveLength(1 + want.length); // Tself and the notice topics: no conversation yet
  });

  it("reads the inbox on a notice and at no slot cadence: a first contact arrives with one read", async () => {
    const alice = makeUser("alice");
    const bob = makeUser("bob");
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    await settle(A, B);
    const before = inboxReads("bob").length;
    const notices = server().rt.notices.length;
    // Quiet: the socket is up, so nothing reads the inbox at the slot cadence.
    server().tick(5_000);
    await sleep(30);
    expect(inboxReads("bob").length).toBe(before);
    expect(server().rt.notices.length).toBe(notices);

    const id = await A.createConversation(["bob"]);
    // The invite's slot closes within 2·Δin; the notice follows SKEW + 1 s later, on the inbox clock (real time here).
    await waitFor(() => server().rt.notices.length > notices, "the notice");
    const n = server().rt.notices[notices];
    expect(n.g).toBe(0);
    expect(n.rel).toBeGreaterThanOrEqual(server().inbox.rowsOf(n.E)[0].rel);
    // Sent once the slot closed and SKEW + 1 s passed, on the inbox clock (§9.3).
    const D = server().params.inboxSlot * 1000;
    expect(n.at - server().inboxLagMs).toBeGreaterThanOrEqual(
      P.T0_MS + n.rel * D + (server().params.skew + 1) * 1000,
    );
    await waitFor(() => viewsOf(B).some((v) => v.id === id), "bob's copy");
    expect(mustView(B, id).name).toBe("@alice");
    // One read for the notice (a second one only if a retry was needed).
    expect(inboxReads("bob").length - before).toBeLessThanOrEqual(2);
    expect(inboxReads("bob").length - before).toBeGreaterThanOrEqual(1);
  });

  it("reads once more after Δin when the read did not reach the announced slot, and not a third time", async () => {
    const bob = makeUser("bob");
    const B = await engineFor(bob);
    await settle(B);
    const E = server().era;
    const before = inboxReads("bob").length;
    const closed = server().inbox.closedNow(E);
    server().rt.inbox(E, 0, closed + 3); // a notice ahead of what a read shows
    await waitFor(() => inboxReads("bob").length === before + 1, "the first read");
    await sleep(30);
    expect(inboxReads("bob").length).toBe(before + 1);
    server().tick(server().params.inboxSlot * 1000); // Δin later: the second read
    await waitFor(() => inboxReads("bob").length >= before + 2, "the second read");
    await sleep(30);
    expect(inboxReads("bob").length).toBe(before + 2);
    server().tick(server().params.inboxSlot * 1000);
    await sleep(30);
    expect(inboxReads("bob").length).toBe(before + 2);
    expect(B.getState().error).toBe("");
  });

  it("ignores a notice for another bucket", async () => {
    const bob = makeUser("bob");
    await engineFor(bob);
    await waitFor(() => socketsOf("bob").length === 1, "the socket");
    const before = inboxReads("bob").length;
    const E = server().era;
    socketsOf("bob")[0]._deliver(W.encodeServerFrame({ f: "inbox", E, g: 1, rel: 1 }));
    await sleep(50);
    expect(inboxReads("bob").length).toBe(before);
    expect(socketsOf("bob")).toHaveLength(1); // the frame parsed: the socket stays
  });

  it("follows the era: a week later the notice topics of the new eras are watched", async () => {
    const bob = makeUser("bob");
    await engineFor(bob);
    const E = server().era;
    await waitFor(() => topicsOf("bob").includes(tinbox(E + 1)), "E + 1");
    server().tick(P.ERA_MS);
    await waitFor(() => topicsOf("bob").includes(tinbox(E + 2)), "E + 2");
    await waitFor(() => !topicsOf("bob").includes(tinbox(E - 1)), "E − 1 gone");
  });
});
