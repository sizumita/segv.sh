// Inbox buckets (docs/PROTOCOL.md §9.3 "Buckets", §10.5, §10.6, §11.5): with 2^β buckets per era, a sender posts each
// invite into the recipient's bucket (from the recipient's directory entry), a reader reads and watches only its own
// bucket (from its own entry), and a first contact still arrives.
import { describe, expect, it } from "vite-plus/test";
import {
  P,
  engineFor,
  freshWorldPerTest,
  makeUser,
  mustView,
  server,
  settle,
  waitFor,
} from "./harness";

freshWorldPerTest({ inboxBuckets: 4 });

const topicsOf = (who: string) =>
  [...server().rt.sockets].filter((ws) => ws.who === who).flatMap((ws) => [...ws.topics.keys()]);
const inboxReads = (who: string) =>
  server().requests.filter(
    (r) => r.who === who && r.method === "GET" && r.path.startsWith("/api/v2/inbox/"),
  );

describe("inbox buckets (§9.3)", () => {
  it("the directory lists each user's bucket of E − 3 .. E + 1, keyed per era, with every bucket below 2^β", async () => {
    const w = server();
    const E = w.era;
    const bob = makeUser("bob");
    const list = w.inboxOf("bob");
    expect(list.map((b) => b.E)).toEqual(
      [E - 3, E - 2, E - 1, E, E + 1].filter((e) => e >= w.params.efirst),
    );
    for (const b of list) {
      expect(b.g).toBeGreaterThanOrEqual(0);
      expect(b.g).toBeLessThan(4);
      expect(b.g).toBe(w.bucketOf(b.E, bob.handle));
    }
    // Over many handles the buckets spread (a keyed hash of the handle prefix, not one bucket for everybody).
    const seen = new Set(Array.from({ length: 64 }, (_, k) => w.bucketOf(E, `user_${k}`)));
    expect(seen.size).toBeGreaterThan(1);
  });

  it("a reader watches and reads only its own bucket, and a sender posts into the recipient's: a first contact arrives", async () => {
    const w = server();
    const alice = makeUser("alice");
    const bob = makeUser("bob");
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    await settle(A, B);
    const E = w.era;
    const gBob = w.bucketOf(E, bob.handle);
    // Bob's notice topics are his own buckets' (§10.8), one per watched era.
    const want = [E - 1, E, E + 1]
      .filter((e) => e >= Math.max(w.params.efirst, E - 3))
      .map((e) => P.b64u(P.topicInbox(e, w.bucketOf(e, bob.handle))));
    await waitFor(() => want.every((t) => topicsOf("bob").includes(t)), "bob's bucket topics");
    for (let g = 0; g < 4; g++)
      if (g !== gBob) expect(topicsOf("bob")).not.toContain(P.b64u(P.topicInbox(E, g)));

    const id = await A.createConversation(["bob"]);
    // The invite sits in bob's bucket and nowhere else.
    await waitFor(() => w.inbox.rowsOf(E, gBob).length === 1, "the invite in bob's bucket");
    for (let g = 0; g < 4; g++) if (g !== gBob) expect(w.inbox.rowsOf(E, g)).toHaveLength(0);
    // Bob's reads name his bucket only, and the conversation arrives.
    await waitFor(() => {
      try {
        mustView(B, id);
        return true;
      } catch {
        return false;
      }
    }, "bob's request");
    const paths = inboxReads("bob").map((r) => r.path);
    expect(paths.length).toBeGreaterThan(0);
    for (const path of paths) {
      const m = /^\/api\/v2\/inbox\/(\d+)\/(\d+)/.exec(path)!;
      expect(Number(m[2])).toBe(w.bucketOf(Number(m[1]), bob.handle));
    }
  });
});
