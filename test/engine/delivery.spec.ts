// Delivering J by inbox invites (docs/PROTOCOL.md §6.12 steps 2–4; docs/STAGE1-PLAN.md M6 test 7's 409 variant,
// rewritten in round 10): a 409 `wrong era` naming an era the Worker accepts rebuilds the invites for it and posts
// again at once; the refused post leaves no trace, and every invitee joins.
import { describe, expect, it } from "vite-plus/test";
import { I, P, engineFor, freshWorldPerTest, makeUser, mustView, server, settle } from "./harness";

freshWorldPerTest({ skew: 1 });

describe("the first delivery attempt (§6.12)", () => {
  it("a 409 for E + 1 at the end of era E: the invites are rebuilt for E + 1 and posted at once", async () => {
    const [alice, bob, carol] = ["alice", "bob", "carol"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const C = await engineFor(carol);
    let E = -1;
    server().hooks.beforeRequest = (m, p) => {
      if (m !== "POST" || p !== "/api/v2/inbox") return;
      if (E < 0) {
        // The creation waited Δ + SKEW before posting: move the server to end(E) − 500 ms, then refuse once with E + 1.
        E = server().era;
        server().advance(P.eraEnd(E) - 500 - server().now(), { keepSockets: true });
        server().inbox.wrongEraOnce(E + 1);
      }
    };
    const inboxPosts = () => server().requests.filter((r) => r.method === "POST" && r.path === "/api/v2/inbox");
    const id = await A.createConversation(["bob", "carol"], "late");
    await settle(A, B, C);
    const sent = inboxPosts();
    expect(sent.map((r) => r.status)).toEqual([409, 200]); // exactly two posts, no wait in between
    expect(server().inbox.rowsOf(E + 1)).toHaveLength(2); // both invites landed in E + 1
    expect(server().inbox.rowsOf(E)).toHaveLength(0); // the refused post stored nothing
    for (const X of [B, C]) expect(mustView(X, id).name).toBe("# late");
    // One DELIVERED row naming both invitees (no record of the refused post).
    const delivered = [...I(A).self!.fold.delivered.values()];
    expect(delivered).toHaveLength(1);
    expect([...delivered[0]].sort()).toEqual([bob.uidB, carol.uidB].sort());
  });
});
