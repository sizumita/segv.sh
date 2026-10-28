// HEADS rows (docs/PROTOCOL.md §7.3 "HEADS splitting"): the records waiting for the next HEADS row and the entries are
// spread over as many self rows as needed, each within the cls-3 budget and the record cap.
import { describe, expect, it } from "vite-plus/test";
import { I, P, engineFor, makeUser, freshWorldPerTest, server } from "./harness";

freshWorldPerTest();

interface MessagingI {
  pendingRecords: P.SelfRecord[];
  flushHeads(): Promise<void>;
}

describe("HEADS rows", () => {
  it("a backlog larger than one row is written over several rows, none of them refused", async () => {
    const alice = makeUser("alice");
    const A = await engineFor(alice);
    const msg = (A as unknown as { msg: MessagingI }).msg;
    const before = server().requests.filter((r) => r.who === "alice" && r.path === "/api/v2/put").length;
    // 600 CONTACT records (51 B each): more than the 255-record cap and the 16 KB budget of one row
    const contacts: P.ContactRec[] = Array.from({ length: 600 }, () => ({
      rtype: P.RT.CONTACT,
      uid: P.random(16),
      pin: P.random(32),
    }));
    msg.pendingRecords.push(...contacts);
    await msg.flushHeads();
    expect(msg.pendingRecords).toEqual([]);
    const fold = I(A).self!.fold;
    for (const c of contacts) expect(fold.contacts.has(P.b64u(c.uid))).toBe(true);
    const puts = server()
      .requests.filter((r) => r.who === "alice" && r.path === "/api/v2/put")
      .slice(before);
    expect(puts.length).toBeGreaterThanOrEqual(3);
    for (const r of puts) expect(r.putResults?.every((x) => x.s === "ok")).toBe(true);
    expect(A.getState().error).toBe("");
  });
});
