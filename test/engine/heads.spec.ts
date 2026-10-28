// HEADS rows (docs/PROTOCOL.md §7.3 "HEADS splitting"): the records waiting for the next HEADS row and the entries are
// spread over as many self rows as needed, each within the cls-3 budget and the record cap.
import { describe, expect, it } from "vite-plus/test";
import { I, P, engineFor, makeUser, freshWorldPerTest, selfRowsOf, server } from "./harness";

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

describe("HEADS entries over several rows (M6 test 11)", () => {
  it("an account with more entries than one row holds writes them over several rows, and restores from them", async () => {
    const users = Array.from({ length: 31 }, (_, i) => makeUser(`m${String(i).padStart(2, "0")}`));
    const alice = makeUser("alice");
    const A = await engineFor(alice);
    const ids: string[] = [];
    // 70 groups of 32: an entry of 68 + 6·32 = 260 B each, more than one cls-3 row holds
    for (let g = 0; g < 70; g++) ids.push(await A.createConversation(users.map((u) => u.handle), `g${g}`));
    const msg = (A as unknown as { msg: MessagingI & { lastHeads: string } }).msg;
    msg.lastHeads = "";
    (msg as unknown as { headsDue: boolean }).headsDue = true;
    const before = selfRowsOf(alice).length;
    await msg.flushHeads();
    const rows = selfRowsOf(alice).slice(before);
    const heads = rows.filter((rs) => rs.some((r) => r.rtype === P.RT.HEADS));
    expect(heads.length).toBeGreaterThanOrEqual(2);
    for (const rs of heads) expect(rs.at(-1)!.rtype).toBe(P.RT.HEADS);
    const entries = heads.flatMap((rs) => (rs.at(-1) as P.HeadsRec).entries);
    expect(new Set(entries.map((x) => P.b64u(x.conv))).size).toBe(70);
    await A.logout();
    const A2 = await engineFor(alice);
    expect(I(A2).views().length).toBe(70);
    for (const id of ids) expect(I(A2).views().some((v) => v.id === id)).toBe(true);
  }, 300_000);
});
