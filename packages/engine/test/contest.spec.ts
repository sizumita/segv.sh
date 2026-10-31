// The ⚠ marks of §6.7 step 6: two held copies of one conversation contest each other in three cases, and a copy whose
// ENDED record the fold holds counts as ended at that record's epoch.
import { describe, expect, it } from "vite-plus/test";
import { contest, type Copy } from "../src/conv";

/** A copy rooted at `root`, at epoch `current`, ended there or not (only what `contest` reads). */
const copy = (root: number, current: number, ended = false): Copy =>
  ({ rootE: root, current, removed: ended }) as unknown as Copy;

describe("contest (§6.7 step 6)", () => {
  it("two copies that have not ended always contest each other", () => {
    expect(contest(copy(0, 3), copy(5, 5))).toBe(true);
  });

  it("an ended copy and another contest while the other holds one of its epochs or the epoch after its last", () => {
    const G = copy(0, 4, true);
    expect(contest(G, copy(2, 2))).toBe(true); // holds 2, one of G's epochs
    expect(contest(G, copy(5, 5))).toBe(true); // holds 5, the epoch after G's last
    expect(contest(G, copy(6, 7))).toBe(false); // an honest re-add, two epochs after
    expect(contest(G, copy(6, 6, true))).toBe(false);
  });

  it("an ended copy rooted at r and a copy rooted below r contest while the latter holds r − 1 or has not ended", () => {
    const G2 = copy(5, 6, true);
    expect(contest(G2, copy(2, 4, true))).toBe(true); // holds r − 1 = 4
    expect(contest(G2, copy(2, 3))).toBe(true); // has not ended
    expect(contest(G2, copy(2, 3, true))).toBe(false); // ended at 3, below r − 1
  });

  it("a copy whose ENDED record the fold holds counts as ended at that epoch, before the device brings it there", () => {
    const G = copy(0, 0); // still at 0 here, its ENDED record names 1
    const Gp = copy(3, 3); // a re-add at 3
    expect(contest(G, Gp)).toBe(true); // both live without the record
    const endOf = (c: Copy) => (c === G ? 1 : c.removed ? c.current : null);
    expect(contest(G, Gp, endOf)).toBe(false);
  });
});
