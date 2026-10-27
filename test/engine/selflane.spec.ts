// The self-lane fold (docs/PROTOCOL.md §7.3): every record type's rule, copy view keys in lane order, the
// CONFIRMED rule, the REQUEST bounds, LEFT's least key, and pin mismatches.
import { describe, expect, it } from "vite-plus/test";
import { CONFIRMED_COPY_WARNING, SelfFold, copyKey, leftKeyCmp } from "../../src/client/selflane";
import { P } from "./harness";

const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
const conv = fill(16, 1);
const rootA = fill(32, 2);
const rootB = fill(32, 3);
const mat = { e: 0, EK: fill(32, 4), bundleId: fill(32, 5), bundleSize: 23456 };
const join = (root: Uint8Array, c = conv): P.ConvJoinRec => ({
  rtype: P.RT.CONV_JOIN,
  conv: c,
  root,
  ...mat,
  rootBy: fill(16, 9),
  via: P.VIA.INBOX,
});
const request = (c: Uint8Array): P.RequestRec => ({
  rtype: P.RT.REQUEST,
  conv: c,
  root: rootA,
  ...mat,
  tReg: 1,
  rootBy: fill(16, 9),
  via: P.VIA.INBOX,
  desc: fill(300, 0),
});
const ERA_S = P.ERA_MS / 1000;

function fold() {
  const warnings: [string, boolean][] = [];
  return { f: new SelfFold({ warn: (t, c = false) => warnings.push([t, c]) }), warnings };
}

describe("the self-lane fold (§7.3)", () => {
  it("assigns view keys in lane order: b64u(conv), then ~1, ~2 for later copies", () => {
    const { f } = fold();
    f.apply([join(rootA), join(rootB)], 1);
    expect(f.viewKeys.get(copyKey({ conv, root: rootA }))).toBe(P.b64u(conv));
    expect(f.viewKeys.get(copyKey({ conv, root: rootB }))).toBe(`${P.b64u(conv)}~1`);
    f.apply([join(rootA)], 2); // the first CONV_JOIN wins; a repeat changes nothing
    expect(f.joins.size).toBe(2);
  });

  it("drops a CONV_JOIN for a conv that holds a different, confirmed copy (critical warning)", () => {
    const { f, warnings } = fold();
    f.apply([join(rootA), { rtype: P.RT.CONFIRMED, conv, root: rootA }], 1);
    f.apply([join(rootB)], 2);
    expect(f.joins.has(copyKey({ conv, root: rootB }))).toBe(false);
    expect(warnings).toEqual([[CONFIRMED_COPY_WARNING, true]]);
  });

  it("keeps at most 64 live REQUESTs, none stored more than 4 eras ago, none superseded by a CONV_JOIN", () => {
    const { f } = fold();
    const convs = Array.from({ length: 70 }, (_, i) => fill(16, 100 + i));
    convs.forEach((c, i) => f.apply([request(c)], 10 * ERA_S + i));
    const live = f.requests(10);
    expect(live.size).toBe(64);
    expect(live.has(copyKey({ conv: convs[5], root: rootA }))).toBe(false); // the oldest six dropped
    expect(live.has(copyKey({ conv: convs[69], root: rootA }))).toBe(true);
    expect(f.requests(15).size).toBe(0); // stored in era 10: more than 4 eras before era 15
    expect(f.requests(14).size).toBe(64);
    f.apply([{ ...join(rootA, convs[69]), via: P.VIA.REQUEST_ACCEPTED }], 10 * ERA_S + 100);
    expect(f.requests(10).has(copyKey({ conv: convs[69], root: rootA }))).toBe(false);
  });

  it("ORs EPOCH flags, unites DELIVERED uids, keeps every EPOCH_PENDING, and the latest HEADS entry", () => {
    const { f } = fold();
    const ep = { rtype: P.RT.EPOCH, conv, root: rootA, ...mat, e: 3, claim: P.NONE, flags: 0 } as const;
    f.apply([ep, { ...ep, flags: P.EPOCH_SKIP }], 1);
    expect(f.epochs.get(`${copyKey({ conv, root: rootA })}:3`)!.flags).toBe(P.EPOCH_SKIP);
    const d = { rtype: P.RT.DELIVERED, conv, root: rootA, e: 0, bundleId: fill(32, 5) } as const;
    f.apply([{ ...d, uids: [fill(16, 1)] }, { ...d, uids: [fill(16, 2), fill(16, 1)] }], 1);
    expect([...f.delivered.values()][0].size).toBe(2);
    const pend: P.EpochPendingRec = { rtype: P.RT.EPOCH_PENDING, conv, root: rootA, ...mat, tReg: 7, uids: [] };
    f.apply([pend, pend], 1);
    expect(f.pending).toHaveLength(2);
    const entry = (cnt: number): P.HeadsEntry => ({ conv, root: rootA, e: 0, lastTs: cnt, ctl: { E: 1, cnt }, lanes: [{ E: 1, cnt }], followed: [] });
    f.apply([{ rtype: P.RT.HEADS, Ein: 5, relIn: 9, entries: [entry(4)] }], 1);
    f.apply([{ rtype: P.RT.HEADS, Ein: 5, relIn: 3, entries: [entry(2)] }], 2);
    expect(f.cursor).toEqual({ E: 5, rel: 9 }); // the cursor takes the maximum
    expect(f.heads.get(copyKey({ conv, root: rootA }))!.lanes[0].cnt).toBe(2); // the latest entry wins
  });

  it("keeps per (copy, e, uid) the LEFT record with the least (t, position), NONE after every real position", () => {
    const { f } = fold();
    const left = (t: number, row: P.Pos): P.LeftRec => ({ rtype: P.RT.LEFT, conv, root: rootA, e: 2, uid: fill(16, 7), t, row });
    f.apply([left(10, P.NONE), left(10, { E: 3, n: 5 }), left(11, { E: 3, n: 1 })], 1);
    expect([...f.lefts.values()]).toEqual([left(10, { E: 3, n: 5 })]);
    expect(leftKeyCmp(left(10, { E: 3, n: 5 }), left(10, P.NONE))).toBeLessThan(0);
    expect(leftKeyCmp(left(9, P.NONE), left(10, { E: 0, n: 0 }))).toBeLessThan(0);
  });

  it("raises the critical warning for a MEMBER or CONTACT whose pin differs from the one held", () => {
    const { f, warnings } = fold();
    const member = (pin: number): P.MemberRec => ({
      rtype: P.RT.MEMBER,
      uid: fill(16, 8),
      sigPk: fill(32, 1),
      kh: fill(32, 2),
      pin: fill(32, pin),
      handle: "bob",
    });
    f.apply([member(1), member(1)], 1);
    expect(warnings).toEqual([]);
    f.apply([member(2)], 2);
    f.apply([{ rtype: P.RT.CONTACT, uid: fill(16, 8), pin: fill(32, 3) }], 3);
    expect(warnings).toEqual([
      ["the public keys of @bob changed", true],
      ["the public keys of @bob changed", true],
    ]);
    expect(f.members.get(P.b64u(fill(16, 8)))!.pin).toEqual(fill(32, 1)); // the first MEMBER wins
  });
});
