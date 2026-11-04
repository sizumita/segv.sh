/**
 * KeyDO (docs/PROTOCOL.md §9.3 "Buckets"): kbucket_E is drawn once per era within the inbox window, the same from then
 * on, and the keys of eras below era(now − SKEW) − 3 are deleted as the window moves; β_E is pinned beside the keys and
 * an ask with a β other than the era's pin is refused.
 */
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import * as P from "@segv/protocol/proto";
import { v2Params } from "../src/env";
import type { KeyDO } from "../src/key-do";
import { keyStub } from "../src/types";

const keys = () => keyStub(env);
type Internals = { clock: () => number; skew: () => number };
const internals = (inst: KeyDO): Internals => inst as unknown as Internals;
const setClock = (ms: number) =>
  runInDurableObject(keys(), (inst: KeyDO) => {
    internals(inst).clock = () => ms;
  });
/** Sets SKEW (seconds) as the KeyDO reads it; null restores the deployment's (the test deployment has SKEW = 0). */
const setSkew = (skew: number | null) =>
  runInDurableObject(keys(), (inst: KeyDO) => {
    internals(inst).skew = () => skew ?? v2Params(env).skew;
  });
const pinned = () =>
  runInDurableObject(keys(), (_inst: KeyDO, state) =>
    state.storage.sql
      .exec<{ E: number; b: number }>("SELECT E, b FROM bits ORDER BY E")
      .toArray()
      .map((r) => [r.E, r.b]),
  );
const stored = () =>
  runInDurableObject(keys(), (_inst: KeyDO, state) =>
    state.storage.sql
      .exec<{ E: number }>("SELECT E FROM k ORDER BY E")
      .toArray()
      .map((r) => r.E),
  );

describe("KeyDO (§9.3)", () => {
  it("makes a random key per era in E_now − 3 .. era(now + SKEW) + 1, keeps it, and refuses other eras", async () => {
    const E = P.era(Date.now()) + 40;
    const now = P.eraStart(E) + 60_000;
    await setClock(now);
    const k = new Uint8Array((await keys().bucketKey(E))!);
    expect(k).toHaveLength(32);
    expect(new Uint8Array((await keys().bucketKey(E))!)).toEqual(k);
    const other = new Uint8Array((await keys().bucketKey(E + 1))!);
    expect(other).not.toEqual(k);
    await keys().bucketKey(E - 3);
    await runInDurableObject(keys(), (inst: KeyDO) => {
      expect(() => inst.bucketKey(E - 4)).toThrow(/window/);
      expect(() => inst.bucketKey(E + 2)).toThrow(/window/);
      expect(() => inst.bucketKey(-1)).toThrow(RangeError);
      expect(() => inst.bucketKey(0xffff)).toThrow(RangeError);
    });
    expect(await stored()).toEqual([E - 3, E, E + 1]);
    // The window moves on: the keys of eras that left the inbox retention are deleted at the next call.
    await setClock(P.eraStart(E + 4) + 60_000);
    expect(new Uint8Array((await keys().bucketKey(E + 1))!)).toEqual(other); // still within the window: unchanged
    expect(await stored()).toEqual([E + 1]);
  });

  it("pins β_E of each era asked for (one bucket included) and refuses an ask with another β", async () => {
    const E = P.era(Date.now()) + 60;
    await setClock(P.eraStart(E) + 60_000);
    // Without a β, the deployment's (the test deployment's INBOX_MAP "0:4": β = 2).
    const k = new Uint8Array((await keys().bucketKey(E))!);
    expect(await pinned()).toEqual([[E, 2]]);
    expect(new Uint8Array((await keys().bucketKey(E, 2))!)).toEqual(k);
    // An era asked with one bucket is pinned at 0 and gets no key.
    expect(await keys().bucketKey(E - 1, 0)).toBeNull();
    // A map raised for E + 1 before any answer listed it: pinned under the new count.
    expect(await keys().bucketKey(E + 1, 3)).toHaveLength(32);
    expect(await pinned()).toEqual([
      [E - 1, 0],
      [E, 2],
      [E + 1, 3],
    ]);
    // A changed count of an era already asked about is refused, the first raise from one bucket included.
    await runInDurableObject(keys(), (inst: KeyDO) => {
      expect(() => inst.bucketKey(E, 3)).toThrow(/INBOX_MAP/);
      expect(() => inst.bucketKey(E - 1, 2)).toThrow(/INBOX_MAP/);
      expect(() => inst.bucketKey(E + 1, 0)).toThrow(/INBOX_MAP/);
      expect(() => inst.bucketKey(E, 17)).toThrow(RangeError);
    });
    // The refused asks changed nothing.
    expect(await pinned()).toEqual([
      [E - 1, 0],
      [E, 2],
      [E + 1, 3],
    ]);
    expect(await stored()).toEqual([E, E + 1]);
    expect(new Uint8Array((await keys().bucketKey(E, 2))!)).toEqual(k);
  });

  it("keeps the lower bound of the window SKEW behind its clock: a clock ahead at an era boundary still serves E_now − 3", async () => {
    const E = P.era(Date.now()) + 80;
    // The Worker's clock is just before start(E): it lists E − 4 .. E. The KeyDO's runs 1.5 s ahead (SKEW = 2).
    const worker = P.eraStart(E) - 500;
    await setClock(worker);
    await setSkew(2);
    try {
      const k = new Uint8Array((await keys().bucketKey(E - 4))!);
      await setClock(worker + 1500);
      expect(new Uint8Array((await keys().bucketKey(E - 4))!)).toEqual(k); // not refused, not deleted
      expect(await stored()).toContain(E - 4);
      // Once its clock is SKEW past the boundary, the era leaves the window and its key is deleted.
      await setClock(P.eraStart(E) + 2000);
      await keys().bucketKey(E);
      expect(await stored()).not.toContain(E - 4);
      await runInDurableObject(keys(), (inst: KeyDO) => {
        expect(() => inst.bucketKey(E - 4)).toThrow(/window/);
      });
    } finally {
      await setSkew(null);
    }
  });
});
