/**
 * KeyDO (docs/PROTOCOL.md §9.3 "Buckets"): kbucket_E is drawn once per era within the inbox window, the same from then
 * on, and the keys of eras below E_now − 3 are deleted as the window moves.
 */
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import * as P from "@segv/protocol/proto";
import type { KeyDO } from "../src/key-do";
import { keyStub } from "../src/types";

const keys = () => keyStub(env);
const setClock = (ms: number) =>
  runInDurableObject(keys(), (inst: KeyDO) => {
    (inst as unknown as { clock: () => number }).clock = () => ms;
  });
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
    const k = new Uint8Array(await keys().bucketKey(E));
    expect(k).toHaveLength(32);
    expect(new Uint8Array(await keys().bucketKey(E))).toEqual(k);
    const other = new Uint8Array(await keys().bucketKey(E + 1));
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
    expect(new Uint8Array(await keys().bucketKey(E + 1))).toEqual(other); // still within the window: unchanged
    expect(await stored()).toEqual([E + 1]);
  });
});
