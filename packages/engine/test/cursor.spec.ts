// The registration's inbox cursor and the self lane's era floor (docs/PROTOCOL.md §7.3, §11.1, §11.5 step 1): the
// cursor comes from the register response's server time, minus SKEW, once; and no
// self row is written below the registration era.
import { describe, expect, it, vi } from "vite-plus/test";
import type { Api } from "../src/api";
import { cursorAt } from "../src/inbox";
import { SelfLane } from "../src/selflane";
import { I, P, freshWorldPerTest, newEngine, server, settle, waitFor, type W } from "./harness";

vi.mock("../src/webauthn", () => ({
  PasskeyError: class PasskeyError extends Error {},
  prfCapability: async () => true,
  createPasskey: async () => ({ credId: crypto.getRandomValues(new Uint8Array(16)), prf: crypto.getRandomValues(new Uint8Array(32)) }),
  prfForCredential: async () => null,
  signInWithPasskey: async () => {
    throw new Error("not used");
  },
  forgetCredential: async () => {},
}));

freshWorldPerTest({ skew: 2 });

/** The cursor of the registration's HEADS: the first self row, at Lself(E, 0) of the first era with a row. */
function firstCursor(e: Parameters<typeof I>[0]): { E: number; rel: number } {
  const id = P.deriveIdentity(I(e).account!.AK);
  for (let E = I(e).account!.regEra! - 1; E <= server().era; E++) {
    const row = server().shard.rows().find((r) => r.E === E && P.equalBytes(r.label, P.Lself(id.rS, E, 0)));
    if (!row) continue;
    const h = P.openSelf(id.kS, E, row.label, row.body).records[0] as P.HeadsRec;
    return { E: h.Ein, rel: h.relIn };
  }
  throw new Error("no self row");
}

/** Moves the server (only) to `start(E_now + 1) + ms`. */
function toNextEraPlus(ms: number): number {
  const w = server();
  const E = w.era + 1;
  w.advance(P.eraStart(E) + ms - w.now(), { keepSockets: true });
  return E;
}

describe("the registration's inbox cursor", () => {
  it("lies below an invite posted right after a registration at start(E) + 500 ms into E − 1 by a lagging InboxDO", async () => {
    const E = toNextEraPlus(500);
    server().inboxLagMs = 2000; // the InboxDO's clock is SKEW behind: still in E − 1
    const R = newEngine("early");
    await R.register("early");
    // an invite posted right after the registration lands in E − 1, at the InboxDO's slot
    const [res] = server().inbox.post(E - 1, [{ eid: P.random(16), body: P.random(P.INBOX_BODY_LEN) }]);
    expect(res).toHaveProperty("rel");
    const rel = (res as { rel: number }).rel;
    await settle(R);
    expect(I(R).account!.regEra).toBe(E);
    const c = firstCursor(R);
    expect(c.E === E - 1 ? c.rel < rel : c.E < E - 1).toBe(true);
    // a device without a cursor starts at the same rule with t_r = start(regEra): also below the invite
    const fromStart = cursorAt(P.eraStart(E), server().params, E);
    expect(fromStart.E === E - 1 ? fromStart.rel < rel : fromStart.E < E - 1).toBe(true);
  });

  it("is computed once: a HEADS write retried after a back-off keeps the first attempt's cursor", async () => {
    let regAt = 0;
    let fails = 1;
    server().hooks.beforeRequest = (m, p) => {
      if (m === "POST" && p === "/api/v2/register") regAt = server().now();
    };
    server().hooks.fail = (m, p) => (m === "POST" && p === "/api/v2/put" && fails-- > 0 ? "before" : null);
    const R = newEngine("retry", { delays: { retryBase: 60_000, retryMax: 60_000 } });
    await R.register("retry");
    await waitFor(() => fails === 0 && /sync failed/.test(R.getState().error), "the failed HEADS put");
    server().tick(60_000); // the back-off: a minute passes (world and engine) before the retry
    await settle(R);
    const c = firstCursor(R);
    const slot = (ms: number) => Math.floor((ms - P.T0_MS) / (server().params.inboxSlot * 1000));
    expect(c.rel).toBeLessThanOrEqual(slot(regAt - 2000));
    expect(c.rel).toBeGreaterThanOrEqual(slot(regAt - 2000) - 4);
    expect(R.getState().error).toBe("");
  });

  it("never sits below (max(E_FIRST, E_now − 3), 0)", () => {
    const p = { skew: 2, inboxSlot: 10, efirst: 40 };
    expect(cursorAt(P.eraStart(41) + 1000, p, 41)).toEqual({ E: 40, rel: expect.any(Number) });
    expect(cursorAt(P.eraStart(40) + 1000, p, 40)).toEqual({ E: 40, rel: 0 });
    expect(cursorAt(P.eraStart(50) + 100_000, p, 54)).toEqual({ E: 51, rel: 0 });
  });
});

describe("the self lane's era floor", () => {
  it("a device whose estimate lags into regEra − 1 writes its first self row in regEra", async () => {
    const id = P.deriveIdentity(P.random(32));
    const puts: W.PutRow[][] = [];
    const api = {
      serverNow: () => P.eraStart(10) - 5000,
      put: async (rows: W.PutRow[]) => {
        puts.push(rows);
        return [{ s: "ok", t: 7, receipt: new Uint8Array(64) }];
      },
    } as unknown as Api;
    const lane = new SelfLane(api, id, { warn() {}, applied() {} });
    lane.floorEra = 10;
    await lane.write([{ rtype: P.RT.HEADS, Ein: 10, relIn: 0, entries: [] }]);
    expect(puts[0][0].E).toBe(10);
    expect(P.equalBytes(puts[0][0].label, P.Lself(id.rS, 10, 0))).toBe(true);
    expect(lane.head).toMatchObject({ E: 10, n: 0 });
  });
});
