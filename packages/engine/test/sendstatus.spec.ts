// The status of a sent message's bubble (docs/PROTOCOL.md §6.8, §11.3 steps 6–8): it stays `sending` while a late
// row waits for step 8, and a row that step 8 does not count as delivered, or that §6.8 drops, leaves it `failed`.
import { describe, expect, it } from "vite-plus/test";
import type { Engine } from "../src/types";
import type { Epoch } from "../src/conv";
import {
  I,
  P,
  chat,
  commitChange,
  conv,
  engineFor,
  epoch,
  freshWorldPerTest,
  makeUser,
  postRow,
  server,
  settle,
  view,
  waitFor,
} from "./harness";

freshWorldPerTest();

async function group(names: string[]) {
  const users = names.map((h) => makeUser(h));
  const engines: Engine[] = [];
  for (const u of users) engines.push(await engineFor(u));
  const id = await engines[0].createConversation(names.slice(1), "g");
  await settle(...engines);
  for (const E of engines.slice(1)) await E.accept(id);
  await settle(...engines);
  return { users, engines, id };
}

/** Holds bob's first put on T_e of `ep` and runs `during` before the fake stores it. */
function onBobsPut(ep: Epoch, during: () => Promise<void>): void {
  let armed = true;
  server().hooks.beforePut = async (rows, who) => {
    if (!armed || who !== "bob" || !rows.some((r) => P.equalBytes(r.topic, ep.topic))) return;
    armed = false;
    await during();
  };
}

/** Moves bob's clocks past Δ + SKEW: the put's answer comes late (§11.3 step 8). */
const makeLate = (B: Engine) =>
  I(B).clock.advance((server().params.delta + server().params.skew) * 1000 + 1);

const status = (e: Engine, id: string, text: string) =>
  view(e, id)?.messages.find((m) => m.mine && m.text === text)?.status;

describe("late rows (§11.3 step 8)", () => {
  it("a late row after two epoch changes leaves its bubble failed", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const ep0 = epoch(A, id);
    onBobsPut(ep0, async () => {
      makeLate(B);
      await commitChange(alice, ep0, [alice, bob, carol], "one");
      await settle(A);
      await commitChange(alice, epoch(A, id), [alice, bob, carol], "two");
      await waitFor(() => epoch(B, id).e === 2, "bob in e+2");
    });
    await B.sendText(id, "late");
    expect(B.getState().error).toMatch(/not delivered/);
    expect(chat(B, id)).toEqual(["bob: late (failed)"]);
    await settle(A, B, C);
    expect(status(B, id, "late")).toBe("failed");
  });

  it("a late row after one epoch change, with a row of bob's other device in e+1, leaves its bubble failed", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const B2 = await engineFor(bob);
    await settle(A, B, C, B2);
    const ep0 = epoch(A, id);
    onBobsPut(ep0, async () => {
      makeLate(B);
      await commitChange(alice, ep0, [alice, bob, carol], "one");
      await B2.sendText(id, "from the other device");
      await waitFor(() => {
        const ep = epoch(B, id);
        return ep.e === 1 && ep.lanes[ep.myIndex].seen;
      }, "bob's row in e+1");
    });
    await B.sendText(id, "late");
    expect(B.getState().error).toMatch(/not delivered/);
    expect(status(B, id, "late")).toBe("failed");
    await settle(A, B, C, B2);
    expect(status(B, id, "late")).toBe("failed");
  });

  it("a late row whose step-8 probe fails stays sending during the probe, then is failed", async () => {
    const {
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const ep0 = epoch(A, id);
    let answered = false;
    const during: (string | undefined)[] = [];
    onBobsPut(ep0, async () => {
      makeLate(B);
    });
    server().hooks.afterPut = (_rows, _res, who) => {
      if (who === "bob") answered = true;
    };
    server().hooks.fail = (method, path, who) => {
      if (!answered || who !== "bob" || method !== "POST" || path !== "/api/v2/get") return null;
      during.push(status(B, id, "late"));
      return "before";
    };
    await B.sendText(id, "late");
    server().hooks.fail = undefined;
    expect(during.length).toBeGreaterThan(0);
    expect(during.every((s) => s === "sending")).toBe(true);
    expect(B.getState().error).toMatch(/not delivered/);
    expect(status(B, id, "late")).toBe("failed");
    await settle(A, B, C);
    expect(status(B, id, "late")).toBe("failed");
  });

  it("a late row still followed by the others is sent", async () => {
    const {
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const ep0 = epoch(A, id);
    onBobsPut(ep0, async () => {
      makeLate(B);
    });
    await B.sendText(id, "late but fine");
    expect(B.getState().error).toBe("");
    expect(status(B, id, "late but fine")).toBe("sent");
    await settle(A, B, C);
    expect(chat(A, id)).toEqual(["bob: late but fine"]);
  });
});

describe("echoes", () => {
  it("a sibling device's row in the slot being sent to does not take the echo; both end sent", async () => {
    const {
      users: [, bob],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const B2 = await engineFor(bob);
    await settle(A, B, C, B2);
    const ep0 = epoch(A, id);
    onBobsPut(ep0, async () => {
      // B2 stores its row in the slot bob's held put is for; bob's put then meets a CONFLICT with it (§11.3 step 6).
      await B2.sendText(id, "from the other device");
      await waitFor(() => chat(B, id).includes("bob: from the other device"), "sibling's row");
    });
    await B.sendText(id, "mine");
    expect(B.getState().error).toBe("");
    expect(chat(B, id)).toEqual(["bob: from the other device", "bob: mine"]);
    await settle(A, B, C, B2);
    expect(chat(A, id)).toEqual(["bob: from the other device", "bob: mine"]);
  });
});

describe("rows that §6.8 drops (§11.3 step 7)", () => {
  it("a removal that lands during the put leaves the bubble failed", async () => {
    const {
      users: [alice, bob, carol],
      engines: [A, B, C],
      id,
    } = await group(["alice", "bob", "carol"]);
    const ep0 = epoch(A, id);
    const r = await commitChange(alice, ep0, [alice, carol], undefined, { noPost: true });
    await settle(A, B, C);
    onBobsPut(ep0, async () => {
      postRow(ep0, r.claim);
      await waitFor(() => conv(B, id).removed, "bob removed");
    });
    await B.sendText(id, "dropped");
    expect(B.getState().error).toMatch(/not delivered/);
    expect(status(B, id, "dropped")).toBe("failed");
    await settle(A, B, C);
    expect(status(B, id, "dropped")).toBe("failed");
    for (const X of [A, C]) expect(chat(X, id)).toEqual([]);
  });
});
