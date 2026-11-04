// Promises with a deadline inside the engine's serial queue: a request that never answers (§10.1 "Timeouts") and an
// inbox worker that fails or never answers (§11.5 step 2). Neither may hold up restore, the polls or a send.
import { describe, expect, it } from "vite-plus/test";
import { WORKER_TIMEOUT_MS } from "../src/inbox";
import {
  I,
  chat,
  engineFor,
  freshWorldPerTest,
  makeUser,
  newEngine,
  server,
  settle,
  sleep,
  view,
  waitFor,
} from "./harness";

freshWorldPerTest();

const isInboxRead = (m: string, p: string) => m === "GET" && p.startsWith("/api/v2/inbox/");

describe("a request that never answers (§10.1)", () => {
  it("times out, and the queue, the inbox poll and a send behind it go on", async () => {
    const alice = makeUser("alice");
    const bob = makeUser("bob");
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(["@bob"]);
    await settle(A, B);

    // Alice's next inbox read reaches the server and never answers.
    let held = 0;
    let release = () => {};
    server().hooks.beforeRequest = (m, p, who) => {
      if (who !== "alice" || !isInboxRead(m, p) || held++ > 0) return;
      return new Promise<void>((r) => (release = r));
    };
    try {
      // A deadline in real time, not a count of rounds: a busy CI runner may need more than 60 × 10 ms to send it.
      for (const end = Date.now() + 20_000; held === 0 && Date.now() < end;) {
        server().tick(1000);
        await sleep(10);
      }
      expect(held).toBe(1);
      const puts = () =>
        server().requests.filter((r) => r.who === "alice" && r.path === "/api/v2/put").length;
      const putsBefore = puts();
      const sent = A.sendText(id, "while a read hangs").catch(() => {});
      await sleep(50);
      expect(chat(A, id)).toContain("alice: while a read hangs (sending)");

      // Up to ten minutes of engine time: the read times out after REQUEST_TIMEOUT_MS and the send goes out.
      for (let i = 0; i < 120 && !chat(A, id).includes("alice: while a read hangs"); i++) {
        server().tick(5000);
        await sleep(10);
      }
      expect(chat(A, id)).toContain("alice: while a read hangs");
      expect(puts()).toBeGreaterThan(putsBefore);
      await sent;
      await settle(A, B);
      expect(chat(B, id)).toContain("alice: while a read hangs");
      // The inbox poll goes on after the timeout.
      expect(
        server().requests.filter((r) => r.who === "alice" && isInboxRead(r.method, r.path)).length,
      ).toBeGreaterThan(1);
    } finally {
      release();
    }
  });
});

/** A Worker that never runs its script: it fires `error` when told to and answers nothing. */
class DeadWorker {
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  onmessageerror: ((ev: MessageEvent) => void) | null = null;
  posted = 0;
  terminated = false;
  constructor(private readonly onPost: (w: DeadWorker) => void = () => {}) {}
  postMessage(): void {
    this.posted++;
    this.onPost(this);
  }
  terminate(): void {
    this.terminated = true;
  }
  fail(): void {
    this.onerror?.(Object.assign(new Event("error"), { message: "failed to load" }));
  }
}

function deadWorkers(onPost?: (w: DeadWorker) => void) {
  const made: DeadWorker[] = [];
  const inboxWorker = async () => {
    const w = new DeadWorker(onPost);
    made.push(w);
    return w as unknown as Worker;
  };
  return { made, inboxWorker };
}

/** After the worker failed, restore is done, the session runs, and a new invite still opens (on this thread). */
async function goesOn(A: ReturnType<typeof newEngine>) {
  expect(A.getState().syncing).toBe(false);
  expect(A.getState().error).toBe("");
  await waitFor(() => A.getState().connected, "alice's realtime socket");
  const B = await engineFor(makeUser("bob"));
  const id = await B.createConversation(["@alice"]);
  await settle(A, B);
  expect(view(A, id)).toBeDefined();
}

describe("an inbox worker that fails (§11.5 step 2)", () => {
  it("an error before the first decrypt: the page's thread decrypts, and restore finishes", async () => {
    const alice = makeUser("alice");
    const w = deadWorkers();
    server().hooks.beforeRequest = (m, p, who) => {
      // the worker exists (made before the read) and has been sent nothing yet
      if (who === "alice" && isInboxRead(m, p) && w.made[0]?.posted === 0) w.made[0].fail();
    };
    const A = await engineFor(alice, { inboxWorker: w.inboxWorker });
    expect(w.made).toHaveLength(1);
    expect(w.made[0].posted).toBe(0);
    expect(w.made[0].terminated).toBe(true);
    await goesOn(A);
    expect(w.made).toHaveLength(1); // never made again
  });

  it("an error during the first decrypt: that page is decrypted on the page's thread, with no error left", async () => {
    const alice = makeUser("alice");
    const w = deadWorkers((x) => {
      if (x.posted === 1) setTimeout(() => x.fail(), 0);
    });
    const A = await engineFor(alice, { inboxWorker: w.inboxWorker });
    expect(w.made).toHaveLength(1);
    expect(w.made[0].posted).toBe(1);
    expect(w.made[0].terminated).toBe(true);
    await goesOn(A);
    expect(w.made).toHaveLength(1);
    expect(w.made[0].posted).toBe(1);
  });

  it("a worker that never answers is given up after its timeout", async () => {
    const alice = makeUser("alice");
    const w = deadWorkers();
    const A = newEngine(alice.handle, { inboxWorker: w.inboxWorker });
    await I(A).unlock(alice.AK, alice.uid, alice.handle);
    await waitFor(() => (w.made[0]?.posted ?? 0) > 0, "the first decrypt");
    let waited = 0;
    for (; waited < 10 * WORKER_TIMEOUT_MS && A.getState().syncing; waited += 5000) {
      server().tick(5000);
      await sleep(10);
    }
    expect(waited).toBeGreaterThanOrEqual(WORKER_TIMEOUT_MS - 5000);
    expect(w.made[0].terminated).toBe(true);
    await settle(A);
    await goesOn(A);
    expect(w.made).toHaveLength(1);
  });
});
