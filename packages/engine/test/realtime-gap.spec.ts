// RESUME after a GAP (docs/PROTOCOL.md §10.8): the catch-up a GAP starts covers every row before it, so the client's
// next RESUME starts at the HELLO of the socket that got the GAP, and a quiet client is not sent GAP at every reconnect.
import { afterEach, describe, expect, it } from "vite-plus/test";
import * as W from "@segv/protocol/wire";
import {
  FakeWebSocket,
  engineFor,
  freshWorldPerTest,
  makeUser,
  server,
  settle,
  waitFor,
} from "./harness";

freshWorldPerTest();

const proto = FakeWebSocket.prototype as unknown as { send: (data: unknown) => void };
const realSend = proto.send;
afterEach(() => {
  proto.send = realSend;
});

describe("realtime RESUME after GAP (§10.8)", () => {
  it("the RESUME after a GAP carries the seq of that socket's HELLO", async () => {
    const bob = makeUser("bob");
    const B = await engineFor(bob);
    await settle(B);
    const socketsOf = () => [...server().rt.sockets].filter((ws) => ws.who === "bob");
    await waitFor(() => socketsOf().length === 1, "the socket");
    const resumes: number[] = [];
    proto.send = function (this: FakeWebSocket, data: unknown) {
      if (data instanceof Uint8Array && data[0] === W.RT_RESUME) {
        const f = W.decodeClientFrame(data);
        if (f.f === "resume") resumes.push(f.since);
      }
      realSend.call(this, data);
    };
    // From here no row reaches the client, so only a GAP can move its seq. Rows on other topics advanced the seq,
    // and none is in the ring any more: a RESUME below it gets GAP.
    server().rt.dropPublish(() => true);
    server().rt.seq += 5;
    server().rt.ring.length = 0;
    const helloSeq = server().rt.seq;
    server().rt.closeAll();
    server().tick(2_000); // the back-off: 1 s with up to 30 % jitter
    await waitFor(() => resumes.length >= 1 && socketsOf().length === 1, "the first RESUME");
    expect(resumes[0]).toBeLessThan(helloSeq);
    // Wait for the GAP to be handled (it starts a catch-up), then reconnect again.
    await settle(B);
    server().rt.closeAll();
    server().tick(2_000);
    await waitFor(() => resumes.length >= 2, "the second RESUME");
    expect(resumes[1]).toBe(helloSeq);
    expect(B.getState().error).toBe("");
  });
});
