// The UI's copies of the engine's states (state-copy.ts): never the engine's objects, and the same copies for whatever
// did not change, down to each message.
import { describe, expect, it } from "vite-plus/test";
import type { ConversationView, EngineState, MessageView } from "@segv/engine/types";
import { initialEngineState } from "./state";
import { StateCopier } from "./state-copy";

const msg = (key: string, text: string): MessageView => ({
  key,
  seq: 1,
  from: "u",
  fromHandle: "bob",
  mine: false,
  ts: 1,
  kind: "text",
  text,
  status: "sent",
  reactions: [],
});

const conv = (id: string, messages: MessageView[], unread = 0): ConversationView => ({
  id,
  ref: `ref-${id}`,
  name: `@${id}`,
  members: [{ uid: "u", handle: "bob", fingerprint: "", left: false }],
  epoch: 0,
  canSend: true,
  blocked: "",
  frozen: false,
  request: false,
  byContact: true,
  lastTs: 1,
  unread,
  messages,
});

const state = (conversations: ConversationView[], warnings: string[] = []): EngineState => ({
  ...initialEngineState(),
  phase: "ready",
  conversations,
  warnings,
});

describe("StateCopier", () => {
  it("copies, never handing out the engine's objects", () => {
    const m = msg("1", "hi");
    const s = state([conv("a", [m])], ["w"]);
    const out = new StateCopier().copy(s);
    expect(out).toEqual(s);
    expect(out).not.toBe(s);
    expect(out.conversations[0]).not.toBe(s.conversations[0]);
    expect(out.conversations[0].messages[0]).not.toBe(m);
    expect(out.conversations[0].members).not.toBe(s.conversations[0].members);
    expect(out.warnings).not.toBe(s.warnings);
  });

  it("gives the same state when nothing changed", () => {
    const m = msg("1", "hi");
    const c = new StateCopier();
    const first = c.copy(state([conv("a", [m])]));
    // the engine builds new views and arrays on every change, around the same message objects
    expect(c.copy(state([conv("a", [m])]))).toBe(first);
  });

  it("keeps the copies of what did not change", () => {
    const m1 = msg("1", "hi");
    const m2 = msg("2", "there");
    const c = new StateCopier();
    const first = c.copy(state([conv("a", [m1]), conv("b", [m2])], ["w"]));
    const m3 = msg("3", "new");
    const next = c.copy(state([conv("a", [m1, m3], 1), conv("b", [m2])], ["w"]));
    expect(next).not.toBe(first);
    expect(next.warnings).toBe(first.warnings);
    // b did not change
    expect(next.conversations[1]).toBe(first.conversations[1]);
    // a did: its members and its old message are the same copies
    const [a0, a1] = [first.conversations[0], next.conversations[0]];
    expect(a1).not.toBe(a0);
    expect(a1.unread).toBe(1);
    expect(a1.members).toBe(a0.members);
    expect(a1.messages[0]).toBe(a0.messages[0]);
    expect(a1.messages[1]).toEqual(m3);
  });

  it("copies a message again when the engine replaces it", () => {
    const m = msg("1", "hi");
    const c = new StateCopier();
    const first = c.copy(state([conv("a", [m])]));
    const sent = { ...m, status: "failed" as const };
    const next = c.copy(state([conv("a", [sent])]));
    expect(next.conversations[0].messages[0]).not.toBe(first.conversations[0].messages[0]);
    expect(next.conversations[0].messages[0].status).toBe("failed");
  });

  it("follows the order of the conversations", () => {
    const [ma, mb] = [msg("1", "a"), msg("2", "b")];
    const c = new StateCopier();
    const first = c.copy(state([conv("a", [ma]), conv("b", [mb])]));
    const next = c.copy(state([conv("b", [mb]), conv("a", [ma])]));
    expect(next.conversations.map((x) => x.id)).toEqual(["b", "a"]);
    expect(next.conversations[0]).toBe(first.conversations[1]);
    expect(next.conversations[1]).toBe(first.conversations[0]);
  });
});
