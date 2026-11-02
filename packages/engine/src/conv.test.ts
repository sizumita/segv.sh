// A copy's message list (conv.ts): the order of §11.8, and the oldest messages dropped once the copy holds more than
// its view shows, which leaves the view as it was.
import { describe, expect, it } from "vite-plus/test";
import { MESSAGE_SLACK, VIEW_MESSAGES, insertMessage, systemLine, type Copy } from "./conv";

const copy = () => ({ messages: [], order: new Map(), lastTs: 0 }) as unknown as Copy;
const line = (k: number) => systemLine(`m${k}`, 1000 + k, `line ${k}`);
const keys = (c: Copy) => c.messages.map((m) => m.key);

describe("a copy's messages", () => {
  it("keeps them in order, whatever order they arrive in", () => {
    const c = copy();
    for (const k of [3, 1, 2]) insertMessage(c, line(k), [k]);
    expect(keys(c)).toEqual(["m1", "m2", "m3"]);
    expect(insertMessage(c, line(2), [2])).toBe(false);
  });

  it("drops the oldest beyond what the view shows, and never takes them back", () => {
    const c = copy();
    const all = VIEW_MESSAGES + MESSAGE_SLACK;
    for (let k = 1; k <= all; k++) insertMessage(c, line(k), [k]);
    expect(c.messages.length).toBe(all);
    insertMessage(c, line(all + 1), [all + 1]);
    // the view (the last VIEW_MESSAGES) is what it would have been
    expect(c.messages.length).toBe(VIEW_MESSAGES);
    expect(keys(c)[0]).toBe(`m${all + 2 - VIEW_MESSAGES}`);
    expect(keys(c).at(-1)).toBe(`m${all + 1}`);
    // a dropped message applied again stays out
    expect(insertMessage(c, line(1), [1])).toBe(false);
    expect(c.messages.length).toBe(VIEW_MESSAGES);
  });

  it("drops an old message that arrives after the list is full", () => {
    const c = copy();
    for (let k = 1000; k < 1000 + VIEW_MESSAGES + MESSAGE_SLACK; k++)
      insertMessage(c, line(k), [k]);
    insertMessage(c, line(5), [5]);
    expect(keys(c)).not.toContain("m5");
    expect(keys(c).at(-1)).toBe(`m${999 + VIEW_MESSAGES + MESSAGE_SLACK}`);
  });
});
