import { describe, expect, it } from "vite-plus/test";
import * as proto from "@segv/protocol/proto";
import {
  HANDLE_RE,
  MAX_MEMBERS,
  MAX_NAME,
  dayKey,
  fitBox,
  inviterOf,
  listOf,
  parseHandles,
  relTime,
  textTooLong,
} from "./util";

describe("ui constants mirror proto.ts", () => {
  it("matches", () => {
    expect(HANDLE_RE.source).toBe(proto.HANDLE_RE.source);
    expect(HANDLE_RE.flags).toBe(proto.HANDLE_RE.flags);
    expect(MAX_MEMBERS).toBe(proto.MAX_MEMBERS);
    expect(MAX_NAME).toBe(proto.MAX_NAME);
  });
});

describe("parseHandles", () => {
  it("splits on spaces, commas and japanese punctuation; strips @; lowercases; dedupes", () => {
    expect(parseHandles("bob, @Carol  dave、ｅｒｉｎ，bob")).toEqual({
      ok: true,
      handles: ["bob", "carol", "dave", "erin"],
    });
  });
  it("rejects invalid handles", () => {
    const r = parseHandles("bo, ok_name, <script>");
    expect(r.ok).toBe(false);
  });
  it("rejects empty input", () => {
    expect(parseHandles("  , ").ok).toBe(false);
  });
  it("rejects self and existing members", () => {
    expect(parseHandles("alice bob", "alice").ok).toBe(false);
    expect(parseHandles("bob", "alice", ["alice", "bob"]).ok).toBe(false);
  });
  it("enforces the member cap", () => {
    const many = Array.from({ length: MAX_MEMBERS }, (_, i) => `user${i}`).join(" ");
    expect(parseHandles(many, "alice").ok).toBe(false);
    const max = Array.from({ length: MAX_MEMBERS - 1 }, (_, i) => `user${i}`).join(" ");
    expect(parseHandles(max, "alice").ok).toBe(true);
  });
});

describe("formatting", () => {
  it("fits images into a box and survives garbage sizes", () => {
    expect(fitBox(1600, 1000, 320)).toEqual({ w: 320, h: 200 });
    expect(fitBox(100, 50, 320)).toEqual({ w: 100, h: 50 });
    expect(fitBox(NaN, 10, 320)).toEqual({ w: 320, h: 240 });
    expect(fitBox(1e9, 10, 320)).toEqual({ w: 320, h: 240 });
  });
  it("relative times", () => {
    const now = Date.UTC(2026, 9, 27, 12, 0, 0);
    expect(relTime(now - 10_000, now)).toBe("now");
    expect(relTime(now - 5 * 60_000, now)).toBe("5m");
    expect(relTime(now - 3 * 3_600_000, now)).toBe("3h");
    expect(relTime(now - 2 * 86_400_000, now)).toBe("2d");
    expect(relTime(now - 40 * 86_400_000, now)).toBe(dayKey(now - 40 * 86_400_000));
    expect(relTime(NaN, now)).toBe("");
  });
  it("text length budget counts JSON-escaped UTF-8 bytes", () => {
    expect(textTooLong("a".repeat(14_000))).toBe(false);
    expect(textTooLong("あ".repeat(5_000))).toBe(true); // 15 000 bytes + quotes
    expect(textTooLong('"'.repeat(7_500))).toBe(true); // escaping doubles it
  });
});

describe("lists", () => {
  it("archives what this user left or was removed from, a removed request too; requests apart", () => {
    expect(listOf({ blocked: "", byContact: true })).toBe("chats");
    expect(listOf({ blocked: "pending", byContact: true })).toBe("chats");
    expect(listOf({ blocked: "frozen", byContact: true })).toBe("chats");
    expect(listOf({ blocked: "", byContact: false })).toBe("requests");
    expect(listOf({ blocked: "pending", byContact: false })).toBe("requests");
    expect(listOf({ blocked: "left", byContact: true })).toBe("archives");
    expect(listOf({ blocked: "removed", byContact: true })).toBe("archives");
    expect(listOf({ blocked: "removed", byContact: false })).toBe("archives");
  });
  it("names a request's inviter: its one resolved member other than self", () => {
    const m = (uid: string, handle: string) => ({ uid, handle, fingerprint: "", left: false });
    const me = m("u-me", "me");
    const alice = m("u-a", "alice");
    const unknown = m("u-x", "?Xk3f9QaZ");
    expect(inviterOf({ request: true, members: [alice, me] }, "u-me")).toBe("alice");
    expect(inviterOf({ request: true, members: [alice, me, unknown] }, "u-me")).toBe("alice");
    expect(inviterOf({ request: true, members: [unknown, me] }, "u-me")).toBeUndefined();
    expect(inviterOf({ request: false, members: [alice, me] }, "u-me")).toBeUndefined();
  });
});
