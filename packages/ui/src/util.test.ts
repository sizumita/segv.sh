import { describe, expect, it } from "vite-plus/test";
import * as proto from "@segv/protocol/proto";
import { MAX_LIVE_ALIASES, type MessageView, type PersonView } from "@segv/engine/types";
import {
  HANDLE_RE,
  MAX_EMOJI_BYTES,
  MAX_FILE_BYTES,
  MAX_MEMBERS,
  MAX_NAME,
  addChips,
  atAliasCap,
  byNickname,
  dayKey,
  editable,
  fitBox,
  fmtBytes,
  handleOnly,
  identitiesOf,
  inviterOf,
  isReservedHandle,
  lastEditable,
  listOf,
  nameOf,
  namesExactly,
  nameWithHandle,
  parseHandles,
  relTime,
  runs,
  shortName,
  startsNickname,
  suggest,
  textTooLong,
} from "./util";

describe("ui constants mirror proto.ts", () => {
  it("matches", () => {
    expect(HANDLE_RE.source).toBe(proto.HANDLE_RE.source);
    expect(HANDLE_RE.flags).toBe(proto.HANDLE_RE.flags);
    expect(MAX_MEMBERS).toBe(proto.MAX_MEMBERS);
    expect(MAX_NAME).toBe(proto.MAX_NAME);
    expect(MAX_FILE_BYTES).toBe(proto.FILE_MAX);
    expect(MAX_EMOJI_BYTES).toBe(proto.MAX_EMOJI_BYTES);
  });
});

describe("fmtBytes", () => {
  it("reads like a size: no trailing .0, whole megabytes from 10 MB", () => {
    expect(
      [0, 1023, 1024, 2_345_678, 2 * 1024 * 1024, 10 * 1024 * 1024, 12_345_678].map(fmtBytes),
    ).toEqual(["0 B", "1023 B", "1 KB", "2.2 MB", "2 MB", "10 MB", "12 MB"]);
  });
});

describe("shortName", () => {
  it("keeps a short name, and elides the middle of a long one so that its extension stays", () => {
    expect(shortName("report.pdf")).toBe("report.pdf");
    const long = `${"a".repeat(80)}.pdf`;
    const s = shortName(long);
    expect(Array.from(s)).toHaveLength(48);
    expect(s.endsWith("aaaaaa.pdf")).toBe(true);
    expect(s).toContain("…");
    // a spoofed extension far into the name is still followed by the real one
    expect(shortName(`invoice.pdf${" ".repeat(60)}.exe`).endsWith(".exe")).toBe(true);
    expect(Array.from(shortName("あ".repeat(60)))).toHaveLength(48);
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
  it("rejects self and existing members, naming them by @handle", () => {
    expect(parseHandles("alice bob", "alice").ok).toBe(false);
    expect(parseHandles("bob", "alice", ["alice", "bob"])).toEqual({
      ok: false,
      error: "already a member: @bob",
    });
  });
  it("refuses the user's other handles, whichever account invites", () => {
    expect(parseHandles("bob _k7m2_q9x4", "alice", [], ["_k7m2_q9x4"])).toEqual({
      ok: false,
      error: "@_k7m2_q9x4 is one of your own handles",
    });
    expect(parseHandles("bob alice", "_k7m2_q9x4", ["_k7m2_q9x4", "carol"], ["alice"])).toEqual({
      ok: false,
      error: "@alice is one of your own handles",
    });
    expect(parseHandles("bob", "_k7m2_q9x4", ["_k7m2_q9x4"], ["alice"]).ok).toBe(true);
  });
  it("enforces the member cap", () => {
    const many = Array.from({ length: MAX_MEMBERS }, (_, i) => `user${i}`).join(" ");
    expect(parseHandles(many, "alice").ok).toBe(false);
    const max = Array.from({ length: MAX_MEMBERS - 1 }, (_, i) => `user${i}`).join(" ");
    expect(parseHandles(max, "alice").ok).toBe(true);
  });
});

describe("new conversation chips", () => {
  it("adds each valid handle once, in order, and keeps what it cannot add with why", () => {
    expect(addChips([], "bob, @Carol  dave、ｅｒｉｎ，bob", "alice", [])).toEqual({
      chips: ["bob", "carol", "dave", "erin"],
      rest: "",
      error: "",
    });
    expect(addChips(["bob"], "bob carol", "alice", [])).toEqual({
      chips: ["bob", "carol"],
      rest: "",
      error: "",
    });
    expect(addChips(["bob"], "x, carol, <b>", "alice", [])).toEqual({
      chips: ["bob", "carol"],
      rest: "x, <b>",
      error: "not a valid handle: x (3–20 of a–z 0–9 _)",
    });
  });
  it("never adds the inviting account or another of the user's handles", () => {
    expect(addChips([], "alice", "alice", ["_k7m2_q9x4"]).error).toBe(
      "you are always included — leave yourself out",
    );
    expect(addChips([], "bob _k7m2_q9x4", "alice", ["_k7m2_q9x4"])).toEqual({
      chips: ["bob"],
      rest: "_k7m2_q9x4",
      error: "@_k7m2_q9x4 is one of your own handles",
    });
    expect(addChips([], "alice", "_k7m2_q9x4", ["alice"]).error).toBe(
      "@alice is one of your own handles",
    );
  });
  it("stops at MAX_MEMBERS − 1 people besides self", () => {
    const full = Array.from({ length: MAX_MEMBERS - 2 }, (_, i) => `user${i}`);
    const r = addChips(full, "last, over", "alice", []);
    expect(r.chips).toHaveLength(MAX_MEMBERS - 1);
    expect(r.rest).toBe("over");
    expect(r.error).toBe(`at most ${MAX_MEMBERS} members per conversation`);
  });
});

describe("people and nicknames", () => {
  const person = (handle: string, nickname = "", contactOf: string[] = []): PersonView => ({
    uid: `u-${handle}`,
    handle,
    nickname,
    contactOf,
  });
  const people = [
    person("bobby"),
    person("bob", "Mom Smith", ["u-alice"]),
    person("carol", "", ["u-alice"]),
    person("dave", "", ["u-alias"]),
    person("oscar", "", ["u-alice"]),
  ];
  const handles = (ps: PersonView[]) => ps.map((p) => p.handle);
  it("suggests by handle or nickname: exact first, the account's contacts next, prefixes before the rest", () => {
    expect(handles(suggest(people, "bob", "u-alice", []))).toEqual(["bob", "bobby"]);
    expect(handles(suggest(people, "mom", "u-alice", []))).toEqual(["bob"]);
    expect(handles(suggest(people, "MOM SMITH", "u-alias", []))).toEqual(["bob"]);
    expect(handles(suggest(people, "car", "u-alice", []))).toEqual(["carol", "oscar"]);
    expect(handles(suggest(people, "", "u-alias", ["carol"]))).toEqual([
      "dave",
      "bobby",
      "bob",
      "oscar",
    ]);
    expect(suggest(people, "", "u-alice", [], 2)).toHaveLength(2);
    expect(suggest(people, "zzz", "u-alice", [])).toEqual([]);
  });
  it("takes an @handle as a handle only, never as someone's nickname", () => {
    // @dave is called "carol", and a real @carol is known; @alexander_k is called "alex", and @alex is not known
    const ps = [
      person("dave", "carol", ["u-alice"]),
      person("carol"),
      person("alexander_k", "alex", ["u-alice"]),
    ];
    expect(handleOnly(" ＠alex")).toBe(true);
    expect(handleOnly("alex")).toBe(false);
    expect(handles(suggest(people, "@MOM SMITH", "u-alias", []))).toEqual([]);
    expect(handles(suggest(people, "@mom", "u-alice", []))).toEqual([]);
    expect(handles(suggest(ps, "@carol", "u-alice", []))).toEqual(["carol"]);
    expect(handles(suggest(ps, "@alex", "u-alice", []))).toEqual(["alexander_k"]);
    expect(namesExactly(ps[2], "@alex")).toBe(false);
    expect(namesExactly(ps[2], "alex")).toBe(true);
    expect(namesExactly(ps[1], "@Carol")).toBe(true);
    expect(byNickname(people, "@mom smith")).toBeUndefined();
    expect(byNickname(ps, "@alex")).toBeUndefined();
    expect(byNickname(ps, "＠ alex")).toBeUndefined();
  });
  it("puts the person whose handle is typed before the one whose nickname it is", () => {
    const ps = [person("dave", "carol", ["u-alice"]), person("carol")];
    // the contact whose nickname it is comes second, and a whole nickname does not stand for a known handle
    expect(handles(suggest(ps, "carol", "u-alice", []))).toEqual(["carol", "dave"]);
    expect(byNickname(ps, "Carol")).toBeUndefined();
    expect(byNickname([ps[0]], "Carol")).toBe("dave");
  });
  it("finds a person by their whole nickname, and sees one being typed", () => {
    expect(byNickname(people, " mom smith ")).toBe("bob");
    expect(byNickname(people, "mom")).toBeUndefined();
    expect(byNickname(people, "")).toBeUndefined();
    expect(startsNickname(people, "Mom ")).toBe(true);
    expect(startsNickname(people, "mom smith")).toBe(true);
    expect(startsNickname(people, "mom smith,")).toBe(false);
    expect(startsNickname(people, "bob ")).toBe(false);
  });
  it("names a user by nickname, else by handle, always with its @ (never an unknown member's ?…)", () => {
    expect(nameOf("bob", "Mom")).toBe("Mom");
    expect(nameOf("bob")).toBe("@bob");
    expect(nameOf("?Xk3f9QaZ")).toBe("?Xk3f9QaZ");
    expect(nameOf("")).toBe("");
    expect(nameWithHandle("bob", "Mom")).toBe("Mom (@bob)");
    expect(nameWithHandle("bob")).toBe("@bob");
  });
  it("counts the live temporary handles against the cap, the retired ones not", () => {
    const alias = (i: number, retired = false) => ({
      uid: `u-${i}`,
      handle: `_a${i}`,
      fingerprint: "",
      alias: true,
      index: i,
      retired,
      status: retired ? ("retired" as const) : ("ready" as const),
    });
    const live = Array.from({ length: MAX_LIVE_ALIASES - 1 }, (_, i) => alias(i));
    expect(atAliasCap([...live, alias(99, true)])).toBe(false);
    expect(atAliasCap([...live, alias(98)])).toBe(true);
  });
  it("starts conversations only as an account that runs here", () => {
    const as = (status: "starting" | "ready" | "failed" | "idle" | "retired") => ({
      uid: "u-1",
      handle: "_a1",
      fingerprint: "",
      alias: true,
      index: 1,
      retired: status === "retired",
      status,
    });
    expect(runs(as("ready"))).toBe(true);
    expect(runs(as("starting"))).toBe(true);
    expect(runs(as("idle"))).toBe(false);
    expect(runs(as("failed"))).toBe(false);
    expect(runs(as("retired"))).toBe(false);
  });
  it("reserves handles starting with _ for temporary handles", () => {
    expect(isReservedHandle("_k7m2_q9x4")).toBe(true);
    expect(isReservedHandle("alice_")).toBe(false);
  });
  it("lists the owner alone while the engine lists no accounts", () => {
    const me = { uid: "u-alice", handle: "alice", fingerprint: "1" };
    expect(identitiesOf({ identities: [], me })).toEqual([
      {
        uid: "u-alice",
        handle: "alice",
        fingerprint: "1",
        alias: false,
        index: -1,
        retired: false,
        status: "ready",
      },
    ]);
    expect(identitiesOf({ identities: [], me: null })).toEqual([]);
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
    const m = (uid: string, handle: string, you = false) => ({
      uid,
      handle,
      nickname: "",
      you,
      own: false,
      fingerprint: "",
      left: false,
    });
    const me = m("u-me", "me", true);
    const alice = m("u-a", "alice");
    const unknown = m("u-x", "?Xk3f9QaZ");
    expect(inviterOf({ request: true, members: [alice, me] })).toBe(alice);
    expect(inviterOf({ request: true, members: [alice, me, unknown] })).toBe(alice);
    expect(inviterOf({ request: true, members: [unknown, me] })).toBeUndefined();
    expect(inviterOf({ request: false, members: [alice, me] })).toBeUndefined();
  });
});

describe("edits", () => {
  const msg = (key: string, p: Partial<MessageView> = {}): MessageView => ({
    key,
    seq: 1,
    from: "u-me",
    fromHandle: "me",
    fromNickname: "",
    mine: true,
    ts: 1,
    kind: "text",
    text: "hi",
    status: "sent",
    reactions: [],
    ...p,
  });
  it("edits only self's sent texts, a reply carrying a text included", () => {
    expect(editable(msg("a"))).toBe(true);
    expect(editable(msg("a", { reply: { key: "b", state: "shown" } }))).toBe(true);
    expect(editable(msg("a", { edited: { ts: 2, count: 1, sending: false } }))).toBe(true);
    expect(editable(msg("a", { mine: false }))).toBe(false);
    expect(editable(msg("local:1", { status: "sending" }))).toBe(false);
    expect(editable(msg("local:1", { status: "failed" }))).toBe(false);
    expect(editable(msg("a", { kind: "image", text: undefined }))).toBe(false);
    expect(editable(msg("a", { kind: "file", text: undefined }))).toBe(false);
    expect(editable(msg("a", { kind: "system", text: "me added bob" }))).toBe(false);
    expect(editable(msg("a", { kind: "leave", text: undefined }))).toBe(false);
  });
  it("ArrowUp edits self's last sent text, past later messages it cannot edit", () => {
    const own = msg("own");
    const later = [
      msg("theirs", { mine: false }),
      msg("img", { kind: "image", text: undefined }),
      msg("local:2", { status: "failed" }),
    ];
    expect(lastEditable([msg("first"), own, ...later])?.key).toBe("own");
    expect(lastEditable(later)).toBeUndefined();
    expect(lastEditable([])).toBeUndefined();
  });
});
