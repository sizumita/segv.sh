// DEV-ONLY mock of the Engine contract (packages/engine/src/types.ts) for UI work and screenshots.
// Loaded only via `import("./mock-engine")` behind `import.meta.env.DEV && ?mock`, so the
// production bundle never contains it. No crypto, no network: everything is in memory.
//
// URL flags (comma separated): ?mock            -> signed-out
//                              ?mock=ready      -> signed in with sample conversations
//                              ?mock=noprf      -> prfSupported = false
//                              ?mock=fatal      -> fatal phase
//                              ?mock=boot       -> stays in boot
//                              ?mock=warn       -> adds security warnings + an error
//                              ?mock=offline    -> connected = false, syncing = true
//                              ?mock=push       -> notifications can be turned on and off
// Signed in, alice has a temporary handle (`_k7m2_q9x4`, with a conversation of its own) and a retired one, and calls
// bob "Bob B" (§2.6, §11.19). Tests can drive it through `window.__segvMock` (DEV only).

import {
  MAX_LIVE_ALIASES,
  type ConversationView,
  type EditVersion,
  type Engine,
  type EngineState,
  type FileRef,
  type IdentityView,
  type ImageRef,
  type MemberView,
  type MessageView,
  type PersonView,
} from "@segv/engine/types";

const HANDLE_RE = /^[a-z0-9_]{3,20}$/;
/** Mirror of MAX_TEXT_BYTES (packages/engine/src/conv.ts): the longest text, in UTF-8. */
const MAX_TEXT_BYTES = 12_000;
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** The letters of a temporary handle (§2.6). */
const ALIAS_CHARS = "0123456789abcdefghjkmnpqrstvwxyz";
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

const blockedMessage = (c: ConversationView): string =>
  c.blocked === "pending"
    ? "the conversation is changing membership; try again in a moment"
    : c.blocked === "frozen"
      ? "a removed member could still read this conversation; start a new conversation"
      : "you are no longer a member of this conversation";

function fakeFingerprint(seed: string): string {
  let h = 2166136261;
  const out: string[] = [];
  for (let g = 0; g < 6; g++) {
    for (const c of `${seed}/${g}`) {
      h ^= c.charCodeAt(0);
      h = Math.imul(h, 16777619) >>> 0;
    }
    out.push(String(h % 100000).padStart(5, "0"));
  }
  return out.join(" ");
}

function randomId(n = 16): string {
  const b = crypto.getRandomValues(new Uint8Array(n));
  return btoa(String.fromCharCode(...b))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** A fixed 12-character ref per seed conversation, so that a reload with `#c/<ref>` finds it again. */
function mockRef(seed: string): string {
  return (seed + "____________").slice(0, 12).replace(/[^A-Za-z0-9_-]/g, "_");
}

function recoveryCode(): string {
  const b = crypto.getRandomValues(new Uint8Array(32));
  const chars = Array.from(b, (x) => CROCKFORD[x & 31]).join("");
  return chars.match(/.{4}/g)!.join("-");
}

/** A random temporary handle: `_k7m2_q9x4` (§2.6). */
function aliasHandle(): string {
  const b = crypto.getRandomValues(new Uint8Array(8));
  const c = Array.from(b, (x) => ALIAS_CHARS[x & 31]).join("");
  return `_${c.slice(0, 4)}_${c.slice(4)}`;
}

/** Another user's uid in the mock: their handle's. The user's own accounts have theirs (`MockEngine.uidOf`). */
const userUid = (handle: string) => `uid-${handle}`;

/** A member as a descriptor lists it; `dress` fills in `you` and the nickname. */
const member = (handle: string, left = false, uid = userUid(handle)): MemberView => ({
  uid,
  handle,
  nickname: "",
  you: false,
  own: false,
  fingerprint: fakeFingerprint(handle),
  left,
});

/** Who a system line names (§11.9): "you" for the copy's own account, a nickname, or `@handle`. */
type Who = (handle: string) => string;

interface MockOpts {
  ready: boolean;
  noprf: boolean;
  fatal: boolean;
  boot: boolean;
  warn: boolean;
  offline: boolean;
  push: boolean;
}

function parseOpts(): MockOpts {
  const raw = new URLSearchParams(location.search).get("mock") ?? "";
  const f = new Set(raw.split(",").map((s) => s.trim()));
  return {
    ready: f.has("ready") || f.has("warn") || f.has("offline"),
    noprf: f.has("noprf"),
    push: f.has("push"),
    fatal: f.has("fatal"),
    boot: f.has("boot"),
    warn: f.has("warn"),
    offline: f.has("offline"),
  };
}

class MockEngine implements Engine {
  private state: EngineState = {
    phase: "boot",
    progress: "",
    error: "",
    me: null,
    identities: [],
    people: [],
    conversations: [],
    head: { seq: 0, h: "" },
    connected: false,
    syncing: false,
    warnings: [],
    prfSupported: null,
    notifications: "unavailable",
    localNotify: false,
    preview: "unavailable",
    quiet: "unavailable",
  };
  private subs = new Set<(s: EngineState) => void>();
  private seq = 1000;
  private local = 0;
  private blobs = new Map<string, Blob>();
  private urls = new Map<string, string>();
  /** the versions of each edited message (§11.18), by its key: its own text first, then each edit's */
  private versions = new Map<string, EditVersion[]>();
  /** the nicknames the user gave (§11.19), by uid */
  private nicks = new Map<string, string>();
  /** the people the accounts know, without their nicknames (`state.people` has them) */
  private known: Omit<PersonView, "nickname">[] = [];
  /** each conversation's own name (§5.1), by id; none for one named after its members */
  private titles = new Map<string, string>();
  /** system lines, drawn again whenever a nickname changes (§11.9): by message key */
  private lines = new Map<string, (who: Who) => string>();
  /** the conversations of retired temporary handles, by the handle's uid: not shown (§2.6 "Retiring") */
  private parked = new Map<string, ConversationView[]>();

  constructor(private opts: MockOpts) {
    void this.boot();
  }

  private async boot() {
    if (this.opts.boot) return;
    await sleep(200);
    this.set({
      prfSupported: !this.opts.noprf,
      notifications: this.opts.push ? "off" : "unavailable",
      preview: this.opts.push ? "none" : "unavailable",
      quiet: this.opts.push ? "on" : "unavailable",
    });
    if (this.opts.fatal) {
      this.set({
        phase: "fatal",
        error: "your account was not found in the directory of this server",
      });
      return;
    }
    if (this.opts.ready) {
      this.signIn("alice");
      if (this.opts.warn) {
        this.set({
          warnings: [
            "the server is showing different messages from @bob to different members",
            "the public keys of @carol changed",
            "ignored an invalid membership change (×2)",
          ],
          error: "upload failed: 413 payload too large",
        });
      }
      if (this.opts.offline) this.set({ connected: false, syncing: true, progress: "restoring…" });
      return;
    }
    this.set({ phase: "signed-out" });
  }

  // ---- plumbing ----
  getState(): EngineState {
    return this.state;
  }
  subscribe(fn: (s: EngineState) => void): () => void {
    this.subs.add(fn);
    fn(this.state);
    return () => this.subs.delete(fn);
  }
  private set(patch: Partial<EngineState>) {
    this.state = { ...this.state, ...patch };
    for (const fn of this.subs) fn(this.state);
  }
  private fail(msg: string): never {
    this.set({ error: msg, progress: "", phase: this.state.me ? "ready" : "signed-out" });
    throw new Error(msg);
  }
  private updateConv(id: string, fn: (c: ConversationView) => ConversationView) {
    const list = this.state.conversations.map((c) => (c.id === id ? this.dress(fn(c)) : c));
    list.sort((a, b) => b.lastTs - a.lastTs);
    this.set({ conversations: list });
  }
  /** The user's account `uid` (the owner or a temporary handle). */
  private identity(uid: string): IdentityView | undefined {
    return this.state.identities.find((i) => i.uid === uid);
  }
  /** The account that holds a conversation (§2.6). */
  private selfOf(c: ConversationView): IdentityView {
    return this.identity(c.as) ?? this.state.identities[0];
  }
  /** A handle's uid: the user's own account's, or another user's. */
  private uidOf(handle: string): string {
    return this.state.identities.find((i) => i.handle === handle)?.uid ?? userUid(handle);
  }
  /** The nickname shown for `uid` (§11.19): never for the user's own accounts, nor for an unknown member. */
  private nickOf(uid: string, handle: string): string {
    if (handle.startsWith("?") || this.identity(uid)) return "";
    return this.nicks.get(uid) ?? "";
  }
  /**
   * A conversation as the engine shows it, from the view of the account that holds it (§11.19): `you`, the members'
   * nicknames, the senders', its name and its system lines. Unchanged parts stay the same objects.
   */
  private dress(c: ConversationView): ConversationView {
    const self = this.selfOf(c);
    const members = c.members.map((m) => {
      const you = m.uid === c.as;
      const own = !you && !!this.identity(m.uid);
      const nickname = you ? "" : this.nickOf(m.uid, m.handle);
      return m.you === you && m.own === own && m.nickname === nickname
        ? m
        : { ...m, you, own, nickname };
    });
    const who: Who = (h) => {
      if (h === self.handle) return "you";
      return this.nickOf(this.uidOf(h), h) || `@${h}`;
    };
    const messages = c.messages.map((m) => {
      const fromNickname = m.mine || !m.from ? "" : this.nickOf(m.from, m.fromHandle);
      const line = this.lines.get(m.key);
      const text = line ? line(who) : m.text;
      return m.fromNickname === fromNickname && m.text === text ? m : { ...m, fromNickname, text };
    });
    const title = this.titles.get(c.id);
    const others = members.filter((m) => !m.you).map((m) => m.nickname || `@${m.handle}`);
    const name = title !== undefined ? `# ${title}` : others.join(", ") || "just you";
    const same =
      name === c.name &&
      members.every((m, i) => m === c.members[i]) &&
      messages.every((m, i) => m === c.messages[i]);
    return same ? c : { ...c, name, members, messages };
  }
  /** The people with their nicknames (§11.19). */
  private dressPeople(): PersonView[] {
    return this.known.map((p) => ({ ...p, nickname: this.nicks.get(p.uid) ?? "" }));
  }
  /** The accounts of `as` now know these users (MEMBER records): they are its contacts from now on. */
  private learn(as: string, handles: string[]) {
    for (const h of handles) {
      const uid = this.uidOf(h);
      if (this.identity(uid)) continue;
      const p = this.known.find((x) => x.uid === uid);
      if (!p) this.known.push({ uid, handle: h, contactOf: [as] });
      else if (!p.contactOf.includes(as)) p.contactOf = [...p.contactOf, as];
    }
    this.set({ people: this.dressPeople() });
  }
  private conv(id: string): ConversationView {
    const c = this.state.conversations.find((x) => x.id === id);
    if (!c) this.fail("unknown conversation");
    return c;
  }
  /**
   * A message of the account `self` (the owner unless given): its own when `fromHandle` is self's handle. A system
   * line's `line` draws its text, again on every nickname change.
   */
  private msg(
    p: Partial<MessageView> & Pick<MessageView, "kind"> & { line?: (who: Who) => string },
    self: { uid: string; handle: string } = this.state.me!,
  ): MessageView {
    const mine = p.mine ?? p.fromHandle === self.handle;
    const seq = p.seq ?? ++this.seq;
    const key = p.key ?? `tag-${seq}-${Math.random().toString(16).slice(2)}`;
    if (p.line) this.lines.set(key, p.line);
    const from = p.kind === "system" ? "" : mine ? self.uid : this.uidOf(p.fromHandle ?? "");
    return {
      key,
      seq,
      from,
      fromHandle: p.kind === "system" ? "" : (p.fromHandle ?? self.handle),
      fromNickname: mine || !from ? "" : this.nickOf(from, p.fromHandle ?? ""),
      mine,
      ts: p.ts ?? Date.now(),
      kind: p.kind,
      text: p.text,
      image: p.image,
      file: p.file,
      status: p.status ?? "sent",
      reactions: p.reactions ?? [],
      ...(p.reply ? { reply: p.reply } : {}),
      ...(p.edited ? { edited: p.edited } : {}),
    };
  }
  /** Replaces one message of a conversation with a new object (the UI's copies need one per change). */
  private updateMsg(convId: string, key: string, fn: (m: MessageView) => MessageView) {
    this.updateConv(convId, (c) => ({
      ...c,
      messages: c.messages.map((m) => (m.key === key ? fn(m) : m)),
    }));
  }
  /**
   * A message as its versions show it (§11.18): the latest text, and when it was made. One without edits shows `own`,
   * its own text.
   */
  private asEdited(m: MessageView, own = m.text): MessageView {
    const v = this.versions.get(m.key);
    const out: MessageView = { ...m, text: own };
    delete out.edited;
    if (!v || v.length < 2) return out;
    const last = v[v.length - 1];
    return {
      ...out,
      text: last.text,
      edited: { ts: last.ts, count: v.length - 1, sending: false },
    };
  }
  /** What a mock send replies to: a message of the conversation, as the engine checks it. */
  private replyOf(c: ConversationView, replyTo?: string): MessageView["reply"] {
    if (!replyTo) return undefined;
    if (!c.messages.some((m) => m.key === replyTo && m.status === "sent"))
      this.fail("unknown message");
    return { key: replyTo, state: "shown" };
  }

  // ---- seed data ----
  private signIn(handle: string) {
    const me = { uid: userUid(handle), handle, fingerprint: fakeFingerprint(handle) };
    // the owner, a temporary handle with a conversation of its own, and a retired one (§2.6)
    const alias = { uid: "uid-alias-0", handle: "_k7m2_q9x4" };
    const retired = { uid: "uid-alias-1", handle: "_r3vd_8hcw" };
    const identities: IdentityView[] = [
      { ...me, alias: false, index: -1, retired: false, status: "ready" },
      {
        ...alias,
        fingerprint: fakeFingerprint(alias.handle),
        alias: true,
        index: 0,
        retired: false,
        status: "ready",
      },
      {
        ...retired,
        fingerprint: fakeFingerprint(retired.handle),
        alias: true,
        index: 1,
        retired: true,
        status: "retired",
      },
    ];
    this.nicks = new Map([[userUid("bob"), "Bob B"]]);
    const contacts = (handles: string[], of: string) =>
      handles.map((h) => ({ uid: userUid(h), handle: h, contactOf: [of] }));
    this.known = [
      ...contacts(["bob", "carol", "dave", "erin", "frank", "grace", "mallory"], me.uid),
      ...contacts(["nina", "otto"], alias.uid),
      // known from requests that were not accepted: contacts of nobody
      { uid: userUid("zed"), handle: "zed", contactOf: [] },
      { uid: userUid("quinn"), handle: "quinn", contactOf: [] },
    ];
    this.set({
      me,
      identities,
      people: this.dressPeople(),
      phase: "ready",
      progress: "",
      connected: true,
      syncing: false,
      head: { seq: 1093, h: "q2Vh3…" },
    });
    const now = Date.now();
    const m = (p: Parameters<MockEngine["msg"]>[0]) => this.msg(p);
    /** A member who is one of the user's accounts, holding the conversation. */
    const self = (left = false) => member(handle, left, me.uid);
    this.versions.clear();
    this.lines.clear();
    this.titles.clear();
    this.parked.clear();
    /** A message that was edited: `text` is its own, each of `edits` a later version (§11.18). */
    const edited = (
      p: Partial<MessageView> & Pick<MessageView, "kind">,
      edits: EditVersion[],
    ): MessageView => {
      const x = this.msg(p);
      this.versions.set(x.key, [{ text: x.text ?? "", ts: x.ts }, ...edits]);
      return this.asEdited(x);
    };
    /** A conversation of the owner, with its own name when `title` is given. */
    const conv = (
      title: string | undefined,
      c: Omit<ConversationView, "id" | "as" | "name"> & { as?: string },
    ): ConversationView => {
      const id = randomId();
      if (title !== undefined) this.titles.set(id, title);
      return { id, as: me.uid, name: "", ...c };
    };
    const dm = conv(undefined, {
      ref: mockRef("dm"),
      members: [self(), member("bob")],
      epoch: 0,
      canSend: true,
      blocked: "",
      frozen: false,
      request: false,
      byContact: true,
      lastTs: now - 2 * MIN,
      unread: 0,
      messages: [
        m({
          kind: "system",
          line: (w) => `${w(handle)} started the conversation`,
          ts: now - 2 * DAY,
        }),
        edited({ kind: "text", fromHandle: "bob", text: "hey", ts: now - 2 * DAY + MIN }, [
          { text: "hey, you around", ts: now - 2 * DAY + MIN + 20_000 },
          { text: "hey, are you around?", ts: now - 2 * DAY + 2 * MIN },
        ]),
        m({
          kind: "text",
          fromHandle: handle,
          text: "yes — what’s up?",
          ts: now - 2 * DAY + 3 * MIN,
        }),
        m({
          kind: "text",
          fromHandle: "bob",
          text: "こんにちは！今日の会議の資料を送ります。\n確認お願いします 🙏\n\n- 議題 1: リリース日程\n- 議題 2: 鍵のローテーション",
          ts: now - 26 * MIN,
        }),
        m({
          kind: "image",
          fromHandle: "bob",
          image: { id: "seed-landscape", k: "k", mime: "image/png", w: 1600, h: 1000 },
          ts: now - 25 * MIN,
        }),
        m({
          kind: "file",
          fromHandle: "bob",
          file: {
            id: "seed-file",
            k: "k",
            name: "会議資料 2026-11 リリース日程と鍵のローテーション.pdf",
            size: 2_345_678,
          },
          ts: now - 24 * MIN,
        }),
        m({
          kind: "text",
          fromHandle: handle,
          text: "ありがとう、見ておきます",
          ts: now - 20 * MIN,
        }),
        m({
          kind: "text",
          fromHandle: "bob",
          text: "also: https://example.com/a/very/long/link/that/should/wrap/instead/of/overflowing/the/message/column/abcdefghijklmnopqrstuvwxyz0123456789",
          ts: now - 2 * MIN,
        }),
      ],
    });
    // A thread (§11.17): two replies to "shipping friday?", each with replies of its own, and one to a message that
    // is not loaded.
    const ship = m({
      kind: "text",
      fromHandle: "carol",
      text: "shipping friday?",
      ts: now - 9 * MIN,
    });
    const to = (x: MessageView) => ({ reply: { key: x.key, state: "shown" as const } });
    const works = m({
      kind: "text",
      fromHandle: "bob",
      text: "friday works for me",
      ts: now - 8 * MIN,
      ...to(ship),
    });
    // edited (§11.18): its quote line above carol's reply shows the edited text
    const thu = edited(
      {
        kind: "text",
        fromHandle: handle,
        text: "could we do thursday?",
        ts: now - 7 * MIN,
        ...to(ship),
      },
      [{ text: "could we do **thursday** instead?", ts: now - 7 * MIN + 40_000 }],
    );
    const fri = m({
      kind: "text",
      fromHandle: "carol",
      text: "friday it is, then. i'll tag the release in the morning",
      ts: now - 6 * MIN,
      ...to(works),
    });
    const notes = m({
      kind: "text",
      fromHandle: "bob",
      text: "i'll write the release notes",
      ts: now - 5 * MIN,
      ...to(fri),
    });
    const tight = m({
      kind: "text",
      fromHandle: "carol",
      text: "thursday is tight, the key rotation is not merged yet",
      ts: now - 5 * MIN + 20_000,
      ...to(thu),
    });
    const lost = m({
      kind: "text",
      fromHandle: "bob",
      text: "about the plan from last month",
      ts: now - 4 * MIN,
      reply: { key: "", state: "waiting" },
    });
    const group = conv("project 夜明け", {
      ref: mockRef("group"),
      members: [self(), member("bob"), member("carol"), member("dave", true)],
      epoch: 3,
      canSend: true,
      blocked: "",
      frozen: false,
      request: false,
      byContact: true,
      lastTs: now - 4 * MIN,
      unread: 3,
      messages: [
        m({
          kind: "system",
          line: (w) => `${w(handle)} renamed the conversation to “project 夜明け”`,
          ts: now - 3 * DAY,
        }),
        m({
          kind: "system",
          line: (w) => `${w(handle)} added ${["bob", "carol", "dave"].map(w).join(", ")}`,
          ts: now - 3 * DAY,
        }),
        m({ kind: "text", fromHandle: "carol", text: "hi all", ts: now - 3 * DAY + HOUR }),
        m({
          kind: "image",
          fromHandle: "carol",
          image: { id: "seed-portrait", k: "k", mime: "image/png", w: 900, h: 1400 },
          ts: now - 3 * DAY + HOUR + MIN,
        }),
        m({ kind: "leave", fromHandle: "dave", ts: now - DAY }),
        m({
          kind: "text",
          fromHandle: "bob",
          text: "dave left, i will rotate the key next time i send",
          ts: now - 12 * MIN,
        }),
        m({ kind: "text", fromHandle: "carol", text: "ok 👍", ts: now - 10 * MIN }),
        ship,
        works,
        thu,
        fri,
        notes,
        tight,
        lost,
        m({
          kind: "text",
          fromHandle: handle,
          text: "this one failed to send",
          status: "failed",
          seq: 0,
          key: `local:${++this.local}`,
          ts: now - 8 * MIN,
        }),
      ],
    });
    const removed = conv("old team", {
      ref: mockRef("removed"),
      members: [member("erin"), member("frank")],
      epoch: 5,
      canSend: false,
      blocked: "removed",
      frozen: false,
      request: false,
      byContact: true,
      lastTs: now - 6 * DAY,
      unread: 0,
      messages: [
        m({ kind: "text", fromHandle: "erin", text: "see you all", ts: now - 6 * DAY - HOUR }),
        m({ kind: "system", line: (w) => `${w("erin")} removed you`, ts: now - 6 * DAY }),
      ],
    });
    const old = conv(undefined, {
      ref: mockRef("old"),
      members: [self(), member("carol")],
      epoch: 0,
      canSend: true,
      blocked: "",
      frozen: false,
      request: false,
      byContact: true,
      lastTs: now - 40 * DAY,
      unread: 0,
      messages: [m({ kind: "text", fromHandle: "carol", text: "ping", ts: now - 40 * DAY })],
    });
    const pending = conv("release", {
      ref: mockRef("pending"),
      members: [self(), member("bob"), member("erin")],
      epoch: 2,
      canSend: false,
      blocked: "pending",
      frozen: false,
      request: false,
      byContact: true,
      lastTs: now - 30 * MIN,
      unread: 0,
      messages: [
        m({ kind: "text", fromHandle: "erin", text: "adding frank in a sec", ts: now - 30 * MIN }),
      ],
    });
    const frozen = conv("infra", {
      ref: mockRef("frozen"),
      members: [self(), member("dave"), member("mallory")],
      epoch: 4,
      canSend: false,
      blocked: "frozen",
      frozen: true,
      request: false,
      byContact: true,
      lastTs: now - 3 * HOUR,
      unread: 0,
      messages: [
        m({
          kind: "system",
          line: (w) => `${w("mallory")} removed ${w("dave")}`,
          ts: now - 3 * HOUR,
        }),
      ],
    });
    const request = conv(undefined, {
      ref: mockRef("request"),
      members: [self(), member("zed")],
      epoch: 0,
      canSend: true,
      blocked: "",
      frozen: false,
      request: true,
      byContact: false,
      lastTs: now - 50 * MIN,
      unread: 1,
      messages: [
        m({
          kind: "text",
          fromHandle: "zed",
          text: "hi! got your handle from erin",
          ts: now - 50 * MIN,
        }),
      ],
    });
    // A group request: only its inviter is resolved, the other members stay `?…` until accepted (§11.5).
    const groupRequest = conv("deals", {
      ref: mockRef("groupRequest"),
      members: [member("quinn"), self(), member("?Xk3f9QaZ")],
      epoch: 0,
      canSend: true,
      blocked: "",
      frozen: false,
      request: true,
      byContact: false,
      lastTs: now - 4 * HOUR,
      unread: 2,
      messages: [
        m({
          kind: "system",
          line: (w) => `${w("quinn")} started the conversation`,
          ts: now - 4 * HOUR - MIN,
        }),
        m({
          kind: "text",
          fromHandle: "quinn",
          text: "limited offer, see below",
          ts: now - 4 * HOUR,
        }),
        m({
          kind: "image",
          fromHandle: "quinn",
          image: { id: "seed-request", k: "k", mime: "image/png", w: 800, h: 600 },
          ts: now - 4 * HOUR,
        }),
      ],
    });
    const left = conv("book club", {
      ref: mockRef("left"),
      members: [self(true), member("erin"), member("grace")],
      epoch: 2,
      canSend: false,
      blocked: "left",
      frozen: false,
      request: false,
      byContact: true,
      lastTs: now - 9 * DAY,
      unread: 0,
      messages: [
        m({
          kind: "text",
          fromHandle: "grace",
          text: "next month: dune",
          ts: now - 9 * DAY - HOUR,
        }),
        m({ kind: "leave", fromHandle: handle, mine: true, ts: now - 9 * DAY }),
      ],
    });
    // The temporary handle's own conversation: nina knows it only as @_k7m2_q9x4.
    const am = (p: Parameters<MockEngine["msg"]>[0]) => this.msg(p, alias);
    const flat = conv(undefined, {
      as: alias.uid,
      ref: mockRef("flat"),
      members: [member(alias.handle, false, alias.uid), member("nina")],
      epoch: 0,
      canSend: true,
      blocked: "",
      frozen: false,
      request: false,
      byContact: true,
      lastTs: now - 15 * MIN,
      unread: 1,
      messages: [
        am({
          kind: "system",
          line: (w) => `${w(alias.handle)} started the conversation`,
          ts: now - HOUR,
        }),
        am({
          kind: "text",
          fromHandle: alias.handle,
          text: "hi, is the flat on 3rd street still available?",
          ts: now - HOUR,
        }),
        am({
          kind: "text",
          fromHandle: "nina",
          text: "it is! viewings on saturday, 10:00 or 14:00",
          ts: now - 15 * MIN,
        }),
      ],
    });
    // Carol added both of the user's accounts to one group: two copies, one for each (§2.6), in which the other account
    // is a member like any other ("your other handle").
    const street = (as: { uid: string; handle: string }, ref: string): ConversationView => {
      const sm = (p: Parameters<MockEngine["msg"]>[0]) => this.msg(p, as);
      return conv("street party", {
        as: as.uid,
        ref: mockRef(ref),
        members: [
          member("carol"),
          member(handle, false, me.uid),
          member(alias.handle, false, alias.uid),
          member("nina"),
        ],
        epoch: 1,
        canSend: true,
        blocked: "",
        frozen: false,
        request: false,
        byContact: true,
        lastTs: now - 70 * MIN,
        unread: 0,
        messages: [
          sm({
            kind: "system",
            line: (w) => `${w("carol")} added ${[handle, alias.handle, "nina"].map(w).join(", ")}`,
            ts: now - 2 * HOUR,
          }),
          sm({
            kind: "text",
            fromHandle: "carol",
            text: "street party on the 14th! who can bring tables?",
            ts: now - 2 * HOUR,
          }),
          sm({
            kind: "text",
            fromHandle: alias.handle,
            text: "i can bring two",
            ts: now - 70 * MIN,
          }),
        ],
      });
    };
    const streetMain = street(me, "street");
    const streetAlias = street(alias, "streetAlias");
    // The retired handle's conversation, shown again once it is brought back.
    this.parked.set(retired.uid, [
      conv(undefined, {
        as: retired.uid,
        ref: mockRef("parked"),
        members: [member(retired.handle, false, retired.uid), member("otto")],
        epoch: 0,
        canSend: true,
        blocked: "",
        frozen: false,
        request: false,
        byContact: true,
        lastTs: now - 12 * DAY,
        unread: 0,
        messages: [
          this.msg(
            {
              kind: "text",
              fromHandle: "otto",
              text: "is the bike still for sale?",
              ts: now - 12 * DAY,
            },
            retired,
          ),
        ],
      }),
    ]);
    const list = [
      dm,
      group,
      removed,
      old,
      pending,
      frozen,
      request,
      groupRequest,
      left,
      flat,
      streetMain,
      streetAlias,
    ]
      .map((c) => this.dress(c))
      .sort((a, b) => b.lastTs - a.lastTs);
    this.set({ conversations: list });
  }

  // ---- account ----
  async register(handle: string): Promise<{ recoveryCode: string }> {
    if (!HANDLE_RE.test(handle)) this.fail("invalid handle");
    if (this.state.prfSupported === false)
      this.fail("this passkey provider does not support the PRF extension");
    this.set({ phase: "working", error: "", progress: "waiting for passkey…" });
    await sleep(700);
    if (handle === "taken") this.fail('handle "taken" is already registered');
    this.set({ progress: "solving proof of work…" });
    await sleep(700);
    this.set({ progress: "publishing account…" });
    await sleep(300);
    const code = recoveryCode();
    this.signIn(handle);
    return { recoveryCode: code };
  }
  async login(remember: boolean): Promise<void> {
    void remember;
    this.set({ phase: "working", error: "", progress: "waiting for passkey…" });
    await sleep(700);
    this.set({ progress: "unlocking…" });
    await sleep(300);
    this.signIn("alice");
  }
  async loginWithRecovery(code: string, remember: boolean): Promise<void> {
    void remember;
    const clean = code.toUpperCase().replace(/[\s-]/g, "");
    if (clean.length !== 32 || [...clean].some((c) => !CROCKFORD.includes(c)))
      this.fail("invalid recovery code");
    this.set({ phase: "working", error: "", progress: "unlocking with recovery code…" });
    await sleep(600);
    this.signIn("alice");
  }
  async addPasskey(): Promise<void> {
    this.set({ progress: "waiting for passkey…", error: "" });
    await sleep(800);
    this.set({ progress: "" });
  }
  async logout(): Promise<void> {
    this.set({
      phase: "signed-out",
      me: null,
      identities: [],
      people: [],
      conversations: [],
      connected: false,
      warnings: [],
      error: "",
      progress: "",
    });
  }

  // ---- conversations ----
  async createConversation(handles: string[], name?: string, as?: string): Promise<string> {
    const me = this.state.me;
    if (!me) this.fail("not signed in");
    const self = as ? this.identity(as) : this.state.identities[0];
    // as the engine's accountFor: only an account this device runs (util.runs)
    if (!self || (self.status !== "ready" && self.status !== "starting"))
      this.fail(self?.retired ? "this temporary handle is retired" : "unknown account");
    for (const h of handles) {
      if (!HANDLE_RE.test(h)) this.fail(`invalid handle: ${h}`);
      if (h === "nobody") this.fail(`unknown: @${h}`);
      // §2.6: the others would see the user's two accounts meet
      if (h !== self.handle && this.state.identities.some((i) => i.handle === h))
        this.fail(`@${h} is one of your own handles`);
    }
    const others = handles.filter((h) => h !== self.handle);
    this.set({ progress: "looking up handles…" });
    await sleep(500);
    this.set({ progress: "creating conversation…" });
    await sleep(400);
    const now = Date.now();
    const id = randomId();
    if (name) this.titles.set(id, name);
    const c: ConversationView = {
      id,
      as: self.uid,
      ref: randomId(9),
      name: "",
      members: [
        member(self.handle, false, self.uid),
        ...others.map((h) => member(h, false, this.uidOf(h))),
      ],
      epoch: 0,
      canSend: true,
      blocked: "",
      frozen: false,
      request: false,
      byContact: true,
      lastTs: now,
      unread: 0,
      messages: [
        this.msg(
          {
            kind: "system",
            line: (w) => `${w(self.handle)} added ${others.map(w).join(", ")}`,
            ts: now,
          },
          self,
        ),
      ],
    };
    this.learn(self.uid, others);
    this.set({ conversations: [this.dress(c), ...this.state.conversations], progress: "" });
    return c.id;
  }

  // ---- temporary handles and nicknames (§2.6, §11.19) ----
  /** As the engine's: at most MAX_LIVE_ALIASES temporary handles that are not retired (§2.6). */
  private checkCap() {
    const live = this.state.identities.filter((i) => i.alias && !i.retired).length;
    if (live >= MAX_LIVE_ALIASES)
      this.fail(`at most ${MAX_LIVE_ALIASES} temporary handles can be active; retire one first`);
  }
  async createAlias(): Promise<string> {
    if (!this.state.me) this.fail("not signed in");
    this.checkCap();
    this.set({ progress: "solving proof of work…", error: "" });
    await sleep(1500);
    const index = Math.max(-1, ...this.state.identities.map((i) => i.index)) + 1;
    const handle = aliasHandle();
    const alias: IdentityView = {
      uid: `uid-alias-${index}`,
      handle,
      fingerprint: fakeFingerprint(handle),
      alias: true,
      index,
      retired: false,
      status: "starting",
    };
    this.set({ identities: [...this.state.identities, alias], progress: "starting it…" });
    await sleep(300);
    this.setIdentity(alias.uid, { status: "ready" });
    this.set({ progress: "" });
    return alias.uid;
  }
  async setAliasRetired(uid: string, retired: boolean): Promise<void> {
    const a = this.identity(uid);
    if (!a?.alias) this.fail("not a temporary handle");
    if (!retired && a.retired) this.checkCap();
    await sleep(250);
    if (retired) {
      // its conversations are not shown while it is retired
      const mine = this.state.conversations.filter((c) => c.as === uid);
      this.parked.set(uid, [...(this.parked.get(uid) ?? []), ...mine]);
      this.setIdentity(uid, { retired: true, status: "retired" });
      this.set({ conversations: this.state.conversations.filter((c) => c.as !== uid) });
      return;
    }
    this.setIdentity(uid, { retired: false, status: "starting" });
    await sleep(500);
    const back = (this.parked.get(uid) ?? []).map((c) => this.dress(c));
    this.parked.delete(uid);
    this.setIdentity(uid, { status: "ready" });
    this.set({
      conversations: [...this.state.conversations, ...back].sort((a, b) => b.lastTs - a.lastTs),
    });
  }
  private setIdentity(uid: string, patch: Partial<IdentityView>) {
    this.set({
      identities: this.state.identities.map((i) => (i.uid === uid ? { ...i, ...patch } : i)),
    });
  }
  /** As the engine's (§11.19): `validName`, never one of the user's own accounts; "" removes it. */
  async setNickname(uid: string, nickname: string): Promise<void> {
    if (this.identity(uid)) this.fail("you cannot give your own handles a nickname");
    const n = nickname;
    if (
      n !== "" &&
      (!n.trim() || [...n].length > 64 || n.normalize("NFKC").trimStart().startsWith("@"))
    )
      this.fail("a nickname: 1–64 characters, not starting with @");
    await sleep(150);
    if (n) this.nicks.set(uid, n);
    else this.nicks.delete(uid);
    // names, lines and senders are drawn again, without reading anything again
    this.set({
      people: this.dressPeople(),
      conversations: this.state.conversations.map((c) => this.dress(c)),
    });
  }

  private pushMessage(convId: string, m: MessageView, bumpUnread = false) {
    this.updateConv(convId, (c) => ({
      ...c,
      messages: [...c.messages, m],
      lastTs: Math.max(c.lastTs, m.ts),
      unread: c.unread + (bumpUnread ? 1 : 0),
    }));
  }
  /** Settles an echo; returns the key of the sent message. */
  private settle(convId: string, key: string, status: "sent" | "failed"): string {
    const seq = status === "sent" ? ++this.seq : 0;
    const next = status === "sent" ? `tag-${seq}` : key;
    this.updateConv(convId, (c) => ({
      ...c,
      messages: c.messages.map((x) => (x.key === key ? { ...x, status, seq, key: next } : x)),
    }));
    return next;
  }

  async sendText(convId: string, text: string, replyTo?: string): Promise<void> {
    const c = this.conv(convId);
    if (!c.canSend) this.fail(blockedMessage(c));
    const reply = this.replyOf(c, replyTo);
    const key = `local:${++this.local}`;
    this.pushMessage(
      convId,
      this.msg(
        { kind: "text", text, mine: true, status: "sending", seq: 0, key, reply },
        this.selfOf(c),
      ),
    );
    await sleep(500);
    const failed = /\bfail\b/i.test(text);
    const sent = this.settle(convId, key, failed ? "failed" : "sent");
    if (failed) return;
    const other = c.members.find((m) => !m.you && !m.left && !m.handle.startsWith("?"));
    if (other) {
      // a reply is answered with a reply to it, so that a thread grows
      const to = reply ? { key: sent, state: "shown" as const } : undefined;
      setTimeout(() => this.incoming(convId, other.handle, `echo: ${text}`, to), 1200);
    }
  }

  async sendImage(convId: string, file: File, replyTo?: string): Promise<void> {
    const c = this.conv(convId);
    if (!c.canSend) this.fail(blockedMessage(c));
    const reply = this.replyOf(c, replyTo);
    if (!file.type.startsWith("image/")) this.fail("not an image");
    let w = 0;
    let h = 0;
    try {
      const bmp = await createImageBitmap(file);
      w = bmp.width;
      h = bmp.height;
      bmp.close();
    } catch {
      this.fail("could not decode image");
    }
    const id = `local-img-${++this.local}`;
    this.blobs.set(id, file);
    const key = `local:${++this.local}`;
    const image: ImageRef = { id, k: "k", mime: file.type, w, h };
    this.pushMessage(
      convId,
      this.msg(
        { kind: "image", image, mine: true, status: "sending", seq: 0, key, reply },
        this.selfOf(c),
      ),
    );
    await sleep(700);
    this.settle(convId, key, "sent");
  }

  async sendFile(convId: string, file: File, replyTo?: string): Promise<void> {
    const c = this.conv(convId);
    if (!c.canSend) this.fail(blockedMessage(c));
    const reply = this.replyOf(c, replyTo);
    if (file.size > 10 * 1024 * 1024) this.fail("the file is too large");
    const id = `local-file-${++this.local}`;
    this.blobs.set(id, file);
    const key = `local:${++this.local}`;
    const ref: FileRef = { id, k: "k", name: file.name || "file", size: file.size };
    this.pushMessage(
      convId,
      this.msg(
        { kind: "file", file: ref, mine: true, status: "sending", seq: 0, key, reply },
        this.selfOf(c),
      ),
    );
    await sleep(700);
    this.settle(convId, key, "sent");
  }

  async addMembers(convId: string, handles: string[]): Promise<void> {
    const c = this.conv(convId);
    const self = this.selfOf(c);
    for (const h of handles) {
      if (!HANDLE_RE.test(h)) this.fail(`invalid handle: ${h}`);
      if (this.state.identities.some((i) => i.handle === h))
        this.fail(`@${h} is one of your own handles`);
    }
    await sleep(300);
    const added = handles.filter((h) => !c.members.some((m) => m.handle === h));
    this.updateConv(convId, (x) => ({
      ...x,
      epoch: x.epoch + 1,
      members: [...x.members, ...added.map((h) => member(h))],
    }));
    this.learn(self.uid, added);
    this.pushMessage(
      convId,
      this.msg(
        { kind: "system", line: (w) => `${w(self.handle)} added ${added.map(w).join(", ")}` },
        self,
      ),
    );
  }
  async removeMember(convId: string, uid: string): Promise<void> {
    const c = this.conv(convId);
    const self = this.selfOf(c);
    const who = c.members.find((m) => m.uid === uid);
    if (!who) this.fail("not a member");
    if (who.you) this.fail("use “leave” to leave a conversation");
    await sleep(300);
    this.updateConv(convId, (x) => ({
      ...x,
      epoch: x.epoch + 1,
      members: x.members.filter((m) => m.uid !== uid),
    }));
    this.pushMessage(
      convId,
      this.msg({ kind: "system", line: (w) => `${w(self.handle)} removed ${w(who.handle)}` }, self),
    );
  }
  async leave(convId: string): Promise<void> {
    const self = this.selfOf(this.conv(convId));
    await sleep(300);
    this.pushMessage(
      convId,
      this.msg({ kind: "leave", fromHandle: self.handle, mine: true }, self),
    );
    this.updateConv(convId, (c) => ({ ...c, canSend: false, blocked: "left" }));
  }

  // ---- images ----
  async loadImage(img: ImageRef): Promise<string> {
    const cached = this.urls.get(img.id);
    if (cached) return cached;
    await sleep(350);
    let blob = this.blobs.get(img.id);
    if (!blob) {
      if (img.id === "seed-broken") throw new Error("blob hash mismatch");
      blob = await this.paint(img.w, img.h, img.id);
    }
    const url = URL.createObjectURL(blob);
    this.urls.set(img.id, url);
    return url;
  }
  /** The mock keeps every image for the page's life. */
  releaseImage(_img: ImageRef): void {}

  // ---- files ----
  async loadFile(file: FileRef): Promise<string> {
    const cached = this.urls.get(file.id);
    if (cached) return cached;
    await sleep(350);
    const bytes = this.blobs.get(file.id) ?? new Blob([`mock file ${file.name}\n`]);
    const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
    this.urls.set(file.id, url);
    return url;
  }

  private async paint(w: number, h: number, seed: string): Promise<Blob> {
    const c = document.createElement("canvas");
    c.width = w;
    c.height = h;
    const g = c.getContext("2d")!;
    const grad = g.createLinearGradient(0, 0, w, h);
    grad.addColorStop(0, seed.includes("portrait") ? "#1d3557" : "#f4a261");
    grad.addColorStop(1, seed.includes("portrait") ? "#a8dadc" : "#264653");
    g.fillStyle = grad;
    g.fillRect(0, 0, w, h);
    g.fillStyle = "rgba(255,255,255,0.85)";
    g.font = `${Math.round(Math.min(w, h) / 10)}px monospace`;
    g.fillText(`${w}×${h}`, w / 12, h / 2);
    return await new Promise<Blob>((r, j) =>
      c.toBlob((b) => (b ? r(b) : j(new Error("toBlob"))), "image/png"),
    );
  }

  async setNotifications(on: boolean): Promise<void> {
    if (this.state.notifications === "unavailable") return;
    await sleep(150);
    this.set({ notifications: on ? "on" : "off" });
  }

  async setQuiet(on: boolean): Promise<void> {
    if (this.state.quiet === "unavailable") return;
    this.set({ quiet: on ? "on" : "off" });
  }

  async setPreview(p: "none" | "name" | "message"): Promise<void> {
    if (this.state.preview === "unavailable") return;
    this.set({ preview: p });
  }

  markRead(convId: string, _opened = true): void {
    // The pane is open: it accepts nothing (§11.11). No BELL rows here: `opened` only matters to the engine (§11.13).
    const c = this.state.conversations.find((x) => x.id === convId);
    if (c?.unread) this.updateConv(convId, (x) => ({ ...x, unread: 0 }));
  }

  async accept(convId: string): Promise<void> {
    const c = this.conv(convId);
    if (c.byContact || !c.canSend) return;
    await sleep(300);
    this.updateConv(convId, (x) => ({ ...x, request: false, byContact: true }));
  }

  async react(convId: string, messageKey: string, emoji: string, on: boolean): Promise<void> {
    const c = this.conv(convId);
    if (!c.canSend) this.fail(blockedMessage(c));
    await sleep(200);
    this.updateConv(convId, (x) => ({
      ...x,
      request: false,
      byContact: true,
      messages: x.messages.map((m) => {
        if (m.key !== messageKey) return m;
        const had = m.reactions.find((r) => r.emoji === emoji);
        if (on && had?.mine) return m;
        if (!on && !had?.mine) return m;
        const others = (had?.count ?? 0) - (had?.mine ? 1 : 0);
        const next = on
          ? { emoji, count: others + 1, mine: true }
          : { emoji, count: others, mine: false };
        const rest = m.reactions.filter((r) => r.emoji !== emoji);
        return { ...m, reactions: next.count > 0 ? [...rest, next] : rest };
      }),
    }));
  }
  /**
   * As the engine's (§11.18): self's sent text only; the new text shows at once (`edited.sending`), and the current
   * text again when the send fails, which a text with the word "fail" in it does.
   */
  async editText(convId: string, messageKey: string, text: string): Promise<void> {
    const c = this.conv(convId);
    const body = text.replace(/\s+$/, "");
    if (!body.trim()) this.fail("an edit cannot be empty");
    if (new TextEncoder().encode(body).length > MAX_TEXT_BYTES) this.fail("message is too long");
    const m = c.messages.find((x) => x.key === messageKey);
    if (!m) this.fail("unknown message");
    if (!m.mine || m.kind !== "text" || m.status !== "sent")
      this.fail("this message cannot be edited");
    if (!c.canSend) this.fail(blockedMessage(c));
    const ts = Date.now();
    this.updateMsg(convId, messageKey, (x) => ({
      ...x,
      text: body,
      edited: { ts, count: x.edited?.count ?? 0, sending: true },
    }));
    await sleep(200);
    // back to the current text: nothing changed, or the send failed
    const current = (x: MessageView) => this.asEdited(x, m.text);
    if (body === (this.versions.get(messageKey)?.at(-1)?.text ?? m.text)) {
      this.updateMsg(convId, messageKey, current);
      return;
    }
    if (/\bfail\b/i.test(body)) {
      this.updateMsg(convId, messageKey, current);
      this.fail("message was not delivered (membership changed or the request failed); try again");
    }
    const v = this.versions.get(messageKey) ?? [{ text: m.text ?? "", ts: m.ts }];
    this.versions.set(messageKey, [...v, { text: body, ts }]);
    this.updateMsg(convId, messageKey, (x) => this.asEdited(x));
  }
  editHistory(convId: string, messageKey: string): EditVersion[] {
    const c = this.state.conversations.find((x) => x.id === convId);
    if (!c?.messages.some((m) => m.key === messageKey)) return [];
    const v = this.versions.get(messageKey) ?? [];
    return v.length < 2 ? [] : v.map((x) => ({ ...x }));
  }
  clearError(): void {
    if (this.state.error) this.set({ error: "" });
  }

  // ---- test hooks ----
  incoming(convId: string, fromHandle: string, text: string, reply?: MessageView["reply"]) {
    const c = this.state.conversations.find((x) => x.id === convId);
    if (!c) return;
    this.pushMessage(
      convId,
      this.msg({ kind: "text", fromHandle, text, mine: false, reply }, this.selfOf(c)),
      true,
    );
  }
  /** Another member's edit of their message `key` (§11.18). */
  incomingEdit(convId: string, key: string, text: string) {
    const m = this.state.conversations
      .find((c) => c.id === convId)
      ?.messages.find((x) => x.key === key);
    if (!m || m.mine || m.kind !== "text") return;
    const v = this.versions.get(key) ?? [{ text: m.text ?? "", ts: m.ts }];
    this.versions.set(key, [...v, { text, ts: Date.now() }]);
    this.updateMsg(convId, key, (x) => this.asEdited(x));
  }
  incomingAt(index: number, text: string) {
    const c = this.state.conversations[index];
    const other = c?.members.find((m) => !m.you && !m.handle.startsWith("?"));
    if (c && other) this.incoming(c.id, other.handle, text);
  }
  setPatch(p: Partial<EngineState>) {
    this.set(p);
  }
}

let instance: MockEngine | undefined;

export function getMockEngine(): Engine {
  if (!import.meta.env.DEV) throw new Error("mock engine is dev-only");
  if (!instance) {
    instance = new MockEngine(parseOpts());
    (globalThis as unknown as { __segvMock?: MockEngine }).__segvMock = instance;
  }
  return instance;
}
