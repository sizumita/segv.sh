// DEV-ONLY mock of the Engine contract (src/client/types.ts) for UI work and screenshots.
// Loaded only via `import('~/client/mock-engine')` behind `import.meta.env.DEV && ?mock`, so the
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
// Tests can drive it through `window.__segvMock` (DEV only).

import type {
  ConversationView,
  Engine,
  EngineState,
  ImageRef,
  MemberView,
  MessageView,
} from "./types";

const HANDLE_RE = /^[a-z0-9_]{3,20}$/;
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
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

const member = (handle: string, left = false): MemberView => ({
  uid: `uid-${handle}`,
  handle,
  fingerprint: fakeFingerprint(handle),
  left,
});

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
    conversations: [],
    head: { seq: 0, h: "" },
    connected: false,
    syncing: false,
    warnings: [],
    prfSupported: null,
    notifications: "unavailable",
    preview: "unavailable",
    quiet: "unavailable",
  };
  private subs = new Set<(s: EngineState) => void>();
  private seq = 1000;
  private local = 0;
  private blobs = new Map<string, Blob>();
  private urls = new Map<string, string>();

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
    const list = this.state.conversations.map((c) => (c.id === id ? fn(c) : c));
    list.sort((a, b) => b.lastTs - a.lastTs);
    this.set({ conversations: list });
  }
  private conv(id: string): ConversationView {
    const c = this.state.conversations.find((x) => x.id === id);
    if (!c) this.fail("unknown conversation");
    return c;
  }
  private msg(p: Partial<MessageView> & Pick<MessageView, "kind">): MessageView {
    const me = this.state.me!;
    const mine = p.mine ?? p.fromHandle === me.handle;
    const seq = p.seq ?? ++this.seq;
    return {
      key: p.key ?? `tag-${seq}-${Math.random().toString(16).slice(2)}`,
      seq,
      from: p.kind === "system" ? "" : mine ? me.uid : `uid-${p.fromHandle}`,
      fromHandle: p.kind === "system" ? "" : (p.fromHandle ?? me.handle),
      mine,
      ts: p.ts ?? Date.now(),
      kind: p.kind,
      text: p.text,
      image: p.image,
      status: p.status ?? "sent",
      reactions: p.reactions ?? [],
    };
  }

  // ---- seed data ----
  private signIn(handle: string) {
    const me = { uid: `uid-${handle}`, handle, fingerprint: fakeFingerprint(handle) };
    this.set({
      me,
      phase: "ready",
      progress: "",
      connected: true,
      syncing: false,
      head: { seq: 1093, h: "q2Vh3…" },
    });
    const now = Date.now();
    const m = (p: Partial<MessageView> & Pick<MessageView, "kind">) => this.msg(p);
    const dm: ConversationView = {
      id: randomId(),
      ref: mockRef("dm"),
      name: "bob",
      members: [member(handle), member("bob")],
      epoch: 0,
      canSend: true,
      blocked: "",
      frozen: false,
      request: false,
      byContact: true,
      lastTs: now - 2 * MIN,
      unread: 0,
      messages: [
        m({ kind: "system", text: `${handle} started a conversation with bob`, ts: now - 2 * DAY }),
        m({
          kind: "text",
          fromHandle: "bob",
          text: "hey, are you around?",
          ts: now - 2 * DAY + MIN,
        }),
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
    };
    const group: ConversationView = {
      id: randomId(),
      ref: mockRef("group"),
      name: "project 夜明け",
      members: [member(handle), member("bob"), member("carol"), member("dave", true)],
      epoch: 3,
      canSend: true,
      blocked: "",
      frozen: false,
      request: false,
      byContact: true,
      lastTs: now - 9 * MIN,
      unread: 3,
      messages: [
        m({ kind: "system", text: `${handle} created "project 夜明け"`, ts: now - 3 * DAY }),
        m({ kind: "system", text: `${handle} added bob, carol, dave`, ts: now - 3 * DAY }),
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
        m({ kind: "text", fromHandle: "carol", text: "shipping friday?", ts: now - 9 * MIN }),
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
    };
    const removed: ConversationView = {
      id: randomId(),
      ref: mockRef("removed"),
      name: "old team",
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
        m({ kind: "system", text: `erin removed ${handle}`, ts: now - 6 * DAY }),
      ],
    };
    const old: ConversationView = {
      id: randomId(),
      ref: mockRef("old"),
      name: "carol",
      members: [member(handle), member("carol")],
      epoch: 0,
      canSend: true,
      blocked: "",
      frozen: false,
      request: false,
      byContact: true,
      lastTs: now - 40 * DAY,
      unread: 0,
      messages: [m({ kind: "text", fromHandle: "carol", text: "ping", ts: now - 40 * DAY })],
    };
    const pending: ConversationView = {
      id: randomId(),
      ref: mockRef("pending"),
      name: "# release",
      members: [member(handle), member("bob"), member("erin")],
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
    };
    const frozen: ConversationView = {
      id: randomId(),
      ref: mockRef("frozen"),
      name: "# infra",
      members: [member(handle), member("dave"), member("mallory")],
      epoch: 4,
      canSend: false,
      blocked: "frozen",
      frozen: true,
      request: false,
      byContact: true,
      lastTs: now - 3 * HOUR,
      unread: 0,
      messages: [m({ kind: "system", text: "@mallory removed @dave", ts: now - 3 * HOUR })],
    };
    const request: ConversationView = {
      id: randomId(),
      ref: mockRef("request"),
      name: "zed",
      members: [member(handle), member("zed")],
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
    };
    // A group request: only its inviter is resolved, the other members stay `?…` until accepted (§11.5).
    const groupRequest: ConversationView = {
      id: randomId(),
      ref: mockRef("groupRequest"),
      name: "# deals",
      members: [member("quinn"), member(handle), member("?Xk3f9QaZ")],
      epoch: 0,
      canSend: true,
      blocked: "",
      frozen: false,
      request: true,
      byContact: false,
      lastTs: now - 4 * HOUR,
      unread: 2,
      messages: [
        m({ kind: "system", text: "@quinn started the conversation", ts: now - 4 * HOUR - MIN }),
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
    };
    const left: ConversationView = {
      id: randomId(),
      ref: mockRef("left"),
      name: "# book club",
      members: [member(handle, true), member("erin"), member("grace")],
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
    };
    const list = [dm, group, removed, old, pending, frozen, request, groupRequest, left].sort(
      (a, b) => b.lastTs - a.lastTs,
    );
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
      conversations: [],
      connected: false,
      warnings: [],
      error: "",
      progress: "",
    });
  }

  // ---- conversations ----
  async createConversation(handles: string[], name?: string): Promise<string> {
    const me = this.state.me;
    if (!me) this.fail("not signed in");
    for (const h of handles) {
      if (!HANDLE_RE.test(h)) this.fail(`invalid handle: ${h}`);
      if (h === "nobody") this.fail(`unknown handle: ${h}`);
    }
    this.set({ progress: "creating conversation…" });
    await sleep(400);
    const now = Date.now();
    const c: ConversationView = {
      id: randomId(),
      ref: randomId(9),
      name: name || handles.join(", "),
      members: [member(me.handle), ...handles.map((h) => member(h))],
      epoch: 0,
      canSend: true,
      blocked: "",
      frozen: false,
      request: false,
      byContact: true,
      lastTs: now,
      unread: 0,
      messages: [],
    };
    c.messages.push(
      this.msg({ kind: "system", text: `${me.handle} added ${handles.join(", ")}`, ts: now }),
    );
    this.set({ conversations: [c, ...this.state.conversations], progress: "" });
    return c.id;
  }

  private pushMessage(convId: string, m: MessageView, bumpUnread = false) {
    this.updateConv(convId, (c) => ({
      ...c,
      messages: [...c.messages, m],
      lastTs: Math.max(c.lastTs, m.ts),
      unread: c.unread + (bumpUnread ? 1 : 0),
    }));
  }
  private settle(convId: string, key: string, status: "sent" | "failed") {
    const seq = status === "sent" ? ++this.seq : 0;
    this.updateConv(convId, (c) => ({
      ...c,
      messages: c.messages.map((x) =>
        x.key === key ? { ...x, status, seq, key: status === "sent" ? `tag-${seq}` : key } : x,
      ),
    }));
  }

  async sendText(convId: string, text: string): Promise<void> {
    const c = this.conv(convId);
    if (!c.canSend) this.fail(blockedMessage(c));
    const key = `local:${++this.local}`;
    this.pushMessage(
      convId,
      this.msg({ kind: "text", text, mine: true, status: "sending", seq: 0, key }),
    );
    await sleep(500);
    const failed = /\bfail\b/i.test(text);
    this.settle(convId, key, failed ? "failed" : "sent");
    if (failed) return;
    const other = c.members.find((m) => m.uid !== this.state.me?.uid && !m.left);
    if (other) {
      setTimeout(() => this.incoming(convId, other.handle, `echo: ${text}`), 1200);
    }
  }

  async sendImage(convId: string, file: File): Promise<void> {
    const c = this.conv(convId);
    if (!c.canSend) this.fail(blockedMessage(c));
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
      this.msg({ kind: "image", image, mine: true, status: "sending", seq: 0, key }),
    );
    await sleep(700);
    this.settle(convId, key, "sent");
  }

  async addMembers(convId: string, handles: string[]): Promise<void> {
    const me = this.state.me!;
    for (const h of handles) if (!HANDLE_RE.test(h)) this.fail(`invalid handle: ${h}`);
    await sleep(300);
    this.updateConv(convId, (c) => ({
      ...c,
      epoch: c.epoch + 1,
      members: [
        ...c.members,
        ...handles.filter((h) => !c.members.some((m) => m.handle === h)).map((h) => member(h)),
      ],
    }));
    this.pushMessage(
      convId,
      this.msg({ kind: "system", text: `${me.handle} added ${handles.join(", ")}` }),
    );
  }
  async removeMember(convId: string, uid: string): Promise<void> {
    const me = this.state.me!;
    const c = this.conv(convId);
    const who = c.members.find((m) => m.uid === uid);
    if (!who) this.fail("not a member");
    await sleep(300);
    this.updateConv(convId, (x) => ({
      ...x,
      epoch: x.epoch + 1,
      members: x.members.filter((m) => m.uid !== uid),
    }));
    this.pushMessage(
      convId,
      this.msg({ kind: "system", text: `${me.handle} removed ${who.handle}` }),
    );
  }
  async leave(convId: string): Promise<void> {
    await sleep(300);
    this.pushMessage(
      convId,
      this.msg({ kind: "leave", fromHandle: this.state.me!.handle, mine: true }),
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

  markRead(convId: string): void {
    // The pane is open: it accepts nothing (§11.11).
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
  clearError(): void {
    if (this.state.error) this.set({ error: "" });
  }

  // ---- test hooks ----
  incoming(convId: string, fromHandle: string, text: string) {
    this.pushMessage(convId, this.msg({ kind: "text", fromHandle, text, mine: false }), true);
  }
  incomingAt(index: number, text: string) {
    const c = this.state.conversations[index];
    const other = c?.members.find((m) => m.uid !== this.state.me?.uid);
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
