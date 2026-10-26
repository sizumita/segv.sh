/**
 * Runs the REAL client engine (src/client/engine.ts) in Node against an in-memory fake of the segv.sh Worker.
 *
 * The fake mirrors the server rules the engine depends on (docs/PROTOCOL.md §4–5, src/server/*):
 *  - a hash-chained, append-only log; batches are atomic; UNIQUE(tag) across every kind -> HTTP 409
 *  - POST /api/append: kinds 3|4, 16-byte tags, exact body lengths, 1..40 rows, distinct tags,
 *    at most ONE kind-4 row per batch (a message, or a claim/decoy followed by invites)
 *  - GET /api/log pages stop at a 4 MiB body budget (always >= 1 row), so short pages are normal
 *  - POST /api/register, POST /api/wraps, GET /api/wraps/:id[?uid=], GET /api/users/:handle,
 *    PUT/GET /api/blob/:id, GET /api/params (PoW difficulty 0; the nonce is not checked)
 *  - the WebSocket feed broadcasts every committed batch as one frame to every socket
 *
 * Browser globals the engine touches (fetch, WebSocket, location, localStorage, indexedDB) are replaced by
 * fakes bound to the *current* FakeServer. `freshWorldPerTest()` gives every test its own server + storage and
 * signs out every engine afterwards (stops feeds and poll timers).
 */
import { afterEach, beforeEach } from "vite-plus/test";
import { x25519 } from "@noble/curves/ed25519.js";
import * as P from "../../src/lib/proto";
import { SegvEngine } from "../../src/client/engine";
import type { ConversationView, MessageView } from "../../src/client/types";

export { P, SegvEngine };

export const PAGE_BODY_BUDGET = 4 * 1024 * 1024;
export const BATCH_MAX = 40;

export interface WireRow {
  seq: number;
  kind: number;
  tag: string;
  body: string;
  ts: number;
  h: string;
}

interface StoredRow extends WireRow {
  bodyLen: number;
}

export type FailMode = "before" | "after" | null | undefined;

interface Res {
  status: number;
  json?: unknown;
  bytes?: Uint8Array;
}

const json = (status: number, j: unknown): Res => ({ status, json: j });

// ───────────────────────── fake Worker ─────────────────────────

export class FakeServer {
  rows: StoredRow[] = [];
  head: { seq: number; h: Uint8Array } = { seq: 0, h: P.ZERO32 };
  private tagSet = new Set<string>();
  handles = new Map<string, string>(); // handle -> uid (b64u)
  users = new Map<string, { user: P.User; seq: number }>(); // uid -> verified bundle
  wraps: { seq: number; id: string; uid: string; record: string; sig: string }[] = [];
  blobs = new Map<string, Uint8Array>();
  /** Every committed batch (kinds in order), for shape assertions. */
  batches: { seqs: number[]; kinds: number[] }[] = [];
  sockets = new Set<FakeWebSocket>();
  /** Every request with its response status (0 = network failure before the server). */
  requests: { method: string; path: string; status: number }[] = [];
  /** false: sockets never open (the engine then only learns rows by fetching the log). */
  wsEnabled = true;
  hooks: {
    /** Runs before an /api/append batch is committed. May await (to hold a request) or commit other rows first. */
    beforeAppend?: (rows: P.Row[]) => void | Promise<void>;
    /** Network failure for one request: 'before' = never reached the server, 'after' = committed, response lost. */
    fail?: (method: string, path: string) => FailMode;
    /** Runs before any request is handled (may await to hold it). */
    beforeRequest?: (method: string, path: string) => void | Promise<void>;
  } = {};

  // ── log ──

  hasTag(tag: Uint8Array | string): boolean {
    return this.tagSet.has(typeof tag === "string" ? tag : P.b64u(tag));
  }

  /** Commits rows atomically WITHOUT request validation (UNIQUE(tag) still applies). null on a tag conflict. */
  commit(rows: P.Row[]): WireRow[] | null {
    const seen = new Set<string>();
    for (const r of rows) {
      const k = P.b64u(r.tag);
      if (seen.has(k) || this.tagSet.has(k)) return null;
      seen.add(k);
    }
    const ts = Math.floor(Date.now() / 1000) * 1000;
    const out: WireRow[] = [];
    for (const r of rows) {
      const seq = this.head.seq + 1;
      const h = P.rowHash(this.head.h, seq, r.kind, r.tag, r.body, ts);
      this.head = { seq, h };
      this.tagSet.add(P.b64u(r.tag));
      const w: StoredRow = {
        seq,
        kind: r.kind,
        tag: P.b64u(r.tag),
        body: P.b64u(r.body),
        ts,
        h: P.b64u(h),
        bodyLen: r.body.length,
      };
      this.rows.push(w);
      out.push(strip(w));
    }
    this.batches.push({ seqs: out.map((w) => w.seq), kinds: rows.map((r) => r.kind) });
    const frame = JSON.stringify({ type: "rows", rows: out });
    for (const ws of this.sockets) setTimeout(() => ws.deliver(frame), 0);
    return out;
  }

  /** The Worker's /api/append request rules. Returns an error message, or null when the batch is acceptable. */
  static checkAppend(rows: P.Row[]): string | null {
    if (rows.length < 1 || rows.length > BATCH_MAX) return `expected 1..${BATCH_MAX} rows`;
    const tags = new Set<string>();
    let kind4 = 0;
    for (const r of rows) {
      if (r.kind !== 3 && r.kind !== 4) return "kind must be 3 or 4";
      if (r.tag.length !== 16) return "tag must be 16 bytes";
      const lens: readonly number[] = r.kind === 3 ? P.INV_BODY_LENS : P.MSG_BODY_LENS;
      if (!lens.includes(r.body.length)) return `bad body length for kind ${r.kind}`;
      const t = P.b64u(r.tag);
      if (tags.has(t)) return "duplicate tag in batch";
      tags.add(t);
      if (r.kind === 4) kind4++;
    }
    if (kind4 > 1) return "at most one kind-4 row per batch";
    return null;
  }

  /** What an anonymous POST /api/append would do (validation + UNIQUE), without HTTP. Used by attackers in tests. */
  append(rows: P.Row[]): { status: 200; seqs: number[] } | { status: 400 | 409; error: string } {
    const err = FakeServer.checkAppend(rows);
    if (err) return { status: 400, error: err };
    const w = this.commit(rows);
    if (!w) return { status: 409, error: "tag already used" };
    return { status: 200, seqs: w.map((x) => x.seq) };
  }

  /** Like append() but throws unless the server accepted the batch. */
  mustAppend(rows: P.Row[]): number[] {
    const r = this.append(rows);
    if (r.status !== 200) throw new Error(`append rejected: ${r.status} ${r.error}`);
    return r.seqs;
  }

  since(after: number, limit: number): { rows: WireRow[]; head: { seq: number; h: string } } {
    const out: WireRow[] = [];
    let bytes = 0;
    for (const r of this.rows) {
      if (r.seq <= after) continue;
      if (out.length >= limit) break;
      if (out.length > 0 && bytes + r.bodyLen > PAGE_BODY_BUDGET) break;
      bytes += r.bodyLen;
      out.push(strip(r));
    }
    return { rows: out, head: { seq: this.head.seq, h: P.b64u(this.head.h) } };
  }

  // ── accounts ──

  register(body: { bundle: string; sig: string; wraps: { record: string; sig: string }[] }): Res {
    let u: P.User;
    try {
      u = P.verifyBundle(body.bundle, body.sig);
      P.checkUserKeys(u);
    } catch (e) {
      return json(400, { error: String(e) });
    }
    if (!Array.isArray(body.wraps) || body.wraps.length < 1)
      return json(400, { error: "wraps required" });
    const recs: P.WrapRecord[] = [];
    for (const w of body.wraps) {
      try {
        const rec = P.verifyWrap(w.record, w.sig, u.sigPk);
        if (rec.uid !== u.uid) return json(400, { error: "wrap uid does not match the bundle" });
        recs.push(rec);
      } catch (e) {
        return json(400, { error: String(e) });
      }
    }
    if (this.handles.has(u.handle) || this.users.has(u.uid))
      return json(409, { error: "handle already taken" });
    const rows: P.Row[] = [
      {
        kind: 1,
        tag: P.userTag(P.fromB64u(u.uid)),
        body: P.utf8(JSON.stringify({ bundle: body.bundle, sig: body.sig })),
      },
      ...recs.map((r) => ({
        kind: 2,
        tag: P.wrapTag(r.record),
        body: P.utf8(JSON.stringify({ record: r.record, sig: r.sig })),
      })),
    ];
    const w = this.commit(rows);
    if (!w) return json(409, { error: "tag already used" });
    this.handles.set(u.handle, u.uid);
    this.users.set(u.uid, { user: u, seq: w[0].seq });
    recs.forEach((r, i) =>
      this.wraps.push({
        seq: w[i + 1].seq,
        id: P.b64u(r.id),
        uid: r.uid,
        record: r.record,
        sig: r.sig,
      }),
    );
    return json(200, { seq: w[0].seq });
  }

  postWrap(body: { record: string; sig: string }): Res {
    let rec: P.WrapRecord;
    try {
      rec = P.parseWrap(body.record, body.sig);
    } catch (e) {
      return json(400, { error: String(e) });
    }
    const owner = this.users.get(rec.uid);
    if (!owner) return json(404, { error: "unknown uid" });
    try {
      P.verifyWrap(body.record, body.sig, owner.user.sigPk); // the Worker only checks the filer's own signature
    } catch {
      return json(400, { error: "bad wrap signature" });
    }
    const w = this.commit([
      { kind: 2, tag: P.wrapTag(body.record), body: P.utf8(JSON.stringify(body)) },
    ]);
    if (!w) return json(409, { error: "tag already used" });
    this.wraps.push({
      seq: w[0].seq,
      id: P.b64u(rec.id),
      uid: rec.uid,
      record: body.record,
      sig: body.sig,
    });
    return json(200, { seq: w[0].seq });
  }

  user(uid: string): P.User {
    const u = this.users.get(uid);
    if (!u) throw new Error(`unknown uid ${uid}`);
    return u.user;
  }

  // ── HTTP ──

  async fetch(input: unknown, init: RequestInit = {}): Promise<Response> {
    const url = new URL(String(input), "http://segv.test/");
    const method = (init.method ?? "GET").toUpperCase();
    const entry = { method, path: url.pathname, status: 0 };
    this.requests.push(entry);
    const fail = this.hooks.fail?.(method, url.pathname);
    if (fail === "before") throw new TypeError("Failed to fetch");
    await this.hooks.beforeRequest?.(method, url.pathname);
    await Promise.resolve();
    const r = await this.route(method, url, init.body);
    entry.status = r.status;
    if (fail === "after") throw new TypeError("Failed to fetch (response lost after commit)");
    if (r.bytes)
      return new Response(r.bytes as BodyInit, {
        status: r.status,
        headers: { "content-type": "application/octet-stream" },
      });
    return new Response(JSON.stringify(r.json ?? {}), {
      status: r.status,
      headers: { "content-type": "application/json" },
    });
  }

  private async route(method: string, url: URL, rawBody: unknown): Promise<Res> {
    const p = url.pathname;
    const body = () =>
      JSON.parse(
        typeof rawBody === "string" ? rawBody : new TextDecoder().decode(rawBody as Uint8Array),
      ) as never;
    if (p === "/api/params" && method === "GET") {
      const now = Date.now();
      return json(200, {
        now,
        window: Math.floor(now / P.POW_WINDOW_MS),
        pow: { register: 0, wrap: 0, append: 0, blob: 0 },
        limits: { batch: BATCH_MAX, blobMax: P.BLOB_MAX },
      });
    }
    if (p === "/api/log" && method === "GET") {
      const after = Number(url.searchParams.get("after") ?? 0);
      const limit = Number(url.searchParams.get("limit") ?? 1000);
      if (
        !Number.isSafeInteger(after) ||
        after < 0 ||
        !Number.isSafeInteger(limit) ||
        limit < 1 ||
        limit > 1000
      )
        return json(400, { error: "bad query" });
      return json(200, this.since(after, limit));
    }
    if (p === "/api/append" && method === "POST") {
      let rows: P.Row[];
      try {
        const b = body() as { rows: { kind: number; tag: string; body: string }[] };
        rows = b.rows.map((r) => ({
          kind: r.kind,
          tag: P.fromB64u(r.tag),
          body: P.fromB64u(r.body),
        }));
      } catch {
        return json(400, { error: "bad body" });
      }
      const err = FakeServer.checkAppend(rows);
      if (err) return json(400, { error: err });
      if (this.hooks.beforeAppend) await this.hooks.beforeAppend(rows);
      const w = this.commit(rows);
      if (!w) return json(409, { error: "tag already used" });
      return json(200, { seqs: w.map((x) => x.seq) });
    }
    if (p === "/api/register" && method === "POST") return this.register(body());
    if (p === "/api/wraps" && method === "POST") return this.postWrap(body());
    let m = /^\/api\/wraps\/([A-Za-z0-9_-]+)$/.exec(p);
    if (m && method === "GET") {
      const uid = url.searchParams.get("uid");
      const ws = this.wraps
        .filter((w) => w.id === m![1] && (uid === null || w.uid === uid))
        .slice(0, 64); // oldest first
      return json(200, {
        wraps: ws.map(({ seq, uid: u, record, sig }) => ({ seq, uid: u, record, sig })),
      });
    }
    m = /^\/api\/users\/([^/]+)$/.exec(p);
    if (m && method === "GET") {
      const handle = decodeURIComponent(m[1]);
      const uid = this.handles.get(handle);
      if (!uid) return json(404, { error: "no such user" });
      const u = this.users.get(uid)!;
      return json(200, { uid, handle, bundle: u.user.bundle, sig: u.user.bundleSig, seq: u.seq });
    }
    m = /^\/api\/blob\/([A-Za-z0-9_-]{43})$/.exec(p);
    if (m && method === "PUT") {
      const bytes = new Uint8Array(rawBody as Uint8Array);
      if (P.b64u(P.H(bytes)) !== m[1]) return json(400, { error: "id does not match the content" });
      if (bytes.length > P.BLOB_MAX) return json(413, { error: "too large" });
      this.blobs.set(m[1], bytes);
      return json(201, {});
    }
    if (m && method === "GET") {
      const b = this.blobs.get(m[1]);
      return b ? { status: 200, bytes: b } : json(404, { error: "no such blob" });
    }
    return json(404, { error: `not found: ${method} ${p}` });
  }
}

const strip = ({ bodyLen: _bodyLen, ...w }: StoredRow): WireRow => w;

// ───────────────────────── browser globals ─────────────────────────

let current = new FakeServer();
/** The FakeServer every global (fetch, WebSocket) is currently bound to. */
export const server = (): FakeServer => current;

export class FakeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  readyState = 0;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  private readonly srv: FakeServer;
  constructor(_url: string | URL) {
    this.srv = current;
    this.srv.sockets.add(this);
    setTimeout(() => {
      if (this.readyState !== 0 || !this.srv.wsEnabled) return;
      this.readyState = 1;
      this.onopen?.();
    }, 0);
  }
  deliver(data: string) {
    if (this.readyState === 1) this.onmessage?.({ data });
  }
  send(_data: string) {}
  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.srv.sockets.delete(this);
    setTimeout(() => this.onclose?.(), 0);
  }
}

const storage = new Map<string, string>();
const g = globalThis as Record<string, unknown>;
g.localStorage = {
  getItem: (k: string) => (storage.has(k) ? storage.get(k)! : null),
  setItem: (k: string, v: string) => void storage.set(k, String(v)),
  removeItem: (k: string) => void storage.delete(k),
  clear: () => storage.clear(),
  key: (i: number) => [...storage.keys()][i] ?? null,
  get length() {
    return storage.size;
  },
};
g.location = {
  href: "http://segv.test/",
  origin: "http://segv.test",
  protocol: "http:",
  hostname: "segv.test",
  host: "segv.test",
};
g.WebSocket = FakeWebSocket;
g.fetch = (input: unknown, init?: RequestInit) => current.fetch(input, init);
// No IndexedDB: "remember this device" fails and clearSession() is a no-op, as in a private window.
g.indexedDB = {
  open() {
    const req: { error?: Error; onerror?: () => void } = {};
    setTimeout(() => {
      req.error = new Error("indexedDB unavailable");
      req.onerror?.();
    }, 0);
    return req;
  },
};

export const localStore = storage;

// ───────────────────────── engine lifecycle ─────────────────────────

const engines: SegvEngine[] = [];

/** A new engine that is signed out (and its timers stopped) after the test. */
export function newEngine(): SegvEngine {
  const e = new SegvEngine();
  engines.push(e);
  return e;
}

/** Fresh FakeServer + empty localStorage for every test; every engine is signed out afterwards. */
export function freshWorldPerTest() {
  beforeEach(() => {
    current = new FakeServer();
    storage.clear();
  });
  afterEach(async () => {
    for (const e of engines.splice(0)) {
      try {
        await e.logout();
      } catch {
        /* ignore */
      }
    }
  });
}

// ───────────────────────── engine internals (white-box access) ─────────────────────────

export interface EpochI {
  e: number;
  EK: Uint8Array;
  keys: P.EpochKeys;
  dText: string;
  d: P.Descriptor;
  members: string[];
  myIndex: number;
  maxN: number[];
  seen: Set<number>[];
  registered: number[];
  claim: { seq: number; dText: string; d: P.Descriptor; dsig: Uint8Array } | null;
  frozen: boolean;
  left: Set<string>;
}

export interface ConvI {
  id: string;
  conv: Uint8Array;
  epochs: Map<number, EpochI>;
  current: number;
  messages: MessageView[];
  unread: number;
  lastTs: number;
  removed: boolean;
  left: boolean;
}

export interface EngineI {
  account: { uid: Uint8Array; uidB: string; AK: Uint8Array; id: P.Identity; handle: string } | null;
  convs: Map<string, ConvI>;
  tags: Map<string, { type: "msg" | "claim"; c: ConvI; ep: EpochI; i?: number; n?: number }>;
  head: { seq: number; h: Uint8Array };
  queue: Promise<unknown>;
  sendChains: Map<string, Promise<unknown>>;
  imageCache: Map<string, Promise<string>>;
  pending: Map<string, string>;
  fatal: boolean;
  generation: number;
  unlock(AK: Uint8Array, uid: Uint8Array, handle: string): Promise<void>;
  views(): ConversationView[];
  syncNow(): Promise<void>;
}

/** White-box view of an engine's private state. */
export const I = (e: SegvEngine): EngineI => e as unknown as EngineI;

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export async function waitFor(cond: () => boolean, what = "condition", ms = 20_000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(5);
  }
}

/**
 * Waits until every given engine has drained its row queue and send chains and has applied the whole log.
 * Engines that are signed out or fatal are skipped.
 */
export async function settle(...es: SegvEngine[]): Promise<void> {
  const end = Date.now() + 30_000;
  for (let round = 0; ; round++) {
    await sleep(round < 2 ? 2 : 10);
    for (const e of es) {
      const x = I(e);
      await x.queue.catch(() => {});
      for (const p of x.sendChains.values()) await p.catch(() => {});
    }
    const behind = es.filter((e) => {
      const x = I(e);
      return x.account && !x.fatal && (x.head.seq < current.head.seq || e.getState().syncing);
    });
    if (behind.length === 0 && round >= 2) return;
    if (round > 0 && round % 20 === 0)
      for (const e of behind)
        void I(e)
          .syncNow()
          .catch(() => {});
    if (Date.now() > end) throw new Error("settle: timed out");
  }
}

// ───────────────────────── users ─────────────────────────

export interface TestUser {
  handle: string;
  AK: Uint8Array;
  uid: Uint8Array;
  uidB: string;
  id: P.Identity;
  code: Uint8Array;
  rk: P.UnlockKey & { id: Uint8Array };
}

/** Registers a user directly on the current server (bundle + recovery wrap), like POST /api/register. */
export function makeUser(handle: string): TestUser {
  const AK = P.random(32);
  const uid = P.random(16);
  const id = P.deriveIdentity(AK);
  const code = P.newRecoveryCode();
  const rk = P.recoveryKem(code);
  const { bundle, sig } = P.makeBundle(uid, handle, id, Date.now());
  const wrap = P.makeWrap(uid, "recovery", rk.id, rk, AK, id, Date.now());
  const r = current.register({ bundle, sig, wraps: [wrap] });
  if (r.status !== 200) throw new Error(`register ${handle} failed: ${JSON.stringify(r.json)}`);
  return { handle, AK, uid, uidB: P.b64u(uid), id, code, rk };
}

/** An engine unlocked for `u` (the state right after a passkey / recovery unlock) that finished its first sync. */
export async function engineFor(u: TestUser): Promise<SegvEngine> {
  const e = newEngine();
  await I(e).unlock(u.AK, u.uid, u.handle);
  await waitFor(
    () => !e.getState().syncing || e.getState().phase === "fatal",
    `${u.handle} initial sync`,
  );
  await settle(e);
  return e;
}

// ───────────────────────── views ─────────────────────────

export const view = (e: SegvEngine, convId: string): ConversationView | undefined =>
  I(e)
    .views()
    .find((c) => c.id === convId);

export function mustView(e: SegvEngine, convId: string): ConversationView {
  const v = view(e, convId);
  if (!v) throw new Error("conversation not found in view");
  return v;
}

/** Non-system messages as "handle: text" (status appended unless 'sent'). */
export const chat = (e: SegvEngine, convId: string): string[] =>
  (view(e, convId)?.messages ?? [])
    .filter((m) => m.kind !== "system")
    .map(
      (m) =>
        `${m.fromHandle}: ${m.kind === "image" ? "[image]" : m.text}${m.status === "sent" ? "" : ` (${m.status})`}`,
    );

export const systemLines = (e: SegvEngine, convId: string): string[] =>
  (view(e, convId)?.messages ?? []).filter((m) => m.kind === "system").map((m) => m.text ?? "");

export const conv = (e: SegvEngine, convId: string): ConvI => {
  const c = I(e).convs.get(convId);
  if (!c) throw new Error("engine does not hold this conversation");
  return c;
};
export const epoch = (e: SegvEngine, convId: string, n?: number): EpochI => {
  const c = conv(e, convId);
  const ep = c.epochs.get(n ?? c.current);
  if (!ep) throw new Error(`engine does not hold epoch ${n}`);
  return ep;
};

// ───────────────────────── protocol constructs (honest and malicious) ─────────────────────────

/** One invite per uid, in the given order (rows exactly as the engine builds them). */
export function invitesFor(
  uids: string[],
  dText: string,
  EK: Uint8Array,
  dsig: Uint8Array,
): P.Row[] {
  return uids.map((u) => P.makeInvite(current.user(u), dText, EK, dsig));
}

/** A descriptor signed by `by` with arbitrary fields (e, prev, members): the raw material of a forged epoch. */
export function signEpoch(o: {
  conv: string;
  e: number;
  members: string[];
  by: TestUser;
  prev: string | null;
  name?: string;
}) {
  const EK = P.random(32);
  const keys = P.epochKeys(EK, P.fromB64u(o.conv), o.e);
  const dText = P.makeDescriptor({
    conv: o.conv,
    e: o.e,
    members: o.members,
    prev: o.prev,
    by: o.by.uidB,
    ts: Date.now(),
    ...(o.name !== undefined ? { name: o.name } : {}),
  });
  const dsig = P.signDescriptor(dText, keys.kc, o.by.id.sigSk);
  return { EK, keys, dText, dsig };
}

/** A well-formed membership change of `ep` (claim + invites) committed by `by`, exactly like changeMembers(). */
export function buildChange(
  by: TestUser,
  convId: string,
  ep: EpochI,
  members: string[],
  name?: string | null,
) {
  const nm = name === null ? undefined : (name ?? ep.d.name);
  const s = signEpoch({
    conv: convId,
    e: ep.e + 1,
    members,
    by,
    prev: P.b64u(P.H(P.utf8(ep.dText))),
    name: nm,
  });
  const claim = P.makeClaim(ep.keys.mk, ep.keys.rk, s.dText, s.dsig, by.id.sigSk);
  return { ...s, claim, rows: [claim, ...invitesFor(members, s.dText, s.EK, s.dsig)] };
}

/** A signed message row exactly as sendPayload() builds it. */
export function buildMessage(
  from: TestUser,
  convId: string,
  ep: EpochI,
  n: number,
  partial: {
    t?: "text" | "leave" | "image";
    text?: string;
    img?: P.ImageRef;
    head?: { seq: number; h: string };
  } = {},
): P.Row {
  const i = ep.members.indexOf(from.uidB);
  if (i < 0) throw new Error("sender is not in this epoch");
  const tag = P.msgTag(ep.keys.rk, i, n);
  const payload: P.Payload = {
    v: 1,
    t: partial.t ?? "text",
    conv: convId,
    e: ep.e,
    from: from.uidB,
    n,
    ts: Date.now(),
    ...(partial.text !== undefined ? { text: partial.text } : {}),
    ...(partial.img ? { img: partial.img } : {}),
    head: partial.head ?? { seq: 0, h: P.b64u(P.ZERO32) },
  };
  return P.makeMessage(ep.keys.mk, tag, payload, from.id.sigSk);
}

/** A kind-3 row whose check tag is valid for `to` (so it passes the scan) but whose body is garbage. */
export function junkInvite(to: { scanPk: Uint8Array }): P.Row {
  const ephSk = x25519.utils.randomSecretKey();
  const eph = x25519.getPublicKey(ephSk);
  const s = x25519.getSharedSecret(ephSk, to.scanPk);
  const vk = P.HKDF(s, P.concat(eph, to.scanPk), "segv.sh/v1/inv/view");
  const check = P.trunc16(P.HMAC(vk, P.utf8("check")));
  return { kind: 3, tag: check, body: P.concat(eph, P.random(P.INV_BODY_LENS[0] - 32)) };
}

/** Random kind-4 row of a legal size (what an outsider or a squatter can post). */
export const junkMessageRow = (tag: Uint8Array = P.random(16), cls = 0): P.Row => ({
  kind: 4,
  tag,
  body: P.random(P.MSG_BODY_LENS[cls]),
});
/** Random kind-3 row of a legal size. */
export const junkInviteRow = (tag: Uint8Array = P.random(16)): P.Row => ({
  kind: 3,
  tag,
  body: P.random(P.INV_BODY_LENS[0]),
});

/** Every kind-4 row in the log that opens as a message under `mk` (what a holder of that key can read). */
export function readableWith(mk: Uint8Array): { seq: number; payload: P.Payload; text: string }[] {
  const out: { seq: number; payload: P.Payload; text: string }[] = [];
  for (const r of current.rows) {
    if (r.kind !== 4) continue;
    try {
      const o = P.openMessage(mk, { tag: P.fromB64u(r.tag), body: P.fromB64u(r.body) });
      out.push({ seq: r.seq, payload: o.payload, text: o.text });
    } catch {
      /* not under this key */
    }
  }
  return out;
}

/** The users (by handle) an invite row is addressed to, by trial scanning with each user's scan key. */
export function inviteRecipients(row: { tag: string; body: string }, users: TestUser[]): string[] {
  const r = { tag: P.fromB64u(row.tag), body: P.fromB64u(row.body) };
  return users
    .filter((u) => P.inviteViewKey(u.id.scanSk, u.id.scanPk, r) !== null)
    .map((u) => u.handle);
}
