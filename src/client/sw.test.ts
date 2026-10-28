// The push Service Worker (src/client/sw-core.ts; docs/PROTOCOL.md §11.13): reading a push, the notifications of each
// preview from real rows, and the worker's events against a minimal worker-like `self`.
import { describe, expect, it } from "vite-plus/test";
import * as P from "~/lib/proto";
import type * as W from "~/lib/wire";
import type { CacheCopy, Move, NotifyCache } from "./notify-cache";
import {
  bellsOf,
  install,
  notesFor,
  proposedOf,
  type Note,
  type Proposed,
  type SwDeps,
  type SwScope,
} from "./sw-core";

const ORIGIN = "https://segv.test";
const E = 60;
const NOW = P.eraStart(E) + 3_600_000;
const tSec = Math.floor((NOW - P.T0_MS) / 1000);

/** One conversation: self (lane 0, "alice"), bob (1) and carol (2), in epoch 3. */
function makeConv(name = "# g") {
  const conv = P.random(16);
  const e = 3;
  const keys = P.epochKeys(P.random(32), conv, e);
  const sks = [0, 1, 2].map(() => P.random(32));
  const handles = ["alice", "bob", "carol"];
  const bell = P.b64u(P.random(16));
  const ref = P.b64u(P.random(9));
  const copy: CacheCopy = {
    bell,
    ref,
    name,
    epoch: {
      e,
      conv: P.b64u(conv),
      mk: P.b64u(keys.mk),
      rk: P.b64u(keys.rk),
      self: 0,
      members: sks.map((sk, j) => ({ sigPk: P.b64u(P.sigPub(sk)), handle: handles[j] })),
      next: [0, 1, 2].map(() => ({ E, n: 0 })),
    },
  };
  /** A row of member `j` at (E, n) (signed by `signer`, default j's own key). */
  const row = (
    j: number,
    n: number,
    body: P.MBody,
    opts: { ts?: number; signer?: number; Era?: number } = {},
  ) => {
    const Era = opts.Era ?? E;
    const msg = {
      from: j,
      lane: j,
      n,
      prev: P.NONE,
      prevh: P.ZERO16,
      ts: opts.ts ?? NOW,
      ckq: 0,
      ck16: P.ZERO16,
      ...body,
    } as P.Msg;
    const r = P.buildRow({ keys, conv, e, sigSk: sks[opts.signer ?? j] }, Era, msg);
    return { E: Era, label: r.label, cls: r.cls, body: r.body };
  };
  return { copy, row, keys, bell, ref };
}

/** A fake server holding rows, and the worker's dependencies around it. */
function world(cache: NotifyCache | null) {
  const rows = new Map<string, { t: number; cls: number; body: Uint8Array }>();
  const asked: W.GetKey[][] = [];
  const moves: Move[][] = [];
  let hang = false;
  const deps: SwDeps = {
    origin: ORIGIN,
    readCache: async () => cache,
    advance: async (m) => void moves.push(m),
    get: (keys) => {
      asked.push(keys);
      if (hang) return new Promise(() => {});
      return Promise.resolve(
        keys.map((k): W.GetStatus => {
          const r = rows.get(`${k.E}:${P.hex(k.label)}`);
          return r ? { s: "hit", t: r.t, cls: r.cls, body: r.body } : { s: "miss", sealed: false };
        }),
      );
    },
    now: () => NOW,
    // The deadline never passes unless a test says so.
    sleep: () => new Promise<void>(() => {}),
  };
  return {
    deps,
    asked,
    moves,
    hang: () => void (hang = true),
    put: (r: { E: number; label: Uint8Array; cls: number; body: Uint8Array }, t = tSec) =>
      rows.set(`${r.E}:${P.hex(r.label)}`, { t, cls: r.cls, body: r.body }),
  };
}

const proposed = (bells: string[]): Proposed => ({
  title: "segv.sh",
  body: "new messages",
  tag: "segv",
  navigate: `${ORIGIN}/`,
  bells,
});
const FIXED_NOTE: Note = {
  title: "segv.sh",
  body: "new messages",
  tag: "segv",
  navigate: `${ORIGIN}/`,
};
const later = NOW + 60_000;

describe("reading a push", () => {
  const bells = [P.random(16), P.random(16)];
  const field = P.b64u(P.concat(bells[0], new Uint8Array(16), bells[1], new Uint8Array(16)));

  it("takes the payload's notification (browsers without declarative push) or the proposed one (with it)", () => {
    const json = {
      web_push: 8030,
      mutable: true,
      notification: {
        title: "segv.sh",
        body: "new messages",
        navigate: `${ORIGIN}/`,
        tag: "segv",
        data: { bells: field },
      },
    };
    const want = { ...proposed(bells.map(P.b64u)) };
    expect(proposedOf(null, json, ORIGIN)).toEqual(want);
    expect(
      proposedOf(
        {
          title: "segv.sh",
          body: "new messages",
          navigate: `${ORIGIN}/`,
          tag: "segv",
          data: { bells: field },
        },
        null,
        ORIGIN,
      ),
    ).toEqual(want);
  });

  it("falls back to the fixed values, never navigates off the origin, and skips the zero padding", () => {
    expect(proposedOf(null, null, ORIGIN)).toEqual(proposed([]));
    expect(proposedOf(null, { web_push: 1, notification: { title: "x" } }, ORIGIN)).toEqual(
      proposed([]),
    );
    expect(
      proposedOf({ title: "", body: 7, navigate: "https://evil.test/x", data: null }, null, ORIGIN),
    ).toEqual(proposed([]));
    expect(bellsOf(P.b64u(new Uint8Array(64)))).toEqual([]);
    expect(bellsOf("!!")).toEqual([]);
    expect(bellsOf(123)).toEqual([]);
  });
});

describe("the notifications of a push (§11.13)", () => {
  it("without a cache, or without a known bell: the fixed notification", async () => {
    const a = makeConv();
    expect(await notesFor(proposed([a.bell]), world(null).deps, later)).toEqual([FIXED_NOTE]);
    const c: NotifyCache = { v: 1, preview: "name", deltaS: 10, copies: [a.copy] };
    expect(await notesFor(proposed([P.b64u(P.random(16))]), world(c).deps, later)).toEqual([
      FIXED_NOTE,
    ]);
    expect(await notesFor(proposed([]), world(c).deps, later)).toEqual([FIXED_NOTE]);
  });

  it("`name`: one notification per conversation, in the bells' order, tagged and linked by its ref, with no request", async () => {
    const a = makeConv("bob");
    const b = makeConv("# g");
    const c: NotifyCache = { v: 1, preview: "name", deltaS: 10, copies: [a.copy, b.copy] };
    const w = world(c);
    const notes = await notesFor(
      proposed([b.bell, a.bell, b.bell, P.b64u(P.random(16))]),
      w.deps,
      later,
    );
    expect(notes).toEqual([
      { title: "# g", body: "new messages", tag: b.ref, navigate: `${ORIGIN}/#c/${b.ref}` },
      { title: "bob", body: "new messages", tag: a.ref, navigate: `${ORIGIN}/#c/${a.ref}` },
    ]);
    expect(w.asked).toEqual([]);
  });

  it("`message`: reads the other lanes from their next slots, shows the newest verified text or image, and moves the lanes", async () => {
    const a = makeConv();
    const c: NotifyCache = { v: 1, preview: "message", deltaS: 10, copies: [a.copy] };
    const w = world(c);
    w.put(a.row(1, 0, { type: P.MT.TEXT, text: "hi" }, { ts: NOW - 2000 }));
    w.put(a.row(1, 1, { type: P.MT.TEXT, text: "there" }, { ts: NOW - 1000 }));
    w.put(
      a.row(
        2,
        0,
        { type: P.MT.IMAGE, image: { id: P.random(32), k: P.random(32), mime: 1, w: 10, h: 10 } },
        { ts: NOW - 1500 },
      ),
    );
    w.put(a.row(0, 0, { type: P.MT.TEXT, text: "mine" }));
    const notes = await notesFor(proposed([a.bell]), w.deps, later);
    expect(notes).toEqual([
      { title: "# g", body: "@bob: there (+2)", tag: a.ref, navigate: `${ORIGIN}/#c/${a.ref}` },
    ]);
    // Self's lane is never read; the other two get 8 slots each.
    expect(w.asked).toHaveLength(1);
    expect(w.asked[0]).toHaveLength(16);
    expect(w.asked[0].every((k) => k.mode === 0 && k.E === E)).toBe(true);
    expect(w.moves).toEqual([
      [
        {
          bell: a.bell,
          e: 3,
          next: [
            { E, n: 0 },
            { E, n: 2 },
            { E, n: 1 },
          ],
        },
      ],
    ]);
  });

  it("keeps only rows that verify: a wrong signer, a reaction and junk occupy their slots but show nothing", async () => {
    const a = makeConv();
    const c: NotifyCache = { v: 1, preview: "message", deltaS: 10, copies: [a.copy] };
    const w = world(c);
    w.put(a.row(1, 0, { type: P.MT.TEXT, text: "forged" }, { signer: 2 }));
    const target = { te: 3, tl: 2, tE: E, tn: 0, th: P.random(16), op: 1, emoji: "👍" };
    w.put(a.row(1, 1, { type: P.MT.REACTION, reaction: target } as P.MBody));
    const junk = a.row(2, 0, { type: P.MT.TEXT, text: "x" });
    w.put({ ...junk, body: P.random(junk.body.length) });
    const notes = await notesFor(proposed([a.bell]), w.deps, later);
    expect(notes).toEqual([
      { title: "# g", body: "new messages", tag: a.ref, navigate: `${ORIGIN}/#c/${a.ref}` },
    ]);
    expect(w.moves[0][0].next).toEqual([
      { E, n: 0 },
      { E, n: 2 },
      { E, n: 1 },
    ]);
  });

  it("cuts a long text to 200 characters, and reads slot 0 of the current era for a lane whose next slot is older", async () => {
    const a = makeConv();
    a.copy.epoch!.next = [
      { E, n: 0 },
      { E: E - 1, n: 4 },
      { E, n: 0 },
    ];
    const c: NotifyCache = { v: 1, preview: "message", deltaS: 10, copies: [a.copy] };
    const w = world(c);
    w.put(a.row(1, 0, { type: P.MT.TEXT, text: "あ".repeat(300) }));
    const notes = await notesFor(proposed([a.bell]), w.deps, later);
    expect(notes[0].body).toBe(`@bob: ${"あ".repeat(193)}…`);
    expect(Array.from(notes[0].body)).toHaveLength(200);
    const lane1 = w.asked[0].slice(0, 8);
    expect(lane1.slice(0, 7).every((k) => k.E === E - 1)).toBe(true);
    expect(lane1[7].E).toBe(E);
    expect(w.moves[0][0].next[1]).toEqual({ E, n: 1 });
  });

  it("a cache read that stalls past the deadline gives the fixed notification; a push without bells reads nothing", async () => {
    const a = makeConv();
    const w = world(null);
    w.deps.readCache = () => new Promise(() => {});
    w.deps.sleep = () => Promise.resolve();
    expect(await notesFor(proposed([a.bell]), w.deps, NOW)).toEqual([FIXED_NOTE]);
    let reads = 0;
    const v = world(null);
    v.deps.readCache = async () => (reads++, null);
    expect(await notesFor(proposed([]), v.deps, later)).toEqual([FIXED_NOTE]);
    expect(reads).toBe(0);
  });

  it("past the deadline, or when the read fails: the names", async () => {
    const a = makeConv("bob");
    const c: NotifyCache = { v: 1, preview: "message", deltaS: 10, copies: [a.copy] };
    const w = world(c);
    w.hang();
    w.deps.sleep = () => Promise.resolve();
    const named = [
      { title: "bob", body: "new messages", tag: a.ref, navigate: `${ORIGIN}/#c/${a.ref}` },
    ];
    expect(await notesFor(proposed([a.bell]), w.deps, NOW)).toEqual(named);
    const v = world(c);
    v.deps.get = () => Promise.reject(new Error("offline"));
    expect(await notesFor(proposed([a.bell]), v.deps, later)).toEqual(named);
  });
});

// ───────────── the worker's events ─────────────

interface Shown {
  title: string;
  opts: { body: string; tag: string; data: { navigate: string } };
}

function load(deps: Partial<SwDeps>, windows: { url: string; refuseFocus?: boolean }[] = []) {
  const listeners = new Map<string, (ev: never) => void>();
  const shown: Shown[] = [];
  const opened: string[] = [];
  const focused: string[] = [];
  const posted: unknown[] = [];
  const self: SwScope = {
    location: { origin: ORIGIN },
    addEventListener: (type, f) => void listeners.set(type, f),
    skipWaiting: () => Promise.resolve(),
    registration: {
      showNotification: (title, opts) => {
        shown.push({ title, opts });
        return Promise.resolve();
      },
    },
    clients: {
      claim: () => Promise.resolve(),
      matchAll: () =>
        Promise.resolve(
          windows.map((w) => ({
            url: w.url,
            focus: () => {
              if (w.refuseFocus) return Promise.reject(new Error("InvalidAccessError"));
              focused.push(w.url);
              return Promise.resolve();
            },
            postMessage: (m: unknown) => void posted.push(m),
          })),
        ),
      openWindow: (u) => {
        opened.push(u);
        return Promise.resolve(null);
      },
    },
  };
  install(self, { ...world(null).deps, ...deps });
  async function dispatch(type: string, ev: Record<string, unknown>): Promise<void> {
    let pending: Promise<unknown> = Promise.resolve();
    (listeners.get(type) as ((e: unknown) => void) | undefined)?.({
      ...ev,
      waitUntil: (p: Promise<unknown>) => (pending = p),
    });
    await pending;
  }
  return { shown, opened, focused, posted, dispatch };
}

describe("the worker", () => {
  it("shows the fixed notification for a push it cannot place, also for a body that is not JSON", async () => {
    const sw = load({});
    await sw.dispatch("push", { data: { json: () => JSON.parse("not json") } });
    await sw.dispatch("push", { data: null });
    expect(sw.shown).toEqual([
      {
        title: "segv.sh",
        opts: { body: "new messages", tag: "segv", data: { navigate: `${ORIGIN}/` } },
      },
      {
        title: "segv.sh",
        opts: { body: "new messages", tag: "segv", data: { navigate: `${ORIGIN}/` } },
      },
    ]);
  });

  it("names the conversation of a declarative push's proposed notification", async () => {
    const a = makeConv("bob");
    const c: NotifyCache = { v: 1, preview: "name", deltaS: 10, copies: [a.copy] };
    const sw = load({ readCache: async () => c });
    const bells = P.b64u(P.concat(P.fromB64u(a.bell), new Uint8Array(48)));
    await sw.dispatch("push", {
      data: null,
      notification: {
        title: "segv.sh",
        body: "new messages",
        tag: "segv",
        navigate: `${ORIGIN}/`,
        data: { bells },
      },
    });
    expect(sw.shown).toEqual([
      {
        title: "bob",
        opts: { body: "new messages", tag: a.ref, data: { navigate: `${ORIGIN}/#c/${a.ref}` } },
      },
    ]);
  });

  it("still shows the fixed notification when the cache's storage never answers", async () => {
    const sw = load({ readCache: () => new Promise(() => {}), sleep: () => Promise.resolve() });
    const bells = P.b64u(P.concat(P.random(16), new Uint8Array(48)));
    await sw.dispatch("push", {
      data: {
        json: () => ({
          web_push: 8030,
          notification: { title: "segv.sh", navigate: "/", data: { bells } },
        }),
      },
    });
    expect(sw.shown.map((s) => [s.title, s.opts.tag])).toEqual([["segv.sh", "segv"]]);
  });

  it("still shows the fixed notification when reading the cache throws", async () => {
    const sw = load({ readCache: () => Promise.reject(new Error("blocked")) });
    await sw.dispatch("push", {
      data: { json: () => ({ web_push: 8030, notification: { title: "segv.sh", navigate: "/" } }) },
    });
    expect(sw.shown.map((s) => s.title)).toEqual(["segv.sh"]);
  });

  it("a click asks an open window to show the conversation, or opens it; never another origin", async () => {
    const note = (navigate: unknown) => ({ notification: { data: { navigate }, close: () => {} } });
    const open = load({}, [{ url: "https://other.test/" }, { url: `${ORIGIN}/#c/x` }]);
    await open.dispatch("notificationclick", note(`${ORIGIN}/#c/AAAAAAAAAAAA`));
    expect(open.focused).toEqual([`${ORIGIN}/#c/x`]);
    expect(open.posted).toEqual([{ type: "segv.open", url: `${ORIGIN}/#c/AAAAAAAAAAAA` }]);
    expect(open.opened).toEqual([]);
    const closed = load({});
    await closed.dispatch("notificationclick", note(`${ORIGIN}/#c/AAAAAAAAAAAA`));
    await closed.dispatch("notificationclick", note("https://evil.test/"));
    expect(closed.opened).toEqual([`${ORIGIN}/#c/AAAAAAAAAAAA`, `${ORIGIN}/`]);
  });

  it("still asks the window to show the conversation when the browser refuses to focus it", async () => {
    const note = {
      notification: { data: { navigate: `${ORIGIN}/#c/AAAAAAAAAAAA` }, close: () => {} },
    };
    const sw = load({}, [{ url: `${ORIGIN}/`, refuseFocus: true }]);
    await sw.dispatch("notificationclick", note);
    expect(sw.posted).toEqual([{ type: "segv.open", url: `${ORIGIN}/#c/AAAAAAAAAAAA` }]);
  });
});
