/**
 * FeedDO — one of the F objects that fan published rows out to the ConnDOs (docs/PROTOCOL.md §9.4). Name
 * "feed/v2/{j}"; a topic's FeedDO is feed(T) (§4.4). It has no storage: the index lives in memory and is rebuilt from
 * the ConnDOs.
 *
 *  - Index: topic → the ConnDOs with interest in it; per ConnDO its topics and the time of its last call.
 *  - Start: at its first request it starts pulling topicsFor(j) from every ConnDO c < C in the background,
 *    `pullConcurrency` at a time, `pullTimeoutMs` each, and answers at once with the interest known so far. A ConnDO
 *    not pulled yet, or whose pull failed, is **pending**: a failed pull is made again at the next request, at most
 *    once per `repullMs`. Rows and notices published while any ConnDO is pending are **held** (`holdMs`, `holdRows`,
 *    `holdBytes`) and delivered to a ConnDO when its pull answers with their topic; a publish made while pulls are
 *    outstanding returns once they have answered (at most `holdMs` later). Nothing blocks construction.
 *  - interest(c, added, removed) / replace(c, topics): from the ConnDOs. Interest from a ConnDO that has made no
 *    call for RT_FORGET is dropped. `c` is not bounded by C (§9.4). A pull that answers after a call from the same
 *    ConnDO arrived only adds topics (the call is newer than what the pull may have read).
 *  - publish(rows): one deliver per ConnDO with interest in a row's topic, in the order published, retried once, then
 *    dropped for that ConnDO (its clients catch up, §11.6). The ConnDO stubs come from `conns`, an instance field
 *    that tests can replace.
 *  - inbox(E, g, rel): from an InboxDO (§9.3): one deliverInbox per ConnDO with interest in Tinbox(E, g), retried
 *    once.
 */
import { DurableObject } from "cloudflare:workers";
import { hex, topicInbox } from "@segv/protocol/proto";
import { v2Params } from "./env";
import { logErr, twice, withTimeout } from "./http";
import { checkNotice, checkRtRows, connStub, parseIndexName, type RtPublishRow } from "./types";

export interface FeedLimits {
  /** RT_FORGET: interest from a ConnDO silent for this long is dropped */
  forgetMs: number;
  /** a pull (topicsFor) that has not answered within this long counts as failed */
  pullTimeoutMs: number;
  /** pulls made at the same time */
  pullConcurrency: number;
  /** a failed pull is made again at a request at most this often */
  repullMs: number;
  /** rows and notices published while a ConnDO is pending are held for it this long, */
  holdMs: number;
  /** at most this many of them, */
  holdRows: number;
  /** and at most this many bytes (rows as encoded in ROWS frames) */
  holdBytes: number;
}

const FEED_LIMITS: Readonly<FeedLimits> = {
  forgetMs: 900_000,
  pullTimeoutMs: 5_000,
  pullConcurrency: 32,
  repullMs: 1_000,
  holdMs: 10_000,
  holdRows: 4096,
  holdBytes: 8 * 1024 * 1024,
};

/** Bytes of one row in a ROWS frame besides the body (§10.8), and what a held notice counts. */
const ROW_WIRE_OVERHEAD = 47;
const NOTICE_SIZE = 16;

/** What a FeedDO calls on a ConnDO. */
export interface ConnLink {
  deliver(rows: RtPublishRow[]): Promise<void>;
  deliverInbox(E: number, g: number, rel: number): Promise<void>;
  topicsFor(j: number): Promise<Uint8Array[]>;
}

/** A row or a notice published while some ConnDO was pending, with the ConnDOs it has already gone to. */
interface Held {
  k: string;
  at: number;
  size: number;
  sent: Set<number>;
  row?: RtPublishRow;
  notice?: { E: number; g: number; rel: number };
}

function checkConn(c: unknown): number {
  if (!Number.isInteger(c) || (c as number) < 0 || (c as number) >= 2 ** 31) throw new TypeError("bad conn index");
  return c as number;
}

function checkTopics(x: unknown, what: string): Uint8Array[] {
  if (!Array.isArray(x)) throw new TypeError(`${what}: bad topics`);
  for (const t of x) if (!(t instanceof Uint8Array) || t.length !== 16) throw new TypeError(`${what}: bad topic`);
  return x as Uint8Array[];
}

export class FeedDO extends DurableObject<Env> {
  /** Time source (Unix ms). An instance field so tests can step the clock. */
  protected clock: () => number = () => Date.now();
  protected limits: FeedLimits = { ...FEED_LIMITS };
  /** The ConnDO a delivery or a pull goes to; tests replace it to observe or fail the calls. */
  protected conns: (c: number) => ConnLink = (c) => connStub(this.env, c);

  /** This object's index j (its name is "feed/v2/{j}"). */
  private readonly j: number;
  /** C: the ConnDOs pulled at start. */
  private readonly C: number;
  /** topic (hex) → ConnDOs with interest in it */
  private readonly byTopic = new Map<string, Set<number>>();
  /** ConnDO → its topics (hex) and the time of its last call */
  private readonly byConn = new Map<number, { topics: Set<string>; seen: number }>();
  /** false until the first request starts the pull */
  private started = false;
  /** ConnDOs whose interest is not known: not pulled yet, or their pull failed (insertion order = pull order). */
  private readonly pending = new Set<number>();
  /** pulls in flight */
  private readonly pulling = new Set<number>();
  /** the time of each pending ConnDO's last pull attempt */
  private readonly tried = new Map<number, number>();
  /** pull workers running */
  private workers = 0;
  /** per ConnDO being pulled: the interest / replace calls received from it since its pull started */
  private readonly calls = new Map<number, number>();
  /** rows and notices published while a ConnDO was pending, oldest first */
  private held: Held[] = [];
  private heldBytes = 0;
  /** publishes waiting for the pulls in flight to answer */
  private readonly idleWaiters = new Set<() => void>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.j = parseIndexName(ctx.id.name, "feed");
    this.C = v2Params(env).rtConns;
  }

  // ───────────── RPC from the Worker ─────────────

  /** §9.4 publish: one deliver per ConnDO with interest in a row's topic; retried once, then dropped for it. */
  async publish(rows: RtPublishRow[]): Promise<void> {
    const input = checkRtRows(rows, "publish");
    if (input.length === 0) return;
    const now = this.begin();
    const holding = this.pending.size > 0;
    const per = new Map<number, RtPublishRow[]>();
    for (const r of input) {
      const k = hex(r.topic);
      const set = this.byTopic.get(k);
      for (const c of set ?? []) {
        const list = per.get(c);
        if (list) list.push(r);
        else per.set(c, [r]);
      }
      if (holding) this.hold({ k, at: now, size: ROW_WIRE_OVERHEAD + r.body.length, sent: new Set(set), row: r });
    }
    await Promise.all([...per].map(([c, list]) => this.deliverTo(c, list)));
    if (holding) await this.pullsAnswered();
  }

  /** §9.3 notice from an InboxDO: one deliverInbox per ConnDO with interest in Tinbox(E, g), made once more on failure. */
  async inbox(E: number, g: number, rel: number): Promise<void> {
    checkNotice(E, g, rel);
    const now = this.begin();
    const k = hex(topicInbox(E, g));
    const set = this.byTopic.get(k);
    const holding = this.pending.size > 0;
    if (holding) this.hold({ k, at: now, size: NOTICE_SIZE, sent: new Set(set), notice: { E, g, rel } });
    await Promise.all([...(set ?? [])].map((c) => this.inboxTo(c, E, g, rel)));
    if (holding) await this.pullsAnswered();
  }

  // ───────────── RPC from the ConnDOs ─────────────

  /** A change of ConnDO c's distinct-topic set at this FeedDO (§9.4 "Interest"). */
  interest(c: number, added: Uint8Array[], removed: Uint8Array[]): void {
    const idx = checkConn(c);
    const add = checkTopics(added, "interest");
    const rem = checkTopics(removed, "interest");
    const now = this.begin();
    this.called(idx);
    const e = this.entry(idx, now);
    for (const t of rem) this.drop(idx, e, hex(t));
    for (const t of add) this.add(idx, e, hex(t));
    if (e.topics.size === 0) this.byConn.delete(idx);
  }

  /** ConnDO c's full set at this FeedDO (its periodic resync, or a repair after a failed call). */
  replace(c: number, topics: Uint8Array[]): void {
    const idx = checkConn(c);
    const list = checkTopics(topics, "replace");
    const now = this.begin();
    this.called(idx);
    this.set(idx, list, now);
  }

  /** The topics a ConnDO has interest in here (tests). */
  topicsOf(c: number): string[] {
    const idx = checkConn(c);
    this.begin();
    return [...(this.byConn.get(idx)?.topics ?? [])];
  }

  // ───────────── internals ─────────────

  /** Every request: start the pull (the first), pull pending ConnDOs again, expire silent ones and old held rows. */
  private begin(): number {
    const now = this.clock();
    if (!this.started) {
      this.started = true;
      for (let c = 0; c < this.C; c++) this.pending.add(c);
    }
    this.pump(now);
    this.expire(now);
    this.trimHeld(now);
    return now;
  }

  /** Runs pull workers, up to `pullConcurrency`, while some pending ConnDO is due for a pull. */
  private pump(now: number): void {
    if (this.pending.size === 0) return;
    while (this.workers < this.limits.pullConcurrency && this.nextPull(now) !== null) {
      this.workers++;
      void this.worker().finally(() => {
        this.workers--;
        this.wakeIdle();
      });
    }
  }

  private async worker(): Promise<void> {
    for (let c = this.nextPull(this.clock()); c !== null; c = this.nextPull(this.clock())) await this.pull(c);
  }

  /**
   * The first pending ConnDO that is not being pulled and was not tried within `repullMs`. A failed pull moves its
   * ConnDO to the back of `pending`, so the scan stops at the first one never tried.
   */
  private nextPull(now: number): number | null {
    for (const c of this.pending) {
      if (this.pulling.has(c)) continue;
      const t = this.tried.get(c);
      if (t !== undefined && now - t < this.limits.repullMs) continue;
      return c;
    }
    return null;
  }

  /** Counts a call from ConnDO c while its pull is in flight. */
  private called(c: number): void {
    const n = this.calls.get(c);
    if (n !== undefined) this.calls.set(c, n + 1);
  }

  private async pull(c: number): Promise<void> {
    this.pulling.add(c);
    this.tried.set(c, this.clock());
    this.calls.set(c, 0);
    try {
      const topics = checkTopics(await withTimeout(this.conns(c).topicsFor(this.j), this.limits.pullTimeoutMs), "pull");
      const now = this.clock();
      if (this.calls.get(c) === 0) this.set(c, topics, now);
      else {
        // A call from c came in while the pull was on its way and may be newer than what the pull read: add only.
        const e = this.entry(c, now);
        for (const t of topics) this.add(c, e, hex(t));
        if (e.topics.size === 0) this.byConn.delete(c);
      }
      this.pending.delete(c);
      this.tried.delete(c);
      await this.flushHeld(c);
    } catch (e) {
      this.pending.delete(c);
      this.pending.add(c); // to the back: the ConnDOs never tried come first
      console.error(JSON.stringify({ msg: "feed pull failed", error: logErr(e) }));
    } finally {
      this.pulling.delete(c);
      this.calls.delete(c);
      if (this.pending.size === 0) {
        this.held = [];
        this.heldBytes = 0;
      }
    }
  }

  /** Keeps a row or notice for the pending ConnDOs. */
  private hold(h: Held): void {
    this.held.push(h);
    this.heldBytes += h.size;
    this.trimHeld(h.at);
  }

  /** Drops held rows older than `holdMs` and beyond `holdRows` / `holdBytes`, oldest first. */
  private trimHeld(now: number): void {
    const L = this.limits;
    let n = 0;
    while (n < this.held.length) {
      const h = this.held[n];
      if (now - h.at <= L.holdMs && this.held.length - n <= L.holdRows && this.heldBytes <= L.holdBytes) break;
      this.heldBytes -= h.size;
      n++;
    }
    if (n > 0) this.held.splice(0, n);
  }

  /** Delivers to ConnDO c, whose pull just answered, the held rows and notices of its topics it has not had. */
  private async flushHeld(c: number): Promise<void> {
    this.trimHeld(this.clock());
    const e = this.byConn.get(c);
    if (!e) return;
    const rows: RtPublishRow[] = [];
    const notices: { E: number; g: number; rel: number }[] = [];
    for (const h of this.held) {
      if (h.sent.has(c) || !e.topics.has(h.k)) continue;
      h.sent.add(c);
      if (h.row) rows.push(h.row);
      if (h.notice) notices.push(h.notice);
    }
    await Promise.all([
      ...(rows.length > 0 ? [this.deliverTo(c, rows)] : []),
      ...notices.map((n) => this.inboxTo(c, n.E, n.g, n.rel)),
    ]);
  }

  /** Resolves once no pull is in flight, or `holdMs` from now. */
  private pullsAnswered(): Promise<void> {
    if (this.workers === 0) return Promise.resolve();
    return new Promise<void>((resolve) => {
      const done = (): void => {
        clearTimeout(timer);
        this.idleWaiters.delete(done);
        resolve();
      };
      const timer = setTimeout(done, this.limits.holdMs);
      this.idleWaiters.add(done);
    });
  }

  private wakeIdle(): void {
    if (this.workers > 0) return;
    for (const done of this.idleWaiters) done(); // each one removes itself: a Set allows that while iterating
  }

  private deliverTo(c: number, rows: RtPublishRow[]): Promise<boolean> {
    return twice(() => this.conns(c).deliver(rows), "feed deliver failed");
  }

  private inboxTo(c: number, E: number, g: number, rel: number): Promise<boolean> {
    return twice(() => this.conns(c).deliverInbox(E, g, rel), "feed inbox failed");
  }

  private entry(c: number, now: number): { topics: Set<string>; seen: number } {
    let e = this.byConn.get(c);
    if (!e) this.byConn.set(c, (e = { topics: new Set(), seen: now }));
    e.seen = now;
    return e;
  }

  private add(c: number, e: { topics: Set<string> }, k: string): void {
    e.topics.add(k);
    const set = this.byTopic.get(k);
    if (set) set.add(c);
    else this.byTopic.set(k, new Set([c]));
  }

  private drop(c: number, e: { topics: Set<string> }, k: string): void {
    e.topics.delete(k);
    const set = this.byTopic.get(k);
    if (!set) return;
    set.delete(c);
    if (set.size === 0) this.byTopic.delete(k);
  }

  private set(c: number, topics: Uint8Array[], now: number): void {
    const e = this.entry(c, now);
    const want = new Set(topics.map(hex));
    for (const k of e.topics) if (!want.has(k)) this.drop(c, e, k);
    for (const k of want) if (!e.topics.has(k)) this.add(c, e, k);
    if (e.topics.size === 0) this.byConn.delete(c);
  }

  /** Drops the interest of every ConnDO that has made no call for `forgetMs`. */
  private expire(now: number): void {
    for (const [c, e] of this.byConn) {
      if (now - e.seen <= this.limits.forgetMs) continue;
      for (const k of e.topics) this.drop(c, e, k);
      this.byConn.delete(c);
    }
  }
}
