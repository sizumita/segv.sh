/**
 * FeedDO — one of the F objects that fan published rows out to the ConnDOs (docs/PROTOCOL.md §9.4). Name
 * "feed/v2/{j}"; a topic's FeedDO is feed(T) (§4.4). It has no storage: the index lives in memory and is rebuilt from
 * the ConnDOs.
 *
 *  - Index: topic → the ConnDOs with interest in it; per ConnDO its topics and the time of its last call.
 *  - Start: before it answers anything (blockConcurrencyWhile in the constructor), it pulls topicsFor(j) from every
 *    ConnDO c < C, 32 at a time, 5 s each; a ConnDO that fails is pulled again at the next publish, at most once a
 *    second, and gets no delivery until it answers.
 *  - interest(c, added, removed) / replace(c, topics): from the ConnDOs. Interest from a ConnDO that has made no
 *    call for RT_FORGET is dropped. `c` is not bounded by C (§9.4).
 *  - publish(rows): one deliver per ConnDO with interest in a row's topic, in the order published, retried once, then
 *    dropped for that ConnDO (its clients catch up, §11.6). The ConnDO stubs come from `conns`, an instance field
 *    that tests can replace.
 */
import { DurableObject } from "cloudflare:workers";
import { BODY_LENS, hex } from "@segv/protocol/proto";
import { v2Params } from "./env";
import { logErr } from "./http";
import { connStub, parseIndexName, type RtPublishRow } from "./types";

export interface FeedLimits {
  /** RT_FORGET: interest from a ConnDO silent for this long is dropped */
  forgetMs: number;
  /** a pull (topicsFor) that has not answered within this long counts as failed */
  pullTimeoutMs: number;
  /** pulls made at the same time when the object starts */
  pullConcurrency: number;
  /** failed pulls are made again at a publish at most this often */
  repullMs: number;
}

const FEED_LIMITS: Readonly<FeedLimits> = { forgetMs: 900_000, pullTimeoutMs: 5_000, pullConcurrency: 32, repullMs: 1_000 };

/** What a FeedDO calls on a ConnDO. */
export interface ConnLink {
  deliver(rows: RtPublishRow[]): Promise<void>;
  topicsFor(j: number): Promise<Uint8Array[]>;
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("timeout")), ms);
  });
  return Promise.race([p, late]).finally(() => clearTimeout(timer));
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

/** Defensive re-validation of publish() input (the Worker validates too). */
function checkPublish(input: unknown): RtPublishRow[] {
  if (!Array.isArray(input)) throw new TypeError("publish: bad rows");
  return input.map((r: unknown) => {
    const { topic, E, label, t, cls, body } = (typeof r === "object" && r !== null ? r : {}) as Record<string, unknown>;
    if (!(topic instanceof Uint8Array) || topic.length !== 16) throw new TypeError("publish: bad topic");
    if (!Number.isInteger(E) || (E as number) < 0 || (E as number) > 0xffff) throw new TypeError("publish: bad era");
    if (!(label instanceof Uint8Array) || label.length !== 16) throw new TypeError("publish: bad label");
    if (!Number.isInteger(t) || (t as number) < 0 || (t as number) > 0xffffffff) throw new TypeError("publish: bad t");
    if (!Number.isInteger(cls) || BODY_LENS[cls as number] === undefined) throw new TypeError("publish: bad class");
    if (!(body instanceof Uint8Array) || body.length !== BODY_LENS[cls as number]) throw new TypeError("publish: bad body");
    return { topic, E: E as number, label, t: t as number, cls: cls as number, body };
  });
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
  /** ConnDOs whose pull failed: pulled again at the next publish. */
  private readonly pending = new Set<number>();
  private lastRepull = 0;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.j = parseIndexName(ctx.id.name, "feed");
    this.C = v2Params(env).rtConns;
    void ctx.blockConcurrencyWhile(() => this.pullAll());
  }

  // ───────────── RPC from the Worker ─────────────

  /** §9.4 publish: one deliver per ConnDO with interest in a row's topic; retried once, then dropped for it. */
  async publish(rows: RtPublishRow[]): Promise<void> {
    const input = checkPublish(rows);
    if (input.length === 0) return;
    const now = this.clock();
    this.repull(now);
    this.expire(now);
    const per = new Map<number, RtPublishRow[]>();
    for (const r of input) {
      const set = this.byTopic.get(hex(r.topic));
      if (!set) continue;
      for (const c of set) {
        const list = per.get(c);
        if (list) list.push(r);
        else per.set(c, [r]);
      }
    }
    await Promise.all([...per].map(([c, list]) => this.deliverTo(c, list)));
  }

  // ───────────── RPC from the ConnDOs ─────────────

  /** A change of ConnDO c's distinct-topic set at this FeedDO (§9.4 "Interest"). */
  interest(c: number, added: Uint8Array[], removed: Uint8Array[]): void {
    const idx = checkConn(c);
    const add = checkTopics(added, "interest");
    const rem = checkTopics(removed, "interest");
    const e = this.entry(idx, this.clock());
    for (const t of rem) this.drop(idx, e, hex(t));
    for (const t of add) this.add(idx, e, hex(t));
  }

  /** ConnDO c's full set at this FeedDO (its periodic resync, or a repair after a failed call). */
  replace(c: number, topics: Uint8Array[]): void {
    this.set(checkConn(c), checkTopics(topics, "replace"), this.clock());
  }

  /** The topics a ConnDO has interest in here (tests). */
  topicsOf(c: number): string[] {
    return [...(this.byConn.get(checkConn(c))?.topics ?? [])];
  }

  // ───────────── internals ─────────────

  /** Pulls every ConnDO below C, `pullConcurrency` at a time (the constructor, before any request is answered). */
  private async pullAll(): Promise<void> {
    let next = 0;
    const worker = async (): Promise<void> => {
      while (next < this.C) await this.pull(next++);
    };
    await Promise.all(Array.from({ length: Math.min(this.limits.pullConcurrency, this.C) }, worker));
  }

  private async pull(c: number): Promise<void> {
    try {
      const topics = checkTopics(await withTimeout(this.conns(c).topicsFor(this.j), this.limits.pullTimeoutMs), "pull");
      this.set(c, topics, this.clock());
      this.pending.delete(c);
    } catch (e) {
      this.pending.add(c);
      console.error(JSON.stringify({ msg: "feed pull failed", error: logErr(e) }));
    }
  }

  /** Pulls the ConnDOs whose pull failed, at most once per `repullMs`, without holding up the publish. */
  private repull(now: number): void {
    if (this.pending.size === 0 || now - this.lastRepull < this.limits.repullMs) return;
    this.lastRepull = now;
    for (const c of this.pending) void this.pull(c);
  }

  private async deliverTo(c: number, rows: RtPublishRow[]): Promise<void> {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        await this.conns(c).deliver(rows);
        return;
      } catch (e) {
        if (attempt === 1) console.error(JSON.stringify({ msg: "feed deliver failed", error: logErr(e) }));
      }
    }
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
