/**
 * BellDO — one of PUSH_SHARDS objects that index the push registrations by bell (docs/PROTOCOL.md §9.8). Name
 * "bell/v2/{j}"; a bell's object is bellShard(tk). It has no storage of its own: the `b/<tk>` keys of the push store are
 * the truth, read into a bounded cache the first time the object touches a bell, and written by this object alone, so
 * that no write races another and the store's limit of one write per key per second is kept (later changes to a key
 * wait for its next write and go into it).
 *
 *  - lookup(tks): the entries under each bell.
 *  - apply(ep, qh, kh, box, add, remove): an endpoint's registration change for the bells of this object: it leaves
 *    the bells in `remove` and takes a place under each bell in `add` (replacing its own earlier entry; a bell whose 8
 *    places other endpoints hold is left out). Answers the bells it holds among `add`.
 */
import { DurableObject } from "cloudflare:workers";
import { hex, type Bytes } from "@segv/protocol/proto";
import { logErr } from "./http";
import { PUSH_PER_BELL, decodeEntries, encodeEntries, keyBell, sameBytes, type BellEntry } from "./push";
import { parseIndexName } from "./types";

/** Bells kept in memory; the least recently used go first (their keys stay in the store). */
const CACHE_BELLS = 16_384;
/** The store takes one write per key per second. */
const WRITE_SPACING_MS = 1_000;

const isBytes = (x: unknown, len: number): x is Bytes => x instanceof Uint8Array && x.length === len;
const checkTks = (xs: unknown, what: string): Bytes[] => {
  if (!Array.isArray(xs) || xs.length > 1024) throw new TypeError(`${what}: bad bells`);
  for (const t of xs) if (!isBytes(t, 16)) throw new TypeError(`${what}: bad bell`);
  return xs as Bytes[];
};

export class BellDO extends DurableObject<Env> {
  /** Time source and sleep: instance fields so tests can step them. */
  protected clock: () => number = () => Date.now();
  protected sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms));

  private readonly j: number;
  /** tk (hex) → entries (empty: none under the bell); insertion order is the recency order */
  private readonly bells = new Map<string, BellEntry[]>();
  /** tk (hex) → the write under way or waiting for its turn */
  private readonly writes = new Map<string, Promise<void>>();
  /** tk (hex) → when its key was last written */
  private readonly lastWrite = new Map<string, number>();
  /** tk (hex) → a change was made while its write was under way: another write follows */
  private readonly dirty = new Set<string>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.j = parseIndexName(ctx.id.name, "bell");
  }

  // ───────────── RPC ─────────────

  /** §9.8 `lookup`: the entries registered under each bell. */
  async lookup(tks: Bytes[]): Promise<{ tk: Bytes; entries: BellEntry[] }[]> {
    const list = checkTks(tks, "lookup");
    return Promise.all(list.map(async (tk) => ({ tk, entries: [...(await this.load(tk))] })));
  }

  /**
   * §9.8 `add` / `remove` for every bell of this object that an endpoint's registration change touches, in one call.
   * Answers the bells of `add` that the endpoint holds afterwards (the others had 8 other holders).
   */
  async apply(ep: Bytes, qh: Bytes | null, kh: Bytes, box: Bytes, add: Bytes[], remove: Bytes[]): Promise<{ held: Bytes[] }> {
    if (!isBytes(ep, 16) || !isBytes(kh, 16) || !(box instanceof Uint8Array) || box.length === 0 || box.length > 2048) throw new TypeError("apply: bad endpoint");
    if (qh !== null && !isBytes(qh, 16)) throw new TypeError("apply: bad quiet tag");
    const adds = checkTks(add, "apply");
    const removes = checkTks(remove, "apply");
    const held: Bytes[] = [];
    const touched = new Set<string>();
    for (const tk of removes) {
      const entries = await this.load(tk);
      const i = entries.findIndex((e) => sameBytes(e.ep, ep));
      if (i < 0) continue;
      entries.splice(i, 1);
      touched.add(hex(tk));
    }
    for (const tk of adds) {
      const entries = await this.load(tk);
      const i = entries.findIndex((e) => sameBytes(e.ep, ep));
      if (i >= 0) {
        const e = entries[i];
        if (!sameBytes(e.kh, kh) || !sameBytes(e.box, box) || (e.qh === null) !== (qh === null) || (e.qh && qh && !sameBytes(e.qh, qh))) {
          entries[i] = { ep, qh, kh, box };
          touched.add(hex(tk));
        }
        held.push(tk);
      } else if (entries.length < PUSH_PER_BELL) {
        entries.push({ ep, qh, kh, box });
        touched.add(hex(tk));
        held.push(tk);
      }
    }
    await Promise.all([...touched].map((k) => this.write(k)));
    return { held };
  }

  /** §9.8 `remove` for every bell of this object that an endpoint leaves (a deletion). */
  async leave(ep: Bytes, remove: Bytes[]): Promise<void> {
    if (!isBytes(ep, 16)) throw new TypeError("leave: bad endpoint");
    const touched = new Set<string>();
    for (const tk of checkTks(remove, "leave")) {
      const entries = await this.load(tk);
      const i = entries.findIndex((e) => sameBytes(e.ep, ep));
      if (i < 0) continue;
      entries.splice(i, 1);
      touched.add(hex(tk));
    }
    await Promise.all([...touched].map((k) => this.write(k)));
  }

  /** The entries under a bell (tests). */
  async entriesOf(tk: Bytes): Promise<BellEntry[]> {
    if (!isBytes(tk, 16)) throw new TypeError("entriesOf: bad bell");
    return [...(await this.load(tk))];
  }

  // ───────────── the cache and the store ─────────────

  /** The entries under `tk`, from the cache or the store; the list is the cache's own (mutated in place). */
  private async load(tk: Bytes): Promise<BellEntry[]> {
    const k = hex(tk);
    const hit = this.bells.get(k);
    if (hit) {
      // Most recently used last.
      this.bells.delete(k);
      this.bells.set(k, hit);
      return hit;
    }
    let entries: BellEntry[] = [];
    try {
      const raw = await this.env.PUSH_KV.get(keyBell(tk), "arrayBuffer");
      if (raw) entries = decodeEntries(new Uint8Array(raw)) ?? [];
    } catch (e) {
      console.error(JSON.stringify({ msg: "push store read failed", error: logErr(e) }));
      throw e;
    }
    // Another load of the same bell may have finished first: keep the first list, which later calls mutate.
    const again = this.bells.get(k);
    if (again) return again;
    this.bells.set(k, entries);
    while (this.bells.size > CACHE_BELLS) {
      const oldest = this.bells.keys().next().value as string;
      if (this.writes.has(oldest) || this.dirty.has(oldest)) break; // never drop a bell whose write is pending
      this.bells.delete(oldest);
    }
    return entries;
  }

  /**
   * Writes the bell's current entries to the store: one write per key at a time, at least WRITE_SPACING_MS after the
   * previous one; a change made while a write is under way gets a write of its own afterwards. Resolves once the
   * entries as they were at the call are in the store.
   */
  private write(k: string): Promise<void> {
    const pending = this.writes.get(k);
    if (pending) {
      this.dirty.add(k);
      return pending.then(() => this.writes.get(k) ?? Promise.resolve());
    }
    const run = (async (): Promise<void> => {
      const wait = (this.lastWrite.get(k) ?? 0) + WRITE_SPACING_MS - this.clock();
      if (wait > 0) await this.sleep(wait);
      this.dirty.delete(k);
      const entries = this.bells.get(k) ?? [];
      const key = `b/${k}`;
      try {
        if (entries.length === 0) await this.env.PUSH_KV.delete(key);
        else await this.env.PUSH_KV.put(key, encodeEntries(entries));
      } catch (e) {
        console.error(JSON.stringify({ msg: "push store write failed", error: logErr(e) }));
        this.dirty.add(k); // tried again by the next change of the bell
      }
      this.lastWrite.set(k, this.clock());
    })().finally(() => {
      this.writes.delete(k);
      if (this.dirty.has(k)) void this.write(k);
    });
    this.writes.set(k, run);
    return run;
  }
}
