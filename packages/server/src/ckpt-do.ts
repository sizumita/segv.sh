/**
 * CheckpointDO — the signed checkpoint chain over the heads of the public data (docs/PROTOCOL.md §9.5, §10.9,
 * §12.3). One instance, "ckpt/v2".
 *
 *  - An alarm runs tick() every 60 s and is re-armed in the same synchronous block as the tick's commit. The
 *    constructor arms it (inside blockConcurrencyWhile) when no alarm is set; the Worker calls ensure() once per
 *    isolate just to wake the object, and ensure() writes nothing while an alarm is scheduled.
 *  - tick() collects (cid, head) from shard/{E_now}/{i} for every i < S_{E_now} (the shard map, §9.1) and
 *    inbox/{E_now}/{g} for every g < 2^β_{E_now} (§9.3); from those of E_now−1 until they are sealed and their final head
 *    appeared once ('final:<cid>'); from the B blob registry shards once per UTC hour, as one value that mixes the
 *    hour in ('blobreg:hour', 'blobreg:head', each shard's last head 'blobreg:head:<j>'); and from the dirlog of
 *    the log database
 *    (ZERO32 when the table is missing or empty). At most 32 component calls
 *    are in flight at a time. A component that fails keeps its previous head. The list is sorted by cid,
 *    hd = H(heads), C_q = H(enc("segv.sh/v2/ckpt", C_{q−1}, u32 q, u32 sec, hd)), sig = Sign(SRV_SK, enc(…, q, C_q)).
 *    An unchanged hd makes no new checkpoint.
 *  - The encoded list of a checkpoint is written to R2 (BLOBS, "ckpt/v2/{q}", immutable) before its row is committed;
 *    the row keeps (q, sec, hd, C, sig) and an empty `heads`. A failed R2 write commits no checkpoint (the next tick
 *    builds it again). Rows written before the move to R2 keep their list in `heads` and are served from it.
 *  - Once per UTC hour it also wakes up to 16 shards of past eras (head()), round-robin over the shards not known to
 *    be paged, from 'page:era' up to E_now − 2 and resuming at 'page:at', so that every sealed shard gets paged into
 *    R2 (§9.1 "Paging", §9.5 "Sweep"); shards found paged are marked 'paged:<E>:<i>', eras 'paged:<E>'.
 *  - latest() / get(q) / range(after, limit) are the §10.9 reads; the latest list is also kept in memory.
 *
 * Time is read through the protected `clock` field so tests can override it.
 */
import { DurableObject } from "cloudflare:workers";
import {
  BLOBREG_CID,
  DIRLOG_CID,
  H,
  ZERO32,
  blobRegCid,
  blobregAll,
  byteCmp,
  ckptC,
  ckptSigMsg,
  enc,
  equalBytes,
  era,
  fromB64u,
  fromUtf8,
  inboxCid,
  secOf,
  shardCid,
  utf8,
} from "@segv/protocol/proto";
import { errMsg, logErr } from "./http";
import { Meta, ab } from "./batch";
import { inboxBucketsOf, logDb, serverKeys, shardsOf, srvSign, v2Params } from "./env";
import { blobRegStub, inboxStub, shardStub, type CkptRange, type CkptRecord } from "./types";

const PERIOD_MS = 60_000;
const HOUR_MS = 3_600_000;
/** Log when a shard reports a databaseSize above this (§9.1 "Retention and capacity"): raise S for the next era. */
const SIZE_WARN_BYTES = 2 * 2 ** 30;
/** A component that has not answered after this long counts as failed (it keeps its previous head). */
const COMPONENT_TIMEOUT_MS = 10_000;
/** Component calls in flight at a time (§9.5). */
const COLLECT_CONCURRENCY = 32;
/** Shards of past eras woken per hour so that each gets paged (§9.5 "Sweep"). */
const SWEEP_SHARDS = 16;
/** 'page:at' is E · 65536 + i: shard indices stay below 2^16 (§9.1). */
const SHARD_SPAN = 65536;

/** Runs the jobs with at most `n` in flight. The jobs never throw (each catches its own failure). */
async function pool(jobs: readonly (() => Promise<void>)[], n: number): Promise<void> {
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < jobs.length) await jobs[next++]();
  };
  await Promise.all(Array.from({ length: Math.min(n, jobs.length) }, worker));
}
const RANGE_MAX = 1440;
const HEADS_LABEL = "segv.sh/v2/ckpt/heads";
/** The R2 key of checkpoint q's encoded list (§9.5). */
const headsKey = (q: number): string => `ckpt/v2/${q}`;

/** `heads` is empty in every row since the lists moved to R2 (§9.5); older rows hold their encoded list there. */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS cp (
  q INTEGER PRIMARY KEY,
  sec INTEGER NOT NULL,
  hd BLOB NOT NULL,
  heads BLOB NOT NULL,
  C BLOB NOT NULL,
  sig BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
`;

type Head = { cid: string; head: Uint8Array };
/** A meta value to write with the checkpoint, or null to delete the key. */
type MetaWrites = Map<string, number | Uint8Array | null>;
type CpRow = { q: number; sec: number; hd: ArrayBuffer; heads: ArrayBuffer; C: ArrayBuffer; sig: ArrayBuffer };
interface Checkpoint {
  q: number;
  sec: number;
  hd: Uint8Array;
  heads: Uint8Array;
  C: Uint8Array;
  sig: Uint8Array;
}

/**
 * The encoded list: enc("segv.sh/v2/ckpt/heads", cid_1, head_1, …) over the list sorted by cid. It is the R2 object
 * "ckpt/v2/{q}"; the `heads` column holds it only in rows written before the lists moved to R2 (empty otherwise).
 */
const encodeHeads = (list: readonly Head[]): Uint8Array => enc(HEADS_LABEL, ...list.flatMap((h) => [h.cid, h.head]));

function decodeHeads(b: Uint8Array): Head[] {
  const fields: Uint8Array[] = [];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let o = 0;
  while (o < b.length) {
    if (o + 4 > b.length) throw new Error("ckpt heads: truncated");
    const n = dv.getUint32(o);
    o += 4;
    if (o + n > b.length) throw new Error("ckpt heads: truncated");
    fields.push(b.subarray(o, o + n));
    o += n;
  }
  if (fields.length % 2 !== 1 || fromUtf8(fields[0]) !== HEADS_LABEL) throw new Error("ckpt heads: bad encoding");
  const out: Head[] = [];
  for (let k = 1; k < fields.length; k += 2) out.push({ cid: fromUtf8(fields[k]), head: fields[k + 1].slice() });
  return out;
}

const toCheckpoint = (r: CpRow): Checkpoint => ({
  q: r.q,
  sec: r.sec,
  hd: new Uint8Array(r.hd),
  heads: new Uint8Array(r.heads),
  C: new Uint8Array(r.C),
  sig: new Uint8Array(r.sig),
});

export class CheckpointDO extends DurableObject<Env> {
  /** Instance fields (not constants) so tests can override them with runInDurableObject. */
  protected clock = (): number => Date.now();
  protected sizeWarnBytes = SIZE_WARN_BYTES;
  protected componentTimeoutMs = COMPONENT_TIMEOUT_MS;
  /** S_E (§9.1); an instance field so tests can set a count without a deployment variable. */
  protected shardsOf = (E: number): number => shardsOf(v2Params(this.env).shardMap, E);
  protected sweepShards = SWEEP_SHARDS;
  /** B, the registry shard count (§9.2); an instance field so tests can set it without a deployment variable. */
  protected blobShards = (): number => v2Params(this.env).blobShards;
  /** 2^β_E, the inbox buckets of an era (§9.3); an instance field so tests can set it without a deployment variable. */
  protected inboxBucketsOf = (E: number): number => inboxBucketsOf(v2Params(this.env).inboxMap, E);

  private readonly sql: SqlStorage;
  private readonly kv: Meta;
  private ticking: Promise<void> | null = null;
  /** The list of the latest checkpoint this instance committed or read. */
  private latestHeads: { q: number; list: Head[] } | null = null;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(SCHEMA);
    this.kv = new Meta(this.sql);
    void ctx.blockConcurrencyWhile(async () => {
      if ((await ctx.storage.getAlarm()) === null) await ctx.storage.setAlarm(this.clock() + PERIOD_MS);
    });
  }

  /** Wakes the object (the constructor arms the alarm). Writes nothing while an alarm is scheduled. */
  async ensure(): Promise<void> {
    if ((await this.ctx.storage.getAlarm()) === null) this.armNext();
  }

  async alarm(): Promise<void> {
    await this.tick();
  }

  /** The alarm body (public for tests). Single-flight; never throws; always leaves the next alarm armed. */
  tick(): Promise<void> {
    if (!this.ticking) {
      this.ticking = this.checkpoint()
        .catch((e: unknown) => {
          console.error(JSON.stringify({ msg: "checkpoint failed", error: logErr(e) }));
          this.armNext();
        })
        .finally(() => {
          this.ticking = null;
        });
    }
    return this.ticking;
  }

  async latest(): Promise<CkptRecord | null> {
    const r = this.latestRow();
    return r ? await this.record(r) : null;
  }

  async get(q: number): Promise<CkptRecord | null> {
    if (!Number.isSafeInteger(q) || q < 1) return null;
    const r = this.sql.exec<CpRow>("SELECT q, sec, hd, heads, C, sig FROM cp WHERE q = ?", q).toArray()[0];
    return r ? await this.record(toCheckpoint(r)) : null;
  }

  /** §10.9 range: entries with q > after (ascending, at most `limit`), C_after, and the latest {q, C, sig}. */
  range(after: number, limit: number): CkptRange | null {
    if (!Number.isSafeInteger(after) || after < 0) throw new RangeError("range: bad after");
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > RANGE_MAX) throw new RangeError("range: bad limit");
    const last = this.latestRow();
    if (!last || after > last.q) return null;
    let fromC: Uint8Array = ZERO32;
    if (after > 0) {
      const r = this.sql.exec<{ C: ArrayBuffer }>("SELECT C FROM cp WHERE q = ?", after).toArray()[0];
      if (!r) return null;
      fromC = new Uint8Array(r.C);
    }
    const entries = this.sql
      .exec<{ q: number; sec: number; hd: ArrayBuffer }>(
        "SELECT q, sec, hd FROM cp WHERE q > ? ORDER BY q LIMIT ?",
        after,
        limit,
      )
      .toArray()
      .map((e) => ({ q: e.q, sec: e.sec, hd: new Uint8Array(e.hd) }));
    return { from: { q: after, C: fromC }, entries, latest: { q: last.q, C: last.C, sig: last.sig } };
  }

  // ───────────── internals ─────────────

  private latestRow(): Checkpoint | null {
    const r = this.sql.exec<CpRow>("SELECT q, sec, hd, heads, C, sig FROM cp ORDER BY q DESC LIMIT 1").toArray()[0];
    return r ? toCheckpoint(r) : null;
  }

  private async record(c: Checkpoint): Promise<CkptRecord> {
    return { q: c.q, sec: c.sec, hd: c.hd, C: c.C, sig: c.sig, heads: await this.headsOf(c) };
  }

  /**
   * The list of checkpoint c: from its row when the row still holds it, else from memory or R2 ("ckpt/v2/{q}"), whose
   * bytes must hash to hd. A list that is missing or does not match throws (the Worker answers 5xx), never a guess.
   */
  private async headsOf(c: Checkpoint): Promise<Head[]> {
    if (c.heads.length > 0) return decodeHeads(c.heads);
    if (this.latestHeads?.q === c.q) return this.latestHeads.list;
    const obj = await this.env.BLOBS.get(headsKey(c.q));
    if (!obj) throw new Error("checkpoint: the list of a checkpoint is missing from R2");
    const bytes = new Uint8Array(await obj.arrayBuffer());
    if (!equalBytes(H(bytes), c.hd)) throw new Error("checkpoint: the list in R2 does not match hd");
    const list = decodeHeads(bytes);
    if (c.q === this.latestRow()?.q) this.latestHeads = { q: c.q, list };
    return list;
  }

  /** Not awaited on purpose: called in the same synchronous block as the commit it belongs to. */
  private armNext(): void {
    this.ctx.storage.setAlarm(this.clock() + PERIOD_MS).catch((e: unknown) => {
      console.error(JSON.stringify({ msg: "setAlarm failed", error: logErr(e) }));
    });
  }

  private timed<T>(p: Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("timed out")), this.componentTimeoutMs);
    });
    return Promise.race([p, timeout]).finally(() => clearTimeout(timer));
  }

  private async checkpoint(): Promise<void> {
    const now = this.clock();
    const prev = this.latestRow();
    const prevHeads = new Map((prev ? await this.headsOf(prev) : []).map((h) => [h.cid, h.head] as const));
    const heads = new Map<string, Uint8Array>();
    /** Meta written with the checkpoint (or alone when hd is unchanged): final marks, the hourly blobreg head. */
    const metaWrites: MetaWrites = new Map();
    const E = era(now);
    const { eFirst } = v2Params(this.env);

    const keep = (cid: string, e: unknown): void => {
      console.error(JSON.stringify({ msg: "checkpoint: component did not answer", cid, error: logErr(e) }));
      const p = prevHeads.get(cid);
      if (p) heads.set(cid, p);
    };

    // A previous-era component stays until it is sealed and that final head appeared once.
    const shard = async (Ec: number, i: number, previous: boolean): Promise<void> => {
      const cid = shardCid(Ec, i);
      if (previous && this.kv.num(`final:${cid}`) !== null) return;
      try {
        const h = await this.timed(Promise.resolve(shardStub(this.env, Ec, i).head(Ec, i)));
        if (h.size > this.sizeWarnBytes) {
          console.error(JSON.stringify({ msg: logErr(`shard ${cid} databaseSize ${h.size} B is above 2 GiB`) }));
        }
        heads.set(cid, new Uint8Array(h.head));
        if (previous && h.sealed) metaWrites.set(`final:${cid}`, 1);
      } catch (e) {
        keep(cid, e);
      }
    };
    const inbox = async (Ec: number, g: number, previous: boolean): Promise<void> => {
      const cid = inboxCid(Ec, g);
      if (previous && this.kv.num(`final:${cid}`) !== null) return;
      try {
        const h = await this.timed(Promise.resolve(inboxStub(this.env, Ec, g).head(Ec, g)));
        heads.set(cid, new Uint8Array(h.head));
        if (previous && h.ended) metaWrites.set(`final:${cid}`, 1);
      } catch (e) {
        keep(cid, e);
      }
    };
    // The registry once per UTC hour, as one value over every shard's head with the hour mixed in (§9.5): it
    // changes every hour whether or not anything was registered, so P learns nothing from it.
    const blobreg = async (): Promise<void> => {
      const hour = Math.floor(now / HOUR_MS);
      const storedHour = this.kv.num("blobreg:hour");
      let head = this.kv.bytes("blobreg:head");
      if (storedHour === null || hour > storedHour) {
        const B = this.blobShards();
        const shardHeads: Uint8Array[] = Array.from({ length: B }, (_, j) => this.kv.bytes(`blobreg:head:${j}`) ?? ZERO32);
        const jobs: (() => Promise<void>)[] = [];
        for (let j = 0; j < B; j++) {
          jobs.push(async () => {
            try {
              const h = new Uint8Array((await this.timed(Promise.resolve(blobRegStub(this.env, j).head()))).head);
              shardHeads[j] = h;
              metaWrites.set(`blobreg:head:${j}`, h);
            } catch (e) {
              console.error(JSON.stringify({ msg: "checkpoint: component did not answer", cid: blobRegCid(j), error: logErr(e) }));
            }
          });
        }
        await pool(jobs, COLLECT_CONCURRENCY);
        head = blobregAll(hour, shardHeads);
        metaWrites.set("blobreg:hour", hour);
        metaWrites.set("blobreg:head", head);
      }
      head ??= prevHeads.get(BLOBREG_CID) ?? null;
      if (head) heads.set(BLOBREG_CID, head);
    };
    const dirlog = async (): Promise<void> => {
      try {
        const r = await this.timed(
          logDb(this.env)
            .prepare("SELECT seq, h FROM dirlog ORDER BY seq DESC LIMIT 1")
            .first<{ seq: number; h: string }>(),
        );
        const h = r ? fromB64u(r.h) : ZERO32;
        if (h.length !== 32) throw new Error("dirlog: bad head");
        heads.set(DIRLOG_CID, h);
      } catch (e) {
        if (/no such table/i.test(errMsg(e))) heads.set(DIRLOG_CID, ZERO32);
        else keep(DIRLOG_CID, e);
      }
    };

    const jobs: (() => Promise<void>)[] = [];
    for (let i = 0; i < this.shardsOf(E); i++) jobs.push(() => shard(E, i, false));
    for (let g = 0; g < this.inboxBucketsOf(E); g++) jobs.push(() => inbox(E, g, false));
    jobs.push(blobreg, dirlog);
    if (E - 1 >= Math.max(eFirst, 0)) {
      for (let i = 0; i < this.shardsOf(E - 1); i++) jobs.push(() => shard(E - 1, i, true));
      for (let g = 0; g < this.inboxBucketsOf(E - 1); g++) jobs.push(() => inbox(E - 1, g, true));
    }
    await pool(jobs, COLLECT_CONCURRENCY);
    await this.sweep(now, E, eFirst, metaWrites);

    const list = [...heads]
      .map(([cid, head]): Head => ({ cid, head }))
      .sort((a, b) => byteCmp(utf8(a.cid), utf8(b.cid)));
    const headsEnc = encodeHeads(list);
    const hd = H(headsEnc);

    if (prev && equalBytes(prev.hd, hd)) {
      // Same heads: no new checkpoint (q grows at most once per 60 s). A sealed head in this list already
      // appeared in checkpoint prev.q, so its final mark is due as well.
      this.commit(null, metaWrites);
      return;
    }
    const keys = serverKeys(this.env);
    if (!keys) throw new Error("server misconfigured: SRV_KEY missing or malformed");
    const q = (prev?.q ?? 0) + 1;
    const sec = Math.max(secOf(now), prev?.sec ?? 0);
    const C = ckptC(prev?.C ?? ZERO32, q, sec, hd);
    const sig = await srvSign(keys, ckptSigMsg(q, C));
    // The list goes to R2 first: a row is never committed without it. An object left by a commit that failed
    // afterwards was never served (no row named it) and is overwritten when q is built again.
    try {
      await this.env.BLOBS.put(headsKey(q), headsEnc, { httpMetadata: { contentType: "application/octet-stream" } });
    } catch (e) {
      console.error(JSON.stringify({ msg: "checkpoint: the list did not reach R2; no checkpoint this tick", error: logErr(e) }));
      // The other meta stands; a final mark waits for the checkpoint that carries its head.
      for (const k of metaWrites.keys()) if (k.startsWith("final:")) metaWrites.delete(k);
      this.commit(null, metaWrites);
      return;
    }
    if ((this.latestRow()?.q ?? 0) !== q - 1) throw new Error("checkpoint: concurrent writer"); // single-flight: unreachable
    this.commit({ q, sec, hd, heads: new Uint8Array(0), C, sig }, metaWrites);
    this.latestHeads = { q, list };
  }

  /**
   * §9.5 "Sweep": once per UTC hour, head() on at most `sweepShards` shards of past eras, so that a sealed shard that
   * still holds rows arms its paging (§9.1). The shards (E, i) of the eras from `page:era` (the lowest era not known
   * to be paged) up to E_now − 2 are walked in order, resuming at `page:at` and wrapping around, skipping the shards
   * marked `paged:<E>:<i>` and the eras marked `paged:<E>`. A shard that answers `paged` is marked; an era whose
   * shards are all marked is marked instead (its shard marks deleted). A shard that fails stays unmarked and comes
   * round again after every other unpaged shard, so it never holds up the others.
   */
  private async sweep(now: number, E: number, eFirst: number, metaWrites: MetaWrites): Promise<void> {
    const hour = Math.floor(now / HOUR_MS);
    if ((this.kv.num("page:hour") ?? -1) >= hour) return;
    metaWrites.set("page:hour", hour);
    const top = E - 2;
    const eraMarked = (e: number): boolean => this.kv.num(`paged:${e}`) !== null || metaWrites.get(`paged:${e}`) === 1;
    const storedLo = this.kv.num("page:era");
    let lo = storedLo ?? Math.max(eFirst, 0);
    while (lo <= top && eraMarked(lo)) lo++;
    const picked: [number, number][] = [];
    const storedAt = this.kv.num("page:at");
    if (lo <= top && this.sweepShards > 0) {
      let e0 = storedAt === null ? lo : Math.floor(storedAt / SHARD_SPAN);
      let i0 = storedAt === null ? 0 : storedAt % SHARD_SPAN;
      if (e0 < lo || e0 > top) {
        e0 = lo;
        i0 = 0;
      }
      for (const pos of this.sweepOrder(lo, top, e0, i0)) {
        picked.push(pos);
        if (picked.length >= this.sweepShards) break;
      }
    }
    const pagedNow = new Set<string>();
    await pool(
      picked.map(([e, i]) => async () => {
        try {
          const h = await this.timed(Promise.resolve(shardStub(this.env, e, i).head(e, i)));
          if (h.paged) pagedNow.add(`${e}:${i}`);
        } catch (err) {
          console.error(JSON.stringify({ msg: "sweep: shard unreachable", E: e, error: logErr(err) }));
        }
      }),
      COLLECT_CONCURRENCY,
    );
    for (const e of new Set(picked.map(([pe]) => pe))) {
      const marked = this.markedShards(e);
      const S = this.shardsOf(e);
      let all = true;
      for (let i = 0; i < S && all; i++) if (!marked.has(i) && !pagedNow.has(`${e}:${i}`)) all = false;
      if (all) {
        metaWrites.set(`paged:${e}`, 1);
        for (const i of marked) metaWrites.set(`paged:${e}:${i}`, null);
      } else {
        for (const [pe, i] of picked) if (pe === e && pagedNow.has(`${e}:${i}`)) metaWrites.set(`paged:${e}:${i}`, 1);
      }
    }
    while (lo <= top && eraMarked(lo)) lo++;
    if (lo !== storedLo) metaWrites.set("page:era", lo);
    if (picked.length > 0) {
      const [e, i] = picked[picked.length - 1];
      const at = e * SHARD_SPAN + i + 1;
      if (at !== storedAt) metaWrites.set("page:at", at);
    }
  }

  /** The unpaged shards from (e0, i0) to the end of E_now − 2, then from `lo` round to just before (e0, i0). */
  private *sweepOrder(lo: number, top: number, e0: number, i0: number): Generator<[number, number]> {
    for (let e = e0; e <= top; e++) yield* this.unpagedShards(e, e === e0 ? i0 : 0, Infinity);
    for (let e = lo; e <= e0; e++) yield* this.unpagedShards(e, 0, e === e0 ? i0 : Infinity);
  }

  private *unpagedShards(e: number, from: number, to: number): Generator<[number, number]> {
    if (this.kv.num(`paged:${e}`) !== null) return;
    const marked = this.markedShards(e);
    const end = Math.min(to, this.shardsOf(e));
    for (let i = from; i < end; i++) if (!marked.has(i)) yield [e, i];
  }

  /** The shards of era e marked `paged:<e>:<i>` ( ':' < ';' bounds the keys of the era). */
  private markedShards(e: number): Set<number> {
    const rows = this.sql
      .exec<{ k: string }>("SELECT k FROM meta WHERE k > ? AND k < ?", `paged:${e}:`, `paged:${e};`)
      .toArray();
    return new Set(rows.map((r) => Number(r.k.slice(`paged:${e}:`.length))));
  }

  /** One transaction for the checkpoint row and its meta, and the next alarm in the same synchronous block. */
  private commit(cp: Checkpoint | null, metaWrites: MetaWrites): void {
    if (cp || metaWrites.size > 0) {
      this.ctx.storage.transactionSync(() => {
        if (cp) {
          this.sql.exec(
            "INSERT INTO cp (q, sec, hd, heads, C, sig) VALUES (?, ?, ?, x'', ?, ?)",
            cp.q,
            cp.sec,
            ab(cp.hd),
            ab(cp.C),
            ab(cp.sig),
          );
        }
        for (const [k, v] of metaWrites) {
          if (v === null) this.kv.del(k);
          else this.kv.set(k, v);
        }
      });
    }
    this.armNext();
  }
}
