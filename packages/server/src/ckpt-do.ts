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
 *  - Once per UTC hour it also wakes a few shards of past eras (head(), from 'page:era' up to E_now − 2) so that
 *    every sealed shard gets paged into R2 (§9.1 "Paging", §9.5 "Sweep"); eras found paged are marked 'paged:<E>'.
 *  - latest() / get(q) / range(after, limit) are the §10.9 reads.
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
type CpRow = { q: number; sec: number; hd: ArrayBuffer; heads: ArrayBuffer; C: ArrayBuffer; sig: ArrayBuffer };
interface Checkpoint {
  q: number;
  sec: number;
  hd: Uint8Array;
  heads: Uint8Array;
  C: Uint8Array;
  sig: Uint8Array;
}

/** The stored `heads` column: enc("segv.sh/v2/ckpt/heads", cid_1, head_1, …) over the list sorted by cid. */
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

  latest(): CkptRecord | null {
    const r = this.latestRow();
    return r ? this.record(r) : null;
  }

  get(q: number): CkptRecord | null {
    if (!Number.isSafeInteger(q) || q < 1) return null;
    const r = this.sql.exec<CpRow>("SELECT q, sec, hd, heads, C, sig FROM cp WHERE q = ?", q).toArray()[0];
    return r ? this.record(toCheckpoint(r)) : null;
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

  private record(c: Checkpoint): CkptRecord {
    return { q: c.q, sec: c.sec, hd: c.hd, C: c.C, sig: c.sig, heads: decodeHeads(c.heads) };
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
    const prevHeads = new Map((prev ? decodeHeads(prev.heads) : []).map((h) => [h.cid, h.head] as const));
    const heads = new Map<string, Uint8Array>();
    /** Meta written with the checkpoint (or alone when hd is unchanged): final marks, the hourly blobreg head. */
    const metaWrites = new Map<string, number | Uint8Array>();
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
    if ((this.latestRow()?.q ?? 0) !== q - 1) throw new Error("checkpoint: concurrent writer"); // single-flight: unreachable
    this.commit({ q, sec, hd, heads: headsEnc, C, sig }, metaWrites);
  }

  /**
   * §9.5 "Sweep": once per UTC hour, head() on the shards of past eras from `page:era` (the lowest era not known to
   * be paged) up to E_now − 2, at most `sweepShards` of them, so that a sealed shard that still holds rows arms its
   * paging (§9.1). An era whose shards all answer `paged` is marked and never asked again; the cursor skips marks.
   */
  private async sweep(now: number, E: number, eFirst: number, metaWrites: Map<string, number | Uint8Array>): Promise<void> {
    const hour = Math.floor(now / HOUR_MS);
    if ((this.kv.num("page:hour") ?? -1) >= hour) return;
    metaWrites.set("page:hour", hour);
    let cursor = this.kv.num("page:era") ?? Math.max(eFirst, 0);
    let calls = 0;
    for (let e = cursor; e <= E - 2 && calls < this.sweepShards; e++) {
      if (this.kv.num(`paged:${e}`) !== null) {
        if (e === cursor) cursor = e + 1;
        continue;
      }
      const S = this.shardsOf(e);
      let all = true;
      const jobs: (() => Promise<void>)[] = [];
      for (let i = 0; i < S; i++) {
        jobs.push(async () => {
          try {
            const h = await this.timed(Promise.resolve(shardStub(this.env, e, i).head(e, i)));
            if (!h.paged) all = false;
          } catch (err) {
            all = false;
            console.error(JSON.stringify({ msg: "sweep: shard unreachable", E: e, error: logErr(err) }));
          }
        });
      }
      calls += S;
      await pool(jobs, COLLECT_CONCURRENCY);
      if (all) {
        metaWrites.set(`paged:${e}`, 1);
        if (e === cursor) cursor = e + 1;
      }
    }
    if (cursor !== (this.kv.num("page:era") ?? -1)) metaWrites.set("page:era", cursor);
  }

  /** One transaction for the checkpoint row and its meta, and the next alarm in the same synchronous block. */
  private commit(cp: Checkpoint | null, metaWrites: Map<string, number | Uint8Array>): void {
    if (cp || metaWrites.size > 0) {
      this.ctx.storage.transactionSync(() => {
        if (cp) {
          this.sql.exec(
            "INSERT INTO cp (q, sec, hd, heads, C, sig) VALUES (?, ?, ?, ?, ?, ?)",
            cp.q,
            cp.sec,
            ab(cp.hd),
            ab(cp.heads),
            ab(cp.C),
            ab(cp.sig),
          );
        }
        for (const [k, v] of metaWrites) this.kv.set(k, v);
      });
    }
    this.armNext();
  }
}
