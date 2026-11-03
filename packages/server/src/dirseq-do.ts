/**
 * DirSeqDO — the only writer of the directory (docs/PROTOCOL.md §9.6). One instance, "dirseq/v2", memory only.
 *
 * The Worker validates a registration or a wrap record (§10.6) and hands it here. The object keeps the dirlog head in
 * memory (read from D1 at start, and again after any failed write), assigns the next contiguous seqs, computes the
 * chain, and runs one atomic D1 batch for every write that arrived since the previous batch started: a burst of
 * registrations is a few batches, never a race on `dirlog.seq`. A UNIQUE failure of a user or wrap key with several
 * writes in the batch means nothing was written: each write is then retried alone, so the conflicting one answers
 * 409 and the others land. A `dirlog.seq` failure (another writer: a Worker of the previous release during a deploy)
 * makes it re-read the head and retry the batch once. Any other D1 failure fails the batch's writes (the Worker
 * answers 503 "directory unavailable"), and the head is re-read before the next one. D1 stays authoritative: the
 * object stores nothing.
 */
import { DurableObject } from "cloudflare:workers";
import { DIRLOG_USER, DIRLOG_WRAP, ZERO32, dirlogH, dirlogRefUser, dirlogRefWrap, fromB64u, type Bytes } from "@segv/protocol/proto";
import { dec64, enc64 } from "./b64";
import { CONFLICTS, HEAD_SQL, MAX_WRAPS_PER_UID, uniqueFailure } from "./directory";
import { logErr } from "./http";
import type { DirWrite, DirWriteResult } from "./types";

const USER_INSERT_SQL =
  "INSERT INTO user (uid, upre, handle, hpre, bundle, sig, reg_era, dirseq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)";
const WRAP_INSERT_SQL = "INSERT INTO wrap (uid, id, record, sig, dirseq) VALUES (?1, ?2, ?3, ?4, ?5)";
const DIRLOG_INSERT_SQL = "INSERT INTO dirlog (seq, kind, ref, h) VALUES (?1, ?2, ?3, ?4)";
const USERS_INC_SQL = "UPDATE dirmeta SET v = v + 1 WHERE k = 'users'";
const WRAP_COUNT_SQL = "SELECT count(*) AS n FROM wrap WHERE uid = ?1";

interface Pending {
  write: DirWrite;
  resolve: (r: DirWriteResult) => void;
  reject: (e: unknown) => void;
}
interface Head {
  seq: number;
  h: Bytes;
}

const isStr = (x: unknown): x is string => typeof x === "string";

function checkWrite(w: unknown): asserts w is DirWrite {
  const bad = (): never => {
    throw new TypeError("dirseq: malformed write");
  };
  if (typeof w !== "object" || w === null) bad();
  const o = w as Record<string, unknown>;
  const wrapOk = (x: unknown): boolean =>
    typeof x === "object" && x !== null && ["uid", "id", "record", "sig"].every((k) => isStr((x as Record<string, unknown>)[k]));
  if (o.kind === "wrap") {
    if (!wrapOk(o.wrap)) bad();
    return;
  }
  if (o.kind !== "user") bad();
  if (!isStr(o.uid) || !isStr(o.handle) || !isStr(o.bundle) || !isStr(o.sig)) bad();
  if (!Number.isInteger(o.upre) || !Number.isInteger(o.hpre) || !Number.isInteger(o.regEra)) bad();
  if (!Array.isArray(o.wraps) || o.wraps.length < 1 || !o.wraps.every(wrapOk)) bad();
}

export class DirSeqDO extends DurableObject<Env> {
  private queue: Pending[] = [];
  private flushing: Promise<void> | null = null;
  /** The dirlog head, or null when it must be read from D1 before the next batch. */
  private head: Head | null = null;

  /** Writes `write` after everything queued before it; resolves with its seqs, or the refusal (400 / 409). */
  append(write: DirWrite): Promise<DirWriteResult> {
    checkWrite(write);
    return new Promise<DirWriteResult>((resolve, reject) => {
      this.queue.push({ write, resolve, reject });
      this.kick();
    });
  }

  private kick(): void {
    if (this.flushing) return;
    this.flushing = this.flushLoop().finally(() => {
      this.flushing = null;
      if (this.queue.length > 0) this.kick();
    });
  }

  private async flushLoop(): Promise<void> {
    while (this.queue.length > 0) {
      const batch = this.queue.splice(0);
      try {
        await this.runBatch(batch, true);
      } catch (e) {
        // Nothing in runBatch throws past its own handlers except a broken binding: fail the round, never wedge it.
        this.head = null;
        for (const p of batch) p.reject(e);
      }
    }
  }

  private async readHead(): Promise<Head> {
    const row = await this.env.DB.prepare(HEAD_SQL).first<{ seq: number; h: string }>();
    return row ? { seq: row.seq, h: dec64(row.h) } : { seq: 0, h: ZERO32 };
  }

  /** Every pending write of `batch` in one D1 batch (see the file comment for the failure cases). */
  private async runBatch(batch: Pending[], retryOnSeq: boolean): Promise<void> {
    const db = this.env.DB;
    let head: Head;
    try {
      head = this.head ?? (this.head = await this.readHead());
    } catch (e) {
      for (const p of batch) p.reject(e);
      return;
    }
    // The cap of 64 wraps per uid, read now: there is no other writer, so it holds until the batch commits (§10.6).
    let live = batch;
    const wrapIdx = batch.flatMap((p, k) => (p.write.kind === "wrap" ? [k] : []));
    if (wrapIdx.length > 0) {
      let counts: D1Result[];
      try {
        counts = await db.batch(
          wrapIdx.map((k) => db.prepare(WRAP_COUNT_SQL).bind((batch[k].write as { wrap: { uid: string } }).wrap.uid)),
        );
      } catch (e) {
        this.head = null;
        for (const p of batch) p.reject(e);
        return;
      }
      const perUid = new Map<string, number>();
      const over = new Set<number>();
      wrapIdx.forEach((k, i) => {
        const uid = (batch[k].write as { wrap: { uid: string } }).wrap.uid;
        const n = perUid.get(uid) ?? (counts[i].results as { n: number }[])[0]?.n ?? 0;
        if (n >= MAX_WRAPS_PER_UID) over.add(k);
        else perUid.set(uid, n + 1);
      });
      for (const k of over) batch[k].resolve({ ok: false, status: 400, error: `too many wraps (at most ${MAX_WRAPS_PER_UID} per uid)` });
      live = batch.filter((_, k) => !over.has(k));
      if (live.length === 0) return;
    }
    // Contiguous seqs after the head, the chain, and the statements: rows, dirlog entries, the user count.
    let seq = head.seq;
    let prev = head.h;
    const stmts: D1PreparedStatement[] = [];
    const seqsOf: number[][] = [];
    for (const p of live) {
      const w = p.write;
      const entries =
        w.kind === "user"
          ? [
              { kind: DIRLOG_USER, ref: dirlogRefUser(w.bundle, fromB64u(w.sig)) },
              ...w.wraps.map((x) => ({ kind: DIRLOG_WRAP, ref: dirlogRefWrap(x.record, fromB64u(x.sig)) })),
            ]
          : [{ kind: DIRLOG_WRAP, ref: dirlogRefWrap(w.wrap.record, fromB64u(w.wrap.sig)) }];
      const seqs: number[] = [];
      const hs: Bytes[] = [];
      for (const en of entries) {
        seq++;
        prev = dirlogH(prev, seq, en.kind, en.ref);
        seqs.push(seq);
        hs.push(prev);
      }
      if (w.kind === "user") {
        stmts.push(db.prepare(USER_INSERT_SQL).bind(w.uid, w.upre, w.handle, w.hpre, w.bundle, w.sig, w.regEra, seqs[0]));
        w.wraps.forEach((x, i) => stmts.push(db.prepare(WRAP_INSERT_SQL).bind(x.uid, x.id, x.record, x.sig, seqs[1 + i])));
      } else {
        stmts.push(db.prepare(WRAP_INSERT_SQL).bind(w.wrap.uid, w.wrap.id, w.wrap.record, w.wrap.sig, seqs[0]));
      }
      entries.forEach((en, i) => stmts.push(db.prepare(DIRLOG_INSERT_SQL).bind(seqs[i], en.kind, enc64(en.ref), enc64(hs[i]))));
      if (w.kind === "user") stmts.push(db.prepare(USERS_INC_SQL));
      seqsOf.push(seqs);
    }
    try {
      await db.batch(stmts);
    } catch (e) {
      const col = uniqueFailure(e);
      if (col === "dirlog.seq") {
        // Another writer moved the head (a Worker of the previous release, during a deploy): once more on the new one.
        this.head = null;
        if (retryOnSeq) {
          console.error(JSON.stringify({ msg: "dirseq: the dirlog head moved under the writer; retrying once" }));
          return this.runBatch(live, false);
        }
        for (const p of live) p.reject(e);
        return;
      }
      if (col !== null && CONFLICTS[col]) {
        if (live.length === 1) {
          live[0].resolve({ ok: false, status: 409, error: CONFLICTS[col] });
          return;
        }
        // Nothing was written: one at a time, so the conflicting write answers 409 and the others land.
        for (const p of live) await this.runBatch([p], true);
        return;
      }
      this.head = null;
      console.error(JSON.stringify({ msg: "dirseq: write failed", error: logErr(e) }));
      for (const p of live) p.reject(e);
      return;
    }
    this.head = { seq, h: prev };
    live.forEach((p, k) => p.resolve({ ok: true, seqs: seqsOf[k] }));
  }
}
