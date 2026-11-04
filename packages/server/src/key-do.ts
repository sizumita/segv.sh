/**
 * KeyDO — the per-era inbox bucket keys (docs/PROTOCOL.md §9.3 "Buckets"). One instance, "keys/v2", SQLite.
 *
 * kbucket_E is a random 32-byte secret made the first time the Worker asks for era E and kept until the era leaves
 * the inbox retention; it is never derived from another secret and never written anywhere else, so a Worker secret
 * that leaks later gives no past era's bucket map. The Worker caches each key per isolate. Keys are made only for
 * eras in era(now − SKEW) − 3 .. era(now + SKEW) + 1 (the eras a client reads or posts to, with the SKEW allowance of
 * a clock that runs ahead of the Worker's), and every call deletes the keys of eras below that window.
 *
 * β_E (INBOX_MAP) is pinned beside the key: the Worker asks once per isolate for every era it lists, with its β_E
 * (β = 0 included: no key is made or returned then). The first ask pins β_E, and an ask with another β throws, so a
 * map changed for an era the directory already listed fails loudly (the Worker answers 503) instead of listing other
 * buckets.
 *
 * Time is read through the protected `clock` field so tests can override it.
 */
import { DurableObject } from "cloudflare:workers";
import { era, random } from "@segv/protocol/proto";
import { INBOX_RETENTION, inboxBitsOf, v2Params } from "./env";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS k (E INTEGER PRIMARY KEY, key BLOB NOT NULL CHECK (length(key) = 32));
CREATE TABLE IF NOT EXISTS bits (E INTEGER PRIMARY KEY, b INTEGER NOT NULL CHECK (b BETWEEN 0 AND 16)) WITHOUT ROWID;
`;

export class KeyDO extends DurableObject<Env> {
  protected clock = (): number => Date.now();
  /** β_E of the deployment (§9.3); an instance field so tests can set a map without a deployment variable. */
  protected inboxBitsOf = (E: number): number => inboxBitsOf(v2Params(this.env).inboxMap, E);
  /** SKEW in seconds; an instance field so tests can set it. */
  protected skew = (): number => v2Params(this.env).skew;
  private readonly sql: SqlStorage;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(SCHEMA);
  }

  /**
   * kbucket_E for an era of 2^bits buckets (bits: the caller's β_E, the deployment's when absent): made on the first
   * call for E (within the window above), the same from then on; null for β_E = 0. Throws when β_E differs from the
   * one pinned for E.
   */
  bucketKey(E: number, bits?: number): Uint8Array | null {
    if (!Number.isInteger(E) || E < 0 || E > 0xfffe) throw new RangeError("keys: bad era");
    const b = bits ?? this.inboxBitsOf(E);
    if (!Number.isInteger(b) || b < 0 || b > 16) throw new RangeError("keys: bad bucket bits");
    const now = this.clock();
    const skew = this.skew();
    const lo = era(now - skew * 1000) - (INBOX_RETENTION - 1);
    const hi = era(now + skew * 1000) + 1;
    if (E < lo || E > hi) throw new RangeError("keys: era outside the inbox window");
    return this.ctx.storage.transactionSync((): Uint8Array | null => {
      this.sql.exec("DELETE FROM k WHERE E < ?", lo);
      this.sql.exec("DELETE FROM bits WHERE E < ?", lo);
      const pinned = this.sql.exec<{ b: number }>("SELECT b FROM bits WHERE E = ?", E).toArray()[0];
      if (pinned && pinned.b !== b) throw new Error(`keys: INBOX_MAP differs from the bucket count pinned for era ${E}`);
      if (!pinned) this.sql.exec("INSERT INTO bits (E, b) VALUES (?, ?)", E, b);
      if (b === 0) return null;
      const row = this.sql.exec<{ key: ArrayBuffer }>("SELECT key FROM k WHERE E = ?", E).toArray()[0];
      if (row) return new Uint8Array(row.key);
      const key = random(32);
      this.sql.exec("INSERT INTO k (E, key) VALUES (?, ?)", E, key.buffer as ArrayBuffer);
      return key;
    });
  }
}
