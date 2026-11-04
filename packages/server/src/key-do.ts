/**
 * KeyDO — the per-era inbox bucket keys (docs/PROTOCOL.md §9.3 "Buckets"). One instance, "keys/v2", SQLite.
 *
 * kbucket_E is a random 32-byte secret made the first time the Worker asks for era E and kept until the era leaves
 * the inbox retention; it is never derived from another secret and never written anywhere else, so a Worker secret
 * that leaks later gives no past era's bucket map. The Worker caches each key per isolate. Keys are made only for
 * eras in E_now − 3 .. era(now + SKEW) + 1 (the eras a client reads or posts to), and every call deletes the keys of
 * eras below E_now − 3.
 *
 * Time is read through the protected `clock` field so tests can override it.
 */
import { DurableObject } from "cloudflare:workers";
import { era, random } from "@segv/protocol/proto";
import { INBOX_RETENTION, v2Params } from "./env";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS k (E INTEGER PRIMARY KEY, key BLOB NOT NULL CHECK (length(key) = 32));
`;

export class KeyDO extends DurableObject<Env> {
  protected clock = (): number => Date.now();
  private readonly sql: SqlStorage;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(SCHEMA);
  }

  /** kbucket_E: made on the first call for E (within the window above), the same from then on. */
  bucketKey(E: number): Uint8Array {
    if (!Number.isInteger(E) || E < 0 || E > 0xfffe) throw new RangeError("keys: bad era");
    const now = this.clock();
    const { skew } = v2Params(this.env);
    const lo = era(now) - (INBOX_RETENTION - 1);
    const hi = era(now + skew * 1000) + 1;
    if (E < lo || E > hi) throw new RangeError("keys: era outside the inbox window");
    return this.ctx.storage.transactionSync((): Uint8Array => {
      this.sql.exec("DELETE FROM k WHERE E < ?", lo);
      const row = this.sql.exec<{ key: ArrayBuffer }>("SELECT key FROM k WHERE E = ?", E).toArray()[0];
      if (row) return new Uint8Array(row.key);
      const key = random(32);
      this.sql.exec("INSERT INTO k (E, key) VALUES (?, ?)", E, key.buffer as ArrayBuffer);
      return key;
    });
  }
}
