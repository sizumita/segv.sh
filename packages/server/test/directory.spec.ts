/**
 * The v2 D1 directory (docs/PROTOCOL.md §2.4–§2.5, §9.6, §10.6), calling
 * packages/server/src/directory.ts directly inside workerd (the HTTP layer is tested separately).
 */
import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { ed25519 } from "@noble/curves/ed25519.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as P from "@segv/protocol/proto";
import { HttpError, ed25519Verify } from "../src/http";
import {
  DIR_RETRY_AFTER_S,
  MAX_WRAPS_PER_ID,
  MAX_WRAPS_PER_UID,
  PREFIX_PAGE,
  P_CACHE_MS,
  P_RETRY_MS,
  PrefixBitsError,
  _resetDirectoryCacheForTests,
  currentP,
  dirAddWrap,
  dirByPrefix,
  dirByUid,
  dirRegister,
  dirWrapsById,
  dirlogHead,
  dirlogPage,
  prefixSql,
  uniqueFailure,
  widePrefix,
  type DirUser,
  type DirlogEntry,
} from "../src/directory";
import type { DirSeqDO } from "../src/dirseq-do";
import { dirShardOf } from "../src/env";
import { dirSeqStub, type DirWrite, type DirWriteResult } from "../src/types";
import { envWith, mixedOrderRegistration } from "./helpers";

// ───────────── accounts (proto) ─────────────

type Signed = { record: string; sig: string };

interface Account {
  AK: Uint8Array;
  ident: P.Identity;
  uid: Uint8Array;
  uidB64: string;
  handle: string;
  bundle: string;
  sig: string;
  credId: Uint8Array;
  cred: P.UnlockKey;
  passkey: Signed;
  recId: Uint8Array;
  rec: P.UnlockKey & { id: Uint8Array };
  recovery: Signed;
}

const freshHandle = (): string => `t_${P.hex(P.random(8))}`;

function makeAccount(handle = freshHandle(), uid = P.random(16), credId = P.random(20)): Account {
  const AK = P.random(32);
  const ident = P.deriveIdentity(AK);
  const now = Date.now();
  const { bundle, sig } = P.makeBundle(uid, handle, ident, now);
  const cred = P.credKem(P.random(32), credId);
  const rec = P.recoveryKem(P.newRecoveryCode());
  return {
    AK,
    ident,
    uid,
    uidB64: P.b64u(uid),
    handle,
    bundle,
    sig,
    credId,
    cred,
    passkey: P.makeWrap(uid, "passkey", credId, cred, AK, ident, now),
    recId: rec.id,
    rec,
    recovery: P.makeWrap(uid, "recovery", rec.id, rec, AK, ident, now),
  };
}

/** A signed wrap record as the DirSeqDO takes it (§9.6): the row of the record, with its id. */
const wrapOf = (a: Account, w: Signed) => ({
  uid: a.uidB64,
  id: P.b64u(P.parseWrap(w.record, w.sig).id),
  record: w.record,
  sig: w.sig,
});
/** A new passkey wrap of `a`'s AK under a fresh credential (id `credId`). */
const newPasskey = (a: Account, credId = P.random(16)): Signed =>
  P.makeWrap(a.uid, "passkey", credId, P.credKem(P.random(32), credId), a.AK, a.ident, Date.now());

const registerBody = (
  a: Account,
  wraps: unknown[] = [a.passkey, a.recovery],
): Record<string, unknown> => ({
  bundle: a.bundle,
  sig: a.sig,
  wraps,
});
const register = (a: Account, wraps?: unknown[]) =>
  dirRegister(env, registerBody(a, wraps), Date.now());

/** Signs arbitrary bundle text (or fields) with `a`'s key, so only the form can be wrong. */
function signBundle(
  a: Account,
  b: string | Record<string, unknown>,
): { bundle: string; sig: string } {
  const bundle = typeof b === "string" ? b : JSON.stringify(b);
  return { bundle, sig: P.b64u(P.sign(P.bundleSigMsg(bundle), a.ident.sigSk)) };
}
function signRecord(a: Account, r: string | Record<string, unknown>): Signed {
  const record = typeof r === "string" ? r : JSON.stringify(r);
  return { record, sig: P.b64u(P.sign(P.wrapSigMsg(record), a.ident.sigSk)) };
}
const fields = (text: string) => JSON.parse(text) as Record<string, unknown>;
/** Same fields in another key order. */
const reorder = (o: Record<string, unknown>, keys: string[]) =>
  Object.fromEntries(keys.map((k) => [k, o[k]]));

/** A canonical-alphabet b64u string with non-zero leftover bits (rejected by strict decoders). */
function nonCanonical(s: string): string {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const v = A.indexOf(s[s.length - 1]);
  return s.slice(0, -1) + A[(v & 0x30) | 1];
}

// ───────────── assertions and D1 inspection ─────────────

async function rejects(p: Promise<unknown>, status: number, msg?: RegExp): Promise<HttpError> {
  let err: unknown = null;
  try {
    await p;
  } catch (e) {
    err = e;
  }
  expect(err, `expected HttpError ${status}`).toBeInstanceOf(HttpError);
  const he = err as HttpError;
  expect(he.status, he.message).toBe(status);
  if (msg) expect(he.message).toMatch(msg);
  return he;
}

/** The user databases of the test deployment (DIR_SHARDS = 2, ../wrangler.test.jsonc; §9.6). */
const USER_DBS = [env.DB, env.DB1];

/** The rows of `sql` from every user database (user, wrap), concatenated. */
async function all<T>(sql: string, ...args: unknown[]): Promise<T[]> {
  const pages = await Promise.all(
    USER_DBS.map((db) =>
      db
        .prepare(sql)
        .bind(...args)
        .all<T>(),
    ),
  );
  return pages.flatMap((pg) => pg.results);
}

/** The rows of `sql` from the log database (dirlog, dirmeta). */
async function logAll<T>(sql: string, ...args: unknown[]): Promise<T[]> {
  return (
    await env.DIRLOG.prepare(sql)
      .bind(...args)
      .all<T>()
  ).results;
}

const count = (rows: { n: number }[]): number => rows.reduce((t, r) => t + r.n, 0);

/** Row counts over the user databases, the dirlog head seq and dirmeta.users. */
async function dirState() {
  const [u, w] = await Promise.all([
    all<{ n: number }>("SELECT count(*) AS n FROM user"),
    all<{ n: number }>("SELECT count(*) AS n FROM wrap"),
  ]);
  const [l, m] = await env.DIRLOG.batch<{ n: number }>([
    env.DIRLOG.prepare("SELECT coalesce(max(seq), 0) AS n FROM dirlog"),
    env.DIRLOG.prepare("SELECT v AS n FROM dirmeta WHERE k = 'users'"),
  ]);
  return { users: count(u), wraps: count(w), head: l.results[0].n, meta: m.results[0].n };
}

/** The seqs waiting in the DirSeqDO's write-ahead log (§9.6). */
const walSeqs = (): Promise<number[]> =>
  runInDurableObject(dirSeqStub(env), (_inst: DirSeqDO, state) =>
    state.storage.sql
      .exec<{ seq: number }>("SELECT seq FROM wal ORDER BY seq")
      .toArray()
      .map((r) => r.seq),
  );

/** Pages the whole dirlog and recomputes the chain from ZERO32: contiguous seqs from 1, every h matches. */
async function verifiedDirlog(): Promise<DirlogEntry[]> {
  const out: DirlogEntry[] = [];
  let head: { seq: number; h: string };
  for (let after = 0; ;) {
    const pg = await dirlogPage(env, after, 1000);
    out.push(...pg.entries);
    head = pg.head;
    if (pg.entries.length < 1000) break;
    after = pg.entries[pg.entries.length - 1].seq;
  }
  let prev: Uint8Array = P.ZERO32;
  out.forEach((e, i) => {
    expect(e.seq).toBe(i + 1);
    expect([P.DIRLOG_USER, P.DIRLOG_WRAP]).toContain(e.kind);
    prev = P.dirlogH(prev, e.seq, e.kind, P.fromB64u(e.ref));
    expect(e.h, `h at seq ${e.seq}`).toBe(P.b64u(prev));
  });
  expect(head).toEqual({ seq: out.length, h: P.b64u(prev) });
  return out;
}

const userRef = (bundle: string, sig: string) => P.b64u(P.dirlogRefUser(bundle, P.fromB64u(sig)));
const wrapRef = (w: Signed) => P.b64u(P.dirlogRefWrap(w.record, P.fromB64u(w.sig)));

/** Temporarily sets dirmeta.users (P is derived from it) and drops the cached P. */
async function withUsers<T>(n: number, f: () => Promise<T>): Promise<T> {
  const before = (await env.DIRLOG.prepare("SELECT v FROM dirmeta WHERE k = 'users'").first<{
    v: number;
  }>())!.v;
  await env.DIRLOG.prepare("UPDATE dirmeta SET v = ?1 WHERE k = 'users'").bind(n).run();
  _resetDirectoryCacheForTests();
  try {
    return await f();
  } finally {
    await env.DIRLOG.prepare("UPDATE dirmeta SET v = ?1 WHERE k = 'users'").bind(before).run();
    _resetDirectoryCacheForTests();
  }
}

/** Runs `fn` with the DirSeqDO's bindings replaced by `patched` (its cached head is dropped before and after). */
async function withDirSeqEnv<T>(patched: Env, fn: () => Promise<T>): Promise<T> {
  type Self = { env: Env; head: unknown };
  let real: Env | undefined;
  await runInDurableObject(dirSeqStub(env), (inst: DirSeqDO) => {
    const self = inst as unknown as Self;
    real = self.env;
    self.env = patched;
    self.head = null;
  });
  try {
    return await fn();
  } finally {
    await runInDurableObject(dirSeqStub(env), (inst: DirSeqDO) => {
      const self = inst as unknown as Self;
      self.env = real!;
      self.head = null;
    });
  }
}

/** Every page of a prefix query. */
async function allPages(kind: "h" | "u", p: number, x: number): Promise<DirUser[]> {
  const out: DirUser[] = [];
  let after: string | null = null;
  for (;;) {
    const pg = await dirByPrefix(env, kind, p, x, after);
    expect(pg.p).toBe(p);
    out.push(...pg.users);
    if (!pg.more) return out;
    expect(pg.users).toHaveLength(PREFIX_PAGE);
    after = pg.users[pg.users.length - 1].uid;
  }
}

const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

beforeEach(() => _resetDirectoryCacheForTests());
afterEach(() => vi.restoreAllMocks());

// ───────────── tests ─────────────

describe("schema", () => {
  it("starts empty: dirlog head {0, b64u(ZERO32)}, P = 0, no rows (storage is per test file)", async () => {
    expect(await dirState()).toEqual({ users: 0, wraps: 0, head: 0, meta: 0 });
    const empty = { seq: 0, h: P.b64u(P.ZERO32) };
    expect(await dirlogHead(env)).toEqual(empty);
    expect(await dirlogPage(env, 0, 1000)).toEqual({ entries: [], head: empty });
    expect(await currentP(env)).toBe(0);
    expect(await dirByPrefix(env, "h", 0, 0, null)).toEqual({ p: 0, users: [], more: false });
    expect(await dirByPrefix(env, "u", 1, 1, null)).toEqual({ p: 1, users: [], more: false });
  });
  it("creates user / wrap / dirlog / dirmeta with the §9.6 indexes", async () => {
    const objs = await all<{ type: string; name: string }>(
      "SELECT type, name FROM sqlite_master WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'",
    );
    const names = objs.map((o) => o.name);
    for (const n of ["user", "wrap", "dirlog", "dirmeta", "user_upre", "user_hpre", "wrap_id"]) {
      expect(names).toContain(n);
    }
    // v1's tables are gone (packages/server/migrations/0001_init.sql holds only the directory).
    for (const n of ["users", "wraps", "blobs"]) expect(names).not.toContain(n);
    const meta = await logAll<{ k: string; v: number }>("SELECT k, v FROM dirmeta");
    expect(meta).toEqual([{ k: "users", v: 0 }]); // inserted by the migration (§9.6)
  });
  it("on the freshly migrated database the first registration makes dirmeta.users = 1, and currentP() follows it", async () => {
    // Storage is per test file, and this is the file's first registration (the directory is still empty).
    expect(await dirState()).toEqual({ users: 0, wraps: 0, head: 0, meta: 0 });
    await register(makeAccount());
    expect(await dirState()).toEqual({ users: 1, wraps: 2, head: 3, meta: 1 });
    _resetDirectoryCacheForTests();
    expect(await currentP(env)).toBe(P.serverP(1));
    // P follows the registrations' increments: at 63 users P = 0, and the 64th registration makes P = 1.
    await env.DIRLOG.prepare("UPDATE dirmeta SET v = 63 WHERE k = 'users'").run();
    try {
      _resetDirectoryCacheForTests();
      expect(await currentP(env)).toBe(0);
      await register(makeAccount());
      expect((await dirState()).meta).toBe(64);
      _resetDirectoryCacheForTests();
      expect(await currentP(env)).toBe(1);
      expect(P.serverP(64)).toBe(1);
    } finally {
      await env.DIRLOG.prepare("UPDATE dirmeta SET v = ?1 WHERE k = 'users'")
        .bind((await dirState()).users)
        .run();
      _resetDirectoryCacheForTests();
    }
    expect(await dirState()).toMatchObject({ users: 2, meta: 2 });
  });
});

describe("dirRegister", () => {
  it("writes the user, its wraps, their dirlog entries and dirmeta.users in one atomic batch", async () => {
    const a = makeAccount();
    const s0 = await dirState();
    const h0 = await dirlogHead(env);
    expect(h0.seq).toBe(s0.head);
    const now = Date.now();
    const { dirseq } = await register(a);
    expect(dirseq).toBe(s0.head + 1);

    const s1 = await dirState();
    expect(s1).toEqual({
      users: s0.users + 1,
      wraps: s0.wraps + 2,
      head: s0.head + 3,
      meta: s0.meta + 1,
    });

    const [u] = await all<Record<string, unknown>>("SELECT * FROM user WHERE uid = ?1", a.uidB64);
    expect(u).toEqual({
      uid: a.uidB64,
      upre: P.upre(a.uid),
      handle: a.handle,
      hpre: P.hpre(a.handle),
      bundle: a.bundle,
      sig: a.sig,
      reg_era: P.era(now),
      dirseq,
    });
    const wraps = await all<Record<string, unknown>>(
      "SELECT * FROM wrap WHERE uid = ?1 ORDER BY dirseq",
      a.uidB64,
    );
    expect(wraps).toEqual([
      {
        uid: a.uidB64,
        id: P.b64u(a.credId),
        record: a.passkey.record,
        sig: a.passkey.sig,
        dirseq: dirseq + 1,
      },
      {
        uid: a.uidB64,
        id: P.b64u(a.recId),
        record: a.recovery.record,
        sig: a.recovery.sig,
        dirseq: dirseq + 2,
      },
    ]);

    // dirlog: user first, then the wraps, chained from the previous head.
    const { entries, head } = await dirlogPage(env, s0.head, 10);
    expect(entries.map((e) => [e.seq, e.kind, e.ref])).toEqual([
      [dirseq, P.DIRLOG_USER, userRef(a.bundle, a.sig)],
      [dirseq + 1, P.DIRLOG_WRAP, wrapRef(a.passkey)],
      [dirseq + 2, P.DIRLOG_WRAP, wrapRef(a.recovery)],
    ]);
    let prev = P.fromB64u(h0.h);
    for (const e of entries) {
      prev = P.dirlogH(prev, e.seq, e.kind, P.fromB64u(e.ref));
      expect(e.h).toBe(P.b64u(prev));
    }
    expect(head).toEqual({ seq: dirseq + 2, h: P.b64u(prev) });
    expect(await dirlogHead(env)).toEqual(head);

    // Exact lookups: own bundle by uid; passkey and recovery login by id (the wraps open to the AK).
    const me = await dirByUid(env, a.uidB64);
    expect(me).toEqual({
      uid: a.uidB64,
      handle: a.handle,
      bundle: a.bundle,
      sig: a.sig,
      regEra: P.era(now),
      dirseq,
    });
    const user = P.verifyBundle(me!.bundle, me!.sig);
    const pk = await dirWrapsById(env, P.b64u(a.credId), a.uidB64);
    expect(pk).toEqual([
      { uid: a.uidB64, record: a.passkey.record, sig: a.passkey.sig, dirseq: dirseq + 1 },
    ]);
    const pw = P.verifyWrap(pk[0].record, pk[0].sig, user.sigPk);
    expect(P.equalBytes(P.unwrapAK(pw, a.cred, user.sigPk), a.AK)).toBe(true);
    const rk = await dirWrapsById(env, P.b64u(a.recId), null);
    expect(rk.map((w) => w.dirseq)).toEqual([dirseq + 2]);
    const rw = P.verifyWrap(rk[0].record, rk[0].sig, user.sigPk);
    expect(P.equalBytes(P.unwrapAK(rw, a.rec, user.sigPk), a.AK)).toBe(true);
  });

  it("accepts the boundary sizes: 1- and 1023-byte credential ids, 3- and 20-character handles", async () => {
    const short = makeAccount("a_" + P.hex(P.random(1)).slice(0, 1), undefined, P.random(1));
    expect(short.handle).toHaveLength(3);
    const long = makeAccount(`l_${P.hex(P.random(9))}`, undefined, P.random(P.MAX_ID_LEN));
    expect(long.handle).toHaveLength(20);
    // a 3-character handle has only 37^3 values; retry on the (unlikely) collision with an earlier run
    await register(short).catch((e: unknown) => {
      if (!(e instanceof HttpError && e.status === 409)) throw e;
    });
    const { dirseq } = await register(long, [long.passkey]);
    expect((await dirWrapsById(env, P.b64u(long.credId), null)).map((w) => w.dirseq)).toEqual([
      dirseq + 1,
    ]);
  });

  it("409 on a taken handle or uid, and nothing is written", async () => {
    const a = makeAccount();
    await register(a);
    const s0 = await dirState();
    const h0 = await dirlogHead(env);

    const sameHandle = makeAccount(a.handle);
    await rejects(register(sameHandle), 409, /handle/);
    const sameUid = makeAccount(undefined, a.uid);
    await rejects(register(sameUid), 409, /uid/);

    expect(await dirState()).toEqual(s0);
    expect(await dirlogHead(env)).toEqual(h0);
    expect(await dirWrapsById(env, P.b64u(sameHandle.credId), null)).toEqual([]);
    expect(await dirWrapsById(env, P.b64u(sameUid.credId), null)).toEqual([]);
    expect((await dirByUid(env, a.uidB64))!.bundle).toBe(a.bundle);
  });

  it("400 on a bad bundle signature; nothing is written", async () => {
    const a = makeAccount();
    const s0 = await dirState();
    const sig = P.fromB64u(a.sig);
    sig[0] ^= 1;
    await rejects(
      dirRegister(env, { ...registerBody(a), sig: P.b64u(sig) }, Date.now()),
      400,
      /signature/,
    );
    // a valid signature over other text
    const other = signBundle(a, { ...fields(a.bundle), ts: 1 });
    await rejects(
      dirRegister(env, { ...registerBody(a), sig: other.sig }, Date.now()),
      400,
      /signature/,
    );
    expect(await dirByUid(env, a.uidB64)).toBeNull();
    expect(await dirState()).toEqual(s0);
  });

  it("400 on a wrap for another uid or signed by another key", async () => {
    const a = makeAccount();
    const b = makeAccount();
    // b's record (b's uid, b's key)
    await rejects(register(a, [a.passkey, b.passkey]), 400, /wraps\[1\]: uid/);
    // a's uid, signed by b's key
    const forged = P.makeWrap(
      a.uid,
      "passkey",
      P.random(16),
      P.credKem(P.random(32), P.random(16)),
      a.AK,
      b.ident,
      Date.now(),
    );
    await rejects(register(a, [forged]), 400, /wraps\[0\]: bad signature/);
    await rejects(register(a, [a.recovery, forged]), 400, /wraps\[1\]: bad signature/);
    expect(await dirByUid(env, a.uidB64)).toBeNull();
  });

  it("400 on malformed bodies, wrap counts and duplicate ids", async () => {
    const a = makeAccount();
    const s0 = await dirState();
    const sameId = newPasskey(a, a.credId); // another record under the same credential id
    const cases: [string, unknown][] = [
      ["no wraps", registerBody(a, [])],
      [
        "5 wraps",
        registerBody(a, [a.passkey, a.recovery, newPasskey(a), newPasskey(a), newPasskey(a)]),
      ],
      ["duplicate record", registerBody(a, [a.passkey, a.passkey])],
      ["duplicate id", registerBody(a, [a.passkey, sameId])],
      ["wraps not an array", { ...registerBody(a), wraps: a.passkey }],
      ["unknown field", { ...registerBody(a), extra: 1 }],
      ["missing wraps", { bundle: a.bundle, sig: a.sig }],
      ["missing sig", { bundle: a.bundle, wraps: [a.passkey] }],
      ["wrap with an extra key", registerBody(a, [{ ...a.passkey, x: 1 }])],
      ["wrap without sig", registerBody(a, [{ record: a.passkey.record }])],
      ["wrap not an object", registerBody(a, ["x"])],
      ["sig not a string", { ...registerBody(a), sig: 42 }],
      ["bundle not a string", { ...registerBody(a), bundle: fields(a.bundle) }],
      ["bundle not JSON", { ...registerBody(a), bundle: "{not json" }],
      ["bundle a JSON array", { ...registerBody(a), bundle: "[]" }],
      ["body an array", [registerBody(a)]],
      ["body null", null],
    ];
    for (const [what, body] of cases) {
      await rejects(dirRegister(env, body as Record<string, unknown>, Date.now()), 400).catch(
        (e: unknown) => {
          throw new Error(`${what}: ${String(e)}`);
        },
      );
    }
    expect(await dirState()).toEqual(s0);
  });

  it("400 on non-canonical bundles, even when correctly signed", async () => {
    const a = makeAccount();
    const f = fields(a.bundle);
    const h = a.handle;
    const texts: [string, string | Record<string, unknown>][] = [
      ["key order", reorder(f, ["uid", "v", "handle", "sig", "kem", "ts"])],
      ["extra key", { ...f, x: 1 }],
      ["missing key", reorder(f, ["v", "uid", "handle", "sig", "kem"])],
      ["whitespace", a.bundle.replace('{"v":2,', '{"v":2, ')],
      ["trailing whitespace", a.bundle + " "],
      ["duplicate key", a.bundle.replace('{"v":2,', '{"v":2,"v":2,')],
      ["number spelling", a.bundle.replace('{"v":2,', '{"v":2.0,')],
      [
        "escaped character",
        a.bundle.replace(
          `"handle":"${h}"`,
          `"handle":"\\u00${h.charCodeAt(0).toString(16)}${h.slice(1)}"`,
        ),
      ],
    ];
    for (const [what, t] of texts) {
      const b = signBundle(a, t);
      expect(b.bundle, what).not.toBe(a.bundle);
      await rejects(
        dirRegister(env, { ...b, wraps: [a.passkey] }, Date.now()),
        400,
        /invalid bundle/,
      ).catch((e: unknown) => {
        throw new Error(`${what}: ${String(e)}`);
      });
    }
    expect(await dirByUid(env, a.uidB64)).toBeNull();
  });

  it("400 on bad bundle fields and sizes", async () => {
    const a = makeAccount();
    const f = fields(a.bundle);
    const uid15 = P.b64u(a.uid.subarray(0, 15));
    const cases: [string, Record<string, unknown>][] = [
      ["v 1", { ...f, v: 1 }],
      ["v string", { ...f, v: "2" }],
      ["uid 15 B", { ...f, uid: uid15 }],
      ["uid 17 B", { ...f, uid: P.b64u(P.concat(a.uid, P.random(1))) }],
      ["uid padded", { ...f, uid: `${a.uidB64}==` }],
      ["uid non-canonical", { ...f, uid: nonCanonical(a.uidB64) }],
      ["uid std alphabet", { ...f, uid: a.uidB64.replace(/[-_]/g, "+").padEnd(22, "+") + "/" }],
      ["sig 31 B", { ...f, sig: P.b64u(a.ident.sigPk.subarray(0, 31)) }],
      ["sig 33 B", { ...f, sig: P.b64u(P.concat(a.ident.sigPk, P.random(1))) }],
      ["kem 1215 B", { ...f, kem: P.b64u(a.ident.kemPk.subarray(0, 1215)) }],
      ["kem 1217 B", { ...f, kem: P.b64u(P.concat(a.ident.kemPk, P.random(1))) }],
      ["handle uppercase", { ...f, handle: "Bad_Handle" }],
      ["handle hyphen", { ...f, handle: "bad-handle" }],
      ["handle 2 chars", { ...f, handle: "ab" }],
      ["handle 21 chars", { ...f, handle: "a".repeat(21) }],
      ["handle number", { ...f, handle: 123 }],
      ["ts negative", { ...f, ts: -1 }],
      ["ts fraction", { ...f, ts: 1.5 }],
      ["ts string", { ...f, ts: "1" }],
      ["ts unsafe", { ...f, ts: 2 ** 53 }],
    ];
    for (const [what, o] of cases) {
      const b = signBundle(a, o);
      await rejects(dirRegister(env, { ...b, wraps: [a.passkey] }, Date.now()), 400).catch(
        (e: unknown) => {
          throw new Error(`${what}: ${String(e)}`);
        },
      );
    }
    // the bundle signature itself: 63 / 65 bytes, padded, non-canonical
    const sig = P.fromB64u(a.sig);
    for (const s of [
      P.b64u(sig.subarray(0, 63)),
      P.b64u(P.concat(sig, P.random(1))),
      `${a.sig}==`,
      nonCanonical(a.sig),
    ]) {
      await rejects(dirRegister(env, { ...registerBody(a), sig: s }, Date.now()), 400);
    }
    // over 8 KiB (checked before parsing)
    await rejects(
      dirRegister(env, { ...registerBody(a), bundle: a.bundle + " ".repeat(8192) }, Date.now()),
      400,
      /too large/,
    );
    expect(await dirByUid(env, a.uidB64)).toBeNull();
  });

  it("400 on non-canonical or mis-sized wrap records, even when correctly signed", async () => {
    const a = makeAccount();
    const f = fields(a.passkey.record);
    const r = fields(a.recovery.record);
    const cases: [string, string | Record<string, unknown>][] = [
      ["key order", reorder(f, ["v", "kind", "uid", "id", "kem", "wrap", "ts"])],
      ["extra key", { ...f, x: 1 }],
      ["missing key", reorder(f, ["v", "uid", "kind", "id", "kem", "wrap"])],
      ["whitespace", a.passkey.record.replace('{"v":2,', '{"v":2, ')],
      ["duplicate key", a.passkey.record.replace('{"v":2,', '{"v":2,"v":2,')],
      ["v 1", { ...f, v: 1 }],
      ["kind", { ...f, kind: "password" }],
      ["empty id", { ...f, id: "" }],
      ["id 1024 B", { ...f, id: P.b64u(P.random(1024)) }],
      ["id padded", { ...f, id: `${f.id as string}=` }],
      ["id non-canonical", { ...f, id: nonCanonical(f.id as string) }],
      ["recovery id 15 B", { ...r, id: P.b64u(a.recId.subarray(0, 15)) }],
      ["recovery id 17 B", { ...r, id: P.b64u(P.concat(a.recId, P.random(1))) }],
      ["uid 15 B", { ...f, uid: P.b64u(a.uid.subarray(0, 15)) }],
      ["kem 1215 B", { ...f, kem: P.b64u(P.fromB64u(f.kem as string).subarray(0, 1215)) }],
      ["wrap 1191 B", { ...f, wrap: P.b64u(P.fromB64u(f.wrap as string).subarray(0, 1191)) }],
      ["wrap 1193 B", { ...f, wrap: P.b64u(P.concat(P.fromB64u(f.wrap as string), P.random(1))) }],
      ["ts negative", { ...f, ts: -1 }],
    ];
    for (const [what, o] of cases) {
      const w = signRecord(a, o);
      await rejects(register(a, [w]), 400, /wrap/).catch((e: unknown) => {
        throw new Error(`${what}: ${String(e)}`);
      });
    }
    const sig = P.fromB64u(a.passkey.sig);
    await rejects(
      register(a, [{ record: a.passkey.record, sig: P.b64u(sig.subarray(0, 63)) }]),
      400,
    );
    await rejects(register(a, [{ record: a.passkey.record, sig: 7 }]), 400);
    await rejects(register(a, [{ record: fields(a.passkey.record), sig: a.passkey.sig }]), 400);
    await rejects(
      register(a, [{ record: a.passkey.record + " ".repeat(8192), sig: a.passkey.sig }]),
      400,
      /too large/,
    );
    expect(await dirByUid(env, a.uidB64)).toBeNull();
  });

  it("400 on bundles with unusable keys (correctly signed or forged)", async () => {
    const a = makeAccount();
    const s0 = await dirState();
    // A KEM key nobody can encapsulate to, correctly signed.
    const badKem = signBundle(a, {
      ...fields(a.bundle),
      kem: P.b64u(new Uint8Array(P.KEM_PK_LEN).fill(0xff)),
    });
    await rejects(dirRegister(env, { ...badKem, wraps: [a.passkey] }, Date.now()), 400, /KEM/);
    // A small-order signing key (the identity point) with the universal forgery R = identity, S = 0.
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const forgedSig = P.b64u(P.concat(identity, new Uint8Array(32)));
    const bundle = JSON.stringify({ ...fields(a.bundle), sig: P.b64u(identity) });
    const rec = { record: a.passkey.record, sig: forgedSig };
    await rejects(dirRegister(env, { bundle, sig: forgedSig, wraps: [rec] }, Date.now()), 400);
    expect(await dirState()).toEqual(s0);
  });

  it("400 on a mixed-order signing key (outside the prime-order subgroup) even when every signature verifies", async () => {
    const a = makeAccount();
    const { pk, body } = mixedOrderRegistration(a);
    const A = ed25519.Point.fromBytes(pk);
    expect(A.isSmallOrder()).toBe(false);
    expect(A.isTorsionFree()).toBe(false);
    // The Worker's own (WebCrypto) checks accept every signature: only checkUserKeys can refuse the key.
    expect(await ed25519Verify(pk, P.fromB64u(body.sig), P.bundleSigMsg(body.bundle))).toBe(true);
    for (const w of body.wraps)
      expect(await ed25519Verify(pk, P.fromB64u(w.sig), P.wrapSigMsg(w.record))).toBe(true);
    const s0 = await dirState();
    await rejects(dirRegister(env, body, Date.now()), 400, /signing key/);
    expect(await dirState()).toEqual(s0);
    expect(await dirByUid(env, a.uidB64)).toBeNull();
    // The same account with its real key registers (nothing of the refused attempt is left).
    await register(a);
    expect((await dirByUid(env, a.uidB64))?.bundle).toBe(a.bundle);
  });
});

/** An alias of a fresh owner (§2.6): AK_i, its derived uid and keys, and its handle for `c`; registered with no wraps. */
function makeAlias(
  i = 0,
  c = 0,
): {
  AKi: Uint8Array;
  ident: P.Identity;
  uid: Uint8Array;
  handle: string;
  bundle: string;
  sig: string;
} {
  const AKi = P.aliasKey(P.random(32), i);
  const ident = P.deriveIdentity(AKi);
  const uid = P.aliasUid(AKi);
  const handle = P.aliasHandle(uid, ident.sigPk, ident.kemPk, c);
  return { AKi, ident, uid, handle, ...P.makeBundle(uid, handle, ident, 0) };
}

describe("aliases (§2.6, §10.6)", () => {
  it("registers an alias with no wraps: one user row and one dirlog entry, counted in dirmeta.users", async () => {
    for (const c of [0, 3]) {
      const al = makeAlias(c, c);
      const s0 = await dirState();
      const now = Date.now();
      const { dirseq } = await dirRegister(env, { bundle: al.bundle, sig: al.sig, wraps: [] }, now);
      expect(dirseq).toBe(s0.head + 1);
      expect(await dirState()).toEqual({
        users: s0.users + 1,
        wraps: s0.wraps,
        head: s0.head + 1,
        meta: s0.meta + 1,
      });
      const [u] = await all<Record<string, unknown>>(
        "SELECT handle, reg_era, dirseq FROM user WHERE uid = ?1",
        P.b64u(al.uid),
      );
      expect(u).toEqual({ handle: al.handle, reg_era: P.era(now), dirseq });
      const { entries } = await dirlogPage(env, s0.head, 10);
      expect(entries.map((e) => e.kind)).toEqual([P.DIRLOG_USER]);
      // sent again (a lost response, §2.5 step 8): answered as the first time, not logged again
      expect(await dirRegister(env, { bundle: al.bundle, sig: al.sig, wraps: [] }, now)).toEqual({
        dirseq,
      });
      expect((await dirState()).head).toBe(s0.head + 1);
    }
  });

  it("400 for an alias handle with wraps, one that is not the bundle's own, and a chosen handle that starts with _", async () => {
    const al = makeAlias();
    const owner = makeAccount();
    const s0 = await dirState();
    // with wraps
    const withWraps = makeAccount(al.handle, al.uid);
    await rejects(register(withWraps), 400, /without wraps/);
    // another account's keys under this alias handle (the handle is bound to the bundle's own uid and keys)
    const stolen = P.makeBundle(owner.uid, al.handle, owner.ident, 0);
    await rejects(dirRegister(env, { ...stolen, wraps: [] }, Date.now()), 400, /alias handle/);
    // a handle of the alias pattern that no c gives
    const other = P.makeBundle(
      al.uid,
      al.handle.slice(0, -1) + (al.handle.endsWith("0") ? "1" : "0"),
      al.ident,
      0,
    );
    await rejects(dirRegister(env, { ...other, wraps: [] }, Date.now()), 400, /alias handle/);
    // chosen handles that start with _ (with wraps or without)
    for (const h of ["_alice", "__", "_abc"]) {
      if (!P.HANDLE_RE.test(h)) continue;
      const a = makeAccount(h);
      await rejects(register(a), 400, /without wraps|alias handle/);
      await rejects(register(a, []), 400, /alias handle/);
    }
    // a normal handle without wraps stays a 400
    await rejects(register(makeAccount(), []), 400, /wraps/);
    expect(await dirState()).toEqual(s0);
  });

  it("409 for an alias handle or uid already registered", async () => {
    const al = makeAlias();
    await dirRegister(env, { bundle: al.bundle, sig: al.sig, wraps: [] }, Date.now());
    // the same uid and keys with another signed text (another ts): the uid is taken
    const again = P.makeBundle(al.uid, al.handle, al.ident, 1);
    await rejects(dirRegister(env, { ...again, wraps: [] }, Date.now()), 409);
  });

  it("an account registered before aliases with a handle that starts with _ is no alias: it may add wraps", async () => {
    // Registered as an older server allowed (written to D1 directly), then a new wrap through dirAddWrap.
    const a = makeAccount("_old_one");
    const s0 = await dirState();
    await dirSeqStub(env).append({
      kind: "user",
      uid: a.uidB64,
      upre: P.upre(a.uid),
      handle: a.handle,
      hpre: P.hpre(a.handle),
      bundle: a.bundle,
      sig: a.sig,
      regEra: P.era(Date.now()),
      wraps: [wrapOf(a, a.passkey)],
    });
    expect((await dirState()).users).toBe(s0.users + 1);
    const w = newPasskey(a);
    const { dirseq } = await dirAddWrap(env, { ...w });
    expect(dirseq).toBeGreaterThan(s0.head);
  });

  it("dirAddWrap refuses a wrap for an alias's uid", async () => {
    const al = makeAlias();
    await dirRegister(env, { bundle: al.bundle, sig: al.sig, wraps: [] }, Date.now());
    const credId = P.random(16);
    const w = P.makeWrap(
      al.uid,
      "passkey",
      credId,
      P.credKem(P.random(32), credId),
      al.AKi,
      al.ident,
      Date.now(),
    );
    const s0 = await dirState();
    await rejects(dirAddWrap(env, { ...w }), 400, /alias/);
    expect(await dirState()).toEqual(s0);
  });
});

describe("dirAddWrap", () => {
  it("adds a wrap (one dirlog entry, dirmeta unchanged); 409 for a duplicate (uid, id)", async () => {
    const a = makeAccount();
    const { dirseq: d0 } = await register(a);
    const credId = P.random(1); // the smallest credential id
    const w = newPasskey(a, credId);
    const s0 = await dirState();
    const { dirseq } = await dirAddWrap(env, { ...w });
    expect(dirseq).toBe(s0.head + 1);
    expect(dirseq).toBeGreaterThan(d0 + 2);
    expect(await dirState()).toEqual({ ...s0, wraps: s0.wraps + 1, head: s0.head + 1 });
    const { entries } = await dirlogPage(env, s0.head, 10);
    expect(entries.map((e) => [e.seq, e.kind, e.ref])).toEqual([
      [dirseq, P.DIRLOG_WRAP, wrapRef(w)],
    ]);
    expect(await dirWrapsById(env, P.b64u(credId), null)).toEqual([
      { uid: a.uidB64, ...w, dirseq },
    ]);

    const s1 = await dirState();
    await rejects(dirAddWrap(env, { ...w }), 409, /duplicate/);
    await rejects(dirAddWrap(env, { ...newPasskey(a, credId) }), 409, /duplicate/); // same (uid, id), new record
    await rejects(dirAddWrap(env, { ...a.recovery }), 409, /duplicate/);
    expect(await dirState()).toEqual(s1);
  });

  it("404 for an unknown uid, 400 for a bad signature or a malformed body", async () => {
    const ghost = makeAccount();
    await rejects(dirAddWrap(env, { ...ghost.passkey }), 404, /unknown uid/);

    const a = makeAccount();
    await register(a);
    const s0 = await dirState();
    const other = makeAccount();
    const forged = P.makeWrap(
      a.uid,
      "recovery",
      P.random(16),
      P.credKem(P.random(32), P.random(16)),
      a.AK,
      other.ident,
      Date.now(),
    );
    await rejects(dirAddWrap(env, { ...forged }), 400, /signature/);
    const w = newPasskey(a);
    await rejects(dirAddWrap(env, { ...w, x: 1 }), 400);
    await rejects(dirAddWrap(env, { record: w.record }), 400);
    await rejects(
      dirAddWrap(env, { ...signRecord(a, { ...fields(w.record), x: 1 }) }),
      400,
      /canonical|fields/,
    );
    await rejects(
      dirAddWrap(env, { ...signRecord(a, w.record.replace('{"v":2,', '{"v":2, ')) }),
      400,
    );
    expect(await dirState()).toEqual(s0);
  });

  it(`at most ${MAX_WRAPS_PER_UID} wraps per uid, also under concurrent adds`, async () => {
    const a = makeAccount();
    await register(a); // 2 wraps
    for (let i = 2; i < MAX_WRAPS_PER_UID - 4; i++) await dirAddWrap(env, { ...newPasskey(a) });
    const wrapCount = async () =>
      count(await all<{ n: number }>("SELECT count(*) AS n FROM wrap WHERE uid = ?1", a.uidB64));
    expect(await wrapCount()).toBe(MAX_WRAPS_PER_UID - 4);
    // 8 concurrent adds at 60: exactly 4 land, the others see the cap (the count is read with the head).
    const results = await Promise.allSettled(
      Array.from({ length: 8 }, () => dirAddWrap(env, { ...newPasskey(a) })),
    );
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(4);
    for (const r of results.filter((x): x is PromiseRejectedResult => x.status === "rejected")) {
      expect(r.reason).toBeInstanceOf(HttpError);
      expect((r.reason as HttpError).status).toBe(400);
      expect((r.reason as HttpError).message).toMatch(/too many wraps/);
    }
    expect(await wrapCount()).toBe(MAX_WRAPS_PER_UID);
    const s0 = await dirState();
    await rejects(dirAddWrap(env, { ...newPasskey(a) }), 400, /too many wraps/);
    expect(await dirState()).toEqual(s0);
  });
});

describe("dirWrapsById", () => {
  it("oldest (lowest dirseq) first, filtered by uid, [] for unknown ids", async () => {
    // Ids are public: b files a record (with b's own uid) under a's credential id.
    const a = makeAccount();
    const b = makeAccount(undefined, undefined, a.credId);
    const { dirseq: da } = await register(a);
    const { dirseq: db } = await register(b);
    const id = P.b64u(a.credId);
    const got = await dirWrapsById(env, id, null);
    expect(got).toEqual([
      { uid: a.uidB64, ...a.passkey, dirseq: da + 1 },
      { uid: b.uidB64, ...b.passkey, dirseq: db + 1 },
    ]);
    expect(await dirWrapsById(env, id, b.uidB64)).toEqual([got[1]]);
    expect(await dirWrapsById(env, id, a.uidB64)).toEqual([got[0]]);
    expect(await dirWrapsById(env, id, P.b64u(P.random(16)))).toEqual([]);
    expect(await dirWrapsById(env, P.b64u(P.random(32)), null)).toEqual([]);
    expect(await dirWrapsById(env, P.b64u(P.random(16)), a.uidB64)).toEqual([]);
  });

  it(`returns at most ${MAX_WRAPS_PER_ID} records`, async () => {
    const id = P.b64u(P.random(24));
    const seqs = Array.from({ length: 70 }, (_, i) => 1e12 + i).sort(() => Math.random() - 0.5);
    // Spread over both user databases: the lookup merges them by dirseq (§9.6 "Reads").
    await Promise.all(
      USER_DBS.map((db, d) =>
        db.batch(
          seqs
            .filter((_, i) => i % 2 === d)
            .map((s) =>
              db
                .prepare(
                  "INSERT INTO wrap (uid, id, record, sig, dirseq) VALUES (?1, ?2, 'r', 's', ?3)",
                )
                .bind(P.b64u(P.random(16)), id, s),
            ),
        ),
      ),
    );
    try {
      const got = await dirWrapsById(env, id, null);
      expect(got.map((w) => w.dirseq)).toEqual(
        Array.from({ length: MAX_WRAPS_PER_ID }, (_, i) => 1e12 + i),
      );
    } finally {
      await Promise.all(
        USER_DBS.map((db) => db.prepare("DELETE FROM wrap WHERE id = ?1").bind(id).run()),
      );
    }
  });

  it("400 for malformed ids and uids", async () => {
    const good = P.b64u(P.random(16));
    for (const id of [
      "",
      "A",
      "AA==",
      "AB",
      "a+b/",
      "a b",
      P.b64u(P.random(1024)),
      nonCanonical(P.b64u(P.random(20))),
    ]) {
      await rejects(dirWrapsById(env, id, null), 400, /invalid id/);
    }
    for (const uid of [
      "",
      P.b64u(P.random(15)),
      P.b64u(P.random(17)),
      `${good}==`,
      nonCanonical(good),
      "x".repeat(22),
    ]) {
      await rejects(dirWrapsById(env, P.b64u(P.random(16)), uid), 400, /invalid uid/);
    }
    await rejects(dirByUid(env, P.b64u(P.random(15))), 400, /invalid uid/);
    await rejects(dirByUid(env, nonCanonical(good)), 400, /invalid uid/);
    expect(await dirByUid(env, good)).toBeNull();
  });
});

describe("prefix lookups", () => {
  it("accepts p ≤ min(32, P + 1) and answers 409 {p: P} above; P comes from dirmeta.users, cached", async () => {
    for (const users of [0, 63, 64, 127, 128, 1000, 2 ** 20, 2 ** 36, 2 ** 40]) {
      await withUsers(users, async () => {
        const Pn = P.serverP(users);
        expect(await currentP(env)).toBe(Pn);
        const pmax = Math.min(32, Pn + 1);
        for (const p of [0, pmax]) {
          const r = await dirByPrefix(env, "h", p, 2 ** p - 1, null);
          expect(r.p).toBe(p);
        }
        if (pmax < 32) {
          for (const kind of ["h", "u"] as const) {
            const e = (await rejects(
              dirByPrefix(env, kind, pmax + 1, 0, null),
              409,
            )) as PrefixBitsError;
            expect(e).toBeInstanceOf(PrefixBitsError);
            expect(e.P).toBe(Pn);
            expect(e.extra).toEqual({ p: Pn });
          }
        }
      });
    }
    // The cached P survives a dirmeta change for ~60 s (per isolate).
    const P0 = await currentP(env);
    await env.DIRLOG.prepare("UPDATE dirmeta SET v = v + 1000000 WHERE k = 'users'").run();
    try {
      expect(await currentP(env)).toBe(P0);
      _resetDirectoryCacheForTests();
      expect(await currentP(env)).toBeGreaterThan(P0);
    } finally {
      await env.DIRLOG.prepare("UPDATE dirmeta SET v = v - 1000000 WHERE k = 'users'").run();
      _resetDirectoryCacheForTests();
    }
  });

  it("p = 0, 1 and 32 return exactly the matching rows, by uid; the stored prefixes are hpre / upre", async () => {
    const accts = Array.from({ length: 6 }, () => makeAccount());
    for (const a of accts) await register(a);
    const rows = await all<{ uid: string; handle: string; hpre: number; upre: number }>(
      "SELECT uid, handle, hpre, upre FROM user",
    );
    for (const r of rows) {
      expect(r.hpre).toBe(P.hpre(r.handle));
      expect(r.upre).toBe(P.upre(P.fromB64u(r.uid)));
    }
    await withUsers(2 ** 40, async () => {
      for (const kind of ["h", "u"] as const) {
        const pre = (r: (typeof rows)[number]) => (kind === "h" ? r.hpre : r.upre);
        const probes: [number, number][] = [
          [0, 0],
          [1, 0],
          [1, 1],
          [32, pre(rows.find((r) => r.uid === accts[0].uidB64)!)],
          [32, pre(rows.find((r) => r.uid === accts[1].uidB64)!)],
          [32, (pre(rows[0]) + 1) % 2 ** 32],
          [32, 2 ** 32 - 1],
          [32, 0],
        ];
        for (const [p, x] of probes) {
          const want = rows
            .filter((r) => P.topBits(pre(r), p) === x)
            .map((r) => r.uid)
            .sort(byteOrder);
          const got = await allPages(kind, p, x);
          expect(
            got.map((u) => u.uid),
            `${kind} p=${p} x=${x}`,
          ).toEqual(want);
        }
        // each account is found by its own 32-bit prefix
        for (const a of accts) {
          const x = kind === "h" ? P.hpre(a.handle) : P.upre(a.uid);
          expect((await allPages(kind, 32, x)).map((u) => u.uid)).toContain(a.uidB64);
        }
      }
    });
  });

  it("the query plan: user_hpre / user_upre for narrow ranges; wide ranges walk the uid key without sorting", async () => {
    for (const [kind, index] of [
      ["h", "user_hpre"],
      ["u", "user_upre"],
    ] as const) {
      for (const paged of [false, true]) {
        const plan = async (wide: boolean) => {
          const stmt = env.DB.prepare(`EXPLAIN QUERY PLAN ${prefixSql(kind, paged, wide)}`);
          const args = paged
            ? [0, 2 ** 31 - 1, PREFIX_PAGE + 1, "AAAAAAAAAAAAAAAAAAAAAA"]
            : [0, 2 ** 31 - 1, PREFIX_PAGE + 1];
          return (await stmt.bind(...args).all<{ detail: string }>()).results
            .map((r) => r.detail)
            .join(" | ");
        };
        const narrow = await plan(false);
        expect(narrow, narrow).toContain(index);
        const wide = await plan(true);
        expect(wide, wide).toMatch(/USING INDEX sqlite_autoindex_user_1/);
        expect(wide, wide).not.toContain(index);
        expect(wide, wide).not.toMatch(/TEMP B-TREE/);
        if (paged) expect(wide, wide).toContain("(uid>?)");
      }
    }
  });

  it("dirByPrefix walks the uid key for p = 0 and wherever users > 257 · 4^p, else the prefix index", async () => {
    expect(widePrefix(0, 0)).toBe(true);
    expect(widePrefix(2 ** 40, 0)).toBe(true);
    expect(widePrefix(257 * 4 ** 5, 5)).toBe(false); // equal: the index reads no more rows
    expect(widePrefix(257 * 4 ** 5 + 1, 5)).toBe(true);
    expect(widePrefix(1000, 1)).toBe(false); // 500 rows in range vs ~514 read by a walk
    expect(widePrefix(1_000_000, 5)).toBe(true); // 31 250 rows in range vs ~8 224
    expect(widePrefix(1_000_000, 6)).toBe(false); // 15 625 rows in range vs ~16 448
    expect(widePrefix(2 ** 40, 16)).toBe(false);
    expect(widePrefix(2 ** 40, 32)).toBe(false);
    const sqls: string[] = [];
    const db = new Proxy(env.DB, {
      get: (t, k) =>
        k === "prepare"
          ? (sql: string) => (sqls.push(sql), t.prepare(sql))
          : ((v) => (typeof v === "function" ? v.bind(t) : v))(Reflect.get(t, k) as unknown),
    });
    const spied = new Proxy(env, { get: (t, k) => (k === "DB" ? db : Reflect.get(t, k)) });
    await withUsers(1_000_000, async () => {
      const after = P.b64u(P.random(16));
      const probes: [kind: "h" | "u", p: number, after: string | null, wide: boolean][] = [
        ["h", 0, null, true],
        ["u", 0, after, true],
        ["h", 5, after, true],
        ["u", 6, null, false],
        ["h", 15, after, false],
      ];
      for (const [kind, p, a, wide] of probes) {
        sqls.length = 0;
        await dirByPrefix(spied, kind, p, 0, a);
        const read = sqls.filter((s) => s.includes("FROM user WHERE"));
        expect(read, `${kind} p=${p}`).toEqual([prefixSql(kind, a !== null, wide)]);
      }
    });
  });

  it(`pages of ${PREFIX_PAGE} with after and more`, async () => {
    const V = 0x5eed0001;
    const n = PREFIX_PAGE + 44;
    const fake = Array.from({ length: n }, (_, i) => ({
      uid: P.b64u(P.random(16)),
      handle: `zz_page_${i}_${P.hex(P.random(3))}`,
    }));
    // Spread over both user databases: every page merges them in uid order (§9.6 "Reads").
    await Promise.all(
      USER_DBS.map((db, d) =>
        db.batch(
          fake
            .map((u, i) => [u, i] as const)
            .filter(([, i]) => i % 2 === d)
            .map(([u, i]) =>
              db
                .prepare(
                  "INSERT INTO user (uid, upre, handle, hpre, bundle, sig, reg_era, dirseq) VALUES (?1, ?2, ?3, ?4, 'b', 's', 0, ?5)",
                )
                .bind(u.uid, V, u.handle, V, 1e12 + i),
            ),
        ),
      ),
    );
    try {
      await withUsers(2 ** 40, async () => {
        for (const kind of ["h", "u"] as const) {
          const p1 = await dirByPrefix(env, kind, 32, V, null);
          expect(p1.users).toHaveLength(PREFIX_PAGE);
          expect(p1.more).toBe(true);
          const p2 = await dirByPrefix(env, kind, 32, V, p1.users[PREFIX_PAGE - 1].uid);
          expect(p2.users).toHaveLength(n - PREFIX_PAGE);
          expect(p2.more).toBe(false);
          const want = fake.map((u) => u.uid).sort(byteOrder);
          expect([...p1.users, ...p2.users].map((u) => u.uid)).toEqual(want);
          // after = the last uid of a full table gives an empty last page
          const p3 = await dirByPrefix(env, kind, 32, V, want[want.length - 1]);
          expect(p3).toEqual({ p: 32, users: [], more: false });
          // a page that ends exactly at 256 has more = false
          const p4 = await dirByPrefix(env, kind, 32, V, want[n - PREFIX_PAGE - 1]);
          expect(p4.users).toHaveLength(PREFIX_PAGE);
          expect(p4.more).toBe(false);
          // the same rows show up under shorter prefixes (p = 31, 16)
          for (const p of [31, 16]) {
            const got = (await allPages(kind, p, P.topBits(V, p))).map((u) => u.uid);
            expect(got.filter((u) => want.includes(u))).toEqual(want);
          }
        }
      });
      // Both plans page the same rows: p = 16 reads the prefix index with 2^40 users and walks the uid key with 2^43.
      expect(widePrefix(2 ** 40, 16)).toBe(false);
      expect(widePrefix(2 ** 43, 16)).toBe(true);
      for (const kind of ["h", "u"] as const) {
        const narrow = await withUsers(2 ** 40, () => allPages(kind, 16, P.topBits(V, 16)));
        const wide = await withUsers(2 ** 43, () => allPages(kind, 16, P.topBits(V, 16)));
        expect(narrow.length).toBeGreaterThan(PREFIX_PAGE);
        expect(wide).toEqual(narrow);
      }
    } finally {
      await Promise.all(
        USER_DBS.map((db) =>
          db.prepare("DELETE FROM user WHERE hpre = ?1 AND bundle = 'b'").bind(V).run(),
        ),
      );
    }
  });

  it("returned bundles verify (signature, keys, uid and handle)", async () => {
    const a = makeAccount();
    const { dirseq } = await register(a);
    const P0 = await currentP(env);
    const p = Math.min(P0 + 1, 32);
    const users = await allPages("h", p, P.topBits(P.hpre(a.handle), p));
    const mine = users.find((u) => u.uid === a.uidB64);
    expect(mine).toEqual({
      uid: a.uidB64,
      handle: a.handle,
      bundle: a.bundle,
      sig: a.sig,
      regEra: P.era(Date.now()),
      dirseq,
    });
    expect(users.length).toBeGreaterThan(0);
    for (const u of users) {
      const v = P.verifyBundle(u.bundle, u.sig);
      expect(v.uid).toBe(u.uid);
      expect(v.handle).toBe(u.handle);
      P.checkUserKeys(v.sigPk, v.kemPk);
      expect(P.topBits(P.hpre(v.handle), p)).toBe(P.topBits(P.hpre(a.handle), p));
    }
    const byU = await allPages("u", p, P.topBits(P.upre(a.uid), p));
    expect(byU.map((u) => u.uid)).toContain(a.uidB64);
  });

  it("400 on a bad kind, p, x or after", async () => {
    await withUsers(2 ** 40, async () => {
      const bad: [string, number, number, string | null][] = [
        ["x", 0, 0, null],
        ["h", -1, 0, null],
        ["h", 33, 0, null],
        ["h", 1.5, 0, null],
        ["h", Number.NaN, 0, null],
        ["h", 1, 2, null],
        ["h", 1, -1, null],
        ["h", 0, 1, null],
        ["u", 32, 2 ** 32, null],
        ["u", 8, 0.5, null],
        ["h", 1, 0, "short"],
        ["h", 1, 0, nonCanonical(P.b64u(P.random(16)))],
      ];
      for (const [kind, p, x, after] of bad) {
        await rejects(dirByPrefix(env, kind as "h", p, x, after), 400);
      }
    });
  });
});

describe("dirlog", () => {
  it("pages ascending with the head; bounds are checked", async () => {
    const a = makeAccount();
    await register(a);
    const head = await dirlogHead(env);
    const one = await dirlogPage(env, head.seq - 3, 1);
    expect(one.entries.map((e) => e.seq)).toEqual([head.seq - 2]);
    expect(one.head).toEqual(head);
    const three = await dirlogPage(env, head.seq - 3, 1000);
    expect(three.entries.map((e) => e.seq)).toEqual([head.seq - 2, head.seq - 1, head.seq]);
    expect(three.entries[2].h).toBe(head.h);
    expect(await dirlogPage(env, head.seq, 10)).toEqual({ entries: [], head });
    expect(await dirlogPage(env, head.seq + 100, 10)).toEqual({ entries: [], head });
    for (const [after, limit] of [
      [-1, 10],
      [0.5, 10],
      [0, 0],
      [0, 1001],
      [0, 2.5],
      [Number.NaN, 1],
    ]) {
      await rejects(dirlogPage(env, after, limit), 400);
    }
  });

  it("8 concurrent registrations all land; the chain recomputes without gaps; dirmeta.users = the user count", async () => {
    const accts = Array.from({ length: 8 }, () => makeAccount());
    const s0 = await dirState();
    const res = await Promise.all(accts.map((a) => dirRegister(env, registerBody(a), Date.now())));
    const seqs = res.map((r) => r.dirseq);
    expect(new Set(seqs).size).toBe(8);
    const s1 = await dirState();
    expect(s1).toEqual({
      users: s0.users + 8,
      wraps: s0.wraps + 16,
      head: s0.head + 24,
      meta: s0.meta + 8,
    });
    expect(s1.meta).toBe(s1.users);

    const log = await verifiedDirlog();
    expect(log).toHaveLength(s1.head);
    // Every entry is one user or wrap row, and each registration's entries are contiguous (user, then wraps).
    const users = await all<{ bundle: string; sig: string; dirseq: number }>(
      "SELECT bundle, sig, dirseq FROM user",
    );
    const wraps = await all<{ record: string; sig: string; dirseq: number }>(
      "SELECT record, sig, dirseq FROM wrap",
    );
    expect(users.length + wraps.length).toBe(log.length);
    for (const u of users)
      expect(log[u.dirseq - 1]).toMatchObject({
        kind: P.DIRLOG_USER,
        ref: userRef(u.bundle, u.sig),
      });
    for (const w of wraps)
      expect(log[w.dirseq - 1]).toMatchObject({ kind: P.DIRLOG_WRAP, ref: wrapRef(w) });
    accts.forEach((a, i) => {
      expect(log[seqs[i]].ref).toBe(wrapRef(a.passkey));
      expect(log[seqs[i] + 1].ref).toBe(wrapRef(a.recovery));
    });
  });
});

describe("D1 failures", () => {
  /** A DB whose every call rejects (async) or throws (sync). */
  function brokenEnv(mode: "async" | "sync"): Env {
    const fail = (): never => {
      throw new Error("D1_ERROR: Network connection lost. (uid q3Z9_xK2mP0aB7cD1eF4gH)");
    };
    const reject = () => Promise.reject(new Error("D1_ERROR: Network connection lost."));
    const stmt: Record<string, unknown> = {};
    for (const k of ["first", "all", "run", "raw"]) stmt[k] = reject;
    stmt.bind = () => stmt;
    const db =
      mode === "sync"
        ? new Proxy(env.DB, { get: () => fail })
        : new Proxy(env.DB, {
            get: (t, k) =>
              k === "prepare"
                ? () => stmt
                : k === "batch" || k === "exec"
                  ? reject
                  : Reflect.get(t, k),
          });
    return envWith({ DB: db, DB1: db, DIRLOG: db });
  }

  for (const mode of ["async", "sync"] as const) {
    it(`503 for every read and write (${mode} failures)`, async () => {
      const a = makeAccount();
      const b = makeAccount();
      await register(b);
      const errors = vi.spyOn(console, "error").mockImplementation(() => {});
      const bad = brokenEnv(mode);
      // Writes fail inside the DirSeqDO (its D1), reads in the Worker.
      await withDirSeqEnv(bad, async () => {
        await rejects(dirRegister(env, registerBody(a), Date.now()), 503);
        await rejects(dirAddWrap(env, { ...newPasskey(b) }), 503);
      });
      await rejects(dirAddWrap(bad, { ...newPasskey(b) }), 503); // the owner read
      expect(await currentP(bad)).toBe(0); // never throws: no good P yet
      await rejects(dirByPrefix(bad, "h", 0, 0, null), 503); // no P known: 503, never a 409 against P = 0
      _resetDirectoryCacheForTests();
      await currentP(env); // warm P cache: the query itself fails
      await rejects(dirByPrefix(bad, "u", 0, 0, null), 503);
      await rejects(dirByUid(bad, b.uidB64), 503);
      await rejects(dirWrapsById(bad, P.b64u(b.credId), null), 503);
      await rejects(dirlogPage(bad, 0, 10), 503);
      await rejects(dirlogHead(bad), 503);
      expect(errors).toHaveBeenCalled();
      for (const call of errors.mock.calls)
        expect(String(call[0])).not.toMatch(/q3Z9_xK2mP0aB7cD1eF4gH/);
      // nothing was written, and the real directory is unaffected
      expect(await dirByUid(env, a.uidB64)).toBeNull();
      expect((await dirByUid(env, b.uidB64))!.bundle).toBe(b.bundle);
    });
  }

  it("currentP never throws: the last good P (0 if none) while D1 fails, one read and one log line per back-off", async () => {
    let failing = true;
    let reads = 0;
    const stmt = {
      bind: () => stmt,
      first: () => Promise.reject(new Error("D1_ERROR: Network connection lost.")),
      all: () => stmt.first(),
    };
    /** `real` while `failing`; prepares are counted on the log database only (dirmeta lives there). */
    const flakyDb = (real: D1Database, counted: boolean) =>
      new Proxy(real, {
        get: (t, k) =>
          k === "prepare"
            ? (sql: string) => {
                if (counted) reads++;
                return failing ? stmt : t.prepare(sql);
              }
            : ((v) => (typeof v === "function" ? v.bind(t) : v))(Reflect.get(t, k) as unknown),
      });
    const flaky = envWith({
      DIRLOG: flakyDb(env.DIRLOG, true),
      DB: flakyDb(env.DB, false),
      DB1: flakyDb(env.DB1, false),
    });
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const dirmetaLogs = () =>
      errors.mock.calls.filter((c) => /dirmeta read failed/.test(String(c[0]))).length;
    await withUsers(2 ** 20, async () => {
      let clock = Date.now();
      vi.spyOn(Date, "now").mockImplementation(() => clock);
      // Nothing read yet: P = 0 from one D1 read and one log line, then no D1 call for P_RETRY_MS.
      for (let i = 0; i < 5; i++) expect(await currentP(flaky)).toBe(0);
      expect(reads).toBe(1);
      expect(dirmetaLogs()).toBe(1);
      await rejects(dirByPrefix(flaky, "h", 0, 0, null), 503); // no P known: 503 without asking D1
      expect(reads).toBe(1);
      clock += P_RETRY_MS - 1;
      expect(await currentP(flaky)).toBe(0);
      expect(reads).toBe(1);
      // After the back-off D1 is asked again; a good answer is cached for P_CACHE_MS.
      clock += 1;
      failing = false;
      expect(await currentP(flaky)).toBe(P.serverP(2 ** 20));
      expect(reads).toBe(2);
      failing = true;
      clock += P_CACHE_MS;
      // Expired and D1 failing: the last good P, one read and one more log line per back-off.
      for (let i = 0; i < 5; i++) expect(await currentP(flaky)).toBe(P.serverP(2 ** 20));
      expect(reads).toBe(3);
      expect(dirmetaLogs()).toBe(2);
      // Prefix lookups keep checking p against the last good P (the page itself then fails with 503).
      const e = (await rejects(
        dirByPrefix(flaky, "h", P.serverP(2 ** 20) + 2, 0, null),
        409,
      )) as PrefixBitsError;
      expect(e.extra).toEqual({ p: P.serverP(2 ** 20) });
      await rejects(dirByPrefix(flaky, "h", P.serverP(2 ** 20) + 1, 0, null), 503);
      expect(reads).toBe(3); // the page query goes to the user databases, not to dirmeta
      clock += P_RETRY_MS;
      expect(await currentP(flaky)).toBe(P.serverP(2 ** 20));
      expect(reads).toBe(4);
      expect(dirmetaLogs()).toBe(3);
    });
  });

  it("the DirSeqDO writes a round of queued writes in one D1 batch, and isolates a conflicting one", async () => {
    const accts = Array.from({ length: 6 }, () => makeAccount());
    const s0 = await dirState();
    const write = (a: Account): DirWrite => ({
      kind: "user",
      uid: a.uidB64,
      upre: P.upre(a.uid),
      handle: a.handle,
      hpre: P.hpre(a.handle),
      bundle: a.bundle,
      sig: a.sig,
      regEra: P.era(Date.now()),
      wraps: [a.passkey, a.recovery].map((w, k) => ({
        uid: a.uidB64,
        id: P.b64u(k === 0 ? a.credId : a.recId),
        record: w.record,
        sig: w.sig,
      })),
    });
    // Count the log database's batches (a round's dirlog entries); writes queued before the first round's D1 round
    // trip ends go out together.
    let writes = 0;
    const db = new Proxy(env.DIRLOG, {
      get: (t, k) => {
        if (k === "batch") {
          return (stmts: D1PreparedStatement[]) => {
            if (stmts.length > 1) writes++;
            return t.batch(stmts);
          };
        }
        const v = Reflect.get(t, k) as unknown;
        return typeof v === "function" ? (v as (...x: unknown[]) => unknown).bind(t) : v;
      },
    });
    const counted = envWith({ DIRLOG: db });
    const results = await withDirSeqEnv(counted, () =>
      runInDurableObject(dirSeqStub(env), (inst: DirSeqDO) => {
        // The second registration repeats the first one's handle: its batch fails, and it alone answers 409.
        const dup = makeAccount(accts[0].handle);
        const all = [accts[0], dup, ...accts.slice(1)];
        return Promise.all(all.map((a) => inst.append(write(a))));
      }),
    );
    expect(results[0]).toEqual({ ok: true, seqs: [s0.head + 1, s0.head + 2, s0.head + 3] });
    expect(results[1]).toEqual({ ok: false, status: 409, error: "handle already taken" });
    for (const r of results.slice(2)) expect(r).toMatchObject({ ok: true });
    const seqs = results.flatMap((r) => (r.ok ? r.seqs : []));
    expect(seqs).toEqual(seqs.map((_, i) => s0.head + 1 + i)); // contiguous, in order
    // The round takes its writes when its turn starts, after the appends made in the same task: all seven are one
    // round, whose checks refused the duplicate before the dirlog batch: one batch in all.
    expect(writes).toBe(1);
    expect(await dirState()).toEqual({
      users: s0.users + 6,
      wraps: s0.wraps + 12,
      head: s0.head + 18,
      meta: s0.meta + 6,
    });
    await verifiedDirlog();
  });

  it("re-reads the head and retries once when another writer moved it; the cap of wraps per uid is counted in the batch", async () => {
    const a = makeAccount();
    await register(a); // the DirSeqDO holds the head in memory now
    const s0 = await dirState();
    // Another writer (a Worker of the previous release) appends an entry behind the object's back.
    const head = await dirlogHead(env);
    const ref = P.random(32);
    const h = P.dirlogH(P.fromB64u(head.h), head.seq + 1, P.DIRLOG_WRAP, ref);
    await env.DIRLOG.prepare("INSERT INTO dirlog (seq, kind, ref, h) VALUES (?1, ?2, ?3, ?4)")
      .bind(head.seq + 1, P.DIRLOG_WRAP, P.b64u(ref), P.b64u(h))
      .run();
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const r = await dirAddWrap(env, { ...newPasskey(a) });
    expect(r.dirseq).toBe(head.seq + 2);
    expect(errors.mock.calls.some((c) => String(c[0]).includes("retrying once"))).toBe(true);
    expect(await dirState()).toEqual({ ...s0, wraps: s0.wraps + 1, head: s0.head + 2 });
    // Two wraps of one uid in the same batch count against the cap together.
    await env.DIRLOG.prepare("DELETE FROM dirlog WHERE seq = ?1")
      .bind(head.seq + 1)
      .run(); // keep the chain checkable
    const b = makeAccount();
    await register(b);
    const fill = Array.from({ length: MAX_WRAPS_PER_UID - 3 }, () => ({
      kind: "wrap" as const,
      wrap: wrapOf(b, newPasskey(b)),
    }));
    const results = await runInDurableObject(dirSeqStub(env), (inst: DirSeqDO) =>
      Promise.all(
        [
          ...fill,
          { kind: "wrap" as const, wrap: wrapOf(b, newPasskey(b)) },
          { kind: "wrap" as const, wrap: wrapOf(b, newPasskey(b)) },
        ].map((w) => inst.append(w)),
      ),
    );
    const refused = results.filter((x: DirWriteResult) => !x.ok);
    expect(refused).toHaveLength(1);
    expect(refused[0]).toMatchObject({ status: 400 });
    expect((await dirWrapsById(env, P.b64u(b.credId), b.uidB64)).length).toBe(1);
    expect(
      count(await all<{ n: number }>("SELECT count(*) AS n FROM wrap WHERE uid = ?1", b.uidB64)),
    ).toBe(MAX_WRAPS_PER_UID);
  });

  it("classifies D1 constraint errors", () => {
    expect(
      uniqueFailure(new Error("D1_ERROR: UNIQUE constraint failed: dirlog.seq: SQLITE_CONSTRAINT")),
    ).toBe("dirlog.seq");
    expect(uniqueFailure(new Error("UNIQUE constraint failed: wrap.uid, wrap.id"))).toBe(
      "wrap.uid",
    );
    const wrapped = new Error("D1_ERROR", {
      cause: new Error("UNIQUE constraint failed: user.handle"),
    });
    expect(uniqueFailure(wrapped)).toBe("user.handle");
    expect(uniqueFailure(new Error("D1_ERROR: Network connection lost."))).toBeNull();
    expect(uniqueFailure("nope")).toBeNull();
  });
});

// ───────────── the user databases (§9.6) ─────────────

/** A uid whose user database under K = 2 is `d` (the top bit of upre, a hash of the uid; §9.6). */
function uidIn(d: 0 | 1): Uint8Array {
  for (;;) {
    const uid = P.random(16);
    if (dirShardOf(P.upre(uid), 1) === d) return uid;
  }
}

const countIn = async (db: D1Database, sql: string, ...args: unknown[]): Promise<number> =>
  (await db
    .prepare(sql)
    .bind(...args)
    .first<{ n: number }>())!.n;

describe("user databases (§9.6)", () => {
  it("rows land in the database of the top bits of upre; lookups merge every database", async () => {
    const a = makeAccount(freshHandle(), uidIn(0));
    const b = makeAccount(freshHandle(), uidIn(1), a.credId); // the same credential id: wraps lookups merge too
    expect(dirShardOf(P.upre(a.uid), 1)).toBe(0);
    expect(dirShardOf(P.upre(b.uid), 1)).toBe(1);
    const ra = await register(a);
    const rb = await register(b);
    for (const [acc, d] of [
      [a, 0],
      [b, 1],
    ] as const) {
      expect(
        await countIn(USER_DBS[d], "SELECT count(*) AS n FROM user WHERE uid = ?1", acc.uidB64),
      ).toBe(1);
      expect(
        await countIn(USER_DBS[1 - d], "SELECT count(*) AS n FROM user WHERE uid = ?1", acc.uidB64),
      ).toBe(0);
      expect(
        await countIn(USER_DBS[d], "SELECT count(*) AS n FROM wrap WHERE uid = ?1", acc.uidB64),
      ).toBe(2);
    }
    expect((await dirByUid(env, a.uidB64))!.dirseq).toBe(ra.dirseq);
    expect((await dirByUid(env, b.uidB64))!.dirseq).toBe(rb.dirseq);
    // One prefix page over both databases, in uid order, each uid once.
    const uids = (await withUsers(2 ** 20, () => allPages("u", 0, 0))).map((u) => u.uid);
    expect(uids).toEqual([...uids].sort(byteOrder));
    expect(new Set(uids).size).toBe(uids.length);
    expect(uids).toContain(a.uidB64);
    expect(uids).toContain(b.uidB64);
    // The wraps of one id across both databases, oldest first; the uid filter keeps one.
    const ws = await dirWrapsById(env, P.b64u(a.credId), null);
    expect(ws.map((w) => [w.uid, w.dirseq])).toEqual([
      [a.uidB64, ra.dirseq + 1],
      [b.uidB64, rb.dirseq + 1],
    ]);
    expect((await dirWrapsById(env, P.b64u(a.credId), b.uidB64)).map((w) => w.uid)).toEqual([
      b.uidB64,
    ]);
    // A handle is unique across the databases, and so is a uid.
    await rejects(register(makeAccount(a.handle, uidIn(1))), 409, /handle already taken/);
    await rejects(register(makeAccount(freshHandle(), b.uid)), 409, /uid already registered/);
  });

  it("a user database whose batch fails: the dirlog keeps the entries, the rows wait in the write-ahead log and land at the replay", async () => {
    const b = makeAccount(freshHandle(), uidIn(1));
    const a = makeAccount(freshHandle(), uidIn(0));
    const s0 = await dirState();
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    // Database 1 loses its wrap table: a registration's batch there fails as a whole, after the dirlog batch.
    await env.DB1.prepare("ALTER TABLE wrap RENAME TO wrap_off").run();
    try {
      const e = await rejects(register(b), 503, /directory unavailable/);
      expect(e.headers).toEqual({ "retry-after": String(DIR_RETRY_AFTER_S) });
      expect(await dirlogHead(env)).toMatchObject({ seq: s0.head + 3 });
      expect(await walSeqs()).toEqual([s0.head + 1]);
      expect(await dirByUid(env, b.uidB64)).toBeNull(); // lookups read the user databases only
      // The same registration sent again answers as the logged one, with its seqs, and logs nothing (§2.5 step 8).
      expect(await register(b)).toEqual({ dirseq: s0.head + 1 });
      expect(await dirlogHead(env)).toMatchObject({ seq: s0.head + 3 });
      expect(await walSeqs()).toEqual([s0.head + 1]);
      // The same bundle with other wrap records is another body: 409.
      await rejects(register(b, [b.passkey]), 409, /handle already taken/);
      expect(
        await runInDurableObject(dirSeqStub(env), (_i: DirSeqDO, state) =>
          state.storage.getAlarm(),
        ),
      ).not.toBeNull();
      // Database 0 is unaffected: a registration there lands, behind the waiting one in the log.
      expect((await register(a)).dirseq).toBe(s0.head + 4);
      expect(await walSeqs()).toEqual([s0.head + 1]);
      // The handle is b's: another account's registration of it answers 409 (the waiting row counts).
      await rejects(register(makeAccount(b.handle, uidIn(0))), 409, /handle already taken/);
    } finally {
      await env.DB1.prepare("ALTER TABLE wrap_off RENAME TO wrap").run();
    }
    // The replay (the alarm) lands the rows; the chain is intact.
    expect(await runDurableObjectAlarm(dirSeqStub(env))).toBe(true);
    expect(await walSeqs()).toEqual([]);
    // Sent again once landed, the registration still answers with its seqs and writes nothing.
    expect(await register(b)).toEqual({ dirseq: s0.head + 1 });
    expect((await dirByUid(env, b.uidB64))!.dirseq).toBe(s0.head + 1);
    expect((await dirWrapsById(env, P.b64u(b.credId), b.uidB64)).map((w) => w.dirseq)).toEqual([
      s0.head + 2,
    ]);
    expect(await dirState()).toEqual({
      users: s0.users + 2,
      wraps: s0.wraps + 4,
      head: s0.head + 6,
      meta: s0.meta + 2,
    });
    // The log holds b's entries first (logged before its rows), then a's.
    const log = (await dirlogPage(env, s0.head, 6)).entries;
    expect(log.map((e) => [e.seq, e.kind, e.ref])).toEqual([
      [s0.head + 1, P.DIRLOG_USER, userRef(b.bundle, b.sig)],
      [s0.head + 2, P.DIRLOG_WRAP, wrapRef(b.passkey)],
      [s0.head + 3, P.DIRLOG_WRAP, wrapRef(b.recovery)],
      [s0.head + 4, P.DIRLOG_USER, userRef(a.bundle, a.sig)],
      [s0.head + 5, P.DIRLOG_WRAP, wrapRef(a.passkey)],
      [s0.head + 6, P.DIRLOG_WRAP, wrapRef(a.recovery)],
    ]);
    expect(errors.mock.calls.some((c) => /user database write failed/.test(String(c[0])))).toBe(
      true,
    );
  });

  it("an alarm while a round's log batch is in flight waits for the round: its rows stay in the write-ahead log and land", async () => {
    const b = makeAccount(freshHandle(), uidIn(1));
    const s0 = await dirState();
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    // The log database holds the round's batch until released.
    let entered!: () => void;
    const inFlight = new Promise<void>((r) => (entered = r));
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const log = new Proxy(env.DIRLOG, {
      get: (t, k) => {
        if (k === "batch") {
          return async (stmts: D1PreparedStatement[]) => {
            if (stmts.length > 1) {
              entered();
              await gate;
            }
            return t.batch(stmts);
          };
        }
        const v = Reflect.get(t, k) as unknown;
        return typeof v === "function" ? (v as (...x: unknown[]) => unknown).bind(t) : v;
      },
    });
    await runInDurableObject(dirSeqStub(env), (_i: DirSeqDO, state) =>
      state.storage.setAlarm(Date.now() + 60_000),
    );
    // Database 1 refuses the rows, so they must survive in the write-ahead log.
    await env.DB1.prepare("ALTER TABLE wrap RENAME TO wrap_off").run();
    try {
      await withDirSeqEnv(envWith({ DIRLOG: log }), async () => {
        const reg = register(b).then(
          () => null,
          (e: unknown) => e,
        );
        await inFlight;
        // The alarm fires while the round awaits its log batch: it must not judge the round's rows.
        const alarm = runDurableObjectAlarm(dirSeqStub(env));
        await new Promise((r) => setTimeout(r, 100));
        release();
        expect((await reg) as HttpError).toMatchObject({ status: 503 });
        expect(await alarm).toBe(true);
      });
      expect(await walSeqs()).toEqual([s0.head + 1]);
      expect(await register(b)).toEqual({ dirseq: s0.head + 1 }); // the logged registration, sent again
    } finally {
      await env.DB1.prepare("ALTER TABLE wrap_off RENAME TO wrap").run();
    }
    expect(await runDurableObjectAlarm(dirSeqStub(env))).toBe(true);
    expect(await walSeqs()).toEqual([]);
    expect(await countIn(env.DB1, "SELECT count(*) AS n FROM wrap WHERE uid = ?1", b.uidB64)).toBe(
      2,
    );
    expect(await dirState()).toEqual({
      users: s0.users + 1,
      wraps: s0.wraps + 2,
      head: s0.head + 3,
      meta: s0.meta + 1,
    });
    expect(errors.mock.calls.some((c) => /dirlog write failed/.test(String(c[0])))).toBe(false);
  });

  it("DIR_SHARDS below the pinned value: writes answer 503, logged once, until it is restored", async () => {
    const a = makeAccount();
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    await withDirSeqEnv(envWith({ DIR_SHARDS: "1" }), async () => {
      await rejects(register(a), 503, /directory misconfigured/);
      await rejects(register(a), 503, /directory misconfigured/);
    });
    expect(
      errors.mock.calls.filter((c) => /below the pinned value/.test(String(c[0]))),
    ).toHaveLength(1);
    await register(a);
  });

  it("raising DIR_SHARDS moves the rows that are no longer in their database, a page per alarm, and pins the new value", async () => {
    // The layout of a deployment with one database: a user of database 1 sits in database 0 with its wrap.
    const legacy = makeAccount(freshHandle(), uidIn(1));
    const s0 = await dirState();
    const seq = 1e12 + 7; // fake dirseqs: these rows never went through the log
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO user (uid, upre, handle, hpre, bundle, sig, reg_era, dirseq) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)",
      ).bind(
        legacy.uidB64,
        P.upre(legacy.uid),
        legacy.handle,
        P.hpre(legacy.handle),
        legacy.bundle,
        legacy.sig,
        seq,
      ),
      env.DB.prepare(
        "INSERT INTO wrap (uid, id, record, sig, dirseq) VALUES (?1, ?2, ?3, ?4, ?5)",
      ).bind(
        legacy.uidB64,
        P.b64u(legacy.credId),
        legacy.passkey.record,
        legacy.passkey.sig,
        seq + 1,
      ),
    ]);
    // The object pinned one database (as under the first release), before the deployment raised DIR_SHARDS to 2.
    await runInDurableObject(dirSeqStub(env), (_i: DirSeqDO, state) => {
      state.storage.sql.exec("INSERT OR REPLACE INTO meta (k, v) VALUES ('dbits', 0)");
      state.storage.sql.exec("DELETE FROM meta WHERE k = 'tobits'");
      state.storage.sql.exec("DELETE FROM mv");
    });
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    // The next write starts the move; new rows go to their new database at once.
    const fresh = makeAccount(freshHandle(), uidIn(1));
    await register(fresh);
    expect(
      await countIn(env.DB1, "SELECT count(*) AS n FROM user WHERE uid = ?1", fresh.uidB64),
    ).toBe(1);
    expect(errors.mock.calls.some((c) => /moving the directory's rows/.test(String(c[0])))).toBe(
      true,
    );
    // Every lookup keeps working while the alarm walks database 0 a page at a time.
    for (let i = 0; i < 64; i++) {
      expect((await dirByUid(env, legacy.uidB64))!.handle).toBe(legacy.handle);
      expect((await dirWrapsById(env, P.b64u(legacy.credId), null)).map((w) => w.dirseq)).toEqual([
        seq + 1,
      ]);
      if (!(await runDurableObjectAlarm(dirSeqStub(env)))) break;
    }
    const meta = await runInDurableObject(dirSeqStub(env), (_i: DirSeqDO, state) =>
      state.storage.sql
        .exec<{ k: string; v: number }>("SELECT k, v FROM meta ORDER BY k")
        .toArray(),
    );
    expect(meta).toEqual([{ k: "dbits", v: 1 }]);
    // The legacy rows are in database 1 and gone from 0, and every row sits in the database of its upre.
    expect(
      await countIn(env.DB1, "SELECT count(*) AS n FROM user WHERE uid = ?1", legacy.uidB64),
    ).toBe(1);
    expect(
      await countIn(env.DB1, "SELECT count(*) AS n FROM wrap WHERE uid = ?1", legacy.uidB64),
    ).toBe(1);
    expect(
      await countIn(env.DB, "SELECT count(*) AS n FROM user WHERE uid = ?1", legacy.uidB64),
    ).toBe(0);
    expect(
      await countIn(env.DB, "SELECT count(*) AS n FROM wrap WHERE uid = ?1", legacy.uidB64),
    ).toBe(0);
    expect(await countIn(env.DB, "SELECT count(*) AS n FROM user WHERE upre >= ?1", 2 ** 31)).toBe(
      0,
    );
    expect(await countIn(env.DB1, "SELECT count(*) AS n FROM user WHERE upre < ?1", 2 ** 31)).toBe(
      0,
    );
    expect(await dirState()).toEqual({
      users: s0.users + 2,
      wraps: s0.wraps + 3,
      head: s0.head + 3,
      meta: s0.meta + 1,
    });
    expect(errors.mock.calls.some((c) => /rows are in their databases/.test(String(c[0])))).toBe(
      true,
    );
  });

  it("a row that waits in the write-ahead log across a raise of DIR_SHARDS lands in its new database", async () => {
    // One database pinned; the deployment runs with one while the row is written, and database 0 refuses it.
    await runInDurableObject(dirSeqStub(env), (_i: DirSeqDO, state) => {
      state.storage.sql.exec("INSERT OR REPLACE INTO meta (k, v) VALUES ('dbits', 0)");
      state.storage.sql.exec("DELETE FROM meta WHERE k = 'tobits'");
      state.storage.sql.exec("DELETE FROM mv");
    });
    const a = makeAccount(freshHandle(), uidIn(1));
    const s0 = await dirState();
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    await env.DB.prepare("ALTER TABLE wrap RENAME TO wrap_off").run();
    try {
      await withDirSeqEnv(envWith({ DIR_SHARDS: "1" }), async () => {
        await rejects(register(a), 503, /directory unavailable/);
      });
      expect(await walSeqs()).toEqual([s0.head + 1]);
    } finally {
      await env.DB.prepare("ALTER TABLE wrap_off RENAME TO wrap").run();
    }
    // The deployment is back at two databases: the alarm starts the move, and the replay places the row by it.
    expect(await runDurableObjectAlarm(dirSeqStub(env))).toBe(true);
    expect(await walSeqs()).toEqual([]);
    expect(await countIn(env.DB1, "SELECT count(*) AS n FROM user WHERE uid = ?1", a.uidB64)).toBe(
      1,
    );
    expect(await countIn(env.DB1, "SELECT count(*) AS n FROM wrap WHERE uid = ?1", a.uidB64)).toBe(
      2,
    );
    expect(await countIn(env.DB, "SELECT count(*) AS n FROM user WHERE uid = ?1", a.uidB64)).toBe(
      0,
    );
    expect(await countIn(env.DB, "SELECT count(*) AS n FROM wrap WHERE uid = ?1", a.uidB64)).toBe(
      0,
    );
    for (let i = 0; i < 64; i++) if (!(await runDurableObjectAlarm(dirSeqStub(env)))) break;
    const meta = await runInDurableObject(dirSeqStub(env), (_i: DirSeqDO, state) =>
      state.storage.sql
        .exec<{ k: string; v: number }>("SELECT k, v FROM meta ORDER BY k")
        .toArray(),
    );
    expect(meta).toEqual([{ k: "dbits", v: 1 }]);
    expect((await dirByUid(env, a.uidB64))!.dirseq).toBe(s0.head + 1);
    expect(errors.mock.calls.some((c) => /user database write failed/.test(String(c[0])))).toBe(
      true,
    );
  });
});
