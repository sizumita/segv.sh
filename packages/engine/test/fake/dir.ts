/**
 * The D1 directory fake (docs/PROTOCOL.md §2.4, §9.6, §10.6): users, wrap records and the dirlog chain, with
 * the server's validation (canonical signed JSON, signatures, checkUserKeys, 409 on a taken handle / uid / wrap,
 * 64 wraps per uid) and the prefix lookups (`p ≤ min(32, P + 1)`, ordered by uid, 256 per page).
 *
 * `register(body)` and `postWrap(body)` are the HTTP handlers and are also called directly by tests (e.g. to register
 * a user between two engines' evaluations). They return the HTTP status and JSON body.
 *
 * Failure knob: `failDir(pred, n)` (prefix lookups for which `pred` holds answer 503 n times).
 */
import {
  MAX_ID_LEN,
  ZERO32,
  b64u,
  bundleSigMsg,
  checkUserKeys,
  dirlogH,
  dirlogRefUser,
  dirlogRefWrap,
  DIRLOG_USER,
  DIRLOG_WRAP,
  era,
  fromB64u,
  hpre,
  parseBundle,
  parseWrap,
  prefixRange,
  serverP,
  upre,
  verify,
  wrapSigMsg,
  type Bytes,
  type User,
  type WrapRecord,
} from "@segv/protocol/proto";
import { err, json, type Res, type WorldCtx } from "./common";

export interface DirUserRow {
  uid: string;
  upre: number;
  handle: string;
  hpre: number;
  bundle: string;
  sig: string;
  regEra: number;
  dirseq: number;
}

export interface DirWrapRow {
  uid: string;
  id: string;
  record: string;
  sig: string;
  dirseq: number;
}

export interface DirlogRow {
  seq: number;
  kind: number;
  ref: string;
  h: string;
}

/** A prefix lookup (`GET /api/v2/dir/{kind}/{p}/{x}[?after=]`) as `failDir` predicates see it. */
export interface DirPrefixQuery {
  kind: "h" | "u";
  p: number;
  x: number;
  /** the `after` uid (b64u), or null */
  after: string | null;
  /** the requesting client (FakeWorld request attribution), or null */
  who: string | null;
}

/** The JSON shape of a user in lookups (§10.6). */
export const userJson = (u: DirUserRow) => ({
  uid: u.uid,
  handle: u.handle,
  bundle: u.bundle,
  sig: u.sig,
  regEra: u.regEra,
  dirseq: u.dirseq,
});

const MAX_SIGNED_TEXT = 8 * 1024;
export const MAX_WRAPS_PER_UID = 64;
export const PREFIX_PAGE = 256;

/** Exactly these keys (any order), else a 400 message. */
function exactKeys(
  x: unknown,
  keys: readonly string[],
  what: string,
): Record<string, unknown> | string {
  if (typeof x !== "object" || x === null || Array.isArray(x)) return `${what}: expected an object`;
  const got = Object.keys(x);
  if (got.length !== keys.length || !keys.every((k) => got.includes(k)))
    return `${what}: expected keys ${keys.join(", ")}`;
  return x as Record<string, unknown>;
}

/** The server's canonical-form rule for signed JSON (§1.2); key order and set are checked by the parsers. */
const canonical = (text: string): boolean => JSON.stringify(JSON.parse(text)) === text;

const why = (e: unknown): string => (e instanceof Error ? e.message : String(e));

export class FakeDirectory {
  readonly users = new Map<string, DirUserRow>();
  private readonly byHandle = new Map<string, string>();
  readonly wraps: DirWrapRow[] = [];
  readonly log: DirlogRow[] = [];
  private headH: Bytes = ZERO32;
  /** dirmeta.users */
  userCount = 0;
  /** failDir rules, in the order they were added */
  private readonly failRules: { pred: (q: DirPrefixQuery) => boolean; left: number }[] = [];

  constructor(private readonly w: WorldCtx) {}

  /** P = max(0, ⌊log2(users / 32)⌋), as reported in params. */
  get P(): number {
    return serverP(this.userCount);
  }

  head(): { seq: number; h: Bytes } {
    return { seq: this.log.length, h: this.headH };
  }

  // ───────────── writes ─────────────

  /** POST /api/v2/register: `{bundle, sig, wraps: [{record, sig}, …1..4]}`. */
  register(body: unknown): Res {
    const o = exactKeys(body, ["bundle", "sig", "wraps"], "register");
    if (typeof o === "string") return err(400, o);
    const u = this.checkBundle(o.bundle, o.sig);
    if (typeof u === "string") return err(400, u);
    if (!Array.isArray(o.wraps) || o.wraps.length < 1 || o.wraps.length > 4)
      return err(400, "wraps: expected 1..4 records");
    const recs: WrapRecord[] = [];
    for (const [i, x] of (o.wraps as unknown[]).entries()) {
      const r = this.checkRecord(x, `wraps[${i}]`);
      if (typeof r === "string") return err(400, r);
      if (r.uid !== u.uid) return err(400, `wraps[${i}]: uid does not match the bundle`);
      if (!verify(fromB64u(r.sig), wrapSigMsg(r.record), u.sigPk))
        return err(400, `wraps[${i}]: bad signature`);
      if (recs.some((p) => b64u(p.id) === b64u(r.id))) return err(400, `wraps[${i}]: duplicate id`);
      recs.push(r);
    }
    if (this.byHandle.has(u.handle) || this.users.has(u.uid))
      return err(409, "handle or uid already taken");
    const dirseq = this.append(DIRLOG_USER, dirlogRefUser(u.bundle, fromB64u(u.bundleSig)));
    const row: DirUserRow = {
      uid: u.uid,
      upre: upre(fromB64u(u.uid)),
      handle: u.handle,
      hpre: hpre(u.handle),
      bundle: u.bundle,
      sig: u.bundleSig,
      regEra: era(this.w.now()),
      dirseq,
    };
    this.users.set(u.uid, row);
    this.byHandle.set(u.handle, u.uid);
    this.userCount++;
    for (const r of recs) this.addWrapRow(r);
    this.w.bumpWrites();
    return json(200, { dirseq });
  }

  /** POST /api/v2/wraps: `{record, sig}`. */
  postWrap(body: unknown): Res {
    const r = this.checkRecord(body, "wrap");
    if (typeof r === "string") return err(400, r);
    const owner = this.users.get(r.uid);
    if (!owner) return err(404, "unknown uid");
    const ownerKey = parseBundle(owner.bundle, owner.sig).sigPk;
    if (!verify(fromB64u(r.sig), wrapSigMsg(r.record), ownerKey))
      return err(400, "bad wrap signature");
    const mine = this.wraps.filter((x) => x.uid === r.uid);
    if (mine.length >= MAX_WRAPS_PER_UID)
      return err(400, `at most ${MAX_WRAPS_PER_UID} wraps per account`);
    if (mine.some((x) => x.id === b64u(r.id))) return err(409, "wrap already exists");
    const dirseq = this.addWrapRow(r);
    this.w.bumpWrites();
    return json(200, { dirseq });
  }

  // ───────────── reads ─────────────

  /** GET /api/v2/dir/{h|u}/{p}/{x}[?after=uid] (p and x already range-checked). */
  byPrefix(kind: "h" | "u", p: number, x: number, after: string | null): Res {
    const P = this.P;
    if (p > Math.min(32, P + 1)) return err(409, "prefix bits out of range", { p: P });
    const { lo, hi } = prefixRange(p, x);
    const rows = [...this.users.values()]
      .filter((u) => {
        const pre = kind === "h" ? u.hpre : u.upre;
        return pre >= lo && pre <= hi && (after === null || u.uid > after);
      })
      .sort((a, b) => (a.uid < b.uid ? -1 : a.uid > b.uid ? 1 : 0));
    return json(200, {
      p,
      users: rows.slice(0, PREFIX_PAGE).map(userJson),
      more: rows.length > PREFIX_PAGE,
    });
  }

  byUid(uid: string): DirUserRow | null {
    return this.users.get(uid) ?? null;
  }

  byHandleName(handle: string): DirUserRow | null {
    const uid = this.byHandle.get(handle);
    return uid ? this.users.get(uid)! : null;
  }

  /** GET /api/v2/dir/wraps/{id}[?uid=]: at most 64, oldest first. */
  wrapsById(idB: string, uidB: string | null): DirWrapRow[] {
    return this.wraps
      .filter((x) => x.id === idB && (uidB === null || x.uid === uidB))
      .sort((a, b) => a.dirseq - b.dirseq)
      .slice(0, MAX_WRAPS_PER_UID);
  }

  /** GET /api/v2/dirlog?after=&limit=. */
  dirlog(after: number, limit: number): { entries: DirlogRow[]; head: { seq: number; h: string } } {
    return {
      entries: this.log.filter((e) => e.seq > after).slice(0, limit),
      head: { seq: this.log.length, h: b64u(this.headH) },
    };
  }

  // ───────────── failure knob ─────────────

  /**
   * The next `n` prefix lookups (`GET /api/v2/dir/{h|u}/{p}/{x}`) for which `pred` holds answer 503
   * `{error: "directory unavailable"}`, as the Worker does when D1 fails (§9.6, §10.6). A lookup fails after its
   * path and query checks (a malformed one still gets its 400 and consumes nothing) and RL_READ, before the
   * prefix-bits check (409). Rules add up: a lookup consumes one failure of the first rule that matches. n = Infinity
   * fails until `failDir(null)`, which removes every rule. Other directory routes (`dir/uid`, `dir/wraps`, `dirlog`,
   * register, wraps) are not affected.
   */
  failDir(pred: ((q: DirPrefixQuery) => boolean) | null, n = 1): void {
    if (pred === null) this.failRules.length = 0;
    else if (n > 0) this.failRules.push({ pred, left: n });
  }

  /** (internal) Consumes one failure for this lookup; true when it must answer 503. */
  takeDirFailure(q: DirPrefixQuery): boolean {
    const i = this.failRules.findIndex((r) => r.pred({ ...q }));
    if (i < 0) return false;
    const r = this.failRules[i];
    if (--r.left <= 0) this.failRules.splice(i, 1);
    return true;
  }

  // ───────────── internals ─────────────

  private checkBundle(bundle: unknown, sig: unknown): User | string {
    if (typeof bundle !== "string" || typeof sig !== "string") return "bundle: expected strings";
    if (bundle.length > MAX_SIGNED_TEXT) return "bundle: too large";
    let u: User;
    try {
      u = parseBundle(bundle, sig);
      if (!canonical(bundle)) return "invalid bundle (not canonical JSON)";
    } catch (e) {
      return `invalid bundle (${why(e)})`;
    }
    if (!verify(fromB64u(sig), bundleSigMsg(bundle), u.sigPk))
      return "invalid bundle (bad signature)";
    try {
      checkUserKeys(u.sigPk, u.kemPk);
    } catch (e) {
      return `invalid bundle (${why(e)})`;
    }
    return u;
  }

  private checkRecord(x: unknown, what: string): WrapRecord | string {
    const o = exactKeys(x, ["record", "sig"], what);
    if (typeof o === "string") return o;
    if (typeof o.record !== "string" || typeof o.sig !== "string")
      return `${what}: expected strings`;
    if (o.record.length > MAX_SIGNED_TEXT) return `${what}: too large`;
    try {
      const r = parseWrap(o.record, o.sig);
      if (!canonical(o.record)) return `${what}: not canonical JSON`;
      if (r.id.length > MAX_ID_LEN) return `${what}: bad id`;
      return r;
    } catch (e) {
      return `${what}: invalid record (${why(e)})`;
    }
  }

  private addWrapRow(r: WrapRecord): number {
    const dirseq = this.append(DIRLOG_WRAP, dirlogRefWrap(r.record, fromB64u(r.sig)));
    this.wraps.push({ uid: r.uid, id: b64u(r.id), record: r.record, sig: r.sig, dirseq });
    return dirseq;
  }

  private append(kind: number, ref: Bytes): number {
    const seq = this.log.length + 1;
    this.headH = dirlogH(this.headH, seq, kind, ref);
    this.log.push({ seq, kind, ref: b64u(ref), h: b64u(this.headH) });
    return seq;
  }
}
