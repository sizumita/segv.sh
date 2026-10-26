/** Shared helpers for the Workers-runtime tests. */
import { exports } from "cloudflare:workers";
import { expect } from "vitest";
import * as P from "../../src/lib/proto";

/** Base difficulties: must match "vars" in ./wrangler.test.jsonc. */
export const DIFF: Record<P.PowScope, number> = { register: 6, wrap: 5, append: 4, blob: 5 };
/** The host the tests talk to (listed in APP_HOSTS in ./wrangler.test.jsonc). */
export const ORIGIN = "https://segv.test";

let ipSeq = Math.floor(Math.random() * 0xffff) << 8;
/** A distinct client IPv4 per call, so rate limits only bite where a test wants them to. */
export const freshIp = (): string => {
  ipSeq = (ipSeq + 1) & 0xffffff;
  return `10.${ipSeq >> 16}.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
};

type ApiInit = Omit<RequestInit, "body"> & {
  body?: BodyInit | Uint8Array | null;
  ip?: string;
  origin?: string;
};

/**
 * Calls the test Worker (./entry.ts). Every request gets a client IP (fresh unless `ip` is given).
 * `origin` replaces the scheme + host of the request URL (default ORIGIN).
 */
export async function api(path: string, init: ApiInit = {}): Promise<Response> {
  const { ip, body, origin = ORIGIN, ...rest } = init;
  const headers = new Headers(rest.headers);
  if (!headers.has("cf-connecting-ip")) headers.set("cf-connecting-ip", ip ?? freshIp());
  const worker = (exports as unknown as { default: Fetcher }).default;
  return worker.fetch(
    new Request(`${origin}${path}`, {
      ...rest,
      headers,
      body: body as BodyInit | null | undefined,
    }),
  );
}

export const currentWindow = (): number => Math.floor(Date.now() / P.POW_WINDOW_MS);

/** Difficulty the server requires for a request of `bytes` bytes (the request body; blobs: the blob). */
export const need = (scope: P.PowScope, bytes: number): number =>
  P.powDifficulty(scope, DIFF[scope], bytes);

/** A PoW header for (scope, digest). `bytes` prices it like the server does; `difficulty` overrides. */
export async function powHeader(
  scope: P.PowScope,
  digest: Uint8Array,
  opts: { bytes?: number; window?: number; difficulty?: number } = {},
) {
  const window = opts.window ?? currentWindow();
  const nonce = await P.powSolve(
    P.powPre(scope, window, digest),
    opts.difficulty ?? need(scope, opts.bytes ?? 0),
  );
  return `${window}.${nonce}`;
}

/** A nonce that does NOT satisfy `difficulty` for (scope, window, digest). */
export function badNonce(
  scope: P.PowScope,
  window: number,
  digest: Uint8Array,
  difficulty = DIFF[scope],
): number {
  const pre = P.powPre(scope, window, digest);
  for (let n = 0; ; n++) if (!P.powCheck(pre, n, difficulty)) return n;
}

/** A nonce that satisfies `atLeast` but not `below` bits for (scope, window, digest). */
export function nonceBetween(
  scope: P.PowScope,
  window: number,
  digest: Uint8Array,
  atLeast: number,
  below: number,
): number {
  const pre = P.powPre(scope, window, digest);
  for (let n = 0; ; n++) if (P.powCheck(pre, n, atLeast) && !P.powCheck(pre, n, below)) return n;
}

export const jsonBytes = (body: unknown): Uint8Array => P.utf8(JSON.stringify(body));

/** POST with a valid proof of work over the exact bytes sent. */
export async function postPow(
  path: string,
  scope: P.PowScope,
  body: unknown,
  extraHeaders: Record<string, string> = {},
) {
  const bytes = body instanceof Uint8Array ? body : jsonBytes(body);
  return api(path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-segv-pow": await powHeader(scope, P.H(bytes), { bytes: bytes.length }),
      ...extraHeaders,
    },
    body: bytes,
  });
}

export const uniqueHandle = (): string => `t_${P.hex(P.random(6))}`;

export interface Account {
  AK: Uint8Array;
  ident: P.Identity;
  uid: Uint8Array;
  uidB64: string;
  handle: string;
  bundle: string;
  sig: string;
  credId: Uint8Array;
  /** Passkey unlock key (what the PRF output derives). */
  cred: P.UnlockKey;
  recId: Uint8Array;
  /** Recovery-code unlock key. */
  rec: P.UnlockKey;
  passkey: { record: string; sig: string };
  recovery: { record: string; sig: string };
}

export function makeAccount(handle = uniqueHandle(), uid = P.random(16)): Account {
  const AK = P.random(32);
  const ident = P.deriveIdentity(AK);
  const ts = Date.now();
  const { bundle, sig } = P.makeBundle(uid, handle, ident, ts);
  const credId = P.random(32);
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
    recId: rec.id,
    rec,
    passkey: P.makeWrap(uid, "passkey", credId, cred, AK, ident, ts),
    recovery: P.makeWrap(uid, "recovery", rec.id, rec, AK, ident, ts),
  };
}

export const registerBody = (a: Account, wraps = [a.passkey, a.recovery]) => ({
  bundle: a.bundle,
  sig: a.sig,
  wraps,
});

export async function registerOk(a: Account): Promise<number> {
  const res = await postPow("/api/register", "register", registerBody(a));
  expect(res.status, await res.clone().text()).toBe(200);
  const { seq } = (await res.json()) as { seq: number };
  return seq;
}

export interface WireRow {
  seq: number;
  kind: number;
  tag: string;
  body: string;
  ts: number;
  h: string;
}
export interface LogPage {
  rows: WireRow[];
  head: { seq: number; h: string };
}

export async function getLog(after: number, limit?: number): Promise<LogPage> {
  const res = await api(`/api/log?after=${after}${limit === undefined ? "" : `&limit=${limit}`}`);
  expect(res.status).toBe(200);
  return (await res.json()) as LogPage;
}

/**
 * The client paging contract: pages may be short (byte budget), so keep going until the last row's seq
 * reaches head.seq (or a page is empty). Returns every row after `after` and the pages' sizes.
 */
export async function pageToHead(
  after: number,
  limit = 1000,
): Promise<{ rows: WireRow[]; head: { seq: number; h: string }; sizes: number[] }> {
  const rows: WireRow[] = [];
  const sizes: number[] = [];
  for (;;) {
    const page = await getLog(after, limit);
    sizes.push(page.rows.length);
    if (page.rows.length > 0) expect(page.rows[0].seq).toBe(after + 1);
    rows.push(...page.rows);
    if (page.rows.length === 0) return { rows, head: page.head, sizes };
    after = page.rows[page.rows.length - 1].seq;
    if (after >= page.head.seq) return { rows, head: page.head, sizes };
  }
}

export async function head(): Promise<{ seq: number; h: string }> {
  return (await getLog(0, 1)).head;
}

/** Downloads the whole log page by page and verifies the hash chain from h_0 like a client does. */
export async function downloadVerified(
  pageLimit: number,
): Promise<{ rows: WireRow[]; head: { seq: number; h: string }; pages: number }> {
  let after = 0;
  let h: Uint8Array = P.ZERO32;
  const rows: WireRow[] = [];
  let pages = 0;
  for (;;) {
    const page = await getLog(after, pageLimit);
    pages++;
    expect(page.rows.length).toBeLessThanOrEqual(pageLimit);
    for (const r of page.rows) {
      expect(r.seq).toBe(after + 1); // no gaps
      h = P.rowHash(h, r.seq, r.kind, P.fromB64u(r.tag), P.fromB64u(r.body), r.ts);
      expect(r.h).toBe(P.b64u(h));
      expect(r.ts % 1000).toBe(0);
      after = r.seq;
      rows.push(r);
    }
    if (page.rows.length === 0 || after >= page.head.seq) {
      expect(after).toBe(page.head.seq);
      expect(page.head.h).toBe(P.b64u(h));
      return { rows, head: page.head, pages };
    }
  }
}

/** A minimal 1:1 conversation epoch between `from` and `to` (docs/PROTOCOL.md §3.1). */
export function makeEpoch(from: Account, to: Account) {
  const conv = P.random(16);
  const EK = P.random(32);
  const keys = P.epochKeys(EK, conv, 0);
  const dText = P.makeDescriptor({
    conv: P.b64u(conv),
    e: 0,
    members: [from.uidB64, to.uidB64],
    prev: null,
    by: from.uidB64,
    ts: Date.now(),
  });
  const dsig = P.signDescriptor(dText, keys.kc, from.ident.sigSk);
  return { conv, EK, keys, dText, dsig };
}

export function makeMsg(
  ep: ReturnType<typeof makeEpoch>,
  from: Account,
  n: number,
  text: string,
): P.Row {
  const tag = P.msgTag(ep.keys.rk, 0, n);
  const payload: P.Payload = {
    v: 1,
    t: "text",
    conv: P.b64u(ep.conv),
    e: 0,
    from: from.uidB64,
    n,
    ts: Date.now(),
    text,
    head: { seq: 0, h: P.b64u(P.ZERO32) },
  };
  return P.makeMessage(ep.keys.mk, tag, payload, from.ident.sigSk);
}

export const wireRows = (rows: P.Row[]) =>
  rows.map((r) => ({ kind: r.kind, tag: P.b64u(r.tag), body: P.b64u(r.body) }));

/** A syntactically valid kind-4 row with a random tag (random "ciphertext"). */
export const randomMsgRow = (size = P.MSG_BODY_LENS[0]): P.Row => ({
  kind: 4,
  tag: P.random(16),
  body: P.random(size),
});
/** A syntactically valid kind-3 row (invite) with a random tag. */
export const randomInvRow = (): P.Row => ({
  kind: 3,
  tag: P.random(16),
  body: P.random(P.INV_BODY_LENS[0]),
});

export async function appendOk(rows: P.Row[]): Promise<number[]> {
  const res = await postPow("/api/append", "append", { rows: wireRows(rows) });
  expect(res.status, await res.clone().text()).toBe(200);
  return ((await res.json()) as { seqs: number[] }).seqs;
}

export async function errorOf(res: Response): Promise<string> {
  const j = (await res.json()) as { error?: unknown };
  expect(typeof j.error).toBe("string");
  return j.error as string;
}
