/**
 * Push, the Worker's part (docs/PROTOCOL.md §9.8, §10.10): the ids and boxes, the push store's key layout (shared with
 * BellDO and QuietDO), the ring (lookups at the BellDOs, `ring` at the QuietDOs, the hold, `due`, sending, `sent`), the
 * queue consumer for pushes due later than a Worker can wait, and the daily expiry.
 *
 * Nothing here writes: the Worker reads the store only in the daily expiry (key names and metadata), and sends the
 * pushes that a QuietDO hands it. The store is written by the objects alone, one writer per key.
 */
import { H, HMAC, aeadOpen, aeadSeal, concat, dec, enc, hex, t16, u16, u32, type Bytes } from "@segv/protocol/proto";
import { pushConfig, pushHostAllowed, pushShardsOf, type PushConfig } from "./env";
import { logErr } from "./http";
import { bellStub, quietStub } from "./types";
import { VapidSigner, encryptPayload, pushPayload } from "./webpush";

/** Bells per endpoint (params `push.maxTokens`). */
export const PUSH_TOKENS = 256;
/** Endpoints per bell: the first ones keep their places; a ninth is left out, never evicting. */
export const PUSH_PER_BELL = 8;
/** At most one push per endpoint per this many seconds (params `push.window`). */
export const PUSH_WINDOW = 60;
/** Seconds a push waits at least after the ring that made it due, for a mark of its row (§9.8 `ring`). */
export const PUSH_HOLD = 5;
/** Registrations not refreshed for more than this many days are deleted (§9.8 "Expiry"). */
export const PUSH_EXPIRY = 30;
/** Seconds a row that rang an endpoint is remembered for it, so that a retry of the ring changes nothing. */
export const RING_DEDUP = 120;
/** Rows remembered per waiting push; once more ring it, it can no longer be cancelled. */
export const PUSH_PENDING = 16;
/** Seconds a row marked seen is remembered per account. */
export const SEEN_TTL = 120;
/** Rows marked seen kept per account (a mark beyond them drops the one that expires first). */
export const PUSH_SEEN = 64;
/** `ring` answers a wait the Worker takes in `waitUntil` (≤ 30 s) only up to this; later pushes go through the queue. */
export const RING_WAIT = 20_000;
/** A failed attempt is retried once after this long, unless the answer's retry-after (≤ 60 s) says otherwise. */
export const RETRY_MS = 10_000;
/** A push in flight whose Worker never reported back is given up after this long. */
export const INFLIGHT_MS = 30_000;
const PUSH_TIMEOUT_MS = 10_000;
/** Pushes a Worker sends at the same time. */
const SEND_PARALLEL = 16;
const DAY_MS = 86_400_000;

export const dayOf = (ms: number): number => Math.floor(ms / DAY_MS);

// ───────────── ids, boxes and keys (§9.8 "The store") ─────────────

export const epOf = (key: Bytes, endpoint: string): Bytes => t16(HMAC(key, enc("segv.sh/v2/push/ep", endpoint)));
export const tkOf = (key: Bytes, bell: Bytes): Bytes => t16(HMAC(key, enc("segv.sh/v2/push/bell", bell)));
/** The keyed hash of a quiet tag: another label than a bell's, so neither ever matches the other. */
export const qkOf = (key: Bytes, quiet: Bytes): Bytes => t16(HMAC(key, enc("segv.sh/v2/push/quiet", quiet)));
/** The keyed hash of an endpoint's keys, kept in its record so that a change of keys re-places its bells. */
export const khOf = (key: Bytes, p256dh: Bytes, auth: Bytes): Bytes => t16(HMAC(key, enc("segv.sh/v2/push/keys", p256dh, auth)));
/** A row as rings and marks name it. */
export const rowIdOf = (E: number, label: Bytes): string => hex(t16(H(enc("segv.sh/v2/push/row", u16(E), label))));
const boxAad = (ep: Bytes): Bytes => enc("segv.sh/v2/push/sub", ep);

export interface Target {
  endpoint: string;
  p256dh: Bytes;
  auth: Bytes;
}

export const sealBox = (key: Bytes, ep: Bytes, t: Target): Bytes => aeadSeal(key, enc(t.endpoint, t.p256dh, t.auth), boxAad(ep));

export function openBox(key: Bytes, ep: Bytes, box: Bytes): Target | null {
  try {
    const [e, p, a] = dec(aeadOpen(key, box, boxAad(ep)), 3);
    if (p.length !== 65 || a.length !== 16) return null;
    return { endpoint: new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(e), p256dh: p.slice(), auth: a.slice() };
  } catch {
    return null;
  }
}

export const keyEp = (ep: Bytes): string => `e/${hex(ep)}`;
export const keyBell = (tk: Bytes): string => `b/${hex(tk)}`;
export const EP_PREFIX = "e/";

/** The owner of an endpoint: its quiet tag's keyed hash, or the endpoint's own hash when it registered none (§9.8). */
export const ownerOf = (ep: Bytes, qh: Bytes | null): Bytes => qh ?? ep;
const u32be = (b: Bytes): number => ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
/** `j = u32(tk[0..4]) mod PUSH_SHARDS`: the BellDO of a bell. */
export const bellShard = (tk: Bytes, shards: number): number => u32be(tk) % shards;
/** `k = u32(owner[0..4]) mod PUSH_SHARDS`: the QuietDO of an endpoint. */
export const quietShard = (owner: Bytes, shards: number): number => u32be(owner) % shards;

export const ZERO16: Bytes = new Uint8Array(16);
const isZero = (b: Bytes): boolean => b.every((x) => x === 0);
const cmp = (a: Bytes, b: Bytes): number => {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};
export const sameBytes = (a: Bytes, b: Bytes): boolean => cmp(a, b) === 0;
/** Distinct 16-byte values in ascending byte order. */
export function sortedDistinct(xs: readonly Bytes[]): Bytes[] {
  const out = [...xs].sort(cmp);
  return out.filter((x, i) => i === 0 || !sameBytes(x, out[i - 1]));
}

/** An endpoint's record, `e/<ep>`: `u32 day ‖ u8 notes ‖ qh[16] ‖ kh[16] ‖ tk[16] × n`. */
export interface EpRecord {
  day: number;
  notes: boolean;
  /** the quiet tag's keyed hash, or null when the endpoint registered none */
  qh: Bytes | null;
  /** the keyed hash of the endpoint's keys */
  kh: Bytes;
  /** the bells it holds, sorted */
  tks: Bytes[];
}

export function encodeRecord(r: EpRecord): Bytes {
  return concat(u32(r.day), Uint8Array.of(r.notes ? 1 : 0), r.qh ?? ZERO16, r.kh, ...r.tks);
}

export function decodeRecord(b: Bytes): EpRecord | null {
  if (b.length < 37 || (b.length - 37) % 16 !== 0) return null;
  const day = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(0);
  const notes = b[4] === 1;
  const qh = b.slice(5, 21);
  const kh = b.slice(21, 37);
  const tks: Bytes[] = [];
  for (let o = 37; o < b.length; o += 16) tks.push(b.slice(o, o + 16));
  return { day, notes, qh: isZero(qh) ? null : qh, kh, tks };
}

/** An entry of a bell's key, `b/<tk>`: `ep[16] ‖ qh[16] ‖ kh[16] ‖ u16 len ‖ box`. */
export interface BellEntry {
  ep: Bytes;
  qh: Bytes | null;
  kh: Bytes;
  box: Bytes;
}

export function encodeEntries(es: readonly BellEntry[]): Bytes {
  return concat(...es.map((e) => concat(e.ep, e.qh ?? ZERO16, e.kh, u16(e.box.length), e.box)));
}

export function decodeEntries(b: Bytes): BellEntry[] | null {
  const out: BellEntry[] = [];
  let o = 0;
  while (o < b.length) {
    if (o + 50 > b.length) return null;
    const len = (b[o + 48] << 8) | b[o + 49];
    if (o + 50 + len > b.length) return null;
    const qh = b.slice(o + 16, o + 32);
    out.push({ ep: b.slice(o, o + 16), qh: isZero(qh) ? null : qh, kh: b.slice(o + 32, o + 48), box: b.slice(o + 50, o + 50 + len) });
    o += 50 + len;
  }
  return out;
}

// ───────────── what crosses the RPC boundary ─────────────

/** An endpoint a ring reaches, as the lookups found it, with the ring's bells it was found under (in the ring's order). */
export interface RingTarget {
  ep: Bytes;
  qh: Bytes | null;
  kh: Bytes;
  box: Bytes;
  bells: Bytes[];
}

/** A push that `due` hands the Worker. */
export interface DuePush {
  ep: Bytes;
  kh: Bytes;
  box: Bytes;
  /** the bells to name, newest first, at most PUSH_BELLS */
  rang: Bytes[];
}

export type SentOutcome = "sent" | "retry" | "gone";

/** What the Worker reports for a push it sent (§9.8 `sent`). */
export interface SentReport {
  ep: Bytes;
  kh: Bytes;
  outcome: SentOutcome;
  /** the answer's retry-after in seconds, when it gave one */
  retryAfterS: number | null;
}

/** A queue message: the QuietDO to ask, and nothing else (§9.8 "The Worker's part"). */
export interface PushQueueMessage {
  k: number;
}

// ───────────── the ring (§10.10 steps 3–4) ─────────────

const realSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
let ringSleep = realSleep;
/** Test hook: how the Worker waits for the push that a ring made due (null: a real timer). */
export function _setRingSleepForTests(f: ((ms: number) => Promise<void>) | null): void {
  ringSleep = f ?? realSleep;
}

type Fetcher = (url: string, init: RequestInit) => Promise<Response>;
const realFetch: Fetcher = (url, init) => fetch(url, init);
let pushFetch: Fetcher = realFetch;
/** Test hook: the request a push is sent with (null: the real fetch). */
export function _setPushFetchForTests(f: Fetcher | null): void {
  pushFetch = f ?? realFetch;
}

/**
 * Looks the ring's bells up at their BellDOs, calls `ring` on the QuietDO of each endpoint found, and for each time
 * answered waits in place (≤ RING_WAIT) and sends, or queues a message for later (§9.8 "The Worker's part").
 */
export async function pushRing(env: Env, cfg: PushConfig, E: number, label: Bytes, tokens: Bytes[]): Promise<void> {
  const shards = cfg.shards;
  const bells = new Map<string, Bytes>();
  for (const b of tokens) bells.set(hex(b), b);
  const byShard = new Map<number, { b: Bytes; tk: Bytes }[]>();
  for (const b of bells.values()) {
    const tk = tkOf(cfg.pushKey, b);
    const j = bellShard(tk, shards);
    const list = byShard.get(j);
    if (list) list.push({ b, tk });
    else byShard.set(j, [{ b, tk }]);
  }
  const found = new Map<string, BellEntry[]>();
  await Promise.all(
    [...byShard].map(async ([j, list]) => {
      const res = await bellStub(env, j).lookup(list.map((x) => x.tk));
      for (const r of res) found.set(hex(r.tk), r.entries);
    }),
  );
  // Each endpoint with the ring's bells it was found under, in the ring's order; grouped by its QuietDO.
  const targets = new Map<string, RingTarget>();
  for (const b of bells.values()) {
    for (const e of found.get(hex(tkOf(cfg.pushKey, b))) ?? []) {
      const k = hex(e.ep);
      const t = targets.get(k) ?? { ep: e.ep, qh: e.qh, kh: e.kh, box: e.box, bells: [] };
      t.bells.push(b);
      targets.set(k, t);
    }
  }
  const byOwner = new Map<number, RingTarget[]>();
  for (const t of targets.values()) {
    const k = quietShard(ownerOf(t.ep, t.qh), shards);
    const list = byOwner.get(k);
    if (list) list.push(t);
    else byOwner.set(k, [t]);
  }
  const row = rowIdOf(E, label);
  await Promise.all(
    [...byOwner].map(async ([k, list]) => {
      const wait = await quietStub(env, k).ring(list, row);
      if (wait !== null) await schedule(env, k, wait, false);
    }),
  );
}

/** Sends after `waitMs` in place when that fits `waitUntil` and `inPlace` allows, else from a queue message then. */
async function schedule(env: Env, k: number, waitMs: number, retry: boolean): Promise<void> {
  if (!retry && waitMs <= RING_WAIT) {
    await ringSleep(waitMs);
    await sendDue(env, k);
    return;
  }
  const msg: PushQueueMessage = { k };
  await env.PUSH_QUEUE.send(msg, { delaySeconds: Math.max(1, Math.ceil(waitMs / 1000)) });
}

/** Asks QuietDO k for the pushes due now, sends them, and reports; a retry that `sent` answers is queued. */
export async function sendDue(env: Env, k: number): Promise<void> {
  const cfg = pushConfig(env);
  if (!cfg) return;
  const stub = quietStub(env, k);
  const due = await stub.due();
  if (due.length === 0) return;
  const reports: SentReport[] = [];
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < due.length) reports.push(await sendOne(cfg, due[next++]));
  };
  await Promise.all(Array.from({ length: Math.min(SEND_PARALLEL, due.length) }, worker));
  const tally = { sent: 0, retry: 0, gone: 0 };
  for (const r of reports) tally[r.outcome]++;
  if (tally.retry + tally.gone > 0) console.error(JSON.stringify({ msg: "push results", ...tally }));
  const retryWait = await stub.sent(reports);
  if (retryWait !== null) await schedule(env, k, retryWait, true);
}

/** The queue consumer: every message names a QuietDO whose due pushes are sent (§9.8 "The Worker's part"). */
export async function pushQueue(batch: MessageBatch<unknown>, env: Env): Promise<void> {
  const ks = new Map<number, Message<unknown>[]>();
  for (const m of batch.messages) {
    const k = (m.body as { k?: unknown } | null)?.k;
    if (!Number.isInteger(k) || (k as number) < 0 || (k as number) >= 4096) {
      m.ack(); // not one of ours: never retried
      continue;
    }
    const list = ks.get(k as number);
    if (list) list.push(m);
    else ks.set(k as number, [m]);
  }
  await Promise.all(
    [...ks].map(async ([k, msgs]) => {
      try {
        await sendDue(env, k);
        for (const m of msgs) m.ack();
      } catch (e) {
        console.error(JSON.stringify({ msg: "push queue failed", error: logErr(e) }));
        for (const m of msgs) m.retry({ delaySeconds: 10 });
      }
    }),
  );
}

/** The daily expiry (§9.8 "Expiry"): endpoints whose day lies more than PUSH_EXPIRY days back are deleted by their owners. */
export async function pushCleanup(env: Env, now = Date.now()): Promise<{ scanned: number; expired: number }> {
  const today = dayOf(now);
  const shards = pushShardsOf(env) ?? 1;
  let cursor: string | undefined;
  let scanned = 0;
  let expired = 0;
  do {
    const page = await env.PUSH_KV.list<{ d?: unknown; o?: unknown }>({ prefix: EP_PREFIX, cursor, limit: 1000 });
    for (const key of page.keys) {
      scanned++;
      const d = key.metadata?.d;
      const o = key.metadata?.o;
      const epHex = key.name.slice(EP_PREFIX.length);
      if (typeof d !== "number" || typeof o !== "string" || !/^[0-9a-f]{32}$/.test(o) || !/^[0-9a-f]{32}$/.test(epHex)) continue;
      if (today - d <= PUSH_EXPIRY) continue;
      const owner = fromHex(o);
      try {
        await quietStub(env, quietShard(owner, shards)).drop(fromHex(epHex));
        expired++;
      } catch (e) {
        console.error(JSON.stringify({ msg: "push expiry failed", error: logErr(e) }));
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  if (expired > 0) console.error(JSON.stringify({ msg: "push expiry", scanned, expired }));
  return { scanned, expired };
}

const fromHex = (h: string): Bytes => Uint8Array.from(h.match(/../g)!.map((x) => parseInt(x, 16)));

// ───────────── sending (§9.8 "Sending a push") ─────────────

let signer: { cfg: PushConfig; s: VapidSigner } | null = null;

/** retry-after in delta-seconds (an HTTP date counts as absent). */
function retryAfterS(v: string | null): number | null {
  return v !== null && /^\d{1,6}$/.test(v.trim()) ? Number(v.trim()) : null;
}

/** One Web Push message for a due push; what the answer means is the report (§9.8). */
async function sendOne(cfg: PushConfig, p: DuePush): Promise<SentReport> {
  const report = (outcome: SentOutcome, retry: number | null = null): SentReport => ({ ep: p.ep, kh: p.kh, outcome, retryAfterS: retry });
  const t = openBox(cfg.pushKey, p.ep, p.box);
  let url: URL | null = null;
  try {
    if (t) url = new URL(t.endpoint);
  } catch {
    url = null;
  }
  if (!t || !url || !pushHostAllowed(cfg, url.hostname)) return report("gone");
  const at = Date.now();
  let status: number | "error";
  let retryAfter: string | null = null;
  // A timer cleared as soon as the answer is in (AbortSignal.timeout would stay pending for the full 10 s).
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), PUSH_TIMEOUT_MS);
  try {
    signer = signer?.cfg === cfg ? signer : { cfg, s: new VapidSigner(cfg.vapidSk, cfg.vapidSub) };
    const body = await encryptPayload(pushPayload(cfg.appHost, p.rang), t.p256dh, t.auth);
    const authorization = await signer.s.authorization(url.origin, at);
    const res = await pushFetch(t.endpoint, {
      method: "POST",
      headers: {
        TTL: "86400",
        // Push services deliver other values when it suits the device's battery; Apple's service only `high` at once.
        Urgency: "high",
        Topic: "segv",
        "Content-Encoding": "aes128gcm",
        "Content-Type": "application/octet-stream",
        Authorization: authorization,
      },
      body: body as BodyInit,
      redirect: "manual",
      signal: abort.signal,
    });
    status = res.status;
    retryAfter = res.headers.get("retry-after");
    await res.body?.cancel().catch(() => {});
  } catch (e) {
    // Keys that cannot be encrypted to: no push service would ever take this endpoint.
    if (e instanceof RangeError) return report("gone");
    status = "error";
  } finally {
    clearTimeout(timer);
  }
  if (typeof status === "number" && status >= 200 && status < 300) return report("sent");
  if (status === "error" || status === 429 || status >= 500) return report("retry", retryAfterS(retryAfter));
  // A 3xx (never followed) or any other 4xx: no push service accepts this endpoint any more.
  return report("gone");
}
