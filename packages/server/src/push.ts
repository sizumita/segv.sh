/**
 * Push, the Worker's part (docs/PROTOCOL.md §9.8, §10.10): the ids and boxes, the push store's key layout (shared with
 * QuietDO), the ring (the bells' entries read from the store, `ring` at the QuietDOs, the hold, `due`, sending,
 * `sent`), the queue consumer for pushes due later than a Worker can wait, and the daily expiry.
 *
 * Nothing here writes the store: the Worker reads it at a ring (the `b/` key of each bell), at a registration (the
 * owner its record's metadata names) and in the daily expiry (key names and metadata), and sends the pushes that a
 * QuietDO hands it. The store is written by the QuietDOs alone, one writer per key.
 */
import { hexToBytes } from "@noble/hashes/utils.js";
import { H, HMAC, aeadOpen, aeadSeal, concat, dec, enc, hex, t16, u16, u32, type Bytes } from "@segv/protocol/proto";
import { pushConfig, pushHostAllowed, pushShardsOf, type PushConfig } from "./env";
import { logErr } from "./http";
import { quietStub } from "./types";
import { VapidSigner, encryptPayload, pushPayload } from "./webpush";

/** Bell secrets per endpoint (params `push.maxTokens`). */
export const PUSH_TOKENS = 256;
/** Endpoints per bell (all of its account's, since registering needs the secret): the first ones keep their places. */
export const PUSH_PER_BELL = 8;
/** A ring's reads of `b/` keys may be served from the edge's cache for this long (the KV minimum). */
export const KV_CACHE_TTL_S = 60;
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
/**
 * A ring's Worker waits in `waitUntil` (cancelled 30 s after the answer) only while the wait ends within this of the
 * answer, and then sends one round of pushes (each ≤ PUSH_TIMEOUT_MS); anything later goes through the queue.
 */
export const RING_WAIT = 15_000;
/** A failed attempt is retried once after this long, unless the answer's retry-after (≤ 60 s) says otherwise. */
export const RETRY_MS = 10_000;
const PUSH_TIMEOUT_MS = 10_000;
/** Pushes a Worker sends at the same time (an invocation waits for the headers of at most 6 requests at once). */
export const SEND_PARALLEL = 6;
/** The most pushes one `due` hands out: what SEND_PARALLEL requests send in 4 rounds. */
export const DUE_BATCH = 24;
/** The pushes the Worker of a ring takes for its one round in `waitUntil`. */
export const IN_PLACE_BATCH = SEND_PARALLEL;
/**
 * A push handed out by `due` whose Worker never reported back (it was stopped) is due again after this long: longer
 * than a batch of DUE_BATCH takes to send.
 */
export const INFLIGHT_MS = 60_000;
/** A queue consumer goes on asking a QuietDO for more pushes due now for this long, then queues the rest. */
const CONSUME_MS = 60_000;
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

/**
 * The owner of an endpoint (§9.8): its quiet tag's keyed hash, or, for a record of the first release, which registered
 * none, the endpoint's own hash.
 */
export const ownerOf = (ep: Bytes, qh: Bytes | null): Bytes => qh ?? ep;
/** `k = u32(owner[0..4]) mod PUSH_SHARDS`: the QuietDO of an endpoint. */
export function quietShard(owner: Bytes, shards: number): number {
  if (!(owner instanceof Uint8Array) || owner.length < 4) throw new Error("owner must be at least 4 bytes");
  if (!Number.isInteger(shards) || shards < 1 || shards > 4096) throw new Error("bad quiet shard count");
  return new DataView(owner.buffer, owner.byteOffset, 4).getUint32(0) % shards;
}

export const ZERO16: Bytes = new Uint8Array(16);
export const isZero = (b: Bytes): boolean => b.every((x) => x === 0);
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

/** An entry of a bell's key, `b/<tk>`: `ep[16] ‖ qh[16] ‖ kh[16] ‖ u16 len ‖ box` (an endpoint of the bell's account). */
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

/** An endpoint a ring reaches, as the store lists it, with the ring's bells it was found under (in the ring's order). */
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

/** What `due` answers: the pushes handed out, and the time until the Worker is to ask again (null: no need). */
export interface DueBatch {
  pushes: DuePush[];
  next: number | null;
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

/**
 * A message on the push queue (§9.8 "The Worker's part", "Expiry"): `{k}` names a QuietDO to ask for its due pushes;
 * `{k, expire, day}` names endpoints (hex ep) the daily expiry of `day` found expired among those QuietDO k owns;
 * `{list, day}` is where that expiry's listing goes on (a cursor of the store's listing).
 */
export type PushQueueMessage = { k: number } | { k: number; expire: string[]; day: number } | { list: string; day: number };

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

/** The endpoints registered under a bell, read from the store (a cached read, §9.8 "The Worker's part"). */
async function entriesOf(env: Env, tk: Bytes): Promise<BellEntry[]> {
  try {
    const raw = await env.PUSH_KV.get(keyBell(tk), { type: "arrayBuffer", cacheTtl: KV_CACHE_TTL_S });
    return raw ? (decodeEntries(new Uint8Array(raw)) ?? []) : [];
  } catch (e) {
    console.error(JSON.stringify({ msg: "push store read failed", error: logErr(e) }));
    return [];
  }
}

/**
 * Reads the ring's bells' entries from the store, calls `ring` on the QuietDO of each endpoint found, and for each
 * time answered waits in place and sends one round, when the wait ends within RING_WAIT of `answeredAt` (when the
 * Worker answered the ring), or else queues a message for then (§9.8 "The Worker's part").
 */
export async function pushRing(env: Env, cfg: PushConfig, E: number, label: Bytes, ringBells: Bytes[], answeredAt = Date.now()): Promise<void> {
  const shards = cfg.shards;
  const bells = new Map<string, Bytes>();
  for (const b of ringBells) bells.set(hex(b), b);
  const found = new Map<string, BellEntry[]>();
  await Promise.all(
    [...bells].map(async ([k, b]) => {
      found.set(k, await entriesOf(env, tkOf(cfg.pushKey, b)));
    }),
  );
  // Each endpoint with the ring's bells it was found under, in the ring's order; grouped by its QuietDO.
  const targets = new Map<string, RingTarget>();
  for (const [k, b] of bells) {
    for (const e of found.get(k) ?? []) {
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
      if (wait === null) return;
      if (Date.now() - answeredAt + wait <= RING_WAIT) {
        await ringSleep(wait);
        await sendDue(env, k, true);
      } else await enqueue(env, k, wait);
    }),
  );
}

/** A message asking QuietDO k for its due pushes after `waitMs` (at least a second: the queue's unit). */
async function enqueue(env: Env, k: number, waitMs: number): Promise<void> {
  const msg: PushQueueMessage = { k };
  await env.PUSH_QUEUE.send(msg, { delaySeconds: Math.max(1, Math.ceil(waitMs / 1000)) });
}

const later = (a: number | null, b: number | null): number | null => (a === null ? b : b === null ? a : Math.min(a, b));

/**
 * Asks QuietDO k for the pushes due now, sends them, and reports them, one batch at a time, so that a Worker stopped
 * midway leaves at most one batch unreported. In place (the Worker of a ring, in `waitUntil`), one round of
 * IN_PLACE_BATCH; from the queue, batches of DUE_BATCH for up to CONSUME_MS. Whatever the QuietDO then still answers a
 * time for (more pushes due, a retry, a push due later) is asked for again through the queue.
 */
export async function sendDue(env: Env, k: number, inPlace = false): Promise<void> {
  const cfg = pushConfig(env);
  if (!cfg) return;
  const stub = quietStub(env, k);
  const start = Date.now();
  for (;;) {
    const { pushes, next } = await stub.due(inPlace ? IN_PLACE_BATCH : DUE_BATCH);
    let after = next;
    if (pushes.length > 0) {
      const reports: SentReport[] = [];
      let i = 0;
      const worker = async (): Promise<void> => {
        while (i < pushes.length) reports.push(await sendOne(cfg, pushes[i++]));
      };
      await Promise.all(Array.from({ length: Math.min(SEND_PARALLEL, pushes.length) }, worker));
      const tally = { sent: 0, retry: 0, gone: 0 };
      for (const r of reports) tally[r.outcome]++;
      if (tally.retry + tally.gone > 0) console.error(JSON.stringify({ msg: "push results", ...tally }));
      after = later(after, await stub.sent(reports));
    }
    if (after === null) return;
    if (!inPlace && after === 0 && Date.now() - start < CONSUME_MS) continue;
    await enqueue(env, k, after);
    return;
  }
}

/**
 * The queue consumer: a `{k}` message names a QuietDO whose due pushes are sent; an expiry message drops the expired
 * endpoints it names at their QuietDO, or goes on with the expiry's listing (§9.8 "The Worker's part", "Expiry").
 */
export async function pushQueue(batch: MessageBatch<unknown>, env: Env): Promise<void> {
  const ks = new Map<number, Message<unknown>[]>();
  const other: Promise<void>[] = [];
  const isK = (k: unknown): k is number => Number.isInteger(k) && (k as number) >= 0 && (k as number) < 4096;
  const isDay = (d: unknown): d is number => Number.isInteger(d) && (d as number) >= 0 && (d as number) < 2 ** 32;
  const attempt = (m: Message<unknown>, what: string, f: () => Promise<void>): Promise<void> =>
    f().then(
      () => m.ack(),
      (e: unknown) => {
        console.error(JSON.stringify({ msg: what, error: logErr(e) }));
        m.retry({ delaySeconds: 10 });
      },
    );
  for (const m of batch.messages) {
    const b = (typeof m.body === "object" && m.body !== null ? m.body : {}) as Record<string, unknown>;
    if (Array.isArray(b.expire) && isK(b.k) && isDay(b.day)) {
      const eps = b.expire.filter((h): h is string => typeof h === "string" && /^[0-9a-f]{32}$/.test(h)).slice(0, EXPIRE_BATCH);
      const k = b.k;
      const day = b.day;
      other.push(attempt(m, "push expiry failed", () => quietStub(env, k).expire(eps.map(fromHex), day).then(() => {})));
    } else if (typeof b.list === "string" && b.list.length <= 4096 && isDay(b.day)) {
      const cursor = b.list;
      const day = b.day;
      other.push(attempt(m, "push expiry failed", () => expiryRun(env, day, cursor).then(() => {})));
    } else if (isK(b.k)) {
      const list = ks.get(b.k);
      if (list) list.push(m);
      else ks.set(b.k, [m]);
    } else m.ack(); // not one of ours: never retried
  }
  await Promise.all([
    ...other,
    ...[...ks].map(async ([k, msgs]) => {
      try {
        await sendDue(env, k);
        for (const m of msgs) m.ack();
      } catch (e) {
        console.error(JSON.stringify({ msg: "push queue failed", error: logErr(e) }));
        for (const m of msgs) m.retry({ delaySeconds: 10 });
      }
    }),
  ]);
}

// ───────────── the daily expiry (§9.8 "Expiry") ─────────────

/** Endpoints named per expiry message. */
export const EXPIRE_BATCH = 64;
const expiryLimits = { pageSize: 1000, pages: 50 };
/** Test hook: the keys per page of the listing, and the pages one run lists before it hands the rest to the queue. */
export function _setExpiryLimitsForTests(l: { pageSize: number; pages: number } | null): void {
  Object.assign(expiryLimits, l ?? { pageSize: 1000, pages: 50 });
}

/**
 * The daily expiry (§9.8 "Expiry"), run by the Cron Trigger: lists the `e/` keys with their metadata and, for the
 * endpoints whose day lies more than PUSH_EXPIRY days back, puts messages on the queue naming them to their owners'
 * QuietDOs, which check each record again and delete it. One run lists a bounded number of pages and then puts the
 * listing's cursor on the queue, whose consumer goes on from there; so a run that is stopped loses nothing that it has
 * queued, and the next day's run lists again from the start.
 */
export async function pushCleanup(env: Env, now = Date.now()): Promise<{ scanned: number; expired: number }> {
  return expiryRun(env, dayOf(now), undefined);
}

async function expiryRun(env: Env, today: number, cursor: string | undefined): Promise<{ scanned: number; expired: number }> {
  const shards = pushShardsOf(env) ?? 1;
  let scanned = 0;
  let expired = 0;
  const byK = new Map<number, string[]>();
  const flush = async (k: number, eps: string[]): Promise<void> => {
    const msg: PushQueueMessage = { k, expire: eps, day: today };
    await env.PUSH_QUEUE.send(msg);
  };
  for (let page = 0; page < expiryLimits.pages; page++) {
    const res = await env.PUSH_KV.list<{ d?: unknown; o?: unknown }>({ prefix: EP_PREFIX, cursor, limit: expiryLimits.pageSize });
    for (const key of res.keys) {
      scanned++;
      const d = key.metadata?.d;
      const o = key.metadata?.o;
      const epHex = key.name.slice(EP_PREFIX.length);
      if (typeof d !== "number" || typeof o !== "string" || !/^[0-9a-f]{32}$/.test(o) || !/^[0-9a-f]{32}$/.test(epHex)) continue;
      if (today - d <= PUSH_EXPIRY) continue;
      const k = quietShard(fromHex(o), shards);
      const list = byK.get(k) ?? [];
      list.push(epHex);
      byK.set(k, list);
      expired++;
      if (list.length === EXPIRE_BATCH) {
        byK.delete(k);
        await flush(k, list);
      }
    }
    cursor = res.list_complete ? undefined : res.cursor;
    if (!cursor) break;
  }
  for (const [k, list] of byK) await flush(k, list);
  if (cursor) {
    const msg: PushQueueMessage = { list: cursor, day: today };
    await env.PUSH_QUEUE.send(msg);
  }
  if (expired > 0) console.error(JSON.stringify({ msg: "push expiry", scanned, expired }));
  return { scanned, expired };
}

/** 32 lowercase hex digits, or anything `hexToBytes` takes (an even number of hex digits); throws otherwise. */
export const fromHex = (h: string): Bytes => hexToBytes(h);

/**
 * The owner of an endpoint by its record's metadata (`o`), or null when the store has no record (§10.10). A failed read
 * throws, so that the call answers 503.
 */
export async function ownerByRecord(env: Env, ep: Bytes): Promise<Bytes | null> {
  let o: unknown;
  try {
    const r = await env.PUSH_KV.getWithMetadata<{ o?: unknown }>(keyEp(ep), "arrayBuffer");
    if (r.value === null) return null;
    o = r.metadata?.o;
  } catch (e) {
    console.error(JSON.stringify({ msg: "push store read failed", error: logErr(e) }));
    throw e;
  }
  return typeof o === "string" && /^[0-9a-f]{32}$/.test(o) ? fromHex(o) : ep;
}

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
