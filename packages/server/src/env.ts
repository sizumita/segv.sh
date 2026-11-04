/**
 * Deployment parameters and server secrets for the v2 API (docs/PROTOCOL.md §3.1, §4.4, §9.5, §9.7).
 *
 * Vars (wrangler.jsonc "vars", strings): DELTA_S (Δ), SKEW_S (SKEW), INBOX_SLOT_S (Δin), E_FIRST, RT_CONNS (C),
 * RT_FEEDS (F, a power of two; §9.4), BLOBREG_SHARDS (B, a power of two, a constant of the deployment; §9.2),
 * SHARD_MAP (the shard count per era, "E:S" entries; §9.1) and INBOX_MAP (the inbox bucket count per era, the same
 * form; §9.3). A var that is present but invalid (not decimal, out of
 * range, a Δ that does not divide 604 800, a malformed shard map) makes the Worker answer 503 "server misconfigured"
 * on /api/v2/* (v2ParamsValid() is false); v2Params() falls back to the default.
 * Secrets: ROUTE_KEY (32 bytes, b64u) and SRV_KEY (32-byte Ed25519 seed, b64u). When either is missing or
 * malformed the Worker answers 503 "server misconfigured" on /api/v2/* (serverKeys() returns null).
 * Shared by the Worker and every v2 Durable Object (they must agree on Δ and SKEW).
 */
import { ERA_MS, ERA_NONE, era, fromB64u, kblob, kcommit, kfeed, kroute, ktag, sigPub, sign } from "@segv/protocol/proto";
import { appHosts } from "./hosts";
import { parseVapidKey, vapidPublicKey } from "./webpush";

export interface V2Params {
  /** Δ, seconds (u16, ≥ 1). Production 10, tests 1. */
  delta: number;
  /** SKEW, seconds: bound on clock differences between server components. Production 2, tests 0. */
  skew: number;
  /** Δin = INBOX_SLOT, seconds. Production 10, tests 1. */
  inboxSlot: number;
  /** Era of the first deploy: lower eras are answered "sealed / not found" without any DO call. */
  eFirst: number;
  /** C: the number of ConnDOs (§9.4). Default 1. */
  rtConns: number;
  /** F: the number of FeedDOs, a power of two (§9.4). Default 1. */
  rtFeeds: number;
  /** B: the number of BlobRegDO shards, a power of two, fixed for the deployment (§9.2). Default 1. */
  blobShards: number;
  /** The shard map (§9.1): entries ascending by `from`; s_E is the `bits` of the last entry at or below E, 0 without one. */
  shardMap: ShardMapEntry[];
  /** The inbox bucket map (§9.3 "Buckets"), the same form: β_E is the `bits` of the last entry at or below E. */
  inboxMap: ShardMapEntry[];
}

/** One SHARD_MAP entry: from era `from` on, 2^bits shards per era. */
export interface ShardMapEntry {
  from: number;
  bits: number;
}

/** The largest shard count (2^16; shardOf() takes at most 16 bits). */
const SHARDS_MAX = 65536;

/**
 * Parses SHARD_MAP ("E:S,E:S,…", §9.1 "Shard map"): [] when the var is absent or empty, null when it is malformed
 * (an entry that is not `E:S`, an E above 0xFFFE or not strictly ascending, an S that is not a power of two in
 * 1..65536).
 */
export function parseShardMap(raw: unknown): ShardMapEntry[] | null {
  if (raw === undefined || raw === null) return [];
  if (typeof raw !== "string") return null;
  const s = raw.trim();
  if (s === "") return [];
  const out: ShardMapEntry[] = [];
  for (const part of s.split(",")) {
    const m = /^\s*(\d{1,5}):(\d{1,5})\s*$/.exec(part);
    if (!m) return null;
    const from = Number(m[1]);
    const S = Number(m[2]);
    if (from > ERA_NONE - 1 || S < 1 || S > SHARDS_MAX || (S & (S - 1)) !== 0) return null;
    if (out.length > 0 && from <= out[out.length - 1].from) return null;
    out.push({ from, bits: 31 - Math.clz32(S) });
  }
  return out;
}

/** s_E: the bits of the last entry at or below E (0 when there is none). */
export function shardBitsOf(map: readonly ShardMapEntry[], E: number): number {
  let bits = 0;
  for (const e of map) {
    if (e.from > E) break;
    bits = e.bits;
  }
  return bits;
}

/** S_E = 2^s_E. */
export const shardsOf = (map: readonly ShardMapEntry[], E: number): number => 2 ** shardBitsOf(map, E);

/** b of the blob registry: B = 2^b shards (§9.2). */
export const blobBitsOf = (B: number): number => 31 - Math.clz32(B);

/** β_E: the bits of the last INBOX_MAP entry at or below E (0 when there is none); 2^β_E inbox buckets (§9.3). */
export const inboxBitsOf = (map: readonly ShardMapEntry[], E: number): number => shardBitsOf(map, E);
export const inboxBucketsOf = (map: readonly ShardMapEntry[], E: number): number => 2 ** inboxBitsOf(map, E);

/** Inbox constants (§9.3, §10.9). */
export const INBOX_DAY_CAP = 2000;
export const INBOX_RETENTION = 4;
export const INBOX_BATCH = 32;

interface VarSpec {
  name: string;
  dflt: number;
  min: number;
  max: number;
  ok?: (n: number) => boolean;
}

/** Seconds per era. */
const ERA_S = ERA_MS / 1000;

const VARS: Readonly<Record<Exclude<keyof V2Params, "shardMap" | "inboxMap">, VarSpec>> = {
  // Δ must divide 604 800: the first rows of an era get t = sec(start(E)), and a BlobReg MISS at now ≥ t_row is
  // final (§6.4(g)) only if tpub(now) ≥ t_row, i.e. only if every sec(start(E)) is a multiple of Δ.
  delta: { name: "DELTA_S", dflt: 10, min: 1, max: 3600, ok: (n) => ERA_S % n === 0 },
  skew: { name: "SKEW_S", dflt: 2, min: 0, max: 60 },
  inboxSlot: { name: "INBOX_SLOT_S", dflt: 10, min: 1, max: 3600 },
  eFirst: { name: "E_FIRST", dflt: 0, min: 0, max: ERA_NONE - 1 },
  rtConns: { name: "RT_CONNS", dflt: 1, min: 1, max: 4096 },
  rtFeeds: { name: "RT_FEEDS", dflt: 1, min: 1, max: 4096, ok: (n) => (n & (n - 1)) === 0 },
  blobShards: { name: "BLOBREG_SHARDS", dflt: 1, min: 1, max: 4096, ok: (n) => (n & (n - 1)) === 0 },
};

/** The var's value; undefined when it is absent, null when it is present but invalid. */
function intVar(env: Env, v: VarSpec): number | null | undefined {
  const raw = (env as unknown as Record<string, unknown>)[v.name];
  if (raw === undefined || raw === null) return undefined;
  const s = typeof raw === "number" ? String(raw) : raw;
  if (typeof s !== "string" || !/^\d{1,5}$/.test(s)) return null;
  const n = Number(s);
  return n >= v.min && n <= v.max && (v.ok?.(n) ?? true) ? n : null;
}

/** The deployment parameters, with the default for any absent or invalid var (the Durable Objects use this). */
export function v2Params(env: Env): V2Params {
  const get = (v: VarSpec): number => intVar(env, v) ?? v.dflt;
  return {
    delta: get(VARS.delta),
    skew: get(VARS.skew),
    inboxSlot: get(VARS.inboxSlot),
    eFirst: get(VARS.eFirst),
    rtConns: get(VARS.rtConns),
    rtFeeds: get(VARS.rtFeeds),
    blobShards: get(VARS.blobShards),
    shardMap: parseShardMap((env as unknown as Record<string, unknown>).SHARD_MAP) ?? [],
    inboxMap: parseShardMap((env as unknown as Record<string, unknown>).INBOX_MAP) ?? [],
  };
}

/**
 * False when a deployment var is present but invalid (not decimal, out of range, a DELTA_S that does not divide
 * 604 800, an RT_FEEDS or BLOBREG_SHARDS that is not a power of two, or a malformed SHARD_MAP or INBOX_MAP): the Worker
 * then answers 503 "server
 * misconfigured" on /api/v2/* instead of running on a fallback.
 */
export function v2ParamsValid(env: Env): boolean {
  return (
    Object.values(VARS).every((v) => intVar(env, v) !== null) &&
    parseShardMap((env as unknown as Record<string, unknown>).SHARD_MAP) !== null &&
    parseShardMap((env as unknown as Record<string, unknown>).INBOX_MAP) !== null
  );
}

/**
 * Era bounds the Worker enforces before any DO call (§9.7): lo = era(now − SKEW), hi = era(now + SKEW).
 * Writes need lo ≤ E ≤ hi; reads of E > hi are NO_ERA, reads of E < E_FIRST are "sealed".
 */
export function eraBounds(nowMs: number, skewS: number): { now: number; lo: number; hi: number } {
  return { now: era(nowMs), lo: era(nowMs - skewS * 1000), hi: era(nowMs + skewS * 1000) };
}

// ───────────── secrets ─────────────

export interface ServerKeys {
  routeKey: Uint8Array;
  /** ktag: the key of the opaque client tag (§4.4) */
  tagKey: Uint8Array;
  /** kfeed: the key of the topic feed hash (§4.4) */
  feedKey: Uint8Array;
  /** kblob: the key that routes blob ids to the registry shards (§4.4, §9.2) */
  blobKey: Uint8Array;
  /** Ed25519 seed (SRV_SK) */
  srvSeed: Uint8Array;
  /** srvKey, published in params */
  srvPk: Uint8Array;
}

let keyCache: { route: string; srv: string; keys: ServerKeys } | null = null;
const krouteCache = new Map<number, Uint8Array>();

function secret32(env: Env, name: string): string | null {
  const raw = (env as unknown as Record<string, unknown>)[name];
  if (typeof raw !== "string") return null;
  try {
    return fromB64u(raw.trim()).length === 32 ? raw.trim() : null;
  } catch {
    return null;
  }
}

/** The server secrets, or null when either is missing / malformed (→ 503 "server misconfigured"). */
export function serverKeys(env: Env): ServerKeys | null {
  const route = secret32(env, "ROUTE_KEY");
  const srv = secret32(env, "SRV_KEY");
  if (route === null || srv === null) return null;
  if (keyCache && keyCache.route === route && keyCache.srv === srv) return keyCache.keys;
  const srvSeed = fromB64u(srv);
  const routeKey = fromB64u(route);
  const keys: ServerKeys = {
    routeKey,
    tagKey: ktag(routeKey),
    feedKey: kfeed(routeKey),
    blobKey: kblob(routeKey),
    srvSeed,
    srvPk: sigPub(srvSeed),
  };
  keyCache = { route, srv, keys };
  krouteCache.clear();
  signKey = null;
  return keys;
}

/** kroute_E for this deployment (cached per era). */
export function krouteFor(keys: ServerKeys, E: number): Uint8Array {
  let k = krouteCache.get(E);
  if (!k) {
    k = kroute(keys.routeKey, E);
    if (krouteCache.size > 64) krouteCache.clear();
    krouteCache.set(E, k);
  }
  return k;
}

export const kcommitFor = (keys: ServerKeys, E: number): Uint8Array => kcommit(krouteFor(keys, E));

// Ed25519 signing (receipts, checkpoints): native WebCrypto when available, noble otherwise.
const ED_PKCS8_PREFIX = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20);
let signKey: { seed: Uint8Array; key: Promise<CryptoKey | null> } | null = null;

async function importSignKey(seed: Uint8Array): Promise<CryptoKey | null> {
  try {
    const der = new Uint8Array(48);
    der.set(ED_PKCS8_PREFIX);
    der.set(seed, 16);
    return await crypto.subtle.importKey("pkcs8", der, { name: "Ed25519" }, false, ["sign"]);
  } catch {
    return null;
  }
}

/** Sign `msg` with SRV_SK. */
export async function srvSign(keys: ServerKeys, msg: Uint8Array): Promise<Uint8Array> {
  if (!signKey || signKey.seed !== keys.srvSeed) signKey = { seed: keys.srvSeed, key: importSignKey(keys.srvSeed) };
  const key = await signKey.key;
  if (key) {
    try {
      return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, msg as Uint8Array<ArrayBuffer>));
    } catch {
      /* fall through to noble */
    }
  }
  return sign(msg, keys.srvSeed);
}

// ───────────── Web Push (§9.8) ─────────────

/** Push service hosts when PUSH_HOSTS is absent (§9.8). */
export const DEFAULT_PUSH_HOSTS = "web.push.apple.com,fcm.googleapis.com,updates.push.services.mozilla.com,*.notify.windows.com";

export interface PushConfig {
  /** VAPID_SK, the 32-byte P-256 scalar */
  vapidSk: Uint8Array;
  /** [d]G, 65 bytes uncompressed: params `push.vapid` */
  vapidPk: Uint8Array;
  /** VAPID_SUB, the JWT `sub` claim */
  vapidSub: string;
  /** PUSH_KEY: the key of the stored registrations */
  pushKey: Uint8Array;
  /** PUSH_HOSTS entries, lowercase; `*.d` matches every host ending in `.d` */
  hosts: readonly string[];
  /** POW_PUSH */
  powBase: number;
  /** PUSH_SHARDS: the number of BellDOs and of QuietDOs (§9.8) */
  shards: number;
  /** The first APP_HOSTS host: the payload's `navigate` is https://<appHost>/ */
  appHost: string;
}

const HOST_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const PUSH_HOST_RE = new RegExp(`^(?:\\*\\.)?${HOST_LABEL}(?:\\.${HOST_LABEL})+$`);

/** Push vars with bounds. The spec gives no upper bounds; these keep a typo from becoming an unbounded setting. */
const PUSH_INT_VARS = {
  powBase: { name: "POW_PUSH", dflt: 20, re: /^\d{1,2}$/, min: 0, max: 64 },
  shards: { name: "PUSH_SHARDS", dflt: 1, re: /^\d{1,4}$/, min: 1, max: 4096 },
} as const;

type PushParse = { ok: true; cfg: PushConfig } | { ok: false; bad: string | null };

const rawVar = (env: Env, name: string): unknown => (env as unknown as Record<string, unknown>)[name];

function parsePush(env: Env): PushParse {
  const vsk = rawVar(env, "VAPID_SK");
  if (vsk === undefined || vsk === null || vsk === "") return { ok: false, bad: null };
  const vapidSk = typeof vsk === "string" ? parseVapidKey(vsk) : null;
  if (!vapidSk) return { ok: false, bad: "VAPID_SK" };
  const pk = secret32(env, "PUSH_KEY");
  if (pk === null) return { ok: false, bad: "PUSH_KEY" };
  const sub = rawVar(env, "VAPID_SUB");
  if (typeof sub !== "string" || !validVapidSub(sub.trim())) return { ok: false, bad: "VAPID_SUB" };
  const hostsRaw = rawVar(env, "PUSH_HOSTS");
  let hosts: string[];
  if (hostsRaw === undefined || hostsRaw === null) hosts = DEFAULT_PUSH_HOSTS.split(",");
  else {
    if (typeof hostsRaw !== "string") return { ok: false, bad: "PUSH_HOSTS" };
    hosts = hostsRaw.split(",").map((h) => h.trim().toLowerCase());
    if (hosts.length === 0 || !hosts.every((h) => PUSH_HOST_RE.test(h))) return { ok: false, bad: "PUSH_HOSTS" };
  }
  const ints: Record<keyof typeof PUSH_INT_VARS, number> = { powBase: 0, shards: 0 };
  for (const [k, v] of Object.entries(PUSH_INT_VARS) as [keyof typeof PUSH_INT_VARS, (typeof PUSH_INT_VARS)[keyof typeof PUSH_INT_VARS]][]) {
    const raw = rawVar(env, v.name);
    if (raw === undefined || raw === null) {
      ints[k] = v.dflt;
      continue;
    }
    const s = typeof raw === "number" ? String(raw) : raw;
    if (typeof s !== "string" || !v.re.test(s)) return { ok: false, bad: v.name };
    const n = Number(s);
    if (n < v.min || n > v.max) return { ok: false, bad: v.name };
    ints[k] = n;
  }
  const app = appHosts(env);
  if (app.length === 0) return { ok: false, bad: "APP_HOSTS" };
  return {
    ok: true,
    cfg: {
      vapidSk,
      vapidPk: vapidPublicKey(vapidSk),
      vapidSub: sub.trim(),
      pushKey: fromB64u(pk),
      hosts,
      powBase: ints.powBase,
      shards: ints.shards,
      appHost: app[0],
    },
  };
}

/** A `mailto:` URI with an address, or an absolute `https:` URL (RFC 8292 §2.1). */
function validVapidSub(s: string): boolean {
  if (s.length === 0 || s.length > 512 || /[\s"\\]/.test(s)) return false;
  if (s.startsWith("mailto:")) return /^mailto:[^@]+@[^@]+$/.test(s);
  try {
    const u = new URL(s);
    return u.protocol === "https:" && u.hostname !== "";
  } catch {
    return false;
  }
}

const PUSH_VAR_NAMES = ["VAPID_SK", "PUSH_KEY", "VAPID_SUB", "PUSH_HOSTS", "POW_PUSH", "PUSH_SHARDS", "APP_HOSTS"];

/**
 * PUSH_SHARDS alone (§9.8): the value, 1 when the var is absent, null when it is present but malformed. The daily
 * expiry routes by it whether or not push is on (a malformed value then counts as 1).
 */
export function pushShardsOf(env: Env): number | null {
  const v = PUSH_INT_VARS.shards;
  const raw = rawVar(env, v.name);
  if (raw === undefined || raw === null) return v.dflt;
  const s = typeof raw === "number" ? String(raw) : raw;
  if (typeof s !== "string" || !v.re.test(s)) return null;
  const n = Number(s);
  return n < v.min || n > v.max ? null : n;
}
let pushCache: { sig: string; cfg: PushConfig | null } | null = null;
const pushLogged = new Set<string>();

/**
 * The push configuration, or null when push is off: VAPID_SK unset, or any push setting missing or invalid. An invalid
 * setting is logged once per isolate by name, never by value, and changes nothing else: serverKeys and v2ParamsValid
 * (the 503 "server misconfigured" path) never read push settings (§9.8).
 */
export function pushConfig(env: Env): PushConfig | null {
  const sig = PUSH_VAR_NAMES.map((n) => String(rawVar(env, n) ?? "\u0000")).join("\u0001");
  if (pushCache && pushCache.sig === sig) return pushCache.cfg;
  const r = parsePush(env);
  if (!r.ok && r.bad !== null && !pushLogged.has(r.bad)) {
    pushLogged.add(r.bad);
    console.error(JSON.stringify({ msg: "push is off: invalid setting", setting: r.bad }));
  }
  const cfg = r.ok ? r.cfg : null;
  pushCache = { sig, cfg };
  return cfg;
}

/** Test hook: forget the cached push configuration and which settings were logged. */
export function _resetPushConfigForTests(): void {
  pushCache = null;
  pushLogged.clear();
}

// ───────────── optional list settings (§9.7, §11.14) ─────────────

/**
 * The entries of a comma-separated setting, each trimmed and kept once: [] when it is unset or empty, null when it is
 * not a string or an entry fails `ok`.
 */
export function listVar(raw: unknown, ok: (entry: string) => boolean): string[] | null {
  if (raw === undefined || raw === null) return [];
  if (typeof raw !== "string") return null;
  if (raw.trim() === "") return [];
  const list = raw.split(",").map((e) => e.trim());
  return list.every(ok) ? [...new Set(list)] : null;
}

const settingLogged = new Set<string>();

/** Logs that an optional setting is invalid, once per isolate, by name and never by value (as for push, §9.8). */
export function logSettingOnce(msg: string, setting: string): void {
  if (settingLogged.has(setting)) return;
  settingLogged.add(setting);
  console.error(JSON.stringify({ msg, setting }));
}

/** Test hook: forget which optional settings were logged. */
export function _resetSettingLogsForTests(): void {
  settingLogged.clear();
}

/** True when `host` (lowercase) is listed in PUSH_HOSTS: exactly, or under a `*.d` entry. */
export function pushHostAllowed(cfg: PushConfig, host: string): boolean {
  const h = host.toLowerCase();
  return cfg.hosts.some((e) => (e.startsWith("*.") ? h.endsWith(e.slice(1)) && h.length > e.length - 1 : h === e));
}
