/**
 * Deployment parameters and server secrets for the v2 API (docs/PROTOCOL.md §3.1, §4.4, §9.5, §9.7).
 *
 * Vars (wrangler.jsonc "vars", strings): DELTA_S (Δ), SKEW_S (SKEW), INBOX_SLOT_S (Δin), E_FIRST. A var that is
 * present but invalid (not decimal, out of range, or a Δ that does not divide 604 800) makes the Worker answer
 * 503 "server misconfigured" on /api/v2/* (v2ParamsValid() is false); v2Params() falls back to the default.
 * Secrets: ROUTE_KEY (32 bytes, b64u) and SRV_KEY (32-byte Ed25519 seed, b64u). When either is missing or
 * malformed the Worker answers 503 "server misconfigured" on /api/v2/* (serverKeys() returns null).
 * Shared by the Worker and every v2 Durable Object (they must agree on Δ and SKEW).
 */
import { ERA_MS, ERA_NONE, era, fromB64u, kcommit, kroute, sigPub, sign } from "../lib/proto";
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
}

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

const VARS: Readonly<Record<keyof V2Params, VarSpec>> = {
  // Δ must divide 604 800: the first rows of an era get t = sec(start(E)), and a BlobReg MISS at now ≥ t_row is
  // final (§6.4(g)) only if tpub(now) ≥ t_row, i.e. only if every sec(start(E)) is a multiple of Δ.
  delta: { name: "DELTA_S", dflt: 10, min: 1, max: 3600, ok: (n) => ERA_S % n === 0 },
  skew: { name: "SKEW_S", dflt: 2, min: 0, max: 60 },
  inboxSlot: { name: "INBOX_SLOT_S", dflt: 10, min: 1, max: 3600 },
  eFirst: { name: "E_FIRST", dflt: 0, min: 0, max: ERA_NONE - 1 },
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
  return { delta: get(VARS.delta), skew: get(VARS.skew), inboxSlot: get(VARS.inboxSlot), eFirst: get(VARS.eFirst) };
}

/**
 * False when a deployment var is present but invalid (not decimal, out of range, or a DELTA_S that does not divide
 * 604 800): the Worker then answers 503 "server misconfigured" on /api/v2/* instead of running on a fallback.
 */
export function v2ParamsValid(env: Env): boolean {
  return Object.values(VARS).every((v) => intVar(env, v) !== null);
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
  const keys: ServerKeys = { routeKey: fromB64u(route), srvSeed, srvPk: sigPub(srvSeed) };
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
  /** PUSH_MAX_SUBS */
  maxSubs: number;
  /** PUSH_DAY_SUBS */
  daySubs: number;
  /** The first APP_HOSTS host: the payload's `navigate` is https://<appHost>/ */
  appHost: string;
}

const HOST_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const PUSH_HOST_RE = new RegExp(`^(?:\\*\\.)?${HOST_LABEL}(?:\\.${HOST_LABEL})+$`);

/** Push vars with bounds. The spec gives no upper bounds; these keep a typo from becoming an unbounded setting. */
const PUSH_INT_VARS = {
  powBase: { name: "POW_PUSH", dflt: 20, re: /^\d{1,2}$/, min: 0, max: 64 },
  maxSubs: { name: "PUSH_MAX_SUBS", dflt: 100_000, re: /^\d{1,8}$/, min: 1, max: 10_000_000 },
  daySubs: { name: "PUSH_DAY_SUBS", dflt: 2_000, re: /^\d{1,6}$/, min: 1, max: 100_000 },
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
  const ints: Record<keyof typeof PUSH_INT_VARS, number> = { powBase: 0, maxSubs: 0, daySubs: 0 };
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
      maxSubs: ints.maxSubs,
      daySubs: ints.daySubs,
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

const PUSH_VAR_NAMES = ["VAPID_SK", "PUSH_KEY", "VAPID_SUB", "PUSH_HOSTS", "POW_PUSH", "PUSH_MAX_SUBS", "PUSH_DAY_SUBS", "APP_HOSTS"];
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

/** True when `host` (lowercase) is listed in PUSH_HOSTS: exactly, or under a `*.d` entry. */
export function pushHostAllowed(cfg: PushConfig, host: string): boolean {
  const h = host.toLowerCase();
  return cfg.hosts.some((e) => (e.startsWith("*.") ? h.endsWith(e.slice(1)) && h.length > e.length - 1 : h === e));
}
