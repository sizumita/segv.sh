/**
 * Deployment parameters and server secrets for the v2 API (docs/PROTOCOL-v2.md §3.1, §4.4, §9.5, §9.7).
 *
 * Vars (wrangler.jsonc "vars", strings): DELTA_S (Δ), SKEW_S (SKEW), INBOX_SLOT_S (Δin), E_FIRST. A var that is
 * present but invalid (not decimal, out of range, or a Δ that does not divide 604 800) makes the Worker answer
 * 503 "server misconfigured" on /api/v2/* (v2ParamsValid() is false); v2Params() falls back to the default.
 * Secrets: ROUTE_KEY (32 bytes, b64u) and SRV_KEY (32-byte Ed25519 seed, b64u). When either is missing or
 * malformed the Worker answers 503 "server misconfigured" on /api/v2/* (serverKeys() returns null).
 * Shared by the Worker and every v2 Durable Object (they must agree on Δ and SKEW).
 */
import { ERA_MS, ERA_NONE, era, fromB64u, kcommit, kroute, sigPub, sign } from "../lib/proto";

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
